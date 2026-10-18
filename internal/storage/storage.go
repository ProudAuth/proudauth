// Package storage provides the PostgreSQL connection pool, the unit-of-work helper
// and schema migrations. PostgreSQL is the durable source of truth for every
// security-critical transition (ARC-002, DEP-010).
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/proudauth/proudauth/migrations"
)

// Querier is satisfied by both the pool and a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DB wraps the connection pool.
type DB struct {
	Pool *pgxpool.Pool
	// fault is the fault-injection seam of SetFault (TEST-059).
	fault atomic.Pointer[FaultFunc]
	// txSlots bounds the transactions Tx and SerializableTx keep open at
	// once to fewer than the pool's connections (TxSlots); nil: no bound.
	txSlots chan struct{}
}

// TxSlots returns how many transactions a pool of maxConns connections runs
// at once: all but a quarter of the connections (at least one is kept back
// when there are two or more). Code inside a transaction also runs
// statements outside it on other pool connections (lookups, rate-limit
// counters, signing keys, claims hooks). With as many open transactions as
// connections, every transaction waited for a connection only another
// waiting transaction could free: token issuance, refresh and sign-in
// stalled until statement_timeout or the request deadline once 20
// concurrent requests met the default storage.max_conns of 20 (found with
// identity-bench, NFR-002). The connections kept back serve those
// statements, so open transactions always make progress.
func TxSlots(maxConns int32) int {
	if maxConns < 2 {
		return 1
	}
	return int(maxConns - max(1, maxConns/4))
}

// Fault points of a transaction run by DB.Tx (TEST-059).
const (
	// FaultBegin is reached after BEGIN, before the transaction's work: the
	// database fails before the transition starts.
	FaultBegin = "begin"
	// FaultCommit is reached after all of the transaction's work, before
	// COMMIT: every statement ran, and the commit fails.
	FaultCommit = "commit"
)

// FaultFunc decides whether a transaction fails at a fault point; an error
// aborts it as a database failure there would: the transaction rolls back,
// nothing of it is committed and the caller receives the error (not
// retried).
type FaultFunc func(ctx context.Context, tx pgx.Tx, point string) error

// SetFault installs a fault-injection seam for tests, in the style of
// impersonation's FailAudit (TEST-059): f is consulted inside every
// transaction run by Tx or SerializableTx at FaultBegin and FaultCommit; nil
// removes it. Production code never sets it. It returns a function that
// removes it again.
func (db *DB) SetFault(f FaultFunc) (clear func()) {
	if f == nil {
		db.fault.Store(nil)
	} else {
		db.fault.Store(&f)
	}
	return func() { db.fault.Store(nil) }
}

func (db *DB) injectFault(ctx context.Context, tx pgx.Tx, point string) error {
	if f := db.fault.Load(); f != nil {
		return (*f)(ctx, tx, point)
	}
	return nil
}

// Options for opening the pool.
type Options struct {
	MaxConns         int32
	MinConns         int32
	StatementTimeout time.Duration
}

// Open connects to PostgreSQL and verifies connectivity.
func Open(ctx context.Context, url string, opt Options) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if opt.MaxConns > 0 {
		cfg.MaxConns = opt.MaxConns
	}
	if opt.MinConns > 0 {
		cfg.MinConns = opt.MinConns
	}
	if opt.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(opt.StatementTimeout.Milliseconds())
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	cfg.ConnConfig.RuntimeParams["application_name"] = "proudauth"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unavailable: %w", err)
	}
	return &DB{Pool: pool, txSlots: make(chan struct{}, TxSlots(cfg.MaxConns))}, nil
}

// Close closes the pool.
func (db *DB) Close() { db.Pool.Close() }

// Ping checks database availability for readiness (DEP-009).
func (db *DB) Ping(ctx context.Context) error { return db.Pool.Ping(ctx) }

// Tx runs fn inside a READ COMMITTED transaction. Every mutation, its audit record and
// its outbox record must be written through the same tx (DB-009). fn must not perform
// external side effects: the transaction may be retried on serialization failure or
// deadlock (DB-014), and is never retried after commit.
func (db *DB) Tx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return db.tx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, fn)
}

// SerializableTx runs fn at SERIALIZABLE isolation with bounded retries.
func (db *DB) SerializableTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return db.tx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable}, fn)
}

const maxTxAttempts = 4

type noRetryKey struct{}

// NoRetry marks work whose transaction may call out to external systems (for
// example claims or eligibility hooks): it runs once, and a deadlock or
// serialization failure is returned instead of retried, so no external effect
// is repeated (DB-014).
func NoRetry(ctx context.Context) context.Context { return context.WithValue(ctx, noRetryKey{}, true) }

func (db *DB) tx(ctx context.Context, opts pgx.TxOptions, fn func(tx pgx.Tx) error) error {
	if db.txSlots != nil {
		// Wait for a transaction slot without holding a connection, so the
		// connections kept back stay free for statements that open
		// transactions run outside themselves (TxSlots).
		select {
		case db.txSlots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		defer func() { <-db.txSlots }()
	}
	var lastErr error
	attempts := maxTxAttempts
	if once, _ := ctx.Value(noRetryKey{}).(bool); once {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		var hooks *commitHooks
		err := pgx.BeginTxFunc(ctx, db.Pool, opts, func(tx pgx.Tx) error {
			hooks = &commitHooks{}
			pendingHooks.Store(tx, hooks)
			defer pendingHooks.Delete(tx)
			if err := db.injectFault(ctx, tx, FaultBegin); err != nil {
				return err
			}
			if err := fn(tx); err != nil {
				return err
			}
			return db.injectFault(ctx, tx, FaultCommit)
		})
		if err == nil {
			for _, h := range hooks.fns {
				h()
			}
			return nil
		}
		if !IsRetryable(err) {
			return err
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 15 * time.Millisecond):
		}
	}
	return lastErr
}

type commitHooks struct {
	mu  sync.Mutex
	fns []func()
}

// pendingHooks maps each open transaction started by DB.Tx to the functions
// waiting for its commit.
var pendingHooks sync.Map

// AfterCommit runs fn once the transaction q belongs to commits; a rolled
// back or retried attempt drops it. For a querier that is not a transaction
// opened by DB.Tx (the pool, or a nested transaction), fn runs at once. fn
// must not block.
func AfterCommit(q Querier, fn func()) {
	if tx, ok := q.(pgx.Tx); ok {
		if v, ok := pendingHooks.Load(tx); ok {
			h := v.(*commitHooks)
			h.mu.Lock()
			h.fns = append(h.fns, fn)
			h.mu.Unlock()
			return
		}
	}
	fn()
}

// IsRetryable reports serialization failures and deadlocks.
func IsRetryable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001" || pgErr.Code == "40P01"
	}
	return false
}

// IsUniqueViolation reports a unique-constraint violation, optionally for a named constraint.
func IsUniqueViolation(err error, constraint ...string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	if len(constraint) == 0 {
		return true
	}
	for _, c := range constraint {
		if pgErr.ConstraintName == c {
			return true
		}
	}
	return false
}

// IsForeignKeyViolation reports a foreign-key violation.
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// IsNoRows reports pgx.ErrNoRows.
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// ---- migrations ----

const migrationLockID = 727274001

// MigrationStatus describes one migration.
type MigrationStatus struct {
	Name     string
	Checksum string
	// Compat is "expand" (older binaries keep working against the migrated
	// schema) or "contract" (older binaries are no longer supported). A
	// migration declares contract with a "-- proudauth:compat=contract" line.
	Compat string
	// NoTransaction marks a migration with a "-- proudauth:no-transaction"
	// line: it runs statement by statement outside a transaction, as
	// CREATE INDEX CONCURRENTLY requires (parseNoTransaction).
	NoTransaction bool
	AppliedAt     *time.Time
}

// ErrSchemaIncompatible reports a database migrated past what this binary
// supports (TEST-061, DEP-012).
var ErrSchemaIncompatible = errors.New("database schema is incompatible with this binary")

// migrationFS is the migration source; tests substitute it.
var migrationFS fs.FS = migrations.Files

func loadMigrations() ([]MigrationStatus, map[string]string, error) {
	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return nil, nil, err
	}
	var out []MigrationStatus
	bodies := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := fs.ReadFile(migrationFS, e.Name())
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, MigrationStatus{Name: e.Name(), Checksum: hex.EncodeToString(sum[:]), Compat: migrationCompat(string(b)),
			NoTransaction: hasLine(string(b), noTransactionDirective)})
		bodies[e.Name()] = string(b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, bodies, nil
}

// noTransactionDirective marks a migration that runs outside a transaction.
const noTransactionDirective = "-- proudauth:no-transaction"

// hasLine reports whether body has a line that is exactly line, apart from
// surrounding white space.
func hasLine(body, line string) bool {
	for _, l := range strings.Split(body, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

// Bounds of a migration run (OPS-008, DEP-012). A migration's DDL takes
// table locks; a statement queued behind a long-running query blocks every
// later query on that table until the migration commits, so on hot tables
// (authorization codes, access tokens, sessions) an unbounded lock wait is an
// outage. Each migration therefore waits at most DefaultMigrationLockTimeout
// for any lock and is retried, after a growing pause, when it gives up.
const (
	DefaultMigrationLockTimeout      = 5 * time.Second
	DefaultMigrationLockRetries      = 5
	DefaultMigrationStatementTimeout = 10 * time.Minute
	defaultLockRetryBackoff          = 500 * time.Millisecond
	maxLockRetryBackoff              = 8 * time.Second
)

// MigrateOptions controls safety gates for schema transitions (OPS-008).
type MigrateOptions struct {
	// BackupReference identifies the verified backup taken before this run
	// (snapshot ID, WAL position, file name). Contract migrations, which drop
	// or rewrite schema older binaries need, refuse to run without it; it is
	// recorded with each migration applied in the run.
	BackupReference string
	// Plan reports what would run, with precondition results, without applying.
	Plan bool
	// LockTimeout bounds every lock wait of a migration (PostgreSQL
	// lock_timeout, set for the migration's own statements only), except
	// the concurrent index statements of a no-transaction migration
	// (applyWithoutTx). Zero selects DefaultMigrationLockTimeout; negative
	// waits without limit.
	LockTimeout time.Duration
	// LockRetries is how often a migration that gave up waiting for a lock
	// (SQLSTATE 55P03) is retried, after a pause that doubles each time.
	// Zero selects DefaultMigrationLockRetries; negative does not retry.
	LockRetries int
	// StatementTimeout bounds each migration statement (statement_timeout,
	// set for the migration's own statements only, so it replaces the
	// runtime connection's limit there and never applies to runtime
	// traffic). Zero selects DefaultMigrationStatementTimeout; negative
	// runs without limit.
	StatementTimeout time.Duration
	// lockRetryBackoff is the first pause between attempts
	// (defaultLockRetryBackoff when zero); tests shorten it.
	lockRetryBackoff time.Duration
}

// migrationBounds are the resolved bounds of a run; zero means no limit.
type migrationBounds struct {
	lockTimeout, statementTimeout time.Duration
	retries                       int
	backoff                       time.Duration
}

func (opt MigrateOptions) bounds() migrationBounds {
	pick := func(d, def time.Duration) time.Duration {
		switch {
		case d == 0:
			return def
		case d < 0:
			return 0
		}
		return d
	}
	b := migrationBounds{
		lockTimeout:      pick(opt.LockTimeout, DefaultMigrationLockTimeout),
		statementTimeout: pick(opt.StatementTimeout, DefaultMigrationStatementTimeout),
		retries:          max(opt.LockRetries, 0),
		backoff:          pick(opt.lockRetryBackoff, defaultLockRetryBackoff),
	}
	if opt.LockRetries == 0 {
		b.retries = DefaultMigrationLockRetries
	}
	return b
}

// pgMillis renders d as a PostgreSQL time setting; "0" disables it.
func pgMillis(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	return fmt.Sprintf("%dms", min(max(d.Milliseconds(), 1), math.MaxInt32))
}

// isLockTimeout reports lock_not_available (SQLSTATE 55P03): lock_timeout
// expired, or NOWAIT found the lock taken.
func isLockTimeout(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}

// withLockRetry runs attempt until it succeeds, fails for another reason
// than a lock timeout, or has been retried b.retries times, pausing between
// attempts. An attempt that fails must leave nothing behind but a rolled
// back transaction or repeatable statements that completed. lockTimeout is
// the lock_timeout the attempts run with, for the error message.
func withLockRetry(ctx context.Context, b migrationBounds, lockTimeout time.Duration, attempt func() error) error {
	pause := b.backoff
	for n := 0; ; n++ {
		err := attempt()
		if err == nil || !isLockTimeout(err) {
			return err
		}
		if n >= b.retries {
			attempts := fmt.Sprintf("%d attempts", n+1)
			if n == 0 {
				attempts = "1 attempt"
			}
			if lockTimeout <= 0 {
				return fmt.Errorf("%w (gave up after %s: run migrate again when the tables are quieter)", err, attempts)
			}
			return fmt.Errorf("%w (gave up after %s with lock_timeout %s: run migrate again when the tables are quieter, or raise -lock-timeout or storage.migration_lock_timeout)", err, attempts, lockTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
		pause = min(pause*2, maxLockRetryBackoff)
	}
}

// MigrationPlanItem is one pending migration in a plan, or one migration a
// run applied.
type MigrationPlanItem struct {
	Name          string
	Compat        string
	NoTransaction bool
	Preconditions []PreconditionResult
	// OutOfOrder is set when the migration sorts before NewestApplied, the
	// newest migration the database had applied before the run (a
	// backported fix, or a file merged after a later one shipped), unless
	// the file carries a "-- proudauth:allow-out-of-order: <reason>" line.
	// It was written against a schema without the newer migrations, which
	// review should confirm. It still runs: the numbering has gaps, and
	// refusing would block hotfix backports (OPS-008).
	OutOfOrder    bool
	NewestApplied string
}

// PreconditionResult is one declared precondition and whether it holds.
type PreconditionResult struct {
	SQL  string
	Held bool
	Err  string
}

// ErrBackupRequired means a contract migration was attempted without a
// recorded backup reference.
var ErrBackupRequired = errors.New("a contract (destructive) migration requires a verified backup reference")

// preconditions extracts "-- proudauth:precondition <SQL>" lines: each is a
// single-row boolean query that must be true before the migration runs.
func preconditions(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if q, ok := strings.CutPrefix(strings.TrimSpace(line), "-- proudauth:precondition "); ok && strings.TrimSpace(q) != "" {
			out = append(out, strings.TrimSpace(q))
		}
	}
	return out
}

func checkPreconditions(ctx context.Context, q Querier, body string) []PreconditionResult {
	var out []PreconditionResult
	for _, sql := range preconditions(body) {
		r := PreconditionResult{SQL: sql}
		if err := q.QueryRow(ctx, sql).Scan(&r.Held); err != nil {
			r.Err = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// Migrate applies pending migrations with default safety options (no backup
// reference: contract migrations are refused).
func (db *DB) Migrate(ctx context.Context) ([]string, error) {
	ran, _, err := db.MigrateWith(ctx, MigrateOptions{})
	return ran, err
}

// MigrateWith applies pending migrations under an advisory lock so concurrent
// nodes cannot race. Applied migrations whose checksum changed abort the run,
// contract migrations require a backup reference, and declared preconditions
// must hold, rather than attempting unsafe automatic recovery (OPS-008).
// Every lock wait and statement of a migration is bounded (LockTimeout,
// StatementTimeout), and a migration that gives up waiting for a lock is
// retried a bounded number of times (LockRetries), so DDL never queues
// indefinitely in front of the service's queries (DEP-012).
//
// It returns the names of the migrations applied and, for a plan, the
// pending migrations; otherwise the migrations applied (also when the run
// fails part-way), so the caller can warn about those applied out of order
// (MigrationPlanItem.OutOfOrder).
func (db *DB) MigrateWith(ctx context.Context, opt MigrateOptions) ([]string, []MigrationPlanItem, error) {
	ran, plan, err := db.migrate(ctx, opt)
	return ran, plan, err
}

func (db *DB) migrate(ctx context.Context, opt MigrateOptions) ([]string, []MigrationPlanItem, error) {
	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return nil, nil, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)

	// A plan is read-only: it runs with the runtime role's data privileges,
	// so it never creates or alters the bookkeeping table (OPS-013).
	var tracked bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&tracked); err != nil {
		return nil, nil, err
	}
	if !opt.Plan {
		if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return nil, nil, err
		}
		// Each applied migration records whether older binaries stay compatible, so
		// an older node can decide without knowing the newer migration's content.
		if _, err := conn.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS compat text NOT NULL DEFAULT 'expand'`); err != nil {
			return nil, nil, err
		}
		if _, err := conn.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS backup_reference text`); err != nil {
			return nil, nil, err
		}
		tracked = true
	}
	all, bodies, err := loadMigrations()
	if err != nil {
		return nil, nil, err
	}
	applied := map[string]string{}
	query := `SELECT name, checksum FROM schema_migrations`
	if !tracked {
		query = `SELECT ''::text, ''::text WHERE false`
	}
	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var n, c string
		if err := rows.Scan(&n, &c); err != nil {
			rows.Close()
			return nil, nil, err
		}
		applied[n] = c
	}
	rows.Close()
	known := map[string]bool{}
	for _, m := range all {
		known[m.Name] = true
	}
	for name := range applied {
		if !known[name] {
			return nil, nil, fmt.Errorf("database has migration %s unknown to this binary: refusing to run an older binary against a newer schema (TEST-061)", name)
		}
	}
	// No-transaction files are split before anything runs, so a file the
	// splitter refuses stops the run (and the plan) before any change.
	noTx := map[string][]noTxStatement{}
	for _, m := range all {
		if _, ok := applied[m.Name]; ok || !m.NoTransaction {
			continue
		}
		stmts, err := parseNoTransaction(bodies[m.Name])
		if err != nil {
			return nil, nil, fmt.Errorf("migration %s (no-transaction): %w", m.Name, err)
		}
		noTx[m.Name] = stmts
	}
	// A pending migration that sorts before the newest applied one runs out
	// of order (MigrationPlanItem.OutOfOrder).
	newest := ""
	for name := range applied {
		newest = max(newest, name)
	}
	bounds := opt.bounds()
	var ran []string
	var items []MigrationPlanItem
	for _, m := range all {
		if sum, ok := applied[m.Name]; ok {
			if sum != m.Checksum {
				return ran, items, fmt.Errorf("migration %s checksum mismatch: applied %s, binary %s", m.Name, sum[:12], m.Checksum[:12])
			}
			continue
		}
		item := MigrationPlanItem{Name: m.Name, Compat: m.Compat, NoTransaction: m.NoTransaction,
			Preconditions: checkPreconditions(ctx, conn, bodies[m.Name])}
		if m.Name < newest && markerReason(bodies[m.Name], allowOutOfOrderMarker) == "" {
			item.OutOfOrder, item.NewestApplied = true, newest
		}
		if opt.Plan {
			items = append(items, item)
			continue
		}
		if m.Compat == "contract" && strings.TrimSpace(opt.BackupReference) == "" {
			return ran, items, fmt.Errorf("%w: %s (run migrate with -backup-reference after taking and verifying a backup)", ErrBackupRequired, m.Name)
		}
		for _, p := range item.Preconditions {
			if !p.Held {
				return ran, items, fmt.Errorf("migration %s precondition failed: %s %s", m.Name, p.SQL, p.Err)
			}
		}
		if m.NoTransaction {
			err = applyWithoutTx(ctx, conn, m, noTx[m.Name], bounds, opt.BackupReference)
		} else {
			err = applyInTx(ctx, conn, m, bodies[m.Name], bounds, opt.BackupReference)
		}
		if err != nil {
			return ran, items, err
		}
		ran = append(ran, m.Name)
		items = append(items, item)
	}
	return ran, items, nil
}

func recordMigration(ctx context.Context, q Querier, m MigrationStatus, backupReference string) error {
	_, err := q.Exec(ctx, `INSERT INTO schema_migrations (name, checksum, compat, backup_reference) VALUES ($1, $2, $3, $4)`,
		m.Name, m.Checksum, m.Compat, nilIfBlank(backupReference))
	return err
}

// applyInTx applies a migration and records it in one transaction, with
// lock_timeout and statement_timeout set for that transaction only. A lock
// timeout rolls everything back, so the whole transaction is retried.
func applyInTx(ctx context.Context, conn *pgxpool.Conn, m MigrationStatus, body string, b migrationBounds, backupReference string) error {
	return withLockRetry(ctx, b, b.lockTimeout, func() error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)`,
			pgMillis(b.lockTimeout), pgMillis(b.statementTimeout)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, body); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "25001" {
				return fmt.Errorf("apply %s: %w (a statement that cannot run in a transaction block, such as CREATE INDEX CONCURRENTLY, needs a file marked %q)", m.Name, err, noTransactionDirective)
			}
			return fmt.Errorf("apply %s: %w", m.Name, err)
		}
		if err := recordMigration(ctx, tx, m, backupReference); err != nil {
			return err
		}
		return tx.Commit(ctx)
	})
}

// applyWithoutTx runs a no-transaction migration one statement at a time
// outside a transaction, then records it once every statement succeeded and
// every index it creates is valid. The file is not atomic: an interrupted
// run leaves its completed statements in place, so each statement is
// repeatable (parseNoTransaction) and a repeated run completes it. A lock
// timeout retries the statement that hit it.
//
// CREATE INDEX CONCURRENTLY and DROP INDEX CONCURRENTLY (and the drop of an
// invalid index) run without lock_timeout, bounded by statement_timeout
// alone. They wait for every transaction older than them, read-only ones
// included, yet take only SHARE UPDATE EXCLUSIVE, which the service's reads
// and writes never wait for; with a lock bound of a few seconds, one long
// export or report would make every attempt give up. Every other statement
// of the file keeps the configured lock bound.
func applyWithoutTx(ctx context.Context, conn *pgxpool.Conn, m MigrationStatus, stmts []noTxStatement, b migrationBounds, backupReference string) error {
	// Session settings, since there is no transaction to scope them to;
	// standard_conforming_strings is what the splitter assumes.
	if _, err := conn.Exec(ctx, `SELECT set_config('statement_timeout', $1, false), set_config('standard_conforming_strings', 'on', false)`,
		pgMillis(b.statementTimeout)); err != nil {
		return err
	}
	// lock_timeout is set before every statement rather than once: the file
	// may change it itself.
	lockTimeout := func(d time.Duration) error {
		_, err := conn.Exec(ctx, `SELECT set_config('lock_timeout', $1, false)`, pgMillis(d))
		return err
	}
	defer func() {
		// The connection goes back to the pool: restore the settings it was
		// opened with (these and any SET of the file itself; RESET ALL keeps
		// the advisory lock and the connection's startup parameters), or
		// close it so no runtime query inherits them.
		if _, err := conn.Exec(context.Background(), `RESET ALL`); err != nil {
			_ = conn.Conn().Close(context.Background())
		}
	}()
	for i, st := range stmts {
		bound := b.lockTimeout
		if st.Concurrently {
			bound = 0
		}
		err := withLockRetry(ctx, b, bound, func() error {
			if st.Index != nil {
				if err := lockTimeout(0); err != nil {
					return err
				}
				if err := dropInvalidIndex(ctx, conn, st.Index); err != nil {
					return err
				}
			}
			if err := lockTimeout(bound); err != nil {
				return err
			}
			_, err := conn.Exec(ctx, st.SQL)
			return err
		})
		if err != nil {
			left := ""
			// A failed concurrent build leaves an invalid index that every
			// write maintains and that may enforce uniqueness: drop it now
			// while the session still works, otherwise the next run does.
			if st.Index != nil && st.Index.Concurrently && (lockTimeout(0) != nil || dropInvalidIndex(ctx, conn, st.Index) != nil) {
				left = fmt.Sprintf("; index %s may be left invalid, and the next migrate run drops and rebuilds it", st.Index.Name)
			}
			return fmt.Errorf("apply %s (no-transaction, statement %d of %d, not recorded%s): %w", m.Name, i+1, len(stmts), left, err)
		}
	}
	for _, st := range stmts {
		if st.Index == nil {
			continue
		}
		name, valid, found, err := indexState(ctx, conn, st.Index)
		switch {
		case err != nil:
			return err
		case !found:
			return fmt.Errorf("migration %s: index %s on %s does not exist after the migration ran; it is not recorded", m.Name, st.Index.Name, st.Index.Table)
		case !valid:
			return fmt.Errorf("migration %s: index %s is invalid (pg_index.indisvalid is false), so the migration is not recorded; run migrate again to drop and rebuild it", m.Name, name)
		}
	}
	return recordMigration(ctx, conn, m, backupReference)
}

// indexState finds the index ix creates on its table: its schema-qualified
// name and whether it is valid.
func indexState(ctx context.Context, q Querier, ix *indexDDL) (name string, valid, found bool, err error) {
	err = q.QueryRow(ctx, `SELECT format('%I.%I', n.nspname, c.relname), i.indisvalid
		FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE i.indrelid = to_regclass($1) AND c.relname = $2`, ix.Table, ix.Name).Scan(&name, &valid)
	if IsNoRows(err) {
		return "", false, false, nil
	}
	return name, valid, err == nil, err
}

// dropInvalidIndex drops an invalid index of the name ix creates: what an
// interrupted CREATE INDEX CONCURRENTLY leaves behind (the migration is not
// recorded yet, and the advisory lock excludes a build still in progress).
// IF NOT EXISTS would keep it, and the migration would be recorded with an
// index that no query uses but every write maintains, and that may still
// enforce uniqueness.
func dropInvalidIndex(ctx context.Context, conn *pgxpool.Conn, ix *indexDDL) error {
	name, valid, found, err := indexState(ctx, conn, ix)
	if err != nil || !found || valid {
		return err
	}
	_, err = conn.Exec(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+name)
	return err
}

func nilIfBlank(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// MigrationsStatus reports applied/pending migrations.
func (db *DB) MigrationsStatus(ctx context.Context) ([]MigrationStatus, error) {
	all, _, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	var exists bool
	if err := db.Pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return all, nil
	}
	rows, err := db.Pool.Query(ctx, `SELECT name, applied_at FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	appliedAt := map[string]time.Time{}
	for rows.Next() {
		var n string
		var t time.Time
		if err := rows.Scan(&n, &t); err != nil {
			return nil, err
		}
		appliedAt[n] = t
	}
	for i := range all {
		if t, ok := appliedAt[all[i].Name]; ok {
			tt := t
			all[i].AppliedAt = &tt
		}
	}
	return all, nil
}

// SchemaCurrent reports whether every embedded migration has been applied. Readiness
// fails when the schema is behind the binary (DEP-009, DEP-012).
func (db *DB) SchemaCurrent(ctx context.Context) (bool, error) {
	st, err := db.MigrationsStatus(ctx)
	if err != nil {
		return false, err
	}
	for _, m := range st {
		if m.AppliedAt == nil {
			return false, nil
		}
	}
	if err := db.SchemaCompatible(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// SchemaCompatible checks the mixed-version window (TEST-061): migrations this
// binary does not know are acceptable only when every one of them is an expand
// migration. A contract migration from a newer release ends support for older
// binaries with a clear error instead of undefined behavior.
func (db *DB) SchemaCompatible(ctx context.Context) error {
	all, _, err := loadMigrations()
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, m := range all {
		known[m.Name] = true
	}
	var hasCompat bool
	if err := db.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='schema_migrations' AND column_name='compat')`).Scan(&hasCompat); err != nil {
		return err
	}
	if !hasCompat {
		return nil
	}
	rows, err := db.Pool.Query(ctx, `SELECT name, compat FROM schema_migrations ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, compat string
		if err := rows.Scan(&name, &compat); err != nil {
			return err
		}
		if !known[name] && compat == "contract" {
			return fmt.Errorf("%w: migration %s from a newer release removed schema this version needs; finish the upgrade to the newer release", ErrSchemaIncompatible, name)
		}
	}
	return rows.Err()
}
