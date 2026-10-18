package storage_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
	"github.com/proudauth/proudauth/migrations"
)

// migrationSource returns the embedded migrations as the test's migration
// source, so a test can add files to it; the test database has all of them
// applied already.
func migrationSource(t *testing.T) fstest.MapFS {
	t.Helper()
	src := fstest.MapFS{}
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := fs.ReadFile(migrations.Files, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		src[e.Name()] = &fstest.MapFile{Data: b}
	}
	t.Cleanup(storage.SetMigrationFS(src))
	return src
}

// waitUntil polls a boolean query until it is true.
func waitUntil(t *testing.T, db *storage.DB, what, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var ok bool
		if err := db.Pool.QueryRow(context.Background(), query, args...).Scan(&ok); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func recorded(t *testing.T, db *storage.DB, name string) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM schema_migrations WHERE name = $1`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestMigrationLockTimeout covers OPS-008 and DEP-012: a migration whose DDL
// queues behind a lock held by another session waits at most lock_timeout,
// so the service's queries that queue behind the migration's lock request
// are released instead of blocking until the migration commits. It is
// retried a bounded number of times, then fails with SQLSTATE 55P03 and
// records nothing; once the lock is released it succeeds on a retry.
func TestMigrationLockTimeout(t *testing.T) {
	db := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	seed(t, db, `CREATE TABLE lock_probe (id int)`)
	const name = "9990_lock_probe.sql"
	src := migrationSource(t)
	src[name] = &fstest.MapFile{Data: []byte("ALTER TABLE lock_probe ADD COLUMN v text;\n")}

	// A long-running query of another session holds ACCESS SHARE until its
	// transaction ends; ALTER TABLE needs ACCESS EXCLUSIVE.
	holder, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if _, err := holder.Exec(ctx, `SELECT count(*) FROM lock_probe`); err != nil {
		t.Fatal(err)
	}

	opt := storage.WithLockRetryBackoff(storage.MigrateOptions{LockTimeout: 300 * time.Millisecond, LockRetries: 2}, 50*time.Millisecond)
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := db.MigrateWith(ctx, opt)
		done <- err
	}()
	waitUntil(t, db, "the migration waits for its lock", `SELECT EXISTS (SELECT 1 FROM pg_locks
		WHERE database = (SELECT oid FROM pg_database WHERE datname = current_database())
		AND relation = 'lock_probe'::regclass AND mode = 'AccessExclusiveLock' AND NOT granted)`)
	// A query of the service arriving now queues behind the migration's
	// request; lock_timeout releases it while the holder still runs.
	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	_, rerr := db.Pool.Exec(rctx, `SELECT count(*) FROM lock_probe`)
	rcancel()
	if rerr != nil {
		t.Fatalf("a query queued behind the migration stayed blocked: %v", rerr)
	}
	err = <-done
	elapsed := time.Since(start)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("want a lock_timeout failure (55P03), got %v", err)
	}
	if !strings.Contains(err.Error(), "3 attempts") || !strings.Contains(err.Error(), name) {
		t.Fatalf("error does not name the migration and its attempts: %v", err)
	}
	// Three waits of 300ms and pauses of 50ms and 100ms.
	if elapsed < 900*time.Millisecond || elapsed > 20*time.Second {
		t.Fatalf("migration gave up after %s", elapsed)
	}
	if n := recorded(t, db, name); n != 0 {
		t.Fatalf("a failed migration was recorded %d times", n)
	}

	// Released during the retries: a later attempt applies it.
	opt = storage.WithLockRetryBackoff(storage.MigrateOptions{LockTimeout: 300 * time.Millisecond, LockRetries: 5}, 100*time.Millisecond)
	released := make(chan error, 1)
	go func() {
		time.Sleep(500 * time.Millisecond)
		released <- holder.Rollback(ctx)
	}()
	ran, _, err := db.MigrateWith(ctx, opt)
	if rerr := <-released; rerr != nil {
		t.Fatal(rerr)
	}
	if err != nil || len(ran) != 1 || ran[0] != name {
		t.Fatalf("migration after the lock was released: %v %v", ran, err)
	}
	var hasColumn bool
	if err := db.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'lock_probe' AND column_name = 'v')`).Scan(&hasColumn); err != nil || !hasColumn {
		t.Fatalf("column not added: %v %v", hasColumn, err)
	}
	if n := recorded(t, db, name); n != 1 {
		t.Fatalf("migration recorded %d times", n)
	}
}

// TestMigrationStatementTimeout covers OPS-008: migration statements run
// with the migration statement_timeout instead of the runtime connection's
// (which would cut a long index build short), and that bound holds too.
func TestMigrationStatementTimeout(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	runtime, err := storage.Open(ctx, db.Pool.Config().ConnString(), storage.Options{MaxConns: 2, StatementTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	src := migrationSource(t)
	src["9990_slow.sql"] = &fstest.MapFile{Data: []byte("SELECT pg_sleep(0.6);\n")}
	if ran, err := runtime.Migrate(ctx); err != nil || len(ran) != 1 {
		t.Fatalf("a migration statement was held to the runtime statement_timeout: %v %v", ran, err)
	}
	src["9991_slower.sql"] = &fstest.MapFile{Data: []byte("SELECT pg_sleep(2);\n")}
	_, _, err = runtime.MigrateWith(ctx, storage.MigrateOptions{StatementTimeout: 200 * time.Millisecond})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		t.Fatalf("want statement_timeout (57014), got %v", err)
	}
	if n := recorded(t, db, "9991_slower.sql"); n != 0 {
		t.Fatal("timed-out migration recorded")
	}
}

func indexValidity(t *testing.T, db *storage.DB, name string) (valid, exists bool) {
	t.Helper()
	err := db.Pool.QueryRow(context.Background(), `SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relname = $1`, name).Scan(&valid)
	if storage.IsNoRows(err) {
		return false, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return valid, true
}

// TestNoTransactionMigrationRebuildsInvalidIndex covers OPS-008 and DEP-012:
// a "-- proudauth:no-transaction" migration runs CREATE INDEX CONCURRENTLY
// outside a transaction. When its build is killed part-way, the index is left
// invalid and the migration is not recorded; the next run drops the invalid
// index, builds it again, checks pg_index.indisvalid and records the
// migration once.
func TestNoTransactionMigrationRebuildsInvalidIndex(t *testing.T) {
	db := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	seed(t, db, `CREATE TABLE cic_probe (id bigint PRIMARY KEY, v text NOT NULL)`,
		`INSERT INTO cic_probe SELECT g, md5(g::text) FROM generate_series(1, 20000) g`)
	const name = "9990_cic_probe.sql"
	src := migrationSource(t)
	src[name] = &fstest.MapFile{Data: []byte("-- proudauth:no-transaction\n" +
		"-- Builds the index without blocking writes; IF NOT EXISTS makes it repeatable.\n" +
		"SET maintenance_work_mem = '96MB';\n" +
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS cic_probe_v ON cic_probe (v);\n")}

	if _, plan, err := db.MigrateWith(ctx, storage.MigrateOptions{Plan: true}); err != nil || len(plan) != 1 || !plan[0].NoTransaction {
		t.Fatalf("plan: %+v %v", plan, err)
	}

	// An open write transaction makes the build wait after it has created
	// the index entry (invalid until the build completes), before it scans
	// the table: the moment to kill it.
	writer, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.Background()) }()
	if _, err := writer.Exec(ctx, `INSERT INTO cic_probe VALUES (0, 'writer')`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		// The build waits for the writer without lock_timeout
		// (TestNoTransactionMigrationLockBounds) until it is killed.
		_, err := db.Migrate(ctx)
		done <- err
	}()
	waitUntil(t, db, "the index build waits for the writer", `SELECT EXISTS (SELECT 1 FROM pg_stat_progress_create_index
		WHERE datname = current_database() AND phase = 'waiting for writers before build')`)
	var killed bool
	if err := db.Pool.QueryRow(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_progress_create_index
		WHERE datname = current_database()`).Scan(&killed); err != nil || !killed {
		t.Fatalf("terminate the index build: %v %v", killed, err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "cic_probe_v") {
		t.Fatalf("killed migration: want an error naming the index, got %v", err)
	}
	if err := writer.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if valid, exists := indexValidity(t, db, "cic_probe_v"); !exists || valid {
		t.Fatalf("after the kill: index exists %v, valid %v; want an invalid index", exists, valid)
	}
	if n := recorded(t, db, name); n != 0 {
		t.Fatalf("killed migration recorded %d times", n)
	}

	// The repeated run must not keep the invalid index (IF NOT EXISTS alone
	// would skip it). It runs on a pool of one connection with a runtime
	// statement_timeout, to check that connection is handed back with the
	// settings it was opened with.
	one, err := storage.Open(ctx, db.Pool.Config().ConnString(), storage.Options{MaxConns: 1, StatementTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	ran, err := one.Migrate(ctx)
	if err != nil || len(ran) != 1 || ran[0] != name {
		t.Fatalf("repeated run: %v %v", ran, err)
	}
	var lockTimeout, statementTimeout, workMem string
	if err := one.Pool.QueryRow(ctx, `SELECT current_setting('lock_timeout'), current_setting('statement_timeout'), current_setting('maintenance_work_mem')`).
		Scan(&lockTimeout, &statementTimeout, &workMem); err != nil || lockTimeout != "0" || statementTimeout != "10s" || workMem == "96MB" {
		t.Fatalf("migration settings leaked to the pool: lock_timeout %q, statement_timeout %q, maintenance_work_mem %q, %v",
			lockTimeout, statementTimeout, workMem, err)
	}
	if valid, exists := indexValidity(t, db, "cic_probe_v"); !exists || !valid {
		t.Fatalf("after the repeated run: index exists %v, valid %v", exists, valid)
	}
	if n := recorded(t, db, name); n != 1 {
		t.Fatalf("migration recorded %d times", n)
	}
	if ran, err := db.Migrate(ctx); err != nil || len(ran) != 0 {
		t.Fatalf("third run must be a no-op: %v %v", ran, err)
	}
}

// TestNoTransactionMigrationLockBounds covers OPS-008 and DEP-012: in a
// no-transaction migration, CREATE INDEX CONCURRENTLY waits for an older
// transaction far longer than the lock timeout, without holding up the
// service's writes, and completes once that transaction ends; an ordinary
// statement of the same file still gives up after the lock timeout, is
// retried a bounded number of times, and leaves the migration unrecorded
// until a later run completes it.
func TestNoTransactionMigrationLockBounds(t *testing.T) {
	db := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	seed(t, db, `CREATE TABLE cic_wait (id bigint PRIMARY KEY, v text NOT NULL)`,
		`INSERT INTO cic_wait SELECT g, md5(g::text) FROM generate_series(1, 5000) g`,
		`CREATE TABLE plain_wait (id int)`)
	const name = "9990_lock_bounds.sql"
	src := migrationSource(t)
	src[name] = &fstest.MapFile{Data: []byte("-- proudauth:no-transaction\n" +
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS cic_wait_v ON cic_wait (v);\n" +
		"ALTER TABLE plain_wait ADD COLUMN IF NOT EXISTS v text;\n")}

	// An open write transaction on cic_wait holds the build back; an open
	// transaction that read plain_wait holds the ALTER TABLE back.
	writer, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.Background()) }()
	if _, err := writer.Exec(ctx, `INSERT INTO cic_wait VALUES (0, 'writer')`); err != nil {
		t.Fatal(err)
	}
	reader, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback(context.Background()) }()
	if _, err := reader.Exec(ctx, `SELECT count(*) FROM plain_wait`); err != nil {
		t.Fatal(err)
	}

	const lockTimeout = 200 * time.Millisecond
	opt := storage.WithLockRetryBackoff(storage.MigrateOptions{LockTimeout: lockTimeout, LockRetries: 1}, 50*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, _, err := db.MigrateWith(ctx, opt)
		done <- err
	}()
	const building = `SELECT index_relid FROM pg_stat_progress_create_index
		WHERE datname = current_database() AND phase = 'waiting for writers before build'`
	waitUntil(t, db, "the index build waits for the writer", `SELECT EXISTS (`+building+`)`)
	var index uint32
	if err := db.Pool.QueryRow(ctx, building).Scan(&index); err != nil {
		t.Fatal(err)
	}
	// Ten lock timeouts later the same build is still waiting: it neither
	// gave up nor was dropped and started again.
	time.Sleep(10 * lockTimeout)
	select {
	case err := <-done:
		t.Fatalf("the concurrent build gave up waiting for an older transaction: %v", err)
	default:
	}
	var still uint32
	if err := db.Pool.QueryRow(ctx, building).Scan(&still); err != nil || still != index {
		t.Fatalf("the build waiting for the writer was interrupted (index %d, now %d): %v", index, still, err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	_, werr := db.Pool.Exec(wctx, `INSERT INTO cic_wait VALUES (-1, 'during the build')`)
	wcancel()
	if werr != nil {
		t.Fatalf("a write waited for the concurrent build: %v", werr)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	err = <-done
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("the ALTER TABLE must give up after the lock timeout (55P03), got %v", err)
	}
	if !strings.Contains(err.Error(), "statement 2 of 2") || !strings.Contains(err.Error(), "2 attempts") {
		t.Fatalf("error does not name the statement and its attempts: %v", err)
	}
	if valid, exists := indexValidity(t, db, "cic_wait_v"); !exists || !valid {
		t.Fatalf("the concurrent build did not complete: exists %v, valid %v", exists, valid)
	}
	if n := recorded(t, db, name); n != 0 {
		t.Fatalf("a partly applied migration was recorded %d times", n)
	}

	if err := reader.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	ran, _, err := db.MigrateWith(ctx, opt)
	if err != nil || len(ran) != 1 || ran[0] != name {
		t.Fatalf("repeated run: %v %v", ran, err)
	}
	var hasColumn bool
	if err := db.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'plain_wait' AND column_name = 'v')`).Scan(&hasColumn); err != nil || !hasColumn {
		t.Fatalf("column not added: %v %v", hasColumn, err)
	}
	if n := recorded(t, db, name); n != 1 {
		t.Fatalf("migration recorded %d times", n)
	}
}

// TestNoTransactionMigrationFailures covers OPS-008: a no-transaction file
// the runner cannot run safely is refused before any migration of the run
// is applied, CREATE INDEX CONCURRENTLY in an ordinary (transactional)
// migration fails with a pointer to the directive, and a concurrent unique
// index build that fails on duplicate rows does not leave its invalid index
// enforcing uniqueness on the service's writes.
func TestNoTransactionMigrationFailures(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	seed(t, db, `CREATE TABLE refusal_probe (id int)`, `INSERT INTO refusal_probe VALUES (1), (1)`)
	src := migrationSource(t)
	src["9990_first.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE refusal_first (id int);\n")}
	src["9991_not_repeatable.sql"] = &fstest.MapFile{Data: []byte("-- proudauth:no-transaction\nCREATE INDEX CONCURRENTLY refusal_ix ON refusal_probe (id);\n")}
	if _, _, err := db.MigrateWith(ctx, storage.MigrateOptions{Plan: true}); err == nil || !strings.Contains(err.Error(), "IF NOT EXISTS") {
		t.Fatalf("plan accepted a non-repeatable no-transaction file: %v", err)
	}
	if _, err := db.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "9991_not_repeatable.sql") {
		t.Fatalf("non-repeatable no-transaction file accepted: %v", err)
	}
	if n := recorded(t, db, "9990_first.sql"); n != 0 {
		t.Fatal("a migration ran before the refused file was reported")
	}
	delete(src, "9991_not_repeatable.sql")
	src["9991_in_transaction.sql"] = &fstest.MapFile{Data: []byte("CREATE INDEX CONCURRENTLY IF NOT EXISTS refusal_ix ON refusal_probe (id);\n")}
	if _, err := db.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "-- proudauth:no-transaction") {
		t.Fatalf("CREATE INDEX CONCURRENTLY in a transaction: %v", err)
	}
	if n := recorded(t, db, "9991_in_transaction.sql"); n != 0 {
		t.Fatal("failed migration recorded")
	}
	delete(src, "9991_in_transaction.sql")
	src["9991_duplicates.sql"] = &fstest.MapFile{Data: []byte("-- proudauth:no-transaction\nCREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS refusal_ix ON refusal_probe (id);\n")}
	if _, err := db.Migrate(ctx); !storage.IsUniqueViolation(err) {
		t.Fatalf("unique index over duplicate rows: %v", err)
	}
	if _, exists := indexValidity(t, db, "refusal_ix"); exists {
		t.Fatal("the failed build's invalid index was left in place")
	}
	if n := recorded(t, db, "9991_duplicates.sql"); n != 0 {
		t.Fatal("failed migration recorded")
	}
}
