// Package server assembles configuration, storage, keys and services into a
// runnable process shared by the server, worker and CLI binaries.
package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/httpapi"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/maintenance"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Env is an initialized process environment.
type Env struct {
	Cfg     *configuration.Config
	Log     *slog.Logger
	DB      *storage.DB
	Keys    *keys.Keyring
	Deps    *runtime.Deps
	Metrics *observability.Metrics
}

// LoadKeyring builds the key hierarchy from secret references (DEP-006, DEP-008).
func LoadKeyring(cfg *configuration.Config) (*keys.Keyring, error) {
	load := func(refs []configuration.KeyRef) (map[uint32][]byte, error) {
		out := map[uint32][]byte{}
		for _, k := range refs {
			v, err := configuration.ResolveSecret(k.Ref)
			if err != nil {
				return nil, fmt.Errorf("key version %d: %w", k.Version, err)
			}
			b, err := configuration.DecodeKey(v)
			if err != nil {
				return nil, fmt.Errorf("key version %d: %w", k.Version, err)
			}
			out[k.Version] = b
		}
		return out, nil
	}
	roots, err := load(cfg.Keys.RootKeys)
	if err != nil {
		return nil, err
	}
	kr, err := keys.New(roots, cfg.Keys.ActiveVersion)
	if err != nil {
		return nil, err
	}
	if len(cfg.Keys.PepperKeys) > 0 {
		p, err := load(cfg.Keys.PepperKeys)
		if err != nil {
			return nil, err
		}
		if err := kr.SetDedicated(keys.PurposePepper, p); err != nil {
			return nil, err
		}
	}
	if len(cfg.Keys.SigningWrapKeys) > 0 {
		p, err := load(cfg.Keys.SigningWrapKeys)
		if err != nil {
			return nil, err
		}
		if err := kr.SetDedicated(keys.PurposeSigningWrap, p); err != nil {
			return nil, err
		}
	}
	return kr, nil
}

// Init loads configuration, validates it, connects storage and builds deps.
func Init(ctx context.Context, configPath string, migrate bool) (*Env, error) {
	return initEnv(ctx, configPath, migrate, true)
}

// InitOperator loads the environment for operator commands. It never applies
// migrations, whatever storage.migrate_on_start says: schema changes are the
// explicit `migrate` command's, with its plan, backup reference and evidence
// (OPS-013).
func InitOperator(ctx context.Context, configPath string) (*Env, error) {
	return initEnv(ctx, configPath, false, false)
}

func initEnv(ctx context.Context, configPath string, migrate, honorMigrateOnStart bool) (*Env, error) {
	cfg, err := configuration.Load(configPath)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	log := observability.NewLogger(os.Stderr, cfg.Observability.LogLevel, cfg.Observability.LogFormat)
	dsn, err := configuration.ResolveSecret(cfg.Storage.DatabaseURL)
	if err != nil {
		return nil, err
	}
	db, err := storage.Open(ctx, dsn, storage.Options{MaxConns: cfg.Storage.MaxConns, MinConns: cfg.Storage.MinConns, StatementTimeout: cfg.Storage.StatementTimeout})
	if err != nil {
		return nil, err
	}
	var migrated []string
	if migrate || honorMigrateOnStart && cfg.Storage.MigrateOnStart {
		ran, applied, err := MigrateAsOwner(ctx, &cfg, db, storage.MigrateOptions{})
		warnOutOfOrder(log, applied)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
		if len(ran) > 0 {
			log.Info("migrations applied", "migrations", strings.Join(ran, ","))
		}
		migrated = ran
	}
	kr, err := LoadKeyring(&cfg)
	if err != nil {
		db.Close()
		return nil, err
	}
	if cfg.Mode == configuration.ModeDevelopment {
		log.Warn("DEVELOPMENT MODE: not for production use (QA-007)")
	}
	deps := runtime.New(db, &cfg, clock.System{}, kr, log)
	if len(migrated) > 0 {
		// Startup migrations are schema changes with evidence too (OPS-013).
		host, _ := os.Hostname()
		if _, err := deps.Audit.Record(ctx, db.Pool, audit.Event{Type: "operations.migrations.applied", Actor: audit.Ref{Type: "operator", ID: "startup:" + host},
			Category: "operations", Metadata: map[string]any{"migrations": migrated, "trigger": map[bool]string{true: "migrate_flag", false: "migrate_on_start"}[migrate]}}); err != nil {
			log.Error("migration evidence not recorded", "error", err)
		}
	}
	return &Env{Cfg: &cfg, Log: log, DB: db, Keys: kr, Deps: deps, Metrics: observability.NewMetrics()}, nil
}

// MigrateAsOwner applies migrations with storage.migration_database_url when
// it is set (a schema-owner role separate from the runtime role, OPS-013),
// otherwise with the runtime connection, then grants the runtime role its
// data privileges when storage.runtime_role is set. It returns the names of
// the migrations applied and their plan items (storage.DB.MigrateWith).
func MigrateAsOwner(ctx context.Context, cfg *configuration.Config, runtimeDB *storage.DB, opt storage.MigrateOptions) ([]string, []storage.MigrationPlanItem, error) {
	// Bounds the caller left unset come from storage.migration_lock_timeout
	// and storage.migration_statement_timeout, where 0 means no limit
	// (negative in MigrateOptions, where zero selects the default).
	if opt.LockTimeout == 0 {
		opt.LockTimeout = MigrationBound(cfg.Storage.MigrationLockTimeout)
	}
	if opt.StatementTimeout == 0 {
		opt.StatementTimeout = MigrationBound(cfg.Storage.MigrationStatementTimeout)
	}
	db := runtimeDB
	if cfg.Storage.MigrationDatabaseURL != "" {
		dsn, err := configuration.ResolveSecret(cfg.Storage.MigrationDatabaseURL)
		if err != nil {
			return nil, nil, err
		}
		owner, err := storage.Open(ctx, dsn, storage.Options{MaxConns: 2, StatementTimeout: 0})
		if err != nil {
			return nil, nil, fmt.Errorf("migration database: %w", err)
		}
		defer owner.Close()
		db = owner
	}
	ran, applied, err := db.MigrateWith(ctx, opt)
	if err != nil || opt.Plan {
		return ran, applied, err
	}
	if role := cfg.Storage.RuntimeRole; role != "" {
		if err := db.GrantRuntime(ctx, role); err != nil {
			return ran, applied, fmt.Errorf("grant runtime role: %w", err)
		}
	}
	return ran, applied, nil
}

// warnOutOfOrder logs a warning for each applied migration that sorts
// before a migration the database had applied already
// (storage.MigrationPlanItem.OutOfOrder, OPS-008).
func warnOutOfOrder(log *slog.Logger, applied []storage.MigrationPlanItem) {
	for _, m := range applied {
		if m.OutOfOrder {
			log.Warn("migration applied out of order", "migration", m.Name, "newest_applied", m.NewestApplied,
				"hint", "it sorts before a migration the database had applied already: check that it does not depend on the schema before that one; a reviewed file says so with -- proudauth:allow-out-of-order: <reason>")
		}
	}
}

// MigrationBound converts a configured or flag migration bound, where 0
// means no limit, to its storage.MigrateOptions value.
func MigrationBound(d time.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return d
}

// InternalHandler serves metrics and operator status on the private listener. When a
// metrics token is configured it is required (OPS-002 restricted metrics).
func InternalHandler(env *Env, app *httpapi.App) http.Handler {
	mux := http.NewServeMux()
	token := ""
	tokenRequired := env.Cfg.Server.MetricsToken != ""
	if tokenRequired {
		var err error
		if token, err = configuration.ResolveSecret(env.Cfg.Server.MetricsToken); err != nil || token == "" {
			// Fail closed: an unresolvable token never leaves /metrics open.
			env.Log.Error("server.metrics_token could not be resolved; /metrics is disabled", "error", err)
		}
	}
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !env.Cfg.Observability.MetricsEnabled {
			http.NotFound(w, r)
			return
		}
		if tokenRequired {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		refreshGauges(r.Context(), env)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		env.Metrics.Registry.WriteText(w)
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if env.Cfg.Mode == "development" {
		// Development mail sink viewer (MSG-011). It exists only in development
		// mode and only on the private operator listener: message bodies carry
		// one-time codes and links, so they are never served by the public API.
		mux.HandleFunc("GET /dev/mailbox", func(w http.ResponseWriter, r *http.Request) {
			rlm, err := app.Realms.ByName(r.Context(), r.URL.Query().Get("realm"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			list, err := app.Notify.DevMailbox(r.Context(), rlm.ID, r.URL.Query().Get("recipient"))
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = jsonEncode(w, map[string]any{"items": list, "warning": "development sink; not available in production"})
		})
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		// Machine-readable degraded-capability status for operators (OPS-015).
		// It is served only on the private listener and, when a metrics token
		// is configured, only to holders of it.
		if tokenRequired {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = jsonEncode(w, operatorStatus(r.Context(), env, app))
	})
	return mux
}

// operatorStatus reports each capability as ok, degraded or unavailable,
// plus the maintenance mode and an overall status.
func operatorStatus(ctx context.Context, env *Env, app *httpapi.App) map[string]any {
	caps := map[string]string{}
	status := map[string]any{"time": time.Now().UTC(), "capabilities": caps}
	// Where the key hierarchy comes from (DEP-016): software keys, or keys
	// unwrapped by an external KMS at startup (protected at rest, in process
	// memory while running).
	status["key_provider"] = "software"
	if env.Cfg.Keys.KMS.Enabled() {
		status["key_provider"] = "kms_unwrapped"
	}
	if r := env.Cfg.Privacy.Residency; r.Region != "" || len(r.AllowedDestinations) > 0 {
		status["residency"] = map[string]any{"region": r.Region, "destinations_restricted": len(r.AllowedDestinations) > 0}
	}
	if err := env.DB.Ping(ctx); err != nil {
		caps["database"] = "unavailable"
		status["status"] = "unavailable"
		return status
	}
	caps["database"] = "ok"
	caps["schema"] = "ok"
	if ok, _ := env.DB.SchemaCurrent(ctx); !ok {
		caps["schema"] = "degraded"
		status["schema"] = "behind"
	}
	caps["signing"] = "ok"
	if realms, err := app.Realms.List(ctx); err == nil {
		for _, rl := range realms {
			if _, err := app.KeyMgr.Active(ctx, rl.ID); err != nil {
				caps["signing"] = "unavailable"
			}
		}
	}
	age := func(q string) int {
		var oldest *time.Time
		_ = env.DB.Pool.QueryRow(ctx, q).Scan(&oldest)
		if oldest == nil {
			return 0
		}
		return int(time.Since(*oldest).Seconds())
	}
	backlogs := map[string]int{
		"outbox":         age(`SELECT min(occurred_at) FROM outbox_events WHERE state='pending'`),
		"email_delivery": age(`SELECT min(next_attempt_at) FROM notification_jobs WHERE state IN ('queued','attempted') AND next_attempt_at <= now()`),
		"webhooks":       age(`SELECT min(next_attempt_at) FROM webhook_deliveries WHERE state IN ('pending','retrying') AND next_attempt_at <= now()`),
		"jobs":           age(`SELECT min(created_at) FROM jobs WHERE state='queued'`),
		"audit_sealing":  age(`SELECT min(recorded_at) FROM audit_events WHERE batch_id IS NULL`),
	}
	status["backlog_oldest_seconds"] = backlogs
	for k, v := range backlogs {
		caps[k] = "ok"
		if v > 300 {
			caps[k] = "degraded"
		}
	}
	var dbNow time.Time
	if err := env.DB.Pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow); err == nil {
		status["clock_skew_ms"] = time.Since(dbNow).Milliseconds()
	}
	m, _ := maintenance.Get(ctx, env.DB.Pool)
	status["maintenance"] = m
	overall := "ok"
	for _, v := range caps {
		if v != "ok" {
			overall = "degraded"
		}
	}
	if m.Mode != maintenance.Off {
		overall = "maintenance"
	}
	status["status"] = overall
	return status
}

// refreshGauges samples point-in-time gauges at scrape time: database
// reachability, the age of the oldest pending outbox event, and clock skew
// against the database (OPS-002, AUD-014).
func refreshGauges(ctx context.Context, env *Env) {
	var dbNow time.Time
	if err := env.DB.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		env.Metrics.DBUp.Set(0)
		return
	}
	env.Metrics.DBUp.Set(1)
	env.Metrics.ClockSkew.Set(time.Since(dbNow).Milliseconds())
	var oldest *time.Time
	_ = env.DB.Pool.QueryRow(ctx, `SELECT min(occurred_at) FROM outbox_events WHERE state='pending'`).Scan(&oldest)
	if oldest != nil {
		env.Metrics.QueueAge.Set(int64(time.Since(*oldest).Seconds()))
	} else {
		env.Metrics.QueueAge.Set(0)
	}
	// Delivery and job backlogs (OPS-002): how long the oldest due item has
	// waited, so a stalled worker or failing channel pages before users notice.
	for _, b := range []struct {
		g   *observability.Gauge
		sql string
	}{
		{env.Metrics.NotificationAge, `SELECT min(next_attempt_at) FROM notification_jobs WHERE state IN ('queued','attempted') AND next_attempt_at <= now()`},
		{env.Metrics.WebhookAge, `SELECT min(next_attempt_at) FROM webhook_deliveries WHERE state IN ('pending','retrying') AND next_attempt_at <= now()`},
		{env.Metrics.JobAge, `SELECT min(run_after) FROM jobs WHERE state='queued' AND run_after <= now()`},
	} {
		var since *time.Time
		_ = env.DB.Pool.QueryRow(ctx, b.sql).Scan(&since)
		if since != nil {
			b.g.Set(int64(time.Since(*since).Seconds()))
		} else {
			b.g.Set(0)
		}
	}
	// Active worker leases (OPS-002): a stuck or crashed worker shows up as
	// leases that never clear while queues age.
	var leases int64
	_ = env.DB.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM jobs WHERE lease_expires_at > now()) +
		(SELECT count(*) FROM notification_jobs WHERE lease_expires_at > now()) +
		(SELECT count(*) FROM webhook_deliveries WHERE lease_expires_at > now()) +
		(SELECT count(*) FROM outbox_events WHERE lease_expires_at > now())`).Scan(&leases)
	env.Metrics.ActiveLeases.Set(leases)
	// Audit backlog (AUD-014): events waiting to be sealed and the oldest age.
	var unsealed int64
	var oldestUnsealed *time.Time
	_ = env.DB.Pool.QueryRow(ctx, `SELECT count(*), min(recorded_at) FROM audit_events WHERE batch_id IS NULL`).Scan(&unsealed, &oldestUnsealed)
	env.Metrics.AuditUnsealed.Set(unsealed)
	if oldestUnsealed != nil {
		env.Metrics.AuditUnsealedAge.Set(int64(time.Since(*oldestUnsealed).Seconds()))
	} else {
		env.Metrics.AuditUnsealedAge.Set(0)
	}
}
