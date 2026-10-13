package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"os/user"
	"time"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/httpapi"
	"github.com/proudbase/proudauth/internal/maintenance"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/server"
	"github.com/proudbase/proudauth/internal/storage"
)

func init() {
	register("generate-root-key", "print a new random 256-bit root key (store it in a secret file)", func(args []string) error {
		fmt.Println(hex.EncodeToString(secret.Random(32)))
		return nil
	})
	register("migrate", "apply database migrations (operator)", func(args []string) error {
		fs := flag.NewFlagSet("migrate", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		status := fs.Bool("status", false, "only show status")
		plan := fs.Bool("plan", false, "show pending migrations, their compatibility class and precondition results without applying (OPS-008)")
		backup := fs.String("backup-reference", "", "identifier of the verified backup taken before this run; required for contract (destructive) migrations")
		_ = fs.Parse(args)
		ctx := context.Background()
		env, err := server.InitOperator(ctx, *cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		if *status {
			st, err := env.DB.MigrationsStatus(ctx)
			if err != nil {
				return err
			}
			for _, m := range st {
				state := "pending"
				if m.AppliedAt != nil {
					state = "applied " + m.AppliedAt.Format(time.RFC3339)
				}
				fmt.Printf("%-48s %s\n", m.Name, state)
			}
			return nil
		}
		var ran []string
		var pending []storage.MigrationPlanItem
		if *plan {
			ran, pending, err = env.DB.MigrateWith(ctx, storage.MigrateOptions{BackupReference: *backup, Plan: true})
		} else {
			// Applied as the schema owner when storage.migration_database_url is
			// set, then the runtime role gets data privileges only (OPS-013).
			ran, err = server.MigrateAsOwner(ctx, env.Cfg, env.DB, storage.MigrateOptions{BackupReference: *backup})
		}
		if *plan {
			if err != nil {
				return err
			}
			if len(pending) == 0 {
				fmt.Println("schema is current")
			}
			for _, m := range pending {
				fmt.Printf("%-48s %s\n", m.Name, m.Compat)
				for _, p := range m.Preconditions {
					state := "holds"
					if !p.Held {
						state = "FAILS " + p.Err
					}
					fmt.Printf("    precondition %s: %s\n", state, p.SQL)
				}
			}
			return nil
		}
		for _, m := range ran {
			fmt.Println("applied", m)
		}
		if err == nil && len(ran) == 0 {
			fmt.Println("schema is current")
		}
		if err == nil && len(ran) > 0 {
			// Schema changes are operator actions with evidence (OPS-013).
			if aerr := recordOperatorEvent(ctx, env, "operations.migrations.applied", map[string]any{"migrations": ran, "backup_reference": *backup}); aerr != nil {
				return fmt.Errorf("migrations applied but their audit record failed: %w", aerr)
			}
		}
		return err
	})
	register("realm-create", "create a realm with built-in configuration (operator)", func(args []string) error {
		fs := flag.NewFlagSet("realm-create", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		name := fs.String("name", "", "realm name (path segment; default identity.default_realm)")
		display := fs.String("display-name", "Main", "display name")
		loginUI := fs.String("login-ui-url", "", "URL of the application-provided login interface")
		_ = fs.Parse(args)
		app, env, err := localApp(*cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		if *name == "" {
			*name = env.Cfg.Identity.DefaultRealm
		}
		p := realm.DefaultPolicy()
		p.Interaction.LoginUIURL = *loginUI
		r, err := app.Provision.CreateRealm(context.Background(), *name, *display, p, operatorRef())
		if err != nil {
			return err
		}
		fmt.Printf("realm %s created\nissuer: %s\n", r.Name, r.Issuer)
		return nil
	})
	register("bootstrap", "create the initial administrator with a one-time setup token (operator)", func(args []string) error {
		fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		rlm := fs.String("realm", "", "realm name (default identity.default_realm)")
		email := fs.String("email", "", "administrator email")
		username := fs.String("username", "", "administrator username")
		ttl := fs.Duration("ttl", time.Hour, "setup token lifetime (max 24h)")
		breakGlass := fs.Bool("break-glass", false, "create an additional administrator after initialization (audited emergency action)")
		_ = fs.Parse(args)
		if *email == "" || *username == "" {
			return errors.New("--email and --username are required")
		}
		app, env, err := localApp(*cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		if *rlm == "" {
			*rlm = env.Cfg.Identity.DefaultRealm
		}
		res, err := app.Provision.BootstrapAdmin(context.Background(), *rlm, *email, *username, *ttl, *breakGlass, operatorName())
		if err != nil {
			return err
		}
		fmt.Printf("administrator %s created (user %s)\n", *username, res.UserID)
		fmt.Printf("one-time setup token (expires %s):\n\n  %s\n\n", res.ExpiresAt.Format(time.RFC3339), res.SetupToken)
		fmt.Println("Complete setup with:  identity-cli setup-account --url <public origin> --realm", *rlm)
		fmt.Println("The first sign-in requires enrolling an authenticator (MFA) and verifying the email address.")
		return nil
	})
	register("doctor", "validate configuration, database, schema and key access (operator)", func(args []string) error {
		fs := flag.NewFlagSet("doctor", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		_ = fs.Parse(args)
		ctx := context.Background()
		c, err := configuration.Load(*cfg)
		if err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return err
		}
		fmt.Println("configuration: ok")
		app, env, err := localApp(*cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		fmt.Println("database: ok")
		if ok, _ := env.DB.SchemaCurrent(ctx); !ok {
			return errors.New("schema is behind this binary: run migrate")
		}
		fmt.Println("schema: current")
		realms, err := app.Realms.List(ctx)
		if err != nil {
			return err
		}
		for _, r := range realms {
			if _, err := app.KeyMgr.Active(ctx, r.ID); err != nil {
				return fmt.Errorf("realm %s: signing key unusable (wrong root key?): %w", r.Name, err)
			}
			fmt.Printf("realm %s: issuer %s, signing key ok\n", r.Name, r.Issuer)
		}
		fmt.Printf("key hierarchy fingerprint: %s\n", env.Keys.Fingerprint())
		// The service's own database role should not be able to change the
		// schema (OPS-013).
		if role, err := env.DB.CurrentRole(ctx); err == nil {
			switch {
			case role.Superuser:
				fmt.Printf("WARNING database role %s is a superuser: run the service as a role with data privileges only (storage.runtime_role, storage.migration_database_url)\n", role.Role)
			case role.OwnsTables || role.CreateRole || role.MemberOfOwner:
				fmt.Printf("WARNING database role %s owns the schema, inherits the owner's privileges or can create roles: use a separate migration role (storage.migration_database_url) and grant this one data privileges only (storage.runtime_role)\n", role.Role)
			case role.CreateInSchema:
				fmt.Printf("WARNING database role %s can create objects in schema public: revoke CREATE (identity-cli migrate with storage.runtime_role does)\n", role.Role)
			default:
				fmt.Printf("database role %s: data privileges only\n", role.Role)
			}
		}
		// Accounts still on imported legacy verifiers (CRED-004): salted
		// SHA-256, bcrypt and PBKDF2 (credential.IsLegacyVerifier). Plan
		// security.password.legacy_hashes_until once this reaches zero.
		var legacy int
		if err := env.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE type='password' AND state='active'
			AND (verifier LIKE '$legacy-sha256$%' OR verifier LIKE '$2a$%' OR verifier LIKE '$2b$%' OR verifier LIKE '$2y$%' OR verifier LIKE '$pbkdf2-%')`).Scan(&legacy); err == nil {
			fmt.Printf("accounts on legacy password hashes: %d (until %s)\n", legacy, map[bool]string{true: "no deadline", false: env.Cfg.Security.Password.LegacyHashesUntil}[env.Cfg.Security.Password.LegacyHashesUntil == ""])
		}
		// Historical rows that predate the database boundary constraints
		// (DB-001); they must be repaired before the constraints are validated.
		var orphans int
		_ = env.DB.Pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM webhook_subscriptions w WHERE w.organization_id IS NOT NULL
				AND NOT EXISTS (SELECT 1 FROM organizations o WHERE o.realm_id=w.realm_id AND o.id=w.organization_id)) +
			(SELECT count(*) FROM jobs j WHERE j.organization_id IS NOT NULL AND j.realm_id IS NOT NULL
				AND NOT EXISTS (SELECT 1 FROM organizations o WHERE o.realm_id=j.realm_id AND o.id=j.organization_id)) +
			(SELECT count(*) FROM webhook_deliveries d WHERE NOT EXISTS (SELECT 1 FROM realms r WHERE r.id=d.realm_id))`).Scan(&orphans)
		if orphans > 0 {
			fmt.Printf("WARNING boundary integrity: %d rows reference another realm or a missing organization (DB-001); repair them before validating constraints\n", orphans)
		} else {
			fmt.Println("boundary integrity: ok")
		}
		return nil
	})
	register("maintenance", "show or set maintenance mode: off, restricted or unavailable (operator)", func(args []string) error {
		fs := flag.NewFlagSet("maintenance", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		mode := fs.String("mode", "", "off, restricted (sign-in and tokens continue; changes refused) or unavailable (verification and revocation only)")
		msg := fs.String("message", "", "plain-text public message shown with refusals (at most 200 characters)")
		retry := fs.Int("retry-after", 300, "Retry-After seconds advertised to clients")
		_ = fs.Parse(args)
		ctx := context.Background()
		env, err := server.InitOperator(ctx, *cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		if *mode != "" {
			// The change and its audit record commit together.
			st := maintenance.State{Mode: *mode, Message: *msg, RetryAfterSeconds: *retry}
			if err := env.DB.Tx(ctx, func(tx pgx.Tx) error {
				if err := maintenance.Set(ctx, tx, st, "local:"+operatorName(), time.Now()); err != nil {
					return err
				}
				ev := auditEvent("operations.maintenance.changed")
				ev.Metadata = map[string]any{"mode": *mode, "retry_after_seconds": *retry, "public_message": *msg}
				_, err := env.Deps.Audit.Record(ctx, tx, ev)
				return err
			}); err != nil {
				return err
			}
		}
		st, err := maintenance.Get(ctx, env.DB.Pool)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	})
	register("debug-window", "open a time-limited, optionally component-scoped debug logging window, or close it (operator)", func(args []string) error {
		fs := flag.NewFlagSet("debug-window", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		dur := fs.Duration("for", 15*time.Minute, "window length (at most 1h in production)")
		component := fs.String("component", "", "limit debug records to one component (http, worker, ...); empty for all")
		closeWindow := fs.Bool("close", false, "close the open window")
		reason := fs.String("reason", "", "why debug logging is needed (recorded in the audit log)")
		_ = fs.Parse(args)
		ctx := context.Background()
		env, err := server.InitOperator(ctx, *cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		d := *dur
		if *closeWindow {
			d = 0
		} else if *reason == "" {
			return errors.New("-reason is required to open a debug window")
		}
		typ := "operations.debug_window.opened"
		if d == 0 {
			typ = "operations.debug_window.closed"
		}
		if err := env.DB.Tx(ctx, func(tx pgx.Tx) error {
			if err := maintenance.SetDebug(ctx, tx, d, *component, env.Cfg.Mode == configuration.ModeProduction, time.Now()); err != nil {
				return err
			}
			ev := auditEvent(typ)
			ev.Metadata = map[string]any{"duration_seconds": int(d.Seconds()), "component": *component, "reason_text": *reason}
			_, err := env.Deps.Audit.Record(ctx, tx, ev)
			return err
		}); err != nil {
			return err
		}
		st, err := maintenance.Get(ctx, env.DB.Pool)
		if err != nil {
			return err
		}
		fmt.Printf("debug window: until %v, component %q (secrets stay redacted)\n", st.DebugUntil, st.DebugComponent)
		return nil
	})
	register("config-diff", "validate a new configuration file and show what changes against the current one (operator)", func(args []string) error {
		fs := flag.NewFlagSet("config-diff", flag.ExitOnError)
		from := fs.String("from", os.Getenv("PROUDAUTH_CONFIG"), "current config file")
		to := fs.String("to", "", "proposed config file")
		asJSON := fs.Bool("json", false, "print the changes as JSON")
		_ = fs.Parse(args)
		if *to == "" {
			return errors.New("-to is required")
		}
		cur, err := configuration.Load(*from)
		if err != nil {
			return fmt.Errorf("current configuration: %w", err)
		}
		next, err := configuration.Load(*to)
		if err != nil {
			return fmt.Errorf("proposed configuration: %w", err)
		}
		// The proposed file is validated before anything is compared: an invalid
		// file is never rolled out, and nothing reloads it on its own.
		if err := next.Validate(); err != nil {
			return fmt.Errorf("proposed configuration is invalid: %w", err)
		}
		changes, err := configuration.Diff(cur, next)
		if err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"valid": true, "changes": changes})
		}
		boundary := 0
		for _, c := range changes {
			mark := " "
			if c.SecurityBoundary {
				mark = "!"
				boundary++
			}
			fmt.Printf("%s %s: %s -> %s (%s)\n", mark, c.Key, c.Old, c.New, c.Effect)
		}
		fmt.Printf("%d changes, %d move a security boundary (marked !) and need review; all take effect on restart\n", len(changes), boundary)
		return nil
	})
	register("verify-audit-archive", "verify an audit archive directory independently of the database (operator)", func(args []string) error {
		fs := flag.NewFlagSet("verify-audit-archive", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file (for the audit signing keys)")
		dir := fs.String("dir", "", "archive directory (default: privacy.audit_archive_dir)")
		_ = fs.Parse(args)
		c, err := configuration.Load(*cfg)
		if err != nil {
			return err
		}
		if *dir == "" {
			*dir = c.Privacy.AuditArchiveDir
		}
		if *dir == "" {
			return errors.New("no archive directory: pass -dir or set privacy.audit_archive_dir")
		}
		kr, err := server.LoadKeyring(&c)
		if err != nil {
			return err
		}
		rep, err := audit.VerifyArchive(*dir, audit.BatchVerifier(kr, true))
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		if !rep.OK {
			return errors.New("audit archive verification failed")
		}
		return nil
	})
	register("verify-audit", "verify the hash-linked audit chain (operator)", func(args []string) error {
		fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		requireSigned := fs.Bool("require-signatures", false, "fail on unsigned batches (use once every batch was sealed with signing enabled)")
		_ = fs.Parse(args)
		_, env, err := localApp(*cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		rep, err := audit.VerifyChainWith(context.Background(), env.DB.Pool, audit.BatchVerifier(env.Keys, *requireSigned))
		if err != nil {
			return err
		}
		kid, pub := audit.BatchPublicKey(env.Keys)
		out := map[string]any{"report": rep, "signing_key": map[string]any{"kid": kid, "ed25519_public_key": base64.StdEncoding.EncodeToString(pub)}}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		if !rep.OK {
			return errors.New("audit chain verification failed")
		}
		return nil
	})
	register("support-bundle", "write a sanitized diagnostic bundle for review before sharing (operator)", supportBundle)
	register("restore-reconcile", "re-apply revocations and invalidate uncertain grants after a restore (operator)", restoreReconcile)
}

func localApp(cfgPath string) (*httpapi.App, *server.Env, error) {
	env, err := server.InitOperator(context.Background(), cfgPath)
	if err != nil {
		return nil, nil, err
	}
	app, err := httpapi.Build(env.Deps, env.Metrics)
	if err != nil {
		env.DB.Close()
		return nil, nil, err
	}
	server.RegisterModules(app)
	return app, env, nil
}

func operatorName() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

func recordOperatorEvent(ctx context.Context, env *server.Env, typ string, meta map[string]any) error {
	ev := auditEvent(typ)
	ev.Metadata = meta
	_, err := env.Deps.Audit.Record(ctx, env.DB.Pool, ev)
	return err
}

func operatorRef() audit.Ref { return audit.Ref{Type: "operator", ID: "local:" + operatorName()} }
