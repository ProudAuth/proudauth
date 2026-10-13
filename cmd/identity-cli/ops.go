package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/restore"
	"github.com/proudbase/proudauth/internal/server"
)

func init() {
	register("restore-begin", "mark a restored database as not reconciled: not ready and no workers until restore-reconcile (operator)", restoreBegin)
	register("revocation-log", "export revocations, tombstones and compromised keys since a time (run regularly to independent storage)", func(args []string) error {
		fs := flag.NewFlagSet("revocation-log", flag.ExitOnError)
		cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
		since := fs.String("since", "", "RFC 3339 start time (default: 24h ago)")
		out := fs.String("out", "", "output file (default stdout)")
		_ = fs.Parse(args)
		t := time.Now().Add(-24 * time.Hour)
		if *since != "" {
			var err error
			if t, err = time.Parse(time.RFC3339, *since); err != nil {
				return err
			}
		}
		_, env, err := localApp(*cfg)
		if err != nil {
			return err
		}
		defer env.DB.Close()
		w := os.Stdout
		if *out != "" {
			f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			// The log is appended to; an existing file keeps its mode on open,
			// so tighten it before writing revocation records.
			if err := f.Chmod(0o600); err != nil {
				return err
			}
			w = f
		}
		n, err := restore.Export(context.Background(), env.DB, t, w)
		fmt.Fprintf(os.Stderr, "exported %d records\n", n)
		if err == nil {
			// Exports of security state are operator actions with evidence (OPS-013).
			// Without that evidence the export is reported as failed.
			if aerr := recordOperatorEvent(context.Background(), env, "operations.revocation_log.exported", map[string]any{"since": t.UTC(), "records": n}); aerr != nil {
				return fmt.Errorf("revocation log written but its audit record failed: %w", aerr)
			}
		}
		return err
	})
}

func restoreReconcile(args []string) error {
	fs := flag.NewFlagSet("restore-reconcile", flag.ExitOnError)
	cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
	logFile := fs.String("log", "", "revocation log exported since the backup was taken")
	invalidate := fs.Bool("invalidate-all-sessions", false, "revoke every session, refresh family, support grant and pending invitation")
	_ = fs.Parse(args)
	if *logFile == "" && !*invalidate {
		return errors.New("provide --log and/or --invalidate-all-sessions; restoring without reconciliation can resurrect revoked access")
	}
	_, env, err := localApp(*cfg)
	if err != nil {
		return err
	}
	defer env.DB.Close()
	var f *os.File
	if *logFile != "" {
		if f, err = os.Open(*logFile); err != nil {
			return err
		}
		defer f.Close()
	} else {
		f, _ = os.Open(os.DevNull)
	}
	rep, err := restore.Reconcile(context.Background(), env.DB, f, restore.Options{InvalidateAllSessions: *invalidate, Actor: operatorRef()}, time.Now().UTC(), env.Deps.Audit)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Println("Next: verify signing keys (identity-cli doctor), rotate if compromise records were applied, test representative flows, then resume traffic.")
	return nil
}

// restoreBegin marks a freshly restored database so it serves no traffic
// before restore-reconcile has run (TEST-060): /health/ready answers 503
// "restore_pending" and identity-worker refuses to start until the
// reconciliation clears the marker. -status only shows the marker.
func restoreBegin(args []string) error {
	fs := flag.NewFlagSet("restore-begin", flag.ExitOnError)
	cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
	status := fs.Bool("status", false, "show the restore marker without setting it")
	_ = fs.Parse(args)
	ctx := context.Background()
	env, err := server.InitOperator(ctx, *cfg)
	if err != nil {
		return err
	}
	defer env.DB.Close()
	var m *restore.Marker
	if *status {
		if m, err = restore.Pending(ctx, env.DB.Pool); err != nil {
			return err
		}
	} else {
		// The marker and its audit record commit together (OPS-013).
		if err := env.DB.Tx(ctx, func(tx pgx.Tx) error {
			var err error
			if m, err = restore.Begin(ctx, tx, "local:"+operatorName(), time.Now().UTC()); err != nil {
				return err
			}
			ev := auditEvent("operations.restore.begun")
			ev.Category = "emergency"
			ev.Metadata = map[string]any{"restore_pending_since": m.Since}
			_, err = env.Deps.Audit.Record(ctx, tx, ev)
			return err
		}); err != nil {
			return fmt.Errorf("restore marker not set: %w (run identity-cli migrate first if the restored schema is older than this binary)", err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"restore_pending": m != nil, "marker": m}); err != nil {
		return err
	}
	if m != nil && !*status {
		fmt.Fprintln(os.Stderr, "Readiness reports restore_pending and identity-worker will not start until identity-cli restore-reconcile has run.")
	}
	return nil
}

// supportBundle writes sanitized diagnostics: versions, redacted configuration,
// schema state and health. It never includes keys, tokens, sessions or user data
// (OPS-010), and the operator reviews it before sharing.
func supportBundle(args []string) error {
	fs := flag.NewFlagSet("support-bundle", flag.ExitOnError)
	cfg := fs.String("config", os.Getenv("PROUDAUTH_CONFIG"), "config file")
	out := fs.String("out", "", "output file (required)")
	_ = fs.Parse(args)
	if *out == "" {
		// Diagnostic artifacts go only where the operator says (DEP-004): never
		// silently into the working directory, which may be an image layer or
		// a shared location.
		return errors.New("support-bundle: -out is required: name a writable location for the bundle")
	}
	app, env, err := localApp(*cfg)
	if err != nil {
		return err
	}
	defer env.DB.Close()
	ctx := context.Background()
	migrations, _ := env.DB.MigrationsStatus(ctx)
	realms, _ := app.Realms.List(ctx)
	rs := []map[string]any{}
	for _, r := range realms {
		keys, _ := app.KeyMgr.List(ctx, r.ID)
		rs = append(rs, map[string]any{"name": r.Name, "state": r.State, "policy_revision": r.PolicyRevision, "signing_keys": keys})
	}
	counts := map[string]int{}
	for _, t := range []string{"users", "organizations", "clients", "sessions", "outbox_events", "notification_jobs", "webhook_deliveries", "jobs"} {
		var n int
		_ = env.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM "+t).Scan(&n)
		counts[t] = n
	}
	var pendingOutbox, failedJobs int
	_ = env.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE state='pending'`).Scan(&pendingOutbox)
	_ = env.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE state='dead_letter'`).Scan(&failedJobs)
	bundle := map[string]any{
		"generated_at": time.Now().UTC(), "version": version, "go_version": runtime.Version(), "os": runtime.GOOS + "/" + runtime.GOARCH,
		"configuration": env.Cfg.Redacted(), "migrations": migrations, "realms": rs, "row_counts": counts,
		"backlogs":                  map[string]int{"pending_outbox": pendingOutbox, "dead_letter_jobs": failedJobs},
		"key_hierarchy_fingerprint": env.Keys.Fingerprint(),
		"notice":                    "Review this file before sharing. It excludes keys, secrets, tokens, sessions and personal data.",
	}
	b, _ := json.MarshalIndent(bundle, "", "  ")
	if err := writePrivateFile(*out, b); err != nil {
		return err
	}
	fmt.Println("wrote", *out)
	if _, err := env.Deps.Audit.Record(ctx, env.DB.Pool, auditEvent("operations.support_bundle.generated")); err != nil {
		return fmt.Errorf("support bundle written but its audit record failed: %w", err)
	}
	return nil
}
