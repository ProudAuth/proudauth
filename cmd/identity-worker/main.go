// Command identity-worker runs durable background work: outbox dispatch, message,
// webhook and back-channel logout delivery, jobs, key lifecycle, audit sealing and
// retention. Several workers may run concurrently (DEP-011).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/proudbase/proudauth/internal/httpapi"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/platform/tracing"
	"github.com/proudbase/proudauth/internal/restore"
	"github.com/proudbase/proudauth/internal/server"
	"github.com/proudbase/proudauth/internal/worker"
)

func main() {
	configPath := flag.String("config", os.Getenv("PROUDAUTH_CONFIG"), "path to the YAML configuration file")
	once := flag.Bool("once", false, "run every task once and exit")
	flag.Parse()
	if err := run(*configPath, *once); err != nil {
		fmt.Fprintln(os.Stderr, "identity-worker:", err)
		os.Exit(1)
	}
}

// version is the release this binary was built from, set at build time with
// -ldflags "-X main.version=<tag>" (Dockerfile, release workflow); it is
// logged at start so operators and support bundles can match logs to a
// release (OPS-010).
var version = "dev"

func run(configPath string, once bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	env, err := server.Init(ctx, configPath, false)
	if err != nil {
		return err
	}
	defer env.DB.Close()
	if ok, err := env.DB.SchemaCurrent(ctx); err != nil || !ok {
		return fmt.Errorf("database schema is not current; run migrations first")
	}
	// A restored database waiting for reconciliation must not send the
	// notifications, webhooks and jobs restored with it (TEST-060).
	if m, err := restore.Pending(ctx, env.DB.Pool); err != nil {
		return err
	} else if m != nil {
		return fmt.Errorf("database restored at %s is not reconciled; run identity-cli restore-reconcile first", m.Since.Format(time.RFC3339))
	}
	app, err := httpapi.Build(env.Deps, env.Metrics)
	if err != nil {
		return err
	}
	server.RegisterModules(app)
	if ep := env.Cfg.Observability.OTLPEndpoint; ep != "" {
		// Sampled task runs go to the operator's collector (OPS-003).
		exp := tracing.NewOTLPExporter(ep, "proudauth-worker")
		tracing.SetTracer(exp)
		defer exp.Close()
	}
	// Leases are owned per process: two workers on one host (or in
	// containers sharing a host name) must never share an owner ID, or one
	// could complete the other's leased work.
	host, _ := os.Hostname()
	w := worker.New(app, fmt.Sprintf("worker-%s-%d-%s", host, os.Getpid(), hex.EncodeToString(secret.Random(4))))
	if once {
		for name, err := range w.RunOnce(ctx) {
			if err != nil {
				env.Log.Error("task failed", "task", name, "error", err)
			}
		}
		return nil
	}
	if addr := env.Cfg.Workers.MetricsListen; addr != "" {
		// Worker task metrics on a private listener (OPS-002).
		srv := &http.Server{Addr: addr, Handler: server.InternalHandler(env, app), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				env.Log.Error("worker metrics listener failed", "error", err)
			}
		}()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()
	}
	env.Log.Info("worker started", "id", w.ID, "version", version)
	w.Run(ctx)
	env.Log.Info("worker stopped")
	return nil
}
