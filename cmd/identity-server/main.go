// Command identity-server runs the public protocol, interaction, self-service and
// administration APIs, plus a private internal listener for metrics and status.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/proudauth/proudauth/internal/httpapi"
	"github.com/proudauth/proudauth/internal/platform/tracing"
	"github.com/proudauth/proudauth/internal/server"
)

func main() {
	configPath := flag.String("config", os.Getenv("PROUDAUTH_CONFIG"), "path to the YAML configuration file")
	migrate := flag.Bool("migrate", false, "apply pending database migrations before serving")
	flag.Parse()
	if err := run(*configPath, *migrate); err != nil {
		fmt.Fprintln(os.Stderr, "identity-server:", err)
		os.Exit(1)
	}
}

// version is the release this binary was built from, set at build time with
// -ldflags "-X main.version=<tag>" (Dockerfile, release workflow); it is
// logged at start so operators and support bundles can match logs to a
// release (OPS-010).
var version = "dev"

func run(configPath string, migrate bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	env, err := server.Init(ctx, configPath, migrate)
	if err != nil {
		return err
	}
	defer env.DB.Close()
	// Refuse to serve against a schema outside the supported mixed-version
	// window (TEST-061). A schema that is merely behind keeps the process up but
	// unready, so operators can run migrations without restart loops (DEP-009).
	if err := env.DB.SchemaCompatible(ctx); err != nil {
		return err
	}
	if ok, _ := env.DB.SchemaCurrent(ctx); !ok {
		env.Log.Warn("database schema is behind this binary; readiness stays false until migrations are applied")
	}
	app, err := httpapi.Build(env.Deps, env.Metrics)
	if err != nil {
		return err
	}
	server.RegisterModules(app)
	// The phishing-resistant floor fails closed (SEC-012, MFA-005).
	if err := app.Auth.CheckPhishingResistantFloor(); err != nil {
		return err
	}
	if err := app.Authz.SyncBuiltIns(ctx); err != nil {
		return fmt.Errorf("sync built-in permissions: %w", err)
	}
	cfg := env.Cfg
	if cfg.Observability.OTLPEndpoint != "" {
		// Sampled spans go to the operator's collector (OPS-003).
		exp := tracing.NewOTLPExporter(cfg.Observability.OTLPEndpoint, "proudauth-server")
		tracing.SetTracer(exp)
		defer exp.Close()
	}
	public := server.PublicServer(cfg, app.Handler())
	internal := &http.Server{Addr: cfg.Server.InternalListen, Handler: server.InternalHandler(env, app), ReadHeaderTimeout: server.ReadHeaderTimeout}
	errc := make(chan error, 3)
	go func() {
		env.Log.Info("public listener starting", "addr", cfg.Server.PublicListen, "public_origin", cfg.Server.PublicOrigin, "version", version)
		var err error
		if cfg.Server.TLSCertFile != "" {
			err = public.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = public.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	var mtls *http.Server
	if cfg.Server.MTLSListen != "" {
		mtls = server.MutualTLSServer(cfg, public.Handler)
		go func() {
			env.Log.Info("mutual-TLS listener starting", "addr", cfg.Server.MTLSListen, "mtls_origin", cfg.Server.MTLSOrigin)
			if err := mtls.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	go func() {
		env.Log.Info("internal listener starting", "addr", cfg.Server.InternalListen)
		if err := internal.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Graceful shutdown (OPS-012): report not-ready first so load balancers
	// stop routing here, then stop accepting and drain in-flight requests within
	// the deadline. Handlers answer only after their transaction commits, so a
	// request cut off by the deadline is never reported as successful.
	env.Log.Info("shutting down", "drain_delay", cfg.Server.DrainDelay)
	app.Draining.Store(true)
	if cfg.Server.DrainDelay > 0 {
		time.Sleep(cfg.Server.DrainDelay)
	}
	sctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownDeadline)
	defer cancel()
	_ = internal.Shutdown(sctx)
	if mtls != nil {
		_ = mtls.Shutdown(sctx)
	}
	return public.Shutdown(sctx)
}
