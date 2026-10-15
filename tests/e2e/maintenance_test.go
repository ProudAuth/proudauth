package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/maintenance"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/server"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestMaintenanceAndStatus covers OPS-015: maintenance modes refuse the right
// requests with a generic 503 and Retry-After while keeping sign-in or token
// verification available, and operator status is authenticated and reports
// capabilities without being reachable from the public listener.
func TestMaintenanceAndStatus(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	set := func(mode, msg string) {
		t.Helper()
		if err := maintenance.Set(ctx, h.App.D.DB.Pool, maintenance.State{Mode: mode, Message: msg, RetryAfterSeconds: 120}, "local:test", time.Now()); err != nil {
			t.Fatal(err)
		}
		h.App.Maintenance.Invalidate()
	}
	if err := maintenance.Set(ctx, h.App.D.DB.Pool, maintenance.State{Mode: "restricted", Message: "<script>"}, "x", time.Now()); err == nil {
		t.Fatal("markup accepted in the public maintenance message")
	}

	set(maintenance.Restricted, "Upgrading, back soon")
	r := f.AdminAPI("POST", "/organizations", map[string]any{"slug": "during-maint", "display_name": "x"})
	if r.Status != 503 || r.Str("code") != "maintenance" || r.Header.Get("Retry-After") != "120" || r.Str("detail") != "Upgrading, back soon" {
		t.Fatalf("restricted mode accepted a configuration change: %d %v %s", r.Status, r.Header, r.Raw)
	}
	mustStatus(t, f.AdminAPI("GET", "/users", nil), 200, "reads continue in restricted mode")
	lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	mustStatus(t, lr.Tokens, 200, "sign-in continues in restricted mode")
	at := lr.Tokens.Str("access_token")

	set(maintenance.Unavailable, "")
	if r := h.API("GET", "/users", f.AdminToken, nil); r.Status != 503 {
		t.Fatalf("unavailable mode served the API: %d", r.Status)
	}
	if st, _, _ := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}); st.Status != 503 {
		t.Fatalf("unavailable mode started a sign-in: %d", st.Status)
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/jwks"}), 200, "JWKS stays available")
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery stays available")
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, at); in.Status != 200 || in.Get("active") != true {
		t.Fatalf("introspection unavailable during maintenance: %d %s", in.Status, in.Raw)
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/health/live"}), 200, "liveness")

	// Operator status: private listener only, token-protected when configured.
	if r := h.Do(Req{Method: "GET", Path: "/status"}); r.Status == 200 {
		t.Fatal("operator status served on the public listener")
	}
	cfg := *h.Cfg
	cfg.Server.MetricsToken = "env:PROUDAUTH_TEST_STATUS_TOKEN"
	t.Setenv("PROUDAUTH_TEST_STATUS_TOKEN", "status-token-123")
	env := &server.Env{Cfg: &cfg, Log: h.App.D.Log, DB: h.App.D.DB, Keys: h.App.D.Keys, Deps: h.App.D, Metrics: h.App.Metrics}
	internal := httptest.NewServer(server.InternalHandler(env, h.App))
	defer internal.Close()
	get := func(tok string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest("GET", internal.URL+"/status", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		return res, body
	}
	if res, _ := get(""); res.StatusCode != 401 {
		t.Fatalf("status without the operator token: %d", res.StatusCode)
	}
	res, body := get("status-token-123")
	if res.StatusCode != 200 || body["status"] != "maintenance" {
		t.Fatalf("status: %d %v", res.StatusCode, body)
	}
	caps := body["capabilities"].(map[string]any)
	for _, c := range []string{"database", "schema", "signing", "outbox", "email_delivery", "webhooks", "jobs"} {
		if caps[c] == nil {
			t.Fatalf("capability %s missing: %v", c, caps)
		}
	}
	// Backlog ages per queue are scraped as metrics (OPS-002).
	cfg.Observability.MetricsEnabled = true
	mreq, _ := http.NewRequest("GET", internal.URL+"/metrics", nil)
	mreq.Header.Set("Authorization", "Bearer status-token-123")
	if mres, err := http.DefaultClient.Do(mreq); err != nil {
		t.Fatal(err)
	} else {
		raw, _ := io.ReadAll(mres.Body)
		mres.Body.Close()
		for _, name := range []string{"proudauth_notification_oldest_due_seconds", "proudauth_webhook_oldest_due_seconds", "proudauth_jobs_oldest_queued_seconds"} {
			if !strings.Contains(string(raw), name) {
				t.Fatalf("metric %s missing: %d", name, mres.StatusCode)
			}
		}
	}
	set(maintenance.Off, "")
	if _, body := get("status-token-123"); body["status"] == "maintenance" {
		t.Fatalf("status still reports maintenance: %v", body)
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations", map[string]any{"slug": "after-maint", "display_name": "After"}), 201, "changes resume")

	// SEC-015: debug windows are bounded, propagate to nodes on refresh and close.
	if err := maintenance.SetDebug(ctx, h.App.D.DB.Pool, 2*time.Hour, "", true, time.Now()); err == nil {
		t.Fatal("production debug window longer than an hour accepted")
	}
	if err := maintenance.SetDebug(ctx, h.App.D.DB.Pool, 10*time.Minute, "worker", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.App.Maintenance.Invalidate()
	h.App.Maintenance.Current(ctx, h.App.D.DB.Pool)
	if until, comp, open := observability.DebugWindow(); !open || comp != "worker" || time.Until(until) > 10*time.Minute {
		t.Fatalf("debug window not applied: %v %q %v", until, comp, open)
	}
	if err := maintenance.SetDebug(ctx, h.App.D.DB.Pool, 0, "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.App.Maintenance.Invalidate()
	h.App.Maintenance.Current(ctx, h.App.D.DB.Pool)
	if _, _, open := observability.DebugWindow(); open {
		t.Fatal("debug window not closed")
	}
	if strings.Contains(string(r.Raw), "database") {
		t.Fatal("maintenance refusal disclosed internal topology")
	}
}

// TestWorkerShutdownReleasesLeases covers OPS-012: a stopping worker claims no
// new work and hands back the leases it holds, so another worker resumes the
// job at once instead of waiting for the lease to expire.
func TestWorkerShutdownReleasesLeases(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	job := f.must(h.API("POST", "/me/exports", f.AccountToken("alice").Tokens.Str("access_token"), nil), 202, "export").Str("job_id")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE jobs SET state='running', lease_owner='worker-drain', lease_expires_at=now() + interval '1 hour'
		WHERE id=$1`, job); err != nil {
		t.Fatal(err)
	}
	w := worker.New(h.App, "worker-drain")
	stopped, stop := context.WithCancel(ctx)
	stop()
	done := make(chan struct{})
	go func() { w.Run(stopped); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not stop")
	}
	var state string
	var owner *string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, lease_owner FROM jobs WHERE id=$1`, job).Scan(&state, &owner)
	if state != "queued" || owner != nil {
		t.Fatalf("lease not released at shutdown: state=%s owner=%v", state, owner)
	}
	runWorker(t, worker.New(h.App, "worker-next"))
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM jobs WHERE id=$1`, job).Scan(&state)
	if state != "succeeded" {
		t.Fatalf("released job not resumed by another worker: %s", state)
	}
}
