package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestSessionLimitsAndAdminRevocation covers SES-002 (realm concurrency limit),
// SES-003 (administrators revoke one session) and SES-013 (safe metadata).
func TestSessionLimitsAndAdminRevocation(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Sessions.MaxConcurrent = 2 })
	h := f.H
	for i := 0; i < 3; i++ {
		f.AccountToken("bob")
	}
	list := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"]+"/sessions", nil), 200, "sessions")
	items := list.Get("items").([]any)
	if len(items) != 2 {
		t.Fatalf("realm max_concurrent not applied: %d sessions", len(items))
	}
	first := items[0].(map[string]any)
	if first["device_label"] == nil || first["network"] == nil {
		t.Fatalf("session metadata: %v", first)
	}
	id := first["id"].(string)
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["alice"]+"/sessions/"+id, nil), 404, "session of another user")
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["bob"]+"/sessions/"+id, nil), 204, "revoke one session")
	if n := len(f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"]+"/sessions", nil), 200, "sessions").Get("items").([]any)); n != 1 {
		t.Fatalf("expected one remaining session, got %d", n)
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mine := h.API("GET", "/me/sessions", bob, nil)
	if mine.Get("items").([]any)[0].(map[string]any)["device"] != "Go client" {
		t.Fatalf("self-service session list lacks device context: %s", mine.Raw)
	}
}

// TestCredentialExpiryAlerts covers MCH-009/TOK-021/APP-014: client secrets
// expiring soon alert the owner and technical contacts, exactly once.
func TestCredentialExpiryAlerts(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE clients SET contacts='{ops@example.test}' WHERE client_id='web-bff'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE client_credentials SET expires_at=$1 WHERE client_ref=(SELECT id FROM clients WHERE client_id='web-bff')`,
		h.Clock.Now().Add(5*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	w := worker.New(h.App, "test")
	for i := 0; i < 3; i++ {
		if _, err := w.CredentialExpiryAlerts(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_jobs WHERE reference_type='credential_expiry'`).Scan(&n)
	if n != 1 {
		t.Fatalf("expected exactly one expiry alert, got %d", n)
	}
	h.Deliver()
	if body := h.Mail("ops@example.test", "credential_expiry"); !strings.Contains(body, "web-bff") {
		t.Fatalf("alert does not name the client: %q", body)
	}
}
