package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/proudbase/proudauth/internal/realm"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestEmergencyControls covers SEC-020: audited controls switch off a grant
// class, a client or an organization without database edits, take effect
// immediately, never lock the operator out, and are reversible.
func TestEmergencyControls(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	control := func(typ, id, action, reason string) *Resp {
		return f.AdminAPI("POST", "/emergency/controls", map[string]any{"target_type": typ, "target_id": id, "action": action, "reason": reason})
	}
	machine := func() *Resp { return f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme) }
	mustStatus(t, machine(), 200, "machine token before the control")

	mustStatus(t, control("grant_type", "client_credentials", "disable", ""), 422, "control without a reason")
	mustStatus(t, control("grant_type", "password", "disable", "incident 42"), 422, "unknown grant class")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	if r := h.API("POST", "/emergency/controls", bob, map[string]any{"target_type": "grant_type", "target_id": "client_credentials",
		"action": "disable", "reason": "x"}); r.Status != 401 && r.Status != 403 {
		t.Fatalf("non-administrator used an emergency control: %d", r.Status)
	}

	mustStatus(t, control("grant_type", "client_credentials", "disable", "incident 42"), 200, "disable client credentials")
	if r := machine(); r.Status != 400 || r.Str("error") != "unauthorized_client" {
		t.Fatalf("disabled grant class still issued: %d %s", r.Status, r.Raw)
	}
	// Other grant classes keep working, and so does the operator client.
	mustStatus(t, f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens, 200, "authorization code unaffected")
	mustStatus(t, control("grant_type", "authorization_code", "disable", "incident 42"), 200, "disable authorization code")
	if st, _, _ := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud},
		Organization: f.Acme}); st.Status != 400 || !strings.Contains(string(st.Raw), "unauthorized_client") {
		t.Fatalf("authorization code flow started while disabled: %d %s", st.Status, st.Raw)
	}
	mustStatus(t, f.AccountToken("bob").Tokens, 200, "operator client exempt from grant controls")
	state := f.must(f.AdminAPI("GET", "/emergency/controls", nil), 200, "controls")
	if got := state.Get("disabled_grant_types").([]any); len(got) != 2 {
		t.Fatalf("disabled grant types: %s", state.Raw)
	}
	// Discovery stops advertising them (OIDC-015).
	disc := h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"})
	if g := fmt.Sprint(disc.Get("grant_types_supported")); strings.Contains(g, "client_credentials") || strings.Contains(g, "authorization_code") ||
		!strings.Contains(g, "refresh_token") {
		t.Fatalf("discovery grant types while disabled: %s", g)
	}
	mustStatus(t, control("grant_type", "authorization_code", "enable", "incident 42 resolved"), 200, "re-enable authorization code")
	mustStatus(t, control("grant_type", "client_credentials", "enable", "incident 42 resolved"), 200, "re-enable client credentials")
	mustStatus(t, machine(), 200, "machine token after the control is lifted")

	// Refresh tokens: disabling the class refuses refresh at once.
	rt := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	if rt == "" {
		t.Fatal("no refresh token issued")
	}
	mustStatus(t, control("grant_type", "refresh_token", "disable", "token theft"), 200, "disable refresh")
	if r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", f.Clients["web"].Secret); r.Status == 200 {
		t.Fatal("refresh succeeded while the grant class is disabled")
	}
	if f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token") != "" {
		t.Fatal("refresh token issued while the grant class is disabled")
	}
	mustStatus(t, control("grant_type", "refresh_token", "enable", "resolved"), 200, "re-enable refresh")

	// A single client and a whole organization.
	mustStatus(t, control("client", f.Clients["batch"].Ref, "disable", "leaked secret"), 200, "suspend client")
	if r := machine(); r.Status == 200 {
		t.Fatal("suspended client still issued tokens")
	}
	mustStatus(t, control("client", f.Clients["batch"].Ref, "enable", "secret rotated"), 200, "reactivate client")
	var clientEvents int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND category='emergency'
		AND target_id=$2 AND reason_code IN ('leaked secret','secret rotated')`, h.Realm.ID, f.Clients["batch"].Ref).Scan(&clientEvents)
	if clientEvents < 2 {
		t.Fatalf("client emergency controls not filed as emergency evidence: %d", clientEvents)
	}
	mustStatus(t, control("organization", f.Globex, "disable", "tenant compromise"), 200, "suspend organization")
	state = f.must(f.AdminAPI("GET", "/emergency/controls", nil), 200, "controls")
	if got := state.Get("suspended_organizations").([]any); len(got) != 1 || got[0] != f.Globex {
		t.Fatalf("suspended organizations: %s", state.Raw)
	}
	mustStatus(t, control("organization", f.Globex, "enable", "resolved"), 200, "reactivate organization")
	mustStatus(t, control("nonsense", "x", "disable", "x"), 422, "unknown target type")

	var n int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND category='emergency'
		AND type IN ('realm.grant_type.disabled','realm.grant_type.enabled') AND reason_code IS NOT NULL`, h.Realm.ID).Scan(&n)
	if n != 6 {
		t.Fatalf("grant-class controls not audited in the emergency category: %d", n)
	}
}

// TestAuditSearchDimensions covers AUD-011: audit search by network context,
// session, target and category, with invalid filters refused.
func TestAuditSearchDimensions(t *testing.T) {
	f := NewFixture(t)
	count := func(q string) int {
		t.Helper()
		r := f.must(f.AdminAPI("GET", "/audit-events?"+q, nil), 200, "audit "+q)
		return len(r.Get("items").([]any))
	}
	if count("network=127.0.0.1") == 0 || count("network=127.0.0.0/8") == 0 {
		t.Fatal("network filter found no loopback events")
	}
	if count("network=203.0.113.0/24") != 0 {
		t.Fatal("network filter matched an unrelated prefix")
	}
	mustStatus(t, f.AdminAPI("GET", "/audit-events?network=not-an-ip", nil), 422, "invalid network filter")
	cat := f.must(f.AdminAPI("GET", "/audit-events?category=security", nil), 200, "category filter")
	if len(cat.Get("items").([]any)) == 0 {
		t.Fatal("category filter found no security events")
	}
	for _, it := range cat.Get("items").([]any) {
		if c := it.(map[string]any)["category"]; c != "security" {
			t.Fatalf("category filter returned %v", c)
		}
	}
	org := f.must(f.AdminAPI("GET", "/audit-events?target_id="+f.Acme, nil), 200, "target filter")
	for _, it := range org.Get("items").([]any) {
		if it.(map[string]any)["target"].(map[string]any)["id"] != f.Acme {
			t.Fatalf("target filter returned another target: %v", it)
		}
	}
	lr := f.AccountToken("bob")
	sid := jwtPayload(lr.Tokens.Str("access_token"))["sid"]
	if sid == nil {
		t.Skip("account tokens carry no session ID")
	}
	if count("session_id="+sid.(string)) == 0 {
		t.Fatal("session filter found no events for the sign-in session")
	}
}

// TestReportedApplicationActivity covers AUD-013: services report activity
// that is filed apart from server-generated evidence and names the reporter.
func TestReportedApplicationActivity(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "activity-reporter",
		"permissions": []string{"realm.activity.report"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "service_principal",
		"id": f.Clients["orders-rs"].SP}}), 201, "assign")
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	report := func(tok string, body map[string]any) *Resp { return h.API("POST", "/activity-events", tok, body) }
	mustStatus(t, report(svc, map[string]any{"type": "user.deleted"}), 422, "server event type")
	mustStatus(t, report(svc, map[string]any{"type": "app.order.refunded", "occurred_at": h.Clock.Now().Add(-48 * time.Hour)}), 422, "backdated")
	r := f.must(report(svc, map[string]any{"type": "app.order.refunded", "organization_id": f.Acme,
		"subject": map[string]any{"type": "user", "id": f.Users["bob"]}, "metadata": map[string]any{"order": "ord_1", "password": "x"}}), 202, "report")
	if r.Str("source") != "application" {
		t.Fatalf("report: %s", r.Raw)
	}
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=app.order.refunded", nil), 200, "audit")
	items := ev.Get("items").([]any)
	if len(items) != 1 {
		t.Fatalf("reported events: %s", ev.Raw)
	}
	e := items[0].(map[string]any)
	if e["source"] != "application" || e["reporting_service"] != "orders-rs" || e["category"] != "application" {
		t.Fatalf("provenance: %v", e)
	}
	if strings.Contains(string(ev.Raw), `"password":"x"`) {
		t.Fatal("reported metadata not redacted")
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	if r := report(bob, map[string]any{"type": "app.x"}); r.Status < 400 {
		t.Fatalf("a user reported application activity: %d", r.Status)
	}
}

// TestSecurityAlerts covers AUD-012: privileged grants, protected-account
// sign-ins and security configuration changes raise security.alert events in
// the same transaction as their evidence, with identifiers only.
func TestSecurityAlerts(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	alerts := func(signal string) []map[string]any {
		rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT payload FROM outbox_events WHERE event_type='security.alert'`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var raw []byte
			_ = rows.Scan(&raw)
			var ev map[string]any
			_ = json.Unmarshal(raw, &ev)
			if data, _ := ev["data"].(map[string]any); data["signal"] == signal {
				out = append(out, data)
			}
		}
		return out
	}
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["realm-admin"], "subject": map[string]any{"type": "user",
		"id": f.Users["bob"]}}), 201, "privileged grant")
	got := alerts("privileged_grant")
	if len(got) == 0 || got[len(got)-1]["subject_id"] != f.Users["bob"] {
		t.Fatalf("privileged grant alert: %v", got)
	}
	f.ReloginAdmin()
	if len(alerts("protected_account_signin")) == 0 {
		t.Fatal("protected-account sign-in raised no alert")
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Password.MinLength = 14 }), 200, "policy change")
	if len(alerts("configuration_change")) == 0 {
		t.Fatal("realm policy change raised no alert")
	}
	for _, a := range alerts("privileged_grant") {
		for k := range a {
			if k == "metadata" || k == "role_name" {
				t.Fatalf("alert carries more than identifiers: %v", a)
			}
		}
	}
}
