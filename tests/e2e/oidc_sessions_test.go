package e2e

import (
	"net/url"
	"strings"
	"testing"
)

// TestOfflineConsentAndTransientSessions covers OIDC-012/SES-021 (offline
// access by a third-party client needs explicit consent) and SES-020 (transient
// sessions mint no refresh authority).
func TestOfflineConsentAndTransientSessions(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	userinfo := ""
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			userinfo = m["id"].(string)
		}
	}
	reg := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "reports-tool", "name": "Reports Tool", "client_type": "confidential",
		"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{"https://reports.test/cb"}, "allow_offline_access": true,
		"environment": "development"}), 201, "third-party client")
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"}}), 204, "grant")
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+userinfo, map[string]any{"allowed_scopes": []string{"openid"}}), 204, "oidc grant")
	secret := reg.Str("client_secret")

	t.Run("offline access requires explicit consent", func(t *testing.T) {
		lr := h.Login(LoginOpts{ClientID: "reports-tool", ClientSecret: secret, RedirectURI: "https://reports.test/cb", Scope: "orders:read offline_access",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", ExpectFail: true})
		// Drive approves consent; verify consent was actually requested and recorded.
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=consent.granted", nil), 200, "audit")
		if !strings.Contains(string(ev.Raw), "offline_access") {
			t.Fatalf("offline access granted without consent: %s", ev.Raw)
		}
		if lr.Tokens == nil || lr.Tokens.Str("refresh_token") == "" {
			t.Fatalf("offline grant should carry a refresh token: %v", lr.Tokens)
		}
	})

	t.Run("transient sessions issue no refresh token", func(t *testing.T) {
		opts := LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"}
		start, verifier, cont := h.StartTx(opts)
		tx := start.Str("transaction_id")
		mustStatus(t, h.Step(tx, cont, "transient", map[string]any{"transient": true}), 200, "transient")
		st := h.Drive(tx, cont, h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}), opts)
		u, _ := url.Parse(st.Str("redirect_to"))
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {webRedirect}, "resource": {f.OrdersAud}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, toks, 200, "token")
		if toks.Str("refresh_token") != "" {
			t.Fatal("transient session minted a refresh token")
		}
		// Asking for offline access does not change that.
		offOpts := LoginOpts{ClientID: "reports-tool", ClientSecret: secret, RedirectURI: "https://reports.test/cb", Scope: "orders:read offline_access",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"}
		start, verifier, cont = h.StartTx(offOpts)
		tx = start.Str("transaction_id")
		mustStatus(t, h.Step(tx, cont, "transient", map[string]any{"transient": true}), 200, "transient")
		st = h.Drive(tx, cont, h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}), offOpts)
		u, _ = url.Parse(st.Str("redirect_to"))
		toks = h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {"https://reports.test/cb"}, "resource": {f.OrdersAud}}, "reports-tool", secret)
		mustStatus(t, toks, 200, "offline token request")
		if toks.Str("refresh_token") != "" || strings.Contains(toks.Str("scope"), "offline_access") {
			t.Fatalf("transient session yielded offline access: %s", toks.Raw)
		}
		// A normal session from the same client does get one.
		normal := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
		if normal.Tokens.Str("refresh_token") == "" {
			t.Fatal("normal session should receive a refresh token")
		}
	})
}
