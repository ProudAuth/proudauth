package e2e

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

// scopeSet returns a token response's scopes, sorted, as one string.
func scopeSet(r *Resp) string {
	s := strings.Fields(r.Str("scope"))
	slices.Sort(s)
	return strings.Join(s, " ")
}

// TestDefaultScopeGrants covers APP-007's default grants: a request that
// names a resource but none of its scopes is requested with the resource's
// default scopes, which then pass exactly the checks a requested scope
// passes. A default scope the client's grant does not list, or that the
// user lacks the permissions for, or that the organization's ceiling
// excludes, or that the user does not consent to, is not issued; a request
// that names any scope of the resource gets no defaults; a refresh never
// adds defaults declared after the authorization; client credentials get
// defaults the same way.
func TestDefaultScopeGrants(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	declare := func(resource string, body map[string]any) {
		t.Helper()
		f.must(f.AdminAPI("POST", "/resources/"+resource+"/scopes", body), 201, "declare "+body["name"].(string))
	}
	declare(f.Orders, map[string]any{"name": "orders:list", "consent_text": "List your orders", "is_default": true})
	declare(f.Orders, map[string]any{"name": "orders:audit", "is_default": true, "required_permissions": []string{"orders.refund"}})
	declare(f.Orders, map[string]any{"name": "orders:export", "is_default": true}) // no client is granted it
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+f.Orders, map[string]any{"subject_types": []string{"user"},
		"allowed_scopes": []string{"orders:read", "orders:write", "orders:list", "orders:audit"}}), 204, "web grant")

	// No scope for the resource: its defaults, as far as the client's
	// grant and the subject's permissions allow.
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid").Tokens
	mustStatus(t, bob, 200, "bob")
	if s := scopeSet(bob); s != "orders:list" {
		t.Fatalf("defaults for a subject without orders.refund: %q", s)
	}
	if s := jwtPayload(bob.Str("access_token"))["scope"]; s != "orders:list" {
		t.Fatalf("access token scope: %v", s)
	}
	if bob.Str("id_token") == "" {
		t.Fatal("openid was requested but no ID token was issued")
	}
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid").Tokens
	mustStatus(t, alice, 200, "alice")
	if s := scopeSet(alice); s != "orders:audit orders:list" {
		t.Fatalf("defaults for a subject with orders.refund: %q", s)
	}

	// A request naming a scope of the resource gets exactly that scope.
	explicit := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens
	mustStatus(t, explicit, 200, "explicit")
	if s := scopeSet(explicit); s != "orders:read" {
		t.Fatalf("requested scopes were extended with defaults: %q", s)
	}

	// A default declared after the authorization is not added on refresh:
	// a refresh never expands the grant.
	declare(f.Orders, map[string]any{"name": "orders:later", "is_default": true})
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+f.Orders, map[string]any{"subject_types": []string{"user"},
		"allowed_scopes": []string{"orders:read", "orders:write", "orders:list", "orders:audit", "orders:later"}}), 204, "web grant")
	refreshed := h.TokenRequest(map[string][]string{"grant_type": {"refresh_token"}, "refresh_token": {bob.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, refreshed, 200, "refresh")
	if s := scopeSet(refreshed); s != "orders:list" {
		t.Fatalf("refresh changed the default grant: %q", s)
	}

	// The organization's scope ceiling applies to defaults.
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Globex, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Globex, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_scopes": []string{"orders:read"}}}}),
		200, "org scope ceiling")
	capped := f.LoginWeb("bob", f.Globex, f.OrdersAud, "openid").Tokens
	mustStatus(t, capped, 200, "globex")
	if s := scopeSet(capped); s != "" {
		t.Fatalf("defaults outside the organization's ceiling were issued: %q", s)
	}

	// Consent covers defaults: the user sees them and may decline one.
	declare(f.Orders, map[string]any{"name": "orders:history", "consent_text": "See your order history", "is_default": true})
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["partner"].Ref+"/resource-grants/"+f.Orders, map[string]any{"subject_types": []string{"user"},
		"allowed_scopes": []string{"orders:read", "orders:list", "orders:history"}}), 204, "partner grant")
	start, verifier, cont := h.StartTx(LoginOpts{ClientID: "partner-app", RedirectURI: "https://partner.test/cb", Resources: []string{f.OrdersAud},
		Organization: f.Acme})
	mustStatus(t, start, 201, "start")
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if has(actionTypes(st), "select_organization") {
		st = h.Step(tx, cont, "organization", map[string]any{"organization_id": f.Acme})
	}
	if !has(actionTypes(st), "consent") || !strings.Contains(string(st.Raw), "List your orders") || !strings.Contains(string(st.Raw), "See your order history") {
		t.Fatalf("consent must show the default scopes: %s", st.Raw)
	}
	done := h.Step(tx, cont, "consent", map[string]any{"approve": true, "scopes": []string{"orders:list"}})
	code := codeFromRedirect(t, done.Str("redirect_to"))
	partner := h.TokenRequest(map[string][]string{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {"https://partner.test/cb"}}, "partner-app", "")
	mustStatus(t, partner, 200, "partner tokens")
	if s := scopeSet(partner); s != "orders:list" {
		t.Fatalf("a default scope the user declined was issued: %q", s)
	}

	// Client credentials: the same rule for a service principal.
	declare(f.Billing, map[string]any{"name": "billing:summary", "is_default": true})
	declare(f.Billing, map[string]any{"name": "billing:export", "is_default": true}) // not granted
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["batch"].Ref+"/resource-grants/"+f.Billing, map[string]any{"subject_types": []string{"service_principal"},
		"allowed_scopes": []string{"billing:read", "billing:summary"}}), 204, "batch grant")
	machine := f.MachineToken(f.Clients["batch"], f.BillingAud, "", f.Acme)
	mustStatus(t, machine, 200, "machine defaults")
	if s := scopeSet(machine); s != "billing:summary" {
		t.Fatalf("client credentials defaults: %q", s)
	}
	machine = f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)
	mustStatus(t, machine, 200, "machine explicit")
	if s := scopeSet(machine); s != "billing:read" {
		t.Fatalf("client credentials with a requested scope: %q", s)
	}
}

// codeFromRedirect extracts the authorization code from a redirect.
func codeFromRedirect(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("no code in redirect %q", redirect)
	}
	return u.Query().Get("code")
}
