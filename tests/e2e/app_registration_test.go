package e2e

import (
	"net/url"
	"strings"
	"testing"
)

// TestBrowserOriginRegistration covers APP-005: browser origins are
// registered per client, separately from redirect URIs and resource
// audiences; CORS answers reflect only registered origins (with credentials
// on the interaction API), and wildcard or path-carrying origins cannot be
// registered.
func TestBrowserOriginRegistration(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	public := func(id string, origins ...string) map[string]any {
		body := map[string]any{"client_id": id, "name": id, "client_type": "public_browser", "redirect_uris": []string{"https://" + id + ".test/cb"}}
		if origins != nil {
			body["allowed_origins"] = origins
		}
		return body
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", public("wildcard", "*")), 422, "wildcard origin")
	mustStatus(t, f.AdminAPI("POST", "/clients", public("wildcard-host", "https://*.app.test")), 422, "wildcard host origin")
	mustStatus(t, f.AdminAPI("POST", "/clients", public("with-path", "https://with-path.test/app")), 422, "origin with a path")
	f.must(f.AdminAPI("POST", "/clients", public("redirect-only")), 201, "client without origins")

	preflight := func(origin string) *Resp {
		return h.Do(Req{Method: "OPTIONS", Path: "/api/v1/realms/main/auth/transactions",
			Headers: map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST"}})
	}
	ok := preflight("https://app.test")
	if ok.Header.Get("Access-Control-Allow-Origin") != "https://app.test" || ok.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("registered origin: %v", ok.Header)
	}
	for _, origin := range []string{"https://evil.test", "https://redirect-only.test", f.OrdersAud, "null", "http://app.test",
		"https://app.test.evil.test", "https://app.test:8443"} {
		r := preflight(origin)
		if r.Header.Get("Access-Control-Allow-Origin") != "" || r.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("unregistered origin %s granted CORS: %v", origin, r.Header)
		}
	}
	// A credentialed call from an unregistered origin gets no CORS grant either.
	_, challenge := PKCE()
	r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions", Headers: map[string]string{"Origin": "https://evil.test"},
		JSON: map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "orders:read", "resource": []string{f.OrdersAud},
			"code_challenge": challenge, "code_challenge_method": "S256"}})
	if r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("cross-origin transaction start granted CORS: %v", r.Header)
	}
}

// TestResourceAudienceRegistration covers APP-006: a resource server is
// registered once with a stable audience identifier, never a wildcard or
// free text; the audience cannot be changed afterwards, and tokens name only
// registered audiences.
func TestResourceAudienceRegistration(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	for name, aud := range map[string]string{"wildcard": "*", "wildcard host": "https://*.reports.test", "whitespace": "https://reports.test/a b",
		"free text": "reports", "script": "javascript:alert(1)", "empty": ""} {
		if r := f.AdminAPI("POST", "/resources", map[string]any{"name": "Reports", "audience": aud}); r.Status != 422 {
			t.Errorf("%s audience %q: %d", name, aud, r.Status)
		}
	}
	mustStatus(t, f.AdminAPI("POST", "/resources", map[string]any{"name": "Orders again", "audience": f.OrdersAud}), 409, "duplicate audience")
	cur := f.must(f.AdminAPI("GET", "/resources/"+f.Billing, nil), 200, "resource")
	upd := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resources/" + f.Billing, Token: f.AdminToken, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")},
		JSON: map[string]any{"name": "Billing API", "audience": "https://attacker.test", "verification_mode": "offline"}})
	mustStatus(t, upd, 200, "update")
	if upd.Str("audience") != f.BillingAud {
		t.Fatalf("audience changed on update: %s", upd.Raw)
	}
	if r := f.MachineToken(f.Clients["batch"], "https://attacker.test", "billing:read", f.Acme); r.Status != 400 || r.Str("error") != "invalid_target" {
		t.Fatalf("token for an unregistered audience: %d %s", r.Status, r.Raw)
	}
	tok := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)
	mustStatus(t, tok, 200, "registered audience")
	if aud := jwtPayload(tok.Str("access_token"))["aud"]; aud != f.BillingAud {
		t.Fatalf("token audience %v", aud)
	}
}

// TestScopeRegistry covers APP-007: scopes are declared on their resource
// with a description, consent text and default flag; only clients whose
// grant lists a scope may request it, consent shows the declared text, and a
// requested scope is granted only as far as consent allows.
func TestScopeRegistry(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.must(f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:export", "description": "Export orders",
		"consent_text": "Export your order history", "is_default": true}), 201, "declare scope")
	res := f.must(f.AdminAPI("GET", "/resources/"+f.Orders, nil), 200, "resource")
	var declared map[string]any
	for _, sc := range res.Get("scopes").([]any) {
		if m := sc.(map[string]any); m["name"] == "orders:export" {
			declared = m
		}
	}
	if declared == nil || declared["description"] != "Export orders" || declared["consent_text"] != "Export your order history" ||
		declared["is_default"] != true || declared["resource_id"] != f.Orders {
		t.Fatalf("declared scope: %v", declared)
	}
	_, challenge := PKCE()
	if r := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "orders:export",
		"resource": []string{f.OrdersAud}, "code_challenge": challenge, "code_challenge_method": "S256"}); r.Status != 400 || !strings.Contains(string(r.Raw), "invalid_scope") {
		t.Fatalf("scope requested by a client without a grant for it: %d %s", r.Status, r.Raw)
	}
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["partner"].Ref+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read", "orders:export"},
		"subject_types": []string{"user"}}), 204, "grant")
	o := LoginOpts{ClientID: "partner-app", RedirectURI: "https://partner.test/cb", Scope: "orders:read orders:export", Resources: []string{f.OrdersAud},
		Organization: f.Acme}
	start, verifier, cont := h.StartTx(o)
	mustStatus(t, start, 201, "start")
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if has(actionTypes(st), "select_organization") {
		st = h.Step(tx, cont, "organization", map[string]any{"organization_id": f.Acme})
	}
	if !has(actionTypes(st), "consent") || !strings.Contains(string(st.Raw), "Export your order history") {
		t.Fatalf("consent must show the declared text: %s", st.Raw)
	}
	done := h.Step(tx, cont, "consent", map[string]any{"approve": true, "scopes": []string{"orders:read"}})
	u, err := url.Parse(done.Str("redirect_to"))
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("consent: %s", done.Raw)
	}
	code := u.Query().Get("code")
	tokens := h.TokenRequest(map[string][]string{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {"https://partner.test/cb"}, "resource": {f.OrdersAud}}, "partner-app", "")
	mustStatus(t, tokens, 200, "tokens")
	if s := tokens.Str("scope"); s != "orders:read" {
		t.Fatalf("a requested scope the user did not consent to was granted: %q", s)
	}
}
