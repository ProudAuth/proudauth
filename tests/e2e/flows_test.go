package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestIntrospectionExchangeAndMachines covers TOK-009 (authenticated
// introspection limited to the token's resource servers, the bare inactive
// response for everyone else), MCH-002 and MCH-003 (client credentials yield
// a short-lived service-principal token and no refresh token), MCH-004
// (machine tokens stay within their audiences, scopes and organizations and
// never reach human self-service APIs) and MCH-015 (exchange keeps the human
// subject and the service actor, checks each audience transition and
// refuses unauthorized exchanges).
func TestIntrospectionExchangeAndMachines(t *testing.T) {
	f := NewFixture(t)
	orders := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	at := orders.Tokens.Str("access_token")

	t.Run("TEST-037 introspection limited to the token's resource servers", func(t *testing.T) {
		r := f.H.Introspect("billing-rs", f.Clients["billing-rs"].Secret, at)
		if r.Get("active") != false || len(r.Body) != 1 {
			t.Fatalf("billing-rs learned about an orders token: %s", r.Raw)
		}
		bad := f.H.Do(Req{Method: "POST", Path: "/realms/main/oauth/introspect", Form: url.Values{"token": {at}}, Basic: [2]string{"orders-rs", "wrong"}})
		mustStatus(t, bad, 401, "unauthenticated introspection")
	})
	t.Run("TEST-038 token exchange", func(t *testing.T) {
		ex := f.H.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {at},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}, "scope": {"billing:read"}},
			"orders-rs", f.Clients["orders-rs"].Secret)
		mustStatus(t, ex, 200, "allowed exchange")
		claims := jwtPayload(ex.Str("access_token"))
		if claims["sub"] != f.Users["alice"] || claims["aud"] != f.BillingAud || claims["org_id"] != f.Acme {
			t.Fatalf("exchanged claims: %v", claims)
		}
		act, _ := claims["act"].(map[string]any)
		if act == nil || act["sub"] != f.Clients["orders-rs"].SP || claims["token_kind"] != "exchange_access" {
			t.Fatalf("delegation provenance must be preserved (TOK-017): %v", claims)
		}
		if claims["exp"].(float64) > jwtPayload(at)["exp"].(float64) {
			t.Fatal("exchange extended the subject token lifetime")
		}
		for name, form := range map[string]url.Values{
			"unregistered audience": {"resource": {f.H.Realm.Issuer + "/admin"}},
			"wider scope":           {"resource": {f.BillingAud}, "scope": {"billing:admin"}},
			"id token subject":      {"resource": {f.BillingAud}, "subject_token": {orders.Tokens.Str("id_token")}},
		} {
			base := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {at},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}
			for k, v := range form {
				base[k] = v
			}
			if r := f.H.TokenRequest(base, "orders-rs", f.Clients["orders-rs"].Secret); r.Status == 200 {
				t.Fatalf("%s: exchange allowed", name)
			}
		}
		// A client without an exchange policy for this transition cannot exchange.
		r := f.H.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {at},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}}, "batch-job", f.Clients["batch"].Secret)
		if r.Status == 200 {
			t.Fatal("unauthorized client exchanged a user token")
		}
	})
	t.Run("MCH client credentials", func(t *testing.T) {
		tok := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)
		mustStatus(t, tok, 200, "client credentials")
		claims := jwtPayload(tok.Str("access_token"))
		if claims["sub"] != f.Clients["batch"].SP || claims["token_kind"] != "service_access" || claims["org_id"] != f.Acme || tok.Str("refresh_token") != "" {
			t.Fatalf("machine token: %v %s", claims, tok.Raw)
		}
		if life := claims["exp"].(float64) - claims["iat"].(float64); life <= 0 || life > 3600 || claims["sid"] != nil || claims["auth_time"] != nil {
			t.Fatalf("machine tokens are short-lived and carry no human login: %v", claims)
		}
		if r := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Globex); r.Status == 200 {
			t.Fatal("machine token for a non-allowed organization")
		}
		if r := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:admin", f.Acme); r.Status == 200 {
			t.Fatal("machine token beyond its scope ceiling")
		}
		// TEST-039: machine tokens cannot reach human self-service routes.
		if r := f.MachineToken(f.Clients["batch"], f.H.Realm.Issuer+"/account", "proudauth:account", ""); r.Status == 200 {
			t.Fatal("machine token for the account API")
		}
		svc := f.MachineToken(f.Clients["orders-rs"], f.H.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		mustStatus(t, f.H.API("GET", "/me", svc, nil), 401, "machine on self-service")
		mustStatus(t, f.H.API("GET", "/users", svc, nil), 403, "machine without user permissions")
		// Disabling the service principal stops it immediately.
		f.must(f.AdminAPI("POST", "/service-principals/"+f.Clients["batch"].SP+"/disable", nil), 204, "disable")
		if r := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
			t.Fatal("disabled service principal obtained a token")
		}
	})
	t.Run("TEST-065 API keys and PATs share central state", func(t *testing.T) {
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		pat := f.H.API("POST", "/me/personal-tokens", bob, map[string]any{"name": "cli", "audience": f.OrdersAud, "scopes": []string{"orders:read"},
			"organization_id": f.Acme, "ttl_days": 30})
		mustStatus(t, pat, 201, "create PAT")
		tok := pat.Str("token")
		if list := f.H.API("GET", "/me/personal-tokens", bob, nil); strings.Contains(string(list.Raw), tok) {
			t.Fatal("secret shown after creation (MCH-008)")
		}
		in := f.H.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok)
		if in.Get("active") != true || in.Str("token_kind") != "personal_access" || in.Str("org_id") != f.Acme {
			t.Fatalf("PAT introspection: %s", in.Raw)
		}
		mustStatus(t, f.H.API("DELETE", "/me/personal-tokens/"+pat.Str("credential.id"), bob, nil), 204, "revoke")
		if in := f.H.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok); in.Get("active") != false {
			t.Fatal("revoked PAT still active")
		}
		bot := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "sync-bot", "allowed_organization_ids": []string{f.Acme}}), 201, "sp")
		key := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": bot.Str("id"), "name": "sync",
			"audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme}), 201, "api key")
		if in := f.H.Introspect("billing-rs", f.Clients["billing-rs"].Secret, key.Str("api_key")); in.Get("active") != true {
			t.Fatalf("api key: %s", in.Raw)
		}
		if in := f.H.Introspect("orders-rs", f.Clients["orders-rs"].Secret, key.Str("api_key")); in.Get("active") != false {
			t.Fatal("api key visible to a resource server of another audience")
		}
	})
	t.Run("OIDC-006 UserInfo audience", func(t *testing.T) {
		mustStatus(t, f.H.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: at}), 401, "business token at userinfo")
		ui := f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {orders.Tokens.Str("refresh_token")},
			"resource": {f.H.Realm.Issuer + "/userinfo"}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, ui, 200, "userinfo token via resource indicator")
		info := f.H.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: ui.Str("access_token")})
		mustStatus(t, info, 200, "userinfo")
		if info.Str("sub") != f.Users["alice"] {
			t.Fatalf("userinfo: %s", info.Raw)
		}
	})
}

// TestDiscoveryAccuracy covers TOK-001 for discovery: only the code response
// type with S256 PKCE is offered and the password and implicit grants are
// never advertised.
func TestDiscoveryAccuracy(t *testing.T) {
	f := NewFixture(t)
	d := f.H.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"})
	mustStatus(t, d, 200, "discovery")
	if d.Str("issuer") != f.H.Realm.Issuer {
		t.Fatal("issuer mismatch")
	}
	for _, g := range d.Get("grant_types_supported").([]any) {
		if g == "password" || g == "implicit" {
			t.Fatalf("unsupported grant advertised: %v", g)
		}
	}
	if rts := d.Get("response_types_supported").([]any); len(rts) != 1 || rts[0] != "code" {
		t.Fatal("only code is supported")
	}
	if pk := d.Get("code_challenge_methods_supported").([]any); len(pk) != 1 || pk[0] != "S256" {
		t.Fatal("only S256")
	}
	m := f.H.Do(Req{Method: "GET", Path: "/.well-known/oauth-authorization-server/realms/main"})
	mustStatus(t, m, 200, "RFC 8414 metadata")
	// Host header injection cannot change the issuer (TOK-022).
	req, _ := http.NewRequest("GET", f.H.Base+"/realms/main/.well-known/openid-configuration", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = jsonDecoder(res).Decode(&body)
	if body["issuer"] != f.H.Realm.Issuer {
		t.Fatalf("issuer derived from Host header: %v", body["issuer"])
	}
}

// browser simulates a user agent with cookies.
type browser struct {
	h      *Harness
	client *http.Client
}

func newBrowser(h *Harness) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{h: h, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(method, path string, body any, headers map[string]string) *Resp {
	saved := b.h.HTTP
	b.h.HTTP = b.client
	defer func() { b.h.HTTP = saved }()
	return b.h.Do(Req{Method: method, Path: path, JSON: body, Headers: headers})
}

// TestBrowserFlowCSRFSSOAndLogout covers SES-010's CSRF and origin controls
// (TEST-056: cookie-authenticated steps from a foreign Origin, without the CSRF
// token or with a wrong one are refused).
// Requirements: AUT-020 (the login UI gets only an opaque transaction ID, no
// continuation secret, and logout refuses an unregistered post-logout redirect).
// OIDC-003 (ID-token issuer, subject, audience, authorized party, expiry,
// issued-at, nonce, auth_time and at_hash), OIDC-004 (prompt=login and max_age
// force authentication; silent SSO keeps the genuine auth_time), OIDC-009 (an
// essential phishing-resistant acr request is not met by a password session).
func TestBrowserFlowCSRFSSOAndLogout(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	b := newBrowser(h)
	verifier, challenge := PKCE()
	authorize := func(extra url.Values) *Resp {
		q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
			"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme}}
		for k, v := range extra {
			q[k] = v
		}
		return b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil)
	}
	r := authorize(nil)
	mustStatus(t, r, 302, "authorize")
	loc, _ := url.Parse(r.Header.Get("Location"))
	if loc.Host != "login.test" {
		t.Fatalf("expected redirect to the login UI: %s", loc)
	}
	tx := loc.Query().Get("transaction_id")
	if strings.Contains(r.Header.Get("Location"), "pa_tx_") {
		t.Fatal("continuation secret leaked into a URL")
	}
	origin := map[string]string{"Origin": h.Base}
	st := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, nil)
	mustStatus(t, st, 200, "view transaction via cookie")
	csrf := st.Str("csrf_token")
	if csrf == "" {
		t.Fatal("csrf token not provided")
	}
	t.Run("TEST-056 forged cross-site requests", func(t *testing.T) {
		mustStatus(t, b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"},
			map[string]string{"Origin": "https://evil.test", "X-CSRF-Token": csrf}), 403, "foreign origin")
		mustStatus(t, b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"}, origin), 403, "missing CSRF")
		mustStatus(t, b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"},
			map[string]string{"Origin": h.Base, "X-CSRF-Token": "pa_csrf_wrong"}), 403, "wrong CSRF")
		// A transaction ID alone is not authority (AUT-003).
		mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/identify", JSON: map[string]any{"identifier": "x@y.z"}}), 400, "no continuation")
		// A verified custom domain is an allowed origin on its default port
		// only: another port on that host is another origin.
		ctx := context.Background()
		saved := realm.CustomDomainTXT
		defer func() { realm.CustomDomainTXT = saved }()
		cd, err := h.App.Realms.AddCustomDomain(ctx, h.Realm, "login.acme.test", audit.Ref{Type: "operator", ID: "test"})
		if err != nil {
			t.Fatal(err)
		}
		realm.CustomDomainTXT = func(context.Context, string) ([]string, error) { return []string{cd.Value}, nil }
		if _, err := h.App.Realms.VerifyCustomDomain(ctx, h.Realm, cd.Domain.ID, audit.Ref{Type: "operator", ID: "test"}); err != nil {
			t.Fatal(err)
		}
		mustStatus(t, b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"},
			map[string]string{"Origin": "https://login.acme.test:8443", "X-CSRF-Token": csrf}), 403, "custom domain on another port")
		if r := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": ""},
			map[string]string{"Origin": "https://login.acme.test", "X-CSRF-Token": csrf}); r.Status == 403 {
			t.Fatalf("verified custom domain refused as origin: %s", r.Raw)
		}
	})
	hdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": csrf}
	b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"}, hdr)
	done := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/password", map[string]any{"password": h.passwords["alice@example.test"]}, hdr)
	mustStatus(t, done, 200, "password")
	redirect, _ := url.Parse(done.Str("redirect_to"))
	if redirect.Query().Get("state") != "s1" || redirect.Query().Get("code") == "" {
		t.Fatalf("completion: %s", done.Raw)
	}
	tok := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {redirect.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {webRedirect}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, tok, 200, "tokens")
	idt := jwtPayload(tok.Str("id_token"))
	if idt["nonce"] != "n1" || idt["aud"] != "web-bff" || idt["auth_time"] == nil || idt["at_hash"] == nil {
		t.Fatalf("ID token: %v", idt)
	}
	// OIDC-003: the required claims, with the client as authorized party.
	if idt["iss"] != h.Realm.Issuer || idt["sub"] != f.Users["alice"] || idt["azp"] != "web-bff" || idt["iat"] == nil ||
		idt["exp"] == nil || idt["exp"].(float64) <= idt["iat"].(float64) {
		t.Fatalf("ID token claims: %v", idt)
	}

	t.Run("SES-014 SSO and prompt semantics", func(t *testing.T) {
		h.Clock.Advance(30 * time.Second)
		r := authorize(url.Values{"prompt": {"none"}, "state": {"s2"}})
		loc, _ := url.Parse(r.Header.Get("Location"))
		if loc.Host != "app.test" || loc.Query().Get("code") == "" {
			t.Fatalf("silent SSO failed: %s", r.Header.Get("Location"))
		}
		// OIDC-004: reusing the session keeps the genuine authentication time.
		sso := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {webRedirect}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, sso, 200, "silent SSO tokens")
		if at := jwtPayload(sso.Str("id_token"))["auth_time"]; at != idt["auth_time"] {
			t.Fatalf("silent SSO reported auth_time %v, the login was at %v", at, idt["auth_time"])
		}
		r = authorize(url.Values{"prompt": {"login"}})
		loc, _ = url.Parse(r.Header.Get("Location"))
		if loc.Host != "login.test" {
			t.Fatalf("prompt=login must require authentication: %s", r.Header.Get("Location"))
		}
		h.Clock.Advance(2 * time.Minute)
		r = authorize(url.Values{"max_age": {"60"}, "prompt": {"none"}})
		loc, _ = url.Parse(r.Header.Get("Location"))
		if loc.Query().Get("error") != "login_required" {
			t.Fatalf("max_age must force fresh authentication: %s", r.Header.Get("Location"))
		}
		// SES-002 per-client restriction: the client's own session-age bound
		// applies even when the request does not ask for max_age.
		setAge := func(n int) {
			if _, err := h.App.D.DB.Pool.Exec(context.Background(), `UPDATE clients SET token_policy = token_policy || jsonb_build_object('max_session_age_seconds', $1::int)
				WHERE client_id='web-bff'`, n); err != nil {
				t.Fatal(err)
			}
		}
		setAge(60)
		r = authorize(url.Values{"prompt": {"none"}})
		loc, _ = url.Parse(r.Header.Get("Location"))
		if loc.Query().Get("error") != "login_required" {
			t.Fatalf("client max_session_age_seconds ignored: %s", r.Header.Get("Location"))
		}
		setAge(0)
	})
	t.Run("OIDC-005 select_account and OIDC-008 claims", func(t *testing.T) {
		// With an SSO session, select_account stops for the user's choice.
		r := authorize(url.Values{"prompt": {"select_account"}, "state": {"s3"}})
		loc, _ := url.Parse(r.Header.Get("Location"))
		if loc.Host != "login.test" {
			t.Fatalf("select_account completed silently: %s", r.Header.Get("Location"))
		}
		stx := loc.Query().Get("transaction_id")
		view := b.do("GET", "/api/v1/realms/main/auth/transactions/"+stx, nil, nil)
		// Resp.Get does not index arrays: find the select_account action and
		// read its hint, which must be present and masked (OIDC-005).
		hint := ""
		actions, _ := view.Get("next_actions").([]any)
		for _, a := range actions {
			if act, _ := a.(map[string]any); act["type"] == "select_account" {
				opts, _ := act["options"].(map[string]any)
				cur, _ := opts["current_account"].(map[string]any)
				hint, _ = cur["email_hint"].(string)
			}
		}
		if !has(actionTypes(view), "select_account") || hint != "a***@example.test" {
			t.Fatalf("select_account state (email hint %q must be the masked address): %s", hint, view.Raw)
		}
		shdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": view.Str("csrf_token")}
		cont := b.do("POST", "/api/v1/realms/main/auth/transactions/"+stx+"/account", map[string]any{"continue": true}, shdr)
		if !strings.Contains(cont.Str("redirect_to"), "state=s3") {
			t.Fatalf("continuing with the current account: %s", cont.Raw)
		}
		// Switching accounts drops the session's identity.
		r = authorize(url.Values{"prompt": {"select_account"}, "state": {"s4"}})
		loc, _ = url.Parse(r.Header.Get("Location"))
		stx = loc.Query().Get("transaction_id")
		view = b.do("GET", "/api/v1/realms/main/auth/transactions/"+stx, nil, nil)
		shdr = map[string]string{"Origin": h.Base, "X-CSRF-Token": view.Str("csrf_token")}
		sw := b.do("POST", "/api/v1/realms/main/auth/transactions/"+stx+"/account", map[string]any{"continue": false}, shdr)
		if !has(actionTypes(sw), "identify") || sw.Str("redirect_to") != "" {
			t.Fatalf("switching accounts: %s", sw.Raw)
		}
		// claims: unsupported claim names are rejected; an essential acr request
		// raises the assurance requirement instead of being ignored.
		r = authorize(url.Values{"claims": {`{"id_token":{"secret_role":null}}`}})
		if loc, _ := url.Parse(r.Header.Get("Location")); loc.Query().Get("error") != "invalid_request" {
			t.Fatalf("unsupported claim accepted: %s", r.Header.Get("Location"))
		}
		r = authorize(url.Values{"prompt": {"none"}, "claims": {`{"id_token":{"acr":{"essential":true,"values":["urn:proudauth:acr:phishing_resistant"]}}}`}})
		if loc, _ := url.Parse(r.Header.Get("Location")); loc.Query().Get("code") != "" {
			t.Fatalf("essential phishing-resistant acr satisfied by a password session: %s", r.Header.Get("Location"))
		}
	})
	t.Run("SES-016 RP-initiated logout", func(t *testing.T) {
		bad := b.do("GET", "/realms/main/oidc/logout?id_token_hint="+tok.Str("id_token")+"&post_logout_redirect_uri="+url.QueryEscape("https://evil.test/"), nil, nil)
		mustStatus(t, bad, 400, "unregistered post-logout redirect")
		r := b.do("GET", "/realms/main/oidc/logout?id_token_hint="+tok.Str("id_token")+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test/bye")+"&state=x", nil, nil)
		mustStatus(t, r, 302, "logout")
		if !strings.HasPrefix(r.Header.Get("Location"), "https://app.test/bye") {
			t.Fatal("logout redirect")
		}
		r = authorize(url.Values{"prompt": {"none"}})
		loc, _ := url.Parse(r.Header.Get("Location"))
		if loc.Query().Get("error") != "login_required" {
			t.Fatalf("session survived logout: %s", r.Header.Get("Location"))
		}
		ref := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, ref, 400, "refresh after logout")
	})
}

func TestDeviceFlowAndPAR(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	start := func() *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/device_authorization", Form: url.Values{"client_id": {"proudauth-cli"},
			"scope": {"proudauth:account"}, "resource": {h.Realm.Issuer + "/account"}}})
	}
	poll := func(dc string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc}}, "proudauth-cli", "")
	}
	da := start()
	mustStatus(t, da, 200, "device authorization")
	dc := da.Str("device_code")
	if r := poll(dc); r.Str("error") != "authorization_pending" {
		t.Fatalf("pending: %s", r.Raw)
	}
	if r := poll(dc); r.Str("error") != "slow_down" {
		t.Fatalf("slow_down: %s", r.Raw)
	}
	// The user approves on another device; consent with the client name is always shown.
	tx := h.API("POST", "/auth/transactions", "", map[string]any{"device_user_code": da.Str("user_code")})
	mustStatus(t, tx, 201, "device transaction")
	if tx.Str("device_request.client_id") != "proudauth-cli" {
		t.Fatal("user-visible binding context missing")
	}
	st := h.Drive(tx.Str("transaction_id"), tx.Str("continuation_token"), &Resp{Status: 200, Body: tx.Get("state").(map[string]any)}, LoginOpts{Identifier: "bob@example.test"})
	if st.Str("status") != "completed" {
		t.Fatalf("device approval: %s", st.Raw)
	}
	h.Clock.Advance(6 * time.Second)
	tokens := poll(dc)
	mustStatus(t, tokens, 200, "device tokens")
	if r := poll(dc); r.Status == 200 {
		t.Fatal("TEST-068: device code replayed")
	}
	// Wrong client and expired codes.
	da2 := start()
	if r := h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da2.Str("device_code")}}, "web-bff", f.Clients["web"].Secret); r.Status == 200 {
		t.Fatal("device code redeemed by another client")
	}
	h.Clock.Advance(11 * time.Minute)
	if r := poll(da2.Str("device_code")); r.Str("error") != "expired_token" {
		t.Fatalf("expired: %s", r.Raw)
	}
	if r := h.API("POST", "/auth/transactions", "", map[string]any{"device_user_code": da2.Str("user_code")}); r.Status == 201 {
		t.Fatal("expired user code started a transaction")
	}
	// PAR: a pushed request is single use and bound to its client.
	h.Clock.Advance(time.Minute)
	_, challenge := PKCE()
	par := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/par", Basic: [2]string{"web-bff", f.Clients["web"].Secret}, Form: url.Values{
		"redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"orders:read"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {f.OrdersAud}}})
	mustStatus(t, par, 201, "PAR")
	ref := par.Str("request_uri")
	use := func() *Resp {
		return h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "request_uri": ref})
	}
	mustStatus(t, use(), 201, "use request_uri")
	if r := use(); r.Status == 201 {
		t.Fatal("request_uri reused")
	}
}

func TestDPoPBoundTokens(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := func(method, htu string) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
			(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		out, _ := jwt.Signed(s).Claims(map[string]any{"jti": secret.Numeric(12), "htm": method, "htu": htu, "iat": h.Clock.Now().Unix()}).Serialize()
		return out
	}
	tokenURL := h.Realm.Issuer + "/oauth/token"
	p := proof("POST", tokenURL)
	r := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"batch-job", f.Clients["batch"].Secret}, Headers: map[string]string{"DPoP": p},
		Form: url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}})
	mustStatus(t, r, 200, "DPoP token")
	claims := jwtPayload(r.Str("access_token"))
	cnf, _ := claims["cnf"].(map[string]any)
	if r.Str("token_type") != "DPoP" || cnf == nil || cnf["jkt"] == "" {
		t.Fatalf("token must be sender-constrained: %s", r.Raw)
	}
	// TEST-067: replayed proofs and proofs for another URI are rejected.
	again := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"batch-job", f.Clients["batch"].Secret}, Headers: map[string]string{"DPoP": p},
		Form: url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}})
	mustStatus(t, again, 400, "replayed DPoP proof")
	wrong := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"batch-job", f.Clients["batch"].Secret},
		Headers: map[string]string{"DPoP": proof("POST", "https://other.test/token")},
		Form:    url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}})
	mustStatus(t, wrong, 400, "DPoP proof for another URI")
	// A proof's required claim names and HTTP method are case-sensitive.
	// Duplicate claims and multiple proof headers cannot select an alternate
	// security interpretation of the same signed request.
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}
	for _, tc := range []struct{ name, payload string }{
		{"duplicate method", fmt.Sprintf(`{"jti":"duplicate-method","htm":"GET","htm":"POST","htu":%q,"iat":%d}`, tokenURL, h.Clock.Now().Unix())},
		{"case-shadowed method", fmt.Sprintf(`{"jti":"shadow-method","htm":"GET","HTM":"POST","htu":%q,"iat":%d}`, tokenURL, h.Clock.Now().Unix())},
		{"missing exact method", fmt.Sprintf(`{"jti":"missing-method","HTM":"POST","htu":%q,"iat":%d}`, tokenURL, h.Clock.Now().Unix())},
	} {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		obj, _ := signer.Sign([]byte(tc.payload))
		invalid, _ := obj.CompactSerialize()
		res := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"batch-job", f.Clients["batch"].Secret},
			Headers: map[string]string{"DPoP": invalid}, Form: form})
		if res.Status != 400 {
			t.Errorf("%s: HTTP %d, want 400", tc.name, res.Status)
		}
	}
	if res := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"batch-job", f.Clients["batch"].Secret},
		Headers: map[string]string{"DPoP": proof("post", tokenURL)}, Form: form}); res.Status != 400 {
		t.Errorf("case-folded HTTP method: HTTP %d, want 400", res.Status)
	}
	req, _ := http.NewRequest("POST", h.Base+"/realms/main/oauth/token", strings.NewReader(form.Encode()))
	req.SetBasicAuth("batch-job", f.Clients["batch"].Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("DPoP", proof("POST", tokenURL))
	req.Header.Add("DPoP", "invalid-second-proof")
	res, err := h.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Errorf("multiple proof headers: HTTP %d, want 400", res.StatusCode)
	}
	jkt := thumbprint(t, &key.PublicKey)
	if cnf["jkt"] != jkt {
		t.Fatal("cnf.jkt must be the proof key thumbprint")
	}
	// Token exchange reports the binding of the token it issues: DPoP with
	// a proof, Bearer without one.
	userAT := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	exchangeForm := func() url.Values {
		return url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {userAT},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}, "scope": {"billing:read"}}
	}
	bound := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"orders-rs", f.Clients["orders-rs"].Secret},
		Headers: map[string]string{"DPoP": proof("POST", tokenURL)}, Form: exchangeForm()})
	mustStatus(t, bound, 200, "DPoP-bound exchange")
	if c, _ := jwtPayload(bound.Str("access_token"))["cnf"].(map[string]any); bound.Str("token_type") != "DPoP" || c == nil || c["jkt"] != jkt {
		t.Fatalf("DPoP-bound exchange result: %s", bound.Raw)
	}
	plain := h.TokenRequest(exchangeForm(), "orders-rs", f.Clients["orders-rs"].Secret)
	mustStatus(t, plain, 200, "unbound exchange")
	if plain.Str("token_type") != "Bearer" || jwtPayload(plain.Str("access_token"))["cnf"] != nil {
		t.Fatalf("unbound exchange result: %s", plain.Raw)
	}
	// Introspection reports the binding the same way (RFC 9449 §6.2).
	for _, c := range []struct {
		token, want string
	}{{bound.Str("access_token"), "DPoP"}, {plain.Str("access_token"), "Bearer"}} {
		in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, c.token)
		if in.Get("active") != true || in.Str("token_type") != c.want {
			t.Fatalf("introspected token_type: want %s: %s", c.want, in.Raw)
		}
	}
	// The IdP's own APIs enforce the binding too (RFC 9449 §7).
	adminTok := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"orders-rs", f.Clients["orders-rs"].Secret},
		Headers: map[string]string{"DPoP": proof("POST", tokenURL)},
		Form:    url.Values{"grant_type": {"client_credentials"}, "resource": {h.Realm.Issuer + "/admin"}, "scope": {"proudauth:admin"}}})
	mustStatus(t, adminTok, 200, "DPoP admin token")
	at := adminTok.Str("access_token")
	checkURL := h.Base + "/api/v1/realms/main/authorization/check"
	body := map[string]any{"subject": map[string]any{"id": f.Users["bob"]}, "action": "orders.read", "resource": map[string]any{"type": "order"}}
	if r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/authorization/check", Token: at, JSON: body}); r.Status != 401 {
		t.Fatalf("DPoP-bound token accepted as a bearer token: %d", r.Status)
	}
	athProof := func() string {
		sum := sha256.Sum256([]byte(at))
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		out, _ := jwt.Signed(s).Claims(map[string]any{"jti": secret.Numeric(12), "htm": "POST", "htu": checkURL, "iat": h.Clock.Now().Unix(),
			"ath": base64.RawURLEncoding.EncodeToString(sum[:])}).Serialize()
		return out
	}
	ok := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/authorization/check", JSON: body,
		Headers: map[string]string{"Authorization": "DPoP " + at, "DPoP": athProof()}})
	if ok.Status != 200 {
		t.Fatalf("DPoP-bound token with a valid proof: %d %s", ok.Status, ok.Raw)
	}
	encoded, _ := json.Marshal(body)
	apiReq, _ := http.NewRequest("POST", checkURL, strings.NewReader(string(encoded)))
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("Authorization", "DPoP "+at)
	apiReq.Header.Add("DPoP", athProof())
	apiReq.Header.Add("DPoP", "invalid-second-proof")
	apiRes, err := h.HTTP.Do(apiReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, apiRes.Body)
	apiRes.Body.Close()
	if apiRes.StatusCode != 401 {
		t.Errorf("multiple proof headers at protected API: HTTP %d, want 401", apiRes.StatusCode)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key = other // a proof from a different key must fail
	if r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/authorization/check", JSON: body,
		Headers: map[string]string{"Authorization": "DPoP " + at, "DPoP": athProof()}}); r.Status != 401 {
		t.Fatalf("proof from another key accepted: %d", r.Status)
	}
}

func thumbprint(t *testing.T, pub *ecdsa.PublicKey) string {
	k := jose.JSONWebKey{Key: pub}
	tp, err := k.Thumbprint(cryptoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

var _ = sha256.Sum256

// TestConcurrentBrowserTransactions covers AUT-016: two tabs of one browser
// run separate transactions (different clients and organizations) without one
// overwriting or completing the other.
func TestConcurrentBrowserTransactions(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	b := newBrowser(h)
	_, challenge := PKCE()
	start := func(org, state string) string {
		q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
			"state": {state}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {org}}
		r := b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil)
		mustStatus(t, r, 302, "authorize "+state)
		loc, _ := url.Parse(r.Header.Get("Location"))
		return loc.Query().Get("transaction_id")
	}
	tab1 := start(f.Acme, "tab1")
	tab2 := start(f.Globex, "tab2")
	if tab1 == tab2 {
		t.Fatal("tabs share a transaction")
	}
	csrf := map[string]string{}
	for _, tx := range []string{tab1, tab2} {
		st := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, nil)
		mustStatus(t, st, 200, "view "+tx)
		csrf[tx] = st.Str("csrf_token")
	}
	hdr := func(tx string) map[string]string {
		return map[string]string{"Origin": h.Base, "X-CSRF-Token": csrf[tx]}
	}
	b.do("POST", "/api/v1/realms/main/auth/transactions/"+tab1+"/identify", map[string]any{"identifier": "bob@example.test"}, hdr(tab1))
	done := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tab1+"/password", map[string]any{"password": h.passwords["bob@example.test"]}, hdr(tab1))
	if !strings.Contains(done.Str("redirect_to"), "state=tab1") {
		t.Fatalf("tab 1 did not complete its own flow: %s", done.Raw)
	}
	// Tab 2 still has its own pending transaction, bound to its organization;
	// tab 1's CSRF token cannot drive it.
	st := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tab2, nil, nil)
	if st.Status != 200 || st.Str("status") != "pending" {
		t.Fatalf("tab 2 lost its transaction: %d %s", st.Status, st.Raw)
	}
	mustStatus(t, b.do("POST", "/api/v1/realms/main/auth/transactions/"+tab2+"/identify", map[string]any{"identifier": "bob@example.test"}, hdr(tab1)), 403,
		"another tab's CSRF token")
}

// TestBrowserRegistration covers REG-001 for browser login surfaces: the
// transaction cookie is scoped to the transaction's path, so registration runs
// on the transaction-scoped route with the same Origin and CSRF protection as
// every other step.
func TestBrowserRegistration(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) {
		p.Interaction.LoginUIURL = "https://login.test/ui"
		p.Registration.Mode = "public"
	})
	h := f.H
	b := newBrowser(h)
	_, challenge := PKCE()
	q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"reg"}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	r := b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil)
	mustStatus(t, r, 302, "authorize")
	loc, _ := url.Parse(r.Header.Get("Location"))
	tx := loc.Query().Get("transaction_id")
	st := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, nil)
	mustStatus(t, st, 200, "view transaction")
	path := "/api/v1/realms/main/auth/transactions/" + tx + "/registration"
	body := map[string]any{"email": "wren@example.test", "password": "wren has a long passphrase 2026"}
	mustStatus(t, b.do("POST", path, body, map[string]string{"Origin": h.Base}), 403, "registration without CSRF")
	mustStatus(t, b.do("POST", path, body, map[string]string{"Origin": "https://evil.test", "X-CSRF-Token": st.Str("csrf_token")}), 403, "foreign origin")
	reg := b.do("POST", path, body, map[string]string{"Origin": h.Base, "X-CSRF-Token": st.Str("csrf_token")})
	mustStatus(t, reg, 200, "browser registration")
	if reg.Str("status") != "pending" || !hasAction(reg, "verify_email") {
		t.Fatalf("registration did not continue to email verification: %s", reg.Raw)
	}
	done := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/otp/verify", map[string]any{"code": CodeFrom(h.Mail("wren@example.test", "email_verification"))},
		map[string]string{"Origin": h.Base, "X-CSRF-Token": st.Str("csrf_token")})
	if !strings.Contains(done.Str("redirect_to"), "state=reg") {
		t.Fatalf("browser registration did not complete: %d %s", done.Status, done.Raw)
	}
}

// TestPersonalTokenCeiling covers MCH-006: personal tokens never exceed the
// owner's current authority (checked at creation and on every introspection)
// and organizations can disable or bound them.
func TestPersonalTokenCeiling(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.must(f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:refund", "required_permissions": []string{"orders.refund"}}), 201, "scope")
	pat := func(user, scope string) *Resp {
		tok := f.AccountToken(user).Tokens.Str("access_token")
		return h.API("POST", "/me/personal-tokens", tok, map[string]any{"name": "ci", "audience": f.OrdersAud, "scopes": []string{scope},
			"organization_id": f.Acme, "ttl_days": 30})
	}
	if r := pat("bob", "orders:refund"); r.Status != 403 {
		t.Fatalf("personal token above the owner's authority: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, pat("bob", "orders:read"), 201, "within authority")
	alice := pat("alice", "orders:refund")
	mustStatus(t, alice, 201, "refunder token")
	in := func() *Resp { return h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, alice.Str("token")) }
	if in().Get("active") != true {
		t.Fatal("valid personal token inactive")
	}
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_scopes": []string{"orders:read"},
			"personal_tokens": "disabled"}}}), 200, "narrow organization policy")
	if r := in(); r.Get("active") != false {
		t.Fatalf("personal token kept a scope its owner no longer qualifies for: %s", r.Raw)
	}
	if r := pat("bob", "orders:read"); r.Status != 403 {
		t.Fatalf("personal token created where the organization disabled them: %d", r.Status)
	}
}

// TestCredentialInventory covers MCH-007, MCH-016 and APP-014: credentials of
// departed owners, over-privileged keys and unmanaged client secrets are
// flagged, and the inventory supports bulk revocation with per-item results.
func TestCredentialInventory(t *testing.T) {
	f := NewFixture(t)
	f.CreateUser("dave")
	bot := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "inv-bot", "allowed_organization_ids": []string{f.Acme},
		"owner_user_id": f.Users["dave"]}), 201, "sp")
	key := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": bot.Str("id"), "name": "inv",
		"audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme}), 201, "api key")
	keyID := key.Str("credential.id")
	f.must(f.AdminAPI("POST", "/users/"+f.Users["dave"]+"/suspend", map[string]any{"reason": "left the company"}), 200, "owner leaves")
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, f.H.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_scopes": []string{"orders:read"}}}}), 200, "narrow scopes")
	inv := f.must(f.AdminAPI("GET", "/credential-inventory?limit=200", nil), 200, "inventory")
	flags := map[string][]any{}
	var clientSecret string
	for _, it := range inv.Get("items").([]any) {
		m := it.(map[string]any)
		flags[m["id"].(string)], _ = m["flags"].([]any)
		if m["kind"] == "client_secret" && m["name"] == "web-bff" {
			clientSecret = m["id"].(string)
		}
	}
	has := func(id, flag string) bool {
		for _, f := range flags[id] {
			if f == flag {
				return true
			}
		}
		return false
	}
	if !has(keyID, "owner_departed") || !has(keyID, "over_privileged") {
		t.Fatalf("api key flags: %v", flags[keyID])
	}
	if clientSecret == "" || !has(clientSecret, "no_expiry") {
		t.Fatalf("unmanaged client secret not inventoried: %s", inv.Raw)
	}
	res := f.must(f.AdminAPI("POST", "/credential-inventory/revocations", map[string]any{"ids": []string{keyID, "akc_does_not_exist"},
		"reason": "offboarding cleanup"}), 200, "bulk revoke")
	out := res.Get("results").([]any)
	if out[0].(map[string]any)["status"] != "revoked" || out[1].(map[string]any)["status"] != "failed" {
		t.Fatalf("per-item results: %s", res.Raw)
	}
	if in := f.H.Introspect("billing-rs", f.Clients["billing-rs"].Secret, key.Str("api_key")); in.Get("active") != false {
		t.Fatal("bulk-revoked key still active")
	}
}
