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
	"github.com/proudauth/proudauth/internal/configuration"
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

// TestDeviceFlowAndPAR covers the device authorization grant (TEST-068:
// device codes are single use, bound to their client, throttled with
// slow_down and expire) and pushed authorization requests: a request_uri is
// single use and bound to the pushing client, and another client presenting
// it neither uses nor spends it.
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
	// Presented with another client's client_id, an unknown one or none, the
	// reference is refused without being spent (RFC 9126 §4), at the
	// headless API and at the authorization endpoint alike: the pushing
	// client can still use it, once.
	for _, other := range []string{"proudauth-cli", "no-such-client", ""} {
		if r := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": other, "request_uri": ref}); r.Status != 400 {
			t.Fatalf("request_uri presented with client_id %q: %d %s", other, r.Status, r.Raw)
		}
		az := h.Do(Req{Method: "GET", Path: "/realms/main/oauth/authorize?" + url.Values{"client_id": {other}, "request_uri": {ref}}.Encode()})
		if az.Status != 400 || az.Str("error") != "invalid_request" || az.Header.Get("Location") != "" {
			t.Fatalf("authorization request with request_uri and client_id %q: %d %s", other, az.Status, az.Raw)
		}
	}
	mustStatus(t, use(), 201, "use request_uri after another client's attempts")
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

// dpopProof signs a DPoP proof (RFC 9449 §4.2) with key for one request.
// Signing with a generated P-256 key cannot fail, so errors are ignored, as
// in TestDPoPBoundTokens.
func dpopProof(h *Harness, key *ecdsa.PrivateKey, method, htu string) string {
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	out, _ := jwt.Signed(s).Claims(map[string]any{"jti": secret.Numeric(12), "htm": method, "htu": htu, "iat": h.Clock.Now().Unix()}).Serialize()
	return out
}

// refreshBinding returns the family of a refresh token and the sender
// binding stored with it (cnf_jkt, cnf_x5t_s256; "" for NULL).
func refreshBinding(t *testing.T, h *Harness, refreshToken string) (family, jkt, x5t string) {
	t.Helper()
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT f.id, coalesce(f.cnf_jkt, ''), coalesce(f.cnf_x5t_s256, '')
		FROM refresh_families f JOIN refresh_tokens t ON t.family_id=f.id WHERE t.token_digest=$1`, secret.Digest(refreshToken)).Scan(&family, &jkt, &x5t); err != nil {
		t.Fatalf("family of refresh token: %v", err)
	}
	return family, jkt, x5t
}

// mustInvalidGrant fails unless r is 400 invalid_grant.
func mustInvalidGrant(t *testing.T, r *Resp, what string) {
	t.Helper()
	if r.Status != 400 || r.Str("error") != "invalid_grant" {
		t.Fatalf("%s: %d %s, want 400 invalid_grant", what, r.Status, r.Raw)
	}
}

// TestSenderBoundRefreshFamilies covers owner decision 13 of 0.2.0-alpha.6
// (TOK-019, SES-006, TEST-067; RFC 9449 §5, RFC 8705 §3): a refresh family
// whose first issuance was bound to a DPoP key or a TLS client certificate
// stores that binding (refresh_families.cnf_jkt and cnf_x5t_s256, migration
// 0089), and every later refresh must prove the same key or certificate,
// whatever the client's require_dpop or certificate policy says: a proof of
// another key, another certificate or none is invalid_grant. A refusal is
// not a reuse signal: it neither rotates nor compromises the family, so the
// holder keeps refreshing, and it is audited as token.refresh.binding_failed.
// Rotation keeps the family and its binding. A family without a binding (a
// bearer family, or one issued before the change) refreshes as before.
func TestSenderBoundRefreshFamilies(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Server.ClientCertHeader = "X-Client-Cert"
		c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	})
	f := fixtureOn(t, h)
	ctx := context.Background()
	tokenURL := h.Realm.Issuer + "/oauth/token"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jkt := thumbprint(t, &key.PublicKey)
	webToken := func(form url.Values, k *ecdsa.PrivateKey) *Resp {
		t.Helper()
		rq := Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"web-bff", f.Clients["web"].Secret}, Form: form}
		if k != nil {
			rq.Headers = map[string]string{"DPoP": dpopProof(h, k, "POST", tokenURL)}
		}
		return h.Do(rq)
	}
	refresh := func(rt string, k *ecdsa.PrivateKey) *Resp {
		t.Helper()
		return webToken(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, k)
	}
	loginDPoP := func(t *testing.T, user string) string {
		t.Helper()
		code, verifier := f.codeFor(t, user)
		r := webToken(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {webRedirect}}, key)
		mustStatus(t, r, 200, "code redemption with a DPoP proof")
		if r.Str("token_type") != "DPoP" || r.Str("refresh_token") == "" {
			t.Fatalf("DPoP-bound tokens: %s", r.Raw)
		}
		return r.Str("refresh_token")
	}

	t.Run("DPoP-bound family", func(t *testing.T) {
		rt := loginDPoP(t, "bob")
		family, boundJKT, boundX5T := refreshBinding(t, h, rt)
		if boundJKT != jkt || boundX5T != "" {
			t.Fatalf("stored binding cnf_jkt %q, cnf_x5t_s256 %q; want cnf_jkt %q", boundJKT, boundX5T, jkt)
		}
		mustInvalidGrant(t, refresh(rt, otherKey), "refresh with a proof from another key")
		// web-bff has no require_dpop: before the binding, a refresh
		// without a proof got a bearer token from a DPoP-bound family.
		mustInvalidGrant(t, refresh(rt, nil), "refresh without a proof")
		next := refresh(rt, key)
		mustStatus(t, next, 200, "refresh with the bound key after refused attempts")
		if c, _ := jwtPayload(next.Str("access_token"))["cnf"].(map[string]any); next.Str("token_type") != "DPoP" || c == nil || c["jkt"] != jkt {
			t.Fatalf("refreshed tokens are not bound to the key: %s", next.Raw)
		}
		rt2 := next.Str("refresh_token")
		if rt2 == "" || rt2 == rt {
			t.Fatal("the refresh token must rotate")
		}
		if fam, j, x := refreshBinding(t, h, rt2); fam != family || j != jkt || x != "" {
			t.Fatalf("after rotation: family %s, cnf_jkt %q, cnf_x5t_s256 %q; want family %s bound to %q", fam, j, x, family, jkt)
		}
		// The consumed generation, presented without the key, is refused as
		// a binding failure and not treated as reuse: the holder's family
		// is not revoked by someone who cannot use the token.
		mustInvalidGrant(t, refresh(rt, otherKey), "consumed generation with another key")
		mustInvalidGrant(t, refresh(rt, nil), "consumed generation without a proof")
		third := refresh(rt2, key)
		mustStatus(t, third, 200, "the holder refreshes after refused presentations of its old token")
		// With the key, reuse detection is unchanged.
		mustInvalidGrant(t, refresh(rt2, key), "reuse of a consumed generation with the bound key")
		mustInvalidGrant(t, refresh(third.Str("refresh_token"), key), "the family after reuse")
		var state string
		var failures int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, (SELECT count(*) FROM audit_events WHERE type='token.refresh.binding_failed'
			AND reason_code='REFRESH_BINDING_FAILED' AND metadata->>'token_family_id'=$1 AND metadata->>'binding'='dpop') FROM refresh_families WHERE id=$1`,
			family).Scan(&state, &failures); err != nil {
			t.Fatal(err)
		}
		if state != "compromised" || failures != 4 {
			t.Fatalf("family state %q with %d audited binding failures; want compromised (by the reuse) and 4", state, failures)
		}
	})

	t.Run("certificate-bound family", func(t *testing.T) {
		_, cert, certPEM := issue(t, nil, "bound-web", "")
		_, _, otherPEM := issue(t, nil, "someone-else", "")
		withCert := func(p string) map[string]string { return map[string]string{"X-Client-Cert": url.QueryEscape(p)} }
		reg := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "bound-web", "name": "Certificate-bound web", "client_type": "confidential",
			"first_party": true, "grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{"https://app.test/cb"},
			"tls_client_certificate_bound_access_tokens": true}), 201, "certificate-bound client")
		for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
			if m := it.(map[string]any); m["kind"] == "userinfo" {
				f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid"}}), 204, "grant")
			}
		}
		clientSecret := reg.Str("client_secret")
		token := func(form url.Values, headers map[string]string) *Resp {
			t.Helper()
			return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form, Basic: [2]string{"bound-web", clientSecret}, Headers: headers})
		}
		refresh := func(rt string, headers map[string]string) *Resp {
			t.Helper()
			return token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, headers)
		}
		start, verifier, cont := h.StartTx(LoginOpts{ClientID: "bound-web", RedirectURI: "https://app.test/cb", Scope: "openid"})
		done := h.Drive(start.Str("transaction_id"), cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, LoginOpts{Identifier: "bob@example.test"})
		code, _ := url.Parse(done.Str("redirect_to"))
		first := token(url.Values{"grant_type": {"authorization_code"}, "code": {code.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {"https://app.test/cb"}}, withCert(certPEM))
		mustStatus(t, first, 200, "certificate-bound tokens")
		rt := first.Str("refresh_token")
		family, j, x := refreshBinding(t, h, rt)
		if x != x5t(cert) || j != "" {
			t.Fatalf("stored binding cnf_jkt %q, cnf_x5t_s256 %q; want cnf_x5t_s256 %q", j, x, x5t(cert))
		}
		mustInvalidGrant(t, refresh(rt, withCert(otherPEM)), "refresh with another certificate")
		next := refresh(rt, withCert(certPEM))
		mustStatus(t, next, 200, "refresh with the bound certificate")
		if c, _ := jwtPayload(next.Str("access_token"))["cnf"].(map[string]any); c == nil || c["x5t#S256"] != x5t(cert) {
			t.Fatalf("refreshed access token is not bound to the certificate: %s", next.Raw)
		}
		rt = next.Str("refresh_token")
		if fam, j, x := refreshBinding(t, h, rt); fam != family || x != x5t(cert) || j != "" {
			t.Fatalf("after rotation: family %s, cnf_jkt %q, cnf_x5t_s256 %q", fam, j, x)
		}
		// The binding belongs to the family, not to the client's current
		// policy: with certificate-bound tokens turned off, a refresh
		// without the certificate (or with a DPoP proof instead) is still
		// refused.
		if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE clients SET protocol_options = protocol_options - 'tls_client_certificate_bound_access_tokens'
			WHERE realm_id=$1 AND client_id='bound-web'`, h.Realm.ID); err != nil {
			t.Fatal(err)
		}
		mustInvalidGrant(t, refresh(rt, nil), "refresh without a certificate after the client's policy changed")
		mustInvalidGrant(t, refresh(rt, map[string]string{"DPoP": dpopProof(h, key, "POST", tokenURL)}), "refresh with a DPoP proof instead of the certificate")
		mustInvalidGrant(t, refresh(rt, withCert(otherPEM)), "refresh with another certificate after the client's policy changed")
		mustStatus(t, refresh(rt, withCert(certPEM)), 200, "refresh with the bound certificate after the client's policy changed")
	})

	t.Run("unbound families refresh as before", func(t *testing.T) {
		// A bearer family: its first issuance had no sender constraint.
		rt := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
		if _, j, x := refreshBinding(t, h, rt); j != "" || x != "" {
			t.Fatalf("a bearer family got a binding: %q %q", j, x)
		}
		mustStatus(t, refresh(rt, nil), 200, "bearer family without a proof")
		// A family issued before the change: DPoP-bound tokens, no stored
		// binding (what migration 0089 leaves on existing rows).
		legacy := loginDPoP(t, "alice")
		family, _, _ := refreshBinding(t, h, legacy)
		if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE refresh_families SET cnf_jkt=NULL, cnf_x5t_s256=NULL WHERE id=$1`, family); err != nil {
			t.Fatal(err)
		}
		bearer := refresh(legacy, nil)
		mustStatus(t, bearer, 200, "legacy family without a proof")
		if bearer.Str("token_type") != "Bearer" {
			t.Fatalf("legacy family refreshed without a proof: %s", bearer.Raw)
		}
		// Rotation does not bind a family that was issued unbound.
		next := bearer.Str("refresh_token")
		if _, j, x := refreshBinding(t, h, next); j != "" || x != "" {
			t.Fatalf("rotation bound a legacy family: %q %q", j, x)
		}
		mustStatus(t, refresh(next, otherKey), 200, "legacy family with any key")
	})
}

// TestDPoPBoundAuthorizationCodes covers the dpop_jkt authorization-code
// binding (RFC 9449 §10, TOK-019, owner decision 13): an authorization
// request that names dpop_jkt, at the authorization endpoint, in a pushed
// request or through the headless API, gets a code that only a DPoP proof
// of that key redeems. A DPoP proof sent with the pushed request binds the
// code to its key the same way (RFC 9449 §10.1), and a pushed request whose
// dpop_jkt names another key is refused. A bound code redeemed with another
// key or without a proof is invalid_grant and spent, like the other code
// binding failures; codes without dpop_jkt are unchanged.
func TestDPoPBoundAuthorizationCodes(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	tokenURL, parURL := h.Realm.Issuer+"/oauth/token", h.Realm.Issuer+"/oauth/par"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jkt := thumbprint(t, &key.PublicKey)
	bound := url.Values{"dpop_jkt": {jkt}}
	redeem := func(code, verifier string, k *ecdsa.PrivateKey) *Resp {
		t.Helper()
		rq := Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"web-bff", f.Clients["web"].Secret},
			Form: url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {webRedirect}}}
		if k != nil {
			rq.Headers = map[string]string{"DPoP": dpopProof(h, k, "POST", tokenURL)}
		}
		return h.Do(rq)
	}
	params := func(challenge string, extra url.Values) url.Values {
		q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
			"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme}}
		for k, v := range extra {
			q[k] = v
		}
		return q
	}
	codeOf := func(t *testing.T, st *Resp) string {
		t.Helper()
		u, _ := url.Parse(st.Str("redirect_to"))
		if u == nil || u.Query().Get("code") == "" {
			t.Fatalf("no code: %d %s", st.Status, st.Raw)
		}
		return u.Query().Get("code")
	}
	// Sign-ins are spread over two users so that no subtest meets the
	// per-identifier password budget.
	viaAuthorize := func(t *testing.T, user string, extra url.Values) (code, verifier string) {
		t.Helper()
		verifier, challenge := PKCE()
		b := newBrowser(h)
		r := b.do("GET", "/realms/main/oauth/authorize?"+params(challenge, extra).Encode(), nil, nil)
		mustStatus(t, r, 302, "authorize")
		loc, _ := url.Parse(r.Header.Get("Location"))
		return codeOf(t, b.drive(t, loc.Query().Get("transaction_id"), user+"@example.test")), verifier
	}
	headless := func(t *testing.T, user string, start *Resp) string {
		t.Helper()
		mustStatus(t, start, 201, "start transaction")
		return codeOf(t, h.Drive(start.Str("transaction_id"), start.Str("continuation_token"), &Resp{Status: 200, Body: start.Get("state").(map[string]any)},
			LoginOpts{Identifier: user + "@example.test", SelectOrg: f.Acme}))
	}
	push := func(challenge string, extra url.Values, k *ecdsa.PrivateKey) *Resp {
		t.Helper()
		rq := Req{Method: "POST", Path: "/realms/main/oauth/par", Basic: [2]string{"web-bff", f.Clients["web"].Secret}, Form: params(challenge, extra)}
		if k != nil {
			rq.Headers = map[string]string{"DPoP": dpopProof(h, k, "POST", parURL)}
		}
		return h.Do(rq)
	}
	viaPAR := func(t *testing.T, extra url.Values, k *ecdsa.PrivateKey) (code, verifier string) {
		t.Helper()
		verifier, challenge := PKCE()
		par := push(challenge, extra, k)
		mustStatus(t, par, 201, "PAR")
		return headless(t, "alice", h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "request_uri": par.Str("request_uri")})), verifier
	}
	issued := func(t *testing.T, r *Resp) {
		t.Helper()
		mustStatus(t, r, 200, "code redeemed with the bound key")
		if c, _ := jwtPayload(r.Str("access_token"))["cnf"].(map[string]any); r.Str("token_type") != "DPoP" || c == nil || c["jkt"] != jkt {
			t.Fatalf("tokens of a DPoP-bound code: %s", r.Raw)
		}
		// The refresh family starts bound to the same key (owner decision 13).
		if _, j, _ := refreshBinding(t, h, r.Str("refresh_token")); j != jkt {
			t.Fatalf("refresh family bound to %q, want %q", j, jkt)
		}
	}

	t.Run("authorization endpoint", func(t *testing.T) {
		code, verifier := viaAuthorize(t, "bob", bound)
		mustInvalidGrant(t, redeem(code, verifier, otherKey), "code redeemed with another key")
		mustInvalidGrant(t, redeem(code, verifier, key), "the code after a binding failure")
		code, verifier = viaAuthorize(t, "bob", bound)
		mustInvalidGrant(t, redeem(code, verifier, nil), "code redeemed without a proof")
		code, verifier = viaAuthorize(t, "bob", bound)
		issued(t, redeem(code, verifier, key))
		// A dpop_jkt that is not a JWK SHA-256 thumbprint is refused at the
		// client's redirect.
		_, challenge := PKCE()
		r := newBrowser(h).do("GET", "/realms/main/oauth/authorize?"+params(challenge, url.Values{"dpop_jkt": {"not-a-thumbprint"}}).Encode(), nil, nil)
		loc, _ := url.Parse(r.Header.Get("Location"))
		if r.Status != 302 || loc == nil || loc.Host != "app.test" || loc.Query().Get("error") != "invalid_request" {
			t.Fatalf("malformed dpop_jkt: %d %s", r.Status, r.Header.Get("Location"))
		}
	})

	t.Run("pushed authorization request", func(t *testing.T) {
		code, verifier := viaPAR(t, bound, nil)
		mustInvalidGrant(t, redeem(code, verifier, otherKey), "pushed dpop_jkt, code redeemed with another key")
		code, verifier = viaPAR(t, bound, nil)
		issued(t, redeem(code, verifier, key))
		// A DPoP proof with the pushed request binds the code to its key.
		code, verifier = viaPAR(t, nil, key)
		mustInvalidGrant(t, redeem(code, verifier, otherKey), "proof at PAR, code redeemed with another key")
		code, verifier = viaPAR(t, nil, key)
		mustInvalidGrant(t, redeem(code, verifier, nil), "proof at PAR, code redeemed without a proof")
		code, verifier = viaPAR(t, bound, key)
		issued(t, redeem(code, verifier, key))
		// dpop_jkt and a proof of another key in one pushed request.
		_, challenge := PKCE()
		if r := push(challenge, bound, otherKey); r.Status != 400 || r.Str("error") != "invalid_request" {
			t.Fatalf("dpop_jkt naming another key than the proof: %d %s", r.Status, r.Raw)
		}
		if r := push(challenge, url.Values{"dpop_jkt": {"not-a-thumbprint"}}, nil); r.Status != 400 || r.Str("error") != "invalid_request" {
			t.Fatalf("malformed dpop_jkt at PAR: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("headless API", func(t *testing.T) {
		start := func() (*Resp, string) {
			verifier, challenge := PKCE()
			return h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "openid orders:read",
				"code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{f.OrdersAud}, "organization": f.Acme, "dpop_jkt": jkt}), verifier
		}
		st, verifier := start()
		mustInvalidGrant(t, redeem(headless(t, "bob", st), verifier, otherKey), "headless dpop_jkt, code redeemed with another key")
		st, verifier = start()
		issued(t, redeem(headless(t, "bob", st), verifier, key))
	})

	t.Run("codes without dpop_jkt are unchanged", func(t *testing.T) {
		code, verifier := f.codeFor(t, "alice")
		mustStatus(t, redeem(code, verifier, otherKey), 200, "an unbound code with any DPoP key")
		code, verifier = f.codeFor(t, "alice")
		mustStatus(t, redeem(code, verifier, nil), 200, "an unbound code without a proof")
	})
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
