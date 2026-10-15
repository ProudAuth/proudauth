package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
)

// TestCheckSessionIframe covers OIDC-014: OpenID Connect Session Management
// is off unless the realm turns it on; then discovery names the iframe,
// authorization responses carry session_state bound to the client and the
// RP origin, the iframe only answers registered origins, and logout clears
// the browser state.
func TestCheckSessionIframe(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	disc := func() *Resp { return h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}) }
	if d := disc(); d.Get("check_session_iframe") != nil {
		t.Fatalf("session management advertised by default: %v", d.Get("check_session_iframe"))
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/check-session"}), 404, "iframe off")
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: "alice"})
	if strings.Contains(lr.State.Str("redirect_to"), "session_state") {
		t.Fatal("session_state returned while session management is off")
	}

	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Sessions.CheckSessionIframe = true }), 200, "enable")
	if d := disc(); d.Str("check_session_iframe") != h.Realm.Issuer+"/oidc/check-session" {
		t.Fatalf("discovery: %v", d.Get("check_session_iframe"))
	}
	page := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/check-session"})
	mustStatus(t, page, 200, "iframe")
	csp := page.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'sha256-") || !strings.Contains(csp, "frame-ancestors *") || page.Header.Get("X-Frame-Options") != "" ||
		!strings.Contains(string(page.Raw), "pa_opbs") || !strings.Contains(string(page.Raw), "postMessage") {
		t.Fatalf("iframe page: %s %s", page.Header, page.Raw)
	}
	allowed := func(client, origin string) any {
		r := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/check-session/origin?client_id=" + url.QueryEscape(client) + "&origin=" + url.QueryEscape(origin)})
		mustStatus(t, r, 200, "origin check")
		return r.Get("allowed")
	}
	if allowed("web-bff", "https://app.test") != true || allowed("web-bff", "https://evil.test") != false || allowed("nope", "https://app.test") != false {
		t.Fatal("origin check")
	}

	// A browser sign-in sets a script-readable browser-state cookie and
	// returns a session_state the iframe can recompute.
	b := newBrowser(h)
	verifier, challenge := PKCE()
	_ = verifier
	authorize := func(extra url.Values) *Resp {
		q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
			"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme}}
		for k, v := range extra {
			q[k] = v
		}
		return b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil)
	}
	r := authorize(nil)
	loc, _ := url.Parse(r.Header.Get("Location"))
	tx := loc.Query().Get("transaction_id")
	csrf := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, nil).Str("csrf_token")
	hdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": csrf}
	b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"}, hdr)
	done := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/password", map[string]any{"password": h.passwords["alice@example.test"]}, hdr)
	mustStatus(t, done, 200, "password")
	var opbsLine string
	for _, c := range done.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "pa_opbs=") {
			opbsLine = c
		}
	}
	if opbsLine == "" || strings.Contains(opbsLine, "HttpOnly") || !strings.Contains(opbsLine, "Path=/realms/main/") {
		t.Fatalf("browser-state cookie: %q", opbsLine)
	}
	opbs := strings.TrimPrefix(strings.SplitN(opbsLine, ";", 2)[0], "pa_opbs=")
	check := func(redirect, origin string) bool {
		u, _ := url.Parse(redirect)
		hash, salt, ok := strings.Cut(u.Query().Get("session_state"), ".")
		if !ok {
			t.Fatalf("no session_state in %s", redirect)
		}
		sum := sha256.Sum256([]byte("web-bff " + origin + " " + opbs + " " + salt))
		return hex.EncodeToString(sum[:]) == hash
	}
	first := done.Str("redirect_to")
	if !check(first, "https://app.test") || check(first, "https://evil.test") {
		t.Fatalf("session_state does not verify for the RP origin only: %s", first)
	}
	// Silent re-authentication returns a fresh salt for the same state.
	r = authorize(url.Values{"prompt": {"none"}, "state": {"s2"}})
	silent := r.Header.Get("Location")
	if !check(silent, "https://app.test") || silent == first {
		t.Fatalf("silent response session_state: %s", silent)
	}
	// The cookie never carries the session secret.
	for _, c := range b.client.Jar.Cookies(mustURL(h.Base + "/realms/main/")) {
		if c.Name == "pa_sid" && c.Value == opbs {
			t.Fatal("browser state equals the session cookie")
		}
	}

	// Logout clears the browser state, which the iframe reports as changed.
	code, _ := url.Parse(silent)
	tok := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {webRedirect}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, tok, 200, "tokens")
	out := b.do("GET", "/realms/main/oidc/logout?id_token_hint="+tok.Str("id_token")+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test/bye"), nil, nil)
	mustStatus(t, out, http.StatusFound, "logout")
	cleared := false
	for _, c := range out.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "pa_opbs=;") && strings.Contains(c, "Max-Age=0") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("browser state not cleared: %v", out.Header.Values("Set-Cookie"))
	}
}
