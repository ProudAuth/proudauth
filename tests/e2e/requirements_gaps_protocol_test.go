package e2e

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
)

// gapTokenStrings collects every string value that looks like a bearer
// credential (an opaque pa_ token or a compact JWT) and every member named
// refresh_token or id_token, whatever its value.
func gapTokenStrings(v any, tokens *[]string, members *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if k == "refresh_token" || k == "id_token" {
				*members = append(*members, k)
			}
			gapTokenStrings(val, tokens, members)
		}
	case []any:
		for _, val := range x {
			gapTokenStrings(val, tokens, members)
		}
	case string:
		if strings.HasPrefix(x, "pa_") || (strings.HasPrefix(x, "eyJ") && strings.Count(x, ".") == 2) {
			*tokens = append(*tokens, x)
		}
	}
}

// TestSupportSessionSeparation covers IMP-019: support access runs in its
// own context. The operator signs in at the IdP in a browser; issuing
// support access and redeeming a handoff return only the support token —
// no refresh token, no ID token, no token of the operator — and afterwards
// the operator's access and refresh tokens still work, the operator's
// sessions are the same, the browser's SSO cookie is unchanged and still
// signs the operator (not the customer) in silently, and the customer has
// no new session.
func TestSupportSessionSeparation(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	bob, samID := f.Users["bob"], f.Users["sam"]
	b := newBrowser(h)
	cli := "http://127.0.0.1/callback"
	authorize := func(scope, resource, prompt string) (*Resp, string) {
		verifier, challenge := PKCE()
		q := url.Values{"client_id": {"proudauth-cli"}, "redirect_uri": {cli}, "response_type": {"code"}, "scope": {scope}, "state": {"op-state"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {resource}}
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		return b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil), verifier
	}
	redeemCode := func(redirect, verifier, resource string) *Resp {
		u, _ := url.Parse(redirect)
		if u == nil || u.Query().Get("code") == "" {
			t.Fatalf("no code in %q", redirect)
		}
		return h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {cli}, "resource": {resource}}, "proudauth-cli", "")
	}
	adminRes, accountRes := h.Realm.Issuer+"/admin", h.Realm.Issuer+"/account"

	// The operator's ordinary browser sign-in.
	r, verifier := authorize("proudauth:admin", adminRes, "")
	mustStatus(t, r, 302, "authorize")
	loc, _ := url.Parse(r.Header.Get("Location"))
	done := b.drive(t, loc.Query().Get("transaction_id"), "sam@example.test")
	operator := redeemCode(done.Str("redirect_to"), verifier, adminRes)
	mustStatus(t, operator, 200, "operator tokens")
	samTok, samRefresh := operator.Str("access_token"), operator.Str("refresh_token")
	sid := cookieValue(b, h, "/realms/main/oauth/authorize", "pa_sid")
	if samTok == "" || samRefresh == "" || sid == "" {
		t.Fatalf("precondition: operator access %t, refresh %t, SSO cookie %t", samTok != "", samRefresh != "", sid != "")
	}
	sessions := func(user string) string {
		items := f.must(f.AdminAPI("GET", "/users/"+user+"/sessions", nil), 200, "sessions").Get("items").([]any)
		out := []string{}
		for _, it := range items {
			m := it.(map[string]any)
			out = append(out, jsonString([]any{m["id"], m["auth_time"], m["amr"], m["acr"], m["recovery_restricted"]}))
		}
		return strings.Join(out, ";")
	}
	samBefore, bobBefore := sessions(samID), sessions(bob)
	if samBefore == "" {
		t.Fatal("precondition: the operator has no session")
	}

	s := &supportCtx{f: f, samTok: samTok}
	issued := s.issue(t, bob, f.Acme)
	ho := f.must(h.API("POST", "/impersonation-grants/"+issued.Str("grant.id")+"/handoffs", samTok, map[string]any{"destination_client_id": "support-bff"}),
		201, "handoff")
	redeemed := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/impersonation-handoffs/redeem", Form: url.Values{"handoff_code": {ho.Str("handoff_code")}},
		Basic: [2]string{"support-bff", f.Clients["support"].Secret}})
	mustStatus(t, redeemed, 200, "redeem")
	for _, out := range []struct {
		what string
		resp *Resp
	}{{"issue", issued}, {"handoff", ho}, {"redeem", redeemed}} {
		for _, secret := range []string{samTok, samRefresh, sid} {
			if strings.Contains(string(out.resp.Raw), secret) {
				t.Fatalf("%s response exposes the operator's credentials", out.what)
			}
		}
		var v any
		_ = json.Unmarshal(out.resp.Raw, &v)
		var tokens, members []string
		gapTokenStrings(v, &tokens, &members)
		if len(members) > 0 {
			t.Fatalf("%s response has %v: %s", out.what, members, out.resp.Raw)
		}
		want := out.resp.Str("access_token")
		if out.what == "handoff" {
			want = out.resp.Str("handoff_code")
		}
		if len(tokens) != 1 || tokens[0] != want {
			t.Fatalf("%s response carries credentials other than its own: %d", out.what, len(tokens))
		}
		if out.what == "handoff" {
			continue
		}
		in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, want)
		if in.Get("active") != true || in.Str("token_kind") != "impersonation_access" || in.Str("sub") != bob || in.Str("act.sub") != samID {
			t.Fatalf("%s token is not a support token for the customer: %s", out.what, in.Raw)
		}
	}

	// The operator's own context is untouched.
	mustStatus(t, h.API("GET", "/impersonation-grants", samTok, nil), 200, "operator token after support access")
	if got := sessions(samID); got != samBefore {
		t.Fatalf("operator sessions changed:\n before %s\n after  %s", samBefore, got)
	}
	if got := sessions(bob); got != bobBefore {
		t.Fatalf("support access created or changed customer sessions:\n before %s\n after  %s", bobBefore, got)
	}
	if got := cookieValue(b, h, "/realms/main/oauth/authorize", "pa_sid"); got != sid {
		t.Fatal("the operator's SSO cookie was replaced")
	}
	r, verifier = authorize("proudauth:account", accountRes, "none")
	mustStatus(t, r, 302, "silent authorize")
	silent := redeemCode(r.Header.Get("Location"), verifier, accountRes)
	mustStatus(t, silent, 200, "silent tokens")
	if me := f.must(h.API("GET", "/me", silent.Str("access_token"), nil), 200, "me"); me.Str("id") != samID {
		t.Fatalf("the browser's SSO session now signs in %s, not the operator", me.Str("id"))
	}
	refreshed := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {samRefresh}}, "proudauth-cli", "")
	mustStatus(t, refreshed, 200, "operator refresh after support access")
}

// TestAuthorizationLocale covers NFR-009 (language tags): the ui_locales of
// an authorization request is returned as the transaction's locale and
// chooses the language of the codes ProudAuth emails during that
// transaction. ui_locales is a preference list, so the first listed
// language with a template wins, before the English default.
func TestAuthorizationLocale(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	for _, tc := range []struct{ user, uiLocales, want string }{
		{"alice", "es-MX", "Tu código de inicio de sesión es"},
		{"bob", "fr-CA es en", "Tu código de inicio de sesión es"},
		{"carol", "de", "Your sign-in code is"},
	} {
		t.Run(tc.uiLocales, func(t *testing.T) {
			b := newBrowser(h)
			_, challenge := PKCE()
			q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
				"state": {"s1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme},
				"ui_locales": {tc.uiLocales}}
			r := b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil)
			mustStatus(t, r, 302, "authorize")
			loc, _ := url.Parse(r.Header.Get("Location"))
			tx := loc.Query().Get("transaction_id")
			base := "/api/v1/realms/main/auth/transactions/" + tx
			st := b.do("GET", base, nil, nil)
			mustStatus(t, st, 200, "transaction")
			if st.Str("locale") != tc.uiLocales {
				t.Fatalf("transaction locale %q, want %q", st.Str("locale"), tc.uiLocales)
			}
			hdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": st.Str("csrf_token")}
			email := tc.user + "@example.test"
			if id := b.do("POST", base+"/identify", map[string]any{"identifier": email}, hdr); !has(actionTypes(id), "email_otp") {
				t.Fatalf("email code not offered: %s", id.Raw)
			}
			mustStatus(t, b.do("POST", base+"/otp/send", map[string]any{"purpose": "login"}, hdr), 200, "send code")
			if body := h.Mail(email, "login_code"); !strings.Contains(body, tc.want) {
				t.Fatalf("emailed code for ui_locales %q: %q", tc.uiLocales, body)
			}
		})
	}
}

// TestIdPCORSAndChallenges covers INT-001 for the identity provider's own
// endpoints: the token and userinfo endpoints (and their preflights) answer
// a registered browser origin with Access-Control-Allow-Origin naming it —
// never "*" — and a foreign origin with no CORS headers; 401 answers carry a
// WWW-Authenticate challenge (Bearer for the API and userinfo, with
// error="invalid_token" for a bad token; Basic for failed client
// authentication at the token endpoint).
func TestIdPCORSAndChallenges(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "openid email",
		Resources: []string{h.Realm.Issuer + "/userinfo"}, Identifier: "alice@example.test"})
	refresh := lr.Tokens.Str("refresh_token")
	userinfoTok := lr.Tokens.Str("access_token")
	allowed, foreign := "https://app.test", "https://evil.test"
	cors := func(what string, r *Resp, origin string, want bool) {
		t.Helper()
		got := r.Header.Get("Access-Control-Allow-Origin")
		switch {
		case want && got != origin:
			t.Fatalf("%s from %s: Access-Control-Allow-Origin %q", what, origin, got)
		case !want && got != "":
			t.Fatalf("%s from foreign origin %s: Access-Control-Allow-Origin %q", what, origin, got)
		case want && !strings.Contains(strings.Join(r.Header.Values("Vary"), ","), "Origin"):
			t.Fatalf("%s: reflected origin without Vary: Origin", what)
		}
	}
	tokenReq := func(origin string, form url.Values) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form, Basic: [2]string{"web-bff", f.Clients["web"].Secret},
			Headers: map[string]string{"Origin": origin}})
	}
	r := tokenReq(allowed, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	mustStatus(t, r, 200, "refresh from the registered origin")
	cors("token", r, allowed, true)
	// Browser clients can read the challenge of a refused request.
	if !strings.Contains(r.Header.Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
		t.Fatalf("WWW-Authenticate is not exposed to the registered origin: %q", r.Header.Get("Access-Control-Expose-Headers"))
	}
	for _, o := range []string{foreign, "https://app.test.evil.test", "null"} {
		bad := tokenReq(o, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"pa_rt_not-a-real-token-0000000000000000"}})
		mustStatus(t, bad, 400, "token request from "+o)
		cors("token", bad, o, false)
	}
	// An error answer to the registered origin is readable by its script too.
	cors("token error", tokenReq(allowed, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"pa_rt_not-a-real-token-0000000000000000"}}), allowed, true)
	for _, o := range []string{allowed, foreign} {
		ui := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: userinfoTok, Headers: map[string]string{"Origin": o}})
		mustStatus(t, ui, 200, "userinfo from "+o)
		cors("userinfo", ui, o, o == allowed)
		for _, p := range []string{"/realms/main/oauth/token", "/realms/main/oidc/userinfo"} {
			pf := h.Do(Req{Method: "OPTIONS", Path: p, Headers: map[string]string{"Origin": o, "Access-Control-Request-Method": "POST"}})
			cors("preflight "+p, pf, o, o == allowed)
			if o == allowed && !strings.Contains(pf.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
				t.Fatalf("preflight %s does not allow Authorization: %v", p, pf.Header)
			}
		}
	}

	// 401 challenges.
	for _, c := range []struct {
		what, path, token, want string
	}{
		{"API without a token", "/api/v1/realms/main/me", "", "Bearer"},
		{"API with a bad token", "/api/v1/realms/main/me", "pa_at_forged-token-000000000000000000", `Bearer error="invalid_token"`},
		{"userinfo without a token", "/realms/main/oidc/userinfo", "", "Bearer"},
		{"userinfo with a bad token", "/realms/main/oidc/userinfo", "pa_at_forged-token-000000000000000000", `Bearer error="invalid_token"`},
	} {
		r := h.Do(Req{Method: "GET", Path: c.path, Token: c.token})
		if r.Status != 401 || !strings.HasPrefix(r.Header.Get("WWW-Authenticate"), c.want) {
			t.Fatalf("%s: %d, WWW-Authenticate %q (want prefix %q)", c.what, r.Status, r.Header.Get("WWW-Authenticate"), c.want)
		}
		// A request without credentials gets no error code (RFC 6750 section 3.1).
		if c.token == "" && r.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("%s: WWW-Authenticate %q, want a bare Bearer challenge", c.what, r.Header.Get("WWW-Authenticate"))
		}
	}
	bad := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: url.Values{"grant_type": {"client_credentials"}}, Basic: [2]string{"web-bff", "wrong-secret"}})
	if bad.Status != 401 || bad.Str("error") != "invalid_client" || !strings.HasPrefix(bad.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("failed client authentication: %d %q %s", bad.Status, bad.Header.Get("WWW-Authenticate"), bad.Raw)
	}
}

// TestJobDownloadGrants covers INT-008 for ProudAuth's own download links:
// a download credential is valid for five minutes, is bound to the
// requester (another principal holding the same permission cannot redeem
// it, and that refused attempt does not spend it), is single use, and a user
// needs recent authentication to obtain one.
func TestJobDownloadGrants(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "config-exporter",
		"permissions": []string{"realm.configuration.export"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	export := func() string {
		job := f.must(f.AdminAPI("POST", "/configuration/exports", nil), 202, "export").Str("job_id")
		runWorker(t, w)
		return job
	}
	issue := func(job string) string {
		dl := f.must(f.AdminAPI("POST", "/jobs/"+job+"/downloads", nil), 201, "download credential")
		if dl.Get("expires_in") != float64(300) {
			t.Fatalf("download credential lifetime: %s", dl.Raw)
		}
		return dl.Str("download_token")
	}
	redeem := func(token, credential string) *Resp {
		return h.API("POST", "/job-downloads", token, map[string]any{"download_token": credential})
	}

	t.Run("five-minute expiry", func(t *testing.T) {
		job := export()
		cred := issue(job)
		var ttl time.Duration
		var exp time.Time
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT expires_at FROM job_download_tokens WHERE job_id=$1`, job).Scan(&exp)
		if ttl = exp.Sub(h.Clock.Now()); ttl <= 4*time.Minute+50*time.Second || ttl > 5*time.Minute {
			t.Fatalf("stored expiry %s from now", ttl)
		}
		h.Clock.Advance(5*time.Minute + time.Second)
		f.ReloginAdmin()
		mustStatus(t, redeem(f.AdminToken, cred), 404, "expired download credential")
		// Just inside the window it works, once.
		cred = issue(job)
		h.Clock.Advance(4*time.Minute + 30*time.Second)
		mustStatus(t, redeem(f.AdminToken, cred), 200, "download within five minutes")
		mustStatus(t, redeem(f.AdminToken, cred), 404, "second use")
		f.ReloginAdmin()
	})

	t.Run("bound to the requester", func(t *testing.T) {
		job := export()
		cred := issue(job)
		carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
		mustStatus(t, redeem(carol, cred), 404, "another principal with the same permission")
		var consumed bool
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM job_download_tokens WHERE job_id=$1`, job).Scan(&consumed)
		if consumed {
			t.Fatal("the refused attempt spent the credential")
		}
		mustStatus(t, h.API("POST", "/jobs/"+job+"/downloads", carol, nil), 404, "carol issuing for the administrator's job")
		f.ReloginAdmin()
		mustStatus(t, redeem(f.AdminToken, cred), 200, "the requester redeems after the refused attempt")
	})

	t.Run("issuance needs recent authentication", func(t *testing.T) {
		job := export()
		lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:admin", Resources: []string{h.Realm.Issuer + "/admin"}, Identifier: "root-admin"})
		h.Clock.Advance(h.Cfg.Security.RecentAuthWindow + time.Minute)
		ref := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}}, "proudauth-cli", "")
		mustStatus(t, ref, 200, "refresh: same session, old authentication")
		r := h.API("POST", "/jobs/"+job+"/downloads", ref.Str("access_token"), nil)
		if r.Status != 403 || r.Str("code") != "recent_authentication_required" {
			t.Fatalf("download credential for a stale session: %d %s", r.Status, r.Raw)
		}
		f.ReloginAdmin()
		issue(job)
	})
}

// TestJWKSPublishesOnlyPublicKeys covers TOK-006: resource servers receive
// only public verification keys. For every signing key type the realm can
// hold (RSA for RS256 and PS256, EC for ES256, OKP for EdDSA), the JWKS
// document has no private or symmetric members (d, p, q, dp, dq, qi, oth, k).
func TestJWKSPublishesOnlyPublicKeys(t *testing.T) {
	h := NewHarness(t)
	h.CreateRealm(nil)
	ctx := context.Background()
	want := map[string]string{}
	for _, alg := range []string{"RS256", "PS256", "ES256", "EdDSA"} {
		kid, err := h.App.KeyMgr.CreateKey(ctx, h.App.D.DB.Pool, h.Realm.ID, alg, "pending", "token")
		if err != nil {
			t.Fatal(err)
		}
		want[kid] = alg
	}
	h.App.KeyMgr.Invalidate(h.Realm.ID)
	r := h.Do(Req{Method: "GET", Path: "/realms/main/jwks"})
	mustStatus(t, r, 200, "jwks")
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/jwk-set+json") {
		t.Fatalf("content type %q", ct)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(r.Raw, &set); err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, k := range set.Keys {
		for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := k[m]; ok {
				t.Fatalf("JWKS key %v publishes private member %q", k["kid"], m)
			}
		}
		kty, _ := k["kty"].(string)
		if kty != "RSA" && kty != "EC" && kty != "OKP" {
			t.Fatalf("JWKS key %v has key type %q", k["kid"], kty)
		}
		types[kty] = true
		delete(want, k["kid"].(string))
	}
	if len(want) != 0 || !types["RSA"] || !types["EC"] || !types["OKP"] {
		t.Fatalf("JWKS misses keys %v or key types (got %v)", want, types)
	}
}

// TestAuthorizationErrorsEchoState covers OIDC-002 on the server side: an
// authorization error returned to the client's validated redirect URI
// carries the client's state exactly as sent (and the issuer), for request
// validation errors, prompt=none without a session and an abandoned
// transaction; an unregistered redirect URI gets a local error instead.
func TestAuthorizationErrorsEchoState(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	state := "st/ä &x=1?#"
	_, challenge := PKCE()
	query := func(mut func(url.Values)) string {
		q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
			"state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme}}
		mut(q)
		return "/realms/main/oauth/authorize?" + q.Encode()
	}
	check := func(what, location, wantErr string) {
		t.Helper()
		u, err := url.Parse(location)
		if err != nil || u.Host != "app.test" {
			t.Fatalf("%s: not returned to the client: %q", what, location)
		}
		q := u.Query()
		if q.Get("error") != wantErr || q.Get("state") != state || q.Get("iss") != h.Realm.Issuer || q.Get("code") != "" {
			t.Fatalf("%s: %s", what, u.RawQuery)
		}
	}
	for _, c := range []struct {
		what, err string
		mut       func(url.Values)
	}{
		{"unknown scope", "invalid_scope", func(q url.Values) { q.Set("scope", "openid orders:everything") }},
		{"unsupported acr value", "invalid_request", func(q url.Values) { q.Set("acr_values", "urn:example:unknown") }},
		{"prompt=none without a session", "login_required", func(q url.Values) { q.Set("prompt", "none") }},
	} {
		r := h.Do(Req{Method: "GET", Path: query(c.mut)})
		mustStatus(t, r, 302, c.what)
		check(c.what, r.Header.Get("Location"), c.err)
	}
	// A redirect URI the client did not register never receives anything.
	r := h.Do(Req{Method: "GET", Path: query(func(q url.Values) {
		q.Set("redirect_uri", "https://evil.test/cb")
		q.Set("scope", "openid orders:everything")
	})})
	if r.Status != 400 || r.Header.Get("Location") != "" || strings.Contains(string(r.Raw), state) {
		t.Fatalf("error sent to an unregistered redirect URI: %d %q", r.Status, r.Header.Get("Location"))
	}
	// An abandoned headless transaction returns access_denied with the state.
	start := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "openid orders:read",
		"state": state, "code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{f.OrdersAud}, "organization": f.Acme})
	mustStatus(t, start, 201, "start")
	c := h.Step(start.Str("transaction_id"), start.Str("continuation_token"), "cancel", nil)
	check("cancelled transaction", c.Str("redirect_to"), "access_denied")
}
