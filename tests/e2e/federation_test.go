package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/proudbase/proudauth/internal/federation"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/realm"
)

// fakeIdP is an upstream OIDC provider plus a GitHub-style OAuth API for tests.
type fakeIdP struct {
	t              *testing.T
	srv            *httptest.Server
	key            *rsa.PrivateKey
	other          *rsa.PrivateKey // a key not published in the JWKS
	mu             sync.Mutex
	codes          map[string]pendingCode
	next           map[string]any // claims for the next login
	tamper         string         // "", "nonce", "aud", "expired", "signature", "issuer"
	now            func() time.Time
	down           bool
	discoveryCalls atomic.Int64
}

type pendingCode struct {
	claims    map[string]any
	challenge string
	redirect  string
	nonce     string
	clientID  string
}

func newFakeIdP(t *testing.T, now func() time.Time) *fakeIdP {
	f := &fakeIdP{t: t, codes: map[string]pendingCode{}, now: now}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.other, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.discoveryCalls.Add(1)
		if f.down {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks", "code_challenge_methods_supported": []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "up-1", Algorithm: "RS256", Use: "sig"}}})
	})
	// The "browser" visits /authorize; the fake user is already signed in upstream.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
			http.Error(w, "bad request", 400)
			return
		}
		code := randomString()
		f.mu.Lock()
		f.codes[code] = pendingCode{claims: f.next, challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), nonce: q.Get("nonce"), clientID: q.Get("client_id")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	token := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, pass, ok := r.BasicAuth()
		if !ok || pass != "upstream-secret" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		f.mu.Lock()
		pc, found := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !found || pc.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/login/oauth") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gh-" + pc.claims["sub"].(string), "token_type": "bearer"})
			return
		}
		now := f.now()
		claims := map[string]any{"iss": f.srv.URL, "aud": user, "nonce": pc.nonce, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
		for k, v := range pc.claims {
			claims[k] = v
		}
		signer := f.key
		switch f.tamper {
		case "nonce":
			claims["nonce"] = "other"
		case "aud":
			claims["aud"] = "someone-else"
		case "expired":
			claims["exp"] = now.Add(-10 * time.Minute).Unix()
		case "signature":
			signer = f.other
		case "issuer":
			claims["iss"] = "https://evil.test"
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signer}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "up-1"))
		payload, _ := json.Marshal(claims)
		jws, _ := sig.Sign(payload)
		idt, _ := jws.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": randomString(), "id_token": idt, "token_type": "Bearer"})
	}
	mux.HandleFunc("POST /token", token)
	mux.HandleFunc("POST /login/oauth/access_token", token)
	mux.HandleFunc("GET /gh/user", func(w http.ResponseWriter, r *http.Request) {
		sub := strings.TrimPrefix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "gh-")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 4242, "login": "octo-" + sub, "name": "Octo Cat"})
	})
	mux.HandleFunc("GET /gh/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"email": "octo@gh.test", "primary": true, "verified": true}, {"email": "unverified@gh.test", "verified": false}})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func randomString() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// browse follows the upstream authorization URL and returns the callback URL the
// upstream redirects back to.
func (f *fakeIdP) browse(t *testing.T, authURL string) string {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}}}
	res, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("upstream authorize: %d", res.StatusCode)
	}
	return res.Header.Get("Location")
}

// TestFederation covers FED-001..FED-012, FED-017, FED-018, REG-009, USR-010 and TEN-016.
// Requirements: DOM-004 (a connection trusts its upstream for its own
// subjects only: upstream assurance is not trusted unless configured, foreign
// upstream tenants are refused, a matching email never links an account and
// an organization's connection never signs in to another organization),
// DOM-008 (an organization's connection is not offered outside it).
func TestFederation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	idp := newFakeIdP(t, h.Clock.Now)
	// Upstreams on loopback with a test CA: allowed only by explicit operator policy.
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	create := func(body map[string]any) *Resp {
		t.Helper()
		return f.AdminAPI("POST", "/identity-providers", body)
	}
	corp := create(map[string]any{"alias": "corp", "display_name": "Corp SSO", "issuer": idp.srv.URL, "client_secret": "upstream-secret",
		"config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true, "organization_id": f.Acme,
		"jit_default_role_id": f.Roles["orders-viewer"]})
	f.must(corp, 201, "create corp connection")
	if strings.Contains(string(corp.Raw), "upstream-secret") || corp.Get("has_client_secret") != true {
		t.Fatalf("client secret disclosed or not stored: %s", corp.Raw)
	}
	corpID := corp.Str("id")
	diag := f.must(f.AdminAPI("POST", "/identity-providers/"+corpID+"/test", nil), 200, "test connection")
	if diag.Get("ok") != true || diag.Get("signing_keys").(float64) != 1 {
		t.Fatalf("diagnostics: %s", diag.Raw)
	}
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}

	// login runs a federated sign-in for the next upstream user and returns the
	// transaction state after the callback plus the callback JSON.
	type fedResult struct {
		txID, cont, verifier string
		callback, state      *Resp
	}
	login := func(provider string, claims map[string]any, opts LoginOpts) fedResult {
		t.Helper()
		idp.next = claims
		start, verifier, cont := h.StartTx(opts)
		txID := start.Str("transaction_id")
		st := h.Step(txID, cont, "federation/start", map[string]any{"provider": provider})
		mustStatus(t, st, 200, "federation start")
		cb := h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))})
		mustStatus(t, cb, 200, "callback")
		return fedResult{txID: txID, cont: cont, verifier: verifier, callback: cb, state: h.Step(txID, cont, "resume", nil)}
	}

	t.Run("connection offered and PKCE enforced", func(t *testing.T) {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}, Organization: f.Acme})
		if !strings.Contains(string(start.Raw), `"alias":"corp"`) {
			t.Fatalf("org connection not offered for its organization: %s", start.Raw)
		}
		other, _, _ := h.StartTx(acct)
		if strings.Contains(string(other.Raw), `"alias":"corp"`) {
			t.Fatal("organization connection offered outside its organization")
		}
		st := h.Step(start.Str("transaction_id"), cont, "federation/start", map[string]any{"provider": "corp"})
		u, _ := url.Parse(st.Str("external_redirect"))
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("scope") != "openid email profile" {
			t.Fatalf("upstream request: %s", u.RawQuery)
		}
	})

	t.Run("just-in-time provisioning with organization membership", func(t *testing.T) {
		opts := LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}, Organization: f.Acme}
		r := login("corp", map[string]any{"sub": "u-zoe", "email": "zoe@corp.test", "email_verified": true, "name": "Zoe Upstream"}, opts)
		if r.callback.Str("status") != "ok" || r.state.Str("redirect_to") == "" {
			t.Fatalf("federated login did not complete: %s / %s", r.callback.Raw, r.state.Raw)
		}
		u, _ := url.Parse(r.state.Str("redirect_to"))
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {r.verifier},
			"redirect_uri": {webRedirect}, "resource": {f.OrdersAud}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, toks, 200, "token")
		claims := jwtPayload(toks.Str("access_token"))
		if claims["org_id"] != f.Acme || !strings.Contains(jsonString(claims["permissions"])+jsonString(claims["scope"]), "orders") {
			t.Fatalf("JIT member token: %v", claims)
		}
		if claims["acr"] != "urn:proudauth:acr:federated" {
			t.Fatalf("upstream assurance trusted without configuration: %v", claims["acr"])
		}
		// Second login reuses the link: no duplicate account.
		r2 := login("corp", map[string]any{"sub": "u-zoe", "email": "zoe@corp.test", "email_verified": true, "name": "Zoe Renamed"}, acct)
		if r2.state.Str("redirect_to") == "" {
			t.Fatalf("second login: %s", r2.state.Raw)
		}
		users := f.must(f.AdminAPI("GET", "/users?q=zoe@corp.test", nil), 200, "users")
		if n := len(users.Get("items").([]any)); n != 1 {
			t.Fatalf("expected one zoe account, got %d", n)
		}
		mem := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members", nil), 200, "members")
		if !strings.Contains(string(mem.Raw), `"jit"`) {
			t.Fatalf("JIT membership provenance missing: %s", mem.Raw)
		}
		// Acme's connection never signs zoe in to Globex, even when she is a
		// member there and picks it after signing in (FED-006).
		zoe := users.Get("items").([]any)[0].(map[string]any)["id"].(string)
		f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/members", map[string]any{"user_id": zoe}), 201, "zoe in globex")
		noOrg := LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}}
		r3 := login("corp", map[string]any{"sub": "u-zoe", "email": "zoe@corp.test", "email_verified": true, "name": "Zoe"}, noOrg)
		if sel := h.Step(r3.txID, r3.cont, "organization", map[string]any{"organization_id": f.Globex}); sel.Status != 403 {
			t.Fatalf("another organization's connection used for Globex: %d %s", sel.Status, sel.Raw)
		}
		if sel := h.Step(r3.txID, r3.cont, "organization", map[string]any{"organization_id": f.Acme}); sel.Status != 200 || sel.Str("redirect_to") == "" {
			t.Fatalf("its own organization: %d %s", sel.Status, sel.Raw)
		}
	})

	t.Run("REG-008 just-in-time accounts wait for registration review", func(t *testing.T) {
		mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.RequireApproval = true }), 200, "approval queue")
		defer f.SetPolicy(func(p *realm.Policy) { p.Registration.RequireApproval = false })
		r := login("corp", map[string]any{"sub": "u-quinn", "email": "quinn@corp.test", "email_verified": true, "name": "Quinn"}, acct)
		if r.state.Str("redirect_to") != "" || !strings.Contains(string(r.state.Raw), "registration_pending_approval") {
			t.Fatalf("JIT account signed in without review: %s", r.state.Raw)
		}
		queue := f.must(f.AdminAPI("GET", "/registration-approvals?state=pending", nil), 200, "queue")
		if len(queue.Get("items").([]any)) != 1 {
			t.Fatalf("JIT account not queued: %s", queue.Raw)
		}
	})

	t.Run("existing account requires proof of control", func(t *testing.T) {
		r := login("corp", map[string]any{"sub": "u-alice", "email": "alice@example.test", "email_verified": true}, acct)
		acts := actionTypes(r.state)
		if !has(acts, "link_account") || !has(acts, "password") || r.state.Str("redirect_to") != "" {
			t.Fatalf("existing account linked without local proof: %v %s", acts, r.state.Raw)
		}
		done := h.Step(r.txID, r.cont, "password", map[string]any{"password": h.passwords["alice@example.test"]})
		done = h.Drive(r.txID, r.cont, done, LoginOpts{Identifier: "alice@example.test"})
		if done.Str("redirect_to") == "" {
			t.Fatalf("link login did not complete: %s", done.Raw)
		}
		// Now the upstream identity signs alice in directly.
		r2 := login("corp", map[string]any{"sub": "u-alice", "email": "alice@example.test", "email_verified": true}, acct)
		if r2.state.Str("redirect_to") == "" && !has(actionTypes(r2.state), "totp") {
			t.Fatalf("linked login: %s", r2.state.Raw)
		}
		tok := f.AccountToken("alice").Tokens.Str("access_token")
		linked := h.API("GET", "/me/linked-identities", tok, nil)
		if !strings.Contains(string(linked.Raw), "verified_local_login") {
			t.Fatalf("link provenance: %s", linked.Raw)
		}
	})

	t.Run("TEST-026 unverified upstream email never claims an account", func(t *testing.T) {
		r := login("corp", map[string]any{"sub": "u-fake-bob", "email": "bob@example.test", "email_verified": false}, acct)
		if has(actionTypes(r.state), "link_account") {
			t.Fatal("unverified email triggered linking to bob")
		}
		if r.state.Str("redirect_to") != "" {
			u, _ := url.Parse(r.state.Str("redirect_to"))
			toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {r.verifier},
				"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}}, "", "")
			if jwtPayload(toks.Str("access_token"))["sub"] == f.Users["bob"] {
				t.Fatal("signed in as bob through an unverified upstream email")
			}
		}
	})

	t.Run("upstream response validation", func(t *testing.T) {
		for _, tamper := range []string{"nonce", "aud", "expired", "signature", "issuer"} {
			idp.tamper = tamper
			r := login("corp", map[string]any{"sub": "u-zoe", "email": "zoe@corp.test", "email_verified": true}, acct)
			if r.callback.Str("error") != "upstream_invalid_response" || r.state.Str("redirect_to") != "" {
				t.Fatalf("tampered ID token (%s) accepted: %s", tamper, r.callback.Raw)
			}
		}
		idp.tamper = ""
		// A replayed callback (same state) is rejected.
		idp.next = map[string]any{"sub": "u-zoe"}
		start, _, cont := h.StartTx(acct)
		st := h.Step(start.Str("transaction_id"), cont, "federation/start", map[string]any{"provider": "corp"})
		cb := idp.browse(t, st.Str("external_redirect"))
		mustStatus(t, h.Do(Req{Method: "GET", Path: cb}), 200, "first callback")
		if r := h.Do(Req{Method: "GET", Path: cb}); r.Status != 400 {
			t.Fatalf("replayed callback: %d %s", r.Status, r.Raw)
		}
		// A callback for another connection's alias is rejected.
		st = h.Step(start.Str("transaction_id"), cont, "federation/start", map[string]any{"provider": "corp"})
		cb = idp.browse(t, st.Str("external_redirect"))
		if r := h.Do(Req{Method: "GET", Path: strings.Replace(cb, "/federation/corp/", "/federation/other/", 1)}); r.Status != 400 {
			t.Fatalf("callback accepted on wrong connection: %d", r.Status)
		}
		// Upstream outage is reported, not bypassed (FED-012).
		idp.down = true
		h.App.Federation.Egress.Timeout = 2 * time.Second
		f.must(f.AdminAPI("PUT", "/identity-providers/"+corpID, nil), 428, "update needs If-Match")
		cur := f.must(f.AdminAPI("GET", "/identity-providers/"+corpID, nil), 200, "get")
		var in map[string]any
		_ = json.Unmarshal(cur.Raw, &in)
		delete(in, "id")
		upd := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + corpID, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"alias": "corp", "display_name": "Corp SSO", "issuer": idp.srv.URL,
				"config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true, "organization_id": f.Acme, "jit_default_role_id": f.Roles["orders-viewer"]}})
		mustStatus(t, upd, 200, "update (clears discovery cache)")
		start, _, cont = h.StartTx(acct)
		st = h.Step(start.Str("transaction_id"), cont, "federation/start", map[string]any{"provider": "corp"})
		if st.Str("notice") != "upstream_unavailable" || st.Str("external_redirect") != "" {
			t.Fatalf("outage not reported: %s", st.Raw)
		}
		idp.down = false
	})

	t.Run("TEST-027 SSO-mandatory organization has no password fallback", func(t *testing.T) {
		// Pat has a local password, but pat's domain belongs to acme, which
		// requires its enterprise connection.
		r := f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "pat@corp.test", "username": "pat", "display_name": "Pat"}), 201, "create pat")
		token := CodeFrom(h.Mail("pat@corp.test", "account_setup"))
		pw := "pat has a long passphrase 2026"
		f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": token, "password": pw}), 200, "setup pat")
		f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": r.Str("user.id")}), 201, "pat member")
		ch := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains", map[string]any{"domain": "corp.test"}), 201, "add domain")
		saved := organization.TXTResolver
		organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
		defer func() { organization.TXTResolver = saved }()
		f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify domain")
		org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
		upd := h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": org.Header.Get("ETag")},
			JSON:    map[string]any{"policy": map[string]any{"sso_required": true, "sso_provider_id": corpID}}})
		mustStatus(t, upd, 200, "require SSO")
		// Another organization cannot require Acme's connection (TEN-007, FED-006).
		gorg := f.must(f.AdminAPI("GET", "/organizations/"+f.Globex, nil), 200, "globex")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Globex, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": gorg.Header.Get("ETag")},
			JSON:    map[string]any{"policy": map[string]any{"sso_required": true, "sso_provider_id": corpID}}}), 422, "another organization's connection")

		start, _, cont := h.StartTx(acct)
		tx := start.Str("transaction_id")
		st := h.Step(tx, cont, "identify", map[string]any{"identifier": "pat@corp.test"})
		acts := actionTypes(st)
		if !has(acts, "external_redirect") || has(acts, "password") || has(acts, "email_otp") {
			t.Fatalf("SSO-mandatory identifier offered local methods: %v", acts)
		}
		// Submitting the correct password anyway cannot complete the sign-in.
		pr := h.Step(tx, cont, "password", map[string]any{"password": pw})
		if pr.Str("redirect_to") != "" || !has(actionTypes(pr), "external_redirect") {
			t.Fatalf("password bypassed mandatory SSO: %d %s", pr.Status, pr.Raw)
		}
		// When the upstream fails, the failure is reported; still no fallback.
		idp.down = true
		h.App.Federation.Egress.Timeout = 2 * time.Second
		cur := f.must(f.AdminAPI("GET", "/identity-providers/"+corpID, nil), 200, "get")
		var in map[string]any
		_ = json.Unmarshal(cur.Raw, &in)
		mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + corpID, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"alias": "corp", "display_name": "Corp SSO", "issuer": idp.srv.URL,
				"config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true, "organization_id": f.Acme, "jit_default_role_id": f.Roles["orders-viewer"]}}),
			200, "reset discovery cache")
		fs := h.Step(tx, cont, "federation/start", map[string]any{"provider": "corp"})
		if fs.Str("notice") != "upstream_unavailable" || fs.Str("redirect_to") != "" || has(actionTypes(fs), "password") {
			t.Fatalf("outage handling: %s", fs.Raw)
		}
		idp.down = false
		// Unset the requirement for the remaining subtests.
		// NFR-006: repeated login steps cannot bypass the negative-fetch
		// cooldown. One eligible retry must recover without local fallback.
		calls := idp.discoveryCalls.Load()
		fs = h.Step(tx, cont, "federation/start", map[string]any{"provider": "corp"})
		if fs.Str("notice") != "upstream_unavailable" || fs.Str("external_redirect") != "" || has(actionTypes(fs), "password") || idp.discoveryCalls.Load() != calls {
			t.Fatalf("retry bypassed metadata failure cooldown: %s", fs.Raw)
		}
		h.Clock.Advance(time.Minute)
		fs = h.Step(tx, cont, "federation/start", map[string]any{"provider": "corp"})
		if fs.Str("external_redirect") == "" || idp.discoveryCalls.Load() != calls+1 {
			t.Fatalf("eligible metadata retry did not recover SSO: %s", fs.Raw)
		}
		org = f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"sso_required": false}}}), 200, "relax SSO")
	})

	t.Run("tenant restriction and trusted upstream MFA", func(t *testing.T) {
		mt := create(map[string]any{"alias": "tenanted", "display_name": "Tenanted", "issuer": idp.srv.URL, "client_secret": "upstream-secret",
			"config":           map[string]any{"client_id": "proudauth-main", "tenant_claim": "tid", "allowed_tenants": []string{"t1"}},
			"jit_provisioning": true, "trust_upstream_mfa": true})
		f.must(mt, 201, "tenanted connection")
		r := login("tenanted", map[string]any{"sub": "u-t2", "tid": "t2", "email": "x@t2.test", "email_verified": true}, acct)
		if r.callback.Str("error") != "upstream_tenant_not_allowed" {
			t.Fatalf("foreign tenant accepted: %s", r.callback.Raw)
		}
		r = login("tenanted", map[string]any{"sub": "u-t1", "tid": "t1", "email": "y@t1.test", "email_verified": true, "amr": []string{"pwd", "mfa"}}, acct)
		u, _ := url.Parse(r.state.Str("redirect_to"))
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {r.verifier},
			"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {h.Realm.Issuer + "/account"}}, "", "")
		mustStatus(t, toks, 200, "token")
		if acr := jwtPayload(toks.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:mfa" {
			t.Fatalf("trusted upstream MFA not mapped: %v", acr)
		}
	})

	t.Run("self-service linking and unlink protection", func(t *testing.T) {
		carol := f.AccountToken("carol").Tokens.Str("access_token")
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		start := h.API("POST", "/me/linked-identities", carol, map[string]any{"provider": "corp"})
		mustStatus(t, start, 200, "start link")
		idp.next = map[string]any{"sub": "u-carol", "email": "carol.upstream@corp.test", "email_verified": true}
		cb := h.Do(Req{Method: "GET", Path: idp.browse(t, start.Str("authorization_url"))})
		code := cb.Str("link_code")
		if code == "" {
			t.Fatalf("no link code: %s", cb.Raw)
		}
		// Another account cannot redeem the code (and does not burn it).
		if r := h.API("POST", "/me/linked-identities/confirm", bob, map[string]any{"code": code}); r.Status != 400 {
			t.Fatalf("link code redeemed by another account: %d", r.Status)
		}
		mustStatus(t, h.API("POST", "/me/linked-identities/confirm", carol, map[string]any{"code": code}), 201, "confirm link")
		if r := h.API("POST", "/me/linked-identities/confirm", carol, map[string]any{"code": code}); r.Status != 400 {
			t.Fatal("link code reusable")
		}
		linked := h.API("GET", "/me/linked-identities", carol, nil)
		items := linked.Get("items").([]any)
		if len(items) != 1 || strings.Contains(string(linked.Raw), "carol.upstream@corp.test") {
			t.Fatalf("linked identities (email must be masked): %s", linked.Raw)
		}
		// Carol has a password, so the link can be removed.
		mustStatus(t, h.API("DELETE", "/me/linked-identities/"+items[0].(map[string]any)["id"].(string), carol, nil), 204, "unlink")
		// Zoe (JIT, federation only) cannot remove her last sign-in method.
		r := login("corp", map[string]any{"sub": "u-zoe", "email": "zoe@corp.test", "email_verified": true}, acct)
		u, _ := url.Parse(r.state.Str("redirect_to"))
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {r.verifier},
			"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {h.Realm.Issuer + "/account"}}, "", "")
		zoe := toks.Str("access_token")
		zl := h.API("GET", "/me/linked-identities", zoe, nil)
		zid := zl.Get("items").([]any)[0].(map[string]any)["id"].(string)
		if r := h.API("DELETE", "/me/linked-identities/"+zid, zoe, nil); r.Status != 409 || r.Str("code") != "last_sign_in_method" {
			t.Fatalf("last sign-in method removed: %d %s", r.Status, r.Raw)
		}
		// A connection with linked identities cannot be deleted.
		if r := f.AdminAPI("DELETE", "/identity-providers/"+corpID, nil); r.Status != 409 {
			t.Fatalf("connection with links deleted: %d", r.Status)
		}
	})

	t.Run("github adapter uses immutable account IDs and verified email", func(t *testing.T) {
		gh := create(map[string]any{"alias": "github", "display_name": "GitHub", "adapter": "github", "client_secret": "upstream-secret",
			"config": map[string]any{"client_id": "gh-client", "authorization_endpoint": idp.srv.URL + "/authorize",
				"token_endpoint": idp.srv.URL + "/login/oauth/access_token", "api_base_url": idp.srv.URL + "/gh"}, "jit_provisioning": true})
		f.must(gh, 201, "github connection")
		if jsonString(gh.Get("config.scopes")) != `["read:user","user:email"]` {
			t.Fatalf("github scopes not minimal: %v", gh.Get("config.scopes"))
		}
		r := login("github", map[string]any{"sub": "x"}, acct)
		if r.state.Str("redirect_to") == "" {
			t.Fatalf("github login: %s %s", r.callback.Raw, r.state.Raw)
		}
		users := f.must(f.AdminAPI("GET", "/users?q=octo@gh.test", nil), 200, "users")
		if len(users.Get("items").([]any)) != 1 {
			t.Fatalf("github JIT user: %s", users.Raw)
		}
		f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "gh2", "display_name": "x", "adapter": "github", "trust_upstream_mfa": true,
			"config": map[string]any{"client_id": "c"}}), 422, "github cannot assert MFA")
		// Switching a linked connection to another protocol would re-key its
		// subjects; the kind follows the adapter.
		ghID := gh.Str("id")
		if gh.Str("kind") != "oauth2_social" {
			t.Fatalf("github kind: %s", gh.Raw)
		}
		cur := f.must(f.AdminAPI("GET", "/identity-providers/"+ghID, nil), 200, "get github")
		swap := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + ghID, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"alias": "github", "display_name": "GitHub", "adapter": "oidc",
				"issuer": cur.Str("issuer"), "config": map[string]any{"client_id": "gh-client"}}})
		mustStatus(t, swap, 409, "protocol change while linked")
		if !strings.Contains(string(swap.Raw), `"adapter"`) {
			t.Fatalf("protocol change refusal: %s", swap.Raw)
		}
		gh3 := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "gh3", "display_name": "x", "adapter": "github", "client_secret": "s",
			"config": map[string]any{"client_id": "c"}}), 201, "unlinked github connection")
		cur = f.must(f.AdminAPI("GET", "/identity-providers/"+gh3.Str("id"), nil), 200, "get gh3")
		moved := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + gh3.Str("id"), Token: f.AdminToken,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"alias": "gh3", "display_name": "x", "adapter": "oidc",
				"issuer": idp.srv.URL, "config": map[string]any{"client_id": "c"}}})
		mustStatus(t, moved, 200, "protocol change without links")
		if moved.Str("kind") != "oidc" {
			t.Fatalf("kind not recomputed: %s", moved.Raw)
		}
	})

	t.Run("TEN-007 organization administrators manage only their own connections", func(t *testing.T) {
		f.EnrollTOTP("alice")
		alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner with an MFA session
		base := "/organizations/" + f.Acme + "/identity-providers"
		list := h.API("GET", base, alice, nil)
		mustStatus(t, list, 200, "list")
		if !strings.Contains(string(list.Raw), corpID) {
			t.Fatalf("organization connection missing: %s", list.Raw)
		}
		c := h.API("POST", base, alice, map[string]any{"alias": "acme-okta", "display_name": "Acme Okta", "issuer": idp.srv.URL,
			"config": map[string]any{"client_id": "acme"}, "organization_id": f.Globex})
		mustStatus(t, c, 201, "create organization connection")
		if c.Str("organization_id") != f.Acme {
			t.Fatalf("connection escaped the organization boundary: %s", c.Raw)
		}
		mustStatus(t, h.API("POST", base, alice, map[string]any{"alias": "acme-mfa", "display_name": "x", "issuer": idp.srv.URL,
			"config": map[string]any{"client_id": "c"}, "trust_upstream_mfa": true}), 403, "upstream MFA trust")
		mustStatus(t, h.API("POST", base, alice, map[string]any{"alias": "acme-email", "display_name": "x", "issuer": idp.srv.URL,
			"linking_policy": "trusted_verified_email", "config": map[string]any{"client_id": "c", "allowed_email_domains": []string{"gmail.com"}}}), 422,
			"trusted email for an unverified domain")
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		mustStatus(t, h.API("GET", base, bob, nil), 403, "member without org.identity_providers.write")
		mustStatus(t, h.API("DELETE", "/organizations/"+f.Globex+"/identity-providers/"+c.Str("id"), alice, nil), 404, "foreign organization path")
		mustStatus(t, h.API("DELETE", base+"/"+c.Str("id"), alice, nil), 204, "delete")
	})

	t.Run("configuration validation", func(t *testing.T) {
		f.must(create(map[string]any{"alias": "plain", "display_name": "x", "issuer": "http://idp.test", "config": map[string]any{"client_id": "c"}}), 422, "http issuer")
		f.must(create(map[string]any{"alias": "trusting", "display_name": "x", "issuer": idp.srv.URL, "linking_policy": "trusted_verified_email",
			"config": map[string]any{"client_id": "c"}}), 422, "trusted linking without domain constraint")
		f.must(create(map[string]any{"alias": "weakalg", "display_name": "x", "issuer": idp.srv.URL, "config": map[string]any{"client_id": "c", "algorithms": []string{"HS256"}}}), 422, "symmetric alg")
		// The JIT default role is bounded by the configuring administrator's authority.
		sam := f.AdminTokenFor("sam")
		if sam.Tokens != nil && sam.Tokens.Status == 200 {
			r := h.API("POST", "/identity-providers", sam.Tokens.Str("access_token"), map[string]any{"alias": "sam", "display_name": "x", "issuer": idp.srv.URL,
				"config": map[string]any{"client_id": "c"}})
			if r.Status != 403 {
				t.Fatalf("support operator configured federation: %d", r.Status)
			}
		}
	})
}

var registerTestAdapter sync.Once

// TestFederationAdapters covers FED-002: provider adapters keep their own
// identity semantics (fixed issuers, tenant rules, which email assertions to
// believe), and the broker is extended by registering adapters.
func TestFederationAdapters(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	create := func(body map[string]any) *Resp { return f.AdminAPI("POST", "/identity-providers", body) }

	g := f.must(create(map[string]any{"alias": "google", "display_name": "Google", "adapter": "google", "client_secret": "s",
		"config": map[string]any{"client_id": "cid", "allowed_tenants": []string{"example.com"}}}), 201, "google")
	if g.Str("issuer") != "https://accounts.google.com" || g.Str("config.tenant_claim") != "hd" {
		t.Fatalf("google defaults: %s", g.Raw)
	}
	mustStatus(t, create(map[string]any{"alias": "g2", "display_name": "x", "adapter": "google", "issuer": idp.srv.URL, "config": map[string]any{"client_id": "c"}}),
		422, "google with another issuer")
	mustStatus(t, create(map[string]any{"alias": "ms", "display_name": "x", "adapter": "microsoft", "config": map[string]any{"client_id": "c"}}),
		422, "microsoft without tenants")
	mustStatus(t, create(map[string]any{"alias": "ms", "display_name": "x", "adapter": "microsoft", "linking_policy": "trusted_verified_email",
		"config": map[string]any{"client_id": "c", "allowed_tenants": []string{"t1"}, "allowed_email_domains": []string{"corp.test"}}}),
		422, "microsoft with trusted email linking")
	ms := f.must(create(map[string]any{"alias": "ms", "display_name": "Microsoft", "adapter": "microsoft", "client_secret": "s",
		"config": map[string]any{"client_id": "c", "allowed_tenants": []string{"t1"}}}), 201, "microsoft")
	if ms.Get("config.multi_tenant_issuer") != true || ms.Str("config.tenant_claim") != "tid" || !strings.Contains(ms.Str("config.jwks_uri"), "login.microsoftonline.com") {
		t.Fatalf("microsoft defaults: %s", ms.Raw)
	}
	mustStatus(t, create(map[string]any{"alias": "x", "display_name": "x", "adapter": "myspace", "config": map[string]any{"client_id": "c"}}), 422, "unknown adapter")

	// An adapter registered by the deployment: OIDC whose email assertions
	// are not trusted, so a JIT account's email stays unverified.
	registerTestAdapter.Do(func() {
		federation.RegisterAdapter(&federation.Adapter{Name: "unverified-oidc", OIDC: true, Prepare: func(in *federation.Input) error { return nil }})
	})
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.Mode = realm.RegistrationPublic }), 200, "public registration")
	f.must(create(map[string]any{"alias": "custom", "display_name": "Custom", "adapter": "unverified-oidc", "issuer": idp.srv.URL, "client_secret": "upstream-secret",
		"config": map[string]any{"client_id": "proudauth-main", "scopes": []string{"openid", "email"}}, "jit_provisioning": true}), 201, "custom adapter")
	idp.next = map[string]any{"sub": "u-custom", "email": "custom@corp.test", "email_verified": true}
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	st := h.Step(start.Str("transaction_id"), cont, "federation/start", map[string]any{"provider": "custom"})
	mustStatus(t, st, 200, "federation start")
	mustStatus(t, h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}), 200, "callback")
	var verified *time.Time
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT verified_at FROM user_identifiers WHERE canonical_value='custom@corp.test'`).Scan(&verified); err != nil {
		t.Fatalf("JIT account not created: %v", err)
	}
	if verified != nil {
		t.Fatal("an adapter without trusted email assertions produced a verified email")
	}
	customLogin := func(claims map[string]any) *Resp {
		t.Helper()
		idp.next = claims
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		st := h.Step(start.Str("transaction_id"), cont, "federation/start", map[string]any{"provider": "custom"})
		mustStatus(t, st, 200, "federation start")
		mustStatus(t, h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}), 200, "callback")
		return h.Step(start.Str("transaction_id"), cont, "resume", nil)
	}
	// An unverified upstream email that another account has verified is never
	// claimed, nor copied into the new account (whose mail would reach alice).
	customLogin(map[string]any{"sub": "u-alice", "email": "alice@example.test", "email_verified": true})
	var holders int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM user_identifiers WHERE canonical_value='alice@example.test'`).Scan(&holders)
	if holders != 1 {
		t.Fatalf("alice's address copied into a JIT account: %d holders", holders)
	}
	// Two upstream accounts with the same login name both get accounts.
	for _, sub := range []string{"u-dup-1", "u-dup-2"} {
		customLogin(map[string]any{"sub": sub, "login": "dup"})
	}
	var dups int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM user_identifiers WHERE type='username' AND canonical_value LIKE 'custom-dup%'`).Scan(&dups)
	if dups != 2 {
		t.Fatalf("username collision: %d accounts", dups)
	}

	// FED-013: local and upstream logout are separate and reported honestly.
	f.must(create(map[string]any{"alias": "custom2", "display_name": "Custom 2", "adapter": "unverified-oidc", "issuer": idp.srv.URL,
		"client_secret": "upstream-secret", "jit_provisioning": true,
		"config": map[string]any{"client_id": "proudauth-main", "scopes": []string{"openid", "email"}, "end_session_endpoint": idp.srv.URL + "/logout"}}), 201, "custom2")
	fedLogin := func(provider, sub string) string {
		t.Helper()
		idp.next = map[string]any{"sub": sub, "email": sub + "@corp.test", "email_verified": true}
		start, verifier, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid"})
		txID := start.Str("transaction_id")
		st := h.Step(txID, cont, "federation/start", map[string]any{"provider": provider})
		mustStatus(t, st, 200, "federation start")
		mustStatus(t, h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}), 200, "callback")
		done := h.Step(txID, cont, "resume", nil)
		u, err := url.Parse(done.Str("redirect_to"))
		if err != nil || u.Query().Get("code") == "" {
			t.Fatalf("federated login: %s", done.Raw)
		}
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {webRedirect}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, toks, 200, "tokens")
		return toks.Str("id_token")
	}
	logout := func(hint string, extra url.Values) *Resp {
		q := url.Values{"id_token_hint": {hint}}
		for k, v := range extra {
			q[k] = v
		}
		return h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout?" + q.Encode()})
	}
	local := logout(fedLogin("custom", "u-custom"), nil)
	if local.Str("upstream_logout.status") != "not_requested" || local.Str("upstream_logout.provider") != "custom" || local.Get("session_ended") != true {
		t.Fatalf("local logout report: %s", local.Raw)
	}
	back := url.Values{"upstream_logout": {"true"}, "post_logout_redirect_uri": {"https://app.test/bye"}, "state": {"xyz"}}
	unsupported := logout(fedLogin("custom", "u-custom"), back)
	if loc := unsupported.Header.Get("Location"); loc != "https://app.test/bye?state=xyz&upstream_logout=unsupported" {
		t.Fatalf("provider without a logout endpoint: %d %s", unsupported.Status, loc)
	}
	redirected := logout(fedLogin("custom2", "u-two"), back)
	up, err := url.Parse(redirected.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(up.String(), idp.srv.URL+"/logout?") || up.Query().Get("client_id") != "proudauth-main" ||
		!strings.HasSuffix(up.Query().Get("post_logout_redirect_uri"), "/realms/main/oidc/logout/upstream-return") {
		t.Fatalf("upstream logout redirect: %d %s", redirected.Status, redirected.Header.Get("Location"))
	}
	ret := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout/upstream-return?state=" + url.QueryEscape(up.Query().Get("state"))})
	if loc := ret.Header.Get("Location"); loc != "https://app.test/bye?state=xyz&upstream_logout=returned" {
		t.Fatalf("return from the provider: %d %s", ret.Status, loc)
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout/upstream-return?state=forged"}), 400, "forged state")
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout/upstream-return?state=" + url.QueryEscape(up.Query().Get("state"))}), 400, "replayed state")
}
