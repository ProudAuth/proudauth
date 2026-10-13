package e2e

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
)

// TestAccessTokenProfile covers TOK-004 (asymmetrically signed at+jwt access
// tokens carrying the JWT access-token profile's claims), TOK-007 (exactly
// one registered audience the client may request, never an unregistered or
// wildcard one) and TOK-014 (compact claims: no contact data, profile or
// permission lists, whatever the user consented to release elsewhere).
func TestAccessTokenProfile(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid profile email orders:read")
	at := lr.Tokens.Str("access_token")

	raw, err := base64URL(strings.Split(at, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["typ"] != "at+jwt" || hdr["kid"] == nil || !slices.Contains([]any{"RS256", "PS256", "ES256", "EdDSA"}, hdr["alg"]) {
		t.Fatalf("access-token header: %v", hdr)
	}
	claims := jwtPayload(at)
	if claims["iss"] != h.Realm.Issuer || claims["sub"] != f.Users["alice"] || claims["client_id"] != "web-bff" || claims["token_kind"] != "user_access" {
		t.Fatalf("access-token claims: %v", claims)
	}
	for _, c := range []string{"exp", "iat", "jti"} {
		if claims[c] == nil {
			t.Errorf("access token lacks %s: %v", c, claims)
		}
	}
	// TOK-007: one audience, the registered resource that was requested.
	if claims["aud"] != f.OrdersAud {
		t.Fatalf("audience must be exactly the requested resource: %v", claims["aud"])
	}
	// TOK-014: only the compact, non-sensitive claim set.
	compact := map[string]bool{"iss": true, "sub": true, "aud": true, "client_id": true, "iat": true, "nbf": true, "exp": true, "jti": true,
		"sid": true, "grant_id": true, "scope": true, "org_id": true, "token_kind": true, "authz_version": true, "auth_time": true, "acr": true, "amr": true}
	for k := range claims {
		if !compact[k] {
			t.Errorf("access token carries %s=%v", k, claims[k])
		}
	}
	if len(at) > 2048 {
		t.Errorf("access token is %d bytes", len(at))
	}
	if idt := jwtPayload(lr.Tokens.Str("id_token")); idt["email"] == nil {
		t.Fatalf("fixture: the consented email belongs in the ID token: %v", idt)
	}

	// TOK-007: unregistered, wildcard and ungranted audiences are refused.
	_, challenge := PKCE()
	start := func(client, scope string, resources ...string) *Resp {
		return h.API("POST", "/auth/transactions", "", map[string]any{"client_id": client, "redirect_uri": map[string]string{"web-bff": webRedirect,
			"partner-app": "https://partner.test/cb"}[client], "scope": scope, "code_challenge": challenge, "code_challenge_method": "S256", "resource": resources})
	}
	for name, r := range map[string]*Resp{
		"unregistered audience":     start("web-bff", "orders:read", "https://unregistered.test"),
		"wildcard audience":         start("web-bff", "orders:read", "*"),
		"audience not granted":      start("partner-app", "billing:read", f.BillingAud),
		"scope of another audience": start("web-bff", "billing:read", f.OrdersAud),
	} {
		if r.Status != 400 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := f.MachineToken(f.Clients["batch"], f.OrdersAud, "orders:read", f.Acme); r.Status != 400 || r.Str("error") != "invalid_target" {
		t.Fatalf("machine token for an audience the client has no grant for: %d %s", r.Status, r.Raw)
	}
	if r := f.MachineToken(f.Clients["batch"], "https://unregistered.test", "billing:read", f.Acme); r.Status != 400 || r.Str("error") != "invalid_target" {
		t.Fatalf("machine token for an unregistered audience: %d %s", r.Status, r.Raw)
	}
	m := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)
	mustStatus(t, m, 200, "machine token")
	if aud := jwtPayload(m.Str("access_token"))["aud"]; aud != f.BillingAud {
		t.Fatalf("machine token audience: %v", aud)
	}
}

// TestBearerArtifactsStoredAsDigests covers TOK-003: authorization codes,
// refresh tokens, opaque support tokens, API keys, personal access tokens and
// client secrets are random, purpose-prefixed values that the database holds
// only as SHA-256 digests; no row contains the secret itself.
func TestBearerArtifactsStoredAsDigests(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	code, verifier := f.codeFor(t, "bob")
	stored := func(table, column, plain, prefix string) {
		t.Helper()
		if !strings.HasPrefix(plain, prefix) {
			t.Fatalf("%s secret %q lacks its purpose prefix %s", table, plain, prefix)
		}
		var n, leaks int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, secret.Digest(plain)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` t WHERE strpos(t::text, $1) > 0`, strings.TrimPrefix(plain, prefix)).Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if n != 1 || leaks != 0 {
			t.Fatalf("%s: %d rows with the digest, %d rows containing the secret", table, n, leaks)
		}
	}
	stored("authorization_codes", "code_digest", code, secret.PrefixAuthCode)
	tokens := f.redeem(code, verifier, webRedirect)
	mustStatus(t, tokens, 200, "redeem")
	stored("refresh_tokens", "token_digest", tokens.Str("refresh_token"), secret.PrefixRefresh)
	stored("client_credentials", "secret_digest", f.Clients["web"].Secret, secret.PrefixClientSecret)

	s := f.support(t)
	support := s.issue(t, f.Users["bob"], f.Acme).Str("access_token")
	stored("opaque_access_tokens", "token_digest", support, secret.PrefixImpersonation)

	key := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": f.Clients["batch"].SP, "name": "digest-check",
		"audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme}), 201, "api key").Str("api_key")
	stored("automation_credentials", "secret_digest", key, secret.PrefixAPIKey)
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	pat := f.must(h.API("POST", "/me/personal-tokens", bob, map[string]any{"name": "cli", "audience": f.OrdersAud, "scopes": []string{"orders:read"},
		"organization_id": f.Acme, "ttl_days": 7}), 201, "personal token").Str("token")
	stored("automation_credentials", "secret_digest", pat, secret.PrefixPAT)
}

// TestAuthorizeRequestValidation covers OIDC-001 and TOK-002: an unknown
// client or an unregistered redirect is answered locally; once the redirect
// is validated, a wrong response type or response mode, missing or non-S256
// PKCE (for a confidential client too), unknown or disallowed scopes and
// unregistered resources return an error to that redirect with state and iss,
// and none of them starts an authentication transaction.
func TestAuthorizeRequestValidation(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	ctx := context.Background()
	_, challenge := PKCE()
	transactions := func() int {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM auth_transactions WHERE realm_id=$1`, h.Realm.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	authorize := func(change map[string]string) *Resp {
		q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
			"state": {"st-7"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}}
		for k, v := range change {
			if v == "" {
				q.Del(k)
			} else {
				q.Set(k, v)
			}
		}
		return h.Do(Req{Method: "GET", Path: "/realms/main/oauth/authorize?" + q.Encode()})
	}
	before := transactions()
	for name, change := range map[string]map[string]string{
		"unknown client":        {"client_id": "no-such-client"},
		"unregistered redirect": {"redirect_uri": "https://app.test/elsewhere"},
		"missing redirect":      {"redirect_uri": ""},
	} {
		r := authorize(change)
		if r.Status != 400 || r.Header.Get("Location") != "" {
			t.Errorf("%s must fail locally: %d %q", name, r.Status, r.Header.Get("Location"))
		}
	}
	for name, c := range map[string]struct {
		change map[string]string
		code   string
	}{
		"implicit response type":  {map[string]string{"response_type": "token"}, "unsupported_response_type"},
		"hybrid response type":    {map[string]string{"response_type": "code id_token"}, "unsupported_response_type"},
		"form_post response mode": {map[string]string{"response_mode": "form_post"}, "invalid_request"},
		"missing PKCE":            {map[string]string{"code_challenge": "", "code_challenge_method": ""}, "invalid_request"},
		"plain PKCE":              {map[string]string{"code_challenge_method": "plain"}, "invalid_request"},
		"malformed challenge":     {map[string]string{"code_challenge": "short"}, "invalid_request"},
		"unknown scope":           {map[string]string{"scope": "openid orders:delete"}, "invalid_scope"},
		"scope not allowed":       {map[string]string{"scope": "billing:admin", "resource": f.BillingAud}, "invalid_scope"},
		"unregistered resource":   {map[string]string{"resource": "https://unregistered.test"}, "invalid_target"},
		"request object":          {map[string]string{"request": "eyJhbGciOiJub25lIn0.e30."}, "request_not_supported"},
	} {
		r := authorize(c.change)
		loc, err := url.Parse(r.Header.Get("Location"))
		if r.Status != 302 || err != nil || loc.Scheme+"://"+loc.Host+loc.Path != webRedirect {
			t.Errorf("%s: want a redirect to the validated redirect URI, got %d %q", name, r.Status, r.Header.Get("Location"))
			continue
		}
		if q := loc.Query(); q.Get("error") != c.code || q.Get("state") != "st-7" || q.Get("iss") != h.Realm.Issuer || q.Get("code") != "" {
			t.Errorf("%s: %s", name, loc.RawQuery)
		}
	}
	if n := transactions(); n != before {
		t.Fatalf("invalid requests started %d transactions", n-before)
	}
	ok := authorize(nil)
	if loc, _ := url.Parse(ok.Header.Get("Location")); ok.Status != 302 || loc.Host != "login.test" || transactions() != before+1 {
		t.Fatalf("valid request: %d %q", ok.Status, ok.Header.Get("Location"))
	}
}

// TestAuthenticationContext covers OIDC-009: discovery publishes the
// recognized assurance values; an unrecognized acr value fails the request;
// acr_values=mfa makes the login require a second factor, and the issued acr
// reports the assurance actually reached instead of echoing the request; a
// phishing-resistant request is not satisfied by a password and TOTP.
func TestAuthenticationContext(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	d := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	published := jsonString(d.Get("acr_values_supported"))
	for _, v := range []string{"urn:proudauth:acr:single_factor", "urn:proudauth:acr:mfa", "urn:proudauth:acr:phishing_resistant"} {
		if !strings.Contains(published, v) {
			t.Fatalf("acr_values_supported lacks %s: %s", v, published)
		}
	}
	opts := func(user, acr string) LoginOpts {
		return LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "openid orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: user + "@example.test", ACR: acr}
	}
	start, _, _ := h.StartTx(opts("bob", "urn:example:acr:gold"))
	if start.Status != 400 || !strings.Contains(string(start.Raw), "acr") {
		t.Fatalf("unrecognized acr value accepted: %d %s", start.Status, start.Raw)
	}
	passwordOnly := func(user, acr string) *Resp {
		start, _, cont := h.StartTx(opts(user, acr))
		mustStatus(t, start, 201, "start "+acr)
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": user + "@example.test"})
		return h.Step(tx, cont, "password", map[string]any{"password": h.passwords[user+"@example.test"]})
	}
	if st := passwordOnly("bob", "urn:proudauth:acr:mfa"); st.Str("redirect_to") != "" || st.Str("status") != "pending" {
		t.Fatalf("an mfa request was satisfied by a password: %s", st.Raw)
	}
	plain := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	if acr := jwtPayload(plain.Tokens.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:single_factor" {
		t.Fatalf("password login reported %v", acr)
	}
	f.EnrollTOTP("alice")
	mfa := h.Login(opts("alice", "urn:proudauth:acr:mfa"))
	if idACR, atACR := jwtPayload(mfa.Tokens.Str("id_token"))["acr"], jwtPayload(mfa.Tokens.Str("access_token"))["acr"]; idACR != "urn:proudauth:acr:mfa" || atACR != idACR {
		t.Fatalf("mfa login reported id %v access %v", idACR, atACR)
	}
	start, _, cont := h.StartTx(opts("alice", "urn:proudauth:acr:phishing_resistant"))
	mustStatus(t, start, 201, "start phishing-resistant")
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "alice@example.test"})
	h.Step(tx, cont, "password", map[string]any{"password": h.passwords["alice@example.test"]})
	if st := h.Step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("alice@example.test")}); st.Str("redirect_to") != "" {
		t.Fatalf("phishing-resistant request satisfied by password and TOTP: %s", st.Raw)
	}
}

// TestInteractionHints covers OIDC-011: login_hint and ui_locales are hints
// only. A hint naming one account neither identifies nor authenticates it
// and another account can sign in instead; the locale shapes the interaction;
// an id_token_hint is verified before its contents are used.
func TestInteractionHints(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	verifier, challenge := PKCE()
	start := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "openid orders:read",
		"code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{f.OrdersAud}, "organization": f.Acme,
		"login_hint": "alice@example.test", "ui_locales": "fr"})
	mustStatus(t, start, 201, "start with hints")
	state := &Resp{Status: 200, Body: start.Get("state").(map[string]any)}
	if types := actionTypes(state); !has(types, "identify") || has(types, "password") || state.Str("locale") != "fr" {
		t.Fatalf("a login hint must not identify the account: %s", start.Raw)
	}
	st := h.Drive(start.Str("transaction_id"), start.Str("continuation_token"), state, LoginOpts{Identifier: "bob@example.test", SelectOrg: f.Acme})
	u, err := url.Parse(st.Str("redirect_to"))
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("login as another account than the hint: %s", st.Raw)
	}
	tokens := f.redeem(u.Query().Get("code"), verifier, webRedirect)
	mustStatus(t, tokens, 200, "tokens")
	idToken := tokens.Str("id_token")
	if sub := jwtPayload(idToken)["sub"]; sub != f.Users["bob"] {
		t.Fatalf("the hint chose the subject: %v", sub)
	}
	forged := forge(t, map[string]any{"iss": h.Realm.Issuer, "sub": f.Users["alice"], "aud": "web-bff", "iat": h.Clock.Now().Unix(),
		"exp": h.Clock.Now().Add(5 * time.Minute).Unix(), "sid": jwtPayload(idToken)["sid"]}, "JWT", kidOf(idToken))
	bye := url.QueryEscape("https://app.test/bye")
	if r := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout?id_token_hint=" + forged + "&post_logout_redirect_uri=" + bye}); r.Status != 400 {
		t.Fatalf("unverified id_token_hint used: %d %s", r.Status, r.Raw)
	}
	if r := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout?id_token_hint=" + idToken + "&post_logout_redirect_uri=" + bye}); r.Status != 302 ||
		!strings.HasPrefix(r.Header.Get("Location"), "https://app.test/bye") {
		t.Fatalf("verified id_token_hint: %d %s", r.Status, r.Header.Get("Location"))
	}
}
