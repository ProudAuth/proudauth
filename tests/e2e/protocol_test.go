package e2e

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func (f *Fixture) codeFor(t *testing.T, user string) (code, verifier string) {
	t.Helper()
	start, v, cont := f.H.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud},
		Organization: f.Acme})
	tx := start.Str("transaction_id")
	st := f.H.Drive(tx, cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, LoginOpts{Identifier: user + "@example.test", SelectOrg: f.Acme})
	u, _ := url.Parse(st.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("no code: %s", st.Raw)
	}
	if u.Query().Get("iss") != f.H.Realm.Issuer {
		t.Fatal("authorization responses must carry iss (RFC 9207)")
	}
	return u.Query().Get("code"), v
}

func (f *Fixture) redeem(code, verifier, redirect string) *Resp {
	return f.H.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirect}},
		"web-bff", f.Clients["web"].Secret)
}

// TestAuthorizationCodeBinding covers AUT-020: a redirect outside the
// client's exact registrations (trailing slash, host, userinfo, query, case,
// encoding and scheme tricks) is refused by the transaction API and never
// redirected to by the authorization endpoint; codes stay bound to the
// original client, redirect and PKCE verifier (TEST-028, TEST-029).
// Requirements: TOK-001 (code with PKCE is the user grant; the password grant
// does not exist), TOK-002 (S256 only, required for confidential clients too,
// and bound to the code).
func TestAuthorizationCodeBinding(t *testing.T) {
	f := NewFixture(t)
	t.Run("TEST-028 wrong PKCE verifier", func(t *testing.T) {
		code, _ := f.codeFor(t, "bob")
		other, _ := PKCE()
		mustStatus(t, f.redeem(code, other, webRedirect), 400, "wrong verifier")
	})
	t.Run("TEST-028 wrong redirect", func(t *testing.T) {
		code, v := f.codeFor(t, "bob")
		mustStatus(t, f.redeem(code, v, "https://app.test/other"), 400, "wrong redirect")
	})
	t.Run("TEST-028 code replay revokes issued tokens", func(t *testing.T) {
		code, v := f.codeFor(t, "bob")
		first := f.redeem(code, v, webRedirect)
		mustStatus(t, first, 200, "first redemption")
		mustStatus(t, f.redeem(code, v, webRedirect), 400, "replay")
		in := f.H.Introspect("orders-rs", f.Clients["orders-rs"].Secret, first.Str("access_token"))
		_ = in
		r := f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, r, 400, "refresh after code replay")
	})
	t.Run("TEST-028 code bound to client", func(t *testing.T) {
		code, v := f.codeFor(t, "bob")
		r := f.H.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}, "redirect_uri": {webRedirect}},
			"partner-app", "")
		if r.Status != 400 {
			t.Fatalf("another client redeemed the code: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("code expiry", func(t *testing.T) {
		code, v := f.codeFor(t, "bob")
		f.H.Clock.Advance(2 * time.Minute)
		mustStatus(t, f.redeem(code, v, webRedirect), 400, "expired code")
	})
	t.Run("TEST-029 redirect tricks", func(t *testing.T) {
		_, challenge := PKCE()
		for _, ru := range []string{"https://app.test/callback/", "https://app.test.evil.com/callback", "https://user@app.test/callback",
			"https://app.test/callback?x=1", "https://APP.test/callback", "https://app.test/%2e%2e/callback", "javascript:alert(1)"} {
			r := f.H.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": ru, "scope": "orders:read",
				"code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{f.OrdersAud}})
			if r.Status == 201 {
				t.Fatalf("redirect %q accepted", ru)
			}
			q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {ru}, "response_type": {"code"}, "scope": {"orders:read"},
				"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
			res := f.H.Do(Req{Method: "GET", Path: "/realms/main/oauth/authorize?" + q.Encode()})
			if res.Status == 302 {
				t.Fatalf("authorize redirected to unregistered %q", ru)
			}
		}
	})
	t.Run("PKCE plain and missing are refused", func(t *testing.T) {
		r := f.H.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "orders:read",
			"code_challenge": "abc", "code_challenge_method": "plain"})
		mustStatus(t, r, 400, "plain PKCE")
		// web-bff is confidential: client authentication does not replace PKCE (TOK-002).
		r = f.H.API("POST", "/auth/transactions", "", map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "orders:read",
			"resource": []string{f.OrdersAud}})
		if r.Status != 400 || !strings.Contains(string(r.Raw), "S256") {
			t.Fatalf("confidential client without PKCE: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("password and implicit grants do not exist", func(t *testing.T) {
		r := f.H.TokenRequest(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"x"}}, "web-bff", f.Clients["web"].Secret)
		if r.Status != 400 || (r.Str("error") != "unsupported_grant_type" && r.Str("error") != "unauthorized_client") {
			t.Fatalf("password grant: %d %s", r.Status, r.Raw)
		}
	})
}

// TestRefreshRotation covers SES-006 (a rotation family issues one successor
// per generation, TEST-030; reuse puts it in a compromised state; it has its
// own absolute expiry, TEST-032) and SES-008 (replaying a rotated token
// invalidates the whole family and is audited, TEST-031).
// Requirements: DB-006 (one authorized successor per consumed generation,
// with the compromise state checked in the rotation), ARC-002 (rotation
// relies on the database, not a cache).
func TestRefreshRotation(t *testing.T) {
	f := NewFixture(t)
	lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	rt := lr.Tokens.Str("refresh_token")
	refresh := func(tok string) *Resp {
		return f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}}, "web-bff", f.Clients["web"].Secret)
	}
	t.Run("TEST-030 parallel refresh creates one successor", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make([]*Resp, 6)
		for i := range results {
			wg.Add(1)
			go func(i int) { defer wg.Done(); results[i] = refresh(rt) }(i)
		}
		wg.Wait()
		ok := 0
		for _, r := range results {
			if r.Status == 200 {
				ok++
			}
		}
		if ok > 1 {
			t.Fatalf("%d independent successors were issued", ok)
		}
	})
	t.Run("TEST-031 rotated token reuse compromises the family", func(t *testing.T) {
		lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
		first := lr.Tokens.Str("refresh_token")
		next := refresh(first)
		mustStatus(t, next, 200, "rotate")
		if next.Str("refresh_token") == first {
			t.Fatal("refresh token must rotate")
		}
		mustStatus(t, refresh(first), 400, "reuse")
		mustStatus(t, refresh(next.Str("refresh_token")), 400, "family revoked after reuse")
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=token.refresh.reuse_detected", nil), 200, "audit")
		if len(ev.Get("items").([]any)) == 0 {
			t.Fatal("reuse must be audited")
		}
	})
	t.Run("refresh cannot expand scope", func(t *testing.T) {
		lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read")
		r := f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}, "scope": {"orders:read orders:write"}},
			"web-bff", f.Clients["web"].Secret)
		mustStatus(t, r, 400, "scope expansion")
	})
	t.Run("TEST-032 absolute session lifetime", func(t *testing.T) {
		started := f.H.Clock.Now()
		lr := f.LoginWeb("carol", f.Globex, f.OrdersAud, "orders:read")
		tok := lr.Tokens.Str("refresh_token")
		for i := 0; i < 30; i++ {
			f.H.Clock.Advance(25 * time.Minute) // inside the idle window each time
			r := refresh(tok)
			if r.Status != 200 {
				if f.H.Clock.Now().Sub(started) < 12*time.Hour {
					t.Fatalf("refresh failed before the absolute bound: %s", r.Raw)
				}
				return
			}
			tok = r.Str("refresh_token")
		}
		t.Fatal("refresh extended the session past its 12h absolute lifetime")
	})
}

// TestMultiFactorAndProofs covers MFA-002: one TOTP code submitted
// concurrently from several transactions is accepted exactly once (TEST-023),
// and repeated wrong codes across transactions hit the per-account proof
// budget, which expires with its window (TEST-021).
// Requirements: DB-005 (TOTP steps and recovery codes are consumed once by
// conditional atomic writes).
func TestMultiFactorAndProofs(t *testing.T) {
	f := NewFixture(t, func(p *realmPolicy) { p.MFA.Requirement = "required" })
	h := f.H
	// Sam (support operator) and everyone else must enroll TOTP; enrollment happens in-transaction.
	lr := f.AccountToken("bob")
	if lr.Tokens.Str("access_token") == "" {
		t.Fatal("login with enrollment failed")
	}
	t.Run("TEST-022 no grant before MFA through any route", func(t *testing.T) {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
		if st.Str("redirect_to") != "" {
			t.Fatal("grant issued before MFA")
		}
		// Client-submitted completion flags are ignored (AUT-004): unknown fields are rejected.
		bad := h.Step(tx, cont, "consent", map[string]any{"approve": true, "mfa_passed": true})
		if bad.Status == 200 && bad.Str("redirect_to") != "" {
			t.Fatal("client flag completed MFA")
		}
		// Email OTP login is a primary factor, not a second factor (PWDLESS-006).
		start2, _, cont2 := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		tx2 := start2.Str("transaction_id")
		h.Step(tx2, cont2, "identify", map[string]any{"identifier": "bob@example.test"})
		h.Clock.Advance(2 * time.Second)
		mustStatus(t, h.Step(tx2, cont2, "otp/send", map[string]any{"purpose": "login"}), 200, "send login otp")
		code := CodeFrom(h.Mail("bob@example.test", "login_code"))
		st2 := h.Step(tx2, cont2, "otp/verify", map[string]any{"code": code})
		if st2.Str("redirect_to") != "" || !strings.Contains(string(st2.Raw), `"totp"`) {
			t.Fatalf("email OTP must not satisfy MFA: %s", st2.Raw)
		}
	})
	t.Run("TEST-023 concurrent TOTP reuse", func(t *testing.T) {
		code := h.TOTPNow("bob@example.test")
		var wg sync.WaitGroup
		statuses := make([]int, 4)
		for i := range statuses {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
				tx := start.Str("transaction_id")
				h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
				h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
				r := h.Step(tx, cont, "totp", map[string]any{"code": code})
				if r.Str("redirect_to") != "" {
					statuses[i] = 200
				} else {
					statuses[i] = r.Status
				}
			}(i)
		}
		wg.Wait()
		ok := 0
		for _, s := range statuses {
			if s == 200 {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("one TOTP step must be usable once: %v", statuses)
		}
	})
	t.Run("TEST-021 distributed OTP guessing is budgeted", func(t *testing.T) {
		f.AccountToken("carol") // enroll TOTP first
		limited := false
		for i := 0; i < 20 && !limited; i++ {
			start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
			tx := start.Str("transaction_id")
			h.Step(tx, cont, "identify", map[string]any{"identifier": "carol@example.test"})
			pw := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["carol@example.test"]})
			if pw.Status == 429 {
				limited = true // the shared per-identifier budget applies across transactions
				break
			}
			r := h.Step(tx, cont, "totp", map[string]any{"code": "000000"})
			if r.Status == 429 {
				limited = true
			}
			t.Logf("attempt %d: password=%d totp=%d %s", i, pw.Status, r.Status, r.Str("code"))
		}
		if !limited {
			t.Fatal("per-account verification budget never applied across transactions")
		}
		h.Clock.Advance(20 * time.Minute) // budgets are windowed: no permanent lockout
		f.AccountToken("carol")
	})
	t.Run("recovery codes are single use and restrict the session", func(t *testing.T) {
		acct := f.AccountToken("alice").Tokens.Str("access_token")
		regen := h.API("POST", "/me/recovery-codes/regenerate", acct, nil)
		mustStatus(t, regen, 200, "regenerate")
		code := regen.Get("recovery_codes").([]any)[0].(string)
		lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
			Identifier: "alice@example.test", UseRecovery: code})
		sessions := h.API("GET", "/me/sessions", lr.Tokens.Str("access_token"), nil)
		restricted := false
		for _, s := range sessions.Get("items").([]any) {
			if m := s.(map[string]any); m["current"] == true && m["recovery_restricted"] == true {
				restricted = true
			}
		}
		if !restricted {
			t.Fatal("recovery-code sessions must be recovery-restricted (MFA-010)")
		}
		// The restricted session may enroll a factor and end sessions, nothing else.
		rtok := lr.Tokens.Str("access_token")
		for name, call := range map[string][2]string{
			"password change":   {"POST", "/me/password"},
			"identifier change": {"POST", "/me/identifiers"},
			"deletion request":  {"POST", "/me/deletion-request"},
			"data export":       {"POST", "/me/exports"},
			"personal token":    {"POST", "/me/personal-tokens"},
			"profile change":    {"PATCH", "/me"},
		} {
			if r := h.API(call[0], call[1], rtok, map[string]any{}); r.Status != 403 || r.Str("code") != "recovery_restricted" {
				t.Fatalf("%s from a recovery-restricted session: %d %s", name, r.Status, r.Raw)
			}
		}
		if r := h.API("POST", "/me/totp/enroll", rtok, nil); r.Str("code") == "recovery_restricted" {
			t.Fatalf("factor enrollment refused to a recovery-restricted session: %s", r.Raw)
		}
		// The account is recovery-restricted until a strong factor is used (USR-003).
		accountState := func() string {
			var st string
			_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state FROM users WHERE id=$1`, f.Users["alice"]).Scan(&st)
			return st
		}
		if st := accountState(); st != "recovery_restricted" {
			t.Fatalf("account state after recovery sign-in: %s", st)
		}
		f.AccountToken("alice")
		if st := accountState(); st != "active" {
			t.Fatalf("account state after a strong sign-in: %s", st)
		}
		again := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
			Identifier: "alice@example.test", UseRecovery: code, ExpectFail: true})
		if again.Code != "" {
			t.Fatal("recovery code reused")
		}
	})
}
