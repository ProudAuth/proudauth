package e2e

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestHOTP covers MFA-013: counter-based codes are opt-in realm policy
// separate from TOTP, the counter advances atomically (a code is accepted
// once, also under concurrent submission), sign-in accepts only a bounded
// look-ahead, and a token pressed further ahead is realigned only by an
// explicit resynchronization with two consecutive codes.
func TestHOTP(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/hotp/enroll", bob, nil), 409, "hotp not allowed by default")
	f.must(f.SetPolicy(func(p *realm.Policy) {
		p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, "hotp")
		p.MFA.HOTP = realm.HOTPPolicy{LookAhead: 5, ResyncWindow: 50}
	}), 200, "allow hotp")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.HOTP.LookAhead = 51 }), 422, "look-ahead bound")

	// A second session of bob, opened before he has any factor: it never
	// completes MFA.
	single := f.AccountToken("bob").Tokens.Str("access_token")
	h.Clock.Advance(time.Second) // later sessions sort after it
	en := f.must(h.API("POST", "/me/hotp/enroll", bob, nil), 201, "enroll")
	seed := en.Str("secret")
	if !strings.HasPrefix(en.Str("otpauth_uri"), "otpauth://hotp/") || !strings.Contains(en.Str("otpauth_uri"), "counter=0") {
		t.Fatalf("provisioning URI: %s", en.Raw)
	}
	code := func(c int64) string {
		t.Helper()
		s, err := credential.HOTPCode(seed, c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	mustStatus(t, h.API("POST", "/me/hotp/activate", bob, map[string]any{"code": code(7)}), 400, "activation beyond the look-ahead")
	act := f.must(h.API("POST", "/me/hotp/activate", bob, map[string]any{"code": code(2)}), 200, "activate")
	recoveryCodes, _ := act.Get("recovery_codes").([]any)
	if len(recoveryCodes) == 0 {
		t.Fatalf("first factor issues recovery codes: %s", act.Raw)
	}
	// Moving the counter is a factor change: like regenerating recovery
	// codes, it needs a session that completed MFA.
	if r := h.API("POST", "/me/hotp/resync", single, map[string]any{"code": code(10), "next_code": code(11)}); r.Status != 403 || r.Str("code") != "mfa_required" {
		t.Fatalf("resync from a single-factor session: %d %s", r.Status, r.Raw)
	}

	login := func(c string) *LoginResult {
		t.Helper()
		return h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
			Identifier: "bob@example.test", HOTPCode: c, ExpectFail: true})
	}
	// The enrolled token makes MFA required and is offered as a step.
	if r := login(code(2)); r.Tokens != nil {
		t.Fatal("the activation code was accepted again at sign-in")
	}
	ok := login(code(3))
	if ok.Tokens == nil || ok.Tokens.Status != 200 {
		t.Fatalf("hotp sign-in: %s", ok.State.Raw)
	}
	if acr := jwtPayload(ok.Tokens.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:mfa" {
		t.Fatalf("acr after hotp: %v", acr)
	}
	var amr []string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT amr FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, f.Users["bob"]).Scan(&amr)
	if !slices.Contains(amr, "hotp") || !slices.Contains(amr, "mfa") {
		t.Fatalf("session amr: %v", amr)
	}
	if r := login(code(3)); r.Tokens != nil {
		t.Fatal("a used code was accepted again")
	}
	if r := login(code(9)); r.Tokens != nil {
		t.Fatal("a code beyond the look-ahead was accepted at sign-in")
	}

	// Concurrent submission of one code: exactly one transaction wins.
	type tx struct{ id, cont string }
	var txs []tx
	for range 4 {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		id := start.Str("transaction_id")
		h.Step(id, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		if st := h.Step(id, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}); !hasAction(st, "hotp") {
			t.Fatalf("hotp not offered: %s", st.Raw)
		}
		txs = append(txs, tx{id, cont})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for _, x := range txs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st := h.Step(x.id, x.cont, "hotp", map[string]any{"code": code(4)}); st.Status == 200 {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("one code accepted %d times", accepted)
	}

	// The token was pressed far ahead: one code there is refused, two
	// consecutive codes realign the counter. (A new budget window first: the
	// failures above used up the account's proof budget.)
	h.Clock.Advance(time.Hour)
	bob = login(code(5)).Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/hotp/resync", bob, map[string]any{"code": code(30), "next_code": code(32)}), 400, "codes not consecutive")
	mustStatus(t, h.API("POST", "/me/hotp/resync", bob, map[string]any{"code": code(80), "next_code": code(81)}), 400, "beyond the resync window")
	f.must(h.API("POST", "/me/hotp/resync", bob, map[string]any{"code": code(30), "next_code": code(31)}), 200, "resync")
	if r := login(code(31)); r.Tokens != nil {
		t.Fatal("a resynchronization code was accepted at sign-in")
	}
	if r := login(code(33)); r.Tokens == nil || r.Tokens.Status != 200 {
		t.Fatalf("sign-in after resynchronization: %s", r.State.Raw)
	}
	var events int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE subject_id=$1 AND type IN ('mfa.hotp.enrolled','mfa.hotp.used','mfa.hotp.resynchronized')`,
		f.Users["bob"]).Scan(&events)
	if events < 4 {
		t.Fatalf("hotp evidence: %d events", events)
	}

	// A recovery-restricted session may enroll HOTP (MFA-010): activation
	// restores the session and the account, as TOTP and passkeys do.
	rec := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "bob@example.test", UseRecovery: recoveryCodes[0].(string)})
	rtok := rec.Tokens.Str("access_token")
	accountState := func() string {
		var st string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["bob"]).Scan(&st)
		return st
	}
	if st := accountState(); st != "recovery_restricted" {
		t.Fatalf("account after a recovery-code sign-in: %s", st)
	}
	mustStatus(t, h.API("POST", "/me/password", rtok, map[string]any{}), 403, "other writes stay closed to the restricted session")
	en = f.must(h.API("POST", "/me/hotp/enroll", rtok, nil), 201, "hotp enrollment from a recovery-restricted session")
	seed = en.Str("secret")
	f.must(h.API("POST", "/me/hotp/activate", rtok, map[string]any{"code": code(1)}), 200, "hotp activation from a recovery-restricted session")
	if st := accountState(); st != "active" {
		t.Fatalf("account after hotp activation in a recovery session: %s", st)
	}
	var restricted bool
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT recovery_restricted FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, f.Users["bob"]).Scan(&restricted)
	if restricted {
		t.Fatal("the session stayed recovery-restricted after hotp activation")
	}

	// Removing hotp from the realm's factors stops offering it.
	f.ReloginAdmin()
	f.must(f.SetPolicy(func(p *realm.Policy) { p.MFA.AllowedFactors = []string{"totp", "webauthn", "recovery_code"} }), 200, "disallow hotp")
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	id := start.Str("transaction_id")
	h.Step(id, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(id, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if hasAction(st, "hotp") {
		t.Fatalf("hotp offered after the realm disallowed it: %s", st.Raw)
	}
	// A disallowed factor satisfies nothing (MFA-005): with no other factor
	// the account is single-factor again, as with a disallowed TOTP.
	if st.Str("redirect_to") == "" {
		t.Fatalf("sign-in without an allowed second factor: %s", st.Raw)
	}
	// Nor is it an enrolled factor elsewhere: the single-factor session it
	// leaves may change the password (CRED-006) and add an allowed factor
	// without proving the disallowed one (MFA-006), which it could not.
	plain := f.AccountToken("bob").Tokens.Str("access_token")
	newPw := "hotp disallowed, new passphrase 2026"
	f.must(h.API("POST", "/me/password", plain, map[string]any{"current_password": h.passwords["bob@example.test"], "new_password": newPw}), 200,
		"password change with only a disallowed factor")
	h.SetPassword("bob@example.test", newPw)
	f.EnrollTOTP("bob")
	// The last-factor guard does not count it either: with MFA mandatory,
	// TOTP is bob's last allowed factor.
	f.must(f.SetPolicy(func(p *realm.Policy) { p.MFA.Requirement = realm.MFARequired }), 200, "mfa required")
	tok := f.AccountToken("bob").Tokens.Str("access_token")
	if r := h.API("DELETE", "/me/totp", tok, nil); r.Status != 409 || r.Str("code") != "last_sign_in_method" {
		t.Fatalf("last allowed factor removed while a disallowed one remained: %d %s", r.Status, r.Raw)
	}
	// Removing the disallowed token loses nothing, so the guard allows it.
	mustStatus(t, h.API("DELETE", "/me/hotp", tok, nil), 204, "removing a disallowed token while MFA is mandatory")
}
