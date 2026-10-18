package e2e

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/realm"
)

// Consecutive code-factor failures (owner decision 10 of 0.2.0-alpha.6,
// docs/protocols/headless-authentication.md#consecutive-code-factor-failures).

// sfCount returns the account's consecutive code-factor failures.
func sfCount(t *testing.T, h *Harness, userID string) int {
	t.Helper()
	var n int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT coalesce((SELECT consecutive FROM second_factor_failures WHERE user_id=$1), 0)`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// sfMails counts the delivered messages of a template to a recipient.
func sfMails(t *testing.T, h *Harness, recipient, template string) int {
	t.Helper()
	h.Deliver()
	var n int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM dev_mailbox WHERE realm_id=$1 AND lower(recipient)=lower($2)
		AND template=$3`, h.Realm.ID, recipient, template).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// sfAudits counts the audit events of a type about a user.
func sfAudits(t *testing.T, h *Harness, typ, userID string) int {
	t.Helper()
	var n int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type=$1 AND subject_id=$2`,
		typ, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// sfRetryAfter is a 429's Retry-After.
func sfRetryAfter(t *testing.T, r *Resp) time.Duration {
	t.Helper()
	s, err := strconv.Atoi(r.Header.Get("Retry-After"))
	if err != nil || s <= 0 {
		t.Fatalf("429 without Retry-After: %v %s", r.Header, r.Raw)
	}
	return time.Duration(s) * time.Second
}

// sfFailTOTP makes one failed TOTP proof of ident in a new transaction. The
// proof budgets, the password budget and the backoff refuse some attempts
// with 429; the clock then moves past Retry-After and the attempt starts
// again, so the failures spread over as many budget windows as they need.
// It returns the time of the failure.
func sfFailTOTP(t *testing.T, h *Harness, ident string) time.Time {
	t.Helper()
	for range 20 {
		start, _, cont := h.StartTx(accountLogin(h))
		tx := start.Str("transaction_id")
		r := h.Step(tx, cont, "identify", map[string]any{"identifier": ident})
		if r.Status == 200 {
			r = h.Step(tx, cont, "password", map[string]any{"password": h.passwords[ident]})
		}
		if r.Status == 200 {
			if !hasAction(r, "totp") {
				t.Fatalf("TOTP not offered: %s", r.Raw)
			}
			r = h.Step(tx, cont, "totp", map[string]any{"code": wrongTOTP(h, h.seeds[ident])})
			if r.Status == 400 && r.Str("code") == "invalid_proof" {
				return h.Clock.Now()
			}
		}
		if r.Status != 429 || r.Str("code") != "rate_limited" {
			t.Fatalf("failed TOTP attempt: %d %s", r.Status, r.Raw)
		}
		h.Clock.Advance(sfRetryAfter(t, r) + time.Second)
	}
	t.Fatal("no TOTP attempt got through the budgets")
	return time.Time{}
}

// TestSecondFactorFailureNotice covers SEC-006, MFA-002, MFA-012, MSG-003 and
// TEST-021 (owner decision 10): consecutive TOTP failures are counted per
// account across transactions and proof-budget windows; the 20th sends the
// owner exactly one mandatory second_factor_failures notice and records
// mfa.code_factors.failure_notice, and further failures send no other. A
// successful TOTP sign-in resets the count, so the next failure is the first
// again, and only a second run of 20 failures sends a second notice.
func TestSecondFactorFailureNotice(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	const ident = "bob@example.test"
	bob := f.Users["bob"]
	f.EnrollTOTP("bob")
	cfg := h.Cfg.Security.SecondFactor
	if cfg.FailureNoticeAt != 20 || cfg.FailureBackoffAfter != 10 || cfg.FailureDisableAt != 100 {
		t.Fatalf("the test expects the default ceiling: %+v", cfg)
	}

	window := h.Cfg.Security.RateLimits.OTPVerifyWindow
	windows := map[time.Time]bool{}
	for i := 1; i < cfg.FailureNoticeAt; i++ {
		windows[sfFailTOTP(t, h, ident).Truncate(window)] = true
	}
	if n := sfCount(t, h, bob); n != cfg.FailureNoticeAt-1 {
		t.Fatalf("after %d failures the count is %d", cfg.FailureNoticeAt-1, n)
	}
	if n := sfMails(t, h, ident, "second_factor_failures"); n != 0 {
		t.Fatalf("%d notices before the threshold", n)
	}
	windows[sfFailTOTP(t, h, ident).Truncate(window)] = true
	if len(windows) < 3 {
		t.Fatalf("the failures should span several proof-budget windows, not %d", len(windows))
	}
	notice := h.Mail(ident, "second_factor_failures")
	if !strings.Contains(notice, "20 attempts in a row") {
		t.Fatalf("notice: %q", notice)
	}
	if n := sfMails(t, h, ident, "second_factor_failures"); n != 1 {
		t.Fatalf("%d notices at the threshold", n)
	}
	var at int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT (metadata->>'consecutive_failures')::int FROM audit_events
		WHERE type='mfa.code_factors.failure_notice' AND subject_id=$1`, bob).Scan(&at); err != nil || at != cfg.FailureNoticeAt {
		t.Fatalf("failure notice evidence: %d %v", at, err)
	}

	// Further failures send no other notice.
	for range 3 {
		sfFailTOTP(t, h, ident)
	}
	if n, m := sfCount(t, h, bob), sfMails(t, h, ident, "second_factor_failures"); n != 23 || m != 1 {
		t.Fatalf("after 23 failures: count %d, %d notices", n, m)
	}
	if n := sfAudits(t, h, "mfa.code_factors.failure_notice", bob); n != 1 {
		t.Fatalf("%d notice audit events", n)
	}

	// A successful TOTP sign-in, once the capped backoff has passed, resets
	// the count: the next failure is the first again.
	h.Clock.Advance(cfg.FailureBackoffMax)
	f.AccountToken("bob")
	if n := sfCount(t, h, bob); n != 0 {
		t.Fatalf("a successful TOTP sign-in left the count at %d", n)
	}
	sfFailTOTP(t, h, ident)
	if n := sfCount(t, h, bob); n != 1 {
		t.Fatalf("the first failure after a reset counts %d", n)
	}
	// The notice comes again only when the count reaches the threshold again.
	for sfCount(t, h, bob) < cfg.FailureNoticeAt-1 {
		sfFailTOTP(t, h, ident)
	}
	if n := sfMails(t, h, ident, "second_factor_failures"); n != 1 {
		t.Fatalf("%d notices before the second run reached the threshold", n)
	}
	sfFailTOTP(t, h, ident)
	if n := sfMails(t, h, ident, "second_factor_failures"); n != 2 {
		t.Fatalf("%d notices after the second run", n)
	}
}

// TestSecondFactorBackoff covers SEC-006, MFA-002 and TEST-021 (owner
// decision 10): from failure_backoff_after consecutive failures on, a TOTP
// proof waits 2 s after the last failure, doubling with each failure up to
// failure_backoff_max: inside the delay it answers 429 rate_limited with the
// remaining Retry-After, even with the correct code, in any transaction of
// the account, and without counting as a failure of the transaction; after
// the delay the correct code signs in and resets the count, so nothing
// waits any more.
func TestSecondFactorBackoff(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.SecondFactor.FailureBackoffAfter = 3
		c.Security.SecondFactor.FailureBackoffMax = 10 * time.Second
		c.Security.RateLimits.OTPVerifyPerAccount = 1000 // only the backoff paces this test
	})
	f := fixtureOn(t, h)
	const ident = "bob@example.test"
	bob := f.Users["bob"]
	f.EnrollTOTP("bob")
	seed := h.seeds[ident]
	h.Clock.Advance(time.Minute) // past the time step the activation used
	current := func() string {
		t.Helper()
		code, err := credential.TOTPCode(seed, credential.TOTPStep(h.Clock.Now()))
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	totp := func(tx, cont, code string) *Resp { return h.Step(tx, cont, "totp", map[string]any{"code": code}) }
	invalid := func(r *Resp, what string) {
		t.Helper()
		if r.Status != 400 || r.Str("code") != "invalid_proof" {
			t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
		}
	}
	waits := func(r *Resp, seconds, what string) {
		t.Helper()
		if r.Status != 429 || r.Str("code") != "rate_limited" || r.Header.Get("Retry-After") != seconds {
			t.Fatalf("%s: want 429 with Retry-After %s, got %d %q %s", what, seconds, r.Status, r.Header.Get("Retry-After"), r.Raw)
		}
	}

	tx, cont, _ := afterPassword(h, ident)
	for i := range 3 {
		invalid(totp(tx, cont, wrongTOTP(h, seed)), fmt.Sprintf("failure %d, below the threshold", i+1))
	}
	waits(totp(tx, cont, wrongTOTP(h, seed)), "2", "a guess right after the third failure")
	waits(totp(tx, cont, current()), "2", "the correct code inside the delay")
	h.Clock.Advance(time.Second)
	waits(totp(tx, cont, current()), "1", "one second later")
	h.Clock.Advance(time.Second)
	invalid(totp(tx, cont, wrongTOTP(h, seed)), "failure 4, after the delay")
	waits(totp(tx, cont, current()), "4", "after the fourth failure")
	// The backoff is the account's, not the transaction's.
	tx2, cont2, st := afterPassword(h, ident)
	if !hasAction(st, "totp") {
		t.Fatalf("TOTP not offered: %s", st.Raw)
	}
	waits(totp(tx2, cont2, current()), "4", "another transaction")
	h.Clock.Advance(4 * time.Second)
	invalid(totp(tx2, cont2, wrongTOTP(h, seed)), "failure 5")
	waits(totp(tx2, cont2, current()), "8", "after the fifth failure")
	h.Clock.Advance(8 * time.Second)
	invalid(totp(tx2, cont2, wrongTOTP(h, seed)), "failure 6")
	waits(totp(tx2, cont2, current()), "10", "after the sixth failure, at the cap")
	// Refusals are not proof failures of the transaction.
	var failures int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT failure_count FROM auth_transactions WHERE id=$1`, tx2).Scan(&failures); err != nil || failures != 2 {
		t.Fatalf("transaction failures: %d %v", failures, err)
	}
	if n := sfCount(t, h, bob); n != 6 {
		t.Fatalf("count after six failures: %d", n)
	}
	h.Clock.Advance(10 * time.Second)
	if done := totp(tx2, cont2, current()); done.Status != 200 || done.Str("redirect_to") == "" {
		t.Fatalf("the correct code after the delay: %d %s", done.Status, done.Raw)
	}
	if n := sfCount(t, h, bob); n != 0 {
		t.Fatalf("a successful TOTP left the count at %d", n)
	}
	tx3, cont3, _ := afterPassword(h, ident)
	for i := range 3 {
		invalid(totp(tx3, cont3, wrongTOTP(h, seed)), fmt.Sprintf("failure %d after the reset", i+1))
	}
}

// TestSecondFactorCeiling covers SEC-006, SEC-005, MFA-002, MFA-008,
// MFA-012 and TEST-021 (owner decision 10): TOTP, HOTP and recovery-code
// failures share one count; at failure_disable_at the account's code factors
// are off: TOTP, HOTP and recovery-code steps answer 403 code_factors_disabled
// even with valid codes (which stay unused), no sign-in code is sent and any
// code is refused like one for an unknown address, and administrators see
// the state. A passkey sign-in, a password reset from the email address and
// an assisted recovery each turn code factors back on
// (mfa.code_factors.restored), so the owner is never locked out.
func TestSecondFactorCeiling(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.SecondFactor = configuration.SecondFactorConfig{FailureNoticeAt: 3, FailureDisableAt: 6} // no backoff
		c.Security.RateLimits.OTPVerifyPerAccount = 1000
		c.Security.RateLimits.LoginPerIdentifier = 1000
	})
	f := fixtureOn(t, h, passkeyPolicy, func(p *realm.Policy) { p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, "hotp") })
	ctx := context.Background()
	const ident = "bob@example.test"
	bob := f.Users["bob"]

	// bob holds TOTP, recovery codes, HOTP and a passkey.
	tok := f.AccountToken("bob").Tokens.Str("access_token")
	h.seeds[ident] = f.must(h.API("POST", "/me/totp/enroll", tok, nil), 201, "enroll TOTP").Str("secret")
	act := f.must(h.API("POST", "/me/totp/activate", tok, map[string]any{"code": h.TOTPNow(ident)}), 200, "activate TOTP")
	recoveryCodes, _ := act.Get("recovery_codes").([]any)
	if len(recoveryCodes) == 0 {
		t.Fatalf("no recovery codes: %s", act.Raw)
	}
	recoveryCode := recoveryCodes[0].(string)
	mfa := f.AccountToken("bob").Tokens.Str("access_token")
	hotpSeed := f.must(h.API("POST", "/me/hotp/enroll", mfa, nil), 201, "enroll HOTP").Str("secret")
	hotp := func(c int64) string {
		t.Helper()
		code, err := credential.HOTPCode(hotpSeed, c)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	f.must(h.API("POST", "/me/hotp/activate", mfa, map[string]any{"code": hotp(0)}), 200, "activate HOTP")
	wrongHOTP := ""
	for i := 0; ; i++ {
		wrongHOTP = fmt.Sprintf("%06d", i)
		if _, ok := credential.MatchHOTP(hotpSeed, wrongHOTP, 1, h.Realm.Policy.MFA.HOTPLookAhead()); !ok {
			break
		}
	}
	key := newSoftKey("login.test", "https://login.test", false)
	opts := f.must(h.API("POST", "/me/webauthn/registration-options", mfa, map[string]any{}), 200, "passkey options")
	f.must(h.API("POST", "/me/webauthn/registration-complete", mfa, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
		"credential": key.create(t, opts.Get("public_key")), "name": "Laptop"}), 201, "register passkey")

	step := func(tx, cont, path, code string) *Resp { return h.Step(tx, cont, path, map[string]any{"code": code}) }
	invalid := func(r *Resp, what string) {
		t.Helper()
		if r.Status != 400 || r.Str("code") != "invalid_proof" {
			t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
		}
	}
	disable := func() {
		t.Helper()
		// Six failures over four factors and three transactions (five fail
		// a transaction), the first a wrong emailed sign-in code.
		start, _, cont := h.StartTx(accountLogin(h))
		tx := start.Str("transaction_id")
		f.must(h.Step(tx, cont, "identify", map[string]any{"identifier": ident}), 200, "identify")
		h.Clock.Advance(2 * time.Second)
		f.must(h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send sign-in code")
		sent := CodeFrom(h.Mail(ident, "login_code"))
		if sent == "" {
			t.Fatal("no sign-in code sent")
		}
		invalid(step(tx, cont, "otp/verify", fmt.Sprintf("%d%s", (sent[0]-'0'+1)%10, sent[1:])), "wrong sign-in code")
		if n := sfCount(t, h, bob); n != 1 {
			t.Fatalf("a wrong sign-in code counts %d", n)
		}
		tx, cont, st := afterPassword(h, ident)
		for _, a := range []string{"totp", "hotp", "recovery_code"} {
			if !hasAction(st, a) {
				t.Fatalf("%s not offered: %s", a, st.Raw)
			}
		}
		invalid(step(tx, cont, "totp", wrongTOTP(h, h.seeds[ident])), "wrong TOTP")
		invalid(step(tx, cont, "hotp", wrongHOTP), "wrong HOTP")
		invalid(step(tx, cont, "recovery-code", "zzzzz-zzzzz-zzzzz"), "wrong recovery code")
		invalid(step(tx, cont, "totp", wrongTOTP(h, h.seeds[ident])), "wrong TOTP")
		tx, cont, _ = afterPassword(h, ident)
		invalid(step(tx, cont, "hotp", wrongHOTP), "wrong HOTP at the ceiling")
		if n := sfCount(t, h, bob); n != 6 {
			t.Fatalf("count at the ceiling: %d", n)
		}
	}
	restored := func(cause string) {
		t.Helper()
		if n := sfCount(t, h, bob); n != 0 {
			t.Fatalf("%s left the count at %d", cause, n)
		}
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='mfa.code_factors.restored' AND subject_id=$1
			AND metadata->>'cause'=$2`, bob, cause).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s restoration evidence: %d %v", cause, n, err)
		}
	}

	disable()
	if n := sfMails(t, h, ident, "second_factor_failures"); n != 1 {
		t.Fatalf("%d notices on the way to the ceiling", n)
	}
	if n := sfAudits(t, h, "mfa.code_factors.disabled", bob); n != 1 {
		t.Fatalf("%d disable audit events", n)
	}

	// Valid codes of every code factor are refused, and stay unused.
	h.Clock.Advance(time.Minute)
	tx, cont, _ := afterPassword(h, ident)
	for path, code := range map[string]string{"totp": h.TOTPNow(ident), "hotp": hotp(1), "recovery-code": recoveryCode} {
		if r := step(tx, cont, path, code); r.Status != 403 || r.Str("code") != "code_factors_disabled" {
			t.Fatalf("valid %s at the ceiling: %d %s", path, r.Status, r.Raw)
		}
	}
	var counter, activeCodes int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT (SELECT counter FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active'),
		(SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active')`, bob).Scan(&counter, &activeCodes); err != nil ||
		counter != 1 || activeCodes != len(recoveryCodes) {
		t.Fatalf("a refused proof used a code: HOTP counter %d, %d recovery codes, %v", counter, activeCodes, err)
	}

	// Sign-in codes: nothing is sent, and a code is refused exactly as for an
	// address without an account (SEC-005).
	before := sfMails(t, h, ident, "login_code")
	codeSignIn := func(identifier string) (*Resp, *Resp) {
		t.Helper()
		start, _, cont := h.StartTx(accountLogin(h))
		tx := start.Str("transaction_id")
		f.must(h.Step(tx, cont, "identify", map[string]any{"identifier": identifier}), 200, "identify")
		h.Clock.Advance(2 * time.Second)
		return h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), h.Step(tx, cont, "otp/verify", map[string]any{"code": "123456"})
	}
	sent, verified := codeSignIn(ident)
	nobodySent, nobodyVerified := codeSignIn("nobody@example.test")
	if sent.Status != 200 || nobodySent.Status != 200 || verified.Status != 400 || verified.Str("code") != "invalid_proof" ||
		nobodyVerified.Status != verified.Status || nobodyVerified.Str("code") != verified.Str("code") {
		t.Fatalf("sign-in code at the ceiling: send %d/%d, verify %d %s / %d %s", sent.Status, nobodySent.Status, verified.Status, verified.Raw,
			nobodyVerified.Status, nobodyVerified.Raw)
	}
	if n := sfMails(t, h, ident, "login_code"); n != before {
		t.Fatal("a sign-in code was sent to an account whose code factors are off")
	}

	// Administrators see the state.
	f.ReloginAdmin()
	view := f.must(f.AdminAPI("GET", "/users/"+bob, nil), 200, "user")
	if view.Get("second_factor_failures.consecutive") != float64(6) || view.Get("second_factor_failures.code_factors_disabled") != true ||
		view.Str("second_factor_failures.disabled_at") == "" || view.Str("second_factor_failures.notified_at") == "" {
		t.Fatalf("administrator view: %s", view.Raw)
	}

	// A passkey still signs in and turns code factors back on.
	start, _, pcont := h.StartTx(accountLogin(h))
	ptx := start.Str("transaction_id")
	popts := f.must(h.Step(ptx, pcont, "webauthn/options", nil), 200, "passkey options")
	if done := h.Step(ptx, pcont, "webauthn/verify", map[string]any{"credential": key.get(t, popts.Get("webauthn.public_key"))}); done.Status != 200 ||
		done.Str("redirect_to") == "" {
		t.Fatalf("passkey sign-in at the ceiling: %d %s", done.Status, done.Raw)
	}
	restored("passkey")
	f.AccountToken("bob") // password and TOTP again

	// The email-verified password reset turns them back on as well.
	disable()
	h.Clock.Advance(2 * time.Second)
	req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": ident}), 202, "request reset")
	code := CodeFrom(h.Mail(ident, "password_reset"))
	newPassword := "bob resets a long passphrase 2026"
	f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code, "new_password": newPassword}),
		200, "complete reset")
	restored("password_reset")
	h.SetPassword(ident, newPassword)
	f.AccountToken("bob")

	// And so does an assisted recovery.
	disable()
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/users/"+bob+"/recovery-requests", map[string]any{"reason": "locked out of code factors, identity verified by video call",
		"evidence_reference": "ticket 4711"}), 202, "assisted recovery")
	restored("assisted_recovery")
	view = f.must(f.AdminAPI("GET", "/users/"+bob, nil), 200, "user")
	if view.Get("second_factor_failures.consecutive") != float64(0) || view.Get("second_factor_failures.code_factors_disabled") != false {
		t.Fatalf("administrator view after recovery: %s", view.Raw)
	}
	if n := sfMails(t, h, ident, "second_factor_failures"); n != 3 {
		t.Fatalf("one notice per run to the ceiling, got %d", n)
	}
}

// TestChangePasswordUnderSignInLock covers CRED-006, SEC-006 and API-009
// (owner decision 10): a wrong current password in a password change counts
// against the account's sign-in failure lock; once failures_before_lock is
// reached the change answers 429 rate_limited without checking the password,
// even the correct one, and password sign-in to the account is locked too.
// Every refusal is audited, and the lock ends with temporary_lock.
func TestChangePasswordUnderSignInLock(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	const ident = "carol@example.test"
	carol := f.Users["carol"]
	rl := h.Cfg.Security.RateLimits
	tok := f.AccountToken("carol").Tokens.Str("access_token")
	newPassword := "carol changes to a long passphrase 2026"
	change := func(current string) *Resp {
		return h.API("POST", "/me/password", tok, map[string]any{"current_password": current, "new_password": newPassword})
	}
	for i := range rl.FailuresBeforeLock {
		if r := change(fmt.Sprintf("not carol's passphrase %d", i)); r.Status != 401 || r.Str("code") != "invalid_credentials" {
			t.Fatalf("wrong current password %d: %d %s", i+1, r.Status, r.Raw)
		}
	}
	r := change(h.passwords[ident])
	if r.Status != 429 || r.Str("code") != "rate_limited" || sfRetryAfter(t, r) != rl.TemporaryLock {
		t.Fatalf("change after %d wrong current passwords: %d %v %s", rl.FailuresBeforeLock, r.Status, r.Header.Get("Retry-After"), r.Raw)
	}
	// The sign-in shares the account's lock: the correct password is not
	// checked and answers as for an unknown account (API-009).
	if _, _, st := afterPassword(h, ident); st.Status != 401 || st.Str("code") != "invalid_credentials" {
		t.Fatalf("password sign-in during the lock: %d %s", st.Status, st.Raw)
	}
	var wrong, locked int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE reason_code='INVALID_CREDENTIALS'),
		count(*) FILTER (WHERE reason_code='TEMPORARY_LOCK') FROM audit_events WHERE type='credential.password.change_failed' AND subject_id=$1`,
		carol).Scan(&wrong, &locked); err != nil || wrong != rl.FailuresBeforeLock || locked != 1 {
		t.Fatalf("change failure evidence: %d wrong, %d locked, %v", wrong, locked, err)
	}
	// The lock is windowed: it ends with temporary_lock.
	h.Clock.Advance(rl.TemporaryLock)
	tok = f.AccountToken("carol").Tokens.Str("access_token")
	f.must(change(h.passwords[ident]), 200, "change after the lock")
}
