package e2e

import (
	"bytes"
	"context"
	"encoding/base32"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/secret"
)

// accountLogin is the self-service sign-in used by the credential lifecycle tests.
func accountLogin(h *Harness) LoginOpts {
	return LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
}

// afterPassword starts a self-service sign-in and answers the identify and
// password steps with the remembered password, returning the transaction and
// the state after the password step.
func afterPassword(h *Harness, ident string) (string, string, *Resp) {
	h.t.Helper()
	start, _, cont := h.StartTx(accountLogin(h))
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": ident})
	return tx, cont, h.Step(tx, cont, "password", map[string]any{"password": h.passwords[ident]})
}

// TestPasswordResetChallengeBinding covers CRED-007: a reset code expires with
// the challenge lifetime, is bound to the password-reset purpose (another
// purpose's challenge and code cannot complete a reset, and the attempt does
// not consume it), and completes a reset only once. Generic public responses
// and the retained MFA requirement are asserted by TestRegistrationAndRecovery.
func TestPasswordResetChallengeBinding(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	const ident = "bob@example.test"
	request := func() (string, string) {
		t.Helper()
		h.Clock.Advance(2 * time.Second) // past the per-identifier send cooldown
		req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": ident}), 202, "request reset")
		code := CodeFrom(h.Mail(ident, "password_reset"))
		if req.Str("reset_id") == "" || code == "" {
			t.Fatalf("no reset code delivered: %s", req.Raw)
		}
		return req.Str("reset_id"), code
	}
	complete := func(id, code, pw string) *Resp {
		t.Helper()
		return h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": id, "code": code, "new_password": pw})
	}

	// Expiry: a code past the challenge lifetime is refused.
	id, code := request()
	h.Clock.Advance(h.Cfg.Tokens.ChallengeTTL + time.Minute)
	if r := complete(id, code, "an expired reset passphrase 2026"); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("expired reset code: %d %s", r.Status, r.Raw)
	}

	// Purpose binding: an emailed sign-in code and its challenge cannot
	// complete a reset.
	start, _, cont := h.StartTx(accountLogin(h))
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": ident})
	h.Clock.Advance(2 * time.Second)
	f.must(h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send sign-in code")
	loginCode := CodeFrom(h.Mail(ident, "login_code"))
	var loginID string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM challenges WHERE purpose='login_otp' AND consumed_at IS NULL
		ORDER BY created_at DESC LIMIT 1`).Scan(&loginID)
	if loginID == "" || loginCode == "" {
		t.Fatal("no sign-in challenge issued")
	}
	if r := complete(loginID, loginCode, "a cross purpose passphrase 2026"); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("sign-in challenge presented as a reset: %d %s", r.Status, r.Raw)
	}
	// The refused attempt neither changed the password nor used up the
	// sign-in code, which still works for its own purpose.
	if st := h.Step(tx, cont, "otp/verify", map[string]any{"code": loginCode}); st.Str("redirect_to") == "" {
		t.Fatalf("sign-in code after a cross-purpose attempt: %d %s", st.Status, st.Raw)
	}
	f.AccountToken("bob") // the old password still signs in

	// Single use: a fresh code completes the reset once.
	id, code = request()
	newPw := "a fresh reset passphrase 2026"
	f.must(complete(id, code, newPw), 200, "reset")
	if r := complete(id, code, "a replayed reset passphrase 2026"); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("reused reset code: %d %s", r.Status, r.Raw)
	}
	h.SetPassword(ident, newPw)
	f.AccountToken("bob")
}

// TestPasswordCompromiseResponse covers CRED-008: marking a password
// compromised revokes the user's sessions and refresh grants at once, the
// compromised password no longer signs in, the action is audited and
// published, and the password-reset recovery workflow restores access with a
// new password.
func TestPasswordCompromiseResponse(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	const ident = "bob@example.test"
	bob := f.Users["bob"]
	acct := f.AccountToken("bob").Tokens.Str("access_token")
	rt := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	if rt == "" {
		t.Fatal("no refresh token issued")
	}
	activeFamilies := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_families WHERE state='active'
			AND grant_id IN (SELECT id FROM authorization_grants WHERE subject_id=$1)`, bob).Scan(&n)
		return n
	}
	if activeFamilies() == 0 {
		t.Fatal("no active refresh family before the compromise")
	}

	f.must(f.AdminAPI("POST", "/users/"+bob+"/credentials/password/compromised", map[string]any{"reason": "BREACH_CORPUS_MATCH"}), 204, "mark compromised")

	if r := h.API("GET", "/me", acct, nil); r.Status != 401 {
		t.Fatalf("sessions must be revoked when the password is compromised: %d", r.Status)
	}
	if n := activeFamilies(); n != 0 {
		t.Fatalf("refresh families still active after the compromise: %d", n)
	}
	if r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", f.Clients["web"].Secret); r.Status != 400 || r.Str("error") != "invalid_grant" {
		t.Fatalf("refresh after the password was marked compromised: %d %s", r.Status, r.Raw)
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM credentials WHERE user_id=$1 AND type='password' ORDER BY created_at DESC LIMIT 1`, bob).Scan(&state)
	if state != "compromised" {
		t.Fatalf("password credential state: %q", state)
	}
	// The compromised password never authenticates.
	if _, _, st := afterPassword(h, ident); st.Status != 401 || st.Str("code") != "invalid_credentials" {
		t.Fatalf("compromised password was not refused: %d %s", st.Status, st.Raw)
	}
	var audited, published int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='credential.password.compromised' AND subject_id=$1
		AND reason_code='BREACH_CORPUS_MATCH'`, bob).Scan(&audited)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_type='security.credential_compromised'`).Scan(&published)
	if audited != 1 || published != 1 {
		t.Fatalf("compromise evidence: audit=%d event=%d", audited, published)
	}

	// Recovery: a password reset replaces the compromised credential.
	h.Clock.Advance(2 * time.Second)
	req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": ident}), 202, "request reset")
	code := CodeFrom(h.Mail(ident, "password_reset"))
	newPw := "a post compromise passphrase 2026"
	f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code, "new_password": newPw}), 200, "reset")
	h.SetPassword(ident, newPw)
	if r := f.AccountToken("bob"); r.Tokens.Str("access_token") == "" {
		t.Fatal("sign-in after recovery failed")
	}
	var compromised int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE user_id=$1 AND type='password' AND state='compromised'`, bob).Scan(&compromised)
	if compromised != 0 {
		t.Fatal("the compromised verifier survived the reset")
	}
}

// wrongTOTP returns a well-formed code that does not match seed within the
// accepted window now.
func wrongTOTP(h *Harness, seed string) string {
	h.t.Helper()
	for i := int64(100); ; i++ {
		c, err := credential.TOTPCode(seed, credential.TOTPStep(h.Clock.Now())+i)
		if err != nil {
			h.t.Fatal(err)
		}
		if _, ok := credential.MatchTOTP(seed, c, h.Clock.Now(), h.Cfg.Security.TOTPSkewSteps); !ok {
			return c
		}
	}
}

// TestTOTPFactorLifecycle covers MFA-001 and MFA-012. Enrollment returns the
// seed once and stores it only encrypted, bound to its credential; the factor
// stays pending until a valid code proves it; once active, sign-in requires
// it and refuses wrong and replayed codes; a recovery code lets a user who
// lost the authenticator enroll a replacement, which retires the old seed;
// the factor can be removed, after which sign-in no longer asks for it; and
// enrollment start and completion, use, failed proofs, removal, recovery and
// an administrator's factor reset are audited without any seed, recovery code
// or submitted code.
func TestTOTPFactorLifecycle(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	const ident = "bob@example.test"
	bob := f.Users["bob"]
	credState := func(id string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM credentials WHERE id=$1`, id).Scan(&s)
		return s
	}
	var submitted []string // every code presented, for the audit check

	// Enrollment: the seed is returned once and stored only encrypted.
	tok := f.AccountToken("bob").Tokens.Str("access_token")
	en := f.must(h.API("POST", "/me/totp/enroll", tok, nil), 201, "enroll")
	seed, credID := en.Str("secret"), en.Str("credential_id")
	if seed == "" || credID == "" || !strings.Contains(en.Str("otpauth_uri"), "secret="+seed) {
		t.Fatalf("enrollment: %s", en.Raw)
	}
	var row string
	var ct []byte
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT row_to_json(c)::text, secret_ciphertext FROM credentials c WHERE id=$1`, credID).Scan(&row, &ct); err != nil {
		t.Fatal(err)
	}
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if len(ct) == 0 || len(raw) == 0 || strings.Contains(row, seed) || bytes.Contains(ct, []byte(seed)) || bytes.Contains(ct, raw) {
		t.Fatal("the TOTP seed must be stored encrypted only")
	}
	if pt, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("totp:"+credID)); err != nil || string(pt) != seed {
		t.Fatalf("stored seed does not decrypt under its credential binding: %v", err)
	}
	if _, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("totp:another-credential")); err == nil {
		t.Fatal("the encrypted seed is not bound to its credential")
	}

	// Proof before activation: a pending enrollment is not a factor, and a
	// wrong code leaves it pending.
	if _, _, st := afterPassword(h, ident); st.Str("redirect_to") == "" {
		t.Fatalf("a pending enrollment was required at sign-in: %s", st.Raw)
	}
	h.seeds[ident] = seed
	bad := wrongTOTP(h, seed)
	submitted = append(submitted, bad)
	mustStatus(t, h.API("POST", "/me/totp/activate", tok, map[string]any{"code": bad}), 400, "activation with a wrong code")
	if s := credState(credID); s != "pending" {
		t.Fatalf("a failed proof changed the enrollment: %s", s)
	}
	good := h.TOTPNow(ident)
	submitted = append(submitted, good)
	act := f.must(h.API("POST", "/me/totp/activate", tok, map[string]any{"code": good}), 200, "activate")
	recovery, _ := act.Get("recovery_codes").([]any)
	if s := credState(credID); s != "active" || len(recovery) != h.Cfg.Security.RecoveryCodeCount {
		t.Fatalf("activation: state %s, %d recovery codes", s, len(recovery))
	}

	// Authentication: sign-in requires the factor; a wrong and a replayed
	// code are refused (MFA-002), the current code completes it.
	tx, cont, st := afterPassword(h, ident)
	if st.Str("redirect_to") != "" || !hasAction(st, "totp") {
		t.Fatalf("TOTP not required after activation: %s", st.Raw)
	}
	bad = wrongTOTP(h, seed)
	submitted = append(submitted, bad)
	if r := h.Step(tx, cont, "totp", map[string]any{"code": bad}); r.Status != 400 {
		t.Fatalf("wrong TOTP code: %d %s", r.Status, r.Raw)
	}
	code := h.TOTPNow(ident)
	submitted = append(submitted, code)
	if r := h.Step(tx, cont, "totp", map[string]any{"code": code}); r.Str("redirect_to") == "" {
		t.Fatalf("valid TOTP code refused: %d %s", r.Status, r.Raw)
	}
	tx, cont, _ = afterPassword(h, ident)
	if r := h.Step(tx, cont, "totp", map[string]any{"code": code}); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("a consumed time step was not refused as an invalid proof: %d %s", r.Status, r.Raw)
	}

	// Recovery: with the authenticator lost, a recovery code signs in and the
	// session may enroll a replacement, which retires the old seed.
	h.Clock.Advance(16 * time.Minute) // a fresh proof budget window
	tx, cont, _ = afterPassword(h, ident)
	if r := h.Step(tx, cont, "recovery-code", map[string]any{"code": "aaaaa-bbbbb-ccccc-ddddd"}); r.Status != 400 {
		t.Fatalf("wrong recovery code: %d %s", r.Status, r.Raw)
	}
	opts := accountLogin(h)
	opts.Identifier, opts.UseRecovery = ident, recovery[0].(string)
	rtok := h.Login(opts).Tokens.Str("access_token")
	en2 := f.must(h.API("POST", "/me/totp/enroll", rtok, nil), 201, "enroll a replacement from the recovery session")
	seed2, credID2 := en2.Str("secret"), en2.Str("credential_id")
	h.seeds[ident] = seed2
	code = h.TOTPNow(ident)
	submitted = append(submitted, code)
	f.must(h.API("POST", "/me/totp/activate", rtok, map[string]any{"code": code}), 200, "activate the replacement")
	if s := credState(credID); s != "revoked" {
		t.Fatalf("the replaced seed is still %s", s)
	}
	old, _ := credential.TOTPCode(seed, credential.TOTPStep(h.Clock.Now()))
	submitted = append(submitted, old)
	tx, cont, _ = afterPassword(h, ident)
	if r := h.Step(tx, cont, "totp", map[string]any{"code": old}); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("the replaced authenticator was not refused: %d %s", r.Status, r.Raw)
	}

	// Removal: the factor is revoked and sign-in no longer asks for it.
	tok = f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("DELETE", "/me/totp", tok, nil), 204, "remove")
	if s := credState(credID2); s != "revoked" {
		t.Fatalf("removed factor is still %s", s)
	}
	if _, _, st := afterPassword(h, ident); st.Str("redirect_to") == "" || hasAction(st, "totp") {
		t.Fatalf("sign-in still requires the removed factor: %s", st.Raw)
	}

	// An administrator's factor reset (assisted recovery) invalidates what is left.
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/users/"+bob+"/recovery-requests", map[string]any{"reason": "lost phone, identity verified by callback",
		"evidence_reference": "ticket 7", "reset_mfa": true}), 202, "assisted recovery with factor reset")
	var activeCodes int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active'`, bob).Scan(&activeCodes)
	if activeCodes != 0 {
		t.Fatalf("recovery codes survived the factor reset: %d", activeCodes)
	}

	// MFA-012: every lifecycle step is audited, failures as failures.
	types := map[string]int{}
	rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT type, outcome FROM audit_events WHERE subject_id=$1`, bob)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var typ, outcome string
		if err := rows.Scan(&typ, &outcome); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(typ, "failed") && outcome != "failure" {
			t.Errorf("%s recorded with outcome %s", typ, outcome)
		}
		types[typ]++
	}
	rows.Close()
	for _, want := range []string{"mfa.totp.enrollment_started", "mfa.totp.proof_failed", "mfa.totp.enrolled", "mfa.totp.failed", "mfa.totp.used",
		"mfa.recovery_codes.regenerated", "mfa.recovery_code.failed", "mfa.recovery_code.used", "mfa.totp.removed"} {
		if types[want] == 0 {
			t.Errorf("no %s audit event (have %v)", want, types)
		}
	}
	var resets int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE subject_id=$1 AND type='recovery.assisted'
		AND metadata->>'reset_mfa'='true'`, bob).Scan(&resets)
	if resets != 1 {
		t.Errorf("factor reset audit events: %d", resets)
	}
	// No seed, recovery code or submitted code is stored in the audit log.
	secrets := []string{seed, seed2}
	for _, c := range recovery {
		secrets = append(secrets, c.(string), secret.NormalizeRecoveryCode(c.(string)))
	}
	rows, err = h.App.D.DB.Pool.Query(ctx, `SELECT row_to_json(a)::text, metadata::text, coalesce(reason_code,'') FROM audit_events a`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var all, meta, reason string
		if err := rows.Scan(&all, &meta, &reason); err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if strings.Contains(all, s) {
				t.Fatalf("audit event carries a factor secret: %s", all)
			}
		}
		for _, c := range submitted {
			if strings.Contains(meta, `"`+c+`"`) || reason == c {
				t.Fatalf("audit event carries a submitted code: %s", all)
			}
		}
	}
}

// TestRecoveryCodeLifecycle covers MFA-004 (and TEST-023 for recovery codes):
// recovery codes are high-entropy and distinct, returned only when generated,
// stored as keyed verifiers, consumed atomically (one code succeeds exactly
// once, also under concurrent submission, and only that code is used up),
// and regeneration invalidates every earlier code.
func TestRecoveryCodeLifecycle(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	const ident = "carol@example.test"
	carol := f.Users["carol"]
	f.EnrollTOTP("carol")
	tok := f.AccountToken("carol").Tokens.Str("access_token")
	codesOf := func(r *Resp) []string {
		t.Helper()
		var out []string
		for _, c := range r.Get("recovery_codes").([]any) {
			out = append(out, c.(string))
		}
		if len(out) != h.Cfg.Security.RecoveryCodeCount {
			t.Fatalf("batch of %d codes: %s", len(out), r.Raw)
		}
		return out
	}
	codes := codesOf(f.must(h.API("POST", "/me/recovery-codes/regenerate", tok, nil), 200, "generate"))

	// About 99 bits each: 20 characters from a 31-character alphabet.
	format := regexp.MustCompile(`^[a-hjkmnp-z2-9]{5}(-[a-hjkmnp-z2-9]{5}){3}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !format.MatchString(c) || seen[c] {
			t.Fatalf("recovery code %q is malformed or repeated", c)
		}
		seen[c] = true
	}
	// Stored only as keyed verifiers.
	rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT row_to_json(r)::text FROM recovery_codes r WHERE user_id=$1 AND state='active'`, carol)
	if err != nil {
		t.Fatal(err)
	}
	stored := 0
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		stored++
		for _, c := range codes {
			if strings.Contains(row, c) || strings.Contains(row, secret.NormalizeRecoveryCode(c)) {
				t.Fatalf("recovery code stored in plaintext: %s", row)
			}
		}
	}
	rows.Close()
	if stored != len(codes) {
		t.Fatalf("%d active verifiers for %d codes", stored, len(codes))
	}
	// Shown once: reading the account's credentials reports a count only.
	cr := f.must(h.API("GET", "/me/credentials", tok, nil), 200, "credentials")
	if cr.Get("recovery_codes_remaining") != float64(len(codes)) {
		t.Fatalf("remaining count: %s", cr.Raw)
	}
	for _, c := range codes {
		if strings.Contains(string(cr.Raw), c) {
			t.Fatal("a recovery code was returned again")
		}
	}

	signIn := func(code string) *Resp {
		t.Helper()
		tx, cont, _ := afterPassword(h, ident)
		return h.Step(tx, cont, "recovery-code", map[string]any{"code": code})
	}
	// Regeneration invalidates every earlier code.
	fresh := codesOf(f.must(h.API("POST", "/me/recovery-codes/regenerate", tok, nil), 200, "regenerate"))
	if r := signIn(codes[0]); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("a code from a replaced batch was not refused: %d %s", r.Status, r.Raw)
	}
	// Three batches so far (enrollment, generate, regenerate): only the last is usable.
	var active, invalidated int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='active'), count(*) FILTER (WHERE state='invalidated')
		FROM recovery_codes WHERE user_id=$1`, carol).Scan(&active, &invalidated)
	if active != len(fresh) || invalidated != 2*len(fresh) {
		t.Fatalf("after regeneration: %d active, %d invalidated", active, invalidated)
	}

	// Atomic consumption: concurrent submissions of one code succeed once.
	h.Clock.Advance(16 * time.Minute) // a fresh proof budget window
	type pending struct{ tx, cont string }
	var txs []pending
	for range 4 {
		tx, cont, st := afterPassword(h, ident)
		if !hasAction(st, "recovery_code") {
			t.Fatalf("recovery code not offered: %s", st.Raw)
		}
		txs = append(txs, pending{tx, cont})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted, refused := 0, 0
	for _, p := range txs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := h.Step(p.tx, p.cont, "recovery-code", map[string]any{"code": fresh[0]})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case r.Str("redirect_to") != "":
				accepted++
			case r.Status == 400 && r.Str("code") == "invalid_proof":
				refused++
			}
		}()
	}
	wg.Wait()
	if accepted != 1 || refused != len(txs)-1 {
		t.Fatalf("one recovery code submitted %d times concurrently: %d accepted, %d refused", len(txs), accepted, refused)
	}
	if r := signIn(fresh[0]); r.Status != 400 || r.Str("code") != "invalid_proof" {
		t.Fatalf("a consumed recovery code was not refused: %d %s", r.Status, r.Raw)
	}
	var consumed int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='active'), count(*) FILTER (WHERE state='consumed')
		FROM recovery_codes WHERE user_id=$1`, carol).Scan(&active, &consumed)
	if active != len(fresh)-1 || consumed != 1 {
		t.Fatalf("after one use: %d active, %d consumed", active, consumed)
	}
	if r := signIn(fresh[1]); r.Str("redirect_to") == "" {
		t.Fatalf("another code of the current batch: %d %s", r.Status, r.Raw)
	}
}
