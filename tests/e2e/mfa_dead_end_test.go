package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
)

// TestFactorPolicyLeavesNoDeadEnd covers MFA-003, MFA-005 and SEC-012: a
// factor policy cannot leave a sign-in that needs MFA without an action that
// completes it. Factor lists with no second factor that can be enrolled, and
// the phishing-resistant profile (realm or operator floor) with passkeys
// disabled, are refused; an enrolled factor the realm no longer offers
// neither makes MFA required nor stands in for one; and a stored policy that
// predates these checks says so instead of waiting forever.
func TestFactorPolicyLeavesNoDeadEnd(t *testing.T) {
	f := NewFixture(t, passkeyPolicy)
	h := f.H
	account := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	field := func(r *Resp, name string) bool {
		errs, _ := r.Get("errors").(map[string]any)
		return r.Status == 422 && errs[name] != nil
	}
	passkeysOff := func(p *realm.Policy) {
		p.Login.Passkeys = false
		p.MFA.AllowedFactors = []string{"totp", "recovery_code"}
	}

	// Refused policies.
	for name, c := range map[string]struct {
		mutate func(p *realm.Policy)
		field  string
	}{
		"hotp and recovery codes only": {func(p *realm.Policy) {
			p.Login.Passkeys, p.MFA.Requirement, p.MFA.AllowedFactors = false, realm.MFARequired, []string{"hotp", "recovery_code"}
		}, "mfa.allowed_factors"},
		"recovery codes only": {func(p *realm.Policy) { p.Login.Passkeys, p.MFA.AllowedFactors = false, []string{"recovery_code"} }, "mfa.allowed_factors"},
		"email codes only":    {func(p *realm.Policy) { p.Login.Passkeys, p.MFA.AllowedFactors = false, []string{"email_otp"} }, "mfa.allowed_factors"},
		"profile without passkeys": {func(p *realm.Policy) {
			passkeysOff(p)
			p.MFA.AdminPhishingResistant = true
		}, "mfa.admin_phishing_resistant"},
	} {
		if r := f.SetPolicy(c.mutate); !field(r, c.field) {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// The operator floor refuses a policy that leaves passkeys disabled
	// (the floor also requires the realm's own flag, whose check runs
	// first; CheckMFAFloor refuses it on its own as well, see the realm
	// unit tests).
	h.App.D.Cfg.Security.MFAFloor.AdminPhishingResistant = true
	defer func() { h.App.D.Cfg.Security.MFAFloor.AdminPhishingResistant = false }()
	r := f.SetPolicy(func(p *realm.Policy) { p.MFA.AdminPhishingResistant = true })
	mustStatus(t, r, 200, "profile with passkeys under the floor")
	if r := f.SetPolicy(passkeysOff); !field(r, "mfa.admin_phishing_resistant") && !field(r, "login.passkeys") {
		t.Errorf("floor accepted a policy with passkeys disabled: %d %s", r.Status, r.Raw)
	}
	h.App.D.Cfg.Security.MFAFloor.AdminPhishingResistant = false
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.AdminPhishingResistant = false }), 200, "profile off")

	// alice holds only a passkey, bob only a TOTP.
	key := newSoftKey("login.test", "https://login.test", false)
	tok := f.AccountToken("alice").Tokens.Str("access_token")
	opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
	mustStatus(t, opts, 200, "registration options")
	mustStatus(t, h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
		"credential": key.create(t, opts.Get("public_key")), "name": "Laptop"}), 201, "register passkey")
	f.EnrollTOTP("bob")

	// Passkeys disabled while MFA is required: alice's passkey is not
	// offered, so she enrolls an allowed factor instead of waiting.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		passkeysOff(p)
		p.MFA.Requirement = realm.MFARequired
	}), 200, "passkeys off, MFA required")
	o := account
	o.Identifier = "alice@example.test"
	start, _, cont := h.StartTx(o)
	txID := start.Str("transaction_id")
	h.Step(txID, cont, "identify", map[string]any{"identifier": o.Identifier})
	st := h.Step(txID, cont, "password", map[string]any{"password": h.passwords[o.Identifier]})
	if acts := actionTypes(st); !has(acts, "enroll_totp") || has(acts, "webauthn") || st.Str("error") != "" {
		t.Fatalf("passkey-only account after passkeys were disabled: %s", st.Raw)
	}
	if done := h.Drive(txID, cont, st, o); done.Str("redirect_to") == "" {
		t.Fatalf("sign-in did not complete: %s", done.Raw)
	}

	// TOTP no longer allowed, MFA optional: bob's TOTP neither makes MFA
	// required nor is offered; he signs in with the password.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Login.Passkeys, p.MFA.Requirement, p.MFA.AllowedFactors = true, realm.MFAOptional, []string{"webauthn", "recovery_code"}
	}), 200, "TOTP not allowed")
	o.Identifier = "bob@example.test"
	start, _, cont = h.StartTx(o)
	txID = start.Str("transaction_id")
	h.Step(txID, cont, "identify", map[string]any{"identifier": o.Identifier})
	st = h.Step(txID, cont, "password", map[string]any{"password": h.passwords[o.Identifier]})
	if st.Str("redirect_to") == "" {
		t.Fatalf("a disallowed TOTP still required MFA: %s", st.Raw)
	}

	// A dead-end policy stored before ValidatePolicy refused it.
	rlm, err := h.App.Realms.ByName(context.Background(), "main")
	if err != nil {
		t.Fatal(err)
	}
	pol := rlm.Policy
	pol.Login.Passkeys, pol.MFA.Requirement, pol.MFA.AllowedFactors = false, realm.MFARequired, []string{"hotp", "recovery_code"}
	doc, _ := json.Marshal(pol)
	if _, err := h.App.D.DB.Pool.Exec(context.Background(), `UPDATE realms SET settings=$2, policy_revision=policy_revision+1 WHERE id=$1`, rlm.ID, doc); err != nil {
		t.Fatal(err)
	}
	h.App.Realms.Invalidate("main")
	o.Identifier = "carol@example.test"
	start, _, cont = h.StartTx(o)
	txID = start.Str("transaction_id")
	h.Step(txID, cont, "identify", map[string]any{"identifier": o.Identifier})
	st = h.Step(txID, cont, "password", map[string]any{"password": h.passwords[o.Identifier]})
	if st.Str("error") != "mfa_enrollment_unavailable" || len(actionTypes(st)) != 0 {
		t.Fatalf("dead-end transaction: %s", st.Raw)
	}
}
