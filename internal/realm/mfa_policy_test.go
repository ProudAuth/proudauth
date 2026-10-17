package realm

import (
	"errors"
	"testing"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

func problemField(err error) string {
	var pe *problem.Error
	if !errors.As(err, &pe) {
		return ""
	}
	for k := range pe.Fields {
		return k
	}
	return ""
}

// TestAllowedFactorsNeedAnEnrollableSecondFactor covers MFA-003 and MFA-005:
// a factor list that leaves no second factor the sign-in transaction can
// enroll (TOTP, or a passkey where passkeys are enabled) is refused, since an
// account that must use MFA would wait for an action that is never offered.
func TestAllowedFactorsNeedAnEnrollableSecondFactor(t *testing.T) {
	for _, c := range []struct {
		allowed  []string
		passkeys bool
		ok       bool
	}{
		{nil, false, true},
		{[]string{"totp", "webauthn", "recovery_code"}, false, true},
		{[]string{"totp"}, false, true},
		{[]string{"webauthn", "recovery_code"}, false, true},
		{[]string{"hotp", "recovery_code"}, true, true}, // login.passkeys enrolls a passkey
		{[]string{"hotp", "recovery_code"}, false, false},
		{[]string{"recovery_code"}, false, false},
		{[]string{"hotp"}, false, false},
		{[]string{"email_otp"}, false, false}, // a primary method, never a second factor
		{[]string{"sms_otp", "email_otp"}, false, false},
	} {
		p := DefaultPolicy()
		p.MFA.AllowedFactors = c.allowed
		p.Login.Passkeys = c.passkeys
		err := ValidatePolicy(p, false)
		if c.ok && err != nil {
			t.Errorf("allowed %v (passkeys %v): refused: %v", c.allowed, c.passkeys, err)
		}
		if !c.ok && problemField(err) != "mfa.allowed_factors" {
			t.Errorf("allowed %v (passkeys %v): dead-end factor list accepted (%v)", c.allowed, c.passkeys, err)
		}
	}
}

// TestPhishingResistantProfileNeedsPasskeys covers SEC-012 and MFA-005: the
// realm's own mfa.admin_phishing_resistant and the operator floor
// security.mfa_floor.admin_phishing_resistant fail closed. A policy that
// leaves passkeys disabled cannot meet the profile and is refused.
func TestPhishingResistantProfileNeedsPasskeys(t *testing.T) {
	off := DefaultPolicy()
	off.Login.Passkeys = false
	off.MFA.AllowedFactors = []string{"totp", "recovery_code"}
	if err := ValidatePolicy(off, false); err != nil {
		t.Fatalf("passkeys off without the profile: %v", err)
	}
	if err := CheckMFAFloor(off, configuration.MFAFloor{}); err != nil {
		t.Fatalf("passkeys off without a floor: %v", err)
	}

	// The realm's own profile without passkeys.
	own := off
	own.MFA.AdminPhishingResistant = true
	if f := problemField(ValidatePolicy(own, false)); f != "mfa.admin_phishing_resistant" {
		t.Fatalf("realm profile with passkeys off accepted (field %q)", f)
	}

	// The operator floor refuses the same policy on its own.
	floor := configuration.MFAFloor{AdminPhishingResistant: true}
	if f := problemField(CheckMFAFloor(own, floor)); f != "login.passkeys" {
		t.Fatalf("floor accepted a policy with passkeys off (field %q)", f)
	}
	if f := problemField(CheckMFAFloor(off, floor)); f != "mfa.admin_phishing_resistant" {
		t.Fatalf("floor accepted a policy without the profile (field %q)", f)
	}

	// A realm saved in that state before these checks is reported
	// (identity-cli doctor).
	if !PhishingResistantUnmet(own, configuration.MFAFloor{}) || !PhishingResistantUnmet(off, floor) {
		t.Fatal("profile without passkeys not reported")
	}
	if PhishingResistantUnmet(off, configuration.MFAFloor{}) {
		t.Fatal("passkeys off without any profile reported")
	}

	// Either way of enabling passkeys meets it.
	for name, mutate := range map[string]func(p *Policy){
		"login.passkeys":     func(p *Policy) { p.Login.Passkeys = true },
		"webauthn as factor": func(p *Policy) { p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, "webauthn") },
	} {
		p := own
		p.MFA.AllowedFactors = append([]string(nil), own.MFA.AllowedFactors...)
		mutate(&p)
		if err := ValidatePolicy(p, false); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := CheckMFAFloor(p, floor); err != nil {
			t.Errorf("%s: floor: %v", name, err)
		}
		if PhishingResistantUnmet(p, floor) {
			t.Errorf("%s: reported although passkeys are enabled", name)
		}
	}
}
