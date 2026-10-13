package session

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// TestAssuranceFromFactorEvidence covers AUT-015: a session's amr values,
// MFA time and acr derive from the recorded factor evidence (type, time, user
// verification), and acr values are local urn:proudauth:acr profiles rather
// than claims of external certification.
func TestAssuranceFromFactorEvidence(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := t0.Add(d); return &v }
	pwd := Factor{Type: "pwd", At: t0}
	for _, c := range []struct {
		name    string
		factors []Factor
		amr     []string
		mfaAt   *time.Time
		acr     string
	}{
		{"password", []Factor{pwd}, []string{"pwd"}, nil, "urn:proudauth:acr:single_factor"},
		{"password then TOTP", []Factor{pwd, {Type: "totp", At: t0.Add(time.Minute)}}, []string{"pwd", "totp", "mfa"}, at(time.Minute), "urn:proudauth:acr:mfa"},
		{"password then recovery code", []Factor{pwd, {Type: "recovery", At: t0.Add(2 * time.Minute)}}, []string{"pwd", "recovery", "mfa"}, at(2 * time.Minute),
			"urn:proudauth:acr:recovery"},
		{"passkey without user verification", []Factor{{Type: "hwk", At: t0}}, []string{"hwk"}, nil, "urn:proudauth:acr:single_factor"},
		{"user-verified passkey", []Factor{{Type: "hwk", At: t0, UserVerified: true}}, []string{"hwk", "mfa"}, at(0), ACRPhishingResistant},
		{"federated", []Factor{{Type: "fed", At: t0, Upstream: "idp_1"}}, []string{"fed"}, nil, "urn:proudauth:acr:federated"},
		{"federated with trusted upstream MFA", []Factor{{Type: "fed", At: t0}, {Type: "fed_mfa", At: t0}}, []string{"fed", "fed_mfa", "mfa"}, at(0),
			"urn:proudauth:acr:mfa"},
		{"guest", []Factor{{Type: "anon", At: t0}}, []string{"anon"}, nil, "urn:proudauth:acr:anonymous"},
	} {
		amr, mfaAt := AMRFromFactors(c.factors)
		if !slices.Equal(amr, c.amr) {
			t.Errorf("%s: amr %v, want %v", c.name, amr, c.amr)
		}
		if (mfaAt == nil) != (c.mfaAt == nil) || mfaAt != nil && !mfaAt.Equal(*c.mfaAt) {
			t.Errorf("%s: MFA time %v, want %v", c.name, mfaAt, c.mfaAt)
		}
		acr := ACRFor(c.factors)
		if acr != c.acr {
			t.Errorf("%s: acr %q, want %q", c.name, acr, c.acr)
		}
		if !strings.HasPrefix(acr, "urn:proudauth:acr:") {
			t.Errorf("%s: acr %q is not a local assurance profile", c.name, acr)
		}
	}
	// Profiles are ordered for "at least" comparisons; unknown values rank nowhere.
	if !(ACRRank(ACRPhishingResistant) > ACRRank("urn:proudauth:acr:mfa") && ACRRank("urn:proudauth:acr:mfa") > ACRRank("urn:proudauth:acr:recovery") &&
		ACRRank("urn:proudauth:acr:recovery") > ACRRank("urn:proudauth:acr:single_factor")) || ACRRank("urn:example:certified:loa3") != 0 {
		t.Fatal("assurance profile ranking")
	}
}
