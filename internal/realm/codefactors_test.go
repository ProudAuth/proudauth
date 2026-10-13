package realm

import (
	"slices"
	"testing"
)

// TestCodeFactorsFollowAllowedFactors covers MFA-005 and MFA-013: only the
// code factors the realm allows count as enrolled second factors outside
// sign-in too. TOTP is allowed by an empty list; HOTP only when listed.
func TestCodeFactorsFollowAllowedFactors(t *testing.T) {
	for _, c := range []struct {
		allowed, want []string
	}{
		{nil, []string{"totp"}},
		{[]string{"totp", "webauthn", "recovery_code"}, []string{"totp"}},
		{[]string{"totp", "hotp"}, []string{"totp", "hotp"}},
		{[]string{"webauthn", "hotp"}, []string{"hotp"}},
		{[]string{"webauthn", "recovery_code"}, []string{}},
	} {
		if got := (MFAPolicy{AllowedFactors: c.allowed}).CodeFactors(); !slices.Equal(got, c.want) {
			t.Errorf("allowed %v: code factors %v, want %v", c.allowed, got, c.want)
		}
	}
}
