package authentication

import (
	"testing"

	"github.com/proudbase/proudauth/internal/federation"
	"github.com/proudbase/proudauth/internal/session"
)

// TestLinkProofRequiresLinkBoundEmailProof covers PWDLESS-008 (and
// PWDLESS-006): an SMS code never proves control of an account for linking
// an external identity; while a link is pending, only an emailed code or
// magic link sent for that link (bound by its challenge metadata) counts,
// and a linking code never serves as a plain sign-in.
func TestLinkProofRequiresLinkBoundEmailProof(t *testing.T) {
	for _, f := range []string{"pwd", "otp", "magic_link", "hwk", "swk"} {
		if !localPrimaryDone(&Transaction{Factors: []session.Factor{{Type: f}}}) {
			t.Errorf("%s does not prove control for linking", f)
		}
	}
	for _, f := range []string{"sms", "fed", "anon", "totp"} {
		if localPrimaryDone(&Transaction{Factors: []session.Factor{{Type: f}}}) {
			t.Errorf("%s proves control for linking", f)
		}
	}

	pending := &Transaction{}
	pending.Pending.PendingLink = &federation.Candidate{ProviderID: "idp_1", UserID: "usr_1"}
	plain := &Transaction{}
	bound := &ConsumedChallenge{IdentifierType: "email", Metadata: map[string]any{linkMetaProvider: "idp_1", linkMetaUser: "usr_1"}}
	login := &ConsumedChallenge{IdentifierType: "email", Metadata: map[string]any{}}
	cases := []struct {
		name string
		t    *Transaction
		c    *ConsumedChallenge
		want bool
	}{
		{"sign-in code, no link pending", plain, login, true},
		{"link code, link pending", pending, bound, true},
		{"sign-in code sent before the link was pending", pending, login, false},
		{"link code for another connection", pending, &ConsumedChallenge{IdentifierType: "email", Metadata: map[string]any{linkMetaProvider: "idp_2", linkMetaUser: "usr_1"}}, false},
		{"link code for another account", pending, &ConsumedChallenge{IdentifierType: "email", Metadata: map[string]any{linkMetaProvider: "idp_1", linkMetaUser: "usr_2"}}, false},
		{"link-bound SMS code", pending, &ConsumedChallenge{IdentifierType: "phone", Metadata: bound.Metadata}, false},
		{"link code used as a plain sign-in", plain, bound, false},
	}
	for _, tc := range cases {
		if got := linkProofMatches(tc.t, tc.c); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
