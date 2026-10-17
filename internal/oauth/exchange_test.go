package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/token"
)

// TestStripQuery pins the DPoP htu comparison form (RFC 9449 §4.3): the URI
// without its query and fragment.
func TestStripQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://idp.example/realms/acme/oauth/token", "https://idp.example/realms/acme/oauth/token"},
		{"https://idp.example/oauth/token?x=1", "https://idp.example/oauth/token"},
		{"https://idp.example/oauth/token#frag", "https://idp.example/oauth/token"},
		{"https://idp.example/oauth/token?x=1#frag", "https://idp.example/oauth/token"},
		{"https://idp.example/oauth/token#frag?x=1", "https://idp.example/oauth/token"},
		{"https://idp.example/oauth/token?", "https://idp.example/oauth/token"},
		{"?x=1", ""},
	}
	for _, tc := range cases {
		if got := stripQuery(tc.in); got != tc.want {
			t.Errorf("stripQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestVerifyAnyAudienceRejectsBeforeVerification covers the structural
// checks introspection, exchange and revocation apply before a token's
// signature is verified: three segments, a base64url payload and exactly
// one audience. The Service has no verifier, so a token that passed these
// checks would panic here.
func TestVerifyAnyAudienceRejectsBeforeVerification(t *testing.T) {
	s := &Service{}
	rlm := &realm.Realm{ID: "rlm_1", Issuer: "https://idp.example/realms/acme"}
	seg := func(payload string) string {
		return "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
	}
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"empty", "", token.ErrMalformed},
		{"opaque token", "pa_at_0123456789", token.ErrMalformed},
		{"two segments", "a.b", token.ErrMalformed},
		{"four segments", "a.b.c.d", token.ErrMalformed},
		{"five segments (JWE)", "a.b.c.d.e", token.ErrMalformed},
		{"payload is not base64url", "a.!!!.c", token.ErrMalformed},
		{"padded payload", "a." + base64.URLEncoding.EncodeToString([]byte(`{"aud":"x"}`)) + ".c", token.ErrMalformed},
		{"payload is not JSON", seg("not json"), token.ErrAudience},
		{"no audience", seg(`{"sub":"usr_1"}`), token.ErrAudience},
		{"empty audience list", seg(`{"aud":[]}`), token.ErrAudience},
		{"two audiences", seg(`{"aud":["https://api.example","https://other.example"]}`), token.ErrAudience},
		{"audience is a number", seg(`{"aud":5}`), token.ErrAudience},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.verifyAnyAudience(context.Background(), rlm, tc.raw)
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("verifyAnyAudience = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
