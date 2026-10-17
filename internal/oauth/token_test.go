package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/token"
)

// s256 is the RFC 7636 S256 transformation of a verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestVerifyPKCE covers the token-endpoint PKCE check (RFC 7636 §4.1,
// §4.6; TEST-028): a verifier is 43 to 128 characters of
// [A-Za-z0-9-._~] and its S256 digest must equal the stored challenge.
func TestVerifyPKCE(t *testing.T) {
	const (
		// RFC 7636 Appendix B.
		rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	valid := strings.Repeat("a", 43)
	cases := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{"RFC 7636 example", rfcVerifier, rfcChallenge, true},
		{"43 characters, the minimum", valid, s256(valid), true},
		{"128 characters, the maximum", strings.Repeat("Z", 128), s256(strings.Repeat("Z", 128)), true},
		{"42 characters", strings.Repeat("a", 42), s256(strings.Repeat("a", 42)), false},
		{"129 characters", strings.Repeat("Z", 129), s256(strings.Repeat("Z", 129)), false},
		{"empty verifier", "", s256(""), false},
		{"upper-case letters", strings.Repeat("Q", 43), s256(strings.Repeat("Q", 43)), true},
		{"lower-case letters", strings.Repeat("q", 43), s256(strings.Repeat("q", 43)), true},
		{"digits", strings.Repeat("7", 43), s256(strings.Repeat("7", 43)), true},
		{"hyphen", strings.Repeat("-", 43), s256(strings.Repeat("-", 43)), true},
		{"period", strings.Repeat(".", 43), s256(strings.Repeat(".", 43)), true},
		{"underscore", strings.Repeat("_", 43), s256(strings.Repeat("_", 43)), true},
		{"tilde", strings.Repeat("~", 43), s256(strings.Repeat("~", 43)), true},
		{"every class mixed", "AZaz09-._~" + strings.Repeat("x", 33), s256("AZaz09-._~" + strings.Repeat("x", 33)), true},
		{"plus in the middle", mid("+"), s256(mid("+")), false},
		{"slash in the middle", mid("/"), s256(mid("/")), false},
		{"padding", mid("="), s256(mid("=")), false},
		{"space", mid(" "), s256(mid(" ")), false},
		{"percent", mid("%"), s256(mid("%")), false},
		{"NUL byte", mid("\x00"), s256(mid("\x00")), false},
		{"non-ASCII letter", mid("é"), s256(mid("é")), false},
		{"invalid UTF-8", mid("\xff"), s256(mid("\xff")), false},
		{"forbidden first character", "+" + valid, s256("+" + valid), false},
		{"forbidden last character", valid + "!", s256(valid + "!"), false},
		{"challenge of another verifier", rfcVerifier, s256(valid), false},
		{"empty challenge", rfcVerifier, "", false},
		{"plain method: challenge equals verifier", rfcVerifier, rfcVerifier, false},
		{"padded challenge", rfcVerifier, rfcChallenge + "=", false},
		{"standard base64 alphabet", rfcVerifier, strings.ReplaceAll(rfcChallenge, "-", "+"), false},
		{"challenge differs in case", rfcVerifier, strings.ToLower(rfcChallenge), false},
		{"truncated challenge", rfcVerifier, rfcChallenge[:42], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyPKCE(tc.verifier, tc.challenge); got != tc.want {
				t.Fatalf("verifyPKCE(%q, %q) = %v, want %v", tc.verifier, tc.challenge, got, tc.want)
			}
		})
	}
}

// mid returns a 43-byte-or-longer verifier with c in the middle.
func mid(c string) string { return strings.Repeat("a", 21) + c + strings.Repeat("a", 21) }

// TestTokenTypeFor pins token_type: DPoP for a DPoP-bound token (RFC 9449
// §5), Bearer otherwise, certificate-bound tokens included (RFC 8705 §3).
func TestTokenTypeFor(t *testing.T) {
	cases := []struct {
		name string
		cnf  *token.Confirmation
		want string
	}{
		{"unbound", nil, "Bearer"},
		{"empty confirmation", &token.Confirmation{}, "Bearer"},
		{"DPoP key", &token.Confirmation{JKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}, "DPoP"},
		{"TLS certificate", &token.Confirmation{X5TS256: "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}, "Bearer"},
		{"both bindings", &token.Confirmation{JKT: "jkt", X5TS256: "x5t"}, "DPoP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenTypeFor(tc.cnf); got != tc.want {
				t.Fatalf("tokenTypeFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGrantAllowed covers grant registration and the realm emergency
// control (SEC-020), from which only the operator CLI client is exempt.
func TestGrantAllowed(t *testing.T) {
	code := application.GrantAuthorizationCode
	disabled := &realm.Realm{DisabledGrantTypes: []string{code}}
	open := &realm.Realm{}
	app := &application.Client{ClientID: "app", GrantTypes: []string{code, application.GrantRefreshToken}}
	operator := &application.Client{ClientID: application.OperatorClientID, GrantTypes: []string{code}}
	cases := []struct {
		name   string
		rlm    *realm.Realm
		client *application.Client
		grant  string
		want   bool
	}{
		{"registered and enabled", open, app, code, true},
		{"not registered", open, app, application.GrantClientCredentials, false},
		{"empty grant", open, app, "", false},
		{"disabled by the realm", disabled, app, code, false},
		{"another grant stays enabled", disabled, app, application.GrantRefreshToken, true},
		{"operator client is exempt", disabled, operator, code, true},
		{"operator client still needs the registration", open, operator, application.GrantRefreshToken, false},
		{"grant type names are exact", open, app, "Authorization_Code", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grantAllowed(tc.rlm, tc.client, tc.grant); got != tc.want {
				t.Fatalf("grantAllowed(%q) = %v, want %v", tc.grant, got, tc.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"", ""}, ""},
		{[]string{"basic", "form", "unknown"}, "basic"},
		{[]string{"", "form", "unknown"}, "form"},
		{[]string{"", "", "unknown"}, "unknown"},
	}
	for _, tc := range cases {
		if got := firstNonEmpty(tc.in...); got != tc.want {
			t.Errorf("firstNonEmpty(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
