package secret

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestBearerSecretsAndDigests covers TOK-003: bearer secrets carry a purpose
// prefix and 256 bits from the CSPRNG, never repeat, and are stored as a
// SHA-256 digest that does not contain the secret.
func TestBearerSecretsAndDigests(t *testing.T) {
	seen := map[string]bool{}
	for _, prefix := range []string{PrefixRefresh, PrefixAuthCode, PrefixOpaqueAccess, PrefixImpersonation, PrefixAPIKey, PrefixPAT, PrefixClientSecret} {
		for i := 0; i < 50; i++ {
			tok := Token(prefix)
			if !strings.HasPrefix(tok, prefix) {
				t.Fatalf("%q lacks its purpose prefix %q", tok, prefix)
			}
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, prefix))
			if err != nil || len(raw) != 32 {
				t.Fatalf("%q: want 32 random bytes, got %d (%v)", tok, len(raw), err)
			}
			if seen[tok] {
				t.Fatalf("secret repeated: %q", tok)
			}
			seen[tok] = true
			d := Digest(tok)
			if b, err := hex.DecodeString(d); err != nil || len(b) != 32 {
				t.Fatalf("digest %q is not a SHA-256 hex value", d)
			}
			if strings.Contains(d, strings.TrimPrefix(tok, prefix)) || d == tok || Digest(tok) != d {
				t.Fatalf("digest of %q must be deterministic and must not contain the secret", tok)
			}
		}
	}
	if Digest(PrefixRefresh+"a") == Digest(PrefixAPIKey+"a") {
		t.Fatal("secrets of different purposes share a digest")
	}
	if Equal("abc", "abd") || !Equal("abc", "abc") {
		t.Fatal("constant-time comparison")
	}
	if n := Numeric(6); len(n) != 6 || strings.Trim(n, "0123456789") != "" {
		t.Fatalf("numeric code %q", n)
	}
}
