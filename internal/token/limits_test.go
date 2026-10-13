package token

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestTokenAndJSONLimits covers NFR-001 for token size and JSON nesting:
// a token longer than the configured limit (limits.max_token_bytes, 8192
// bytes when unset) is refused before it is parsed or any key is looked up,
// and a JSON document nested deeper than limits.max_json_depth is malformed
// while one at the limit is accepted.
func TestTokenAndJSONLimits(t *testing.T) {
	ctx := context.Background()
	// No key manager: a refusal on size must happen before any key lookup.
	v := &Verifier{MaxBytes: 64}
	shaped := func(n int) string { return "eyJ." + strings.Repeat("a", n-8) + ".sig" }
	if _, err := v.VerifyAccess(ctx, "rlm", "iss", "aud", shaped(65)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("token one byte over max_token_bytes: %v, want ErrTooLarge", err)
	}
	if _, err := v.VerifyAccess(ctx, "rlm", "iss", "aud", shaped(64)); errors.Is(err, ErrTooLarge) || err == nil {
		t.Fatalf("token at max_token_bytes refused for its size or accepted: %v", err)
	}
	if _, err := v.VerifyIDTokenHint(ctx, "rlm", "iss", shaped(65)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ID token hint over the limit: %v, want ErrTooLarge", err)
	}
	unset := &Verifier{}
	if _, err := unset.VerifyAccess(ctx, "rlm", "iss", "aud", shaped(8193)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("unset limit must default to 8192 bytes: %v", err)
	}

	// JSON depth: the top-level value is depth 0, so n nested objects put
	// the innermost scalar at depth n.
	nested := func(n int) []byte {
		return []byte(strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n))
	}
	for _, max := range []int{4, 8, 32} {
		if err := RejectDuplicateKeysDepth(nested(max), max); err != nil {
			t.Fatalf("depth %d at max_json_depth %d refused: %v", max, max, err)
		}
		if err := RejectDuplicateKeysDepth(nested(max+1), max); !errors.Is(err, ErrMalformed) {
			t.Fatalf("depth %d over max_json_depth %d: %v, want ErrMalformed", max+1, max, err)
		}
		arrays := []byte(strings.Repeat("[", max+1) + "1" + strings.Repeat("]", max+1))
		if err := RejectDuplicateKeysDepth(arrays, max); !errors.Is(err, ErrMalformed) {
			t.Fatalf("arrays nested %d deep over max_json_depth %d: %v", max+1, max, err)
		}
	}
	// An unset limit falls back to the default of 32.
	if err := RejectDuplicateKeysDepth(nested(33), 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unset max_json_depth must default to 32: %v", err)
	}
}
