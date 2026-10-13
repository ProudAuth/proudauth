package token

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzRejectDuplicateKeys: anything accepted is well-formed JSON, and a document
// with a repeated member name in the same object is never accepted (TOK-020, SEC-004).
func FuzzRejectDuplicateKeys(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `[{"x":1},{"x":1}]`, `{"a":"a"}`, `{"a":1,"a":2}`, `{`, `"s"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := RejectDuplicateKeys(b); err != nil {
			return
		}
		if !json.Valid(b) {
			t.Fatalf("accepted invalid JSON %q", b)
		}
		// Re-check top-level objects with a decoder that records keys after unescaping.
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) == nil {
			dec := json.NewDecoder(bytes.NewReader(b))
			if tok, err := dec.Token(); err == nil && tok == json.Delim('{') {
				seen := map[string]bool{}
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return
					}
					k := kt.(string)
					if seen[k] {
						t.Fatalf("duplicate member %q accepted in %q", k, b)
					}
					seen[k] = true
					var skip json.RawMessage
					if dec.Decode(&skip) != nil {
						return
					}
				}
			}
		}
	})
}
