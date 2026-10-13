package reqctx

import (
	"strings"
	"testing"
)

// FuzzParseTraceparent (QA-003, API-012): only well-formed W3C headers are
// accepted, and an accepted trace ID is 32 lowercase hex digits and not all
// zeros, so nothing else from the header reaches logs or outbound calls.
func FuzzParseTraceparent(f *testing.F) {
	f.Add("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	f.Add("00-00000000000000000000000000000000-b7ad6b7169203331-01")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, h string) {
		id, _, ok := ParseTraceparent(h)
		if !ok {
			return
		}
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || id == strings.Repeat("0", 32) {
			t.Fatalf("accepted malformed trace ID %q from %q", id, h)
		}
	})
}
