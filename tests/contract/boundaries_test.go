package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestHTTPLayerDoesNotWriteTables guards ARC-001: HTTP handlers call module
// services, which own their tables, write audit evidence and enforce
// invariants; they never issue INSERT, UPDATE or DELETE statements directly.
// The idempotency store is the API layer's own table and is exempt.
func TestHTTPLayerDoesNotWriteTables(t *testing.T) {
	write := regexp.MustCompile(`(?i)\b(INSERT\s+INTO|UPDATE\s+[a-z_]+\s+SET|DELETE\s+FROM)\b`)
	allowed := map[string]bool{"idempotency.go": true}
	files, err := filepath.Glob("../../internal/httpapi/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no handler sources found: %v", err)
	}
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasSuffix(base, "_test.go") || allowed[base] {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if write.MatchString(line) {
				t.Errorf("%s:%d writes a table directly; move the statement into the owning module's service: %s", base, i+1, strings.TrimSpace(line))
			}
		}
	}
}
