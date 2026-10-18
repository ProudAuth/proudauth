package authentication

import (
	"fmt"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/session"
)

// TestDescribeCredentials covers CRED-008 and MCH-008: the credentials_revoked
// notice names each revoked credential by name and display prefix, never a
// secret, and a long list is bounded with a count of the rest.
func TestDescribeCredentials(t *testing.T) {
	two := []session.RevokedCredential{{Name: "cli", DisplayPrefix: "pa_pat_AbC123"}, {Name: "sync", DisplayPrefix: "pa_key_XyZ789"}}
	if got, want := describeCredentials(two), "cli (pa_pat_AbC123), sync (pa_key_XyZ789)"; got != want {
		t.Fatalf("describeCredentials = %q, want %q", got, want)
	}
	var many []session.RevokedCredential
	for i := range maxNamedCredentials + 5 {
		many = append(many, session.RevokedCredential{Name: fmt.Sprintf("ci-%02d", i), DisplayPrefix: "pa_pat_000000"})
	}
	got := describeCredentials(many)
	if !strings.HasSuffix(got, ", and 5 more") || strings.Count(got, "pa_pat_") != maxNamedCredentials || strings.Contains(got, "ci-20") {
		t.Fatalf("long list not bounded: %q", got)
	}
}
