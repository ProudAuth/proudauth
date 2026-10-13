package e2e

import (
	"context"
	"testing"

	"github.com/proudbase/proudauth/internal/bench"
)

// TestBenchComplexAuditFilterLiveFixtures covers NFR-004, NFR-006 and
// NFR-008: owned public reports must prove exact compound pages and typed
// invalid-input/cursor refusals, rather than only successful HTTP statuses.
func TestBenchComplexAuditFilterLiveFixtures(t *testing.T) {
	f := NewFixture(t)
	c := bench.NewClient(f.H.Base, "main", 8)
	e := &bench.Env{Client: c, Admin: bench.StaticToken(f.AdminToken), Now: f.H.Clock.Now,
		Seed: &bench.SeedData{Prefix: "b31-", AdminAudience: f.H.Realm.Issuer + "/admin", LargeOrgID: f.Acme, OrgIDs: []string{f.Acme, f.Globex}, Spec: bench.SeedSpec{Users: 32}}}
	r, err := bench.Run(context.Background(), e, bench.Scenarios()["complex-audit-filter"](), bench.Options{Concurrency: 8, Operations: 63, Seed: 31})
	if err != nil {
		t.Fatal(err)
	}
	labels := []string{"compound_match", "compound_empty", "literal_prefix_empty", "invalid_network", "invalid_time", "cursor_scope_rejected", "cursor_page"}
	if !r.Complete || r.Operations != 63 || len(r.Outcomes) != len(labels) {
		t.Fatalf("incomplete audit scenario: %+v", r.Outcomes)
	}
	for _, label := range labels {
		if r.Outcomes[label] != 9 {
			t.Fatalf("audit profile %s did not pass nine times: %+v", label, r.Outcomes)
		}
	}
}
