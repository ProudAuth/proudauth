package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/bench"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestBenchComplexGroupFilterLiveFixtures covers NFR-004, NFR-006 and
// NFR-008: public-API Group fixtures, including a large member set, must pass
// all measured name/member, projection, ETag and parser-bound criteria.
func TestBenchComplexGroupFilterLiveFixtures(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var done sync.WaitGroup
	done.Add(1)
	w := worker.New(h.App, "group-filter-fixture")
	go func() {
		defer done.Done()
		for ctx.Err() == nil {
			w.RunOnce(ctx)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer done.Wait()
	defer cancel()
	c := bench.NewClient(h.Srv.URL, "main", 4)
	d, err := bench.Seed(ctx, c, bench.StaticToken(f.AdminToken), bench.SeedSpec{Seed: 19, Users: 20, Organizations: 3, LargeOrgUsers: 10, MachineClients: 2, RoleDepth: 3, GroupMembers: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &bench.Env{Client: c, Admin: bench.StaticToken(f.AdminToken), Seed: d, Now: h.Clock.Now}
	r, err := bench.Run(ctx, e, bench.Scenarios()["complex-group-filter"](), bench.Options{Concurrency: 4, Operations: 32, Seed: 19})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || r.Operations != 32 || r.Outcomes["bounded_true"] == 0 || r.Outcomes["bounded_false"] == 0 || r.Outcomes["invalid_filter_nodes"] == 0 || r.Outcomes["invalid_filter_bytes"] == 0 {
		t.Fatalf("incomplete Group scenario: %+v", r.Outcomes)
	}
	for name := range r.Outcomes {
		if name != "bounded_true" && name != "bounded_false" && name != "invalid_filter_nodes" && name != "invalid_filter_bytes" && name != "rate_limited" {
			t.Fatalf("Group scenario invariant failed: %s", name)
		}
	}
}
