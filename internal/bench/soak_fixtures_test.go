package bench

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

type fixtureScenario struct {
	fakeScenario
	prepared, slots int
}

func (s *fixtureScenario) Prepare(_ context.Context, e *Env) error {
	s.prepared++
	if e.Concurrency < 1 {
		return fmt.Errorf("no worker fixtures")
	}
	s.slots = e.Concurrency
	return nil
}
func (s *fixtureScenario) Op(ctx context.Context, e *Env, w int, r *rand.Rand) string {
	if w >= s.slots {
		return "invariant_missing_worker_fixture"
	}
	return s.fakeScenario.Op(ctx, e, w, r)
}

// NFR-005: soak preparation must reserve every configured worker's credential
// or connector before the first window, and reuse those fixtures throughout.
func TestSoakPreparesAllWorkerFixturesOnce(t *testing.T) {
	s := &fixtureScenario{}
	results, err := Soak(context.Background(), &Env{Client: &Client{BaseURL: "http://bench.test"}}, s, Options{Concurrency: 4}, 40*time.Millisecond, 10*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.prepared != 1 || s.slots != 4 || len(results) < 2 {
		t.Fatalf("preparations %d, slots %d, windows %d", s.prepared, s.slots, len(results))
	}
	for _, r := range results {
		if r.Outcomes["ok"] == 0 || len(r.Outcomes) != 1 || r.Concurrency != 4 {
			t.Fatalf("window %+v", r)
		}
	}
}
