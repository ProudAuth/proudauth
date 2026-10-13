package bench

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"
)

type ownedScenario struct {
	fakeScenario
	closed     int
	prepareErr error
	cancel     context.CancelFunc
	outcome    string
}

func (s *ownedScenario) Prepare(context.Context, *Env) error { return s.prepareErr }
func (s *ownedScenario) Close(context.Context, *Env) error   { s.closed++; return nil }
func (s *ownedScenario) Op(context.Context, *Env, int, *rand.Rand) string {
	if s.cancel != nil {
		s.cancel()
	}
	return s.outcome
}

// NFR-008: successful component operations at cancellation are still complete;
// interrupted operations are not portable reference samples.
func TestBenchCountsCompletedMixedOperationAtBoundary(t *testing.T) {
	for _, out := range []string{"ok", "webhook-delivery:ok", "transport_error", "webhook-delivery:transport_error"} {
		ctx, cancel := context.WithCancel(context.Background())
		s := &ownedScenario{cancel: cancel, outcome: out}
		r, err := Run(ctx, &Env{Client: &Client{}}, s, Options{Concurrency: 1, Operations: 1})
		cancel()
		if !errors.Is(err, context.Canceled) || r == nil || r.Complete {
			t.Fatalf("interruption lost: result %+v, error %v", r, err)
		}
		want := int64(0)
		if out == "ok" || out == "webhook-delivery:ok" {
			want = 1
		}
		if r.Operations != want || s.closed != 1 {
			t.Fatalf("%s counted %d, cleanup %d", out, r.Operations, s.closed)
		}
	}
}

func TestBenchClosesScenarioOnceAcrossSoakOrPreparationFailure(t *testing.T) {
	e := &Env{Client: &Client{}}
	s := &ownedScenario{prepareErr: errors.New("setup failed")}
	if _, err := Run(context.Background(), e, s, Options{Operations: 1}); err == nil || s.closed != 1 {
		t.Fatal("failed preparation not cleaned up")
	}
	s = &ownedScenario{outcome: "ok"}
	results, err := Soak(context.Background(), e, s, Options{Concurrency: 2}, 30*time.Millisecond, 10*time.Millisecond, nil)
	if err != nil || len(results) < 2 || s.closed != 1 {
		t.Fatalf("soak windows %d, cleanup %d, error %v", len(results), s.closed, err)
	}
}
