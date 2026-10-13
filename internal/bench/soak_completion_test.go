package bench

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"
)

type windowScenario struct {
	prepared, closed, calls int
	durations               []time.Duration
	cancel                  context.CancelFunc
	closeErr                error
}

func (*windowScenario) Name() string                          { return "window-fixture" }
func (s *windowScenario) Prepare(context.Context, *Env) error { s.prepared++; return nil }
func (s *windowScenario) Close(ctx context.Context, _ *Env) error {
	s.closed++
	if ctx.Err() != nil {
		return errors.New("cleanup received cancelled parent")
	}
	return s.closeErr
}
func (s *windowScenario) Op(ctx context.Context, _ *Env, _ int, _ *rand.Rand) string {
	s.calls++
	deadline, _ := ctx.Deadline()
	s.durations = append(s.durations, time.Until(deadline))
	if s.calls == 2 && s.cancel != nil {
		s.cancel()
	}
	<-ctx.Done()
	return "ok"
}

// NFR-005, NFR-008: completed windows survive interruption, but an aborted
// sustained run must carry an error and a partial-window marker.
func TestBenchSoakPreservesInterruptedWindowAndError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &windowScenario{cancel: cancel}
	results, err := Soak(ctx, &Env{Client: &Client{}}, s, Options{Concurrency: 1}, time.Second, 100*time.Millisecond, nil)
	if !errors.Is(err, context.Canceled) || len(results) != 2 || !results[0].Complete || results[1].Complete || s.closed != 1 {
		t.Fatalf("windows %+v, cleanup %d, error %v", results, s.closed, err)
	}
	if results[0].Operations != 1 || results[1].Operations != 1 {
		t.Fatal("completed operations were lost")
	}
}

func TestBenchSoakShortensLastWindowAndExcludesWarmup(t *testing.T) {
	s := &windowScenario{}
	results, err := Soak(context.Background(), &Env{Client: &Client{}}, s, Options{Concurrency: 1, Warmup: 250 * time.Millisecond}, 175*time.Millisecond, 100*time.Millisecond, nil)
	if err != nil || len(results) != 2 || s.prepared != 1 || s.closed != 1 || len(s.durations) != 3 {
		t.Fatalf("windows %d, fixture %+v, error %v", len(results), s, err)
	}
	// First call is warm-up (longer than the total measured budget); each
	// measured window still executes. The final deadline is 75 ms, not 100 ms.
	if s.durations[2] > 90*time.Millisecond || s.durations[2] <= 0 {
		t.Fatalf("last window budget: %v", s.durations[2])
	}
	for _, r := range results {
		if !r.Complete || r.Operations != 1 {
			t.Fatalf("window %+v", r)
		}
	}
}

func TestBenchSoakRejectsInvalidDurationsBeforePreparation(t *testing.T) {
	for _, d := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {-time.Second, time.Second}, {time.Second, -time.Second}} {
		s := &windowScenario{}
		if _, err := Soak(context.Background(), &Env{Client: &Client{}}, s, Options{}, d[0], d[1], nil); err == nil || s.prepared != 0 || s.closed != 0 {
			t.Fatalf("invalid durations %v prepared %+v: %v", d, s, err)
		}
	}
}
