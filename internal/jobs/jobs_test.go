package jobs_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/jobs"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/clock"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/testutil"
)

func ok(context.Context, *jobs.Job, func(map[string]any) error) (map[string]any, []byte, error) {
	return map[string]any{"ok": true}, nil, nil
}

// TestJobLeasesRetriesAndDeadLetters covers DEP-011 (and worker ownership,
// DEP-010): a claimed job carries a bounded lease and no other worker can
// claim it while the lease holds; a crashed worker's job is reclaimed once
// its lease expires; transient failures are retried with backoff until the
// attempt limit and then dead-lettered, permanent failures are dead-lettered
// at once; an idempotency key returns the same job; and workers of separate
// processes racing for the same jobs run each job exactly once.
func TestJobLeasesRetriesAndDeadLetters(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	cfg := configuration.Defaults()
	clk := clock.NewFake(time.Now())
	kr := keys.NewRandom()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := jobs.NewService(runtime.New(db, &cfg, clk, kr, log))
	deadLetters := 0
	svc.OnDeadLetter = func(string) { deadLetters++ }
	requester := audit.Ref{Type: "operator", ID: "local:test"}
	const lease = time.Minute
	create := func(sp jobs.Spec) string {
		t.Helper()
		sp.Requester = requester
		id, err := svc.Create(ctx, sp)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	type row struct {
		state, lastError string
		attempts         int
		runAfter         time.Time
	}
	get := func(id string) row {
		t.Helper()
		var r row
		var last *string
		if err := db.Pool.QueryRow(ctx, `SELECT state, last_error, attempts, run_after FROM jobs WHERE id=$1`, id).Scan(&r.state, &last, &r.attempts, &r.runAfter); err != nil {
			t.Fatal(err)
		}
		if last != nil {
			r.lastError = *last
		}
		return r
	}
	run := func(worker, typ string, h jobs.Handler) bool {
		t.Helper()
		ran, err := svc.RunOnce(ctx, worker, lease, map[string]jobs.Handler{typ: h})
		if err != nil {
			t.Fatal(err)
		}
		return ran
	}

	// A bounded lease; a duplicate worker cannot claim the leased job.
	leased := create(jobs.Spec{Type: "test.lease"})
	var owner string
	var until time.Time
	duplicate := true
	if !run("worker-a", "test.lease", func(ctx context.Context, j *jobs.Job, p func(map[string]any) error) (map[string]any, []byte, error) {
		_ = db.Pool.QueryRow(ctx, `SELECT lease_owner, lease_expires_at FROM jobs WHERE id=$1`, j.ID).Scan(&owner, &until)
		duplicate = run("worker-b", "test.lease", ok)
		return ok(ctx, j, p)
	}) {
		t.Fatal("job not claimed")
	}
	if owner != "worker-a" || !until.Equal(clk.Now().Add(lease)) || duplicate {
		t.Fatalf("lease: owner %q until %v (want %v), duplicate claim %v", owner, until, clk.Now().Add(lease), duplicate)
	}
	if r := get(leased); r.state != "succeeded" || r.attempts != 1 {
		t.Fatalf("leased job: %+v", r)
	}

	// A crashed worker's lease expires and the job is taken over.
	crashed := create(jobs.Spec{Type: "test.crash"})
	if _, err := db.Pool.Exec(ctx, `UPDATE jobs SET state='running', attempts=1, lease_owner='crashed', lease_expires_at=$2 WHERE id=$1`,
		crashed, clk.Now().Add(lease)); err != nil {
		t.Fatal(err)
	}
	if run("worker-b", "test.crash", ok) {
		t.Fatal("job taken over before its lease expired")
	}
	clk.Advance(lease + time.Second)
	if !run("worker-b", "test.crash", ok) {
		t.Fatal("expired lease not reclaimed")
	}
	if r := get(crashed); r.state != "succeeded" || r.attempts != 2 {
		t.Fatalf("reclaimed job: %+v", r)
	}

	// Retry classification and dead letters.
	flaky := create(jobs.Spec{Type: "test.flaky", MaxAttempts: 2})
	transient := func(context.Context, *jobs.Job, func(map[string]any) error) (map[string]any, []byte, error) {
		return nil, nil, errors.New("upstream timeout")
	}
	run("worker-a", "test.flaky", transient)
	if r := get(flaky); r.state != "queued" || r.attempts != 1 || r.lastError != "upstream timeout" || !r.runAfter.After(clk.Now()) {
		t.Fatalf("transient failure not retried with backoff: %+v", r)
	}
	if run("worker-a", "test.flaky", transient) {
		t.Fatal("retry ran before its backoff")
	}
	clk.Advance(time.Hour)
	run("worker-a", "test.flaky", transient)
	if r := get(flaky); r.state != "dead_letter" || r.attempts != 2 || deadLetters != 1 {
		t.Fatalf("exhausted job not dead-lettered: %+v (dead letters %d)", r, deadLetters)
	}
	clk.Advance(time.Hour)
	if run("worker-a", "test.flaky", transient) {
		t.Fatal("dead-lettered job ran again")
	}
	permanent := create(jobs.Spec{Type: "test.permanent"})
	run("worker-a", "test.permanent", func(context.Context, *jobs.Job, func(map[string]any) error) (map[string]any, []byte, error) {
		return nil, nil, fmt.Errorf("input refers to a deleted organization: %w", jobs.ErrPermanent)
	})
	if r := get(permanent); r.state != "dead_letter" || r.attempts != 1 || deadLetters != 2 {
		t.Fatalf("permanent failure retried: %+v", r)
	}

	// Idempotent creation.
	a := create(jobs.Spec{Type: "test.idempotent", IdempotencyKey: "request-1"})
	if b := create(jobs.Spec{Type: "test.idempotent", IdempotencyKey: "request-1"}); b != a {
		t.Fatalf("a retried request created a second job: %s %s", a, b)
	}

	// Workers in separate processes (own pools and services) race for the
	// same jobs; each job runs once.
	const n = 16
	for i := 0; i < n; i++ {
		create(jobs.Spec{Type: "test.race"})
	}
	var mu sync.Mutex
	runs := map[string]int{}
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		pool, err := storage.Open(ctx, db.Pool.Config().ConnString(), storage.Options{MaxConns: 2})
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		other := jobs.NewService(runtime.New(pool, &cfg, clk, kr, log))
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				ran, err := other.RunOnce(ctx, fmt.Sprintf("racer-%d", w), lease, map[string]jobs.Handler{"test.race": func(ctx context.Context, j *jobs.Job, p func(map[string]any) error) (map[string]any, []byte, error) {
					mu.Lock()
					runs[j.ID]++
					mu.Unlock()
					time.Sleep(2 * time.Millisecond)
					return ok(ctx, j, p)
				}})
				if err != nil {
					t.Errorf("racer %d: %v", w, err)
					return
				}
				if !ran {
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if len(runs) != n {
		t.Fatalf("%d of %d jobs ran", len(runs), n)
	}
	for id, c := range runs {
		if c != 1 {
			t.Fatalf("job %s ran %d times", id, c)
		}
	}
}
