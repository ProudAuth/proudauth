package jobs_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/testutil"
)

// TestJobAttemptFencing covers DEP-011 and TEST-058: expired attempts cannot
// renew progress, lock domain writes or publish success/retry/cancel/dead-letter
// results over a replacement. The attempt guards reuse of the same worker ID.
func TestJobAttemptFencing(t *testing.T) {
	for _, outcome := range []string{"success", "retry", "permanent", "cancel", "same-worker-id", "expired-no-takeover"} {
		t.Run(outcome, func(t *testing.T) {
			db := testutil.NewDB(t)
			ctx := context.Background()
			cfg := configuration.Defaults()
			clk := clock.NewFake(time.Now())
			svc := jobs.NewService(runtime.New(db, &cfg, clk, keys.NewRandom(), slog.New(slog.NewTextHandler(io.Discard, nil))))
			deadLetters := 0
			svc.OnDeadLetter = func(string) { deadLetters++ }
			id, err := svc.Create(ctx, jobs.Spec{Type: "test.fence", MaxAttempts: 5, Requester: audit.Ref{Type: "operator", ID: "local:test"}})
			if err != nil {
				t.Fatal(err)
			}
			const lease = time.Minute
			snapshot := func() string {
				t.Helper()
				var value string
				if err := db.Pool.QueryRow(ctx, `SELECT to_jsonb(j)::text FROM jobs j WHERE id=$1`, id).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			var replacementSnapshot string
			var oldJob *jobs.Job
			var oldProgress func(map[string]any) error
			assertLost := func() {
				t.Helper()
				if err := oldProgress(map[string]any{"owner": "stale"}); !errors.Is(err, jobs.ErrLeaseLost) {
					t.Fatalf("stale progress: %v", err)
				}
				tx, err := db.Pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				err = oldJob.LockLease(ctx, tx)
				_ = tx.Rollback(ctx)
				if !errors.Is(err, jobs.ErrLeaseLost) {
					t.Fatalf("stale domain transaction: %v", err)
				}
			}
			replacement := func() {
				t.Helper()
				workerID := "replacement"
				if outcome == "same-worker-id" {
					workerID = "original"
				}
				ran, err := svc.RunOnce(ctx, workerID, lease, map[string]jobs.Handler{"test.fence": func(ctx context.Context, j *jobs.Job, p func(map[string]any) error) (map[string]any, []byte, error) {
					if outcome != "expired-no-takeover" {
						assertLost()
					}
					tx, err := db.Pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					err = j.LockLease(ctx, tx)
					if err != nil {
						_ = tx.Rollback(ctx)
						t.Fatalf("replacement domain lease: %v", err)
					}
					if err := tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					if err := p(map[string]any{"owner": "replacement"}); err != nil {
						t.Fatal(err)
					}
					return map[string]any{"owner": "replacement"}, []byte("test-only protected result"), nil
				}})
				if !ran || err != nil {
					t.Fatalf("replacement claim: %v/%v", ran, err)
				}
				replacementSnapshot = snapshot()
			}
			ran, err := svc.RunOnce(ctx, "original", lease, map[string]jobs.Handler{"test.fence": func(ctx context.Context, j *jobs.Job, p func(map[string]any) error) (map[string]any, []byte, error) {
				oldJob, oldProgress = j, p
				if err := p(map[string]any{"owner": "original"}); err != nil {
					t.Fatal(err)
				}
				clk.Advance(lease + time.Second)
				assertLost()
				if outcome != "expired-no-takeover" {
					replacement()
				}
				switch outcome {
				case "retry":
					return nil, nil, errors.New("stale retry")
				case "permanent":
					return nil, nil, jobs.ErrPermanent
				case "cancel":
					return nil, nil, context.Canceled
				default:
					return map[string]any{"owner": "stale"}, []byte("stale protected result"), nil
				}
			}})
			if !ran || !errors.Is(err, jobs.ErrLeaseLost) {
				t.Fatalf("stale attempt completion: %v/%v", ran, err)
			}
			if outcome == "expired-no-takeover" {
				replacement()
			}
			var state, progressOwner, resultOwner string
			var attempts int
			var protected bool
			if err := db.Pool.QueryRow(ctx, `SELECT state,attempts,progress->>'owner',result->>'owner',result_ciphertext IS NOT NULL FROM jobs WHERE id=$1`, id).
				Scan(&state, &attempts, &progressOwner, &resultOwner, &protected); err != nil {
				t.Fatal(err)
			}
			if state != "succeeded" || attempts != 2 || progressOwner != "replacement" || resultOwner != "replacement" || !protected || deadLetters != 0 || snapshot() != replacementSnapshot {
				t.Fatal("stale attempt altered replacement progress/result/state or emitted dead-letter evidence")
			}
		})
	}
}
