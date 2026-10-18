package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/bench"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestBenchOTPGuessesShareAccountBudget exercises NFR-006: 32 concurrent
// attackers share one owned factor across eight transactions; a separate
// sequential case exhausts and retires two transactions at five failures.
// Exactly ten proofs are evaluated under the default account budget, and
// database/audit evidence agrees with the API. Source budgets alone are raised.
func TestBenchOTPGuessesShareAccountBudget(t *testing.T) {
	for _, tc := range []struct {
		name        string
		concurrency int
		operations  int64
	}{
		{"concurrent account budget", 32, 128}, {"transaction retirement", 1, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHarness(t, func(c *configuration.Config) {
				c.Security.RateLimits.LoginPerIP = 100000
				c.Security.RateLimits.StartPerNetwork = 100000
				c.Security.RateLimits.TokenFailuresPerNetwork = 100000
				c.Security.RateLimits.LoginPerRealm = 100000
				c.Security.RateLimits.LoginPerClient = 100000
				c.Security.RateLimits.TokenPerClient = 100000
			})
			f := fixtureOn(t, h)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			var wg sync.WaitGroup
			wg.Add(1)
			w := worker.New(h.App, "bench-otp")
			go func() {
				defer wg.Done()
				for ctx.Err() == nil {
					w.RunOnce(ctx)
					time.Sleep(50 * time.Millisecond)
				}
			}()
			defer wg.Wait()
			defer cancel()
			c := bench.NewClient(h.Srv.URL, "main", 32)
			d, err := bench.Seed(ctx, c, bench.StaticToken(f.AdminToken), bench.SeedSpec{Seed: 9, Users: 30, Organizations: 3, LargeOrgUsers: 12, MachineClients: 2, RoleDepth: 3, GroupMembers: 5}, nil)
			if err != nil {
				t.Fatal(err)
			}
			e := &bench.Env{Client: c, Admin: bench.StaticToken(f.AdminToken), Seed: d, Now: h.Clock.Now}
			r, err := bench.Run(ctx, e, bench.Scenarios()["otp-guess"](), bench.Options{Concurrency: tc.concurrency, Operations: tc.operations, Duration: 30 * time.Second, Seed: 9})
			if err != nil {
				t.Fatal(err)
			}
			if !r.Complete || r.Operations != tc.operations || r.Outcomes["invalid_proof"] != 10 || r.Outcomes["rate_limited"] == 0 {
				t.Fatalf("account budget outcomes %+v", r)
			}
			for label := range r.Outcomes {
				if label != "invalid_proof" && label != "rate_limited" && label != "transaction_limit" {
					t.Fatalf("unexpected %s", label)
				}
			}
			var user string
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND canonical_value LIKE 'b9-otp-guess-%@bench.test'`, h.Realm.ID).Scan(&user); err != nil {
				t.Fatal(err)
			}
			var failures, maxFailures, pending, failed, count int
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT sum(failure_count), max(failure_count), count(*) FILTER (WHERE status='pending'), count(*) FILTER (WHERE status='failed'), count(*) FROM auth_transactions WHERE realm_id=$1 AND user_id=$2 AND status IN ('pending','failed')`, h.Realm.ID, user).Scan(&failures, &maxFailures, &pending, &failed, &count); err != nil {
				t.Fatal(err)
			}
			if failures != 10 || maxFailures > 5 || count != 8 || pending < 6 || failed > 2 {
				t.Fatalf("stored failures %d, max %d, pending %d, failed %d, count %d", failures, maxFailures, pending, failed, count)
			}
			if tc.concurrency == 1 && (failed != 2 || pending != 6 || maxFailures != 5 || r.Outcomes["transaction_limit"] != 2) {
				t.Fatalf("five-failure retirement: failed %d, pending %d, max %d, outcomes %v", failed, pending, maxFailures, r.Outcomes)
			}
			var audited int
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND subject_id=$2 AND type='mfa.totp.failed'`, h.Realm.ID, user).Scan(&audited); err != nil {
				t.Fatal(err)
			}
			if audited != 10 {
				t.Fatalf("audited failed proofs %d, want 10", audited)
			}
		})
	}
}
