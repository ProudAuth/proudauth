package ratelimit

import (
	"context"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
)

// queryCounter is a pgx tracer that counts the statements sent through a pool.
type queryCounter struct {
	n    atomic.Int64
	mu   sync.Mutex
	sqls []string
}

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	q.n.Add(1)
	q.mu.Lock()
	q.sqls = append(q.sqls, data.SQL)
	q.mu.Unlock()
	return ctx
}

func (q *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (q *queryCounter) reset() {
	q.n.Store(0)
	q.mu.Lock()
	q.sqls = nil
	q.mu.Unlock()
}

// newLimiter returns a limiter on a fresh database whose dedicated pool counts
// every statement, and the fake clock it reads.
func newLimiter(t *testing.T) (*Limiter, *queryCounter, *clock.Fake) {
	t.Helper()
	db := testutil.NewDB(t)
	cfg, err := pgxpool.ParseConfig(db.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	qc := &queryCounter{}
	cfg.ConnConfig.Tracer = qc
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	clk := clock.NewFake(time.Date(2026, 10, 18, 10, 0, 20, 0, time.UTC))
	return New(&runtime.Deps{DB: &storage.DB{Pool: pool}, Clock: clk}), qc, clk
}

// stored returns the counter of a budget's current window (0 when absent),
// read directly from rate_limit_counters.
func stored(t *testing.T, l *Limiter, b Budget) int {
	t.Helper()
	var n int
	err := l.d.DB.Pool.QueryRow(context.Background(),
		`SELECT coalesce((SELECT count FROM rate_limit_counters WHERE bucket=$1 AND window_start=$2), 0)`,
		secret.Digest(b.Key)[:40], l.d.Now().Truncate(b.Window)).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHitConsumesEveryBudgetInOneStatement covers SEC-006 and ARC-006
// (ratelimiter-design-config): one Hit with three budgets is one database
// statement, which increments all three counters. Before, each budget was a
// separate round trip.
func TestHitConsumesEveryBudgetInOneStatement(t *testing.T) {
	l, qc, _ := newLimiter(t)
	ctx := context.Background()
	budgets := []Budget{
		{Key: "id:alice", Limit: 5, Window: 15 * time.Minute},
		{Key: "ip:192.0.2.1", Limit: 5, Window: 15 * time.Minute},
		{Key: "realm:r1", Limit: 5, Window: time.Hour},
	}
	for round := 1; round <= 3; round++ {
		qc.reset()
		d, err := l.Hit(ctx, budgets...)
		if err != nil || !d.Allowed {
			t.Fatalf("round %d: %+v %v", round, d, err)
		}
		if n := qc.n.Load(); n != 1 {
			t.Fatalf("round %d: one Hit with three budgets sent %d statements: %q", round, n, qc.sqls)
		}
		if !strings.Contains(qc.sqls[0], "INSERT INTO rate_limit_counters") {
			t.Fatalf("unexpected statement: %q", qc.sqls[0])
		}
		for _, b := range budgets {
			if got := stored(t, l, b); got != round {
				t.Fatalf("round %d: %s counted %d", round, b.Key, got)
			}
		}
	}
	// Raw keys are never stored, only their digests.
	var raw int
	if err := l.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM rate_limit_counters WHERE bucket LIKE '%alice%' OR bucket LIKE '%192.0.2.1%'`).Scan(&raw); err != nil || raw != 0 {
		t.Fatalf("raw keys stored: %d %v", raw, err)
	}
}

// TestHitDeniesAndStillConsumesEveryBudget covers SEC-006 and REG-012: when
// budgets are exhausted, the decision names the first exhausted one in
// argument order with the time left in its window, and every budget of the
// call is consumed anyway, including those after the exhausted one, so a
// refused request still counts toward the aggregate budgets. Before, the
// budgets after the first exhausted one were not counted.
func TestHitDeniesAndStillConsumesEveryBudget(t *testing.T) {
	l, _, clk := newLimiter(t)
	ctx := context.Background()
	id := Budget{Key: "id:bob", Limit: 10, Window: 15 * time.Minute}
	ip := Budget{Key: "ip:198.51.100.7", Limit: 1, Window: time.Minute}
	client := Budget{Key: "client:c1", Limit: 1, Window: time.Hour}
	realm := Budget{Key: "realm:r1", Limit: 100, Window: time.Hour}
	all := []Budget{id, ip, client, realm}
	if d, err := l.Hit(ctx, all...); err != nil || !d.Allowed {
		t.Fatalf("first hit: %+v %v", d, err)
	}
	d, err := l.Hit(ctx, all...)
	if err != nil {
		t.Fatal(err)
	}
	// ip and client are both exhausted; ip comes first. The clock is at
	// 10:00:20, so ip's one-minute window ends in 40 s.
	if d.Allowed || d.Bucket != ip.Key || d.RetryAfter != 40*time.Second {
		t.Fatalf("want denial on %q after 40s, got %+v", ip.Key, d)
	}
	for _, b := range all {
		if got := stored(t, l, b); got != 2 {
			t.Errorf("%s counted %d after two hits, want 2 (every budget is consumed)", b.Key, got)
		}
	}
	// Argument order decides which exhausted budget is reported.
	if d, err := l.Hit(ctx, realm, client, ip); err != nil || d.Allowed || d.Bucket != client.Key || d.RetryAfter != time.Hour-20*time.Second {
		t.Fatalf("want denial on %q after 59m40s, got %+v %v", client.Key, d, err)
	}
	// Under the limit everything passes again once the short window rolls
	// over; the hour-long client budget still refuses.
	clk.Advance(time.Minute)
	if d, err := l.Hit(ctx, id, ip); err != nil || !d.Allowed {
		t.Fatalf("new ip window: %+v %v", d, err)
	}
	if d, err := l.Hit(ctx, id, client); err != nil || d.Allowed || d.Bucket != client.Key {
		t.Fatalf("client window still exhausted: %+v %v", d, err)
	}
}

// TestDisabledBudgetsPeekLikeHit covers SEC-006 (ratelimiter-design-config):
// a disabled budget (limit or window not positive, or no key) is allowed by
// Peek as it is skipped by Hit; before, Peek reported a zero limit as
// exhausted. A Hit whose budgets are all disabled sends no statement, and
// disabled budgets mixed with live ones are not stored.
func TestDisabledBudgetsPeekLikeHit(t *testing.T) {
	l, qc, _ := newLimiter(t)
	ctx := context.Background()
	disabled := []Budget{
		{Key: "zero-limit", Limit: 0, Window: time.Minute},
		{Key: "negative-limit", Limit: -1, Window: time.Minute},
		{Key: "zero-window", Limit: 3, Window: 0},
		{Key: "negative-window", Limit: 3, Window: -time.Minute},
		{Key: "", Limit: 3, Window: time.Minute},
	}
	for _, b := range disabled {
		qc.reset()
		ok, err := l.Peek(ctx, b)
		if err != nil || !ok {
			t.Errorf("Peek(%+v) = %v, %v; want allowed like Hit", b, ok, err)
		}
		if n := qc.n.Load(); n != 0 {
			t.Errorf("Peek(%+v) sent %d statements for a disabled budget", b, n)
		}
	}
	qc.reset()
	if d, err := l.Hit(ctx, disabled...); err != nil || !d.Allowed {
		t.Fatalf("Hit with only disabled budgets: %+v %v", d, err)
	}
	if n := qc.n.Load(); n != 0 {
		t.Fatalf("Hit with only disabled budgets sent %d statements", n)
	}
	if d, err := l.Hit(ctx); err != nil || !d.Allowed {
		t.Fatalf("Hit without budgets: %+v %v", d, err)
	}
	live := Budget{Key: "pwd-fail:r1:id:carol", Limit: 2, Window: 15 * time.Minute}
	for i := range 2 {
		if ok, err := l.Peek(ctx, live); err != nil || !ok {
			t.Fatalf("Peek before failure %d: %v %v", i+1, ok, err)
		}
		if d, err := l.Hit(ctx, append([]Budget{live}, disabled...)...); err != nil || !d.Allowed {
			t.Fatalf("Hit %d: %+v %v", i+1, d, err)
		}
	}
	// Peek keeps its meaning for live budgets: exhausted once Limit units
	// are consumed, without consuming one itself.
	if ok, err := l.Peek(ctx, live); err != nil || ok {
		t.Fatalf("Peek after the limit: %v %v", ok, err)
	}
	if got := stored(t, l, live); got != 2 {
		t.Fatalf("Peek consumed: %d", got)
	}
	var rows int
	if err := l.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM rate_limit_counters`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("disabled budgets stored: %d rows, %v", rows, err)
	}
}

// TestHitSharedCountersConcurrently covers SEC-006 and ARC-006: concurrent
// hits naming the same counters in different orders neither deadlock nor
// lose increments, and budgets that share a counter in one call (the same
// key in windows starting at the same instant) count once each.
func TestHitSharedCountersConcurrently(t *testing.T) {
	l, _, _ := newLimiter(t)
	ctx := context.Background()
	budgets := []Budget{
		{Key: "a", Limit: 1000, Window: time.Hour},
		{Key: "b", Limit: 1000, Window: time.Hour},
		{Key: "c", Limit: 1000, Window: time.Hour},
		{Key: "d", Limit: 1000, Window: time.Hour},
	}
	const workers, rounds = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(w), 1))
			for range rounds {
				order := append([]Budget(nil), budgets...)
				r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
				if d, err := l.Hit(ctx, order...); err != nil || !d.Allowed {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent hit: %v", err)
	}
	for _, b := range budgets {
		if got := stored(t, l, b); got != workers*rounds {
			t.Errorf("%s counted %d, want %d", b.Key, got, workers*rounds)
		}
	}
	// The same key twice in one call (windows aligned at the hour) is one
	// counter consumed twice, as two hits would.
	twice := []Budget{{Key: "e", Limit: 3, Window: time.Hour}, {Key: "e", Limit: 3, Window: 15 * time.Minute}}
	if d, err := l.Hit(ctx, twice...); err != nil || !d.Allowed {
		t.Fatalf("shared counter: %+v %v", d, err)
	}
	if got := stored(t, l, twice[0]); got != 2 {
		t.Fatalf("shared counter counted %d, want 2", got)
	}
	if d, err := l.Hit(ctx, twice...); err != nil || d.Allowed || d.Bucket != "e" {
		t.Fatalf("shared counter over its limit: %+v %v", d, err)
	}
}
