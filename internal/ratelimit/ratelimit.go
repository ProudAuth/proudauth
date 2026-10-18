// Package ratelimit implements layered abuse budgets with concurrency-safe counters
// stored in PostgreSQL so every node observes the same budget (SEC-006, ARC-006).
//
// Budgets are keyed by identifier hints (whether or not an account exists, so a 429
// never reveals account existence), network, client, realm and organization. They
// use fixed windows (the window containing now, aligned to multiples of its length),
// so an attacker cannot cause a permanent lockout.
//
// A budget with Limit <= 0, Window <= 0 or an empty Key is disabled: Hit does not
// count it and Peek reports it as allowed. Configuration uses 0 to disable a
// budget; negative values are refused by configuration validation.
//
// Hit consumes one unit from every live budget of the call in a single statement,
// one database round trip however many budgets the call names. Every budget is
// consumed even when another one of the call is exhausted: a refused request still
// counts toward the aggregate budgets (client, organization, realm) it would have
// used, so retrying a refused request cannot bypass them. Check reads budgets
// without consuming them, in one read-only statement: a failure budget is
// checked before an attempt and charged with Hit only once the attempt fails.
//
// Per-network budgets count networks, not addresses (SEC-006, ABU-001): an IPv4
// address is its own network (/32), an IPv6 address counts by its /64, which one
// subscriber or LAN usually holds whole, so rotating addresses inside it gains
// nothing. A wider budget on the IPv4 /24 or IPv6 /48 (security.rate_limits.
// network_coarse_factor times the per-network limit) bounds someone who holds
// many networks of one site (PerNetwork).
package ratelimit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
)

// Limiter enforces fixed-window budgets.
type Limiter struct {
	d *runtime.Deps
	// peaks is the highest utilization this process has seen per aggregate
	// budget family in the family's current window (Utilization).
	mu    sync.Mutex
	peaks map[string]peak
}

// peak is the highest utilization of one aggregate budget family in the
// window that starts at start and ends at end.
type peak struct {
	start, end time.Time
	value      float64
}

// New returns a limiter.
func New(d *runtime.Deps) *Limiter { return &Limiter{d: d, peaks: map[string]peak{}} }

// AggregateBudgets are the budget families shared by everyone who uses one
// client, organization or realm (SEC-006, REG-012, TEN-018), named by the key
// prefix before the first colon. They are the label values of
// proudauth_rate_budget_utilization, a fixed set so its series are bounded.
// token-client counts every token request of a confidential client and only
// the failed grants of a public one; par-client counts the pushed
// authorization requests of a public client.
var AggregateBudgets = []string{
	"dcr-realm",
	"guest-client", "guest-realm",
	"par-client",
	"pwd-client", "pwd-org", "pwd-realm",
	"send-client", "send-org", "send-realm",
	"signup-client", "signup-realm",
	"token-client", "token-org",
	"verify-client", "verify-org", "verify-realm",
}

// UtilizationMetric is the name of the gauge that exports Utilization.
const UtilizationMetric = "proudauth_rate_budget_utilization"

// UtilizationHelp is the gauge's help text.
const UtilizationHelp = "Highest count/limit this process has seen in the current window of an aggregate abuse budget, by budget family (SEC-006, owner decision 9 of 0.2.0-alpha.6); 1 is exhausted"

var aggregate = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range AggregateBudgets {
		m[f] = true
	}
	return m
}()

// family returns a budget key's family: the prefix before the first colon.
func family(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}
	return key
}

// observe records the utilization of an aggregate budget for Utilization.
func (l *Limiter) observe(b Budget, start time.Time, count int) {
	f := family(b.Key)
	if !aggregate[f] {
		return
	}
	u := float64(count) / float64(b.Limit)
	l.mu.Lock()
	defer l.mu.Unlock()
	// A newer window starts over; a counter of an older window, read late,
	// changes nothing.
	if p, ok := l.peaks[f]; !ok || start.After(p.start) || (start.Equal(p.start) && u > p.value) {
		l.peaks[f] = peak{start: start, end: start.Add(b.Window), value: u}
	}
}

// Utilization returns the highest count/limit this process has seen for an
// aggregate budget family (AggregateBudgets) in its current window: the
// largest over the family's keys (every client, organization or realm), so an
// alert near 1 fires before the budget refuses sign-ins. Counts come from the
// shared counters, so each process reports the global count of the keys it
// touched; the maximum over processes covers them all. It is 0 once the
// window ends, and above 1 while refused attempts keep counting.
func (l *Limiter) Utilization(family string) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.peaks[family]
	if !ok || !l.d.Now().Before(p.end) {
		return 0
	}
	return p.value
}

// NetworkKey returns the network a per-network budget counts for an address:
// the IPv4 address itself as a /32, or the /64 of an IPv6 address, in prefix
// form ("192.0.2.7/32", "2001:db8:1:2::/64"). An address that does not parse
// is returned unchanged, so it still has a budget of its own.
func NetworkKey(ip string) string {
	if n := reqctx.NetworkPrefix(ip, 32, 64); n != "" {
		return n
	}
	return ip
}

// CoarseNetworkKey returns the wider network of an address, the IPv4 /24 or
// the IPv6 /48, or "" when the address does not parse.
func CoarseNetworkKey(ip string) string { return reqctx.NetworkPrefix(ip, 24, 48) }

// PerNetwork returns the budgets of a per-network limit for an address: the
// key prefix plus NetworkKey(ip) with limit, and, when coarseFactor is
// positive and the address parses, the prefix plus CoarseNetworkKey(ip) with
// coarseFactor times limit, both over window. A limit of 0 disables both.
func PerNetwork(prefix, ip string, limit int, window time.Duration, coarseFactor int) []Budget {
	b := []Budget{{Key: prefix + NetworkKey(ip), Limit: limit, Window: window}}
	if coarseFactor > 0 && limit > 0 {
		if wide := CoarseNetworkKey(ip); wide != "" {
			b = append(b, Budget{Key: prefix + wide, Limit: limit * coarseFactor, Window: window})
		}
	}
	return b
}

// Budget is one named limit.
type Budget struct {
	Key    string
	Limit  int
	Window time.Duration
}

// disabled reports whether the budget is switched off (Limit or Window not
// positive, or no key): Hit skips it and Peek allows it.
func (b Budget) disabled() bool { return b.Limit <= 0 || b.Window <= 0 || b.Key == "" }

// Decision is the result of a check.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	// Bucket is the key of the first exhausted budget, in argument order.
	Bucket string
}

// errMissingCounter reports a counter the upsert did not return.
var errMissingCounter = errors.New("ratelimit: counter missing from the upsert result")

// counter identifies one stored counter row: a digested key and the start of
// its window.
type counter struct {
	bucket string
	start  int64 // window start in Unix microseconds (the column's precision)
}

// hitSQL upserts every counter of one Hit and returns their new values. Rows
// are inserted in (bucket, window_start) order so two concurrent hits that
// share counters lock them in the same order and cannot deadlock.
const hitSQL = `INSERT INTO rate_limit_counters (bucket, window_start, count, expires_at)
	SELECT b.bucket, b.window_start, b.n, b.expires_at
	FROM unnest($1::text[], $2::timestamptz[], $3::int4[], $4::timestamptz[]) AS b(bucket, window_start, n, expires_at)
	ORDER BY b.bucket, b.window_start
	ON CONFLICT (bucket, window_start) DO UPDATE SET count = rate_limit_counters.count + EXCLUDED.count
	RETURNING bucket, window_start, count`

// Hit consumes one unit from every live budget in one statement and denies if
// any is exhausted. Every live budget is consumed, also when one of them is
// exhausted; the decision names the first exhausted budget in argument order
// and the time until its window ends. Disabled budgets are skipped, and a call
// without live budgets does not touch the database. Keys are digested so raw
// identifiers are never stored in counters.
func (l *Limiter) Hit(ctx context.Context, budgets ...Budget) (Decision, error) {
	now := l.d.Now()
	type live struct {
		Budget
		start time.Time
		c     counter
	}
	lives := make([]live, 0, len(budgets))
	// Budgets that share a counter (the same key in windows that start at the
	// same instant) are merged into one row consuming one unit per budget: a
	// single INSERT ... ON CONFLICT cannot update a row twice.
	index := map[counter]int{}
	var (
		buckets []string
		starts  []time.Time
		incs    []int32
		expires []time.Time
	)
	for _, b := range budgets {
		if b.disabled() {
			continue
		}
		start := now.Truncate(b.Window)
		c := counter{bucket: secret.Digest(b.Key)[:40], start: start.UnixMicro()}
		lives = append(lives, live{Budget: b, start: start, c: c})
		if i, ok := index[c]; ok {
			incs[i]++
			if end := start.Add(b.Window); end.After(expires[i]) {
				expires[i] = end
			}
			continue
		}
		index[c] = len(buckets)
		buckets = append(buckets, c.bucket)
		starts = append(starts, start)
		incs = append(incs, 1)
		expires = append(expires, start.Add(b.Window))
	}
	if len(lives) == 0 {
		return Decision{Allowed: true}, nil
	}
	rows, err := l.d.DB.Pool.Query(ctx, hitSQL, buckets, starts, incs, expires)
	if err != nil {
		return Decision{}, err
	}
	counts := make(map[counter]int, len(buckets))
	for rows.Next() {
		var (
			bucket string
			start  time.Time
			count  int
		)
		if err := rows.Scan(&bucket, &start, &count); err != nil {
			rows.Close()
			return Decision{}, err
		}
		counts[counter{bucket: bucket, start: start.UnixMicro()}] = count
	}
	if err := rows.Err(); err != nil {
		return Decision{}, err
	}
	denied := -1
	for i, b := range lives {
		count, ok := counts[b.c]
		if !ok {
			// Every row is inserted or updated, so each one is returned; a
			// missing row means the statement did not do what it says.
			return Decision{}, errMissingCounter
		}
		l.observe(b.Budget, b.start, count)
		if count > b.Limit && denied < 0 {
			denied = i
		}
	}
	if denied >= 0 {
		b := lives[denied]
		return Decision{Allowed: false, RetryAfter: b.start.Add(b.Window).Sub(now), Bucket: b.Key}, nil
	}
	return Decision{Allowed: true}, nil
}

// checkSQL reads the counters of one Check, one row per (bucket, window)
// asked for, 0 for a counter not stored yet.
const checkSQL = `SELECT b.bucket, b.window_start, coalesce(c.count, 0)
	FROM unnest($1::text[], $2::timestamptz[]) AS b(bucket, window_start)
	LEFT JOIN rate_limit_counters c ON c.bucket = b.bucket AND c.window_start = b.window_start`

// Check reports whether every live budget still has a unit left (its count
// below Limit) without consuming any, in one read-only statement. It is the
// check of a failure budget, which the caller charges with Hit only once an
// attempt has failed, so that successful attempts never use it up. The
// decision names the first exhausted budget in argument order and the time
// until its window ends. Disabled budgets are skipped, and a call without
// live budgets does not touch the database. Attempts that run concurrently
// can all pass the check before any of them is charged, so a failure budget
// may be exceeded by the attempts in flight.
func (l *Limiter) Check(ctx context.Context, budgets ...Budget) (Decision, error) {
	now := l.d.Now()
	type live struct {
		Budget
		start time.Time
		c     counter
	}
	lives := make([]live, 0, len(budgets))
	var (
		buckets []string
		starts  []time.Time
	)
	for _, b := range budgets {
		if b.disabled() {
			continue
		}
		start := now.Truncate(b.Window)
		c := counter{bucket: secret.Digest(b.Key)[:40], start: start.UnixMicro()}
		lives = append(lives, live{Budget: b, start: start, c: c})
		buckets = append(buckets, c.bucket)
		starts = append(starts, start)
	}
	if len(lives) == 0 {
		return Decision{Allowed: true}, nil
	}
	rows, err := l.d.DB.Pool.Query(ctx, checkSQL, buckets, starts)
	if err != nil {
		return Decision{}, err
	}
	counts := make(map[counter]int, len(buckets))
	for rows.Next() {
		var (
			bucket string
			start  time.Time
			count  int
		)
		if err := rows.Scan(&bucket, &start, &count); err != nil {
			rows.Close()
			return Decision{}, err
		}
		counts[counter{bucket: bucket, start: start.UnixMicro()}] = count
	}
	if err := rows.Err(); err != nil {
		return Decision{}, err
	}
	for _, b := range lives {
		count := counts[b.c]
		l.observe(b.Budget, b.start, count)
		if count >= b.Limit {
			return Decision{Allowed: false, RetryAfter: b.start.Add(b.Window).Sub(now), Bucket: b.Key}, nil
		}
	}
	return Decision{Allowed: true}, nil
}

// Peek reports whether a budget is not yet exhausted, without consuming it.
// A disabled budget is always allowed, as in Hit.
func (l *Limiter) Peek(ctx context.Context, b Budget) (bool, error) {
	if b.disabled() {
		return true, nil
	}
	now := l.d.Now()
	start := now.Truncate(b.Window)
	var count int
	err := l.d.DB.Pool.QueryRow(ctx, `SELECT coalesce((SELECT count FROM rate_limit_counters WHERE bucket=$1 AND window_start=$2), 0)`,
		secret.Digest(b.Key)[:40], start).Scan(&count)
	return count < b.Limit, err
}

// Cleanup removes expired counters.
func (l *Limiter) Cleanup(ctx context.Context) (int64, error) {
	tag, err := l.d.DB.Pool.Exec(ctx, `DELETE FROM rate_limit_counters WHERE expires_at < $1`, l.d.Now())
	return tag.RowsAffected(), err
}
