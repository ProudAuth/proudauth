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
// used, so retrying a refused request cannot bypass them.
package ratelimit

import (
	"context"
	"errors"
	"time"

	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
)

// Limiter enforces fixed-window budgets.
type Limiter struct {
	d *runtime.Deps
}

// New returns a limiter.
func New(d *runtime.Deps) *Limiter { return &Limiter{d: d} }

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
	for _, b := range lives {
		count, ok := counts[b.c]
		if !ok {
			// Every row is inserted or updated, so each one is returned; a
			// missing row means the statement did not do what it says.
			return Decision{}, errMissingCounter
		}
		if count > b.Limit {
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
