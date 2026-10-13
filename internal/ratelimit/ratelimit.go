// Package ratelimit implements layered abuse budgets with concurrency-safe counters
// stored in PostgreSQL so every node observes the same budget (SEC-006, ARC-006).
//
// Budgets are keyed by identifier hints (whether or not an account exists, so a 429
// never reveals account existence), network, client, realm and organization. They
// are time-windowed, so an attacker cannot cause a permanent lockout.
package ratelimit

import (
	"context"
	"time"

	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/runtime"
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

// Decision is the result of a check.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Bucket     string
}

// Hit consumes one unit from every budget and denies if any is exhausted. Keys are
// digested so raw identifiers are never stored in counters.
func (l *Limiter) Hit(ctx context.Context, budgets ...Budget) (Decision, error) {
	now := l.d.Now()
	for _, b := range budgets {
		if b.Limit <= 0 || b.Window <= 0 || b.Key == "" {
			continue
		}
		start := now.Truncate(b.Window)
		bucket := secret.Digest(b.Key)[:40]
		var count int
		err := l.d.DB.Pool.QueryRow(ctx, `INSERT INTO rate_limit_counters (bucket, window_start, count, expires_at)
			VALUES ($1, $2, 1, $3)
			ON CONFLICT (bucket, window_start) DO UPDATE SET count = rate_limit_counters.count + 1
			RETURNING count`, bucket, start, start.Add(b.Window)).Scan(&count)
		if err != nil {
			return Decision{}, err
		}
		if count > b.Limit {
			return Decision{Allowed: false, RetryAfter: start.Add(b.Window).Sub(now), Bucket: b.Key}, nil
		}
	}
	return Decision{Allowed: true}, nil
}

// Peek reports whether a budget is already exhausted without consuming.
func (l *Limiter) Peek(ctx context.Context, b Budget) (bool, error) {
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
