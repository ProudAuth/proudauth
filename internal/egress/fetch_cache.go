package egress

import (
	"context"
	"strings"
	"sync"
	"time"
)

// FetchCache shares bounded metadata fetches (NFR-006). A failed response
// consumes the same retry budget as a successful one. Caller cancellation
// stops only that waiter; the shared fetch has its own fixed deadline.
// Values must be immutable after the fetch returns.
type FetchCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*fetchEntry[T]
}

type fetchEntry[T any] struct {
	value   T
	present bool
	fetched time.Time
	retryAt time.Time
	err     error
	done    chan struct{}
}

type FetchOptions[T any] struct {
	TTL, RetryAfter, Timeout time.Duration
	Now                      func() time.Time
	// Usable may request a refresh within TTL, e.g. for an unknown kid.
	// RetryAfter still applies, even when Usable always returns false.
	Usable func(T) bool
	Fetch  func(context.Context) (T, error)
}

// Load returns a cached value or one shared fetch's result. On failure it
// returns the last good value with the error; callers decide explicitly
// whether their protocol permits that fallback. Forgetting an entry never
// lets its returning in-flight fetch overwrite a newer cache generation.
func (c *FetchCache[T]) Load(ctx context.Context, key string, opt FetchOptions[T]) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.RetryAfter <= 0 {
		opt.RetryAfter = time.Minute
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*fetchEntry[T]{}
	}
	e := c.entries[key]
	if e == nil {
		e = &fetchEntry[T]{}
		c.entries[key] = e
	}
	now := opt.Now()
	if e.present && now.Sub(e.fetched) < opt.TTL && (opt.Usable == nil || opt.Usable(e.value)) {
		value := e.value
		c.mu.Unlock()
		return value, nil
	}
	if e.done == nil && now.Before(e.retryAt) {
		value, err := e.value, e.err
		c.mu.Unlock()
		return value, err
	}
	if e.done == nil {
		e.done = make(chan struct{})
		done := e.done
		go func() {
			fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opt.Timeout)
			defer cancel()
			value, err := opt.Fetch(fetchCtx)
			c.mu.Lock()
			if err == nil {
				e.value, e.present, e.fetched = value, true, opt.Now()
			}
			e.err, e.retryAt = err, opt.Now().Add(opt.RetryAfter)
			e.done = nil
			close(done)
			c.mu.Unlock()
		}()
	}
	done := e.done
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-done:
		c.mu.Lock()
		value, err := e.value, e.err
		c.mu.Unlock()
		return value, err
	}
}

func (c *FetchCache[T]) ForgetPrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if strings.HasPrefix(key, prefix) {
			delete(c.entries, key)
		}
	}
}
