// Package clock provides an injectable UTC time source. All security expiry
// decisions use UTC instants (OPS-011, NFR-010).
package clock

import (
	"sync"
	"time"
)

// Clock returns the current instant.
type Clock interface {
	Now() time.Time
}

// System is the real wall clock, always in UTC.
type System struct{}

// Now returns the current UTC time truncated to microseconds (PostgreSQL precision).
func (System) Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// Fake is a controllable clock for tests.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a fake clock set to t.
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC().Truncate(time.Microsecond)} }

// Now returns the fake current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

// Set sets the fake clock.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	f.now = t.UTC().Truncate(time.Microsecond)
	f.mu.Unlock()
}
