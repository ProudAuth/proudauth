// Package slots bounds how many callers run a costly operation at once
// (NFR-002). A full pool refuses at once instead of queueing, so a burst or a
// stalled dependency answers a retryable error quickly rather than holding a
// request, and the database transaction slot it may hold, while it waits.
package slots

// Pool is a fail-fast counting semaphore. A nil Pool is unbounded.
type Pool struct{ ch chan struct{} }

// New returns a pool of n slots; n < 1 returns nil (unbounded).
func New(n int) *Pool {
	if n < 1 {
		return nil
	}
	return &Pool{ch: make(chan struct{}, n)}
}

// TryAcquire takes a slot without waiting. ok is false when every slot is in
// use; otherwise release must be called exactly once to return the slot.
func (p *Pool) TryAcquire() (release func(), ok bool) {
	if p == nil {
		return func() {}, true
	}
	select {
	case p.ch <- struct{}{}:
		return func() { <-p.ch }, true
	default:
		return nil, false
	}
}

// Size is the number of slots (0 when unbounded).
func (p *Pool) Size() int {
	if p == nil {
		return 0
	}
	return cap(p.ch)
}
