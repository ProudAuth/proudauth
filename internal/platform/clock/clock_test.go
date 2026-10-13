package clock

import (
	"testing"
	"time"
)

// TestClocksAreUTC covers OPS-011: whatever the host's local time zone, the
// service clock and the test clock hand out UTC instants at database
// (microsecond) precision, so expiry and audit times agree across nodes.
func TestClocksAreUTC(t *testing.T) {
	local := time.Local
	time.Local = time.FixedZone("UTC+05:30", 5*3600+1800)
	defer func() { time.Local = local }()

	now := System{}.Now()
	if now.Location() != time.UTC || now.Nanosecond()%1000 != 0 {
		t.Fatalf("system clock: %v (%v)", now, now.Location())
	}
	if d := time.Since(now); d < 0 || d > time.Minute {
		t.Fatalf("system clock is not the current instant: %v", d)
	}
	start := time.Date(2026, 10, 11, 12, 0, 0, 123456789, time.Local)
	f := NewFake(start)
	if got := f.Now(); got.Location() != time.UTC || !got.Equal(start.Truncate(time.Microsecond)) {
		t.Fatalf("fake clock: %v", got)
	}
	f.Advance(time.Hour)
	if got := f.Now(); got.Location() != time.UTC || !got.Equal(start.Truncate(time.Microsecond).Add(time.Hour)) {
		t.Fatalf("advanced fake clock: %v", got)
	}
	f.Set(start)
	if got := f.Now(); got.Location() != time.UTC || !got.Equal(start.Truncate(time.Microsecond)) {
		t.Fatalf("set fake clock: %v", got)
	}
}
