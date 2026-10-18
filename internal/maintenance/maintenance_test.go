package maintenance

import (
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/platform/problem"
)

// TestRetryAfterClampsZero covers OPS-015 with API-009: a maintenance
// refusal always carries a positive Retry-After. retry_after_seconds 0 (the
// column default, and accepted by Set) is clamped to
// problem.DefaultRetryAfter instead of sending no header; an operator's own
// value is kept.
func TestRetryAfterClampsZero(t *testing.T) {
	for _, tc := range []struct {
		seconds int
		want    time.Duration
	}{
		{0, problem.DefaultRetryAfter},
		{-1, problem.DefaultRetryAfter},
		{1, time.Second},
		{120, 2 * time.Minute},
		{86400, 24 * time.Hour},
	} {
		if got := (State{Mode: Unavailable, RetryAfterSeconds: tc.seconds}).RetryAfter(); got != tc.want {
			t.Errorf("retry_after_seconds %d: Retry-After %v, want %v", tc.seconds, got, tc.want)
		}
	}
}
