package bench

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"time"
)

// emailDelivery measures transactional enqueue through worker SMTP acceptance,
// not just HTTP acceptance of the enqueue request (NFR-003). Test messages go
// to the administrator's own verified address; ordinary send budgets stay on.
type emailDelivery struct{ reference string }

func (*emailDelivery) Name() string { return "email-delivery" }
func (*emailDelivery) Notes() []string {
	return []string{"one operation: POST /notification-tests then poll the exact job until accepted by the SMTP adapter; provider acceptance does not prove inbox delivery",
		"100 ms polling is included in latency and API/database load; one realm and one verified administrator destination; worker tenant shares and send budgets are unchanged"}
}
func (s *emailDelivery) Prepare(ctx context.Context, e *Env) error {
	r, err := e.Client.API(ctx, "POST", "/notification-settings/check", e.adminToken(ctx), map[string]any{})
	if _, err := Must(r, err, 200, "SMTP configuration check"); err != nil {
		return err
	}
	if r.Body["email_adapter"] != "smtp" || r.Body["ok"] != true {
		return fmt.Errorf("email-delivery requires a reachable SMTP adapter, not a development mailbox")
	}
	s.reference, _ = jwtData(e.adminToken(ctx))["sub"].(string)
	if s.reference == "" {
		return fmt.Errorf("email-delivery requires an administrator subject")
	}
	return nil
}

func (s *emailDelivery) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	r, err := e.Client.API(ctx, "POST", "/notification-tests", e.adminToken(ctx), map[string]any{})
	if out := expectedOutcome(r, err, 202); out != "ok" {
		return out
	}
	id := r.Str("job_id")
	if id == "" {
		return "invariant_missing_job_id"
	}
	// A broken worker must produce a recorded failure, rather than letting
	// the run's deadline discard every unfinished operation.
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for wctx.Err() == nil {
		state, out := s.jobState(wctx, e, id)
		if out != "ok" {
			return out
		}
		switch state {
		case "accepted":
			return "ok"
		case "queued", "attempted":
		default:
			return "delivery_" + state
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-wctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return "delivery_timeout"
}

func expectedOutcome(r *Response, err error, want int) string {
	if err != nil || r == nil {
		return "transport_error"
	}
	if r.Status == want {
		return "ok"
	}
	if r.Status < 400 {
		return fmt.Sprintf("invariant_unexpected_http_%d", r.Status)
	}
	return r.Outcome()
}

func (s *emailDelivery) jobState(ctx context.Context, e *Env, id string) (string, string) {
	path := "/notification-jobs?reference_type=notification_test&reference_id=" + url.QueryEscape(s.reference) + "&limit=200"
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		r, err := e.Client.API(ctx, "GET", path, e.adminToken(ctx), nil)
		if out := expectedOutcome(r, err, 200); out != "ok" {
			return "", out
		}
		items, valid := r.Body["items"].([]any)
		if !valid {
			return "", "invariant_invalid_job_page"
		}
		for _, item := range items {
			j := object(item)
			if j["id"] == id {
				state, _ := j["state"].(string)
				if state == "" || j["channel"] != "email" || j["template"] != "configuration_test" ||
					j["reference_type"] != "notification_test" || j["reference_id"] != s.reference {
					return "", "invariant_wrong_job"
				}
				return state, "ok"
			}
		}
		cursor := r.Str("next_cursor")
		if cursor == "" {
			return "", "invariant_job_not_found"
		}
		if seen[cursor] {
			return "", "invariant_repeated_cursor"
		}
		seen[cursor] = true
		path = "/notification-jobs?reference_type=notification_test&reference_id=" + url.QueryEscape(s.reference) + "&limit=200&cursor=" + url.QueryEscape(cursor)
	}
	return "", "invariant_job_page_limit"
}
