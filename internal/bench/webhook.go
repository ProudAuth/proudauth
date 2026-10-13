package bench

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"strings"
	"time"
)

const memberAdded = "organization.membership.added"
const memberRemoved = "organization.membership.removed"

// webhookDelivery measures two committed membership changes, signed callbacks
// and the worker's delivered state. Retry mode refuses each first attempt with
// 503, then checks the same event/body with a fresh timestamp (NFR-003, NFR-005).
type webhookDelivery struct {
	retry   bool
	workers []*webhookWorker
	origin  string
	probeS  float64
}

func (s *webhookDelivery) Name() string {
	if s.retry {
		return "webhook-retry"
	}
	return "webhook-delivery"
}
func (s *webhookDelivery) Notes() []string {
	notes := []string{fmt.Sprintf("%d additional isolated users, organizations and scoped version-2 minimal subscriptions; callback receiver %s; private signing keys only in memory", len(s.workers), s.origin),
		"one operation: clear an interrupted live membership, add/remove the worker's synthetic member, verify both request-correlated HMAC callbacks and poll both exact deliveries until delivered; 100 ms polling included; at-least-once delivery, no inbox/remote/TLS capacity claim"}
	notes = append(notes, fmt.Sprintf("unmeasured public-API readiness cycle took %.3f s (15 min preparation deadline) to cross any seed outbox backlog before warm-up; measured operations retain their 30 s timeout", s.probeS))
	if s.retry {
		notes = append(notes, "receiver returns 503 for each event's first valid attempt, then 204; require identical event ID/body, a fresh timestamp and exactly two delivered attempts under unmodified retry backoff")
	}
	return notes
}

func (s *webhookDelivery) Prepare(ctx context.Context, e *Env) error {
	s.workers = nil
	if e.Concurrency < 1 || e.Seed.RoleID == "" {
		return fmt.Errorf("webhook workloads require a fresh seed and configured concurrency")
	}
	prefix, err := runPrefix(e.Seed, "webhook")
	if err != nil {
		return err
	}
	// Organization slugs accept hyphens, not base64url underscores.
	prefix = strings.ReplaceAll(prefix, "_", "-")
	h, err := e.getWebhookHub()
	if err != nil {
		return err
	}
	s.origin = h.origin
	users := make([]map[string]any, e.Concurrency)
	for i := range users {
		users[i] = map[string]any{"source_id": fmt.Sprint(i), "email": fmt.Sprintf("%s-%d@bench.test", prefix, i), "email_verified": true}
	}
	for start := 0; start < len(users); start += 500 {
		job, err := e.Client.API(ctx, "POST", "/user-imports", e.adminToken(ctx), map[string]any{"source_system": prefix, "users": users[start:min(start+500, len(users))], "trust_email_verification": true, "verification_reason": "synthetic webhook benchmark users"})
		if _, err := Must(job, err, 202, "webhook fixture import"); err != nil {
			return err
		}
		if err := waitJob(ctx, e.Client, e.Admin, job.Str("job_id")); err != nil {
			return err
		}
	}
	for i := range users {
		user, err := webhookFixtureUser(ctx, e, users[i]["email"].(string))
		if err != nil {
			return err
		}
		org, err := e.Client.API(ctx, "POST", "/organizations", e.adminToken(ctx), map[string]any{"slug": fmt.Sprintf("%s-%d", prefix, i), "display_name": "Webhook benchmark"})
		if _, err := Must(org, err, 201, "webhook fixture organization"); err != nil {
			return err
		}
		w := &webhookWorker{ready: make(chan struct{}), realm: org.Str("realm_id"), org: org.Str("id"), user: user, retry: s.retry, pending: map[string]*webhookCycle{}}
		if w.realm == "" || w.org == "" {
			return fmt.Errorf("webhook fixture organization lacks identity")
		}
		w.destination = h.add(fmt.Sprintf("/%s/%d", prefix, i), w)
		s.workers = append(s.workers, w)
		r, err := e.Client.API(ctx, "POST", "/webhooks", e.adminToken(ctx), map[string]any{"name": s.Name(), "organization_id": w.org, "destination_url": w.destination,
			"event_types": []string{memberAdded, memberRemoved}, "allow_private_network": e.WebhookPrivate || e.WebhookURL == "", "payload_form": "minimal", "event_version": 2})
		if out := expectedOutcome(r, err, 201); out != "ok" {
			return fmt.Errorf("webhook fixture subscription: %s (configure the operator egress policy for the receiver)", out)
		}
		w.subscription = stringValue(object(r.Body["subscription"]), "id")
		secret := r.Str("signing_secret")
		key, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(secret, "whsec_"), "="))
		if err != nil || len(key) != 32 || !strings.HasPrefix(secret, "whsec_") || w.subscription == "" {
			return fmt.Errorf("webhook fixture subscription lacks identity or signing key")
		}
		w.mu.Lock()
		w.secret = key
		close(w.ready)
		w.mu.Unlock()
	}
	// Full-cardinality seeding can enqueue events faster than a default worker
	// dispatches them. Prove a fresh cycle through that queue before timing;
	// raising worker budgets would change the deployment being measured.
	started := time.Now()
	out := s.op(ctx, e, 0, 15*time.Minute)
	s.probeS = time.Since(started).Seconds()
	if out != "ok" {
		return fmt.Errorf("webhook readiness cycle: %s", out)
	}
	return nil
}

func webhookFixtureUser(ctx context.Context, e *Env, email string) (string, error) {
	// Administrative search is exact, not a prefix search. Its view carries
	// identifiers, not a top-level email; check that the found account owns it.
	r, err := e.Client.API(ctx, "GET", "/users?q="+url.QueryEscape(email)+"&limit=2", e.adminToken(ctx), nil)
	if _, err := Must(r, err, 200, "webhook fixture lookup"); err != nil {
		return "", err
	}
	items, _ := r.Body["items"].([]any)
	if len(items) != 1 {
		return "", fmt.Errorf("webhook fixture exact search did not find one user")
	}
	u := object(items[0])
	identifiers, _ := u["identifiers"].([]any)
	for _, identifier := range identifiers {
		v := object(identifier)
		if v["type"] == "email" && v["value"] == email && stringValue(u, "id") != "" {
			return stringValue(u, "id"), nil
		}
	}
	return "", fmt.Errorf("webhook fixture lookup did not return the expected identifier")
}

func (s *webhookDelivery) Op(ctx context.Context, e *Env, worker int, _ *mrand.Rand) string {
	return s.op(ctx, e, worker, 30*time.Second)
}

func (s *webhookDelivery) op(ctx context.Context, e *Env, worker int, timeout time.Duration) string {
	if worker < 0 || worker >= len(s.workers) {
		return "setup_missing_webhook_worker"
	}
	w := s.workers[worker]
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	base := "/organizations/" + w.org + "/members"
	// Reconcile an add/delete whose response was interrupted by warm-up or
	// a soak boundary. Removed history is excluded and cannot grow this page.
	r, err := e.Client.API(ctx, "GET", base+"?state=active&limit=200", e.adminToken(ctx), nil)
	if out := expectedOutcome(r, err, 200); out != "ok" {
		return out
	}
	items, ok := r.Body["items"].([]any)
	if !ok || r.Str("next_cursor") != "" {
		return "invariant_member_page"
	}
	for _, item := range items {
		m := object(item)
		if m["user_id"] == w.user {
			r, err = e.Client.API(ctx, "DELETE", base+"/"+stringValue(m, "id"), e.adminToken(ctx), nil)
			if out := expectedOutcome(r, err, 204); out != "ok" {
				return out
			}
		}
	}
	cid, err := runPrefix(e.Seed, "cycle")
	if err != nil {
		return "setup_randomness_failed"
	}
	cycle := &webhookCycle{events: map[string]*webhookReceipt{}}
	w.mu.Lock()
	w.pending[cid] = cycle
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.pending, cid); w.mu.Unlock() }()
	call := func(method, path string, body any) (*Response, error) {
		return e.Client.Do(ctx, Request{Method: method, Path: "/api/v1/realms/" + e.Client.Realm + path, Token: e.adminToken(ctx), JSON: body, Headers: map[string]string{"X-Request-Id": cid}})
	}
	r, err = call("POST", base, map[string]any{"user_id": w.user, "role_ids": []string{e.Seed.RoleID}})
	if out := expectedOutcome(r, err, 201); out != "ok" {
		return out
	}
	mid := r.Str("id")
	if mid == "" || r.Str("user_id") != w.user || r.Str("organization_id") != w.org || r.Str("state") != "active" {
		return "invariant_added_member"
	}
	r, err = call("DELETE", base+"/"+mid, nil)
	if out := expectedOutcome(r, err, 204); out != "ok" {
		return out
	}
	for ctx.Err() == nil {
		w.mu.Lock()
		bad := cycle.bad
		var receipts []webhookReceipt
		for _, typ := range []string{memberAdded, memberRemoved} {
			if receipt := cycle.events[typ]; receipt != nil && receipt.accepted {
				receipts = append(receipts, *receipt)
			}
		}
		invalid := w.stats.Invalid
		w.mu.Unlock()
		if bad != "" {
			return bad
		}
		if invalid > 0 {
			return "invariant_receiver_invalid"
		}
		if len(receipts) == 2 {
			attempts := 1
			if s.retry {
				attempts = 2
			}
			if receipts[0].id == receipts[1].id || receipts[0].member != mid || receipts[1].member != mid || receipts[0].attempts != attempts || receipts[1].attempts != attempts {
				return "invariant_callback_identity"
			}
			if out := s.deliveryStates(ctx, e, w, receipts); out != "pending" {
				return out
			}
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return "delivery_timeout"
}

func (s *webhookDelivery) deliveryStates(ctx context.Context, e *Env, w *webhookWorker, receipts []webhookReceipt) string {
	wanted := map[string]bool{}
	for _, r := range receipts {
		wanted[r.id] = false
	}
	path := "/webhooks/" + w.subscription + "/deliveries?limit=200"
	for page := 0; page < 100; page++ {
		r, err := e.Client.API(ctx, "GET", path, e.adminToken(ctx), nil)
		if out := expectedOutcome(r, err, 200); out != "ok" {
			return out
		}
		items, valid := r.Body["items"].([]any)
		if !valid {
			return "invariant_delivery_page"
		}
		for _, item := range items {
			d := object(item)
			id := stringValue(d, "event_id")
			if _, ok := wanted[id]; !ok {
				continue
			}
			if d["state"] == "pending" || d["state"] == "retrying" {
				return "pending"
			}
			attempts := float64(1)
			if s.retry {
				attempts = 2
			}
			typ := memberAdded
			if id == receipts[1].id {
				typ = memberRemoved
			}
			if d["event_type"] != typ || d["state"] != "delivered" || d["attempts"] != attempts || d["last_status_code"] != float64(204) || stringValue(d, "id") == "" || stringValue(d, "delivered_at") == "" {
				return "invariant_delivery_state"
			}
			wanted[id] = true
		}
		if wanted[receipts[0].id] && wanted[receipts[1].id] {
			return "ok"
		}
		cursor := r.Str("next_cursor")
		if cursor == "" {
			return "pending"
		}
		path = "/webhooks/" + w.subscription + "/deliveries?limit=200&cursor=" + url.QueryEscape(cursor)
	}
	return "invariant_delivery_page_limit"
}

func (s *webhookDelivery) Observations() map[string]any {
	stats := webhookStats{}
	active := 0
	for _, w := range s.workers {
		w.mu.Lock()
		a := w.stats
		active += len(w.pending)
		w.mu.Unlock()
		stats.Received += a.Received
		stats.Accepted += a.Accepted
		stats.Intentional503 += a.Intentional503
		stats.Recovered += a.Recovered
		stats.Invalid += a.Invalid
		stats.Ignored += a.Ignored
		if !a.FirstRetryAt.IsZero() && (stats.FirstRetryAt.IsZero() || a.FirstRetryAt.Before(stats.FirstRetryAt)) {
			stats.FirstRetryAt = a.FirstRetryAt
		}
		if a.LastRetryAt.After(stats.LastRetryAt) {
			stats.LastRetryAt = a.LastRetryAt
		}
		if a.LastRecoveryAt.After(stats.LastRecoveryAt) {
			stats.LastRecoveryAt = a.LastRecoveryAt
		}
	}
	return map[string]any{"receiver": s.origin, "subscriptions": len(s.workers), "active_cycles": active, "readiness_cycle_s": s.probeS, "cumulative": stats, "scope": "counts include preparation/warm-up and boundary-interrupted cycles; subtract before from after for a measurement/window"}
}
func (s *webhookDelivery) Close(ctx context.Context, e *Env) error {
	h := e.webhookHub
	if h == nil {
		return nil
	}
	var errs []error
	for _, w := range s.workers {
		if w.subscription != "" {
			r, err := e.Client.API(ctx, "DELETE", "/webhooks/"+w.subscription, e.adminToken(ctx), nil)
			if out := expectedOutcome(r, err, 204); out != "ok" {
				errs = append(errs, fmt.Errorf("benchmark subscription cleanup: %s", out))
			}
			w.subscription = ""
		}
		h.remove(w.destination)
		w.mu.Lock()
		clear(w.secret)
		w.mu.Unlock()
	}
	errs = append(errs, h.closeIfEmpty(e))
	return errors.Join(errs...)
}
