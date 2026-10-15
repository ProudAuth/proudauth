package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/webhooks"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestWebhookSubscriptionLifecycle covers EXT-001 (a subscription records its
// destination, event types, organization scope, owner and state, returns its
// signing secret only once, and the secret rotates with an audit record),
// EXT-003 (every attempt is signed over the exact body, timestamp and event
// ID; after a rotation the new and the previous secret both sign until the
// previous one expires) and EXT-004 (a retried delivery keeps its event ID
// for deduplication and carries a fresh timestamp; the previous secret stops
// verifying after the 24-hour rollover).
func TestWebhookSubscriptionLifecycle(t *testing.T) {
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	w := worker.New(h.App, "webhooks")
	if _, err := w.DispatchOutbox(bg()); err != nil {
		t.Fatal(err)
	}
	ep := newEndpoint(t)

	// EXT-001: an organization-scoped subscription with its owner and state.
	created := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "acme membership sync", "organization_id": f.Acme,
		"destination_url": ep.srv.URL + "/acme", "event_types": []string{"organization.membership.added", "organization.membership.removed"},
		"allow_private_network": true, "payload_form": "standard"}), 201, "organization subscription")
	id, secret := created.Str("subscription.id"), created.Str("signing_secret")
	if !strings.HasPrefix(secret, "whsec_") || created.Str("subscription.organization_id") != f.Acme ||
		created.Str("subscription.owner_user_id") != f.Users["admin"] || created.Str("subscription.state") != "active" ||
		created.Str("subscription.destination_url") != ep.srv.URL+"/acme" || len(created.Get("subscription.event_types").([]any)) != 2 {
		t.Fatalf("subscription: %s", created.Raw)
	}
	got := f.must(f.AdminAPI("GET", "/webhooks/"+id, nil), 200, "read subscription")
	if strings.Contains(string(got.Raw), secret) || strings.Contains(string(got.Raw), "whsec_") {
		t.Fatalf("signing secret readable after creation: %s", got.Raw)
	}
	listed := f.must(f.AdminAPI("GET", "/webhooks?organization_id="+f.Globex, nil), 200, "other organization's subscriptions")
	if strings.Contains(string(listed.Raw), id) {
		t.Fatalf("organization subscription listed for another organization: %s", listed.Raw)
	}

	// Membership changes in both organizations: only Acme's reach the
	// organization-scoped subscription.
	carolAcme := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["carol"],
		"role_ids": []string{f.Roles["member"]}}), 201, "add carol to acme").Str("id")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/members", map[string]any{"user_id": f.Users["sam"],
		"role_ids": []string{f.Roles["member"]}}), 201, "add sam to globex")
	deliverWebhooks(t, w)
	calls := ep.received("/acme")
	if len(calls) != 1 {
		t.Fatalf("organization-scoped deliveries: %d", len(calls))
	}
	var env map[string]any
	_ = json.Unmarshal(calls[0].Body, &env)
	if env["org_id"] != f.Acme || env["event_type"] != "organization.membership.added" || env["event_id"] != calls[0].Header.Get("Webhook-Id") {
		t.Fatalf("delivery: %s %v", calls[0].Body, calls[0].Header)
	}
	verify := func(c capturedCall, sec string, now time.Time) error {
		return webhooks.VerifySignature(sec, c.Header.Get("Webhook-Id"), c.Header.Get("Webhook-Timestamp"), c.Header.Get("Webhook-Signature"), c.Body, now, 5*time.Minute)
	}
	if err := verify(calls[0], secret, h.Clock.Now()); err != nil {
		t.Fatalf("signature: %v", err)
	}

	// EXT-001 status: a paused subscription receives nothing.
	f.must(f.AdminAPI("PATCH", "/webhooks/"+id, map[string]any{"state": "paused"}), 200, "pause")
	mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+carolAcme, nil), 204, "remove carol while paused")
	deliverWebhooks(t, w)
	if n := len(ep.received("/acme")); n != 1 {
		t.Fatalf("paused subscription received %d deliveries", n-1)
	}
	f.must(f.AdminAPI("PATCH", "/webhooks/"+id, map[string]any{"state": "active"}), 200, "resume")

	// EXT-001 and EXT-003: rotation. The new secret is returned once and
	// audited; for 24 hours both secrets sign each delivery.
	rot := f.must(f.AdminAPI("POST", "/webhooks/"+id+"/rotate-secret", nil), 200, "rotate secret")
	newSecret := rot.Str("signing_secret")
	if !strings.HasPrefix(newSecret, "whsec_") || newSecret == secret || rot.Get("previous_secret_valid_for_seconds").(float64) != 86400 {
		t.Fatalf("rotation: %s", rot.Raw)
	}
	if n := auditCount(t, h, "webhook.secret_rotated", id); n != 1 {
		t.Fatalf("rotation audit events: %d", n)
	}
	ep.reset()
	carolAcme = f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["carol"],
		"role_ids": []string{f.Roles["member"]}}), 201, "re-add carol").Str("id")
	deliverWebhooks(t, w)
	calls = ep.received("/acme")
	if len(calls) != 1 || len(strings.Fields(calls[0].Header.Get("Webhook-Signature"))) != 2 {
		t.Fatalf("delivery during the rollover: %d calls %v", len(calls), calls)
	}
	for name, sec := range map[string]string{"new": newSecret, "previous": secret} {
		if err := verify(calls[0], sec, h.Clock.Now()); err != nil {
			t.Fatalf("%s secret during the rollover: %v", name, err)
		}
	}

	// EXT-004: a failed attempt is retried with the same event ID (the
	// receiver's deduplication key) and a fresh timestamp and signature.
	ep.reset()
	ep.status(http.StatusServiceUnavailable)
	mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+carolAcme, nil), 204, "remove carol")
	deliverWebhooks(t, w)
	h.Clock.Advance(time.Minute)
	ep.status(http.StatusNoContent)
	if _, err := w.Webhooks.DeliverDue(bg(), w.ID, 100); err != nil {
		t.Fatal(err)
	}
	calls = ep.received("/acme")
	if len(calls) != 2 || calls[0].Status != http.StatusServiceUnavailable || calls[1].Status != http.StatusNoContent {
		t.Fatalf("retry: %d calls", len(calls))
	}
	if calls[0].Header.Get("Webhook-Id") != calls[1].Header.Get("Webhook-Id") || calls[0].Header.Get("Webhook-Timestamp") == calls[1].Header.Get("Webhook-Timestamp") {
		t.Fatalf("retry headers: %v / %v", calls[0].Header, calls[1].Header)
	}
	if err := verify(calls[1], newSecret, h.Clock.Now()); err != nil {
		t.Fatalf("retried delivery signature: %v", err)
	}
	dl := f.must(f.AdminAPI("GET", "/webhooks/"+id+"/deliveries", nil), 200, "deliveries")
	if last := dl.Get("items").([]any)[0].(map[string]any); last["state"] != "delivered" || last["attempts"].(float64) != 2 {
		t.Fatalf("retried delivery state: %v", last)
	}

	// After the rollover window only the new secret signs.
	h.Clock.Advance(24*time.Hour + time.Minute)
	f.ReloginAdmin()
	ep.reset()
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["carol"],
		"role_ids": []string{f.Roles["member"]}}), 201, "re-add carol after the rollover")
	deliverWebhooks(t, w)
	calls = ep.received("/acme")
	if len(calls) != 1 || len(strings.Fields(calls[0].Header.Get("Webhook-Signature"))) != 1 {
		t.Fatalf("delivery after the rollover: %d calls %v", len(calls), calls)
	}
	if err := verify(calls[0], newSecret, h.Clock.Now()); err != nil {
		t.Fatalf("new secret after the rollover: %v", err)
	}
	if verify(calls[0], secret, h.Clock.Now()) == nil {
		t.Fatal("previous secret still verifies after the rollover")
	}
}

// TestPostActionIntegrationsAfterCommit covers EXT-010: a post-action
// integration (a webhook) runs asynchronously from the transactional outbox
// after the change committed. The administrator's request never calls it, a
// destination that times out leaves the committed security state as it is
// and is retried later with the same event, and a refused action publishes
// nothing.
func TestPostActionIntegrationsAfterCommit(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Delivery.AllowPrivateWebhooks = true
		c.Delivery.WebhookTimeout = 300 * time.Millisecond
	})
	f := fixtureOn(t, h)
	w := worker.New(h.App, "post-action")
	if _, err := w.DispatchOutbox(bg()); err != nil {
		t.Fatal(err)
	}
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.setAnswer(func(*http.Request, []byte) (int, http.Header, []byte) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		return http.StatusNoContent, nil, nil
	})
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "slow integration", "destination_url": ep.srv.URL + "/slow",
		"event_types": []string{"organization.membership.removed"}, "allow_private_network": true}), 201, "subscription").Str("subscription.id")
	outboxCount := func(membership string) int {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(bg(), `SELECT count(*) FROM outbox_events WHERE event_type='organization.membership.removed'
			AND payload->'data'->>'membership_id'=$1`, membership).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	membershipState := func() string {
		return f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 200, "membership").Str("membership.state")
	}

	// The removal commits and answers without calling the integration; its
	// event is in the outbox with the change.
	mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "remove bob")
	if n := len(ep.received("")); n != 0 {
		t.Fatalf("the integration was called during the request: %d calls", n)
	}
	if outboxCount(f.MemberAcme["bob"]) != 1 || membershipState() != "removed" {
		t.Fatalf("committed change: outbox %d, state %s", outboxCount(f.MemberAcme["bob"]), membershipState())
	}

	// The integration times out: the delivery is retried later, and the
	// committed removal stands.
	deliverWebhooks(t, w)
	dl := f.must(f.AdminAPI("GET", "/webhooks/"+sub+"/deliveries", nil), 200, "deliveries")
	items := dl.Get("items").([]any)
	if len(items) != 1 {
		t.Fatalf("deliveries: %s", dl.Raw)
	}
	if d := items[0].(map[string]any); d["state"] != "retrying" || d["last_response_category"] != "network_error" {
		t.Fatalf("timed-out delivery: %v", d)
	}
	if membershipState() != "removed" {
		t.Fatal("a timed-out integration changed the committed membership state")
	}
	m := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 200, "membership")
	if as, _ := m.Get("role_assignments").([]any); len(as) != 0 {
		t.Fatalf("removed member's roles came back after the integration failed: %s", m.Raw)
	}

	// Only committed changes publish: repeating the removal changes nothing
	// and publishes nothing, and a refused removal (the last owner) rolls
	// back without an event.
	mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "repeat removal")
	if n := outboxCount(f.MemberAcme["bob"]); n != 1 {
		t.Fatalf("a repeated removal published %d events", n)
	}
	if r := f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["alice"], nil); r.Status < 400 {
		t.Fatalf("removing the last owner: %d %s", r.Status, r.Raw)
	}
	if n := outboxCount(f.MemberAcme["alice"]); n != 0 {
		t.Fatalf("a refused removal published %d events", n)
	}

	// Once the destination answers, the same event is delivered.
	close(release)
	h.Clock.Advance(time.Minute)
	if _, err := w.Webhooks.DeliverDue(bg(), w.ID, 100); err != nil {
		t.Fatal(err)
	}
	dl = f.must(f.AdminAPI("GET", "/webhooks/"+sub+"/deliveries", nil), 200, "deliveries")
	if d := dl.Get("items").([]any)[0].(map[string]any); d["state"] != "delivered" || d["attempts"].(float64) != 2 {
		t.Fatalf("retried delivery: %v", d)
	}
	for _, c := range ep.received("/slow") {
		var env map[string]any
		_ = json.Unmarshal(c.Body, &env)
		if env["event_type"] != "organization.membership.removed" || c.Header.Get("Webhook-Id") != env["event_id"] {
			t.Fatalf("delivered event: %s", c.Body)
		}
	}
}
