package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/webhooks"
	"github.com/proudbase/proudauth/internal/worker"
)

// raceClaims runs workers on the given nodes (several per node, as in
// several worker processes on one database) until none of them claims
// anything more.
func raceClaims(t *testing.T, nodes []*Harness, workers int, claim func(node *Harness, worker string) (int, error)) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int, n *Harness) {
			defer wg.Done()
			for {
				got, err := claim(n, fmt.Sprintf("worker-%d", i))
				if err != nil {
					t.Errorf("worker-%d: %v", i, err)
					return
				}
				if got == 0 {
					return
				}
			}
		}(i, nodes[i%len(nodes)])
	}
	wg.Wait()
}

// TestWebhookDeliveryClaimedOnce covers DEP-011 for webhook delivery:
// workers of two processes on one database race for a burst of due
// deliveries in small batches, and each delivery is claimed by exactly one
// worker and sent exactly once. A delivery another worker claimed (or
// already delivered) after a claim statement's snapshot is skipped, not
// claimed and sent a second time.
func TestWebhookDeliveryClaimedOnce(t *testing.T) {
	f := newOpsFixture(t)
	h := f.H
	ctx := context.Background()
	var mu sync.Mutex
	sent := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		sent[r.Header.Get("Webhook-Id")]++
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer srv.Close()
	f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "burst", "destination_url": srv.URL + "/hooks",
		"event_types": []string{"session.revoked"}, "allow_private_network": true}), 201, "webhook")

	const burst = 90
	fan := webhooks.NewService(h.App.D)
	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		for i := 0; i < burst; i++ {
			id := fmt.Sprintf("evt_burst_%03d", i)
			env := []byte(`{"event_id":"` + id + `","event_type":"session.revoked","data":{}}`)
			if n, err := fan.FanOut(ctx, tx, h.Realm.ID, "", id, "session.revoked", env); err != nil || n != 1 {
				return fmt.Errorf("fan out %s: %d %v", id, n, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h.Clock.Advance(time.Second)

	nodes := []*Harness{h, replica(t, h, h.App.D.DB, h.App.D.Keys)}
	services := map[*Harness]*webhooks.Service{}
	for _, n := range nodes {
		services[n] = webhooks.NewService(n.App.D)
	}
	raceClaims(t, nodes, 8, func(n *Harness, worker string) (int, error) {
		return services[n].DeliverDue(ctx, worker, 2)
	})

	mu.Lock()
	defer mu.Unlock()
	var twice []string
	for id, c := range sent {
		if c != 1 {
			twice = append(twice, fmt.Sprintf("%s×%d", id, c))
		}
	}
	var delivered, reclaimed int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='delivered'), count(*) FILTER (WHERE attempts <> 1)
		FROM webhook_deliveries WHERE event_id LIKE 'evt_burst_%'`).Scan(&delivered, &reclaimed)
	if len(sent) != burst || len(twice) != 0 || delivered != burst || reclaimed != 0 {
		t.Fatalf("burst of %d: %d events received, sent more than once: %v; %d deliveries delivered, %d claimed more than once",
			burst, len(sent), twice, delivered, reclaimed)
	}
}

// TestOutboundDeliveryClaimedOnce covers DEP-011 for outbound SCIM
// provisioning: workers of two processes race for a burst of due outbound
// deliveries, and each is claimed by exactly one worker, so the downstream
// service receives exactly one write per account.
func TestOutboundDeliveryClaimedOnce(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	down := newFakeSCIM(t, "downstream token")
	connID := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/directory-connectors", map[string]any{"name": "Downstream", "kind": "scim_outbound",
		"credential": "downstream token", "config": map[string]any{"base_url": down.srv.URL, "allow_private_network": true}}), 201, "outbound connector").Str("id")

	const burst = 40
	for i := 0; i < burst; i++ {
		name := fmt.Sprintf("burst%02d", i)
		uid := f.must(f.AdminAPI("POST", "/users", map[string]any{"email": name + "@example.test", "username": name, "display_name": name}), 201,
			"create "+name).Str("user.id")
		f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": uid, "role_ids": []string{}}), 201, "member "+name)
	}
	// The outbox fans the membership events out into one delivery per
	// account (members of the fixture included).
	w := h.App
	disp := worker.New(h.App, "dispatch")
	for {
		n, err := disp.DispatchOutbox(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	var due int
	_ = w.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries WHERE connector_id=$1 AND resource_type='User' AND state='pending'`,
		connID).Scan(&due)
	if due < burst {
		t.Fatalf("%d outbound deliveries queued for a burst of %d", due, burst)
	}
	h.Clock.Advance(time.Second)

	nodes := []*Harness{h, replica(t, h, h.App.D.DB, h.App.D.Keys)}
	raceClaims(t, nodes, 8, func(n *Harness, worker string) (int, error) {
		return n.App.Directory.DeliverDue(ctx, worker, 2)
	})

	writes := map[string]int{}
	for _, r := range down.reqs() {
		if !strings.HasPrefix(r, "GET ") {
			writes[r]++
		}
	}
	down.mu.Lock()
	created := len(down.users)
	down.mu.Unlock()
	var delivered, reclaimed int
	_ = w.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='delivered'), count(*) FILTER (WHERE attempts <> 1)
		FROM outbound_deliveries WHERE connector_id=$1 AND resource_type='User'`, connID).Scan(&delivered, &reclaimed)
	if writes["POST /Users"] != due || len(writes) != 1 || created != due || delivered != due || reclaimed != 0 {
		t.Fatalf("%d deliveries: downstream writes %v, %d accounts created; %d delivered, %d claimed more than once",
			due, writes, created, delivered, reclaimed)
	}
}

// TestWorkflowRunClaimRechecksState covers DEP-011 for lifecycle workflow
// runs: a run that another worker advanced and parked for later after a
// claim statement read it as due is not claimed again, so its next step
// (an endpoint call) does not run early or twice. The claim waits on the
// other worker's row lock, so the interleaving is deterministic.
func TestWorkflowRunClaimRechecksState(t *testing.T) {
	e := newWorkflowEnv(t)
	h := e.H
	e.createWorkflow(t, "notify on join", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "event", "event_types": []string{"organization.membership.added"}}},
		"steps":    []any{map[string]any{"id": "sync", "type": "call_webhook", "subscription_id": e.subID}}})
	e.ep.status(204)
	e.CreateUser("joiner")
	e.addMember(t, e.Acme, "joiner")
	if _, err := e.w.DispatchOutbox(e.ctx); err != nil {
		t.Fatal(err)
	}
	var runID string
	if err := h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT id FROM workflow_runs WHERE realm_id=$1 AND next_run_at <= $2 AND lease_owner IS NULL`,
		h.Realm.ID, h.Clock.Now()).Scan(&runID); err != nil {
		t.Fatalf("due run: %v", err)
	}

	// Another worker holds the run: it ends up parked an hour from now
	// without a lease (as after a retryable failure).
	other, err := h.App.D.DB.Pool.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(e.ctx) }()
	if _, err := other.Exec(e.ctx, `UPDATE workflow_runs SET state='running', next_run_at=$2, lease_owner=NULL, lease_expires_at=NULL WHERE id=$1`,
		runID, h.Clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := h.App.Workflows.RunDue(e.ctx, "late-worker", 10, time.Minute, 0)
		done <- result{n, err}
	}()
	// The late claim has read the run as due and waits for the row.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		_ = h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'
			AND query LIKE '%UPDATE workflow_runs SET lease_owner%'`).Scan(&waiting)
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late claim never waited for the run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := other.Commit(e.ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	var owner *string
	_ = h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT lease_owner FROM workflow_runs WHERE id=$1`, runID).Scan(&owner)
	if r.err != nil || r.n != 0 || owner != nil || len(e.ep.received("/steps")) != 0 {
		t.Fatalf("a run parked for later was claimed again: claimed %d (%v), lease owner %v, endpoint calls %d", r.n, r.err, owner,
			len(e.ep.received("/steps")))
	}
}
