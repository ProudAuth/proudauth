package e2e

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth-sdk-go/verifier"
	"github.com/proudauth/proudauth/internal/events"
)

// TestSessionEventStream covers SES-019: an authenticated, gap-free change
// stream with catch-up from a cursor.
func TestSessionEventStream(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	head := h.API("GET", "/session-events?from=now", svc, nil)
	mustStatus(t, head, 200, "head")
	cursor := head.Str("next_cursor")

	f.must(f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "test"}), 200, "suspend")
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "remove member")
	page := h.API("GET", "/session-events?cursor="+cursor, svc, nil)
	mustStatus(t, page, 200, "read")
	body := string(page.Raw)
	if !strings.Contains(body, `"user.suspended"`) || !strings.Contains(body, `"organization.membership.removed"`) {
		t.Fatalf("expected change events: %s", body)
	}
	if strings.Contains(body, "@example.test") {
		t.Fatal("stream leaks contact data")
	}
	next := page.Str("next_cursor")
	if again := h.API("GET", "/session-events?cursor="+next, svc, nil); len(again.Get("events").([]any)) != 0 {
		t.Fatalf("events repeated after cursor: %s", again.Raw)
	}
	// Ordinary users cannot read the stream.
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	if r := h.API("GET", "/session-events", alice, nil); r.Status != 401 && r.Status != 403 {
		t.Fatalf("account token read the stream: %d", r.Status)
	}
	// Gap-freedom: an event whose transaction is still open is not delivered,
	// and a later-committing event is never skipped by a cursor that advanced.
	ctx := context.Background()
	tx, err := h.App.D.DB.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.D.Outbox.Publish(ctx, tx, events.Event{EventType: "session.revoked", RealmID: h.Realm.ID, Data: map[string]any{"session_id": "ses_slow"}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// A transaction that starts later and commits first.
		_ = h.App.D.DB.Tx(ctx, func(t2 pgx.Tx) error {
			_, err := h.App.D.Outbox.Publish(ctx, t2, events.Event{EventType: "session.revoked", RealmID: h.Realm.ID, Data: map[string]any{"session_id": "ses_fast"}})
			return err
		})
	}()
	wg.Wait()
	mid := h.API("GET", "/session-events?cursor="+next, svc, nil)
	if strings.Contains(string(mid.Raw), "ses_slow") || strings.Contains(string(mid.Raw), "ses_fast") {
		t.Fatalf("events past an open transaction delivered early: %s", mid.Raw)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after := h.API("GET", "/session-events?cursor="+mid.Str("next_cursor"), svc, nil)
	if !strings.Contains(string(after.Raw), "ses_slow") || !strings.Contains(string(after.Raw), "ses_fast") {
		t.Fatalf("an event was skipped: %s", after.Raw)
	}
}

// TestBoundedStateVerification covers SDK-002: the bounded-state mode verifies
// tokens locally, rejects tokens whose session or subject was revoked once the
// change is replayed from the stream, and fails closed (never downgrades to
// offline acceptance) when its state is older than the bound.
func TestBoundedStateVerification(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	state := &verifier.BoundedState{BaseURL: h.Base, Realm: "main", MaxStaleness: time.Minute, Now: h.Clock.Now,
		Token: func(context.Context) (string, error) { return svc, nil }}
	if err := state.Start(ctx); err != nil {
		t.Fatal(err)
	}
	bv := &verifier.BoundedVerifier{Verifier: f.verifier(t, f.OrdersAud), State: state}
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	if _, err := bv.Authenticate(ctx, bob); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	f.must(f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/revoke-sessions", map[string]any{}), 200, "revoke bob")
	if err := state.Sync(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := bv.Authenticate(ctx, bob); !errors.Is(err, verifier.ErrRevoked) {
		t.Fatalf("revoked session accepted: %v", err)
	}
	if _, err := bv.Authenticate(ctx, alice); err != nil {
		t.Fatalf("unaffected token rejected: %v", err)
	}
	h.Clock.Advance(2 * time.Minute)
	if _, err := bv.Authenticate(ctx, alice); !errors.Is(err, verifier.ErrStateStale) {
		t.Fatalf("stale state must fail closed, got %v", err)
	}
}

// TestStreamOutlivingAuthorization covers TEST-062: a long-polling consumer
// is disconnected once its permission is revoked, not at the end of its wait.
// Requirements: INT-005 (an authorized handshake is not permanent access: the
// open stream is re-authorized while it waits).
func TestStreamOutlivingAuthorization(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "stream-reader",
		"permissions": []string{"realm.session_events.read"}}), 201, "role").Str("id")
	asg := f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}),
		201, "assign").Str("id")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	head := f.must(h.API("GET", "/session-events?from=now", carol, nil), 200, "head")
	done := make(chan *Resp, 1)
	start := time.Now()
	go func() { done <- h.API("GET", "/session-events?wait=20&cursor="+head.Str("next_cursor"), carol, nil) }()
	time.Sleep(500 * time.Millisecond)
	mustStatus(t, f.AdminAPI("DELETE", "/role-assignments/"+asg, nil), 204, "revoke")
	select {
	case r := <-done:
		if r.Status != 403 || time.Since(start) > 10*time.Second {
			t.Fatalf("stream after revocation: %d after %s", r.Status, time.Since(start))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("stream kept waiting after its permission was revoked")
	}
}

// TestStreamCursorAfterPruning covers SES-019 retention: a consumer that was
// caught up keeps its cursor when its last event ages out on a quiet realm;
// a cursor before pruned events expires.
func TestStreamCursorAfterPruning(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	publish := func(sid string) {
		t.Helper()
		if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			_, err := h.App.D.Outbox.Publish(ctx, tx, events.Event{EventType: "session.revoked", RealmID: h.Realm.ID, Data: map[string]any{"session_id": sid}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := events.Head(ctx, h.App.D.DB.Pool, h.Realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	publish("ses_old")
	// An event without a realm ages out too; it has no stream horizon and
	// must not make pruning fail.
	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := h.App.D.Outbox.Publish(ctx, tx, events.Event{EventType: "session.revoked", Data: map[string]any{"session_id": "ses_platform"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	evs, caughtUp, err := events.Read(ctx, h.App.D.DB.Pool, h.Realm.ID, before, 500)
	if err != nil || len(evs) == 0 {
		t.Fatalf("read: %v %d", err, len(evs))
	}
	// Everything so far is dispatched and ages out.
	aged, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE outbox_events SET state='dispatched', dispatched_at=now() - interval '30 days'`)
	if err != nil {
		t.Fatal(err)
	}
	// The count is of pruned events, not of horizon rows written.
	if n, err := events.PruneDispatched(ctx, h.App.D.DB.Pool, time.Now().Add(-7*24*time.Hour)); err != nil || n != aged.RowsAffected() {
		t.Fatalf("pruned %d of %d: %v", n, aged.RowsAffected(), err)
	}
	publish("ses_new")
	evs, _, err = events.Read(ctx, h.App.D.DB.Pool, h.Realm.ID, caughtUp, 500)
	if err != nil || len(evs) != 1 || evs[0].Data["session_id"] != "ses_new" {
		t.Fatalf("caught-up cursor after pruning: %v %v", err, evs)
	}
	if _, _, err := events.Read(ctx, h.App.D.DB.Pool, h.Realm.ID, before, 500); !errors.Is(err, events.ErrCursorExpired) {
		t.Fatalf("cursor before pruned events: %v", err)
	}
}
