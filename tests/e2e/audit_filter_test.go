package e2e

import (
	"context"
	"maps"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
)

// TestAuditTypePrefixIsLiteral covers AUD-011: a prefix is literal even
// when it includes SQL LIKE metacharacters, including real event underscores.
func TestAuditTypePrefixIsLiteral(t *testing.T) {
	f := NewFixture(t)
	types := []string{"app.audit_test.one", "app.audit_test.two", "app.auditXtest.one", "app.audit%test.one", `app.audit\test.one`, "app.auditZtest.one"}
	for _, typ := range types {
		if _, err := f.H.App.D.Audit.Record(context.Background(), f.H.App.D.DB.Pool, audit.Event{RealmID: f.H.Realm.ID, Type: typ}); err != nil {
			t.Fatal(err)
		}
	}
	for _, prefix := range []string{"app.audit_test.", "app.audit%test.", `app.audit\test.`, "app.audit", "app.absent_"} {
		t.Run(prefix, func(t *testing.T) {
			want := map[string]bool{}
			for _, typ := range types {
				if strings.HasPrefix(typ, prefix) {
					want[typ] = true
				}
			}
			r := f.must(f.AdminAPI("GET", "/audit-events?type_prefix="+url.QueryEscape(prefix), nil), 200, "literal prefix")
			items := r.Get("items").([]any)
			if len(items) != len(want) {
				t.Errorf("prefix %q returned %d events, want %d", prefix, len(items), len(want))
			}
			for _, item := range items {
				if typ := item.(map[string]any)["type"].(string); !want[typ] {
					t.Errorf("prefix %q matched foreign type %q", prefix, typ)
				}
			}
		})
	}
}

// TestAuditCompoundFiltersAndCursors covers AUD-006, AUD-011 and API-004:
// conjunctions retain exact realm/organization results and sequence pages;
// a cursor cannot silently skip evidence under a different route/filter set.
func TestAuditCompoundFiltersAndCursors(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	at := h.Clock.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	base := audit.Event{RealmID: h.Realm.ID, OrgID: f.Acme, Type: "app.audit_test.match", Actor: audit.Ref{Type: "user", ID: f.Users["bob"], SessionID: "audit-actor-session"},
		Subject: &audit.Ref{Type: "user", ID: f.Users["alice"]}, Target: &audit.Ref{Type: "organization", ID: f.Acme},
		ClientID: "audit-client", RequestID: "audit-request", GrantID: "audit-grant", SessionID: "audit-event-session", Category: "application",
		Outcome: audit.Success, IPContext: "203.0.113.0/24", OccurredAt: at}
	record := func(ev audit.Event) string {
		t.Helper()
		id, err := h.App.D.Audit.Record(ctx, h.App.D.DB.Pool, ev)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	want := map[string]bool{}
	for range 9 {
		want[record(base)] = true
	}
	decoys := []func(*audit.Event){
		func(e *audit.Event) { e.RealmID = "realm-foreign-fixture" },
		func(e *audit.Event) { e.OrgID = f.Globex },
		func(e *audit.Event) { e.Type = "app.audit_test.other" },
		func(e *audit.Event) { e.Actor.ID = f.Users["carol"] },
		func(e *audit.Event) { e.Subject = &audit.Ref{Type: "user", ID: f.Users["bob"]} },
		func(e *audit.Event) { e.Target = &audit.Ref{Type: "organization", ID: f.Globex} },
		func(e *audit.Event) { e.ClientID = "other-client" },
		func(e *audit.Event) { e.RequestID = "other-request" },
		func(e *audit.Event) { e.GrantID = "other-grant" },
		func(e *audit.Event) { e.SessionID, e.Actor.SessionID = "other-session", "other-session" },
		func(e *audit.Event) { e.Category = "security" },
		func(e *audit.Event) { e.Outcome = audit.Denied },
		func(e *audit.Event) { e.IPContext = "198.51.100.0/24" },
		func(e *audit.Event) { e.OccurredAt = at.Add(-time.Second) },
		func(e *audit.Event) { e.OccurredAt = at.Add(time.Second) },
	}
	for _, mutate := range decoys {
		e := base
		mutate(&e)
		record(e)
	}
	q := url.Values{"limit": {"3"}, "organization_id": {f.Acme}, "type": {base.Type}, "actor_id": {base.Actor.ID}, "subject_id": {base.Subject.ID},
		"target_id": {f.Acme}, "client_id": {base.ClientID}, "request_id": {base.RequestID}, "grant_id": {base.GrantID}, "session_id": {base.SessionID},
		"category": {base.Category}, "outcome": {base.Outcome}, "network": {"203.0.113.7"}, "from": {at.Format(time.RFC3339)}, "to": {at.Add(time.Second).Format(time.RFC3339)}}
	first := f.must(f.AdminAPI("GET", "/audit-events?"+q.Encode(), nil), 200, "compound first page")
	cur := first.Str("next_cursor")
	if cur == "" || len(first.Get("items").([]any)) != 3 {
		t.Fatal("compound search missing bounded page/cursor")
	}
	// A newer matching insertion must not duplicate/shift older sequence pages.
	record(base)
	seen := map[string]bool{}
	page := first
	for n := 0; ; n++ {
		if n > 4 {
			t.Fatal("audit cursor failed to terminate")
		}
		for _, item := range page.Get("items").([]any) {
			id := item.(map[string]any)["id"].(string)
			if !want[id] || seen[id] {
				t.Fatalf("unexpected/duplicate event in exact pages: %q", id)
			}
			seen[id] = true
		}
		cursor := page.Str("next_cursor")
		if cursor == "" {
			break
		}
		q.Set("cursor", cursor)
		q.Set("limit", "2") // Changing only page size is valid.
		page = f.must(f.AdminAPI("GET", "/audit-events?"+q.Encode(), nil), 200, "compound next page")
	}
	if len(seen) != len(want) {
		t.Fatalf("compound pages returned %d/%d original matches", len(seen), len(want))
	}
	q.Set("cursor", cur)
	for key := range q {
		if key == "limit" || key == "cursor" {
			continue
		}
		t.Run("changed_"+key, func(t *testing.T) {
			changed := maps.Clone(q)
			changed.Del(key)
			mustStatus(t, f.AdminAPI("GET", "/audit-events?"+changed.Encode(), nil), 400, "cursor changed filter")
		})
	}
	q.Set("cursor", cur)
	mustStatus(t, f.AdminAPI("GET", "/organizations/"+f.Acme+"/audit-events?"+q.Encode(), nil), 400, "cursor changed route")
}
