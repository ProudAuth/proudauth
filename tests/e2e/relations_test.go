package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/worker"
)

// TestRelationshipAuthorization covers AZ-021, AZ-022, AZ-023 and AZ-027:
// services register resource types (relations, implied relations, links to
// other types, permissions); relationship tuples stay inside one
// organization; decisions on named objects use them (bounded), lists return
// only verified objects (or "all" for organization-wide grants); members
// share objects with each other only through offers the recipient accepts.
func TestRelationshipAuthorization(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	api := func(method, path string, body any) *Resp {
		return h.API(method, path, svc, body)
	}
	for _, perm := range []string{"docs.read", "docs.write", "docs.share", "folders.read"} {
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": perm}), 201, "permission "+perm)
	}
	folder := map[string]any{"resource_id": f.Orders, "relations": []map[string]any{{"name": "viewer", "subject_types": []string{"user", "group", "organization"}}},
		"permissions": map[string][]string{"folders.read": {"viewer"}}}
	f.must(api("PUT", "/resource-types/folder", folder), 201, "folder type")
	doc := map[string]any{"resource_id": f.Orders, "relations": []map[string]any{
		{"name": "owner", "subject_types": []string{"user"}},
		{"name": "editor", "subject_types": []string{"user", "group"}, "implied_by": []string{"owner"}},
		{"name": "viewer", "subject_types": []string{"user", "group", "organization"}, "implied_by": []string{"editor"}},
		{"name": "parent", "subject_types": []string{"folder"}}},
		"permissions":         map[string][]string{"docs.read": {"viewer", "parent.viewer"}, "docs.write": {"editor"}, "docs.share": {"owner"}},
		"shareable_relations": []string{"viewer", "editor"}, "share_permission": "docs.share"}
	created := f.must(api("PUT", "/resource-types/document", doc), 201, "document type")
	bad := func(name string, mut func(m map[string]any)) {
		t.Helper()
		m := map[string]any{}
		for k, v := range doc {
			m[k] = v
		}
		mut(m)
		mustStatus(t, api("PUT", "/resource-types/bad_"+strings.ReplaceAll(name, " ", "_"), m), 422, name)
	}
	bad("cycle", func(m map[string]any) {
		m["relations"] = []map[string]any{{"name": "a", "subject_types": []string{"user"}, "implied_by": []string{"b"}}, {"name": "b", "implied_by": []string{"a"}}}
		m["permissions"], m["shareable_relations"] = map[string][]string{"docs.read": {"a"}}, []string{}
	})
	bad("unregistered permission", func(m map[string]any) { m["permissions"] = map[string][]string{"docs.delete": {"owner"}} })
	bad("built-in permission", func(m map[string]any) { m["permissions"] = map[string][]string{"realm.users.read": {"owner"}} })
	bad("link to a person", func(m map[string]any) { m["permissions"] = map[string][]string{"docs.read": {"owner.viewer"}} })
	mustStatus(t, api("PUT", "/resource-types/document", doc), 428, "replacing without If-Match")
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resource-types/document", Token: svc, JSON: doc,
		Headers: map[string]string{"If-Match": created.Header.Get("ETag")}}), 200, "replace with If-Match")

	grp := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Readers"}), 201, "group").Str("id")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/members", map[string]any{"membership_id": f.MemberAcme["bob"]}), 204, "bob in group")
	write := func(org string, writes ...map[string]any) *Resp {
		return api("POST", "/organizations/"+org+"/relationships", map[string]any{"writes": writes})
	}
	tuple := func(typ, id, rel, st, sid string) map[string]any {
		return map[string]any{"op": "add", "object_type": typ, "object_id": id, "relation": rel, "subject_type": st, "subject_id": sid}
	}
	f.must(write(f.Acme, tuple("document", "doc1", "owner", "user", f.Users["alice"]), tuple("document", "doc1", "parent", "folder", "f1"),
		tuple("folder", "f1", "viewer", "group", grp), tuple("document", "doc2", "viewer", "organization", f.Acme)), 200, "acme tuples")
	f.must(write(f.Globex, tuple("document", "doc3", "owner", "user", f.Users["carol"])), 200, "globex tuple")
	mustStatus(t, write(f.Acme, tuple("document", "doc9", "owner", "user", f.Users["carol"])), 422, "non-member subject")
	mustStatus(t, write(f.Acme, tuple("document", "doc9", "parent", "user", f.Users["alice"])), 422, "subject type the relation does not accept")
	mustStatus(t, write(f.Acme, tuple("document", "doc9", "owner", "organization", f.Globex)), 422, "another organization as subject")

	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	check := func(subject, action, id string) *Resp {
		t.Helper()
		return f.must(api("POST", "/authorization/check", map[string]any{"subject_token": subject, "action": action,
			"resource": map[string]any{"type": "document", "id": id, "org_id": f.Acme}}), 200, "check")
	}
	expect := func(subject, action, id string, allowed bool) {
		t.Helper()
		d := check(subject, action, id)
		if d.Get("allowed") != allowed {
			t.Fatalf("%s on %s: %s", action, id, d.Raw)
		}
		if allowed && d.Str("cache_key") != "" {
			t.Fatalf("relationship decisions are not cacheable: %s", d.Raw)
		}
	}
	expect(bob, "docs.read", "doc1", true)    // folder viewer through a group, via parent
	expect(bob, "docs.write", "doc1", false)  // viewer only
	expect(alice, "docs.write", "doc1", true) // owner implies editor
	expect(bob, "docs.read", "doc2", true)    // every member
	expect(bob, "docs.read", "doc3", false)   // the tuple lives in another organization
	list := f.must(api("POST", "/authorization/list-objects", map[string]any{"subject_token": bob, "action": "docs.read",
		"resource": map[string]any{"type": "document", "org_id": f.Acme}}), 200, "list objects")
	if jsonString(list.Get("objects")) != `["doc1","doc2"]` || list.Get("all") != false {
		t.Fatalf("listed objects: %s", list.Raw)
	}
	if l := f.must(api("POST", "/authorization/list-objects", map[string]any{"subject_token": bob, "action": "orders.read",
		"resource": map[string]any{"type": "document", "org_id": f.Acme}}), 200, "list with an organization grant"); l.Get("all") != true {
		t.Fatalf("organization-wide grant: %s", l.Raw)
	}

	// Sharing: alice offers bob the editor relation; it counts only once accepted.
	aliceAcct := f.AccountToken("alice").Tokens.Str("access_token")
	bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
	offer := func(tok, rel, recipient string) *Resp {
		return h.API("POST", "/me/shares", tok, map[string]any{"organization_id": f.Acme, "resource_type": "document", "object_id": "doc1",
			"relation": rel, "recipient_user_id": recipient})
	}
	mustStatus(t, offer(aliceAcct, "owner", f.Users["bob"]), 422, "owner is not shareable")
	mustStatus(t, offer(aliceAcct, "editor", f.Users["carol"]), 422, "recipient outside the organization")
	mustStatus(t, offer(bobAcct, "viewer", f.Users["alice"]), 403, "bob may not share")
	sh := f.must(offer(aliceAcct, "editor", f.Users["bob"]), 201, "offer")
	expect(bob, "docs.write", "doc1", false)
	recv := f.must(h.API("GET", "/me/shares", bobAcct, nil), 200, "received")
	if len(recv.Get("items").([]any)) != 1 {
		t.Fatalf("received shares: %s", recv.Raw)
	}
	f.must(h.API("POST", "/me/shares/"+sh.Str("id")+"/accept", bobAcct, nil), 200, "accept")
	expect(bob, "docs.write", "doc1", true)
	mustStatus(t, h.API("POST", "/me/shares/"+sh.Str("id")+"/accept", bobAcct, nil), 409, "accepted twice")
	mustStatus(t, h.API("DELETE", "/me/shares/"+sh.Str("id"), aliceAcct, nil), 204, "owner revokes")
	expect(bob, "docs.write", "doc1", false)

	// Shares with an end: one offer nobody answers in time, one accepted.
	timed := func(rel string) *Resp {
		return f.must(h.API("POST", "/me/shares", aliceAcct, map[string]any{"organization_id": f.Acme, "resource_type": "document", "object_id": "doc1",
			"relation": rel, "recipient_user_id": f.Users["bob"], "expires_at": h.Clock.Now().Add(time.Hour)}), 201, "offer with an end "+rel)
	}
	unanswered, answered := timed("viewer"), timed("editor")
	f.must(h.API("POST", "/me/shares/"+answered.Str("id")+"/accept", bobAcct, nil), 200, "accept a share with an end")

	// Time-bound tuples lapse on their own.
	f.must(write(f.Acme, map[string]any{"op": "add", "object_type": "document", "object_id": "doc4", "relation": "viewer", "subject_type": "user",
		"subject_id": f.Users["bob"], "expires_at": h.Clock.Now().Add(time.Hour)}), 200, "temporary viewer")
	expect(bob, "docs.read", "doc4", true)
	h.Clock.Advance(2 * time.Hour)
	bob = f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	svc = f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	expect(bob, "docs.read", "doc4", false)

	// An expired share is stored as expired: the refused acceptance records
	// it (its own transaction rolls back), and the expiry sweep records
	// accepted ones, removing the tuple the acceptance wrote.
	ctx := context.Background()
	shareState := func(id string) string {
		var st string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM resource_shares WHERE id=$1`, id).Scan(&st)
		return st
	}
	bobAcct = f.AccountToken("bob").Tokens.Str("access_token")
	aliceAcct = f.AccountToken("alice").Tokens.Str("access_token")
	if r := h.API("POST", "/me/shares/"+unanswered.Str("id")+"/accept", bobAcct, nil); r.Status != 409 || !strings.Contains(string(r.Raw), "expired") {
		t.Fatalf("accepting an expired offer: %d %s", r.Status, r.Raw)
	}
	if st := shareState(unanswered.Str("id")); st != "expired" {
		t.Fatalf("expired offer stored as %q", st)
	}
	if st := shareState(answered.Str("id")); st != "accepted" {
		t.Fatalf("accepted share before the sweep: %q", st)
	}
	listed := f.must(h.API("GET", "/me/shares?state=expired", bobAcct, nil), 200, "expired shares")
	if len(listed.Get("items").([]any)) != 2 {
		t.Fatalf("shares past their end are listed as expired before the sweep: %s", listed.Raw)
	}
	if _, err := worker.New(h.App, "test").Expiry(ctx); err != nil {
		t.Fatal(err)
	}
	if st := shareState(answered.Str("id")); st != "expired" {
		t.Fatalf("accepted share after its end: %q", st)
	}
	var tuples, expiredEvents int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_relationships WHERE object_id='doc1' AND relation='editor' AND subject_id=$1`,
		f.Users["bob"]).Scan(&tuples)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='authorization.share.expired'`).Scan(&expiredEvents)
	if tuples != 0 || expiredEvents != 2 {
		t.Fatalf("after the sweep: %d tuples of the expired share, %d expiry events", tuples, expiredEvents)
	}
	// An expired offer no longer blocks a new one.
	f.must(offer(aliceAcct, "viewer", f.Users["bob"]), 201, "offer again after expiry")

	// list-objects: a limit above 500 is clamped to 500 (not reset to 100),
	// and an object whose own evaluation reaches a bound is left out with
	// truncated set.
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO resource_relationships (id, realm_id, organization_id, subject_type, subject_id, relation,
		object_type, object_id, source) SELECT 'rel_bulk_'||g, $1, $2, 'user', $3, 'viewer', 'document', 'bulk_'||lpad(g::text, 3, '0'), 'test'
		FROM generate_series(1, 150) g`, h.Realm.ID, f.Acme, f.Users["bob"]); err != nil {
		t.Fatal(err)
	}
	listAll := func() *Resp {
		return f.must(api("POST", "/authorization/list-objects", map[string]any{"subject_token": bob, "action": "docs.read", "limit": 1000,
			"resource": map[string]any{"type": "document", "org_id": f.Acme}}), 200, "list objects")
	}
	all := listAll()
	if n := len(all.Get("objects").([]any)); n != 152 || all.Get("next_cursor") != nil || all.Get("truncated") != false {
		t.Fatalf("limit 1000: %d objects, next_cursor %v, truncated %v", n, all.Get("next_cursor"), all.Get("truncated"))
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO resource_relationships (id, realm_id, organization_id, subject_type, subject_id, relation,
		object_type, object_id, source) SELECT 'rel_big_'||g, $1, $2, 'group', 'grp_absent_'||g, 'viewer', 'document', 'big', 'test'
		FROM generate_series(1, 1001) g UNION ALL SELECT 'rel_big_bob', $1, $2, 'user', $3, 'viewer', 'document', 'big', 'test'`,
		h.Realm.ID, f.Acme, f.Users["bob"]); err != nil {
		t.Fatal(err)
	}
	if bounded := listAll(); bounded.Get("truncated") != true || strings.Contains(jsonString(bounded.Get("objects")), `"big"`) {
		t.Fatalf("an object that reached a bound: truncated %v, objects include it: %v", bounded.Get("truncated"),
			strings.Contains(jsonString(bounded.Get("objects")), `"big"`))
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `DELETE FROM resource_relationships WHERE source='test'`); err != nil {
		t.Fatal(err)
	}

	mustStatus(t, api("DELETE", "/resource-types/document", nil), 409, "type in use")
	var n int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type IN ('authorization.relationships.written',
		'authorization.share.offered','authorization.share.accepted','authorization.share.revoked')`).Scan(&n)
	if n < 5 {
		t.Fatalf("relationship evidence: %d events", n)
	}
}
