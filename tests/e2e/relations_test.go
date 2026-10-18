package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/identity"
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

// TestRelationshipTenantEligibility covers AZ-021 with AZ-007 and AZ-010:
// relationship decisions and lists apply the tenant eligibility RBAC
// applies. A suspended organization grants nothing, also to a realm-scoped
// token that names it only in resource.org_id; a membership past its
// expires_at counts as gone before the expiry sweep stores it; a dynamic
// group whose recomputation is stale no longer matches; a service principal
// matches only while active and allowed in the organization, also through
// explicit-subject evaluation.
func TestRelationshipTenantEligibility(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, f.SetPolicy(func(p *realmPolicy) {
		p.Profile.Attributes = []identity.AttributeDef{{Name: "department", Type: "string", MaxLength: 64, Visibility: "admin", Source: "directory"}}
	}), 200, "schema")
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": "docs.read"}), 201, "permission")
	f.must(h.API("PUT", "/resource-types/document", svc, map[string]any{"resource_id": f.Orders,
		"relations":   []map[string]any{{"name": "viewer", "subject_types": []string{"user", "group", "organization", "service_principal"}}},
		"permissions": map[string][]string{"docs.read": {"viewer"}}}), 201, "document type")

	// bob is in the dynamic group Sales through his department.
	u := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "user")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/users/" + f.Users["bob"], Token: f.AdminToken,
		Headers: map[string]string{"If-Match": u.Header.Get("ETag")}, JSON: map[string]any{"profile": map[string]any{"department": "sales"}}}), 200, "department")
	grp := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Sales"}), 201, "group").Str("id")
	f.must(f.AdminAPI("PUT", "/organizations/"+f.Acme+"/groups/"+grp+"/dynamic-rule",
		map[string]any{"all": []map[string]any{{"attribute": "department", "equals": "sales"}}}), 200, "dynamic rule")

	batchSP := f.Clients["batch"].SP // allowed in Acme
	tuple := func(id, st, sid string) map[string]any {
		return map[string]any{"op": "add", "object_type": "document", "object_id": id, "relation": "viewer", "subject_type": st, "subject_id": sid}
	}
	f.must(h.API("POST", "/organizations/"+f.Acme+"/relationships", svc, map[string]any{"writes": []map[string]any{
		tuple("doc_bob", "user", f.Users["bob"]), tuple("doc_group", "group", grp), tuple("doc_org", "organization", f.Acme),
		tuple("doc_sp", "service_principal", batchSP)}}), 200, "tuples")

	bob := map[string]any{"type": "user", "id": f.Users["bob"]}
	sp := map[string]any{"type": "service_principal", "id": batchSP}
	resource := func(id string) map[string]any {
		r := map[string]any{"type": "document", "org_id": f.Acme}
		if id != "" {
			r["id"] = id
		}
		return r
	}
	// Explicit-subject evaluation (realm.authorization.simulate) by the administrator.
	expect := func(subject map[string]any, id string, allowed bool, what string) {
		t.Helper()
		d := f.must(f.AdminAPI("POST", "/authorization/check", map[string]any{"subject": subject, "action": "docs.read", "resource": resource(id)}), 200, "check")
		if d.Get("allowed") != allowed {
			t.Fatalf("%s: %s on %s: %s", what, subject["type"], id, d.Raw)
		}
	}
	listed := func(subject map[string]any) string {
		t.Helper()
		return jsonString(f.must(f.AdminAPI("POST", "/authorization/list-objects", map[string]any{"subject": subject, "action": "docs.read",
			"resource": resource("")}), 200, "list objects").Get("objects"))
	}
	// A realm-scoped token (no org_id; the organization comes from the
	// resource) for an audience that does not require an organization.
	docs := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Docs API", "audience": "https://docs.test", "requires_organization": false,
		"scopes": []map[string]any{{"name": "docs:read"}}}), 201, "docs resource").Str("id")
	f.must(f.AdminAPI("POST", "/resources/"+docs+"/introspectors", map[string]any{"client": f.Clients["orders-rs"].Ref}), 204, "introspector")
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+docs, map[string]any{"allowed_scopes": []string{"docs:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	realmTok := f.LoginWeb("bob", "", "https://docs.test", "docs:read").Tokens.Str("access_token")
	if c := h.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, realmTok); c.Get("active") != true || c.Str("org_id") != "" {
		t.Fatalf("fixture: realm-scoped token: %s", c.Raw)
	}
	expectToken := func(id string, allowed bool, what string) {
		t.Helper()
		d := f.must(h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": realmTok, "action": "docs.read", "resource": resource(id)}),
			200, "token check")
		if d.Get("allowed") != allowed {
			t.Fatalf("%s: realm token on %s: %s", what, id, d.Raw)
		}
	}
	listedToken := func() string {
		t.Helper()
		return jsonString(f.must(h.API("POST", "/authorization/list-objects", svc, map[string]any{"subject_token": realmTok, "action": "docs.read",
			"resource": resource("")}), 200, "token list").Get("objects"))
	}
	all := `["doc_bob","doc_group","doc_org"]`
	baseline := func(what string) {
		t.Helper()
		for _, id := range []string{"doc_bob", "doc_group", "doc_org"} {
			expect(bob, id, true, what)
		}
		expect(sp, "doc_sp", true, what)
		if l := listed(bob); l != all {
			t.Fatalf("%s: listed for bob: %s", what, l)
		}
		if l := listed(sp); l != `["doc_sp"]` {
			t.Fatalf("%s: listed for the service principal: %s", what, l)
		}
	}
	baseline("before")
	expectToken("doc_bob", true, "before")
	if l := listedToken(); l != all {
		t.Fatalf("realm token list before: %s", l)
	}

	// A suspended organization: the realm token stays active, but no
	// relationship of the organization counts.
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/suspend", map[string]any{"reason": "billing hold"}), 200, "suspend")
	for _, id := range []string{"doc_bob", "doc_group", "doc_org"} {
		expectToken(id, false, "suspended organization")
		expect(bob, id, false, "suspended organization")
	}
	expect(sp, "doc_sp", false, "suspended organization")
	if l := listedToken(); l != `[]` {
		t.Fatalf("realm token list in a suspended organization: %s", l)
	}
	if l := listed(sp); l != `[]` {
		t.Fatalf("service principal list in a suspended organization: %s", l)
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/reactivate", map[string]any{"reason": "paid"}), 200, "reactivate")
	baseline("after reactivation")
	expectToken("doc_bob", true, "after reactivation")

	// A membership past its expires_at, not yet swept (still 'active').
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE memberships SET expires_at=$2 WHERE id=$1`, f.MemberAcme["bob"], h.Clock.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"doc_bob", "doc_group", "doc_org"} {
		expect(bob, id, false, "expired membership")
		expectToken(id, false, "expired membership")
	}
	if l := listed(bob); l != `[]` {
		t.Fatalf("list with an expired membership: %s", l)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE memberships SET expires_at=NULL WHERE id=$1`, f.MemberAcme["bob"]); err != nil {
		t.Fatal(err)
	}
	baseline("membership without an end")

	// A service principal no longer allowed in the organization, then disabled.
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE service_principals SET allowed_organization_ids='{}' WHERE id=$1`, batchSP); err != nil {
		t.Fatal(err)
	}
	expect(sp, "doc_sp", false, "service principal not allowed in the organization")
	if l := listed(sp); l != `[]` {
		t.Fatalf("list for a service principal not allowed in the organization: %s", l)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE service_principals SET allowed_organization_ids=ARRAY[$2::text] WHERE id=$1`, batchSP, f.Acme); err != nil {
		t.Fatal(err)
	}
	expect(sp, "doc_sp", true, "allowed again")
	mustStatus(t, f.AdminAPI("POST", "/service-principals/"+batchSP+"/disable", nil), 204, "disable")
	expect(sp, "doc_sp", false, "disabled service principal")
	if l := listed(sp); l != `[]` {
		t.Fatalf("list for a disabled service principal: %s", l)
	}

	// A stale dynamic group (no recomputation within the staleness window):
	// its tuples stop matching; bob's own tuple and the organization's do not.
	h.Clock.Advance(2 * time.Hour)
	f.ReloginAdmin()
	expect(bob, "doc_group", false, "stale dynamic group")
	expect(bob, "doc_bob", true, "stale dynamic group")
	if l := listed(bob); l != `["doc_bob","doc_org"]` {
		t.Fatalf("list with a stale dynamic group: %s", l)
	}
	runWorker(t, worker.New(h.App, "test"))
	expect(bob, "doc_group", true, "recomputed dynamic group")
}

// TestResourceSharesKeepForeignTuples covers AZ-021 and AZ-027: a share
// writes a relationship tuple of its own (source share:<id>) or none. When
// the recipient already holds the relation through a tuple the application
// or another share wrote, accepting is 409 and that tuple keeps its source,
// expires_at and revision (a permanent grant does not become time-boxed, a
// time-boxed one does not become permanent), also after it has expired; the
// offer stays pending. Revoking a share removes only the tuple it wrote,
// also for a share that an earlier version recorded as holding a foreign
// tuple.
func TestResourceSharesKeepForeignTuples(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	api := func(method, path string, body any) *Resp {
		return h.API(method, path, svc, body)
	}
	for _, perm := range []string{"docs.read", "docs.write", "docs.share"} {
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": perm}), 201, "permission "+perm)
	}
	f.must(api("PUT", "/resource-types/document", map[string]any{"resource_id": f.Orders, "relations": []map[string]any{
		{"name": "owner", "subject_types": []string{"user"}},
		{"name": "editor", "subject_types": []string{"user"}, "implied_by": []string{"owner"}},
		{"name": "viewer", "subject_types": []string{"user"}, "implied_by": []string{"editor"}}},
		"permissions":         map[string][]string{"docs.read": {"viewer"}, "docs.write": {"editor"}, "docs.share": {"owner"}},
		"shareable_relations": []string{"viewer", "editor"}, "share_permission": "docs.share"}), 201, "document type")
	write := func(what string, writes ...map[string]any) {
		t.Helper()
		f.must(api("POST", "/organizations/"+f.Acme+"/relationships", map[string]any{"writes": writes}), 200, what)
	}
	tuple := func(op, obj, rel, user string, expires *time.Time) map[string]any {
		w := map[string]any{"op": op, "object_type": "document", "object_id": obj, "relation": rel, "subject_type": "user", "subject_id": user}
		if expires != nil {
			w["expires_at"] = *expires
		}
		return w
	}
	var owners []map[string]any
	for _, obj := range []string{"docA", "docB", "docC", "docD"} {
		owners = append(owners, tuple("add", obj, "owner", f.Users["alice"], nil))
	}
	write("alice owns the documents", owners...)

	type row struct {
		id, source string
		expiresAt  *time.Time
		revision   int64
	}
	bobTuple := func(obj, rel string) *row {
		t.Helper()
		var r row
		err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id, source, expires_at, revision FROM resource_relationships WHERE organization_id=$1
			AND subject_type='user' AND subject_id=$2 AND relation=$3 AND object_type='document' AND object_id=$4`, f.Acme, f.Users["bob"], rel, obj).
			Scan(&r.id, &r.source, &r.expiresAt, &r.revision)
		if err != nil {
			return nil
		}
		return &r
	}
	same := func(what string, got, want *row) {
		t.Helper()
		if got == nil || got.id != want.id || got.source != want.source || got.revision != want.revision ||
			(got.expiresAt == nil) != (want.expiresAt == nil) || (got.expiresAt != nil && !got.expiresAt.Equal(*want.expiresAt)) {
			t.Fatalf("%s: tuple %+v, want it unchanged: %+v", what, got, want)
		}
	}
	shareState := func(id string) (state, relID string) {
		t.Helper()
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, coalesce(relationship_id,'') FROM resource_shares WHERE id=$1`, id).Scan(&state, &relID); err != nil {
			t.Fatal(err)
		}
		return state, relID
	}

	var bob, aliceAcct, bobAcct string
	login := func() {
		svc = f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		bob = f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		aliceAcct = f.AccountToken("alice").Tokens.Str("access_token")
		bobAcct = f.AccountToken("bob").Tokens.Str("access_token")
	}
	login()
	expect := func(action, obj string, allowed bool, what string) {
		t.Helper()
		d := f.must(api("POST", "/authorization/check", map[string]any{"subject_token": bob, "action": action,
			"resource": map[string]any{"type": "document", "id": obj, "org_id": f.Acme}}), 200, "check")
		if d.Get("allowed") != allowed {
			t.Fatalf("%s: %s on %s: %s", what, action, obj, d.Raw)
		}
	}
	offer := func(obj, rel string, expires *time.Time) string {
		t.Helper()
		body := map[string]any{"organization_id": f.Acme, "resource_type": "document", "object_id": obj, "relation": rel, "recipient_user_id": f.Users["bob"]}
		if expires != nil {
			body["expires_at"] = *expires
		}
		return f.must(h.API("POST", "/me/shares", aliceAcct, body), 201, "offer "+rel+" on "+obj).Str("id")
	}
	accept := func(id string) *Resp {
		return h.API("POST", "/me/shares/"+id+"/accept", bobAcct, nil)
	}
	refused := func(id, what string) {
		t.Helper()
		if r := accept(id); r.Status != 409 || !strings.Contains(string(r.Raw), "already hold this relation") {
			t.Fatalf("%s: accepting %d %s, want 409 already hold this relation", what, r.Status, r.Raw)
		}
		if st, rel := shareState(id); st != "pending" || rel != "" {
			t.Fatalf("%s: refused share stored as %q with tuple %q, want it pending", what, st, rel)
		}
	}
	inAnHour := h.Clock.Now().Add(time.Hour)

	// Without an equivalent tuple, acceptance writes the share's own tuple
	// and revoking removes it.
	plain := offer("docC", "viewer", nil)
	f.must(accept(plain), 200, "accept a share")
	written := bobTuple("docC", "viewer")
	if _, rel := shareState(plain); written == nil || written.source != "share:"+plain || written.expiresAt != nil || rel != written.id {
		t.Fatalf("tuple of an accepted share: %+v, recorded %q", written, rel)
	}
	expect("docs.read", "docC", true, "accepted share")
	mustStatus(t, h.API("DELETE", "/me/shares/"+plain, aliceAcct, nil), 204, "owner revokes")
	if r := bobTuple("docC", "viewer"); r != nil {
		t.Fatalf("revoked share left its tuple: %+v", r)
	}
	expect("docs.read", "docC", false, "revoked share")

	// A permanent grant from the application does not become time-boxed,
	// and revoking the share leaves it.
	write("permanent viewer", tuple("add", "docA", "viewer", f.Users["bob"], nil))
	permanent := bobTuple("docA", "viewer")
	timed := offer("docA", "viewer", &inAnHour)
	refused(timed, "permanent grant, time-boxed share")
	same("after the refused acceptance", bobTuple("docA", "viewer"), permanent)
	mustStatus(t, h.API("DELETE", "/me/shares/"+timed, aliceAcct, nil), 204, "owner withdraws the offer")
	same("after the offer was withdrawn", bobTuple("docA", "viewer"), permanent)
	expect("docs.read", "docA", true, "application grant after the share ended")
	// A share accepted before this fix recorded the application's tuple as
	// its own; giving it back must not remove that tuple.
	legacy := offer("docA", "viewer", &inAnHour)
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE resource_shares SET state='accepted', decided_at=$2, relationship_id=$3 WHERE id=$1`,
		legacy, h.Clock.Now(), permanent.id); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, h.API("DELETE", "/me/shares/"+legacy, bobAcct, nil), 204, "recipient gives back a share that recorded a foreign tuple")
	same("after revoking a share that recorded the application's tuple", bobTuple("docA", "viewer"), permanent)
	expect("docs.read", "docA", true, "application grant after the legacy share was revoked")

	// A time-boxed grant from the application does not become permanent.
	write("time-boxed editor", tuple("add", "docB", "editor", f.Users["bob"], &inAnHour))
	boxed := bobTuple("docB", "editor")
	forever := offer("docB", "editor", nil)
	refused(forever, "time-boxed grant, permanent share")
	same("after the refused acceptance", bobTuple("docB", "editor"), boxed)
	expect("docs.write", "docB", true, "time-boxed application grant")

	// Another share's tuple is not taken over either.
	first := offer("docD", "viewer", &inAnHour)
	f.must(accept(first), 200, "accept a time-boxed share")
	firstTuple := bobTuple("docD", "viewer")

	h.Clock.Advance(2 * time.Hour)
	login()
	expect("docs.write", "docB", false, "the application's grant lapsed; the share did not make it permanent")
	refused(forever, "expired application tuple not yet removed")
	same("expired application tuple", bobTuple("docB", "editor"), boxed)
	write("the application removes its tuple", tuple("remove", "docB", "editor", f.Users["bob"], nil))
	f.must(accept(forever), 200, "accept once the application's tuple is gone")
	if r := bobTuple("docB", "editor"); r == nil || r.source != "share:"+forever || r.expiresAt != nil {
		t.Fatalf("tuple of the permanent share: %+v", r)
	}
	expect("docs.write", "docB", true, "permanent share")

	second := offer("docD", "viewer", nil) // the first share is past its end
	refused(second, "tuple of another share")
	same("the other share's tuple", bobTuple("docD", "viewer"), firstTuple)
	if _, err := worker.New(h.App, "test").Expiry(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := shareState(first); st != "expired" || bobTuple("docD", "viewer") != nil {
		t.Fatalf("after the sweep: first share %q, tuple %+v", st, bobTuple("docD", "viewer"))
	}
	f.must(accept(second), 200, "accept once the sweep removed the other share's tuple")
	if r := bobTuple("docD", "viewer"); r == nil || r.source != "share:"+second {
		t.Fatalf("tuple of the second share: %+v", r)
	}
	expect("docs.read", "docD", true, "second share")
}
