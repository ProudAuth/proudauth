package e2e

import (
	"context"
	"testing"
	"time"
)

// TestOrganizationRelationshipsAndPartnerProjects covers TEN-021
// (explicit parent/child and partner relationships that grant nothing by
// themselves) and TEN-020 (a project owner grants selected project roles to
// a related organization, which assigns only that subset to its members).
func TestOrganizationRelationshipsAndPartnerProjects(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	// alice owns Acme; carol administers Globex.
	alice := f.AdminTokenFor("alice").Tokens.Str("access_token")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	acme, globex := "/organizations/"+f.Acme, "/organizations/"+f.Globex

	// A project owned by Acme with two roles.
	project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Shared Portal", "owner_organization_id": f.Acme}), 201, "project").Str("id")
	viewer := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "portal-viewer",
		"permissions": []string{"orders.read"}}), 201, "viewer role").Str("id")
	admin := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "portal-admin",
		"permissions": []string{"orders.read"}}), 201, "admin role").Str("id")

	// Without a relationship Acme cannot share the project with Globex.
	share := func(tok string) *Resp {
		return h.API("POST", acme+"/projects/"+project+"/grants", tok, map[string]any{"organization_id": f.Globex, "allowed_role_ids": []string{viewer}})
	}
	mustStatus(t, share(alice), 422, "share without relationship")
	// Globex's administrator cannot share Acme's project.
	if r := h.API("POST", globex+"/projects/"+project+"/grants", carol, map[string]any{"organization_id": f.Globex}); r.Status != 404 && r.Status != 403 {
		t.Fatalf("non-owner shared the project: %d %s", r.Status, r.Raw)
	}

	// TEN-021: Acme proposes a partnership; it is inert until Globex accepts.
	prop := h.API("POST", acme+"/organization-relationships", alice, map[string]any{"kind": "partner", "target_organization_id": f.Globex, "note": "reseller"})
	mustStatus(t, prop, 201, "propose")
	rel := prop.Str("id")
	if prop.Str("state") != "proposed" {
		t.Fatalf("tenant relationship active without consent: %s", prop.Raw)
	}
	mustStatus(t, share(alice), 422, "share with a proposed relationship")
	mustStatus(t, h.API("POST", acme+"/organization-relationships/"+rel+"/accept", alice, nil), 403, "proposer accepts")
	mustStatus(t, h.API("POST", acme+"/organization-relationships", alice, map[string]any{"kind": "partner", "target_organization_id": f.Globex}), 409, "duplicate")
	acc := h.API("POST", globex+"/organization-relationships/"+rel+"/accept", carol, nil)
	mustStatus(t, acc, 200, "accept")
	if acc.Str("state") != "active" {
		t.Fatalf("accept: %s", acc.Raw)
	}
	// The relationship alone grants nothing: Acme's owner cannot read
	// Globex's members, and Globex's admin cannot read Acme's.
	if r := h.API("GET", globex+"/members", alice, nil); r.Status == 200 {
		t.Fatal("a relationship gave access to the partner's members")
	}
	if r := h.API("GET", acme+"/members", carol, nil); r.Status == 200 {
		t.Fatal("a relationship gave access to the partner's members")
	}
	if list := h.API("GET", globex+"/organization-relationships", carol, nil); len(list.Get("items").([]any)) != 1 {
		t.Fatalf("relationships: %s", list.Raw)
	}

	// TEN-020: Acme shares only portal-viewer with Globex.
	g := share(alice)
	mustStatus(t, g, 201, "share")
	grant := g.Str("id")
	recv := h.API("GET", globex+"/project-grants", carol, nil)
	if items := recv.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["id"] != grant {
		t.Fatalf("received grants: %s", recv.Raw)
	}
	assign := func(role, user string) *Resp {
		return h.API("POST", globex+"/project-role-assignments", carol, map[string]any{"project_id": project, "role_id": role, "user_id": user})
	}
	if r := assign(admin, f.Users["bob"]); r.Status != 403 {
		t.Fatalf("assigned a role outside the shared subset: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, assign(viewer, f.Users["alice"]), 422, "non-member")
	a := assign(viewer, f.Users["bob"])
	mustStatus(t, a, 201, "assign shared role")
	if a.Str("project_grant_id") != grant {
		t.Fatalf("assignment basis: %s", a.Raw)
	}
	has := func() bool {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE subject_id=$1 AND scope_type='project' AND scope_id=$2`,
			f.Users["bob"], project).Scan(&n)
		return n > 0
	}
	if !has() {
		t.Fatal("assignment missing")
	}
	// Acme's members who are not Globex admins cannot assign in Globex.
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	if r := h.API("POST", globex+"/project-role-assignments", bob, map[string]any{"project_id": project, "role_id": viewer, "user_id": f.Users["bob"]}); r.Status != 403 && r.Status != 404 {
		t.Fatalf("plain member assigned project roles: %d", r.Status)
	}
	list := h.API("GET", globex+"/project-role-assignments", carol, nil)
	if items := list.Get("items").([]any); len(items) != 1 {
		t.Fatalf("assignment list: %s", list.Raw)
	}
	// Revoking the grant removes what the partner assigned through it.
	mustStatus(t, h.API("POST", acme+"/projects/"+project+"/grants/"+grant+"/revoke", alice, nil), 204, "revoke")
	if has() {
		t.Fatal("delegated assignment survived the grant")
	}
	// Removing the member removes it too.
	g2 := share(alice)
	mustStatus(t, g2, 201, "share again")
	mustStatus(t, assign(viewer, f.Users["bob"]), 201, "assign again")
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"], nil), 204, "remove member")
	if has() {
		t.Fatal("delegated assignment survived the membership")
	}

	// Ending the relationship stops new grants.
	mustStatus(t, h.API("POST", globex+"/organization-relationships/"+rel+"/end", carol, nil), 204, "end")
	mustStatus(t, h.API("POST", acme+"/projects/"+project+"/grants/"+g2.Str("id")+"/revoke", alice, nil), 204, "revoke second grant")
	mustStatus(t, share(alice), 422, "share after the relationship ended")

	// Parent/child: realm administrators record it directly; cycles and
	// second parents are refused.
	child := f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "acme-eu", "display_name": "Acme EU"}), 201, "child org").Str("id")
	pc := f.must(f.AdminAPI("POST", acme+"/organization-relationships", map[string]any{"kind": "parent_child", "target_organization_id": child}), 201, "parent")
	if pc.Str("state") != "active" {
		t.Fatalf("realm administrator relationship: %s", pc.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+child+"/organization-relationships", map[string]any{"kind": "parent_child", "target_organization_id": f.Acme}), 409, "cycle")
	mustStatus(t, f.AdminAPI("POST", globex+"/organization-relationships", map[string]any{"kind": "parent_child", "target_organization_id": child}), 409, "second parent")
	all := f.must(f.AdminAPI("GET", "/organization-relationships", nil), 200, "realm list")
	if len(all.Get("items").([]any)) != 2 {
		t.Fatalf("realm relationships: %s", all.Raw)
	}
}

// TestProjectGrantExpiry covers TEN-020 grant lifetimes: at valid_until a
// project grant ends with every role assigned through it, and the holders'
// authorization revision moves so cached decisions are re-evaluated.
func TestProjectGrantExpiry(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Expiring Portal", "owner_organization_id": f.Acme}), 201, "project").Str("id")
	viewer := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "expiring-viewer",
		"permissions": []string{"orders.read"}}), 201, "role").Str("id")
	until := h.Clock.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	grant := f.must(f.AdminAPI("POST", "/projects/"+project+"/grants", map[string]any{"organization_id": f.Globex, "allowed_role_ids": []string{viewer},
		"valid_until": until}), 201, "grant").Str("id")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/organizations/"+f.Globex+"/project-role-assignments", carol, map[string]any{"project_id": project, "role_id": viewer,
		"user_id": f.Users["bob"]}), 201, "assign")
	revision := func() int64 {
		var n int64
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT authz_revision FROM users WHERE id=$1`, f.Users["bob"]).Scan(&n)
		return n
	}
	held := func() bool {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE subject_id=$1 AND scope_type='project' AND scope_id=$2`,
			f.Users["bob"], project).Scan(&n)
		return n > 0
	}
	before := revision()
	if n, err := h.App.Apps.ExpireProjectGrants(ctx); err != nil || n != 0 || !held() {
		t.Fatalf("grant ended early: %d %v", n, err)
	}
	h.Clock.Advance(3 * time.Hour)
	if n, err := h.App.Apps.ExpireProjectGrants(ctx); err != nil || n != 1 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	if held() || revision() <= before {
		t.Fatalf("expired grant kept its assignment (held %v) or did not move the revision", held())
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM project_grants WHERE id=$1`, grant).Scan(&state)
	if state != "revoked" {
		t.Fatalf("grant state %s", state)
	}
	var events int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='project.grant.expired' AND target_id=$1`, grant).Scan(&events)
	if events != 1 {
		t.Fatalf("expiry not audited: %d", events)
	}
}
