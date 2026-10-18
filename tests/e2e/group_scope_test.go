package e2e

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestGroupsHoldOrganizationRolesOnly: a group belongs to one organization
// and holds that organization's roles (AZ-010, TEN-013). Realm and project
// assignments to a group would be stored but never evaluated, so they are
// refused with 422 and nothing is stored.
func TestGroupsHoldOrganizationRolesOnly(t *testing.T) {
	f := NewFixture(t)
	group := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "auditors"}), 201, "group").Str("id")
	realmRole := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "realm-reader",
		"permissions": []string{"realm.users.read"}}), 201, "realm role").Str("id")
	project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Ledger", "owner_organization_id": f.Acme}), 201, "project").Str("id")
	projectRole := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "ledger-admin",
		"permissions": []string{"orders.read"}}), 201, "project role").Str("id")
	for name, body := range map[string]map[string]any{
		"realm":   {"role_id": realmRole, "subject": map[string]any{"type": "group", "id": group}},
		"project": {"role_id": projectRole, "subject": map[string]any{"type": "group", "id": group}, "scope": map[string]any{"type": "project", "id": project}},
	} {
		if r := f.AdminAPI("POST", "/role-assignments", body); r.Status != 422 || !containsRaw(r, "groups hold organization roles only") {
			t.Errorf("%s-scoped group assignment: %d %s", name, r.Status, r.Raw)
		}
	}
	var stored int
	if err := f.H.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1`, group).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("refused group assignments stored: %d %v", stored, err)
	}
}

// TestGroupRemovalNeedsTheGroupCeiling covers TEN-007, TEN-008 and AZ-006 for
// group removals: removing a member from a group, or deleting a group, takes
// from its members the roles the group grants, its ancestors' included, so
// the administrator must be able to assign those roles, as for adding a
// member. An organization administrator beyond them gets 403
// grant_ceiling_exceeded and nothing changes; within them, and for a realm
// administrator, the removal succeeds. A SCIM connector still removes
// members from, and deletes, a group it owns without an administrator's
// ceiling (PROV-007).
func TestGroupRemovalNeedsTheGroupCeiling(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	org := "/organizations/" + f.Globex
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex admin: may assign orders-viewer, not orders-refunder
	bob := f.MemberGlobex["bob"]
	dave := f.must(f.AdminAPI("POST", org+"/members", map[string]any{"user_id": f.CreateUser("dave")}), 201, "dave").Str("id")
	group := func(name, parent string, roles ...string) string {
		t.Helper()
		body := map[string]any{"name": name}
		if parent != "" {
			body["parent_id"] = parent
		}
		id := f.must(f.AdminAPI("POST", org+"/groups", body), 201, "group "+name).Str("id")
		for _, r := range roles {
			f.must(f.AdminAPI("POST", org+"/groups/"+id+"/roles", map[string]any{"role_id": r}), 201, "group role")
		}
		return id
	}
	join := func(g, membership string) {
		t.Helper()
		f.must(f.AdminAPI("POST", org+"/groups/"+g+"/members", map[string]any{"membership_id": membership}), 204, "join")
	}
	holdsRefund := func(membership string) bool {
		t.Helper()
		perms, _ := f.must(f.AdminAPI("GET", org+"/members/"+membership+"/permissions", nil), 200, "permissions").Get("permissions").([]any)
		return slices.Contains(perms, any("orders.refund"))
	}
	refunders := group("refunders", "", f.Roles["orders-refunder"])
	team := group("refund-team", refunders) // inherits orders-refunder
	viewers := group("viewers", "", f.Roles["orders-viewer"])
	join(refunders, bob)
	join(team, dave)
	join(viewers, bob)

	for _, c := range []struct{ what, path string }{
		{"removing a member", org + "/groups/" + refunders + "/members/" + bob},
		{"removing a member of a group that inherits the role", org + "/groups/" + team + "/members/" + dave},
		{"deleting a leaf group that inherits the role", org + "/groups/" + team},
		{"deleting the group", org + "/groups/" + refunders},
	} {
		if r := h.API("DELETE", c.path, carol, nil); r.Status != 403 || r.Str("code") != "grant_ceiling_exceeded" {
			t.Errorf("%s by an administrator beyond the group's roles: %d %s", c.what, r.Status, r.Raw)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	// The refusals changed nothing: the groups, their grant and members stay.
	for _, g := range []struct{ group, member string }{{refunders, bob}, {team, dave}} {
		if m := string(f.must(f.AdminAPI("GET", org+"/groups/"+g.group+"/members", nil), 200, "members").Raw); !strings.Contains(m, g.member) {
			t.Fatalf("refused removal applied: %s", m)
		}
	}
	if !holdsRefund(bob) || !holdsRefund(dave) {
		t.Fatal("a refused removal took the group's role")
	}

	// Within the administrator's ceiling, removal works.
	mustStatus(t, h.API("DELETE", org+"/groups/"+viewers+"/members/"+bob, carol, nil), 204, "removing a member within the ceiling")
	mustStatus(t, h.API("DELETE", org+"/groups/"+viewers, carol, nil), 204, "deleting a group within the ceiling")
	// A realm administrator can assign every role and removes the rest.
	f.must(f.AdminAPI("DELETE", org+"/groups/"+team+"/members/"+dave, nil), 204, "administrator removes a member")
	f.must(f.AdminAPI("DELETE", org+"/groups/"+team, nil), 204, "administrator deletes the leaf group")
	f.must(f.AdminAPI("DELETE", org+"/groups/"+refunders, nil), 204, "administrator deletes the group")
	if holdsRefund(bob) || holdsRefund(dave) {
		t.Fatal("removal left the group's role")
	}

	// A connector manages its own group without an administrator's ceiling:
	// the role an administrator granted to it is beyond the connector's
	// ceiling and carol's, yet the connector removes the member and deletes
	// the group.
	conn := f.must(f.AdminAPI("POST", org+"/provisioning-connectors", map[string]any{"name": "Okta",
		"role_ceiling_ids": []string{f.Roles["orders-viewer"]}}), 201, "connector")
	scim := func(method, path string, body any) *Resp {
		t.Helper()
		rq := Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: map[string]string{"Authorization": "Bearer " + conn.Str("token")}}
		if body != nil {
			rq.JSON = body
		}
		return h.Do(rq)
	}
	erin := scim("POST", "/Users", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "scim.erin",
		"emails": []map[string]any{{"value": "erin@globex.test", "primary": true}}, "active": true})
	mustStatus(t, erin, 201, "provision user")
	sg := scim("POST", "/Groups", map[string]any{"displayName": "Refund Desk", "members": []map[string]any{{"value": erin.Str("id")}}})
	mustStatus(t, sg, 201, "provision group")
	f.must(f.AdminAPI("POST", org+"/groups/"+sg.Str("id")+"/roles", map[string]any{"role_id": f.Roles["orders-refunder"]}), 201, "administrator grant")
	rm := scim("PATCH", "/Groups/"+sg.Str("id"), map[string]any{"Operations": []map[string]any{{"op": "remove",
		"path": fmt.Sprintf(`members[value eq "%s"]`, erin.Str("id"))}}})
	if rm.Status != 200 || len(rm.Get("members").([]any)) != 0 {
		t.Fatalf("connector removes a member of its group: %d %s", rm.Status, rm.Raw)
	}
	mustStatus(t, scim("DELETE", "/Groups/"+sg.Str("id"), nil), 204, "connector deletes its group")
	var left int
	if err := h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1`,
		sg.Str("id")).Scan(&left); err != nil || left != 0 {
		t.Fatalf("connector deletion left %d group assignments: %v", left, err)
	}
}

// TestGroupRoleUnassignRoute covers TEN-007, TEN-008 and MFA-003 for
// DELETE /organizations/{org}/groups/{group}/roles/{assignment}: an
// organization administrator with org.roles.assign, acting from an MFA
// session, removes a group's role within their delegable set; a role beyond
// it is refused with 403 grant_ceiling_exceeded. The assignment must be that
// group's in that organization: another group's, another organization's or
// a user's assignment is not found (404) and stays.
func TestGroupRoleUnassignRoute(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	globex, acme := "/organizations/"+f.Globex, "/organizations/"+f.Acme
	group := func(org, name string) string {
		t.Helper()
		return f.must(f.AdminAPI("POST", org+"/groups", map[string]any{"name": name}), 201, "group "+name).Str("id")
	}
	grant := func(org, g, role string) string {
		t.Helper()
		return f.must(f.AdminAPI("POST", org+"/groups/"+g+"/roles", map[string]any{"role_id": role}), 201, "group grant").Str("id")
	}
	viewers, refunders, other, acmeTeam := group(globex, "viewers"), group(globex, "refunders"), group(globex, "other"), group(acme, "acme-team")
	f.must(f.AdminAPI("POST", globex+"/groups/"+viewers+"/members", map[string]any{"membership_id": f.MemberGlobex["bob"]}), 204, "join")
	viewerGrant := grant(globex, viewers, f.Roles["orders-viewer"])
	refunderGrant := grant(globex, refunders, f.Roles["orders-refunder"])
	otherGrant := grant(globex, other, f.Roles["orders-viewer"])
	acmeGrant := grant(acme, acmeTeam, f.Roles["orders-viewer"])
	userGrant := f.must(f.AdminAPI("POST", globex+"/members/"+f.MemberGlobex["bob"]+"/roles", map[string]any{"role_id": f.Roles["billing-viewer"]}),
		201, "user grant").Str("id")
	path := func(org, g, assignment string) string { return org + "/groups/" + g + "/roles/" + assignment }
	exists := func(id string) bool {
		t.Helper()
		var n int
		if err := h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM role_assignments WHERE id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	// Removing a role is authority administration: an MFA session is required.
	single := f.AccountToken("carol").Tokens.Str("access_token")
	if r := h.API("DELETE", path(globex, viewers, viewerGrant), single, nil); r.Status != 403 || r.Str("code") != "mfa_required" {
		t.Fatalf("group role removal from a single-factor session: %d %s", r.Status, r.Raw)
	}
	f.EnrollTOTP("carol")
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex admin, MFA session

	if r := h.API("DELETE", path(globex, refunders, refunderGrant), carol, nil); r.Status != 403 || r.Str("code") != "grant_ceiling_exceeded" {
		t.Errorf("removing a group role beyond the ceiling: %d %s", r.Status, r.Raw)
	}
	for _, c := range []struct{ what, path string }{
		{"another group's assignment", path(globex, viewers, otherGrant)},
		{"another organization's assignment", path(globex, viewers, acmeGrant)},
		{"another organization's group in this organization", path(globex, acmeTeam, acmeGrant)},
		{"another organization's group", path(acme, acmeTeam, acmeGrant)},
		{"a user's assignment", path(globex, viewers, userGrant)},
		{"an unknown assignment", path(globex, viewers, "ras_unknown")},
	} {
		if r := h.API("DELETE", c.path, carol, nil); r.Status != 404 {
			t.Errorf("%s: %d %s", c.what, r.Status, r.Raw)
		}
	}
	for _, id := range []string{viewerGrant, refunderGrant, otherGrant, acmeGrant, userGrant} {
		if !exists(id) {
			t.Fatalf("refused removal deleted assignment %s", id)
		}
	}

	mustStatus(t, h.API("DELETE", path(globex, viewers, viewerGrant), carol, nil), 204, "removing a group role within the ceiling")
	if exists(viewerGrant) {
		t.Fatal("group role still assigned")
	}
	var audited int
	if err := h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE type='role.unassigned' AND target_id=$1 AND actor_id=$2`,
		viewerGrant, f.Users["carol"]).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("role.unassigned audit: %d %v", audited, err)
	}
	mustStatus(t, h.API("DELETE", path(globex, viewers, viewerGrant), carol, nil), 404, "removing it again")
	// A realm administrator can assign the refunder role and removes it.
	f.must(f.AdminAPI("DELETE", path(globex, refunders, refunderGrant), nil), 204, "administrator removes a group role")
}
