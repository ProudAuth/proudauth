package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/authorization"
)

// permissionsOf lists every registered permission, following cursors.
func (f *Fixture) permissionsOf(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	path := "/permissions?limit=100"
	for i := 0; i < 50; i++ {
		page := f.must(f.AdminAPI("GET", path, nil), 200, "permissions")
		for _, it := range page.Get("items").([]any) {
			out = append(out, it.(map[string]any))
		}
		next := page.Str("next_cursor")
		if next == "" {
			return out
		}
		path = "/permissions?limit=100&cursor=" + url.QueryEscape(next)
	}
	t.Fatal("permission listing did not end")
	return nil
}

// TestPermissionRegistry covers AZ-001: application permissions are
// registered under a namespace with a description, sensitivity, resource type
// and owning resource; names without a namespace, wildcards, whitespace,
// reserved identity-provider namespaces, unknown sensitivities and
// duplicates are refused.
func TestPermissionRegistry(t *testing.T) {
	f := NewFixture(t)
	f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": "orders.export", "description": "Export orders to CSV", "sensitivity": "high",
		"resource_type": "order", "owner_resource_id": f.Orders}), 201, "register")
	var got map[string]any
	for _, p := range f.permissionsOf(t) {
		if p["name"] == "orders.export" {
			got = p
		}
	}
	if got == nil || got["description"] != "Export orders to CSV" || got["sensitivity"] != "high" || got["resource_type"] != "order" ||
		got["owner_resource_id"] != f.Orders || got["namespace"] != "application" || got["built_in"] != false {
		t.Fatalf("registered permission: %v", got)
	}
	for name, body := range map[string]map[string]any{
		"no namespace":          {"name": "export"},
		"wildcard":              {"name": "orders.*"},
		"whitespace":            {"name": "orders .export"},
		"realm namespace":       {"name": "realm.users.erase"},
		"organization prefix":   {"name": "org.members.purge"},
		"support namespace":     {"name": "support.impersonation.extend"},
		"platform namespace":    {"name": "platform.tenants.delete"},
		"unknown sensitivity":   {"name": "orders.archive", "sensitivity": "extreme"},
		"oversized description": {"name": "orders.archive", "description": strings.Repeat("x", 1001)},
	} {
		if r := f.AdminAPI("POST", "/permissions", body); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	mustStatus(t, f.AdminAPI("POST", "/permissions", map[string]any{"name": "orders.export"}), 409, "duplicate")
}

// TestMembershipScopedRoles covers AZ-003: a user holds an organization role
// through the membership in that organization. It cannot be given to a
// non-member or at realm scope, it applies only inside its organization (not
// in the user's other organizations), and it ends with the membership.
func TestMembershipScopedRoles(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	assign := func(user, org string) *Resp {
		body := map[string]any{"role_id": f.Roles["billing-viewer"], "subject": map[string]any{"type": "user", "id": f.Users[user]}}
		if org != "" {
			body["scope"] = map[string]any{"type": "organization", "id": org}
		}
		return f.AdminAPI("POST", "/role-assignments", body)
	}
	if r := assign("alice", f.Globex); r.Status != 422 || !strings.Contains(string(r.Raw), "membership") {
		t.Fatalf("organization role for a non-member: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, assign("bob", ""), 422, "organization role as a realm-wide flag")
	as := assign("bob", f.Acme)
	mustStatus(t, as, 201, "assign in acme")
	if as.Str("membership_id") != f.MemberAcme["bob"] {
		t.Fatalf("assignment must reference bob's acme membership: %s", as.Raw)
	}
	bob := authorization.Subject{Type: authorization.SubjectUser, ID: f.Users["bob"]}
	holds := func(org, perm string) bool {
		t.Helper()
		eff, err := h.App.Authz.Effective(ctx, nil, h.Realm.ID, bob, authorization.Scope{Type: authorization.ScopeOrganization, ID: org})
		if err != nil {
			t.Fatal(err)
		}
		return eff.Has(perm)
	}
	if !holds(f.Acme, "billing.read") || holds(f.Globex, "billing.read") {
		t.Fatal("an acme role must apply in acme only")
	}
	mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "remove membership")
	if holds(f.Acme, "billing.read") || holds(f.Acme, "orders.read") {
		t.Fatal("organization roles outlived the membership")
	}
	if !holds(f.Globex, "orders.read") {
		t.Fatal("the other membership's roles must remain")
	}
}

// TestAdministrativeBoundaries covers AZ-005: built-in permissions are
// separated into realm, organization and support namespaces and application
// permissions into their own; organization roles cannot carry realm or
// support permissions, project (application) roles cannot carry any
// identity-provider permission, and a customer application role gives no
// access to the administration API.
func TestAdministrativeBoundaries(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	prefix := map[string]string{"realm": "realm.", "organization": "org.", "support": "support.", "platform": "platform."}
	for _, p := range f.permissionsOf(t) {
		name, ns := p["name"].(string), p["namespace"].(string)
		switch {
		case p["built_in"] == true && (prefix[ns] == "" || !strings.HasPrefix(name, prefix[ns])):
			t.Errorf("built-in permission %s is in namespace %s", name, ns)
		case p["built_in"] == false && ns != "application":
			t.Errorf("application permission %s is in namespace %s", name, ns)
		}
	}
	project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Customer portal"}), 201, "project").Str("id")
	for _, perm := range []string{"realm.users.read", "realm.settings.write", "org.members.write", "support.impersonation.start"} {
		r := f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "app-" + strings.ReplaceAll(perm, ".", "-"),
			"permissions": []string{perm}})
		if r.Status != 422 {
			t.Errorf("project role with %s: %d %s", perm, r.Status, r.Raw)
		}
	}
	f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "portal-reader",
		"permissions": []string{"orders.read"}}), 201, "application role")
	for _, perm := range []string{"realm.users.read", "support.impersonation.start"} {
		if r := f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "org-" + strings.ReplaceAll(perm, ".", "-"),
			"permissions": []string{perm}}); r.Status != 422 {
			t.Errorf("organization role with %s: %d %s", perm, r.Status, r.Raw)
		}
	}
	// Bob holds customer application roles (orders-viewer) only.
	bob := f.AdminTokenFor("bob").Tokens.Str("access_token")
	for _, path := range []string{"/users", "/clients", "/roles", "/organizations/" + f.Acme + "/members"} {
		if r := h.API("GET", path, bob, nil); r.Status != 403 && r.Status != 404 {
			t.Errorf("application role reached administration %s: %d", path, r.Status)
		}
	}
	if r := h.API("POST", "/roles", bob, map[string]any{"boundary_type": "organization", "organization_id": f.Acme, "name": "bob-role",
		"permissions": []string{"orders.read"}}); r.Status != 403 {
		t.Errorf("application role created a role: %d %s", r.Status, r.Raw)
	}
}
