package e2e

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/configuration"
)

// TestProjectScopedRoles covers AZ-002: a role assigned at project scope is
// evaluated, for that project only. Dave's only grant of widgets.manage is a
// role of project Widgets (owned by acme). The decision API allows it for a
// resource of that project (alone, or in acme's context) and nowhere else:
// not for another project, not at organization or realm level, not in an
// organization the project does not belong to; an unknown project denies.
// Explicit denies still override, decision cache keys differ per project,
// the permission views show it only with the project, and the token
// endpoint grants a scope requiring widgets.manage only for a resource of
// that project.
func TestProjectScopedRoles(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": "widgets.manage"}), 201, "permission")
	project := func(name, owner string) string {
		return f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": name, "owner_organization_id": owner}), 201, "project "+name).Str("id")
	}
	widgets, gadgets, sprockets := project("Widgets", f.Acme), project("Gadgets", f.Acme), project("Sprockets", f.Globex)
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": widgets, "name": "widget-admin",
		"permissions": []string{"widgets.manage"}}), 201, "project role").Str("id")
	dave := f.CreateUser("dave")
	for _, org := range []string{f.Acme, f.Globex} {
		f.must(f.AdminAPI("POST", "/organizations/"+org+"/members", map[string]any{"user_id": dave, "role_ids": []string{}}), 201, "membership")
	}
	daveAcme := ""
	for _, it := range f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members", nil), 200, "members").Get("items").([]any) {
		if m := it.(map[string]any); m["user_id"] == dave {
			daveAcme, _ = m["id"].(string)
		}
	}
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": dave},
		"scope": map[string]any{"type": "project", "id": widgets}}), 201, "project assignment")

	check := func(res map[string]any) *Resp {
		t.Helper()
		return f.must(f.AdminAPI("POST", "/authorization/check", map[string]any{"subject": map[string]any{"type": "user", "id": dave},
			"action": "widgets.manage", "resource": res}), 200, "decision")
	}
	widget := func(extra ...string) map[string]any {
		res := map[string]any{"type": "widget", "id": "w1"}
		for i := 0; i+1 < len(extra); i += 2 {
			res[extra[i]] = extra[i+1]
		}
		return res
	}
	expect := func(what string, d *Resp, allowed bool, reason string) {
		t.Helper()
		if d.Get("allowed") != allowed || (reason != "" && d.Str("reason_code") != reason) {
			t.Fatalf("%s: %s, want allowed=%v %s", what, d.Raw, allowed, reason)
		}
	}

	t.Run("decision API evaluates project roles for their project only", func(t *testing.T) {
		inProject := check(widget("project_id", widgets))
		expect("resource of the project", inProject, true, "ALLOWED")
		expect("resource of the project in the owning organization", check(widget("project_id", widgets, "org_id", f.Acme)), true, "ALLOWED")
		other := check(widget("project_id", gadgets))
		expect("resource of another project", other, false, "NOT_PERMITTED")
		realm := check(widget())
		expect("realm level", realm, false, "NOT_PERMITTED")
		expect("organization level", check(widget("org_id", f.Acme)), false, "NOT_PERMITTED")
		expect("project of another organization", check(widget("project_id", sprockets, "org_id", f.Acme)), false, "PROJECT_ORGANIZATION_MISMATCH")
		expect("project outside the organization's context", check(widget("project_id", widgets, "org_id", f.Globex)), false, "PROJECT_ORGANIZATION_MISMATCH")
		expect("unknown project", check(widget("project_id", "prj_does_not_exist")), false, "UNKNOWN_PROJECT")

		// The decision cache key covers the project (AZ-019).
		keys := []string{inProject.Str("cache_key"), other.Str("cache_key"), realm.Str("cache_key")}
		if keys[0] == "" || keys[0] == keys[1] || keys[0] == keys[2] {
			t.Fatalf("cache keys must be set and differ per project: %v", keys)
		}

		batch := f.must(f.AdminAPI("POST", "/authorization/check-batch", map[string]any{"checks": []map[string]any{
			{"subject": map[string]any{"id": dave}, "action": "widgets.manage", "resource": widget("project_id", widgets)},
			{"subject": map[string]any{"id": dave}, "action": "widgets.manage", "resource": widget("project_id", gadgets)},
			{"subject": map[string]any{"id": dave}, "action": "widgets.manage", "resource": widget("org_id", f.Acme)},
		}}), 200, "batch")
		ds := batch.Get("decisions").([]any)
		if ds[0].(map[string]any)["allowed"] != true || ds[1].(map[string]any)["allowed"] != false || ds[2].(map[string]any)["allowed"] != false {
			t.Fatalf("batch semantics differ from single checks (AZ-014): %s", batch.Raw)
		}
	})

	t.Run("subject tokens: the token's organization bounds the project", func(t *testing.T) {
		svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		tok := f.LoginWeb("dave", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		decide := func(projectID string) *Resp {
			return f.must(h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": tok, "action": "widgets.manage",
				"resource": widget("project_id", projectID)}), 200, "decision")
		}
		expect("project of the token's organization", decide(widgets), true, "ALLOWED")
		expect("project of another organization", decide(sprockets), false, "PROJECT_ORGANIZATION_MISMATCH")
	})

	t.Run("permission views show project grants only with the project", func(t *testing.T) {
		has := func(r *Resp) bool {
			t.Helper()
			mustStatus(t, r, 200, "permissions")
			return strings.Contains(jsonString(r.Get("permissions")), `"widgets.manage"`)
		}
		if !has(f.AdminAPI("GET", "/subjects/"+dave+"/permissions?project_id="+widgets, nil)) {
			t.Fatal("admin view with the project lacks the project grant")
		}
		if has(f.AdminAPI("GET", "/subjects/"+dave+"/permissions", nil)) || has(f.AdminAPI("GET", "/subjects/"+dave+"/permissions?organization_id="+f.Acme, nil)) {
			t.Fatal("project grant shown at realm or organization level")
		}
		mustStatus(t, f.AdminAPI("GET", "/subjects/"+dave+"/permissions?organization_id="+f.Globex+"&project_id="+widgets, nil), 422,
			"project outside the organization")
		self := f.AccountToken("dave").Tokens.Str("access_token")
		if !has(h.API("GET", "/me/permissions?organization_id="+f.Acme+"&project_id="+widgets, self, nil)) {
			t.Fatal("my permissions with the project lack the project grant")
		}
		if has(h.API("GET", "/me/permissions?organization_id="+f.Acme, self, nil)) {
			t.Fatal("my organization permissions include a project grant")
		}
	})

	t.Run("token scopes requiring the permission only for the project's resources", func(t *testing.T) {
		resource := func(name, aud, projectID, prefix string) string {
			body := map[string]any{"name": name, "audience": aud, "scopes": []map[string]any{{"name": prefix + ":read"},
				{"name": prefix + ":manage", "required_permissions": []string{"widgets.manage"}}}}
			if projectID != "" {
				body["project_id"] = projectID
			}
			id := f.must(f.AdminAPI("POST", "/resources", body), 201, "resource "+name).Str("id")
			mustStatus(t, f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+id, map[string]any{
				"allowed_scopes": []string{prefix + ":read", prefix + ":manage"}, "subject_types": []string{"user"}}), 204, "grant "+name)
			return aud
		}
		widgetsAud := resource("Widgets API", "https://widgets.test", widgets, "widgets")
		gadgetsAud := resource("Gadgets API", "https://gadgets.test", gadgets, "gadgets")
		plainAud := resource("Plain API", "https://plain.test", "", "plain")
		scopes := func(user, org, aud, prefix string) []string {
			t.Helper()
			lr := f.LoginWeb(user, org, aud, prefix+":read "+prefix+":manage")
			mustStatus(t, lr.Tokens, 200, "token for "+aud)
			return strings.Fields(lr.Tokens.Str("scope"))
		}
		if s := scopes("dave", f.Acme, widgetsAud, "widgets"); !slices.Contains(s, "widgets:manage") {
			t.Fatalf("project role did not qualify for its project's scope: %v", s)
		}
		if s := scopes("dave", f.Acme, gadgetsAud, "gadgets"); slices.Contains(s, "gadgets:manage") || !slices.Contains(s, "gadgets:read") {
			t.Fatalf("project role qualified for another project's scope: %v", s)
		}
		if s := scopes("dave", f.Acme, plainAud, "plain"); slices.Contains(s, "plain:manage") {
			t.Fatalf("project role qualified for a scope outside any project: %v", s)
		}
		if s := scopes("dave", f.Globex, widgetsAud, "widgets"); slices.Contains(s, "widgets:manage") {
			t.Fatalf("project role applied in an organization the project does not belong to: %v", s)
		}
		if s := scopes("bob", f.Acme, widgetsAud, "widgets"); slices.Contains(s, "widgets:manage") {
			t.Fatalf("subject without the project role received the scope: %v", s)
		}
	})

	t.Run("explicit denies override project grants (AZ-004)", func(t *testing.T) {
		deny := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles", map[string]any{"name": "no-widgets", "permissions": []string{"orders.read"},
			"denied_permissions": []string{"widgets.manage"}}), 201, "deny role").Str("id")
		f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+daveAcme+"/roles", map[string]any{"role_id": deny}), 201, "assign deny")
		expect("denied in the organization", check(widget("project_id", widgets, "org_id", f.Acme)), false, "NOT_PERMITTED")
		expect("project alone", check(widget("project_id", widgets)), true, "ALLOWED")
	})
}

// TestCompositeRoleBounds covers AZ-011 (with TEST-014): a project role
// cannot compose another project's role (422); a composite role whose
// expansion would exceed limits.max_role_expansion is refused with 422, both
// when its composites alone exceed the bound and when the new role tips it
// over; and evaluating held roles that together exceed the bound fails
// closed: decisions deny with EVALUATION_ERROR instead of granting.
func TestCompositeRoleBounds(t *testing.T) {
	f := fixtureOn(t, NewHarness(t, func(c *configuration.Config) { c.Limits.MaxRoleExpansion = 8 }))
	h := f.H

	t.Run("cross-project composition is refused", func(t *testing.T) {
		p1 := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Alpha"}), 201, "alpha").Str("id")
		p2 := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Beta"}), 201, "beta").Str("id")
		a := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": p1, "name": "alpha-reader",
			"permissions": []string{"orders.read"}}), 201, "alpha role").Str("id")
		r := f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": p2, "name": "beta-wrapper",
			"permissions": []string{"orders.read"}, "composite_role_ids": []string{a}})
		mustStatus(t, r, 422, "composing another project's role")
		if !strings.Contains(string(r.Raw), "another project") {
			t.Fatalf("refusal does not name the reason: %s", r.Raw)
		}
		f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": p1, "name": "alpha-wrapper",
			"permissions": []string{"orders.read"}, "composite_role_ids": []string{a}}), 201, "composing a role of the same project")
	})

	t.Run("composition beyond the evaluation bound is refused", func(t *testing.T) {
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": "gizmos.use"}), 201, "permission")
		realmRole := func(name string, composites ...string) *Resp {
			body := map[string]any{"boundary_type": "realm", "name": name, "permissions": []string{"gizmos.use"}}
			if len(composites) > 0 {
				body["composite_role_ids"] = composites
			}
			return f.AdminAPI("POST", "/roles", body)
		}
		// A chain g1 <- g2 <- ... <- g8 reaches 8 roles from g8: at the bound.
		top := ""
		for i := 1; i <= 8; i++ {
			var composites []string
			if top != "" {
				composites = []string{top}
			}
			top = f.must(realmRole(fmt.Sprintf("g%d", i), composites...), 201, fmt.Sprintf("g%d", i)).Str("id")
		}
		if r := realmRole("g9", top); r.Status != 422 || !strings.Contains(string(r.Raw), "max_role_expansion") {
			t.Fatalf("role one past the bound: %d %s", r.Status, r.Raw)
		}
		other := f.must(realmRole("g-other"), 201, "g-other").Str("id")
		if r := realmRole("g-wide", top, other); r.Status != 422 || !strings.Contains(string(r.Raw), "max_role_expansion") {
			t.Fatalf("composites past the bound: %d %s", r.Status, r.Raw)
		}

		// Held roles that together exceed the bound fail closed.
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": "gizmos.audit"}), 201, "permission")
		auditor := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "gizmo-auditor",
			"permissions": []string{"gizmos.audit"}}), 201, "auditor").Str("id")
		assign := func(role string) {
			f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["bob"]}}),
				201, "assign")
		}
		decide := func(action string, res map[string]any) *Resp {
			return f.must(f.AdminAPI("POST", "/authorization/check", map[string]any{"subject": map[string]any{"id": f.Users["bob"]},
				"action": action, "resource": res}), 200, "decision")
		}
		assign(auditor)
		if d := decide("gizmos.audit", map[string]any{"type": "gizmo"}); d.Get("allowed") != true {
			t.Fatalf("within the bound: %s", d.Raw)
		}
		assign(top) // bob now holds g8..g1 and gizmo-auditor: 9 roles to evaluate
		for _, c := range []struct {
			action string
			res    map[string]any
		}{
			{"gizmos.audit", map[string]any{"type": "gizmo"}},
			{"gizmos.use", map[string]any{"type": "gizmo"}},
			{"orders.read", map[string]any{"type": "order", "org_id": f.Acme}},
		} {
			if d := decide(c.action, c.res); d.Get("allowed") != false || d.Str("reason_code") != "EVALUATION_ERROR" {
				t.Fatalf("%s over an oversized role graph must deny: %s", c.action, d.Raw)
			}
		}
		if r := h.API("GET", "/me/permissions", f.AccountToken("bob").Tokens.Str("access_token"), nil); r.Status == 200 {
			t.Fatalf("permission view over an oversized role graph answered: %s", r.Raw)
		}
	})
}
