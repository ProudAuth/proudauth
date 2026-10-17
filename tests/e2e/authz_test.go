package e2e

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestInactiveSubjectsHoldNoPermissions covers AZ-007 with USR-003: a
// suspended account, or a disabled service principal, holds no effective
// permission in any scope, whatever assignments remain; reactivation
// restores them.
func TestInactiveSubjectsHoldNoPermissions(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	realmScope := authorization.Scope{Type: authorization.ScopeRealm, ID: h.Realm.ID}
	acme := authorization.Scope{Type: authorization.ScopeOrganization, ID: f.Acme}
	alice := authorization.Subject{Type: authorization.SubjectUser, ID: f.Users["alice"]}
	held := func(subj authorization.Subject, scope authorization.Scope) int {
		t.Helper()
		ps, err := h.App.Authz.Effective(ctx, nil, h.Realm.ID, subj, scope)
		if err != nil {
			t.Fatal(err)
		}
		return len(ps.Allow)
	}
	if held(alice, acme) == 0 {
		t.Fatal("fixture: alice holds permissions in acme")
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
	if n := held(alice, acme); n != 0 {
		t.Fatalf("suspended account holds %d permissions", n)
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate")
	if held(alice, acme) == 0 {
		t.Fatal("reactivated account holds no permissions")
	}

	svc := authorization.Subject{Type: authorization.SubjectService, ID: f.Clients["orders-rs"].SP}
	if held(svc, realmScope) == 0 {
		t.Fatal("fixture: orders-api holds realm permissions")
	}
	mustStatus(t, f.AdminAPI("POST", "/service-principals/"+svc.ID+"/disable", nil), 204, "disable")
	if n := held(svc, realmScope); n != 0 {
		t.Fatalf("disabled service principal holds %d permissions", n)
	}
}

// Requirements: NFR-001 (group recursion is bounded by limits.max_group_depth,
// also when a subtree moves; TEST-014 subtest), TEN-008 (no grant above the
// delegable set, directly, through composites or group nesting; TEST-010
// subtests), TEN-023 (an organization administrator cannot reset, suspend,
// recover or read a shared realm-wide account; TEST-012 subtest), AZ-006
// (creating roles, editing their permissions, assigning roles and delegating
// through groups are checked against the actor's delegable set).
func TestDelegationCeilings(t *testing.T) {
	f := NewFixture(t)
	// Changing roles is authority-changing organization administration: it
	// requires an MFA session (MFA-003), checked before any ceiling.
	single := f.AccountToken("carol").Tokens.Str("access_token")
	if r := f.H.API("POST", "/organizations/"+f.Globex+"/roles", single, map[string]any{"name": "x", "permissions": []string{"orders.read"}}); r.Str("code") != "mfa_required" {
		t.Fatalf("org role change without MFA: %d %s", r.Status, r.Raw)
	}
	f.EnrollTOTP("carol")
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex organization admin, MFA session

	t.Run("TEST-010 direct escalation", func(t *testing.T) {
		// An org admin cannot create a role with permissions they do not hold.
		r := f.H.API("POST", "/organizations/"+f.Globex+"/roles", carol, map[string]any{"name": "super", "permissions": []string{"org.ownership.transfer"}})
		mustStatus(t, r, 403, "ceiling on org permission")
		r = f.H.API("POST", "/organizations/"+f.Globex+"/roles", carol, map[string]any{"name": "refund", "permissions": []string{"orders.refund"}})
		mustStatus(t, r, 403, "ceiling on application permission")
		// Nor assign the owner role.
		r = f.H.API("POST", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"]+"/roles", carol, map[string]any{"role_id": f.Roles["owner"]})
		mustStatus(t, r, 403, "owner assignment above ceiling")
		// Nor realm-level permissions inside an organization role.
		r = f.H.API("POST", "/organizations/"+f.Globex+"/roles", carol, map[string]any{"name": "sneaky", "permissions": []string{"realm.users.write"}})
		if r.Status != 403 && r.Status != 422 {
			t.Fatalf("realm permission in org role: %d", r.Status)
		}
	})
	t.Run("TEST-010 indirect escalation through composites", func(t *testing.T) {
		ok := f.H.API("POST", "/organizations/"+f.Globex+"/roles", carol, map[string]any{"name": "viewer-plus", "permissions": []string{"orders.read"}})
		mustStatus(t, ok, 201, "within ceiling")
		r := f.H.API("POST", "/organizations/"+f.Globex+"/roles", carol, map[string]any{"name": "wrapper", "permissions": []string{"orders.read"},
			"composite_role_ids": []string{f.Roles["orders-refunder"]}})
		mustStatus(t, r, 403, "composite escalation")
		// Editing an existing role to add an out-of-ceiling permission is refused too.
		r = f.H.API("POST", "/organizations/"+f.Globex+"/roles/"+ok.Str("id")+"/permissions", carol, map[string]any{"add": []string{"orders.refund"}})
		mustStatus(t, r, 403, "edit escalation")
	})
	t.Run("TEST-010 escalation through group nesting", func(t *testing.T) {
		// A group holding the owner role: its descendants' members inherit it.
		admins := f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/groups", map[string]any{"name": "owners"}), 201, "owners group")
		f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/groups/"+admins.Str("id")+"/roles", map[string]any{"role_id": f.Roles["owner"]}), 201, "owner grant")
		child := f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "owners-child", "parent_id": admins.Str("id")})
		mustStatus(t, child, 201, "empty child group")
		r := f.H.API("POST", "/organizations/"+f.Globex+"/groups/"+child.Str("id")+"/members", carol, map[string]any{"membership_id": f.MemberGlobex["carol"]})
		mustStatus(t, r, 403, "joining a child of a privileged group")
		mine := f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "mine"})
		mustStatus(t, mine, 201, "own group")
		mustStatus(t, f.H.API("POST", "/organizations/"+f.Globex+"/groups/"+mine.Str("id")+"/members", carol, map[string]any{"membership_id": f.MemberGlobex["carol"]}),
			204, "joining an unprivileged group")
		r = f.H.API("PATCH", "/organizations/"+f.Globex+"/groups/"+mine.Str("id"), carol, map[string]any{"parent_id": admins.Str("id")})
		mustStatus(t, r, 403, "moving a group under a privileged parent")
		perms := f.H.API("GET", "/me/permissions?organization_id="+f.Globex, carol, nil)
		for _, p := range perms.Get("permissions").([]any) {
			if p == "org.ownership.transfer" {
				t.Fatal("org admin gained owner permissions through group nesting")
			}
		}
	})
	t.Run("TEST-012 org admin cannot change a shared user's global credentials", func(t *testing.T) {
		// Bob is shared between acme and globex; carol administers only globex.
		r := f.H.API("POST", "/users/"+f.Users["bob"]+"/credentials/password/compromised", carol, map[string]any{})
		if r.Status != 401 && r.Status != 403 {
			t.Fatalf("org admin reached global credential administration: %d", r.Status)
		}
		r = f.H.API("POST", "/users/"+f.Users["bob"]+"/suspend", carol, map[string]any{})
		if r.Status != 401 && r.Status != 403 {
			t.Fatalf("org admin suspended a realm-wide account: %d", r.Status)
		}
		// Nor reset bob's MFA through assisted recovery, nor read his
		// realm-wide record (TEN-023).
		r = f.H.API("POST", "/users/"+f.Users["bob"]+"/recovery-requests", carol, map[string]any{"reason": "lost phone", "reset_mfa": true})
		if r.Status != 401 && r.Status != 403 {
			t.Fatalf("org admin started an MFA reset of a shared user: %d", r.Status)
		}
		r = f.H.API("GET", "/users/"+f.Users["bob"], carol, nil)
		if r.Status != 401 && r.Status != 403 || strings.Contains(string(r.Raw), "bob@example.test") {
			t.Fatalf("org admin read a shared user's realm-wide record: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("TEST-013 self-edited attributes cannot escalate", func(t *testing.T) {
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		r := f.H.API("PATCH", "/me", bob, map[string]any{"admin_metadata": map[string]any{"role": "admin"}})
		mustStatus(t, r, 400, "unknown admin field rejected")
		r = f.H.API("PATCH", "/me", bob, map[string]any{"display_name": "Bobby"})
		mustStatus(t, r, 200, "allowed field")
		perms := f.H.API("GET", "/me/permissions?organization_id="+f.Globex, bob, nil)
		for _, p := range perms.Get("permissions").([]any) {
			if p == "org.members.write" {
				t.Fatal("profile edit changed permissions")
			}
		}
	})
	t.Run("TEST-014 cyclic and oversized graphs", func(t *testing.T) {
		g1 := f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "g1"})
		mustStatus(t, g1, 201, "g1")
		g2 := f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "g2", "parent_id": g1.Str("id")})
		mustStatus(t, g2, 201, "g2")
		r := f.H.API("PATCH", "/organizations/"+f.Globex+"/groups/"+g1.Str("id"), carol, map[string]any{"parent_id": g2.Str("id")})
		mustStatus(t, r, 422, "group cycle rejected")
		parent := g2.Str("id")
		var last *Resp
		for i := 0; i < 10; i++ {
			last = f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "deep" + string(rune('a'+i)), "parent_id": parent})
			if last.Status != 201 {
				break
			}
			parent = last.Str("id")
		}
		if last.Status != 422 {
			t.Fatalf("group depth must be bounded: %d", last.Status)
		}
		// Moving a subtree counts its own depth (TEN-013).
		top := f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "subtree-top"})
		below := f.H.API("POST", "/organizations/"+f.Globex+"/groups", carol, map[string]any{"name": "subtree-below", "parent_id": top.Str("id")})
		mustStatus(t, below, 201, "subtree")
		r = f.H.API("PATCH", "/organizations/"+f.Globex+"/groups/"+top.Str("id"), carol, map[string]any{"parent_id": parent})
		mustStatus(t, r, 422, "subtree moved beyond the depth limit")
		a := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "ra", "permissions": []string{"realm.users.read"}}), 201, "ra")
		b := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "rb", "permissions": []string{"realm.users.read"},
			"composite_role_ids": []string{a.Str("id")}}), 201, "rb")
		_ = b
	})
}

// TestOrgAuthorityGrantsNeedMFA covers MFA-003 with TEN-008 and TEN-013: an
// organization administrator who grants roles without the role routes (a
// member added with roles, an organization or project invitation with roles,
// alone or in a batch, the reassignment of such an invitation, joining a
// group that grants roles, moving a group under one, or a dynamic rule on
// one) must act from an MFA session, as on the role routes. Plain membership
// needs none, and the realm waiver (OrgAdminMFAOptional) still applies.
func TestOrgAuthorityGrantsNeedMFA(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{{Name: "department", Type: "string", MaxLength: 64, Visibility: "admin", Source: "directory"}}
	}), 200, "schema")
	org := "/organizations/" + f.Globex
	viewer := []string{f.Roles["orders-viewer"]} // within carol's ceiling
	dave, erin := f.CreateUser("dave"), f.CreateUser("erin")
	group := func(name string, roles ...string) string {
		t.Helper()
		id := f.must(f.AdminAPI("POST", org+"/groups", map[string]any{"name": name}), 201, "group "+name).Str("id")
		for _, r := range roles {
			f.must(f.AdminAPI("POST", org+"/groups/"+id+"/roles", map[string]any{"role_id": r}), 201, "group role")
		}
		return id
	}
	viewers, ruled, plain, open := group("viewers", viewer[0]), group("ruled", viewer[0]), group("plain"), group("open")
	pending := f.must(f.AdminAPI("POST", org+"/invitations", map[string]any{"email": "frank@example.test", "role_ids": viewer}), 201, "pending invitation")
	project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Globex Portal"}), 201, "project").Str("id")
	portal := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "portal-user",
		"permissions": []string{"orders.read"}}), 201, "project role").Str("id")
	f.must(f.AdminAPI("POST", "/projects/"+project+"/grants", map[string]any{"organization_id": f.Globex, "allowed_role_ids": []string{portal}}), 201, "grant")

	grants := []struct {
		what, method, path string
		body               map[string]any
		want               int
	}{
		{"adding a member with roles", "POST", org + "/members", map[string]any{"user_id": dave, "role_ids": viewer}, 201},
		{"an invitation with roles", "POST", org + "/invitations", map[string]any{"email": "ivy@example.test", "role_ids": viewer}, 201},
		{"a project invitation", "POST", org + "/invitations", map[string]any{"email": "pat@example.test", "purpose": "project_access",
			"project_id": project, "role_ids": []string{portal}}, 201},
		{"a batch with one role-granting entry", "POST", org + "/invitations/batch", map[string]any{"items": []map[string]any{
			{"email": "jo@example.test"}, {"email": "kim@example.test", "role_ids": viewer}}}, 200},
		{"reassigning a role-granting invitation", "POST", org + "/invitations/" + pending.Str("invitation.id") + "/reassign",
			map[string]any{"email": "frank.new@example.test", "reason": "ticket 77: address changed"}, 201},
		{"joining a role-granting group", "POST", org + "/groups/" + viewers + "/members", map[string]any{"membership_id": f.MemberGlobex["bob"]}, 204},
		{"moving a group under a role-granting parent", "PATCH", org + "/groups/" + plain, map[string]any{"parent_id": viewers}, 200},
		{"a dynamic rule on a role-granting group", "PUT", org + "/groups/" + ruled + "/dynamic-rule",
			map[string]any{"all": []map[string]any{{"attribute": "department", "equals": "sales"}}}, 200},
	}

	single := f.AccountToken("carol").Tokens.Str("access_token") // globex admin, password only
	for _, g := range grants {
		if r := h.API(g.method, g.path, single, g.body); r.Status != 403 || r.Str("code") != "mfa_required" {
			t.Errorf("%s from a single-factor session: %d %s", g.what, r.Status, r.Raw)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	// The refusals changed nothing.
	if m := string(f.must(f.AdminAPI("GET", org+"/groups/"+viewers+"/members", nil), 200, "group members").Raw); strings.Contains(m, f.MemberGlobex["bob"]) {
		t.Fatalf("refused group join applied: %s", m)
	}
	if g := f.must(f.AdminAPI("GET", org+"/groups/"+plain, nil), 200, "group"); g.Str("parent_id") != "" {
		t.Fatalf("refused group move applied: %s", g.Raw)
	}
	// Plain membership is not authority.
	mustStatus(t, h.API("POST", org+"/members", single, map[string]any{"user_id": erin}), 201, "adding a plain member")
	mustStatus(t, h.API("POST", org+"/invitations", single, map[string]any{"email": "lou@example.test"}), 201, "a plain invitation")
	mustStatus(t, h.API("POST", org+"/invitations/batch", single, map[string]any{"items": []map[string]any{{"email": "max@example.test"}}}), 200, "a plain batch")
	mustStatus(t, h.API("POST", org+"/groups/"+open+"/members", single, map[string]any{"membership_id": f.MemberGlobex["bob"]}), 204, "joining a plain group")
	// Where the realm waives MFA for organization administration, the grant
	// routes follow the role routes.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.OrgAdminMFAOptional = true }), 200, "waive")
	mustStatus(t, h.API("POST", org+"/invitations", single, map[string]any{"email": "waived@example.test", "role_ids": viewer}), 201, "a grant under the waiver")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.OrgAdminMFAOptional = false }), 200, "unwaive")

	f.EnrollTOTP("carol")
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	for _, g := range grants {
		mustStatus(t, h.API(g.method, g.path, carol, g.body), g.want, g.what+" from an MFA session")
	}
}

// TestLastOwnerProtection covers TEST-011 with TEN-006 and DB-007: the only
// owner cannot leave or be removed, and concurrent removals of the two owners
// serialize on the organization so exactly one succeeds.
func TestLastOwnerProtection(t *testing.T) {
	f := NewFixture(t)
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	// The only owner cannot leave or be removed.
	r := f.H.API("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["alice"], alice, nil)
	mustStatus(t, r, 409, "last owner self-removal")
	// TEST-011: concurrent attempts to remove two owners leave at least one.
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": f.Roles["owner"]}), 201, "bob owner")
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i, m := range []string{f.MemberAcme["alice"], f.MemberAcme["bob"]} {
		wg.Add(1)
		go func(i int, m string) {
			defer wg.Done()
			results[i] = f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+m, nil).Status
		}(i, m)
	}
	wg.Wait()
	ok := 0
	for _, s := range results {
		if s == 204 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one concurrent owner removal must succeed, got %v", results)
	}
	members := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members", nil), 200, "members")
	owners := 0
	for _, it := range members.Get("items").([]any) {
		for _, role := range it.(map[string]any)["roles"].([]any) {
			if role == "owner" {
				owners++
			}
		}
	}
	if owners != 1 {
		t.Fatalf("organization must keep one owner, has %d", owners)
	}
}

// TestPolicyDecisionContract covers the decision API contract: obligations,
// deny by default, and AZ-014 (bounded batches decide item by item exactly as
// individual checks do). Through the example orders API it also covers
// SDK-005's current-permission policy: a refund is denied for a subject
// without orders.refund and, with a step-up obligation, for one whose
// authentication is not strong and fresh enough.
func TestPolicyDecisionContract(t *testing.T) {
	f := NewFixture(t)
	s := f.StartServices(t)
	// Alice may refund but the decision carries a step-up obligation unless her
	// authentication is fresh and multi-factor; the resource cannot satisfy it, so it denies.
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read orders:write").Tokens.Str("access_token")
	st, body := call(t, "POST", s.OrdersURL+"/orders/ord_acme_1/refund", alice)
	if st != 403 || body["reason_code"] != "STEP_UP_REQUIRED" {
		t.Fatalf("refund without MFA: %d %v", st, body)
	}
	obs := body["obligations"].([]any)
	if len(obs) == 0 || obs[0].(map[string]any)["type"] != "reauthenticate" {
		t.Fatalf("missing obligation: %v", body)
	}
	// Bob lacks orders.refund entirely.
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read orders:write").Tokens.Str("access_token")
	st, body = call(t, "POST", s.OrdersURL+"/orders/ord_acme_1/refund", bob)
	if st != 403 || body["reason_code"] != "NOT_PERMITTED" {
		t.Fatalf("refund without permission: %d %v", st, body)
	}
	// A missing action denies by default (AZ-007).
	svc := f.MachineToken(f.Clients["orders-rs"], f.H.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	r := f.H.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "resource": map[string]any{"type": "order"}})
	mustStatus(t, r, 200, "decision")
	if r.Get("allowed") != false {
		t.Fatalf("empty action must deny: %s", r.Raw)
	}
	batch := f.H.API("POST", "/authorization/check-batch", svc, map[string]any{"checks": []map[string]any{
		{"subject_token": bob, "action": "orders.read", "resource": map[string]any{"type": "order", "id": "ord_acme_1", "org_id": f.Acme}},
		{"subject_token": bob, "action": "orders.read", "resource": map[string]any{"type": "order", "id": "ord_globex_1", "org_id": f.Globex}},
	}})
	mustStatus(t, batch, 200, "batch")
	ds := batch.Get("decisions").([]any)
	if ds[0].(map[string]any)["allowed"] != true || ds[1].(map[string]any)["allowed"] != false {
		t.Fatalf("batch semantics: %s", batch.Raw)
	}
	// AZ-014: each batch item decides exactly as the individual check does, and
	// batches are bounded by limits.max_batch_size.
	for i, org := range []string{f.Acme, f.Globex} {
		id := map[string]string{f.Acme: "ord_acme_1", f.Globex: "ord_globex_1"}[org]
		one := f.H.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": "orders.read",
			"resource": map[string]any{"type": "order", "id": id, "org_id": org}})
		mustStatus(t, one, 200, "individual decision")
		item := ds[i].(map[string]any)
		if one.Get("allowed") != item["allowed"] || one.Str("reason_code") != item["reason_code"] {
			t.Fatalf("batch item %d differs from the individual check: %v vs %s", i, item, one.Raw)
		}
	}
	tooMany := make([]map[string]any, f.H.Cfg.Limits.MaxBatchSize+1)
	for i := range tooMany {
		tooMany[i] = map[string]any{"subject_token": bob, "action": "orders.read", "resource": map[string]any{"type": "order", "org_id": f.Acme}}
	}
	mustStatus(t, f.H.API("POST", "/authorization/check-batch", svc, map[string]any{"checks": tooMany}), 422, "oversized batch")
}

// TestSeparationOfDuties covers AZ-018: incompatible roles are refused on the
// roles a subject would actually hold — through groups and their ancestors
// and through composites — not only direct assignments.
func TestSeparationOfDuties(t *testing.T) {
	f := NewFixture(t)
	org := "/organizations/" + f.Acme
	payer := f.must(f.AdminAPI("POST", org+"/roles", map[string]any{"name": "payer", "permissions": []string{"orders.read"}}), 201, "payer")
	approver := f.must(f.AdminAPI("POST", org+"/roles", map[string]any{"name": "approver", "permissions": []string{"orders.read"},
		"incompatible_role_ids": []string{payer.Str("id")}}), 201, "approver")
	bundle := f.must(f.AdminAPI("POST", org+"/roles", map[string]any{"name": "approver-bundle", "permissions": []string{"orders.read"},
		"composite_role_ids": []string{approver.Str("id")}}), 201, "bundle")

	// bob holds payer through a nested group.
	parent := f.must(f.AdminAPI("POST", org+"/groups", map[string]any{"name": "finance"}), 201, "finance")
	child := f.must(f.AdminAPI("POST", org+"/groups", map[string]any{"name": "finance-emea", "parent_id": parent.Str("id")}), 201, "child")
	f.must(f.AdminAPI("POST", org+"/groups/"+parent.Str("id")+"/roles", map[string]any{"role_id": payer.Str("id")}), 201, "payer to group")
	mustStatus(t, f.AdminAPI("POST", org+"/groups/"+child.Str("id")+"/members", map[string]any{"membership_id": f.MemberAcme["bob"]}), 204, "bob in child")

	mustStatus(t, f.AdminAPI("POST", org+"/members/"+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": approver.Str("id")}), 409,
		"incompatible with a role inherited from a parent group")
	mustStatus(t, f.AdminAPI("POST", org+"/members/"+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": bundle.Str("id")}), 409,
		"incompatible through a composite")

	// alice holds approver directly: she cannot join the payer group, and a
	// group of hers cannot be given payer.
	f.must(f.AdminAPI("POST", org+"/members/"+f.MemberAcme["alice"]+"/roles", map[string]any{"role_id": approver.Str("id")}), 201, "alice approver")
	mustStatus(t, f.AdminAPI("POST", org+"/groups/"+child.Str("id")+"/members", map[string]any{"membership_id": f.MemberAcme["alice"]}), 409,
		"joining a group with an incompatible role")
	solo := f.must(f.AdminAPI("POST", org+"/groups", map[string]any{"name": "alice-team"}), 201, "alice team")
	mustStatus(t, f.AdminAPI("POST", org+"/groups/"+solo.Str("id")+"/members", map[string]any{"membership_id": f.MemberAcme["alice"]}), 204, "alice team member")
	mustStatus(t, f.AdminAPI("POST", org+"/groups/"+solo.Str("id")+"/roles", map[string]any{"role_id": payer.Str("id")}), 409,
		"group grant incompatible with a member's role")
	mustStatus(t, f.AdminAPI("PATCH", org+"/groups/"+solo.Str("id"), map[string]any{"parent_id": parent.Str("id")}), 409,
		"moving a member under an incompatible ancestor")

	// An ended membership cannot be put back into groups.
	if _, err := f.H.App.D.DB.Pool.Exec(context.Background(), `UPDATE memberships SET state='removed' WHERE id=$1`, f.MemberAcme["bob"]); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, f.AdminAPI("POST", org+"/groups/"+solo.Str("id")+"/members", map[string]any{"membership_id": f.MemberAcme["bob"]}), 422, "removed membership")
}

// TestRoleLevelDeny covers AZ-004: a deny in any held role overrides allows
// from other roles, and the decision explains it.
func TestRoleLevelDeny(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	perms := func() string {
		return jsonString(f.must(h.API("GET", "/me/permissions?organization_id="+f.Acme, alice, nil), 200, "permissions").Get("permissions"))
	}
	if !strings.Contains(perms(), "orders.refund") {
		t.Fatalf("fixture: alice should hold orders.refund: %s", perms())
	}
	deny := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles", map[string]any{"name": "no-refunds", "permissions": []string{"orders.read"},
		"denied_permissions": []string{"orders.refund"}}), 201, "deny role")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["alice"]+"/roles", map[string]any{"role_id": deny.Str("id")}), 201, "assign")
	if p := perms(); strings.Contains(p, "orders.refund") || !strings.Contains(p, "orders.read") {
		t.Fatalf("role-level deny not applied: %s", p)
	}
}

// TestExchangeChainLimits covers TOK-017: delegation chains are bounded and
// machine tokens are never exchanged for a user's authority (MCH-015).
func TestExchangeChainLimits(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	exchange := func(client Client, clientID, subject, aud, scope string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subject},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {aud}, "scope": {scope}}, clientID, client.Secret)
	}
	// web-bff may also exchange billing tokens back into orders.
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}, "exchange_policy": map[string]any{"accept_from_audiences": []string{f.BillingAud}}}), 204, "grant")
	at := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	one := exchange(f.Clients["orders-rs"], "orders-rs", at, f.BillingAud, "billing:read")
	mustStatus(t, one, 200, "depth 1")
	two := exchange(f.Clients["web"], "web-bff", one.Str("access_token"), f.OrdersAud, "orders:read")
	mustStatus(t, two, 200, "depth 2")
	three := exchange(f.Clients["orders-rs"], "orders-rs", two.Str("access_token"), f.BillingAud, "billing:read")
	if three.Status != 400 || three.Str("error") != "invalid_grant" {
		t.Fatalf("chain beyond the limit: %d %s", three.Status, three.Raw)
	}
	machine := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme).Str("access_token")
	if r := exchange(f.Clients["web"], "web-bff", machine, f.OrdersAud, "orders:read"); r.Status != 400 || r.Str("error") != "invalid_grant" {
		t.Fatalf("machine token exchanged: %d %s", r.Status, r.Raw)
	}
}
