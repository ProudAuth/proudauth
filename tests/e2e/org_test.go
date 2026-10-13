package e2e

import (
	"context"
	"fmt"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
	"strings"
	"testing"
	"time"
)

// TestOrganizationLifecycleAndValidation covers TEN-001 (suspend, reactivate,
// archive with access consequences) and TEN-002 (typed contact and locale).
func TestOrganizationLifecycleAndValidation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/organizations", map[string]any{"slug": "badloc", "display_name": "Bad", "locale": "not a locale"}), 422, "locale")
	mustStatus(t, f.AdminAPI("POST", "/organizations", map[string]any{"slug": "badcontact", "display_name": "Bad",
		"contact": map[string]any{"email": "nope"}}), 422, "contact email")
	mustStatus(t, f.AdminAPI("POST", "/organizations", map[string]any{"slug": "oddcontact", "display_name": "Odd",
		"contact": map[string]any{"pager": "123"}}), 422, "unknown contact field")
	mustStatus(t, f.AdminAPI("POST", "/organizations", map[string]any{"slug": "goodorg", "display_name": "Good", "locale": "pt-BR",
		"contact": map[string]any{"email": "ops@good.test", "name": "Ops"}}), 201, "valid organization")

	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens
	introspect := func() bool {
		r := h.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, bob.Str("access_token"))
		return r.Get("active") == true
	}
	if !introspect() {
		t.Fatal("token inactive before suspension")
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/suspend", map[string]any{"reason": "billing hold"}), 200, "suspend")
	if introspect() {
		t.Fatal("organization token still active after suspension")
	}
	refresh := h.TokenRequest(map[string][]string{"grant_type": {"refresh_token"}, "refresh_token": {bob.Str("refresh_token")}},
		"web-bff", f.Clients["web"].Secret)
	if refresh.Status == 200 {
		t.Fatal("refresh succeeded for a suspended organization")
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/reactivate", map[string]any{"reason": "paid"}), 200, "reactivate")
	mustStatus(t, f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens, 200, "sign-in after reactivation")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Globex+"/archive", map[string]any{"reason": "customer left"}), 200, "archive")
	if org := f.must(f.AdminAPI("GET", "/organizations/"+f.Globex, nil), 200, "org"); org.Str("state") != "archived" {
		t.Fatalf("archive state: %s", org.Raw)
	}
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	mustStatus(t, h.API("GET", "/organizations/"+f.Globex+"/members", carol, nil), 404, "archived organization administration")
	// USR-020: deleting the only owner would orphan Acme.
	r := f.AdminAPI("DELETE", "/users/"+f.Users["alice"], nil)
	if r.Status != 409 || !strings.Contains(string(r.Raw), f.Acme) {
		t.Fatalf("sole owner deleted: %d %s", r.Status, r.Raw)
	}
}

// TestMembershipLifecycle covers TEN-003 (invited and pending_approval
// memberships grant nothing until they become active) and INV-013 (join
// requests with reviewers and expiry).
func TestMembershipLifecycle(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"join_requests_enabled": true}}}), 200, "enable joins")
	f.CreateUser("dave")
	dave := f.AccountToken("dave").Tokens.Str("access_token")
	jr := h.API("POST", "/organizations/"+f.Acme+"/join-requests", dave, map[string]any{"reason": "new hire in sales"})
	mustStatus(t, jr, 201, "join request")
	stateOf := func(user string) string {
		var st string
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state FROM memberships WHERE organization_id=$1 AND user_id=$2
			ORDER BY created_at DESC LIMIT 1`, f.Acme, f.Users[user]).Scan(&st)
		return st
	}
	if st := stateOf("dave"); st != "pending_approval" {
		t.Fatalf("join request membership state: %q", st)
	}
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "dave@example.test", ExpectFail: true})
	if lr.Tokens != nil && lr.Tokens.Status == 200 {
		t.Fatal("pending_approval membership produced an organization token")
	}
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/join-requests/"+jr.Str("id")+"/decision", dave, map[string]any{"approve": true}), 404, "self-approval by non-reviewer")
	// Reviewers are told a request waits, without the requester's identity.
	notice := h.Mail("alice@example.test", "join_request")
	if notice == "" || strings.Contains(notice, "dave") {
		t.Fatalf("reviewer notice: %q", notice)
	}
	reviewers := "/organizations/" + f.Acme + "/join-requests/" + jr.Str("id") + "/reviewers"
	mustStatus(t, f.AdminAPI("POST", reviewers, map[string]any{"reviewer_ids": []string{f.Users["bob"]}}), 422, "reviewer without review permission")
	mustStatus(t, f.AdminAPI("POST", reviewers, map[string]any{"reviewer_ids": []string{f.Users["dave"]}}), 422, "requester as reviewer")
	mustStatus(t, f.AdminAPI("POST", reviewers, map[string]any{"reviewer_ids": []string{f.Users["alice"]}}), 204, "assign alice")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/join-requests/"+jr.Str("id")+"/decision", map[string]any{"approve": true, "reason": "ok"}), 204, "approve")
	if !strings.Contains(h.Mail("dave@example.test", "join_request_decision"), "approved") {
		t.Fatal("requester not told the outcome")
	}
	mine := f.must(h.API("GET", "/me/join-requests", dave, nil), 200, "my requests")
	if it := mine.Get("items").([]any); len(it) != 1 || it[0].(map[string]any)["state"] != "approved" || len(it[0].(map[string]any)["reviewer_ids"].([]any)) != 0 {
		t.Fatalf("own requests (reviewers must stay private): %s", mine.Raw)
	}
	if st := stateOf("dave"); st != "active" {
		t.Fatalf("approved membership state: %q", st)
	}
	mustStatus(t, f.LoginWeb("dave", f.Acme, f.OrdersAud, "orders:read").Tokens, 200, "sign-in after approval")

	// An invitation naming an existing account creates an invited membership
	// that revocation releases.
	f.CreateUser("erin")
	inv := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/invitations", map[string]any{"user_id": f.Users["erin"]}), 201, "invite erin")
	if st := stateOf("erin"); st != "invited" {
		t.Fatalf("invited membership state: %q", st)
	}
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/invitations/"+inv.Str("invitation.id")+"/revoke", nil), 204, "revoke")
	if st := stateOf("erin"); st != "removed" {
		t.Fatalf("revoked invitation left membership %q", st)
	}

	// The requester can withdraw a pending request.
	f.CreateUser("gus")
	gus := f.AccountToken("gus").Tokens.Str("access_token")
	gjr := f.must(h.API("POST", "/organizations/"+f.Acme+"/join-requests", gus, map[string]any{}), 201, "gus requests")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/join-requests/"+gjr.Str("id")+"/withdraw", dave, nil), 404, "someone else's request")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/join-requests/"+gjr.Str("id")+"/withdraw", gus, nil), 204, "withdraw")
	if st := stateOf("gus"); st != "removed" {
		t.Fatalf("withdrawn request left membership %q", st)
	}

	// Undecided requests expire and release their pending membership.
	f.CreateUser("finn")
	finn := f.AccountToken("finn").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/join-requests", finn, map[string]any{}), 201, "finn requests")
	h.Clock.Advance(15 * 24 * time.Hour)
	if _, err := h.App.Orgs.ExpireJoinRequests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := stateOf("finn"); st != "removed" {
		t.Fatalf("expired request left membership %q", st)
	}
}

// TestProjectLifecycle covers APP-001: owners, ownership transfer with a
// reason, and the clients, resources and organization grants of a project.
func TestProjectLifecycle(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	prj := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Storefront", "environment": "staging", "owner_user_id": f.Users["alice"]}), 201, "project")
	id := prj.Str("id")
	f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "storefront-web", "name": "Storefront", "client_type": "confidential",
		"project_id": id, "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://storefront.test/cb"}}), 201, "project client")
	f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Storefront API", "audience": "https://storefront.test", "project_id": id,
		"scopes": []map[string]any{{"name": "storefront:read"}}}), 201, "project resource")
	apps := f.must(f.AdminAPI("GET", "/projects/"+id+"/applications", nil), 200, "applications")
	if len(apps.Get("clients").([]any)) != 1 || len(apps.Get("resources").([]any)) != 1 {
		t.Fatalf("project applications: %s", apps.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/projects/"+id+"/ownership-transfer", map[string]any{"owner_user_id": f.Users["bob"]}), 422, "reason required")
	cur := f.must(f.AdminAPI("GET", "/projects/"+id, nil), 200, "project")
	tr := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/projects/" + id + "/ownership-transfer", Token: f.AdminToken,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"owner_user_id": f.Users["bob"], "owner_organization_id": f.Acme,
			"reason": "team change"}})
	mustStatus(t, tr, 200, "transfer")
	if tr.Str("owner_user_id") != f.Users["bob"] || tr.Str("owner_organization_id") != f.Acme {
		t.Fatalf("transfer result: %s", tr.Raw)
	}
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/projects/" + id + "/ownership-transfer", Token: f.AdminToken,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"owner_user_id": f.Users["carol"], "reason": "stale"}}), 412, "stale version")
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=project.ownership_transferred", nil), 200, "audit")
	if len(ev.Get("items").([]any)) != 1 {
		t.Fatalf("transfer not audited: %s", ev.Raw)
	}
}

// TestOrganizationRegistrationMode covers REG-001: an organization narrows
// registration in its own context (requested organization or owned domain).
func TestOrganizationRegistrationMode(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	setMode := func(mode string) {
		org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"registration_mode": mode}}}), 200, "mode "+mode)
	}
	register := func(email string) *Resp {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme})
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": start.Str("transaction_id"),
			"email": email, "password": "a brand new passphrase 2026"}, Headers: map[string]string{"X-Transaction-Token": cont}})
	}
	cur := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"registration_mode": "wide_open"}}}),
		422, "unknown mode")
	setMode("closed")
	if r := register("new1@example.test"); r.Status != 403 {
		t.Fatalf("registration into a closed organization: %d %s", r.Status, r.Raw)
	}
	setMode("invitation_only")
	if r := register("new2@example.test"); r.Status != 403 {
		t.Fatalf("uninvited registration into an invitation-only organization: %d %s", r.Status, r.Raw)
	}
	setMode("inherit")
	mustStatus(t, register("new3@example.test"), 201, "inherited public registration")
}

// TestOrganizationTemplates covers TEN-017: versioned onboarding templates
// with dry run and diff, idempotent application, and conflicts instead of
// silent rewrites of existing roles.
func TestOrganizationTemplates(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	doc := map[string]any{"policy": map[string]any{"mfa_required": true},
		"roles":  []map[string]any{{"name": "support-agent", "permissions": []string{"orders.read"}}},
		"groups": []map[string]any{{"name": "Support", "role_names": []string{"support-agent"}}}}
	mustStatus(t, f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "Bad Name", "document": doc}), 422, "invalid name")
	v1 := f.must(f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "standard-customer", "document": doc}), 201, "save v1")
	if v1.Get("version").(float64) != 1 {
		t.Fatalf("first version: %s", v1.Raw)
	}
	apply := func(tok, org string, body map[string]any) *Resp {
		return h.API("POST", "/organizations/"+org+"/template-applications", tok, body)
	}
	f.EnrollTOTP("carol")
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	dry := f.must(apply(carol, f.Globex, map[string]any{"template": "standard-customer", "dry_run": true}), 200, "dry run")
	if dry.Get("applied") != false || len(dry.Get("create").([]any)) != 3 || len(dry.Get("update").([]any)) != 1 {
		t.Fatalf("dry-run plan: %s", dry.Raw)
	}
	if r := f.must(f.AdminAPI("GET", "/organizations/"+f.Globex+"/groups", nil), 200, "groups"); strings.Contains(string(r.Raw), "Support") {
		t.Fatal("dry run created a group")
	}
	mustStatus(t, apply(carol, f.Acme, map[string]any{"template": "standard-customer"}), 404, "another organization")
	done := f.must(apply(carol, f.Globex, map[string]any{"template": "standard-customer"}), 200, "apply")
	if done.Get("applied") != true {
		t.Fatalf("apply: %s", done.Raw)
	}
	again := f.must(apply(carol, f.Globex, map[string]any{"template": "standard-customer"}), 200, "re-apply")
	if len(again.Get("create").([]any)) != 0 || len(again.Get("update").([]any)) != 0 {
		t.Fatalf("re-applying is not idempotent: %s", again.Raw)
	}
	// A new version that changes an existing role is a conflict, not a rewrite.
	doc["roles"] = []map[string]any{{"name": "support-agent", "permissions": []string{"orders.read", "orders.refund"}}}
	f.must(f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "standard-customer", "document": doc}), 201, "save v2")
	plan := f.must(apply(carol, f.Globex, map[string]any{"template": "standard-customer", "dry_run": true}), 200, "dry run v2")
	if plan.Get("version").(float64) != 2 || len(plan.Get("conflicts").([]any)) != 1 {
		t.Fatalf("v2 plan: %s", plan.Raw)
	}
	mustStatus(t, apply(carol, f.Globex, map[string]any{"template": "standard-customer"}), 409, "conflicting version")
	mustStatus(t, apply(carol, f.Globex, map[string]any{"template": "standard-customer", "version": 1}), 200, "pinned version")
	versions := f.must(f.AdminAPI("GET", "/organization-templates?name=standard-customer", nil), 200, "versions")
	if len(versions.Get("items").([]any)) != 2 {
		t.Fatalf("versions: %s", versions.Raw)
	}

	// Templates also provision the organization's clients and integrations:
	// organization-owned service principals with roles, and webhooks.
	integ := map[string]any{"roles": []map[string]any{{"name": "sync-bot", "permissions": []string{"orders.read"}}},
		"service_principals": []map[string]any{{"name": "billing-sync", "role_names": []string{"sync-bot"}}},
		"webhooks": []map[string]any{{"name": "Membership feed", "destination_url": "https://1.1.1.1/proudauth-template-test",
			"event_types": []string{"organization.membership.added"}}}}
	mustStatus(t, f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "bad-integrations", "document": map[string]any{
		"roles": []map[string]any{{"name": "x", "permissions": []string{"support.impersonation.start"}}}}}), 422, "support permission in a template role")
	f.must(f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "integrations", "document": integ}), 201, "save integrations")
	idry := f.must(apply(carol, f.Globex, map[string]any{"template": "integrations", "dry_run": true}), 200, "integrations dry run")
	if c := fmt.Sprint(idry.Get("create")); !strings.Contains(c, "service principal globex-billing-sync") || !strings.Contains(c, "webhook Membership feed") ||
		!strings.Contains(c, "grant sync-bot to service principal globex-billing-sync") {
		t.Fatalf("integrations plan: %s", idry.Raw)
	}
	// carol administers Globex but may not manage its integrations.
	if denied := apply(carol, f.Globex, map[string]any{"template": "integrations"}); denied.Status != 409 || !strings.Contains(string(denied.Raw), "org.integrations.write") {
		t.Fatalf("webhooks without org.integrations.write: %d %s", denied.Status, denied.Raw)
	}
	applied := f.must(apply(f.AdminToken, f.Globex, map[string]any{"template": "integrations"}), 200, "apply integrations")
	if applied.Get("applied") != true || !strings.HasPrefix(applied.Str("webhook_secrets.Membership feed"), "whsec_") {
		t.Fatalf("integrations apply: %s", applied.Raw)
	}
	var owner, scope string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT sp.owner_organization_id, ra.scope_id FROM service_principals sp
		JOIN role_assignments ra ON ra.subject_type='service_principal' AND ra.subject_id=sp.id WHERE sp.name='globex-billing-sync'`).Scan(&owner, &scope)
	if owner != f.Globex || scope != f.Globex {
		t.Fatalf("service principal ownership %q, role scope %q", owner, scope)
	}
	reapplied := f.must(apply(f.AdminToken, f.Globex, map[string]any{"template": "integrations"}), 200, "re-apply integrations")
	if len(reapplied.Get("create").([]any)) != 0 || reapplied.Get("webhook_secrets") != nil {
		t.Fatalf("re-applying integrations: %s", reapplied.Raw)
	}
}

// TestDynamicGroups covers TEN-014: group membership derived from
// authoritative attributes, recomputed with status, closed to manual changes,
// and never driven by attributes users can edit themselves.
func TestDynamicGroups(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{
			{Name: "department", Type: "string", MaxLength: 64, Visibility: "admin", Source: "directory"},
			{Name: "nickname", Type: "string", MaxLength: 64, UserEditable: true, Visibility: "self", Source: "local"},
		}
	}), 200, "schema")
	setDept := func(user, dept string) {
		t.Helper()
		u := f.must(f.AdminAPI("GET", "/users/"+f.Users[user], nil), 200, "user")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/users/" + f.Users[user], Token: f.AdminToken,
			Headers: map[string]string{"If-Match": u.Header.Get("ETag")}, JSON: map[string]any{"profile": map[string]any{"department": dept}}}), 200, "department "+user)
	}
	setDept("bob", "sales")
	setDept("alice", "engineering")
	grp := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Sales"}), 201, "group").Str("id")
	rulePath := "/organizations/" + f.Acme + "/groups/" + grp + "/dynamic-rule"
	mustStatus(t, f.AdminAPI("PUT", rulePath, map[string]any{"all": []map[string]any{{"attribute": "nickname", "equals": "boss"}}}), 422, "user-editable attribute")
	mustStatus(t, f.AdminAPI("PUT", rulePath, map[string]any{"all": []map[string]any{{"attribute": "unknown", "equals": "x"}}}), 422, "unknown attribute")
	st := f.must(f.AdminAPI("PUT", rulePath, map[string]any{"all": []map[string]any{{"attribute": "department", "equals": "sales"}}}), 200, "rule")
	if st.Get("member_count").(float64) != 1 || st.Str("recomputed_at") == "" {
		t.Fatalf("rule status: %s", st.Raw)
	}
	members := func() string {
		return string(f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/groups/"+grp+"/members", nil), 200, "members").Raw)
	}
	if m := members(); !strings.Contains(m, f.Users["bob"]) || strings.Contains(m, f.Users["alice"]) {
		t.Fatalf("dynamic members: %s", m)
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/members", map[string]any{"membership_id": f.MemberAcme["alice"]}), 409,
		"manual member of a dynamic group")
	// Attribute changes are picked up by recomputation.
	setDept("alice", "sales")
	setDept("bob", "support")
	runWorker(t, worker.New(h.App, "test"))
	if m := members(); strings.Contains(m, f.Users["bob"]) || !strings.Contains(m, f.Users["alice"]) {
		t.Fatalf("recomputed members: %s", m)
	}
	// Rule-driven changes are audited per member, with the causing actor.
	var added, removed, bySystem int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE type='group.member.added'), count(*) FILTER (WHERE type='group.member.removed'),
		count(*) FILTER (WHERE actor_type='system') FROM audit_events WHERE target_id=$1 AND metadata->>'source'='dynamic'`, grp).Scan(&added, &removed, &bySystem)
	if added != 2 || removed != 1 || bySystem != 2 {
		t.Fatalf("dynamic membership audit: added %d removed %d by system %d", added, removed, bySystem)
	}
	// AZ-010: rule-derived roles count only while recomputation is fresh.
	f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": "sales.forecast"}), 201, "permission")
	role := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles", map[string]any{"name": "forecaster", "permissions": []string{"sales.forecast"}}), 201,
		"role").Str("id")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/roles", map[string]any{"role_id": role}), 201, "group role")
	perms := func() string {
		return string(f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["alice"]+"/permissions", nil), 200, "permissions").Raw)
	}
	if !strings.Contains(perms(), "sales.forecast") {
		t.Fatalf("dynamic group role not effective: %s", perms())
	}
	h.Clock.Advance(2 * time.Hour)
	f.ReloginAdmin()
	if strings.Contains(perms(), "sales.forecast") {
		t.Fatal("stale dynamic membership still grants roles")
	}
	runWorker(t, worker.New(h.App, "test"))
	if !strings.Contains(perms(), "sales.forecast") {
		t.Fatal("recomputed dynamic membership does not grant roles again")
	}
	mustStatus(t, f.AdminAPI("DELETE", rulePath, nil), 204, "static again")
	// Removing the rule keeps its members, now as ordinary members.
	if !strings.Contains(perms(), "sales.forecast") || !strings.Contains(members(), f.Users["alice"]) {
		t.Fatal("removing the rule stripped its members")
	}
	h.Clock.Advance(2 * time.Hour)
	f.ReloginAdmin()
	if !strings.Contains(perms(), "sales.forecast") {
		t.Fatal("former rule members treated as stale dynamic members")
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/members", map[string]any{"membership_id": f.MemberAcme["bob"]}), 204,
		"manual member after the rule is removed")
}

// TestDynamicGroupSeparationSkips covers TEN-014 with AZ-018: a member whose
// roles conflict with the group's is left out, the skip is audited once
// rather than on every recomputation, and the member count counts only
// actual members.
func TestDynamicGroupSeparationSkips(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{{Name: "department", Type: "string", MaxLength: 64, Visibility: "admin", Source: "directory"}}
	}), 200, "schema")
	for _, user := range []string{"alice", "bob"} {
		u := f.must(f.AdminAPI("GET", "/users/"+f.Users[user], nil), 200, "user")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/users/" + f.Users[user], Token: f.AdminToken,
			Headers: map[string]string{"If-Match": u.Header.Get("ETag")}, JSON: map[string]any{"profile": map[string]any{"department": "finance"}}}), 200, "department "+user)
	}
	org := "/organizations/" + f.Acme
	payer := f.must(f.AdminAPI("POST", org+"/roles", map[string]any{"name": "payer", "permissions": []string{"orders.read"}}), 201, "payer")
	approver := f.must(f.AdminAPI("POST", org+"/roles", map[string]any{"name": "approver", "permissions": []string{"orders.read"},
		"incompatible_role_ids": []string{payer.Str("id")}}), 201, "approver")
	f.must(f.AdminAPI("POST", org+"/members/"+f.MemberAcme["alice"]+"/roles", map[string]any{"role_id": approver.Str("id")}), 201, "alice approver")
	grp := f.must(f.AdminAPI("POST", org+"/groups", map[string]any{"name": "Payers"}), 201, "group").Str("id")
	f.must(f.AdminAPI("POST", org+"/groups/"+grp+"/roles", map[string]any{"role_id": payer.Str("id")}), 201, "group role")
	st := f.must(f.AdminAPI("PUT", org+"/groups/"+grp+"/dynamic-rule", map[string]any{"all": []map[string]any{{"attribute": "department", "equals": "finance"}}}),
		200, "rule")
	if st.Get("member_count").(float64) != 1 {
		t.Fatalf("member count includes skipped members: %s", st.Raw)
	}
	skips := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='group.member.skipped' AND target_id=$1`, grp).Scan(&n)
		return n
	}
	if skips() != 1 {
		t.Fatalf("skip audited %d times", skips())
	}
	for range 2 {
		runWorker(t, worker.New(h.App, "test"))
	}
	var count int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT rule_member_count FROM groups WHERE id=$1`, grp).Scan(&count)
	if skips() != 1 || count != 1 {
		t.Fatalf("after recomputation: skip audited %d times, member count %d", skips(), count)
	}
	members := string(f.must(f.AdminAPI("GET", org+"/groups/"+grp+"/members", nil), 200, "members").Raw)
	if strings.Contains(members, f.Users["alice"]) || !strings.Contains(members, f.Users["bob"]) {
		t.Fatalf("members: %s", members)
	}
}

// TestOrganizationAliasesAndDomainRouting covers TEN-011: former slugs and
// aliases keep resolving and cannot be claimed by another organization, and
// email-domain routing is deterministic: exact verified domains win over a
// parent domain that opted into subdomains.
func TestOrganizationAliasesAndDomainRouting(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	oldSlug := org.Str("slug")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"slug": "acme-renamed"}}), 200, "rename")
	if o, err := h.App.Orgs.Resolve(ctx, h.Realm.ID, oldSlug); err != nil || o.ID != f.Acme {
		t.Fatalf("former slug does not resolve: %v", err)
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations", map[string]any{"slug": oldSlug, "display_name": "Impostor"}), 409, "claim a former slug")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/aliases", map[string]any{"alias": "acme-inc"}), 204, "alias")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Globex+"/aliases", map[string]any{"alias": "acme-inc"}), 409, "another organization's alias")
	if o, err := h.App.Orgs.Resolve(ctx, h.Realm.ID, "acme-inc"); err != nil || o.ID != f.Acme {
		t.Fatal("alias does not resolve")
	}
	aliases := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/aliases", nil), 200, "aliases")
	if !strings.Contains(string(aliases.Raw), oldSlug) || !strings.Contains(string(aliases.Raw), "acme-inc") {
		t.Fatalf("aliases: %s", aliases.Raw)
	}

	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	verify := func(orgID, domain string) string {
		t.Helper()
		ch := f.must(f.AdminAPI("POST", "/organizations/"+orgID+"/domains", map[string]any{"domain": domain}), 201, "domain "+domain)
		organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
		f.must(f.AdminAPI("POST", "/organizations/"+orgID+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify "+domain)
		return ch.Str("domain.id")
	}
	parent := verify(f.Acme, "route.test")
	route := func(domain string) string {
		id, _, _, err := h.App.Orgs.DiscoverByEmailDomain(ctx, h.Realm.ID, domain)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if route("eng.route.test") != "" {
		t.Fatal("subdomain routed without opting in")
	}
	mustStatus(t, f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/domains/"+parent, map[string]any{"include_subdomains": true}), 204, "include subdomains")
	if route("eng.route.test") != f.Acme || route("route.test") != f.Acme {
		t.Fatal("subdomain routing")
	}
	verify(f.Globex, "eng.route.test")
	if route("eng.route.test") != f.Globex || route("ops.route.test") != f.Acme {
		t.Fatal("an exact verified domain must win over a parent with subdomains")
	}
	// Deleting an organization releases its aliases with its slug.
	tmp := f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "short-lived", "display_name": "Short"}), 201, "org").Str("id")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+tmp+"/aliases", map[string]any{"alias": "short-alias"}), 204, "alias")
	f.must(f.AdminAPI("DELETE", "/organizations/"+tmp, nil), 202, "delete org")
	runWorker(t, worker.New(h.App, "test"))
	f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "short-alias", "display_name": "Reuse"}), 201, "reuse a released alias")
}

// TestOrganizationDeletionRequesterRechecked covers TEN-024 with INT-006: the
// deletion job finishes only while its requester still holds org.delete (an
// owner's authority counts although the deletion already closed the
// organization); a refused deletion stays closed and an administrator who
// holds the authority finishes it by requesting it again.
func TestOrganizationDeletionRequesterRechecked(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.CreateUser("olga")
	f.EnrollTOTP("olga")
	owned := func(slug string) string {
		org := f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": slug, "display_name": slug}), 201, "org").Str("id")
		f.must(f.AdminAPI("POST", "/organizations/"+org+"/members", map[string]any{"user_id": f.Users["olga"], "role_ids": []string{f.Roles["owner"]}}), 201, "owner")
		return org
	}
	state := func(org string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state FROM organizations WHERE id=$1`, org).Scan(&s)
		return s
	}
	first, second := owned("doomed-one"), owned("doomed-two")
	olga := f.AccountToken("olga").Tokens.Str("access_token")
	mustStatus(t, h.API("DELETE", "/organizations/"+first, olga, nil), 202, "owner deletes")
	runWorker(t, worker.New(h.App, "test"))
	if s := state(first); s != "deleted" {
		t.Fatalf("the owner's deletion did not finish: %s", s)
	}

	job := h.API("DELETE", "/organizations/"+second, olga, nil)
	mustStatus(t, job, 202, "owner deletes")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["olga"]+"/suspend", map[string]any{"reason": "left the company"}), 200, "suspend requester")
	runWorker(t, worker.New(h.App, "test"))
	if j := f.must(f.AdminAPI("GET", "/jobs/"+job.Str("job_id"), nil), 200, "job"); j.Str("state") != "dead_letter" || state(second) != "deleting" {
		t.Fatalf("deletion finished for a requester without authority: %s (%s)", j.Raw, state(second))
	}
	mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+second, nil), 202, "administrator resumes the deletion")
	runWorker(t, worker.New(h.App, "test"))
	if s := state(second); s != "deleted" {
		t.Fatalf("resumed deletion: %s", s)
	}
}

// TestOrganizationDeletionWorkflow covers TEN-024: the preview lists what a
// deletion affects and retains; deletion stops the organization's clients and
// integrations at once, erases export results and customer-owned
// credentials, and keeps the audit evidence.
func TestOrganizationDeletionWorkflow(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	org := f.Globex
	f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "globex feed", "organization_id": org, "destination_url": "https://1.1.1.1/globex",
		"event_types": []string{"organization.membership.added"}}), 201, "webhook")
	f.must(f.AdminAPI("PUT", "/organizations/"+org+"/notification-settings/smtp", map[string]any{"host": "smtp.globex.test", "port": 587,
		"tls_mode": "starttls", "username": "mailer", "password": "globex-smtp-secret"}), 200, "mail server")
	idp := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "globex-sso", "display_name": "Globex SSO", "issuer": "https://sso.globex.test",
		"organization_id": org, "client_secret": "upstream-secret", "config": map[string]any{"client_id": "pa"}}), 201, "identity provider").Str("id")
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "globex-sync", "owner_organization_id": org,
		"allowed_organization_ids": []string{org}}), 201, "service principal").Str("id")
	f.must(f.AdminAPI("POST", "/clients/"+f.Clients["web"].Ref+"/consent-preauthorizations", map[string]any{"organization_id": org,
		"scopes": []string{"orders:read"}, "reason": "procurement ticket 12"}), 201, "pre-authorization")
	f.must(f.AdminAPI("POST", "/audit-exports", map[string]any{"organization_id": org, "from": time.Now().Add(-time.Hour).Format(time.RFC3339),
		"to": time.Now().Add(time.Hour).Format(time.RFC3339)}), 202, "audit export")
	// A project the organization owns, with a client.
	prj := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Globex Portal", "owner_organization_id": org}), 201, "owned project").Str("id")
	pc := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "globex-portal", "name": "Globex Portal", "client_type": "confidential",
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://portal.globex.test/cb"}, "project_id": prj}), 201, "project client").Str("client.id")
	runWorker(t, worker.New(h.App, "test"))

	prev := f.must(f.AdminAPI("GET", "/organizations/"+org+"/deletion-preview", nil), 200, "preview")
	for _, k := range []string{"active_members", "owned_projects", "owned_clients", "role_assignments", "owned_service_principals", "webhook_subscriptions", "identity_providers",
		"consent_preauthorizations", "export_results", "retained_audit_events"} {
		if n, _ := prev.Get(k).(float64); n < 1 {
			t.Fatalf("preview %s: %s", k, prev.Raw)
		}
	}
	if prev.Get("mail_server_configured") != true || len(prev.Get("retained").([]any)) == 0 {
		t.Fatalf("preview: %s", prev.Raw)
	}
	auditBefore := int(prev.Get("retained_audit_events").(float64))

	f.must(f.AdminAPI("DELETE", "/organizations/"+org, nil), 202, "delete")
	state := func(q string, args ...any) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, q, args...).Scan(&s)
		return s
	}
	if state(`SELECT state FROM service_principals WHERE id=$1`, sp) != "disabled" || state(`SELECT state FROM identity_providers WHERE id=$1`, idp) != "disabled" ||
		state(`SELECT state FROM webhook_subscriptions WHERE organization_id=$1`, org) != "disabled" ||
		state(`SELECT count(*)::text FROM consent_preauthorizations WHERE organization_id=$1 AND revoked_at IS NULL`, org) != "0" ||
		state(`SELECT count(*)::text FROM jobs WHERE organization_id=$1 AND result_ciphertext IS NOT NULL`, org) != "0" {
		t.Fatal("organization integrations or exports survived the start of deletion")
	}
	if state(`SELECT state FROM projects WHERE id=$1`, prj) != "suspended" || state(`SELECT state FROM clients WHERE id=$1`, pc) != "suspended" {
		t.Fatal("owned projects and their clients survived the start of deletion")
	}
	runWorker(t, worker.New(h.App, "test"))
	if state(`SELECT state FROM organizations WHERE id=$1`, org) != "deleted" {
		t.Fatal("deletion did not finish")
	}
	if state(`SELECT count(*)::text FROM notification_settings WHERE organization_id=$1`, org) != "0" ||
		state(`SELECT count(*)::text FROM webhook_subscriptions WHERE organization_id=$1`, org) != "0" ||
		state(`SELECT count(*)::text FROM identity_providers WHERE id=$1 AND secret_ciphertext IS NOT NULL`, idp) != "0" {
		t.Fatal("customer-owned credentials survived the deletion")
	}
	if state(`SELECT count(*)::text FROM client_credentials WHERE client_ref=$1 AND (state <> 'revoked' OR secret_digest IS NOT NULL)`, pc) != "0" {
		t.Fatal("credentials of the organization's clients survived the deletion")
	}
	var after int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1`, org).Scan(&after)
	if after < auditBefore {
		t.Fatalf("audit evidence removed: %d before, %d after", auditBefore, after)
	}
}

// TestOrganizationPartialUpdate: PATCH changes only the members it names;
// omitted members keep their values and an explicit empty string clears.
func TestOrganizationPartialUpdate(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	patch := func(body map[string]any) *Resp {
		t.Helper()
		return f.must(h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Globex, Token: f.AdminToken, JSON: body}), 200, "patch")
	}
	patch(map[string]any{"locale": "de", "time_zone": "Europe/Berlin", "external_id": "crm-42"})
	if o := patch(map[string]any{"display_name": "Globex AG"}); o.Str("locale") != "de" || o.Str("time_zone") != "Europe/Berlin" || o.Str("external_id") != "crm-42" {
		t.Fatalf("omitted members cleared: %s", o.Raw)
	}
	if o := patch(map[string]any{"external_id": ""}); o.Str("external_id") != "" || o.Str("locale") != "de" {
		t.Fatalf("explicit clear: %s", o.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "spoof", "name": "Spoof", "client_type": "confidential",
		"grant_types": []string{"client_credentials"}, "access_token_claims": map[string]any{"email": "ceo@example.test"}}), 422, "static email claim")
}
