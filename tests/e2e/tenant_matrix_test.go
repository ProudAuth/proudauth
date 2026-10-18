package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/worker"
)

// TestTenantCrossingMatrix covers SEC-017: for every organization-scoped
// resource family, an administrator of another organization is refused (404
// concealment, never a partial result), and organization administrators cannot
// escalate to realm administration through any tenant route. Control requests
// against the administrator's own organization succeed, so a refusal is not an
// artifact of a broken route. Worker, export and stream paths are covered at
// the end.
// Requirements: API-003 (the organization in the path is a selector checked
// against the caller's authority), DOM-007 (reads, writes, jobs and audit
// queries are scoped to the organization), DOM-008 (refusals disclose no
// other organization's members, policy, connections or data).
func TestTenantCrossingMatrix(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.EnrollTOTP("carol")
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex admin with an MFA session
	alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner

	// Acme objects that carol must never reach.
	grp := f.must(h.API("POST", "/organizations/"+f.Acme+"/groups", alice, map[string]any{"name": "acme-team"}), 201, "acme group").Str("id")
	inv := f.must(h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "target@example.test"}), 201, "acme invite").Str("invitation.id")
	dom := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains", map[string]any{"domain": "acme-corp.test"}), 201, "acme domain").Str("domain.id")
	role := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles", map[string]any{"name": "acme-only", "permissions": []string{"orders.read"}}), 201, "acme role").Str("id")
	bobAcme := f.MemberAcme["bob"]
	f.must(h.API("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/members", alice, map[string]any{"membership_id": bobAcme}), 204, "acme group member")
	grpRole := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/roles", map[string]any{"role_id": role}), 201, "acme group role").Str("id")

	acme := "/organizations/" + f.Acme
	cases := []struct {
		family, method, path string
		body                 map[string]any
	}{
		{"organization", "GET", acme, nil},
		{"organization", "PATCH", acme, map[string]any{"display_name": "pwned"}},
		{"organization", "GET", acme + "/deletion-preview", nil},
		{"organization", "DELETE", acme, nil},
		{"members", "GET", acme + "/members", nil},
		{"members", "GET", acme + "/members/" + bobAcme, nil},
		{"members", "GET", acme + "/members/" + bobAcme + "/permissions", nil},
		{"members", "PATCH", acme + "/members/" + bobAcme, map[string]any{"state": "suspended"}},
		{"members", "DELETE", acme + "/members/" + bobAcme, nil},
		{"members", "POST", acme + "/members", map[string]any{"user_id": f.Users["carol"]}},
		{"roles", "GET", acme + "/roles", nil},
		{"roles", "POST", acme + "/roles", map[string]any{"name": "x", "permissions": []string{"orders.read"}}},
		{"roles", "POST", acme + "/roles/" + role + "/permissions", map[string]any{"add": []string{"orders.refund"}}},
		{"roles", "POST", acme + "/members/" + bobAcme + "/roles", map[string]any{"role_id": f.Roles["orders-refunder"]}},
		{"invitations", "GET", acme + "/invitations", nil},
		{"invitations", "POST", acme + "/invitations", map[string]any{"email": "x@example.test"}},
		{"invitations", "POST", acme + "/invitations/batch", map[string]any{"items": []map[string]any{{"email": "y@example.test"}}}},
		{"invitations", "POST", acme + "/invitations/" + inv + "/resend", nil},
		{"invitations", "POST", acme + "/invitations/" + inv + "/revoke", nil},
		{"invitations", "POST", acme + "/invitations/" + inv + "/reassign", map[string]any{"email": "z@example.test", "reason": "takeover"}},
		{"join-requests", "GET", acme + "/join-requests", nil},
		{"groups", "GET", acme + "/groups", nil},
		{"groups", "GET", acme + "/groups/" + grp, nil},
		{"groups", "PATCH", acme + "/groups/" + grp, map[string]any{"name": "pwned"}},
		{"groups", "DELETE", acme + "/groups/" + grp, nil},
		{"groups", "GET", acme + "/groups/" + grp + "/members", nil},
		{"groups", "POST", acme + "/groups/" + grp + "/members", map[string]any{"membership_id": bobAcme}},
		{"groups", "POST", acme + "/groups/" + grp + "/roles", map[string]any{"role_id": f.Roles["orders-refunder"]}},
		{"groups", "DELETE", acme + "/groups/" + grp + "/roles/" + grpRole, nil},
		{"groups", "DELETE", acme + "/groups/" + grp + "/members/" + bobAcme, nil},
		{"domains", "GET", acme + "/domains", nil},
		{"domains", "POST", acme + "/domains", map[string]any{"domain": "evil.test"}},
		{"domains", "POST", acme + "/domains/" + dom + "/verify", nil},
		{"domains", "DELETE", acme + "/domains/" + dom, nil},
		{"audit", "GET", acme + "/audit-events", nil},
		{"identity-providers", "GET", acme + "/identity-providers", nil},
		{"support", "POST", acme + "/ownership-transfers", map[string]any{"new_owner_membership_id": bobAcme}},
	}
	for _, c := range cases {
		r := h.Do(Req{Method: c.method, Path: "/api/v1/realms/main" + c.path, Token: carol, JSON: c.body})
		if r.Status != 404 {
			t.Errorf("[%s] %s %s by another organization's administrator: %d %s", c.family, c.method, c.path, r.Status, r.Raw)
		}
		// The random request ID can contain any letters; leave it out.
		body := strings.Replace(string(r.Raw), r.Str("request_id"), "", 1)
		if strings.Contains(body, "acme") || strings.Contains(body, f.Users["bob"]) {
			t.Errorf("[%s] %s %s leaked tenant data: %s", c.family, c.method, c.path, r.Raw)
		}
	}
	// Control: the same administrator can use the same routes in Globex.
	mustStatus(t, h.API("GET", "/organizations/"+f.Globex+"/members", carol, nil), 200, "own organization members")
	mustStatus(t, h.API("GET", "/organizations/"+f.Globex+"/groups", carol, nil), 200, "own organization groups")

	// Role escalation through tenant routes.
	for _, c := range []struct {
		what string
		r    *Resp
	}{
		{"organization role carrying realm permissions", h.API("POST", "/organizations/"+f.Globex+"/roles", carol,
			map[string]any{"name": "sneaky", "permissions": []string{"realm.users.write"}})},
		{"assigning a realm role through a membership", h.API("POST", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"]+"/roles", carol,
			map[string]any{"role_id": f.Roles["realm-admin"]})},
		{"granting ownership without being an owner", h.API("POST", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"]+"/roles", carol,
			map[string]any{"role_id": f.Roles["owner"]})},
		{"realm administration API", h.API("GET", "/users", carol, nil)},
		{"realm role assignment API", h.API("POST", "/role-assignments", carol, map[string]any{"role_id": f.Roles["realm-admin"],
			"subject": map[string]any{"type": "user", "id": f.Users["carol"]}})},
	} {
		if c.r.Status < 400 {
			t.Errorf("escalation accepted (%s): %d %s", c.what, c.r.Status, c.r.Raw)
		}
	}

	// Worker, export and stream paths.
	job := h.API("POST", "/me/exports", alice, nil)
	mustStatus(t, job, 202, "alice export")
	runWorker(t, worker.New(h.App, "test"))
	mustStatus(t, h.API("GET", "/jobs/"+job.Str("job_id"), carol, nil), 404, "another user's job")
	mustStatus(t, h.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", carol, nil), 404, "another user's export download")
	if r := h.API("GET", "/session-events?from=now", carol, nil); r.Status != 401 && r.Status != 403 {
		t.Errorf("organization administrator read the realm session stream: %d", r.Status)
	}
	if r := h.API("GET", "/hooks", carol, nil); r.Status != 401 && r.Status != 403 {
		t.Errorf("organization administrator listed realm hooks: %d", r.Status)
	}
	if r := h.API("GET", "/webhooks", carol, nil); r.Status != 401 && r.Status != 403 {
		t.Errorf("organization administrator listed realm webhooks: %d", r.Status)
	}
	var acmeAudit int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE organization_id=$1`, f.Acme).Scan(&acmeAudit)
	globex := h.API("GET", "/organizations/"+f.Globex+"/audit-events", carol, nil)
	if strings.Contains(string(globex.Raw), f.Acme) && acmeAudit > 0 {
		t.Error("organization audit view includes another organization's events")
	}
}
