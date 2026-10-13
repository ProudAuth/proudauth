package e2e

import (
	"strings"
	"testing"
)

// TestAuthorizationInspection covers AZ-009: "my effective permissions" and
// scoped administrator inspection with provenance (direct, group, realm) and
// sensitive-policy redaction.
func TestAuthorizationInspection(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner
	g := f.must(h.API("POST", "/organizations/"+f.Acme+"/groups", alice, map[string]any{"name": "billing-team"}), 201, "group")
	f.must(h.API("POST", "/organizations/"+f.Acme+"/groups/"+g.Str("id")+"/members", alice, map[string]any{"membership_id": f.MemberAcme["bob"]}), 204, "group member")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+g.Str("id")+"/roles", map[string]any{"role_id": f.Roles["billing-viewer"]}), 201, "group role")
	pol := f.must(f.AdminAPI("POST", "/policies", map[string]any{"name": "secret-fraud-rules", "definition": map[string]any{
		"target": map[string]any{"actions": []string{"orders.*"}}, "rules": []map[string]any{{"id": "r1", "effect": "deny", "reason_code": "FRAUD",
			"when": map[string]any{"op": "eq", "attr": "context.risk", "value": "high"}}}}}), 201, "policy")
	f.must(f.AdminAPI("POST", "/policies/"+pol.Str("policy.id")+"/versions/1/publish", nil), 200, "publish")

	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mine := h.API("GET", "/me/permissions?organization_id="+f.Acme, bob, nil)
	mustStatus(t, mine, 200, "my permissions")
	via := map[string]string{}
	for _, s := range mine.Get("sources").([]any) {
		m := s.(map[string]any)
		via[m["role_name"].(string)] = m["via"].(string)
	}
	if via["orders-viewer"] != "organization" || via["billing-viewer"] != "group" {
		t.Fatalf("provenance: %s", mine.Raw)
	}
	if mine.Get("restricting_policies") != float64(1) || strings.Contains(string(mine.Raw), "secret-fraud-rules") {
		t.Fatalf("policy redaction for the account owner: %s", mine.Raw)
	}
	admin := f.must(f.AdminAPI("GET", "/subjects/"+f.Users["bob"]+"/permissions?organization_id="+f.Acme, nil), 200, "admin inspection")
	if !strings.Contains(string(admin.Raw), "secret-fraud-rules") {
		t.Fatalf("realm administrators with realm.policies.read see restricting policies: %s", admin.Raw)
	}
	// Organization administrators inspect members of their own organization
	// only, and never see realm-level role names.
	samMember := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["sam"], "role_ids": []string{f.Roles["member"]}}),
		201, "sam joins acme").Str("id")
	org := h.API("GET", "/organizations/"+f.Acme+"/members/"+samMember+"/permissions", alice, nil)
	mustStatus(t, org, 200, "org inspection")
	if strings.Contains(string(org.Raw), "support-operator") || !strings.Contains(string(org.Raw), `"redacted":true`) {
		t.Fatalf("realm role disclosed to an organization administrator: %s", org.Raw)
	}
	mustStatus(t, h.API("GET", "/organizations/"+f.Acme+"/members/"+samMember+"/permissions", bob, nil), 403, "member without org.roles.read")
	mustStatus(t, h.API("GET", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"]+"/permissions", alice, nil), 404, "other organization")
}
