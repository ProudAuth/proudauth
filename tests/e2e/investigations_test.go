package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestHistoricalEntitlements covers ADV-011: a user's entitlements at a past
// instant are rebuilt from retained evidence (assignments, memberships, role
// definitions as they stood, OAuth grants, policy revisions), with caveats
// instead of claims about application-owned facts.
func TestHistoricalEntitlements(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	beforeAll := h.Clock.Now().Add(-48 * time.Hour)
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "case-reviewer",
		"permissions": []string{"orders.read"}}), 201, "role").Str("id")
	h.Clock.Advance(time.Minute)
	assigned := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": role}), 201, "assign")
	assignment := assigned.Str("id")
	f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	h.Clock.Advance(time.Hour)
	t1 := h.Clock.Now()
	h.Clock.Advance(time.Hour)
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/roles/"+role+"/permissions", map[string]any{"add": []string{"billing.read"}}), 200, "change role")
	h.Clock.Advance(time.Hour)
	t2 := h.Clock.Now()
	h.Clock.Advance(time.Hour)
	f.ReloginAdmin()
	f.must(f.AdminAPI("DELETE", "/role-assignments/"+assignment, nil), 204, "unassign")
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"], nil), 204, "leave globex")
	h.Clock.Advance(time.Hour)
	t3 := h.Clock.Now()
	h.Clock.Advance(time.Minute)
	f.ReloginAdmin()

	ask := func(at time.Time) *Resp {
		t.Helper()
		return f.must(f.AdminAPI("POST", "/investigations/entitlements", map[string]any{"subject_type": "user", "subject_id": f.Users["bob"],
			"at": at.UTC().Format(time.RFC3339Nano), "reason": "INC-7"}), 200, "reconstruct")
	}
	held := func(r *Resp) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, it := range r.Get("assignments").([]any) {
			m := it.(map[string]any)
			out[m["role_name"].(string)] = m
		}
		return out
	}
	r1 := ask(t1)
	a := held(r1)["case-reviewer"]
	if a == nil || jsonString(a["permissions"]) != `["orders.read"]` || a["permissions_evidence"] != "reconstructed" {
		t.Fatalf("at t1: %s", r1.Raw)
	}
	if r1.Get("account_state") != "active" || len(r1.Get("memberships").([]any)) != 2 || len(r1.Get("oauth_grants").([]any)) == 0 {
		t.Fatalf("t1 memberships/grants: %s", r1.Raw)
	}
	if !strings.Contains(jsonString(r1.Get("permissions")), "orders.read") || strings.Contains(jsonString(r1.Get("permissions")), "billing.read") {
		t.Fatalf("t1 permissions: %v", r1.Get("permissions"))
	}
	r2 := ask(t2)
	if a := held(r2)["case-reviewer"]; a == nil || !strings.Contains(jsonString(a["permissions"]), "billing.read") {
		t.Fatalf("at t2 the role definition change is not reflected: %s", r2.Raw)
	}
	r3 := ask(t3)
	if held(r3)["case-reviewer"] != nil || len(r3.Get("memberships").([]any)) != 1 {
		t.Fatalf("at t3 ended entitlements still shown: %s", r3.Raw)
	}
	// Built-in roles are shown with their current definition, said so.
	if a := held(r3)["member"]; a == nil || a["permissions_evidence"] != "current_definition" {
		t.Fatalf("built-in role evidence: %s", r3.Raw)
	}
	if r3.Get("completeness.complete") != true || !strings.Contains(jsonString(r3.Get("completeness.caveats")), "Application-owned facts") {
		t.Fatalf("completeness: %s", r3.Raw)
	}
	early := ask(beforeAll)
	if early.Get("completeness.complete") != false || len(early.Get("assignments").([]any)) != 0 {
		t.Fatalf("before retained evidence: %s", early.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/investigations/entitlements", map[string]any{"subject_type": "user", "subject_id": f.Users["bob"],
		"at": t1.Format(time.RFC3339)}), 422, "reason required")
	mustStatus(t, f.AdminAPI("POST", "/investigations/entitlements", map[string]any{"subject_type": "user", "subject_id": f.Users["bob"],
		"at": h.Clock.Now().Add(time.Hour).Format(time.RFC3339), "reason": "x"}), 422, "future instant")
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=investigation.entitlements.reconstructed", nil), 200, "audit")
	if !strings.Contains(string(ev.Raw), "INC-7") {
		t.Fatalf("investigation not audited: %s", ev.Raw)
	}
	// Readers without audit access cannot reconstruct.
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	if r := h.API("POST", "/investigations/entitlements", carol, map[string]any{"subject_type": "user", "subject_id": f.Users["bob"],
		"at": t1.Format(time.RFC3339), "reason": "x"}); r.Status != 403 {
		t.Fatalf("unprivileged reconstruction: %d", r.Status)
	}
}
