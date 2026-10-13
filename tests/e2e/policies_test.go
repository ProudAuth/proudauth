package e2e

import (
	"strings"
	"testing"
)

// TestPoliciesAndConditionalGrants covers AZ-012, AZ-013, AZ-015..AZ-019.
func TestPoliciesAndConditionalGrants(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	check := func(ctx map[string]any) *Resp {
		t.Helper()
		body := map[string]any{"subject_token": bob, "action": "orders.read", "resource": map[string]any{"type": "order", "id": "ord_acme_1", "org_id": f.Acme}}
		if ctx != nil {
			body["context"] = ctx
		}
		r := h.API("POST", "/authorization/check", svc, body)
		mustStatus(t, r, 200, "decision")
		return r
	}
	regionPolicy := map[string]any{
		"target": map[string]any{"actions": []string{"orders.*"}, "resource_types": []string{"order"}},
		"rules": []map[string]any{{"id": "eu-block", "effect": "deny", "reason_code": "REGION_BLOCKED",
			"when": map[string]any{"op": "eq", "attr": "context.region", "value": "eu"}}},
	}
	created := f.must(f.AdminAPI("POST", "/policies", map[string]any{"name": "orders-region", "definition": regionPolicy}), 201, "create policy")
	pid := created.Str("policy.id")

	t.Run("staged revisions do not apply; simulation shows the effect", func(t *testing.T) {
		if r := check(map[string]any{"region": "eu"}); r.Get("allowed") != true {
			t.Fatalf("staged policy applied: %s", r.Raw)
		}
		sim := f.must(f.AdminAPI("POST", "/authorization/simulate", map[string]any{"policy": pid, "version": 1, "checks": []map[string]any{
			{"subject": map[string]any{"id": f.Users["bob"]}, "subject_attributes": map[string]any{"org_id": f.Acme}, "action": "orders.read",
				"resource": map[string]any{"type": "order", "org_id": f.Acme}, "context": map[string]any{"region": "eu"}},
			{"subject": map[string]any{"id": f.Users["bob"]}, "action": "orders.read", "resource": map[string]any{"type": "order", "org_id": f.Acme},
				"context": map[string]any{"region": "us"}},
		}}), 200, "simulate")
		res := sim.Get("results").([]any)
		if sim.Get("changed") != float64(1) || res[0].(map[string]any)["candidate"].(map[string]any)["reason_code"] != "REGION_BLOCKED" {
			t.Fatalf("simulation: %s", sim.Raw)
		}
	})

	t.Run("published policies restrict RBAC and fail closed on missing attributes", func(t *testing.T) {
		f.must(f.AdminAPI("POST", "/policies/"+pid+"/versions/1/publish", nil), 200, "publish")
		r := check(map[string]any{"region": "eu"})
		if r.Get("allowed") != false || r.Str("reason_code") != "REGION_BLOCKED" || !strings.Contains(r.Str("policy_version"), "orders-region@1") {
			t.Fatalf("published policy not enforced: %s", r.Raw)
		}
		if r := check(map[string]any{"region": "us"}); r.Get("allowed") != true {
			t.Fatalf("policy over-applied: %s", r.Raw)
		}
		if r := check(nil); r.Get("allowed") != false || r.Str("reason_code") != "POLICY_ATTRIBUTE_MISSING" {
			t.Fatalf("missing attribute did not fail closed: %s", r.Raw)
		}
		// Policies never grant: an action RBAC denies stays denied.
		r = h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": "orders.refund",
			"resource": map[string]any{"type": "order", "org_id": f.Acme}, "context": map[string]any{"region": "us"}})
		if r.Get("allowed") != false || r.Str("reason_code") != "NOT_PERMITTED" {
			t.Fatalf("policy changed an RBAC denial: %s", r.Raw)
		}
	})

	t.Run("obligations, versions, diff and rollback", func(t *testing.T) {
		v2 := map[string]any{
			"target": map[string]any{"actions": []string{"orders.*"}},
			"rules": []map[string]any{
				{"id": "eu-block", "effect": "deny", "reason_code": "REGION_BLOCKED",
					"when": map[string]any{"all": []map[string]any{{"op": "exists", "attr": "context.region"}, {"op": "eq", "attr": "context.region", "value": "eu"}}}},
				{"id": "large-read", "effect": "require", "obligations": []map[string]any{{"type": "reauthenticate", "required_profile": "phishing_resistant", "max_age_seconds": 300}},
					"when": map[string]any{"op": "gt", "attr": "context.amount_minor", "value": 100000}},
				{"id": "justify", "effect": "require", "obligations": []map[string]any{{"type": "justification"}},
					"when": map[string]any{"op": "eq", "attr": "subject.assurance", "value": "single_factor"}},
			},
		}
		f.must(f.AdminAPI("POST", "/policies/"+pid+"/versions", map[string]any{"definition": v2, "note": "obligations"}), 201, "stage v2")
		f.must(f.AdminAPI("POST", "/policies/"+pid+"/versions/2/publish", nil), 200, "publish v2")
		r := check(map[string]any{"amount_minor": 500000})
		obs := jsonString(r.Get("obligations"))
		if r.Get("allowed") != false || r.Str("reason_code") != "STEP_UP_REQUIRED" || !strings.Contains(obs, "phishing_resistant") {
			t.Fatalf("step-up obligation: %s", r.Raw)
		}
		// Without region the v2 rule no longer fails closed (exists guard), and the
		// caller-enforced justification obligation is returned with the allow.
		r = check(map[string]any{"amount_minor": 10})
		if r.Get("allowed") != true || !strings.Contains(jsonString(r.Get("obligations")), "justification") {
			t.Fatalf("caller-enforced obligation: %s", r.Raw)
		}
		diff := f.must(f.AdminAPI("GET", "/policies/"+pid+"/diff?from=1&to=2", nil), 200, "diff")
		if !strings.Contains(diff.Str("diff"), "+ ") || !strings.Contains(diff.Str("diff"), "large-read") {
			t.Fatalf("diff: %s", diff.Raw)
		}
		rb := f.must(f.AdminAPI("POST", "/policies/"+pid+"/rollback", map[string]any{"to_version": 1}), 200, "rollback")
		if rb.Get("active_version") != float64(3) {
			t.Fatalf("rollback must create a new immutable revision: %s", rb.Raw)
		}
		if r := check(nil); r.Str("reason_code") != "POLICY_ATTRIBUTE_MISSING" {
			t.Fatalf("rollback content not active: %s", r.Raw)
		}
		vers := f.must(f.AdminAPI("GET", "/policies/"+pid+"/versions", nil), 200, "versions")
		if n := len(vers.Get("items").([]any)); n != 3 {
			t.Fatalf("history rewritten: %d versions", n)
		}
		f.must(f.AdminAPI("POST", "/policies/"+pid+"/state", map[string]any{"state": "disabled"}), 204, "disable")
		if r := check(nil); r.Get("allowed") != true {
			t.Fatalf("disabled policy still enforced: %s", r.Raw)
		}
	})

	t.Run("validation and separation of duties", func(t *testing.T) {
		bad := []map[string]any{
			{"target": map[string]any{"actions": []string{"orders.read"}}, "rules": []map[string]any{{"id": "x", "effect": "permit"}}},
			{"target": map[string]any{"actions": []string{"*"}}, "rules": []map[string]any{{"id": "x", "effect": "deny"}}},
			{"target": map[string]any{"actions": []string{"orders.read"}}, "rules": []map[string]any{{"id": "x", "effect": "deny",
				"when": map[string]any{"op": "eq", "attr": "request.body.owner", "value": "me"}}}},
			{"target": map[string]any{"actions": []string{"orders.read"}}, "rules": []map[string]any{{"id": "x", "effect": "deny", "script": "return true"}}},
		}
		for i, def := range bad {
			if r := f.AdminAPI("POST", "/policies", map[string]any{"name": "bad-" + string(rune('a'+i)), "definition": def}); r.Status != 422 {
				t.Fatalf("invalid policy %d accepted: %d %s", i, r.Status, r.Raw)
			}
		}
		sod := f.must(f.AdminAPI("POST", "/policies", map[string]any{"name": "billing-guard", "requires_approval": true, "definition": regionPolicy}), 201, "create")
		id := sod.Str("policy.id")
		f.must(f.AdminAPI("POST", "/policies/"+id+"/versions/1/publish", nil), 403, "publish without approval")
		f.must(f.AdminAPI("POST", "/policies/"+id+"/versions/1/approve", nil), 403, "self-approval")
	})

	t.Run("conditional grants apply only when their conditions hold", func(t *testing.T) {
		f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["orders-refunder"],
			"subject": map[string]any{"type": "user", "id": f.Users["bob"]}, "scope": map[string]any{"type": "organization", "id": f.Acme},
			"conditions": map[string]any{"bogus": true}}), 422, "unknown condition")
		f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["orders-refunder"],
			"subject": map[string]any{"type": "user", "id": f.Users["bob"]}, "scope": map[string]any{"type": "organization", "id": f.Acme},
			"conditions": map[string]any{"min_assurance": "mfa", "client_ids": []string{"web-bff"}}}), 201, "conditional grant")
		// Bob's real (single-factor) token: the conditional grant does not apply.
		r := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": "orders.refund",
			"resource": map[string]any{"type": "order", "org_id": f.Acme}})
		if r.Get("allowed") != false || r.Str("reason_code") != "NOT_PERMITTED" {
			t.Fatalf("conditional grant applied without MFA: %s", r.Raw)
		}
		sim := func(acr, client string) map[string]any {
			res := f.must(f.AdminAPI("POST", "/authorization/simulate", map[string]any{"checks": []map[string]any{{
				"subject": map[string]any{"id": f.Users["bob"]}, "subject_attributes": map[string]any{"acr": acr, "auth_age_seconds": 30, "client_id": client, "org_id": f.Acme},
				"action": "orders.refund", "resource": map[string]any{"type": "order", "org_id": f.Acme}}}}), 200, "simulate")
			return res.Get("results").([]any)[0].(map[string]any)["current"].(map[string]any)
		}
		if d := sim("urn:proudauth:acr:mfa", "web-bff"); d["allowed"] != true {
			t.Fatalf("conditional grant did not apply when satisfied: %v", d)
		}
		if d := sim("urn:proudauth:acr:mfa", "partner-app"); d["allowed"] != false {
			t.Fatalf("client restriction ignored: %v", d)
		}
		if d := sim("urn:proudauth:acr:single_factor", "web-bff"); d["allowed"] != false {
			t.Fatalf("assurance condition ignored: %v", d)
		}
		// AZ-016: outside simulation a caller cannot assert MFA completion.
		real := f.AdminAPI("POST", "/authorization/check", map[string]any{"subject": map[string]any{"id": f.Users["bob"]},
			"subject_attributes": map[string]any{"acr": "urn:proudauth:acr:mfa", "auth_age_seconds": 30, "client_id": "web-bff", "org_id": f.Acme},
			"action":             "orders.refund", "resource": map[string]any{"type": "order", "org_id": f.Acme}})
		if real.Get("allowed") == true {
			t.Fatalf("caller-asserted assurance satisfied a real decision: %s", real.Raw)
		}
		// Simulations are not recorded as real decisions.
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=authorization.decision&subject_id="+f.Users["bob"], nil), 200, "audit")
		for _, it := range ev.Get("items").([]any) {
			if m := it.(map[string]any); m["outcome"] == "success" && strings.Contains(jsonString(m), "orders.refund") {
				t.Fatal("simulation audited as a real allow decision")
			}
		}
	})
}
