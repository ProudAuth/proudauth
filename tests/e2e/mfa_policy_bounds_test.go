package e2e

import (
	"slices"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/realm"
)

// TestNoSecurityQuestionsInPolicy covers MFA-011 through the administration
// API: a realm policy that names a knowledge-based question as an MFA factor
// or as a flow-rule sign-in method is refused with 422, a policy member that
// would configure security questions is refused as an unknown member, an
// organization cannot allow one as a login method, and nothing changes.
func TestNoSecurityQuestionsInPolicy(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	before := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
	fieldErr := func(r *Resp, field string) bool {
		errs, _ := r.Get("errors").(map[string]any)
		return errs[field] != nil
	}

	r := f.SetPolicy(func(p *realm.Policy) { p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, "security_question") })
	if r.Status != 422 || !fieldErr(r, "mfa.allowed_factors") {
		t.Fatalf("security_question as an MFA factor: %d %s", r.Status, r.Raw)
	}
	r = f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "questions", When: realm.AuthFlowCondition{Methods: []string{"security_question"}}, Outcome: realm.FlowAllow}}
	})
	if r.Status != 422 || !fieldErr(r, "authentication_flow.rules[0].when.methods") {
		t.Fatalf("security_question as a flow method: %d %s", r.Status, r.Raw)
	}
	// A member that would configure questions does not exist: the policy
	// document is decoded strictly.
	for name, mutate := range map[string]func(pol map[string]any){
		"recovery.security_questions": func(pol map[string]any) {
			pol["recovery"].(map[string]any)["security_questions"] = []map[string]any{{"question": "First pet?", "answer": "rex"}}
		},
		"mfa.security_questions": func(pol map[string]any) { pol["mfa"].(map[string]any)["security_questions"] = true },
	} {
		cur := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
		pol := cur.Get("policy").(map[string]any)
		if pol["recovery"] == nil {
			pol["recovery"] = map[string]any{}
		}
		mutate(pol)
		r := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/settings", Token: f.AdminToken, JSON: map[string]any{"policy": pol, "reason": "test"},
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
		if r.Status != 400 || !strings.Contains(string(r.Raw), "unknown field 'security_questions'") {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	after := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
	factors := func(r *Resp) []string { return toStrings(r.Get("policy.mfa.allowed_factors")) }
	if !slices.Equal(factors(before), factors(after)) || after.Get("policy_revision") != before.Get("policy_revision") {
		t.Fatalf("a refused policy changed the realm: %v -> %v", before.Get("policy"), after.Get("policy"))
	}
	// Organizations cannot allow one either.
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "organization")
	r = h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_login_methods": []string{"security_question"}}}})
	if r.Status != 422 || !fieldErr(r, "policy.allowed_login_methods") {
		t.Fatalf("security_question as an organization login method: %d %s", r.Status, r.Raw)
	}
}
