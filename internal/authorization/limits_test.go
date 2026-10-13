package authorization

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPolicyExecutionLimits covers NFR-001 for policy execution: a policy
// definition is bounded in size (MaxPolicyBytes), rule count
// (MaxPolicyRules), condition nesting (MaxConditionDepth), condition nodes
// per rule (MaxConditionNodes) and list values (MaxListValues), so the cost
// of evaluating a stored policy is bounded. A definition at each limit is
// accepted and one past it is refused.
func TestPolicyExecutionLimits(t *testing.T) {
	leaf := func() map[string]any { return map[string]any{"attr": "context.amount", "op": "gt", "value": 1} }
	policy := func(rules ...map[string]any) []byte {
		b, err := json.Marshal(map[string]any{"target": map[string]any{"actions": []string{"orders.*"}}, "rules": rules})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rule := func(id string, when map[string]any) map[string]any {
		return map[string]any{"id": id, "effect": "deny", "when": when}
	}
	check := func(what string, raw []byte, ok bool) {
		t.Helper()
		_, err := ParsePolicy(raw)
		if ok && err != nil {
			t.Fatalf("%s at the limit refused: %v", what, err)
		}
		if !ok && err == nil {
			t.Fatalf("%s past the limit accepted", what)
		}
	}

	// Rules per policy.
	rules := func(n int) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			out[i] = rule("r"+strings.Repeat("x", i), leaf())
		}
		return out
	}
	check("rule count", policy(rules(MaxPolicyRules)...), true)
	check("rule count", policy(rules(MaxPolicyRules+1)...), false)

	// Condition depth: the rule's when is depth 1, each not adds one.
	nots := func(k int) map[string]any {
		c := leaf()
		for i := 0; i < k; i++ {
			c = map[string]any{"not": c}
		}
		return c
	}
	check("condition depth", policy(rule("deep", nots(MaxConditionDepth-1))), true)
	check("condition depth", policy(rule("deep", nots(MaxConditionDepth))), false)

	// Condition nodes per rule: an any node with n leaves has n+1 nodes.
	anyOf := func(n int) map[string]any {
		l := make([]map[string]any, n)
		for i := range l {
			l[i] = leaf()
		}
		return map[string]any{"any": l}
	}
	check("condition nodes", policy(rule("wide", anyOf(MaxConditionNodes-1))), true)
	check("condition nodes", policy(rule("wide", anyOf(MaxConditionNodes))), false)

	// Values of an in list.
	in := func(n int) map[string]any {
		v := make([]any, n)
		for i := range v {
			v[i] = i
		}
		return map[string]any{"attr": "context.region", "op": "in", "value": v}
	}
	check("in list", policy(rule("list", in(MaxListValues))), true)
	check("in list", policy(rule("list", in(MaxListValues+1))), false)

	// Document size.
	big, err := json.Marshal(map[string]any{"description": strings.Repeat("d", MaxPolicyBytes), "target": map[string]any{"actions": []string{"orders.*"}},
		"rules": []map[string]any{rule("r", leaf())}})
	if err != nil {
		t.Fatal(err)
	}
	check("policy size", big, false)
}
