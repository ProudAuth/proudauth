package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
)

// TestAuthenticationFlowRevisions covers AUT-019: flow definitions are
// versioned, analysed for unreachable rules and bypass paths, simulated
// against the live flow, published only from a current base, and rolled
// back by republishing an earlier revision as a new one.
func TestAuthenticationFlowRevisions(t *testing.T) {
	f := NewFixture(t)
	yes := true
	revs := func(t *testing.T) []map[string]any {
		r := f.must(f.AdminAPI("GET", "/authentication-flow/revisions", nil), 200, "list revisions")
		out := []map[string]any{}
		for _, it := range r.Get("items").([]any) {
			out = append(out, it.(map[string]any))
		}
		return out
	}
	num := func(v any) int { n, _ := v.(float64); return int(n) }
	path := func(rev int, rest string) string {
		return fmt.Sprintf("/authentication-flow/revisions/%d%s", rev, rest)
	}

	// A draft whose allow-everything rule shadows a stricter rule is saved
	// with its analysis but cannot be published.
	bypass := realm.AuthFlowPolicy{Rules: []realm.AuthFlowRule{
		{Name: "everyone", Outcome: "allow"},
		{Name: "admins need mfa", When: realm.AuthFlowCondition{Privileged: &yes}, Outcome: "require_mfa"},
	}}
	d1 := f.must(f.AdminAPI("POST", "/authentication-flow/revisions", map[string]any{"definition": bypass, "note": "first try"}), 201, "draft with bypass")
	rev1 := num(d1.Get("revision"))
	if d1.Str("state") != "draft" || !strings.Contains(string(d1.Raw), `"code":"bypass"`) || !strings.Contains(string(d1.Raw), "admins need mfa") {
		t.Fatalf("draft analysis: %s", d1.Raw)
	}
	r := f.AdminAPI("POST", path(rev1, "/publish"), map[string]any{"acknowledge_warnings": true})
	if r.Status != 422 || !strings.Contains(string(r.Raw), "rules[1]") {
		t.Fatalf("bypass published: %d %s", r.Status, r.Raw)
	}
	// The same definition through the settings document is refused too.
	if r := f.SetPolicy(func(p *realm.Policy) { p.AuthFlow = bypass }); r.Status != 422 {
		t.Fatalf("settings accepted a bypass path: %d %s", r.Status, r.Raw)
	}
	// Invalid definitions are rejected outright.
	mustStatus(t, f.AdminAPI("POST", "/authentication-flow/revisions", map[string]any{"definition": realm.AuthFlowPolicy{Rules: []realm.AuthFlowRule{
		{Name: "x", Outcome: "maybe"}}}}), 422, "invalid draft")

	// A draft with warnings needs them acknowledged.
	good := realm.AuthFlowPolicy{Rules: []realm.AuthFlowRule{
		{Name: "office", When: realm.AuthFlowCondition{Networks: []string{"10.0.0.0/8"}}, Outcome: "allow"},
		{Name: "new devices", When: realm.AuthFlowCondition{NewDevice: &yes}, Outcome: "require_mfa"},
	}}
	d2 := f.must(f.AdminAPI("POST", "/authentication-flow/revisions", map[string]any{"definition": good}), 201, "good draft")
	rev2 := num(d2.Get("revision"))
	if !strings.Contains(string(d2.Raw), `"code":"partial_bypass"`) {
		t.Fatalf("partial overlap not reported: %s", d2.Raw)
	}

	// Simulation compares the draft with the live (empty) flow.
	sim := f.must(f.AdminAPI("POST", path(rev2, "/simulate"), map[string]any{"cases": []map[string]any{
		{"name": "office laptop", "ip": "10.1.1.1", "client_id": "web-bff"},
		{"name": "new phone", "ip": "198.51.100.7"},
		{"name": "no address"},
		{"name": "known device", "ip": "198.51.100.7", "known_device": true},
	}}), 200, "simulate")
	results := sim.Get("results").([]any)
	change := func(i int) string { return results[i].(map[string]any)["change"].(string) }
	if change(0) != "rule_changed" || change(1) != "stricter" || change(2) != "stricter" || change(3) != "unchanged" {
		t.Fatalf("simulation: %s", sim.Raw)
	}
	if num(sim.Get("summary.stricter")) != 2 {
		t.Fatalf("summary: %s", sim.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", path(rev2, "/simulate"), map[string]any{"cases": []map[string]any{{"risk": "extreme"}}}), 422, "bad case")

	r = f.AdminAPI("POST", path(rev2, "/publish"), map[string]any{})
	if r.Status != 422 || !strings.Contains(string(r.Raw), "acknowledge_warnings") {
		t.Fatalf("warnings not enforced: %d %s", r.Status, r.Raw)
	}
	pub := f.must(f.AdminAPI("POST", path(rev2, "/publish"), map[string]any{"acknowledge_warnings": true, "reason": "office exemption"}), 200, "publish")
	if pub.Str("revision.state") != "published" || num(pub.Get("revision.policy_revision")) != num(pub.Get("policy_revision")) {
		t.Fatalf("publish: %s", pub.Raw)
	}
	set := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
	if !strings.Contains(string(set.Raw), "new devices") {
		t.Fatalf("live flow not updated: %s", set.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", path(rev2, "/publish"), map[string]any{"acknowledge_warnings": true}), 409, "republish")

	// A draft made before someone else changed the live flow is stale.
	d3 := f.must(f.AdminAPI("POST", "/authentication-flow/revisions", map[string]any{"definition": realm.AuthFlowPolicy{Rules: []realm.AuthFlowRule{
		{Name: "risky", When: realm.AuthFlowCondition{RiskAtLeast: "high"}, Outcome: "deny"}}}}), 201, "draft 3")
	rev3 := num(d3.Get("revision"))
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow = realm.AuthFlowPolicy{Rules: []realm.AuthFlowRule{{Name: "admins", When: realm.AuthFlowCondition{Privileged: &yes}, Outcome: "require_mfa"}}}
	}), 200, "settings flow edit")
	r = f.AdminAPI("POST", path(rev3, "/publish"), map[string]any{"acknowledge_warnings": true})
	if r.Status != 409 || !strings.Contains(string(r.Raw), "changed") {
		t.Fatalf("stale draft published: %d %s", r.Status, r.Raw)
	}
	// The settings edit was recorded as its own published revision.
	list := revs(t)
	if list[0]["state"] != "published" || !strings.Contains(fmt.Sprint(list[0]["definition"]), "admins") {
		t.Fatalf("settings edit not versioned: %v", list[0])
	}
	settingsRev := num(list[0]["revision"])
	for _, it := range list {
		if num(it["revision"]) == rev2 && it["state"] != "superseded" {
			t.Fatalf("previous revision not superseded: %v", it)
		}
	}
	// Unrelated settings changes do not create flow revisions.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Sessions.MaxConcurrent = 9 }), 200, "unrelated settings edit")
	if n := num(revs(t)[0]["revision"]); n != settingsRev {
		t.Fatalf("unrelated change created revision %d", n)
	}

	// Rollback republishes revision 2 as a new revision.
	rb := f.must(f.AdminAPI("POST", path(rev2, "/rollback"), map[string]any{"acknowledge_warnings": true}), 201, "rollback")
	if num(rb.Get("revision.rollback_of")) != rev2 || rb.Str("revision.state") != "published" || num(rb.Get("revision.revision")) <= settingsRev {
		t.Fatalf("rollback: %s", rb.Raw)
	}
	set = f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
	if !strings.Contains(string(set.Raw), "new devices") || strings.Contains(string(set.Raw), `"name":"admins"`) {
		t.Fatalf("rollback did not restore the flow: %s", set.Raw)
	}
	// Only published revisions can be restored; drafts can be discarded once.
	mustStatus(t, f.AdminAPI("POST", path(rev1, "/rollback"), map[string]any{"acknowledge_warnings": true}), 409, "rollback to draft")
	mustStatus(t, f.AdminAPI("DELETE", path(rev3, ""), nil), 204, "discard")
	mustStatus(t, f.AdminAPI("DELETE", path(rev3, ""), nil), 409, "discard twice")
	mustStatus(t, f.AdminAPI("GET", path(999, ""), nil), 404, "missing revision")

}
