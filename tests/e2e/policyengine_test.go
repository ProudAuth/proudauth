package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/realm"
)

// TestExternalPolicyEngine covers AZ-026: a realm delegates decisions to an
// operator-configured engine over an authenticated call carrying the same
// tenant, subject, actor and token context; restrict mode lets it only deny,
// decide mode makes it final; an unreachable or malformed engine denies
// unless the realm chose the local decision; such decisions are never
// cacheable.
func TestExternalPolicyEngine(t *testing.T) {
	var mu sync.Mutex
	answer := `{"allowed": true}`
	status := 200
	calls := 0
	var last map[string]any
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer engine-token" {
			w.WriteHeader(401)
			return
		}
		var body struct {
			Input map[string]any `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		defer mu.Unlock()
		calls++
		last = body.Input
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer engine.Close()
	set := func(a string, st int) {
		mu.Lock()
		answer, status = a, st
		mu.Unlock()
	}
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.PolicyEngines = []configuration.PolicyEngineConfig{{Name: "opa", URL: engine.URL + "/v1/data/proudauth", Token: "engine-token", Timeout: 500 * time.Millisecond}}
	})
	f := fixtureOn(t, h)
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.PolicyEngine = realm.PolicyEnginePolicy{Name: "missing"} }), 422, "unknown engine")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.PolicyEngine = realm.PolicyEnginePolicy{Name: "opa", Mode: "veto"} }), 422, "unknown mode")
	f.must(f.SetPolicy(func(p *realm.Policy) { p.PolicyEngine = realm.PolicyEnginePolicy{Name: "opa"} }), 200, "restrict mode")

	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	check := func(action string) *Resp {
		t.Helper()
		return f.must(h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": action,
			"resource": map[string]any{"type": "order", "id": "o1", "org_id": f.Acme}}), 200, "check")
	}
	if d := check("orders.read"); d.Get("allowed") != true || d.Str("cache_key") != "" {
		t.Fatalf("engine allows: %s", d.Raw)
	}
	mu.Lock()
	if last["organization_id"] != f.Acme || last["subject"].(map[string]any)["id"] != f.Users["bob"] || last["client_id"] != "web-bff" ||
		last["token_kind"] != "user_access" || last["local"].(map[string]any)["allowed"] != true || last["action"] != "orders.read" {
		t.Fatalf("engine input: %v", last)
	}
	before := calls
	mu.Unlock()
	set(`{"result": {"allowed": false, "reason_code": "OUTSIDE_SHIFT"}}`, 200)
	if d := check("orders.read"); d.Get("allowed") != false || d.Str("reason_code") != "OUTSIDE_SHIFT" {
		t.Fatalf("engine denies: %s", d.Raw)
	}
	set(`{"result": true}`, 200)
	if d := check("billing.read"); d.Get("allowed") != false || d.Str("reason_code") != "NOT_PERMITTED" {
		t.Fatalf("restrict mode never grants: %s", d.Raw)
	}
	mu.Lock()
	if calls != before+1 {
		t.Fatalf("restrict mode consulted the engine for a local denial: %d calls", calls-before)
	}
	mu.Unlock()
	set(`{"allowed": "yes"}`, 200)
	if d := check("orders.read"); d.Str("reason_code") != "EXTERNAL_POLICY_UNAVAILABLE" {
		t.Fatalf("malformed answer: %s", d.Raw)
	}
	set(`{}`, 500)
	if d := check("orders.read"); d.Get("allowed") != false || d.Str("reason_code") != "EXTERNAL_POLICY_UNAVAILABLE" {
		t.Fatalf("engine down: %s", d.Raw)
	}
	f.must(f.SetPolicy(func(p *realm.Policy) { p.PolicyEngine = realm.PolicyEnginePolicy{Name: "opa", OnError: "local"} }), 200, "fall back to local")
	if d := check("orders.read"); d.Get("allowed") != true {
		t.Fatalf("local fallback: %s", d.Raw)
	}

	// Decide mode: the engine's answer is final either way.
	f.must(f.SetPolicy(func(p *realm.Policy) { p.PolicyEngine = realm.PolicyEnginePolicy{Name: "opa", Mode: "decide"} }), 200, "decide mode")
	set(`{"allowed": true, "policy_version": "bundle-7"}`, 200)
	if d := check("billing.read"); d.Get("allowed") != true {
		t.Fatalf("decide mode grant: %s", d.Raw)
	}
	mu.Lock()
	if last["local"].(map[string]any)["allowed"] != false {
		t.Fatalf("local answer passed to the engine: %v", last["local"])
	}
	mu.Unlock()
	set(`{"allowed": false}`, 200)
	if d := check("orders.read"); d.Get("allowed") != false || d.Str("reason_code") != "EXTERNAL_POLICY_DENIED" {
		t.Fatalf("decide mode denial: %s", d.Raw)
	}
}
