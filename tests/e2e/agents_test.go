package e2e

import (
	"net/url"
	"strings"
	"testing"
)

// TestAgentPrincipals covers MCH-017: autonomous agents are service principals
// with an accountable human owner; they get no privileged role on one
// administrator's say-so (two-party approval); their tokens, and the act
// claims of delegations they perform, mark them as agents; and they pass
// through ordinary authorization like any service.
func TestAgentPrincipals(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/service-principals", map[string]any{"name": "orphan-agent", "is_agent": true, "owner_organization_id": f.Acme}),
		422, "agent without a human owner")
	agent := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "triage-agent", "is_agent": true,
		"allowed_organization_ids": []string{f.Acme}}), 201, "agent").Str("id")
	assign := func(role string) *Resp {
		return f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles[role], "subject": map[string]any{"type": "service_principal", "id": agent},
			"scope": map[string]any{"type": "organization", "id": f.Acme}, "reason": "agent rollout"})
	}
	f.must(assign("orders-viewer"), 201, "ordinary role")
	pending := f.must(assign("orders-refunder"), 202, "privileged role needs approval")
	if pending.Str("status") != "pending_approval" {
		t.Fatalf("privileged grant to an agent: %s", pending.Raw)
	}
	reqID := pending.Str("request.id")
	mustStatus(t, f.AdminAPI("POST", "/role-assignment-requests/"+reqID+"/approve", nil), 403, "the requester cannot approve")
	// A second administrator approves.
	second := f.CreateUser("dana")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["realm-admin"], "subject": map[string]any{"type": "user", "id": second}}),
		201, "second administrator")
	dana := f.AdminTokenFor("dana").Tokens.Str("access_token")
	f.must(h.API("POST", "/role-assignment-requests/"+reqID+"/approve", dana, nil), 200, "approved by another administrator")
	// The same role for an ordinary service principal needs no approval.
	plain := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "batch", "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["orders-refunder"], "subject": map[string]any{"type": "service_principal", "id": plain},
		"scope": map[string]any{"type": "organization", "id": f.Acme}}), 201, "ordinary service principal")

	// Agent tokens say so, in the token and at introspection.
	cl := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "triage-bot", "name": "Triage agent", "client_type": "machine",
		"service_principal_id": agent, "grant_types": []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"}}), 201, "agent client")
	f.must(f.AdminAPI("PUT", "/clients/"+cl.Str("client.id")+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal", "user"}, "exchange_policy": map[string]any{"accept_from_audiences": []string{f.OrdersAud}}}), 204, "grant")
	tok := h.TokenRequest(url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}},
		"triage-bot", cl.Str("client_secret"))
	mustStatus(t, tok, 200, "agent token")
	if c := jwtPayload(tok.Str("access_token")); c["agent"] != true || c["sub"] != agent {
		t.Fatalf("agent token claims: %v", c)
	}
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, tok.Str("access_token")); in.Get("agent") != true {
		t.Fatalf("introspection: %s", in.Raw)
	}
	// Acting for a person, the agent is the visible actor.
	at := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("access_token")
	ex := h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {at},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}, "scope": {"billing:read"}},
		"triage-bot", cl.Str("client_secret"))
	mustStatus(t, ex, 200, "agent delegation")
	c := jwtPayload(ex.Str("access_token"))
	act, _ := c["act"].(map[string]any)
	if c["sub"] != f.Users["alice"] || act == nil || act["sub"] != agent || act["agent"] != true || c["agent"] != nil {
		t.Fatalf("delegated claims: %v", c)
	}
	// An agent's API keys are marked like its access tokens; an ordinary
	// service principal's are not.
	key := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": agent, "name": "triage-key",
		"audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme}), 201, "agent api key")
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, key.Str("api_key")); in.Get("active") != true || in.Get("agent") != true {
		t.Fatalf("agent api key introspection: %s", in.Raw)
	}
	plainKey := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": plain, "name": "batch-key",
		"audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme}), 201, "ordinary api key")
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, plainKey.Str("api_key")); in.Get("active") != true || in.Get("agent") != nil {
		t.Fatalf("ordinary api key introspection: %s", in.Raw)
	}

	// Organization templates follow the same two-party rule: a template
	// that would grant an agent a privileged role is refused (a conflict
	// naming the direct route) until the grant is approved directly.
	helper := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "acme-helper", "is_agent": true, "owner_user_id": f.Users["alice"],
		"owner_organization_id": f.Acme, "allowed_organization_ids": []string{f.Acme}}), 201, "organization agent").Str("id")
	f.must(f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "agent-roles", "document": map[string]any{
		"service_principals": []map[string]any{{"name": "helper", "role_names": []string{"orders-viewer", "orders-refunder"}}}}}), 201, "template")
	applyTemplate := func(dry bool) *Resp {
		return f.AdminAPI("POST", "/organizations/"+f.Acme+"/template-applications", map[string]any{"template": "agent-roles", "dry_run": dry})
	}
	plan := f.must(applyTemplate(true), 200, "template dry run")
	if cs := jsonString(plan.Get("conflicts")); !strings.Contains(cs, "grant orders-refunder to service principal acme-helper needs an independent approver") ||
		strings.Contains(cs, "orders-viewer") {
		t.Fatalf("template plan for an agent: %s", plan.Raw)
	}
	if r := applyTemplate(false); r.Status != 409 || !strings.Contains(string(r.Raw), "independent approver") {
		t.Fatalf("template granting an agent a privileged role: %d %s", r.Status, r.Raw)
	}
	var held int
	_ = h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM role_assignments WHERE subject_type='service_principal' AND subject_id=$1`, helper).Scan(&held)
	if held != 0 {
		t.Fatalf("a refused template left %d assignments", held)
	}
	direct := f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["orders-refunder"],
		"subject": map[string]any{"type": "service_principal", "id": helper}, "scope": map[string]any{"type": "organization", "id": f.Acme}}), 202, "direct request")
	f.must(h.API("POST", "/role-assignment-requests/"+direct.Str("request.id")+"/approve", dana, nil), 200, "approved")
	applied := f.must(applyTemplate(false), 200, "template once the grant is approved")
	if applied.Get("applied") != true || !strings.Contains(jsonString(applied.Get("unchanged")), "grant orders-refunder to service principal acme-helper") {
		t.Fatalf("template after approval: %s", applied.Raw)
	}
}
