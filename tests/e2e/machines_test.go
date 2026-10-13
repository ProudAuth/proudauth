package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/authorization"
)

// TestServicePrincipalLifecycle covers MCH-001: a service principal records
// its accountable owner, description and allowed organizations, holds
// permissions through ordinary role assignments, and is disabled, re-enabled
// and deleted on its own: disabling stops issuance and online acceptance at
// once while other principals keep working, and deletion removes it together
// with its role assignments.
func TestServicePrincipalLifecycle(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "report-exporter", "description": "Exports monthly reports",
		"owner_user_id": f.Users["alice"], "allowed_organization_ids": []string{f.Acme}}), 201, "service principal")
	id := sp.Str("id")
	got := f.must(f.AdminAPI("GET", "/service-principals/"+id, nil), 200, "service principal")
	if got.Str("description") != "Exports monthly reports" || got.Str("owner_user_id") != f.Users["alice"] || got.Str("state") != "active" ||
		jsonString(got.Get("allowed_organization_ids")) != jsonString([]string{f.Acme}) {
		t.Fatalf("service principal record: %s", got.Raw)
	}
	cl := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "report-exporter", "name": "Report exporter", "client_type": "machine",
		"service_principal_id": id}), 201, "machine client")
	sec := cl.Str("client_secret")
	f.must(f.AdminAPI("PUT", "/clients/"+cl.Str("client.id")+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal"}}), 204, "grant")
	token := func(org string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {org}},
			"report-exporter", sec)
	}
	first := token(f.Acme)
	mustStatus(t, first, 200, "client credentials")
	if sub := jwtPayload(first.Str("access_token"))["sub"]; sub != id {
		t.Fatalf("token subject %v, want the service principal %s", sub, id)
	}
	if r := token(f.Globex); r.Status == 200 {
		t.Fatal("token for an organization the principal is not allowed in")
	}
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["billing-viewer"],
		"subject": map[string]any{"type": "service_principal", "id": id}, "scope": map[string]any{"type": "organization", "id": f.Acme}}), 201, "role")
	subject := authorization.Subject{Type: authorization.SubjectService, ID: id}
	acme := authorization.Scope{Type: authorization.ScopeOrganization, ID: f.Acme}
	if eff, err := h.App.Authz.Effective(ctx, nil, h.Realm.ID, subject, acme); err != nil || !eff.Has("billing.read") {
		t.Fatalf("permission through the role assignment: %v %v", eff, err)
	}

	mustStatus(t, f.AdminAPI("POST", "/service-principals/"+id+"/disable", nil), 204, "disable")
	if r := token(f.Acme); r.Status == 200 {
		t.Fatal("disabled principal obtained a token")
	}
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, first.Str("access_token")); in.Get("active") != false {
		t.Fatalf("disabled principal's token still active: %s", in.Raw)
	}
	mustStatus(t, f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme), 200, "another principal is unaffected")
	mustStatus(t, f.AdminAPI("POST", "/service-principals/"+id+"/enable", nil), 204, "enable")
	mustStatus(t, token(f.Acme), 200, "re-enabled principal")

	mustStatus(t, f.AdminAPI("DELETE", "/service-principals/"+id, nil), 204, "delete")
	mustStatus(t, f.AdminAPI("GET", "/service-principals/"+id, nil), 404, "deleted principal")
	if r := token(f.Acme); r.Status == 200 {
		t.Fatal("deleted principal obtained a token")
	}
	left := f.must(f.AdminAPI("GET", "/role-assignments?subject_type=service_principal&subject_id="+id, nil), 200, "assignments")
	if items, _ := left.Get("items").([]any); len(items) != 0 {
		t.Fatalf("deleted principal kept role assignments: %s", left.Raw)
	}
}

// TestScopedAPIKeys covers MCH-005: an API key is a prefix-plus-secret value
// shown once, owned by a service principal and restricted to one business
// resource, its declared non-privileged scopes and an allowed organization,
// with a mandatory expiry; each use is recorded; revocation and expiry take
// effect on the next online check.
func TestScopedAPIKeys(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	owner := f.Clients["batch"].SP // allowed in acme only
	create := func(body map[string]any) *Resp {
		body["service_principal_id"] = owner
		return f.AdminAPI("POST", "/api-keys", body)
	}
	for name, c := range map[string]struct {
		body   map[string]any
		status int
	}{
		"privileged scope":      {map[string]any{"name": "k", "audience": f.BillingAud, "scopes": []string{"billing:admin"}, "organization_id": f.Acme}, 422},
		"undeclared scope":      {map[string]any{"name": "k", "audience": f.BillingAud, "scopes": []string{"billing:write"}, "organization_id": f.Acme}, 422},
		"no scopes":             {map[string]any{"name": "k", "audience": f.BillingAud, "organization_id": f.Acme}, 422},
		"expiry beyond a year":  {map[string]any{"name": "k", "audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme, "ttl_days": 400}, 422},
		"administration API":    {map[string]any{"name": "k", "audience": h.Realm.Issuer + "/admin", "scopes": []string{"proudauth:admin"}}, 422},
		"unknown resource":      {map[string]any{"name": "k", "audience": "https://unregistered.test", "scopes": []string{"billing:read"}}, 422},
		"organization not held": {map[string]any{"name": "k", "audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Globex}, 403},
	} {
		if r := create(c.body); r.Status != c.status {
			t.Errorf("%s: %d %s, want %d", name, r.Status, r.Raw, c.status)
		}
	}
	key := create(map[string]any{"name": "nightly", "audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme, "ttl_days": 1})
	mustStatus(t, key, 201, "api key")
	plain := key.Str("api_key")
	cred := key.Get("credential").(map[string]any)
	prefix, _ := cred["display_prefix"].(string)
	if !strings.HasPrefix(plain, "pa_key_") || prefix == "" || !strings.HasPrefix(plain, prefix) || len(prefix) >= len(plain)/2 {
		t.Fatalf("key %q with display prefix %q", plain, prefix)
	}
	if cred["owner_type"] != "service_principal" || cred["owner_id"] != owner || cred["resource_id"] != f.Billing || cred["organization_id"] != f.Acme ||
		jsonString(cred["scopes"]) != `["billing:read"]` || cred["last_used_at"] != nil {
		t.Fatalf("key metadata: %v", cred)
	}
	exp, err := time.Parse(time.RFC3339, cred["expires_at"].(string))
	if err != nil || exp.Sub(h.Clock.Now()) > 25*time.Hour || exp.Sub(h.Clock.Now()) < 23*time.Hour {
		t.Fatalf("expiry %v (%v)", cred["expires_at"], err)
	}
	list := func() string {
		return string(f.must(f.AdminAPI("GET", "/api-keys?owner_type=service_principal&owner_id="+owner, nil), 200, "list").Raw)
	}
	if l := list(); strings.Contains(l, plain) || !strings.Contains(l, prefix) {
		t.Fatal("the key secret must be shown only once")
	}
	in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, plain)
	if in.Get("active") != true || in.Str("sub") != owner || in.Str("aud") != f.BillingAud || in.Str("scope") != "billing:read" ||
		in.Str("org_id") != f.Acme || in.Str("token_kind") != "api_key" {
		t.Fatalf("api key introspection: %s", in.Raw)
	}
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, plain); in.Get("active") != false {
		t.Fatalf("api key accepted by another resource: %s", in.Raw)
	}
	if l := list(); !strings.Contains(l, `"last_used_at"`) {
		t.Fatalf("last use not recorded: %s", l)
	}

	revoked := create(map[string]any{"name": "temporary", "audience": f.BillingAud, "scopes": []string{"billing:read"}, "organization_id": f.Acme})
	mustStatus(t, revoked, 201, "second key")
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, revoked.Str("api_key")); in.Get("active") != true {
		t.Fatalf("second key: %s", in.Raw)
	}
	mustStatus(t, f.AdminAPI("DELETE", "/api-keys/"+revoked.Str("credential.id"), nil), 204, "revoke")
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, revoked.Str("api_key")); in.Get("active") != false {
		t.Fatalf("revoked key still active: %s", in.Raw)
	}
	h.Clock.Advance(25 * time.Hour)
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, plain); in.Get("active") != false {
		t.Fatalf("expired key still active: %s", in.Raw)
	}
}
