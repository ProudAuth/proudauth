package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestRegistryTokenBridge covers ADV-010: the container-registry token
// bridge maps authenticated principals to exact repository actions through
// their permissions, with a dedicated audience and short-lived tokens.
func TestRegistryTokenBridge(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	for _, p := range []string{"images.pull", "images.push"} {
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": p}), 201, "permission "+p)
	}
	registryRes := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Registry", "audience": "https://registry.test", "verification_mode": "offline",
		"scopes": []map[string]any{{"name": "pull"}, {"name": "push"}, {"name": "delete"}}}), 201, "registry resource").Str("id")
	publisher := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "image-publisher",
		"permissions": []string{"images.pull", "images.push"}}), 201, "publisher role").Str("id")
	reader := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "image-reader",
		"permissions": []string{"images.pull"}}), 201, "reader role").Str("id")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["alice"]+"/roles", map[string]any{"role_id": publisher}), 201, "alice publisher")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": reader}), 201, "bob reader")

	mustStatus(t, f.AdminAPI("POST", "/registry-services", map[string]any{"service": "unknown.test", "audience": "https://unknown.test", "rules": []map[string]any{{"repository": "x", "pull": "images.pull"}}}), 422, "no resource")
	mustStatus(t, f.AdminAPI("POST", "/registry-services", map[string]any{"service": "registry.test", "audience": "https://registry.test", "rules": []map[string]any{{"repository": "x", "pull": "nope.pull"}}}), 422, "unknown permission")
	f.must(f.AdminAPI("POST", "/registry-services", map[string]any{"service": "registry.test", "audience": "https://registry.test", "rules": []map[string]any{
		{"repository": "acme/*", "organization_id": f.Acme, "pull": "images.pull", "push": "images.push"},
		{"repository": "public/*", "anonymous_pull": true},
		{"repository": "ci/*", "pull": "images.pull", "push": "images.push"},
	}}), 201, "registry service")

	pat := func(user string, scopes ...string) string {
		tok := f.AccountToken(user).Tokens.Str("access_token")
		r := h.API("POST", "/me/personal-tokens", tok, map[string]any{"name": "docker", "audience": "https://registry.test", "scopes": scopes,
			"organization_id": f.Acme, "ttl_days": 30})
		mustStatus(t, r, 201, "PAT")
		return r.Str("token")
	}
	jwks := func() jose.JSONWebKeySet {
		var set jose.JSONWebKeySet
		_ = json.Unmarshal(h.Do(Req{Method: "GET", Path: "/realms/main/jwks"}).Raw, &set)
		return set
	}()
	request := func(user, pass string, scopes ...string) (*Resp, map[string]any) {
		t.Helper()
		q := url.Values{"service": {"registry.test"}, "scope": scopes}
		req := Req{Method: "GET", Path: "/realms/main/registry/token?" + q.Encode()}
		if pass != "" {
			req.Headers = map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
		}
		r := h.Do(req)
		if r.Status != 200 {
			return r, nil
		}
		sig, err := jose.ParseSigned(r.Str("token"), []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA})
		if err != nil {
			t.Fatal(err)
		}
		k := jwks.Key(sig.Signatures[0].Header.KeyID)
		payload, err := sig.Verify(k[0])
		if err != nil {
			t.Fatalf("registry token signature: %v", err)
		}
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		if claims["aud"] != "registry.test" || claims["iss"] != h.Realm.Issuer || claims["exp"].(float64)-claims["iat"].(float64) != 300 {
			t.Fatalf("registry token claims: %v", claims)
		}
		return r, claims
	}
	access := func(c map[string]any) string { return jsonString(c["access"]) }

	alicePAT := pat("alice", "pull", "push")
	_, c := request("alice", alicePAT, "repository:acme/app:pull,push", "repository:other/x:pull", "registry:catalog:*")
	if a := access(c); !strings.Contains(a, `"name":"acme/app"`) || !strings.Contains(a, `"push"`) || strings.Contains(a, "other/x") || strings.Contains(a, "catalog") {
		t.Fatalf("alice access: %s", a)
	}
	// Permissions decide: bob can pull but not push.
	_, c = request("bob", pat("bob", "pull", "push"), "repository:acme/app:pull,push")
	if a := access(c); !strings.Contains(a, `"pull"`) || strings.Contains(a, `"push"`) {
		t.Fatalf("bob access: %s", a)
	}
	// The credential's scopes cap the actions.
	_, c = request("alice", pat("alice", "pull"), "repository:acme/app:pull,push")
	if a := access(c); strings.Contains(a, `"push"`) {
		t.Fatalf("pull-only credential pushed: %s", a)
	}
	// Anonymous callers get anonymous pulls only.
	_, c = request("", "", "repository:public/base:pull,push", "repository:acme/app:pull")
	if a := access(c); !strings.Contains(a, "public/base") || strings.Contains(a, `"push"`) || strings.Contains(a, "acme/app") {
		t.Fatalf("anonymous access: %s", a)
	}
	if c["sub"] != "" {
		t.Fatalf("anonymous subject: %v", c["sub"])
	}
	// docker login: no scope, valid credentials.
	if r, c := request("alice", alicePAT); r.Status != 200 || access(c) != "[]" {
		t.Fatalf("login probe: %d %s", r.Status, r.Raw)
	}
	bad, _ := request("alice", "pa_pat_notatoken")
	if bad.Status != 401 || !strings.Contains(bad.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("bad credentials: %d %s", bad.Status, bad.Raw)
	}
	if r := h.Do(Req{Method: "GET", Path: "/realms/main/registry/token?service=elsewhere.test"}); r.Status != 400 {
		t.Fatalf("unknown service: %d", r.Status)
	}
	// A credential minted for another resource is not a registry credential.
	other := f.AccountToken("bob").Tokens.Str("access_token")
	orders := h.API("POST", "/me/personal-tokens", other, map[string]any{"name": "cli", "audience": f.OrdersAud, "scopes": []string{"orders:read"},
		"organization_id": f.Acme, "ttl_days": 30})
	if r, _ := request("bob", orders.Str("token"), "repository:acme/app:pull"); r.Status != 401 {
		t.Fatalf("orders PAT accepted by the registry: %d", r.Status)
	}
	// Machine credentials: a service principal holding a realm role, through
	// its client secret (the grant's scopes cap the actions) or an API key.
	ciRole := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "ci-publisher",
		"permissions": []string{"images.pull", "images.push"}}), 201, "ci role").Str("id")
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "ci-bot", "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": ciRole, "subject": map[string]any{"type": "service_principal", "id": sp}}), 201, "ci role")
	cc := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "ci-runner", "name": "CI runner", "client_type": "machine",
		"service_principal_id": sp, "grant_types": []string{"client_credentials"}}), 201, "ci client")
	f.must(f.AdminAPI("PUT", "/clients/"+cc.Str("client.id")+"/resource-grants/"+registryRes, map[string]any{"allowed_scopes": []string{"pull"},
		"subject_types": []string{"service_principal"}}), 204, "registry grant")
	_, c = request("ci-runner", cc.Str("client_secret"), "repository:ci/app:pull,push", "repository:other/app:pull")
	if a := access(c); !strings.Contains(a, `"name":"ci/app"`) || strings.Contains(a, `"push"`) || strings.Contains(a, "other/app") || c["sub"] != sp {
		t.Fatalf("client-secret access: %s (sub %v)", a, c["sub"])
	}
	if r, _ := request("ci-runner", "wrong-secret", "repository:ci/app:pull"); r.Status != 401 {
		t.Fatalf("wrong client secret: %d", r.Status)
	}
	// An API key bound to Acme reaches Acme's repositories only.
	key := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": sp, "name": "registry", "audience": "https://registry.test",
		"scopes": []string{"pull", "push"}, "organization_id": f.Acme}), 201, "api key").Str("api_key")
	_, c = request("ci", key, "repository:acme/ci-app:pull,push", "repository:ci/app:pull")
	if a := access(c); !strings.Contains(a, `"name":"acme/ci-app"`) || !strings.Contains(a, `"push"`) || strings.Contains(a, `"ci/app"`) {
		t.Fatalf("api-key access: %s", a)
	}

	// Disabling the service stops issuance.
	list := f.must(f.AdminAPI("GET", "/registry-services", nil), 200, "list")
	id := list.Get("items").([]any)[0].(map[string]any)["id"].(string)
	f.must(f.AdminAPI("PUT", "/registry-services/"+id, map[string]any{"state": "disabled", "rules": []map[string]any{{"repository": "public/*", "anonymous_pull": true}}}), 200, "disable")
	if r, _ := request("alice", alicePAT, "repository:public/base:pull"); r.Status != 400 {
		t.Fatalf("disabled registry issued: %d", r.Status)
	}

	// Repeated failed sign-ins from one address are throttled, valid
	// credentials included, until the window passes.
	f.must(f.AdminAPI("PUT", "/registry-services/"+id, map[string]any{"state": "active", "rules": []map[string]any{{"repository": "public/*", "anonymous_pull": true}}}), 200, "enable")
	for i := 0; i < 20; i++ {
		request("alice", "pa_pat_wrong")
	}
	if r, _ := request("alice", alicePAT, "repository:public/base:pull"); r.Status != 429 {
		t.Fatalf("failed sign-ins not throttled: %d", r.Status)
	}
	h.Clock.Advance(16 * time.Minute)
	if r, _ := request("alice", alicePAT, "repository:public/base:pull"); r.Status != 200 {
		t.Fatalf("throttle did not lift: %d", r.Status)
	}
}
