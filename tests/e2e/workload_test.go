package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/worker"
)

// TestWorkloadFederation covers MCH-011..MCH-013 and ADV-004: a machine
// client trusts named workload issuers (GitHub Actions, a Kubernetes cluster,
// a SPIFFE trust domain); an assertion becomes a short local token for the
// client's service principal only when issuer, key, algorithm, audience,
// lifetime, subject, claims and jti all match. Client authentication and the
// authorization grant stay separate, and refusals leave evidence.
func TestWorkloadFederation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	key := func() (*rsa.PrivateKey, json.RawMessage) {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		b, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		return k, b
	}
	ghKey, ghJWKS := key()
	k8sKey, k8sJWKS := key()
	spiffeKey, spiffeJWKS := key()
	otherKey, _ := key()
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(k8sJWKS)
	}))
	defer jwksSrv.Close()
	// The cluster's key endpoint is on a private address: reachable only
	// through an explicit egress allowance, as for federation.
	h.App.Workload.Egress.AllowCIDRs = []string{"127.0.0.1/32"}

	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "ci-deployer", "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	wl := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "wl-ci", "name": "CI workloads", "client_type": "machine",
		"service_principal_id": sp, "token_endpoint_auth_method": "none", "grant_types": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"}}), 201, "client")
	ref := wl.Str("client.id")
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "wl-bad", "name": "x", "client_type": "machine", "service_principal_id": sp,
		"token_endpoint_auth_method": "none", "grant_types": []string{"client_credentials"}}), 422, "secretless machine client with client credentials")
	f.must(f.AdminAPI("PUT", "/clients/"+ref+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal"}}), 204, "grant")
	trusts := "/clients/" + ref + "/workload-trusts"
	mustStatus(t, f.AdminAPI("POST", "/clients/"+f.Clients["web"].Ref+"/workload-trusts", map[string]any{"name": "x", "profile": "kubernetes",
		"issuer": "https://k8s.example", "jwks": ghJWKS, "audience": "a", "subject": "system:serviceaccount:a:b"}), 409, "client without the grant")
	for name, body := range map[string]map[string]any{
		"generic wildcard":       {"profile": "generic", "issuer": "https://idp.example", "jwks": ghJWKS, "audience": "a", "subject": "*"},
		"kubernetes wildcard":    {"profile": "kubernetes", "issuer": "https://k8s.example", "jwks": ghJWKS, "audience": "a", "subject": "system:serviceaccount:*:api"},
		"github any repository":  {"profile": "github_actions", "jwks": ghJWKS, "audience": "a", "subject": "repo:*"},
		"two key sources":        {"profile": "generic", "issuer": "https://idp.example", "jwks": ghJWKS, "jwks_uri": jwksSrv.URL, "audience": "a", "subject": "x"},
		"no audience":            {"profile": "generic", "issuer": "https://idp.example", "jwks": ghJWKS, "subject": "x"},
		"symmetric algorithm":    {"profile": "generic", "issuer": "https://idp.example", "jwks": ghJWKS, "audience": "a", "subject": "x", "algorithms": []string{"HS256"}},
		"reserved claim":         {"profile": "generic", "issuer": "https://idp.example", "jwks": ghJWKS, "audience": "a", "subject": "x", "claim_constraints": map[string][]string{"sub": {"x"}}},
		"spiffe outside domains": {"profile": "spiffe", "jwks": ghJWKS, "audience": "a", "subject": "https://example.org/x"},
	} {
		body["name"] = name
		mustStatus(t, f.AdminAPI("POST", trusts, body), 422, name)
	}
	gh := f.must(f.AdminAPI("POST", trusts, map[string]any{"name": "deploy from main", "profile": "github_actions", "jwks": ghJWKS,
		"audience": "https://proudauth.example/wl", "subject": "repo:acme/api:environment:prod",
		"claim_constraints": map[string][]string{"repository_owner": {"acme"}, "repository_id": {"4242"}}}), 201, "github trust")
	if gh.Str("issuer") != "https://token.actions.githubusercontent.com" || gh.Get("require_jti") != true || gh.Header.Get("ETag") == "" {
		t.Fatalf("github profile defaults: %s", gh.Raw)
	}
	f.must(f.AdminAPI("POST", trusts, map[string]any{"name": "payments api", "profile": "kubernetes", "issuer": "https://k8s.example",
		"jwks_uri": jwksSrv.URL + "/keys", "audience": "proudauth", "subject": "system:serviceaccount:payments:api",
		"claim_constraints": map[string][]string{"kubernetes.io/namespace": {"payments"}}}), 201, "kubernetes trust")
	f.must(f.AdminAPI("POST", trusts, map[string]any{"name": "mesh", "profile": "spiffe", "jwks": spiffeJWKS, "audience": "proudauth",
		"subject": "spiffe://example.org/ns/payments/*"}), 201, "spiffe trust")
	list := f.must(f.AdminAPI("GET", trusts, nil), 200, "list")
	if len(list.Get("items").([]any)) != 3 {
		t.Fatalf("trust list: %s", list.Raw)
	}

	now := time.Now()
	sign := func(k *rsa.PrivateKey, claims map[string]any) string {
		t.Helper()
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		out, err := jwt.Signed(s).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	ghClaims := func(mut func(m map[string]any)) map[string]any {
		m := map[string]any{"iss": "https://token.actions.githubusercontent.com", "sub": "repo:acme/api:environment:prod", "aud": "https://proudauth.example/wl",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": "j-" + time.Now().Format("150405.000000000"),
			"repository_owner": "acme", "repository_id": "4242"}
		if mut != nil {
			mut(m)
		}
		return m
	}
	exchange := func(assertion string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion},
			"resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}, "wl-ci", "")
	}
	// A request refused after the assertion is verified (an organization
	// the service principal may not use, a scope beyond its grant) does not
	// spend the assertion's jti: the same assertion is accepted once the
	// request is right, and only that use makes it single-use.
	first := sign(ghKey, ghClaims(nil))
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {first},
		"resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Globex}}, "wl-ci", ""), 400, "organization not allowed")
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {first},
		"resource": {f.BillingAud}, "scope": {"billing:admin"}, "organization": {f.Acme}}, "wl-ci", ""), 400, "scope beyond the grant")
	mustStatus(t, exchange(first), 200, "the assertion after refused requests")
	mustStatus(t, exchange(first), 400, "the assertion replayed after its use")
	var replayEvidence int
	_ = h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE type='workload.assertion.rejected' AND metadata->>'reason' LIKE '%replayed jti%'`).
		Scan(&replayEvidence)
	if replayEvidence == 0 {
		t.Fatal("a replayed assertion left no evidence")
	}
	ok := ghClaims(nil)
	assertion := sign(ghKey, ok)
	tok := exchange(assertion)
	mustStatus(t, tok, 200, "github workload token")
	claims := jwtPayload(tok.Str("access_token"))
	if claims["sub"] != sp || claims["token_kind"] != "service_access" || tok.Get("expires_in").(float64) > 300 {
		t.Fatalf("workload token: %v %v", claims, tok.Get("expires_in"))
	}
	mustStatus(t, exchange(assertion), 400, "replayed assertion")
	for name, m := range map[string]map[string]any{
		"wrong audience":      ghClaims(func(m map[string]any) { m["aud"] = "https://other.example" }),
		"other repository":    ghClaims(func(m map[string]any) { m["sub"] = "repo:evil/api:environment:prod" }),
		"constraint mismatch": ghClaims(func(m map[string]any) { m["repository_id"] = "1" }),
		"expired": ghClaims(func(m map[string]any) {
			m["exp"] = now.Add(-5 * time.Minute).Unix()
			m["iat"] = now.Add(-10 * time.Minute).Unix()
		}),
		"too long":         ghClaims(func(m map[string]any) { m["exp"] = now.Add(3 * time.Hour).Unix() }),
		"no jti":           ghClaims(func(m map[string]any) { delete(m, "jti") }),
		"untrusted issuer": ghClaims(func(m map[string]any) { m["iss"] = "https://evil.example" }),
		"no expiry":        ghClaims(func(m map[string]any) { delete(m, "exp") }),
	} {
		mustStatus(t, exchange(sign(ghKey, m)), 400, name)
	}
	mustStatus(t, exchange(sign(otherKey, ghClaims(nil))), 400, "wrong key")
	unsigned := strings.Join([]string{"eyJhbGciOiJub25lIn0", strings.Split(assertion, ".")[1], ""}, ".")
	mustStatus(t, exchange(unsigned), 400, "unsigned assertion")
	// A client assertion (client authentication) is not an authorization grant.
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "client_assertion": {assertion},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "resource": {f.BillingAud}}, "wl-ci", ""), 401,
		"client assertion in place of a grant")
	var rejected int
	_ = h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE type='workload.assertion.rejected' AND metadata->>'reason' LIKE '%audience%'`).Scan(&rejected)
	if rejected == 0 {
		t.Fatal("refused assertion left no evidence")
	}

	// Kubernetes: one service account in one namespace, keys from the cluster.
	k8s := func(sub, ns string) string {
		return sign(k8sKey, map[string]any{"iss": "https://k8s.example", "sub": sub, "aud": []string{"proudauth", "other"}, "iat": now.Unix(),
			"exp": now.Add(10 * time.Minute).Unix(), "kubernetes.io": map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": "api"}}})
	}
	if r := exchange(k8s("system:serviceaccount:payments:api", "payments")); r.Status != 200 {
		var reason string
		_ = h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT metadata->>'reason' FROM audit_events WHERE type='workload.assertion.rejected' ORDER BY recorded_at DESC, id DESC LIMIT 1`).Scan(&reason)
		t.Fatalf("kubernetes workload: %d %s (%s)", r.Status, r.Raw, reason)
	}
	mustStatus(t, exchange(k8s("system:serviceaccount:payments:batch", "payments")), 400, "another service account of the cluster")
	// SPIFFE: a JWT-SVID without iss, within the trust domain prefix.
	svid := func(sub string) string {
		return sign(spiffeKey, map[string]any{"sub": sub, "aud": "proudauth", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix()})
	}
	mustStatus(t, exchange(svid("spiffe://example.org/ns/payments/sa/api")), 200, "spiffe workload")
	mustStatus(t, exchange(svid("spiffe://example.org/ns/other/sa/api")), 400, "outside the SPIFFE path")
	mustStatus(t, exchange(svid("spiffe://evil.org/ns/payments/sa/api")), 400, "another trust domain")

	// Disabling a trust stops it at once; the If-Match version is required.
	cur := f.must(f.AdminAPI("GET", trusts+"/"+gh.Str("id"), nil), 200, "get")
	body := map[string]any{"name": "deploy from main", "profile": "github_actions", "jwks": ghJWKS, "audience": "https://proudauth.example/wl",
		"subject": "repo:acme/api:environment:prod", "state": "disabled"}
	mustStatus(t, f.AdminAPI("PUT", trusts+"/"+gh.Str("id"), body), 428, "update without If-Match")
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + trusts + "/" + gh.Str("id"), Token: f.AdminToken, JSON: body,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "disable")
	mustStatus(t, exchange(sign(ghKey, ghClaims(nil))), 400, "disabled trust")
	mustStatus(t, f.AdminAPI("DELETE", trusts+"/"+gh.Str("id"), nil), 204, "delete")

	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	if !strings.Contains(jsonString(disco.Get("grant_types_supported")), "jwt-bearer") {
		t.Fatalf("grant types: %v", disco.Get("grant_types_supported"))
	}

	// Replay records go with the worker's retention run once they expire,
	// also those of trusts that are no longer used; live ones stay.
	nowDB := h.Clock.Now()
	if _, err := h.App.D.DB.Pool.Exec(t.Context(), `INSERT INTO workload_assertion_jtis (trust_id, jti, expires_at) VALUES
		('wlt_unused', 'expired', $1), ('wlt_unused', 'live', $2)`, nowDB.Add(-time.Minute), nowDB.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.New(h.App, "test").Retention(t.Context()); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := h.App.D.DB.Pool.Query(t.Context(), `SELECT jti FROM workload_assertion_jtis WHERE trust_id='wlt_unused'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var j string
		_ = rows.Scan(&j)
		left = append(left, j)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "live" {
		t.Fatalf("replay records after retention: %v", left)
	}
}
