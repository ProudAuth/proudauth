package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestPrivateKeyJWT covers APP-009 and MCH-010: a machine client
// authenticates with a signed assertion from its registered key; the
// assertion is single-use, short-lived and addressed to this server only:
// its aud is the issuer as a single JSON string (decision 16). The token
// endpoint URL and arrays, even ["<issuer>"], are refused unless the realm
// sets client_auth.allow_endpoint_audience, which re-admits them but never
// an audience naming another party.
func TestPrivateKeyJWT(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "jwt-job", "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	c := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "jwt-job", "name": "JWT job", "client_type": "machine",
		"service_principal_id": sp, "token_endpoint_auth_method": "private_key_jwt", "jwks": json.RawMessage(jwks)}), 201, "client")
	if c.Str("client_secret") != "" {
		t.Fatalf("a private_key_jwt client got a secret: %s", c.Raw)
	}
	// Registering keys for a client that does not exist is a missing
	// resource, not an unacceptable key set.
	mustStatus(t, f.AdminAPI("POST", "/clients/cli_doesnotexist/credentials", map[string]any{"jwks": json.RawMessage(jwks)}), 404, "keys for an unknown client")
	f.must(f.AdminAPI("PUT", "/clients/"+c.Str("client.id")+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal"}}), 204, "grant")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := h.Realm.Issuer + "/oauth/token"
	// aud is a string or a []string, serialized as given: a JWT library
	// would write a one-element list as a string.
	assertion := func(aud any, ttl time.Duration, jti string) string {
		now := h.Clock.Now()
		s, err := jwt.Signed(signer).Claims(map[string]any{"iss": "jwt-job", "sub": "jwt-job", "aud": aud, "jti": jti,
			"iat": now.Unix(), "exp": now.Add(ttl).Unix()}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	token := func(a string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme},
			"client_id": {"jwt-job"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {a}}, "", "")
	}
	jti := func() string { return hex.EncodeToString(secret.Random(8)) }
	good := assertion(h.Realm.Issuer, time.Minute, jti())
	if r := token(good); r.Status != 200 || r.Str("access_token") == "" {
		t.Fatalf("private_key_jwt: %d %s", r.Status, r.Raw)
	}
	if r := token(good); r.Status != 401 {
		t.Fatalf("replayed assertion: %d %s", r.Status, r.Raw)
	}
	// Refused by default (decision 16), and the audiences refused whatever
	// the realm allows.
	legacy := map[string]any{
		"token endpoint URL":         endpoint,
		"issuer in an array":         []string{h.Realm.Issuer},
		"token endpoint in an array": []string{endpoint},
		"endpoint and issuer":        []string{endpoint, h.Realm.Issuer},
	}
	never := map[string]any{
		"another audience too":   []string{endpoint, "https://other.test/token"},
		"issuer and another":     []string{h.Realm.Issuer, "https://other.test"},
		"three audiences":        []string{h.Realm.Issuer, endpoint, h.Realm.Issuer},
		"another server":         "https://other.test",
		"issuer with a slash":    h.Realm.Issuer + "/",
		"the introspection URL":  h.Realm.Issuer + "/oauth/introspect",
		"an empty audience list": []string{},
	}
	for name, aud := range legacy {
		mustStatus(t, token(assertion(aud, time.Minute, jti())), 401, name+" by default")
	}
	for name, aud := range never {
		mustStatus(t, token(assertion(aud, time.Minute, jti())), 401, name)
	}
	mustStatus(t, token(assertion(h.Realm.Issuer, time.Hour, jti())), 401, "long-lived")

	// client_auth.allow_endpoint_audience re-admits the endpoint URL and
	// arrays naming this server for clients other than fapi2 ones.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.ClientAuth.AllowEndpointAudience = true }), 200, "allow endpoint audiences")
	for name, aud := range legacy {
		mustStatus(t, token(assertion(aud, time.Minute, jti())), 200, name+" with allow_endpoint_audience")
	}
	for name, aud := range never {
		mustStatus(t, token(assertion(aud, time.Minute, jti())), 401, name+" with allow_endpoint_audience")
	}
	mustStatus(t, token(assertion(h.Realm.Issuer, time.Minute, jti())), 200, "issuer with allow_endpoint_audience")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.ClientAuth.AllowEndpointAudience = false }), 200, "strict again")
	mustStatus(t, token(assertion(endpoint, time.Minute, jti())), 401, "token endpoint URL once the realm is strict again")

	// A different key than the registered one never authenticates.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	mustStatus(t, token(assertion(h.Realm.Issuer, time.Minute, "j-other")), 401, "unregistered key")
}

// TestClientSecretLifecycle covers APP-003, APP-008, MCH-009, TOK-010 and
// TOK-024: secret rotation with a bounded overlap, revocation of refresh
// tokens, decommissioning, and no-store token responses.
func TestClientSecretLifecycle(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	batch := f.Clients["batch"]
	old := f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme)
	mustStatus(t, old, 200, "old secret")
	if cc := old.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("token response Cache-Control: %q", cc)
	}
	rot := f.must(f.AdminAPI("POST", "/clients/"+batch.Ref+"/credentials", map[string]any{"retire_others_after_seconds": 120}), 201, "rotate")
	fresh := Client{ID: batch.ID, Secret: rot.Str("client_secret"), Ref: batch.Ref}
	mustStatus(t, f.MachineToken(fresh, f.BillingAud, "billing:read", f.Acme), 200, "new secret")
	mustStatus(t, f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme), 200, "old secret during the overlap")
	h.Clock.Advance(3 * time.Minute)
	if r := f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
		t.Fatal("old secret accepted after the overlap")
	}
	mustStatus(t, f.MachineToken(fresh, f.BillingAud, "billing:read", f.Acme), 200, "new secret after the overlap")

	// Revocation of a refresh token (RFC 7009): the token and its family stop.
	lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	rt := lr.Tokens.Str("refresh_token")
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {rt}, "token_type_hint": {"refresh_token"}},
		Basic: [2]string{"web-bff", f.Clients["web"].Secret}}), 200, "revoke")
	if r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", f.Clients["web"].Secret); r.Status == 200 {
		t.Fatal("revoked refresh token used")
	}
	// Revoking an unknown token is not an error (no information leak).
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {"pa_rt_unknown"}},
		Basic: [2]string{"web-bff", f.Clients["web"].Secret}}), 200, "unknown token")

	// Decommissioning ends the client for good.
	mustStatus(t, f.AdminAPI("POST", "/clients/"+batch.Ref+"/decommission", map[string]any{"reason": "replaced"}), 200, "decommission")
	if r := f.MachineToken(fresh, f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
		t.Fatal("decommissioned client issued a token")
	}
	if r := f.AdminAPI("POST", "/clients/"+batch.Ref+"/reactivate", map[string]any{"reason": "oops"}); r.Status == 200 {
		t.Fatalf("decommissioned client reactivated: %s", r.Raw)
	}
}
