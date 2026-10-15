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
)

// TestPrivateKeyJWT covers APP-009 and MCH-010: a machine client
// authenticates with a signed assertion from its registered key; the
// assertion is single-use, short-lived and addressed to this server only.
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
	assertion := func(aud []string, ttl time.Duration, jti string) string {
		now := h.Clock.Now()
		s, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: "jwt-job", Subject: "jwt-job", Audience: aud, ID: jti,
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(ttl))}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	token := func(a string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme},
			"client_id": {"jwt-job"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {a}}, "", "")
	}
	good := assertion([]string{endpoint}, time.Minute, hex.EncodeToString(secret.Random(8)))
	if r := token(good); r.Status != 200 || r.Str("access_token") == "" {
		t.Fatalf("private_key_jwt: %d %s", r.Status, r.Raw)
	}
	if r := token(good); r.Status != 401 {
		t.Fatalf("replayed assertion: %d %s", r.Status, r.Raw)
	}
	for name, a := range map[string]string{
		"another audience too": assertion([]string{endpoint, "https://other.test/token"}, time.Minute, "j-aud"),
		"long-lived":           assertion([]string{endpoint}, time.Hour, "j-ttl"),
		"issuer as audience":   assertion([]string{h.Realm.Issuer}, time.Minute, "j-iss"),
	} {
		r := token(a)
		if name == "issuer as audience" {
			mustStatus(t, r, 200, name)
			continue
		}
		if r.Status != 401 {
			t.Fatalf("%s accepted: %d %s", name, r.Status, r.Raw)
		}
	}
	// A different key than the registered one never authenticates.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	mustStatus(t, token(assertion([]string{endpoint}, time.Minute, "j-other")), 401, "unregistered key")
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
