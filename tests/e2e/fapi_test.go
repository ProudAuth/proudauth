package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestFAPI2Profile covers ADV-001: the fapi2 client profile is a separately
// enforced rule set (confidential client, private_key_jwt or mutual TLS with
// FAPI algorithms and the issuer as the assertion's only audience, PAR, PKCE,
// sender-constrained tokens, https redirects, 60-second codes, short access
// tokens, no refresh-token rotation, a realm signing algorithm FAPI allows),
// not ordinary defaults with a label.
func TestFAPI2Profile(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Keys.SigningAlgorithm = "PS256" })
	f := fixtureOn(t, h)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "c1", Use: "sig"}}})
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{"client_id": "bank-app", "name": "Bank app", "client_type": "confidential", "security_profile": "fapi2",
			"token_endpoint_auth_method": "private_key_jwt", "jwks": json.RawMessage(jwks), "redirect_uris": []string{"https://bank.test/cb"},
			"grant_types": []string{"authorization_code", "refresh_token"}, "token_policy": map[string]any{"require_dpop": true}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", base(map[string]any{"token_policy": map[string]any{}})), 422, "no sender constraint")
	mustStatus(t, f.AdminAPI("POST", "/clients", base(map[string]any{"token_endpoint_auth_method": "client_secret_basic", "jwks": nil})), 422, "shared secret")
	mustStatus(t, f.AdminAPI("POST", "/clients", base(map[string]any{"redirect_uris": []string{"http://127.0.0.1/cb"}})), 422, "non-https redirect")
	mustStatus(t, f.AdminAPI("POST", "/clients", base(map[string]any{"grant_types": []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"}})),
		422, "other grants")
	reg := f.must(f.AdminAPI("POST", "/clients", base(nil)), 201, "fapi2 client")
	if reg.Get("client.token_policy.require_par") != true {
		t.Fatalf("PAR not forced: %s", reg.Raw)
	}
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"}}), 204, "grant")

	assertion := func(alg jose.SignatureAlgorithm) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: "c1"}}, nil)
		out, _ := jwt.Signed(s).Claims(map[string]any{"iss": "bank-app", "sub": "bank-app", "aud": h.Realm.Issuer, "jti": secret.Numeric(16),
			"iat": h.Clock.Now().Unix(), "exp": h.Clock.Now().Add(time.Minute).Unix()}).Serialize()
		return out
	}
	clientAuth := func(form url.Values, alg jose.SignatureAlgorithm) url.Values {
		form.Set("client_id", "bank-app")
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion(alg))
		return form
	}
	dkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dpop := func() string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: dkey}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		out, _ := jwt.Signed(s).Claims(map[string]any{"jti": secret.Numeric(12), "htm": "POST", "htu": h.Realm.Issuer + "/oauth/token", "iat": h.Clock.Now().Unix()}).Serialize()
		return out
	}
	loginFor := func(scope, resource string) (string, string) {
		t.Helper()
		verifier, challenge := PKCE()
		par := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/par", Form: clientAuth(url.Values{"response_type": {"code"}, "redirect_uri": {"https://bank.test/cb"},
			"scope": {scope}, "resource": {resource}, "organization": {f.Acme}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
			"state": {"s1"}}, jose.PS256)})
		mustStatus(t, par, 201, "PAR")
		st := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": "bank-app", "request_uri": par.Str("request_uri")})
		mustStatus(t, st, 201, "start from PAR")
		done := h.Drive(st.Str("transaction_id"), st.Str("continuation_token"), &Resp{Status: 200, Body: st.Get("state").(map[string]any)},
			LoginOpts{Identifier: "bob@example.test", SelectOrg: f.Acme})
		u, _ := url.Parse(done.Str("redirect_to"))
		if u.Query().Get("code") == "" {
			t.Fatalf("fapi2 login: %s", done.Raw)
		}
		return u.Query().Get("code"), verifier
	}
	login := func() (string, string) { return loginFor("orders:read", f.OrdersAud) }
	// Without PAR the authorization request is refused.
	if st, _, _ := h.StartTx(LoginOpts{ClientID: "bank-app", RedirectURI: "https://bank.test/cb", Scope: "orders:read", Resources: []string{f.OrdersAud}}); st.Status != 400 {
		t.Fatalf("authorization without PAR: %d %s", st.Status, st.Raw)
	}
	code, verifier := login()
	exchange := func(code, verifier string, alg jose.SignatureAlgorithm, proof bool) *Resp {
		hdr := map[string]string{}
		if proof {
			hdr["DPoP"] = dpop()
		}
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Headers: hdr, Form: clientAuth(url.Values{"grant_type": {"authorization_code"},
			"code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://bank.test/cb"}, "resource": {f.OrdersAud}}, alg)})
	}
	mustStatus(t, exchange(code, verifier, jose.RS256, true), 401, "RS256 client assertion")
	mustStatus(t, exchange(code, verifier, jose.PS256, false), 400, "no DPoP proof")
	tok := exchange(code, verifier, jose.PS256, true)
	mustStatus(t, tok, 200, "fapi2 tokens")
	claims := jwtPayload(tok.Str("access_token"))
	if tok.Str("token_type") != "DPoP" || claims["exp"].(float64)-claims["iat"].(float64) > 600 {
		t.Fatalf("fapi2 access token: %s %v", tok.Raw, claims)
	}
	// Refresh tokens are not rotated: the same token keeps working.
	rt := tok.Str("refresh_token")
	for i := range 2 {
		r := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Headers: map[string]string{"DPoP": dpop()},
			Form: clientAuth(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, jose.PS256)})
		mustStatus(t, r, 200, "refresh")
		if r.Str("refresh_token") != rt {
			t.Fatalf("refresh %d rotated the token", i)
		}
	}
	// The assertion's aud is the issuer as a single JSON string (FAPI 2.0,
	// RFC 7523bis, decision 16): an endpoint URL, which the audience-injection
	// attack relies on, and arrays are refused, also when the realm re-admits
	// them for other clients (client_auth.allow_endpoint_audience).
	audAssertion := func(aud any) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: jose.JSONWebKey{Key: key, KeyID: "c1"}}, nil)
		out, _ := jwt.Signed(s).Claims(map[string]any{"iss": "bank-app", "sub": "bank-app", "aud": aud, "jti": secret.Numeric(16),
			"iat": h.Clock.Now().Unix(), "exp": h.Clock.Now().Add(time.Minute).Unix()}).Serialize()
		return out
	}
	refreshWith := func(aud any) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Headers: map[string]string{"DPoP": dpop()}, Form: url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"bank-app"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {audAssertion(aud)}}})
	}
	tokenURL := h.Realm.Issuer + "/oauth/token"
	refused := map[string]any{
		"token endpoint URL":         tokenURL,
		"issuer in an array":         []string{h.Realm.Issuer},
		"token endpoint in an array": []string{tokenURL},
		"endpoint and issuer":        []string{tokenURL, h.Realm.Issuer},
	}
	for _, strict := range []bool{true, false} {
		mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.ClientAuth.AllowEndpointAudience = !strict }), 200, "realm client_auth policy")
		for name, aud := range refused {
			mustStatus(t, refreshWith(aud), 401, fmt.Sprintf("fapi2 assertion with %s (allow_endpoint_audience %v)", name, !strict))
		}
		mustStatus(t, refreshWith(h.Realm.Issuer), 200, fmt.Sprintf("fapi2 assertion with the issuer (allow_endpoint_audience %v)", !strict))
	}
	_, parChallenge := PKCE()
	par := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/par", Form: url.Values{"response_type": {"code"}, "redirect_uri": {"https://bank.test/cb"},
		"scope": {"orders:read"}, "resource": {f.OrdersAud}, "code_challenge": {parChallenge}, "code_challenge_method": {"S256"}, "client_id": {"bank-app"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {audAssertion(h.Realm.Issuer + "/oauth/par")}}})
	mustStatus(t, par, 401, "fapi2 assertion naming the PAR endpoint")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.ClientAuth.AllowEndpointAudience = false }), 200, "strict realm")

	// Codes live at most 60 seconds.
	code, verifier = login()
	h.Clock.Advance(61 * time.Second)
	mustStatus(t, exchange(code, verifier, jose.PS256, true), 400, "code older than 60 seconds")

	// An organization switch issues a code outside PAR, so a fapi2 client
	// never gets one there; it switches with a new pushed request instead.
	var accountRes string
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "account" {
			accountRes = m["id"].(string)
		}
	}
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+accountRes, map[string]any{"allowed_scopes": []string{"proudauth:account"}}),
		204, "account grant")
	code, verifier = loginFor("proudauth:account", h.Realm.Issuer+"/account")
	acct := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Headers: map[string]string{"DPoP": dpop()}, Form: clientAuth(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://bank.test/cb"},
		"resource": {h.Realm.Issuer + "/account"}}, jose.PS256)})
	mustStatus(t, acct, 200, "fapi2 account token")
	accountAT := acct.Str("access_token")
	switchURL := h.Base + "/api/v1/realms/main/me/organization-grants"
	sum := sha256.Sum256([]byte(accountAT))
	ps, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: dkey}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	switchProof, _ := jwt.Signed(ps).Claims(map[string]any{"jti": secret.Numeric(12), "htm": "POST", "htu": switchURL, "iat": h.Clock.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(sum[:])}).Serialize()
	_, switchChallenge := PKCE()
	sw := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/me/organization-grants", Headers: map[string]string{"Authorization": "DPoP " + accountAT,
		"DPoP": switchProof}, JSON: map[string]any{"client_id": "bank-app", "organization_id": f.Globex, "redirect_uri": "https://bank.test/cb",
		"code_challenge": switchChallenge, "code_challenge_method": "S256", "scope": "orders:read", "resource": []string{f.OrdersAud}, "state": "s2"}})
	if sw.Status != 403 || !strings.Contains(string(sw.Raw), "pushed authorization") {
		t.Fatalf("organization switch for a fapi2 client: %d %s", sw.Status, sw.Raw)
	}

	// A realm signing with RS256 cannot register fapi2 clients.
	h2 := NewHarness(t)
	f2 := fixtureOn(t, h2)
	mustStatus(t, f2.AdminAPI("POST", "/clients", base(nil)), 422, "RS256 realm")
}
