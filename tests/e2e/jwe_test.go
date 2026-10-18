package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// TestEncryptedResponses covers TOK-020 and OIDC-013: ID tokens encrypted to
// a client's registered key (nested: signed, then encrypted), UserInfo as a
// signed JWT and as an encrypted one, only the advertised algorithms, and a
// clear error when the client has no key that can receive the encryption.
func TestEncryptedResponses(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &rsaKey.PublicKey, KeyID: "rsa-enc", Use: "enc"},
		{Key: &ecKey.PublicKey, KeyID: "ec-enc", Use: "enc"},
	}}
	rawJWKS, _ := json.Marshal(jwks)
	alg, err := h.App.Signer.ActiveAlgorithm(ctx, h.Realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	client := func(id string, opts map[string]any) *Resp {
		body := map[string]any{"client_id": id, "name": "JWE", "client_type": "confidential", "first_party": true,
			"redirect_uris": []string{"https://app.test/cb"}, "jwks": json.RawMessage(rawJWKS)}
		for k, v := range opts {
			body[k] = v
		}
		return f.AdminAPI("POST", "/clients", body)
	}
	mustStatus(t, client("jwe-weak", map[string]any{"id_token_encrypted_response_alg": "RSA1_5", "id_token_encrypted_response_enc": "A128GCM"}), 422,
		"RSA1_5 refused")
	mustStatus(t, client("jwe-cbc", map[string]any{"id_token_encrypted_response_alg": "RSA-OAEP-256", "id_token_encrypted_response_enc": "A128CBC-HS256"}), 422,
		"CBC refused")
	mustStatus(t, client("jwe-noenc", map[string]any{"id_token_encrypted_response_alg": "RSA-OAEP-256"}), 422, "enc is explicit")
	other := "RS256"
	if alg == "RS256" {
		other = "ES256"
	}
	mustStatus(t, client("jwe-alg", map[string]any{"userinfo_signed_response_alg": other}), 422, "userinfo signed with another algorithm")
	reg := f.must(client("jwe-app", map[string]any{"id_token_encrypted_response_alg": "RSA-OAEP-256", "id_token_encrypted_response_enc": "A256GCM",
		"userinfo_signed_response_alg": alg, "userinfo_encrypted_response_alg": "ECDH-ES", "userinfo_encrypted_response_enc": "A128GCM"}), 201, "client")
	resources := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	var uiRes, uiAud string
	for _, it := range resources.Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			uiRes, uiAud = m["id"].(string), m["audience"].(string)
		}
	}
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+uiRes, map[string]any{"allowed_scopes": []string{"openid", "email"}}), 204, "grant")
	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	if !strings.Contains(jsonString(disco.Get("id_token_encryption_alg_values_supported")), "RSA-OAEP-256") ||
		strings.Contains(jsonString(disco.Get("id_token_encryption_alg_values_supported")), "RSA1_5") ||
		!strings.Contains(jsonString(disco.Get("userinfo_signing_alg_values_supported")), alg) {
		t.Fatalf("discovery: %v %v", disco.Get("id_token_encryption_alg_values_supported"), disco.Get("userinfo_signing_alg_values_supported"))
	}

	lr := h.Login(LoginOpts{ClientID: "jwe-app", ClientSecret: reg.Str("client_secret"), RedirectURI: "https://app.test/cb", Scope: "openid email",
		Resources: []string{uiAud}, Identifier: "bob@example.test"})
	idt := lr.Tokens.Str("id_token")
	if strings.Count(idt, ".") != 4 {
		t.Fatalf("ID token is not a JWE: %s", idt)
	}
	enc, err := jose.ParseEncrypted(idt, []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	if enc.Header.KeyID != "rsa-enc" || enc.Header.ExtraHeaders["cty"] != "JWT" {
		t.Fatalf("JWE header: %+v", enc.Header)
	}
	inner, err := enc.Decrypt(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwtPayload(string(inner))
	if claims["aud"] == nil || claims["sub"] != f.Users["bob"] || claims["email"] != "bob@example.test" {
		t.Fatalf("inner ID token: %v", claims)
	}
	if typ := jwsType(t, string(inner)); typ != "JWT" {
		t.Fatalf("inner ID token typ: %q", typ)
	}
	// The inner, signed ID token is what the client sends back as a hint.
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout?id_token_hint=" + string(inner)}), 200, "logout with the inner token")

	lr = h.Login(LoginOpts{ClientID: "jwe-app", ClientSecret: reg.Str("client_secret"), RedirectURI: "https://app.test/cb", Scope: "openid email",
		Resources: []string{uiAud}, Identifier: "bob@example.test"})
	ui := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: lr.Tokens.Str("access_token")})
	mustStatus(t, ui, 200, "userinfo")
	if ui.Header.Get("Content-Type") != "application/jwt" {
		t.Fatalf("userinfo media type: %s", ui.Header.Get("Content-Type"))
	}
	uenc, err := jose.ParseEncrypted(string(ui.Raw), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := uenc.Decrypt(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	uc := jwtPayload(string(signed))
	if uc["iss"] != h.Realm.Issuer || uc["aud"] != "jwe-app" || uc["email"] != "bob@example.test" {
		t.Fatalf("signed userinfo: %v", uc)
	}
	// Signed UserInfo has its own typ, so it never passes as an ID token
	// (decision 15, TestLogoutHintTypes).
	if typ := jwsType(t, string(signed)); typ != "userinfo+jwt" {
		t.Fatalf("signed userinfo typ: %q", typ)
	}

	// Encryption without a usable key is refused clearly at issuance.
	sigOnly, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "sig", Use: "sig"}}})
	bad := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "jwe-nokey", "name": "JWE", "client_type": "confidential", "first_party": true,
		"redirect_uris": []string{"https://app.test/cb"}, "jwks": json.RawMessage(sigOnly),
		"id_token_encrypted_response_alg": "RSA-OAEP-256", "id_token_encrypted_response_enc": "A256GCM"}), 201, "client without an encryption key")
	f.must(f.AdminAPI("PUT", "/clients/"+bad.Str("client.id")+"/resource-grants/"+uiRes, map[string]any{"allowed_scopes": []string{"openid"}}), 204, "grant")
	fail := h.Login(LoginOpts{ClientID: "jwe-nokey", ClientSecret: bad.Str("client_secret"), RedirectURI: "https://app.test/cb", Scope: "openid",
		Resources: []string{uiAud}, Identifier: "bob@example.test", ExpectFail: true})
	if fail.Tokens == nil || fail.Tokens.Status != 400 || !strings.Contains(string(fail.Tokens.Raw), "encryption") {
		t.Fatalf("issuance without an encryption key: %v", fail.Tokens)
	}
	// A missing key is a configuration problem, not a used code: the code is
	// not consumed, so a retry gets the same answer instead of being taken
	// for replay (which would revoke the grant), and once a key is
	// registered the same code is redeemed.
	redeem := func() *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"jwe-nokey", bad.Str("client_secret")},
			Form: url.Values{"grant_type": {"authorization_code"}, "code": {fail.Code}, "code_verifier": {fail.Verifier},
				"redirect_uri": {"https://app.test/cb"}, "resource": {uiAud}}})
	}
	if again := redeem(); again.Status != 400 || again.Str("error") != "unauthorized_client" {
		t.Fatalf("retry without an encryption key: %d %s", again.Status, again.Raw)
	}
	var replays int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='token.code.replay_detected' AND realm_id=$1`, h.Realm.ID).
		Scan(&replays); err != nil || replays != 0 {
		t.Fatalf("a configuration problem was recorded as code replay: %d %v", replays, err)
	}
	encOnly, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "enc-later", Use: "enc"}}})
	mustStatus(t, f.AdminAPI("POST", "/clients/"+bad.Str("client.id")+"/credentials", map[string]any{"jwks": json.RawMessage(encOnly)}), 201, "encryption key")
	fixed := redeem()
	mustStatus(t, fixed, 200, "the same code once a key is registered")
	if strings.Count(fixed.Str("id_token"), ".") != 4 {
		t.Fatalf("ID token is not a JWE: %s", fixed.Raw)
	}
	mustStatus(t, redeem(), 400, "the code is single-use once redeemed")

	// Encrypt-only UserInfo: the payload is plain JSON, so the JWE header
	// carries no cty (only nested JWTs name one).
	plainEnc := f.must(client("jwe-ui-enc", map[string]any{"userinfo_encrypted_response_alg": "RSA-OAEP-256", "userinfo_encrypted_response_enc": "A128GCM"}),
		201, "encrypt-only userinfo client")
	f.must(f.AdminAPI("PUT", "/clients/"+plainEnc.Str("client.id")+"/resource-grants/"+uiRes, map[string]any{"allowed_scopes": []string{"openid", "email"}}), 204, "grant")
	lr = h.Login(LoginOpts{ClientID: "jwe-ui-enc", ClientSecret: plainEnc.Str("client_secret"), RedirectURI: "https://app.test/cb", Scope: "openid email",
		Resources: []string{uiAud}, Identifier: "bob@example.test"})
	ui = h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: lr.Tokens.Str("access_token")})
	mustStatus(t, ui, 200, "encrypt-only userinfo")
	if ui.Header.Get("Content-Type") != "application/jwt" {
		t.Fatalf("userinfo media type: %s", ui.Header.Get("Content-Type"))
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(strings.SplitN(string(ui.Raw), ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if _, has := hdr["cty"]; has || hdr["typ"] != "JWT" {
		t.Fatalf("encrypt-only userinfo header: %s", hdrJSON)
	}
	uenc, err = jose.ParseEncrypted(string(ui.Raw), []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	plainClaims, err := uenc.Decrypt(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	var pc map[string]any
	if err := json.Unmarshal(plainClaims, &pc); err != nil || pc["email"] != "bob@example.test" || pc["iss"] != nil {
		t.Fatalf("encrypt-only userinfo payload: %s %v", plainClaims, err)
	}
}

// TestJARM covers ADV-002: with response_mode=jwt or query.jwt the
// authorization response (code or error) is a JWT signed by the realm,
// addressed to the client, optionally encrypted to it; other JWT modes are
// refused, and discovery advertises what is offered.
func TestJARM(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rawJWKS, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &ecKey.PublicKey, KeyID: "ec-enc", Use: "enc"}}})
	alg, _ := h.App.Signer.ActiveAlgorithm(ctx, h.Realm.ID)
	newClient := func(id string, opts map[string]any) *Resp {
		body := map[string]any{"client_id": id, "name": "JARM", "client_type": "confidential", "first_party": true,
			"redirect_uris": []string{"https://app.test/cb"}, "jwks": json.RawMessage(rawJWKS)}
		for k, v := range opts {
			body[k] = v
		}
		return f.must(f.AdminAPI("POST", "/clients", body), 201, "client "+id)
	}
	plain := newClient("jarm-plain", map[string]any{"authorization_signed_response_alg": alg})
	enc := newClient("jarm-enc", map[string]any{"authorization_encrypted_response_alg": "ECDH-ES", "authorization_encrypted_response_enc": "A256GCM"})
	resources := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	for _, it := range resources.Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			for _, c := range []*Resp{plain, enc} {
				f.must(f.AdminAPI("PUT", "/clients/"+c.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid"}}),
					204, "grant")
			}
		}
	}
	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	if modes := jsonString(disco.Get("response_modes_supported")); !strings.Contains(modes, "query.jwt") || strings.Contains(modes, "form_post") {
		t.Fatalf("response modes: %s", modes)
	}
	jwks := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/jwks"}), 200, "jwks")
	var set jose.JSONWebKeySet
	_ = json.Unmarshal(jwks.Raw, &set)
	verify := func(compact string) map[string]any {
		t.Helper()
		sig, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
		if err != nil {
			t.Fatal(err)
		}
		// JARM responses have their own typ, so one never passes as an ID
		// token (decision 15, TestLogoutHintTypes).
		if typ := sig.Signatures[0].Header.ExtraHeaders[jose.HeaderType]; typ != "oauth-authz-resp+jwt" {
			t.Fatalf("JARM response typ: %v", typ)
		}
		keys := set.Key(sig.Signatures[0].Header.KeyID)
		if len(keys) == 0 {
			t.Fatal("response signed with an unpublished key")
		}
		payload, err := sig.Verify(keys[0].Key)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		return m
	}
	var started *Resp
	start := func(clientID, mode string) (string, string, string) {
		t.Helper()
		st, verifier, cont := h.StartTx(LoginOpts{ClientID: clientID, RedirectURI: "https://app.test/cb", Scope: "openid", ResponseMode: mode})
		mustStatus(t, st, 201, "start "+mode)
		started = &Resp{Status: 200, Body: st.Get("state").(map[string]any)}
		return st.Str("transaction_id"), cont, verifier
	}
	mustStatus(t, func() *Resp {
		st, _, _ := h.StartTx(LoginOpts{ClientID: "jarm-plain", RedirectURI: "https://app.test/cb", Scope: "openid", ResponseMode: "form_post.jwt"})
		return st
	}(), 400, "form_post.jwt not offered")

	id, cont, verifier := start("jarm-plain", "jwt")
	done := h.Drive(id, cont, started, LoginOpts{Identifier: "bob@example.test"})
	u, _ := url.Parse(done.Str("redirect_to"))
	if u.Query().Get("code") != "" || u.Query().Get("response") == "" {
		t.Fatalf("JARM redirect: %s", done.Str("redirect_to"))
	}
	claims := verify(u.Query().Get("response"))
	if claims["iss"] != h.Realm.Issuer || claims["aud"] != "jarm-plain" || claims["code"] == nil || claims["exp"] == nil || claims["state"] == nil {
		t.Fatalf("JARM claims: %v", claims)
	}
	tok := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {claims["code"].(string)}, "code_verifier": {verifier},
		"redirect_uri": {"https://app.test/cb"}}, "jarm-plain", plain.Str("client_secret"))
	mustStatus(t, tok, 200, "code from the JWT response")

	// Encrypted to the client (nested), and errors use the same mode.
	id, cont, _ = start("jarm-enc", "query.jwt")
	cancel := h.Step(id, cont, "cancel", nil)
	u, _ = url.Parse(cancel.Str("redirect_to"))
	resp := u.Query().Get("response")
	if strings.Count(resp, ".") != 4 || u.Query().Get("error") != "" {
		t.Fatalf("encrypted JARM error response: %s", cancel.Str("redirect_to"))
	}
	obj, err := jose.ParseEncrypted(resp, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := obj.Decrypt(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if ec := verify(string(inner)); ec["error"] != "access_denied" || ec["aud"] != "jarm-enc" {
		t.Fatalf("JARM error claims: %v", ec)
	}
}

// jwsType returns the typ header of a compact JWS.
func jwsType(t *testing.T, compact string) string {
	t.Helper()
	seg, err := base64.RawURLEncoding.DecodeString(strings.SplitN(compact, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(seg, &hdr); err != nil {
		t.Fatal(err)
	}
	typ, _ := hdr["typ"].(string)
	return typ
}
