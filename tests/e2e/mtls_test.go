package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/realm"
)

// testCA issues certificates for mutual-TLS and X.509 tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
	next int64
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name, Organization: []string{"Test"}}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), next: 100}
}

// issue returns a client certificate (signed by the CA, or self-signed when
// ca is nil) with its TLS form and PEM.
func issue(t *testing.T, ca *testCA, cn string, email string) (tls.Certificate, *x509.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := big.NewInt(time.Now().UnixNano())
	if ca != nil {
		ca.next++
		serial = big.NewInt(ca.next)
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"Acme"}}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if email != "" {
		tpl.EmailAddresses = []string{email}
	}
	parent, signer := tpl, any(key)
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: c}, c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func x5t(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestMutualTLS covers TOK-019 and MCH-014 (RFC 8705): tls_client_auth
// against realm trust anchors and one registered certificate identity,
// self_signed_tls_client_auth against registered certificates,
// certificate-bound tokens that the IdP's own endpoints honour, clients
// that never get a bearer token without their certificate, and the proxy
// header honoured only from trusted proxies.
func TestMutualTLS(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Server.ClientCertHeader = "X-Client-Cert"
		c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	})
	f := fixtureOn(t, h)
	ca := newTestCA(t, "Acme Machines CA")
	other := newTestCA(t, "Unknown CA")
	_, _, leafPEM := issue(t, ca, "not-a-ca", "")
	mustStatus(t, f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "client", "name": "leaf", "certificate_pem": leafPEM}), 422,
		"a leaf certificate is not an authority")
	f.must(f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "client", "name": "Acme machines", "certificate_pem": ca.pem}), 201, "anchor")
	mustStatus(t, f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "client", "name": "again", "certificate_pem": ca.pem}), 409, "duplicate anchor")

	good, goodCert, _ := issue(t, ca, "billing-sync", "")
	wrongName, _, _ := issue(t, ca, "someone-else", "")
	untrusted, _, _ := issue(t, other, "billing-sync", "")
	selfSigned, selfCert, _ := issue(t, nil, "self-signed-sync", "")
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "mtls-svc", "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "mtls-bad", "name": "x", "client_type": "machine", "service_principal_id": sp,
		"token_endpoint_auth_method": "tls_client_auth"}), 422, "tls_client_auth without an identity")
	reg := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "mtls-svc", "name": "mTLS service", "client_type": "machine", "service_principal_id": sp,
		"token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_subject_dn": goodCert.Subject.String(), "tls_client_certificate_bound_access_tokens": true}), 201, "client")
	if reg.Str("client_secret") != "" {
		t.Fatalf("a certificate client got a secret: %s", reg.Raw)
	}
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal"}}), 204, "grant")
	selfJWKS, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: selfCert.PublicKey, Certificates: []*x509.Certificate{selfCert}, KeyID: "self"}}})
	self := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "mtls-self", "name": "Self-signed", "client_type": "machine",
		"service_principal_id": sp, "token_endpoint_auth_method": "self_signed_tls_client_auth", "jwks": json.RawMessage(selfJWKS)}), 201, "self-signed client")
	f.must(f.AdminAPI("PUT", "/clients/"+self.Str("client.id")+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal"}}), 204, "grant")

	// The mutual-TLS listener: same handler, client certificates requested.
	mt := httptest.NewUnstartedServer(h.Srv.Config.Handler)
	mt.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	mt.StartTLS()
	defer mt.Close()
	tokenWith := func(clientID string, cert *tls.Certificate) *Resp {
		t.Helper()
		cl := mt.Client()
		tr := cl.Transport.(*http.Transport).Clone()
		if cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}
		saved := h.HTTP
		h.HTTP = &http.Client{Transport: tr, Timeout: 10 * time.Second}
		defer func() { h.HTTP = saved }()
		return h.Do(Req{Method: "POST", Path: mt.URL + "/realms/main/oauth/token", Form: url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
			"resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}})
	}
	tok := tokenWith("mtls-svc", &good)
	mustStatus(t, tok, 200, "tls_client_auth")
	if c := jwtPayload(tok.Str("access_token")); c["cnf"].(map[string]any)["x5t#S256"] != x5t(goodCert) || c["sub"] != sp {
		t.Fatalf("certificate-bound token: %v", c)
	}
	// RFC 8705 §3: a certificate-bound token is a Bearer token; only
	// DPoP-bound tokens are reported as DPoP.
	if tok.Str("token_type") != "Bearer" {
		t.Fatalf("certificate-bound token_type: %s", tok.Raw)
	}
	mustStatus(t, tokenWith("mtls-svc", nil), 401, "no certificate")
	mustStatus(t, tokenWith("mtls-svc", &untrusted), 401, "untrusted authority")
	mustStatus(t, tokenWith("mtls-svc", &wrongName), 401, "another identity under the same authority")
	mustStatus(t, tokenWith("mtls-self", &selfSigned), 200, "self_signed_tls_client_auth")
	mustStatus(t, tokenWith("mtls-self", &good), 401, "an unregistered certificate")

	// A bound user token at the IdP's own UserInfo endpoint, through the
	// trusted proxy header.
	hdr := func(c *x509.Certificate) map[string]string {
		return map[string]string{"X-Client-Cert": url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))}
	}
	web := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "mtls-web", "name": "Bound web", "client_type": "confidential", "first_party": true,
		"redirect_uris": []string{"https://app.test/cb"}, "tls_client_certificate_bound_access_tokens": true}), 201, "bound web client")
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			f.must(f.AdminAPI("PUT", "/clients/"+web.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid"}}), 204, "grant")
		}
	}
	start, verifier, cont := h.StartTx(LoginOpts{ClientID: "mtls-web", RedirectURI: "https://app.test/cb", Scope: "openid"})
	done := h.Drive(start.Str("transaction_id"), cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, LoginOpts{Identifier: "bob@example.test"})
	code, _ := url.Parse(done.Str("redirect_to"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://app.test/cb"}}
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form, Basic: [2]string{"mtls-web", web.Str("client_secret")}}), 400,
		"bound client without a certificate")
	user := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form, Basic: [2]string{"mtls-web", web.Str("client_secret")}, Headers: hdr(goodCert)})
	mustStatus(t, user, 200, "bound user token")
	if user.Str("token_type") != "Bearer" {
		t.Fatalf("certificate-bound user token_type: %s", user.Raw)
	}
	at := user.Str("access_token")
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: at}), 401, "bound token without the certificate")
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: at, Headers: hdr(selfCert)}), 401, "another certificate")
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: at, Headers: hdr(goodCert)}), 200, "the bound certificate")

	// The header counts only from trusted proxies.
	h.App.D.Cfg.Server.TrustedProxies = nil
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: at, Headers: hdr(goodCert)}), 401, "header from an untrusted peer")
	h.App.D.Cfg.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}

	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	if disco.Get("tls_client_certificate_bound_access_tokens") != true || !strings.Contains(jsonString(disco.Get("token_endpoint_auth_methods_supported")), "tls_client_auth") {
		t.Fatalf("discovery: %v", disco.Get("token_endpoint_auth_methods_supported"))
	}
}

// TestCertificateSignIn covers PROV-016: X.509 sign-in with certificates
// that chain to a user trust anchor and are bound to the account (or carry
// an e-mail address the anchor maps), revocation through the anchor's CRL,
// and smart-card certificates counting as phishing-resistant MFA.
func TestCertificateSignIn(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Server.ClientCertHeader = "X-Client-Cert"
		c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	})
	f := fixtureOn(t, h)
	ca := newTestCA(t, "Acme Smart Cards")
	anchor := f.must(f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "user", "name": "Smart cards", "certificate_pem": ca.pem,
		"multi_factor": true, "map_san_email": true}), 201, "user anchor").Str("id")
	_, bobCert, bobPEM := issue(t, ca, "Bob Builder", "")
	_, aliceCert, _ := issue(t, ca, "Alice", "alice@example.test")
	_, strangerCert, _ := issue(t, ca, "Stranger", "")
	f.must(f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/certificate-bindings", map[string]any{"anchor_id": anchor, "certificate_pem": bobPEM}), 201, "bind")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/certificate-bindings", map[string]any{"anchor_id": anchor, "certificate_pem": bobPEM}), 409,
		"the same certificate identity twice")
	hdr := func(c *x509.Certificate) map[string]string {
		return map[string]string{"X-Client-Cert": url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))),
			"X-Transaction-Token": ""}
	}
	signIn := func(c *x509.Certificate) (*Resp, string, string) {
		t.Helper()
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		id := start.Str("transaction_id")
		headers := hdr(c)
		headers["X-Transaction-Token"] = cont
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + id + "/certificate", JSON: map[string]any{}, Headers: headers}), id, cont
	}
	if r, _, _ := signIn(bobCert); r.Status != 409 {
		t.Fatalf("certificate sign-in before the realm enables it: %d %s", r.Status, r.Raw)
	}
	f.must(f.SetPolicy(func(p *realm.Policy) { p.Login.Certificates = true }), 200, "enable certificates")
	r, _, _ := signIn(bobCert)
	if r.Str("redirect_to") == "" {
		t.Fatalf("bound certificate sign-in: %s", r.Raw)
	}
	var acr string
	_ = h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT acr FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, f.Users["bob"]).Scan(&acr)
	if acr != "urn:proudauth:acr:phishing_resistant" {
		t.Fatalf("smart-card sign-in assurance: %q", acr)
	}
	if r, _, _ := signIn(aliceCert); r.Str("redirect_to") == "" && !hasAction(r, "totp") && !hasAction(r, "enroll_totp") {
		t.Fatalf("e-mail-mapped certificate: %s", r.Raw)
	}
	mustStatus(t, func() *Resp { r, _, _ := signIn(strangerCert); return r }(), 400, "unbound certificate")
	// Before identify the attempt budget is per certificate and network, not
	// one budget for the whole realm: using it up with one certificate
	// leaves everyone else's certificate sign-in working.
	limited := false
	for range h.App.D.Cfg.Security.RateLimits.OTPVerifyPerAccount + 1 {
		if r, _, _ := signIn(strangerCert); r.Status == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("certificate attempts before identify were never budgeted")
	}
	if r, _, _ := signIn(bobCert); r.Str("redirect_to") == "" {
		t.Fatalf("another certificate shared the exhausted budget: %d %s", r.Status, r.Raw)
	}
	// Revocation through the anchor's CRL.
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: bobCert.SerialNumber, RevocationTime: time.Now()}}},
		ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	f.must(f.AdminAPI("PUT", "/certificate-trust-anchors/"+anchor+"/crl", map[string]any{"crl_pem": string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))}),
		200, "publish CRL")
	mustStatus(t, func() *Resp { r, _, _ := signIn(bobCert); return r }(), 400, "revoked certificate")
	var reason string
	_ = h.App.D.DB.Pool.QueryRow(t.Context(), `SELECT reason_code FROM audit_events WHERE type='authentication.certificate.failed' ORDER BY recorded_at DESC, id DESC LIMIT 1`).Scan(&reason)
	if reason != "CERTIFICATE_REVOKED" {
		t.Fatalf("revocation evidence: %q", reason)
	}
	// A replacement list must be newer: the same list again is accepted, an
	// equal CRL number with other content is not.
	crlPEM := func(der []byte) map[string]any {
		return map[string]any{"crl_pem": string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))}
	}
	f.must(f.AdminAPI("PUT", "/certificate-trust-anchors/"+anchor+"/crl", crlPEM(crlDER)), 200, "the same CRL again")
	sameNumber, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour)}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, f.AdminAPI("PUT", "/certificate-trust-anchors/"+anchor+"/crl", crlPEM(sameNumber)), 422, "another CRL with an equal number")
	if r, _, _ := signIn(bobCert); r.Status != 400 {
		t.Fatalf("the refused CRL replaced the list: %d %s", r.Status, r.Raw)
	}

	// A binding made from a sample certificate is checked against the anchor
	// it names, not against any user anchor of the realm.
	ca2 := newTestCA(t, "Other Smart Cards")
	anchor2 := f.must(f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "user", "name": "Other cards", "certificate_pem": ca2.pem}),
		201, "second user anchor").Str("id")
	_, _, doraPEM := issue(t, ca2, "Dora", "")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/certificate-bindings", map[string]any{"anchor_id": anchor, "certificate_pem": doraPEM}), 422,
		"a sample issued under another anchor")
	f.must(f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/certificate-bindings", map[string]any{"anchor_id": anchor2, "certificate_pem": doraPEM}), 201,
		"a sample of the named anchor")
	// A removed anchor can be trusted again, as a new anchor.
	mustStatus(t, f.AdminAPI("DELETE", "/certificate-trust-anchors/"+anchor2, nil), 204, "remove anchor")
	again := f.must(f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "user", "name": "Other cards again", "certificate_pem": ca2.pem}),
		201, "re-add a removed anchor")
	if again.Str("id") == anchor2 {
		t.Fatalf("the removed anchor was revived instead of added anew: %s", again.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "user", "name": "twice", "certificate_pem": ca2.pem}), 409,
		"an active anchor twice")
}
