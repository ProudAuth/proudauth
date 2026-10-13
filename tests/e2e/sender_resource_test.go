package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/proudbase/proudauth-sdk-go/verifier"
)

// TestResourceSenderVerifier proves sender enforcement outside the IdP:
// real issued tokens, a separate TLS resource API, correct tenant/scope,
// missing/wrong proofs, replay and strict-online opaque tokens (TEST-067).
func TestResourceSenderVerifier(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := func(method, uri, raw, jti string) string {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		claims := map[string]any{"jti": jti, "htm": method, "htu": uri, "iat": h.Clock.Now().Unix()}
		if raw != "" {
			sum := sha256.Sum256([]byte(raw))
			claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		out, _ := jwt.Signed(signer).Claims(claims).Serialize()
		return out
	}
	issueToken := func(jti, audience, scope string) string {
		r := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"batch-job", f.Clients["batch"].Secret},
			Headers: map[string]string{"DPoP": proof("POST", h.Realm.Issuer+"/oauth/token", "", jti)},
			Form:    url.Values{"grant_type": {"client_credentials"}, "resource": {audience}, "scope": {scope}, "organization": {f.Acme}}})
		return f.must(r, 200, "bound machine token").Str("access_token")
	}
	for _, online := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline JWT", true: "strict online opaque"}[online], func(t *testing.T) {
			audience, scope := f.BillingAud, "billing:read"
			if online {
				audience, scope = "urn:proudauth:sender-opaque", "sender-opaque:read"
				resource := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Sender opaque API", "audience": audience,
					"token_format": "opaque", "verification_mode": "strict_online", "scopes": []map[string]any{{"name": scope}}}), 201, "opaque resource").Str("id")
				f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["batch"].Ref+"/resource-grants/"+resource,
					map[string]any{"allowed_scopes": []string{scope}, "subject_types": []string{"service_principal"}}), 204, "opaque client grant")
				f.must(f.AdminAPI("POST", "/resources/"+resource+"/introspectors", map[string]any{"client": f.Clients["billing-rs"].Ref}), 204, "opaque introspector")
			}
			raw := issueToken(map[bool]string{false: "token-jwt", true: "token-opaque"}[online], audience, scope)
			cfg := verifier.SenderConfig{PublicOrigin: "https://billing.api.test", Now: h.Clock.Now}
			cfg.Replay, _ = verifier.NewMemoryProofReplayStore(100)
			if online {
				cfg.Online = &verifier.Introspector{Endpoint: h.Realm.Issuer + "/oauth/introspect", ClientID: "billing-rs", ClientSecret: f.Clients["billing-rs"].Secret,
					Issuer: h.Realm.Issuer, Audience: audience, HTTPClient: h.HTTP}
			} else {
				var err error
				cfg.Offline, err = verifier.New(verifier.Config{Issuer: h.Realm.Issuer, Audience: audience, Now: h.Clock.Now, HTTPClient: h.HTTP})
				if err != nil {
					t.Fatal(err)
				}
			}
			sender, err := verifier.NewSenderVerifier(cfg)
			if err != nil {
				t.Fatal(err)
			}
			api := httptest.NewTLSServer(verifier.Middleware(sender, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c := verifier.FromContext(r.Context())
				if c.RequireOrganization(f.Acme) != nil || c.RequireScope(scope) != nil || c.Online != online || c.Confirmation == nil {
					t.Error("resource API lost verified tenant, scope, binding or mode")
					w.WriteHeader(403)
					return
				}
				w.WriteHeader(204)
			})))
			defer api.Close()
			request := func(scheme, p string) int {
				req, _ := http.NewRequest("GET", api.URL+"/billing?view=small", nil)
				req.Header.Set("Authorization", scheme+" "+raw)
				if p != "" {
					req.Header.Set("DPoP", p)
				}
				res, err := api.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
				return res.StatusCode
			}
			valid := proof("GET", "https://billing.api.test/billing", raw, "resource-proof")
			for _, tc := range []struct {
				scheme, proof string
				want          int
			}{
				{"Bearer", "", 401}, {"DPoP", "", 401}, {"DPoP", proof("POST", "https://billing.api.test/billing", raw, "wrong-method"), 401},
				{"DPoP", valid, 204}, {"DPoP", valid, 401},
			} {
				if status := request(tc.scheme, tc.proof); status != tc.want {
					t.Fatalf("%s request: HTTP %d, want %d", tc.scheme, status, tc.want)
				}
			}
		})
	}

	// A real TLS handshake supplies the client certificate to the SDK. No
	// certificate-forwarding headers are accepted by the resource API.
	cert, _, _ := issue(t, nil, "bound-resource-client", "")
	other, _, _ := issue(t, nil, "wrong-resource-client", "")
	mtlsClient := f.must(f.AdminAPI("POST", "/clients", map[string]any{"name": "Sender mTLS client", "client_id": "sender-mtls", "client_type": "machine",
		"service_principal_id": f.Clients["batch"].SP, "tls_client_certificate_bound_access_tokens": true}), 201, "bound machine client")
	f.must(f.AdminAPI("PUT", "/clients/"+mtlsClient.Str("client.id")+"/resource-grants/"+f.Billing,
		map[string]any{"allowed_scopes": []string{"billing:read"}, "subject_types": []string{"service_principal"}}), 204, "bound client grant")
	tokenServer := httptest.NewUnstartedServer(h.Srv.Config.Handler)
	tokenServer.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	tokenServer.StartTLS()
	defer tokenServer.Close()
	client := tokenServer.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	defer tr.CloseIdleConnections()
	client.Transport = tr
	req, _ := http.NewRequest("POST", tokenServer.URL+"/realms/main/oauth/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud},
		"scope": {"billing:read"}, "organization": {f.Acme}}.Encode()))
	req.SetBasicAuth("sender-mtls", mtlsClient.Str("client_secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("certificate token issuance: HTTP %d", res.StatusCode)
	}
	var token map[string]any
	if json.Unmarshal(body, &token) != nil {
		t.Fatal("malformed token response")
	}
	raw := token["access_token"].(string)
	v, _ := verifier.New(verifier.Config{Issuer: h.Realm.Issuer, Audience: f.BillingAud, Now: h.Clock.Now, HTTPClient: h.HTTP})
	s, _ := verifier.NewSenderVerifier(verifier.SenderConfig{Offline: v, PublicOrigin: "https://billing.api.test", Now: h.Clock.Now})
	api := httptest.NewUnstartedServer(verifier.Middleware(s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	api.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	api.StartTLS()
	defer api.Close()
	for _, tc := range []struct {
		cert *tls.Certificate
		want int
	}{{nil, 401}, {&other, 401}, {&cert, 204}} {
		client := api.Client()
		tr := client.Transport.(*http.Transport).Clone()
		if tc.cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*tc.cert}
		}
		client.Transport = tr
		req, _ := http.NewRequest("GET", api.URL+"/billing", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		req.Header.Set("X-Client-Cert", "spoofed")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		tr.CloseIdleConnections()
		if res.StatusCode != tc.want {
			t.Fatalf("TLS resource: HTTP %d, want %d", res.StatusCode, tc.want)
		}
	}
}
