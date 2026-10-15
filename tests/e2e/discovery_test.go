package e2e

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestDiscoveryDocumented keeps the OpenAPI OpenIDConfiguration schema in
// step with the discovery document (OIDC-015): with every optional
// capability on (logout, session management, registration, PAR, device
// flow, DPoP, mutual TLS with an advertised origin), every member the server
// emits is documented.
func TestDiscoveryDocumented(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Server.ClientCertHeader = "X-Client-Cert"
		c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
		c.Server.MTLSOrigin = "https://mtls.example.test"
	})
	f := fixtureOn(t, h)
	f.must(f.SetPolicy(func(p *realm.Policy) {
		p.ClientRegistration.Enabled = true
		p.Sessions.CheckSessionIframe = true
	}), 200, "policy")
	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	for _, k := range []string{"mtls_endpoint_aliases", "registration_endpoint", "check_session_iframe", "frontchannel_logout_session_supported",
		"authorization_encryption_alg_values_supported", "backchannel_logout_supported"} {
		if disco.Get(k) == nil {
			t.Fatalf("discovery lacks %s with the capability on: %s", k, disco.Raw)
		}
	}

	raw, err := os.ReadFile("../../api/openapi/proudauth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Properties map[string]any `yaml:"properties"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc.Components.Schemas["OpenIDConfiguration"].Properties
	var missing []string
	for k := range disco.Body {
		if _, ok := props[k]; !ok {
			missing = append(missing, k)
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("discovery members missing from the OpenAPI OpenIDConfiguration schema: %v", missing)
	}
	aliases, _ := disco.Get("mtls_endpoint_aliases").(map[string]any)
	for k := range aliases {
		if _, ok := props["mtls_endpoint_aliases"].Properties[k]; !ok {
			t.Errorf("mtls_endpoint_aliases.%s is missing from the OpenAPI schema", k)
		}
	}
}
