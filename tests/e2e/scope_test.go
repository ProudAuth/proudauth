package e2e

import (
	"strings"
	"testing"
)

// TestUnofferedCapabilitiesNotAdvertised: the optional capabilities this
// release does not offer (docs/protocols/compatibility.md, "Capabilities not
// offered": MFA-014, ADV-005, ADV-006, ADV-008, ADV-009, JAR, API-014) appear
// in no metadata document and have no well-known endpoint, so no client can
// mistake them for supported features (APP-020, plan section 35.1).
func TestUnofferedCapabilitiesNotAdvertised(t *testing.T) {
	f := NewFixture(t)
	for _, path := range []string{
		"/realms/main/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server/realms/main",
	} {
		d := f.H.Do(Req{Method: "GET", Path: path})
		mustStatus(t, d, 200, path)
		for _, member := range []string{
			// CIBA (ADV-005)
			"backchannel_authentication_endpoint", "backchannel_token_delivery_modes_supported",
			"backchannel_authentication_request_signing_alg_values_supported", "backchannel_user_code_parameter_supported",
			// UMA (ADV-006)
			"uma_profiles_supported", "permission_endpoint", "resource_registration_endpoint",
			// Verifiable credentials (ADV-008, ADV-009)
			"credential_issuer", "credential_endpoint", "credential_configurations_supported", "vp_formats_supported",
			"presentation_definition_uri_supported",
		} {
			if d.Get(member) != nil {
				t.Errorf("%s advertises %s", path, member)
			}
		}
		raw := string(d.Raw)
		for _, value := range []string{"urn:openid:params:grant-type:ciba", "urn:ietf:params:oauth:grant-type:uma-ticket", "vp_token"} {
			if strings.Contains(raw, value) {
				t.Errorf("%s mentions %s", path, value)
			}
		}
		if d.Get("request_parameter_supported") == true {
			t.Errorf("%s claims request objects (JAR) are supported", path)
		}
	}
	for _, path := range []string{
		"/realms/main/.well-known/uma2-configuration",
		"/realms/main/.well-known/openid-credential-issuer",
		"/.well-known/uma2-configuration",
		"/.well-known/openid-credential-issuer",
	} {
		// 405 comes from routes for other methods on the same path (the CORS
		// preflight); either way nothing is served.
		if r := f.H.Do(Req{Method: "GET", Path: path}); (r.Status != 404 && r.Status != 405) || r.Get("issuer") != nil || r.Get("credential_issuer") != nil {
			t.Errorf("GET %s: %d %s, want 404 or 405 without metadata", path, r.Status, r.Raw)
		}
	}
}
