package application

import (
	"slices"
	"strings"
	"testing"
)

// fieldOf returns the field a validation error names, or "" when valid.
func fieldOf(t *testing.T, in ClientInput) string {
	t.Helper()
	err := in.Normalize()
	if err == nil {
		return ""
	}
	for f := range err.Fields {
		return f
	}
	t.Fatalf("validation error without a field: %v", err)
	return ""
}

func clientOf(typ string, mut func(*ClientInput)) ClientInput {
	in := ClientInput{Name: "c", Type: typ}
	switch typ {
	case TypeConfidential, TypePublicBrowser:
		in.RedirectURIs = []string{"https://app.example.com/cb"}
	case TypeNative:
		in.RedirectURIs = []string{"http://127.0.0.1/cb"}
	case TypeMachine:
		in.ServicePrincipalID = "svc_1"
	}
	if mut != nil {
		mut(&in)
	}
	return in
}

// TestClientTypeCapabilities covers APP-002: confidential, public browser,
// native, device and machine clients each have their own default and
// permitted credentials and grant types, and nothing outside a type's set is
// accepted.
func TestClientTypeCapabilities(t *testing.T) {
	defaults := map[string]struct {
		auth   string
		grants []string
	}{
		TypeConfidential:  {"client_secret_basic", []string{GrantAuthorizationCode, GrantRefreshToken}},
		TypePublicBrowser: {"none", []string{GrantAuthorizationCode, GrantRefreshToken}},
		TypeNative:        {"none", []string{GrantAuthorizationCode, GrantRefreshToken}},
		TypeDevice:        {"none", []string{GrantDeviceCode, GrantRefreshToken}},
		TypeMachine:       {"client_secret_basic", []string{GrantClientCredentials}},
	}
	for typ, want := range defaults {
		in := clientOf(typ, nil)
		if err := in.Normalize(); err != nil {
			t.Fatalf("%s defaults: %v", typ, err)
		}
		if in.AuthMethod != want.auth || !slices.Equal(in.GrantTypes, want.grants) {
			t.Errorf("%s defaults: auth %q grants %v, want %q %v", typ, in.AuthMethod, in.GrantTypes, want.auth, want.grants)
		}
	}
	refused := map[string]ClientInput{
		"confidential without authentication": clientOf(TypeConfidential, func(c *ClientInput) { c.AuthMethod = "none" }),
		"public browser holding a secret":     clientOf(TypePublicBrowser, func(c *ClientInput) { c.AuthMethod = "client_secret_basic" }),
		"native holding a secret":             clientOf(TypeNative, func(c *ClientInput) { c.AuthMethod = "client_secret_post" }),
		"machine without authentication":      clientOf(TypeMachine, func(c *ClientInput) { c.AuthMethod = "none" }),
		"public browser with mutual TLS":      clientOf(TypePublicBrowser, func(c *ClientInput) { c.AuthMethod = "tls_client_auth" }),
		"public browser client credentials":   clientOf(TypePublicBrowser, func(c *ClientInput) { c.GrantTypes = []string{GrantClientCredentials} }),
		"public browser device code":          clientOf(TypePublicBrowser, func(c *ClientInput) { c.GrantTypes = []string{GrantDeviceCode} }),
		"public browser token exchange":       clientOf(TypePublicBrowser, func(c *ClientInput) { c.GrantTypes = []string{GrantTokenExchange} }),
		"native client credentials":           clientOf(TypeNative, func(c *ClientInput) { c.GrantTypes = []string{GrantClientCredentials} }),
		"device authorization code":           clientOf(TypeDevice, func(c *ClientInput) { c.GrantTypes = []string{GrantAuthorizationCode} }),
		"machine authorization code":          clientOf(TypeMachine, func(c *ClientInput) { c.GrantTypes = []string{GrantAuthorizationCode} }),
		"machine refresh token":               clientOf(TypeMachine, func(c *ClientInput) { c.GrantTypes = []string{GrantClientCredentials, GrantRefreshToken} }),
		"machine without service principal":   clientOf(TypeMachine, func(c *ClientInput) { c.ServicePrincipalID = "" }),
		"password grant":                      clientOf(TypeConfidential, func(c *ClientInput) { c.GrantTypes = []string{"password"} }),
		"implicit grant":                      clientOf(TypePublicBrowser, func(c *ClientInput) { c.GrantTypes = []string{"implicit"} }),
		"unknown type":                        {Name: "c", Type: "spa"},
	}
	for name, in := range refused {
		if fieldOf(t, in) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	accepted := map[string]ClientInput{
		"native device code":              clientOf(TypeNative, func(c *ClientInput) { c.GrantTypes = []string{GrantAuthorizationCode, GrantDeviceCode} }),
		"confidential token exchange":     clientOf(TypeConfidential, func(c *ClientInput) { c.GrantTypes = []string{GrantAuthorizationCode, GrantTokenExchange} }),
		"machine private key JWT":         clientOf(TypeMachine, func(c *ClientInput) { c.AuthMethod = "private_key_jwt" }),
		"machine workload federation":     clientOf(TypeMachine, func(c *ClientInput) { c.AuthMethod = "none"; c.GrantTypes = []string{GrantJWTBearer} }),
		"confidential client_secret_post": clientOf(TypeConfidential, func(c *ClientInput) { c.AuthMethod = "client_secret_post" }),
	}
	for name, in := range accepted {
		if f := fieldOf(t, in); f != "" {
			t.Errorf("%s: refused on %s", name, f)
		}
	}
}

// TestClientSecurityProfiles covers APP-010: the third_party, privileged and
// high_assurance profiles impose their rules on top of the client type, and
// high_assurance turns on pushed authorization requests.
func TestClientSecurityProfiles(t *testing.T) {
	refused := map[string]ClientInput{
		"third party marked first party": clientOf(TypeConfidential, func(c *ClientInput) { c.SecurityProfile = "third_party"; c.FirstParty = true }),
		"third party without consent": clientOf(TypeConfidential, func(c *ClientInput) {
			c.SecurityProfile = "third_party"
			c.ConsentMode = "preauthorized"
		}),
		"privileged third party":            clientOf(TypeConfidential, func(c *ClientInput) { c.SecurityProfile = "privileged" }),
		"privileged public browser":         clientOf(TypePublicBrowser, func(c *ClientInput) { c.SecurityProfile = "privileged"; c.FirstParty = true }),
		"high assurance with shared secret": clientOf(TypeConfidential, func(c *ClientInput) { c.SecurityProfile = "high_assurance" }),
		"unknown profile":                   clientOf(TypeConfidential, func(c *ClientInput) { c.SecurityProfile = "relaxed" }),
	}
	for name, in := range refused {
		if f := fieldOf(t, in); f != "security_profile" {
			t.Errorf("%s: want a security_profile refusal, got %q", name, f)
		}
	}
	third := clientOf(TypePublicBrowser, func(c *ClientInput) { c.SecurityProfile = "third_party" })
	if err := third.Normalize(); err != nil || third.ConsentMode != "required" {
		t.Fatalf("third-party public client: %v consent %q", err, third.ConsentMode)
	}
	priv := clientOf(TypeConfidential, func(c *ClientInput) { c.SecurityProfile = "privileged"; c.FirstParty = true })
	if err := priv.Normalize(); err != nil {
		t.Fatalf("privileged first-party confidential client: %v", err)
	}
	high := clientOf(TypeConfidential, func(c *ClientInput) { c.SecurityProfile = "high_assurance"; c.AuthMethod = "private_key_jwt" })
	if err := high.Normalize(); err != nil || !high.TokenPolicy.RequirePAR {
		t.Fatalf("high-assurance client: %v, require_par %v", err, high.TokenPolicy.RequirePAR)
	}
	std := clientOf(TypeConfidential, nil)
	if err := std.Normalize(); err != nil || std.SecurityProfile != "standard" {
		t.Fatalf("default profile: %v %q", err, std.SecurityProfile)
	}
}

// TestOriginRegistration covers APP-005 at registration: browser origins are
// exact scheme://host[:port] values, never wildcards or paths, https except
// for loopback outside production, and stored lower-cased.
func TestOriginRegistration(t *testing.T) {
	for _, o := range []string{"https://*.example.com", "https://app.example.com/path", "https://app.example.com?x=1", "https://u:p@app.example.com",
		"app.example.com", "http://app.example.com", "ftp://app.example.com", "https://app.example.com#f"} {
		if _, msg := ValidateOrigin(o, "development"); msg == "" {
			t.Errorf("origin %q accepted", o)
		}
	}
	if _, msg := ValidateOrigin("http://localhost:3000", "production"); msg == "" {
		t.Error("plain-http loopback origin accepted in production")
	}
	if got, msg := ValidateOrigin("http://localhost:3000", "development"); msg != "" || got != "http://localhost:3000" {
		t.Errorf("development loopback origin: %q %s", got, msg)
	}
	if got, msg := ValidateOrigin("https://App.Example.COM:8443", "production"); msg != "" || got != "https://app.example.com:8443" {
		t.Errorf("origin normalization: %q %s", got, msg)
	}
	in := clientOf(TypePublicBrowser, func(c *ClientInput) { c.Origins = []string{"https://*.example.com"} })
	if f := fieldOf(t, in); f != "allowed_origins" {
		t.Errorf("client with a wildcard origin: refused on %q", f)
	}
}

// TestResourceRegistrationRules covers APP-006 (an audience is a stable
// registered https URI or URN, never a wildcard or free text), IMP-010
// (support access needs the strict-online contract) and INT-010 (opting in
// records the validated support contract version).
func TestResourceRegistrationRules(t *testing.T) {
	valid := func(mut func(*ResourceInput)) ResourceInput {
		in := ResourceInput{Name: "Orders", Audience: "https://orders.example.com"}
		if mut != nil {
			mut(&in)
		}
		return in
	}
	field := func(in ResourceInput) string {
		t.Helper()
		err := in.normalize(3600)
		if err == nil {
			return ""
		}
		for f := range err.Fields {
			return f
		}
		return "?"
	}
	for _, aud := range []string{"", "*", "https://*.example.com", "https://orders.example.com/ x", "orders", "ftp://orders.example.com",
		"javascript:alert(1)", "https://orders.example.com/" + strings.Repeat("a", 600)} {
		if f := field(valid(func(r *ResourceInput) { r.Audience = aud })); f != "audience" {
			t.Errorf("audience %q: refused on %q, want audience", aud, f)
		}
	}
	for _, aud := range []string{"https://orders.example.com", "urn:example:orders"} {
		if f := field(valid(func(r *ResourceInput) { r.Audience = aud })); f != "" {
			t.Errorf("audience %q refused on %s", aud, f)
		}
	}
	for _, mode := range []string{ModeOffline, ModeBoundedOnline} {
		in := valid(func(r *ResourceInput) {
			r.VerificationMode = mode
			r.ImpersonationEnabled = true
			r.ImpersonationPolicy.ContractVersion = "support-contract-1"
		})
		if f := field(in); f != "impersonation_enabled" {
			t.Errorf("support access on a %s resource: refused on %q", mode, f)
		}
	}
	unvalidated := valid(func(r *ResourceInput) { r.VerificationMode = ModeStrictOnline; r.ImpersonationEnabled = true })
	if f := field(unvalidated); f != "impersonation_policy.contract_version" {
		t.Errorf("support opt-in without a validated contract version: refused on %q", f)
	}
	ok := valid(func(r *ResourceInput) {
		r.VerificationMode = ModeStrictOnline
		r.ImpersonationEnabled = true
		r.ImpersonationPolicy.ContractVersion = "support-contract-1"
	})
	if f := field(ok); f != "" {
		t.Errorf("strict-online resource with a validated contract: refused on %s", f)
	}
}
