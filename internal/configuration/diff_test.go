package configuration

import (
	"strings"
	"testing"
	"time"
)

func TestDiffClassifiesAndRedacts(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.Observability.LogLevel = "debug"
	b.Tokens.AccessTokenTTL = a.Tokens.AccessTokenTTL + time.Hour
	b.Storage.DatabaseURL = "postgres://user:hunter2@db/proudauth"
	changes, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range changes {
		got[c.Key] = c
		if strings.Contains(c.New, "hunter2") {
			t.Fatalf("diff leaked a literal secret: %+v", c)
		}
	}
	if c, ok := got["observability.log_level"]; !ok || c.SecurityBoundary || c.Effect != "restart" {
		t.Fatalf("log level change: %+v", c)
	}
	if c, ok := got["tokens.access_token_ttl"]; !ok || !c.SecurityBoundary {
		t.Fatalf("token lifetime change not a security boundary: %+v", c)
	}
	if _, ok := got["storage.database_url"]; !ok {
		t.Fatal("database URL change not reported")
	}
	if len(changes) != 3 {
		t.Fatalf("unexpected changes: %+v", changes)
	}
}

func TestDiffBoundaryKeys(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.Server.HostPolicy = "strict"
	b.Observability.OTLPEndpoint = "https://otel.example/v1/traces"
	b.Storage.RuntimeRole = "proudauth_app"
	b.Storage.MaxConns = a.Storage.MaxConns + 5
	changes, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"server.host_policy": true, "observability.otlp_endpoint": true, "storage.runtime_role": true, "storage.max_conns": false}
	for _, c := range changes {
		if boundary, ok := want[c.Key]; ok {
			if c.SecurityBoundary != boundary {
				t.Fatalf("%s: security_boundary=%v", c.Key, c.SecurityBoundary)
			}
			delete(want, c.Key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("changes not reported: %v", want)
	}
}

// TestDiffSAMLAndDirectoryBoundaries: switching the SAML profiles or the
// directory module on, and the directory's egress and trusted roots, need a
// second reviewer; directory timeouts do not.
func TestDiffSAMLAndDirectoryBoundaries(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.SAML.Enabled = !a.SAML.Enabled
	b.SAML.MaxClockSkew = a.SAML.MaxClockSkew + time.Minute
	b.Directory.Enabled = !a.Directory.Enabled
	b.Directory.AllowPrivateNetwork = !a.Directory.AllowPrivateNetwork
	b.Directory.EgressAllowlist = []string{"10.20.0.0/16"}
	b.Directory.CAFile = "/etc/proudauth/directory-ca.pem"
	b.Directory.ConnectTimeout = a.Directory.ConnectTimeout + time.Second
	changes, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"saml.enabled": true, "saml.max_clock_skew": true, "directory.enabled": true, "directory.allow_private_network": true,
		"directory.egress_allowlist": true, "directory.ca_file": true, "directory.connect_timeout": false}
	for _, c := range changes {
		if boundary, ok := want[c.Key]; ok {
			if c.SecurityBoundary != boundary {
				t.Fatalf("%s: security_boundary=%v", c.Key, c.SecurityBoundary)
			}
			delete(want, c.Key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("changes not reported: %v", want)
	}
}

// TestDiffMutualTLSBoundaries: the mutual-TLS listener, its advertised
// origin and the proxy's client-certificate header decide where client
// certificates are accepted from (TOK-019, MCH-014), so changing them needs
// a second reviewer.
func TestDiffMutualTLSBoundaries(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.Server.MTLSListen = ":8443"
	b.Server.MTLSOrigin = "https://mtls.example.com"
	b.Server.ClientCertHeader = "X-Client-Cert"
	changes, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"server.mtls_listen": true, "server.mtls_origin": true, "server.client_cert_header": true}
	for _, c := range changes {
		if _, ok := want[c.Key]; ok {
			if !c.SecurityBoundary {
				t.Fatalf("%s is not marked as a security boundary", c.Key)
			}
			delete(want, c.Key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("changes not reported: %v", want)
	}
}

// TestAllowPrivateEgressEnv: PROUDAUTH_ALLOW_PRIVATE_EGRESS covers every
// outbound integration, directory connections included, and production
// refuses it for each of them.
func TestAllowPrivateEgressEnv(t *testing.T) {
	t.Setenv("PROUDAUTH_ALLOW_PRIVATE_EGRESS", "true")
	c := Defaults()
	if err := applyEnv(&c); err != nil {
		t.Fatal(err)
	}
	if !c.Federation.AllowPrivateNetwork || !c.Delivery.AllowPrivateWebhooks || !c.Directory.AllowPrivateNetwork {
		t.Fatalf("private egress: federation %v delivery %v directory %v", c.Federation.AllowPrivateNetwork, c.Delivery.AllowPrivateWebhooks,
			c.Directory.AllowPrivateNetwork)
	}
	c.Mode = ModeProduction
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "directory.allow_private_network") {
		t.Fatalf("production accepted private directory egress: %v", err)
	}
}

func TestEnvParseErrorsFailClosed(t *testing.T) {
	t.Setenv("PROUDAUTH_IMPERSONATION_ENABLED", "ture")
	t.Setenv("PROUDAUTH_SMTP_PORT", "25x")
	c := Defaults()
	err := applyEnv(&c)
	if err == nil || !strings.Contains(err.Error(), "PROUDAUTH_IMPERSONATION_ENABLED") || !strings.Contains(err.Error(), "PROUDAUTH_SMTP_PORT") {
		t.Fatalf("malformed environment accepted: %v", err)
	}
}

func TestRedactedHidesProviderSecrets(t *testing.T) {
	c := Defaults()
	c.Security.ChallengeProviders = []ChallengeProviderConfig{{Name: "cp", VerifyURL: "https://cp.example/verify", Secret: "literal-challenge-secret"}}
	c.Security.PolicyEngines = []PolicyEngineConfig{{Name: "opa", URL: "https://opa.example/v1/data/allow", Token: "literal-engine-token"},
		{Name: "opa2", URL: "https://opa.example/v1/data/allow", Token: "env:OPA_TOKEN"}}
	r := c.Redacted()
	if r.Security.ChallengeProviders[0].Secret != "[REDACTED]" || r.Security.PolicyEngines[0].Token != "[REDACTED]" || r.Security.PolicyEngines[1].Token != "env:OPA_TOKEN" {
		t.Fatalf("redacted: %+v %+v", r.Security.ChallengeProviders, r.Security.PolicyEngines)
	}
	if c.Security.ChallengeProviders[0].Secret != "literal-challenge-secret" || c.Security.PolicyEngines[0].Token != "literal-engine-token" {
		t.Fatal("redaction changed the live configuration")
	}
}
