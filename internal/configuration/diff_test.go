package configuration

import (
	"fmt"
	"os"
	"path/filepath"
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

// TestProductionFromEnvironmentOnly: the published image runs in production
// from PROUDAUTH_* variables alone. Secrets given directly in a variable
// become env: references, so they pass DEP-006 and never appear in redacted
// exports; the same literals in a YAML file are still refused.
func TestProductionFromEnvironmentOnly(t *testing.T) {
	const dsn, rootKey, smtpPassword = "postgres://proudauth:db-password-value@db.example.com:5432/proudauth?sslmode=require",
		"6465762d6f6e6c792d726f6f742d6b65792d6e6f742d666f722d70726f642121", "smtp-password-value"
	for name, v := range map[string]string{
		"PROUDAUTH_MODE": "production", "PROUDAUTH_PUBLIC_ORIGIN": "https://id.example.com", "PROUDAUTH_HOST_POLICY": "strict",
		"PROUDAUTH_DATABASE_URL": dsn, "PROUDAUTH_ROOT_KEY": rootKey,
		"PROUDAUTH_EMAIL_ADAPTER": "smtp", "PROUDAUTH_SMTP_HOST": "smtp.example.com", "PROUDAUTH_SMTP_PORT": "587",
		"PROUDAUTH_SMTP_TLS": "starttls", "PROUDAUTH_SMTP_USERNAME": "mailer", "PROUDAUTH_SMTP_PASSWORD": smtpPassword,
		"PROUDAUTH_EMAIL_FROM": "no-reply@example.com",
	} {
		t.Setenv(name, v)
	}
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("environment-only production configuration refused: %v", err)
	}
	if c.Storage.DatabaseURL != "env:PROUDAUTH_DATABASE_URL" || c.Keys.RootKeys[0].Ref != "env:PROUDAUTH_ROOT_KEY" ||
		c.Delivery.Email.SMTPPassword != "env:PROUDAUTH_SMTP_PASSWORD" {
		t.Fatalf("secret variables must become env: references: %q %q %q", c.Storage.DatabaseURL, c.Keys.RootKeys[0].Ref, c.Delivery.Email.SMTPPassword)
	}
	for ref, want := range map[string]string{c.Storage.DatabaseURL: dsn, c.Keys.RootKeys[0].Ref: rootKey, c.Delivery.Email.SMTPPassword: smtpPassword} {
		if got, err := ResolveSecret(ref); err != nil || got != want {
			t.Fatalf("%s does not resolve to its variable: %v", ref, err)
		}
	}
	if c.Delivery.Email.SMTPUsername != "mailer" || c.Server.HostPolicy != "strict" {
		t.Fatalf("SMTP username or host policy not taken from the environment: %q %q", c.Delivery.Email.SMTPUsername, c.Server.HostPolicy)
	}
	exported := fmt.Sprintf("%+v", c.Redacted())
	for _, secret := range []string{"db-password-value", rootKey, smtpPassword} {
		if strings.Contains(exported, secret) {
			t.Fatalf("redacted configuration exposes a secret from the environment")
		}
	}
	t.Setenv("PROUDAUTH_SMTP_PASSWORD", "file:/run/secrets/smtp_password")
	if c, err = Load(""); err != nil || c.Delivery.Email.SMTPPassword != "file:/run/secrets/smtp_password" {
		t.Fatalf("an explicit reference must be kept as given: %q %v", c.Delivery.Email.SMTPPassword, err)
	}
	for name := range map[string]bool{"PROUDAUTH_DATABASE_URL": true, "PROUDAUTH_SMTP_PASSWORD": true} {
		t.Setenv(name, "")
	}
	yaml := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(yaml, []byte("storage:\n  database_url: \""+dsn+"\"\ndelivery:\n  email:\n    smtp_password: literal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = Load(yaml); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "smtp_password") || !strings.Contains(err.Error(), "database_url embeds a password") {
		t.Fatalf("production accepted literal secrets from a configuration file: %v", err)
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
