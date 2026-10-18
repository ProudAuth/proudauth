package notification

import (
	"strings"
	"testing"
)

// TestBuiltInCatalogComplete covers MSG-003, MSG-004 and MSG-006: every
// template a flow can send has an English built-in, the English fallback of
// every locale; every built-in, in every locale, names a documented template
// and references only that template's documented variables, the rules custom
// templates are held to (ValidateTemplate), so a realm can replace any
// message it receives.
func TestBuiltInCatalogComplete(t *testing.T) {
	c := DefaultCatalog()
	for name, vars := range Variables {
		if _, ok := c.lookup(name, "en"); !ok {
			t.Errorf("%s has no English built-in template", name)
		}
		if len(vars) == 0 {
			t.Errorf("%s documents no variables", name)
		}
	}
	for key, tpl := range c.byKey {
		name, _, _ := strings.Cut(key, "/")
		vars, ok := Variables[name]
		if !ok {
			t.Errorf("built-in %s names a template without documented variables", key)
			continue
		}
		if err := ValidateTemplate(tpl.Subject, tpl.Text, tpl.HTML, vars); err != nil {
			t.Errorf("built-in %s would be refused as a custom template: %v", key, err)
		}
	}
}

// TestCredentialsRevokedTemplate covers CRED-008 and MCH-007: the notice a
// password reset, compromise marking or assisted recovery sends names the
// revoked credentials, says why and when, and tells the owner what to do.
func TestCredentialsRevokedTemplate(t *testing.T) {
	tpl, ok := DefaultCatalog().lookup(TplCredentialsRevoked, "en")
	if !ok {
		t.Fatal("no English credentials_revoked template")
	}
	for _, v := range []string{"{{.credentials}}", "{{.change}}", "{{.time}}"} {
		if !strings.Contains(tpl.Text, v) {
			t.Errorf("credentials_revoked does not show %s: %q", v, tpl.Text)
		}
	}
	if !strings.Contains(tpl.Text, "create new ones") {
		t.Errorf("credentials_revoked does not say how to replace the credentials: %q", tpl.Text)
	}
}

// TestSecondFactorFailuresTemplate covers SEC-006 and MSG-003 (owner decision
// 10 of 0.2.0-alpha.6): the notice sent at the failure threshold says how
// many code proofs failed and when, which factors count, and how the owner
// gets back in once code factors are turned off.
func TestSecondFactorFailuresTemplate(t *testing.T) {
	tpl, ok := DefaultCatalog().lookup(TplSecondFactorFailures, "en")
	if !ok {
		t.Fatal("no English second_factor_failures template")
	}
	for _, v := range []string{"{{.count}}", "{{.time}}", "authenticator app", "recovery codes", "passkey", "reset your password"} {
		if !strings.Contains(tpl.Text, v) {
			t.Errorf("second_factor_failures does not mention %s: %q", v, tpl.Text)
		}
	}
	if !strings.Contains(tpl.Subject, "{{.realm}}") {
		t.Errorf("subject does not name the realm: %q", tpl.Subject)
	}
}
