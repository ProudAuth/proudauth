package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestRedirectRegistrationRules covers APP-004: redirect and post-logout
// targets on the identity provider's own origin are refused, since its
// endpoints redirect onwards and would form open-redirect chains.
func TestRedirectRegistrationRules(t *testing.T) {
	f := NewFixture(t)
	// The realm's verified custom host serves the identity provider too.
	ch := f.must(f.AdminAPI("POST", "/custom-domains", map[string]any{"host": "login.acme.test"}), 201, "custom domain")
	saved := realm.CustomDomainTXT
	defer func() { realm.CustomDomainTXT = saved }()
	realm.CustomDomainTXT = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/custom-domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify")
	own := "https://login.acme.test"
	for name, body := range map[string]map[string]any{
		"redirect at the authorize endpoint": {"redirect_uris": []string{own + "/realms/main/oauth/authorize"}},
		"post-logout at the logout endpoint": {"redirect_uris": []string{"https://app.test/cb"}, "post_logout_redirect_uris": []string{own + ":8443/realms/main/oidc/logout"}},
	} {
		body["client_id"], body["name"], body["client_type"], body["grant_types"] = "chain-"+name[:4], "Chain", "confidential", []string{"authorization_code"}
		if r := f.AdminAPI("POST", "/clients", body); r.Status != 422 || !strings.Contains(string(r.Raw), "identity provider itself") {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "ok-app", "name": "OK", "client_type": "confidential",
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://app.test/cb"}}), 201, "ordinary redirect")
}

// TestConfigurableLimits covers OSS-007: safety limits come from the
// operator's configuration rather than fixed values.
func TestConfigurableLimits(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Limits.ClientSecretsMax = 2; c.Limits.SharedInvitationMaxUses = 5 })
	f := fixtureOn(t, h)
	path := "/clients/" + f.Clients["web"].Ref + "/credentials"
	f.must(f.AdminAPI("POST", path, map[string]any{}), 201, "second secret")
	if r := f.AdminAPI("POST", path, map[string]any{}); r.Status != 409 || !strings.Contains(string(r.Raw), "at most 2") {
		t.Fatalf("configured secret limit: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/invitations", map[string]any{"purpose": "shared_link", "max_uses": 6,
		"allowed_domains": []string{"example.test"}}), 422, "shared link above the configured uses")
}

// TestVerificationBudgetPerClient covers REG-012: proof attempts made through
// one client (factor codes and passwords alike) share a budget across
// accounts and networks, security.rate_limits.login_per_client. Every request
// here comes from the loopback address, which the fixture's sign-ins make a
// known network, so the known-device quota (owner decision 9,
// TestKnownDeviceQuota) is off: then the exhausted client budget refuses
// everyone.
func TestVerificationBudgetPerClient(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.RateLimits.LoginPerClient = 3
		c.Security.RateLimits.KnownQuotaDays = 0
	})
	f := fixtureOn(t, h)
	f.EnrollTOTP("bob")
	f.EnrollTOTP("carol")
	start := func(user string) (string, string, int) {
		st, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme})
		tx := st.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": user + "@example.test"})
		return tx, cont, h.Step(tx, cont, "password", map[string]any{"password": h.passwords[user+"@example.test"]}).Status
	}
	// Two passwords, then four wrong codes spread over both accounts: the
	// fourth code is over the client's budget.
	var codes []int
	for _, user := range []string{"bob", "carol"} {
		tx, cont, pw := start(user)
		if pw == 429 {
			t.Fatalf("password %s refused early", user)
		}
		for range 2 {
			codes = append(codes, h.Step(tx, cont, "totp", map[string]any{"code": "000000"}).Status)
		}
	}
	if codes[3] != 429 || codes[0] == 429 {
		t.Fatalf("per-client verification budget: %v", codes)
	}
	// Passwords through the client are budgeted by login_per_client too
	// (two used above): the fourth is refused.
	passwords := []int{}
	for _, user := range []string{"bob", "carol"} {
		_, _, pw := start(user)
		passwords = append(passwords, pw)
	}
	if passwords[0] == 429 || passwords[1] != 429 {
		t.Fatalf("per-client password budget: %v", passwords)
	}
}
