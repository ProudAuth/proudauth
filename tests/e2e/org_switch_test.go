package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestOrganizationSwitch covers TEN-005 and TEN-012: switching the
// organization context of an existing session issues a grant only when the
// session meets the organization's sign-in rules — membership, required SSO,
// allowed methods and session lifetime — as a fresh login into it would.
func TestOrganizationSwitch(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	_, challenge := PKCE()
	switchTo := func(org string) *Resp {
		t.Helper()
		return h.API("POST", "/me/organization-grants", bob, map[string]any{"client_id": "proudauth-cli", "organization_id": org,
			"redirect_uri": "http://127.0.0.1:5000/callback", "code_challenge": challenge, "code_challenge_method": "S256",
			"scope": "proudauth:account", "resource": []string{h.Realm.Issuer + "/account"}, "state": "s1"})
	}
	setPolicy := func(org string, policy map[string]any) {
		t.Helper()
		cur := f.must(f.AdminAPI("GET", "/organizations/"+org, nil), 200, "org")
		f.must(h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + org, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"policy": policy}}), 200, "org policy")
	}

	ok := switchTo(f.Globex)
	if ok.Status != 200 || !strings.Contains(ok.Str("redirect_to"), "code=") {
		t.Fatalf("switch: %d %s", ok.Status, ok.Raw)
	}
	other := f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "initech", "display_name": "Initech"}), 201, "org without bob")
	mustStatus(t, switchTo(other.Str("id")), 403, "switch without membership")

	// A password session does not meet a passkey-only organization.
	setPolicy(f.Globex, map[string]any{"allowed_login_methods": []string{"passkey"}})
	if r := switchTo(f.Globex); r.Status != 403 || r.Str("code") != "step_up_required" {
		t.Fatalf("disallowed sign-in method: %d %s", r.Status, r.Raw)
	}
	// Nor an organization that requires its SSO connection.
	setPolicy(f.Globex, map[string]any{"sso_required": true})
	if r := switchTo(f.Globex); r.Str("code") != "sso_required" {
		t.Fatalf("SSO-required organization: %d %s", r.Status, r.Raw)
	}
	// The organization's session lifetime bounds the switch.
	setPolicy(f.Globex, map[string]any{"session_absolute_seconds": 120})
	mustStatus(t, switchTo(f.Globex), 200, "within the organization's lifetime")
	h.Clock.Advance(3 * time.Minute)
	if r := switchTo(f.Globex); r.Str("code") != "step_up_required" {
		t.Fatalf("switch beyond the organization's session lifetime: %s", r.Raw)
	}
}
