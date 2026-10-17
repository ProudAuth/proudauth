package federation

import "testing"

// TestGoogleEmailVerifiedAuthority covers FED-002 and FED-004: the google
// adapter believes email_verified only where Google is authoritative for the
// address, reading hd from the ID token even without allowed_tenants.
func TestGoogleEmailVerifiedAuthority(t *testing.T) {
	p := &Provider{Adapter: AdapterGoogle}
	for _, tc := range []struct {
		name   string
		email  string
		claims map[string]any
		want   bool
	}{
		{"gmail", "someone@gmail.com", map[string]any{}, true},
		{"googlemail", "Someone@GoogleMail.com", map[string]any{}, true},
		{"workspace hd matches", "alice@corp.example", map[string]any{"hd": "corp.example"}, true},
		{"workspace hd matches case-insensitively", "alice@Corp.Example", map[string]any{"hd": "CORP.example"}, true},
		{"consumer account with a corporate address", "alice@corp.example", map[string]any{}, false},
		{"hd names another domain", "alice@corp.example", map[string]any{"hd": "other.example"}, false},
		{"hd of a parent domain", "alice@eu.corp.example", map[string]any{"hd": "corp.example"}, false},
		{"hd not a string", "alice@corp.example", map[string]any{"hd": true}, false},
		{"invalid email", "not-an-address", map[string]any{"hd": "corp.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := &Upstream{Email: tc.email, EmailVerified: true}
			normalize(p, up, tc.claims)
			if up.EmailVerified != tc.want {
				t.Fatalf("email_verified for %s with %v: got %v, want %v", tc.email, tc.claims, up.EmailVerified, tc.want)
			}
		})
	}
	// An unverified assertion is never upgraded.
	up := &Upstream{Email: "someone@gmail.com"}
	normalize(p, up, map[string]any{})
	if up.EmailVerified {
		t.Fatal("an unverified Gmail address became verified")
	}
	// The generic OIDC adapter is unchanged: its operator chose to trust it.
	up = &Upstream{Email: "alice@corp.example", EmailVerified: true}
	normalize(&Provider{Adapter: AdapterOIDC}, up, map[string]any{})
	if !up.EmailVerified {
		t.Fatal("the oidc adapter dropped a verified email")
	}
}
