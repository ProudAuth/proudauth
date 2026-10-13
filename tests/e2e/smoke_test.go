package e2e

import "testing"

func TestSmokeFixtureAndLogin(t *testing.T) {
	f := NewFixture(t)
	lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	at := lr.Tokens.Str("access_token")
	if at == "" || lr.Tokens.Str("refresh_token") == "" || lr.Tokens.Str("id_token") == "" {
		t.Fatalf("expected access, refresh and id tokens: %s", lr.Tokens.Raw)
	}
	in := f.H.Introspect("orders-rs", f.Clients["orders-rs"].Secret, at)
	if in.Get("active") != true || in.Str("org_id") != f.Acme || in.Str("sub") != f.Users["alice"] {
		t.Fatalf("introspection: %s", in.Raw)
	}
}
