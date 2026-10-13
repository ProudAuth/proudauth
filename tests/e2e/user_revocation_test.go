package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestLogoutEverywhereEndsOfflineTokens covers SES-005 for access tokens that
// carry no session: an offline grant's JWT and opaque access tokens, and its
// UserInfo token, are inactive at introspection and UserInfo as soon as "log
// out everywhere" commits (the user-level revocation record covers every
// token issued at or before it), not when they expire. Tokens of other users
// stay active, an offline grant obtained afterwards works, and a revocation
// that keeps offline grants (account merge, a shared signal without offline
// scope) leaves offline tokens alone.
func TestLogoutEverywhereEndsOfflineTokens(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	rs := f.Clients["orders-rs"]
	web := f.Clients["web"]
	active := func(tok string) bool {
		t.Helper()
		return h.Introspect("orders-rs", rs.Secret, tok).Get("active") == true
	}
	// An opaque-token resource the same resource server introspects.
	ledger := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Ledger API", "audience": "https://ledger.test",
		"token_format": "opaque", "verification_mode": "strict_online", "scopes": []map[string]any{{"name": "ledger:read"}}}), 201, "ledger").Str("id")
	f.must(f.AdminAPI("PUT", "/clients/"+web.Ref+"/resource-grants/"+ledger, map[string]any{"allowed_scopes": []string{"ledger:read"},
		"subject_types": []string{"user"}}), 204, "ledger grant")
	f.must(f.AdminAPI("POST", "/resources/"+ledger+"/introspectors", map[string]any{"client": rs.Ref}), 204, "ledger introspector")

	offline := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read offline_access").Tokens
	if _, sid := jwtPayload(offline.Str("access_token"))["sid"]; sid {
		t.Fatalf("an offline grant's access token carries a sid: %v", jwtPayload(offline.Str("access_token")))
	}
	opaque := f.LoginWeb("bob", f.Acme, "https://ledger.test", "ledger:read offline_access").Tokens
	if !strings.HasPrefix(opaque.Str("access_token"), "pa_at_") {
		t.Fatalf("expected an opaque token: %s", opaque.Raw)
	}
	userinfo := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {offline.Str("refresh_token")},
		"resource": {h.Realm.Issuer + "/userinfo"}}, "web-bff", web.Secret)
	mustStatus(t, userinfo, 200, "offline userinfo token")
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read offline_access").Tokens
	if !active(offline.Str("access_token")) || !active(opaque.Str("access_token")) || !active(alice.Str("access_token")) {
		t.Fatal("tokens inactive before the revocation")
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: userinfo.Str("access_token")}), 200, "userinfo before")

	// A revocation that keeps offline grants does not end them.
	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := h.App.Sessions.RevokeUserTx(ctx, tx, h.Realm.ID, f.Users["bob"], "test_sessions_only", false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !active(offline.Str("access_token")) || !active(opaque.Str("access_token")) {
		t.Fatal("a sessions-only revocation ended offline tokens")
	}

	h.Clock.Advance(2 * time.Second)
	cli := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/sessions/revoke-all", cli, nil), 200, "log out everywhere")
	for name, tok := range map[string]string{"offline JWT": offline.Str("access_token"), "offline opaque": opaque.Str("access_token")} {
		if in := h.Introspect("orders-rs", rs.Secret, tok); in.Get("active") != false {
			t.Fatalf("%s still active at introspection after log out everywhere: %s", name, in.Raw)
		}
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: userinfo.Str("access_token")}), 401, "offline userinfo token after")
	if !active(alice.Str("access_token")) {
		t.Fatal("another user's offline token was ended")
	}

	// Tokens issued after the revocation are unaffected.
	h.Clock.Advance(2 * time.Second)
	fresh := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read offline_access").Tokens
	if !active(fresh.Str("access_token")) {
		t.Fatal("an offline grant obtained after the revocation is inactive")
	}
}
