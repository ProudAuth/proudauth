package e2e

import (
	"context"
	"net/url"
	"testing"
	"time"
)

// TestRefreshNeverShortensSession covers SES-002 and SES-006: a refresh is
// activity on the shared SSO session, but the refresh family's idle window is
// its own. A client whose token_policy.refresh_idle_seconds (5 minutes) is
// shorter than the session's idle timeout (30 minutes) refreshes without
// pulling the session's idle expiry in to its own window, and never touches
// the absolute expiry; the session stays usable for its own idle period.
func TestRefreshNeverShortensSession(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	db := h.App.D.DB.Pool
	short := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "short-idle-bff", "name": "Short refresh window BFF",
		"client_type": "confidential", "first_party": true, "grant_types": []string{"authorization_code", "refresh_token"},
		"redirect_uris": []string{"https://short-idle.test/cb"}, "token_policy": map[string]any{"refresh_idle_seconds": 300}}), 201, "short-idle client")
	f.must(f.AdminAPI("PUT", "/clients/"+short.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	secret := short.Str("client_secret")
	lr := h.Login(LoginOpts{ClientID: "short-idle-bff", ClientSecret: secret, RedirectURI: "https://short-idle.test/cb", Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	sid := sidOf(t, lr.Tokens.Str("access_token"))
	expiry := func() (last, idle, absolute time.Time) {
		t.Helper()
		if err := db.QueryRow(ctx, `SELECT last_activity_at, idle_expires_at, absolute_expires_at FROM sessions WHERE id=$1`, sid).Scan(&last, &idle, &absolute); err != nil {
			t.Fatal(err)
		}
		return
	}
	_, idle0, abs0 := expiry()

	h.Clock.Advance(time.Minute)
	r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}}, "short-idle-bff", secret)
	mustStatus(t, r, 200, "refresh")
	last1, idle1, abs1 := expiry()
	if !last1.Equal(h.Clock.Now()) {
		t.Fatalf("refresh not recorded as activity: last activity %v, now %v", last1, h.Clock.Now())
	}
	if idle1.Before(idle0) || !abs1.Equal(abs0) {
		t.Fatalf("refresh shortened the session: idle %v -> %v, absolute %v -> %v", idle0, idle1, abs0, abs1)
	}

	// Past the family's 5-minute window but within the session's own idle
	// timeout, the session is still live.
	h.Clock.Advance(10 * time.Minute)
	if n := sesCount(t, h, `SELECT count(*) FROM sessions WHERE id=$1 AND state='active' AND idle_expires_at > $2`, sid, h.Clock.Now()); n != 1 {
		t.Fatalf("the session expired with its refresh family's idle window (idle expiry %v, now %v)", idle1, h.Clock.Now())
	}
}
