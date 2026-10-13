package e2e

import (
	"context"
	"net/url"
	"slices"
	"testing"
)

// TestAccountMergeEndsSessions covers SES-022 with USR-011: a merge changes
// which identifiers, upstream links and memberships stand behind a subject,
// so no session survives it. Every session of both accounts ends with a
// session.revoked event, session-bound refresh tokens stop working, a
// strict-online resource sees their access tokens as inactive, the
// merged-away account's offline grant ends with it, account tokens of both
// owners stop working, and both owners sign in again. Other users'
// sessions are untouched.
func TestAccountMergeEndsSessions(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	ctx := context.Background()
	maya, milo := f.CreateUser("maya"), f.CreateUser("milo")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": maya, "role_ids": []string{f.Roles["orders-viewer"]}}), 201, "maya in acme")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/members", map[string]any{"user_id": milo, "role_ids": []string{f.Roles["orders-viewer"]}}), 201, "milo in globex")

	mayaWeb := f.LoginWeb("maya", f.Acme, f.OrdersAud, "openid orders:read").Tokens
	miloWeb := f.LoginWeb("milo", f.Globex, f.OrdersAud, "openid orders:read").Tokens
	miloOffline := f.LoginWeb("milo", f.Globex, f.OrdersAud, "orders:read offline_access").Tokens
	bobWeb := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens

	prop := f.must(f.AdminAPI("POST", "/users/"+maya+"/merges", map[string]any{"source_user_id": milo, "reason": "same person, two sign-ups (ticket 78)"}), 201, "propose")
	id := prop.Str("id")
	account := map[string]string{}
	for _, u := range []string{"maya", "milo"} {
		account[u] = f.AccountToken(u).Tokens.Str("access_token")
		mustStatus(t, h.API("POST", "/me/account-merges/"+id+"/confirm", account[u], nil), 204, u+" confirms")
	}
	sessions := func(user, state string) []string {
		t.Helper()
		rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT id FROM sessions WHERE user_id=$1 AND state=$2 ORDER BY id`, user, state)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}
	before := map[string][]string{"maya": sessions(maya, "active"), "milo": sessions(milo, "active")}
	if len(before["maya"]) < 2 || len(before["milo"]) < 2 {
		t.Fatalf("sessions before the merge: %v", before)
	}
	bobSessions := sessions(f.Users["bob"], "active")

	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/account-merges/"+id+"/execute", nil), 200, "execute")

	revokedEvents := func(user string) map[string]string {
		t.Helper()
		rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT payload->'data'->>'session_id', payload->'data'->>'reason' FROM outbox_events
			WHERE event_type='session.revoked' AND aggregate_id=$1`, user)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var sid, reason string
			if err := rows.Scan(&sid, &reason); err != nil {
				t.Fatal(err)
			}
			out[sid] = reason
		}
		return out
	}
	for user, uid := range map[string]string{"maya": maya, "milo": milo} {
		if left := sessions(uid, "active"); len(left) != 0 {
			t.Fatalf("%s kept %d sessions through the merge", user, len(left))
		}
		events := revokedEvents(uid)
		for _, sid := range before[user] {
			if !slices.Contains(sessions(uid, "revoked"), sid) || events[sid] == "" {
				t.Fatalf("%s's session %s not revoked with an event: %v", user, sid, events)
			}
		}
	}
	if left := sessions(f.Users["bob"], "active"); !slices.Equal(left, bobSessions) {
		t.Fatalf("another user's sessions changed: %v -> %v", bobSessions, left)
	}

	web := f.Clients["web"]
	refresh := func(tok *Resp) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Str("refresh_token")}}, "web-bff", web.Secret)
	}
	for name, tok := range map[string]*Resp{"maya": mayaWeb, "milo": miloWeb, "milo offline": miloOffline} {
		if tok.Str("refresh_token") == "" {
			t.Fatalf("%s: no refresh token before the merge: %s", name, tok.Raw)
		}
		if r := refresh(tok); r.Status != 400 || r.Str("error") != "invalid_grant" {
			t.Fatalf("%s refresh after the merge: %d %s", name, r.Status, r.Raw)
		}
	}
	for name, tok := range map[string]*Resp{"maya": mayaWeb, "milo": miloWeb} {
		if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok.Str("access_token")); in.Get("active") != false {
			t.Fatalf("%s's online authority survived the merge: %s", name, in.Raw)
		}
	}
	for u, tok := range account {
		mustStatus(t, h.API("GET", "/me", tok, nil), 401, u+"'s account token after the merge")
	}
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, bobWeb.Str("access_token")); in.Get("active") != true {
		t.Fatalf("another user's token revoked: %s", in.Raw)
	}
	mustStatus(t, refresh(bobWeb), 200, "another user's refresh")

	// The survivor signs in again, also with the merged-away account's email.
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "milo@example.test", Password: "maya has a long passphrase 2026"})
	if c := jwtPayload(lr.Tokens.Str("access_token")); c["sub"] != maya {
		t.Fatalf("sign-in after the merge: %v", c)
	}
}
