package e2e

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/proudauth/proudauth-sdk-go/verifier"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// sidOf returns the session ID (sid claim) a JWT carries.
func sidOf(t *testing.T, jwt string) string {
	t.Helper()
	sid, _ := jwtPayload(jwt)["sid"].(string)
	if sid == "" {
		t.Fatalf("token carries no sid: %v", jwtPayload(jwt))
	}
	return sid
}

// respCookie parses the Set-Cookie header a response carries for name.
func respCookie(r *Resp, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// sesAuthorizeQuery builds an authorization request and returns its PKCE verifier.
func sesAuthorizeQuery(clientID, redirect, scope, resource, org string, extra url.Values) (string, string) {
	verifier, challenge := PKCE()
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {scope},
		"state": {"st"}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {resource}}
	if org != "" {
		q.Set("organization", org)
	}
	for k, v := range extra {
		q[k] = v
	}
	return "/realms/main/oauth/authorize?" + q.Encode(), verifier
}

// sesBrowserSignIn completes, with a cookie-carrying browser, the login UI
// transaction an authorize response redirected to and returns the completing
// step (its redirect_to carries the code).
func sesBrowserSignIn(t *testing.T, b *browser, authz *Resp, user string) *Resp {
	t.Helper()
	loc, _ := url.Parse(authz.Header.Get("Location"))
	tx := ""
	if loc != nil {
		tx = loc.Query().Get("transaction_id")
	}
	if tx == "" {
		t.Fatalf("authorize did not reach the login UI: %d %s", authz.Status, authz.Header.Get("Location"))
	}
	path := "/api/v1/realms/main/auth/transactions/" + tx
	hdr := map[string]string{"Origin": b.h.Base, "X-CSRF-Token": b.do("GET", path, nil, nil).Str("csrf_token")}
	b.do("POST", path+"/identify", map[string]any{"identifier": user + "@example.test"}, hdr)
	done := b.do("POST", path+"/password", map[string]any{"password": b.h.passwords[user+"@example.test"]}, hdr)
	if done.Str("redirect_to") == "" {
		t.Fatalf("browser sign-in: %d %s", done.Status, done.Raw)
	}
	return done
}

// sesRedeem exchanges the code in an authorization redirect.
func sesRedeem(t *testing.T, h *Harness, redirect, verifier, redirectURI, clientID, clientSecret string) *Resp {
	t.Helper()
	u, _ := url.Parse(redirect)
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("no code in %q", redirect)
	}
	tok := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {redirectURI}}, clientID, clientSecret)
	mustStatus(t, tok, 200, "code redemption")
	return tok
}

// sesGrantOf returns the session and offline flag of the grant a refresh
// token belongs to (offline access tokens carry no sid).
func sesGrantOf(t *testing.T, h *Harness, refreshToken string) (sessionID string, offline bool) {
	t.Helper()
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT coalesce(g.session_id, ''), g.offline FROM authorization_grants g
		JOIN refresh_families rf ON rf.grant_id=g.id JOIN refresh_tokens t ON t.family_id=rf.id WHERE t.token_digest=$1`,
		secret.Digest(refreshToken)).Scan(&sessionID, &offline); err != nil {
		t.Fatalf("grant of refresh token: %v", err)
	}
	return sessionID, offline
}

// sesCount runs a count query against the harness database.
func sesCount(t *testing.T, h *Harness, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// TestDurableSessionRecord covers SES-001: a sign-in persists a session row
// with its realm, user, authentication evidence (auth_time, amr, acr), creation
// time, last activity and idle/absolute expiry, together with its client
// association and the organization-bound grant and refresh family that hang
// off it; meaningful activity (a refresh) advances the last-activity time; and
// revocation is recorded on the same durable row instead of deleting it.
func TestDurableSessionRecord(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	db := h.App.D.DB.Pool
	cfg := h.App.D.Cfg.Sessions
	lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	sid := sidOf(t, lr.Tokens.Str("access_token"))

	var realmID, userID, state, acr string
	var amr []string
	var authTime, created, lastActivity, idleExp, absExp time.Time
	if err := db.QueryRow(ctx, `SELECT realm_id, user_id, state, acr, amr, auth_time, created_at, last_activity_at, idle_expires_at, absolute_expires_at
		FROM sessions WHERE id=$1`, sid).Scan(&realmID, &userID, &state, &acr, &amr, &authTime, &created, &lastActivity, &idleExp, &absExp); err != nil {
		t.Fatalf("session %s not persisted: %v", sid, err)
	}
	if realmID != h.Realm.ID || userID != f.Users["bob"] || state != "active" {
		t.Fatalf("session identity: realm=%s user=%s state=%s", realmID, userID, state)
	}
	if !slices.Contains(amr, "pwd") || acr == "" || authTime.IsZero() || authTime.After(created.Add(time.Second)) {
		t.Fatalf("authentication evidence: amr=%v acr=%q auth_time=%v created=%v", amr, acr, authTime, created)
	}
	if !lastActivity.Equal(created) || idleExp.Sub(lastActivity) != cfg.IdleTimeout || absExp.Sub(created) != cfg.AbsoluteTimeout {
		t.Fatalf("lifetimes: created=%v last=%v idle=%v absolute=%v", created, lastActivity, idleExp, absExp)
	}
	if n := sesCount(t, h, `SELECT count(*) FROM client_sessions cs JOIN clients c ON c.id=cs.client_ref
		WHERE cs.session_id=$1 AND c.client_id='web-bff' AND cs.state='active'`, sid); n != 1 {
		t.Fatalf("client association: %d", n)
	}
	if n := sesCount(t, h, `SELECT count(*) FROM authorization_grants g JOIN refresh_families rf ON rf.grant_id=g.id
		WHERE g.session_id=$1 AND g.organization_id=$2 AND g.subject_id=$3 AND g.state='active' AND rf.state='active'`, sid, f.Acme, f.Users["bob"]); n != 1 {
		t.Fatalf("grant relationship: %d", n)
	}

	// Meaningful activity moves the last-activity time and the idle expiry.
	h.Clock.Advance(10 * time.Minute)
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}},
		"web-bff", f.Clients["web"].Secret), 200, "refresh")
	var touched, touchedIdle time.Time
	if err := db.QueryRow(ctx, `SELECT last_activity_at, idle_expires_at FROM sessions WHERE id=$1`, sid).Scan(&touched, &touchedIdle); err != nil {
		t.Fatal(err)
	}
	if touched.Sub(lastActivity) != 10*time.Minute || !touchedIdle.After(idleExp) {
		t.Fatalf("activity not recorded: last %v -> %v, idle %v -> %v", lastActivity, touched, idleExp, touchedIdle)
	}

	// Revocation is recorded on the row; the record and its grant remain.
	f.ReloginAdmin()
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["bob"]+"/sessions/"+sid, nil), 204, "revoke")
	var revokedAt *time.Time
	var reason *string
	if err := db.QueryRow(ctx, `SELECT state, revoked_at, revoke_reason FROM sessions WHERE id=$1`, sid).Scan(&state, &revokedAt, &reason); err != nil {
		t.Fatalf("revoked session row gone: %v", err)
	}
	if state != "revoked" || revokedAt == nil || reason == nil || *reason == "" {
		t.Fatalf("revocation not recorded: state=%s at=%v reason=%v", state, revokedAt, reason)
	}
	if n := sesCount(t, h, `SELECT count(*) FROM authorization_grants WHERE session_id=$1 AND state='revoked'`, sid); n != 1 {
		t.Fatalf("grant revocation not recorded: %d", n)
	}
}

// TestLocalLogout covers SES-004: logout ends the server-side session and its
// grants and tells the browser to drop its session cookie; the old cookie
// value stops working too, so clearing the cookie is not what revokes. A
// header client's DELETE /me/sessions/{id} ends that one session only.
func TestLocalLogout(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	b := newBrowser(h)
	path, verifier := sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, nil)
	done := sesBrowserSignIn(t, b, b.do("GET", path, nil, nil), "alice")
	cookie := respCookie(done, "pa_sid")
	if cookie == nil || cookie.Value == "" {
		t.Fatal("sign-in set no session cookie")
	}
	tok := sesRedeem(t, h, done.Str("redirect_to"), verifier, webRedirect, "web-bff", f.Clients["web"].Secret)
	sid := sidOf(t, tok.Str("access_token"))

	out := b.do("GET", "/realms/main/oidc/logout?id_token_hint="+tok.Str("id_token")+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test/bye"), nil, nil)
	mustStatus(t, out, 302, "logout")
	if c := respCookie(out, "pa_sid"); c == nil || c.MaxAge >= 0 || c.Path != "/realms/main/" {
		t.Fatalf("logout must instruct the browser to clear its session cookie: %v", out.Header.Values("Set-Cookie"))
	}
	if n := sesCount(t, h, `SELECT count(*) FROM sessions WHERE id=$1 AND state='revoked' AND cookie_digest IS NULL AND revoked_at IS NOT NULL`, sid); n != 1 {
		t.Fatal("logout did not revoke the server-side session")
	}
	if n := sesCount(t, h, `SELECT count(*) FROM authorization_grants WHERE session_id=$1 AND state='active'`, sid); n != 0 {
		t.Fatalf("%d grants of the ended session remain active", n)
	}
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret),
		400, "refresh after logout")
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok.Str("access_token")); in.Get("active") != false {
		t.Fatalf("access token of the ended session still active: %s", in.Raw)
	}
	// A copy of the old cookie (one the browser failed to clear) is worthless.
	silent, _ := sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, url.Values{"prompt": {"none"}})
	r := h.Do(Req{Method: "GET", Path: silent, Headers: map[string]string{"Cookie": "pa_sid=" + cookie.Value}})
	if loc, _ := url.Parse(r.Header.Get("Location")); loc == nil || loc.Query().Get("error") != "login_required" {
		t.Fatalf("replayed session cookie still authenticates: %d %s", r.Status, r.Header.Get("Location"))
	}

	// Header client: ending one session leaves the user's other sessions alone.
	first := f.AccountToken("bob").Tokens
	second := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("DELETE", "/me/sessions/"+sidOf(t, first.Str("access_token")), second, nil), 204, "end one session")
	mustStatus(t, h.API("GET", "/me/sessions", first.Str("access_token"), nil), 401, "token of the ended session")
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.Str("refresh_token")}}, "proudauth-cli", ""),
		400, "refresh of the ended session")
	mustStatus(t, h.API("GET", "/me/sessions", second, nil), 200, "other session")
}

// TestLogoutAllDevices covers SES-005: "log out everywhere" revokes every
// session of the user, every refresh family including offline grants, and the
// sessions' online authority, and publishes a session.revoked event per
// session for participating applications; other users are unaffected.
func TestLogoutAllDevices(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	web := f.Clients["web"]
	laptop := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens
	phone := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens
	offline := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read offline_access").Tokens
	cli := f.AccountToken("bob").Tokens
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens
	offlineSession, isOffline := sesGrantOf(t, h, offline.Str("refresh_token"))
	if !isOffline || offlineSession == "" {
		t.Fatalf("offline grant expected: %s", offline.Raw)
	}
	sids := []string{sidOf(t, laptop.Str("access_token")), sidOf(t, phone.Str("access_token")), offlineSession, sidOf(t, cli.Str("access_token"))}
	refresh := func(tok *Resp, client, clientSecret string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Str("refresh_token")}}, client, clientSecret)
	}

	r := h.API("POST", "/me/sessions/revoke-all", cli.Str("access_token"), nil)
	mustStatus(t, r, 200, "logout everywhere")
	if n, _ := r.Get("revoked_sessions").(float64); int(n) != len(sids) {
		t.Fatalf("revoked %v sessions, want %d", r.Get("revoked_sessions"), len(sids))
	}
	for name, tok := range map[string]*Resp{"laptop": laptop, "phone": phone, "offline": offline} {
		mustStatus(t, refresh(tok, "web-bff", web.Secret), 400, name+" refresh after logout everywhere")
	}
	mustStatus(t, refresh(cli, "proudauth-cli", ""), 400, "native refresh after logout everywhere")
	if n := sesCount(t, h, `SELECT count(*) FROM refresh_families rf JOIN authorization_grants g ON g.id=rf.grant_id
		WHERE g.subject_id=$1 AND rf.state='active'`, f.Users["bob"]); n != 0 {
		t.Fatalf("%d refresh families survived", n)
	}
	for _, tok := range []*Resp{laptop, phone} { // session-bound tokens (offline ones carry no sid)
		if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok.Str("access_token")); in.Get("active") != false {
			t.Fatalf("online authority survived: %s", in.Raw)
		}
	}
	mustStatus(t, h.API("GET", "/me/sessions", cli.Str("access_token"), nil), 401, "account token after logout everywhere")

	// One invalidation event per session for applications (webhooks, the
	// session event stream, back-channel logout).
	rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT payload->'data'->>'session_id' FROM outbox_events
		WHERE event_type='session.revoked' AND aggregate_id=$1`, f.Users["bob"])
	if err != nil {
		t.Fatal(err)
	}
	published := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		published = append(published, s)
	}
	rows.Close()
	for _, sid := range sids {
		if !slices.Contains(published, sid) {
			t.Fatalf("no session.revoked event for %s: %v", sid, published)
		}
	}

	// Another user's session is untouched.
	mustStatus(t, refresh(alice, "web-bff", web.Secret), 200, "other user's refresh")
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, alice.Str("access_token")); in.Get("active") != true {
		t.Fatalf("other user's token revoked: %s", in.Raw)
	}
}

// TestRefreshFamilyLineage covers SES-006 facets beyond rotation and reuse
// (TestRefreshRotation): every rotation records its parent, so the family keeps
// a durable parent/child chain; a family is bound to its client, and another
// client presenting the token is refused without compromising the family; and
// a family's own expiry is independent of its session's.
func TestRefreshFamilyLineage(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	db := h.App.D.DB.Pool
	short := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "short-bff", "name": "Short refresh BFF", "client_type": "confidential",
		"first_party": true, "grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{"https://short.test/cb"},
		"token_policy": map[string]any{"refresh_idle_seconds": 300}}), 201, "short-idle client")
	f.must(f.AdminAPI("PUT", "/clients/"+short.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	shortSecret := short.Str("client_secret")
	refresh := func(rt, client, clientSecret string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, client, clientSecret)
	}

	lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	rt1 := lr.Tokens.Str("refresh_token")
	// Client binding: another client cannot use the token, and its attempt is
	// not treated as reuse.
	other := refresh(rt1, "short-bff", shortSecret)
	if other.Status != 400 || other.Str("error") != "invalid_grant" {
		t.Fatalf("another client used the refresh token: %d %s", other.Status, other.Raw)
	}
	r2 := refresh(rt1, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, r2, 200, "owning client after a foreign attempt")
	r3 := refresh(r2.Str("refresh_token"), "web-bff", f.Clients["web"].Secret)
	mustStatus(t, r3, 200, "second rotation")

	// Lineage: generation n+1's parent is generation n; consumed parents stay.
	var familyID, clientRef, state string
	var current int
	if err := db.QueryRow(ctx, `SELECT rf.id, rf.client_ref, rf.state, rf.current_generation FROM refresh_families rf
		JOIN refresh_tokens t ON t.family_id=rf.id WHERE t.token_digest=$1`, secret.Digest(rt1)).Scan(&familyID, &clientRef, &state, &current); err != nil {
		t.Fatal(err)
	}
	if clientRef != f.Clients["web"].Ref || state != "active" || current != 3 {
		t.Fatalf("family: client=%s state=%s generation=%d", clientRef, state, current)
	}
	rows, err := db.Query(ctx, `SELECT t.generation, coalesce(p.generation, 0), t.consumed_at IS NOT NULL, t.token_digest FROM refresh_tokens t
		LEFT JOIN refresh_tokens p ON p.id=t.parent_id WHERE t.family_id=$1 ORDER BY t.generation`, familyID)
	if err != nil {
		t.Fatal(err)
	}
	type gen struct {
		n, parent int
		consumed  bool
		digest    string
	}
	chain := []gen{}
	for rows.Next() {
		var g gen
		if err := rows.Scan(&g.n, &g.parent, &g.consumed, &g.digest); err != nil {
			t.Fatal(err)
		}
		chain = append(chain, g)
	}
	rows.Close()
	want := []gen{{1, 0, true, secret.Digest(rt1)}, {2, 1, true, secret.Digest(r2.Str("refresh_token"))}, {3, 2, false, secret.Digest(r3.Str("refresh_token"))}}
	if !slices.Equal(chain, want) {
		t.Fatalf("lineage %+v, want %+v", chain, want)
	}

	// Independent expiry: the client's 5-minute refresh idle window ends the
	// family while its session (30-minute idle) is still live.
	slr := h.Login(LoginOpts{ClientID: "short-bff", ClientSecret: shortSecret, RedirectURI: "https://short.test/cb", Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	sid := sidOf(t, slr.Tokens.Str("access_token"))
	h.Clock.Advance(6 * time.Minute)
	mustStatus(t, refresh(slr.Tokens.Str("refresh_token"), "short-bff", shortSecret), 400, "refresh past the family idle window")
	if n := sesCount(t, h, `SELECT count(*) FROM sessions WHERE id=$1 AND state='active' AND idle_expires_at > $2`, sid, h.Clock.Now()); n != 1 {
		t.Fatal("the session should outlive its refresh family's idle window")
	}
}

// TestRefreshReuseEndsSession covers SES-008 and the effect ADR 0011 documents:
// replaying a rotated refresh token marks the family compromised, revokes
// the grant and the session it belongs to so the user must sign in again (the
// session's access tokens become inactive), and raises the security event
// security.refresh_reuse_detected alongside the audit record.
func TestRefreshReuseEndsSession(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	refresh := func(rt string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", f.Clients["web"].Secret)
	}
	lr := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	sid := sidOf(t, lr.Tokens.Str("access_token"))
	rt := lr.Tokens.Str("refresh_token")
	next := refresh(rt)
	mustStatus(t, next, 200, "rotate")
	reuse := refresh(rt)
	if reuse.Status != 400 || reuse.Str("error") != "invalid_grant" {
		t.Fatalf("reuse: %d %s", reuse.Status, reuse.Raw)
	}
	var familyState, familyReason, sessionState, sessionReason string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT rf.state, rf.revoke_reason FROM refresh_families rf JOIN refresh_tokens t ON t.family_id=rf.id
		WHERE t.token_digest=$1`, secret.Digest(rt)).Scan(&familyState, &familyReason); err != nil {
		t.Fatal(err)
	}
	if familyState != "compromised" || familyReason != "reuse_detected" {
		t.Fatalf("family %s (%s), want compromised", familyState, familyReason)
	}
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, revoke_reason FROM sessions WHERE id=$1`, sid).Scan(&sessionState, &sessionReason); err != nil {
		t.Fatal(err)
	}
	if sessionState != "revoked" || sessionReason != "refresh_reuse" {
		t.Fatalf("session %s (%s): reuse must end the session", sessionState, sessionReason)
	}
	mustStatus(t, refresh(next.Str("refresh_token")), 400, "legitimate successor after reuse")
	for _, at := range []string{lr.Tokens.Str("access_token"), next.Str("access_token")} {
		if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, at); in.Get("active") != false {
			t.Fatalf("access token survived reuse detection: %s", in.Raw)
		}
	}
	if n := sesCount(t, h, `SELECT count(*) FROM outbox_events WHERE event_type='security.refresh_reuse_detected'`); n != 1 {
		t.Fatalf("security events: %d", n)
	}
	if ev := f.must(f.AdminAPI("GET", "/audit-events?type=token.refresh.reuse_detected", nil), 200, "audit"); len(ev.Get("items").([]any)) != 1 {
		t.Fatalf("audit: %s", ev.Raw)
	}
}

// TestSessionCookieAttributes covers SES-010: with Secure cookies (anything
// but the plain-http development switch), the transaction and session cookies
// are Secure, HttpOnly and SameSite=Lax, carry no Domain, and are scoped to one
// transaction's API path and to the realm; cookie-authenticated steps still
// need the CSRF token and an allowed Origin; and the script-readable
// check-session cookie is not set unless the realm opts into that integration.
func TestSessionCookieAttributes(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Sessions.CookieInsecureDev = false })
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	check := func(c *http.Cookie, name, path string) {
		t.Helper()
		if c == nil {
			t.Fatalf("%s not set", name)
		}
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != path || c.Domain != "" {
			t.Fatalf("%s attributes: %q", name, c.Raw)
		}
	}
	path, _ := sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, nil)
	authz := h.Do(Req{Method: "GET", Path: path})
	mustStatus(t, authz, 302, "authorize")
	loc, _ := url.Parse(authz.Header.Get("Location"))
	tx := loc.Query().Get("transaction_id")
	txPath := "/api/v1/realms/main/auth/transactions/" + tx
	txCookie := respCookie(authz, "pa_tx")
	check(txCookie, "pa_tx", txPath)
	// A Secure cookie is never sent over plain http, so this test sends it by hand.
	send := func(method, p string, body any, extra map[string]string) *Resp {
		hdr := map[string]string{"Cookie": "pa_tx=" + txCookie.Value}
		for k, v := range extra {
			hdr[k] = v
		}
		return h.Do(Req{Method: method, Path: p, JSON: body, Headers: hdr})
	}
	view := send("GET", txPath, nil, nil)
	mustStatus(t, view, 200, "view transaction")
	csrf := view.Str("csrf_token")
	ident := map[string]any{"identifier": "alice@example.test"}
	mustStatus(t, send("POST", txPath+"/identify", ident, map[string]string{"Origin": h.Base}), 403, "missing CSRF token")
	mustStatus(t, send("POST", txPath+"/identify", ident, map[string]string{"Origin": "https://evil.test", "X-CSRF-Token": csrf}), 403, "foreign origin")
	ok := map[string]string{"Origin": h.Base, "X-CSRF-Token": csrf}
	mustStatus(t, send("POST", txPath+"/identify", ident, ok), 200, "identify")
	done := send("POST", txPath+"/password", map[string]any{"password": h.passwords["alice@example.test"]}, ok)
	if done.Str("redirect_to") == "" {
		t.Fatalf("sign-in: %d %s", done.Status, done.Raw)
	}
	sess := respCookie(done, "pa_sid")
	check(sess, "pa_sid", "/realms/main/")
	if sess.MaxAge <= 0 || time.Duration(sess.MaxAge)*time.Second > h.App.D.Cfg.Sessions.AbsoluteTimeout {
		t.Fatalf("session cookie lifetime %ds exceeds the session's", sess.MaxAge)
	}
	if c := respCookie(done, "pa_tx"); c == nil || c.MaxAge >= 0 {
		t.Fatal("the finished transaction's cookie must be cleared")
	}
	if respCookie(done, "pa_opbs") != nil {
		t.Fatal("script-readable browser-state cookie set without the check-session integration")
	}
}

// TestRememberMeGrants covers SES-012: remember-me is an explicit per-sign-in
// opt-in honored only for clients that allow it; it gives the session and its
// refresh family the bounded sessions.remember_me_idle and
// sessions.remember_me_absolute lifetimes instead of the defaults, both of
// which are enforced; and ending a remembered session revokes its refresh
// family like any other.
func TestRememberMeGrants(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	cfg := h.App.D.Cfg.Sessions
	signIn := func(clientID, clientSecret, redirect, scope, resource string, remember bool) *Resp {
		t.Helper()
		opts := LoginOpts{ClientID: clientID, ClientSecret: clientSecret, RedirectURI: redirect, Scope: scope, Resources: []string{resource},
			Identifier: "bob@example.test"}
		if clientID == "web-bff" {
			opts.Organization, opts.SelectOrg = f.Acme, f.Acme
		}
		start, verifier, cont := h.StartTx(opts)
		mustStatus(t, start, 201, "start")
		tx := start.Str("transaction_id")
		st := &Resp{Status: 200, Body: start.Get("state").(map[string]any)}
		if remember {
			st = h.Step(tx, cont, "remember-me", map[string]any{"remember": true})
			mustStatus(t, st, 200, "remember me")
		}
		st = h.Drive(tx, cont, st, opts)
		return sesRedeem(t, h, st.Str("redirect_to"), verifier, redirect, clientID, clientSecret)
	}
	web := func(remember bool) *Resp {
		return signIn("web-bff", f.Clients["web"].Secret, webRedirect, "openid orders:read", f.OrdersAud, remember)
	}
	lifetimes := func(tok *Resp) (remembered bool, idle, absolute, familyIdle, familyAbsolute time.Duration) {
		t.Helper()
		sid := sidOf(t, tok.Str("access_token"))
		var created, idleAt, absAt, famCreated, famIdleAt, famAbsAt time.Time
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT s.remember_me, s.created_at, s.idle_expires_at, s.absolute_expires_at,
			rf.created_at, rf.idle_expires_at, rf.absolute_expires_at
			FROM sessions s JOIN authorization_grants g ON g.session_id=s.id JOIN refresh_families rf ON rf.grant_id=g.id
			JOIN refresh_tokens t ON t.family_id=rf.id WHERE s.id=$1 AND t.token_digest=$2`, sid, secret.Digest(tok.Str("refresh_token"))).Scan(
			&remembered, &created, &idleAt, &absAt, &famCreated, &famIdleAt, &famAbsAt); err != nil {
			t.Fatal(err)
		}
		return remembered, idleAt.Sub(created), absAt.Sub(created), famIdleAt.Sub(famCreated), famAbsAt.Sub(famCreated)
	}
	refresh := func(tok *Resp) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	}

	plain := web(false)
	if rm, idle, abs, fIdle, fAbs := lifetimes(plain); rm || idle != cfg.IdleTimeout || abs != cfg.AbsoluteTimeout || fIdle != cfg.IdleTimeout || fAbs != cfg.AbsoluteTimeout {
		t.Fatalf("default sign-in: remember=%v session %v/%v family %v/%v", rm, idle, abs, fIdle, fAbs)
	}
	idleCase, absCase, revokeCase := web(true), web(true), web(true)
	if rm, idle, abs, fIdle, fAbs := lifetimes(idleCase); !rm || idle != cfg.RememberMeIdle || abs != cfg.RememberMeAbsolute ||
		fIdle != cfg.RememberMeIdle || fAbs != cfg.RememberMeAbsolute {
		t.Fatalf("remember-me sign-in: remember=%v session %v/%v family %v/%v", rm, idle, abs, fIdle, fAbs)
	}
	// A client that does not allow remember-me gets the defaults even if asked.
	cli := signIn("proudauth-cli", "", "http://127.0.0.1/callback", "proudauth:account", h.Realm.Issuer+"/account", true)
	if rm, _, abs, _, _ := lifetimes(cli); rm || abs != cfg.AbsoluteTimeout {
		t.Fatalf("remember-me honored for a client that does not allow it: remember=%v absolute=%v", rm, abs)
	}

	// Revocation: ending the remembered session ends its refresh family.
	acct := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("DELETE", "/me/sessions/"+sidOf(t, revokeCase.Str("access_token")), acct, nil), 204, "end remembered session")
	mustStatus(t, refresh(revokeCase), 400, "refresh of an ended remembered session")

	// Idle bound: six idle days keep a remembered family alive (a default one
	// is long gone); twelve end it. Absolute bound: a family refreshed every
	// six days still ends at sessions.remember_me_absolute.
	day := 24 * time.Hour
	h.Clock.Advance(6 * day)
	mustStatus(t, refresh(plain), 400, "default family after six idle days")
	next := refresh(idleCase)
	mustStatus(t, next, 200, "remembered family after six idle days")
	idleCase = next
	for elapsed := 6 * day; elapsed < cfg.RememberMeAbsolute; elapsed += 6 * day {
		if elapsed == 18*day {
			mustStatus(t, refresh(idleCase), 400, "remembered family after twelve idle days")
		}
		r := refresh(absCase)
		if r.Status != 200 {
			t.Fatalf("remembered family ended before its absolute bound (day %d): %s", elapsed/day, r.Raw)
		}
		absCase = r
		h.Clock.Advance(6 * day)
	}
	mustStatus(t, refresh(absCase), 400, "remembered family past its absolute bound")
}

// TestRefreshTokensRefusedByAPIs covers SES-011: native and backend clients
// present access tokens in the Authorization header, but a refresh token in
// that header is refused everywhere a token is checked (the IdP's own APIs,
// introspection by a resource server, the strict-online example API and the
// offline SDK verifier); the refused presentations leave the token usable at
// the token endpoint by its own client.
func TestRefreshTokensRefusedByAPIs(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	s := f.StartServices(t)
	native := f.AccountToken("bob").Tokens // proudauth-cli: a public native client
	backend := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens
	nativeRT, backendRT := native.Str("refresh_token"), backend.Str("refresh_token")
	if nativeRT == "" || backendRT == "" {
		t.Fatal("refresh tokens expected")
	}
	mustStatus(t, h.API("GET", "/me/sessions", native.Str("access_token"), nil), 200, "native access token in the Authorization header")
	mustStatus(t, h.API("GET", "/me/sessions", nativeRT, nil), 401, "refresh token as a bearer token")
	if st, _ := call(t, "GET", s.OrdersURL+"/orders", backend.Str("access_token")); st != 200 {
		t.Fatalf("backend access token refused: %d", st)
	}
	if st, _ := call(t, "GET", s.OrdersURL+"/orders", backendRT); st != 401 {
		t.Fatalf("strict-online API accepted a refresh token: %d", st)
	}
	for _, rt := range []string{nativeRT, backendRT} {
		if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, rt); in.Status != 200 || in.Get("active") != false {
			t.Fatalf("introspection reported a refresh token active: %s", in.Raw)
		}
		if _, err := f.verifier(t, f.OrdersAud).Verify(context.Background(), rt); err == nil {
			t.Fatal("offline verifier accepted a refresh token")
		}
	}
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {backendRT}}, "web-bff", f.Clients["web"].Secret),
		200, "backend refresh at the token endpoint")
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {nativeRT}}, "proudauth-cli", ""),
		200, "native refresh at the token endpoint")
}

// TestSessionRevocationVisibility covers SES-023: after a session is revoked, a
// strict-online resource (introspection on every request) refuses its access
// token at once, while local JWT verification cannot see the revocation and
// keeps accepting the token until it expires plus the clock tolerance, the
// limitation docs/operations/revocation-exposure.md states.
func TestSessionRevocationVisibility(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	s := f.StartServices(t)
	orders := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	billing := f.LoginWeb("alice", f.Acme, f.BillingAud, "billing:read").Tokens.Str("access_token")
	offline := f.verifier(t, f.BillingAud)
	if st, _ := call(t, "GET", s.OrdersURL+"/orders", orders); st != 200 {
		t.Fatalf("strict-online API before revocation: %d", st)
	}
	if st, _ := call(t, "GET", s.BillingURL+"/invoices", billing); st != 200 {
		t.Fatalf("offline API before revocation: %d", st)
	}

	f.must(f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/revoke-sessions", map[string]any{}), 200, "revoke sessions")
	if st, _ := call(t, "GET", s.OrdersURL+"/orders", orders); st != 401 {
		t.Fatalf("strict-online API must refuse a revoked session at once: %d", st)
	}
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, orders); in.Get("active") != false {
		t.Fatalf("introspection reports a revoked session active: %s", in.Raw)
	}
	// The stated limitation: offline verification still accepts the token.
	if _, err := offline.Verify(ctx, billing); err != nil {
		t.Fatalf("offline verification is expected to accept the token until expiry: %v", err)
	}
	if st, _ := call(t, "GET", s.BillingURL+"/invoices", billing); st != 200 {
		t.Fatalf("offline API inside the stale-token window: %d", st)
	}
	exp := time.Unix(int64(jwtPayload(billing)["exp"].(float64)), 0)
	h.Clock.Advance(exp.Sub(h.Clock.Now()) + 61*time.Second)
	if _, err := offline.Verify(ctx, billing); !errors.Is(err, verifier.ErrExpired) {
		t.Fatalf("offline verification after expiry plus tolerance: %v", err)
	}
	if st, _ := call(t, "GET", s.BillingURL+"/invoices", billing); st != 401 {
		t.Fatalf("offline API after expiry: %d", st)
	}
}

// TestLogoutScopes covers SES-015: one global SSO session is shared by several
// clients, each with its own client session, organization-bound grant and
// refresh family. Revoking one client's refresh token ends that client's
// grant only; global logout ends the SSO session, every client session and
// every session-bound grant; an offline grant is separate and survives it.
func TestLogoutScopes(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	notesCB := "https://notes.test/cb"
	reg := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "notes-bff", "name": "Notes BFF", "client_type": "confidential",
		"first_party": true, "grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{notesCB},
		"post_logout_redirect_uris": []string{"https://notes.test/bye"}, "allow_offline_access": true}), 201, "second client")
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "orders grant")
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid"},
				"subject_types": []string{"user"}}), 204, "oidc grant")
		}
	}
	notesSecret := reg.Str("client_secret")
	refresh := func(rt, client, clientSecret string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, client, clientSecret)
	}
	b := newBrowser(h)
	silent := func(client, redirect, scope, clientSecret string) *Resp {
		t.Helper()
		path, verifier := sesAuthorizeQuery(client, redirect, scope, f.OrdersAud, f.Acme, url.Values{"prompt": {"none"}})
		return sesRedeem(t, h, b.do("GET", path, nil, nil).Header.Get("Location"), verifier, redirect, client, clientSecret)
	}

	path, verifier := sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, nil)
	web := sesRedeem(t, h, sesBrowserSignIn(t, b, b.do("GET", path, nil, nil), "alice").Str("redirect_to"), verifier, webRedirect, "web-bff", f.Clients["web"].Secret)
	notes := silent("notes-bff", notesCB, "openid orders:read", notesSecret)
	notesOffline := silent("notes-bff", notesCB, "orders:read offline_access", notesSecret)
	sid := sidOf(t, web.Str("access_token"))
	offlineSession, isOffline := sesGrantOf(t, h, notesOffline.Str("refresh_token"))
	if sidOf(t, notes.Str("access_token")) != sid || offlineSession != sid {
		t.Fatal("single sign-on must reuse the global session")
	}
	if !isOffline {
		t.Fatal("offline_access must yield an offline grant")
	}
	if n := sesCount(t, h, `SELECT count(*) FROM client_sessions WHERE session_id=$1 AND state='active'`, sid); n != 2 {
		t.Fatalf("want one client session per client, got %d", n)
	}
	if n := sesCount(t, h, `SELECT count(DISTINCT rf.id) FROM authorization_grants g JOIN refresh_families rf ON rf.grant_id=g.id
		WHERE g.session_id=$1 AND g.organization_id=$2 AND rf.state='active'`, sid, f.Acme); n != 3 {
		t.Fatalf("want three organization grants with their own refresh families, got %d", n)
	}

	// Client-local logout: revoking web-bff's refresh token ends its grant only.
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {web.Str("refresh_token")}},
		Basic: [2]string{"web-bff", f.Clients["web"].Secret}}), 200, "revoke web-bff refresh token")
	mustStatus(t, refresh(web.Str("refresh_token"), "web-bff", f.Clients["web"].Secret), 400, "revoked client grant")
	notesNext := refresh(notes.Str("refresh_token"), "notes-bff", notesSecret)
	mustStatus(t, notesNext, 200, "other client's grant after a client-local revocation")
	if n := sesCount(t, h, `SELECT count(*) FROM sessions WHERE id=$1 AND state='active'`, sid); n != 1 {
		t.Fatal("revoking one client's refresh token ended the SSO session")
	}
	silent("web-bff", webRedirect, "openid orders:read", f.Clients["web"].Secret) // SSO still signs web-bff in

	// Global logout ends the SSO session and every session-bound grant.
	out := b.do("GET", "/realms/main/oidc/logout?id_token_hint="+notes.Str("id_token")+"&post_logout_redirect_uri="+url.QueryEscape("https://notes.test/bye"), nil, nil)
	mustStatus(t, out, 302, "global logout")
	mustStatus(t, refresh(notesNext.Str("refresh_token"), "notes-bff", notesSecret), 400, "session-bound grant after global logout")
	if n := sesCount(t, h, `SELECT count(*) FROM client_sessions WHERE session_id=$1 AND state='active'`, sid); n != 0 {
		t.Fatalf("%d client sessions survived global logout", n)
	}
	path, _ = sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, url.Values{"prompt": {"none"}})
	if loc, _ := url.Parse(b.do("GET", path, nil, nil).Header.Get("Location")); loc == nil || loc.Query().Get("error") != "login_required" {
		t.Fatal("SSO session survived global logout")
	}
	// The offline grant is not part of the SSO session's logout scope.
	mustStatus(t, refresh(notesOffline.Str("refresh_token"), "notes-bff", notesSecret), 200, "offline grant after global logout")
}
