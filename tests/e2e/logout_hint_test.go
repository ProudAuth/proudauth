package e2e

import (
	"context"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/token"
)

// TestLogoutHintTypes covers SES-016 with ADV-002 and OIDC-013
// (logout-hint-typ-confusion, decision 15). The realm key signs ID tokens,
// JWT-secured authorization responses and signed UserInfo; only an ID token
// is a logout hint. Anyone can get a JARM error response by sending the
// authorization endpoint a valid client_id and redirect_uri without PKCE;
// lured to GET /oidc/logout with it as id_token_hint, a browser used to lose
// its SSO session (and the clients their front- and back-channel logout).
// Now JARM responses (oauth-authz-resp+jwt) and signed UserInfo
// (userinfo+jwt) have their own typ, a hint must be ID-token shaped, and a
// GET ends the cookie session only when the hint's sid is that session or its
// sub is the session's user: anything else is 400 invalid_request and the
// session stays. POST keeps its rules: the cookie session ends unless the
// hint names another session.
func TestLogoutHintTypes(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	ctx := context.Background()
	b := newBrowser(h)
	signIn := func() (tokens *Resp, sid, cookie string) {
		t.Helper()
		path, verifier := sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, nil)
		done := sesBrowserSignIn(t, b, b.do("GET", path, nil, nil), "alice")
		c := respCookie(done, "pa_sid")
		if c == nil || c.Value == "" {
			t.Fatal("sign-in set no session cookie")
		}
		tokens = sesRedeem(t, h, done.Str("redirect_to"), verifier, webRedirect, "web-bff", f.Clients["web"].Secret)
		return tokens, sidOf(t, tokens.Str("access_token")), c.Value
	}
	active := func(sid string) bool {
		return sesCount(t, h, `SELECT count(*) FROM sessions WHERE id=$1 AND state='active'`, sid) == 1
	}
	getLogout := func(hint string) *Resp {
		return b.do("GET", "/realms/main/oidc/logout?"+url.Values{"id_token_hint": {hint}}.Encode(), nil, nil)
	}
	refused := func(name string, r *Resp, sid string) {
		t.Helper()
		if r.Status != 400 || r.Str("error") != "invalid_request" {
			t.Fatalf("%s as id_token_hint on GET logout: %d %s", name, r.Status, r.Raw)
		}
		if c := respCookie(r, "pa_sid"); c != nil {
			t.Fatalf("%s: a refused logout cleared the session cookie: %v", name, r.Header.Values("Set-Cookie"))
		}
		if !active(sid) {
			t.Fatalf("%s as id_token_hint ended the browser session", name)
		}
	}
	tokens, sid, cookie := signIn()

	// A JARM error response, obtained without any credential: a valid
	// client_id and redirect_uri, response_mode=jwt and no PKCE.
	authz := h.Do(Req{Method: "GET", Path: "/realms/main/oauth/authorize?" + url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect},
		"response_type": {"code"}, "scope": {"openid"}, "response_mode": {"jwt"}, "state": {"lure"}}.Encode()})
	loc, _ := url.Parse(authz.Header.Get("Location"))
	if authz.Status != 302 || loc == nil || loc.Query().Get("response") == "" {
		t.Fatalf("anonymous JARM error response: %d %s", authz.Status, authz.Header.Get("Location"))
	}
	jarm := loc.Query().Get("response")
	if typ := jwsType(t, jarm); typ != token.TypeJARM {
		t.Fatalf("JARM response typ: %q", typ)
	}
	if c := jwtPayload(jarm); c["error"] != "invalid_request" || c["sub"] != nil || c["sid"] != nil {
		t.Fatalf("JARM error claims: %v", c)
	}
	refused("a JARM error response", getLogout(jarm), sid)
	// The same response as it was signed before JARM had its own typ: the
	// ID-token shape check refuses it (no sub, no iat, an error member).
	legacyJARM, err := h.App.Signer.Sign(ctx, h.Realm.ID, token.TypeID, map[string]any{"iss": h.Realm.Issuer, "aud": "web-bff",
		"exp": h.Clock.Now().Unix() + 600, "error": "invalid_request", "error_description": "PKCE required", "state": "lure"})
	if err != nil {
		t.Fatal(err)
	}
	refused("a JARM error response typed JWT", getLogout(legacyJARM), sid)

	// A signed UserInfo response, here even the browser user's own.
	alg, err := h.App.Signer.ActiveAlgorithm(ctx, h.Realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	ui := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "ui-signed", "name": "Signed UserInfo", "client_type": "confidential",
		"first_party": true, "redirect_uris": []string{"https://app.test/cb"}, "userinfo_signed_response_alg": alg}), 201, "signed userinfo client")
	var uiAud string
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			uiAud = m["audience"].(string)
			f.must(f.AdminAPI("PUT", "/clients/"+ui.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid", "email"}}),
				204, "userinfo grant")
		}
	}
	lr := h.Login(LoginOpts{ClientID: "ui-signed", ClientSecret: ui.Str("client_secret"), RedirectURI: "https://app.test/cb", Scope: "openid email",
		Resources: []string{uiAud}, Identifier: "alice@example.test"})
	info := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: lr.Tokens.Str("access_token")})
	mustStatus(t, info, 200, "signed userinfo")
	signedInfo := string(info.Raw)
	if typ := jwsType(t, signedInfo); typ != token.TypeUserInfo || jwtPayload(signedInfo)["sub"] != f.Users["alice"] {
		t.Fatalf("signed userinfo: typ %q, claims %v", typ, jwtPayload(signedInfo))
	}
	refused("a signed UserInfo response", getLogout(signedInfo), sid)

	// ID tokens that do not belong to the browser session: another user's
	// (its sid names that user's session), and one without sid whose sub is
	// another user (the shape of ID tokens from flows without a session).
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("id_token")
	refused("another user's ID token", getLogout(bob), sid)
	mint := func(sub string) string {
		t.Helper()
		now := h.Clock.Now().Unix()
		raw, err := h.App.Signer.Sign(ctx, h.Realm.ID, token.TypeID, token.IDClaims{Issuer: h.Realm.Issuer, Subject: sub,
			Audience: jwt.Audience{"web-bff"}, AZP: "web-bff", Expiry: now + 300, IssuedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	refused("another user's ID token without sid", getLogout(mint(f.Users["bob"])), sid)

	// The cookie still signs the browser in silently.
	silent, _ := sesAuthorizeQuery("web-bff", webRedirect, "openid orders:read", f.OrdersAud, f.Acme, url.Values{"prompt": {"none"}})
	if l, _ := url.Parse(b.do("GET", silent, nil, nil).Header.Get("Location")); l == nil || l.Query().Get("code") == "" {
		t.Fatal("the browser session no longer authenticates after refused logouts")
	}

	// POST is unchanged: a hint naming another session leaves the cookie
	// session alone without an error; a hint that is not an ID token is
	// refused as before (invalid id_token_hint).
	post := func(hint string) *Resp {
		form := url.Values{}
		if hint != "" {
			form.Set("id_token_hint", hint)
		}
		return h.Do(Req{Method: "POST", Path: "/realms/main/oidc/logout", Form: form, Headers: map[string]string{"Cookie": "pa_sid=" + cookie}})
	}
	if r := post(bob); r.Status != 200 || r.Get("session_ended") != false || !active(sid) {
		t.Fatalf("POST with another session's hint: %d %s", r.Status, r.Raw)
	}
	if r := post(jarm); r.Status != 400 || r.Str("error") != "invalid_request" || !active(sid) {
		t.Fatalf("POST with a JARM response as hint: %d %s", r.Status, r.Raw)
	}

	// The browser's own ID token ends the session.
	if r := getLogout(tokens.Str("id_token")); r.Status != 200 || r.Get("session_ended") != true || active(sid) {
		t.Fatalf("GET logout with the session's ID token: %d %s", r.Status, r.Raw)
	}
	// So does an ID token without sid whose sub is the session's user.
	_, sid, _ = signIn()
	if r := getLogout(mint(f.Users["alice"])); r.Status != 200 || r.Get("session_ended") != true || active(sid) {
		t.Fatalf("GET logout with the user's ID token without sid: %d %s", r.Status, r.Raw)
	}
	// And POST with the cookie alone, as before.
	_, sid, cookie = signIn()
	if r := post(""); r.Status != 200 || r.Get("session_ended") != true || active(sid) {
		t.Fatalf("POST logout with the cookie: %d %s", r.Status, r.Raw)
	}
	var revoked int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='session.logout' AND realm_id=$1`, h.Realm.ID).
		Scan(&revoked); err != nil || revoked != 3 {
		t.Fatalf("session.logout audit events: %d %v", revoked, err)
	}
}
