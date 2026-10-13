package e2e

import (
	"net/url"
	"strings"
	"testing"
)

// TestFrontChannelLogout covers SES-018: clients may register a front-channel
// logout URI on their own site; ending a session at the logout endpoint
// lists the participating clients' URIs (with iss and sid when asked) in a
// page that frames only those origins, or as JSON for a login UI. Discovery
// advertises the profile.
func TestFrontChannelLogout(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	base := map[string]any{"name": "Front channel", "client_type": "confidential", "first_party": true,
		"redirect_uris": []string{"https://app.test/cb"}, "post_logout_redirect_uris": []string{"https://app.test/bye"}}
	with := func(id string, extra map[string]any) map[string]any {
		m := map[string]any{"client_id": id}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", with("fc-bad", map[string]any{"frontchannel_logout_uri": "https://other.test/fc"})), 422,
		"front-channel URI on another site")
	mustStatus(t, f.AdminAPI("POST", "/clients", with("fc-bad2", map[string]any{"frontchannel_logout_session_required": true})), 422,
		"session_required without a URI")
	reg := f.must(f.AdminAPI("POST", "/clients", with("fc-app", map[string]any{"frontchannel_logout_uri": "https://app.test/fc?x=1",
		"frontchannel_logout_session_required": true})), 201, "client")
	if reg.Str("client.frontchannel_logout_uri") != "https://app.test/fc?x=1" || reg.Get("client.frontchannel_logout_session_required") != true {
		t.Fatalf("client representation: %s", reg.Raw)
	}
	resources := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	for _, it := range resources.Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid"}}),
				204, "oidc grant")
		}
	}
	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	if disco.Get("frontchannel_logout_supported") != true || disco.Get("frontchannel_logout_session_supported") != true {
		t.Fatalf("discovery: %v %v", disco.Get("frontchannel_logout_supported"), disco.Get("frontchannel_logout_session_supported"))
	}

	login := func() *LoginResult {
		t.Helper()
		return h.Login(LoginOpts{ClientID: "fc-app", ClientSecret: reg.Str("client_secret"), RedirectURI: "https://app.test/cb", Scope: "openid",
			Identifier: "bob@example.test"})
	}
	// A browser gets a page that frames the client's URI and then continues.
	tok := login().Tokens
	sid := jwtPayload(tok.Str("id_token"))["sid"].(string)
	page := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/logout?id_token_hint=" + tok.Str("id_token") + "&post_logout_redirect_uri=" +
		url.QueryEscape("https://app.test/bye") + "&state=s1"})
	mustStatus(t, page, 200, "front-channel page")
	body := string(page.Raw)
	frame := "https://app.test/fc?x=1&amp;iss=" + url.QueryEscape(h.Realm.Issuer)
	if !strings.Contains(page.Header.Get("Content-Type"), "text/html") || !strings.Contains(body, "<iframe src=\"https://app.test/fc?x=1&amp;iss=") ||
		!strings.Contains(body, "sid="+sid) || !strings.Contains(body, "https://app.test/bye?state=s1") {
		t.Fatalf("front-channel page (want a frame like %s): %s", frame, body)
	}
	if csp := page.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-src https://app.test;") || strings.Contains(csp, "script-src") {
		t.Fatalf("content policy: %s", csp)
	}
	// A login UI asking for JSON renders the frames itself.
	tok = login().Tokens
	js := h.Do(Req{Method: "POST", Path: "/realms/main/oidc/logout", Headers: map[string]string{"Accept": "application/json"},
		Form: url.Values{"id_token_hint": {tok.Str("id_token")}}})
	mustStatus(t, js, 200, "front-channel JSON")
	uris, _ := js.Get("frontchannel_logout_uris").([]any)
	if len(uris) != 1 || !strings.HasPrefix(uris[0].(string), "https://app.test/fc?x=1&iss=") || js.Get("session_ended") != true {
		t.Fatalf("front-channel JSON: %s", js.Raw)
	}
}
