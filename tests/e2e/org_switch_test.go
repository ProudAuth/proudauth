package e2e

import (
	"context"
	"net/url"
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

// switchApp is a third-party client (consent_mode required) holding the
// account resource, so it can call POST /me/organization-grants for its
// users, and the Orders resource, whose tokens carry an organization.
type switchApp struct {
	f         *Fixture
	ref       string
	secret    string
	verifier  string
	challenge string
}

const switchRedirect = "https://switch.test/cb"

func newSwitchApp(t *testing.T, f *Fixture) *switchApp {
	t.Helper()
	created := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "switch-app", "name": "Switch App", "client_type": "confidential",
		"first_party": false, "grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{switchRedirect}}), 201, "third-party client")
	if created.Str("client.consent_mode") != "required" {
		t.Fatalf("third-party client consent mode: %s", created.Raw)
	}
	app := &switchApp{f: f, ref: created.Str("client.id"), secret: created.Str("client_secret")}
	app.verifier, app.challenge = PKCE()
	var account string
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "account" {
			account = m["id"].(string)
		}
	}
	for res, scopes := range map[string][]string{account: {"proudauth:account"}, f.Orders: {"orders:read", "orders:write"}} {
		f.must(f.AdminAPI("PUT", "/clients/"+app.ref+"/resource-grants/"+res, map[string]any{"allowed_scopes": scopes, "subject_types": []string{"user"}}),
			204, "client grant")
	}
	return app
}

// login signs the user in to the app within org and returns its account token.
func (a *switchApp) login(t *testing.T, user, org string) string {
	t.Helper()
	lr := a.f.H.Login(LoginOpts{ClientID: "switch-app", ClientSecret: a.secret, RedirectURI: switchRedirect, Scope: "proudauth:account orders:read",
		Resources: []string{a.f.H.Realm.Issuer + "/account", a.f.OrdersAud}, Organization: org, SelectOrg: org, Identifier: user + "@example.test"})
	return lr.Tokens.Str("access_token")
}

func (a *switchApp) switchTo(tok, org, scope string) *Resp {
	return a.f.H.API("POST", "/me/organization-grants", tok, map[string]any{"client_id": "switch-app", "organization_id": org,
		"redirect_uri": switchRedirect, "code_challenge": a.challenge, "code_challenge_method": "S256", "scope": scope,
		"resource": []string{a.f.H.Realm.Issuer + "/account", a.f.OrdersAud}, "state": "s1"})
}

// code returns the authorization code of a successful switch.
func (a *switchApp) code(t *testing.T, r *Resp, what string) string {
	t.Helper()
	u, err := url.Parse(r.Str("redirect_to"))
	if r.Status != 200 || err != nil || u.Query().Get("code") == "" {
		t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
	}
	return u.Query().Get("code")
}

func (a *switchApp) redeem(code string) *Resp {
	return a.f.H.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {a.verifier},
		"redirect_uri": {switchRedirect}, "resource": {a.f.OrdersAud}}, "switch-app", a.secret)
}

func (a *switchApp) refresh(rt string) *Resp {
	return a.f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "switch-app", a.secret)
}

// grantConsent returns the consent the user's newest active grant for the
// app in org rests on.
func (a *switchApp) grantConsent(t *testing.T, user, org string) string {
	t.Helper()
	var id string
	if err := a.f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT coalesce(consent_id,'') FROM authorization_grants
		WHERE subject_id=$1 AND client_ref=$2 AND organization_id=$3 AND state='active' ORDER BY created_at DESC LIMIT 1`,
		a.f.Users[user], a.ref, org).Scan(&id); err != nil {
		t.Fatalf("grant of %s in %s: %v", user, org, err)
	}
	return id
}

// mustConsentRequired checks a 403 consent_required with an authorize
// obligation naming the organization.
func mustConsentRequired(t *testing.T, r *Resp, org, what string) {
	t.Helper()
	obl, _ := r.Get("obligations").([]any)
	if r.Status != 403 || r.Str("code") != "consent_required" || len(obl) != 1 {
		t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
	}
	if o := obl[0].(map[string]any); o["type"] != "authorize" || o["organization_id"] != org {
		t.Fatalf("%s: obligation %v", what, o)
	}
}

// TestOrganizationSwitchConsent covers QA-008, TOK-008, APP-013, TEN-005 and
// SES-002 (CHANGELOG 0.2.0-alpha.6 Security, "POST /me/organization-grants,
// the organization switch, runs the consent coverage"; alpha.6 decision 12):
// the switch runs the consent coverage of an authorization for the target
// organization. A scope the user never consented to for a
// consent_mode=required client is 403 consent_required with an authorize
// obligation; a covered switch creates a grant that rests on the user's
// consent, which ends with it; and the client's
// token_policy.max_session_age_seconds refuses an older session.
func TestOrganizationSwitchConsent(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	app := newSwitchApp(t, f)
	bob := app.login(t, "bob", f.Acme) // consents to proudauth:account orders:read
	cli := f.AccountToken("bob").Tokens.Str("access_token")
	consents := f.must(h.API("GET", "/me/consents", cli, nil), 200, "consents").Get("items").([]any)
	if len(consents) != 1 || consents[0].(map[string]any)["mode"] != "user" {
		t.Fatalf("consents after sign-in: %v", consents)
	}
	consent := consents[0].(map[string]any)["id"].(string)

	// Covered scopes: the switch issues a code whose grant rests on the
	// user's consent.
	tokens := app.redeem(app.code(t, app.switchTo(bob, f.Globex, "proudauth:account orders:read"), "covered switch"))
	mustStatus(t, tokens, 200, "redeem the switch code")
	if org := jwtPayload(tokens.Str("access_token"))["org_id"]; org != f.Globex {
		t.Fatalf("switched token organization %v", org)
	}
	if got := app.grantConsent(t, "bob", f.Globex); got != consent {
		t.Fatalf("switch grant consent %q, want %q", got, consent)
	}

	// A scope the user never approved for the client, in either organization.
	mustConsentRequired(t, app.switchTo(bob, f.Globex, "proudauth:account orders:read orders:write"), f.Globex, "unconsented scope")
	mustConsentRequired(t, app.switchTo(bob, f.Acme, "orders:write"), f.Acme, "unconsented scope in the sign-in organization")

	// The client's session-age bound (SES-002) refuses an older session as
	// an authorization would.
	setAge := func(n int) {
		t.Helper()
		if _, err := h.App.D.DB.Pool.Exec(context.Background(), `UPDATE clients SET token_policy = token_policy || jsonb_build_object('max_session_age_seconds', $1::int)
			WHERE id=$2`, n, app.ref); err != nil {
			t.Fatal(err)
		}
	}
	setAge(60)
	h.Clock.Advance(2 * time.Minute)
	r := app.switchTo(bob, f.Globex, "proudauth:account orders:read")
	obl, _ := r.Get("obligations").([]any)
	if r.Status != 403 || r.Str("code") != "step_up_required" || len(obl) != 1 ||
		obl[0].(map[string]any)["type"] != "reauthenticate" || obl[0].(map[string]any)["max_age_seconds"] != float64(60) {
		t.Fatalf("switch beyond the client's max_session_age_seconds: %d %s", r.Status, r.Raw)
	}
	setAge(0)

	// Revoking the consent ends the switch grant: its refresh token and an
	// unredeemed switch code stop working.
	pending := app.code(t, app.switchTo(bob, f.Globex, "proudauth:account orders:read"), "second switch")
	mustStatus(t, h.API("DELETE", "/me/consents/"+consent, cli, nil), 204, "revoke consent")
	if r := app.refresh(tokens.Str("refresh_token")); r.Status == 200 {
		t.Fatal("the switch grant survived the revoked consent")
	}
	if r := app.redeem(pending); r.Status == 200 {
		t.Fatal("a switch code was redeemed after the consent was revoked")
	}
}

// TestOrganizationSwitchPreauthorization covers QA-008, APP-013 and TOK-008
// (CHANGELOG 0.2.0-alpha.6 Security, "POST /me/organization-grants, the
// organization switch, runs the consent coverage"; alpha.6 decision 12):
// without the user's own consent a switch needs an administrative
// pre-authorization for the realm or the target organization. A
// pre-authorization of another organization, and the consent recorded for it
// at sign-in, do not reach the target, for the switch and for an
// authorization alike. A covered switch rests on a consent recorded for the
// pre-authorization, so revoking the pre-authorization ends it.
func TestOrganizationSwitchPreauthorization(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	app := newSwitchApp(t, f)
	preauthorize := func(org string) string {
		t.Helper()
		return f.must(f.AdminAPI("POST", "/clients/"+app.ref+"/consent-preauthorizations", map[string]any{"organization_id": org,
			"scopes": []string{"proudauth:account", "orders:read"}, "reason": "procurement ticket 81"}), 201, "pre-authorize").Str("id")
	}
	asked := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type='consent.granted' AND subject_id=$1`, f.Users["bob"]).Scan(&n)
		return n
	}
	preauthorize(f.Acme)
	bob := app.login(t, "bob", f.Acme)
	if n := asked(); n != 0 {
		t.Fatalf("pre-authorized sign-in asked for consent: %d", n)
	}
	// Acme's pre-authorization does not cover Globex.
	mustConsentRequired(t, app.switchTo(bob, f.Globex, "proudauth:account orders:read"), f.Globex, "switch to an organization without a pre-authorization")
	// Within Acme the switch is covered.
	app.code(t, app.switchTo(bob, f.Acme, "proudauth:account orders:read"), "switch within the pre-authorized organization")

	// A pre-authorization for Globex covers the switch; the grant rests on a
	// consent recorded for it and ends with it.
	globex := preauthorize(f.Globex)
	tokens := app.redeem(app.code(t, app.switchTo(bob, f.Globex, "proudauth:account orders:read"), "pre-authorized switch"))
	mustStatus(t, tokens, 200, "redeem the switch code")
	var mode, pre string
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT mode, coalesce(preauthorization_id,'') FROM consents WHERE id=$1`,
		app.grantConsent(t, "bob", f.Globex)).Scan(&mode, &pre); err != nil || mode != "preauthorized" || pre != globex {
		t.Fatalf("switch grant consent basis: %v %q %q", err, mode, pre)
	}
	mustStatus(t, f.AdminAPI("DELETE", "/clients/"+app.ref+"/consent-preauthorizations/"+globex, nil), 204, "revoke pre-authorization")
	if r := app.refresh(tokens.Str("refresh_token")); r.Status == 200 {
		t.Fatal("the switch grant survived the revoked pre-authorization")
	}

	// The authorization path applies the same coverage: a sign-in to Acme
	// is not asked, a sign-in to Globex is.
	app.login(t, "bob", f.Acme)
	if n := asked(); n != 0 {
		t.Fatalf("pre-authorized sign-in asked for consent: %d", n)
	}
	app.login(t, "bob", f.Globex)
	if n := asked(); n != 1 {
		t.Fatalf("sign-in to an organization without a pre-authorization was not asked for consent: %d", n)
	}
}
