package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestDynamicClientRegistration covers APP-016, APP-017 and ADV-003:
// registration is off until a realm enables it; it needs an administrator's
// initial access token (bounded uses, non-privileged scopes) unless open
// registration is allowed, in which case clients wait for approval; metadata
// is validated (exact redirects, no key fetching, no software statements, no
// other grants); the registrant manages its own client with a rotating
// registration access token and nothing else.
func TestDynamicClientRegistration(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	register := func(token string, meta map[string]any) *Resp {
		t.Helper()
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/register", Token: token, JSON: meta})
	}
	meta := func(extra map[string]any) map[string]any {
		m := map[string]any{"redirect_uris": []string{"https://dcr.test/cb"}, "client_name": "Partner integration",
			"scope": "openid email orders:read orders:write", "grant_types": []string{"authorization_code", "refresh_token"}, "x-unknown-member": 1}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	mustStatus(t, register("", meta(nil)), 404, "registration disabled by default")
	f.must(f.SetPolicy(func(p *realm.Policy) { p.ClientRegistration.Enabled = true }), 200, "enable registration")
	disco := f.must(h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}), 200, "discovery")
	if disco.Str("registration_endpoint") != h.Realm.Issuer+"/oauth/register" {
		t.Fatalf("registration endpoint: %v", disco.Get("registration_endpoint"))
	}
	if r := register("", meta(nil)); r.Status != 401 || r.Str("error") != "invalid_token" {
		t.Fatalf("registration without a token: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"allowed_scopes": []map[string]any{{"resource_id": f.Billing,
		"scopes": []string{"billing:admin"}}}}), 422, "privileged scope in an initial access token")
	iat := f.must(f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"description": "partner onboarding", "max_uses": 2,
		"allowed_scopes": []map[string]any{{"resource_id": f.Orders, "scopes": []string{"orders:read"}}}}), 201, "initial access token")
	token := iat.Str("initial_access_token")
	for name, c := range map[string]struct {
		extra map[string]any
		code  string
	}{
		"http redirect":      {map[string]any{"redirect_uris": []string{"http://evil.test/cb"}}, "invalid_redirect_uri"},
		"wildcard redirect":  {map[string]any{"redirect_uris": []string{"https://*.dcr.test/cb"}}, "invalid_redirect_uri"},
		"key fetching":       {map[string]any{"jwks_uri": "https://dcr.test/jwks"}, "invalid_client_metadata"},
		"software statement": {map[string]any{"software_statement": "eyJ.x.y"}, "unapproved_software_statement"},
		"client credentials": {map[string]any{"grant_types": []string{"client_credentials"}}, "invalid_client_metadata"},
		"implicit":           {map[string]any{"response_types": []string{"token"}}, "invalid_client_metadata"},
		"http logo":          {map[string]any{"logo_uri": "http://dcr.test/logo.png"}, "invalid_client_metadata"},
	} {
		if r := register(token, meta(c.extra)); r.Status != 400 || r.Str("error") != c.code {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	reg := register(token, meta(map[string]any{"software_id": "partner-sync", "software_version": "1.2", "logo_uri": "https://dcr.test/logo.png"}))
	mustStatus(t, reg, 201, "registration")
	clientID, secret, rat := reg.Str("client_id"), reg.Str("client_secret"), reg.Str("registration_access_token")
	if secret == "" || !strings.HasPrefix(rat, "pa_rat_") || reg.Str("proudauth_approval_state") != "approved" ||
		reg.Str("scope") != "openid email orders:read" || reg.Str("registration_client_uri") != h.Realm.Issuer+"/oauth/register/"+clientID {
		t.Fatalf("registration response: %s", reg.Raw)
	}
	// The registered client works like any third-party client: consent, then tokens.
	lr := h.Login(LoginOpts{ClientID: clientID, ClientSecret: secret, RedirectURI: "https://dcr.test/cb", Scope: "openid orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	if c := jwtPayload(lr.Tokens.Str("access_token")); c["scope"] != "orders:read" {
		t.Fatalf("registered client token: %v", c)
	}
	// Management with the registration access token only.
	manage := func(method, id, tok string, body any) *Resp {
		return h.Do(Req{Method: method, Path: "/realms/main/oauth/register/" + id, Token: tok, JSON: body})
	}
	if g := manage("GET", clientID, rat, nil); g.Status != 200 || g.Str("client_secret") != "" || g.Str("software_id") != "partner-sync" {
		t.Fatalf("read registration: %d %s", g.Status, g.Raw)
	}
	mustStatus(t, manage("GET", clientID, "pa_rat_wrong", nil), 401, "wrong registration token")
	mustStatus(t, manage("GET", clientID, f.AdminToken, nil), 401, "admin token is not a registration token")
	mustStatus(t, manage("GET", "web-bff", rat, nil), 401, "another client")
	upd := manage("PUT", clientID, rat, meta(map[string]any{"client_id": clientID, "client_name": "Partner integration v2", "rotate_secret": true,
		"redirect_uris": []string{"https://dcr.test/cb", "https://dcr.test/cb2"}}))
	mustStatus(t, upd, 200, "update registration")
	newRAT, newSecret := upd.Str("registration_access_token"), upd.Str("client_secret")
	if newRAT == "" || newRAT == rat || newSecret == "" || upd.Str("client_name") != "Partner integration v2" || upd.Str("scope") != "openid email orders:read" {
		t.Fatalf("update response: %s", upd.Raw)
	}
	mustStatus(t, manage("GET", clientID, rat, nil), 401, "rotated registration token")
	mustStatus(t, manage("PUT", clientID, newRAT, meta(map[string]any{"client_id": clientID, "token_endpoint_auth_method": "none"})), 400, "type change")
	for _, s := range []string{secret, newSecret} {
		mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"pa_rt_unknown"}}, clientID, s), 400,
			"client authenticates (old secret within its grace period)")
	}
	ctx := context.Background()
	var clientRef string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM clients WHERE client_id=$1`, clientID).Scan(&clientRef); err != nil {
		t.Fatal(err)
	}

	// Rotation is atomic and the limit counts only usable secrets: a third
	// overlapping secret (limits.client_secrets_max, 3 by default) is
	// refused without changing anything, and the presented registration
	// access token keeps working.
	rotate := func(tok, name string) *Resp {
		return manage("PUT", clientID, tok, meta(map[string]any{"client_id": clientID, "client_name": name, "rotate_secret": true,
			"contacts": []string{"dev@partner.test"}, "redirect_uris": []string{"https://dcr.test/cb", "https://dcr.test/cb2"}}))
	}
	second := rotate(newRAT, "Partner integration v2")
	mustStatus(t, second, 200, "second rotation")
	newRAT = second.Str("registration_access_token")
	if second.Get("contacts") == nil {
		t.Fatalf("contacts not registered: %s", second.Raw)
	}
	// Registrant-supplied contacts are unverified: the old secrets expiring
	// within the hour alert nobody (the client has no owner).
	if _, err := worker.New(h.App, "test").CredentialExpiryAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	var alerts int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_jobs WHERE reference_type='credential_expiry'`).Scan(&alerts)
	if alerts != 0 {
		t.Fatalf("credential-expiry mail to registrant-supplied contacts: %d", alerts)
	}
	if r := rotate(newRAT, "Partner integration v3"); r.Status != 409 {
		t.Fatalf("third overlapping secret: %d %s", r.Status, r.Raw)
	}
	if g := manage("GET", clientID, newRAT, nil); g.Status != 200 || g.Str("client_name") != "Partner integration v2" {
		t.Fatalf("a refused rotation changed the registration or its token: %d %s", g.Status, g.Raw)
	}
	var secrets int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM client_credentials WHERE client_ref=$1 AND kind='secret' AND state='active'`, clientRef).Scan(&secrets)
	if secrets != 3 {
		t.Fatalf("secrets after a refused rotation: %d", secrets)
	}
	// An initial access token past its expiry is reported as expired.
	short := f.must(f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"expires_in_seconds": 60}), 201, "short-lived token")
	// Secrets past their expiry no longer count against the limit.
	h.Clock.Advance(61 * time.Minute)
	f.ReloginAdmin()
	third := rotate(newRAT, "Partner integration v3")
	mustStatus(t, third, 200, "rotation once the overlapping secrets expired")
	newRAT, newSecret = third.Str("registration_access_token"), third.Str("client_secret")
	listed := f.must(f.AdminAPI("GET", "/client-registration-tokens", nil), 200, "initial access tokens")
	for _, it := range listed.Get("items").([]any) {
		m := it.(map[string]any)
		if m["id"] == short.Str("token.id") && m["state"] != "expired" {
			t.Fatalf("expired initial access token listed as %v", m["state"])
		}
	}
	mustStatus(t, register(short.Str("initial_access_token"), meta(nil)), 401, "expired initial access token")

	// What an administrator set is not the registrant's to reset: a
	// registrant's PUT keeps the token policy, a pairwise subject and the
	// back-channel logout URI, and refuses redirect URIs outside the
	// pairwise sector.
	cur := f.must(f.AdminAPI("GET", "/clients/"+clientRef, nil), 200, "registered client")
	admin := map[string]any{"client_id": clientID, "name": "Partner integration v3", "client_type": "confidential",
		"token_endpoint_auth_method": "client_secret_basic", "grant_types": []string{"authorization_code", "refresh_token"},
		"redirect_uris": []string{"https://dcr.test/cb", "https://dcr.test/cb2"}, "security_profile": "third_party", "consent_mode": "required",
		"subject_type": "pairwise", "token_policy": map[string]any{"access_token_ttl_seconds": 120}, "backchannel_logout_uri": "https://dcr.test/bcl"}
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/clients/" + clientRef, Token: f.AdminToken, JSON: admin,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "administrator settings")
	kept := manage("PUT", clientID, newRAT, meta(map[string]any{"client_id": clientID, "client_name": "Partner integration v4",
		"redirect_uris": []string{"https://dcr.test/cb", "https://app.dcr.test/cb"}}))
	mustStatus(t, kept, 200, "registrant update after administrator changes")
	newRAT = kept.Str("registration_access_token")
	after := f.must(f.AdminAPI("GET", "/clients/"+clientRef, nil), 200, "registered client after the update")
	if after.Str("client.name") != "Partner integration v4" || after.Str("client.subject_type") != "pairwise" || after.Str("client.sector_identifier") != "dcr.test" ||
		after.Get("client.token_policy.access_token_ttl_seconds") != float64(120) || after.Str("client.backchannel_logout_uri") != "https://dcr.test/bcl" {
		t.Fatalf("a registrant update reset administrator settings: %s", after.Raw)
	}
	if r := manage("PUT", clientID, newRAT, meta(map[string]any{"client_id": clientID, "redirect_uris": []string{"https://other.test/cb"}})); r.Status != 400 ||
		r.Str("error") != "invalid_client_metadata" {
		t.Fatalf("redirect outside the pairwise sector: %d %s", r.Status, r.Raw)
	}
	// The initial access token is spent after two registrations, and can be revoked.
	mustStatus(t, register(token, meta(nil)), 201, "second use")
	mustStatus(t, register(token, meta(nil)), 401, "exhausted token")
	iat2 := f.must(f.AdminAPI("POST", "/client-registration-tokens", map[string]any{}), 201, "another token")
	mustStatus(t, f.AdminAPI("DELETE", "/client-registration-tokens/"+iat2.Str("token.id"), nil), 204, "revoke")
	mustStatus(t, register(iat2.Str("initial_access_token"), meta(nil)), 401, "revoked token")

	// Open registration: OpenID Connect scopes only, held for approval.
	f.must(f.SetPolicy(func(p *realm.Policy) { p.ClientRegistration.Open = true }), 200, "open registration")
	open := register("", meta(map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []string{"http://127.0.0.1/cb"}}))
	mustStatus(t, open, 201, "open registration")
	if open.Str("proudauth_approval_state") != "pending" || open.Str("proudauth_client_state") != "suspended" || open.Str("scope") != "openid email" ||
		open.Str("client_secret") != "" {
		t.Fatalf("open registration: %s", open.Raw)
	}
	if st, _, _ := h.StartTx(LoginOpts{ClientID: open.Str("client_id"), RedirectURI: "http://127.0.0.1/cb", Scope: "openid"}); st.Status != 400 {
		t.Fatalf("a pending registration was usable: %d %s", st.Status, st.Raw)
	}
	pending := f.must(f.AdminAPI("GET", "/client-registrations?approval_state=pending", nil), 200, "pending list")
	items := pending.Get("items").([]any)
	if len(items) != 1 || items[0].(map[string]any)["client_id"] != open.Str("client_id") {
		t.Fatalf("pending registrations: %s", pending.Raw)
	}
	ref := items[0].(map[string]any)["client_ref"].(string)
	// The client API cannot activate a pending registration around its approval.
	mustStatus(t, f.AdminAPI("POST", "/clients/"+ref+"/reactivate", map[string]any{}), 409, "reactivating a pending registration")
	if c := f.must(f.AdminAPI("GET", "/clients/"+ref, nil), 200, "pending client"); c.Str("client.state") != "suspended" {
		t.Fatalf("pending client state: %s", c.Raw)
	}
	// The approval names the client version the administrator reviewed.
	reviewed := map[string]any{"reviewed_version": items[0].(map[string]any)["version"]}
	mustStatus(t, f.AdminAPI("POST", "/client-registrations/"+ref+"/approve", reviewed), 204, "approve")
	mustStatus(t, f.AdminAPI("POST", "/client-registrations/"+ref+"/approve", reviewed), 409, "already decided")
	h.Login(LoginOpts{ClientID: open.Str("client_id"), RedirectURI: "http://127.0.0.1/cb", Scope: "openid", Identifier: "bob@example.test"})

	// The registrant deletes its client: tokens and management stop.
	mustStatus(t, manage("DELETE", clientID, newRAT, nil), 204, "delete")
	mustStatus(t, manage("GET", clientID, newRAT, nil), 401, "deleted client")
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}}, clientID, newSecret), 401,
		"deleted client cannot authenticate")
}

// TestDynamicRegistrationReapproval covers APP-016, APP-017 and ADV-003 with
// alpha.6 decision 14: where a registration requires approval, a
// registrant's change of the reviewed metadata (client_name,
// redirect_uris, post_logout_redirect_uris, grant_types, client_uri,
// logo_uri, policy_uri, tos_uri) returns an approved registration to
// pending and suspends its client, with the values before and after in the
// audit record; a secret rotation or an update that changes none of them
// does not; an approval names the client version the administrator
// reviewed and is refused with 409 when the client changed since, also
// while the registration was under review; realms without approval keep
// approved clients active.
func TestDynamicRegistrationReapproval(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	f.must(f.SetPolicy(func(p *realm.Policy) {
		p.ClientRegistration.Enabled = true
		p.ClientRegistration.RequireApproval = true
	}), 200, "registration with approval")
	iat := f.must(f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"max_uses": 10}), 201, "initial access token").Str("initial_access_token")
	register := func(token string, meta map[string]any) *Resp {
		t.Helper()
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/register", Token: token, JSON: meta})
	}
	type registered struct{ id, ref, secret, rat string }
	registerClient := func(token string, meta map[string]any) *registered {
		t.Helper()
		r := register(token, meta)
		mustStatus(t, r, 201, "registration")
		c := &registered{id: r.Str("client_id"), secret: r.Str("client_secret"), rat: r.Str("registration_access_token")}
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM clients WHERE client_id=$1`, c.id).Scan(&c.ref); err != nil {
			t.Fatal(err)
		}
		return c
	}
	// put sends a registrant update and keeps the new registration access token.
	put := func(c *registered, meta map[string]any) *Resp {
		t.Helper()
		body := map[string]any{"client_id": c.id}
		for k, v := range meta {
			body[k] = v
		}
		r := h.Do(Req{Method: "PUT", Path: "/realms/main/oauth/register/" + c.id, Token: c.rat, JSON: body})
		mustStatus(t, r, 200, "registrant update")
		c.rat = r.Str("registration_access_token")
		return r
	}
	listed := func(c *registered) map[string]any {
		t.Helper()
		l := f.must(f.AdminAPI("GET", "/client-registrations", nil), 200, "registrations")
		for _, it := range l.Get("items").([]any) {
			if m := it.(map[string]any); m["client_ref"] == c.ref {
				return m
			}
		}
		t.Fatalf("registration %s not listed: %s", c.ref, l.Raw)
		return nil
	}
	approve := func(c *registered, version any) *Resp {
		t.Helper()
		return f.AdminAPI("POST", "/client-registrations/"+c.ref+"/approve", map[string]any{"reviewed_version": version})
	}
	approveListed := func(c *registered) {
		t.Helper()
		l := listed(c)
		mustStatus(t, approve(c, l["version"]), 204, "approve the listed version")
		if l2 := listed(c); l2["approval_state"] != "approved" || l2["client_state"] != "active" || l2["reviewed_version"] != l["version"] {
			t.Fatalf("after approval: %v (approved %v)", l2, l["version"])
		}
	}
	// probe is a token request with the client's own credentials: an active
	// client authenticates and is told the refresh token is unknown (400),
	// a suspended one cannot authenticate (401 invalid_client).
	probe := func(c *registered) *Resp {
		t.Helper()
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"pa_rt_unknown"}}, c.id, c.secret)
	}
	mustBeActive := func(c *registered, what string) {
		t.Helper()
		if r := probe(c); r.Status != 400 {
			t.Fatalf("%s: the client cannot authenticate: %d %s", what, r.Status, r.Raw)
		}
	}
	lastUpdate := func(c *registered) map[string]any {
		t.Helper()
		var meta map[string]any
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata FROM audit_events WHERE type='client.registration.updated' AND target_id=$1
			ORDER BY seq DESC LIMIT 1`, c.ref).Scan(&meta); err != nil {
			t.Fatal(err)
		}
		return meta
	}
	meta := map[string]any{"client_name": "Partner app", "redirect_uris": []string{"https://dcr.test/cb"},
		"grant_types": []string{"authorization_code", "refresh_token"}, "logo_uri": "https://dcr.test/logo.png",
		"client_uri": "https://dcr.test/", "policy_uri": "https://dcr.test/privacy", "tos_uri": "https://dcr.test/terms"}
	with := func(changes map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range meta {
			out[k] = v
		}
		for k, v := range changes {
			out[k] = v
		}
		return out
	}
	c := registerClient(iat, meta)
	if l := listed(c); l["approval_state"] != "pending" || l["client_state"] != "suspended" || l["logo_uri"] != "https://dcr.test/logo.png" ||
		l["tos_uri"] != "https://dcr.test/terms" || l["version"] == nil {
		t.Fatalf("pending registration as listed for review: %v", l)
	}

	// (c) The approval names the reviewed version: missing is 422; a
	// version the client has moved past (any registrant update gives it a
	// new one) is 409 and changes nothing; the current one approves.
	stale := listed(c)["version"].(float64)
	mustStatus(t, f.AdminAPI("POST", "/client-registrations/"+c.ref+"/approve", map[string]any{}), 422, "approval without reviewed_version")
	put(c, meta)
	current := listed(c)["version"].(float64)
	if current == stale {
		t.Fatalf("an update kept the client version %v", current)
	}
	for _, v := range []float64{stale, current + 1} {
		if r := approve(c, v); r.Status != 409 {
			t.Fatalf("approval of version %v (the client is at %v): %d %s", v, current, r.Status, r.Raw)
		}
	}
	if l := listed(c); l["approval_state"] != "pending" || l["client_state"] != "suspended" || l["reviewed_version"] != nil {
		t.Fatalf("a refused approval changed the registration: %v", l)
	}
	approveListed(c)
	var reviewed int64
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(reviewed_version,0) FROM client_registrations WHERE client_ref=$1`, c.ref).Scan(&reviewed); err != nil ||
		reviewed != int64(current) {
		t.Fatalf("reviewed_version recorded: %d (%v), want %v", reviewed, err, current)
	}
	mustBeActive(c, "approved client")

	// (b) An update that changes none of the reviewed fields (only contacts
	// and software_version), a secret rotation, and an unchanged PUT keep
	// the approval and the client active.
	for _, u := range []struct {
		name  string
		extra map[string]any
	}{
		{"unchanged", nil},
		{"unreviewed metadata", map[string]any{"contacts": []string{"dev@partner.test"}, "software_version": "2.0"}},
		{"secret rotation", map[string]any{"rotate_secret": true}},
		{"reordered lists", map[string]any{"grant_types": []string{"refresh_token", "authorization_code"}}},
	} {
		r := put(c, with(u.extra))
		rotated := r.Str("client_secret") != ""
		if rotated {
			c.secret = r.Str("client_secret")
		}
		if r.Str("proudauth_approval_state") != "approved" || r.Str("proudauth_client_state") != "active" || rotated != (u.name == "secret rotation") {
			t.Fatalf("%s: the registration went back to review: %s", u.name, r.Raw)
		}
		mustBeActive(c, u.name)
		if m := lastUpdate(c); m["requeued"] != false || m["changes"] != nil || m["approval_state"] != "approved" || m["secret_rotated"] != rotated {
			t.Fatalf("%s: audit record %v", u.name, m)
		}
	}

	// A user signed in before the change: their refresh token ends with the
	// suspension, so the new brand needs a new sign-in and consent.
	lr := h.Login(LoginOpts{ClientID: c.id, ClientSecret: c.secret, RedirectURI: "https://dcr.test/cb", Scope: "openid", Identifier: "bob@example.test"})
	refresh := lr.Tokens.Str("refresh_token")
	if refresh == "" {
		t.Fatalf("no refresh token: %s", lr.Tokens.Raw)
	}

	// (a) Each reviewed field, changed on an approved client: pending,
	// suspended (token requests refused), before and after audited.
	for i, ch := range []struct {
		field         string
		value         any
		before, after any
	}{
		{"client_name", "Partner app (new brand)", "Partner app", "Partner app (new brand)"},
		{"redirect_uris", []string{"https://dcr.test/cb", "https://dcr.test/cb2"}, []any{"https://dcr.test/cb"}, []any{"https://dcr.test/cb", "https://dcr.test/cb2"}},
		{"post_logout_redirect_uris", []string{"https://dcr.test/bye"}, []any{}, []any{"https://dcr.test/bye"}},
		{"grant_types", []string{"authorization_code"}, []any{"authorization_code", "refresh_token"}, []any{"authorization_code"}},
		{"logo_uri", "https://dcr.test/other-logo.png", "https://dcr.test/logo.png", "https://dcr.test/other-logo.png"},
		{"client_uri", "https://partner.dcr.test/", "https://dcr.test/", "https://partner.dcr.test/"},
		{"policy_uri", "https://dcr.test/privacy-v2", "https://dcr.test/privacy", "https://dcr.test/privacy-v2"},
		{"tos_uri", "https://dcr.test/terms-v2", "https://dcr.test/terms", "https://dcr.test/terms-v2"},
	} {
		meta = with(map[string]any{ch.field: ch.value})
		r := put(c, meta)
		if r.Str("proudauth_approval_state") != "pending" {
			t.Fatalf("%s changed: the registration stayed approved: %s", ch.field, r.Raw)
		}
		if l := listed(c); l["approval_state"] != "pending" || l["requeued_at"] == nil {
			t.Fatalf("%s changed: listed as %v", ch.field, l)
		}
		if r.Str("proudauth_client_state") != "suspended" || listed(c)["client_state"] != "suspended" {
			t.Fatalf("%s changed: the client was not suspended: %s", ch.field, r.Raw)
		}
		if p := probe(c); p.Status != 401 || p.Str("error") != "invalid_client" {
			t.Fatalf("%s changed: a token request of the re-queued client: %d %s", ch.field, p.Status, p.Raw)
		}
		m := lastUpdate(c)
		changes, _ := m["changes"].(map[string]any)
		got, _ := changes[ch.field].(map[string]any)
		if m["requeued"] != true || m["approval_state"] != "pending" || len(changes) != 1 || got == nil ||
			jsonString(got["before"]) != jsonString(ch.before) || jsonString(got["after"]) != jsonString(ch.after) {
			t.Fatalf("%s changed: audit record %v", ch.field, m)
		}
		if i == 0 {
			var reason string
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(reason_code,'') FROM audit_events WHERE type='client.suspended' AND target_id=$1
				ORDER BY seq DESC LIMIT 1`, c.ref).Scan(&reason); err != nil || reason != "registration_requeued" {
				t.Fatalf("suspension audit: %q %v", reason, err)
			}
			// Only the approval activates it again.
			mustStatus(t, f.AdminAPI("POST", "/clients/"+c.ref+"/reactivate", map[string]any{}), 409, "reactivating a re-queued registration")
		}
		approveListed(c)
		mustBeActive(c, ch.field+" approved")
		if i == 0 {
			if r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, c.id, c.secret); r.Status != 400 ||
				r.Str("error") != "invalid_grant" {
				t.Fatalf("a refresh token issued before the re-queue: %d %s", r.Status, r.Raw)
			}
		}
	}

	// (d) A change made while the registration is under review is not
	// approved with the version reviewed before it.
	meta = with(map[string]any{"client_name": "Partner app (rebrand)"})
	put(c, meta)
	seen := listed(c)
	if seen["name"] != "Partner app (rebrand)" || seen["approval_state"] != "pending" {
		t.Fatalf("re-queued registration: %v", seen)
	}
	meta = with(map[string]any{"logo_uri": "https://dcr.test/swapped-logo.png"})
	if r := put(c, meta); r.Str("proudauth_approval_state") != "pending" || r.Str("proudauth_client_state") != "suspended" {
		t.Fatalf("an update under review: %s", r.Raw)
	}
	if m := lastUpdate(c); m["requeued"] != false || m["changes"] == nil {
		t.Fatalf("audit record of an update under review: %v", m)
	}
	if r := approve(c, seen["version"]); r.Status != 409 {
		t.Fatalf("approval of the version reviewed before a change: %d %s", r.Status, r.Raw)
	}
	if l := listed(c); l["approval_state"] != "pending" || l["client_state"] != "suspended" || l["logo_uri"] != "https://dcr.test/swapped-logo.png" {
		t.Fatalf("after a refused approval: %v", l)
	}
	if p := probe(c); p.Status != 401 {
		t.Fatalf("a refused approval activated the client: %d %s", p.Status, p.Raw)
	}
	approveListed(c)
	mustBeActive(c, "approved after review")

	// A re-queued registration can be rejected; that ends the client.
	put(c, with(map[string]any{"client_name": "Partner app (third brand)"}))
	mustStatus(t, f.AdminAPI("POST", "/client-registrations/"+c.ref+"/reject", nil), 204, "reject a re-queued registration")
	if l := listed(c); l["approval_state"] != "rejected" || l["client_state"] != "decommissioned" {
		t.Fatalf("rejected registration: %v", l)
	}

	// Open registrations always need approval, so their changes re-queue
	// even when require_approval is off.
	f.must(f.SetPolicy(func(p *realm.Policy) {
		p.ClientRegistration.RequireApproval = false
		p.ClientRegistration.Open = true
	}), 200, "open registration without require_approval")
	openMeta := map[string]any{"client_name": "Open app", "redirect_uris": []string{"https://open.dcr.test/cb"}}
	o := registerClient("", openMeta)
	approveListed(o)
	mustBeActive(o, "approved open registration")
	if r := put(o, map[string]any{"client_name": "Open app (new brand)", "redirect_uris": []string{"https://open.dcr.test/cb"}}); r.Str("proudauth_approval_state") != "pending" ||
		r.Str("proudauth_client_state") != "suspended" {
		t.Fatalf("a changed open registration: %s", r.Raw)
	}

	// (e) Without approval, changes keep the client approved and active;
	// the audit record still names them.
	free := registerClient(iat, meta)
	if l := listed(free); l["approval_state"] != "approved" || l["client_state"] != "active" {
		t.Fatalf("registration without approval: %v", l)
	}
	r := put(free, with(map[string]any{"client_name": "Free app (new brand)", "logo_uri": "https://dcr.test/free-logo.png"}))
	if r.Str("proudauth_approval_state") != "approved" || r.Str("proudauth_client_state") != "active" {
		t.Fatalf("a realm without approval re-queued a change: %s", r.Raw)
	}
	mustBeActive(free, "changed client without approval")
	if m := lastUpdate(free); m["requeued"] != false || m["changes"].(map[string]any)["client_name"] == nil {
		t.Fatalf("audit record without approval: %v", m)
	}
}
