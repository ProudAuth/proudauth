package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/organization"
)

// fedSignIn runs one federated sign-in through the named connection for the
// upstream user described by claims and returns the transaction state after
// the callback.
func fedSignIn(t *testing.T, f *Fixture, idp *fakeIdP, provider string, claims map[string]any) *Resp {
	t.Helper()
	h := f.H
	idp.next = claims
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	txID := start.Str("transaction_id")
	st := h.Step(txID, cont, "federation/start", map[string]any{"provider": provider})
	mustStatus(t, st, 200, "federation start")
	mustStatus(t, h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}), 200, "callback")
	return h.Step(txID, cont, "resume", nil)
}

// fedEmailHolders reports who holds an email address and whether it is
// verified there, plus the holder's required actions.
type fedEmailHolder struct {
	userID   string
	verified bool
	actions  []string
}

func fedEmailHolders(t *testing.T, f *Fixture, email string) []fedEmailHolder {
	t.Helper()
	rows, err := f.H.App.D.DB.Pool.Query(context.Background(), `SELECT i.user_id, i.verified_at IS NOT NULL, u.required_actions
		FROM user_identifiers i JOIN users u ON u.id = i.user_id WHERE i.type='email' AND i.canonical_value=$1 ORDER BY i.created_at`, email)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []fedEmailHolder
	for rows.Next() {
		var h fedEmailHolder
		if err := rows.Scan(&h.userID, &h.verified, &h.actions); err != nil {
			t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

// fedLinkedUser returns the account an upstream subject is linked to.
func fedLinkedUser(t *testing.T, f *Fixture, providerID, subject string) string {
	t.Helper()
	var uid string
	_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT user_id FROM external_identities WHERE provider_id=$1 AND upstream_subject=$2`,
		providerID, subject).Scan(&uid)
	return uid
}

// TestOrganizationJITEmailVerification covers REG-009, TEN-007, TEN-010 and
// FED-004: an organization's connection vouches for email addresses only in
// that organization's verified domains. A just-in-time account whose upstream
// asserts a verified address in another organization's domain (or a public
// one) keeps the address unverified behind verify_email, so it neither blocks
// nor impersonates the address's owner, and the other organization's SCIM
// connector does not adopt it.
func TestOrganizationJITEmailVerification(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	gapVerifyDomain(f, f.Acme, "acme.test")
	gapVerifyDomain(f, f.Globex, "globex.test")

	// An Acme-scoped JIT connection that admits every domain, as earlier
	// alphas let an organization owner save (a realm administrator still can).
	conn := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "acme-sso", "display_name": "Acme SSO", "issuer": idp.srv.URL,
		"client_secret": "upstream-secret", "config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true,
		"organization_id": f.Acme}), 201, "acme connection")

	// Acme's upstream asserts a verified address in Globex's verified domain.
	st := fedSignIn(t, f, idp, "acme-sso", map[string]any{"sub": "u-mallory", "email": "victim@globex.test", "email_verified": true})
	mallory := fedLinkedUser(t, f, conn.Str("id"), "u-mallory")
	if mallory == "" {
		t.Fatalf("JIT account not created: %s", st.Raw)
	}
	holders := fedEmailHolders(t, f, "victim@globex.test")
	if len(holders) != 1 || holders[0].userID != mallory || holders[0].verified || !has(holders[0].actions, "verify_email") {
		t.Fatalf("another organization's domain verified through Acme's connection: %+v", holders)
	}
	if st.Str("redirect_to") != "" || !has(actionTypes(st), "verify_email") {
		t.Fatalf("JIT account signed in without proving the address: %s", st.Raw)
	}
	// A public domain nobody verified is not vouched for either.
	fedSignIn(t, f, idp, "acme-sso", map[string]any{"sub": "u-public", "email": "someone@public.test", "email_verified": true})
	if hs := fedEmailHolders(t, f, "someone@public.test"); len(hs) != 1 || hs[0].verified || !has(hs[0].actions, "verify_email") {
		t.Fatalf("public domain verified through an organization's connection: %+v", hs)
	}
	// Inside Acme's own verified domain the upstream assertion stands.
	ok := fedSignIn(t, f, idp, "acme-sso", map[string]any{"sub": "u-dev", "email": "dev@acme.test", "email_verified": true})
	if hs := fedEmailHolders(t, f, "dev@acme.test"); len(hs) != 1 || !hs[0].verified || has(hs[0].actions, "verify_email") {
		t.Fatalf("Acme's own domain not verified: %+v", hs)
	}
	if ok.Str("redirect_to") == "" {
		t.Fatalf("JIT sign-in in a verified domain: %s", ok.Raw)
	}

	// Globex's SCIM connector does not adopt the account Acme's upstream made.
	viewer := f.Roles["orders-viewer"]
	created := f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/provisioning-connectors", map[string]any{"name": "Okta",
		"role_ceiling_ids": []string{viewer}, "default_role_id": viewer}), 201, "globex connector")
	scim := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/scim/v2/Users", Headers: map[string]string{"Authorization": "Bearer " + created.Str("token")},
		JSON: map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "victim@globex.test",
			"emails": []map[string]any{{"value": "victim@globex.test", "primary": true}}, "active": true}})
	if scim.Status == 201 && scim.Str("id") == mallory {
		t.Fatalf("Globex's SCIM connector adopted the account Acme's upstream created: %s", scim.Raw)
	}
	var inGlobex bool
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`,
		f.Globex, mallory).Scan(&inGlobex)
	if inGlobex {
		t.Fatal("the JIT account joined Globex through SCIM")
	}

	// The upgrade runbook's query finds accounts earlier releases created
	// this way (simulated here by verifying the address as they did) and
	// nothing the connection's own domain vouches for.
	ctx := context.Background()
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE user_identifiers SET verified_at=now(), verification_source='federation:acme-sso'
		WHERE user_id=$1 AND type='email'`, mallory); err != nil {
		t.Fatal(err)
	}
	rows, err := h.App.D.DB.Pool.Query(ctx, incidentQuery(t, "## Federation-created verified addresses outside an organization's domains"))
	if err != nil {
		t.Fatalf("runbook query: %v", err)
	}
	defer rows.Close()
	var listed []string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, fmt.Sprint(vals[3], " ", vals[4], " ", vals[6]))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := mallory + " victim@globex.test " + f.Globex; len(listed) != 1 || listed[0] != want {
		t.Fatalf("runbook query listed %q, want [%s]", listed, want)
	}
}

// incidentQuery returns the first SQL block of a section of the incident
// runbooks, so the documented query is the one tested.
func incidentQuery(t *testing.T, heading string) string {
	t.Helper()
	doc, err := os.ReadFile("../../docs/operations/incidents.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "\n"+heading+"\n")
	if !ok {
		t.Fatalf("incidents.md has no section %q", heading)
	}
	_, block, ok := strings.Cut(section, "```sql\n")
	if !ok {
		t.Fatalf("section %q has no SQL block", heading)
	}
	q, _, _ := strings.Cut(block, "```")
	return q
}

// TestOrganizationJITConnectionDomains covers TEN-007 and REG-009: an
// organization administrator enables just-in-time provisioning only for a
// non-empty list of the organization's own verified domains.
func TestOrganizationJITConnectionDomains(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	gapVerifyDomain(f, f.Acme, "acme.test")
	gapVerifyDomain(f, f.Globex, "globex.test")
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token") // Acme owner with an MFA session
	base := "/organizations/" + f.Acme + "/identity-providers"
	conn := func(alias string, domains []string) map[string]any {
		cfg := map[string]any{"client_id": "acme"}
		if domains != nil {
			cfg["allowed_email_domains"] = domains
		}
		return map[string]any{"alias": alias, "display_name": "Acme", "issuer": idp.srv.URL, "config": cfg, "jit_provisioning": true}
	}
	for name, domains := range map[string][]string{
		"no domain list":            nil,
		"another tenant's domain":   {"globex.test"},
		"a public domain":           {"gmail.com"},
		"one foreign among its own": {"acme.test", "globex.test"},
	} {
		r := h.API("POST", base, alice, conn("acme-jit", domains))
		if r.Status != 422 || r.Str("code") != "validation_failed" || !strings.Contains(string(r.Raw), "config.allowed_email_domains") {
			t.Fatalf("JIT connection with %s: %d %s", name, r.Status, r.Raw)
		}
	}
	ok := h.API("POST", base, alice, conn("acme-jit", []string{"ACME.test"}))
	mustStatus(t, ok, 201, "JIT connection for the organization's verified domain")
	// Without JIT the connection needs no domain list.
	plain := h.API("POST", base, alice, map[string]any{"alias": "acme-plain", "display_name": "Acme", "issuer": idp.srv.URL,
		"config": map[string]any{"client_id": "acme"}})
	mustStatus(t, plain, 201, "connection without JIT")
	// Turning JIT on later is held to the same rule.
	cur := h.API("GET", base+"/"+plain.Str("id"), alice, nil)
	upd := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + base + "/" + plain.Str("id"), Token: alice,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: conn("acme-plain", nil)})
	if upd.Status != 422 || !strings.Contains(string(upd.Raw), "config.allowed_email_domains") {
		t.Fatalf("JIT enabled on update without domains: %d %s", upd.Status, upd.Raw)
	}
}

// TestGoogleAdapterEmailAuthority covers FED-002 and FED-004 end to end:
// a Google ID token's email_verified is believed only for Gmail addresses or
// when its hd claim names the address's domain, so a consumer Google account
// holding a corporate address never links to (or verifies) that address,
// even on a trusted_verified_email connection without allowed_tenants.
func TestGoogleAdapterEmailAuthority(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	const google = "https://accounts.google.com"
	g := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "google", "display_name": "Google", "adapter": "google",
		"client_secret": "upstream-secret", "linking_policy": "trusted_verified_email", "jit_provisioning": true,
		"config": map[string]any{"client_id": "proudauth-main", "allowed_email_domains": []string{"example.test", "gmail.com"},
			"authorization_endpoint": idp.srv.URL + "/authorize", "token_endpoint": idp.srv.URL + "/token", "jwks_uri": idp.srv.URL + "/jwks"}}),
		201, "google connection")
	gid := g.Str("id")

	// A Google account without hd asserting alice's corporate address.
	fedSignIn(t, f, idp, "google", map[string]any{"iss": google, "sub": "g-consumer", "email": "alice@example.test", "email_verified": true})
	if uid := fedLinkedUser(t, f, gid, "g-consumer"); uid == "" || uid == f.Users["alice"] {
		t.Fatalf("a consumer Google account linked to alice through an address Google does not own: %q", uid)
	}
	if hs := fedEmailHolders(t, f, "alice@example.test"); len(hs) != 1 || hs[0].userID != f.Users["alice"] {
		t.Fatalf("alice's address copied: %+v", hs)
	}
	// hd naming another domain is no better.
	fedSignIn(t, f, idp, "google", map[string]any{"iss": google, "sub": "g-other-hd", "hd": "other.test", "email": "alice@example.test", "email_verified": true})
	if uid := fedLinkedUser(t, f, gid, "g-other-hd"); uid == f.Users["alice"] {
		t.Fatal("a Workspace account of another domain linked to alice")
	}
	// The Workspace that runs example.test is authoritative for it.
	fedSignIn(t, f, idp, "google", map[string]any{"iss": google, "sub": "g-workspace", "hd": "Example.test", "email": "alice@example.test", "email_verified": true})
	if uid := fedLinkedUser(t, f, gid, "g-workspace"); uid != f.Users["alice"] {
		t.Fatalf("matching hd not trusted: linked to %q", uid)
	}
	// Google is authoritative for Gmail addresses.
	fedSignIn(t, f, idp, "google", map[string]any{"iss": google, "sub": "g-gmail", "email": "someone@gmail.com", "email_verified": true})
	if hs := fedEmailHolders(t, f, "someone@gmail.com"); len(hs) != 1 || !hs[0].verified {
		t.Fatalf("Gmail address not verified: %+v", hs)
	}
}
