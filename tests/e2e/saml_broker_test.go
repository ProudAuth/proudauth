package e2e

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// TestSAMLBroker covers SAML connections (FED-014, SAML-002..SAML-006,
// SAML-009, TEST-051) against an independent test identity provider: the
// signed AuthnRequest and service provider metadata, the happy path into
// the federation linking/JIT/organization pipeline, every assertion check
// (signature, algorithm floor, issuer, audience, destination, recipient,
// correlation, time and skew), replay, signature wrapping, unsafe XML,
// unsolicited responses and an overlapping certificate rollover.
func TestSAMLBroker(t *testing.T) {
	h := NewHarness(t, samlEnabled)
	f := fixtureOn(t, h)
	h.App.SAMLKeys.RSABits = 2048
	now := h.Clock.Now
	idp := &testIdP{entityID: "https://idp.test/saml", sso: "https://idp.test/sso"}
	k1, k2, rogue := newKeyPair(t, "idp-1", now()), newKeyPair(t, "idp-2", now()), newKeyPair(t, "rogue", now())

	conn := f.must(f.AdminAPI("POST", "/saml/connections", map[string]any{"alias": "corp-saml", "display_name": "Corp SAML",
		"metadata_xml": idp.metadata(k1), "jit_provisioning": true, "email_attribute": "mail", "organization_id": f.Acme,
		"jit_default_role_id": f.Roles["orders-viewer"]}), 201, "create SAML connection")
	connID := conn.Str("id")
	acsURL := h.Realm.Issuer + "/saml/acs/corp-saml"
	if conn.Str("saml.idp_entity_id") != idp.entityID || conn.Str("saml.sso_url") != idp.sso || conn.Str("service_provider.acs_url") != acsURL ||
		conn.Get("saml.sign_authn_requests") != true {
		t.Fatalf("connection: %s", conn.Raw)
	}
	spMD := h.Do(Req{Method: "GET", Path: "/realms/main/saml/sp/corp-saml"})
	mustStatus(t, spMD, 200, "service provider metadata")
	spCerts := metadataCerts(t, spMD.Raw)
	if len(spCerts) != 1 || !strings.Contains(string(spMD.Raw), `Location="`+acsURL+`"`) || !strings.Contains(string(spMD.Raw), `AuthnRequestsSigned="true"`) ||
		strings.Contains(string(spMD.Raw), "SingleLogoutService") {
		t.Fatalf("SP metadata: %s", spMD.Raw)
	}
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	web := LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}, Organization: f.Acme}

	type pendingLogin struct {
		txID, cont, verifier string
		req                  samlRequest
	}
	begin := func(opts LoginOpts, alias string) pendingLogin {
		t.Helper()
		start, verifier, cont := h.StartTx(opts)
		mustStatus(t, start, 201, "start")
		txID := start.Str("transaction_id")
		st := h.Step(txID, cont, "federation/start", map[string]any{"provider": alias})
		mustStatus(t, st, 200, "federation start")
		return pendingLogin{txID: txID, cont: cont, verifier: verifier, req: idp.receive(t, st.Str("external_redirect"), spCerts)}
	}
	good := func(p pendingLogin, sub string) idpResponse {
		return idpResponse{Req: p.req, NameID: sub, Attrs: map[string]string{"mail": sub + "@corp.test", "displayName": "User " + sub},
			Issued: now(), SignAssertion: true, SignResponse: true, Key: k1}
	}
	firstAssertion := xmlID()

	t.Run("signed AuthnRequest and happy path into JIT and organization membership", func(t *testing.T) {
		start, _, _ := h.StartTx(web)
		if !strings.Contains(string(start.Raw), `"alias":"corp-saml"`) {
			t.Fatalf("SAML connection not offered for its organization: %s", start.Raw)
		}
		p := begin(web, "corp-saml")
		if !p.req.Signed || p.req.ACS != acsURL || p.req.Issuer != h.Realm.Issuer+"/saml/sp/corp-saml" || len(p.req.RelayState) < 40 {
			t.Fatalf("AuthnRequest: %+v", p.req)
		}
		resp := good(p, "u-zed")
		resp.AssertionID = firstAssertion
		value := idp.build(t, resp)
		cb := postACS(h, "corp-saml", value, p.req.RelayState)
		mustStatus(t, cb, 200, "ACS")
		if cb.Str("status") != "ok" || cb.Str("transaction_id") != p.txID {
			t.Fatalf("callback: %s", cb.Raw)
		}
		st := h.Step(p.txID, p.cont, "resume", nil)
		u, _ := url.Parse(st.Str("redirect_to"))
		if u.Query().Get("code") == "" {
			t.Fatalf("federated SAML login did not complete: %s", st.Raw)
		}
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {p.verifier},
			"redirect_uri": {webRedirect}, "resource": {f.OrdersAud}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, toks, 200, "token")
		claims := jwtPayload(toks.Str("access_token"))
		if claims["org_id"] != f.Acme || claims["acr"] != "urn:proudauth:acr:federated" {
			t.Fatalf("token: %v", claims)
		}
		users := f.must(f.AdminAPI("GET", "/users?q=u-zed@corp.test", nil), 200, "users")
		if n := len(users.Get("items").([]any)); n != 1 {
			t.Fatalf("expected one JIT account, got %d", n)
		}
		// The same response again: its request is consumed (single use).
		if r := postACS(h, "corp-saml", value, p.req.RelayState); r.Status != 400 {
			t.Fatalf("replayed response accepted: %d %s", r.Status, r.Raw)
		}
	})

	// rejected posts a response for a fresh request and expects the
	// transaction to learn the failure, with no sign-in.
	rejected := func(t *testing.T, mut func(*idpResponse), code string) {
		t.Helper()
		p := begin(acct, "corp-saml")
		r := good(p, "u-eve")
		mut(&r)
		cb := postACS(h, "corp-saml", idp.build(t, r), p.req.RelayState)
		mustStatus(t, cb, 200, "ACS")
		if cb.Str("status") != "error" || cb.Str("error") != code {
			t.Fatalf("expected %s: %s", code, cb.Raw)
		}
		st := h.Step(p.txID, p.cont, "resume", nil)
		if st.Str("redirect_to") != "" || st.Str("notice") != code {
			t.Fatalf("transaction completed after a rejected response: %s", st.Raw)
		}
	}
	invalid := "upstream_invalid_response"

	t.Run("assertion validation (SAML-003, SAML-009)", func(t *testing.T) {
		cases := map[string]func(*idpResponse){
			"unsigned":                     func(r *idpResponse) { r.SignAssertion, r.SignResponse = false, false },
			"untrusted key":                func(r *idpResponse) { r.Key = rogue },
			"SHA-1 signature":              func(r *idpResponse) { r.SHA1 = true },
			"wrong audience":               func(r *idpResponse) { r.Audience = "https://other-sp.test" },
			"wrong destination":            func(r *idpResponse) { r.Destination = "https://other-sp.test/acs" },
			"wrong recipient":              func(r *idpResponse) { r.Recipient = "https://other-sp.test/acs" },
			"InResponseTo mismatch":        func(r *idpResponse) { r.InResponseTo = "_another-request" },
			"expired":                      func(r *idpResponse) { r.Issued = now().Add(-20 * time.Minute) },
			"issued in the future":         func(r *idpResponse) { r.Issued = now().Add(10 * time.Minute) },
			"transient NameID as subject":  func(r *idpResponse) { r.NameIDFormat = fmtT },
			"assertion replayed elsewhere": func(r *idpResponse) { r.AssertionID = firstAssertion },
			"status without a code": func(r *idpResponse) {
				r.SignResponse = false
				r.Mutate = func(resp *etree.Element) {
					st := child(resp, nsP, "Status")
					st.RemoveChild(child(st, nsP, "StatusCode"))
				}
			},
		}
		for name, mut := range cases {
			t.Run(name, func(t *testing.T) { rejected(t, mut, invalid) })
		}
		t.Run("error status", func(t *testing.T) {
			rejected(t, func(r *idpResponse) { r.Status = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, "upstream_denied")
		})
		t.Run("clock skew within tolerance", func(t *testing.T) {
			p := begin(acct, "corp-saml")
			r := good(p, "u-skew")
			r.Issued = now().Add(90 * time.Second) // connection skew: 120s
			cb := postACS(h, "corp-saml", idp.build(t, r), p.req.RelayState)
			if cb.Str("status") != "ok" {
				t.Fatalf("response within the skew refused: %s", cb.Raw)
			}
		})
		t.Run("repeated attribute elements (Keycloak role list)", func(t *testing.T) {
			// Keycloak's default SAML client scope role_list sends one
			// Attribute element per role; such a response used to be
			// refused as a whole (duplicate_attribute), so no Keycloak user
			// with roles could sign in (scripts/interop-keycloak.sh).
			signIn := func(sub string, extra [][2]string) map[string]any {
				t.Helper()
				p := begin(acct, "corp-saml")
				r := good(p, sub)
				r.ExtraAttrs = extra
				cb := postACS(h, "corp-saml", idp.build(t, r), p.req.RelayState)
				if cb.Str("status") != "ok" {
					t.Fatalf("response with repeated attribute elements refused: %s", cb.Raw)
				}
				if st := h.Step(p.txID, p.cont, "resume", nil); st.Str("redirect_to") == "" {
					t.Fatalf("sign-in with repeated attribute elements did not complete: %s", st.Raw)
				}
				users := f.must(f.AdminAPI("GET", "/users?q="+sub+"@corp.test", nil), 200, "users")
				items := users.Get("items").([]any)
				if len(items) != 1 {
					t.Fatalf("expected one JIT account: %s", users.Raw)
				}
				return items[0].(map[string]any)
			}
			if u := signIn("u-roles", [][2]string{{"Role", "chemist"}, {"Role", "reviewer"}}); u["display_name"] != "User u-roles" {
				t.Fatalf("single-valued displayName not mapped next to repeated Role elements: %v", u)
			}
			// displayName arriving twice is multi-valued: it does not fill
			// the single-valued profile field.
			if u := signIn("u-roles-2", [][2]string{{"displayName", "Second Name"}}); u["display_name"] == "Second Name" || u["display_name"] == "User u-roles-2" {
				t.Fatalf("ambiguous displayName mapped to the profile: %v", u)
			}
			// The email attribute (email_attribute "mail") identifies the
			// user: repeated, it is ambiguous and refuses the response.
			rejected(t, func(r *idpResponse) { r.ExtraAttrs = [][2]string{{"mail", "u-victim@corp.test"}} }, invalid)
			ev := f.must(f.AdminAPI("GET", "/audit-events?type=saml.response.rejected", nil), 200, "audit")
			if !strings.Contains(string(ev.Raw), `"duplicate_attribute"`) {
				t.Fatalf("repeated email attribute not audited as duplicate_attribute: %s", ev.Raw)
			}
		})
		t.Run("response signature alone covers the assertion", func(t *testing.T) {
			p := begin(acct, "corp-saml")
			r := good(p, "u-resp-only")
			r.SignAssertion = false
			if cb := postACS(h, "corp-saml", idp.build(t, r), p.req.RelayState); cb.Str("status") != "ok" {
				t.Fatalf("signed response refused: %s", cb.Raw)
			}
		})
	})

	t.Run("signature wrapping (SAML-004)", func(t *testing.T) {
		// An unsigned assertion for another user next to the signed one.
		rejected(t, func(r *idpResponse) {
			r.SignResponse = false
			r.Mutate = func(resp *etree.Element) {
				signed := child(resp, nsA, "Assertion")
				evil := signed.Copy()
				evil.RemoveChild(child(evil, nsDS, "Signature"))
				evil.CreateAttr("ID", xmlID())
				child(child(evil, nsA, "Subject"), nsA, "NameID").SetText("u-victim")
				resp.InsertChildAt(signed.Index(), evil)
			}
		}, invalid)
		// An extra unsigned assertion after the signed one: refused outright
		// (exactly one assertion), not resolved by picking one of them.
		rejected(t, func(r *idpResponse) {
			r.SignResponse = false
			r.Mutate = func(resp *etree.Element) {
				evil := child(resp, nsA, "Assertion").Copy()
				evil.RemoveChild(child(evil, nsDS, "Signature"))
				evil.CreateAttr("ID", xmlID())
				child(child(evil, nsA, "Subject"), nsA, "NameID").SetText("u-victim")
				resp.AddChild(evil)
			}
		}, invalid)
		// The signed assertion hidden in Extensions, an unsigned one in its place.
		rejected(t, func(r *idpResponse) {
			r.SignResponse = false
			r.Mutate = func(resp *etree.Element) {
				signed := child(resp, nsA, "Assertion")
				resp.RemoveChild(signed)
				evil := signed.Copy()
				evil.RemoveChild(child(evil, nsDS, "Signature"))
				child(child(evil, nsA, "Subject"), nsA, "NameID").SetText("u-victim")
				ext := etree.NewElement("samlp:Extensions")
				ext.AddChild(signed)
				resp.InsertChildAt(1, ext)
				evil.CreateAttr("ID", xmlID())
				resp.AddChild(evil)
			}
		}, invalid)
		// A signed response whose assertion is then swapped for another.
		rejected(t, func(r *idpResponse) {
			r.SignAssertion = false
			r.Mutate = func(resp *etree.Element) {
				child(child(child(resp, nsA, "Assertion"), nsA, "Subject"), nsA, "NameID").SetText("u-victim")
			}
		}, invalid)
		// An encrypted assertion is not accepted (not implemented, APP-020).
		rejected(t, func(r *idpResponse) {
			r.SignResponse = false
			r.Mutate = func(resp *etree.Element) { resp.AddChild(etree.NewElement("saml:EncryptedAssertion")) }
		}, invalid)
	})

	t.Run("local refusals before any transaction is touched", func(t *testing.T) {
		p := begin(acct, "corp-saml")
		r := good(p, "u-local")
		expect := func(value, relay, what string) {
			t.Helper()
			if cb := postACS(h, "corp-saml", value, relay); cb.Status != 400 && cb.Status != 413 {
				t.Fatalf("%s: %d %s", what, cb.Status, cb.Raw)
			}
		}
		unsolicited := r
		unsolicited.NoResponseIRT = true
		expect(idp.build(t, unsolicited), p.req.RelayState, "unsolicited response (SAML-007)")
		expect(idp.build(t, r), "wrong-relay-state", "wrong RelayState")
		xxe := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="` + nsP +
			`" ID="_r" Version="2.0" InResponseTo="` + p.req.ID + `"><samlp:Status>&x;</samlp:Status></samlp:Response>`
		expect(base64.StdEncoding.EncodeToString([]byte(xxe)), p.req.RelayState, "DTD and external entity")
		dup := r
		dup.Mutate = func(resp *etree.Element) {
			child(resp, nsA, "Assertion").CreateAttr("ID", resp.SelectAttrValue("ID", ""))
		}
		expect(idp.build(t, dup), p.req.RelayState, "duplicate IDs")
		raw, _ := base64.StdEncoding.DecodeString(idp.build(t, r))
		commented := strings.Replace(string(raw), "u-local</saml:NameID>", "u-lo<!-- x -->cal</saml:NameID>", 1)
		expect(base64.StdEncoding.EncodeToString([]byte(commented)), p.req.RelayState, "comment inside NameID")
		expect(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 600<<10))), p.req.RelayState, "oversized response")
		// The genuine response still completes: none of the above consumed it.
		if cb := postACS(h, "corp-saml", idp.build(t, r), p.req.RelayState); cb.Str("status") != "ok" {
			t.Fatalf("pending request lost to refused responses: %s", cb.Raw)
		}
		var rejections int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type='saml.response.rejected'`).Scan(&rejections)
		if rejections < 5 {
			t.Fatalf("rejections not recorded as evidence: %d", rejections)
		}
	})

	put := func(body map[string]any) *Resp {
		t.Helper()
		cur := f.must(f.AdminAPI("GET", "/saml/connections/"+connID, nil), 200, "get connection")
		return h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/saml/connections/" + connID, Token: f.AdminToken, JSON: body,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
	}
	base := map[string]any{"display_name": "Corp SAML", "idp_entity_id": idp.entityID, "sso_url": idp.sso, "jit_provisioning": true,
		"email_attribute": "mail", "organization_id": f.Acme, "jit_default_role_id": f.Roles["orders-viewer"]}

	t.Run("certificate rollover with overlap (SAML-002)", func(t *testing.T) {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body["signing_certificates"] = []string{k1.pem(), k2.pem()}
		f.must(put(body), 200, "add the next certificate")
		for i, k := range []keyPair{k1, k2} {
			p := begin(acct, "corp-saml")
			r := good(p, "u-roll")
			r.Key = k
			if cb := postACS(h, "corp-saml", idp.build(t, r), p.req.RelayState); cb.Str("status") != "ok" {
				t.Fatalf("key %d refused during the overlap: %s", i+1, cb.Raw)
			}
		}
		body["signing_certificates"] = []string{k2.pem()}
		f.must(put(body), 200, "retire the old certificate")
		rejected(t, func(r *idpResponse) { r.Key = k1 }, invalid)
		var audited int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type='federation.provider.updated'
			AND metadata->'signing_certificates_removed' ? $1`, certFingerprint(k1.cert)).Scan(&audited)
		if audited != 1 {
			t.Fatalf("certificate removal not audited: %d", audited)
		}
		k1 = k2
		body["require_signed_assertions"] = true
		f.must(put(body), 200, "require signed assertions")
		rejected(t, func(r *idpResponse) { r.SignAssertion = false }, invalid)
	})

	t.Run("trusted email linking (FED-004)", func(t *testing.T) {
		f.must(f.AdminAPI("POST", "/saml/connections", map[string]any{"alias": "partner-saml", "display_name": "Partner SAML",
			"idp_entity_id": idp.entityID, "sso_url": idp.sso, "signing_certificates": []string{k2.pem()}, "email_attribute": "mail",
			"linking_policy": "trusted_verified_email", "trust_email_verified": true, "allowed_email_domains": []string{"example.test"}}), 201, "partner")
		p := begin(acct, "partner-saml")
		r := good(p, "alice-upstream")
		r.Key = k2
		r.Attrs["mail"] = "alice@example.test"
		cb := postACS(h, "partner-saml", idp.build(t, r), p.req.RelayState)
		if cb.Str("status") != "ok" {
			t.Fatalf("link: %s", cb.Raw)
		}
		st := h.Step(p.txID, p.cont, "resume", nil)
		u, _ := url.Parse(st.Str("redirect_to"))
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {p.verifier},
			"redirect_uri": {"http://127.0.0.1/callback"}, "resource": {h.Realm.Issuer + "/account"}}, "proudauth-cli", "")
		mustStatus(t, toks, 200, "token")
		if sub := jwtPayload(toks.Str("access_token"))["sub"]; sub != f.Users["alice"] {
			t.Fatalf("trusted email did not link to the existing account: %v", sub)
		}
		// Without the explicit trust decision, the same email links nothing.
		bad := f.AdminAPI("POST", "/saml/connections", map[string]any{"alias": "loose-saml", "display_name": "Loose", "idp_entity_id": idp.entityID,
			"sso_url": idp.sso, "signing_certificates": []string{k2.pem()}, "linking_policy": "trusted_verified_email",
			"allowed_email_domains": []string{"example.test"}})
		if bad.Status != 422 {
			t.Fatalf("trusted linking without trust_email_verified: %d %s", bad.Status, bad.Raw)
		}
	})

	t.Run("self-service linking through a SAML connection (USR-010)", func(t *testing.T) {
		tok := f.AccountToken("bob").Tokens.Str("access_token")
		start := f.must(h.API("POST", "/me/linked-identities", tok, map[string]any{"provider": "partner-saml"}), 200, "start link")
		req := idp.receive(t, start.Str("authorization_url"), spCerts)
		r := idpResponse{Req: req, NameID: "bob-upstream", Attrs: map[string]string{"mail": "bob@example.test"}, Issued: now(),
			SignAssertion: true, Key: k2}
		cb := postACS(h, "partner-saml", idp.build(t, r), req.RelayState)
		if cb.Str("status") != "link_pending_confirmation" || cb.Str("link_code") == "" {
			t.Fatalf("link callback: %s", cb.Raw)
		}
		f.must(h.API("POST", "/me/linked-identities/confirm", tok, map[string]any{"code": cb.Str("link_code")}), 201, "confirm link")
		linked := f.must(h.API("GET", "/me/linked-identities", tok, nil), 200, "linked identities")
		if !strings.Contains(string(linked.Raw), `"provider":"partner-saml"`) {
			t.Fatalf("link missing: %s", linked.Raw)
		}
	})

	t.Run("connection administration guards", func(t *testing.T) {
		list := f.must(f.AdminAPI("GET", "/identity-providers", nil), 200, "identity providers")
		if !strings.Contains(string(list.Raw), `"kind":"saml"`) {
			t.Fatalf("SAML connections not listed with the realm's connections: %s", list.Raw)
		}
		cur := f.must(f.AdminAPI("GET", "/identity-providers/"+connID, nil), 200, "generic view")
		r := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + connID, Token: f.AdminToken,
			JSON:    map[string]any{"display_name": "x", "issuer": "https://x.test", "config": map[string]any{"client_id": "x"}},
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
		if r.Status != 409 {
			t.Fatalf("SAML connection rewritten as OIDC: %d %s", r.Status, r.Raw)
		}
		if r := f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "sneaky", "display_name": "x", "adapter": "saml",
			"issuer": "https://x.test", "config": map[string]any{"client_id": "x"}}); r.Status != 422 {
			t.Fatalf("SAML created through the OIDC API: %d %s", r.Status, r.Raw)
		}
		weak := f.AdminAPI("POST", "/saml/connections", map[string]any{"alias": "weak", "display_name": "Weak", "idp_entity_id": idp.entityID,
			"sso_url": idp.sso, "signing_certificates": []string{}})
		if weak.Status != 422 {
			t.Fatalf("connection without a trusted key: %d %s", weak.Status, weak.Raw)
		}
		diag := f.must(f.AdminAPI("POST", "/identity-providers/"+connID+"/test", nil), 200, "diagnostics")
		if diag.Get("ok") != true || diag.Get("signing_keys").(float64) != 1 {
			t.Fatalf("diagnostics: %s", diag.Raw)
		}
	})
}

func certFingerprint(c *x509.Certificate) string {
	b := make([]byte, 0, 64)
	for _, v := range sha256Sum(c.Raw) {
		b = append(b, "0123456789abcdef"[v>>4], "0123456789abcdef"[v&15])
	}
	return string(b)
}
