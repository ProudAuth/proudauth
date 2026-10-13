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

	"github.com/proudbase/proudauth/internal/realm"
)

const (
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	statusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// post submits a form from the browser.
func (b *browser) post(path string, form url.Values) *Resp {
	saved := b.h.HTTP
	b.h.HTTP = b.client
	defer func() { b.h.HTTP = saved }()
	return b.h.Do(Req{Method: "POST", Path: path, Form: form})
}

// drive completes a browser transaction like a login interface would:
// cookie continuation, CSRF token and an allowed Origin (SEC-002).
func (b *browser) drive(t *testing.T, txID, identifier string) *Resp {
	t.Helper()
	h := b.h
	base := "/api/v1/realms/main/auth/transactions/" + txID
	st := b.do("GET", base, nil, nil)
	mustStatus(t, st, 200, "view transaction")
	hdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": st.Str("csrf_token")}
	for i := 0; i < 12; i++ {
		if st.Status != 200 || st.Str("status") != "pending" || st.Str("redirect_to") != "" {
			return st
		}
		types := map[string]bool{}
		for _, a := range st.Get("next_actions").([]any) {
			types[a.(map[string]any)["type"].(string)] = true
		}
		switch {
		case types["identify"]:
			st = b.do("POST", base+"/identify", map[string]any{"identifier": identifier}, hdr)
		case types["password"]:
			st = b.do("POST", base+"/password", map[string]any{"password": h.passwords[identifier]}, hdr)
		case types["enroll_totp"]:
			en := b.do("POST", base+"/totp/enroll", map[string]any{}, hdr)
			mustStatus(t, en, 200, "enroll totp")
			h.seeds[identifier] = en.Str("one_time.totp.secret")
			st = b.do("POST", base+"/totp/activate", map[string]any{"code": h.TOTPNow(identifier)}, hdr)
		case types["totp"]:
			st = b.do("POST", base+"/totp", map[string]any{"code": h.TOTPNow(identifier)}, hdr)
		case types["consent"]:
			st = b.do("POST", base+"/consent", map[string]any{"approve": true}, hdr)
		default:
			return st
		}
	}
	return st
}

// TestSAMLIdentityProvider covers the outbound profile (APP-018,
// SAML-001..SAML-009, TEST-051): registration, SP-initiated SSO over both
// bindings with a reused session, ForceAuthn and IsPassive, request
// validation, browser binding, IdP-initiated policy, NameID and attribute
// rules, consent and organization binding, assurance requests and logout.
func TestSAMLIdentityProvider(t *testing.T) {
	h := NewHarness(t, samlEnabled)
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h.App.SAMLKeys.RSABits = 2048
	now := h.Clock.Now
	ssoURL := h.Realm.Issuer + "/saml/sso"
	sp := &testSP{entityID: "https://sp.test/metadata", acs: "https://sp.test/acs", slo: "https://sp.test/slo", kp: newKeyPair(t, "sp", now())}
	appBody := map[string]any{"entity_id": sp.entityID, "name": "Test SP", "first_party": true,
		"assertion_consumer_services": []map[string]any{{"url": sp.acs}},
		"single_logout_services":      []map[string]any{{"url": sp.slo, "binding": bindingRedirect}},
		"signing_certificates":        []string{sp.kp.pem()},
		"attributes": []map[string]any{{"name": "mail", "source": "email"}, {"name": "displayName", "source": "name"},
			{"name": "tier", "source": "static", "value": "gold"}}}
	app := f.must(f.AdminAPI("POST", "/saml/applications", appBody), 201, "create SAML application")
	appID := app.Str("id")
	if app.Str("client_ref") == "" || app.Str("identity_provider.entity_id") != h.Realm.Issuer || app.Get("require_signed_requests") != true {
		t.Fatalf("application: %s", app.Raw)
	}
	md := h.Do(Req{Method: "GET", Path: "/realms/main/saml/metadata"})
	mustStatus(t, md, 200, "IdP metadata")
	certs := metadataCerts(t, md.Raw)
	if len(certs) != 1 || !strings.Contains(string(md.Raw), `entityID="`+h.Realm.Issuer+`"`) {
		t.Fatalf("metadata: %s", md.Raw)
	}
	idpCert := certs[0]

	sso := func(b *browser, mutate func(*etree.Element), alg string) (*Resp, string) {
		t.Helper()
		id := xmlID()
		q := redirectQuery(t, "SAMLRequest", serialize(t, sp.authnRequest(id, ssoURL, now(), mutate)), "relay-1", sp.kp, alg)
		return b.do("GET", "/realms/main/saml/sso?"+q, nil, nil), id
	}
	login := func(b *browser, r *Resp, user string) *Resp {
		t.Helper()
		mustStatus(t, r, 302, "SSO redirect to the login interface")
		loc, _ := url.Parse(r.Header.Get("Location"))
		if loc.Host != "login.test" || loc.Query().Get("transaction_id") == "" {
			t.Fatalf("expected the login interface: %s", loc)
		}
		st := b.drive(t, loc.Query().Get("transaction_id"), user)
		if st.Str("redirect_to") == "" {
			t.Fatalf("sign-in did not complete: %d %s", st.Status, st.Raw)
		}
		return b.do("GET", st.Str("redirect_to"), nil, nil)
	}

	alice := newBrowser(h)
	var alicePersistent, aliceIndex string
	t.Run("SP-initiated SSO over HTTP-Redirect", func(t *testing.T) {
		r, id := sso(alice, nil, rsa256)
		form := parseForm(t, login(alice, r, "alice@example.test"))
		res := sp.check(t, form, idpCert, now(), id)
		if res.Status != statusSuccess || form.RelayState != "relay-1" || res.NameFormat != fmtP || !strings.HasPrefix(res.NameID, "sps_") {
			t.Fatalf("response: %+v relay=%q", res, form.RelayState)
		}
		if res.Attrs["mail"] != "alice@example.test" || res.Attrs["displayName"] != "alice" || res.Attrs["tier"] != "gold" || res.SessionIdx == "" {
			t.Fatalf("attributes: %v", res.Attrs)
		}
		if res.ClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" {
			t.Fatalf("authn context %q", res.ClassRef)
		}
		alicePersistent, aliceIndex = res.NameID, res.SessionIdx
	})

	t.Run("SSO session reuse and ForceAuthn", func(t *testing.T) {
		r, id := sso(alice, nil, rsa256)
		res := sp.check(t, parseForm(t, r), idpCert, now(), id)
		if res.NameID != alicePersistent || res.SessionIdx != aliceIndex {
			t.Fatalf("persistent identifier or session index changed: %+v", res)
		}
		forced, _ := sso(alice, func(e *etree.Element) { e.CreateAttr("ForceAuthn", "true") }, rsa256)
		mustStatus(t, forced, 302, "ForceAuthn shows the login interface")
	})

	t.Run("IsPassive without a session answers NoPassive", func(t *testing.T) {
		r, id := sso(newBrowser(h), func(e *etree.Element) { e.CreateAttr("IsPassive", "true") }, rsa256)
		res := sp.check(t, parseForm(t, r), idpCert, now(), id)
		if res.Status != "urn:oasis:names:tc:SAML:2.0:status:Responder" || res.SubStatus != "urn:oasis:names:tc:SAML:2.0:status:NoPassive" || res.Assertion != nil {
			t.Fatalf("passive response: %+v", res)
		}
	})

	t.Run("HTTP-POST binding with an enveloped signature", func(t *testing.T) {
		b := newBrowser(h)
		id := xmlID()
		req := sp.authnRequest(id, ssoURL, now(), nil)
		sign(t, req, sp.kp, false)
		r := b.post("/realms/main/saml/sso", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(serialize(t, req))}, "RelayState": {"rs-post"}})
		mustStatus(t, r, 303, "POST binding continues by GET")
		cont := b.do("GET", r.Header.Get("Location"), nil, nil)
		form := parseForm(t, login(b, cont, "bob@example.test"))
		res := sp.check(t, form, idpCert, now(), id)
		if res.Status != statusSuccess || form.RelayState != "rs-post" || res.Attrs["mail"] != "bob@example.test" {
			t.Fatalf("POST binding: %+v", res)
		}
		if res.NameID == alicePersistent {
			t.Fatal("persistent identifiers collide between accounts")
		}
	})

	t.Run("request validation", func(t *testing.T) {
		b := newBrowser(h)
		rogue := newKeyPair(t, "rogue", now())
		expect := func(r *Resp, reason, what string) {
			t.Helper()
			if r.Status != 400 || (reason != "" && r.Str("reason") != reason) || r.Header.Get("Location") != "" {
				t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
			}
		}
		r, _ := sso(b, nil, "")
		expect(r, "saml_signature", "unsigned request")
		r, _ = sso(b, nil, rsa1)
		expect(r, "saml_signature", "SHA-1 request signature (SAML-009)")
		q := redirectQuery(t, "SAMLRequest", serialize(t, sp.authnRequest(xmlID(), ssoURL, now(), nil)), "", rogue, rsa256)
		expect(b.do("GET", "/realms/main/saml/sso?"+q, nil, nil), "saml_signature", "request signed by another key")
		r, _ = sso(b, func(e *etree.Element) { e.CreateAttr("AssertionConsumerServiceURL", "https://evil.test/acs") }, rsa256)
		expect(r, "saml_unregistered_acs", "unregistered ACS")
		r, _ = sso(b, func(e *etree.Element) {
			e.RemoveChildAt(0)
			iss := etree.NewElement("saml:Issuer")
			iss.SetText("https://unknown.test")
			e.InsertChildAt(0, iss)
		}, rsa256)
		expect(r, "saml_unknown_service_provider", "unknown service provider")
		r, _ = sso(b, func(e *etree.Element) { e.CreateAttr("Destination", "https://elsewhere.test/sso") }, rsa256)
		expect(r, "saml_invalid_request", "wrong destination")
		r, _ = sso(b, func(e *etree.Element) { e.CreateAttr("IssueInstant", xmlTime(now().Add(-time.Hour))) }, rsa256)
		expect(r, "saml_invalid_request", "stale request")
		q = redirectQuery(t, "SAMLRequest", serialize(t, sp.authnRequest(xmlID(), ssoURL, now(), nil)), "", sp.kp, rsa256)
		mustStatus(t, b.do("GET", "/realms/main/saml/sso?"+q, nil, nil), 302, "first use")
		expect(b.do("GET", "/realms/main/saml/sso?"+q, nil, nil), "saml_request_replay", "replayed request")
		xxe := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` +
			`<samlp:AuthnRequest xmlns:samlp="` + nsP + `" xmlns:saml="` + nsA + `" ID="_x" Version="2.0" IssueInstant="` + xmlTime(now()) +
			`"><saml:Issuer>` + sp.entityID + `</saml:Issuer><saml:Subject>&x;</saml:Subject></samlp:AuthnRequest>`
		q = redirectQuery(t, "SAMLRequest", []byte(xxe), "", sp.kp, rsa256)
		expect(b.do("GET", "/realms/main/saml/sso?"+q, nil, nil), "saml_invalid_request", "DTD and external entity")
		// A request the IdP cannot honor goes back to the validated ACS.
		r, id := sso(b, func(e *etree.Element) {
			p := e.CreateElement("samlp:NameIDPolicy")
			p.CreateAttr("Format", fmtT)
		}, rsa256)
		res := sp.check(t, parseForm(t, r), idpCert, now(), id)
		if res.SubStatus != "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy" || res.Assertion != nil {
			t.Fatalf("unsupported NameID policy: %+v", res)
		}
	})

	t.Run("continuation is bound to the requesting browser", func(t *testing.T) {
		b := newBrowser(h)
		r, id := sso(b, nil, rsa256)
		mustStatus(t, r, 302, "sso")
		loc, _ := url.Parse(r.Header.Get("Location"))
		st := b.drive(t, loc.Query().Get("transaction_id"), "carol@example.test")
		next := st.Str("redirect_to")
		if !strings.HasPrefix(next, h.Realm.Issuer+"/saml/sso/continue?") {
			t.Fatalf("completion: %s", st.Raw)
		}
		if other := newBrowser(h).do("GET", next, nil, nil); other.Status != 400 {
			t.Fatalf("another browser received the assertion: %d %s", other.Status, other.Raw)
		}
		res := sp.check(t, parseForm(t, b.do("GET", next, nil, nil)), idpCert, now(), id)
		if res.Attrs["mail"] != "carol@example.test" {
			t.Fatalf("carol: %+v", res)
		}
		if again := b.do("GET", next, nil, nil); again.Status != 400 {
			t.Fatalf("continuation replayed: %d", again.Status)
		}
	})

	t.Run("IdP-initiated sign-in is refused unless enabled (SAML-007)", func(t *testing.T) {
		r := alice.do("GET", "/realms/main/saml/idp-initiated?sp="+url.QueryEscape(sp.entityID), nil, nil)
		if r.Status != 403 || r.Str("reason") != "saml_unsolicited_disabled" {
			t.Fatalf("unsolicited response not refused: %d %s", r.Status, r.Raw)
		}
		cur := f.must(f.AdminAPI("GET", "/saml/applications/"+appID, nil), 200, "get app")
		body := map[string]any{}
		for k, v := range appBody {
			body[k] = v
		}
		body["allow_idp_initiated"], body["idp_initiated_relay_state"] = true, "https://sp.test/home"
		f.must(h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/saml/applications/" + appID, Token: f.AdminToken, JSON: body,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "enable IdP-initiated")
		form := parseForm(t, alice.do("GET", "/realms/main/saml/idp-initiated?sp="+url.QueryEscape(sp.entityID)+"&RelayState=https://evil.test", nil, nil))
		res := sp.check(t, form, idpCert, now(), "")
		if res.Status != statusSuccess || form.RelayState != "https://sp.test/home" || res.NameID != alicePersistent {
			t.Fatalf("IdP-initiated: %+v relay=%q", res, form.RelayState)
		}
	})

	t.Run("backing client is not an OAuth client", func(t *testing.T) {
		got := f.must(f.AdminAPI("GET", "/clients/"+app.Str("client_ref"), nil), 200, "backing client")
		if got.Str("client.protocol") != "saml" {
			t.Fatalf("protocol: %s", got.Raw)
		}
		v, ch := PKCE()
		_ = v
		q := url.Values{"client_id": {app.Str("client_id")}, "redirect_uri": {h.Realm.Issuer + "/saml/sso/continue"}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"s"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}
		if r := h.Do(Req{Method: "GET", Path: "/realms/main/oauth/authorize?" + q.Encode()}); r.Status != 400 || r.Str("error") != "invalid_client" {
			t.Fatalf("authorize with the backing client: %d %s", r.Status, r.Raw)
		}
		if r := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/clients/" + app.Str("client_ref"), Token: f.AdminToken,
			JSON: map[string]any{"name": "x", "client_type": "confidential"}, Headers: map[string]string{"If-Match": got.Header.Get("ETag")}}); r.Status != 409 {
			t.Fatalf("backing client edited as an OAuth client: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("registration rules", func(t *testing.T) {
		bad := func(mut func(map[string]any), field string) {
			t.Helper()
			body := map[string]any{"entity_id": "https://sp-bad.test", "name": "Bad", "assertion_consumer_services": []map[string]any{{"url": "https://sp-bad.test/acs"}}}
			mut(body)
			r := f.AdminAPI("POST", "/saml/applications", body)
			if r.Status != 422 || !strings.Contains(string(r.Raw), field) {
				t.Fatalf("%s accepted: %d %s", field, r.Status, r.Raw)
			}
		}
		bad(func(b map[string]any) {
			b["attributes"] = []map[string]any{{"name": "mail", "source": "static", "value": "ceo@corp.test"}}
		}, "attributes")
		bad(func(b map[string]any) {
			b["attributes"] = []map[string]any{{"name": "urn:oid:0.9.2342.19200300.100.1.1", "source": "name"}}
		}, "attributes")
		bad(func(b map[string]any) { b["encryption_certificate"] = sp.kp.pem() }, "encrypt_assertions")
		bad(func(b map[string]any) {
			b["encrypt_assertions"], b["encryption_certificate"] = true, sp.kp.pem()
			b["data_encryption_algorithm"] = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
		}, "data_encryption_algorithm")
		bad(func(b map[string]any) {
			b["encrypt_assertions"], b["encryption_certificate"] = true, sp.kp.pem()
			b["key_transport_algorithm"] = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		}, "key_transport_algorithm")
		bad(func(b map[string]any) { b["encrypt_assertions"] = true }, "encryption_certificate")
		bad(func(b map[string]any) { b["signature_algorithm"] = rsa1 }, "signature_algorithm")
		bad(func(b map[string]any) {
			b["assertion_consumer_services"] = []map[string]any{{"url": "https://sp-bad.test/acs", "binding": bindingRedirect}}
		}, "assertion_consumer_services")
		bad(func(b map[string]any) {
			b["assertion_consumer_services"] = []map[string]any{{"url": "https://sp-bad.test/acs#frag"}}
		}, "assertion_consumer_services")
		bad(func(b map[string]any) { b["require_signed_requests"] = true }, "signing_certificates")
	})

	// A third-party application bound to Acme, releasing the verified email
	// as NameID.
	sp2 := &testSP{entityID: "https://partner-sp.test", acs: "https://partner-sp.test/acs", kp: sp.kp}
	f.must(f.AdminAPI("POST", "/saml/applications", map[string]any{"entity_id": sp2.entityID, "name": "Partner SP", "organization_id": f.Acme,
		"name_id_format": fmtE, "assertion_consumer_services": []map[string]any{{"url": sp2.acs}}, "signing_certificates": []string{sp.kp.pem()},
		"attributes": []map[string]any{{"name": "uid", "source": "user_id"}}}), 201, "partner application")
	sso2 := func(b *browser, mutate func(*etree.Element)) (*Resp, string) {
		id := xmlID()
		q := redirectQuery(t, "SAMLRequest", serialize(t, sp2.authnRequest(id, ssoURL, now(), mutate)), "", sp.kp, rsa256)
		return b.do("GET", "/realms/main/saml/sso?"+q, nil, nil), id
	}

	t.Run("organization binding and consent", func(t *testing.T) {
		carol := newBrowser(h)
		r, id := sso2(carol, nil)
		res := sp2.check(t, parseForm(t, login(carol, r, "carol@example.test")), idpCert, now(), id)
		if res.SubStatus != "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || res.Assertion != nil {
			t.Fatalf("non-member received an assertion: %+v", res)
		}
		// Alice reuses her SSO session but must consent to the third party.
		r, id = sso2(alice, nil)
		res = sp2.check(t, parseForm(t, login(alice, r, "alice@example.test")), idpCert, now(), id)
		if res.Status != statusSuccess || res.NameFormat != fmtE || res.NameID != "alice@example.test" || res.Attrs["uid"] != f.Users["alice"] {
			t.Fatalf("partner: %+v", res)
		}
		var consents int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM consents c JOIN clients k ON k.id=c.client_ref
			WHERE c.user_id=$1 AND k.protocol='saml' AND c.revoked_at IS NULL`, f.Users["alice"]).Scan(&consents)
		if consents != 1 {
			t.Fatalf("consent for the SAML application not recorded: %d", consents)
		}
	})

	t.Run("encrypted assertions (sign, then encrypt)", func(t *testing.T) {
		enc := newKeyPair(t, "sp-enc", now())
		for i, keyAlg := range []string{"", "http://www.w3.org/2009/xmlenc11#rsa-oaep"} {
			sp3 := &testSP{entityID: "https://enc-sp.test/" + string(rune('a'+i)), acs: "https://enc-sp.test/acs", kp: sp.kp, enc: &enc}
			body := map[string]any{"entity_id": sp3.entityID, "name": "Encrypting SP", "first_party": true, "require_signed_requests": false,
				"assertion_consumer_services": []map[string]any{{"url": sp3.acs}}, "encrypt_assertions": true, "encryption_certificate": enc.pem(),
				"attributes": []map[string]any{{"name": "mail", "source": "email"}}}
			if keyAlg != "" {
				body["key_transport_algorithm"] = keyAlg
			}
			f.must(f.AdminAPI("POST", "/saml/applications", body), 201, "encrypting application")
			id := xmlID()
			q := redirectQuery(t, "SAMLRequest", serialize(t, sp3.authnRequest(id, ssoURL, now(), nil)), "", sp.kp, "")
			form := parseForm(t, alice.do("GET", "/realms/main/saml/sso?"+q, nil, nil))
			if strings.Contains(string(mustDecode(t, form.Value)), "alice@example.test") {
				t.Fatal("assertion content visible outside the encryption")
			}
			res := sp3.check(t, form, idpCert, now(), id)
			if res.Status != statusSuccess || res.Attrs["mail"] != "alice@example.test" || res.NameID == "" {
				t.Fatalf("encrypted assertion: %+v", res)
			}
		}
	})

	t.Run("requested authentication context steps up (MFA)", func(t *testing.T) {
		b := newBrowser(h)
		r, id := sso(b, func(e *etree.Element) {
			rac := e.CreateElement("samlp:RequestedAuthnContext")
			rac.CreateAttr("Comparison", "minimum")
			rac.CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract")
		}, rsa256)
		res := sp.check(t, parseForm(t, login(b, r, "bob@example.test")), idpCert, now(), id)
		if res.Status != statusSuccess || res.ClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract" {
			t.Fatalf("MFA context: %+v", res)
		}
		r, id = sso(b, func(e *etree.Element) {
			e.CreateElement("samlp:RequestedAuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:example:unknown-context")
		}, rsa256)
		if res := sp.check(t, parseForm(t, r), idpCert, now(), id); res.SubStatus != "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext" {
			t.Fatalf("unknown context: %+v", res)
		}
	})

	t.Run("single logout (SAML-008)", func(t *testing.T) {
		logout := func(b *browser, nameID, format, index string, signed bool) *Resp {
			req := etree.NewElement("samlp:LogoutRequest")
			req.CreateAttr("xmlns:samlp", nsP)
			req.CreateAttr("xmlns:saml", nsA)
			req.CreateAttr("ID", xmlID())
			req.CreateAttr("Version", "2.0")
			req.CreateAttr("IssueInstant", xmlTime(now()))
			req.CreateAttr("Destination", h.Realm.Issuer+"/saml/slo")
			req.CreateElement("saml:Issuer").SetText(sp.entityID)
			nid := req.CreateElement("saml:NameID")
			nid.CreateAttr("Format", format)
			nid.SetText(nameID)
			req.CreateElement("samlp:SessionIndex").SetText(index)
			alg := ""
			if signed {
				alg = rsa256
			}
			return b.do("GET", "/realms/main/saml/slo?"+redirectQuery(t, "SAMLRequest", serialize(t, req), "lo-1", sp.kp, alg), nil, nil)
		}
		if r := logout(alice, alicePersistent, fmtP, aliceIndex, false); r.Status != 400 {
			t.Fatalf("unsigned logout accepted: %d %s", r.Status, r.Raw)
		}
		r := logout(alice, alicePersistent, fmtP, aliceIndex, true)
		mustStatus(t, r, 302, "logout response")
		loc := r.Header.Get("Location")
		if !strings.HasPrefix(loc, sp.slo+"?") {
			t.Fatalf("logout response destination: %s", loc)
		}
		raw := strings.TrimPrefix(loc, sp.slo+"?")
		q, _ := url.ParseQuery(raw)
		sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
		if err := idpCert.CheckSignature(x509.SHA256WithRSA, []byte(raw[:strings.Index(raw, "&Signature=")]), sig); err != nil || q.Get("RelayState") != "lo-1" {
			t.Fatalf("logout response signature: %v", err)
		}
		doc := etree.NewDocument()
		_ = doc.ReadFromBytes(inflate64(t, q.Get("SAMLResponse")))
		code := child(child(doc.Root(), nsP, "Status"), nsP, "StatusCode")
		// Alice's session also signed in to the partner application, which
		// is not sent a logout request: the logout is reported as partial.
		if code.SelectAttrValue("Value", "") != statusSuccess || child(code, nsP, "StatusCode").SelectAttrValue("Value", "") != "urn:oasis:names:tc:SAML:2.0:status:PartialLogout" {
			t.Fatalf("logout status: %s", serialize(t, doc.Root().Copy()))
		}
		if !strings.Contains(r.Header.Get("Set-Cookie"), "pa_sid=;") {
			t.Fatalf("browser session cookie not cleared: %v", r.Header.Values("Set-Cookie"))
		}
		again, _ := sso(alice, nil, rsa256)
		mustStatus(t, again, 302, "the ended session is not reused")
	})
}

// TestSAMLKeyRollover covers the controlled signing-key rollover of the
// identity provider (SAML-002): the next key is published before it signs,
// activation waits for the prepublication period, and the previous key
// stays published while it retires.
func mustDecode(t *testing.T, v string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSAMLKeyRollover(t *testing.T) {
	h := NewHarness(t, samlEnabled)
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h.App.SAMLKeys.RSABits = 2048
	now := h.Clock.Now
	sp := &testSP{entityID: "https://roll-sp.test", acs: "https://roll-sp.test/acs", kp: newKeyPair(t, "sp", now())}
	f.must(f.AdminAPI("POST", "/saml/applications", map[string]any{"entity_id": sp.entityID, "name": "Rollover SP", "first_party": true,
		"assertion_consumer_services": []map[string]any{{"url": sp.acs}}, "require_signed_requests": false}), 201, "app")
	signIn := func() (samlForm, string) {
		t.Helper()
		b := newBrowser(h)
		id := xmlID()
		q := redirectQuery(t, "SAMLRequest", serialize(t, sp.authnRequest(id, h.Realm.Issuer+"/saml/sso", now(), nil)), "", sp.kp, "")
		r := b.do("GET", "/realms/main/saml/sso?"+q, nil, nil)
		mustStatus(t, r, 302, "sso")
		loc, _ := url.Parse(r.Header.Get("Location"))
		st := b.drive(t, loc.Query().Get("transaction_id"), "bob@example.test")
		return parseForm(t, b.do("GET", st.Str("redirect_to"), nil, nil)), id
	}
	metadata := func() []*x509.Certificate {
		r := h.Do(Req{Method: "GET", Path: "/realms/main/saml/metadata"})
		mustStatus(t, r, 200, "metadata")
		return metadataCerts(t, r.Raw)
	}
	old := metadata()
	if len(old) != 1 {
		t.Fatalf("initial keys: %d", len(old))
	}
	next := f.must(f.AdminAPI("POST", "/saml/signing-keys", map[string]any{"reason": "scheduled"}), 201, "prepare next key")
	if next.Str("state") != "pending" || next.Get("published") != true {
		t.Fatalf("next key: %s", next.Raw)
	}
	if got := metadata(); len(got) != 2 {
		t.Fatalf("next key not published before use: %d certificates", len(got))
	}
	// Still signed with the current key while the next one is only published.
	form, id := signIn()
	sp.check(t, form, old[0], now(), id)
	r := f.AdminAPI("POST", "/saml/signing-keys/"+next.Str("id")+"/activate", map[string]any{})
	if r.Status != 409 {
		t.Fatalf("activation before the prepublication period: %d %s", r.Status, r.Raw)
	}
	if r := f.AdminAPI("POST", "/saml/signing-keys/"+next.Str("id")+"/activate", map[string]any{"force": true}); r.Status != 422 {
		t.Fatalf("forced activation without a reason: %d %s", r.Status, r.Raw)
	}
	h.Clock.Advance(49 * time.Hour)
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/saml/signing-keys/"+next.Str("id")+"/activate", map[string]any{"reason": "scheduled"}), 200, "activate")
	certs := metadata()
	if len(certs) != 2 {
		t.Fatalf("retiring key not published: %d", len(certs))
	}
	var fresh *x509.Certificate
	for _, c := range certs {
		if !c.Equal(old[0]) {
			fresh = c
		}
	}
	form, id = signIn()
	sp.check(t, form, fresh, now(), id)
	raw, _ := base64.StdEncoding.DecodeString(form.Value)
	doc := etree.NewDocument()
	_ = doc.ReadFromBytes(raw)
	if _, err := verifyEnveloped(child(doc.Root(), nsA, "Assertion"), old[0], now()); err == nil {
		t.Fatal("assertion still signed with the retired key")
	}
	h.Clock.Advance(8 * 24 * time.Hour)
	if got := metadata(); len(got) != 1 || !got[0].Equal(fresh) {
		t.Fatalf("retired key still published: %d", len(got))
	}
}
