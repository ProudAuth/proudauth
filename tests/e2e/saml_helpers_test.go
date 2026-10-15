package e2e

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/proudauth/proudauth/internal/configuration"
)

// The SAML test counterparties are built directly on etree and goxmldsig,
// not on internal/saml, so the server is checked against an independent
// implementation of the messages and signatures (SAML-010).

const (
	nsP    = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsA    = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMD   = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDS   = "http://www.w3.org/2000/09/xmldsig#"
	rsa256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	rsa1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	fmtP   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	fmtE   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	fmtT   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

func samlEnabled(c *configuration.Config) { c.SAML.Enabled = true }

type keyPair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newKeyPair(t *testing.T, cn string, now time.Time) keyPair {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return keyPair{key: k, cert: c}
}

func (kp keyPair) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kp.cert.Raw}))
}

func xmlID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

func xmlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// sign adds an enveloped signature after the Issuer child, with goxmldsig.
func sign(t *testing.T, el *etree.Element, kp keyPair, sha1Digest bool) {
	t.Helper()
	ctx, err := dsig.NewSigningContext(kp.key, [][]byte{kp.cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if sha1Digest {
		ctx.Hash = crypto.SHA1
	}
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		t.Fatal(err)
	}
	at := 0
	for i, c := range el.Child {
		if e, ok := c.(*etree.Element); ok && e.Tag == "Issuer" {
			at = i + 1
		}
	}
	el.InsertChildAt(at, sig)
}

func serialize(t *testing.T, el *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func deflate64(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func inflate64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// redirectQuery builds an HTTP-Redirect query, signed when alg is set.
func redirectQuery(t *testing.T, param string, msg []byte, relay string, kp keyPair, alg string) string {
	t.Helper()
	q := param + "=" + url.QueryEscape(deflate64(t, msg))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if alg == "" {
		return q
	}
	q += "&SigAlg=" + url.QueryEscape(alg)
	var digest []byte
	h := crypto.SHA256
	if alg == rsa1 {
		s := sha1.Sum([]byte(q))
		digest, h = s[:], crypto.SHA1
	} else {
		s := sha256.Sum256([]byte(q))
		digest = s[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, kp.key, h, digest)
	if err != nil {
		t.Fatal(err)
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// verifyEnveloped checks el's enveloped signature with goxmldsig against one
// certificate, in the namespace context of the document.
func verifyEnveloped(el *etree.Element, cert *x509.Certificate, now time.Time) (*etree.Element, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, err
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	vc.Clock = dsig.NewFakeClockAt(now)
	return vc.Validate(detached)
}

func child(el *etree.Element, ns, tag string) *etree.Element {
	if el == nil {
		return nil
	}
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

func text(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return strings.TrimSpace(el.Text())
}

// ---------- test service provider (for the identity provider profile) ----------

type testSP struct {
	entityID string
	acs      string
	slo      string
	kp       keyPair
	// enc decrypts encrypted assertions, when the SP registered one.
	enc *keyPair
}

const nsXENC = "http://www.w3.org/2001/04/xmlenc#"

// decrypt opens an EncryptedAssertion with the standard library only
// (RSA-OAEP key transport, AES-GCM content), independently of the server.
func (sp *testSP) decrypt(t *testing.T, ea *etree.Element) *etree.Element {
	t.Helper()
	ed := child(ea, nsXENC, "EncryptedData")
	if ed == nil || sp.enc == nil {
		t.Fatal("no EncryptedData or no decryption key")
	}
	ek := child(child(ed, nsDS, "KeyInfo"), nsXENC, "EncryptedKey")
	keyAlg := child(ek, nsXENC, "EncryptionMethod").SelectAttrValue("Algorithm", "")
	wrapped, _ := base64.StdEncoding.DecodeString(text(child(child(ek, nsXENC, "CipherData"), nsXENC, "CipherValue")))
	var key []byte
	var err error
	switch keyAlg {
	case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
		key, err = rsa.DecryptOAEP(sha1.New(), nil, sp.enc.key, wrapped, nil)
	case "http://www.w3.org/2009/xmlenc11#rsa-oaep":
		key, err = rsa.DecryptOAEP(sha256.New(), nil, sp.enc.key, wrapped, nil)
	default:
		t.Fatalf("unexpected key transport %s", keyAlg)
	}
	if err != nil {
		t.Fatalf("key transport: %v", err)
	}
	if alg := child(ed, nsXENC, "EncryptionMethod").SelectAttrValue("Algorithm", ""); !strings.HasSuffix(alg, "-gcm") {
		t.Fatalf("content encryption %s", alg)
	}
	ct, _ := base64.StdEncoding.DecodeString(text(child(child(ed, nsXENC, "CipherData"), nsXENC, "CipherValue")))
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("content decryption: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plain); err != nil {
		t.Fatal(err)
	}
	return doc.Root()
}

func (sp *testSP) authnRequest(id, destination string, now time.Time, mutate func(*etree.Element)) *etree.Element {
	r := etree.NewElement("samlp:AuthnRequest")
	r.CreateAttr("xmlns:samlp", nsP)
	r.CreateAttr("xmlns:saml", nsA)
	r.CreateAttr("ID", id)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", xmlTime(now))
	r.CreateAttr("Destination", destination)
	r.CreateAttr("AssertionConsumerServiceURL", sp.acs)
	r.CreateAttr("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	r.CreateElement("saml:Issuer").SetText(sp.entityID)
	if mutate != nil {
		mutate(r)
	}
	return r
}

// samlForm is a parsed auto-submitting form page.
type samlForm struct {
	Action, Value, RelayState string
}

var (
	formAction = regexp.MustCompile(`action="([^"]*)"`)
	formValue  = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
	formRelay  = regexp.MustCompile(`name="RelayState" value="([^"]*)"`)
	formNonce  = regexp.MustCompile(`<script nonce="([^"]+)">`)
)

func parseForm(t *testing.T, r *Resp) samlForm {
	t.Helper()
	if r.Status != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("expected an auto-submitting form, got %d %s: %s", r.Status, r.Header.Get("Content-Type"), r.Raw)
	}
	body := string(r.Raw)
	nonce := formNonce.FindStringSubmatch(body)
	if nonce == nil || !strings.Contains(r.Header.Get("Content-Security-Policy"), "script-src 'nonce-"+html.UnescapeString(nonce[1])+"'") {
		t.Fatalf("form script not bound to the content security policy: %s / %s", r.Header.Get("Content-Security-Policy"), body)
	}
	f := samlForm{}
	if m := formAction.FindStringSubmatch(body); m != nil {
		f.Action = html.UnescapeString(m[1])
	}
	if m := formValue.FindStringSubmatch(body); m != nil {
		f.Value = html.UnescapeString(m[1])
	}
	if m := formRelay.FindStringSubmatch(body); m != nil {
		f.RelayState = html.UnescapeString(m[1])
	}
	return f
}

// samlResult is a response checked by the test service provider.
type samlResult struct {
	Root       *etree.Element
	Status     string
	SubStatus  string
	Assertion  *etree.Element // verified
	NameID     string
	NameFormat string
	Attrs      map[string]string
	SessionIdx string
	ClassRef   string
}

// check decodes and verifies a response the way an independent service
// provider would: the signature with the IdP's published certificate, then
// recipient, audience and correlation.
func (sp *testSP) check(t *testing.T, form samlForm, idpCert *x509.Certificate, now time.Time, inResponseTo string) samlResult {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(form.Value)
	if err != nil {
		t.Fatalf("response encoding: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	res := samlResult{Root: root, Attrs: map[string]string{}}
	if root.SelectAttrValue("Destination", "") != sp.acs || form.Action != sp.acs {
		t.Fatalf("response destination %q / form action %q", root.SelectAttrValue("Destination", ""), form.Action)
	}
	if root.SelectAttrValue("InResponseTo", "") != inResponseTo {
		t.Fatalf("InResponseTo %q, want %q", root.SelectAttrValue("InResponseTo", ""), inResponseTo)
	}
	st := child(child(root, nsP, "Status"), nsP, "StatusCode")
	res.Status = st.SelectAttrValue("Value", "")
	if sub := child(st, nsP, "StatusCode"); sub != nil {
		res.SubStatus = sub.SelectAttrValue("Value", "")
	}
	if child(root, nsDS, "Signature") != nil {
		if _, err := verifyEnveloped(root, idpCert, now); err != nil {
			t.Fatalf("response signature: %v", err)
		}
	}
	a := child(root, nsA, "Assertion")
	if ea := child(root, nsA, "EncryptedAssertion"); ea != nil {
		a = sp.decrypt(t, ea)
	} else if sp.enc != nil && res.Status == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Fatal("assertion not encrypted")
	}
	if a == nil {
		return res
	}
	verified, err := verifyEnveloped(a, idpCert, now)
	if err != nil {
		t.Fatalf("assertion signature: %v", err)
	}
	res.Assertion = verified
	subj := child(verified, nsA, "Subject")
	nid := child(subj, nsA, "NameID")
	res.NameID, res.NameFormat = text(nid), nid.SelectAttrValue("Format", "")
	scd := child(child(subj, nsA, "SubjectConfirmation"), nsA, "SubjectConfirmationData")
	if scd.SelectAttrValue("Recipient", "") != sp.acs || scd.SelectAttrValue("InResponseTo", "") != inResponseTo {
		t.Fatalf("subject confirmation: %s", serialize(t, scd.Copy()))
	}
	aud := child(child(child(verified, nsA, "Conditions"), nsA, "AudienceRestriction"), nsA, "Audience")
	if text(aud) != sp.entityID {
		t.Fatalf("audience %q", text(aud))
	}
	as := child(verified, nsA, "AuthnStatement")
	res.SessionIdx = as.SelectAttrValue("SessionIndex", "")
	res.ClassRef = text(child(child(as, nsA, "AuthnContext"), nsA, "AuthnContextClassRef"))
	if stmt := child(verified, nsA, "AttributeStatement"); stmt != nil {
		for _, at := range stmt.ChildElements() {
			res.Attrs[at.SelectAttrValue("Name", "")] = text(child(at, nsA, "AttributeValue"))
		}
	}
	return res
}

// metadataCerts extracts the signing certificates from metadata.
func metadataCerts(t *testing.T, raw []byte) []*x509.Certificate {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	var out []*x509.Certificate
	for _, el := range doc.FindElements("//KeyDescriptor/KeyInfo/X509Data/X509Certificate") {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(el.Text()), ""))
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// ---------- test identity provider (for the broker) ----------

type testIdP struct {
	entityID string
	sso      string
}

// samlRequest is an AuthnRequest received by the test identity provider.
type samlRequest struct {
	ID, ACS, Issuer, RelayState string
	Signed                      bool
}

// receive decodes the broker's HTTP-Redirect AuthnRequest and, when it is
// signed, checks the signature with the broker's published certificate.
func (idp *testIdP) receive(t *testing.T, redirect string, spCerts []*x509.Certificate) samlRequest {
	t.Helper()
	if !strings.HasPrefix(redirect, idp.sso+"?") {
		t.Fatalf("not sent to the identity provider: %s", redirect)
	}
	rawQuery := strings.TrimPrefix(redirect, idp.sso+"?")
	q, _ := url.ParseQuery(rawQuery)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(inflate64(t, q.Get("SAMLRequest"))); err != nil {
		t.Fatal(err)
	}
	r := doc.Root()
	out := samlRequest{ID: r.SelectAttrValue("ID", ""), ACS: r.SelectAttrValue("AssertionConsumerServiceURL", ""),
		Issuer: text(child(r, nsA, "Issuer")), RelayState: q.Get("RelayState")}
	if sig := q.Get("Signature"); sig != "" {
		signed := rawQuery[:strings.Index(rawQuery, "&Signature=")]
		raw, _ := base64.StdEncoding.DecodeString(sig)
		ok := false
		for _, c := range spCerts {
			if c.CheckSignature(x509.SHA256WithRSA, []byte(signed), raw) == nil {
				ok = true
			}
		}
		if !ok || q.Get("SigAlg") != rsa256 {
			t.Fatalf("AuthnRequest signature does not verify with the published certificates")
		}
		out.Signed = true
	}
	return out
}

// idpResponse describes a response the test identity provider sends.
type idpResponse struct {
	Req          samlRequest
	NameID       string
	NameIDFormat string
	Attrs        map[string]string
	// ExtraAttrs are emitted after Attrs, each as its own Attribute
	// element, so a name may repeat (as Keycloak's role list sends roles).
	ExtraAttrs    [][2]string
	AssertionID   string
	Issued        time.Time
	Lifetime      time.Duration
	Audience      string
	Destination   string
	Recipient     string
	InResponseTo  string // overrides the subject confirmation correlation
	NoResponseIRT bool   // unsolicited: no InResponseTo anywhere
	ClassRef      string
	Status        string
	SignResponse  bool
	SignAssertion bool
	SHA1          bool
	Key           keyPair
	// Mutate changes the signed document before encoding (attacks).
	Mutate func(resp *etree.Element)
}

func (idp *testIdP) assertion(r idpResponse) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsA)
	a.CreateAttr("ID", r.AssertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", xmlTime(r.Issued))
	a.CreateElement("saml:Issuer").SetText(idp.entityID)
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", r.NameIDFormat)
	nid.SetText(r.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	irt := r.Req.ID
	if r.InResponseTo != "" {
		irt = r.InResponseTo
	}
	if !r.NoResponseIRT {
		scd.CreateAttr("InResponseTo", irt)
	}
	scd.CreateAttr("NotOnOrAfter", xmlTime(r.Issued.Add(r.Lifetime)))
	scd.CreateAttr("Recipient", r.Recipient)
	conds := a.CreateElement("saml:Conditions")
	conds.CreateAttr("NotBefore", xmlTime(r.Issued.Add(-time.Minute)))
	conds.CreateAttr("NotOnOrAfter", xmlTime(r.Issued.Add(r.Lifetime)))
	conds.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(r.Audience)
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", xmlTime(r.Issued))
	as.CreateAttr("SessionIndex", "_s1")
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(r.ClassRef)
	if len(r.Attrs)+len(r.ExtraAttrs) > 0 {
		stmt := a.CreateElement("saml:AttributeStatement")
		for k, v := range r.Attrs {
			at := stmt.CreateElement("saml:Attribute")
			at.CreateAttr("Name", k)
			at.CreateElement("saml:AttributeValue").SetText(v)
		}
		for _, kv := range r.ExtraAttrs {
			at := stmt.CreateElement("saml:Attribute")
			at.CreateAttr("Name", kv[0])
			at.CreateElement("saml:AttributeValue").SetText(kv[1])
		}
	}
	return a
}

// build returns the base64 SAMLResponse.
func (idp *testIdP) build(t *testing.T, r idpResponse) string {
	t.Helper()
	if r.AssertionID == "" {
		r.AssertionID = xmlID()
	}
	if r.Lifetime == 0 {
		r.Lifetime = 5 * time.Minute
	}
	if r.NameIDFormat == "" {
		r.NameIDFormat = fmtP
	}
	if r.Status == "" {
		r.Status = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}
	if r.ClassRef == "" {
		r.ClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	}
	if r.Destination == "" {
		r.Destination = r.Req.ACS
	}
	if r.Recipient == "" {
		r.Recipient = r.Req.ACS
	}
	if r.Audience == "" {
		r.Audience = r.Req.Issuer
	}
	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsP)
	resp.CreateAttr("xmlns:saml", nsA)
	resp.CreateAttr("ID", xmlID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", xmlTime(r.Issued))
	resp.CreateAttr("Destination", r.Destination)
	if !r.NoResponseIRT {
		resp.CreateAttr("InResponseTo", r.Req.ID)
	}
	resp.CreateElement("saml:Issuer").SetText(idp.entityID)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", r.Status)
	if r.Status == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		a := idp.assertion(r)
		if r.SignAssertion {
			sign(t, a, r.Key, r.SHA1)
		}
		resp.AddChild(a)
	}
	if r.SignResponse {
		sign(t, resp, r.Key, r.SHA1)
	}
	if r.Mutate != nil {
		r.Mutate(resp)
	}
	return base64.StdEncoding.EncodeToString(serialize(t, resp))
}

// metadata renders identity provider metadata for upload.
func (idp *testIdP) metadata(kps ...keyPair) string {
	root := etree.NewElement("md:EntityDescriptor")
	root.CreateAttr("xmlns:md", nsMD)
	root.CreateAttr("xmlns:ds", nsDS)
	root.CreateAttr("entityID", idp.entityID)
	d := root.CreateElement("md:IDPSSODescriptor")
	d.CreateAttr("protocolSupportEnumeration", nsP)
	d.CreateAttr("WantAuthnRequestsSigned", "true")
	for _, kp := range kps {
		kd := d.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(kp.cert.Raw))
	}
	d.CreateElement("md:NameIDFormat").SetText(fmtP)
	ep := d.CreateElement("md:SingleSignOnService")
	ep.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	ep.CreateAttr("Location", idp.sso)
	doc := etree.NewDocument()
	doc.SetRoot(root)
	s, _ := doc.WriteToString()
	return s
}

// postACS posts a SAMLResponse to the broker's assertion consumer service.
func postACS(h *Harness, alias, value, relay string) *Resp {
	return h.Do(Req{Method: "POST", Path: "/realms/main/saml/acs/" + alias, Form: url.Values{"SAMLResponse": {value}, "RelayState": {relay}}})
}

func cookieValue(b *browser, h *Harness, path, name string) string {
	u, _ := url.Parse(h.Base + path)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

var _ = http.MethodGet

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
