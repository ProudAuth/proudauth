package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func testCert(t *testing.T, now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return k, c
}

func assertion(id, nameID string) *etree.Element {
	a := NewElement("saml", "Assertion")
	a.CreateAttr("xmlns:saml", NSAssertion)
	a.CreateAttr("ID", id)
	a.CreateAttr("Version", "2.0")
	AddChild(a, "saml", "Issuer").SetText("https://idp.test")
	s := AddChild(a, "saml", "Subject")
	AddChild(s, "saml", "NameID").SetText(nameID)
	return a
}

func response(a *etree.Element) *etree.Element {
	r := NewElement("samlp", "Response")
	r.CreateAttr("xmlns:samlp", NSProtocol)
	r.CreateAttr("xmlns:saml", NSAssertion)
	r.CreateAttr("ID", "_resp1")
	AddChild(r, "saml", "Issuer").SetText("https://idp.test")
	r.AddChild(a)
	return r
}

func roundTrip(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	b, err := Serialize(el)
	if err != nil {
		t.Fatal(err)
	}
	root, err := Parse(b, DefaultLimits(0))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, b)
	}
	return root
}

func TestSignVerifyAndWrapping(t *testing.T) {
	now := time.Now()
	key, cert := testCert(t, now)
	_, other := testCert(t, now)
	a := assertion("_a1", "alice@example.test")
	if err := Sign(a, key, cert.Raw, SigRSASHA256); err != nil {
		t.Fatal(err)
	}
	doc := roundTrip(t, response(a))
	signed := Children(doc, NSAssertion, "Assertion")[0]
	got, err := Verify(signed, []*x509.Certificate{other, cert}, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	nid, _ := RequiredChild(mustChild(t, got, "Subject"), NSAssertion, "NameID")
	if v, _ := Text(nid); v != "alice@example.test" {
		t.Fatalf("name id %q", v)
	}
	if _, err := Verify(signed, []*x509.Certificate{other}, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("untrusted key accepted: %v", err)
	}
	if _, err := Verify(signed, []*x509.Certificate{cert}, now.Add(2*time.Hour)); !errors.Is(err, ErrSignature) {
		t.Fatalf("expired certificate accepted: %v", err)
	}
	// Tampering with the signed content breaks the digest.
	b, _ := Serialize(doc)
	tampered := strings.Replace(string(b), "alice@example.test", "mallory@example.test", 1)
	root, err := Parse([]byte(tampered), DefaultLimits(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Children(root, NSAssertion, "Assertion")[0], []*x509.Certificate{cert}, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered assertion accepted: %v", err)
	}
	// Wrapping: the signed assertion moved under an unsigned one with its ID
	// cannot be verified as the outer element (duplicate ID is refused by
	// the parser; a different ID leaves the outer element unsigned).
	evil := assertion("_evil", "mallory@example.test")
	inner := signed.Copy()
	evil.AddChild(inner)
	if _, err := Verify(roundTrip(t, evil), []*x509.Certificate{cert}, now); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("wrapped assertion accepted: %v", err)
	}
}

func mustChild(t *testing.T, el *etree.Element, local string) *etree.Element {
	t.Helper()
	c, err := RequiredChild(el, NSAssertion, local)
	if err != nil {
		t.Fatalf("%s: %v", local, err)
	}
	return c
}

func TestSHA1Refused(t *testing.T) {
	now := time.Now()
	key, cert := testCert(t, now)
	a := assertion("_a2", "bob")
	ctx, _ := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.Hash = crypto.SHA1
	sig, err := ctx.ConstructSignature(a, true)
	if err != nil {
		t.Fatal(err)
	}
	a.InsertChildAt(1, sig)
	if _, err := Verify(roundTrip(t, a), []*x509.Certificate{cert}, now); !errors.Is(err, ErrWeakAlgorithm) {
		t.Fatalf("SHA-1 signature accepted: %v", err)
	}
}

func TestParserRefusals(t *testing.T) {
	lim := DefaultLimits(4096)
	cases := map[string]string{
		"doctype":     `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		"entity":      `<r>&unknown;</r>`,
		"comment":     `<r><n>alice@example.test<!---->.evil</n></r>`,
		"pi":          `<r><?php x?></r>`,
		"duplicateID": `<r><a ID="x"/><b ID="x"/></r>`,
		"dupAttr":     `<r a="1" a="2"/>`,
		"tworoots":    `<r/><s/>`,
		"encoding":    `<?xml version="1.0" encoding="ISO-8859-1"?><r/>`,
		"large":       "<r>" + strings.Repeat("a", 5000) + "</r>",
		"deep":        strings.Repeat("<a>", 40) + strings.Repeat("</a>", 40),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), lim); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(`<?xml version="1.0" encoding="UTF-8"?><r a="1"><s>t</s></r>`), lim); err != nil {
		t.Fatalf("ordinary document refused: %v", err)
	}
}

func TestRedirectBinding(t *testing.T) {
	now := time.Now()
	key, cert := testCert(t, now)
	enc, err := EncodeRedirect([]byte("<x/>"))
	if err != nil {
		t.Fatal(err)
	}
	q, err := SignRedirect("SAMLRequest", enc, "rs 1", key, SigRSASHA256)
	if err != nil {
		t.Fatal(err)
	}
	msg, rs, sig, err := ParseRedirect(q, "SAMLRequest")
	if err != nil || sig == nil || rs != "rs 1" {
		t.Fatalf("parse: %v %v %q", err, sig, rs)
	}
	if err := sig.Verify([]*x509.Certificate{cert}, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if raw, err := DecodeRedirect(msg, 1024); err != nil || string(raw) != "<x/>" {
		t.Fatalf("decode: %v %q", err, raw)
	}
	_, _, sig2, _ := ParseRedirect(strings.Replace(q, "rs+1", "rs+2", 1), "SAMLRequest")
	if err := sig2.Verify([]*x509.Certificate{cert}, now); err == nil {
		t.Fatal("altered relay state accepted")
	}
	big, _ := EncodeRedirect([]byte(strings.Repeat("a", 100000)))
	if _, err := DecodeRedirect(big, 1024); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("inflation bomb not bounded: %v", err)
	}
}
