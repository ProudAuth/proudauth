package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/platform/clock"
	"github.com/proudbase/proudauth/internal/runtime"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

func mint(t *testing.T, parent *testCA, cn string, isCA bool, fixedSerial int64) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	s := serial
	if fixedSerial != 0 {
		s = fixedSerial
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(s), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour)}
	if isCA {
		tpl.IsCA, tpl.BasicConstraintsValid = true, true
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	signerCert, signerKey := tpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

func crlOf(t *testing.T, ca *testCA, number int64, thisUpdate time.Time, revoked ...*big.Int) (*x509.RevocationList, []byte) {
	t.Helper()
	tpl := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: thisUpdate, NextUpdate: thisUpdate.Add(2 * time.Hour)}
	for _, s := range revoked {
		tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: thisUpdate})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl, der
}

func anchorOf(ca *testCA, crl *x509.RevocationList) *Anchor {
	a := &Anchor{ID: "cta_test", State: "active", Revocation: "none", cert: ca.cert}
	if crl != nil {
		a.Revocation, a.crl = "crl", crl
	}
	return a
}

// TestCRLCoversTheChain covers PROV-016/MCH-014 revocation: the anchor's CRL
// is applied to every certificate the anchor issued (an intermediate
// included), matched against the certificate actually issued by it, and a
// certificate below an intermediate, whose own CRL the anchor cannot hold,
// is refused as revocation-unknown instead of being looked up in the
// anchor's list by its serial alone.
func TestCRLCoversTheChain(t *testing.T) {
	now := time.Now().UTC()
	s := &Service{d: &runtime.Deps{Clock: clock.NewFake(now)}}
	root := mint(t, nil, "Root", true, 0)
	inter := mint(t, root, "Issuing", true, 0)
	direct := mint(t, root, "direct", false, 0)
	below := mint(t, inter, "below", false, 0)

	clean, _ := crlOf(t, root, 1, now.Add(-time.Minute))
	if err := s.VerifyAgainst(anchorOf(root, clean), direct.cert, nil); err != nil {
		t.Fatalf("leaf issued by the anchor, not revoked: %v", err)
	}
	revokedDirect, _ := crlOf(t, root, 2, now.Add(-time.Minute), direct.cert.SerialNumber)
	if err := s.VerifyAgainst(anchorOf(root, revokedDirect), direct.cert, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked leaf issued by the anchor: %v", err)
	}
	revokedInter, _ := crlOf(t, root, 3, now.Add(-time.Minute), inter.cert.SerialNumber)
	if err := s.VerifyAgainst(anchorOf(root, revokedInter), below.cert, []*x509.Certificate{inter.cert}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("leaf under a revoked intermediate: %v", err)
	}
	if err := s.VerifyAgainst(anchorOf(root, clean), below.cert, []*x509.Certificate{inter.cert}); !errors.Is(err, ErrNoCRL) {
		t.Fatalf("leaf under an intermediate whose CRL the anchor does not hold: %v", err)
	}
	// The anchor's list names serials of the anchor's own certificates: a
	// certificate another authority issued with the same serial is not the
	// one it revokes (the old check refused it as revoked).
	collide := mint(t, inter, "collides", false, direct.cert.SerialNumber.Int64())
	if err := s.VerifyAgainst(anchorOf(root, revokedDirect), collide.cert, []*x509.Certificate{inter.cert}); errors.Is(err, ErrRevoked) {
		t.Fatalf("a serial of another issuer was treated as revoked")
	}
	// Without revocation checking, intermediates work as before.
	if err := s.VerifyAgainst(anchorOf(root, nil), below.cert, []*x509.Certificate{inter.cert}); err != nil {
		t.Fatalf("intermediate chain without revocation: %v", err)
	}
	// Trusting the issuing CA itself covers its leaves with its own CRL.
	interCRL, _ := crlOf(t, inter, 1, now.Add(-time.Minute), below.cert.SerialNumber)
	if err := s.VerifyAgainst(anchorOf(inter, interCRL), below.cert, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("leaf revoked by the issuing CA as anchor: %v", err)
	}
	// A stale list refuses everything.
	stale, _ := crlOf(t, root, 4, now.Add(-3*time.Hour))
	if err := s.VerifyAgainst(anchorOf(root, stale), direct.cert, nil); !errors.Is(err, ErrNoCRL) {
		t.Fatalf("stale CRL: %v", err)
	}
	// Another anchor's certificate does not verify against this one.
	other := mint(t, nil, "Other", true, 0)
	if err := s.VerifyAgainst(anchorOf(other, nil), direct.cert, nil); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("certificate of another authority: %v", err)
	}
}

// TestCRLUpdateOrdering covers the CRL replacement rule: a strictly greater
// CRL number (or, without numbers, a later thisUpdate), or the identical
// list again; an equal number with other content is not newer.
func TestCRLUpdateOrdering(t *testing.T) {
	ca := mint(t, nil, "CA", true, 0)
	now := time.Now().UTC().Truncate(time.Second)
	cur, curDER := crlOf(t, ca, 5, now)
	same, sameDER := crlOf(t, ca, 5, now.Add(time.Minute), big.NewInt(42))
	higher, higherDER := crlOf(t, ca, 6, now.Add(time.Minute))
	lower, lowerDER := crlOf(t, ca, 4, now.Add(time.Minute))
	if !newerCRL(cur, curDER, cur, curDER) {
		t.Error("the identical list again is accepted")
	}
	if newerCRL(cur, curDER, same, sameDER) {
		t.Error("an equal CRL number with other content was accepted")
	}
	if !newerCRL(cur, curDER, higher, higherDER) {
		t.Error("a greater CRL number was refused")
	}
	if newerCRL(cur, curDER, lower, lowerDER) {
		t.Error("a lower CRL number was accepted")
	}
	// Lists without a CRL number (Go cannot issue one, so only the fields
	// the comparison reads are set).
	unnumbered, unnumberedDER := &x509.RevocationList{ThisUpdate: now}, []byte{1}
	later, laterDER := &x509.RevocationList{ThisUpdate: now.Add(time.Minute)}, []byte{2}
	if !newerCRL(unnumbered, unnumberedDER, later, laterDER) || newerCRL(later, laterDER, unnumbered, unnumberedDER) {
		t.Error("without numbers, thisUpdate decides")
	}
}

// TestCRLNeedsNextUpdate covers the upload check: a list without a next
// update would leave every certificate of the anchor refused (or, read the
// other way, never stale), so it is refused when uploaded.
func TestCRLNeedsNextUpdate(t *testing.T) {
	ca := mint(t, nil, "CA", true, 0)
	_, der := crlOf(t, ca, 1, time.Now().Add(-time.Minute))
	var cl pkix.CertificateList //nolint:staticcheck // building a test CRL without nextUpdate
	if _, err := asn1.Unmarshal(der, &cl); err != nil {
		t.Fatal(err)
	}
	tbs := cl.TBSCertList
	tbs.Raw = nil
	tbs.NextUpdate = time.Time{}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ca.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, cl.SignatureAlgorithm, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(out)
	if err != nil || !parsed.NextUpdate.IsZero() || parsed.CheckSignatureFrom(ca.cert) != nil {
		t.Fatalf("test CRL without nextUpdate: %v", err)
	}
	if _, _, err := parseCRL(string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: out})), ca.cert); err == nil {
		t.Fatal("a CRL without nextUpdate was accepted")
	}
	if _, _, err := parseCRL(string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), ca.cert); err != nil {
		t.Fatalf("a CRL with nextUpdate: %v", err)
	}
}
