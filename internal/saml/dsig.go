package saml

import (
	"crypto"
	"crypto/x509"
	"slices"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// Signature algorithms (SAML-009). Only RSA with SHA-256 or stronger is
// accepted or produced: SHA-1 is refused, and ECDSA is not offered because
// XML-DSig implementations disagree on its signature value encoding.
const (
	SigRSASHA256 = dsig.RSASHA256SignatureMethod
	SigRSASHA384 = dsig.RSASHA384SignatureMethod
	SigRSASHA512 = dsig.RSASHA512SignatureMethod

	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// SignatureAlgorithms maps accepted signature methods to their X.509 algorithm.
var SignatureAlgorithms = map[string]x509.SignatureAlgorithm{
	SigRSASHA256: x509.SHA256WithRSA,
	SigRSASHA384: x509.SHA384WithRSA,
	SigRSASHA512: x509.SHA512WithRSA,
}

var digestAlgorithms = []string{DigestSHA256, DigestSHA384, DigestSHA512}

// Canonicalization and transform algorithms accepted on inbound signatures.
// The "with comments" variants are refused: they would make comments, which
// Parse already rejects, part of what is signed.
var c14nAlgorithms = []string{string(dsig.CanonicalXML10ExclusiveAlgorithmId), string(dsig.CanonicalXML10RecAlgorithmId),
	string(dsig.CanonicalXML11AlgorithmId)}

// Signed reports whether el carries an enveloped signature as a direct child.
func Signed(el *etree.Element) bool { return len(Children(el, NSDSig, "Signature")) > 0 }

// Verify checks the enveloped signature of el (a Response, Assertion or
// request) against the trusted certificates, and returns the element as
// verified: the canonical bytes that were digested, parsed again. Callers
// must read everything they rely on from the returned element, never from
// el, so content outside what was signed (an injected assertion, an
// unsigned wrapper) is never consumed (signature-wrapping defense,
// SAML-004).
//
// Before goxmldsig runs, the signature's shape is pinned down so the library
// cannot pick a different signature than the one checked here: exactly one
// ds:Signature is a direct child of el, it is the only signature anywhere in
// the subtree that refers to el, it has exactly one Reference with URI
// "#<ID>", and its canonicalization, transforms, digest and signature
// methods meet the floor (SAML-009). Each trusted certificate is tried in
// turn (overlap during rollover, SAML-002); an expired certificate verifies
// nothing.
func Verify(el *etree.Element, certs []*x509.Certificate, now time.Time) (*etree.Element, error) {
	id := Attr(el, "ID")
	if !ValidID(id) {
		return nil, ErrMalformed
	}
	direct := Children(el, NSDSig, "Signature")
	switch {
	case len(direct) == 0:
		return nil, ErrNoSignature
	case len(direct) > 1:
		return nil, ErrAmbiguousSignature
	}
	sig := direct[0]
	referring := 0
	for _, s := range Descendants(el, NSDSig, "Signature") {
		for _, si := range Children(s, NSDSig, "SignedInfo") {
			for _, ref := range Children(si, NSDSig, "Reference") {
				// goxmldsig compares URI[1:] with the ID, so any one-character
				// prefix would match; count those as references too.
				if uri := Attr(ref, "URI"); uri == "" || uri[1:] == id {
					if s != sig {
						return nil, ErrAmbiguousSignature
					}
					referring++
				}
			}
		}
	}
	if referring != 1 {
		return nil, ErrAmbiguousSignature
	}
	if err := checkShape(sig, id); err != nil {
		return nil, err
	}
	// Detach el with every namespace in scope declared on it, so the
	// canonical form does not depend on where el sits in the document.
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, ErrMalformed
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, ErrMalformed
	}
	for _, cert := range certs {
		if cert == nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		vc.IdAttribute = "ID"
		vc.Clock = dsig.NewFakeClockAt(now)
		out, err := vc.Validate(detached)
		if err != nil {
			continue
		}
		if out == nil || out.Tag != el.Tag || out.NamespaceURI() != el.NamespaceURI() || Attr(out, "ID") != id {
			return nil, ErrSignature
		}
		return out, nil
	}
	return nil, ErrSignature
}

// checkShape enforces the algorithm floor and a single reference to id.
func checkShape(sig *etree.Element, id string) error {
	si, err := RequiredChild(sig, NSDSig, "SignedInfo")
	if err != nil {
		return err
	}
	c14n, err := RequiredChild(si, NSDSig, "CanonicalizationMethod")
	if err != nil {
		return err
	}
	if !slices.Contains(c14nAlgorithms, Attr(c14n, "Algorithm")) {
		return ErrWeakAlgorithm
	}
	sm, err := RequiredChild(si, NSDSig, "SignatureMethod")
	if err != nil {
		return err
	}
	if _, ok := SignatureAlgorithms[Attr(sm, "Algorithm")]; !ok {
		return ErrWeakAlgorithm
	}
	refs := Children(si, NSDSig, "Reference")
	if len(refs) != 1 || Attr(refs[0], "URI") != "#"+id {
		return ErrAmbiguousSignature
	}
	// Exactly the enveloped-signature transform plus one canonicalization:
	// nothing else (XPath, XSLT, base64) is ever needed for SAML.
	ts, err := RequiredChild(refs[0], NSDSig, "Transforms")
	if err != nil {
		return err
	}
	list := Children(ts, NSDSig, "Transform")
	if len(list) != 2 {
		return ErrMalformed
	}
	enveloped, c14nCount := 0, 0
	for _, t := range list {
		switch alg := Attr(t, "Algorithm"); {
		case alg == string(dsig.EnvelopedSignatureAltorithmId):
			enveloped++
		case slices.Contains(c14nAlgorithms, alg):
			c14nCount++
		default:
			return ErrWeakAlgorithm
		}
	}
	if enveloped != 1 || c14nCount != 1 {
		return ErrMalformed
	}
	dm, err := RequiredChild(refs[0], NSDSig, "DigestMethod")
	if err != nil {
		return err
	}
	if !slices.Contains(digestAlgorithms, Attr(dm, "Algorithm")) {
		return ErrWeakAlgorithm
	}
	return nil
}

// Sign adds an enveloped signature to el (exclusive canonicalization, the
// given RSA signature method, the certificate in KeyInfo) and places it right
// after the Issuer child, where the SAML schema requires it. el must be a
// standalone element (not yet inserted into a parent) whose namespaces are
// declared on itself: the canonicalizer resolves prefixes from el alone.
func Sign(el *etree.Element, key crypto.Signer, certDER []byte, method string) error {
	if _, ok := SignatureAlgorithms[method]; !ok {
		return ErrWeakAlgorithm
	}
	ctx, err := dsig.NewSigningContext(key, [][]byte{certDER})
	if err != nil {
		return err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.IdAttribute = "ID"
	ctx.Prefix = "ds"
	if err := ctx.SetSignatureMethod(method); err != nil {
		return err
	}
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return err
	}
	at := 0
	for i, c := range el.Child {
		if e, ok := c.(*etree.Element); ok && e.Tag == "Issuer" {
			at = i + 1
			break
		}
	}
	el.InsertChildAt(at, sig)
	return nil
}

// HashFor returns the digest for a signature method (HTTP-Redirect binding).
func HashFor(method string) (crypto.Hash, error) {
	switch method {
	case SigRSASHA256:
		return crypto.SHA256, nil
	case SigRSASHA384:
		return crypto.SHA384, nil
	case SigRSASHA512:
		return crypto.SHA512, nil
	}
	return 0, ErrWeakAlgorithm
}
