package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"hash"

	"github.com/beevik/etree"
)

// XML encryption algorithms (SAML-009). Assertions are encrypted with an
// authenticated cipher only: AES-GCM content encryption and RSA-OAEP key
// transport. AES-CBC and RSA PKCS#1 v1.5 key transport, both open to
// padding-oracle attacks on the decrypting side, are not offered.
const (
	NSXMLEnc11 = "http://www.w3.org/2009/xmlenc11#"

	EncAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	// KeyRSAOAEPMGF1P is RSA-OAEP with SHA-1 for the mask and digest, the
	// form most service providers implement. OAEP's security does not rest
	// on SHA-1 collision resistance.
	KeyRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	// KeyRSAOAEP is xmlenc 1.1 RSA-OAEP with SHA-256 digest and MGF1-SHA-256.
	KeyRSAOAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep"

	encTypeElement = "http://www.w3.org/2001/04/xmlenc#Element"
	mgf1SHA256     = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
)

// EncryptionAlgorithms and KeyTransportAlgorithms are the offered choices.
var (
	EncryptionAlgorithms   = []string{EncAES256GCM, EncAES128GCM}
	KeyTransportAlgorithms = []string{KeyRSAOAEPMGF1P, KeyRSAOAEP}
)

// EncryptAssertion encrypts a (signed, standalone) assertion to a service
// provider's RSA certificate and returns the saml:EncryptedAssertion that
// replaces it (sign, then encrypt). A fresh content key and nonce are used
// for every assertion.
func EncryptAssertion(assertion *etree.Element, cert *x509.Certificate, dataAlg, keyAlg string) (*etree.Element, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < MinRSABits {
		return nil, ErrCertificate
	}
	keyLen := 32
	switch dataAlg {
	case EncAES256GCM:
	case EncAES128GCM:
		keyLen = 16
	default:
		return nil, ErrWeakAlgorithm
	}
	var h hash.Hash
	switch keyAlg {
	case KeyRSAOAEPMGF1P:
		h = sha1.New()
	case KeyRSAOAEP:
		h = sha256.New()
	default:
		return nil, ErrWeakAlgorithm
	}
	plain, err := Serialize(assertion.Copy())
	if err != nil {
		return nil, err
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// xmlenc 1.1 §5.2.4: the cipher value is the IV followed by the
	// ciphertext and the 128-bit authentication tag.
	sealed := gcm.Seal(append([]byte{}, nonce...), nonce, plain, nil)
	wrapped, err := rsa.EncryptOAEP(h, rand.Reader, pub, key, nil)
	if err != nil {
		return nil, err
	}
	ea := NewElement("saml", "EncryptedAssertion")
	ea.CreateAttr("xmlns:saml", NSAssertion)
	ed := AddChild(ea, "xenc", "EncryptedData")
	ed.CreateAttr("xmlns:xenc", NSXMLEnc)
	ed.CreateAttr("Type", encTypeElement)
	AddChild(ed, "xenc", "EncryptionMethod").CreateAttr("Algorithm", dataAlg)
	ki := AddChild(ed, "ds", "KeyInfo")
	ki.CreateAttr("xmlns:ds", NSDSig)
	ek := AddChild(ki, "xenc", "EncryptedKey")
	em := AddChild(ek, "xenc", "EncryptionMethod")
	em.CreateAttr("Algorithm", keyAlg)
	dm := AddChild(em, "ds", "DigestMethod")
	if keyAlg == KeyRSAOAEP {
		dm.CreateAttr("Algorithm", DigestSHA256)
		mgf := AddChild(em, "xenc11", "MGF")
		mgf.CreateAttr("xmlns:xenc11", NSXMLEnc11)
		mgf.CreateAttr("Algorithm", mgf1SHA256)
	} else {
		dm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	}
	ekd := AddChild(AddChild(ek, "ds", "KeyInfo"), "ds", "X509Data")
	AddChild(ekd, "ds", "X509Certificate").SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	AddChild(AddChild(ek, "xenc", "CipherData"), "xenc", "CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
	AddChild(AddChild(ed, "xenc", "CipherData"), "xenc", "CipherValue").SetText(base64.StdEncoding.EncodeToString(sealed))
	return ea, nil
}
