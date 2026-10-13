package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"html/template"
	"io"
	"net/url"
	"strings"
	"time"
)

// MaxRelayState bounds RelayState. The bindings specification caps it at 80
// bytes; deployed service providers routinely send longer values (URLs), so
// a larger but still bounded value is accepted.
const MaxRelayState = 1024

// DecodeRedirect decodes an HTTP-Redirect binding parameter: base64, then
// raw DEFLATE, inflated only up to the size limit (a compression bomb stops
// at the limit instead of filling memory).
func DecodeRedirect(param string, maxBytes int) ([]byte, error) {
	if param == "" || len(param) > base64.StdEncoding.EncodedLen(maxBytes) {
		return nil, ErrTooLarge
	}
	compressed, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return nil, ErrMalformed
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return nil, ErrMalformed
	}
	if len(out) > maxBytes {
		return nil, ErrTooLarge
	}
	return out, nil
}

// EncodeRedirect deflates and base64-encodes a message for HTTP-Redirect.
func EncodeRedirect(msg []byte) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(msg); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodePOST decodes an HTTP-POST binding parameter. Line breaks inserted by
// encoders that wrap base64 are tolerated.
func DecodePOST(param string, maxBytes int) ([]byte, error) {
	if param == "" || len(param) > base64.StdEncoding.EncodedLen(maxBytes)+base64.StdEncoding.EncodedLen(maxBytes)/64+4 {
		return nil, ErrTooLarge
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, param)
	out, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, ErrMalformed
	}
	if len(out) > maxBytes {
		return nil, ErrTooLarge
	}
	return out, nil
}

// SignRedirect builds a signed HTTP-Redirect query (bindings §3.4.4.1):
// the signature covers "param=value[&RelayState=value]&SigAlg=value" with
// the URL-encoded values, in that order.
func SignRedirect(param, encoded, relayState string, key crypto.Signer, method string) (string, error) {
	q := param + "=" + url.QueryEscape(encoded)
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(method)
	h, err := HashFor(method)
	if err != nil {
		return "", err
	}
	d := h.New()
	d.Write([]byte(q))
	sig, err := key.Sign(rand.Reader, d.Sum(nil), h)
	if err != nil {
		return "", err
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), nil
}

// RedirectQuery returns an unsigned HTTP-Redirect query.
func RedirectQuery(param, encoded, relayState string) string {
	q := param + "=" + url.QueryEscape(encoded)
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	return q
}

// RedirectSignature is the detached signature of an HTTP-Redirect message.
type RedirectSignature struct {
	SigAlg string
	signed []byte
	value  []byte
}

// ParseRedirect splits a raw HTTP-Redirect query into the message parameter
// (SAMLRequest or SAMLResponse), RelayState and, when present, the detached
// signature. The signed octets are rebuilt from the values exactly as they
// were encoded in the query, so re-encoding differences cannot break (or
// forge) verification. Repeated parameters are refused.
func ParseRedirect(rawQuery, param string) (message, relayState string, sig *RedirectSignature, err error) {
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		key, kerr := url.QueryUnescape(k)
		if kerr != nil {
			return "", "", nil, ErrMalformed
		}
		switch key {
		case param, "RelayState", "SigAlg", "Signature":
			if _, dup := raw[key]; dup {
				return "", "", nil, ErrMalformed
			}
			raw[key] = v
		}
	}
	dec := func(k string) (string, error) {
		v, err := url.QueryUnescape(raw[k])
		if err != nil {
			return "", ErrMalformed
		}
		return v, nil
	}
	if message, err = dec(param); err != nil || message == "" {
		return "", "", nil, ErrMalformed
	}
	if relayState, err = dec("RelayState"); err != nil {
		return "", "", nil, err
	}
	if len(relayState) > MaxRelayState {
		return "", "", nil, ErrTooLarge
	}
	_, hasSig := raw["Signature"]
	_, hasAlg := raw["SigAlg"]
	if hasSig != hasAlg {
		return "", "", nil, ErrMalformed
	}
	if !hasSig {
		return message, relayState, nil, nil
	}
	alg, err := dec("SigAlg")
	if err != nil {
		return "", "", nil, err
	}
	sv, err := dec("Signature")
	if err != nil {
		return "", "", nil, err
	}
	value, err := base64.StdEncoding.DecodeString(sv)
	if err != nil || len(value) > 2048 {
		return "", "", nil, ErrMalformed
	}
	signed := param + "=" + raw[param]
	if _, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + raw["RelayState"]
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	return message, relayState, &RedirectSignature{SigAlg: alg, signed: []byte(signed), value: value}, nil
}

// Verify checks the detached signature against the trusted certificates.
func (s *RedirectSignature) Verify(certs []*x509.Certificate, now time.Time) error {
	alg, ok := SignatureAlgorithms[s.SigAlg]
	if !ok {
		return ErrWeakAlgorithm
	}
	for _, c := range certs {
		if c == nil || now.Before(c.NotBefore) || now.After(c.NotAfter) {
			continue
		}
		if c.CheckSignature(alg, s.signed, s.value) == nil {
			return nil
		}
	}
	return ErrSignature
}

// PostForm is an auto-submitting HTML form for the HTTP-POST binding.
type PostForm struct {
	Action     string
	Param      string // SAMLResponse or SAMLRequest
	Value      string // base64-encoded message
	RelayState string
	Nonce      string
}

var postPage = template.Must(template.New("saml-post").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Continuing sign-in</title></head>
<body>
<form method="post" action="{{.Action}}" id="saml-post">
<input type="hidden" name="{{.Param}}" value="{{.Value}}">
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}">{{end}}
<noscript><p>Script is disabled. Select Continue to finish signing in.</p></noscript>
<button type="submit">Continue</button>
</form>
<script nonce="{{.Nonce}}">document.getElementById("saml-post").submit();</script>
</body></html>
`))

// Render writes the form page. The caller must send a content security
// policy that allows only the script carrying f.Nonce.
func (f PostForm) Render(w io.Writer) error { return postPage.Execute(w, f) }

// ---------- certificates ----------

// MinRSABits is the smallest accepted RSA modulus for SAML keys.
const MinRSABits = 2048

// ErrCertificate reports an unusable certificate.
var ErrCertificate = errors.New("saml: certificate must be an X.509 RSA certificate of at least 2048 bits")

// ParseCertificate accepts a PEM certificate or the bare base64 DER form used
// in metadata, and requires an RSA key of at least MinRSABits.
func ParseCertificate(s string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if strings.HasPrefix(s, "-----BEGIN") {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) > 0 {
			return nil, ErrCertificate
		}
		der = b.Bytes
	} else {
		clean := strings.Join(strings.Fields(s), "")
		b, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, ErrCertificate
		}
		der = b
	}
	if len(der) == 0 || len(der) > 16<<10 {
		return nil, ErrCertificate
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrCertificate
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < MinRSABits {
		return nil, ErrCertificate
	}
	return c, nil
}

// CertificatePEM encodes a certificate as PEM.
func CertificatePEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// Fingerprint is the SHA-256 fingerprint of a certificate (hex).
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// CertificateInfo is the public description of a trusted certificate.
type CertificateInfo struct {
	PEM         string    `json:"pem"`
	Fingerprint string    `json:"sha256_fingerprint"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
}

// Describe returns the public description of a certificate.
func Describe(c *x509.Certificate) CertificateInfo {
	return CertificateInfo{PEM: CertificatePEM(c), Fingerprint: Fingerprint(c), Subject: c.Subject.String(), NotBefore: c.NotBefore.UTC(),
		NotAfter: c.NotAfter.UTC()}
}

// ParseCertificates parses a list and rejects duplicates and certificates
// that already expired at now (they could verify nothing).
func ParseCertificates(list []string, max int, now time.Time) ([]*x509.Certificate, error) {
	if len(list) > max {
		return nil, ErrCertificate
	}
	out := make([]*x509.Certificate, 0, len(list))
	seen := map[string]bool{}
	for _, s := range list {
		c, err := ParseCertificate(s)
		if err != nil {
			return nil, err
		}
		if now.After(c.NotAfter) {
			return nil, errors.New("saml: certificate expired on " + c.NotAfter.UTC().Format(time.RFC3339))
		}
		fp := Fingerprint(c)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, c)
	}
	return out, nil
}
