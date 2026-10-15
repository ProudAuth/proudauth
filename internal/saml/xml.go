// Package saml holds the SAML 2.0 building blocks shared by the identity
// provider profile (internal/saml/idp, APP-018) and the broker profile
// (internal/federation, FED-014): bounded, hardened XML parsing (SAML-004),
// XML-signature verification and creation through goxmldsig (ARC-009,
// SAML-009), the HTTP-Redirect and HTTP-POST bindings (SAML-005), metadata,
// and the realm's SAML signing keys with controlled rollover (SAML-002).
//
// Nothing here canonicalizes or verifies signatures by hand: goxmldsig does,
// and this package only decides which signatures and algorithms are
// acceptable and which element the caller may consume afterwards.
package saml

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/beevik/etree"

	"github.com/proudauth/proudauth/internal/platform/secret"
)

// Namespaces.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	NSDSig      = "http://www.w3.org/2000/09/xmldsig#"
	NSXMLEnc    = "http://www.w3.org/2001/04/xmlenc#"
)

// Bindings (SAML-005). Artifact is recognized only to be refused.
const (
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
)

// Name identifier formats (SAML-006).
const (
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

// NameIDFormats are the formats either profile issues or accepts.
var NameIDFormats = []string{NameIDPersistent, NameIDEmail, NameIDUnspecified, NameIDTransient}

// Status codes.
const (
	StatusSuccess              = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester            = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder            = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusVersionMismatch      = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	StatusAuthnFailed          = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusInvalidNameIDPolicy  = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	StatusNoAuthnContext       = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
	StatusNoPassive            = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	StatusRequestDenied        = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusRequestUnsupported   = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	StatusUnsupportedBinding   = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
	StatusPartialLogout        = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	StatusUnknownPrincipal     = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	ConfirmationMethodBearer   = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	AttrNameFormatBasic        = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	AttrNameFormatURI          = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	AttrNameFormatUnspecified  = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	ClassUnspecified           = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	ClassPassword              = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	ClassPasswordProtected     = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	ClassMobileTwoFactor       = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	ClassTimeSyncToken         = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
	ClassMicrosoftMultipleAuth = "http://schemas.microsoft.com/claims/multipleauthn"
	ClassREFEDSMFA             = "https://refeds.org/profile/mfa"
)

// Errors. They are deliberately coarse: detail stays in audit evidence, not in
// responses an attacker can probe.
var (
	ErrMalformed          = errors.New("saml: malformed message")
	ErrUnsafeXML          = errors.New("saml: document type declarations, entities, comments and processing instructions are not accepted")
	ErrTooLarge           = errors.New("saml: message exceeds the size limit")
	ErrDuplicateID        = errors.New("saml: duplicate ID attribute")
	ErrNoSignature        = errors.New("saml: the element is not signed")
	ErrAmbiguousSignature = errors.New("saml: more than one signature references the element")
	ErrSignature          = errors.New("saml: signature verification failed")
	ErrWeakAlgorithm      = errors.New("saml: algorithm below the cryptographic floor")
)

// Limits bound the resources one inbound message may use (SAML-004,
// TEST-051). They are checked on a streaming pass before any tree is built.
type Limits struct {
	// MaxBytes bounds the decoded (and, for HTTP-Redirect, inflated) document.
	MaxBytes    int
	MaxDepth    int
	MaxElements int
	// MaxAttrs bounds attributes per element.
	MaxAttrs int
}

// DefaultLimits returns the parser limits for a maximum document size.
func DefaultLimits(maxBytes int) Limits {
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	return Limits{MaxBytes: maxBytes, MaxDepth: 32, MaxElements: 4096, MaxAttrs: 64}
}

// Parse checks raw against the limits and the safety rules, then returns the
// root element. It refuses, before building a tree:
//
//   - documents larger than the limit, invalid UTF-8 and non-UTF-8 encodings;
//   - DOCTYPE and every other markup declaration (no DTD, so no external or
//     internal entities: XXE and entity expansion cannot happen), unknown
//     entity references;
//   - comments and processing instructions other than the XML declaration
//     (a comment inside NameID is the classic text-truncation trick);
//   - depth, element and attribute counts over the limits, duplicate
//     attributes on one element, more than one root;
//   - duplicate ID attribute values anywhere in the document, which make the
//     element a signature reference points at ambiguous.
func Parse(raw []byte, lim Limits) (*etree.Element, error) {
	if len(raw) == 0 {
		return nil, ErrMalformed
	}
	if len(raw) > lim.MaxBytes {
		return nil, ErrTooLarge
	}
	if !utf8.Valid(raw) {
		return nil, ErrMalformed
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	depth, elements, roots := 0, 0, 0
	ids := map[string]bool{}
	first := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrMalformed
		}
		switch t := tok.(type) {
		case xml.ProcInst:
			if !first || t.Target != "xml" {
				return nil, ErrUnsafeXML
			}
		case xml.Directive, xml.Comment:
			return nil, ErrUnsafeXML
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return nil, ErrMalformed
				}
			}
			depth++
			elements++
			if depth > lim.MaxDepth || elements > lim.MaxElements || len(t.Attr) > lim.MaxAttrs {
				return nil, ErrTooLarge
			}
			seen := make(map[xml.Name]bool, len(t.Attr))
			for _, a := range t.Attr {
				if seen[a.Name] {
					return nil, ErrMalformed
				}
				seen[a.Name] = true
				if a.Name.Space == "" && a.Name.Local == "ID" {
					if ids[a.Value] {
						return nil, ErrDuplicateID
					}
					ids[a.Value] = true
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return nil, ErrMalformed
			}
		}
		first = false
	}
	if roots != 1 || depth != 0 {
		return nil, ErrMalformed
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, ErrMalformed
	}
	root := doc.Root()
	if root == nil {
		return nil, ErrMalformed
	}
	return root, nil
}

// Is reports whether el is the named element in the namespace (namespace URI,
// never the prefix, which the sender chooses).
func Is(el *etree.Element, ns, local string) bool {
	return el != nil && el.Tag == local && el.NamespaceURI() == ns
}

// Children returns the direct child elements with the name.
func Children(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if Is(c, ns, local) {
			out = append(out, c)
		}
	}
	return out
}

// Child returns the single direct child with the name, nil when absent, and
// an error when the element repeats.
func Child(el *etree.Element, ns, local string) (*etree.Element, error) {
	cs := Children(el, ns, local)
	switch len(cs) {
	case 0:
		return nil, nil
	case 1:
		return cs[0], nil
	}
	return nil, ErrMalformed
}

// RequiredChild is Child for an element that must be present.
func RequiredChild(el *etree.Element, ns, local string) (*etree.Element, error) {
	c, err := Child(el, ns, local)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrMalformed
	}
	return c, nil
}

// Descendants returns every element below el (not el itself) with the name.
func Descendants(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		for _, c := range e.ChildElements() {
			if Is(c, ns, local) {
				out = append(out, c)
			}
			walk(c)
		}
	}
	walk(el)
	return out
}

// Text returns the character content of an element that may hold only text.
// All character data is concatenated (etree's Text() returns only the first
// run, which is how comment-split values are misread), and a child element
// is an error.
func Text(el *etree.Element) (string, error) {
	var sb strings.Builder
	for _, c := range el.Child {
		switch v := c.(type) {
		case *etree.CharData:
			sb.WriteString(v.Data)
		default:
			return "", ErrMalformed
		}
	}
	return strings.TrimSpace(sb.String()), nil
}

// Attr returns an unqualified attribute value.
func Attr(el *etree.Element, name string) string {
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value
		}
	}
	return ""
}

var idPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,255}$`)

// ValidID reports whether v is an acceptable xs:ID value (an NCName subset).
func ValidID(v string) bool { return idPattern.MatchString(v) }

// NewID returns a fresh message identifier (160 random bits; an xs:ID must
// not start with a digit).
func NewID() string { return "_" + hex.EncodeToString(secret.Random(20)) }

// Time formats an xs:dateTime in UTC.
func Time(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ParseTime parses an xs:dateTime that carries a time zone (SAML requires
// UTC; an offset is converted).
func ParseTime(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}, ErrMalformed
	}
	return t.UTC(), nil
}

// Serialize writes an element as a standalone document.
func Serialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	doc.WriteSettings.CanonicalEndTags = false
	return doc.WriteToBytes()
}

// NewElement creates a namespaced element with a prefix.
func NewElement(prefix, local string) *etree.Element {
	return &etree.Element{Space: prefix, Tag: local}
}

// AddChild appends a new prefixed child element.
func AddChild(parent *etree.Element, prefix, local string) *etree.Element {
	c := parent.CreateElement(local)
	c.Space = prefix
	return c
}
