package saml

import (
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/beevik/etree"
)

// Endpoint is a metadata endpoint.
type Endpoint struct {
	Binding     string `json:"binding"`
	URL         string `json:"url"`
	ResponseURL string `json:"response_url,omitempty"`
	Index       int    `json:"index,omitempty"`
	Default     bool   `json:"is_default,omitempty"`
}

// IdPDescriptor describes an identity provider: this realm's (published) or
// an upstream one (parsed from uploaded metadata).
type IdPDescriptor struct {
	EntityID                string
	SSO                     []Endpoint
	SLO                     []Endpoint
	SigningCerts            []*x509.Certificate
	NameIDFormats           []string
	WantAuthnRequestsSigned bool
}

// SPDescriptor describes a service provider: one registered with this realm
// (parsed from uploaded metadata) or a broker connection (published).
type SPDescriptor struct {
	EntityID             string
	ACS                  []Endpoint
	SLO                  []Endpoint
	SigningCerts         []*x509.Certificate
	EncryptionCerts      []*x509.Certificate
	NameIDFormats        []string
	AuthnRequestsSigned  bool
	WantAssertionsSigned bool
}

func newMetadataRoot(entityID string) *etree.Element {
	root := NewElement("md", "EntityDescriptor")
	root.CreateAttr("xmlns:md", NSMetadata)
	root.CreateAttr("xmlns:ds", NSDSig)
	root.CreateAttr("entityID", entityID)
	return root
}

func addKeys(parent *etree.Element, use string, certs []*x509.Certificate) {
	for _, c := range certs {
		kd := AddChild(parent, "md", "KeyDescriptor")
		kd.CreateAttr("use", use)
		ki := AddChild(kd, "ds", "KeyInfo")
		xd := AddChild(ki, "ds", "X509Data")
		AddChild(xd, "ds", "X509Certificate").SetText(base64.StdEncoding.EncodeToString(c.Raw))
	}
}

func addEndpoints(parent *etree.Element, tag string, eps []Endpoint, indexed bool) {
	for _, ep := range eps {
		e := AddChild(parent, "md", tag)
		e.CreateAttr("Binding", ep.Binding)
		e.CreateAttr("Location", ep.URL)
		if ep.ResponseURL != "" {
			e.CreateAttr("ResponseLocation", ep.ResponseURL)
		}
		if indexed {
			e.CreateAttr("index", strconv.Itoa(ep.Index))
			if ep.Default {
				e.CreateAttr("isDefault", "true")
			}
		}
	}
}

// IdPMetadata renders identity provider metadata. Only what is implemented
// is declared (SAML-005, APP-020): the HTTP-Redirect and HTTP-POST bindings,
// no artifact resolution, no attribute authority, no encryption key.
func IdPMetadata(d IdPDescriptor) ([]byte, error) {
	root := newMetadataRoot(d.EntityID)
	idp := AddChild(root, "md", "IDPSSODescriptor")
	idp.CreateAttr("protocolSupportEnumeration", NSProtocol)
	idp.CreateAttr("WantAuthnRequestsSigned", strconv.FormatBool(d.WantAuthnRequestsSigned))
	addKeys(idp, "signing", d.SigningCerts)
	addEndpoints(idp, "SingleLogoutService", d.SLO, false)
	for _, f := range d.NameIDFormats {
		AddChild(idp, "md", "NameIDFormat").SetText(f)
	}
	addEndpoints(idp, "SingleSignOnService", d.SSO, false)
	return Serialize(root)
}

// SPMetadata renders service provider metadata for a broker connection.
func SPMetadata(d SPDescriptor) ([]byte, error) {
	root := newMetadataRoot(d.EntityID)
	sp := AddChild(root, "md", "SPSSODescriptor")
	sp.CreateAttr("protocolSupportEnumeration", NSProtocol)
	sp.CreateAttr("AuthnRequestsSigned", strconv.FormatBool(d.AuthnRequestsSigned))
	sp.CreateAttr("WantAssertionsSigned", strconv.FormatBool(d.WantAssertionsSigned))
	addKeys(sp, "signing", d.SigningCerts)
	addEndpoints(sp, "SingleLogoutService", d.SLO, false)
	for _, f := range d.NameIDFormats {
		AddChild(sp, "md", "NameIDFormat").SetText(f)
	}
	addEndpoints(sp, "AssertionConsumerService", d.ACS, true)
	return Serialize(root)
}

// entity returns the single EntityDescriptor of uploaded metadata. An
// aggregate (EntitiesDescriptor) is refused: each counterparty is registered
// on its own, from its own metadata.
func entity(raw []byte, lim Limits) (*etree.Element, error) {
	root, err := Parse(raw, lim)
	if err != nil {
		return nil, err
	}
	if !Is(root, NSMetadata, "EntityDescriptor") {
		return nil, ErrMalformed
	}
	if Attr(root, "entityID") == "" {
		return nil, ErrMalformed
	}
	return root, nil
}

func parseKeys(desc *etree.Element) (signing, encryption []*x509.Certificate, err error) {
	for _, kd := range Children(desc, NSMetadata, "KeyDescriptor") {
		use := Attr(kd, "use")
		for _, ki := range Children(kd, NSDSig, "KeyInfo") {
			for _, xd := range Children(ki, NSDSig, "X509Data") {
				for _, xc := range Children(xd, NSDSig, "X509Certificate") {
					txt, err := Text(xc)
					if err != nil {
						return nil, nil, err
					}
					c, err := ParseCertificate(txt)
					if err != nil {
						return nil, nil, err
					}
					if use == "" || use == "signing" {
						signing = append(signing, c)
					}
					if use == "" || use == "encryption" {
						encryption = append(encryption, c)
					}
				}
			}
		}
	}
	return signing, encryption, nil
}

func parseEndpoints(desc *etree.Element, tag string) ([]Endpoint, error) {
	var out []Endpoint
	for _, e := range Children(desc, NSMetadata, tag) {
		ep := Endpoint{Binding: Attr(e, "Binding"), URL: Attr(e, "Location"), ResponseURL: Attr(e, "ResponseLocation"),
			Default: Attr(e, "isDefault") == "true"}
		if v := Attr(e, "index"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				return nil, ErrMalformed
			}
			ep.Index = n
		}
		if ep.Binding == "" || ep.URL == "" {
			return nil, ErrMalformed
		}
		out = append(out, ep)
	}
	return out, nil
}

func parseFormats(desc *etree.Element) []string {
	var out []string
	for _, f := range Children(desc, NSMetadata, "NameIDFormat") {
		if v, err := Text(f); err == nil && v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// ParseIdPMetadata reads uploaded identity provider metadata (SAML-002).
// Metadata is never fetched from a URL: the administrator uploads it, and
// its own signature (if any) is not what establishes trust here: the
// authenticated administrator is.
func ParseIdPMetadata(raw []byte, lim Limits) (*IdPDescriptor, error) {
	root, err := entity(raw, lim)
	if err != nil {
		return nil, err
	}
	desc, err := RequiredChild(root, NSMetadata, "IDPSSODescriptor")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(Attr(desc, "protocolSupportEnumeration"), NSProtocol) {
		return nil, ErrMalformed
	}
	out := &IdPDescriptor{EntityID: Attr(root, "entityID"), WantAuthnRequestsSigned: Attr(desc, "WantAuthnRequestsSigned") == "true",
		NameIDFormats: parseFormats(desc)}
	if out.SigningCerts, _, err = parseKeys(desc); err != nil {
		return nil, err
	}
	if out.SSO, err = parseEndpoints(desc, "SingleSignOnService"); err != nil {
		return nil, err
	}
	if out.SLO, err = parseEndpoints(desc, "SingleLogoutService"); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseSPMetadata reads uploaded service provider metadata (APP-018).
func ParseSPMetadata(raw []byte, lim Limits) (*SPDescriptor, error) {
	root, err := entity(raw, lim)
	if err != nil {
		return nil, err
	}
	desc, err := RequiredChild(root, NSMetadata, "SPSSODescriptor")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(Attr(desc, "protocolSupportEnumeration"), NSProtocol) {
		return nil, ErrMalformed
	}
	out := &SPDescriptor{EntityID: Attr(root, "entityID"), AuthnRequestsSigned: Attr(desc, "AuthnRequestsSigned") == "true",
		WantAssertionsSigned: Attr(desc, "WantAssertionsSigned") == "true", NameIDFormats: parseFormats(desc)}
	if out.SigningCerts, out.EncryptionCerts, err = parseKeys(desc); err != nil {
		return nil, err
	}
	if out.ACS, err = parseEndpoints(desc, "AssertionConsumerService"); err != nil {
		return nil, err
	}
	if out.SLO, err = parseEndpoints(desc, "SingleLogoutService"); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidEntityID reports whether v is an acceptable entity identifier: an
// absolute URI (URL or URN) of at most 1024 characters without whitespace.
func ValidEntityID(v string) bool {
	if v == "" || len(v) > 1024 || strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	u, err := url.Parse(v)
	return err == nil && u.Scheme != ""
}
