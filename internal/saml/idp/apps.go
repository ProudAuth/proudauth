// Package idp is the SAML 2.0 identity provider profile (APP-018,
// SAML-001..SAML-010): registered service providers ("SAML applications"),
// single sign-on over the HTTP-Redirect and HTTP-POST bindings, a declared
// subset of single logout, and the realm's IdP metadata.
//
// A SAML application is backed by a client record (application.Protocol
// "saml"). Sign-in runs the ordinary authentication transaction for that
// client, so login methods, MFA and step-up, consent and
// pre-authorization, organization policy, sessions, client lifecycle
// (suspension) and audit apply unchanged; the transaction completes with an
// authorization code bound to the realm's own SAML continuation endpoint and
// a server-held PKCE verifier, which this package redeems internally and
// turns into a signed SAML Response.
package idp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authentication"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/saml"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/storage"
)

const appIDPrefix = "sap"

// Defaults.
const (
	defaultSkewSeconds      = 120
	defaultLifetimeSeconds  = 300
	minLifetimeSeconds      = 60
	maxLifetimeSeconds      = 1800
	maxACS                  = 10
	maxSLO                  = 4
	maxAttributes           = 50
	maxSigningCertificates  = 4
	maxAdditionalAudiences  = 5
	maxAuthnContextMappings = 20
)

// Service is the identity provider profile.
type Service struct {
	d        *runtime.Deps
	Keys     *saml.Keys
	Apps     *application.Service
	Auth     *authentication.Service
	Sessions *session.Service
	Users    *identity.Service
	Orgs     *organization.Service
	Limits   saml.Limits
	// MaxSkew bounds per-application clock skew (saml.max_clock_skew).
	MaxSkew time.Duration
}

// New builds the profile.
func New(d *runtime.Deps, keys *saml.Keys, apps *application.Service, auth *authentication.Service, sessions *session.Service,
	users *identity.Service, orgs *organization.Service) *Service {
	return &Service{d: d, Keys: keys, Apps: apps, Auth: auth, Sessions: sessions, Users: users, Orgs: orgs,
		Limits: saml.DefaultLimits(d.Cfg.SAML.MaxMessageBytes), MaxSkew: d.Cfg.SAML.MaxClockSkew}
}

// AttributeMapping releases one attribute (SAML-006). Sources are fixed
// account fields; identity-bearing attribute names are protected.
type AttributeMapping struct {
	Name         string `json:"name"`
	NameFormat   string `json:"name_format,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	// Source is email, email_verified, name, given_name, family_name,
	// preferred_username, locale, zoneinfo, phone_number, user_id, subject,
	// organization_id or static.
	Source string `json:"source"`
	// Value is the value of a static attribute.
	Value string `json:"value,omitempty"`
}

var attributeSources = []string{"email", "email_verified", "name", "given_name", "family_name", "preferred_username", "locale", "zoneinfo",
	"phone_number", "user_id", "subject", "organization_id", "static"}

// Protected attribute names (SAML-006): names service providers commonly
// key accounts on. They never carry a static value or a user-editable
// profile field: email names come only from the verified email, identifier
// names only from a stable identifier.
var (
	protectedEmailNames = []string{"email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3"}
	protectedIdentifierNames = []string{"uid", "sub", "nameid", "upn", "eppn", "user_id", "userid",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
		"http://schemas.microsoft.com/identity/claims/objectidentifier", "urn:oid:0.9.2342.19200300.100.1.1",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", "urn:oid:1.3.6.1.4.1.5923.1.1.1.13"}
)

// Settings are an application's protocol settings.
type Settings struct {
	ACS []saml.Endpoint `json:"assertion_consumer_services"`
	SLO []saml.Endpoint `json:"single_logout_services"`
	// SigningCertificates verify the service provider's signed requests;
	// several may be listed for an overlapping rollover (SAML-002).
	SigningCertificates   []string           `json:"signing_certificates"`
	RequireSignedRequests bool               `json:"require_signed_requests"`
	NameIDFormat          string             `json:"name_id_format"`
	Attributes            []AttributeMapping `json:"attributes"`
	SignResponse          bool               `json:"sign_response"`
	SignAssertion         bool               `json:"sign_assertion"`
	SignatureAlgorithm    string             `json:"signature_algorithm"`
	// AllowIdPInitiated permits unsolicited responses (SAML-007), always to
	// the default ACS and with the registered RelayState only.
	AllowIdPInitiated        bool              `json:"allow_idp_initiated"`
	IdPInitiatedRelayState   string            `json:"idp_initiated_relay_state,omitempty"`
	ClockSkewSeconds         int               `json:"clock_skew_seconds"`
	AssertionLifetimeSeconds int               `json:"assertion_lifetime_seconds"`
	AdditionalAudiences      []string          `json:"additional_audiences"`
	AuthnContextMap          map[string]string `json:"authn_context_map,omitempty"`
	// EncryptAssertions encrypts assertions to EncryptionCertificate (after
	// signing them) with AES-GCM and RSA-OAEP only (SAML-009).
	EncryptAssertions       bool   `json:"encrypt_assertions"`
	EncryptionCertificate   string `json:"encryption_certificate,omitempty"`
	DataEncryptionAlgorithm string `json:"data_encryption_algorithm,omitempty"`
	KeyTransportAlgorithm   string `json:"key_transport_algorithm,omitempty"`
}

// App is a registered SAML service provider.
type App struct {
	ID                   string `json:"id"`
	EntityID             string `json:"entity_id"`
	Name                 string `json:"name"`
	Description          string `json:"description,omitempty"`
	OrganizationID       string `json:"organization_id,omitempty"`
	ProjectID            string `json:"project_id,omitempty"`
	Environment          string `json:"environment"`
	ClientRef            string `json:"client_ref"`
	ClientID             string `json:"client_id"`
	State                string `json:"state"`
	FirstParty           bool   `json:"first_party"`
	ConsentMode          string `json:"consent_mode"`
	ConsentTermsVersion  string `json:"consent_terms_version,omitempty"`
	RequireMFA           bool   `json:"require_mfa"`
	MaxSessionAgeSeconds int    `json:"max_session_age_seconds,omitempty"`
	AllowRememberMe      bool   `json:"allow_remember_me"`
	LoginUIURL           string `json:"login_ui_url,omitempty"`
	Settings
	// SigningCertificates and EncryptionCertificate shadow the PEM values
	// with certificate details.
	SigningCertificates   []saml.CertificateInfo `json:"signing_certificates"`
	EncryptionCertificate *saml.CertificateInfo  `json:"encryption_certificate,omitempty"`
	IdentityProvider      Endpoints              `json:"identity_provider"`
	Version               int64                  `json:"version"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`

	client *application.Client
}

// Endpoints are this realm's identity provider endpoints.
type Endpoints struct {
	EntityID    string `json:"entity_id"`
	MetadataURL string `json:"metadata_url"`
	SSOURL      string `json:"sso_url"`
	SLOURL      string `json:"slo_url"`
}

// Input creates or replaces an application. MetadataXML, when given,
// supplies the entity ID, endpoints and certificates not set explicitly.
type Input struct {
	EntityID              string             `json:"entity_id"`
	Name                  string             `json:"name"`
	Description           string             `json:"description"`
	OrganizationID        string             `json:"organization_id"`
	ProjectID             string             `json:"project_id"`
	Environment           string             `json:"environment"`
	MetadataXML           string             `json:"metadata_xml"`
	ACS                   []saml.Endpoint    `json:"assertion_consumer_services"`
	SLO                   []saml.Endpoint    `json:"single_logout_services"`
	SigningCertificates   []string           `json:"signing_certificates"`
	EncryptionCertificate string             `json:"encryption_certificate"`
	EncryptAssertions     bool               `json:"encrypt_assertions"`
	DataEncryption        string             `json:"data_encryption_algorithm"`
	KeyTransport          string             `json:"key_transport_algorithm"`
	RequireSignedRequests *bool              `json:"require_signed_requests"`
	NameIDFormat          string             `json:"name_id_format"`
	Attributes            []AttributeMapping `json:"attributes"`
	SignResponse          *bool              `json:"sign_response"`
	SignAssertion         *bool              `json:"sign_assertion"`
	SignatureAlgorithm    string             `json:"signature_algorithm"`
	AllowIdPInitiated     bool               `json:"allow_idp_initiated"`
	IdPInitiatedRelay     string             `json:"idp_initiated_relay_state"`
	ClockSkewSeconds      int                `json:"clock_skew_seconds"`
	AssertionLifetime     int                `json:"assertion_lifetime_seconds"`
	AdditionalAudiences   []string           `json:"additional_audiences"`
	AuthnContextMap       map[string]string  `json:"authn_context_map"`
	FirstParty            bool               `json:"first_party"`
	ConsentMode           string             `json:"consent_mode"`
	ConsentTermsVersion   string             `json:"consent_terms_version"`
	RequireMFA            bool               `json:"require_mfa"`
	MaxSessionAgeSeconds  int                `json:"max_session_age_seconds"`
	AllowRememberMe       bool               `json:"allow_remember_me"`
	LoginUIURL            string             `json:"login_ui_url"`
}

// IdPEndpoints returns the realm's identity provider endpoints. The entity
// ID is the realm issuer, as for OpenID Connect.
func (s *Service) IdPEndpoints(rlm *realm.Realm) Endpoints {
	base := s.d.Cfg.Issuer(rlm.Name)
	return Endpoints{EntityID: base, MetadataURL: base + "/saml/metadata", SSOURL: base + "/saml/sso", SLOURL: base + "/saml/slo"}
}

func (s *Service) continueURL(rlm *realm.Realm) string {
	return s.d.Cfg.Issuer(rlm.Name) + "/saml/sso/continue"
}

func (s *Service) validate(ctx context.Context, q storage.Querier, rlm *realm.Realm, in *Input) (*Settings, error) {
	verr := problem.ErrValidation
	now := s.d.Now()
	if in.Environment == "" && in.ProjectID != "" {
		_ = q.QueryRow(ctx, `SELECT environment FROM projects WHERE realm_id=$1 AND id=$2`, rlm.ID, in.ProjectID).Scan(&in.Environment)
	}
	if in.Environment == "" {
		in.Environment = "production"
	}
	if in.MetadataXML != "" {
		md, err := saml.ParseSPMetadata([]byte(in.MetadataXML), s.Limits)
		if err != nil {
			return nil, verr.WithField("metadata_xml", "not usable service provider metadata: "+err.Error())
		}
		if in.EntityID == "" {
			in.EntityID = md.EntityID
		} else if in.EntityID != md.EntityID {
			return nil, verr.WithField("entity_id", "differs from the metadata's entityID")
		}
		if len(in.ACS) == 0 {
			for _, ep := range md.ACS {
				// Responses go only over HTTP-POST; other bindings are skipped.
				if ep.Binding == saml.BindingPOST {
					in.ACS = append(in.ACS, ep)
				}
			}
		}
		if len(in.SLO) == 0 {
			for _, ep := range md.SLO {
				if ep.Binding == saml.BindingPOST || ep.Binding == saml.BindingRedirect {
					in.SLO = append(in.SLO, ep)
				}
			}
		}
		if len(in.SigningCertificates) == 0 {
			for _, c := range md.SigningCerts {
				in.SigningCertificates = append(in.SigningCertificates, saml.CertificatePEM(c))
			}
		}
		if in.RequireSignedRequests == nil && md.AuthnRequestsSigned {
			t := true
			in.RequireSignedRequests = &t
		}
		// A published encryption key is used only when the administrator
		// asks for encrypted assertions.
		if in.EncryptAssertions && in.EncryptionCertificate == "" && len(md.EncryptionCerts) > 0 {
			in.EncryptionCertificate = saml.CertificatePEM(md.EncryptionCerts[0])
		}
	}
	if !saml.ValidEntityID(in.EntityID) {
		return nil, verr.WithField("entity_id", "required: an absolute URI of at most 1024 characters")
	}
	out := &Settings{AdditionalAudiences: []string{}}
	if len(in.ACS) == 0 || len(in.ACS) > maxACS {
		return nil, verr.WithField("assertion_consumer_services", "1..10 HTTP-POST endpoints are required")
	}
	indexes := map[int]bool{}
	allZero := !slices.ContainsFunc(in.ACS, func(e saml.Endpoint) bool { return e.Index != 0 })
	defaults := 0
	for i, ep := range in.ACS {
		if ep.Binding == "" {
			ep.Binding = saml.BindingPOST
		}
		if ep.Binding != saml.BindingPOST {
			// The Web SSO profile forbids HTTP-Redirect for responses, and the
			// artifact binding is not implemented (SAML-005).
			return nil, verr.WithField("assertion_consumer_services", "only the HTTP-POST binding is supported for assertion consumers")
		}
		if msg := application.ValidateRedirectRegistration(ep.URL, application.TypeConfidential, in.Environment); msg != "" {
			return nil, verr.WithField("assertion_consumer_services", msg+": "+ep.URL)
		}
		if allZero {
			ep.Index = i
		}
		if ep.Index < 0 || ep.Index > 65535 || indexes[ep.Index] {
			return nil, verr.WithField("assertion_consumer_services", "indexes must be unique numbers in 0..65535")
		}
		indexes[ep.Index] = true
		if ep.Default {
			defaults++
		}
		ep.ResponseURL = ""
		out.ACS = append(out.ACS, ep)
	}
	if defaults > 1 {
		return nil, verr.WithField("assertion_consumer_services", "at most one default endpoint")
	}
	if defaults == 0 {
		out.ACS[0].Default = true
	}
	if len(in.SLO) > maxSLO {
		return nil, verr.WithField("single_logout_services", "at most 4 endpoints")
	}
	for _, ep := range in.SLO {
		if ep.Binding != saml.BindingPOST && ep.Binding != saml.BindingRedirect {
			return nil, verr.WithField("single_logout_services", "HTTP-Redirect or HTTP-POST")
		}
		for _, u := range []string{ep.URL, ep.ResponseURL} {
			if u == "" {
				continue
			}
			if msg := application.ValidateRedirectRegistration(u, application.TypeConfidential, in.Environment); msg != "" {
				return nil, verr.WithField("single_logout_services", msg+": "+u)
			}
		}
		if ep.URL == "" {
			return nil, verr.WithField("single_logout_services", "url is required")
		}
		ep.Index, ep.Default = 0, false
		out.SLO = append(out.SLO, ep)
	}
	certs, err := saml.ParseCertificates(in.SigningCertificates, maxSigningCertificates, now)
	if err != nil {
		return nil, verr.WithField("signing_certificates", err.Error())
	}
	for _, c := range certs {
		out.SigningCertificates = append(out.SigningCertificates, saml.CertificatePEM(c))
	}
	out.RequireSignedRequests = len(certs) > 0
	if in.RequireSignedRequests != nil {
		out.RequireSignedRequests = *in.RequireSignedRequests
	}
	if out.RequireSignedRequests && len(certs) == 0 {
		return nil, verr.WithField("signing_certificates", "required when signed requests are required")
	}
	if len(out.SLO) > 0 && len(certs) == 0 {
		// Logout requests must be signed (SAML-008): without the service
		// provider's key nobody could tell its logout from a forged one.
		return nil, verr.WithField("signing_certificates", "single logout requires the service provider's signing certificate")
	}
	out.NameIDFormat = in.NameIDFormat
	if out.NameIDFormat == "" {
		out.NameIDFormat = saml.NameIDPersistent
	}
	if !slices.Contains(saml.NameIDFormats, out.NameIDFormat) {
		return nil, verr.WithField("name_id_format", "one of "+strings.Join(saml.NameIDFormats, ", "))
	}
	if out.Attributes, err = validateAttributes(in.Attributes); err != nil {
		return nil, err
	}
	out.SignResponse, out.SignAssertion = true, true
	if in.SignResponse != nil {
		out.SignResponse = *in.SignResponse
	}
	if in.SignAssertion != nil {
		out.SignAssertion = *in.SignAssertion
	}
	if !out.SignResponse && !out.SignAssertion {
		return nil, verr.WithField("sign_assertion", "the response, the assertion or both must be signed")
	}
	out.SignatureAlgorithm = in.SignatureAlgorithm
	if out.SignatureAlgorithm == "" {
		out.SignatureAlgorithm = saml.SigRSASHA256
	}
	if _, ok := saml.SignatureAlgorithms[out.SignatureAlgorithm]; !ok {
		// SAML-009: no SHA-1, no deprecated methods, no exception.
		return nil, verr.WithField("signature_algorithm", "rsa-sha256, rsa-sha384 or rsa-sha512 (xmldsig-more URIs)")
	}
	out.AllowIdPInitiated = in.AllowIdPInitiated
	if in.IdPInitiatedRelay != "" {
		if !in.AllowIdPInitiated {
			return nil, verr.WithField("idp_initiated_relay_state", "only with allow_idp_initiated")
		}
		if len(in.IdPInitiatedRelay) > saml.MaxRelayState {
			return nil, verr.WithField("idp_initiated_relay_state", "at most 1024 bytes")
		}
	}
	out.IdPInitiatedRelayState = in.IdPInitiatedRelay
	out.ClockSkewSeconds = in.ClockSkewSeconds
	if out.ClockSkewSeconds == 0 {
		out.ClockSkewSeconds = defaultSkewSeconds
	}
	if out.ClockSkewSeconds < 0 || time.Duration(out.ClockSkewSeconds)*time.Second > s.MaxSkew {
		return nil, verr.WithField("clock_skew_seconds", "between 0 and saml.max_clock_skew")
	}
	out.AssertionLifetimeSeconds = in.AssertionLifetime
	if out.AssertionLifetimeSeconds == 0 {
		out.AssertionLifetimeSeconds = defaultLifetimeSeconds
	}
	if out.AssertionLifetimeSeconds < minLifetimeSeconds || out.AssertionLifetimeSeconds > maxLifetimeSeconds {
		return nil, verr.WithField("assertion_lifetime_seconds", "between 60 and 1800")
	}
	if len(in.AdditionalAudiences) > maxAdditionalAudiences {
		return nil, verr.WithField("additional_audiences", "at most 5")
	}
	for _, a := range in.AdditionalAudiences {
		if !saml.ValidEntityID(a) {
			return nil, verr.WithField("additional_audiences", "absolute URIs")
		}
		if a != in.EntityID && !slices.Contains(out.AdditionalAudiences, a) {
			out.AdditionalAudiences = append(out.AdditionalAudiences, a)
		}
	}
	if len(in.AuthnContextMap) > maxAuthnContextMappings {
		return nil, verr.WithField("authn_context_map", "at most 20 entries")
	}
	for k, v := range in.AuthnContextMap {
		if !saml.ValidEntityID(k) || len(k) > 256 {
			return nil, verr.WithField("authn_context_map", "keys are AuthnContextClassRef URIs")
		}
		if session.ACRRank(v) == 0 {
			return nil, verr.WithField("authn_context_map", "values are local assurance profiles (urn:proudauth:acr:...)")
		}
	}
	if len(in.AuthnContextMap) > 0 {
		out.AuthnContextMap = in.AuthnContextMap
	}
	if err := validateEncryption(in, out, now); err != nil {
		return nil, err
	}
	if in.OrganizationID != "" {
		if _, err := s.Orgs.Get(ctx, q, rlm.ID, in.OrganizationID); err != nil {
			return nil, verr.WithField("organization_id", "unknown organization")
		}
	}
	return out, nil
}

// validateEncryption applies the encryption choices: an explicit decision,
// a usable RSA certificate, and authenticated algorithms only.
func validateEncryption(in *Input, out *Settings, now time.Time) error {
	verr := problem.ErrValidation
	if !in.EncryptAssertions {
		if in.EncryptionCertificate != "" || in.DataEncryption != "" || in.KeyTransport != "" {
			return verr.WithField("encrypt_assertions", "set encrypt_assertions to encrypt assertions with this certificate")
		}
		return nil
	}
	if in.EncryptionCertificate == "" {
		return verr.WithField("encryption_certificate", "required to encrypt assertions")
	}
	certs, err := saml.ParseCertificates([]string{in.EncryptionCertificate}, 1, now)
	if err != nil {
		return verr.WithField("encryption_certificate", err.Error())
	}
	out.EncryptAssertions = true
	out.EncryptionCertificate = saml.CertificatePEM(certs[0])
	out.DataEncryptionAlgorithm, out.KeyTransportAlgorithm = in.DataEncryption, in.KeyTransport
	if out.DataEncryptionAlgorithm == "" {
		out.DataEncryptionAlgorithm = saml.EncAES256GCM
	}
	if out.KeyTransportAlgorithm == "" {
		out.KeyTransportAlgorithm = saml.KeyRSAOAEPMGF1P
	}
	if !slices.Contains(saml.EncryptionAlgorithms, out.DataEncryptionAlgorithm) {
		// AES-CBC is refused (SAML-009): it is open to padding-oracle attacks.
		return verr.WithField("data_encryption_algorithm", "aes256-gcm or aes128-gcm (xmlenc11)")
	}
	if !slices.Contains(saml.KeyTransportAlgorithms, out.KeyTransportAlgorithm) {
		// RSA PKCS#1 v1.5 key transport is refused (SAML-009).
		return verr.WithField("key_transport_algorithm", "rsa-oaep-mgf1p or xmlenc11 rsa-oaep")
	}
	return nil
}

func protectedClass(name string) string {
	n := strings.ToLower(name)
	switch {
	case slices.Contains(protectedEmailNames, n):
		return "email"
	case slices.Contains(protectedIdentifierNames, n):
		return "identifier"
	}
	return ""
}

func validateAttributes(in []AttributeMapping) ([]AttributeMapping, error) {
	verr := problem.ErrValidation
	if len(in) > maxAttributes {
		return nil, verr.WithField("attributes", "at most 50 attributes")
	}
	out := []AttributeMapping{}
	seen := map[string]bool{}
	for _, m := range in {
		if m.Name == "" || len(m.Name) > 256 || strings.ContainsFunc(m.Name, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			return nil, verr.WithField("attributes", "names are 1..256 printable characters")
		}
		key := strings.ToLower(m.Name)
		if seen[key] {
			return nil, verr.WithField("attributes", "attribute "+m.Name+" is mapped twice")
		}
		seen[key] = true
		if m.NameFormat == "" {
			m.NameFormat = saml.AttrNameFormatBasic
			if strings.Contains(m.Name, ":") {
				m.NameFormat = saml.AttrNameFormatURI
			}
		}
		if m.NameFormat != saml.AttrNameFormatBasic && m.NameFormat != saml.AttrNameFormatURI && m.NameFormat != saml.AttrNameFormatUnspecified {
			return nil, verr.WithField("attributes", "name_format is the basic, uri or unspecified attribute name format")
		}
		if len(m.FriendlyName) > 128 {
			return nil, verr.WithField("attributes", "friendly_name is at most 128 characters")
		}
		if !slices.Contains(attributeSources, m.Source) {
			return nil, verr.WithField("attributes", "source is one of "+strings.Join(attributeSources, ", "))
		}
		if (m.Source == "static") != (m.Value != "") || len(m.Value) > 512 {
			return nil, verr.WithField("attributes", "value (at most 512 characters) is set exactly for static attributes")
		}
		switch protectedClass(m.Name) {
		case "email":
			if m.Source != "email" {
				return nil, verr.WithField("attributes", m.Name+" is protected: it can only carry the verified email")
			}
		case "identifier":
			if m.Source != "user_id" && m.Source != "subject" && m.Source != "email" && m.Source != "preferred_username" {
				return nil, verr.WithField("attributes", m.Name+" is protected: it can only carry a stable identifier (user_id, subject, email, preferred_username)")
			}
		}
		out = append(out, m)
	}
	return out, nil
}

const appCols = `id, entity_id, coalesce(organization_id,''), client_ref, config, version, created_at, updated_at`

func (s *Service) scanApp(ctx context.Context, q storage.Querier, rlm *realm.Realm, row pgx.Row) (*App, error) {
	a := &App{}
	var cfg []byte
	if err := row.Scan(&a.ID, &a.EntityID, &a.OrganizationID, &a.ClientRef, &cfg, &a.Version, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(cfg, &a.Settings); err != nil {
		return nil, err
	}
	c, err := s.Apps.ClientByRef(ctx, q, rlm.ID, a.ClientRef)
	if err != nil {
		return nil, err
	}
	a.client = c
	a.ClientID, a.Name, a.Description, a.State, a.FirstParty, a.ConsentMode = c.ClientID, c.Name, c.Description, c.State, c.FirstParty, c.ConsentMode
	a.ConsentTermsVersion, a.RequireMFA, a.MaxSessionAgeSeconds = c.ConsentTermsVersion, c.TokenPolicy.RequireMFA, c.TokenPolicy.MaxSessionAgeSeconds
	a.AllowRememberMe, a.LoginUIURL, a.Environment, a.ProjectID = c.AllowRememberMe, c.LoginUIURL, c.Environment, c.ProjectID
	a.SigningCertificates = []saml.CertificateInfo{}
	for _, c := range a.certificates() {
		a.SigningCertificates = append(a.SigningCertificates, saml.Describe(c))
	}
	if c, err := saml.ParseCertificate(a.Settings.EncryptionCertificate); err == nil {
		info := saml.Describe(c)
		a.EncryptionCertificate = &info
	}
	if a.Attributes == nil {
		a.Attributes = []AttributeMapping{}
	}
	if a.SLO == nil {
		a.SLO = []saml.Endpoint{}
	}
	if a.AdditionalAudiences == nil {
		a.AdditionalAudiences = []string{}
	}
	a.IdentityProvider = s.IdPEndpoints(rlm)
	return a, nil
}

// Get returns an application by ID.
func (s *Service) Get(ctx context.Context, q storage.Querier, rlm *realm.Realm, id string) (*App, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	return s.scanApp(ctx, q, rlm, q.QueryRow(ctx, `SELECT `+appCols+` FROM saml_service_providers WHERE realm_id=$1 AND id=$2`, rlm.ID, id))
}

// ByEntityID returns the application registered for an entity ID.
func (s *Service) ByEntityID(ctx context.Context, q storage.Querier, rlm *realm.Realm, entityID string) (*App, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	if entityID == "" || len(entityID) > 1024 {
		return nil, problem.ErrNotFound
	}
	return s.scanApp(ctx, q, rlm, q.QueryRow(ctx, `SELECT `+appCols+` FROM saml_service_providers WHERE realm_id=$1 AND entity_id=$2`, rlm.ID, entityID))
}

// List returns the realm's applications.
func (s *Service) List(ctx context.Context, rlm *realm.Realm) ([]*App, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id FROM saml_service_providers WHERE realm_id=$1 ORDER BY created_at, id`, rlm.ID)
	if err != nil {
		return nil, err
	}
	var idList []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		idList = append(idList, id)
	}
	rows.Close()
	out := []*App{}
	for _, id := range idList {
		a, err := s.Get(ctx, nil, rlm, id)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (in *Input) clientInput(continueURL string) application.SAMLClientInput {
	return application.SAMLClientInput{Name: in.Name, Description: in.Description, ProjectID: in.ProjectID, Environment: in.Environment,
		FirstParty: in.FirstParty, ConsentMode: in.ConsentMode, ConsentTermsVersion: in.ConsentTermsVersion, LoginUIURL: in.LoginUIURL,
		RequireMFA: in.RequireMFA, MaxSessionAgeSeconds: in.MaxSessionAgeSeconds, AllowRememberMe: in.AllowRememberMe, ContinueURI: continueURL}
}

func certFingerprints(pems []string) []string {
	out := []string{}
	for _, p := range pems {
		if c, err := saml.ParseCertificate(p); err == nil {
			out = append(out, saml.Fingerprint(c))
		}
	}
	return out
}

func attributeNames(list []AttributeMapping) []string {
	out := []string{}
	for _, m := range list {
		out = append(out, m.Name+"<-"+m.Source)
	}
	return out
}

// Create registers an application and its backing client.
func (s *Service) Create(ctx context.Context, rlm *realm.Realm, in Input, actor audit.Ref) (*App, error) {
	var out *App
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		set, err := s.validate(ctx, tx, rlm, &in)
		if err != nil {
			return err
		}
		client, err := s.Apps.CreateSAMLClientTx(ctx, tx, rlm.ID, in.clientInput(s.continueURL(rlm)), actor)
		if err != nil {
			return err
		}
		id := ids.New(appIDPrefix)
		cfg, _ := json.Marshal(set)
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO saml_service_providers (id, realm_id, client_ref, entity_id, organization_id, config, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, id, rlm.ID, client.Ref, in.EntityID, nilIfEmpty(in.OrganizationID), cfg, now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("entity_id", "a service provider with this entity ID is already registered")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.application.created", RealmID: rlm.ID, OrgID: in.OrganizationID, Actor: actor,
			Target: &audit.Ref{Type: "saml_application", ID: id}, ClientID: client.ClientID, Category: "application",
			Metadata: map[string]any{"entity_id": in.EntityID, "client_ref": client.Ref, "signing_certificates": certFingerprints(set.SigningCertificates),
				"name_id_format": set.NameIDFormat, "attributes": attributeNames(set.Attributes), "allow_idp_initiated": set.AllowIdPInitiated,
				"require_signed_requests": set.RequireSignedRequests}}); err != nil {
			return err
		}
		out, err = s.Get(ctx, tx, rlm, id)
		return err
	})
	return out, err
}

// Update replaces an application (optimistic concurrency). Certificate and
// attribute changes are audited (SAML-002, SAML-006).
func (s *Service) Update(ctx context.Context, rlm *realm.Realm, id string, version int64, in Input, actor audit.Ref) (*App, error) {
	var out *App
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := s.scanApp(ctx, tx, rlm, tx.QueryRow(ctx, `SELECT `+appCols+` FROM saml_service_providers WHERE realm_id=$1 AND id=$2 FOR UPDATE`, rlm.ID, id))
		if err != nil {
			return err
		}
		if version != 0 && cur.Version != version {
			return problem.ErrPrecondition
		}
		if in.Environment == "" {
			in.Environment = cur.Environment
		}
		set, err := s.validate(ctx, tx, rlm, &in)
		if err != nil {
			return err
		}
		if _, err := s.Apps.UpdateSAMLClientTx(ctx, tx, rlm.ID, cur.ClientRef, in.clientInput(s.continueURL(rlm)), actor); err != nil {
			return err
		}
		cfg, _ := json.Marshal(set)
		if _, err := tx.Exec(ctx, `UPDATE saml_service_providers SET entity_id=$3, organization_id=$4, config=$5, version=version+1, updated_at=$6
			WHERE realm_id=$1 AND id=$2`, rlm.ID, id, in.EntityID, nilIfEmpty(in.OrganizationID), cfg, s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("entity_id", "a service provider with this entity ID is already registered")
			}
			return err
		}
		before, after := certFingerprints(cur.Settings.SigningCertificates), certFingerprints(set.SigningCertificates)
		added, removed := []string{}, []string{}
		for _, f := range after {
			if !slices.Contains(before, f) {
				added = append(added, f)
			}
		}
		for _, f := range before {
			if !slices.Contains(after, f) {
				removed = append(removed, f)
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.application.updated", RealmID: rlm.ID, OrgID: in.OrganizationID, Actor: actor,
			Target: &audit.Ref{Type: "saml_application", ID: id}, ClientID: cur.ClientID, Category: "application",
			Metadata: map[string]any{"entity_id": in.EntityID, "previous_entity_id": cur.EntityID, "signing_certificates_added": added,
				"signing_certificates_removed": removed, "name_id_format": set.NameIDFormat, "attributes": attributeNames(set.Attributes),
				"allow_idp_initiated": set.AllowIdPInitiated, "version": cur.Version + 1}}); err != nil {
			return err
		}
		out, err = s.Get(ctx, tx, rlm, id)
		return err
	})
	return out, err
}

// Delete removes an application and decommissions its backing client, which
// revokes the grants made to it (APP-008). The entity ID becomes free.
func (s *Service) Delete(ctx context.Context, rlm *realm.Realm, id string, actor audit.Ref) error {
	var clientRef string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var entityID string
		if err := tx.QueryRow(ctx, `DELETE FROM saml_service_providers WHERE realm_id=$1 AND id=$2 RETURNING client_ref, entity_id`, rlm.ID, id).
			Scan(&clientRef, &entityID); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.application.deleted", RealmID: rlm.ID, Actor: actor,
			Target: &audit.Ref{Type: "saml_application", ID: id}, Category: "application", Metadata: map[string]any{"entity_id": entityID, "client_ref": clientRef}})
		return err
	})
	if err != nil {
		return err
	}
	if err := s.Apps.SetClientState(ctx, rlm.ID, clientRef, "decommissioned", actor, "saml_application_deleted"); err != nil && !problem.Is(err, problem.ErrConflict) {
		return err
	}
	return nil
}

func (a *App) certificates() []*x509.Certificate {
	out := []*x509.Certificate{}
	for _, p := range a.Settings.SigningCertificates {
		if c, err := saml.ParseCertificate(p); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// defaultACS returns the default assertion consumer service.
func (a *App) defaultACS() saml.Endpoint {
	for _, ep := range a.ACS {
		if ep.Default {
			return ep
		}
	}
	return a.ACS[0]
}

// scopes are the consent scopes that describe what the application
// receives: the subject identifier always, plus the attribute groups its
// mappings release.
func (a *App) scopes() []string {
	out := []string{"openid"}
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if a.NameIDFormat == saml.NameIDEmail {
		add("email")
	}
	for _, m := range a.Attributes {
		switch m.Source {
		case "email", "email_verified":
			add("email")
		case "name", "given_name", "family_name", "preferred_username", "locale", "zoneinfo":
			add("profile")
		case "phone_number":
			add("phone")
		}
	}
	return out
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
