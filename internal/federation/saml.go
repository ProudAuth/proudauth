package federation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/saml"
	"github.com/proudbase/proudauth/internal/storage"
)

// SAML connections (FED-014): an enterprise SAML identity provider as a
// federation connection. The identity_providers row (kind and adapter
// "saml") carries what every connection kind shares, and is what linking,
// just-in-time provisioning, organization binding and SSO-mandatory
// organizations already use; the SAML protocol settings live in
// saml_connections. The broker acts as a service provider with its own
// metadata per connection (SAML-001).
const (
	KindSAML    = "saml"
	AdapterSAML = "saml"
)

// SAMLSettings is a connection's SAML protocol configuration.
type SAMLSettings struct {
	// IdPEntityID is the trusted issuer; it is also the connection's issuer.
	IdPEntityID string `json:"idp_entity_id"`
	// SSOURL is the identity provider's HTTP-Redirect single sign-on endpoint.
	SSOURL string `json:"sso_url"`
	// SigningCertificates are trusted for response and assertion signatures.
	// Several may be listed at once for an overlapping rollover (SAML-002).
	SigningCertificates []string `json:"signing_certificates"`
	// SPEntityID overrides the default service provider entity ID.
	SPEntityID string `json:"sp_entity_id,omitempty"`
	// SignAuthnRequests signs requests with the realm SAML key.
	SignAuthnRequests bool `json:"sign_authn_requests"`
	// RequireSignedAssertions refuses responses whose assertion is covered
	// only by the response signature.
	RequireSignedAssertions bool   `json:"require_signed_assertions"`
	NameIDFormat            string `json:"name_id_format,omitempty"`
	// SubjectAttribute takes the stable subject from an attribute instead of
	// the NameID (required for transient NameIDs).
	SubjectAttribute string `json:"subject_attribute,omitempty"`
	// EmailAttribute names the email attribute; without it an emailAddress
	// NameID supplies the email.
	EmailAttribute string `json:"email_attribute,omitempty"`
	// TrustEmailVerified treats the asserted email as verified. SAML has no
	// verification flag, so this is an explicit, reviewed trust decision.
	TrustEmailVerified bool `json:"trust_email_verified"`
	// TrustedAuthnContexts are AuthnContextClassRef values accepted as MFA
	// when trust_upstream_mfa is enabled (FED-009).
	TrustedAuthnContexts []string `json:"trusted_authn_contexts,omitempty"`
	// RequestedAuthnContexts are sent as a minimum RequestedAuthnContext.
	RequestedAuthnContexts []string `json:"requested_authn_contexts,omitempty"`
	ForceAuthn             bool     `json:"force_authn,omitempty"`
	ClockSkewSeconds       int      `json:"clock_skew_seconds"`
}

// SAMLConnection is the administrator's view of a SAML connection.
type SAMLConnection struct {
	ID                  string                 `json:"id"`
	OrganizationID      string                 `json:"organization_id,omitempty"`
	Alias               string                 `json:"alias"`
	DisplayName         string                 `json:"display_name"`
	State               string                 `json:"state"`
	LinkingPolicy       string                 `json:"linking_policy"`
	JIT                 bool                   `json:"jit_provisioning"`
	JITDefaultRoleID    string                 `json:"jit_default_role_id,omitempty"`
	TrustUpstreamMFA    bool                   `json:"trust_upstream_mfa"`
	AllowedEmailDomains []string               `json:"allowed_email_domains"`
	ClaimMapping        ClaimMapping           `json:"claim_mapping"`
	SAML                SAMLSettingsView       `json:"saml"`
	ServiceProvider     SAMLServiceProviderURL `json:"service_provider"`
	Version             int64                  `json:"version"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// SAMLSettingsView shows the settings with certificate details.
type SAMLSettingsView struct {
	SAMLSettings
	SigningCertificates []saml.CertificateInfo `json:"signing_certificates"`
}

// SAMLServiceProviderURL is this realm's service provider side of a
// connection: what the identity provider's administrator registers.
type SAMLServiceProviderURL struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"metadata_url"`
}

// SAMLInput creates or replaces a SAML connection. MetadataXML, when given,
// supplies the entity ID, SSO endpoint and certificates that are not set
// explicitly; explicit fields win.
type SAMLInput struct {
	OrganizationID          string        `json:"organization_id,omitempty"`
	Alias                   string        `json:"alias"`
	DisplayName             string        `json:"display_name"`
	MetadataXML             string        `json:"metadata_xml,omitempty"`
	IdPEntityID             string        `json:"idp_entity_id,omitempty"`
	SSOURL                  string        `json:"sso_url,omitempty"`
	SigningCertificates     []string      `json:"signing_certificates,omitempty"`
	SPEntityID              string        `json:"sp_entity_id,omitempty"`
	SignAuthnRequests       *bool         `json:"sign_authn_requests,omitempty"`
	RequireSignedAssertions bool          `json:"require_signed_assertions"`
	NameIDFormat            string        `json:"name_id_format,omitempty"`
	SubjectAttribute        string        `json:"subject_attribute,omitempty"`
	EmailAttribute          string        `json:"email_attribute,omitempty"`
	TrustEmailVerified      bool          `json:"trust_email_verified"`
	TrustedAuthnContexts    []string      `json:"trusted_authn_contexts,omitempty"`
	RequestedAuthnContexts  []string      `json:"requested_authn_contexts,omitempty"`
	ForceAuthn              bool          `json:"force_authn"`
	ClockSkewSeconds        int           `json:"clock_skew_seconds,omitempty"`
	AllowedEmailDomains     []string      `json:"allowed_email_domains,omitempty"`
	LinkingPolicy           string        `json:"linking_policy,omitempty"`
	JIT                     bool          `json:"jit_provisioning"`
	JITDefaultRoleID        string        `json:"jit_default_role_id,omitempty"`
	TrustUpstreamMFA        bool          `json:"trust_upstream_mfa"`
	ClaimMapping            *ClaimMapping `json:"claim_mapping,omitempty"`
	State                   string        `json:"state,omitempty"`
}

// SAMLBroker runs SAML connections: their administration, the AuthnRequest
// and the validation of responses.
type SAMLBroker struct {
	fed    *Service
	keys   *saml.Keys
	limits saml.Limits
	// MaxSkew bounds the per-connection clock skew (saml.max_clock_skew).
	MaxSkew time.Duration
}

// NewSAMLBroker attaches SAML connections to the federation service.
func NewSAMLBroker(fed *Service, keys *saml.Keys) *SAMLBroker {
	b := &SAMLBroker{fed: fed, keys: keys, limits: saml.DefaultLimits(fed.d.Cfg.SAML.MaxMessageBytes), MaxSkew: fed.d.Cfg.SAML.MaxClockSkew}
	fed.SAML = b
	return b
}

const defaultSAMLSkew = 120

// defaultSAMLMapping maps common directory attribute names.
func defaultSAMLMapping() ClaimMapping {
	return ClaimMapping{DisplayName: FieldMapping{Claim: "displayName"}, GivenName: FieldMapping{Claim: "givenName"},
		FamilyName: FieldMapping{Claim: "sn"}}
}

func (b *SAMLBroker) realmBase(realmName string) string {
	return strings.TrimSuffix(b.fed.d.Cfg.Server.PublicOrigin, "/") + "/realms/" + realmName
}

// ServiceProvider returns this realm's service provider identity for a
// connection.
func (b *SAMLBroker) ServiceProvider(realmName string, p *Provider, set *SAMLSettings) SAMLServiceProviderURL {
	base := b.realmBase(realmName) + "/saml/sp/" + p.Alias
	out := SAMLServiceProviderURL{EntityID: base, ACSURL: b.realmBase(realmName) + "/saml/acs/" + p.Alias, MetadataURL: base}
	if set != nil && set.SPEntityID != "" {
		out.EntityID = set.SPEntityID
	}
	return out
}

func (b *SAMLBroker) settings(ctx context.Context, q storage.Querier, p *Provider) (*SAMLSettings, error) {
	if q == nil {
		q = b.fed.d.DB.Pool
	}
	var raw []byte
	if err := q.QueryRow(ctx, `SELECT config FROM saml_connections WHERE provider_id=$1`, p.ID).Scan(&raw); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	var s SAMLSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// certificates parses the trusted certificates (validated when saved).
func (s *SAMLSettings) certificates() []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(s.SigningCertificates))
	for _, pem := range s.SigningCertificates {
		if c, err := saml.ParseCertificate(pem); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func (s *SAMLSettings) skew() time.Duration {
	return time.Duration(s.ClockSkewSeconds) * time.Second
}

func (b *SAMLBroker) view(realmName string, p *Provider, set *SAMLSettings) *SAMLConnection {
	v := &SAMLConnection{ID: p.ID, OrganizationID: p.OrganizationID, Alias: p.Alias, DisplayName: p.DisplayName, State: p.State,
		LinkingPolicy: p.LinkingPolicy, JIT: p.JIT, JITDefaultRoleID: p.JITDefaultRoleID, TrustUpstreamMFA: p.TrustUpstreamMFA,
		AllowedEmailDomains: p.Config.AllowedEmailDomains, ClaimMapping: p.ClaimMapping, Version: p.Version, CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt, ServiceProvider: b.ServiceProvider(realmName, p, set)}
	if v.AllowedEmailDomains == nil {
		v.AllowedEmailDomains = []string{}
	}
	v.SAML.SAMLSettings = *set
	v.SAML.SAMLSettings.SigningCertificates = nil
	v.SAML.SigningCertificates = []saml.CertificateInfo{}
	for _, c := range set.certificates() {
		v.SAML.SigningCertificates = append(v.SAML.SigningCertificates, saml.Describe(c))
	}
	return v
}

// connection loads a SAML connection by ID or alias.
func (b *SAMLBroker) connection(ctx context.Context, q storage.Querier, realmID, ref string) (*Provider, *SAMLSettings, error) {
	p, err := b.fed.Get(ctx, q, realmID, ref)
	if err != nil {
		return nil, nil, err
	}
	if p.Kind != KindSAML {
		return nil, nil, problem.ErrNotFound
	}
	set, err := b.settings(ctx, q, p)
	if err != nil {
		return nil, nil, err
	}
	return p, set, nil
}

// Get returns one SAML connection.
func (b *SAMLBroker) Get(ctx context.Context, realmID, realmName, ref string) (*SAMLConnection, error) {
	p, set, err := b.connection(ctx, nil, realmID, ref)
	if err != nil {
		return nil, err
	}
	return b.view(realmName, p, set), nil
}

// List returns the realm's SAML connections.
func (b *SAMLBroker) List(ctx context.Context, realmID, realmName string) ([]*SAMLConnection, error) {
	all, err := b.fed.List(ctx, nil, realmID, false)
	if err != nil {
		return nil, err
	}
	out := []*SAMLConnection{}
	for _, p := range all {
		if p.Kind != KindSAML {
			continue
		}
		set, err := b.settings(ctx, nil, p)
		if err != nil {
			return nil, err
		}
		out = append(out, b.view(realmName, p, set))
	}
	return out, nil
}

// validate checks a connection definition: the shared federation rules
// (linking, JIT, organization) and the SAML settings, including the
// certificate floor (SAML-002, SAML-009).
func (b *SAMLBroker) validate(ctx context.Context, tx pgx.Tx, realmID string, in *SAMLInput, actor authorization.Subject) (*SAMLSettings, error) {
	verr := problem.ErrValidation
	if slug, ok := canonical.Slug(in.Alias); !ok || slug != in.Alias {
		return nil, verr.WithField("alias", "lower-case letters, digits and dashes (2..63)")
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" || len(in.DisplayName) > 100 {
		return nil, verr.WithField("display_name", "required, at most 100 characters")
	}
	now := b.fed.d.Now()
	if in.MetadataXML != "" {
		md, err := saml.ParseIdPMetadata([]byte(in.MetadataXML), b.limits)
		if err != nil {
			return nil, verr.WithField("metadata_xml", "not usable identity provider metadata: "+err.Error())
		}
		if in.IdPEntityID == "" {
			in.IdPEntityID = md.EntityID
		} else if in.IdPEntityID != md.EntityID {
			return nil, verr.WithField("idp_entity_id", "differs from the metadata's entityID")
		}
		if in.SSOURL == "" {
			for _, ep := range md.SSO {
				if ep.Binding == saml.BindingRedirect {
					in.SSOURL = ep.URL
					break
				}
			}
			if in.SSOURL == "" {
				return nil, verr.WithField("metadata_xml", "the identity provider offers no HTTP-Redirect single sign-on endpoint")
			}
		}
		if len(in.SigningCertificates) == 0 {
			for _, c := range md.SigningCerts {
				in.SigningCertificates = append(in.SigningCertificates, saml.CertificatePEM(c))
			}
		}
		if in.SignAuthnRequests == nil && md.WantAuthnRequestsSigned {
			t := true
			in.SignAuthnRequests = &t
		}
	}
	if !saml.ValidEntityID(in.IdPEntityID) {
		return nil, verr.WithField("idp_entity_id", "required: an absolute URI of at most 1024 characters")
	}
	if in.SPEntityID != "" && !saml.ValidEntityID(in.SPEntityID) {
		return nil, verr.WithField("sp_entity_id", "an absolute URI of at most 1024 characters")
	}
	u, err := url.Parse(in.SSOURL)
	if err != nil || in.SSOURL == "" || len(in.SSOURL) > 2048 || u.Host == "" || u.User != nil || u.Fragment != "" ||
		(u.Scheme != "https" && (u.Scheme != "http" || b.fed.d.Cfg.Mode == "production")) {
		return nil, verr.WithField("sso_url", "required: an absolute https URL")
	}
	if !egress.HostAllowed(u.Hostname()) {
		return nil, verr.WithField("sso_url", "outside the deployment's destination residency policy")
	}
	certs, err := saml.ParseCertificates(in.SigningCertificates, 4, now)
	if err != nil {
		return nil, verr.WithField("signing_certificates", err.Error())
	}
	if len(certs) == 0 {
		// Unsigned assertions are never accepted (§18.2), so a connection
		// without a trusted key could never sign anyone in.
		return nil, verr.WithField("signing_certificates", "at least one trusted signing certificate is required")
	}
	pems := make([]string, 0, len(certs))
	for _, c := range certs {
		pems = append(pems, saml.CertificatePEM(c))
	}
	if in.NameIDFormat != "" && !slices.Contains(saml.NameIDFormats, in.NameIDFormat) {
		return nil, verr.WithField("name_id_format", "one of "+strings.Join(saml.NameIDFormats, ", "))
	}
	if in.NameIDFormat == saml.NameIDTransient && in.SubjectAttribute == "" {
		return nil, verr.WithField("subject_attribute", "a transient NameID changes on every sign-in; name the attribute that carries a stable subject")
	}
	for field, v := range map[string]string{"subject_attribute": in.SubjectAttribute, "email_attribute": in.EmailAttribute} {
		if len(v) > 256 || strings.ContainsAny(v, " \t\r\n") {
			return nil, verr.WithField(field, "an attribute name of at most 256 characters")
		}
	}
	for field, list := range map[string][]string{"trusted_authn_contexts": in.TrustedAuthnContexts, "requested_authn_contexts": in.RequestedAuthnContexts} {
		if len(list) > 10 {
			return nil, verr.WithField(field, "at most 10 values")
		}
		for _, v := range list {
			if !saml.ValidEntityID(v) || len(v) > 256 {
				return nil, verr.WithField(field, "AuthnContextClassRef values are URIs")
			}
		}
	}
	if in.TrustUpstreamMFA && len(in.TrustedAuthnContexts) == 0 {
		return nil, verr.WithField("trusted_authn_contexts", "trusting upstream MFA needs the authentication contexts that mean MFA (FED-009)")
	}
	if in.ClockSkewSeconds == 0 {
		in.ClockSkewSeconds = defaultSAMLSkew
	}
	if in.ClockSkewSeconds < 0 || time.Duration(in.ClockSkewSeconds)*time.Second > b.MaxSkew {
		return nil, verr.WithField("clock_skew_seconds", "between 0 and saml.max_clock_skew")
	}
	if in.LinkingPolicy == "" {
		in.LinkingPolicy = LinkVerifyExisting
	}
	if !slices.Contains([]string{LinkVerifyExisting, LinkTrustedEmail, LinkCreateOnly}, in.LinkingPolicy) {
		return nil, verr.WithField("linking_policy", "verify_existing, trusted_verified_email or create_only")
	}
	if in.LinkingPolicy == LinkTrustedEmail {
		// Trusted email linking needs both an explicit decision to believe the
		// identity provider's email and an identifier constraint (FED-004).
		if !in.TrustEmailVerified {
			return nil, verr.WithField("trust_email_verified", "trusted_verified_email linking requires trusting the identity provider's email")
		}
		if len(in.AllowedEmailDomains) == 0 {
			return nil, verr.WithField("allowed_email_domains", "required for trusted_verified_email linking")
		}
	}
	for i, d := range in.AllowedEmailDomains {
		c, err := canonical.Domain(d)
		if err != nil {
			return nil, verr.WithField("allowed_email_domains", "invalid domain "+d)
		}
		in.AllowedEmailDomains[i] = c
	}
	if in.OrganizationID != "" {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, in.OrganizationID).Scan(&state); err != nil {
			return nil, verr.WithField("organization_id", "unknown organization")
		}
	}
	if in.JITDefaultRoleID != "" {
		if in.OrganizationID == "" {
			return nil, verr.WithField("jit_default_role_id", "a JIT default role requires an organization-scoped connection")
		}
		role, err := b.fed.Authz.Role(ctx, tx, realmID, in.JITDefaultRoleID)
		if err != nil {
			return nil, verr.WithField("jit_default_role_id", "unknown role")
		}
		// The administrator configuring JIT must be able to grant the role
		// themselves; a connection cannot launder a privilege (TEN-016, AZ-007).
		if err := b.fed.Authz.CheckAssignable(ctx, tx, realmID, actor, role, authorization.Scope{Type: authorization.ScopeOrganization, ID: in.OrganizationID}); err != nil {
			return nil, err
		}
	}
	if in.State == "" {
		in.State = "active"
	}
	if in.State != "active" && in.State != "disabled" {
		return nil, verr.WithField("state", "active or disabled")
	}
	sign := true
	if in.SignAuthnRequests != nil {
		sign = *in.SignAuthnRequests
	}
	return &SAMLSettings{IdPEntityID: in.IdPEntityID, SSOURL: in.SSOURL, SigningCertificates: pems, SPEntityID: in.SPEntityID,
		SignAuthnRequests: sign, RequireSignedAssertions: in.RequireSignedAssertions, NameIDFormat: in.NameIDFormat,
		SubjectAttribute: in.SubjectAttribute, EmailAttribute: in.EmailAttribute, TrustEmailVerified: in.TrustEmailVerified,
		TrustedAuthnContexts: in.TrustedAuthnContexts, RequestedAuthnContexts: in.RequestedAuthnContexts, ForceAuthn: in.ForceAuthn,
		ClockSkewSeconds: in.ClockSkewSeconds}, nil
}

func fingerprints(pems []string) []string {
	out := []string{}
	for _, p := range pems {
		if c, err := saml.ParseCertificate(p); err == nil {
			out = append(out, saml.Fingerprint(c))
		}
	}
	return out
}

// Create registers a SAML connection.
func (b *SAMLBroker) Create(ctx context.Context, realmID, realmName string, in SAMLInput, actor authorization.Subject, auditActor audit.Ref) (*SAMLConnection, error) {
	var out *SAMLConnection
	err := b.fed.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		set, err := b.validate(ctx, tx, realmID, &in, actor)
		if err != nil {
			return err
		}
		id := ids.New(ids.IdentityProv)
		mapping := defaultSAMLMapping()
		if in.ClaimMapping != nil {
			mapping = *in.ClaimMapping
		}
		cfg, _ := json.Marshal(Config{AllowedEmailDomains: in.AllowedEmailDomains})
		mj, _ := json.Marshal(mapping)
		sj, _ := json.Marshal(set)
		now := b.fed.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO identity_providers (id, realm_id, organization_id, alias, display_name, kind, adapter, state, issuer, config,
			linking_policy, jit_provisioning, jit_default_role_id, trust_upstream_mfa, claim_mapping, owner_user_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,'saml','saml',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`,
			id, realmID, nilIfEmpty(in.OrganizationID), in.Alias, in.DisplayName, in.State, set.IdPEntityID, cfg, in.LinkingPolicy, in.JIT,
			nilIfEmpty(in.JITDefaultRoleID), in.TrustUpstreamMFA, mj, nilIfEmpty(auditActor.ID), now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("alias", "already in use")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO saml_connections (provider_id, realm_id, config) VALUES ($1,$2,$3)`, id, realmID, sj); err != nil {
			return err
		}
		if _, err := b.fed.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.provider.created", RealmID: realmID, OrgID: in.OrganizationID,
			Actor: auditActor, Target: &audit.Ref{Type: "identity_provider", ID: id}, Category: "configuration",
			Metadata: map[string]any{"alias": in.Alias, "adapter": AdapterSAML, "issuer": set.IdPEntityID, "linking_policy": in.LinkingPolicy,
				"jit": in.JIT, "trust_upstream_mfa": in.TrustUpstreamMFA, "trust_email_verified": set.TrustEmailVerified,
				"signing_certificates": fingerprints(set.SigningCertificates)}}); err != nil {
			return err
		}
		p, err := b.fed.Get(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		out = b.view(realmName, p, set)
		return nil
	})
	return out, err
}

// Update replaces a SAML connection (optimistic concurrency). Certificate
// changes are audited with the fingerprints added and removed (SAML-002).
func (b *SAMLBroker) Update(ctx context.Context, realmID, realmName, ref string, version int64, in SAMLInput, actor authorization.Subject, auditActor audit.Ref) (*SAMLConnection, error) {
	var out *SAMLConnection
	err := b.fed.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, curSet, err := b.connection(ctx, tx, realmID, ref)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM identity_providers WHERE id=$1 FOR UPDATE`, cur.ID); err != nil {
			return err
		}
		if version != 0 && cur.Version != version {
			return problem.ErrPrecondition
		}
		if in.Alias == "" {
			in.Alias = cur.Alias
		}
		if in.Alias != cur.Alias {
			return problem.ErrValidation.WithField("alias", "cannot be changed (it is part of the registered service provider endpoints)")
		}
		set, err := b.validate(ctx, tx, realmID, &in, actor)
		if err != nil {
			return err
		}
		if set.IdPEntityID != cur.Issuer {
			var links int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE provider_id=$1`, cur.ID).Scan(&links); err != nil {
				return err
			}
			if links > 0 {
				// Changing the trusted issuer would re-key every linked subject (FED-016).
				return problem.ErrConflict.WithField("idp_entity_id", "cannot change while identities are linked; use a reviewed migration")
			}
		}
		mapping := cur.ClaimMapping
		rev := cur.MappingRevision
		if in.ClaimMapping != nil && *in.ClaimMapping != cur.ClaimMapping {
			mapping = *in.ClaimMapping
			rev++
		}
		cfg, _ := json.Marshal(Config{AllowedEmailDomains: in.AllowedEmailDomains})
		mj, _ := json.Marshal(mapping)
		sj, _ := json.Marshal(set)
		if _, err := tx.Exec(ctx, `UPDATE identity_providers SET display_name=$3, state=$4, issuer=$5, config=$6, linking_policy=$7, jit_provisioning=$8,
			jit_default_role_id=$9, trust_upstream_mfa=$10, claim_mapping=$11, mapping_revision=$12, organization_id=$13, version=version+1, updated_at=$14
			WHERE realm_id=$1 AND id=$2`, realmID, cur.ID, in.DisplayName, in.State, set.IdPEntityID, cfg, in.LinkingPolicy, in.JIT,
			nilIfEmpty(in.JITDefaultRoleID), in.TrustUpstreamMFA, mj, rev, nilIfEmpty(in.OrganizationID), b.fed.d.Now()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE saml_connections SET config=$2 WHERE provider_id=$1`, cur.ID, sj); err != nil {
			return err
		}
		before, after := fingerprints(curSet.SigningCertificates), fingerprints(set.SigningCertificates)
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
		if _, err := b.fed.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.provider.updated", RealmID: realmID, OrgID: in.OrganizationID,
			Actor: auditActor, Target: &audit.Ref{Type: "identity_provider", ID: cur.ID}, Category: "configuration",
			Metadata: map[string]any{"state": in.State, "issuer": set.IdPEntityID, "linking_policy": in.LinkingPolicy, "jit": in.JIT,
				"trust_upstream_mfa": in.TrustUpstreamMFA, "trust_email_verified": set.TrustEmailVerified, "mapping_revision": rev,
				"signing_certificates_added": added, "signing_certificates_removed": removed}}); err != nil {
			return err
		}
		p, err := b.fed.Get(ctx, tx, realmID, cur.ID)
		if err != nil {
			return err
		}
		out = b.view(realmName, p, set)
		return nil
	})
	return out, err
}

// Delete removes a SAML connection without linked identities.
func (b *SAMLBroker) Delete(ctx context.Context, realmID, ref string, auditActor audit.Ref) error {
	p, _, err := b.connection(ctx, nil, realmID, ref)
	if err != nil {
		return err
	}
	return b.fed.Delete(ctx, realmID, p.ID, auditActor)
}

// SPMetadata renders this realm's service provider metadata for a
// connection: the HTTP-POST assertion consumer service, the realm SAML
// signing certificates (published "next" key included) and the requested
// NameID format. Single logout is not offered: upstream SAML sessions are
// not ended by this broker (FED-013, SAML-008).
func (b *SAMLBroker) SPMetadata(ctx context.Context, realmID, realmName, alias string) ([]byte, error) {
	p, set, err := b.connection(ctx, nil, realmID, alias)
	if err != nil {
		return nil, err
	}
	certs, err := b.keys.Published(ctx, realmID)
	if err != nil {
		return nil, err
	}
	sp := b.ServiceProvider(realmName, p, set)
	d := saml.SPDescriptor{EntityID: sp.EntityID, AuthnRequestsSigned: set.SignAuthnRequests, WantAssertionsSigned: true,
		SigningCerts: certs, ACS: []saml.Endpoint{{Binding: saml.BindingPOST, URL: sp.ACSURL, Index: 0, Default: true}}}
	if set.NameIDFormat != "" {
		d.NameIDFormats = []string{set.NameIDFormat}
	}
	return saml.SPMetadata(d)
}

// BeginTx records an AuthnRequest and returns the HTTP-Redirect URL that
// carries it to the identity provider. The request ID correlates the
// response (InResponseTo); the RelayState is a random bearer secret whose
// digest is stored, so a response is accepted only for this request, from
// this round trip, once (SAML-003).
func (b *SAMLBroker) BeginTx(ctx context.Context, tx pgx.Tx, realmID, realmName string, p *Provider, purpose, transactionID, userID, sessionID string) (string, error) {
	set, err := b.settings(ctx, tx, p)
	if err != nil {
		return "", err
	}
	sp := b.ServiceProvider(realmName, p, set)
	id := saml.NewID()
	relay := secret.Token("")
	now := b.fed.d.Now()
	if _, err := tx.Exec(ctx, `INSERT INTO saml_broker_requests (id, realm_id, provider_id, purpose, transaction_id, user_id, session_id, relay_digest,
		expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, realmID, p.ID, purpose, nilIfEmpty(transactionID), nilIfEmpty(userID),
		nilIfEmpty(sessionID), secret.Digest(relay), now.Add(RequestTTL), now); err != nil {
		return "", err
	}
	r := saml.NewElement("samlp", "AuthnRequest")
	r.CreateAttr("xmlns:samlp", saml.NSProtocol)
	r.CreateAttr("xmlns:saml", saml.NSAssertion)
	r.CreateAttr("ID", id)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", saml.Time(now))
	r.CreateAttr("Destination", set.SSOURL)
	r.CreateAttr("AssertionConsumerServiceURL", sp.ACSURL)
	r.CreateAttr("ProtocolBinding", saml.BindingPOST)
	if set.ForceAuthn {
		r.CreateAttr("ForceAuthn", "true")
	}
	saml.AddChild(r, "saml", "Issuer").SetText(sp.EntityID)
	policy := saml.AddChild(r, "samlp", "NameIDPolicy")
	if set.NameIDFormat != "" {
		policy.CreateAttr("Format", set.NameIDFormat)
	}
	policy.CreateAttr("AllowCreate", "true")
	if len(set.RequestedAuthnContexts) > 0 {
		rac := saml.AddChild(r, "samlp", "RequestedAuthnContext")
		rac.CreateAttr("Comparison", "minimum")
		for _, c := range set.RequestedAuthnContexts {
			saml.AddChild(rac, "saml", "AuthnContextClassRef").SetText(c)
		}
	}
	raw, err := saml.Serialize(r)
	if err != nil {
		return "", err
	}
	enc, err := saml.EncodeRedirect(raw)
	if err != nil {
		return "", err
	}
	query := saml.RedirectQuery("SAMLRequest", enc, relay)
	if set.SignAuthnRequests {
		key, err := b.keys.Active(ctx, realmID)
		if err != nil {
			return "", err
		}
		if query, err = saml.SignRedirect("SAMLRequest", enc, relay, key.Signer, saml.SigRSASHA256); err != nil {
			return "", err
		}
	}
	sep := "?"
	if strings.Contains(set.SSOURL, "?") {
		sep = "&"
	}
	return set.SSOURL + sep + query, nil
}

// testSAML reports configuration problems without contacting anyone.
func (s *Service) testSAML(ctx context.Context, p *Provider) *Diagnostics {
	d := &Diagnostics{Issuer: p.Issuer, Problems: []string{}}
	if s.SAML == nil {
		d.Problems = append(d.Problems, "SAML is not enabled (saml.enabled)")
		return d
	}
	set, err := s.SAML.settings(ctx, nil, p)
	if err != nil {
		d.Problems = append(d.Problems, "connection settings are missing")
		return d
	}
	d.AuthorizationEndpoint = set.SSOURL
	now := s.d.Now()
	for _, c := range set.certificates() {
		switch {
		case now.After(c.NotAfter):
			d.Problems = append(d.Problems, "certificate "+saml.Fingerprint(c)[:16]+" expired")
		case now.Before(c.NotBefore):
			d.Problems = append(d.Problems, "certificate "+saml.Fingerprint(c)[:16]+" is not valid yet")
		default:
			d.SigningKeys++
			if c.NotAfter.Sub(now) < 30*24*time.Hour {
				d.Problems = append(d.Problems, "certificate "+saml.Fingerprint(c)[:16]+" expires within 30 days; add its successor")
			}
		}
	}
	if d.SigningKeys == 0 {
		d.Problems = append(d.Problems, "no trusted signing certificate is valid now")
	}
	d.OK = d.SigningKeys > 0 && p.State == "active"
	return d
}

// Cleanup removes expired SAML requests and replay records.
func (b *SAMLBroker) Cleanup(ctx context.Context) (int64, error) {
	now := b.fed.d.Now()
	t1, err := b.fed.d.DB.Pool.Exec(ctx, `DELETE FROM saml_broker_requests WHERE expires_at < $1`, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	t2, err := b.fed.d.DB.Pool.Exec(ctx, `DELETE FROM saml_assertion_ids WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return t1.RowsAffected() + t2.RowsAffected(), nil
}
