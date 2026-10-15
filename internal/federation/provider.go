// Package federation brokers sign-in through upstream identity providers
// (FED-001..FED-013, FED-017, FED-018, REG-009, USR-010, TEN-016).
//
// Trust model (DOM-004): a connection trusts exactly one configured upstream
// issuer for authentication of the subjects it asserts. It does not trust the
// upstream's organizations, administrators or assurance claims unless the
// connection explicitly says so (allowed tenants, trusted ACR values). External
// identities are keyed by connection + validated issuer + subject, never by email
// (FED-003). Linking an upstream identity to an existing local account requires
// proof of control of both, unless an explicitly constrained trusted-email policy
// applies (FED-004, FED-005). Upstream access and refresh tokens are used only
// during the callback and never stored (FED-010).
package federation

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Linking policies (FED-004).
const (
	LinkVerifyExisting = "verify_existing"
	LinkTrustedEmail   = "trusted_verified_email"
	LinkCreateOnly     = "create_only"
)

// Adapters (FED-002).
const (
	AdapterOIDC   = "oidc"
	AdapterGitHub = "github"
)

// Config is the connection-specific protocol configuration.
type Config struct {
	// DiscoveryURL defaults to Issuer + "/.well-known/openid-configuration" for
	// OIDC connections. Explicit endpoints override discovered values.
	DiscoveryURL          string `json:"discovery_url,omitempty"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	// APIBaseURL is the user API for non-OIDC social adapters (GitHub).
	APIBaseURL string `json:"api_base_url,omitempty"`
	ClientID   string `json:"client_id"`
	// ClientAuth is client_secret_basic (default) or client_secret_post.
	ClientAuth string   `json:"client_auth,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	// Algorithms allowed for upstream ID tokens (asymmetric only).
	Algorithms []string `json:"algorithms,omitempty"`
	// TenantClaim/AllowedTenants restrict which upstream tenants may sign in
	// (e.g. "tid" for Microsoft Entra, "hd" for Google Workspace) (FED-006).
	TenantClaim    string   `json:"tenant_claim,omitempty"`
	AllowedTenants []string `json:"allowed_tenants,omitempty"`
	// MultiTenantIssuer: Issuer contains "{tenant}", substituted from TenantClaim;
	// AllowedTenants is then mandatory.
	MultiTenantIssuer bool `json:"multi_tenant_issuer,omitempty"`
	// AllowedEmailDomains limits JIT creation and is required for trusted email
	// linking.
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
	// TrustedACRValues are upstream acr values accepted as MFA when
	// trust_upstream_mfa is enabled; "mfa" in amr is also accepted (FED-009).
	TrustedACRValues []string `json:"trusted_acr_values,omitempty"`
}

// FieldMapping maps an upstream claim to a local profile field (FED-008).
type FieldMapping struct {
	Claim string `json:"claim"`
	// Mode is "on_create" (default: provider fills the field only when the
	// account is created) or "sync" (provider-authoritative: refreshed on every
	// upstream login).
	Mode string `json:"mode,omitempty"`
}

// ClaimMapping maps upstream claims to the profile. Roles, memberships and
// administrative metadata are never mapped from upstream claims.
type ClaimMapping struct {
	DisplayName FieldMapping `json:"display_name,omitempty"`
	GivenName   FieldMapping `json:"given_name,omitempty"`
	FamilyName  FieldMapping `json:"family_name,omitempty"`
	Locale      FieldMapping `json:"locale,omitempty"`
	Zoneinfo    FieldMapping `json:"zoneinfo,omitempty"`
}

func defaultMapping() ClaimMapping {
	return ClaimMapping{DisplayName: FieldMapping{Claim: "name"}, GivenName: FieldMapping{Claim: "given_name"},
		FamilyName: FieldMapping{Claim: "family_name"}, Locale: FieldMapping{Claim: "locale"}}
}

// Provider is a federation connection.
type Provider struct {
	ID               string       `json:"id"`
	RealmID          string       `json:"-"`
	OrganizationID   string       `json:"organization_id,omitempty"`
	Alias            string       `json:"alias"`
	DisplayName      string       `json:"display_name"`
	Kind             string       `json:"kind"`
	Adapter          string       `json:"adapter"`
	State            string       `json:"state"`
	Issuer           string       `json:"issuer"`
	Config           Config       `json:"config"`
	HasClientSecret  bool         `json:"has_client_secret"`
	LinkingPolicy    string       `json:"linking_policy"`
	JIT              bool         `json:"jit_provisioning"`
	JITDefaultRoleID string       `json:"jit_default_role_id,omitempty"`
	TrustUpstreamMFA bool         `json:"trust_upstream_mfa"`
	ClaimMapping     ClaimMapping `json:"claim_mapping"`
	MappingRevision  int64        `json:"mapping_revision"`
	Version          int64        `json:"version"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	secretCT         []byte
}

// Input creates or replaces a connection.
type Input struct {
	OrganizationID   string        `json:"organization_id,omitempty"`
	Alias            string        `json:"alias"`
	DisplayName      string        `json:"display_name"`
	Adapter          string        `json:"adapter,omitempty"`
	Issuer           string        `json:"issuer"`
	Config           Config        `json:"config"`
	ClientSecret     *string       `json:"client_secret,omitempty"`
	LinkingPolicy    string        `json:"linking_policy,omitempty"`
	JIT              bool          `json:"jit_provisioning"`
	JITDefaultRoleID string        `json:"jit_default_role_id,omitempty"`
	TrustUpstreamMFA bool          `json:"trust_upstream_mfa"`
	ClaimMapping     *ClaimMapping `json:"claim_mapping,omitempty"`
	State            string        `json:"state,omitempty"`
}

// Service manages connections and runs the upstream protocol.
type Service struct {
	d      *runtime.Deps
	Users  *identity.Service
	Orgs   *organization.Service
	Authz  *authorization.Service
	Egress egress.Policy
	// SAML runs SAML connections (FED-014); nil when SAML is disabled.
	SAML *SAMLBroker

	disco egress.FetchCache[discovery]
	jwks  egress.FetchCache[jose.JSONWebKeySet]
}

// New builds the service; the egress policy comes from configuration.
func New(d *runtime.Deps) *Service {
	return &Service{d: d,
		Egress: egress.Policy{AllowPrivate: d.Cfg.Federation.AllowPrivateNetwork, AllowCIDRs: d.Cfg.Federation.EgressAllowlist, RequireHTTPS: true,
			Timeout: d.Cfg.Federation.FetchTimeout, MaxBytes: d.Cfg.Federation.MaxResponseBytes}}
}

const providerCols = `id, realm_id, coalesce(organization_id,''), alias, display_name, kind, adapter, state, coalesce(issuer,''), config,
	secret_ciphertext, linking_policy, jit_provisioning, coalesce(jit_default_role_id,''), trust_upstream_mfa, claim_mapping,
	mapping_revision, version, created_at, updated_at`

func scanProvider(row pgx.Row) (*Provider, error) {
	p := &Provider{}
	var cfg, mapping []byte
	if err := row.Scan(&p.ID, &p.RealmID, &p.OrganizationID, &p.Alias, &p.DisplayName, &p.Kind, &p.Adapter, &p.State, &p.Issuer, &cfg,
		&p.secretCT, &p.LinkingPolicy, &p.JIT, &p.JITDefaultRoleID, &p.TrustUpstreamMFA, &mapping, &p.MappingRevision, &p.Version,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cfg, &p.Config)
	_ = json.Unmarshal(mapping, &p.ClaimMapping)
	p.HasClientSecret = len(p.secretCT) > 0
	return p, nil
}

// Get returns a connection by ID or alias within a realm.
func (s *Service) Get(ctx context.Context, q storage.Querier, realmID, ref string) (*Provider, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	p, err := scanProvider(q.QueryRow(ctx, `SELECT `+providerCols+` FROM identity_providers WHERE realm_id=$1 AND (id=$2 OR alias=$2)`, realmID, ref))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// List returns connections, optionally only active ones or one organization's.
func (s *Service) List(ctx context.Context, q storage.Querier, realmID string, activeOnly bool) ([]*Provider, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT `+providerCols+` FROM identity_providers WHERE realm_id=$1 AND ($2 = false OR state='active')
		AND kind IN ('oidc','oauth2_social','saml') ORDER BY alias`, realmID, activeOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Provider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) validate(ctx context.Context, tx pgx.Tx, realmID string, in *Input, actor authorization.Subject) error {
	if slug, ok := canonical.Slug(in.Alias); !ok || slug != in.Alias {
		return problem.ErrValidation.WithField("alias", "lower-case letters, digits and dashes (2..63)")
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" || len(in.DisplayName) > 100 {
		return problem.ErrValidation.WithField("display_name", "required, at most 100 characters")
	}
	if in.Adapter == "" {
		in.Adapter = AdapterOIDC
	}
	adapter, ok := adapterFor(in.Adapter)
	if !ok {
		return problem.ErrValidation.WithField("adapter", "one of "+strings.Join(AdapterNames(), ", "))
	}
	if err := adapter.Prepare(in); err != nil {
		return err
	}
	if in.LinkingPolicy == "" {
		in.LinkingPolicy = LinkVerifyExisting
	}
	if !slices.Contains([]string{LinkVerifyExisting, LinkTrustedEmail, LinkCreateOnly}, in.LinkingPolicy) {
		return problem.ErrValidation.WithField("linking_policy", "verify_existing, trusted_verified_email or create_only")
	}
	if in.LinkingPolicy == LinkTrustedEmail && len(in.Config.AllowedEmailDomains) == 0 {
		// Trusted email linking needs an explicit identifier constraint (FED-004).
		return problem.ErrValidation.WithField("config.allowed_email_domains", "required for trusted_verified_email linking")
	}
	for i, d := range in.Config.AllowedEmailDomains {
		c, err := canonical.Domain(d)
		if err != nil {
			return problem.ErrValidation.WithField("config.allowed_email_domains", "invalid domain "+d)
		}
		in.Config.AllowedEmailDomains[i] = c
	}
	if in.Config.ClientID == "" || len(in.Config.ClientID) > 255 {
		return problem.ErrValidation.WithField("config.client_id", "required")
	}
	switch in.Config.ClientAuth {
	case "", "client_secret_basic", "client_secret_post":
	default:
		return problem.ErrValidation.WithField("config.client_auth", "client_secret_basic or client_secret_post")
	}
	for _, a := range in.Config.Algorithms {
		if !slices.Contains(allowedAlgs, a) {
			return problem.ErrValidation.WithField("config.algorithms", "asymmetric algorithms only: "+strings.Join(allowedAlgs, ", "))
		}
	}
	if in.Config.MultiTenantIssuer && (in.Config.TenantClaim == "" || len(in.Config.AllowedTenants) == 0 || !strings.Contains(in.Issuer, "{tenant}")) {
		return problem.ErrValidation.WithField("config.allowed_tenants", "a multi-tenant issuer requires tenant_claim, allowed_tenants and {tenant} in the issuer")
	}
	if len(in.Config.Scopes) > 20 {
		return problem.ErrValidation.WithField("config.scopes", "at most 20 scopes")
	}
	for _, sc := range in.Config.Scopes {
		if strings.ContainsAny(sc, " \t\r\n\"") || sc == "" {
			return problem.ErrValidation.WithField("config.scopes", "invalid scope")
		}
	}
	if in.LinkingPolicy == LinkTrustedEmail && !adapter.EmailLinkable {
		return problem.ErrValidation.WithField("linking_policy", "this provider does not assert verified email addresses; trusted_verified_email linking is unavailable")
	}
	if adapter.OIDC && !slices.Contains(in.Config.Scopes, "openid") {
		return problem.ErrValidation.WithField("config.scopes", "OIDC connections must request openid")
	}
	if !adapter.OIDC && in.TrustUpstreamMFA {
		return problem.ErrValidation.WithField("trust_upstream_mfa", "this adapter does not report authentication assurance")
	}
	for field, raw := range map[string]string{"issuer": strings.ReplaceAll(in.Issuer, "{tenant}", "tenant"), "config.discovery_url": in.Config.DiscoveryURL,
		"config.authorization_endpoint": in.Config.AuthorizationEndpoint, "config.token_endpoint": in.Config.TokenEndpoint,
		"config.jwks_uri": in.Config.JWKSURI, "config.end_session_endpoint": in.Config.EndSessionEndpoint, "config.api_base_url": in.Config.APIBaseURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return problem.ErrValidation.WithField(field, "must be an absolute https URL")
		}
		// Checked when the connection is saved as well as when it is
		// contacted (PRV-003).
		if !egress.HostAllowed(u.Hostname()) {
			return problem.ErrValidation.WithField(field, "outside the deployment's destination residency policy")
		}
	}
	if in.OrganizationID != "" {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, in.OrganizationID).Scan(&state); err != nil {
			return problem.ErrValidation.WithField("organization_id", "unknown organization")
		}
	}
	if in.JITDefaultRoleID != "" {
		if in.OrganizationID == "" {
			return problem.ErrValidation.WithField("jit_default_role_id", "a JIT default role requires an organization-scoped connection")
		}
		role, err := s.Authz.Role(ctx, tx, realmID, in.JITDefaultRoleID)
		if err != nil {
			return problem.ErrValidation.WithField("jit_default_role_id", "unknown role")
		}
		// The administrator configuring JIT must be able to grant the role
		// themselves; a connection cannot launder a privilege (TEN-016, AZ-007).
		if err := s.Authz.CheckAssignable(ctx, tx, realmID, actor, role, authorization.Scope{Type: authorization.ScopeOrganization, ID: in.OrganizationID}); err != nil {
			return err
		}
	}
	if in.State == "" {
		in.State = "active"
	}
	if in.State != "active" && in.State != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	return nil
}

func (s *Service) encryptSecret(id, secretValue string) ([]byte, int, error) {
	return s.d.Keys.Encrypt(keys.PurposeData, []byte(secretValue), []byte("idp-client-secret:"+id))
}

func (s *Service) clientSecret(p *Provider) (string, error) {
	if len(p.secretCT) == 0 {
		return "", nil
	}
	b, err := s.d.Keys.Decrypt(keys.PurposeData, p.secretCT, []byte("idp-client-secret:"+p.ID))
	return string(b), err
}

// Create registers a connection. The client secret is write-only.
func (s *Service) Create(ctx context.Context, realmID string, in Input, actor authorization.Subject, auditActor audit.Ref) (*Provider, error) {
	var out *Provider
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.validate(ctx, tx, realmID, &in, actor); err != nil {
			return err
		}
		id := ids.New(ids.IdentityProv)
		var ct []byte
		var kv *int
		if in.ClientSecret != nil && *in.ClientSecret != "" {
			c, v, err := s.encryptSecret(id, *in.ClientSecret)
			if err != nil {
				return err
			}
			ct, kv = c, &v
		}
		mapping := defaultMapping()
		if in.ClaimMapping != nil {
			mapping = *in.ClaimMapping
		}
		cfg, _ := json.Marshal(in.Config)
		mj, _ := json.Marshal(mapping)
		kind := kindOf(in.Adapter)
		now := s.d.Now()
		_, err := tx.Exec(ctx, `INSERT INTO identity_providers (id, realm_id, organization_id, alias, display_name, kind, adapter, state, issuer, config,
			secret_ciphertext, key_version, linking_policy, jit_provisioning, jit_default_role_id, trust_upstream_mfa, claim_mapping, owner_user_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19)`,
			id, realmID, nilIfEmpty(in.OrganizationID), in.Alias, in.DisplayName, kind, in.Adapter, in.State, in.Issuer, cfg, ct, kv,
			in.LinkingPolicy, in.JIT, nilIfEmpty(in.JITDefaultRoleID), in.TrustUpstreamMFA, mj, nilIfEmpty(auditActor.ID), now)
		if err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("alias", "already in use")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.provider.created", RealmID: realmID, OrgID: in.OrganizationID, Actor: auditActor,
			Target: &audit.Ref{Type: "identity_provider", ID: id}, Category: "configuration",
			Metadata: map[string]any{"alias": in.Alias, "adapter": in.Adapter, "issuer": in.Issuer, "linking_policy": in.LinkingPolicy, "jit": in.JIT,
				"trust_upstream_mfa": in.TrustUpstreamMFA}}); err != nil {
			return err
		}
		var err2 error
		out, err2 = s.Get(ctx, tx, realmID, id)
		return err2
	})
	return out, err
}

// kindOf is the provider kind an adapter implies.
func kindOf(adapter string) string {
	if a, ok := adapterFor(adapter); ok && !a.OIDC {
		return "oauth2_social"
	}
	return "oidc"
}

// Update replaces a connection's configuration (optimistic concurrency). A nil
// client secret keeps the stored one; an empty string removes it.
func (s *Service) Update(ctx context.Context, realmID, id string, version int64, in Input, actor authorization.Subject, auditActor audit.Ref) (*Provider, error) {
	var out *Provider
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerCols+` FROM identity_providers WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if version != 0 && cur.Version != version {
			return problem.ErrPrecondition
		}
		if cur.Kind == KindSAML {
			// Its protocol settings live with the SAML connection (FED-014).
			return problem.ErrConflict.WithDetail("SAML connections are managed at /saml/connections")
		}
		if in.Alias == "" {
			in.Alias = cur.Alias
		}
		if in.Alias != cur.Alias {
			return problem.ErrValidation.WithField("alias", "cannot be changed (it is part of the registered callback URL)")
		}
		kind := kindOf(in.Adapter)
		if in.Issuer != cur.Issuer || kind != cur.Kind {
			var links int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE provider_id=$1`, id).Scan(&links); err != nil {
				return err
			}
			if links > 0 {
				// Changing the issuer or the protocol would silently re-key
				// every linked subject (FED-016).
				field := "issuer"
				if in.Issuer == cur.Issuer {
					field = "adapter"
				}
				return problem.ErrConflict.WithField(field, "cannot change while identities are linked; use a reviewed migration")
			}
		}
		if err := s.validate(ctx, tx, realmID, &in, actor); err != nil {
			return err
		}
		ct, kv := cur.secretCT, (*int)(nil)
		if in.ClientSecret != nil {
			ct = nil
			if *in.ClientSecret != "" {
				c, v, err := s.encryptSecret(id, *in.ClientSecret)
				if err != nil {
					return err
				}
				ct, kv = c, &v
			}
		}
		mapping := cur.ClaimMapping
		rev := cur.MappingRevision
		if in.ClaimMapping != nil && *in.ClaimMapping != cur.ClaimMapping {
			mapping = *in.ClaimMapping
			rev++
		}
		cfg, _ := json.Marshal(in.Config)
		mj, _ := json.Marshal(mapping)
		if _, err := tx.Exec(ctx, `UPDATE identity_providers SET display_name=$3, adapter=$4, state=$5, issuer=$6, config=$7, secret_ciphertext=$8,
			key_version=coalesce($9, key_version), linking_policy=$10, jit_provisioning=$11, jit_default_role_id=$12, trust_upstream_mfa=$13,
			claim_mapping=$14, mapping_revision=$15, organization_id=$16, version=version+1, updated_at=$17, kind=$18 WHERE realm_id=$1 AND id=$2`,
			realmID, id, in.DisplayName, in.Adapter, in.State, in.Issuer, cfg, ct, kv, in.LinkingPolicy, in.JIT, nilIfEmpty(in.JITDefaultRoleID),
			in.TrustUpstreamMFA, mj, rev, nilIfEmpty(in.OrganizationID), s.d.Now(), kind); err != nil {
			return err
		}
		s.forget(id)
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.provider.updated", RealmID: realmID, OrgID: in.OrganizationID, Actor: auditActor,
			Target: &audit.Ref{Type: "identity_provider", ID: id}, Category: "configuration",
			Metadata: map[string]any{"state": in.State, "issuer": in.Issuer, "linking_policy": in.LinkingPolicy, "jit": in.JIT,
				"trust_upstream_mfa": in.TrustUpstreamMFA, "secret_changed": in.ClientSecret != nil, "mapping_revision": rev}}); err != nil {
			return err
		}
		out, err = s.Get(ctx, tx, realmID, id)
		return err
	})
	return out, err
}

// SetState disables or re-enables a connection through an emergency control
// (SEC-020) without revalidating its configuration: disabling must work even
// when the upstream is unreachable or misconfigured.
func (s *Service) SetState(ctx context.Context, realmID, id, state string, actor audit.Ref, reason string) error {
	if state != "active" && state != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE identity_providers SET state=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND id=$2`,
			realmID, id, state, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.provider.state_changed", RealmID: realmID, Actor: actor, Category: "emergency",
			Target: &audit.Ref{Type: "identity_provider", ID: id}, ReasonCode: reason, Metadata: map[string]any{"state": state}})
		return err
	})
	s.forget(id)
	return err
}

// Delete removes a connection without linked identities; connections with links
// must be disabled instead, so users keep a visible, removable link (FED-011).
func (s *Service) Delete(ctx context.Context, realmID, id string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var links int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE realm_id=$1 AND provider_id=$2`, realmID, id).Scan(&links); err != nil {
			return err
		}
		if links > 0 {
			return problem.ErrConflict.WithDetailf("%d identities are linked to this connection; disable it instead", links)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM federation_requests WHERE realm_id=$1 AND provider_id=$2`, realmID, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM identity_providers WHERE realm_id=$1 AND id=$2`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		s.forget(id)
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.provider.deleted", RealmID: realmID, Actor: auditActor,
			Target: &audit.Ref{Type: "identity_provider", ID: id}, Category: "configuration"})
		return err
	})
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
