// Package application manages projects, OAuth clients, API resources (audiences),
// scopes and the client-to-resource grant policy (§7).
package application

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/certauth"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Client types (APP-002).
const (
	TypeConfidential  = "confidential"
	TypePublicBrowser = "public_browser"
	TypeNative        = "native"
	TypeDevice        = "device"
	TypeMachine       = "machine"
)

// Grant types.
const (
	// OperatorClientID is the built-in operator CLI client. Emergency grant
	// controls never apply to it, so administrators can always reach the
	// administration API to reverse one (SEC-020).
	OperatorClientID = "proudauth-cli"

	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// ProfileFAPI2 is the FAPI 2.0 Security Profile client profile (ADV-001).
const ProfileFAPI2 = "fapi2"

// FAPI2SigningAlgs are the algorithms FAPI 2.0 allows for signatures.
var FAPI2SigningAlgs = []string{"PS256", "ES256", "EdDSA"}

// FAPI2 reports a client under the FAPI 2.0 Security Profile.
func (c *Client) FAPI2() bool { return c.SecurityProfile == ProfileFAPI2 }

// Resource kinds.
const (
	KindBusiness = "business"
	KindAccount  = "account"
	KindAdmin    = "admin"
	KindUserInfo = "userinfo"
)

// Verification modes (§13.2).
const (
	ModeOffline       = "offline"
	ModeBoundedOnline = "bounded_online"
	ModeStrictOnline  = "strict_online"
)

// Client is a registered OAuth/OIDC client.
type Client struct {
	Ref             string   `json:"id"`
	RealmID         string   `json:"realm_id"`
	ClientID        string   `json:"client_id"`
	ProjectID       string   `json:"project_id,omitempty"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Type            string   `json:"client_type"`
	AuthMethod      string   `json:"token_endpoint_auth_method"`
	GrantTypes      []string `json:"grant_types"`
	SecurityProfile string   `json:"security_profile"`
	State           string   `json:"state"`
	FirstParty      bool     `json:"first_party"`
	ConsentMode     string   `json:"consent_mode"`
	// ConsentTermsVersion is the client's current terms; a consent given for
	// another version no longer covers the client (APP-013).
	ConsentTermsVersion   string         `json:"consent_terms_version,omitempty"`
	AllowOfflineAccess    bool           `json:"allow_offline_access"`
	AllowRememberMe       bool           `json:"allow_remember_me"`
	DefaultResourceID     string         `json:"default_resource_id,omitempty"`
	ServicePrincipalID    string         `json:"service_principal_id,omitempty"`
	Environment           string         `json:"environment"`
	SubjectType           string         `json:"subject_type"`
	SectorIdentifier      string         `json:"sector_identifier,omitempty"`
	LoginUIURL            string         `json:"login_ui_url,omitempty"`
	BackchannelLogoutURI  string         `json:"backchannel_logout_uri,omitempty"`
	IDTokenClaims         map[string]any `json:"id_token_claims,omitempty"`
	AccessTokenClaims     map[string]any `json:"access_token_claims,omitempty"`
	TokenPolicy           TokenPolicy    `json:"token_policy"`
	OwnerUserID           string         `json:"owner_user_id,omitempty"`
	Contacts              []string       `json:"contacts,omitempty"`
	RedirectURIs          []string       `json:"redirect_uris"`
	PostLogoutRedirects   []string       `json:"post_logout_redirect_uris"`
	Origins               []string       `json:"allowed_origins"`
	DynamicallyRegistered bool           `json:"dynamically_registered"`
	// Protocol is "oidc", or "saml" for the client backing a SAML application
	// (APP-018), which is managed only through the SAML application API.
	Protocol string `json:"protocol"`
	ProtocolOptions
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TokenPolicy holds per-client lifetime overrides (TOK-018) and sender constraints.
type TokenPolicy struct {
	AccessTokenTTLSeconds  int  `json:"access_token_ttl_seconds,omitempty"`
	RefreshIdleSeconds     int  `json:"refresh_idle_seconds,omitempty"`
	RefreshAbsoluteSeconds int  `json:"refresh_absolute_seconds,omitempty"`
	RequireDPoP            bool `json:"require_dpop,omitempty"`
	RequirePAR             bool `json:"require_par,omitempty"`
	RequireMFA             bool `json:"require_mfa,omitempty"`
	// MaxSessionAgeSeconds makes the client re-authenticate users whose SSO
	// session is older than this, independent of max_age (SES-002).
	MaxSessionAgeSeconds int `json:"max_session_age_seconds,omitempty"`
}

// SessionTooOld reports whether a session authenticated at authTime is older
// than the client's MaxSessionAgeSeconds allows at now (SES-002). The
// authentication transaction then does not reuse the session, and an
// organization switch refuses it.
func (p TokenPolicy) SessionTooOld(authTime, now time.Time) bool {
	return p.MaxSessionAgeSeconds > 0 && now.Sub(authTime) > time.Duration(p.MaxSessionAgeSeconds)*time.Second
}

// Active reports whether the client may be used.
func (c *Client) Active() bool { return c.State == "active" }

// Public reports whether the client cannot keep a secret.
func (c *Client) Public() bool {
	return c.Type == TypePublicBrowser || c.Type == TypeNative || (c.Type == TypeDevice && c.AuthMethod == "none")
}

// AllowsGrant reports whether the grant type is enabled for the client.
func (c *Client) AllowsGrant(g string) bool { return slices.Contains(c.GrantTypes, g) }

// Resource is a registered resource server (APP-006).
type Resource struct {
	ID                   string              `json:"id"`
	RealmID              string              `json:"realm_id"`
	ProjectID            string              `json:"project_id,omitempty"`
	Name                 string              `json:"name"`
	Audience             string              `json:"audience"`
	Description          string              `json:"description,omitempty"`
	Kind                 string              `json:"kind"`
	TokenFormat          string              `json:"token_format"`
	VerificationMode     string              `json:"verification_mode"`
	AccessTokenTTL       int                 `json:"access_token_ttl_seconds"`
	RequiresOrganization bool                `json:"requires_organization"`
	ImpersonationEnabled bool                `json:"impersonation_enabled"`
	ImpersonationPolicy  ImpersonationPolicy `json:"impersonation_policy"`
	SigningAlgorithm     string              `json:"signing_algorithm"`
	State                string              `json:"state"`
	Version              int64               `json:"version"`
	Scopes               []Scope             `json:"scopes,omitempty"`
	CreatedAt            time.Time           `json:"created_at"`
}

// ImpersonationPolicy is a resource's support-access opt-in contract (IMP-001, IMP-011).
type ImpersonationPolicy struct {
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	WriteScopes   []string `json:"write_scopes,omitempty"` // explicitly reviewed state-changing scopes
	// WriteActions are the explicitly reviewed state-changing actions an
	// allowlisted_write support token may perform through the decision API
	// (IMP-011); every other write is refused.
	WriteActions        []string `json:"write_actions,omitempty"`
	ContractVersion     string   `json:"contract_version,omitempty"`
	ContractValidatedAt string   `json:"contract_validated_at,omitempty"`
	SupportClientIDs    []string `json:"support_client_ids,omitempty"`
}

// Scope is a declared scope (APP-007).
type Scope struct {
	ID          string `json:"id"`
	ResourceID  string `json:"resource_id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ConsentText string `json:"consent_text,omitempty"`
	Sensitivity string `json:"sensitivity"`
	IsDefault   bool   `json:"is_default"`
	Kind        string `json:"kind"`
	// RequiredPermissions is the scope's subject policy (TOK-008).
	RequiredPermissions []string `json:"required_permissions,omitempty"`
	// StepUpACR and MaxAuthAgeSeconds are the scope's step-up policy (AUT-010).
	StepUpACR         string `json:"step_up_acr,omitempty"`
	MaxAuthAgeSeconds int    `json:"max_auth_age_seconds,omitempty"`
}

// StepUp returns the assurance and authentication age the scopes require
// together (AUT-010): the strongest ACR and the shortest age. Privileged
// scopes require MFA even without an explicit setting.
func StepUp(defs map[string]Scope) (acr string, maxAge int) {
	rank := map[string]int{"urn:proudauth:acr:mfa": 1, "urn:proudauth:acr:phishing_resistant": 2}
	for _, d := range defs {
		want := d.StepUpACR
		if want == "" && d.Sensitivity == "privileged" {
			want = "urn:proudauth:acr:mfa"
		}
		if rank[want] > rank[acr] {
			acr = want
		}
		if d.MaxAuthAgeSeconds > 0 && (maxAge == 0 || d.MaxAuthAgeSeconds < maxAge) {
			maxAge = d.MaxAuthAgeSeconds
		}
	}
	return acr, maxAge
}

// ResourceGrant is a client's permission to request a resource (TOK-007, TOK-008).
type ResourceGrant struct {
	ID             string         `json:"id"`
	ClientRef      string         `json:"client_ref"`
	ResourceID     string         `json:"resource_id"`
	AllowedScopes  []string       `json:"allowed_scopes"`
	SubjectTypes   []string       `json:"subject_types"`
	ExchangePolicy ExchangePolicy `json:"exchange_policy"`
}

// ExchangePolicy controls token exchange into this resource (TOK-016).
type ExchangePolicy struct {
	// AcceptFromAudiences lists source audiences whose user tokens this client may exchange.
	AcceptFromAudiences []string `json:"accept_from_audiences,omitempty"`
	MaxScopes           []string `json:"max_scopes,omitempty"`
}

// Project groups clients, resources and roles (APP-001).
type Project struct {
	ID                  string    `json:"id"`
	RealmID             string    `json:"realm_id"`
	OwnerOrganizationID string    `json:"owner_organization_id,omitempty"`
	Name                string    `json:"name"`
	Description         string    `json:"description,omitempty"`
	Environment         string    `json:"environment"`
	State               string    `json:"state"`
	OwnerUserID         string    `json:"owner_user_id,omitempty"`
	Version             int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
}

// Service manages the application registry.
type Service struct {
	d *runtime.Deps
	// Certs verifies client certificates against realm trust anchors
	// (mutual-TLS client authentication, MCH-014).
	Certs *certauth.Service
	// SigningAlgorithm, when set, reports a realm's active token signing
	// algorithm, which signed responses use (OIDC-013).
	SigningAlgorithm func(ctx context.Context, realmID string) (string, error)
}

// NewService returns the registry service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

// ---------- clients ----------

const clientCols = `id, realm_id, client_id, coalesce(project_id,''), name, coalesce(description,''), client_type, token_endpoint_auth_method,
	grant_types, security_profile, state, first_party, consent_mode, allow_offline_access, allow_remember_me,
	coalesce(default_resource_id,''), coalesce(service_principal_id,''), environment, subject_type, coalesce(sector_identifier,''),
	coalesce(login_ui_url,''), coalesce(backchannel_logout_uri,''), id_token_claims, access_token_claims, token_policy,
	coalesce(owner_user_id,''), contacts, dynamically_registered, version, created_at, updated_at, coalesce(consent_terms_version,''),
	protocol_options, protocol`

func scanClient(row pgx.Row) (*Client, error) {
	var c Client
	var idc, atc, tp, po []byte
	err := row.Scan(&c.Ref, &c.RealmID, &c.ClientID, &c.ProjectID, &c.Name, &c.Description, &c.Type, &c.AuthMethod,
		&c.GrantTypes, &c.SecurityProfile, &c.State, &c.FirstParty, &c.ConsentMode, &c.AllowOfflineAccess, &c.AllowRememberMe,
		&c.DefaultResourceID, &c.ServicePrincipalID, &c.Environment, &c.SubjectType, &c.SectorIdentifier,
		&c.LoginUIURL, &c.BackchannelLogoutURI, &idc, &atc, &tp, &c.OwnerUserID, &c.Contacts, &c.DynamicallyRegistered,
		&c.Version, &c.CreatedAt, &c.UpdatedAt, &c.ConsentTermsVersion, &po, &c.Protocol)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(po, &c.ProtocolOptions)
	_ = json.Unmarshal(idc, &c.IDTokenClaims)
	_ = json.Unmarshal(atc, &c.AccessTokenClaims)
	_ = json.Unmarshal(tp, &c.TokenPolicy)
	return &c, nil
}

func (s *Service) loadClientURIs(ctx context.Context, q storage.Querier, c *Client) error {
	rows, err := q.Query(ctx, `SELECT uri, purpose FROM client_redirect_uris WHERE client_ref=$1 ORDER BY created_at, uri`, c.Ref)
	if err != nil {
		return err
	}
	c.RedirectURIs, c.PostLogoutRedirects = []string{}, []string{}
	for rows.Next() {
		var uri, purpose string
		if err := rows.Scan(&uri, &purpose); err != nil {
			rows.Close()
			return err
		}
		if purpose == "redirect" {
			c.RedirectURIs = append(c.RedirectURIs, uri)
		} else {
			c.PostLogoutRedirects = append(c.PostLogoutRedirects, uri)
		}
	}
	rows.Close()
	orows, err := q.Query(ctx, `SELECT origin FROM client_origins WHERE client_ref=$1 ORDER BY origin`, c.Ref)
	if err != nil {
		return err
	}
	defer orows.Close()
	c.Origins = []string{}
	for orows.Next() {
		var o string
		if err := orows.Scan(&o); err != nil {
			return err
		}
		c.Origins = append(c.Origins, o)
	}
	return orows.Err()
}

// ClientByClientID loads a client by its public client_id within a realm.
func (s *Service) ClientByClientID(ctx context.Context, q storage.Querier, realmID, clientID string) (*Client, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	if clientID == "" || len(clientID) > 128 {
		return nil, problem.ErrNotFound
	}
	c, err := scanClient(q.QueryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=$1 AND client_id=$2`, realmID, clientID))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return c, s.loadClientURIs(ctx, q, c)
}

// ClientByRef loads a client by internal reference.
func (s *Service) ClientByRef(ctx context.Context, q storage.Querier, realmID, ref string) (*Client, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	c, err := scanClient(q.QueryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=$1 AND id=$2`, realmID, ref))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return c, s.loadClientURIs(ctx, q, c)
}

// ClientInput is the create/update payload.
type ClientInput struct {
	ClientID              string          `json:"client_id"`
	ProjectID             string          `json:"project_id"`
	Name                  string          `json:"name"`
	Description           string          `json:"description"`
	Type                  string          `json:"client_type"`
	AuthMethod            string          `json:"token_endpoint_auth_method"`
	GrantTypes            []string        `json:"grant_types"`
	SecurityProfile       string          `json:"security_profile"`
	FirstParty            bool            `json:"first_party"`
	ConsentMode           string          `json:"consent_mode"`
	ConsentTermsVersion   string          `json:"consent_terms_version"`
	AllowOfflineAccess    bool            `json:"allow_offline_access"`
	AllowRememberMe       bool            `json:"allow_remember_me"`
	DefaultResourceID     string          `json:"default_resource_id"`
	ServicePrincipalID    string          `json:"service_principal_id"`
	Environment           string          `json:"environment"`
	SubjectType           string          `json:"subject_type"`
	SectorIdentifier      string          `json:"sector_identifier"`
	LoginUIURL            string          `json:"login_ui_url"`
	BackchannelLogoutURI  string          `json:"backchannel_logout_uri"`
	RedirectURIs          []string        `json:"redirect_uris"`
	PostLogoutRedirects   []string        `json:"post_logout_redirect_uris"`
	Origins               []string        `json:"allowed_origins"`
	IDTokenClaims         map[string]any  `json:"id_token_claims"`
	AccessTokenClaims     map[string]any  `json:"access_token_claims"`
	TokenPolicy           TokenPolicy     `json:"token_policy"`
	OwnerUserID           string          `json:"owner_user_id"`
	Contacts              []string        `json:"contacts"`
	JWKS                  json.RawMessage `json:"jwks"`
	DynamicallyRegistered bool            `json:"-"`
	ProtocolOptions
}

// Normalize applies type defaults and validates the client definition, including
// security-profile rules (APP-010) and the negative capability rule that flows not
// enabled are never implied (APP-020).
func (in *ClientInput) Normalize() *problem.Error {
	verr := problem.ErrValidation
	if in.Name == "" || len(in.Name) > 200 {
		return verr.WithField("name", "required, at most 200 characters")
	}
	if in.ClientID == "" {
		in.ClientID = ids.New("app")
	}
	if len(in.ClientID) > 128 || strings.ContainsAny(in.ClientID, " \t\r\n:/?#[]@") {
		return verr.WithField("client_id", "must be at most 128 URL-safe characters")
	}
	if in.Environment == "" {
		in.Environment = "production"
	}
	if in.SubjectType == "" {
		in.SubjectType = "public"
	}
	if in.SubjectType == "pairwise" {
		// Reviewed sector registration (OIDC-010): the sector is a host the
		// client's redirect URIs belong to, so one client cannot claim another
		// sector and correlate its users. Default: the redirect URIs' common host.
		if in.SectorIdentifier == "" {
			in.SectorIdentifier = commonRedirectHost(in.RedirectURIs)
		}
		if in.SectorIdentifier == "" {
			return verr.WithField("sector_identifier", "required for pairwise subjects when redirect URIs span several hosts")
		}
		sector, err := canonical.Domain(in.SectorIdentifier)
		if err != nil {
			return verr.WithField("sector_identifier", "must be a host name")
		}
		in.SectorIdentifier = sector
		for _, ru := range in.RedirectURIs {
			u, err := url.Parse(ru)
			if err != nil {
				continue
			}
			h := strings.ToLower(u.Hostname())
			if h != sector && !strings.HasSuffix(h, "."+sector) {
				return verr.WithField("sector_identifier", "every redirect URI must belong to the sector host "+sector)
			}
		}
	}
	if len(in.ConsentTermsVersion) > 64 {
		return verr.WithField("consent_terms_version", "at most 64 characters")
	}
	if in.ConsentMode == "" {
		if in.FirstParty {
			in.ConsentMode = "preauthorized"
		} else {
			in.ConsentMode = "required"
		}
	}
	if in.SecurityProfile == "" {
		in.SecurityProfile = "standard"
	}
	switch in.Type {
	case TypeConfidential:
		if in.AuthMethod == "" {
			in.AuthMethod = "client_secret_basic"
		}
		if in.AuthMethod == "none" {
			return verr.WithField("token_endpoint_auth_method", "confidential clients must authenticate")
		}
		if len(in.GrantTypes) == 0 {
			in.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
		}
	case TypePublicBrowser, TypeNative:
		if in.AuthMethod == "" {
			in.AuthMethod = "none"
		}
		if in.AuthMethod != "none" {
			return verr.WithField("token_endpoint_auth_method", "public clients cannot hold a secret (§28.4)")
		}
		if len(in.GrantTypes) == 0 {
			in.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
		}
	case TypeDevice:
		if in.AuthMethod == "" {
			in.AuthMethod = "none"
		}
		if len(in.GrantTypes) == 0 {
			in.GrantTypes = []string{GrantDeviceCode, GrantRefreshToken}
		}
	case TypeMachine:
		if in.AuthMethod == "" {
			in.AuthMethod = "client_secret_basic"
		}
		// A workload-federation client (MCH-011) holds no secret: the trusted
		// workload assertion is its credential, so it may use only that grant.
		if in.AuthMethod == "none" && (len(in.GrantTypes) == 0 || slices.ContainsFunc(in.GrantTypes, func(g string) bool { return g != GrantJWTBearer })) {
			return verr.WithField("token_endpoint_auth_method", "machine clients must authenticate unless their only grant is "+GrantJWTBearer)
		}
		if len(in.GrantTypes) == 0 {
			in.GrantTypes = []string{GrantClientCredentials}
		}
	default:
		return verr.WithField("client_type", "must be confidential, public_browser, native, device or machine")
	}
	switch in.AuthMethod {
	case "client_secret_basic", "client_secret_post", "private_key_jwt", "none":
	case "tls_client_auth", "self_signed_tls_client_auth":
		// Mutual TLS proves possession of a key the client keeps (RFC 8705).
		if in.Type != TypeConfidential && in.Type != TypeMachine {
			return verr.WithField("token_endpoint_auth_method", "mutual-TLS authentication is for confidential and machine clients")
		}
	default:
		return verr.WithField("token_endpoint_auth_method", "unsupported method")
	}
	allowed := map[string][]string{
		TypeConfidential:  {GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantTokenExchange, GrantDeviceCode},
		TypePublicBrowser: {GrantAuthorizationCode, GrantRefreshToken},
		TypeNative:        {GrantAuthorizationCode, GrantRefreshToken, GrantDeviceCode},
		TypeDevice:        {GrantDeviceCode, GrantRefreshToken},
		// The JWT-bearer authorization grant (RFC 7523 §2.1) serves workload
		// federation (MCH-011, ADV-004): assertions from trusted workload
		// issuers only, mapped to the client's service principal.
		TypeMachine: {GrantClientCredentials, GrantTokenExchange, GrantJWTBearer},
	}[in.Type]
	for _, g := range in.GrantTypes {
		if g == "password" || g == "implicit" {
			return verr.WithField("grant_types", "password and implicit grants are intentionally unsupported (§18.2)")
		}
		if !slices.Contains(allowed, g) {
			return verr.WithField("grant_types", fmt.Sprintf("%s is not permitted for %s clients", g, in.Type))
		}
	}
	if slices.Contains(in.GrantTypes, GrantClientCredentials) && in.ServicePrincipalID == "" {
		return verr.WithField("service_principal_id", "client_credentials requires a service principal (MCH-002)")
	}
	if slices.Contains(in.GrantTypes, GrantJWTBearer) && in.ServicePrincipalID == "" {
		return verr.WithField("service_principal_id", GrantJWTBearer+" requires a service principal for the workload to act as (MCH-011)")
	}
	if slices.Contains(in.GrantTypes, GrantAuthorizationCode) && len(in.RedirectURIs) == 0 {
		return verr.WithField("redirect_uris", "authorization_code clients need at least one exact redirect URI")
	}
	for _, r := range in.RedirectURIs {
		if msg := ValidateRedirectRegistration(r, in.Type, in.Environment); msg != "" {
			return verr.WithField("redirect_uris", msg+": "+r)
		}
	}
	for _, r := range in.PostLogoutRedirects {
		if msg := ValidateRedirectRegistration(r, in.Type, in.Environment); msg != "" {
			return verr.WithField("post_logout_redirect_uris", msg+": "+r)
		}
	}
	for i, o := range in.Origins {
		norm, msg := ValidateOrigin(o, in.Environment)
		if msg != "" {
			return verr.WithField("allowed_origins", msg)
		}
		in.Origins[i] = norm
	}
	if in.BackchannelLogoutURI != "" {
		if msg := ValidateRedirectRegistration(in.BackchannelLogoutURI, TypeConfidential, in.Environment); msg != "" {
			return verr.WithField("backchannel_logout_uri", msg)
		}
	}
	if err := in.ProtocolOptions.validate(in); err != nil {
		return err
	}
	if in.LoginUIURL != "" {
		if msg := ValidateRedirectRegistration(in.LoginUIURL, TypeConfidential, in.Environment); msg != "" {
			return verr.WithField("login_ui_url", msg)
		}
	}
	for k := range in.IDTokenClaims {
		if isReserved(k) {
			return verr.WithField("id_token_claims", "reserved claim "+k+" cannot be mapped (TOK-015)")
		}
		// Standard user claims carry verified provenance from the user record
		// and are released by scope; a static client mapping must never stand
		// in for them (OIDC-007).
		if IsStandardUserClaim(k) {
			return verr.WithField("id_token_claims", "standard user claim "+k+" is released from the user record by scope, not by static mapping (OIDC-007)")
		}
	}
	for k, v := range in.AccessTokenClaims {
		if isReserved(k) {
			return verr.WithField("access_token_claims", "reserved claim "+k+" cannot be mapped (TOK-015)")
		}
		// A resource server may read standard claim names as user data: they
		// can only carry a mapped user attribute, never a static value, and
		// never contact data, whose verified provenance a mapping cannot give.
		if IsStandardUserClaim(k) {
			if _, mapped := v.(map[string]any); !mapped || strings.HasPrefix(k, "email") || strings.HasPrefix(k, "phone_number") || k == "address" {
				return verr.WithField("access_token_claims", "standard user claim "+k+" cannot hold a static value or contact data (OIDC-007)")
			}
		}
	}
	if err := validateClaimMap("id_token_claims", in.IDTokenClaims); err != nil {
		return verr.WithField("id_token_claims", err.Error())
	}
	if err := validateClaimMap("access_token_claims", in.AccessTokenClaims); err != nil {
		return verr.WithField("access_token_claims", err.Error())
	}
	// Security profiles (APP-010).
	switch in.SecurityProfile {
	case "standard":
	case "third_party":
		if in.FirstParty || in.ConsentMode != "required" {
			return verr.WithField("security_profile", "third_party clients require user consent and cannot be first-party")
		}
	case "privileged":
		if !in.FirstParty {
			return verr.WithField("security_profile", "privileged clients must be first-party")
		}
		if in.Type == TypePublicBrowser {
			return verr.WithField("security_profile", "privileged clients cannot be public browser clients")
		}
	case "high_assurance":
		if in.AuthMethod != "private_key_jwt" {
			return verr.WithField("security_profile", "high_assurance clients must use private_key_jwt")
		}
		in.TokenPolicy.RequirePAR = true
	case ProfileFAPI2:
		// FAPI 2.0 Security Profile (ADV-001): its own complete rule set,
		// never ordinary defaults under a financial-grade label.
		if in.Type != TypeConfidential {
			return verr.WithField("security_profile", "fapi2 clients are confidential clients")
		}
		if !slices.Contains([]string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}, in.AuthMethod) {
			return verr.WithField("security_profile", "fapi2 clients authenticate with private_key_jwt or mutual TLS")
		}
		for _, g := range in.GrantTypes {
			if g != GrantAuthorizationCode && g != GrantRefreshToken {
				return verr.WithField("security_profile", "fapi2 clients use the authorization code grant (and refresh tokens) only")
			}
		}
		if !in.TokenPolicy.RequireDPoP && !in.TLSClientCertificateBoundAccessTokens {
			return verr.WithField("security_profile", "fapi2 clients need sender-constrained tokens: token_policy.require_dpop or tls_client_certificate_bound_access_tokens")
		}
		for _, r := range in.RedirectURIs {
			if !strings.HasPrefix(strings.ToLower(r), "https://") {
				return verr.WithField("redirect_uris", "fapi2 redirect URIs use https")
			}
		}
		in.TokenPolicy.RequirePAR = true
	default:
		return verr.WithField("security_profile", "must be standard, third_party, privileged, high_assurance or fapi2")
	}
	if in.TokenPolicy.AccessTokenTTLSeconds < 0 || in.TokenPolicy.AccessTokenTTLSeconds > 3600 {
		return verr.WithField("token_policy.access_token_ttl_seconds", "must be within 0..3600")
	}
	if in.TokenPolicy.MaxSessionAgeSeconds < 0 || in.TokenPolicy.MaxSessionAgeSeconds > 90*24*3600 {
		return verr.WithField("token_policy.max_session_age_seconds", "must be within 0..7776000")
	}
	return nil
}

// IsStandardUserClaim reports OIDC Core §5.1 user claims.
func IsStandardUserClaim(k string) bool {
	switch k {
	case "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website",
		"email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at":
		return true
	}
	return false
}

func isReserved(k string) bool {
	switch k {
	case "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "client_id", "scope", "token_kind", "act", "may_act", "cnf",
		"sid", "org_id", "auth_time", "acr", "amr", "azp", "nonce", "at_hash", "c_hash", "authz_version", "events",
		"impersonation_grant_id", "support_mode", "project_id", "typ":
		return true
	}
	return false
}

// CreateClient registers a client. Confidential/machine clients using a shared
// secret receive one generated secret, returned exactly once (APP-003, API-006).
func (s *Service) CreateClient(ctx context.Context, realmID string, in ClientInput, actor audit.Ref) (*Client, string, error) {
	var out *Client
	var plain string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, plain, err = s.CreateClientTx(ctx, tx, realmID, in, actor)
		return err
	})
	return out, plain, err
}

// CreateClientTx is CreateClient inside an existing transaction.
// checkOwnOrigin refuses redirect targets on the identity provider's own
// origin (APP-004): its endpoints forward to further redirects (authorize,
// logout, federation), so a redirect URI there would build open-redirect
// chains that exact matching alone cannot see.
func (s *Service) checkOwnOrigin(ctx context.Context, q storage.Querier, realmID string, in *ClientInput) *problem.Error {
	own := map[string]bool{}
	if u, err := url.Parse(s.d.Cfg.Server.PublicOrigin); err == nil && u.Hostname() != "" {
		own[strings.ToLower(u.Hostname())] = true
	}
	// The realm's verified custom hosts serve the same endpoints (DEP-014).
	if rows, err := q.Query(ctx, `SELECT host FROM realm_custom_domains WHERE realm_id=$1 AND state='verified'`, realmID); err == nil {
		for rows.Next() {
			var h string
			if rows.Scan(&h) == nil {
				own[strings.ToLower(h)] = true
			}
		}
		rows.Close()
	}
	for field, list := range map[string][]string{"redirect_uris": in.RedirectURIs, "post_logout_redirect_uris": in.PostLogoutRedirects} {
		for _, raw := range list {
			if u, err := url.Parse(raw); err == nil && own[strings.ToLower(u.Hostname())] && !isLoopbackHost(u.Hostname()) {
				return problem.ErrValidation.WithField(field, "must not point at the identity provider itself: "+raw)
			}
		}
	}
	return nil
}

// checkResponseSigning accepts userinfo_signed_response_alg only when it is
// the realm's signing algorithm: responses are signed with the realm's
// active key, never with a key kept for one client.
func (s *Service) checkResponseSigning(ctx context.Context, realmID string, in *ClientInput) *problem.Error {
	if s.SigningAlgorithm == nil {
		return nil
	}
	if in.SecurityProfile == ProfileFAPI2 {
		// ID tokens and other responses to the client are signed with the
		// realm key, so its algorithm must be one FAPI 2.0 allows.
		if alg, err := s.SigningAlgorithm(ctx, realmID); err != nil || !slices.Contains(FAPI2SigningAlgs, alg) {
			return problem.ErrValidation.WithField("security_profile", "fapi2 needs a realm signing algorithm of PS256, ES256 or EdDSA (keys.signing_algorithm); it is "+alg)
		}
	}
	for field, want := range map[string]string{"userinfo_signed_response_alg": in.UserinfoSignedResponseAlg,
		"authorization_signed_response_alg": in.AuthorizationSignedResponseAlg} {
		if want == "" {
			continue
		}
		alg, err := s.SigningAlgorithm(ctx, realmID)
		if err != nil || alg != want {
			return problem.ErrValidation.WithField(field, "must be the realm's signing algorithm ("+alg+")")
		}
	}
	return nil
}

func (s *Service) CreateClientTx(ctx context.Context, tx pgx.Tx, realmID string, in ClientInput, actor audit.Ref) (*Client, string, error) {
	if in.Environment == "" && in.ProjectID != "" {
		// A project's clients default to the project's environment (APP-015).
		_ = tx.QueryRow(ctx, `SELECT environment FROM projects WHERE realm_id=$1 AND id=$2`, realmID, in.ProjectID).Scan(&in.Environment)
	}
	if perr := in.Normalize(); perr != nil {
		return nil, "", perr
	}
	if perr := s.checkOwnOrigin(ctx, tx, realmID, &in); perr != nil {
		return nil, "", perr
	}
	if perr := s.checkResponseSigning(ctx, realmID, &in); perr != nil {
		return nil, "", perr
	}
	if err := s.checkProjectEnvironment(ctx, tx, realmID, in.ProjectID, in.Environment); err != nil {
		return nil, "", err
	}
	now := s.d.Now()
	ref := ids.New(ids.Client)
	idc, _ := json.Marshal(nonNil(in.IDTokenClaims))
	atc, _ := json.Marshal(nonNil(in.AccessTokenClaims))
	tp, _ := json.Marshal(in.TokenPolicy)
	po, _ := json.Marshal(in.ProtocolOptions)
	_, err := tx.Exec(ctx, `INSERT INTO clients (id, realm_id, client_id, project_id, name, description, client_type, token_endpoint_auth_method,
		grant_types, security_profile, first_party, consent_mode, allow_offline_access, allow_remember_me, default_resource_id,
		service_principal_id, environment, subject_type, sector_identifier, login_ui_url, backchannel_logout_uri, id_token_claims,
		access_token_claims, token_policy, owner_user_id, contacts, dynamically_registered, created_at, updated_at, consent_terms_version,
		protocol_options)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$28,$29,$30)`,
		ref, realmID, in.ClientID, nilIfEmpty(in.ProjectID), in.Name, nilIfEmpty(in.Description), in.Type, in.AuthMethod,
		in.GrantTypes, in.SecurityProfile, in.FirstParty, in.ConsentMode, in.AllowOfflineAccess, in.AllowRememberMe,
		nilIfEmpty(in.DefaultResourceID), nilIfEmpty(in.ServicePrincipalID), in.Environment, in.SubjectType,
		nilIfEmpty(in.SectorIdentifier), nilIfEmpty(in.LoginUIURL), nilIfEmpty(in.BackchannelLogoutURI), idc, atc, tp,
		nilIfEmpty(in.OwnerUserID), nonNilStrings(in.Contacts), in.DynamicallyRegistered, now, nilIfEmpty(in.ConsentTermsVersion), po)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, "", problem.ErrConflict.WithDetail("client_id already registered")
		}
		if storage.IsForeignKeyViolation(err) {
			return nil, "", problem.ErrValidation.WithDetail("referenced project, resource or service principal does not exist in this realm")
		}
		return nil, "", err
	}
	if err := s.replaceURIs(ctx, tx, realmID, ref, in.RedirectURIs, in.PostLogoutRedirects, in.Origins); err != nil {
		return nil, "", err
	}
	var plain string
	if strings.HasPrefix(in.AuthMethod, "client_secret") {
		plain, err = s.insertSecret(ctx, tx, realmID, ref, nil)
		if err != nil {
			return nil, "", err
		}
	}
	if len(in.JWKS) > 0 {
		if err := s.addJWKS(ctx, tx, realmID, ref, in.JWKS); err != nil {
			return nil, "", err
		}
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.created", RealmID: realmID, Actor: actor,
		Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"client_id": in.ClientID, "client_type": in.Type,
			"grant_types": in.GrantTypes, "security_profile": in.SecurityProfile}}); err != nil {
		return nil, "", err
	}
	c, err := s.ClientByRef(ctx, tx, realmID, ref)
	return c, plain, err
}

func (s *Service) replaceURIs(ctx context.Context, tx pgx.Tx, realmID, ref string, redirects, postLogout, origins []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM client_redirect_uris WHERE client_ref=$1`, ref); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM client_origins WHERE client_ref=$1`, ref); err != nil {
		return err
	}
	for _, u := range dedupe(redirects) {
		if _, err := tx.Exec(ctx, `INSERT INTO client_redirect_uris (id, realm_id, client_ref, uri, purpose) VALUES ($1,$2,$3,$4,'redirect')`,
			ids.New(ids.Redirect), realmID, ref, u); err != nil {
			return err
		}
	}
	for _, u := range dedupe(postLogout) {
		if _, err := tx.Exec(ctx, `INSERT INTO client_redirect_uris (id, realm_id, client_ref, uri, purpose) VALUES ($1,$2,$3,$4,'post_logout')`,
			ids.New(ids.Redirect), realmID, ref, u); err != nil {
			return err
		}
	}
	for _, o := range dedupe(origins) {
		if _, err := tx.Exec(ctx, `INSERT INTO client_origins (id, realm_id, client_ref, origin) VALUES ($1,$2,$3,$4)`,
			ids.New(ids.Origin), realmID, ref, o); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) insertSecret(ctx context.Context, tx pgx.Tx, realmID, ref string, expires *time.Time) (string, error) {
	plain := secret.Token(secret.PrefixClientSecret)
	_, err := tx.Exec(ctx, `INSERT INTO client_credentials (id, realm_id, client_ref, kind, secret_digest, display_prefix, expires_at, created_at)
		VALUES ($1,$2,$3,'secret',$4,$5,$6,$7)`, ids.New(ids.ClientCred), realmID, ref, secret.Digest(plain), plain[:12], expires, s.d.Now())
	return plain, err
}

// checkProjectEnvironment keeps a project's clients in the project's
// environment (APP-015).
func (s *Service) checkProjectEnvironment(ctx context.Context, q storage.Querier, realmID, projectID, env string) error {
	if projectID == "" {
		return nil
	}
	var projectEnv string
	if err := q.QueryRow(ctx, `SELECT coalesce(environment,'') FROM projects WHERE realm_id=$1 AND id=$2`, realmID, projectID).Scan(&projectEnv); err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrValidation.WithField("project_id", "unknown project")
		}
		return err
	}
	if projectEnv != "" && projectEnv != env {
		return problem.ErrValidation.WithField("environment", "the client must use its project's environment ("+projectEnv+")")
	}
	return nil
}

// UpdateClient replaces mutable client fields with optimistic concurrency (API-010).
func (s *Service) UpdateClient(ctx context.Context, realmID, ref string, expectedVersion int64, in ClientInput, actor audit.Ref) (*Client, error) {
	var out *Client
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.UpdateClientTx(ctx, tx, realmID, ref, expectedVersion, in, actor)
		return err
	})
	return out, err
}

// UpdateClientTx is UpdateClient inside tx.
func (s *Service) UpdateClientTx(ctx context.Context, tx pgx.Tx, realmID, ref string, expectedVersion int64, in ClientInput, actor audit.Ref) (*Client, error) {
	var out *Client
	err := func() error {
		cur, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, ref))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		in.ClientID = cur.ClientID
		if in.Type == "" {
			in.Type = cur.Type
		}
		// Environment separation (APP-015): a client's environment is fixed, so
		// a development client and its credentials are never promoted in place.
		if in.Environment == "" {
			in.Environment = cur.Environment
		}
		if in.Environment != cur.Environment {
			return problem.ErrValidation.WithField("environment", "a client's environment cannot change; register a new client for that environment")
		}
		if err := s.checkProjectEnvironment(ctx, tx, realmID, in.ProjectID, in.Environment); err != nil {
			return err
		}
		if in.Type != cur.Type {
			return problem.ErrValidation.WithField("client_type", "client type cannot change; register a new client")
		}
		if cur.Protocol == ProtocolSAML {
			// Its redirect and credentials are internal to the SAML profile.
			return problem.ErrConflict.WithDetail("this client backs a SAML application; change it through /saml/applications")
		}
		if perr := in.Normalize(); perr != nil {
			return perr
		}
		if perr := s.checkOwnOrigin(ctx, tx, realmID, &in); perr != nil {
			return perr
		}
		if perr := s.checkResponseSigning(ctx, realmID, &in); perr != nil {
			return perr
		}
		idc, _ := json.Marshal(nonNil(in.IDTokenClaims))
		atc, _ := json.Marshal(nonNil(in.AccessTokenClaims))
		tp, _ := json.Marshal(in.TokenPolicy)
		po, _ := json.Marshal(in.ProtocolOptions)
		_, err = tx.Exec(ctx, `UPDATE clients SET name=$3, description=$4, token_endpoint_auth_method=$5, grant_types=$6, security_profile=$7,
			first_party=$8, consent_mode=$9, allow_offline_access=$10, allow_remember_me=$11, default_resource_id=$12, service_principal_id=$13,
			environment=$14, subject_type=$15, sector_identifier=$16, login_ui_url=$17, backchannel_logout_uri=$18, id_token_claims=$19,
			access_token_claims=$20, token_policy=$21, owner_user_id=$22, contacts=$23, project_id=$24, version=version+1, updated_at=$25,
			consent_terms_version=$26, protocol_options=$27
			WHERE realm_id=$1 AND id=$2`, realmID, ref, in.Name, nilIfEmpty(in.Description), in.AuthMethod, in.GrantTypes, in.SecurityProfile,
			in.FirstParty, in.ConsentMode, in.AllowOfflineAccess, in.AllowRememberMe, nilIfEmpty(in.DefaultResourceID), nilIfEmpty(in.ServicePrincipalID),
			in.Environment, in.SubjectType, nilIfEmpty(in.SectorIdentifier), nilIfEmpty(in.LoginUIURL), nilIfEmpty(in.BackchannelLogoutURI),
			idc, atc, tp, nilIfEmpty(in.OwnerUserID), nonNilStrings(in.Contacts), nilIfEmpty(in.ProjectID), s.d.Now(), nilIfEmpty(in.ConsentTermsVersion), po)
		if err != nil {
			if storage.IsForeignKeyViolation(err) {
				return problem.ErrValidation.WithDetail("referenced project, resource or service principal does not exist in this realm")
			}
			return err
		}
		if err := s.replaceURIs(ctx, tx, realmID, ref, in.RedirectURIs, in.PostLogoutRedirects, in.Origins); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"client_id": cur.ClientID, "version": cur.Version + 1}}); err != nil {
			return err
		}
		out, err = s.ClientByRef(ctx, tx, realmID, ref)
		return err
	}()
	return out, err
}

// SetClientState suspends, reactivates or decommissions a client (APP-008). Suspension
// and decommissioning revoke the client's refresh families and live grants so no
// further issuance happens. A dynamically registered client whose registration
// is still pending cannot be activated this way: only the registration's
// approval activates it (APP-017).
func (s *Service) SetClientState(ctx context.Context, realmID, ref, state string, actor audit.Ref, reason string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.setClientStateTx(ctx, tx, realmID, ref, state, actor, reason, false)
	})
}

// setClientStateTx changes a client's state in tx; approving is set only by
// the approval of a pending registration.
func (s *Service) setClientStateTx(ctx context.Context, tx pgx.Tx, realmID, ref, state string, actor audit.Ref, reason string, approving bool) error {
	if state != "active" && state != "suspended" && state != "decommissioned" {
		return problem.ErrValidation.WithField("state", "must be active, suspended or decommissioned")
	}
	var cur string
	if err := tx.QueryRow(ctx, `SELECT state FROM clients WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, ref).Scan(&cur); err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	if cur == "decommissioned" {
		return problem.ErrConflict.WithDetail("decommissioned clients cannot change state")
	}
	if state == "active" && !approving {
		var approval string
		err := tx.QueryRow(ctx, `SELECT approval_state FROM client_registrations WHERE realm_id=$1 AND client_ref=$2`, realmID, ref).Scan(&approval)
		if err != nil && !storage.IsNoRows(err) {
			return err
		}
		if approval == "pending" {
			return problem.ErrConflict.WithDetail("the client's dynamic registration is pending approval; approve it with POST /client-registrations/{client}/approve")
		}
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE clients SET state=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND id=$2`, realmID, ref, state, now); err != nil {
		return err
	}
	if state != "active" {
		if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason='client_'||$3
			WHERE client_ref=$1 AND state='active'`, ref, now, state); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$2, revoke_reason='client_'||$3
			WHERE client_ref=$1 AND state='active'`, ref, now, state); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE client_ref=$1 AND revoked_at IS NULL`, ref, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
			VALUES ($1,$2,'client',$3,$4,$5)`, ids.New(ids.Revocation), realmID, ref, "client_"+state, now); err != nil {
			return err
		}
	}
	if state == "decommissioned" {
		if _, err := tx.Exec(ctx, `UPDATE client_credentials SET state='revoked', revoked_at=$2 WHERE client_ref=$1 AND state='active'`, ref, now); err != nil {
			return err
		}
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client." + state, RealmID: realmID, Actor: actor,
		Target: &audit.Ref{Type: "client", ID: ref}, ReasonCode: reason}); err != nil {
		return err
	}
	_, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "client.state_changed", RealmID: realmID,
		AggregateType: "client", AggregateID: ref, Data: map[string]any{"client_ref": ref, "state": state}})
	return err
}

// ClientCredential is safe metadata about a client credential (no secret material).
type ClientCredential struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	DisplayPrefix string     `json:"display_prefix,omitempty"`
	KeyID         string     `json:"key_id,omitempty"`
	State         string     `json:"state"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// IssueSecret creates an additional secret for overlapping rotation (APP-003). When
// retireOthersAfter > 0 every other active secret is given that bounded expiry.
func (s *Service) IssueSecret(ctx context.Context, realmID, ref string, retireOthersAfter time.Duration, actor audit.Ref) (string, *ClientCredential, error) {
	var plain string
	var meta *ClientCredential
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		plain, meta, err = s.IssueSecretTx(ctx, tx, realmID, ref, retireOthersAfter, actor)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return plain, meta, nil
}

// IssueSecretTx is IssueSecret inside the caller's transaction, so a
// rotation can be part of a larger change that commits or fails as a whole
// (RFC 7592 updates). limits.client_secrets_max bounds the secrets that are
// still usable: a secret past its expiry no longer counts, as it no longer
// authenticates.
func (s *Service) IssueSecretTx(ctx context.Context, tx pgx.Tx, realmID, ref string, retireOthersAfter time.Duration, actor audit.Ref) (string, *ClientCredential, error) {
	var method string
	if err := tx.QueryRow(ctx, `SELECT token_endpoint_auth_method FROM clients WHERE realm_id=$1 AND id=$2 AND state <> 'decommissioned' FOR UPDATE`,
		realmID, ref).Scan(&method); err != nil {
		if storage.IsNoRows(err) {
			return "", nil, problem.ErrNotFound
		}
		return "", nil, err
	}
	if !strings.HasPrefix(method, "client_secret") {
		return "", nil, problem.ErrValidation.WithDetail("client does not use shared secrets")
	}
	now := s.d.Now()
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM client_credentials WHERE client_ref=$1 AND kind='secret' AND state='active'
		AND (expires_at IS NULL OR expires_at > $2)`, ref, now).Scan(&active); err != nil {
		return "", nil, err
	}
	if active >= s.d.Cfg.Limits.ClientSecretsMax {
		return "", nil, problem.ErrConflict.WithDetailf("at most %d overlapping secrets (limits.client_secrets_max); revoke an old secret first", s.d.Cfg.Limits.ClientSecretsMax)
	}
	if retireOthersAfter > 0 {
		if _, err := tx.Exec(ctx, `UPDATE client_credentials SET expires_at=LEAST(coalesce(expires_at, $2), $2)
			WHERE client_ref=$1 AND kind='secret' AND state='active'`, ref, now.Add(retireOthersAfter)); err != nil {
			return "", nil, err
		}
	}
	plain, err := s.insertSecret(ctx, tx, realmID, ref, nil)
	if err != nil {
		return "", nil, err
	}
	var meta ClientCredential
	if err := tx.QueryRow(ctx, `SELECT id, kind, coalesce(display_prefix,''), coalesce(key_id,''), state, expires_at, last_used_at, created_at
		FROM client_credentials WHERE secret_digest=$1`, secret.Digest(plain)).Scan(&meta.ID, &meta.Kind, &meta.DisplayPrefix, &meta.KeyID,
		&meta.State, &meta.ExpiresAt, &meta.LastUsedAt, &meta.CreatedAt); err != nil {
		return "", nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.credential.issued", RealmID: realmID, Actor: actor,
		Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"credential_id": meta.ID, "display_prefix": meta.DisplayPrefix}}); err != nil {
		return "", nil, err
	}
	return plain, &meta, nil
}

// RevokeCredential revokes one client credential.
func (s *Service) RevokeCredential(ctx context.Context, realmID, ref, credID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE client_credentials SET state='revoked', revoked_at=$4 WHERE realm_id=$1 AND client_ref=$2 AND id=$3 AND state='active'`,
			realmID, ref, credID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.credential.revoked", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"credential_id": credID}})
		return err
	})
}

// ListCredentials lists safe credential metadata (MCH-008).
func (s *Service) ListCredentials(ctx context.Context, realmID, ref string) ([]ClientCredential, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, kind, coalesce(display_prefix,''), coalesce(key_id,''), state, expires_at, last_used_at, created_at
		FROM client_credentials WHERE realm_id=$1 AND client_ref=$2 ORDER BY created_at`, realmID, ref)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientCredential{}
	for rows.Next() {
		var m ClientCredential
		if err := rows.Scan(&m.ID, &m.Kind, &m.DisplayPrefix, &m.KeyID, &m.State, &m.ExpiresAt, &m.LastUsedAt, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListClients pages through clients ordered by creation (API-004).
func (s *Service) ListClients(ctx context.Context, realmID, after string, limit int) ([]*Client, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=$1 AND ($2 = '' OR id > $2) ORDER BY id LIMIT $3`,
		realmID, after, limit)
	if err != nil {
		return nil, err
	}
	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	for _, c := range out {
		if err := s.loadClientURIs(ctx, s.d.DB.Pool, c); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ---------- helpers ----------

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// commonRedirectHost returns the single host shared by all redirect URIs, or "".
func commonRedirectHost(uris []string) string {
	host := ""
	for _, ru := range uris {
		u, err := url.Parse(ru)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		h := strings.ToLower(u.Hostname())
		if host != "" && h != host {
			return ""
		}
		host = h
	}
	return host
}

func nilIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
