// Package oauth implements the OAuth 2.0 / OpenID Connect protocol endpoints:
// authorization, token (code+PKCE, refresh, client credentials, device, exchange),
// introspection, revocation, discovery, JWKS, UserInfo and logout (§14, §18).
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/hooks"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/token"
	"github.com/proudauth/proudauth/internal/workload"
)

// Error is an OAuth protocol error (RFC 6749 §5.2) rendered in the protocol's own
// format rather than problem details (API-001, API-007).
type Error struct {
	Code        string        `json:"error"`
	Description string        `json:"error_description,omitempty"`
	Status      int           `json:"-"`
	RetryAfter  time.Duration `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

// serverError maps an internal failure to an OAuth error: protocol errors raised
// inside a transaction (e.g. a budget refusal) keep their code; anything else is
// logged and reported as server_error without detail.
func serverError(s *Service, err error) *Error {
	var oe *Error
	if errors.As(err, &oe) {
		return oe
	}
	s.d.Log.Error("token endpoint failure", "error", err)
	return ErrServerError
}

func oerr(status int, code, desc string) *Error {
	return &Error{Code: code, Description: desc, Status: status}
}

// Common protocol errors.
var (
	ErrInvalidRequest = func(d string) *Error { return oerr(400, "invalid_request", d) }
	ErrInvalidClient  = oerr(401, "invalid_client", "client authentication failed")
	// ErrInvalidClientMetadata reports a registration the server cannot
	// honour at issuance (for example encryption without a usable key).
	ErrInvalidClientMetadata  = func(d string) *Error { return oerr(400, "invalid_client_metadata", d) }
	ErrInvalidGrant           = func(d string) *Error { return oerr(400, "invalid_grant", d) }
	ErrUnauthorizedClient     = func(d string) *Error { return oerr(400, "unauthorized_client", d) }
	ErrUnsupportedGrantType   = oerr(400, "unsupported_grant_type", "grant type not supported")
	ErrInvalidScope           = func(d string) *Error { return oerr(400, "invalid_scope", d) }
	ErrInvalidTarget          = func(d string) *Error { return oerr(400, "invalid_target", d) }
	ErrServerError            = oerr(500, "server_error", "")
	ErrTemporarilyUnavailable = oerr(503, "temporarily_unavailable", "")
	ErrSlowDown               = oerr(400, "slow_down", "")
	ErrAuthorizationPending   = oerr(400, "authorization_pending", "")
	ErrExpiredToken           = oerr(400, "expired_token", "")
	ErrAccessDenied           = oerr(400, "access_denied", "")
)

// Service implements the protocol.
type Service struct {
	d        *runtime.Deps
	Realms   *realm.Service
	Apps     *application.Service
	Users    *identity.Service
	Sessions *session.Service
	Orgs     *organization.Service
	Authz    *authorization.Service
	Auth     *authentication.Service
	KeyMgr   *token.KeyManager
	Signer   *token.Signer
	Verifier *token.Verifier
	Limiter  *ratelimit.Limiter
	// Hooks runs claims-enrichment hooks; nil disables them.
	Hooks *hooks.Service
	// Workload verifies federated workload assertions (MCH-011); nil
	// disables the jwt-bearer grant.
	Workload *workload.Service
	// Exchange and impersonation hooks are wired by the server (P1).
	Impersonation ImpersonationIntrospector
}

// ImpersonationIntrospector validates support-access tokens on each introspection
// (strict-online, IMP-010).
type ImpersonationIntrospector interface {
	ValidateGrant(ctx context.Context, q interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	}, realmID, grantID string) (map[string]any, bool)
}

// NewService builds the protocol service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

// IssuedTokens is a token-endpoint response.
type IssuedTokens struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// AccessSpec describes an access token to mint.
type AccessSpec struct {
	Realm        *realm.Realm
	Client       *application.Client
	Resource     *application.Resource
	SubjectType  string // user | service_principal
	SubjectID    string
	Scopes       []string
	OrgID        string
	SessionID    string
	GrantID      string
	AuthTime     *time.Time
	ACR          string
	AMR          []string
	Actor        *token.Actor
	Kind         string
	AuthzVersion int64
	TTLCap       time.Duration
	Confirmation *token.Confirmation
}

func (s *Service) accessTTL(sp AccessSpec) time.Duration {
	ttl := s.d.Cfg.Tokens.AccessTokenTTL
	var pol realm.TokenLifetimePolicy
	if sp.Realm != nil {
		pol = sp.Realm.Policy.Tokens
	}
	if sp.Resource != nil && sp.Resource.AccessTokenTTL > 0 {
		ttl = time.Duration(sp.Resource.AccessTokenTTL) * time.Second
	}
	if sp.Client != nil && sp.Client.TokenPolicy.AccessTokenTTLSeconds > 0 {
		if c := time.Duration(sp.Client.TokenPolicy.AccessTokenTTLSeconds) * time.Second; c < ttl {
			ttl = c
		}
	}
	// Realm limits by subject type, assurance and support status (TOK-018).
	limit := func(seconds int) {
		if d := time.Duration(seconds) * time.Second; seconds > 0 && d < ttl {
			ttl = d
		}
	}
	limit(pol.AccessTokenTTLSeconds)
	if sp.SubjectType == "service_principal" {
		limit(pol.ServiceAccessTokenTTLSeconds)
	}
	if sp.SubjectType == "user" && session.ACRRank(sp.ACR) < session.ACRRank("urn:proudauth:acr:mfa") {
		limit(pol.SingleFactorAccessTokenTTLSeconds)
	}
	if sp.Kind == token.KindImpersonationAccess {
		limit(pol.ImpersonationAccessTokenTTLSeconds)
	}
	if sp.Client != nil && sp.Client.FAPI2() {
		limit(600) // FAPI 2.0: short-lived access tokens (ADV-001)
	}
	if sp.TTLCap > 0 && sp.TTLCap < ttl {
		ttl = sp.TTLCap
	}
	if ttl > s.d.Cfg.Tokens.MaxAccessTokenTTL {
		ttl = s.d.Cfg.Tokens.MaxAccessTokenTTL
	}
	return ttl
}

// MintAccess issues a JWT or opaque access token according to the resource's token
// format (TOK-004, §37.1). Opaque tokens are persisted inside tx.
func (s *Service) MintAccess(ctx context.Context, tx pgx.Tx, sp AccessSpec) (string, time.Duration, error) {
	now := s.d.Now()
	if sp.OrgID != "" && s.Limiter != nil {
		// Per-organization issuance budget: one tenant cannot exhaust token
		// issuance capacity for everyone else (TEN-018, SEC-006).
		rl := s.d.Cfg.Security.RateLimits
		if d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "token-org:" + sp.OrgID, Limit: rl.OrganizationPerWindow, Window: rl.TokenWindow}); err != nil {
			return "", 0, oerr(503, "temporarily_unavailable", "organization budget unavailable")
		} else if !d.Allowed {
			e := oerr(429, "slow_down", "organization token budget exhausted")
			e.RetryAfter = d.RetryAfter
			return "", 0, e
		}
	}
	ttl := s.accessTTL(sp)
	if sp.Kind == "" {
		sp.Kind = token.KindUserAccess
	}
	if sp.Resource.TokenFormat == "opaque" {
		var actor []byte
		if sp.Actor != nil {
			actor, _ = json.Marshal(sp.Actor)
		}
		prefix := secret.PrefixOpaqueAccess
		if sp.Kind == token.KindImpersonationAccess {
			prefix = secret.PrefixImpersonation
		}
		var cnf []byte
		if sp.Confirmation != nil {
			cnf, _ = json.Marshal(sp.Confirmation)
		}
		plain, err := s.Sessions.IssueOpaqueTx(ctx, tx, prefix, &session.OpaqueToken{RealmID: sp.Realm.ID, Kind: sp.Kind, GrantID: sp.GrantID,
			ClientRef: sp.Client.Ref, SubjectType: sp.SubjectType, SubjectID: sp.SubjectID, Actor: actor, OrgID: sp.OrgID,
			ResourceID: sp.Resource.ID, Scopes: sp.Scopes, SessionID: sp.SessionID, AuthTime: sp.AuthTime, ACR: sp.ACR, ExpiresAt: now.Add(ttl), Cnf: cnf})
		return plain, ttl, err
	}
	claims := token.AccessClaims{
		Issuer: sp.Realm.Issuer, Subject: sp.SubjectID, Audience: jwt.Audience{sp.Resource.Audience}, ClientID: sp.Client.ClientID,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(ttl).Unix(), JTI: ids.New(ids.AccessToken), SessionID: sp.SessionID,
		Scope: strings.Join(sp.Scopes, " "), OrgID: sp.OrgID, ProjectID: sp.Resource.ProjectID, TokenKind: sp.Kind, GrantID: sp.GrantID,
		AuthzVersion: sp.AuthzVersion, ACR: sp.ACR, Act: sp.Actor, Cnf: sp.Confirmation,
	}
	if sp.AuthTime != nil {
		claims.AuthTime = sp.AuthTime.Unix()
	}
	if sp.SubjectType == "service_principal" {
		claims.Agent = s.isAgent(ctx, tx, sp.Realm.ID, sp.SubjectID)
	}
	if sp.Resource.Kind != application.KindBusiness {
		claims.OrgID = "" // account/admin/userinfo tokens are never business-organization tokens (DOM-003)
	}
	// Approved non-sensitive claim mappings only (TOK-014, TOK-015, APP-011).
	if len(sp.Client.AccessTokenClaims) > 0 {
		claims.Extra = map[string]any{}
		src := application.ClaimSource{}
		if sp.SubjectType == "user" && application.HasMappings(sp.Client.AccessTokenClaims) {
			var q storage.Querier = s.d.DB.Pool
			if tx != nil {
				q = tx
			}
			// Attribute values are profile data: they are released only when
			// the grant includes the profile scope the user consented to.
			profile := slices.Contains(sp.Scopes, "profile")
			if !profile && sp.GrantID != "" {
				_ = q.QueryRow(ctx, `SELECT 'profile' = ANY(scopes) FROM authorization_grants WHERE id=$1`, sp.GrantID).Scan(&profile)
			}
			if u, err := s.Users.User(ctx, q, sp.Realm.ID, sp.SubjectID); err == nil && profile {
				src = claimSource(sp.Realm, u)
			}
		}
		for k, v := range application.ResolveClaims(sp.Client.AccessTokenClaims, src) {
			// Standard user claims carry verified provenance elsewhere; a
			// mapping or its default never stands in for them, even for
			// clients registered before the rule (APP-011, OIDC-007).
			if !token.ReservedClaims[k] && !application.IsStandardUserClaim(k) {
				claims.Extra[k] = v
			}
		}
	}
	// Claims-enrichment hooks add non-reserved claims; they cannot change
	// subject, audience, scope or any other reserved claim (EXT-011).
	if s.Hooks != nil {
		extra, err := s.Hooks.Claims(ctx, sp.Realm.ID, hooks.ClaimsInput{SubjectType: sp.SubjectType, SubjectID: sp.SubjectID, ClientID: sp.Client.ClientID,
			Audience: sp.Resource.Audience, Scopes: sp.Scopes, OrgID: claims.OrgID, TokenKind: sp.Kind})
		if err != nil {
			return "", 0, oerr(503, "temporarily_unavailable", "a required token policy check is unavailable")
		}
		if len(extra) > 0 && claims.Extra == nil {
			claims.Extra = map[string]any{}
		}
		for k, v := range extra {
			claims.Extra[k] = v
		}
	}
	// The resource's algorithm profile is enforced at issuance (TOK-005): a
	// key of another algorithm never signs tokens for a pinned resource.
	if want := sp.Resource.SigningAlgorithm; want != "" && sp.Resource.Kind == application.KindBusiness {
		alg, err := s.Signer.ActiveAlgorithm(ctx, sp.Realm.ID)
		if err != nil {
			return "", 0, err
		}
		if alg != want {
			s.d.Log.Error("active signing key does not match the resource algorithm profile", "resource", sp.Resource.Audience, "want", want, "active", alg)
			return "", 0, oerr(503, "temporarily_unavailable", "no signing key satisfies the resource's algorithm profile")
		}
	}
	signed, err := s.Signer.Sign(ctx, sp.Realm.ID, token.TypeAccess, claims)
	return signed, ttl, err
}

// IDSpec describes an ID token.
type IDSpec struct {
	Realm       *realm.Realm
	Client      *application.Client
	User        *identity.User
	Scopes      []string
	Nonce       string
	SessionID   string
	AuthTime    *time.Time
	ACR         string
	AMR         []string
	AccessToken string
	Code        string
	OrgID       string
	// ClaimsRequest narrows ID-token user claims to the "id_token" member of
	// the OIDC claims parameter (OIDC-008).
	ClaimsRequest string
}

// SubjectFor returns the subject identifier presented to a client: public (the
// immutable user ID) or pairwise per sector (APP-012, OIDC-010).
//
// Pairwise values are derived with the realm secret on first use and then
// kept in pairwise_subjects, so they stay stable across root-key rotation and
// disappear with the user (OIDC-010).
func (s *Service) SubjectFor(ctx context.Context, c *application.Client, userID string) (string, error) {
	if c.SubjectType != "pairwise" {
		return userID, nil
	}
	var sub string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT subject FROM pairwise_subjects WHERE realm_id=$1 AND sector=$2 AND user_id=$3`,
		c.RealmID, c.SectorIdentifier, userID).Scan(&sub)
	if err == nil {
		return sub, nil
	}
	b := s.d.Keys.DeriveBytes(keys.PurposePairwise, c.SectorIdentifier, userID)
	sub = "pws_" + base64.RawURLEncoding.EncodeToString(b[:20])
	if _, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO pairwise_subjects (realm_id, sector, user_id, subject) VALUES ($1,$2,$3,$4)
		ON CONFLICT (realm_id, sector, user_id) DO NOTHING`, c.RealmID, c.SectorIdentifier, userID, sub); err != nil {
		return "", err
	}
	err = s.d.DB.Pool.QueryRow(ctx, `SELECT subject FROM pairwise_subjects WHERE realm_id=$1 AND sector=$2 AND user_id=$3`,
		c.RealmID, c.SectorIdentifier, userID).Scan(&sub)
	return sub, err
}

// UserClaims returns claims released for the scopes (OIDC-007, minimal disclosure).
func UserClaims(u *identity.User, scopes []string) map[string]any {
	out := map[string]any{}
	if slices.Contains(scopes, "profile") {
		if u.DisplayName != "" {
			out["name"] = u.DisplayName
		}
		if u.GivenName != "" {
			out["given_name"] = u.GivenName
		}
		if u.FamilyName != "" {
			out["family_name"] = u.FamilyName
		}
		if u.Locale != "" {
			out["locale"] = u.Locale
		}
		if u.Zoneinfo != "" {
			out["zoneinfo"] = u.Zoneinfo
		}
		if un := u.Username(); un != "" {
			out["preferred_username"] = un
		}
		out["updated_at"] = u.UpdatedAt.Unix()
	}
	if slices.Contains(scopes, "email") {
		if e := u.PrimaryEmail(); e != nil {
			out["email"] = e.Value
			out["email_verified"] = e.Verified()
		}
	}
	if slices.Contains(scopes, "phone") {
		for _, i := range u.Identifiers {
			if i.Type == "phone" && i.IsPrimary {
				out["phone_number"] = i.Value
				out["phone_number_verified"] = i.Verified()
			}
		}
	}
	if slices.Contains(scopes, "address") {
		if a, ok := u.Profile["address"].(map[string]any); ok {
			out["address"] = a
		}
	}
	return out
}

// MintID issues an ID token (OIDC-003). It authenticates the user to the client
// only and has its own JOSE type so it is never accepted as an access token.
func (s *Service) MintID(ctx context.Context, sp IDSpec) (string, error) {
	now := s.d.Now()
	alg, err := s.Signer.ActiveAlgorithm(ctx, sp.Realm.ID)
	if err != nil {
		return "", err
	}
	subject, err := s.SubjectFor(ctx, sp.Client, sp.User.ID)
	if err != nil {
		return "", err
	}
	c := token.IDClaims{Issuer: sp.Realm.Issuer, Subject: subject, Audience: jwt.Audience{sp.Client.ClientID},
		Expiry: now.Add(s.d.Cfg.Tokens.IDTokenTTL).Unix(), IssuedAt: now.Unix(), Nonce: sp.Nonce, ACR: sp.ACR, AMR: sp.AMR,
		AZP: sp.Client.ClientID, SessionID: sp.SessionID, OrgID: sp.OrgID, Claims: releaseFor(UserClaims(sp.User, sp.Scopes), sp.ClaimsRequest, "id_token")}
	if sp.AuthTime != nil {
		c.AuthTime = sp.AuthTime.Unix()
	}
	if sp.AccessToken != "" {
		c.AtHash = token.HalfHash(alg, sp.AccessToken)
	}
	if sp.Code != "" {
		c.CHash = token.HalfHash(alg, sp.Code)
	}
	src := application.ClaimSource{}
	if sp.User != nil && application.HasMappings(sp.Client.IDTokenClaims) && slices.Contains(sp.Scopes, "profile") {
		src = claimSource(sp.Realm, sp.User)
	}
	for k, v := range application.ResolveClaims(sp.Client.IDTokenClaims, src) {
		// Static mappings never overwrite reserved claims or user claims with
		// verified provenance (OIDC-007), even for clients registered earlier.
		if _, released := c.Claims[k]; !token.ReservedClaims[k] && !released && !application.IsStandardUserClaim(k) {
			c.Claims[k] = v
		}
	}
	signed, err := s.Signer.Sign(ctx, sp.Realm.ID, token.TypeID, c)
	if err != nil || sp.Client.IDTokenEncryptedResponseAlg == "" {
		return signed, err
	}
	// A nested JWT (TOK-020): signed, then encrypted to the client.
	return s.encryptTo(ctx, sp.Client, []byte(signed), sp.Client.IDTokenEncryptedResponseAlg, sp.Client.IDTokenEncryptedResponseEnc, "JWT")
}

// isAgent reports a service principal registered as an autonomous agent
// (MCH-017).
func (s *Service) isAgent(ctx context.Context, q pgx.Tx, realmID, spID string) bool {
	var agent bool
	if spID == "" {
		return false
	}
	if q != nil {
		_ = q.QueryRow(ctx, `SELECT is_agent FROM service_principals WHERE realm_id=$1 AND id=$2`, realmID, spID).Scan(&agent)
	} else {
		_ = s.d.DB.Pool.QueryRow(ctx, `SELECT is_agent FROM service_principals WHERE realm_id=$1 AND id=$2`, realmID, spID).Scan(&agent)
	}
	return agent
}

// authzVersion returns the authorization revision used as a consistency hint.
func (s *Service) authzVersion(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, subjectType, subjectID, orgID string) int64 {
	var v int64
	switch {
	case subjectType == "service_principal":
		_ = q.QueryRow(ctx, `SELECT permission_revision FROM service_principals WHERE id=$1`, subjectID).Scan(&v)
	case orgID != "":
		_ = q.QueryRow(ctx, `SELECT m.revision + o.authz_revision FROM memberships m JOIN organizations o ON o.id=m.organization_id
			WHERE m.organization_id=$1 AND m.user_id=$2 AND m.state='active'`, orgID, subjectID).Scan(&v)
	default:
		_ = q.QueryRow(ctx, `SELECT authz_revision FROM users WHERE id=$1`, subjectID).Scan(&v)
	}
	return v
}

// claimSource exposes the approved attributes of a user to claim mappings
// (APP-011): standard name and locale fields, and the profile attributes the
// realm marked claimable.
func claimSource(rlm *realm.Realm, u *identity.User) application.ClaimSource {
	claimable := map[string]bool{}
	for _, a := range rlm.Policy.Profile.Attributes {
		// A policy stored before claimable and user-editable became exclusive
		// still never releases user-set values.
		if a.Claimable && !a.UserEditable {
			claimable[a.Name] = true
		}
	}
	return application.ClaimSource{
		User: map[string]string{"given_name": u.GivenName, "family_name": u.FamilyName, "display_name": u.DisplayName,
			"locale": u.Locale, "zoneinfo": u.Zoneinfo},
		Profile: u.Profile, Claimable: claimable}
}
