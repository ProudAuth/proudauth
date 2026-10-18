package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/certauth"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/token"
)

// TokenRequest carries the token endpoint form and client authentication.
type TokenRequest struct {
	Form       url.Values
	Auth       application.ClientAuthInput
	Endpoint   string
	DPoPProof  string
	HTTPMethod string
	HTTPURL    string
	ClientIP   string
}

// Token dispatches token endpoint grants (TOK-001). There is deliberately no
// password grant and no "mint a token for any user" operation (§18.2).
func (s *Service) Token(ctx context.Context, rlm *realm.Realm, req TokenRequest) (*IssuedTokens, *Error) {
	if s.Hooks != nil && s.Hooks.HasActive(ctx, rlm.ID) {
		// Claims hooks run inside the issuance transaction; it is not retried,
		// so a hook call is never repeated (DB-014).
		ctx = storage.NoRetry(ctx)
	}
	for k, v := range req.Form {
		if k != "resource" && len(v) > 1 {
			return nil, ErrInvalidRequest("parameter " + k + " must not repeat")
		}
	}
	if !rlm.Active() {
		return nil, ErrInvalidGrant("identity domain unavailable")
	}
	c, err := s.Apps.Authenticate(ctx, rlm.ID, rlm.Issuer, req.Endpoint, req.Auth)
	if err != nil {
		_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "client.authentication.failed", RealmID: rlm.ID,
			Actor: audit.Ref{Type: "client", ID: firstNonEmpty(req.Auth.BasicID, req.Auth.FormClientID, "unknown")}, Outcome: audit.Failure})
		return nil, ErrInvalidClient
	}
	rl := s.d.Cfg.Security.RateLimits
	// Budgets fail closed: an unavailable limiter refuses issuance (SEC-006).
	if d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "token-client:" + c.Ref, Limit: rl.TokenPerClient, Window: rl.TokenWindow}); err != nil {
		return nil, oerr(503, "temporarily_unavailable", "request budget unavailable")
	} else if !d.Allowed {
		e := oerr(429, "slow_down", "token request budget exhausted")
		e.RetryAfter = d.RetryAfter
		return nil, e
	}
	grant := req.Form.Get("grant_type")
	if c.AllowsGrant(grant) && !grantAllowed(rlm, c, grant) {
		return nil, ErrUnauthorizedClient("this grant type is disabled by an emergency control")
	}
	if !c.AllowsGrant(grant) {
		if grant == "" {
			return nil, ErrInvalidRequest("grant_type is required")
		}
		if grant == "password" || grant == "implicit" {
			return nil, ErrUnsupportedGrantType
		}
		return nil, ErrUnauthorizedClient("grant type not allowed for this client")
	}
	if c.TokenPolicy.RequireDPoP && req.DPoPProof == "" {
		return nil, ErrInvalidRequest("this client requires DPoP-bound tokens")
	}
	var cnf *token.Confirmation
	// proof is what the request proves about its sender, whatever the
	// client's binding policy: the key of its DPoP proof and the TLS client
	// certificate of its connection. Sender-bound refresh families are
	// checked against it (TOK-019).
	var proof session.SenderBinding
	if req.DPoPProof != "" {
		jkt, oe := s.VerifyDPoPProof(ctx, rlm, req.DPoPProof, req.HTTPMethod, req.HTTPURL, "")
		if oe != nil {
			return nil, oe
		}
		cnf = &token.Confirmation{JKT: jkt}
		proof.JKT = jkt
	}
	if req.Auth.Certificate != nil {
		proof.X5TS256 = certauth.Thumbprint(req.Auth.Certificate)
	}
	// Certificate-bound tokens (RFC 8705, TOK-019): a client registered for
	// them gets tokens bound to the presented TLS certificate, and none
	// without one; it never silently falls back to bearer tokens.
	if c.TLSClientCertificateBoundAccessTokens {
		if req.Auth.Certificate == nil {
			return nil, ErrInvalidRequest("this client's tokens are bound to its TLS client certificate; use the mutual-TLS endpoint")
		}
		if cnf != nil {
			return nil, ErrInvalidRequest("use one sender constraint: DPoP or a TLS client certificate")
		}
		cnf = &token.Confirmation{X5TS256: certauth.Thumbprint(req.Auth.Certificate)}
	}
	switch grant {
	case application.GrantAuthorizationCode:
		return s.codeGrant(ctx, rlm, c, req.Form, cnf)
	case application.GrantRefreshToken:
		return s.refreshGrant(ctx, rlm, c, req.Form, cnf, proof)
	case application.GrantClientCredentials:
		return s.clientCredentialsGrant(ctx, rlm, c, req.Form, cnf)
	case application.GrantDeviceCode:
		return s.deviceGrant(ctx, rlm, c, req.Form, cnf)
	case application.GrantTokenExchange:
		return s.exchangeGrant(ctx, rlm, c, req.Form, cnf)
	case application.GrantJWTBearer:
		return s.jwtBearerGrant(ctx, rlm, c, req.Form, cnf)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

// grantAllowed reports whether the client may use the grant type now: it must
// be registered for the client and not disabled by a realm emergency control
// (SEC-020). The operator CLI client is exempt so the control can be reversed.
func grantAllowed(rlm *realm.Realm, c *application.Client, grant string) bool {
	return c.AllowsGrant(grant) && (c.ClientID == application.OperatorClientID || !rlm.GrantDisabled(grant))
}

// tokenTypeFor names the token_type of an issued access token: "DPoP" for a
// token bound to a DPoP key (RFC 9449 §5), "Bearer" for every other token,
// certificate-bound tokens included (RFC 8705 §3: they are presented with
// the Bearer scheme and the binding is proven by the TLS connection).
func tokenTypeFor(cnf *token.Confirmation) string {
	if cnf != nil && cnf.JKT != "" {
		return "DPoP"
	}
	return "Bearer"
}

// verifyPKCE checks an S256 verifier (RFC 7636).
func verifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || strings.Trim(verifier, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") != "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return secret.Equal(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

func (s *Service) codeGrant(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation) (*IssuedTokens, *Error) {
	code, verifier, redirect := f.Get("code"), f.Get("code_verifier"), f.Get("redirect_uri")
	if code == "" || verifier == "" || redirect == "" {
		return nil, ErrInvalidRequest("code, code_verifier and redirect_uri are required")
	}
	var out *IssuedTokens
	var oe *Error
	var replayed bool
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		oe, replayed = nil, false
		stored, err := s.Sessions.ConsumeCodeTx(ctx, tx, rlm.ID, code)
		if err != nil {
			if errors.Is(err, session.ErrCodeReplay) && stored != nil {
				// A replayed code revokes everything it produced (RFC 9700 §4.5) and the
				// revocation is committed even though the request fails.
				if err := s.Sessions.RevokeGrantTx(ctx, tx, stored.GrantID, "code_replay"); err != nil {
					return err
				}
				if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.code.replay_detected", RealmID: rlm.ID, Actor: audit.Ref{Type: "client", ID: c.Ref},
					GrantID: stored.GrantID, Outcome: audit.Denied, ReasonCode: "CODE_REPLAY"}); err != nil {
					return err
				}
				replayed = true
				return nil
			}
			oe = ErrInvalidGrant("invalid authorization code")
			return nil
		}
		// Binding checks (TEST-028): same client, exact redirect, PKCE verifier.
		if stored.ClientRef != c.Ref || stored.RedirectURI != redirect || !verifyPKCE(verifier, stored.Challenge) {
			if err := s.Sessions.RevokeGrantTx(ctx, tx, stored.GrantID, "code_binding_failed"); err != nil {
				return err
			}
			oe = ErrInvalidGrant("authorization code binding failed")
			return nil
		}
		// DPoP binding (RFC 9449 §10, TOK-019): a code whose authorization
		// request carried dpop_jkt (or whose pushed request carried a DPoP
		// proof) is redeemed only with a DPoP proof of that key. A failure
		// is a binding failure like the others: the code is spent and the
		// grant revoked.
		if stored.DPoPJKT != "" && (cnf == nil || cnf.JKT != stored.DPoPJKT) {
			if err := s.Sessions.RevokeGrantTx(ctx, tx, stored.GrantID, "code_binding_failed"); err != nil {
				return err
			}
			oe = ErrInvalidGrant("authorization code binding failed: the code is bound to the DPoP key named by dpop_jkt")
			return nil
		}
		g, err := s.Sessions.GrantTx(ctx, tx, stored.GrantID)
		if err != nil {
			return err
		}
		if g.State != "active" {
			oe = ErrInvalidGrant("grant is no longer active")
			return nil
		}
		out, oe, err = s.issueForUserGrant(ctx, tx, rlm, c, g, g.Scopes, f["resource"], stored.Nonce, true, cnf)
		if err != nil {
			return err
		}
		if oe != nil {
			return nil
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.issued", RealmID: rlm.ID, OrgID: g.OrgID, Actor: audit.Ref{Type: "client", ID: c.Ref},
			Subject: &audit.Ref{Type: "user", ID: g.SubjectID}, ClientID: c.ClientID, GrantID: g.ID, SessionID: g.SessionID, Category: "token",
			Metadata: map[string]any{"grant_type": "authorization_code", "refresh_issued": out.RefreshToken != ""}})
		return err
	})
	if err != nil {
		return nil, serverError(s, err)
	}
	if replayed {
		return nil, ErrInvalidGrant("authorization code already used")
	}
	return out, oe
}

// validateUserAccess re-checks live state before any issuance for a user grant.
func (s *Service) validateUserAccess(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, c *application.Client, g *session.Grant) (*identity.User, *Error) {
	if !c.Active() {
		return nil, ErrInvalidGrant("client is not active")
	}
	u, err := s.Users.User(ctx, tx, rlm.ID, g.SubjectID)
	if err != nil || !u.CanAuthenticate(s.d.Now()) {
		return nil, ErrInvalidGrant("account is not active")
	}
	if g.SessionID != "" && !g.Offline {
		if _, err := s.Sessions.Active(ctx, tx, rlm.ID, g.SessionID); err != nil {
			return nil, ErrInvalidGrant("session is no longer active")
		}
	}
	if g.OrgID != "" {
		if _, err := s.Orgs.LockActiveTx(ctx, tx, rlm.ID, g.OrgID); err != nil {
			return nil, ErrInvalidGrant("organization is not active")
		}
		if _, err := s.Orgs.ActiveMembership(ctx, tx, rlm.ID, g.OrgID, g.SubjectID); err != nil {
			return nil, ErrInvalidGrant("membership is not active")
		}
	}
	return u, nil
}

// issueForUserGrant mints tokens for a user grant. The access token names exactly one
// audience: the requested resource, or the first resource of the grant (TOK-007).
//
// A failure that is a configuration problem rather than a property of the
// presented credential (no active signing key, or no client key for the
// registered response encryption, TOK-020) is returned as the error, not
// as the protocol error: the caller's transaction then rolls back, so the
// authorization code, device code or refresh token it consumed stays usable
// once the configuration is fixed, and a retry is never mistaken for a
// replay that revokes the grant.
func (s *Service) issueForUserGrant(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, c *application.Client, g *session.Grant, scopes []string,
	requested []string, nonce string, withRefresh bool, cnf *token.Confirmation) (*IssuedTokens, *Error, error) {
	u, oe := s.validateUserAccess(ctx, tx, rlm, c, g)
	if oe != nil {
		return nil, oe, nil
	}
	res, oe := s.selectResource(ctx, tx, rlm, g, requested)
	if oe != nil {
		return nil, oe, nil
	}
	if res.Kind == application.KindAdmin && g.SessionID != "" {
		sess, err := s.Sessions.Get(ctx, tx, rlm.ID, g.SessionID)
		if err != nil || !sess.HasMFA() || sess.RecoveryRestricted {
			return nil, ErrInvalidGrant("administrative access requires an MFA session"), nil
		}
	}
	tokenScopes := scopesForResource(ctx, s, rlm.ID, res, scopes)
	orgID := ""
	if res.RequiresOrganization {
		if g.OrgID == "" {
			return nil, ErrInvalidTarget("this resource requires an organization context"), nil
		}
		orgID = g.OrgID
	}
	tokenScopes, err := s.applyScopePolicy(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: u.ID}, orgID, tokenScopes)
	if err != nil {
		return nil, nil, err
	}
	if tokenScopes, err = s.applyStepUp(ctx, tx, rlm.ID, g, tokenScopes); err != nil {
		return nil, nil, err
	}
	sid := g.SessionID
	if g.Offline {
		sid = ""
	}
	access, ttl, err := s.MintAccess(ctx, tx, AccessSpec{Realm: rlm, Client: c, Resource: res, SubjectType: "user", SubjectID: u.ID,
		Scopes: tokenScopes, OrgID: orgID, SessionID: sid, GrantID: g.ID, AuthTime: g.AuthTime, ACR: g.ACR, AMR: g.AMR,
		AuthzVersion: s.authzVersion(ctx, tx, "user", u.ID, orgID), Confirmation: cnf})
	if err != nil {
		if errors.Is(err, token.ErrNoActiveKey) {
			return nil, nil, ErrTemporarilyUnavailable
		}
		return nil, nil, err
	}
	out := &IssuedTokens{AccessToken: access, TokenType: tokenTypeFor(cnf), ExpiresIn: int(ttl.Seconds()), Scope: strings.Join(tokenScopes, " ")}
	if slices.Contains(scopes, "openid") {
		idt, err := s.MintID(ctx, IDSpec{Realm: rlm, Client: c, User: u, Scopes: scopes, Nonce: nonce, SessionID: g.SessionID,
			AuthTime: g.AuthTime, ACR: g.ACR, AMR: g.AMR, AccessToken: access, OrgID: g.OrgID, ClaimsRequest: g.ClaimsRequest})
		if errors.Is(err, ErrNoEncryptionKey) {
			return nil, nil, ErrUnauthorizedClient(err.Error())
		}
		if errors.Is(err, token.ErrNoActiveKey) {
			return nil, nil, ErrTemporarilyUnavailable
		}
		if err != nil {
			return nil, nil, err
		}
		out.IDToken = idt
	}
	if withRefresh && g.SessionID != "" {
		// Transient sessions never mint long-lived refresh authority (SES-020),
		// offline grants included.
		if sess, err := s.Sessions.Get(ctx, tx, rlm.ID, g.SessionID); err == nil && sess.Transient {
			withRefresh = false
		}
	}
	if withRefresh && grantAllowed(rlm, c, application.GrantRefreshToken) {
		idle, abs := s.d.Cfg.Sessions.IdleTimeout, s.d.Cfg.Sessions.AbsoluteTimeout
		var cap *time.Time
		if g.Offline {
			idle, abs = s.d.Cfg.Sessions.OfflineIdle, s.d.Cfg.Sessions.OfflineAbsolute
		} else if g.SessionID != "" {
			sess, err := s.Sessions.Get(ctx, tx, rlm.ID, g.SessionID)
			if err == nil {
				cap = &sess.AbsoluteExpiresAt
				if sess.RememberMe {
					idle, abs = s.d.Cfg.Sessions.RememberMeIdle, s.d.Cfg.Sessions.RememberMeAbsolute
				}
			}
		}
		if p := c.TokenPolicy; p.RefreshIdleSeconds > 0 && time.Duration(p.RefreshIdleSeconds)*time.Second < idle {
			idle = time.Duration(p.RefreshIdleSeconds) * time.Second
		}
		if p := c.TokenPolicy; p.RefreshAbsoluteSeconds > 0 && time.Duration(p.RefreshAbsoluteSeconds)*time.Second < abs {
			abs = time.Duration(p.RefreshAbsoluteSeconds) * time.Second
		}
		// The family keeps the sender constraint of this first issuance for
		// its whole life, whatever require_dpop says (TOK-019, owner decision
		// 13): every refresh must prove the same DPoP key or certificate.
		var bind session.SenderBinding
		if cnf != nil {
			bind = session.SenderBinding{JKT: cnf.JKT, X5TS256: cnf.X5TS256}
		}
		rt, _, err := s.Sessions.IssueRefreshTx(ctx, tx, rlm.ID, g.ID, c.Ref, bind, idle, abs, cap)
		if err != nil {
			return nil, nil, err
		}
		out.RefreshToken = rt
	}
	return out, nil, nil
}

// selectResource picks the access-token audience among the grant's resources.
func (s *Service) selectResource(ctx context.Context, q pgx.Tx, rlm *realm.Realm, g *session.Grant, requested []string) (*application.Resource, *Error) {
	if len(requested) > 1 {
		return nil, ErrInvalidTarget("request one resource per access token")
	}
	if len(requested) == 1 {
		res, err := s.Apps.ResourceByAudience(ctx, q, rlm.ID, requested[0])
		if err != nil || !slices.Contains(g.ResourceIDs, res.ID) {
			return nil, ErrInvalidTarget("resource was not part of the authorization")
		}
		if res.State != "active" {
			return nil, ErrInvalidTarget("resource is disabled")
		}
		return res, nil
	}
	if len(g.ResourceIDs) == 0 {
		return nil, ErrInvalidTarget("no resource in the authorization")
	}
	res, err := s.Apps.Resource(ctx, q, rlm.ID, g.ResourceIDs[0])
	if err != nil || res.State != "active" {
		return nil, ErrInvalidTarget("resource is unavailable")
	}
	return res, nil
}

// applyScopePolicy narrows token scopes by organization and subject policy
// (TOK-008): an organization may cap the scopes usable in its context, and a
// scope may require the subject to hold permissions there. It runs at every
// issuance, so a refresh after a permission or policy change never keeps a
// scope the subject no longer qualifies for.
//
// The permissions are evaluated where the scope's resource lives: realm and
// organization assignments as before and, for a resource that belongs to a
// project, the subject's assignments scoped to that project (AZ-002;
// authorization.EffectiveInProject). A project role therefore qualifies the
// subject only for scopes of its own project's resources.
func (s *Service) applyScopePolicy(ctx context.Context, q storage.Querier, realmID string, subj authorization.Subject, orgID string, scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return scopes, nil
	}
	var orgAllowed []string
	if orgID != "" && s.Orgs != nil {
		org, err := s.Orgs.Get(ctx, q, realmID, orgID)
		if err != nil {
			return nil, err
		}
		orgAllowed = org.Policy.AllowedScopes
	}
	defs, err := s.Apps.ScopesByName(ctx, q, realmID, scopes)
	if err != nil {
		return nil, err
	}
	effs := map[string]*authorization.PermissionSet{} // by the resource's project ("" for none)
	projects := map[string]string{}                   // resource ID -> project ID
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		d := defs[sc]
		if d.Kind != "oidc" && len(orgAllowed) > 0 && !slices.Contains(orgAllowed, sc) {
			continue
		}
		if len(d.RequiredPermissions) > 0 {
			project, known := projects[d.ResourceID]
			if !known && d.ResourceID != "" {
				if project, err = s.resourceProject(ctx, q, realmID, d.ResourceID); err != nil {
					return nil, err
				}
				projects[d.ResourceID] = project
			}
			eff := effs[project]
			if eff == nil {
				scope := authorization.Scope{Type: authorization.ScopeRealm, ID: realmID}
				if orgID != "" {
					scope = authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
				}
				if eff, err = s.Authz.EffectiveInProject(ctx, q, realmID, subj, scope, project); err != nil {
					return nil, err
				}
				effs[project] = eff
			}
			if !slices.ContainsFunc(d.RequiredPermissions, func(p string) bool { return !eff.Has(p) }) {
				out = append(out, sc)
			}
			continue
		}
		out = append(out, sc)
	}
	return out, nil
}

// resourceProject returns the project an API resource belongs to, or "".
func (s *Service) resourceProject(ctx context.Context, q storage.Querier, realmID, resourceID string) (string, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var project string
	err := q.QueryRow(ctx, `SELECT coalesce(project_id,'') FROM api_resources WHERE realm_id=$1 AND id=$2`, realmID, resourceID).Scan(&project)
	if storage.IsNoRows(err) {
		return "", nil
	}
	return project, err
}

// applyStepUp drops scopes whose step-up policy the grant no longer meets
// (AUT-010): a refresh never carries a sensitive scope past its maximum
// authentication age or above the assurance the grant was authenticated with.
// The client steps up again with a new authorization request to regain it.
func (s *Service) applyStepUp(ctx context.Context, q storage.Querier, realmID string, g *session.Grant, scopes []string) ([]string, error) {
	defs, err := s.Apps.ScopesByName(ctx, q, realmID, scopes)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		acr, maxAge := application.StepUp(map[string]application.Scope{sc: defs[sc]})
		if acr != "" && session.ACRRank(g.ACR) < session.ACRRank(acr) {
			continue
		}
		if maxAge > 0 && (g.AuthTime == nil || s.d.Now().Sub(*g.AuthTime) > time.Duration(maxAge)*time.Second) {
			continue
		}
		out = append(out, sc)
	}
	return out, nil
}

// ScopesPermitted applies organization and subject scope policy (TOK-008)
// for non-interactive credentials such as personal tokens and API keys.
// Scopes with a step-up policy are never available to these credentials:
// they carry no authentication event to be strong or fresh (AUT-010).
func (s *Service) ScopesPermitted(ctx context.Context, realmID, subjectType, subjectID, orgID string, scopes []string) ([]string, error) {
	out, err := s.applyScopePolicy(ctx, nil, realmID, authorization.Subject{Type: subjectType, ID: subjectID}, orgID, scopes)
	if err != nil {
		return nil, err
	}
	return s.applyStepUp(ctx, nil, realmID, &session.Grant{}, out)
}

// scopesForResource keeps only scopes belonging to the token's resource (plus
// openid for the UserInfo audience).
func scopesForResource(ctx context.Context, s *Service, realmID string, res *application.Resource, scopes []string) []string {
	defs, _ := s.Apps.ScopesByName(ctx, nil, realmID, scopes)
	out := []string{}
	for _, sc := range scopes {
		d, ok := defs[sc]
		if !ok {
			continue
		}
		if d.ResourceID == res.ID || (res.Kind == application.KindUserInfo && d.Kind == "oidc" && sc != "offline_access") {
			out = append(out, sc)
		}
	}
	return out
}

// refreshGrant uses a refresh token (SES-006). cnf binds the access token it
// issues; proof is what the request proves about its sender (its DPoP key and
// TLS client certificate), which a sender-bound family must match.
func (s *Service) refreshGrant(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation,
	proof session.SenderBinding) (*IssuedTokens, *Error) {
	presented := f.Get("refresh_token")
	if presented == "" {
		return nil, ErrInvalidRequest("refresh_token is required")
	}
	requestedScopes := strings.Fields(f.Get("scope"))
	var out *IssuedTokens
	var oe *Error
	idle := s.d.Cfg.Sessions.IdleTimeout
	res, err := s.Sessions.UseRefresh(ctx, rlm.ID, presented, c.Ref, proof, idle, c.FAPI2(),
		func(tx pgx.Tx, g *session.Grant) error {
			// Scope can only narrow on refresh (TOK-008).
			for _, sc := range requestedScopes {
				if !slices.Contains(g.Scopes, sc) {
					oe = ErrInvalidScope("refresh cannot expand scope")
					return errStop
				}
			}
			if _, e := s.validateUserAccess(ctx, tx, rlm, c, g); e != nil {
				oe = e
				return errStop
			}
			return nil
		},
		func(tx pgx.Tx, g *session.Grant, fam *session.Family) error {
			scopes := g.Scopes
			if len(requestedScopes) > 0 {
				scopes = requestedScopes
			}
			// Re-evaluate the client's current ceiling: revoked scopes disappear (§24.3).
			grants, err := s.Apps.ResourceGrants(ctx, tx, c.Ref)
			if err != nil {
				return err
			}
			allowed := map[string]bool{"openid": true, "profile": true, "email": true, "phone": true, "address": true}
			if c.AllowOfflineAccess {
				allowed["offline_access"] = true
			}
			for _, gr := range grants {
				for _, sc := range gr.AllowedScopes {
					allowed[sc] = true
				}
			}
			scopes = slices.DeleteFunc(slices.Clone(scopes), func(sc string) bool { return !allowed[sc] })
			var e *Error
			out, e, err = s.issueForUserGrant(ctx, tx, rlm, c, g, scopes, f["resource"], "", false, cnf)
			if err != nil {
				return err
			}
			if e != nil {
				oe = e
				return errStop
			}
			_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.refreshed", RealmID: rlm.ID, OrgID: g.OrgID, Actor: audit.Ref{Type: "client", ID: c.Ref},
				Subject: &audit.Ref{Type: "user", ID: g.SubjectID}, ClientID: c.ClientID, GrantID: g.ID, Category: "token",
				Metadata: map[string]any{"token_family_id": fam.ID, "generation": fam.Generation}})
			return err
		})
	if err != nil {
		if oe != nil {
			return nil, oe
		}
		switch {
		case errors.Is(err, session.ErrRefreshSender):
			return nil, ErrInvalidGrant("refresh token is sender-constrained: present a DPoP proof signed with its key, or its TLS client certificate")
		case errors.Is(err, session.ErrRefreshReuse):
			return nil, ErrInvalidGrant("refresh token reuse detected; the token family was revoked")
		case errors.Is(err, session.ErrRefreshInvalid):
			return nil, ErrInvalidGrant("invalid refresh token")
		}
		return nil, serverError(s, err)
	}
	out.RefreshToken = res.RefreshToken
	return out, nil
}

var errStop = errors.New("stop")

// clientCredentialsGrant issues a short-lived token representing the service
// principal, never a fabricated human login, and never a refresh token (MCH-002, MCH-003).
func (s *Service) clientCredentialsGrant(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation) (*IssuedTokens, *Error) {
	if c.Public() || c.ServicePrincipalID == "" || c.AuthMethod == "none" {
		return nil, ErrUnauthorizedClient("client credentials require a confidential client with a service principal")
	}
	return s.issueServiceToken(ctx, rlm, c, f, cnf, serviceIssue{grant: "client_credentials"})
}

// serviceIssue carries what differs between the grants that mint service
// principal tokens.
type serviceIssue struct {
	grant  string
	ttlCap time.Duration
	meta   map[string]any
	// consume, when set, spends a single-use credential of the request (a
	// workload assertion's jti) inside the issuing transaction, after every
	// other check and before the token is minted. A protocol error refuses
	// the request without writing anything.
	consume func(tx pgx.Tx) (*Error, error)
}

// issueServiceToken mints an access token for the client's service principal
// within its resource grants, organizations and scope policy (MCH-002,
// MCH-004).
func (s *Service) issueServiceToken(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation, si serviceIssue) (*IssuedTokens, *Error) {
	var spState string
	var allowedOrgs []string
	var ownerOrg *string
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT state, allowed_organization_ids, owner_organization_id FROM service_principals WHERE realm_id=$1 AND id=$2`,
		rlm.ID, c.ServicePrincipalID).Scan(&spState, &allowedOrgs, &ownerOrg); err != nil || spState != "active" {
		return nil, ErrInvalidGrant("service principal is not active")
	}
	scopes, resources, oe := s.ResolveScopes(ctx, rlm, c, f.Get("scope"), f["resource"], "service_principal")
	if oe != nil {
		return nil, oe
	}
	if len(resources) != 1 {
		return nil, ErrInvalidTarget("request exactly one resource")
	}
	var out *IssuedTokens
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		res, err := s.Apps.Resource(ctx, tx, rlm.ID, resources[0])
		if err != nil {
			return err
		}
		if res.Kind == application.KindAccount || res.Kind == application.KindUserInfo {
			oe = ErrInvalidTarget("machine tokens cannot target human self-service APIs (MCH-004)")
			return nil
		}
		orgID := ""
		if res.RequiresOrganization {
			orgID = f.Get("organization")
			if orgID == "" && ownerOrg != nil {
				orgID = *ownerOrg
			}
			if orgID == "" || !(slices.Contains(allowedOrgs, orgID) || ownerOrg != nil && *ownerOrg == orgID) {
				oe = ErrInvalidTarget("the service principal is not allowed in that organization")
				return nil
			}
			if _, err := s.Orgs.LockActiveTx(ctx, tx, rlm.ID, orgID); err != nil {
				oe = ErrInvalidTarget("organization is not active")
				return nil
			}
		}
		tokenScopes, err := s.applyScopePolicy(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectService, ID: c.ServicePrincipalID},
			orgID, scopesForResource(ctx, s, rlm.ID, res, scopes))
		if err != nil {
			return err
		}
		if si.consume != nil {
			if oe, err = si.consume(tx); err != nil || oe != nil {
				return err
			}
		}
		access, ttl, err := s.MintAccess(ctx, tx, AccessSpec{Realm: rlm, Client: c, Resource: res, SubjectType: "service_principal",
			SubjectID: c.ServicePrincipalID, Scopes: tokenScopes, OrgID: orgID, Kind: token.KindServiceAccess,
			AuthzVersion: s.authzVersion(ctx, tx, "service_principal", c.ServicePrincipalID, ""), Confirmation: cnf, TTLCap: si.ttlCap})
		if err != nil {
			if errors.Is(err, token.ErrNoActiveKey) {
				// Rolled back: a consumed credential stays usable (see
				// issueForUserGrant).
				return ErrTemporarilyUnavailable
			}
			return err
		}
		out = &IssuedTokens{AccessToken: access, TokenType: tokenTypeFor(cnf), ExpiresIn: int(ttl.Seconds()), Scope: strings.Join(tokenScopes, " ")}
		meta := map[string]any{"grant_type": si.grant, "audience": res.Audience}
		for k, v := range si.meta {
			meta[k] = v
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.issued", RealmID: rlm.ID, OrgID: orgID, Actor: audit.Ref{Type: "client", ID: c.Ref},
			Subject: &audit.Ref{Type: "service_principal", ID: c.ServicePrincipalID}, ClientID: c.ClientID, Category: "token", Metadata: meta})
		return err
	})
	if err != nil {
		return nil, serverError(s, err)
	}
	if oe != nil {
		return nil, oe
	}
	return out, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

var _ = problem.ErrInternal
