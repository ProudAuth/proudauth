package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/certauth"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/reqctx"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/provision"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/token"
)

// Principal is the authenticated caller of a custom API. Identity is always derived
// from validated credentials; path and body identifiers are only selectors (API-003).
type Principal struct {
	Realm     *realm.Realm
	Kind      string // user | service_principal
	SubjectID string
	ClientID  string
	SessionID string
	Session   *session.Session
	Scopes    []string
	Audience  string // account | admin
	TokenKind string
	JTI       string
	Expiry    time.Time
	// ACR, AuthTime and ResourceID feed conditional grants (AZ-012); they come
	// from the validated token, never from the request body.
	ACR        string
	AuthTime   time.Time
	ResourceID string
	ResourceAu string
	// ClientRef and OrgID are the token's client (its internal reference)
	// and organization, for per-client and per-organization budgets
	// (REG-012); OrgID is empty for tokens not bound to an organization.
	ClientRef string
	OrgID     string
}

// Subject returns the authorization subject.
func (p *Principal) Subject() authorization.Subject {
	if p.Kind == "service_principal" {
		return authorization.Subject{Type: authorization.SubjectService, ID: p.SubjectID}
	}
	return authorization.Subject{Type: authorization.SubjectUser, ID: p.SubjectID}
}

// AuditRef returns the actor reference for audit records.
func (p *Principal) AuditRef() audit.Ref {
	t := "user"
	if p.Kind == "service_principal" {
		t = "service_principal"
	}
	return audit.Ref{Type: t, ID: p.SubjectID, SessionID: p.SessionID}
}

// IsUser reports a human principal.
func (p *Principal) IsUser() bool { return p.Kind == "user" }

type principalKey struct{}

// bearer extracts a bearer token from the Authorization header only. Tokens in
// query strings are never accepted (TOK-023).
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if len(h) > 5 && strings.EqualFold(h[:5], "dpop ") {
		return strings.TrimSpace(h[5:])
	}
	return ""
}

// checkSenderConstraint enforces DPoP for sender-constrained tokens on the
// IdP's own APIs (RFC 9449 §7, TOK-019): a token bound to a key is usable only
// with the "DPoP" scheme and a fresh proof for this request and token.
func (a *App) checkSenderConstraint(r *http.Request, rlm *realm.Realm, raw string, cnf *token.Confirmation) error {
	scheme := strings.ToLower(strings.SplitN(r.Header.Get("Authorization"), " ", 2)[0])
	if cnf != nil && cnf.X5TS256 != "" {
		// Certificate-bound (RFC 8705 §3): the request must come with the
		// same TLS client certificate.
		cert, _ := a.peerCertificate(r)
		if cert == nil || certauth.Thumbprint(cert) != cnf.X5TS256 {
			return problem.ErrUnauthenticated.WithDetail("this token is bound to a TLS client certificate; present it with the same certificate")
		}
		return nil
	}
	if cnf == nil || cnf.JKT == "" {
		if scheme == "dpop" {
			return problem.ErrUnauthenticated.WithDetail("the token is not sender-constrained; use the Bearer scheme")
		}
		return nil
	}
	if scheme != "dpop" || len(r.Header.Values("DPoP")) != 1 {
		return problem.ErrUnauthenticated.WithDetail("this token is DPoP-bound; present it with the DPoP scheme and a proof")
	}
	htu := strings.TrimSuffix(a.D.Cfg.Server.PublicOrigin, "/") + r.URL.Path
	jkt, oe := a.OAuth.VerifyDPoPProof(r.Context(), rlm, r.Header.Get("DPoP"), r.Method, htu, raw)
	if oe != nil || jkt != cnf.JKT {
		return problem.ErrUnauthenticated.WithDetail("invalid DPoP proof for this request")
	}
	return nil
}

// authenticate resolves the principal for an audience kind with strict-online
// checks: the session, user, client and service principal must be live now
// (identity administration and credential changes are strict-online, §13.2).
func (a *App) authenticate(r *http.Request, rlm *realm.Realm, kinds ...string) (*Principal, error) {
	raw := bearer(r)
	if raw == "" {
		return nil, problem.ErrUnauthenticated.WithoutCredentials()
	}
	if r.URL.Query().Has("access_token") {
		return nil, problem.ErrBadRequest.WithDetail("tokens are not accepted in query strings")
	}
	if strings.HasPrefix(raw, secret.PrefixImpersonation) {
		// Support tokens never reach identity or administration APIs (IMP-012,
		// TEST-042). The refusal names the operator, the customer and the
		// support grant when the token is known (IMP-006, IMP-024).
		ev := audit.Event{Type: "support.token.rejected", RealmID: rlm.ID, Actor: audit.Ref{Type: "support_token", ID: "unknown"},
			Outcome: audit.Denied, ReasonCode: "IMPERSONATION_RESTRICTED", Category: "support", Metadata: map[string]any{"route": a.routeOf(r)}}
		if t, err := a.Sessions.Opaque(r.Context(), nil, rlm.ID, raw); err == nil {
			var act struct {
				Sub string `json:"sub"`
			}
			if json.Unmarshal(t.Actor, &act) == nil && act.Sub != "" {
				ev.Actor = audit.Ref{Type: "user", ID: act.Sub}
			}
			ev.Subject = &audit.Ref{Type: t.SubjectType, ID: t.SubjectID}
			ev.ImpersonationGrantID, ev.OrgID = t.ImpersonationGrantID, t.OrgID
		}
		_, _ = a.D.Audit.Record(r.Context(), a.D.DB.Pool, ev)
		return nil, problem.ErrImpersonationToken
	}
	if strings.HasPrefix(raw, secret.PrefixRefresh) || strings.HasPrefix(raw, secret.PrefixAuthCode) {
		// Refresh tokens are never accepted by APIs (SES-011).
		return nil, problem.ErrUnauthenticated
	}
	var claims *token.AccessClaims
	var aud string
	var resource *application.Resource
	for _, kind := range kinds {
		res, err := a.Apps.ResourceByKind(r.Context(), nil, rlm.ID, kind)
		if err != nil {
			return nil, err
		}
		c, err := a.Verifier.VerifyAccess(r.Context(), rlm.ID, rlm.Issuer, res.Audience, raw)
		if err == nil {
			claims, aud, resource = c, kind, res
			break
		}
		if err != token.ErrAudience {
			return nil, problem.ErrUnauthenticated
		}
	}
	if claims == nil {
		return nil, problem.ErrUnauthenticated
	}
	if err := a.checkSenderConstraint(r, rlm, raw, claims.Cnf); err != nil {
		return nil, err
	}
	ctx := r.Context()
	if revoked, err := a.Sessions.JTIRevoked(ctx, nil, rlm.ID, claims.JTI); err != nil || revoked {
		return nil, problem.ErrUnauthenticated
	}
	client, err := a.Apps.ClientByClientID(ctx, nil, rlm.ID, claims.ClientID)
	if err != nil || !client.Active() {
		return nil, problem.ErrUnauthenticated
	}
	if claims.TokenKind == token.KindUserAccess && !a.Sessions.AccessGrantActive(ctx, nil, rlm.ID, claims.GrantID, claims.Subject, client.Ref) {
		return nil, problem.ErrUnauthenticated
	}
	p := &Principal{Realm: rlm, SubjectID: claims.Subject, ClientID: claims.ClientID, SessionID: claims.SessionID, Scopes: claims.Scopes(),
		Audience: aud, TokenKind: claims.TokenKind, JTI: claims.JTI, Expiry: time.Unix(claims.Expiry, 0), ACR: claims.ACR,
		ResourceID: resource.ID, ResourceAu: resource.Audience, ClientRef: client.Ref, OrgID: claims.OrgID}
	if claims.AuthTime > 0 {
		p.AuthTime = time.Unix(claims.AuthTime, 0)
	}
	switch claims.TokenKind {
	case token.KindUserAccess:
		p.Kind = "user"
		// IdP APIs accept only session-bound user tokens, so account-wide
		// revocations ("log out everywhere", SES-005) apply exactly: they
		// revoke every session. Offline-grant tokens (no sid) never get here;
		// introspection and UserInfo check them against the user-level
		// revocation record (session.UserTokenRevoked).
		if claims.SessionID == "" {
			return nil, problem.ErrUnauthenticated
		}
		sess, err := a.Sessions.Active(ctx, nil, rlm.ID, claims.SessionID)
		if err != nil || sess.UserID != claims.Subject {
			return nil, problem.ErrUnauthenticated
		}
		p.Session = sess
		u, err := a.Users.User(ctx, nil, rlm.ID, claims.Subject)
		if err != nil || !u.CanAuthenticate(a.D.Now()) {
			return nil, problem.ErrUnauthenticated
		}
	case token.KindServiceAccess:
		p.Kind = "service_principal"
		var state string
		if err := a.D.DB.Pool.QueryRow(ctx, `SELECT state FROM service_principals WHERE realm_id=$1 AND id=$2`, rlm.ID, claims.Subject).Scan(&state); err != nil || state != "active" {
			return nil, problem.ErrUnauthenticated
		}
	default:
		// Exchange tokens and other kinds are not accepted by IdP APIs.
		return nil, problem.ErrUnauthenticated
	}
	need := map[string]string{application.KindAccount: provision.ScopeAccount, application.KindAdmin: provision.ScopeAdmin}[aud]
	if need != "" && !slices.Contains(p.Scopes, need) {
		return nil, problem.ErrForbidden.WithDetail("token lacks the " + need + " scope")
	}
	return p, nil
}

// requireMFASession enforces that administrative users act from an MFA session that
// is not recovery-restricted (MFA-003, MFA-010).
func (a *App) requireMFASession(p *Principal) error {
	if !p.IsUser() {
		return nil
	}
	if p.Session == nil || !p.Session.HasMFA() {
		return problem.ErrMFARequired.WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "required_profile": "mfa"}})
	}
	if p.Session.RecoveryRestricted {
		return problem.ErrMFARequired.WithDetail("recovery-restricted sessions cannot perform administration; enroll a new factor first")
	}
	return nil
}

// requireRecentAuth requires a recent genuine authentication on the session
// (CRED-006, MFA-006, MCH-006). It returns a step-up challenge otherwise.
func (a *App) requireRecentAuth(p *Principal, window time.Duration) error {
	if p.Session == nil {
		return problem.ErrRecentAuthRequired
	}
	if window <= 0 {
		window = a.D.Cfg.Security.RecentAuthWindow
	}
	if a.D.Now().Sub(p.Session.AuthTime) > window {
		return problem.ErrRecentAuthRequired.WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "max_age_seconds": int(window.Seconds())}})
	}
	return nil
}

// can checks a permission in a scope for the principal.
func (a *App) can(ctx context.Context, p *Principal, perm string, scope authorization.Scope) bool {
	return a.Authz.Check(ctx, nil, p.Realm.ID, p.Subject(), perm, scope)
}

func (a *App) realmScope(p *Principal) authorization.Scope {
	return authorization.Scope{Type: authorization.ScopeRealm, ID: p.Realm.ID}
}

func orgScope(id string) authorization.Scope {
	return authorization.Scope{Type: authorization.ScopeOrganization, ID: id}
}

// guard wraps a handler with realm resolution and authentication.
type handlerFunc func(w http.ResponseWriter, r *http.Request, p *Principal) error

func (a *App) self(h handlerFunc) http.HandlerFunc {
	return a.protected(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if !p.IsUser() {
			// Machine tokens cannot call human self-service routes (MCH-004, TEST-039).
			return problem.ErrForbidden.WithDetail("self-service APIs require a user")
		}
		return h(w, r, p)
	}, application.KindAccount)
}

func (a *App) tenant(h handlerFunc) http.HandlerFunc {
	return a.protected(h, application.KindAccount, application.KindAdmin)
}

func (a *App) admin(h handlerFunc) http.HandlerFunc {
	return a.protected(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		return h(w, r, p)
	}, application.KindAdmin)
}

func (a *App) protected(h handlerFunc, kinds ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rlm, err := a.Realms.ByName(r.Context(), r.PathValue("realm"))
		if err != nil {
			a.fail(w, r, problem.ErrNotFound)
			return
		}
		if !rlm.Active() {
			a.fail(w, r, problem.ErrUnavailable.WithDetail("identity domain unavailable"))
			return
		}
		p, err := a.authenticate(r, rlm, kinds...)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if p.Session != nil && p.Session.RecoveryRestricted && !recoveryPermitted(r) {
			a.fail(w, r, problem.ErrRecoveryRestricted)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		authTime := p.AuthTime
		if p.Session != nil {
			authTime = p.Session.AuthTime
		}
		ctx = authorization.WithDecisionContext(ctx, authorization.DecisionContext{ClientID: p.ClientID, ACR: p.ACR, AuthTime: authTime,
			Resources: []string{p.ResourceID, p.ResourceAu}})
		denied := false
		ctx = context.WithValue(ctx, denialKey{}, &denied)
		if err := a.idempotent(w, r.WithContext(ctx), p, h); err != nil {
			// Refusals decided inside handlers (a.can checks, service-level
			// permission checks) are evidence too (AZ-020).
			if pe, ok := problem.As(err); ok && pe.Status == http.StatusForbidden && pe.Code == problem.ErrForbidden.Code {
				a.recordDenial(r.WithContext(ctx), p, "", "", false)
			}
			a.fail(w, r, err)
		}
	}
}

// recoveryAllowed are the changes a recovery-restricted session may make
// (MFA-010): enroll a new factor and end sessions or remembered devices.
// Everything else that changes state — password, identifiers, deletion,
// exports, tokens, consents, organization administration — waits for a
// session that authenticated with the restored factor.
var recoveryAllowed = map[string]bool{
	"POST /me/totp/enroll": true, "POST /me/totp/activate": true,
	// HOTP activation restores the session like TOTP (MFA-013); the realm
	// must still list hotp for the routes to accept it.
	"POST /me/hotp/enroll": true, "POST /me/hotp/activate": true,
	"POST /me/webauthn/registration-options": true, "POST /me/webauthn/registration-complete": true,
	"DELETE /me/sessions/{id}": true, "POST /me/sessions/revoke-all": true,
	"DELETE /me/remembered-devices": true, "DELETE /me/remembered-devices/{id}": true,
}

func recoveryPermitted(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	_, rest, ok := strings.Cut(r.Pattern, "/api/v1/realms/{realm}")
	return ok && recoveryAllowed[r.Method+" "+rest]
}

// public resolves the realm for unauthenticated endpoints.
func (a *App) public(h func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rlm, err := a.Realms.ByName(r.Context(), r.PathValue("realm"))
		if err != nil {
			a.fail(w, r, problem.ErrNotFound)
			return
		}
		if err := h(w, r, rlm); err != nil {
			a.fail(w, r, err)
		}
	}
}

func (a *App) fail(w http.ResponseWriter, r *http.Request, err error) {
	pe, ok := problem.As(err)
	if !ok || pe.Status >= 500 {
		a.D.Log.Error("request failed", "request_id", reqctx.From(r.Context()).RequestID, "route", a.routeOf(r), "error", err)
	}
	if ok && pe.Code == problem.ErrRateLimited.Code {
		a.Metrics.RateLimited.Inc(a.routeOf(r))
	}
	problem.Write(w, reqctx.From(r.Context()).RequestID, err)
}
