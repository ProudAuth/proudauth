package oauth

import (
	"context"
	"crypto"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/token"
)

func crypto256() crypto.Hash { return crypto.SHA256 }

// Inactive is the protocol's inactive response; it never explains why (TOK-009).
var Inactive = map[string]any{"active": false}

// Introspect validates a token with authoritative live state (strict-online). Only
// clients registered as resource servers for the token's audience learn anything
// about it; everyone else receives the inactive response (TEST-037).
func (s *Service) Introspect(ctx context.Context, rlm *realm.Realm, auth application.ClientAuthInput, endpoint, raw string) (map[string]any, *Error) {
	caller, err := s.Apps.Authenticate(ctx, rlm.ID, rlm.Issuer, endpoint, auth)
	if err != nil || caller.Public() {
		return nil, ErrInvalidClient
	}
	allowed, err := s.Apps.IntrospectableResources(ctx, caller.Ref)
	if err != nil {
		return nil, ErrServerError
	}
	res := s.IntrospectWithAllowed(ctx, rlm, raw, allowed)
	if active, _ := res["active"].(bool); active && res["token_kind"] == token.KindImpersonationAccess {
		_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "support.token.introspected", RealmID: rlm.ID, Actor: audit.Ref{Type: "client", ID: caller.Ref},
			Subject: &audit.Ref{Type: "user", ID: res["sub"].(string)}, ImpersonationGrantID: res["impersonation_grant_id"].(string), Category: "support"})
	}
	return res, nil
}

// IntrospectWithAllowed evaluates a token for a caller authorized for the given
// resource IDs.
func (s *Service) IntrospectWithAllowed(ctx context.Context, rlm *realm.Realm, raw string, allowed map[string]bool) map[string]any {
	if raw == "" || len(raw) > s.d.Cfg.Limits.MaxTokenBytes {
		return Inactive
	}
	var res map[string]any
	switch {
	case strings.HasPrefix(raw, secret.PrefixOpaqueAccess) || strings.HasPrefix(raw, secret.PrefixImpersonation):
		res = s.introspectOpaque(ctx, rlm, raw, allowed)
	case strings.Count(raw, ".") == 2:
		res = s.introspectJWT(ctx, rlm, raw, allowed)
	default:
		res = Inactive
	}
	return res
}

func (s *Service) introspectJWT(ctx context.Context, rlm *realm.Realm, raw string, allowed map[string]bool) map[string]any {
	c, err := s.verifyAnyAudience(ctx, rlm, raw)
	if err != nil {
		return Inactive
	}
	res, err := s.Apps.ResourceByAudience(ctx, nil, rlm.ID, c.Audience[0])
	if err != nil || !allowed[res.ID] || res.State != "active" {
		return Inactive
	}
	if revoked, err := s.Sessions.JTIRevoked(ctx, nil, rlm.ID, c.JTI); err != nil || revoked {
		return Inactive
	}
	client, err := s.Apps.ClientByClientID(ctx, nil, rlm.ID, c.ClientID)
	if err != nil || !client.Active() {
		return Inactive
	}
	if c.TokenKind == token.KindUserAccess || c.TokenKind == token.KindExchangeAccess {
		grantClient := client.Ref
		if c.TokenKind == token.KindExchangeAccess {
			grantClient = "" // the grant belongs to the originating client
		}
		if !s.Sessions.AccessGrantActive(ctx, nil, rlm.ID, c.GrantID, c.Subject, grantClient) {
			return Inactive
		}
	}
	current, ok := s.subjectActive(ctx, rlm, c.TokenKind, c.Subject, c.SessionID, c.OrgID, time.Unix(c.IssuedAt, 0))
	if !ok {
		return Inactive
	}
	out := map[string]any{"active": true, "iss": c.Issuer, "sub": c.Subject, "aud": c.Audience[0], "client_id": c.ClientID,
		"scope": c.Scope, "exp": c.Expiry, "iat": c.IssuedAt, "jti": c.JTI, "token_kind": c.TokenKind, "token_type": "Bearer",
		"authz_version": current}
	if c.OrgID != "" {
		out["org_id"] = c.OrgID
	}
	if c.SessionID != "" {
		out["sid"] = c.SessionID
	}
	if c.AuthTime != 0 {
		out["auth_time"] = c.AuthTime
	}
	if c.ACR != "" {
		out["acr"] = c.ACR
	}
	if c.Act != nil {
		out["act"] = c.Act
	}
	if c.Agent {
		out["agent"] = true
	}
	if c.Cnf != nil {
		out["cnf"] = c.Cnf
	}
	// A DPoP-bound token is reported as such (RFC 9449 §6.2), as in the
	// token response; certificate-bound tokens stay Bearer (RFC 8705).
	out["token_type"] = tokenTypeFor(c.Cnf)
	return out
}

// subjectActive performs the authoritative live-state checks and returns the
// current authorization revision. issuedAt is when the token was issued: a
// user token without a session (an offline grant's) is inactive once an
// account-wide revocation took effect at or after it (SES-005); a
// session-bound token is covered by the session check.
func (s *Service) subjectActive(ctx context.Context, rlm *realm.Realm, kind, subject, sid, orgID string, issuedAt time.Time) (int64, bool) {
	now := s.d.Now()
	if kind == token.KindServiceAccess {
		var state string
		if err := s.d.DB.Pool.QueryRow(ctx, `SELECT state FROM service_principals WHERE realm_id=$1 AND id=$2`, rlm.ID, subject).Scan(&state); err != nil || state != "active" {
			return 0, false
		}
		if orgID != "" {
			if _, err := s.Orgs.Get(ctx, nil, rlm.ID, orgID); err != nil {
				return 0, false
			}
		}
		return s.authzVersion(ctx, s.d.DB.Pool, "service_principal", subject, ""), true
	}
	u, err := s.Users.User(ctx, nil, rlm.ID, subject)
	if err != nil || !u.CanAuthenticate(now) {
		return 0, false
	}
	if sid != "" {
		if _, err := s.Sessions.Active(ctx, nil, rlm.ID, sid); err != nil {
			return 0, false
		}
	} else if revoked, err := s.Sessions.UserTokenRevoked(ctx, nil, rlm.ID, subject, issuedAt); err != nil || revoked {
		return 0, false
	}
	if orgID != "" {
		if _, err := s.Orgs.ActiveMembership(ctx, nil, rlm.ID, orgID, subject); err != nil {
			return 0, false
		}
	}
	return s.authzVersion(ctx, s.d.DB.Pool, "user", subject, orgID), true
}

func (s *Service) introspectOpaque(ctx context.Context, rlm *realm.Realm, raw string, allowed map[string]bool) map[string]any {
	t, err := s.Sessions.Opaque(ctx, nil, rlm.ID, raw)
	if err != nil || t.RevokedAt != nil || !s.d.Now().Before(t.ExpiresAt) || !allowed[t.ResourceID] {
		return Inactive
	}
	if (strings.HasPrefix(raw, secret.PrefixImpersonation)) != (t.Kind == token.KindImpersonationAccess) {
		return Inactive
	}
	res, err := s.Apps.Resource(ctx, nil, rlm.ID, t.ResourceID)
	if err != nil || res.State != "active" {
		return Inactive
	}
	client, err := s.Apps.ClientByRef(ctx, nil, rlm.ID, t.ClientRef)
	if err != nil || !client.Active() {
		return Inactive
	}
	if t.GrantID != "" {
		if g, err := s.Sessions.Grant(ctx, nil, t.GrantID); err != nil || g.State != "active" {
			return Inactive
		}
	}
	out := map[string]any{"active": true, "iss": rlm.Issuer, "sub": t.SubjectID, "aud": res.Audience, "client_id": client.ClientID,
		"scope": strings.Join(t.Scopes, " "), "exp": t.ExpiresAt.Unix(), "iat": t.CreatedAt.Unix(), "jti": t.JTI, "token_kind": t.Kind,
		"token_type": "Bearer"}
	if t.OrgID != "" {
		out["org_id"] = t.OrgID
	}
	if t.Kind == token.KindImpersonationAccess {
		// Every support request re-validates the grant, actor and target (IMP-010, IMP-016, IMP-017).
		if s.Impersonation == nil {
			return Inactive
		}
		extra, ok := s.Impersonation.ValidateGrant(ctx, s.d.DB.Pool, rlm.ID, t.ImpersonationGrantID)
		if !ok {
			return Inactive
		}
		for k, v := range extra {
			out[k] = v
		}
		out["impersonation_grant_id"] = t.ImpersonationGrantID
		return out
	}
	current, ok := s.subjectActive(ctx, rlm, t.Kind, t.SubjectID, t.SessionID, t.OrgID, t.CreatedAt)
	if !ok {
		return Inactive
	}
	out["authz_version"] = current
	if t.SessionID != "" {
		out["sid"] = t.SessionID
	}
	if len(t.Actor) > 0 {
		var act map[string]any
		_ = json.Unmarshal(t.Actor, &act)
		out["act"] = act
	}
	if t.AuthTime != nil {
		out["auth_time"] = t.AuthTime.Unix()
	}
	if t.SubjectType == "service_principal" && s.isAgent(ctx, nil, rlm.ID, t.SubjectID) {
		out["agent"] = true
	}
	if len(t.Cnf) > 0 {
		var cnf map[string]any
		if json.Unmarshal(t.Cnf, &cnf) == nil {
			out["cnf"] = cnf
			if jkt, _ := cnf["jkt"].(string); jkt != "" {
				out["token_type"] = "DPoP"
			}
		}
	}
	return out
}

// Revoke implements RFC 7009 with caller binding (TOK-010). The response is the
// same whether or not the token existed or belonged to the caller.
func (s *Service) Revoke(ctx context.Context, rlm *realm.Realm, auth application.ClientAuthInput, endpoint, raw, hint string) *Error {
	c, err := s.Apps.Authenticate(ctx, rlm.ID, rlm.Issuer, endpoint, auth)
	if err != nil {
		return ErrInvalidClient
	}
	actor := audit.Ref{Type: "client", ID: c.Ref}
	switch {
	case strings.HasPrefix(raw, secret.PrefixRefresh):
		_ = s.Sessions.RevokeRefresh(ctx, rlm.ID, raw, c.Ref, actor)
	case strings.HasPrefix(raw, secret.PrefixOpaqueAccess), strings.HasPrefix(raw, secret.PrefixImpersonation):
		_ = s.Sessions.RevokeOpaque(ctx, rlm.ID, raw, c.Ref)
	case strings.Count(raw, ".") == 2:
		claims, err := s.verifyAnyAudience(ctx, rlm, raw)
		if err == nil && claims.ClientID == c.ClientID {
			_ = s.Sessions.RevokeJTITx(ctx, s.d.DB.Pool, rlm.ID, claims.JTI, "client_revocation", time.Unix(claims.Expiry, 0).Add(s.d.Cfg.Tokens.ClockSkew))
			_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "token.access.revoked", RealmID: rlm.ID, Actor: actor,
				Subject: &audit.Ref{Type: "user", ID: claims.Subject}, Metadata: map[string]any{"jti": claims.JTI}})
		}
	}
	_ = hint
	return nil
}

var _ = slices.Contains[[]string]
var _ = session.ErrRefreshInvalid
