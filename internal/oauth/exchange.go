package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/token"
)

const (
	tokenTypeAccess = "urn:ietf:params:oauth:token-type:access_token"
)

// exchangeGrant implements explicitly authorized token exchange (TOK-016, TOK-017,
// MCH-015). The presenting client must be allowed to accept tokens from the subject
// token's audience into the requested audience; scope is limited by the target
// grant; provenance is preserved in the act claim; lifetime never exceeds the
// subject token; and support-access tokens can never be exchanged (IMP-014).
func (s *Service) exchangeGrant(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation) (*IssuedTokens, *Error) {
	if c.Public() {
		return nil, ErrUnauthorizedClient("token exchange requires a confidential client")
	}
	if f.Get("subject_token_type") != tokenTypeAccess {
		return nil, ErrInvalidRequest("subject_token_type must be an access token")
	}
	if f.Get("actor_token") != "" {
		return nil, ErrInvalidRequest("actor tokens are not supported; the authenticated client is the actor")
	}
	if rt := f.Get("requested_token_type"); rt != "" && rt != tokenTypeAccess {
		return nil, ErrInvalidRequest("only access tokens can be requested")
	}
	subjectToken := f.Get("subject_token")
	if strings.HasPrefix(subjectToken, "pa_it_") || strings.HasPrefix(subjectToken, "pa_at_") {
		return nil, ErrInvalidGrant("this subject token cannot be exchanged")
	}
	claims, err := s.verifyAnyAudience(ctx, rlm, subjectToken)
	if err != nil {
		return nil, ErrInvalidGrant("invalid subject token")
	}
	if claims.TokenKind == token.KindImpersonationAccess || claims.TokenKind == token.KindServiceAccess {
		return nil, ErrInvalidGrant("this subject token cannot be exchanged")
	}
	depth := 0
	if claims.Act != nil {
		depth = claims.Act.Depth()
	}
	if depth+1 > s.d.Cfg.Tokens.ExchangeMaxChainDepth {
		return nil, ErrInvalidGrant("delegation chain too deep")
	}
	targets := f["resource"]
	if a := f.Get("audience"); a != "" {
		targets = append(targets, a)
	}
	if len(targets) != 1 {
		return nil, ErrInvalidTarget("request exactly one target resource")
	}
	var out *IssuedTokens
	var oe *Error
	txErr := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		out, oe = nil, nil // a retried transaction starts clean (DB-014)
		res, err := s.Apps.ResourceByAudience(ctx, tx, rlm.ID, targets[0])
		if err != nil || res.State != "active" || res.Kind != application.KindBusiness {
			oe = ErrInvalidTarget("unknown target resource")
			return nil
		}
		// A token minted for a client of another environment is never accepted:
		// production cannot trust development by accident (APP-015).
		origin, err := s.Apps.ClientByClientID(ctx, tx, rlm.ID, claims.ClientID)
		if err != nil || origin.Environment != c.Environment {
			oe = ErrInvalidGrant("the subject token was issued to a client of another environment")
			return nil
		}
		grantClient := origin.Ref
		if claims.TokenKind == token.KindExchangeAccess {
			grantClient = ""
		}
		if !s.Sessions.AccessGrantActive(ctx, tx, rlm.ID, claims.GrantID, claims.Subject, grantClient) {
			oe = ErrInvalidGrant("the subject token's authorization grant is inactive")
			return nil
		}
		grant, err := s.Apps.ResourceGrant(ctx, tx, c.Ref, res.ID)
		if err != nil || !slices.Contains(grant.ExchangePolicy.AcceptFromAudiences, claims.Audience[0]) {
			// Confused-deputy protection: every accepted transition is registered (TEST-038).
			oe = ErrInvalidTarget("this audience transition is not permitted for the client")
			return nil
		}
		if res.RequiresOrganization && claims.OrgID == "" {
			oe = ErrInvalidTarget("the subject token has no organization context")
			return nil
		}
		requested := strings.Fields(f.Get("scope"))
		explicit := len(requested) > 0
		ceiling := grant.AllowedScopes
		if len(grant.ExchangePolicy.MaxScopes) > 0 {
			ceiling = slices.DeleteFunc(slices.Clone(ceiling), func(sc string) bool { return !slices.Contains(grant.ExchangePolicy.MaxScopes, sc) })
		}
		if !explicit {
			requested = ceiling
		}
		for _, sc := range requested {
			if !slices.Contains(ceiling, sc) {
				oe = ErrInvalidScope("scope " + sc + " exceeds the exchange ceiling")
				return nil
			}
		}
		// Live subject checks (strict).
		if claims.SessionID != "" {
			if _, err := s.Sessions.Active(ctx, tx, rlm.ID, claims.SessionID); err != nil {
				oe = ErrInvalidGrant("subject session is not active")
				return nil
			}
		}
		u, err := s.Users.User(ctx, tx, rlm.ID, claims.Subject)
		if err != nil || !u.CanAuthenticate(s.d.Now()) {
			oe = ErrInvalidGrant("subject is not active")
			return nil
		}
		if claims.OrgID != "" {
			if _, err := s.Orgs.ActiveMembership(ctx, tx, rlm.ID, claims.OrgID, claims.Subject); err != nil {
				oe = ErrInvalidGrant("subject membership is not active")
				return nil
			}
		}
		actor := &token.Actor{Issuer: rlm.Issuer, Subject: c.ClientID, Act: claims.Act}
		if c.ServicePrincipalID != "" {
			actor.Subject = c.ServicePrincipalID
			// An agent acting for a person stays visible as one (MCH-017).
			actor.Agent = s.isAgent(ctx, tx, rlm.ID, c.ServicePrincipalID)
		}
		if s.d.Now().After(time.Unix(claims.Expiry, 0)) {
			oe = ErrInvalidGrant("subject token expired")
			return nil
		}
		remaining := time.Unix(claims.Expiry, 0).Sub(s.d.Now())
		var authTime *time.Time
		if claims.AuthTime != 0 {
			t := time.Unix(claims.AuthTime, 0)
			authTime = &t
		}
		// Step-up scopes (AUT-010) need the subject token's own authentication
		// to be strong and fresh enough; an exchange never upgrades it.
		stepped, err := s.applyStepUp(ctx, tx, rlm.ID, &session.Grant{ACR: claims.ACR, AuthTime: authTime}, requested)
		if err != nil {
			return err
		}
		// Scopes named in the request must all be granted; the default ceiling
		// silently drops scopes the subject token's authentication cannot carry.
		if len(stepped) < len(requested) && (explicit || len(stepped) == 0) {
			oe = oerr(400, "invalid_scope", "a requested scope needs a stronger or more recent authentication than the subject token carries")
			return nil
		}
		// The organization's scope ceiling and scope permission requirements
		// apply to exchanged tokens as to every other issuance (TOK-008).
		permitted, err := s.applyScopePolicy(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: claims.Subject}, claims.OrgID, stepped)
		if err != nil {
			return err
		}
		if len(permitted) < len(stepped) && explicit {
			oe = ErrInvalidScope("a requested scope is not permitted for the subject in this organization")
			return nil
		}
		if len(permitted) == 0 {
			oe = ErrInvalidScope("no scope is available for this exchange")
			return nil
		}
		// Consent (TOK-008): when the subject token's client is governed by
		// user consent, an exchange carries no scope the user did not consent
		// to for that client; a policy cannot widen what the user approved.
		// A machine client never collected consent: its subject token came
		// from an earlier exchange, where the originating client's consent
		// was already applied.
		if origin.ConsentMode == "required" && origin.Type != application.TypeMachine {
			var consented []string
			err := tx.QueryRow(ctx, `SELECT scopes FROM consents WHERE user_id=$1 AND client_ref=$2 AND revoked_at IS NULL`, claims.Subject, origin.Ref).Scan(&consented)
			if err != nil && !storage.IsNoRows(err) {
				return err
			}
			covered := slices.DeleteFunc(slices.Clone(permitted), func(sc string) bool { return !slices.Contains(consented, sc) })
			if len(covered) < len(permitted) && explicit || len(covered) == 0 {
				oe = ErrInvalidScope("a requested scope is outside the user's consent for the originating client")
				return nil
			}
			permitted = covered
		}
		requested = permitted
		access, ttl, err := s.MintAccess(ctx, tx, AccessSpec{Realm: rlm, Client: c, Resource: res, SubjectType: "user", SubjectID: claims.Subject,
			Scopes: requested, OrgID: claims.OrgID, SessionID: claims.SessionID, GrantID: claims.GrantID, AuthTime: authTime, ACR: claims.ACR, Actor: actor,
			Kind: token.KindExchangeAccess, TTLCap: remaining, AuthzVersion: s.authzVersion(ctx, tx, "user", claims.Subject, claims.OrgID), Confirmation: cnf})
		if err != nil {
			if errors.Is(err, token.ErrNoActiveKey) {
				oe = ErrTemporarilyUnavailable
				return nil
			}
			return err
		}
		out = &IssuedTokens{AccessToken: access, TokenType: tokenTypeFor(cnf), ExpiresIn: int(ttl.Seconds()), Scope: strings.Join(requested, " "),
			IssuedTokenType: tokenTypeAccess}
		// Actor preservation (AUD-005): the real actor is the service
		// principal (or agent) the client acts as, the act claim's outermost
		// subject, and the whole delegation chain, including the actors of
		// the subject token's own act claim, is kept next to the effective
		// subject.
		evActor := audit.Ref{Type: "client", ID: c.Ref}
		if c.ServicePrincipalID != "" {
			evActor = audit.Ref{Type: "service_principal", ID: c.ServicePrincipalID}
		}
		chain, truncated := actor.AuditChain()
		meta := map[string]any{"from_audience": claims.Audience[0], "to_audience": res.Audience, "chain_depth": depth + 1,
			"actor_chain": chain, "client_ref": c.Ref, "subject_client_id": claims.ClientID}
		if truncated {
			meta["actor_chain_truncated"] = true
		}
		if actor.Agent {
			meta["agent"] = true
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.exchanged", RealmID: rlm.ID, OrgID: claims.OrgID, Actor: evActor,
			Subject: &audit.Ref{Type: "user", ID: claims.Subject}, ClientID: c.ClientID, Category: "token", Metadata: meta})
		return err
	})
	if txErr != nil {
		return nil, serverError(s, txErr)
	}
	return out, oe
}

// verifyAnyAudience verifies a JWT access token issued by this realm without
// constraining the audience (used by introspection and exchange only).
func (s *Service) verifyAnyAudience(ctx context.Context, rlm *realm.Realm, raw string) (*token.AccessClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, token.ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, token.ErrMalformed
	}
	var peek struct {
		Aud jwt.Audience `json:"aud"`
	}
	if err := json.Unmarshal(payload, &peek); err != nil || len(peek.Aud) != 1 {
		return nil, token.ErrAudience
	}
	return s.Verifier.VerifyAccess(ctx, rlm.ID, rlm.Issuer, peek.Aud[0], raw)
}

// ---------- DPoP (RFC 9449) ----------

// VerifyDPoPProof validates a DPoP proof and returns the JWK thumbprint (jkt). For
// resource requests, accessToken binds the proof via the "ath" claim.
func (s *Service) VerifyDPoPProof(ctx context.Context, rlm *realm.Realm, proof, method, htu, accessToken string) (string, *Error) {
	if len(proof) > 4096 {
		return "", oerr(400, "invalid_dpop_proof", "proof too large")
	}
	tok, err := jwt.ParseSigned(proof, application.AsymmetricAlgorithms)
	if err != nil || len(tok.Headers) != 1 {
		return "", oerr(400, "invalid_dpop_proof", "malformed proof")
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return "", oerr(400, "invalid_dpop_proof", "wrong typ")
	}
	if h.JSONWebKey == nil || !h.JSONWebKey.IsPublic() {
		return "", oerr(400, "invalid_dpop_proof", "missing public jwk")
	}
	var c struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	if err := tok.Claims(h.JSONWebKey.Key, &c); err != nil {
		return "", oerr(400, "invalid_dpop_proof", "signature invalid")
	}
	now := s.d.Now()
	iat := time.Unix(c.IAT, 0)
	if c.JTI == "" || len(c.JTI) > 128 || iat.After(now.Add(30*time.Second)) || now.Sub(iat) > 2*time.Minute {
		return "", oerr(400, "invalid_dpop_proof", "stale or invalid proof")
	}
	if c.HTM != method || stripQuery(c.HTU) != stripQuery(htu) {
		return "", oerr(400, "invalid_dpop_proof", "method or URI mismatch")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if c.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return "", oerr(400, "invalid_dpop_proof", "access token hash mismatch")
		}
	}
	tp, err := h.JSONWebKey.Thumbprint(crypto256())
	if err != nil {
		return "", oerr(400, "invalid_dpop_proof", "bad key")
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)
	tag, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO dpop_proof_jtis (realm_id, jkt, jti, expires_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		rlm.ID, jkt, c.JTI, now.Add(5*time.Minute))
	if err != nil || tag.RowsAffected() != 1 {
		return "", oerr(400, "invalid_dpop_proof", "proof replayed")
	}
	return jkt, nil
}

func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}
