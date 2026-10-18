package session

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/storage"
)

// Grant is a persisted authorization relationship (§4.1).
type Grant struct {
	ID          string     `json:"id"`
	RealmID     string     `json:"realm_id"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	ClientRef   string     `json:"client_ref"`
	OrgID       string     `json:"organization_id,omitempty"`
	SessionID   string     `json:"session_id,omitempty"`
	ResourceIDs []string   `json:"resource_ids"`
	Scopes      []string   `json:"scopes"`
	Offline     bool       `json:"offline"`
	ConsentID   string     `json:"consent_id,omitempty"`
	AuthTime    *time.Time `json:"auth_time,omitempty"`
	AMR         []string   `json:"amr"`
	ACR         string     `json:"acr,omitempty"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	// ClaimsRequest is the OIDC claims parameter of the authorization (OIDC-008).
	ClaimsRequest string `json:"-"`
}

const grantCols = `id, realm_id, subject_type, subject_id, client_ref, coalesce(organization_id,''), coalesce(session_id,''), resource_ids, scopes,
	offline, coalesce(consent_id,''), auth_time, amr, coalesce(acr,''), state, created_at, expires_at, coalesce(claims_request,'')`

func scanGrant(row pgx.Row) (*Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.RealmID, &g.SubjectType, &g.SubjectID, &g.ClientRef, &g.OrgID, &g.SessionID, &g.ResourceIDs, &g.Scopes,
		&g.Offline, &g.ConsentID, &g.AuthTime, &g.AMR, &g.ACR, &g.State, &g.CreatedAt, &g.ExpiresAt, &g.ClaimsRequest)
	return &g, err
}

// CreateGrantTx persists a grant.
func (s *Service) CreateGrantTx(ctx context.Context, tx pgx.Tx, g *Grant) error {
	g.ID = ids.New(ids.Grant)
	g.State = "active"
	g.CreatedAt = s.d.Now()
	if g.AMR == nil {
		g.AMR = []string{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO authorization_grants (id, realm_id, subject_type, subject_id, client_ref, organization_id, session_id,
		resource_ids, scopes, offline, consent_id, auth_time, amr, acr, created_at, expires_at, claims_request)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, g.ID, g.RealmID, g.SubjectType, g.SubjectID, g.ClientRef,
		nilIfEmpty(g.OrgID), nilIfEmpty(g.SessionID), g.ResourceIDs, g.Scopes, g.Offline, nilIfEmpty(g.ConsentID), g.AuthTime, g.AMR,
		nilIfEmpty(g.ACR), g.CreatedAt, g.ExpiresAt, nilIfEmpty(g.ClaimsRequest))
	return err
}

// GrantTx loads a grant FOR UPDATE.
func (s *Service) GrantTx(ctx context.Context, tx pgx.Tx, id string) (*Grant, error) {
	g, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantCols+` FROM authorization_grants WHERE id=$1 FOR UPDATE`, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return g, err
}

// Grant loads a grant.
func (s *Service) Grant(ctx context.Context, q storage.Querier, id string) (*Grant, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	g, err := scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+` FROM authorization_grants WHERE id=$1`, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return g, err
}

// AccessGrantActive checks a signed user token's durable grant within its realm
// and subject. Exchanges retain the originating grant and pass an empty client
// reference; ordinary tokens must also match the grant's client. Missing grant
// authority or database errors fail closed, including pre-fix user JWTs.
func (s *Service) AccessGrantActive(ctx context.Context, q storage.Querier, realmID, grantID, userID, clientRef string) bool {
	if grantID == "" {
		return false
	}
	if q == nil {
		q = s.d.DB.Pool
	}
	var active bool
	err := q.QueryRow(ctx, `SELECT state='active' AND expires_at > $4 FROM authorization_grants
		WHERE realm_id=$1 AND id=$2 AND subject_type='user' AND subject_id=$3 AND ($5='' OR client_ref=$5)`,
		realmID, grantID, userID, s.d.Now(), clientRef).Scan(&active)
	return err == nil && active
}

// RevokeGrantTx revokes a grant and its refresh families and opaque tokens.
func (s *Service) RevokeGrantTx(ctx context.Context, tx pgx.Tx, grantID, reason string) error {
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$2, revoke_reason=$3 WHERE id=$1 AND state='active'`, grantID, now, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason=$3 WHERE grant_id=$1 AND state='active'`, grantID, now, reason); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE grant_id=$1 AND revoked_at IS NULL`, grantID, now)
	return err
}

// RevokeOrgGrantsTx revokes a user's grants for one organization (membership removal,
// §27.7). Unrelated organizations are untouched (TEN-004, TEST-033).
func (s *Service) RevokeOrgGrantsTx(ctx context.Context, tx pgx.Tx, realmID, userID, orgID, reason string) error {
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$4, revoke_reason=$5 WHERE state='active' AND grant_id IN
		(SELECT id FROM authorization_grants WHERE realm_id=$1 AND subject_id=$2 AND organization_id=$3)`, realmID, userID, orgID, now, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$4, revoke_reason=$5
		WHERE realm_id=$1 AND subject_id=$2 AND organization_id=$3 AND state='active'`, realmID, userID, orgID, now, reason); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$4 WHERE realm_id=$1 AND subject_id=$2 AND organization_id=$3 AND revoked_at IS NULL`,
		realmID, userID, orgID, now)
	return err
}

// RevokeOrganizationTx revokes every grant bound to an organization (suspension/deletion).
func (s *Service) RevokeOrganizationTx(ctx context.Context, tx pgx.Tx, realmID, orgID, reason string) error {
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$3, revoke_reason=$4 WHERE state='active' AND grant_id IN
		(SELECT id FROM authorization_grants WHERE realm_id=$1 AND organization_id=$2)`, realmID, orgID, now, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$3, revoke_reason=$4 WHERE realm_id=$1 AND organization_id=$2 AND state='active'`,
		realmID, orgID, now, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$3 WHERE realm_id=$1 AND organization_id=$2 AND revoked_at IS NULL`, realmID, orgID, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$3, revoked_by_type='system', revoke_reason=$4
		WHERE realm_id=$1 AND organization_id=$2 AND state='active'`, realmID, orgID, now, reason)
	return err
}

// ---------- authorization codes ----------

// Code is a stored authorization code.
type Code struct {
	ID            string
	ClientRef     string
	TransactionID string
	GrantID       string
	RedirectURI   string
	Challenge     string
	Method        string
	Nonce         string
	// DPoPJKT is the dpop_jkt of the authorization request (RFC 9449 §10):
	// the code is redeemed only with a DPoP proof of that key. Empty: no
	// binding.
	DPoPJKT   string
	ExpiresAt time.Time
}

// IssueCodeTx creates a single-use authorization code bound to client, redirect,
// PKCE challenge, transaction (§14.1) and, when the request named one, a DPoP
// key (TOK-019). Only its digest is stored.
func (s *Service) IssueCodeTx(ctx context.Context, tx pgx.Tx, realmID string, c Code, ttl time.Duration) (string, error) {
	plain := secret.Token(secret.PrefixAuthCode)
	now := s.d.Now()
	_, err := tx.Exec(ctx, `INSERT INTO authorization_codes (id, realm_id, code_digest, client_ref, transaction_id, grant_id, redirect_uri,
		code_challenge, code_challenge_method, nonce, expires_at, created_at, dpop_jkt) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		ids.New(ids.AuthCode), realmID, secret.Digest(plain), c.ClientRef, c.TransactionID, c.GrantID, c.RedirectURI, c.Challenge, c.Method,
		nilIfEmpty(c.Nonce), now.Add(ttl), now, nilIfEmpty(c.DPoPJKT))
	return plain, err
}

// ErrCodeReplay indicates a consumed code was presented again.
var ErrCodeReplay = problem.ErrInvalidProof.WithDetail("authorization code replay")

// ConsumeCodeTx atomically consumes a code (DB-005). A second presentation of a
// consumed code revokes the grant it produced (RFC 9700 §4.5 replay response).
func (s *Service) ConsumeCodeTx(ctx context.Context, tx pgx.Tx, realmID, plain string) (*Code, error) {
	if !secret.HasPrefix(plain, secret.PrefixAuthCode) || len(plain) > 100 {
		return nil, problem.ErrInvalidProof
	}
	var c Code
	var consumed *time.Time
	var nonce, jkt *string
	err := tx.QueryRow(ctx, `SELECT id, client_ref, transaction_id, grant_id, redirect_uri, code_challenge, code_challenge_method, nonce, expires_at, consumed_at,
		dpop_jkt FROM authorization_codes WHERE realm_id=$1 AND code_digest=$2 FOR UPDATE`, realmID, secret.Digest(plain)).Scan(&c.ID, &c.ClientRef,
		&c.TransactionID, &c.GrantID, &c.RedirectURI, &c.Challenge, &c.Method, &nonce, &c.ExpiresAt, &consumed, &jkt)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrInvalidProof
		}
		return nil, err
	}
	c.Nonce, c.DPoPJKT = deref(nonce), deref(jkt)
	if consumed != nil {
		return &c, ErrCodeReplay
	}
	if !s.d.Now().Before(c.ExpiresAt) {
		return nil, problem.ErrInvalidProof.WithDetail("authorization code expired")
	}
	if _, err := tx.Exec(ctx, `UPDATE authorization_codes SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`, c.ID, s.d.Now()); err != nil {
		return nil, err
	}
	return &c, nil
}

// ---------- refresh families ----------

// Family is a refresh rotation family (SES-006).
type Family struct {
	ID                string
	GrantID           string
	ClientRef         string
	Generation        int
	State             string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	// Binding is the sender constraint of the family's first issuance,
	// kept for its whole life (TOK-019).
	Binding SenderBinding
}

// SenderBinding is a sender constraint (TOK-019): the JWK SHA-256
// thumbprint of a DPoP key (RFC 9449, the cnf.jkt of a token) or the
// SHA-256 thumbprint of a TLS client certificate (RFC 8705, cnf.x5t#S256).
// For a refresh family it is what the first issuance was bound to (both
// empty: unbound); for a token request it is what the request proves, its
// DPoP proof's key and the certificate of its connection, whatever the
// client's binding policy.
type SenderBinding struct {
	JKT     string
	X5TS256 string
}

// refusal reports what a request that proves p fails to prove of the
// binding b: the binding kind ("dpop" or "mtls") and why ("missing" or
// "mismatch"), or two empty strings when p satisfies b. An unbound b is
// satisfied by any request.
func (b SenderBinding) refusal(p SenderBinding) (kind, why string) {
	switch {
	case b.JKT != "" && p.JKT == "":
		return "dpop", "missing"
	case b.JKT != "" && p.JKT != b.JKT:
		return "dpop", "mismatch"
	case b.X5TS256 != "" && p.X5TS256 == "":
		return "mtls", "missing"
	case b.X5TS256 != "" && p.X5TS256 != b.X5TS256:
		return "mtls", "mismatch"
	}
	return "", ""
}

// IssueRefreshTx creates a new family with its first generation. A family
// issued with a sender constraint (bind) keeps it for its whole life: every
// later use must prove the same DPoP key or TLS client certificate
// (UseRefresh), and rotation never changes it.
func (s *Service) IssueRefreshTx(ctx context.Context, tx pgx.Tx, realmID, grantID, clientRef string, bind SenderBinding, idle, absolute time.Duration,
	absoluteCap *time.Time) (string, *Family, error) {
	now := s.d.Now()
	abs := now.Add(absolute)
	if absoluteCap != nil && absoluteCap.Before(abs) {
		abs = *absoluteCap // refresh cannot outlive the parent session (§14.5)
	}
	idleAt := now.Add(idle)
	if idleAt.After(abs) {
		idleAt = abs
	}
	f := &Family{ID: ids.New(ids.RefreshFamily), GrantID: grantID, ClientRef: clientRef, Generation: 1, State: "active", IdleExpiresAt: idleAt,
		AbsoluteExpiresAt: abs, Binding: bind}
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_families (id, realm_id, grant_id, client_ref, idle_expires_at, absolute_expires_at, created_at, idle_window_seconds,
		cnf_jkt, cnf_x5t_s256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.ID, realmID, grantID, clientRef, idleAt, abs, now, int(idle.Seconds()),
		nilIfEmpty(bind.JKT), nilIfEmpty(bind.X5TS256)); err != nil {
		return "", nil, err
	}
	plain := secret.Token(secret.PrefixRefresh)
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (id, realm_id, family_id, generation, token_digest, issued_at) VALUES ($1,$2,$3,1,$4,$5)`,
		ids.New(ids.RefreshToken), realmID, f.ID, secret.Digest(plain), now); err != nil {
		return "", nil, err
	}
	return plain, f, nil
}

// RotateResult is returned by RotateRefresh.
type RotateResult struct {
	Grant        *Grant
	Family       *Family
	RefreshToken string
}

// RotateRefresh implements the §24.3 transaction. The family row and presented
// generation are locked. A sender-bound family that the request's proof (the
// DPoP key and TLS client certificate it presents) does not satisfy is
// refused with ErrRefreshSender before anything else, recording only an
// audit event. A reused generation marks the family compromised, commits
// that state with audit/outbox, and returns ErrRefreshReuse without issuing tokens.
// Otherwise validate re-evaluates permitted scope and access, and mint creates the
// access artifacts inside the same transaction before the successor is committed.
func (s *Service) RotateRefresh(ctx context.Context, realmID, presented, clientRef string, proof SenderBinding, idle time.Duration,
	validate func(tx pgx.Tx, g *Grant) error, mint func(tx pgx.Tx, g *Grant, f *Family) error) (*RotateResult, error) {
	return s.UseRefresh(ctx, realmID, presented, clientRef, proof, idle, false, validate, mint)
}

// UseRefresh is RotateRefresh with a choice: keep leaves the presented token
// current instead of rotating it, for clients whose profile forbids
// rotation (FAPI 2.0, ADV-001). Such clients are confidential and their
// tokens sender-constrained, so a stolen refresh token alone is not usable
// (their families are sender-bound as well); the family's idle and absolute
// expiry still apply.
func (s *Service) UseRefresh(ctx context.Context, realmID, presented, clientRef string, proof SenderBinding, idle time.Duration, keep bool,
	validate func(tx pgx.Tx, g *Grant) error, mint func(tx pgx.Tx, g *Grant, f *Family) error) (*RotateResult, error) {
	if !secret.HasPrefix(presented, secret.PrefixRefresh) || len(presented) > 100 {
		return nil, ErrRefreshInvalid
	}
	var result *RotateResult
	var reuse, refused bool
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		reuse, refused = false, false
		var tokenID, familyID, sessionID, owner string
		var offline bool
		var generation int
		var consumedAt, revokedAt *time.Time
		err := tx.QueryRow(ctx, `SELECT t.id, t.family_id, t.generation, t.consumed_at, t.revoked_at,
			coalesce(g.session_id,''), g.offline, f.client_ref FROM refresh_tokens t
			JOIN refresh_families f ON f.id=t.family_id JOIN authorization_grants g ON g.id=f.grant_id
			WHERE t.realm_id=$1 AND t.token_digest=$2`, realmID, secret.Digest(presented)).
			Scan(&tokenID, &familyID, &generation, &consumedAt, &revokedAt, &sessionID, &offline, &owner)
		if err != nil {
			if storage.IsNoRows(err) {
				return ErrRefreshInvalid
			}
			return err
		}
		if owner != clientRef {
			return ErrRefreshInvalid
		}
		if sessionID != "" && !offline {
			// Session revocation locks the session before its families. Take
			// the same lock order before rotation/reuse touches that session;
			// otherwise refresh holds a family while logout holds the session.
			var locked string
			if err := tx.QueryRow(ctx, `SELECT id FROM sessions WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, sessionID).Scan(&locked); err != nil {
				if storage.IsNoRows(err) {
					return ErrRefreshInvalid
				}
				return err
			}
		}
		var f Family
		var window *int
		var cnfJKT, cnfX5T *string
		err = tx.QueryRow(ctx, `SELECT id, grant_id, client_ref, current_generation, state, idle_expires_at, absolute_expires_at, idle_window_seconds,
			cnf_jkt, cnf_x5t_s256 FROM refresh_families WHERE id=$1 FOR UPDATE`, familyID).Scan(&f.ID, &f.GrantID, &f.ClientRef, &f.Generation, &f.State,
			&f.IdleExpiresAt, &f.AbsoluteExpiresAt, &window, &cnfJKT, &cnfX5T)
		if window != nil && *window > 0 {
			// Rotation keeps the family's own idle window (remember-me and
			// offline families are not shortened to the browser idle timeout).
			idle = time.Duration(*window) * time.Second
		}
		if err != nil {
			return err
		}
		// Client binding: a token presented by another client is invalid (and not a reuse signal).
		if f.ClientRef != clientRef {
			return ErrRefreshInvalid
		}
		now := s.d.Now()
		// Sender binding (TOK-019, RFC 9449 §5, RFC 8705 §3; owner decision
		// 13): a family whose first issuance was bound to a DPoP key or a TLS
		// client certificate is used only by a request that proves the same
		// one, whatever the client's require_dpop says now. It is checked
		// before reuse detection and changes nothing but the audit trail: a
		// presenter that cannot prove possession cannot use the token, of the
		// current generation or an earlier one, so it must not be able to
		// revoke the holder's family, grant and session through reuse
		// detection either. Families issued before migration 0089 have no
		// binding and are not checked.
		f.Binding = SenderBinding{JKT: deref(cnfJKT), X5TS256: deref(cnfX5T)}
		if kind, why := f.Binding.refusal(proof); kind != "" {
			g, err := s.Grant(ctx, tx, f.GrantID)
			if err != nil {
				return err
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.refresh.binding_failed", RealmID: realmID, OrgID: g.OrgID,
				Actor: audit.Ref{Type: "client", ID: clientRef}, Subject: &audit.Ref{Type: g.SubjectType, ID: g.SubjectID}, Outcome: audit.Denied,
				GrantID: g.ID, SessionID: g.SessionID, ReasonCode: "REFRESH_BINDING_FAILED", Metadata: map[string]any{"token_family_id": f.ID,
					"presented_generation": generation, "binding": kind, "proof": why}}); err != nil {
				return err
			}
			refused = true
			return nil // commit the audit record only
		}
		if consumedAt != nil || generation != f.Generation {
			if f.State == "active" {
				if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='compromised', revoked_at=$2, revoke_reason='reuse_detected' WHERE id=$1`, f.ID, now); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE family_id=$1 AND revoked_at IS NULL`, f.ID, now); err != nil {
					return err
				}
				g, err := s.GrantTx(ctx, tx, f.GrantID)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
					VALUES ($1,$2,'family',$3,'reuse_detected',$4)`, ids.New(ids.Revocation), realmID, f.ID, now); err != nil {
					return err
				}
				// Documented effect (SES-008): the grant is revoked and, for session-bound
				// grants, the session is revoked so the user must authenticate again.
				if err := s.RevokeGrantTx(ctx, tx, g.ID, "refresh_reuse"); err != nil {
					return err
				}
				if g.SessionID != "" && !g.Offline {
					if err := s.RevokeTx(ctx, tx, realmID, g.SessionID, "refresh_reuse"); err != nil {
						return err
					}
				}
				if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.refresh.reuse_detected", RealmID: realmID, OrgID: g.OrgID,
					Actor: audit.Ref{Type: "client", ID: clientRef}, Subject: &audit.Ref{Type: g.SubjectType, ID: g.SubjectID}, Outcome: audit.Denied,
					GrantID: g.ID, SessionID: g.SessionID, ReasonCode: "REFRESH_REUSE", Metadata: map[string]any{"token_family_id": f.ID, "presented_generation": generation}}); err != nil {
					return err
				}
				if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "security.refresh_reuse_detected", RealmID: realmID, OrgID: g.OrgID,
					AggregateType: "grant", AggregateID: g.ID, Data: map[string]any{"subject_id": g.SubjectID, "family_id": f.ID}}); err != nil {
					return err
				}
			}
			reuse = true
			return nil // commit compromise state
		}
		if f.State != "active" || revokedAt != nil || !now.Before(f.IdleExpiresAt) || !now.Before(f.AbsoluteExpiresAt) {
			return ErrRefreshInvalid
		}
		g, err := s.GrantTx(ctx, tx, f.GrantID)
		if err != nil {
			return err
		}
		if g.State != "active" || !now.Before(g.ExpiresAt) {
			return ErrRefreshInvalid
		}
		if g.SessionID != "" && !g.Offline {
			sess, err := s.Get(ctx, tx, realmID, g.SessionID)
			if err != nil || !sess.IsActive(now) {
				return ErrRefreshInvalid
			}
			// The family's window may be shorter than the session's: the
			// refresh extends the session but never shortens it (SES-002).
			if err := s.TouchFromRefreshTx(ctx, tx, g.SessionID, idle); err != nil {
				return err
			}
		}
		if err := validate(tx, g); err != nil {
			return err
		}
		if keep {
			newIdle := now.Add(idle)
			if newIdle.After(f.AbsoluteExpiresAt) {
				newIdle = f.AbsoluteExpiresAt
			}
			if _, err := tx.Exec(ctx, `UPDATE refresh_families SET idle_expires_at=$2, last_rotated_at=$3 WHERE id=$1`, f.ID, newIdle, now); err != nil {
				return err
			}
			f.IdleExpiresAt = newIdle
			if err := mint(tx, g, &f); err != nil {
				return err
			}
			result = &RotateResult{Grant: g, Family: &f, RefreshToken: presented}
			return nil
		}
		// Consume the current generation; exactly one successor (DB-006).
		tag, err := tx.Exec(ctx, `UPDATE refresh_tokens SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`, tokenID, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRefreshInvalid
		}
		plain := secret.Token(secret.PrefixRefresh)
		if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (id, realm_id, family_id, generation, token_digest, parent_id, issued_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, ids.New(ids.RefreshToken), realmID, f.ID, f.Generation+1, secret.Digest(plain), tokenID, now); err != nil {
			return err
		}
		newIdle := now.Add(idle)
		if newIdle.After(f.AbsoluteExpiresAt) {
			newIdle = f.AbsoluteExpiresAt
		}
		if _, err := tx.Exec(ctx, `UPDATE refresh_families SET current_generation=current_generation+1, idle_expires_at=$2, last_rotated_at=$3 WHERE id=$1`,
			f.ID, newIdle, now); err != nil {
			return err
		}
		f.Generation++
		f.IdleExpiresAt = newIdle
		if err := mint(tx, g, &f); err != nil {
			return err
		}
		result = &RotateResult{Grant: g, Family: &f, RefreshToken: plain}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if refused {
		return nil, ErrRefreshSender
	}
	if reuse {
		return nil, ErrRefreshReuse
	}
	return result, nil
}

// RevokeRefresh revokes the family of a presented refresh token, bound to the
// presenting client (TOK-010). Unknown tokens are ignored per RFC 7009.
func (s *Service) RevokeRefresh(ctx context.Context, realmID, presented, clientRef string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var familyID, grantID, owner string
		err := tx.QueryRow(ctx, `SELECT f.id, f.grant_id, f.client_ref FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id
			WHERE t.realm_id=$1 AND t.token_digest=$2 FOR UPDATE OF f`, realmID, secret.Digest(presented)).Scan(&familyID, &grantID, &owner)
		if err != nil {
			if storage.IsNoRows(err) {
				return nil
			}
			return err
		}
		if owner != clientRef {
			return nil // RFC 7009: a client may only revoke its own tokens; respond identically.
		}
		if err := s.RevokeGrantTx(ctx, tx, grantID, "client_revocation"); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.refresh.revoked", RealmID: realmID, Actor: actor, GrantID: grantID,
			Metadata: map[string]any{"token_family_id": familyID}})
		return err
	})
}

// ---------- opaque access tokens ----------

// OpaqueToken is an online-verified access token record.
type OpaqueToken struct {
	ID                   string
	RealmID              string
	Kind                 string
	GrantID              string
	ClientRef            string
	SubjectType          string
	SubjectID            string
	Actor                []byte
	OrgID                string
	ResourceID           string
	Scopes               []string
	SessionID            string
	ImpersonationGrantID string
	JTI                  string
	AuthTime             *time.Time
	ACR                  string
	// Cnf is the sender constraint (DPoP key or TLS certificate thumbprint)
	// as the JSON cnf claim, kept so opaque tokens stay bound (TOK-019).
	Cnf       []byte
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// IssueOpaqueTx stores an opaque access token and returns its plaintext.
func (s *Service) IssueOpaqueTx(ctx context.Context, tx pgx.Tx, prefix string, t *OpaqueToken) (string, error) {
	plain := secret.Token(prefix)
	t.ID = ids.New(ids.AccessToken)
	if t.JTI == "" {
		t.JTI = t.ID
	}
	t.CreatedAt = s.d.Now()
	_, err := tx.Exec(ctx, `INSERT INTO opaque_access_tokens (id, realm_id, token_digest, token_kind, grant_id, client_ref, subject_type, subject_id,
		actor, organization_id, resource_id, scopes, session_id, impersonation_grant_id, jti, auth_time, acr, expires_at, created_at, cnf)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, t.ID, t.RealmID, secret.Digest(plain), t.Kind,
		nilIfEmpty(t.GrantID), t.ClientRef, t.SubjectType, t.SubjectID, nullJSON(t.Actor), nilIfEmpty(t.OrgID), t.ResourceID, t.Scopes,
		nilIfEmpty(t.SessionID), nilIfEmpty(t.ImpersonationGrantID), t.JTI, t.AuthTime, nilIfEmpty(t.ACR), t.ExpiresAt, t.CreatedAt, nullJSON(t.Cnf))
	return plain, err
}

// Opaque loads an opaque token by plaintext (authoritative, uncached).
func (s *Service) Opaque(ctx context.Context, q storage.Querier, realmID, plain string) (*OpaqueToken, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var t OpaqueToken
	var grant, org, sess, imp, acr *string
	err := q.QueryRow(ctx, `SELECT id, realm_id, token_kind, grant_id, client_ref, subject_type, subject_id, actor, organization_id, resource_id, scopes,
		session_id, impersonation_grant_id, jti, auth_time, acr, expires_at, revoked_at, created_at, cnf FROM opaque_access_tokens
		WHERE realm_id=$1 AND token_digest=$2`, realmID, secret.Digest(plain)).Scan(&t.ID, &t.RealmID, &t.Kind, &grant, &t.ClientRef,
		&t.SubjectType, &t.SubjectID, &t.Actor, &org, &t.ResourceID, &t.Scopes, &sess, &imp, &t.JTI, &t.AuthTime, &acr, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
		&t.Cnf)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	t.GrantID, t.OrgID, t.SessionID, t.ImpersonationGrantID, t.ACR = deref(grant), deref(org), deref(sess), deref(imp), deref(acr)
	return &t, nil
}

// RevokeOpaque revokes an opaque token presented by its owning client.
func (s *Service) RevokeOpaque(ctx context.Context, realmID, plain, clientRef string) error {
	_, err := s.d.DB.Pool.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$4 WHERE realm_id=$1 AND token_digest=$2 AND client_ref=$3 AND revoked_at IS NULL`,
		realmID, secret.Digest(plain), clientRef, s.d.Now())
	return err
}

// RevokeJTITx records a JWT access-token revocation for online verifiers.
func (s *Service) RevokeJTITx(ctx context.Context, q storage.Querier, realmID, jti, reason string, expiresAt time.Time) error {
	_, err := q.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at, expires_at)
		VALUES ($1,$2,'jti',$3,$4,$5,$6)`, ids.New(ids.Revocation), realmID, jti, reason, s.d.Now(), expiresAt)
	return err
}

// JTIRevoked reports whether a JWT ID has been revoked.
func (s *Service) JTIRevoked(ctx context.Context, q storage.Querier, realmID, jti string) (bool, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var b bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM token_revocations WHERE realm_id=$1 AND reference_type='jti' AND reference_id=$2)`, realmID, jti).Scan(&b)
	return b, err
}

// UserTokenRevoked reports whether an account-wide revocation of the user's
// tokens ("log out everywhere" and the other revocations that include offline
// grants, RevokeUserTx, SES-005) took effect at or after issuedAt: a token
// issued at or before that time is inactive. It is one lookup on the
// token_revocations_ref index. JWTs give issuedAt in whole seconds (iat), so a
// token issued in the same second as the revocation counts as revoked.
//
// Tokens bound to a session (sid) need no such lookup: RevokeUserTx revokes
// every session, and the session check is exact.
func (s *Service) UserTokenRevoked(ctx context.Context, q storage.Querier, realmID, userID string, issuedAt time.Time) (bool, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var b bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM token_revocations WHERE realm_id=$1 AND reference_type='user' AND reference_id=$2
		AND effective_at >= $3)`, realmID, userID, issuedAt).Scan(&b)
	return b, err
}

// CleanupExpired removes expired one-time artifacts and replay records (OPS-009).
func (s *Service) CleanupExpired(ctx context.Context, retention time.Duration) (int64, error) {
	now := s.d.Now()
	var total int64
	for _, q := range []string{
		`DELETE FROM authorization_codes WHERE expires_at < $1`,
		`DELETE FROM opaque_access_tokens WHERE expires_at < $1`,
		`DELETE FROM token_revocations WHERE reference_type='jti' AND expires_at IS NOT NULL AND expires_at < $1`,
		`DELETE FROM dpop_proof_jtis WHERE expires_at < $1`,
		`DELETE FROM pushed_authorization_requests WHERE expires_at < $1`,
		`DELETE FROM device_codes WHERE expires_at < $1 AND state IN ('expired','consumed','denied','pending')`,
	} {
		tag, err := s.d.DB.Pool.Exec(ctx, q, now.Add(-time.Minute))
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	// Ended grants go first, with their refresh families, refresh tokens and
	// codes (PRV-004): until now a grant was kept forever and kept its
	// session row alive with it.
	cutoff := now.Add(-retention)
	if n, err := s.purgeEndedGrants(ctx, cutoff); err != nil {
		return total, err
	} else {
		total += n
	}
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM client_sessions c USING sessions s WHERE c.session_id=s.id AND s.state <> 'active'
		AND coalesce(s.revoked_at, s.absolute_expires_at) < $1`, cutoff)
	if err != nil {
		return total, err
	}
	total += tag.RowsAffected()
	tag, err = s.d.DB.Pool.Exec(ctx, `DELETE FROM sessions s WHERE state <> 'active' AND coalesce(revoked_at, absolute_expires_at) < $1
		AND NOT EXISTS (SELECT 1 FROM authorization_grants g WHERE g.session_id=s.id)
		AND NOT EXISTS (SELECT 1 FROM client_sessions c WHERE c.session_id=s.id)`, cutoff)
	if err != nil {
		return total, err
	}
	total += tag.RowsAffected()
	return total, nil
}

// purgeEndedGrants deletes, in bounded batches, grants that ended (revoked,
// or past their expiry) before cutoff, with everything hanging off them.
func (s *Service) purgeEndedGrants(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		total = 0
		rows, err := tx.Query(ctx, `SELECT id FROM authorization_grants WHERE (state <> 'active' AND coalesce(revoked_at, expires_at) < $1)
			OR expires_at < $1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED`, cutoff)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if len(ids) == 0 {
			return nil
		}
		for _, q := range []string{
			`DELETE FROM refresh_tokens WHERE family_id IN (SELECT id FROM refresh_families WHERE grant_id = ANY($1))`,
			`DELETE FROM refresh_families WHERE grant_id = ANY($1)`,
			`DELETE FROM authorization_codes WHERE grant_id = ANY($1)`,
			`DELETE FROM opaque_access_tokens WHERE grant_id = ANY($1)`,
			`DELETE FROM authorization_grants WHERE id = ANY($1)`,
		} {
			tag, err := tx.Exec(ctx, q, ids)
			if err != nil {
				return err
			}
			total += tag.RowsAffected()
		}
		return nil
	})
	return total, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
