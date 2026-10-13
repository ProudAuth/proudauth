// Package session owns IdP sessions, authorization grants and refresh-token families (§13).
package session

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/reqctx"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
)

// Factor is evidence of one completed authentication factor (AUT-015).
type Factor struct {
	Type         string    `json:"type"` // pwd | otp | totp | hwk | swk | recovery | fed | fed_mfa | magic_link | sms
	At           time.Time `json:"at"`
	CredentialID string    `json:"credential_id,omitempty"`
	UserVerified bool      `json:"user_verified,omitempty"`
	Upstream     string    `json:"upstream,omitempty"`
}

// Session is a durable IdP session (SES-001).
type Session struct {
	ID                 string     `json:"id"`
	RealmID            string     `json:"realm_id"`
	UserID             string     `json:"user_id"`
	State              string     `json:"state"`
	AuthTime           time.Time  `json:"auth_time"`
	MFATime            *time.Time `json:"mfa_time,omitempty"`
	AMR                []string   `json:"amr"`
	ACR                string     `json:"acr"`
	Factors            []Factor   `json:"-"`
	RecoveryRestricted bool       `json:"recovery_restricted"`
	RememberMe         bool       `json:"remember_me"`
	Transient          bool       `json:"transient"`
	CreatedAt          time.Time  `json:"created_at"`
	LastActivityAt     time.Time  `json:"last_activity_at"`
	IdleExpiresAt      time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt  time.Time  `json:"absolute_expires_at"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	RevokeReason       string     `json:"revoke_reason,omitempty"`
	ClientIP           string     `json:"network,omitempty"`
	UserAgent          string     `json:"user_agent,omitempty"`
	DeviceLabel        string     `json:"device_label,omitempty"`
}

// IsActive reports whether the session is usable at now.
func (s *Session) IsActive(now time.Time) bool {
	return s.State == "active" && now.Before(s.IdleExpiresAt) && now.Before(s.AbsoluteExpiresAt)
}

// HasMFA reports whether the session holds multi-factor evidence.
func (s *Session) HasMFA() bool { return s.MFATime != nil }

// Errors.
var (
	ErrRefreshInvalid = errors.New("refresh token invalid")
	ErrRefreshReuse   = errors.New("refresh token reuse detected")
)

// Service manages sessions and grants.
type Service struct {
	d *runtime.Deps
}

// NewService returns the session service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

const sessionCols = `id, realm_id, user_id, state, auth_time, mfa_time, amr, acr, factors, recovery_restricted, remember_me, transient,
	created_at, last_activity_at, idle_expires_at, absolute_expires_at, revoked_at, coalesce(revoke_reason,''), coalesce(client_ip,''),
	coalesce(user_agent,''), coalesce(device_label,'')`

func scanSession(row pgx.Row) (*Session, error) {
	var s Session
	var factors []byte
	if err := row.Scan(&s.ID, &s.RealmID, &s.UserID, &s.State, &s.AuthTime, &s.MFATime, &s.AMR, &s.ACR, &factors, &s.RecoveryRestricted,
		&s.RememberMe, &s.Transient, &s.CreatedAt, &s.LastActivityAt, &s.IdleExpiresAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.RevokeReason,
		&s.ClientIP, &s.UserAgent, &s.DeviceLabel); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(factors, &s.Factors)
	return &s, nil
}

// CreateInput describes a new session.
type CreateInput struct {
	RealmID            string
	UserID             string
	AuthTime           time.Time
	Factors            []Factor
	ACR                string
	RecoveryRestricted bool
	RememberMe         bool
	Transient          bool
	Idle               time.Duration
	Absolute           time.Duration
	MaxConcurrent      int
	ClientIP           string
	UserAgent          string
	WithCookie         bool
}

// AMRFromFactors derives RFC 8176 amr values and the MFA time.
func AMRFromFactors(fs []Factor) ([]string, *time.Time) {
	var amr []string
	kinds := map[string]bool{}
	var latest time.Time
	for _, f := range fs {
		if !slices.Contains(amr, f.Type) {
			amr = append(amr, f.Type)
		}
		switch f.Type {
		case "pwd", "magic_link", "otp", "fed", "sms":
			kinds["knowledge_or_possession_primary"] = true
		case "totp", "hotp", "recovery", "fed_mfa":
			// fed_mfa: upstream MFA asserted by a connection explicitly trusted for
			// it (FED-009).
			kinds["second"] = true
		case "hwk", "swk":
			kinds["second"] = true
			if f.UserVerified {
				kinds["knowledge_or_possession_primary"] = true // a user-verified passkey is multi-factor itself (MFA-007)
			}
		case "x509":
			// A client certificate is possession; a key protected by a second
			// factor (smart card and PIN) is multi-factor itself (PROV-016).
			kinds["knowledge_or_possession_primary"] = true
			if f.UserVerified {
				kinds["second"] = true
			}
		}
		if f.At.After(latest) {
			latest = f.At
		}
	}
	if kinds["knowledge_or_possession_primary"] && kinds["second"] {
		amr = append(amr, "mfa")
		t := latest
		return amr, &t
	}
	return amr, nil
}

// ACRPhishingResistant is the local profile for a user-verified passkey.
const ACRPhishingResistant = "urn:proudauth:acr:phishing_resistant"

// ACRFor returns the local assurance profile for a set of factors (AUT-015). These
// are local profile names, not external certification claims.
func ACRFor(fs []Factor) string {
	amr, mfa := AMRFromFactors(fs)
	phishingResistant := false
	recovery := false
	for _, f := range fs {
		if (f.Type == "hwk" || f.Type == "swk" || f.Type == "x509") && f.UserVerified {
			// The key never leaves its holder and the TLS handshake binds
			// it to this server, so it cannot be relayed by a phishing site.
			phishingResistant = true
		}
		if f.Type == "recovery" {
			recovery = true
		}
	}
	switch {
	case phishingResistant:
		return ACRPhishingResistant
	case mfa != nil && !recovery:
		return "urn:proudauth:acr:mfa"
	case mfa != nil && recovery:
		return "urn:proudauth:acr:recovery"
	case slices.Contains(amr, "fed"):
		return "urn:proudauth:acr:federated"
	case len(amr) == 1 && amr[0] == "anon":
		return "urn:proudauth:acr:anonymous" // guest identity (REG-010)
	default:
		return "urn:proudauth:acr:single_factor"
	}
}

// ACRRank orders assurance profiles for "at least" comparisons.
func ACRRank(acr string) int {
	switch acr {
	case "urn:proudauth:acr:phishing_resistant":
		return 4
	case "urn:proudauth:acr:mfa":
		return 3
	case "urn:proudauth:acr:recovery":
		return 2
	case "urn:proudauth:acr:federated", "urn:proudauth:acr:single_factor":
		return 1
	}
	return 0
}

// CreateTx creates a fresh session (new handle after authentication, AUT-007). It
// enforces the concurrent-session limit by revoking the oldest sessions (SES-002).
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, in CreateInput) (*Session, string, error) {
	now := s.d.Now()
	amr, mfa := AMRFromFactors(in.Factors)
	if amr == nil {
		amr = []string{}
	}
	acr := in.ACR
	if acr == "" {
		acr = ACRFor(in.Factors)
	}
	factors, _ := json.Marshal(in.Factors)
	abs := now.Add(in.Absolute)
	idle := now.Add(in.Idle)
	if idle.After(abs) {
		idle = abs
	}
	var cookie string
	var cookieDigest *string
	if in.WithCookie {
		cookie = secret.Token(secret.PrefixSession)
		d := secret.Digest(cookie)
		cookieDigest = &d
	}
	sess := &Session{ID: ids.New(ids.Session)}
	if in.MaxConcurrent > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active' AND absolute_expires_at > $2`, in.UserID, now).Scan(&n); err != nil {
			return nil, "", err
		}
		if n >= in.MaxConcurrent {
			rows, err := tx.Query(ctx, `SELECT id FROM sessions WHERE user_id=$1 AND state='active' ORDER BY last_activity_at ASC LIMIT $2`, in.UserID, n-in.MaxConcurrent+1)
			if err != nil {
				return nil, "", err
			}
			var old []string
			for rows.Next() {
				var id string
				_ = rows.Scan(&id)
				old = append(old, id)
			}
			rows.Close()
			for _, id := range old {
				if err := s.RevokeTx(ctx, tx, in.RealmID, id, "concurrent_limit"); err != nil {
					return nil, "", err
				}
			}
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO sessions (id, realm_id, user_id, auth_time, mfa_time, amr, acr, factors, recovery_restricted, remember_me,
		transient, cookie_digest, created_at, last_activity_at, idle_expires_at, absolute_expires_at, client_ip, user_agent, device_label)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16,$17,$18)`, sess.ID, in.RealmID, in.UserID, in.AuthTime, mfa, amr, acr,
		factors, in.RecoveryRestricted, in.RememberMe, in.Transient, cookieDigest, now, idle, abs, nilIfEmpty(s.networkContext(in.ClientIP)), nilIfEmpty(reqctx.TruncateUA(in.UserAgent)),
		nilIfEmpty(DeviceLabel(in.UserAgent)))
	if err != nil {
		return nil, "", err
	}
	out, err := s.Get(ctx, tx, in.RealmID, sess.ID)
	return out, cookie, err
}

// Get loads a session.
func (s *Service) Get(ctx context.Context, q storage.Querier, realmID, id string) (*Session, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	sess, err := scanSession(q.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return sess, err
}

// Active loads a session and fails unless it is currently active (authoritative
// strict-online check: no cache is consulted, §13.2).
func (s *Service) Active(ctx context.Context, q storage.Querier, realmID, id string) (*Session, error) {
	sess, err := s.Get(ctx, q, realmID, id)
	if err != nil {
		return nil, err
	}
	if !sess.IsActive(s.d.Now()) {
		return nil, problem.ErrUnauthenticated
	}
	return sess, nil
}

// ByCookie resolves a browser session cookie.
func (s *Service) ByCookie(ctx context.Context, realmID, cookie string) (*Session, error) {
	if !secret.HasPrefix(cookie, secret.PrefixSession) || len(cookie) > 100 {
		return nil, problem.ErrNotFound
	}
	sess, err := scanSession(s.d.DB.Pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE realm_id=$1 AND cookie_digest=$2`, realmID, secret.Digest(cookie)))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if !sess.IsActive(s.d.Now()) {
		return nil, problem.ErrNotFound
	}
	return sess, nil
}

// TouchTx records meaningful activity, extending the idle window but never past the
// absolute bound (SES-002).
func (s *Service) TouchTx(ctx context.Context, q storage.Querier, sessionID string, idle time.Duration) error {
	now := s.d.Now()
	_, err := q.Exec(ctx, `UPDATE sessions SET last_activity_at=$2, idle_expires_at=LEAST($3::timestamptz, absolute_expires_at)
		WHERE id=$1 AND state='active'`, sessionID, now, now.Add(idle))
	return err
}

// TouchFromRefreshTx records activity seen through a refresh of one of the
// session's grants (SES-002, SES-006). The refresh family's idle window is
// its own (a client's token_policy.refresh_idle_seconds can make it shorter
// than the session's), so the session's idle expiry only ever moves later:
// a refresh never shortens the shared session's idle or absolute expiry.
func (s *Service) TouchFromRefreshTx(ctx context.Context, q storage.Querier, sessionID string, idle time.Duration) error {
	now := s.d.Now()
	_, err := q.Exec(ctx, `UPDATE sessions SET last_activity_at=$2,
		idle_expires_at=GREATEST(idle_expires_at, LEAST($3::timestamptz, absolute_expires_at))
		WHERE id=$1 AND state='active'`, sessionID, now, now.Add(idle))
	return err
}

// StepUpTx records newly completed factors on an existing session (AUT-010). Only
// genuinely completed factors update auth/MFA times (AUT-017).
func (s *Service) StepUpTx(ctx context.Context, tx pgx.Tx, sessionID string, newFactors []Factor, freshAuth bool) (*Session, error) {
	sess, err := scanSession(tx.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id=$1 FOR UPDATE`, sessionID))
	if err != nil {
		return nil, err
	}
	all := append(sess.Factors, newFactors...)
	amr, mfa := AMRFromFactors(all)
	if mfa == nil {
		mfa = sess.MFATime
	}
	authTime := sess.AuthTime
	if freshAuth {
		authTime = s.d.Now()
	}
	acr := ACRFor(all)
	if ACRRank(sess.ACR) > ACRRank(acr) {
		acr = sess.ACR
	}
	factors, _ := json.Marshal(all)
	recoveryRestricted := sess.RecoveryRestricted
	for _, f := range newFactors {
		if f.Type == "totp" || f.Type == "hotp" || f.Type == "hwk" || f.Type == "swk" {
			recoveryRestricted = false // assurance restored (MFA-010)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE sessions SET auth_time=$2, mfa_time=$3, amr=$4, acr=$5, factors=$6, recovery_restricted=$7,
		revision=revision+1 WHERE id=$1`, sessionID, authTime, mfa, amr, acr, factors, recoveryRestricted); err != nil {
		return nil, err
	}
	return s.Get(ctx, tx, sess.RealmID, sessionID)
}

// RotateCookieTx issues a new cookie handle for an existing session (AUT-007 after
// privilege changes).
func (s *Service) RotateCookieTx(ctx context.Context, tx pgx.Tx, sessionID string) (string, error) {
	cookie := secret.Token(secret.PrefixSession)
	_, err := tx.Exec(ctx, `UPDATE sessions SET cookie_digest=$2 WHERE id=$1`, sessionID, secret.Digest(cookie))
	return cookie, err
}

// RevokeTx revokes one session and everything derived from it: grants, refresh
// families and opaque tokens. Clients registered for back-channel logout receive a
// queued signed logout token (SES-004, SES-017).
func (s *Service) RevokeTx(ctx context.Context, tx pgx.Tx, realmID, sessionID, reason string) error {
	now := s.d.Now()
	var userID string
	err := tx.QueryRow(ctx, `UPDATE sessions SET state='revoked', revoked_at=$3, revoke_reason=$4, cookie_digest=NULL, revision=revision+1
		WHERE realm_id=$1 AND id=$2 AND state='active' RETURNING user_id`, realmID, sessionID, now, reason).Scan(&userID)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil // already inactive: idempotent
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason=$3
		WHERE state='active' AND grant_id IN (SELECT id FROM authorization_grants WHERE session_id=$1 AND NOT offline)`, sessionID, now, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$2, revoke_reason=$3
		WHERE session_id=$1 AND state='active' AND NOT offline`, sessionID, now, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE session_id=$1 AND revoked_at IS NULL`, sessionID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
		VALUES ($1,$2,'session',$3,$4,$5)`, ids.New(ids.Revocation), realmID, sessionID, reason, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE client_sessions SET state='logged_out' WHERE session_id=$1`, sessionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO logout_deliveries (id, realm_id, client_ref, session_id, user_id, next_attempt_at)
		SELECT 'lgd_' || substr(md5(random()::text || cs.id), 1, 26), $2, cs.client_ref, $1, $3, $4
		FROM client_sessions cs JOIN clients c ON c.id=cs.client_ref
		WHERE cs.session_id=$1 AND c.backchannel_logout_uri IS NOT NULL AND c.state='active'
		ON CONFLICT (client_ref, session_id) DO NOTHING`, sessionID, realmID, userID, now); err != nil {
		return err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "session.revoked", RealmID: realmID, Actor: audit.System,
		Subject: &audit.Ref{Type: "user", ID: userID}, SessionID: sessionID, ReasonCode: reason}); err != nil {
		return err
	}
	_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "session.revoked", RealmID: realmID, AggregateType: "user", AggregateID: userID,
		Data: map[string]any{"user_id": userID, "session_id": sessionID, "reason": reason}})
	return err
}

// RevokeUserTx revokes all of a user's sessions and (optionally) offline grants and
// support grants targeting or acting as the user (SES-005, §31.3).
func (s *Service) RevokeUserTx(ctx context.Context, tx pgx.Tx, realmID, userID, reason string, includeOffline bool) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM sessions WHERE realm_id=$1 AND user_id=$2 AND state='active' ORDER BY id`, realmID, userID)
	if err != nil {
		return 0, err
	}
	var list []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, id)
	}
	rows.Close()
	for _, id := range list {
		if err := s.RevokeTx(ctx, tx, realmID, id, reason); err != nil {
			return 0, err
		}
	}
	now := s.d.Now()
	if includeOffline {
		if _, err := tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$3, revoke_reason=$4
			WHERE state='active' AND grant_id IN (SELECT id FROM authorization_grants WHERE realm_id=$1 AND subject_type='user' AND subject_id=$2)`,
			realmID, userID, now, reason); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$3, revoke_reason=$4
			WHERE realm_id=$1 AND subject_type='user' AND subject_id=$2 AND state='active'`, realmID, userID, now, reason); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$3 WHERE realm_id=$1 AND subject_id=$2 AND revoked_at IS NULL`,
			realmID, userID, now); err != nil {
			return 0, err
		}
	}
	// Account-wide revocation also forgets remembered devices (AUT-013).
	if _, err := tx.Exec(ctx, `UPDATE remembered_devices SET revoked_at=$3 WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL`,
		realmID, userID, now); err != nil {
		return 0, err
	}
	// Support grants where the user is the actor or the target stop immediately (IMP-016, IMP-017).
	if _, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$3, revoked_by_type='system', revoke_reason=$4
		WHERE realm_id=$1 AND (actor_user_id=$2 OR target_user_id=$2) AND state='active'`, realmID, userID, now, reason); err != nil {
		return 0, err
	}
	if includeOffline {
		// Every token of the user issued until now is inactive, offline-grant
		// access tokens (no sid) included: introspection and UserInfo read
		// this record (UserTokenRevoked, SES-005). A revocation that keeps
		// offline grants records only its sessions, so it never ends them.
		if _, err := tx.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
			VALUES ($1,$2,'user',$3,$4,$5)`, ids.New(ids.Revocation), realmID, userID, reason, now); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET session_revision=session_revision+1 WHERE id=$1`, userID); err != nil {
		return 0, err
	}
	return len(list), nil
}

// ListForUser lists a user's active sessions (SES-003). Returned metadata is safe:
// no cookie digests or tokens.
func (s *Service) ListForUser(ctx context.Context, realmID, userID string) ([]*Session, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+sessionCols+` FROM sessions WHERE realm_id=$1 AND user_id=$2 AND state='active'
		AND absolute_expires_at > $3 AND idle_expires_at > $3 ORDER BY last_activity_at DESC LIMIT 200`, realmID, userID, s.d.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RecordClientSessionTx associates a session with a client (SES-015).
func (s *Service) RecordClientSessionTx(ctx context.Context, tx pgx.Tx, realmID, sessionID, clientRef string) error {
	_, err := tx.Exec(ctx, `INSERT INTO client_sessions (id, realm_id, session_id, client_ref) VALUES ($1,$2,$3,$4)
		ON CONFLICT (session_id, client_ref) DO UPDATE SET last_used_at=now(), state='active'`, ids.New(ids.ClientSession), realmID, sessionID, clientRef)
	return err
}

// ExpireSessions marks idle/absolute-expired sessions expired (retention, OPS-009).
func (s *Service) ExpireSessions(ctx context.Context) (int64, error) {
	now := s.d.Now()
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE sessions SET state='expired', cookie_digest=NULL WHERE state='active' AND
		(idle_expires_at <= $1 OR absolute_expires_at <= $1)`, now)
	return tag.RowsAffected(), err
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// networkContext minimizes the stored client address for long-lived session
// records: a /24 (IPv4) or /48 (IPv6) network unless the operator configured
// privacy.store_full_ip (PRV-002, SES-013). Short-lived authentication
// transactions keep the full address for abuse budgets only until they expire.
func (s *Service) networkContext(ip string) string {
	return reqctx.NetworkContext(ip, s.d.Cfg.Privacy.StoreFullIP)
}
