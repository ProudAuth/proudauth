package authentication

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/storage"
)

// Challenge purposes.
const (
	PurposeEmailVerification = "email_verification"
	PurposeLoginOTP          = "login_otp"
	PurposeMagicLink         = "magic_link"
	PurposePasswordReset     = "password_reset"
	PurposeIdentifierChange  = "identifier_change"
	PurposeAccountSetup      = "account_setup"
	PurposePhoneVerification = "phone_verification"
)

// ChallengeSpec describes a new challenge.
type ChallengeSpec struct {
	RealmID        string
	Purpose        string
	TransactionID  string
	UserID         string
	IdentifierType string
	Identifier     string // canonical
	Kind           string // code | link
	TTL            time.Duration
	MaxAttempts    int
	Metadata       map[string]any
}

// IssueChallengeTx creates a purpose-bound challenge and supersedes earlier open
// challenges with the same purpose and binding, so a replaced secret is invalid
// (INV-009, TEST-019). Only a keyed verifier is stored (PWDLESS-007).
func (s *Service) IssueChallengeTx(ctx context.Context, tx pgx.Tx, c ChallengeSpec) (id, plain string, err error) {
	if c.Kind == "" {
		c.Kind = "code"
	}
	if c.TTL == 0 {
		c.TTL = s.d.Cfg.Tokens.ChallengeTTL
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = s.d.Cfg.Security.OTPMaxAttempts
	}
	now := s.d.Now()
	var sendCount int
	_ = tx.QueryRow(ctx, `SELECT coalesce(max(send_count), 0) FROM challenges WHERE realm_id=$1 AND purpose=$2
		AND coalesce(transaction_id,'')=$3 AND coalesce(user_id,'')=$4 AND coalesce(identifier_canonical,'')=$5 AND created_at > $6`,
		c.RealmID, c.Purpose, c.TransactionID, c.UserID, c.Identifier, now.Add(-time.Hour)).Scan(&sendCount)
	if _, err := tx.Exec(ctx, `UPDATE challenges SET superseded_at=$6 WHERE realm_id=$1 AND purpose=$2 AND coalesce(transaction_id,'')=$3
		AND coalesce(user_id,'')=$4 AND coalesce(identifier_canonical,'')=$5 AND consumed_at IS NULL AND superseded_at IS NULL`,
		c.RealmID, c.Purpose, c.TransactionID, c.UserID, c.Identifier, now); err != nil {
		return "", "", err
	}
	id = ids.New(ids.Challenge)
	if c.Kind == "link" {
		// The challenge ID is embedded so the link resolves without scanning; the
		// random part carries the authority.
		plain = secret.PrefixLink + id + "." + secret.Token("")
	} else {
		plain = secret.Numeric(s.d.Cfg.Security.OTPLength)
	}
	verifier, ver := s.d.Keys.MAC(keys.PurposeOTP, "challenge", id, c.Purpose, plain)
	meta, _ := json.Marshal(nonNilMap(c.Metadata))
	_, err = tx.Exec(ctx, `INSERT INTO challenges (id, realm_id, purpose, transaction_id, user_id, identifier_type, identifier_canonical, verifier,
		key_version, secret_kind, max_attempts, send_count, metadata, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		id, c.RealmID, c.Purpose, nilIfEmpty(c.TransactionID), nilIfEmpty(c.UserID), nilIfEmpty(c.IdentifierType), nilIfEmpty(c.Identifier),
		verifier, ver, c.Kind, c.MaxAttempts, sendCount+1, meta, now.Add(c.TTL), now)
	return id, plain, err
}

// ConsumedChallenge describes a successfully consumed challenge.
type ConsumedChallenge struct {
	ID             string
	Purpose        string
	TransactionID  string
	UserID         string
	IdentifierType string
	Identifier     string
	Metadata       map[string]any
}

// ConsumeChallengeTx verifies and consumes a challenge atomically. Attempts are
// counted before comparison so concurrent guesses cannot exceed the budget
// (MFA-002, TEST-021); success sets consumed_at exactly once (DB-005).
func (s *Service) ConsumeChallengeTx(ctx context.Context, tx pgx.Tx, realmID, id, purpose, plain string) (*ConsumedChallenge, error) {
	if !ids.Valid(id) || plain == "" || len(plain) > 128 {
		return nil, errProof(problem.ErrInvalidProof)
	}
	var c ConsumedChallenge
	var verifier string
	var keyVersion, attempts, maxAttempts int
	var txID, userID, idType, ident *string
	var meta []byte
	err := tx.QueryRow(ctx, `UPDATE challenges SET attempts=attempts+1 WHERE realm_id=$1 AND id=$2 AND purpose=$3 AND consumed_at IS NULL
		AND superseded_at IS NULL AND expires_at > $4 AND attempts < max_attempts
		RETURNING id, purpose, transaction_id, user_id, identifier_type, identifier_canonical, verifier, key_version, attempts, max_attempts, metadata`,
		realmID, id, purpose, s.d.Now()).Scan(&c.ID, &c.Purpose, &txID, &userID, &idType, &ident, &verifier, &keyVersion, &attempts, &maxAttempts, &meta)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, errProof(problem.ErrInvalidProof)
		}
		return nil, err
	}
	if !s.d.Keys.VerifyMAC(keys.PurposeOTP, keyVersion, verifier, "challenge", id, purpose, plain) {
		return nil, errProof(problem.ErrInvalidProof)
	}
	tag, err := tx.Exec(ctx, `UPDATE challenges SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`, id, s.d.Now())
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errProof(problem.ErrInvalidProof)
	}
	c.TransactionID, c.UserID, c.IdentifierType, c.Identifier = deref(txID), deref(userID), deref(idType), deref(ident)
	_ = json.Unmarshal(meta, &c.Metadata)
	return &c, nil
}

// ConsumeLinkTx consumes a high-entropy link secret (magic, setup or reset links).
func (s *Service) ConsumeLinkTx(ctx context.Context, tx pgx.Tx, realmID, purpose, plain string) (*ConsumedChallenge, error) {
	if !secret.HasPrefix(plain, secret.PrefixLink) || len(plain) > 160 {
		return nil, errProof(problem.ErrInvalidProof)
	}
	rest := strings.TrimPrefix(plain, secret.PrefixLink)
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return nil, errProof(problem.ErrInvalidProof)
	}
	return s.ConsumeChallengeTx(ctx, tx, realmID, rest[:dot], purpose, plain)
}

// sendBudget applies cooldown and aggregate send budgets per identifier and network
// (REG-012, PWDLESS-004). Resend limits never reset the aggregate budget.
//
// clientRef and orgID, when known, add per-client and per-organization budgets;
// a realm-wide budget always applies (SEC-006).
//
// The cooldown is checked on its own first: it paces resends by legitimate
// users rather than signalling abuse, so a resend it refuses consumes nothing
// but the cooldown. The aggregate budgets are then counted together, each of
// them consumed even when another one is exhausted.
func (s *Service) sendBudget(ctx context.Context, realmID, identifier, ip string, clientOrg ...string) error {
	rl := s.d.Cfg.Security.RateLimits
	d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "send-cooldown:" + realmID + ":" + identifier, Limit: 1, Window: rl.SendCooldown})
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	budgets := []ratelimit.Budget{
		{Key: "send-id:" + realmID + ":" + identifier, Limit: rl.SendPerIdentifier, Window: rl.SendWindow},
		{Key: "send-ip:" + realmID + ":" + ip, Limit: rl.SendPerIP, Window: rl.SendWindow},
		{Key: "send-realm:" + realmID, Limit: rl.SendPerRealm, Window: rl.SendWindow},
	}
	if len(clientOrg) > 0 && clientOrg[0] != "" {
		budgets = append(budgets, ratelimit.Budget{Key: "send-client:" + clientOrg[0], Limit: rl.SendPerClient, Window: rl.SendWindow})
	}
	if len(clientOrg) > 1 && clientOrg[1] != "" {
		budgets = append(budgets, ratelimit.Budget{Key: "send-org:" + clientOrg[1], Limit: rl.SendPerOrganization, Window: rl.SendWindow})
	}
	d, err = s.Limiter.Hit(ctx, budgets...)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}

// verifyBudget bounds proof attempts per account across transactions and networks
// (TEST-021). It is time-windowed so it cannot cause a permanent lockout.
//
// clientOrg names the client and organization when known: their budgets and
// a realm-wide one apply too, so one integration or tenant cannot exhaust
// the realm's verification capacity (REG-012, SEC-006).
func (s *Service) verifyBudget(ctx context.Context, realmID, subject, ip string, clientOrg ...string) error {
	rl := s.d.Cfg.Security.RateLimits
	budgets := []ratelimit.Budget{
		{Key: "verify-subject:" + realmID + ":" + subject, Limit: rl.OTPVerifyPerAccount, Window: rl.OTPVerifyWindow},
		{Key: "verify-ip:" + realmID + ":" + ip, Limit: rl.LoginPerIP, Window: rl.LoginWindow},
	}
	if rl.LoginPerRealm > 0 {
		budgets = append(budgets, ratelimit.Budget{Key: "verify-realm:" + realmID, Limit: rl.LoginPerRealm, Window: rl.LoginWindow})
	}
	if len(clientOrg) > 0 && clientOrg[0] != "" && rl.LoginPerClient > 0 {
		budgets = append(budgets, ratelimit.Budget{Key: "verify-client:" + clientOrg[0], Limit: rl.LoginPerClient, Window: rl.LoginWindow})
	}
	if len(clientOrg) > 1 && clientOrg[1] != "" && rl.LoginPerOrganization > 0 {
		budgets = append(budgets, ratelimit.Budget{Key: "verify-org:" + clientOrg[1], Limit: rl.LoginPerOrganization, Window: rl.LoginWindow})
	}
	d, err := s.Limiter.Hit(ctx, budgets...)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}

// CleanupChallenges removes expired and consumed challenges (REG-011, OPS-009).
func (s *Service) CleanupChallenges(ctx context.Context) (int64, error) {
	now := s.d.Now()
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM challenges WHERE expires_at < $1`, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	n := tag.RowsAffected()
	tag, err = s.d.DB.Pool.Exec(ctx, `UPDATE auth_transactions SET status='expired' WHERE status='pending' AND expires_at < $1`, now)
	if err == nil {
		n += tag.RowsAffected()
	}
	if !s.d.Cfg.Privacy.StoreFullIP {
		// Finished transactions no longer need the full address or user agent
		// for abuse budgets; they are dropped at once rather than kept for the
		// day before the row goes (PRV-002).
		if tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE auth_transactions SET client_ip=NULL, user_agent=NULL
			WHERE status <> 'pending' AND (client_ip IS NOT NULL OR user_agent IS NOT NULL)`); err == nil {
			n += tag.RowsAffected()
		}
	}
	tag, err = s.d.DB.Pool.Exec(ctx, `DELETE FROM auth_transactions WHERE status <> 'pending' AND updated_at < $1
		AND NOT EXISTS (SELECT 1 FROM authorization_codes c WHERE c.transaction_id=auth_transactions.id)`, now.Add(-24*time.Hour))
	if err == nil {
		n += tag.RowsAffected()
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE credentials SET state='revoked' WHERE state='pending' AND expires_at < $1`, now)
	return n, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
