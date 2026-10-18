package authentication

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// Consecutive code-factor failures (owner decision 10 of 0.2.0-alpha.6;
// SEC-006, MFA-002, MFA-012, TEST-021).
//
// Code factors are TOTP, HOTP, recovery codes and emailed or texted sign-in
// codes: secrets short enough to guess. The proof budgets (verifyBudget)
// bound guesses per fixed window but let them resume in every new one, about
// 960 a day per account. second_factor_failures keeps one count per account
// across windows:
//
//   - each failed proof adds one, in the step's transaction, so it commits
//     with the transaction's own failure count and audit;
//   - from security.second_factor.failure_backoff_after on, a TOTP, HOTP or
//     recovery-code proof waits 2 s after the last failure, doubling with
//     each further failure up to failure_backoff_max (429 rate_limited with
//     Retry-After, before the proof budgets are counted);
//   - at failure_notice_at the owner receives one mandatory notice
//     (second_factor_failures), recorded as mfa.code_factors.failure_notice;
//   - at failure_disable_at the account's code factors are turned off
//     (403 code_factors_disabled, mfa.code_factors.disabled), and sign-in
//     codes are no longer sent.
//
// Passkeys never count and are never blocked. A successful TOTP, HOTP,
// recovery-code or passkey proof, a completed sign-in, a password reset and an
// assisted recovery reset the count: whoever can prove the account gets back
// in, so an attacker cannot lock the owner out for good (SEC-006). A
// password alone never resets it, and neither does an emailed or texted code
// on its own: only the sign-in it completes does.
//
// Emailed and texted sign-in codes prove a primary factor before the account
// is known to the client, so they get neither the backoff nor a distinct
// refusal: once code factors are off, no code is sent and every code is
// refused with invalid_proof, exactly as for an address without an account
// (SEC-005, API-009).

// codeFactorFailures is an account's count; zero when it has no row.
type codeFactorFailures struct {
	consecutive int
	lastFailure *time.Time
}

// loadCodeFactorFailures reads the account's count; lock takes its row
// lock (when it has one) until the caller's transaction ends.
func (s *Service) loadCodeFactorFailures(ctx context.Context, q storage.Querier, userID string, lock bool) (codeFactorFailures, error) {
	query := `SELECT consecutive, last_failure_at FROM second_factor_failures WHERE user_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var f codeFactorFailures
	err := q.QueryRow(ctx, query, userID).Scan(&f.consecutive, &f.lastFailure)
	if storage.IsNoRows(err) {
		return codeFactorFailures{}, nil
	}
	return f, err
}

// gateCodeFactor runs before a TOTP, HOTP or recovery-code proof of an
// identified account: 403 code_factors_disabled at the ceiling, 429 while the
// backoff since the last failure runs.
//
// It creates the account's row when missing and locks it, before the proof
// locks the factor's own row: concurrent proofs of one account then take
// their turn instead of sharing one backoff slot, and every path takes the
// count's row before the credential and account rows (a failure's update and
// the reset at completion only reuse it), so they cannot deadlock.
func (s *Service) gateCodeFactor(ctx context.Context, tx pgx.Tx, realmID, userID string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO second_factor_failures (user_id, realm_id, consecutive, updated_at) VALUES ($1,$2,0,$3)
		ON CONFLICT (user_id) DO NOTHING`, userID, realmID, s.d.Now()); err != nil {
		return err
	}
	f, err := s.loadCodeFactorFailures(ctx, tx, userID, true)
	if err != nil || f.consecutive == 0 || f.lastFailure == nil {
		return err
	}
	cfg := s.d.Cfg.Security.SecondFactor
	if cfg.CodeFactorsDisabled(f.consecutive) {
		return problem.ErrCodeFactorsDisabled
	}
	if wait := f.lastFailure.Add(cfg.BackoffDelay(f.consecutive)).Sub(s.d.Now()); wait > 0 {
		return problem.ErrRateLimited.WithRetryAfter(wait)
	}
	return nil
}

// codeFactorsDisabled reports whether the account's code factors are off.
func (s *Service) codeFactorsDisabled(ctx context.Context, q storage.Querier, userID string) (bool, error) {
	f, err := s.loadCodeFactorFailures(ctx, q, userID, false)
	return s.d.Cfg.Security.SecondFactor.CodeFactorsDisabled(f.consecutive), err
}

// codeFactorFailed counts a failed code-factor proof of the account in the
// caller's transaction, sends the owner's notice once the notice threshold is
// reached and records the disable once the ceiling is. factor names the
// proof for the audit (totp, hotp, recovery_code, email_code, sms_code).
func (s *Service) codeFactorFailed(ctx context.Context, tx pgx.Tx, realmID, userID, factor string) error {
	now := s.d.Now()
	var n int
	var notified, disabled bool
	if err := tx.QueryRow(ctx, `INSERT INTO second_factor_failures (user_id, realm_id, consecutive, last_failure_at, updated_at)
		VALUES ($1,$2,1,$3,$3)
		ON CONFLICT (user_id) DO UPDATE SET consecutive=second_factor_failures.consecutive+1, last_failure_at=$3, updated_at=$3
		RETURNING consecutive, notified_at IS NOT NULL, disabled_at IS NOT NULL`, userID, realmID, now).Scan(&n, &notified, &disabled); err != nil {
		return err
	}
	cfg := s.d.Cfg.Security.SecondFactor
	subject := &audit.Ref{Type: "user", ID: userID}
	if cfg.FailureNoticeAt > 0 && n >= cfg.FailureNoticeAt && !notified {
		if _, err := tx.Exec(ctx, `UPDATE second_factor_failures SET notified_at=$2 WHERE user_id=$1`, userID, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.code_factors.failure_notice", RealmID: realmID, Actor: audit.System,
			Subject: subject, Category: "security", Metadata: map[string]any{"consecutive_failures": n, "factor": factor}}); err != nil {
			return err
		}
		if err := s.notifySecurityWith(ctx, tx, realmID, userID, notification.TplSecondFactorFailures,
			map[string]string{"count": strconv.Itoa(n)}); err != nil {
			return err
		}
	}
	if cfg.CodeFactorsDisabled(n) && !disabled {
		if _, err := tx.Exec(ctx, `UPDATE second_factor_failures SET disabled_at=$2 WHERE user_id=$1`, userID, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.code_factors.disabled", RealmID: realmID, Actor: audit.System,
			Subject: subject, Category: "security", Outcome: audit.Denied, ReasonCode: "CONSECUTIVE_FAILURES",
			Metadata: map[string]any{"consecutive_failures": n, "factor": factor}}); err != nil {
			return err
		}
	}
	return nil
}

// resetCodeFactorFailures sets the account's count back to zero after
// something proved the account: cause names it for the audit (totp, hotp,
// recovery_code, passkey, sign_in, password_reset, assisted_recovery). A reset
// that turns code factors back on is recorded as mfa.code_factors.restored.
func (s *Service) resetCodeFactorFailures(ctx context.Context, tx pgx.Tx, realmID, userID, cause string, actor audit.Ref) error {
	var n int
	var wasDisabled bool
	err := tx.QueryRow(ctx, `WITH old AS (SELECT user_id, consecutive, disabled_at IS NOT NULL AS disabled FROM second_factor_failures
			WHERE user_id=$1 AND consecutive > 0 FOR UPDATE)
		UPDATE second_factor_failures f SET consecutive=0, notified_at=NULL, disabled_at=NULL, updated_at=$2 FROM old
		WHERE f.user_id=old.user_id RETURNING old.consecutive, old.disabled`, userID, s.d.Now()).Scan(&n, &wasDisabled)
	if storage.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !wasDisabled && !s.d.Cfg.Security.SecondFactor.CodeFactorsDisabled(n) {
		return nil
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.code_factors.restored", RealmID: realmID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: userID}, Category: "security", Metadata: map[string]any{"consecutive_failures": n, "cause": cause}})
	return err
}

// SecondFactorFailures is an account's consecutive code-factor failure state,
// for administrators (GET /users/{user}).
type SecondFactorFailures struct {
	Consecutive   int        `json:"consecutive"`
	LastFailureAt *time.Time `json:"last_failure_at"`
	NotifiedAt    *time.Time `json:"notified_at"`
	DisabledAt    *time.Time `json:"disabled_at"`
	// BackoffUntil is when the next TOTP, HOTP or recovery-code proof may
	// be made, while the backoff runs.
	BackoffUntil *time.Time `json:"backoff_until"`
	// CodeFactorsDisabled: TOTP, HOTP, recovery codes and sign-in codes are
	// refused until a passkey sign-in, a password reset or an assisted
	// recovery.
	CodeFactorsDisabled bool `json:"code_factors_disabled"`
}

// SecondFactorFailureState returns the account's state; a zero count when it
// never failed or was reset since.
func (s *Service) SecondFactorFailureState(ctx context.Context, realmID, userID string) (*SecondFactorFailures, error) {
	out := &SecondFactorFailures{}
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT consecutive, last_failure_at, notified_at, disabled_at FROM second_factor_failures
		WHERE realm_id=$1 AND user_id=$2`, realmID, userID).Scan(&out.Consecutive, &out.LastFailureAt, &out.NotifiedAt, &out.DisabledAt)
	if storage.IsNoRows(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if out.Consecutive == 0 || out.LastFailureAt == nil {
		return out, nil // never failed, or reset since: the last failure is history only
	}
	cfg := s.d.Cfg.Security.SecondFactor
	out.CodeFactorsDisabled = cfg.CodeFactorsDisabled(out.Consecutive)
	if until := out.LastFailureAt.Add(cfg.BackoffDelay(out.Consecutive)); !out.CodeFactorsDisabled && until.After(s.d.Now()) {
		out.BackoffUntil = &until
	}
	return out, nil
}
