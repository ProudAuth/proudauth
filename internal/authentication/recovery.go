package authentication

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/session"
)

// ResetRequested is the enumeration-resistant public response (SEC-005, §27.6). A
// reset ID is returned for every request; for unknown accounts it refers to nothing.
type ResetRequested struct {
	ResetID   string    `json:"reset_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Message   string    `json:"message"`
}

// RequestPasswordReset sends a short-lived, purpose-bound code to a verified email.
func (s *Service) RequestPasswordReset(ctx context.Context, realmID, identifier, ip, locale string) (*ResetRequested, error) {
	start := time.Now()
	defer padTiming(start, s.d.Cfg.Security.MinAuthResponse)
	typ, canon, ok := identity.CanonicalizeLogin(identifier)
	resp := &ResetRequested{ResetID: ids.New(ids.Challenge), ExpiresAt: s.d.Now().Add(s.d.Cfg.Tokens.ChallengeTTL),
		Message: "If an account matches, a reset code was sent to its verified email address."}
	if !ok {
		return resp, nil
	}
	if err := s.sendBudget(ctx, realmID, canon, ip); err != nil {
		return nil, err
	}
	u, err := s.Users.FindByLogin(ctx, realmID, typ, canon)
	if err != nil || u.State == identity.StateDeleted || u.State == identity.StateSuspended || u.State == identity.StatePendingDeletion {
		return resp, nil
	}
	email := u.PrimaryEmail()
	if email == nil || !email.Verified() {
		return resp, nil
	}
	rlm, err := s.Realms.ByID(ctx, nil, realmID)
	if err != nil {
		return nil, err
	}
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		id, code, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: realmID, Purpose: PurposePasswordReset, UserID: u.ID,
			IdentifierType: "email", Identifier: email.Canonical})
		if err != nil {
			return err
		}
		resp.ResetID = id
		if _, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, Template: notification.TplPasswordReset, Locale: locale,
			Recipient: email.Value, Mandatory: true, ReferenceType: "challenge", ReferenceID: id, TTL: s.d.Cfg.Tokens.ChallengeTTL, UserID: u.ID,
			Data: map[string]string{"code": code, "realm": rlm.DisplayName, "expires_minutes": minutes(s.d.Cfg.Tokens.ChallengeTTL)}}); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.password_reset.requested", RealmID: realmID,
			Actor: audit.Ref{Type: "anonymous", ID: "public"}, Subject: &audit.Ref{Type: "user", ID: u.ID}})
		return err
	})
	return resp, err
}

// CompletePasswordReset consumes the proof atomically and replaces the password. It
// never removes MFA requirements (CRED-007, TEST-070) and revokes sessions per the
// documented rule (all sessions and grants are revoked).
func (s *Service) CompletePasswordReset(ctx context.Context, realmID, resetID, code, newPassword, ip string) error {
	var proofErr error
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		proofErr = nil
		if !ids.Valid(resetID) {
			proofErr = problem.ErrInvalidProof
			return nil
		}
		var userID string
		_ = tx.QueryRow(ctx, `SELECT coalesce(user_id,'') FROM challenges WHERE id=$1 AND realm_id=$2`, resetID, realmID).Scan(&userID)
		if err := s.verifyBudget(ctx, realmID, "reset:"+resetID+userID, requester{ip: ip}); err != nil {
			return err
		}
		c, err := s.ConsumeChallengeTx(ctx, tx, realmID, resetID, PurposePasswordReset, strings.TrimSpace(code))
		if err != nil {
			proofErr = problem.ErrInvalidProof
			return nil // commit the attempt counter
		}
		// An email-verified recovery turns code factors back on (owner
		// decision 10, SEC-006). Before the account row is locked, in the
		// order sign-in steps take these locks.
		if err := s.resetCodeFactorFailures(ctx, tx, realmID, c.UserID, "password_reset", audit.Ref{Type: "user", ID: c.UserID}); err != nil {
			return err
		}
		u, err := s.Users.LockUser(ctx, tx, realmID, c.UserID)
		if err != nil {
			return err
		}
		rlm, err := s.Realms.ByID(ctx, tx, realmID)
		if err != nil {
			return err
		}
		words := []string{u.Username()}
		if e := u.PrimaryEmail(); e != nil {
			words = append(words, e.Value, strings.Split(e.Value, "@")[0])
		}
		if err := s.SetPasswordTx(ctx, tx, realmID, u.ID, newPassword, rlm.Policy.Password.MinLength, rlm.Policy.Password.HistoryCount, words...); err != nil {
			return err
		}
		if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, u.ID, session.ReasonPasswordReset, true); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.password_reset.completed", RealmID: realmID,
			Actor: audit.Ref{Type: "user", ID: u.ID}, Subject: &audit.Ref{Type: "user", ID: u.ID}}); err != nil {
			return err
		}
		if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "user.password_reset", RealmID: realmID, AggregateType: "user",
			AggregateID: u.ID, Data: map[string]any{"user_id": u.ID}}); err != nil {
			return err
		}
		if err := s.notifySecurity(ctx, tx, realmID, u.ID, notification.TplPasswordChanged, "password reset"); err != nil {
			return err
		}
		// Personal access tokens minted by whoever knew the old password end
		// with it (CRED-008, MCH-007).
		return s.revokeUserCredentialsTx(ctx, tx, realmID, u.ID, session.ReasonPasswordReset, audit.Ref{Type: "user", ID: u.ID},
			"a password reset")
	})
	if err != nil {
		if problem.Is(err, problem.ErrPasswordPolicy) {
			return err
		}
		return err
	}
	return proofErr
}

// SetupToken is a one-time account-setup authority (admin-created accounts and the
// initial administrator, DEP-007).
type SetupToken struct {
	Token     string    `json:"setup_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueAccountSetupTx creates a single-use setup link secret. When deliver is true
// it is emailed (proving control of the address on use); otherwise it is returned
// to an operator channel only.
func (s *Service) IssueAccountSetupTx(ctx context.Context, tx pgx.Tx, realmID, userID string, ttl time.Duration, deliver bool, realmName string) (*SetupToken, error) {
	var email, display string
	// The same address as identity.User.PrimaryEmail, which assisted recovery
	// checks is verified before it calls this.
	_ = tx.QueryRow(ctx, `SELECT canonical_value, original_value FROM user_identifiers WHERE user_id=$1 AND type='email'
		ORDER BY is_primary DESC, created_at, id LIMIT 1`, userID).Scan(&email, &display)
	_, plain, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: realmID, Purpose: PurposeAccountSetup, UserID: userID,
		IdentifierType: "email", Identifier: email, Kind: "link", TTL: ttl, MaxAttempts: 3,
		Metadata: map[string]any{"delivered_by_email": deliver}})
	if err != nil {
		return nil, err
	}
	if deliver && display != "" {
		if _, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, Template: notification.TplAccountSetup, Recipient: display,
			Mandatory: true, ReferenceType: "user", ReferenceID: userID, TTL: ttl,
			Data: map[string]string{"code": plain, "realm": realmName, "expires_hours": fmt.Sprint(int(ttl.Hours()))}}); err != nil {
			return nil, err
		}
	}
	return &SetupToken{Token: plain, ExpiresAt: s.d.Now().Add(ttl)}, nil
}

// CompleteAccountSetup sets the first password using a setup token. Email delivery
// of the token proves control of the address, so the email becomes verified;
// operator-printed bootstrap tokens do not verify email.
func (s *Service) CompleteAccountSetup(ctx context.Context, realmID, token, password, ip string) error {
	var proofErr error
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		proofErr = nil
		rl := s.d.Cfg.Security.RateLimits
		d, err := s.Limiter.Hit(ctx, ratelimit.PerNetwork("setup-ip:"+realmID+":", ip, rl.LoginPerIP, time.Hour, rl.NetworkCoarseFactor)...)
		if err != nil {
			return err
		}
		if !d.Allowed {
			return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		c, err := s.ConsumeLinkTx(ctx, tx, realmID, PurposeAccountSetup, strings.TrimSpace(token))
		if err != nil {
			proofErr = problem.ErrInvalidProof
			return nil
		}
		u, err := s.Users.LockUser(ctx, tx, realmID, c.UserID)
		if err != nil {
			return err
		}
		if u.State != identity.StateActive && u.State != identity.StatePendingVerification {
			return problem.ErrAccountState
		}
		rlm, err := s.Realms.ByID(ctx, tx, realmID)
		if err != nil {
			return err
		}
		words := []string{u.Username()}
		if e := u.PrimaryEmail(); e != nil {
			words = append(words, e.Value, strings.Split(e.Value, "@")[0])
		}
		if err := s.SetPasswordTx(ctx, tx, realmID, u.ID, password, rlm.Policy.Password.MinLength, 0, words...); err != nil {
			return err
		}
		if delivered, _ := c.Metadata["delivered_by_email"].(bool); delivered && c.Identifier != "" {
			if err := s.Users.MarkIdentifierVerifiedTx(ctx, tx, realmID, u.ID, "email", c.Identifier, "setup_link"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET state='active', required_actions=array_remove(required_actions,'verify_email') WHERE id=$1 AND state='pending_verification'`, u.ID); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "account.setup.completed", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: u.ID},
			Subject: &audit.Ref{Type: "user", ID: u.ID}}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return proofErr
}

// ChangePassword changes a password for an authenticated user with recent
// authentication (CRED-006). Other sessions are revoked per policy; the current
// session survives so the user is not logged out of the device they used.
func (s *Service) ChangePassword(ctx context.Context, realmID, userID, currentSessionID, currentPassword, newPassword string) error {
	// One hashing slot covers the current-password check and the new
	// verifier; a full bound refuses before the transaction opens (NFR-002).
	ctx, release, err := s.hashSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	if ctx, err = s.directoryOnce(ctx, realmID); err != nil {
		return err
	}
	// The current password is checked under the account's sign-in failure
	// lock (owner decision 10, SEC-006): a wrong one counts against the same
	// budget a wrong sign-in password does, and while it is spent the
	// password is not checked here either, so a recently authenticated
	// session cannot guess the current password without bound.
	rl := s.d.Cfg.Security.RateLimits
	lockOn := rl.FailuresBeforeLock > 0 && rl.TemporaryLock > 0
	lock := ratelimit.Budget{Key: "pwd-fail:" + realmID + ":user:" + userID, Limit: rl.FailuresBeforeLock, Window: rl.TemporaryLock}
	var failure error
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		failure = nil
		u, err := s.Users.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		rlm, err := s.Realms.ByID(ctx, tx, realmID)
		if err != nil {
			return err
		}
		// Factor policy (CRED-006): an account with MFA enrolled changes its
		// password only from a session that completed MFA, so a stolen password
		// plus a single-factor session cannot replace the credential. A code
		// factor the realm does not allow satisfies nothing (MFA-005) and does
		// not count as enrolled.
		var hasMFA, sessionMFA bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM credentials WHERE user_id=$1 AND type = ANY($2) AND state='active')
			OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=$1 AND state='active')`, userID, rlm.Policy.MFA.CodeFactors()).Scan(&hasMFA); err != nil {
			return err
		}
		if hasMFA {
			_ = tx.QueryRow(ctx, `SELECT mfa_time IS NOT NULL FROM sessions WHERE id=$1 AND user_id=$2 AND state='active'`, currentSessionID, userID).Scan(&sessionMFA)
			if !sessionMFA {
				return problem.ErrStepUpRequired.WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "required_profile": "mfa"}})
			}
		}
		if lockOn {
			allowed, err := s.Limiter.Peek(ctx, lock)
			if err != nil {
				return err
			}
			if !allowed {
				if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.change_failed", RealmID: realmID,
					Actor: audit.Ref{Type: "user", ID: userID, SessionID: currentSessionID}, Subject: &audit.Ref{Type: "user", ID: userID},
					Outcome: audit.Denied, ReasonCode: "TEMPORARY_LOCK"}); err != nil {
					return err
				}
				failure = problem.ErrRateLimited.WithRetryAfter(rl.TemporaryLock)
				return nil // commit the evidence
			}
		}
		ok, err := s.VerifyPassword(ctx, tx, userID, currentPassword)
		if err != nil {
			return err
		}
		if !ok {
			if lockOn {
				_, _ = s.Limiter.Hit(ctx, lock)
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.change_failed", RealmID: realmID,
				Actor: audit.Ref{Type: "user", ID: userID, SessionID: currentSessionID}, Subject: &audit.Ref{Type: "user", ID: userID},
				Outcome: audit.Failure, ReasonCode: "INVALID_CREDENTIALS"}); err != nil {
				return err
			}
			failure = problem.ErrInvalidCredentials
			return nil // commit the evidence
		}
		words := []string{u.Username()}
		if e := u.PrimaryEmail(); e != nil {
			words = append(words, e.Value, strings.Split(e.Value, "@")[0])
		}
		if err := s.SetPasswordTx(ctx, tx, realmID, userID, newPassword, rlm.Policy.Password.MinLength, rlm.Policy.Password.HistoryCount, words...); err != nil {
			return err
		}
		if rlm.Policy.Password.RevokeSessionsOnChange {
			rows, err := tx.Query(ctx, `SELECT id FROM sessions WHERE user_id=$1 AND state='active' AND id <> $2`, userID, currentSessionID)
			if err != nil {
				return err
			}
			var others []string
			for rows.Next() {
				var id string
				_ = rows.Scan(&id)
				others = append(others, id)
			}
			rows.Close()
			for _, id := range others {
				if err := s.Sessions.RevokeTx(ctx, tx, realmID, id, "password_changed"); err != nil {
					return err
				}
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.changed", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID, SessionID: currentSessionID},
			Subject: &audit.Ref{Type: "user", ID: userID}}); err != nil {
			return err
		}
		return s.notifySecurity(ctx, tx, realmID, userID, notification.TplPasswordChanged, "password changed")
	})
	if err != nil {
		return err
	}
	return failure
}

// IdentifierChallenge starts proof of a new identifier for an authenticated user
// (USR-004). The identifier stays unverified until the proof is consumed.
// clientOrg names the requesting client (and organization, when the token is
// bound to one): the send counts against their budgets like every other code
// send (REG-012).
func (s *Service) IdentifierChallenge(ctx context.Context, realmID, userID, identifierID, ip string, clientOrg ...string) (string, error) {
	var cid string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var typ, canon, display string
		var verified *time.Time
		if err := tx.QueryRow(ctx, `SELECT type, canonical_value, original_value, verified_at FROM user_identifiers WHERE user_id=$1 AND id=$2`,
			userID, identifierID).Scan(&typ, &canon, &display, &verified); err != nil {
			return problem.ErrNotFound
		}
		if verified != nil {
			return problem.ErrConflict.WithDetail("already verified")
		}
		if typ != "email" && typ != "phone" {
			return problem.ErrValidation.WithDetail("only email and phone identifiers need verification")
		}
		if err := s.sendBudget(ctx, realmID, canon, ip, clientOrg...); err != nil {
			return err
		}
		purpose := PurposeIdentifierChange
		id, code, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: realmID, Purpose: purpose, UserID: userID, IdentifierType: typ, Identifier: canon})
		if err != nil {
			return err
		}
		cid = id
		rlm, err := s.Realms.ByID(ctx, tx, realmID)
		if err != nil {
			return err
		}
		channel := "email"
		if typ == "phone" {
			channel = "sms"
		}
		_, err = s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, Channel: channel, Template: notification.TplEmailVerification,
			Recipient: display, Mandatory: true, ReferenceType: "challenge", ReferenceID: id, TTL: s.d.Cfg.Tokens.ChallengeTTL, UserID: userID,
			Data: map[string]string{"code": code, "realm": rlm.DisplayName, "expires_minutes": minutes(s.d.Cfg.Tokens.ChallengeTTL)}})
		return err
	})
	return cid, err
}

// ConsumeIdentifierChallenge completes identifier verification and notifies the
// previous primary contact when it exists (USR-004).
func (s *Service) ConsumeIdentifierChallenge(ctx context.Context, realmID, userID, challengeID, code, ip string) error {
	var proofErr error
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		proofErr = nil
		if err := s.verifyBudget(ctx, realmID, userID, requester{ip: ip}); err != nil {
			return err
		}
		c, err := s.ConsumeChallengeTx(ctx, tx, realmID, challengeID, PurposeIdentifierChange, strings.TrimSpace(code))
		if err != nil || c.UserID != userID {
			proofErr = problem.ErrInvalidProof
			return nil
		}
		if err := s.Users.MarkIdentifierVerifiedTx(ctx, tx, realmID, userID, c.IdentifierType, c.Identifier, "challenge"); err != nil {
			return err
		}
		if err := s.completeGuestUpgradeTx(ctx, tx, realmID, userID); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.identifier.verified", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"identifier_type": c.IdentifierType}}); err != nil {
			return err
		}
		return s.notifySecurity(ctx, tx, realmID, userID, notification.TplIdentifierChanged, "a new "+c.IdentifierType+" was verified")
	})
	if err != nil {
		return err
	}
	return proofErr
}
