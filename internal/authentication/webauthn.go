package authentication

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/passkey"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/ratelimit"
)

// passkeyErr converts a failed passkey proof into a counted proof failure whose
// audit evidence commits with the transaction (MFA-012).
func passkeyErr(err error) error {
	if passkey.IsProofFailure(err) {
		var r interface{ Unwrap() error }
		if errors.As(err, &r) {
			return errProof(r.Unwrap())
		}
		return errProof(err)
	}
	return err
}

// WebAuthnOptions begins a passkey authentication ceremony for the transaction
// (PASS-002, PASS-003). Before primary authentication it is a sign-in ceremony:
// username-less when nothing was identified, otherwise bound to the identified
// account (or a decoy for unknown identifiers). After primary authentication it is
// a second-factor ceremony for the authenticated user.
func (s *Service) WebAuthnOptions(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	if s.Passkeys == nil {
		return nil, problem.ErrFeatureDisabled
	}
	var opts *passkey.AssertionOptions
	st, err := s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if err := s.loginBudgetIP(ctx, t); err != nil {
			return nil, err
		}
		if primaryDone(t) {
			r, err := s.evaluate(ctx, tx, t)
			if err != nil {
				return nil, err
			}
			// A passkey answers an MFA prompt or a flow challenge, or gives
			// the upgrade proof under the phishing-resistant profile.
			if !(r.mfaRequired && !r.mfaDone || r.challenge) || !r.hasPasskey || !r.passkeysEnabled {
				return nil, problem.ErrUnexpectedStep
			}
			if err := s.offered(ctx, tx, t, "webauthn"); err != nil {
				return nil, err
			}
			// An upgrade proof is a passkey never used with user
			// verification: the ceremony asks for it without requiring it,
			// and a verified answer meets the profile at once.
			opts, err = s.Passkeys.BeginLogin(ctx, tx, rlm, t.ID, t.UserID, "", r.phishingResistant && !r.upgrade)
			return nil, err
		}
		if !rlm.Policy.Login.Passkeys {
			return nil, problem.ErrUnexpectedStep
		}
		userID := ""
		if t.Pending.Identifier != "" {
			if u, err := s.Users.FindByLogin(ctx, t.RealmID, t.Pending.IdentifierType, t.Pending.Identifier); err == nil {
				userID = u.ID
			}
		}
		requireUV := slices.ContainsFunc(t.ACRValues, func(a string) bool { return strings.Contains(a, "phishing_resistant") })
		opts, err = s.Passkeys.BeginLogin(ctx, tx, rlm, t.ID, userID, t.Pending.Identifier, requireUV)
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	st.WebAuthn = opts
	return st, nil
}

// WebAuthnVerify completes the open authentication ceremony with the client's
// PublicKeyCredential JSON.
func (s *Service) WebAuthnVerify(ctx context.Context, realmID, id string, p Proof, response []byte) (*State, error) {
	if s.Passkeys == nil {
		return nil, problem.ErrFeatureDisabled
	}
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		subject := t.UserID
		if subject == "" {
			subject = "tx:" + t.ID
		}
		if err := s.verifyBudget(ctx, t.RealmID, subject, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		second := primaryDone(t)
		expected := ""
		upgrade := false
		if second {
			expected = t.UserID
			r, err := s.evaluate(ctx, tx, t)
			if err != nil {
				return nil, err
			}
			if err := s.offered(ctx, tx, t, "webauthn"); err != nil {
				return nil, err
			}
			upgrade = r.upgrade
		}
		actor := audit.Ref{Type: "anonymous", ID: "transaction:" + t.ID}
		if t.UserID != "" {
			actor = audit.Ref{Type: "user", ID: t.UserID}
		}
		userID, f, err := s.Passkeys.FinishLogin(ctx, tx, rlm, t.ID, expected, response, actor)
		if err != nil {
			return nil, passkeyErr(err)
		}
		if !second {
			// Primary sign-in with a passkey: the identified account (if any) must be
			// the credential owner, and the account must be usable.
			if t.Pending.Identifier != "" {
				if u, err := s.Users.FindByLogin(ctx, t.RealmID, t.Pending.IdentifierType, t.Pending.Identifier); err != nil || u.ID != userID {
					return nil, errProof(passkey.ErrCeremony)
				}
			}
			if t.UserID != "" && t.UserID != userID {
				return nil, problem.ErrTransactionInvalid
			}
			u, err := s.Users.User(ctx, tx, t.RealmID, userID)
			if err != nil {
				return nil, err
			}
			// Pending deletion continues to the cancel_deletion step (USR-012).
			if u.State == identity.StateSuspended || u.State == identity.StateDeleted || u.State == identity.StateLocked {
				_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.denied", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: u.ID},
					Subject: &audit.Ref{Type: "user", ID: u.ID}, Outcome: audit.Denied, ReasonCode: "ACCOUNT_" + strings.ToUpper(u.State)})
				return nil, errProof(problem.ErrInvalidCredentials)
			}
			t.UserID = userID
			t.IdentifiedVia = "webauthn"
			now := s.d.Now()
			t.AuthTime = &now
		}
		// A passkey is never counted or blocked by the code-factor ceiling,
		// and proving one resets it (owner decision 10, SEC-006).
		if err := s.resetCodeFactorFailures(ctx, tx, t.RealmID, t.UserID, "passkey", audit.Ref{Type: "user", ID: t.UserID}); err != nil {
			return nil, err
		}
		if upgrade && !f.UserVerified {
			// Proves the existing passkey but cannot meet the profile: it
			// unlocks registering a user-verified one (MFA-006, SEC-012).
			return nil, s.recordUpgradeProof(ctx, tx, t, "webauthn", f.CredentialID)
		}
		t.Factors = append(t.Factors, f)
		return nil, nil
	})
}

// WebAuthnRegistrationOptions starts passkey enrollment inside the transaction
// when an MFA enrollment is required (MFA-003, SEC-012).
func (s *Service) WebAuthnRegistrationOptions(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	if s.Passkeys == nil {
		return nil, problem.ErrFeatureDisabled
	}
	var opts *passkey.RegistrationOptions
	st, err := s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		if !r.passkeysEnabled || !slices.Contains(r.actions, identity.ActionConfigureTOTP) {
			return nil, problem.ErrUnexpectedStep
		}
		// Under the phishing-resistant profile an account that holds another
		// second factor proves it first (upgrade proof, MFA-006).
		if err := s.offered(ctx, tx, t, "enroll_webauthn"); err != nil {
			return nil, err
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		opts, err = s.Passkeys.BeginRegistration(ctx, tx, rlm, t.UserID, t.ID, r.phishingResistant)
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	st.WebAuthn = opts
	return st, nil
}

// WebAuthnRegister completes in-transaction enrollment. Proving possession of the
// new authenticator counts as the second factor.
func (s *Service) WebAuthnRegister(ctx context.Context, realmID, id string, p Proof, response []byte, name string) (*State, error) {
	if s.Passkeys == nil {
		return nil, problem.ErrFeatureDisabled
	}
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		// Registration stays open only while it is offered: the profile or
		// the factor policy may have changed since the ceremony began.
		if err := s.offered(ctx, tx, t, "enroll_webauthn"); err != nil {
			return nil, err
		}
		if err := s.verifyBudget(ctx, t.RealmID, t.UserID, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		cred, f, err := s.Passkeys.FinishRegistration(ctx, tx, rlm, t.UserID, "", t.ID, response, name, audit.Ref{Type: "user", ID: t.UserID})
		if err != nil {
			return nil, passkeyErr(err)
		}
		t.Factors = append(t.Factors, f)
		t.Pending.UpgradeProof = nil
		t.ActionsDone = append(t.ActionsDone, identity.ActionConfigureTOTP)
		// A passkey satisfies the forced second-factor enrollment.
		if err := s.Users.RemoveRequiredActionTx(ctx, tx, t.UserID, identity.ActionConfigureTOTP); err != nil {
			return nil, err
		}
		return map[string]any{"webauthn_credential": cred}, s.notifySecurity(ctx, tx, t.RealmID, t.UserID, notification.TplMFAChanged, "a passkey was added to your account")
	})
}

// loginBudgetIP bounds ceremony creation per client IP (NFR-006).
func (s *Service) loginBudgetIP(ctx context.Context, t *Transaction) error {
	rl := s.d.Cfg.Security.RateLimits
	d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "wan-ip:" + t.RealmID + ":" + t.ClientIP, Limit: rl.LoginPerIP, Window: rl.LoginWindow})
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}

// CheckPhishingResistantFloor refuses, in production, an operator floor
// (security.mfa_floor.admin_phishing_resistant) that sign-in could not
// meet because passkeys (WebAuthn) are not configured: the floor fails
// closed instead of leaving administrators on phishable factors (SEC-012,
// MFA-005). The server calls it at startup.
func (s *Service) CheckPhishingResistantFloor() error {
	cfg := s.d.Cfg
	if cfg.Mode == configuration.ModeProduction && cfg.Security.MFAFloor.AdminPhishingResistant && s.Passkeys == nil {
		return errors.New("security.mfa_floor.admin_phishing_resistant requires passkeys (WebAuthn), which this server does not provide")
	}
	return nil
}
