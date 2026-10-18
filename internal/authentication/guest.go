package authentication

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
)

// ACRAnonymous is the assurance of a guest session (REG-010).
const ACRAnonymous = "urn:proudauth:acr:anonymous"

// Guest signs in as a new low-privilege guest identity (REG-010). Guests hold
// no organization membership, roles or administrative access; they can later
// upgrade the same account by proving an email address and setting a
// password, never by taking over an existing account.
func (s *Service) Guest(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID != "" || t.Intent != "login" {
			return nil, problem.ErrUnexpectedStep
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if !rlm.Policy.Registration.AllowGuests {
			return nil, problem.ErrUnexpectedStep.WithDetail("guest access is not enabled")
		}
		if err := s.guestBudget(ctx, t); err != nil {
			return nil, err
		}
		u, err := s.Users.CreateTx(ctx, tx, t.RealmID, identity.CreateInput{IsGuest: true, State: identity.StateActive, CreatedVia: "guest"})
		if err != nil {
			return nil, err
		}
		t.UserID = u.ID
		now := s.d.Now()
		t.AuthTime = &now
		t.Factors = append(t.Factors, session.Factor{Type: "anon", At: now})
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.guest.created", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: u.ID},
			Subject: &audit.Ref{Type: "user", ID: u.ID}, Category: "account"})
		return nil, err
	})
}

// UpgradeGuest turns the caller's guest account into a registered account
// (REG-010): it sets a password and adds the email address unverified; the
// account stops being a guest when the address is verified. The response is
// the same whether or not the address already belongs to another account:
// the challenge goes to the address, and verifying an address another account
// owns fails, so nothing is ever linked or merged (USR-021).
//
// An upgrade is a registration: the realm and organization registration modes
// and the registration-eligibility hooks apply exactly as they do to
// self-registration, and realms that review registrations queue the upgraded
// account for approval when it completes (REG-008).
func (s *Service) UpgradeGuest(ctx context.Context, realmID, clientID, userID, email, password string) (string, error) {
	canon, display, err := canonical.Email(email)
	if err != nil {
		return "", problem.ErrValidation.WithField("email", "invalid email address")
	}
	if err := s.guestUpgradeEligible(ctx, realmID, clientID, canon); err != nil {
		return "", err
	}
	var identifierID string
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		u, err := s.Users.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if !u.IsGuest {
			return problem.ErrConflict.WithDetail("the account is already registered")
		}
		rlm, err := s.Realms.ByID(ctx, tx, realmID)
		if err != nil {
			return err
		}
		if err := s.SetPasswordTx(ctx, tx, realmID, userID, password, rlm.Policy.Password.MinLength, rlm.Policy.Password.HistoryCount,
			strings.Split(canon, "@")[0]); err != nil {
			return err
		}
		id, err := s.Users.AddIdentifierTx(ctx, tx, realmID, userID, "email", display, false)
		if err != nil {
			return err
		}
		identifierID = id.ID
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.guest.upgrade_started", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
			Subject: &audit.Ref{Type: "user", ID: userID}, Category: "account"})
		return err
	})
	return identifierID, err
}

// guestUpgradeEligible applies the registration rules to a guest upgrade.
func (s *Service) guestUpgradeEligible(ctx context.Context, realmID, clientID, canon string) error {
	rlm, err := s.Realms.ByID(ctx, nil, realmID)
	if err != nil {
		return err
	}
	domain := canonical.EmailDomain(canon)
	switch rlm.Policy.Registration.Mode {
	case realm.RegistrationPublic:
	case realm.RegistrationDomainRestricted:
		if !slices.Contains(rlm.Policy.Registration.AllowedDomains, domain) {
			return problem.ErrForbidden.WithDetail("registration is not open for this email domain")
		}
	case realm.RegistrationInvitationOnly:
		return problem.ErrForbidden.WithDetail("registration requires an invitation")
	default:
		return problem.ErrForbidden.WithDetail("registration is closed")
	}
	if err := s.orgRegistrationPolicy(ctx, s.d.DB.Pool, &Transaction{RealmID: realmID}, domain, ""); err != nil {
		return err
	}
	if s.Hooks != nil {
		return s.Hooks.CheckRegistration(ctx, realmID, clientID, map[string]any{"email": canon, "email_domain": domain, "invited": false,
			"creates_organization": false, "guest_upgrade": true})
	}
	return nil
}

// completeGuestUpgradeTx clears the guest flag once a verified email and a
// password exist (called after identifier verification). In realms that
// review registrations the account then waits for approval: its sessions end
// and sign-in is refused until a reviewer approves it.
func (s *Service) completeGuestUpgradeTx(ctx context.Context, tx pgx.Tx, realmID, userID string) error {
	tag, err := tx.Exec(ctx, `UPDATE users SET is_guest=false, updated_at=$2, version=version+1 WHERE id=$1 AND is_guest
		AND EXISTS (SELECT 1 FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL)
		AND EXISTS (SELECT 1 FROM credentials WHERE user_id=$1 AND type='password' AND state='active')`, userID, s.d.Now())
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	rlm, err := s.Realms.ByID(ctx, tx, realmID)
	if err != nil {
		return err
	}
	if rlm.Policy.Registration.RequireApproval {
		if _, err := tx.Exec(ctx, `INSERT INTO registration_approvals (id, realm_id, user_id, expires_at) VALUES ($1,$2,$3,$4)`,
			ids.New(ids.RegApproval), realmID, userID, s.d.Now().Add(14*24*time.Hour)); err != nil {
			return err
		}
		if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, userID, "registration_pending_approval", true); err != nil {
			return err
		}
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.guest.upgraded", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Category: "account"})
	return err
}

// guestBudget bounds guest creation like self-registration (SEC-006).
func (s *Service) guestBudget(ctx context.Context, t *Transaction) error {
	rl := s.d.Cfg.Security.RateLimits
	budgets := append(ratelimit.PerNetwork("guest-ip:"+t.RealmID+":", chargeIP(ctx, t), rl.SignupPerIP, rl.SignupWindow, rl.NetworkCoarseFactor),
		ratelimit.Budget{Key: "guest-client:" + t.ClientRef, Limit: rl.SignupPerClient, Window: rl.SignupWindow},
		ratelimit.Budget{Key: "guest-realm:" + t.RealmID, Limit: rl.SignupPerRealm, Window: rl.SignupWindow})
	d, err := s.Limiter.Hit(ctx, budgets...)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}
