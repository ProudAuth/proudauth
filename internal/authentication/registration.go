package authentication

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

func digest(s string) string { return secret.Digest(s) }

// RegistrationInput is submitted within a registration transaction.
type RegistrationInput struct {
	Email            string              `json:"email"`
	Password         string              `json:"password"`
	Username         string              `json:"username"`
	GivenName        string              `json:"given_name"`
	FamilyName       string              `json:"family_name"`
	DisplayName      string              `json:"display_name"`
	Locale           string              `json:"locale"`
	TermsVersion     string              `json:"terms_version"`
	Profile          map[string]any      `json:"profile"`
	Organization     *organization.Input `json:"organization"`
	InvitationSecret string              `json:"invitation"`
}

// Register starts account creation (REG-001). The response is identical whether or
// not the address already belongs to an account: an existing owner is notified
// instead of being revealed (REG-005, TEST-020). No usable token is issued until
// the email is verified and every other requirement is met (§27.1).
func (s *Service) Register(ctx context.Context, realmID, id string, p Proof, in RegistrationInput) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		// A fresh login transaction may switch to registration before anyone is identified.
		if (t.Intent != "register" && t.Intent != "login") || t.UserID != "" || len(t.Factors) > 0 || t.Pending.PhantomRegistration {
			return nil, problem.ErrUnexpectedStep
		}
		t.Intent = "register"
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		rl := s.d.Cfg.Security.RateLimits
		budgets := append(ratelimit.PerNetwork("signup-ip:"+t.RealmID+":", chargeIP(ctx, t), rl.SignupPerIP, rl.SignupWindow, rl.NetworkCoarseFactor),
			ratelimit.Budget{Key: "signup-client:" + t.ClientRef, Limit: rl.SignupPerClient, Window: rl.SignupWindow},
			ratelimit.Budget{Key: "signup-realm:" + t.RealmID, Limit: rl.SignupPerRealm, Window: rl.SignupWindow})
		d, err := s.Limiter.Hit(ctx, budgets...)
		if err != nil {
			return nil, err
		}
		if !d.Allowed {
			return nil, problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		canon, display, err := canonical.Email(in.Email)
		if err != nil {
			return nil, problem.ErrValidation.WithField("email", "invalid email address")
		}
		domain := canonical.EmailDomain(canon)
		// Registration mode checks happen before expensive work or outbound messages.
		invitationTarget, invitedOrg := "", ""
		if in.InvitationSecret != "" {
			org, target, err := s.Orgs.InvitationTargetForSecret(ctx, t.RealmID, in.InvitationSecret)
			if err != nil {
				return nil, problem.ErrInvitationInvalid
			}
			invitationTarget, invitedOrg = target, org
			if target != "" && target != canon {
				return nil, problem.ErrInvitationInvalid.WithDetail("register with the invited address")
			}
		}
		switch rlm.Policy.Registration.Mode {
		case realm.RegistrationPublic:
		case realm.RegistrationDomainRestricted:
			if !slices.Contains(rlm.Policy.Registration.AllowedDomains, domain) {
				return nil, problem.ErrForbidden.WithDetail("registration is not open for this email domain")
			}
		case realm.RegistrationInvitationOnly:
			if in.InvitationSecret == "" {
				return nil, problem.ErrForbidden.WithDetail("registration requires an invitation")
			}
		default:
			return nil, problem.ErrForbidden.WithDetail("registration is closed")
		}
		// Organization registration policy (REG-001): an organization in whose
		// context the account is being created (requested, invited, or owning
		// the email domain) may close or narrow registration further. It can only
		// tighten the realm mode, never open a closed realm.
		if err := s.orgRegistrationPolicy(ctx, tx, t, domain, invitedOrg); err != nil {
			return nil, err
		}
		if rlm.Policy.Registration.TermsVersion != "" && in.TermsVersion != rlm.Policy.Registration.TermsVersion {
			return nil, problem.ErrValidation.WithField("terms_version", "accept the current terms version")
		}
		if in.Organization != nil && !rlm.Policy.Registration.AllowOrganizationCreation {
			return nil, problem.ErrForbidden.WithDetail("organization creation during registration is disabled")
		}
		// Registration-eligibility and profile hooks run before any account or
		// message is created; they fail closed (EXT-009, EXT-012).
		if s.Hooks != nil {
			client, err := s.Apps.ClientByRef(ctx, tx, t.RealmID, t.ClientRef)
			if err != nil {
				return nil, err
			}
			reg := map[string]any{"email": canon, "email_domain": domain, "username": in.Username, "invited": in.InvitationSecret != "",
				"creates_organization": in.Organization != nil}
			if err := s.Hooks.CheckRegistration(ctx, t.RealmID, client.ClientID, reg); err != nil {
				return nil, err
			}
			if len(in.Profile) > 0 {
				if err := s.Hooks.CheckProfile(ctx, t.RealmID, "", in.Profile); err != nil {
					return nil, err
				}
			}
		}
		words := []string{canon, strings.Split(canon, "@")[0], in.Username}
		if v := s.Policy.Check(in.Password, rlm.Policy.Password.MinLength, words...); v != nil {
			return nil, problem.ErrPasswordPolicy.WithDetail(v.Message).WithExtension("policy_code", v.Code)
		}
		if tomb, _ := s.Users.IsTombstoned(ctx, tx, t.RealmID, "email", canon); tomb {
			// Deleted identities may register again as new accounts; tombstones only
			// prevent restore/import resurrection. Nothing to do here.
			_ = tomb
		}
		if err := s.sendBudget(ctx, t.RealmID, canon, chargeIP(ctx, t), t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		existing, err := s.Users.VerifiedEmailOwner(ctx, tx, t.RealmID, canon)
		if err != nil {
			return nil, err
		}
		if existing != "" {
			t.Pending.PhantomRegistration = true
			t.Pending.RegistrationEmail = canon
			_, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: t.RealmID, Template: notification.TplRegistrationExists,
				Recipient: display, Mandatory: true, ReferenceType: "user", ReferenceID: existing, Data: map[string]string{"realm": rlm.DisplayName}})
			if err != nil {
				return nil, err
			}
			_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "registration.duplicate_attempt", RealmID: t.RealmID,
				Actor: audit.Ref{Type: "anonymous", ID: "transaction:" + t.ID}, Subject: &audit.Ref{Type: "user", ID: existing}, Outcome: audit.Denied})
			return nil, err
		}
		u, err := s.Users.CreateTx(ctx, tx, t.RealmID, identity.CreateInput{Email: display, Username: in.Username, GivenName: in.GivenName,
			FamilyName: in.FamilyName, DisplayName: in.DisplayName, Locale: in.Locale, State: identity.StatePendingVerification,
			CreatedVia: "registration", Profile: in.Profile})
		if err != nil {
			return nil, err
		}
		if schema := s.schema(t.RealmID); schema != nil && len(in.Profile) > 0 {
			if perr := schema.ValidateSelfEdit(map[string]any{}, in.Profile); perr != nil {
				return nil, perr
			}
		}
		if rlm.Policy.Registration.RequireApproval && in.InvitationSecret == "" {
			if _, err := tx.Exec(ctx, `INSERT INTO registration_approvals (id, realm_id, user_id, expires_at) VALUES ($1,$2,$3,$4)`,
				ids.New(ids.RegApproval), t.RealmID, u.ID, s.d.Now().Add(14*24*time.Hour)); err != nil {
				return nil, err
			}
		}
		if err := s.SetPasswordTx(ctx, tx, t.RealmID, u.ID, in.Password, rlm.Policy.Password.MinLength, 0, words...); err != nil {
			return nil, err
		}
		t.UserID = u.ID
		t.IdentifiedVia = "registration"
		now := s.d.Now()
		t.Factors = append(t.Factors, session.Factor{Type: "pwd", At: now})
		t.AuthTime = &now
		if rlm.Policy.Registration.TermsVersion != "" {
			if err := s.recordTerms(ctx, tx, t, in.TermsVersion, "registration"); err != nil {
				return nil, err
			}
			t.ActionsDone = append(t.ActionsDone, identity.ActionAcceptTerms)
		}
		if in.Organization != nil {
			o := *in.Organization
			t.Pending.CreateOrganization = &o
		}
		if in.InvitationSecret != "" {
			ct, _, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(in.InvitationSecret), []byte("invitation:"+t.ID))
			if err != nil {
				return nil, err
			}
			t.Pending.InvitationSecretCT = ct
			t.Pending.InvitedOrgID = invitedOrg
			_ = invitationTarget
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "registration.started", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: u.ID},
			Subject: &audit.Ref{Type: "user", ID: u.ID}, Category: "account", Metadata: map[string]any{"with_organization": in.Organization != nil,
				"with_invitation": in.InvitationSecret != ""}}); err != nil {
			return nil, err
		}
		return nil, s.sendCode(ctx, tx, t, rlm.DisplayName, PurposeEmailVerification, u.ID, canon, display, notification.TplEmailVerification)
	})
}

// orgRegistrationPolicy applies the registration mode of the organization the
// registration targets (REG-001).
func (s *Service) orgRegistrationPolicy(ctx context.Context, q storage.Querier, t *Transaction, domain, invitedOrg string) error {
	if s.Orgs == nil {
		return nil
	}
	orgID := t.RequestedOrgID
	if orgID == "" {
		if id, _, _, err := s.Orgs.DiscoverByEmailDomain(ctx, t.RealmID, domain); err == nil {
			orgID = id
		}
	}
	if orgID == "" {
		orgID = invitedOrg
	}
	if orgID == "" {
		return nil
	}
	org, err := s.Orgs.Get(ctx, q, t.RealmID, orgID)
	if err != nil {
		return nil // an unknown requested organization is handled by the transaction rules
	}
	switch org.Policy.RegistrationMode {
	case "", "inherit", realm.RegistrationPublic:
		return nil
	case realm.RegistrationClosed:
		return problem.ErrForbidden.WithDetail("this organization does not accept new registrations")
	case realm.RegistrationInvitationOnly:
		if invitedOrg != org.ID {
			return problem.ErrForbidden.WithDetail("this organization accepts registrations by invitation only")
		}
	case realm.RegistrationDomainRestricted:
		allowed := slices.Contains(org.Policy.AllowedEmailDomains, domain)
		if !allowed {
			covered, err := s.Orgs.DomainCovered(ctx, t.RealmID, org.ID, domain)
			if err != nil {
				return err
			}
			allowed = covered
		}
		if !allowed {
			return problem.ErrForbidden.WithDetail("this organization accepts registrations from its own email domains only")
		}
	}
	return nil
}
