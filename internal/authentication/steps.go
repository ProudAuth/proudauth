package authentication

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

// Completion is the result of a completed transaction.
type Completion struct {
	SessionID     string
	SessionCookie string
	// RememberedDevice is a new remembered-device secret (returned once).
	RememberedDevice string
	// Transient marks a non-persistent session: browsers get a session cookie
	// without an expiry attribute.
	Transient  bool
	GrantID    string
	Code       string
	RedirectTo string
}

// step runs fn under the transaction lock. Proof failures are committed (failure
// count, audit) and returned to the caller; other errors roll back.
func (s *Service) step(ctx context.Context, realmID, id string, p Proof, fn func(tx pgx.Tx, t *Transaction) (map[string]any, error)) (*State, error) {
	if s.Hooks != nil && s.Hooks.HasActive(ctx, realmID) {
		// Registration and profile hooks run inside the step transaction; it is
		// not retried, so a hook call is never repeated (DB-014).
		ctx = storage.NoRetry(ctx)
	}
	var st *State
	var stepErr error
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		stepErr = nil
		t, err := s.lockTx(ctx, tx, realmID, id, p)
		if err != nil {
			return err
		}
		t.deviceToken = p.RememberedDevice
		oneTime, err := fn(tx, t)
		if err != nil {
			var pe *proofError
			if errors.As(err, &pe) {
				t.FailureCount++
				if t.FailureCount >= MaxFailures {
					t.Status = StatusFailed
					t.Pending.ErrorCode = "too_many_failures"
				}
				if serr := s.save(ctx, tx, t); serr != nil {
					return serr
				}
				stepErr = pe.err
				return nil
			}
			return err
		}
		if err := s.settlePendingLink(ctx, tx, t); err != nil {
			return err
		}
		if err := s.save(ctx, tx, t); err != nil {
			return err
		}
		st, err = s.advance(ctx, tx, t)
		if err != nil {
			return err
		}
		if len(oneTime) > 0 {
			st.OneTime = oneTime
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if stepErr != nil {
		return nil, stepErr
	}
	return st, nil
}

// offered refuses a step whose action the transaction does not offer now
// (AUT-002, AUT-004): the server alone decides which steps are open, so a
// step left out of next_actions (an enrollment the profile forbids, a
// factor the realm does not allow) cannot be called directly either.
func (s *Service) offered(ctx context.Context, q storage.Querier, t *Transaction, types ...string) error {
	st, err := s.state(ctx, q, t)
	if err != nil {
		return err
	}
	if st.Error == "" && slices.ContainsFunc(st.NextActions, func(a Action) bool { return slices.Contains(types, a.Type) }) {
		return nil
	}
	return problem.ErrUnexpectedStep
}

// recordUpgradeProof keeps a factor proved under the phishing-resistant
// profile as the upgrade proof that unlocks passkey registration (MFA-006,
// SEC-012). It is not added to the completed factors, so it never satisfies
// MFA, and its audit evidence commits with the transaction.
func (s *Service) recordUpgradeProof(ctx context.Context, tx pgx.Tx, t *Transaction, factor, credID string) error {
	t.Pending.UpgradeProof = &UpgradeProof{UserID: t.UserID, Factor: factor, CredentialID: credID, At: s.d.Now()}
	md := map[string]any{"factor": factor, "transaction_id": t.ID}
	if credID != "" {
		md["credential_id"] = credID
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.upgrade_proof.recorded", RealmID: t.RealmID, Actor: actorFor(t),
		Subject: &audit.Ref{Type: "user", ID: t.UserID}, Metadata: md})
	return err
}

// advance computes next actions and completes automatically when nothing remains.
func (s *Service) advance(ctx context.Context, tx pgx.Tx, t *Transaction) (*State, error) {
	st, err := s.state(ctx, tx, t)
	if err != nil {
		return nil, err
	}
	if t.flowChanged {
		t.flowChanged = false
		if err := s.save(ctx, tx, t); err != nil {
			return nil, err
		}
	}
	if t.Status == StatusPending && len(st.NextActions) == 1 && st.NextActions[0].Type == "complete" {
		comp, err := s.complete(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		st, err = s.state(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		st.RedirectTo = comp.RedirectTo
		st.SessionCookie = comp.SessionCookie
		st.Completion = comp
		if comp.RememberedDevice != "" {
			if st.OneTime == nil {
				st.OneTime = map[string]any{}
			}
			st.OneTime["remembered_device_token"] = comp.RememberedDevice
		}
	}
	return st, nil
}

// Resume returns current state and auto-completes when possible (used right after
// starting a transaction that reuses an SSO session).
func (s *Service) Resume(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) { return nil, nil })
}

// Identify records the identifier without revealing whether an account exists
// (AUT-009, SEC-005). Verified-domain SSO routing may be returned; that discloses
// routing configuration only.
func (s *Service) Identify(ctx context.Context, realmID, id string, p Proof, identifier string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID != "" && t.ReusedSessionID == "" {
			return nil, problem.ErrUnexpectedStep
		}
		typ, canon, ok := identity.CanonicalizeLogin(identifier)
		if !ok {
			return nil, problem.ErrValidation.WithField("identifier", "not a valid email, phone or username")
		}
		// Only the identifier types the realm permits are accepted (REG-002,
		// AUT-005). The refusal depends on the input's form, never on whether an
		// account exists.
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if ids := rlm.Policy.Login.Identifiers; len(ids) > 0 && !slices.Contains(ids, typ) {
			return nil, problem.ErrValidation.WithField("identifier", "sign in with: "+strings.Join(ids, ", "))
		}
		if err := s.loginBudget(ctx, t, canon); err != nil {
			return nil, err
		}
		t.Pending.Identifier = canon
		t.Pending.IdentifierType = typ
		t.Pending.SSORouted = false
		t.Pending.ExternalProvider = ""
		t.Pending.PendingLink = nil
		t.ReusedSessionID = ""
		t.UserID = ""
		t.Factors = nil
		t.AuthTime = nil
		if typ == "email" && s.Orgs != nil {
			if orgID, sso, provider, err := s.Orgs.DiscoverByEmailDomain(ctx, t.RealmID, canonical.EmailDomain(canon)); err == nil && orgID != "" {
				if t.RequestedOrgID == "" {
					t.RequestedOrgID = orgID
				}
				if sso && provider != "" {
					t.Pending.ExternalProvider = provider
					t.Pending.SSORouted = true
				}
			}
		}
		return nil, nil
	})
}

func (s *Service) loginBudget(ctx context.Context, t *Transaction, canon string) error {
	rl := s.d.Cfg.Security.RateLimits
	d, err := s.Limiter.Hit(ctx,
		ratelimit.Budget{Key: "login-id:" + t.RealmID + ":" + canon, Limit: rl.LoginPerIdentifier * 3, Window: rl.LoginWindow},
		ratelimit.Budget{Key: "login-ip:" + t.RealmID + ":" + t.ClientIP, Limit: rl.LoginPerIP, Window: rl.LoginWindow},
	)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}

// Password verifies a password against the identified account with generic
// failures and comparable timing for unknown accounts (AUT-005).
func (s *Service) Password(ctx context.Context, realmID, id string, p Proof, identifier, password string) (*State, error) {
	if identifier != "" {
		if _, err := s.Identify(ctx, realmID, id, p, identifier); err != nil {
			return nil, err
		}
	}
	// Stopgap until the password step runs its slow work outside the
	// transaction (NFR-002): the Argon2id check (or its dummy) needs a
	// hashing slot, refused at once when none is free, and a step that may
	// bind against a directory runs once (DB-014).
	ctx, release, err := s.hashSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if ctx, err = s.directoryOnce(ctx, realmID); err != nil {
		return nil, err
	}
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.Pending.Identifier == "" {
			return nil, problem.ErrUnexpectedStep.WithDetail("identify first")
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if !rlm.Policy.Login.Password {
			return nil, problem.ErrUnexpectedStep
		}
		rl := s.d.Cfg.Security.RateLimits
		budgets := []ratelimit.Budget{
			{Key: "pwd-id:" + t.RealmID + ":" + t.Pending.Identifier, Limit: rl.LoginPerIdentifier, Window: rl.LoginWindow},
			{Key: "pwd-ip:" + t.RealmID + ":" + t.ClientIP, Limit: rl.LoginPerIP, Window: rl.LoginWindow},
			// Password attempts through one client are sign-in proof attempts,
			// bounded by login_per_client like codes and factors (REG-012),
			// not by the token endpoint's budget.
			{Key: "pwd-client:" + t.ClientRef, Limit: rl.LoginPerClient, Window: rl.LoginWindow},
			{Key: "pwd-realm:" + t.RealmID, Limit: rl.LoginPerRealm, Window: rl.LoginWindow},
		}
		if t.RequestedOrgID != "" && rl.LoginPerOrganization > 0 {
			budgets = append(budgets, ratelimit.Budget{Key: "pwd-org:" + t.RequestedOrgID, Limit: rl.LoginPerOrganization, Window: rl.LoginWindow})
		}
		d, err := s.Limiter.Hit(ctx, budgets...)
		if err != nil {
			return nil, err
		}
		if !d.Allowed {
			return nil, problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		start := time.Now()
		u, lookupErr := s.Users.FindByLogin(ctx, t.RealmID, t.Pending.IdentifierType, t.Pending.Identifier)
		// Temporary password lock after repeated failures (SEC-006). Every
		// failure counts against the identifier tried and, when it names an
		// account, against the account as well:
		//   - the identifier's budget is the only one an unknown identifier
		//     has and the only one that answers 429, so a lock looks the same
		//     whether or not an account exists (API-009);
		//   - the account's budget bounds password guessing per account,
		//     whichever of its identifiers is tried: once it is spent the
		//     password is no longer checked, and another identifier of the
		//     account answers like an unknown identifier (401, counted against
		//     its own budget, then 429), so a lock reached through one
		//     identifier does not reveal which other identifiers share the
		//     account (API-009).
		// The lock expires on its own and never blocks passkey, federated or
		// emailed-code sign-in, so an attacker cannot cause a permanent lockout.
		lockOn := rl.FailuresBeforeLock > 0 && rl.TemporaryLock > 0
		locks := []ratelimit.Budget{{Key: "pwd-fail:" + t.RealmID + ":id:" + t.Pending.Identifier, Limit: rl.FailuresBeforeLock, Window: rl.TemporaryLock}}
		if lookupErr == nil {
			locks = append(locks, ratelimit.Budget{Key: "pwd-fail:" + t.RealmID + ":user:" + u.ID, Limit: rl.FailuresBeforeLock, Window: rl.TemporaryLock})
		}
		accountLocked := false
		if lockOn {
			if allowed, err := s.Limiter.Peek(ctx, locks[0]); err == nil && !allowed {
				s.Hasher.DummyVerify(password)
				padTiming(start, s.d.Cfg.Security.MinAuthResponse)
				ev := audit.Event{Type: "authentication.password.temporarily_locked", RealmID: t.RealmID, Actor: audit.Ref{Type: "anonymous", ID: "transaction:" + t.ID},
					Outcome: audit.Denied, ReasonCode: "TEMPORARY_LOCK"}
				if u != nil {
					ev.Subject = &audit.Ref{Type: "user", ID: u.ID}
				}
				if _, err := s.d.Audit.Record(ctx, tx, ev); err != nil {
					return nil, err
				}
				return nil, errProof(problem.ErrRateLimited.WithRetryAfter(rl.TemporaryLock))
			}
			if len(locks) > 1 {
				if allowed, err := s.Limiter.Peek(ctx, locks[1]); err == nil && !allowed {
					accountLocked = true
				}
			}
		}
		ok := false
		if lookupErr != nil && s.Directory != nil {
			// First sign-in of an account a directory knows but this realm has
			// not imported yet (FED-015): the directory's bind verifies the
			// password, and the account is created and linked in this step.
			du, err := s.Directory.ProvisionOnLogin(ctx, tx, t.RealmID, t.Pending.Identifier, password)
			if err != nil {
				return nil, err
			}
			if du != nil {
				u, lookupErr, ok = du, nil, true
			}
		}
		if lookupErr == nil && !ok && !accountLocked {
			ok, err = s.VerifyPassword(ctx, tx, u.ID, password)
			if err != nil {
				return nil, err
			}
		} else if !ok {
			s.Hasher.DummyVerify(password)
		}
		padTiming(start, s.d.Cfg.Security.MinAuthResponse)
		if !ok && lockOn {
			for _, b := range locks {
				_, _ = s.Limiter.Hit(ctx, b)
			}
		}
		if !ok {
			ev := audit.Event{Type: "authentication.password.failed", RealmID: t.RealmID, Actor: audit.Ref{Type: "anonymous", ID: "transaction:" + t.ID},
				Outcome: audit.Failure, ReasonCode: "INVALID_CREDENTIALS", Metadata: map[string]any{"transaction_id": t.ID}}
			if accountLocked {
				// The account is locked; the password was not checked.
				ev.Type, ev.Outcome, ev.ReasonCode = "authentication.password.temporarily_locked", audit.Denied, "TEMPORARY_LOCK"
			}
			if u != nil {
				ev.Subject = &audit.Ref{Type: "user", ID: u.ID}
			}
			if _, err := s.d.Audit.Record(ctx, tx, ev); err != nil {
				return nil, err
			}
			return nil, errProof(problem.ErrInvalidCredentials)
		}
		// A pending-deletion account continues: once every factor it needs is
		// done, its only action is cancel_deletion (USR-012, evaluate).
		if u.State == identity.StateSuspended || u.State == identity.StateDeleted || u.State == identity.StateLocked {
			_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.denied", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: u.ID},
				Subject: &audit.Ref{Type: "user", ID: u.ID}, Outcome: audit.Denied, ReasonCode: "ACCOUNT_" + strings.ToUpper(u.State)})
			return nil, errProof(problem.ErrInvalidCredentials)
		}
		if t.UserID != "" && t.UserID != u.ID {
			return nil, problem.ErrTransactionInvalid
		}
		t.UserID = u.ID
		t.IdentifiedVia = t.Pending.IdentifierType
		now := s.d.Now()
		t.Factors = append(t.Factors, session.Factor{Type: "pwd", At: now})
		t.AuthTime = &now
		return nil, nil
	})
}

// padTiming bounds timing differences between known and unknown accounts.
func padTiming(start time.Time, min time.Duration) {
	if elapsed := time.Since(start); elapsed < min {
		time.Sleep(min - elapsed)
	}
}

// SendOTP sends an email code for verification or passwordless login. Responses are
// identical whether or not an account exists (SEC-005).
func (s *Service) SendOTP(ctx context.Context, realmID, id string, p Proof, purpose string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		switch purpose {
		case "verify_email":
			if t.Pending.PhantomRegistration {
				// Nothing is sent to an unrelated mailbox; the response is indistinguishable.
				return nil, s.sendBudget(ctx, t.RealmID, t.Pending.RegistrationEmail, t.ClientIP, t.ClientRef, t.RequestedOrgID)
			}
			if t.UserID == "" {
				return nil, problem.ErrUnexpectedStep
			}
			u, err := s.Users.User(ctx, tx, t.RealmID, t.UserID)
			if err != nil {
				return nil, err
			}
			e := u.PrimaryEmail()
			if e == nil || e.Verified() {
				return nil, problem.ErrUnexpectedStep
			}
			if err := s.sendBudget(ctx, t.RealmID, e.Canonical, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
				return nil, err
			}
			return nil, s.sendCode(ctx, tx, t, rlm.DisplayName, PurposeEmailVerification, u.ID, e.Canonical, e.Value, notification.TplEmailVerification)
		case "verify_contact":
			// An administrator asked the account to re-confirm its address
			// (AUT-018): the code goes to the primary email, verified or not.
			if t.UserID == "" || !primaryDone(t) {
				return nil, problem.ErrUnexpectedStep
			}
			u, err := s.Users.User(ctx, tx, t.RealmID, t.UserID)
			if err != nil {
				return nil, err
			}
			e := u.PrimaryEmail()
			if e == nil || !u.HasRequiredAction(identity.ActionVerifyContact) || slices.Contains(t.ActionsDone, identity.ActionVerifyContact) {
				return nil, problem.ErrUnexpectedStep
			}
			if err := s.sendBudget(ctx, t.RealmID, e.Canonical, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
				return nil, err
			}
			return nil, s.sendCode(ctx, tx, t, rlm.DisplayName, PurposeEmailVerification, u.ID, e.Canonical, e.Value, notification.TplEmailVerification)
		case "magic_link":
			return nil, s.sendMagicLink(ctx, tx, t, rlm)
		case "login":
			typ := t.Pending.IdentifierType
			if !((typ == "email" && rlm.Policy.Login.EmailOTP) || (typ == "phone" && rlm.Policy.Login.SMSOTP && s.Notify.SMSEnabled())) {
				return nil, problem.ErrUnexpectedStep
			}
			if t.Pending.PendingLink != nil && typ != "email" {
				// SMS never proves control for linking an external identity
				// (PWDLESS-006, PWDLESS-008).
				return nil, problem.ErrUnexpectedStep
			}
			if err := s.sendBudget(ctx, t.RealmID, t.Pending.Identifier, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
				return nil, err
			}
			if typ == "phone" {
				// The SMS ceilings (country restriction, the deployment's daily
				// budget) are checked before the account is looked up, so a
				// number without an account gets the same refusal, body and
				// Retry-After as one with an account (API-009, SEC-005).
				if err := s.Notify.SMSAdmissible(ctx, tx, t.Pending.Identifier); err != nil {
					return nil, err
				}
			}
			u, err := s.Users.FindByLogin(ctx, t.RealmID, typ, t.Pending.Identifier)
			userID := ""
			if err == nil && (u.CanAuthenticate(s.d.Now()) || u.MayCancelDeletion(s.d.Now())) {
				userID = u.ID
			}
			// While an external identity waits to be linked, the code is bound
			// to that link and its message says so (PWDLESS-008).
			tpl, data, meta, err := s.linkProof(ctx, tx, t, notification.TplLoginCode, map[string]string{"realm": rlm.DisplayName,
				"expires_minutes": minutes(s.d.Cfg.Tokens.ChallengeTTL)})
			if err != nil {
				return nil, err
			}
			// A challenge row is created either way so the follow-up verify behaves identically.
			cid, code, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: t.RealmID, Purpose: PurposeLoginOTP, TransactionID: t.ID,
				UserID: userID, IdentifierType: typ, Identifier: t.Pending.Identifier, Metadata: meta})
			if err != nil {
				return nil, err
			}
			t.Pending.LoginOTPChallenge = cid
			if userID != "" {
				channel := "email"
				if typ == "phone" {
					channel = "sms"
				}
				data["code"] = code
				if _, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: t.RealmID, Template: tpl, Locale: t.UILocales,
					Channel: channel, Recipient: t.Pending.Identifier, Mandatory: true, ReferenceType: "challenge", ReferenceID: cid, TTL: s.d.Cfg.Tokens.ChallengeTTL,
					UserID: userID, Data: data}); err != nil {
					// The SMS refusals were checked above for every number alike.
					return nil, err
				}
			}
			return nil, nil
		default:
			return nil, problem.ErrValidation.WithField("purpose", "verify_email, login or magic_link")
		}
	})
}

func minutes(d time.Duration) string { return strings.TrimSuffix(d.Round(time.Minute).String(), "m0s") }

func (s *Service) sendCode(ctx context.Context, tx pgx.Tx, t *Transaction, realmName, purpose, userID, canon, display, tpl string) error {
	cid, code, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: t.RealmID, Purpose: purpose, TransactionID: t.ID, UserID: userID,
		IdentifierType: "email", Identifier: canon})
	if err != nil {
		return err
	}
	_, err = s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: t.RealmID, Template: tpl, Locale: t.UILocales, Recipient: display,
		Mandatory: true, ReferenceType: "challenge", ReferenceID: cid, TTL: s.d.Cfg.Tokens.ChallengeTTL, UserID: userID,
		Data: map[string]string{"code": code, "realm": realmName, "expires_minutes": minutes(s.d.Cfg.Tokens.ChallengeTTL)}})
	return err
}

// VerifyOTP verifies an email or SMS code for the transaction's current purpose.
func (s *Service) VerifyOTP(ctx context.Context, realmID, id string, p Proof, code string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		subject := t.UserID
		if subject == "" {
			subject = t.Pending.Identifier + t.Pending.RegistrationEmail
			if t.Pending.LoginOTPChallenge != "" {
				// A passwordless transaction has not authenticated its user yet.
				// The issued challenge still binds the account, so aliases and
				// email/SMS/HOTP share its proof budget (TEST-021, NFR-006).
				// A phantom challenge keeps the identifier budget and never
				// assigns authentication authority to the transaction.
				var userID string
				err := tx.QueryRow(ctx, `SELECT coalesce(user_id,'') FROM challenges
					WHERE realm_id=$1 AND id=$2 AND transaction_id=$3 AND purpose=$4`,
					t.RealmID, t.Pending.LoginOTPChallenge, t.ID, PurposeLoginOTP).Scan(&userID)
				if err != nil && !storage.IsNoRows(err) {
					return nil, err
				}
				if userID != "" {
					subject = userID
				}
			}
		}
		if err := s.verifyBudget(ctx, t.RealmID, subject, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		if t.Pending.PhantomRegistration {
			return nil, errProof(problem.ErrInvalidProof)
		}
		// Determine which challenge is expected.
		purpose, challengeID := "", ""
		if t.UserID != "" {
			u, err := s.Users.User(ctx, tx, t.RealmID, t.UserID)
			if err != nil {
				return nil, err
			}
			if u.State == identity.StatePendingVerification || (u.HasRequiredAction(identity.ActionVerifyEmail) && !hasVerifiedEmail(u)) ||
				(primaryDone(t) && u.HasRequiredAction(identity.ActionVerifyContact) && !slices.Contains(t.ActionsDone, identity.ActionVerifyContact)) {
				purpose = PurposeEmailVerification
			}
		}
		if purpose == "" && t.Pending.LoginOTPChallenge != "" {
			purpose, challengeID = PurposeLoginOTP, t.Pending.LoginOTPChallenge
		}
		if purpose == "" {
			return nil, problem.ErrUnexpectedStep
		}
		if challengeID == "" {
			if err := tx.QueryRow(ctx, `SELECT id FROM challenges WHERE realm_id=$1 AND transaction_id=$2 AND purpose=$3 AND consumed_at IS NULL
				AND superseded_at IS NULL ORDER BY created_at DESC LIMIT 1`, t.RealmID, t.ID, purpose).Scan(&challengeID); err != nil {
				return nil, errProof(problem.ErrInvalidProof)
			}
		}
		c, err := s.ConsumeChallengeTx(ctx, tx, t.RealmID, challengeID, purpose, strings.TrimSpace(code))
		if err != nil {
			_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.otp.failed", RealmID: t.RealmID, Actor: actorFor(t), Outcome: audit.Failure,
				Metadata: map[string]any{"purpose": purpose}})
			return nil, err
		}
		if c.TransactionID != t.ID {
			return nil, errProof(problem.ErrInvalidProof)
		}
		switch purpose {
		case PurposeEmailVerification:
			var hadContact bool
			_ = tx.QueryRow(ctx, `SELECT 'verify_contact' = ANY(required_actions) FROM users WHERE id=$1`, t.UserID).Scan(&hadContact)
			if err := s.Users.MarkIdentifierVerifiedTx(ctx, tx, t.RealmID, t.UserID, "email", c.Identifier, "email_otp"); err != nil {
				return nil, err
			}
			// Re-confirming an already verified contact (AUT-018) records the
			// new proof: verified_at is when control was last proven.
			if hadContact {
				if err := s.Users.ReconfirmIdentifierTx(ctx, tx, t.RealmID, t.UserID, "email", c.Identifier, "email_otp"); err != nil {
					return nil, err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET state=CASE WHEN state='pending_verification' THEN 'active' ELSE state END,
				required_actions=array_remove(array_remove(required_actions, 'verify_email'), 'verify_contact'), updated_at=$2 WHERE id=$1`, t.UserID, s.d.Now()); err != nil {
				return nil, err
			}
			if hadContact && !slices.Contains(t.ActionsDone, identity.ActionVerifyContact) {
				t.ActionsDone = append(t.ActionsDone, identity.ActionVerifyContact)
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.identifier.verified", RealmID: t.RealmID, Actor: actorFor(t),
				Subject: &audit.Ref{Type: "user", ID: t.UserID}, Metadata: map[string]any{"identifier_type": "email"}}); err != nil {
				return nil, err
			}
			// Registration side effects run once, right after the account becomes real.
			if err := s.afterRegistrationVerified(ctx, tx, t); err != nil {
				return nil, err
			}
		case PurposeLoginOTP:
			if c.UserID == "" || !linkProofMatches(t, c) {
				return nil, errProof(problem.ErrInvalidProof)
			}
			if t.UserID != "" && t.UserID != c.UserID {
				return nil, problem.ErrTransactionInvalid
			}
			t.UserID = c.UserID
			factor := "otp"
			t.IdentifiedVia = "email"
			if c.IdentifierType == "phone" {
				// SMS codes are a distinct, weaker channel (PWDLESS-005, PWDLESS-006).
				factor, t.IdentifiedVia = "sms", "phone"
			}
			now := s.d.Now()
			t.Factors = append(t.Factors, session.Factor{Type: factor, At: now})
			t.AuthTime = &now
			t.Pending.LoginOTPChallenge = ""
		}
		return nil, nil
	})
}

// TOTP verifies the second factor.
func (s *Service) TOTP(ctx context.Context, realmID, id string, p Proof, code string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		switch {
		case r.upgrade && r.hasTOTP:
			// An upgrade proof under the phishing-resistant profile (below).
		case r.phishingResistant:
			return nil, problem.ErrUnexpectedStep.WithDetail("a phishing-resistant authenticator is required")
		case r.totpDisallowed:
			return nil, problem.ErrUnexpectedStep.WithDetail("TOTP is not an allowed factor in this realm")
		}
		if err := s.offered(ctx, tx, t, "totp"); err != nil {
			return nil, err
		}
		if err := s.verifyBudget(ctx, t.RealmID, t.UserID, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		credID, ok, err := s.VerifyTOTPTx(ctx, tx, t.UserID, code)
		if err != nil {
			return nil, err
		}
		if !ok {
			_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.failed", RealmID: t.RealmID, Actor: actorFor(t),
				Subject: &audit.Ref{Type: "user", ID: t.UserID}, Outcome: audit.Failure})
			return nil, errProof(problem.ErrInvalidProof)
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.used", RealmID: t.RealmID, Actor: actorFor(t),
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, Metadata: map[string]any{"credential_id": credID, "upgrade_proof": r.upgrade}}); err != nil {
			return nil, err
		}
		if r.upgrade {
			return nil, s.recordUpgradeProof(ctx, tx, t, "totp", credID)
		}
		t.Factors = append(t.Factors, session.Factor{Type: "totp", At: s.d.Now(), CredentialID: credID})
		return nil, nil
	})
}

// HOTP verifies a counter-based code as the second factor (MFA-013), only in
// realms that list hotp in allowed_factors.
func (s *Service) HOTP(ctx context.Context, realmID, id string, p Proof, code string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		switch {
		case r.upgrade && r.hasHOTP:
			// An upgrade proof under the phishing-resistant profile (below).
		case r.phishingResistant:
			return nil, problem.ErrUnexpectedStep.WithDetail("a phishing-resistant authenticator is required")
		case !r.hasHOTP:
			return nil, problem.ErrUnexpectedStep.WithDetail("no counter-based token is usable in this realm")
		}
		if err := s.offered(ctx, tx, t, "hotp"); err != nil {
			return nil, err
		}
		if err := s.verifyBudget(ctx, t.RealmID, t.UserID, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		credID, ok, err := s.VerifyHOTPTx(ctx, tx, t.UserID, code, rlm.Policy.MFA.HOTPLookAhead())
		if err != nil {
			return nil, err
		}
		if !ok {
			_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.failed", RealmID: t.RealmID, Actor: actorFor(t),
				Subject: &audit.Ref{Type: "user", ID: t.UserID}, Outcome: audit.Failure})
			return nil, errProof(problem.ErrInvalidProof)
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.used", RealmID: t.RealmID, Actor: actorFor(t),
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, Metadata: map[string]any{"credential_id": credID, "upgrade_proof": r.upgrade}}); err != nil {
			return nil, err
		}
		if r.upgrade {
			return nil, s.recordUpgradeProof(ctx, tx, t, "hotp", credID)
		}
		t.Factors = append(t.Factors, session.Factor{Type: "hotp", At: s.d.Now(), CredentialID: credID})
		return nil, nil
	})
}

// RecoveryCode uses a recovery code as the second factor. The resulting session is
// recovery-restricted until stronger assurance is restored (MFA-010).
func (s *Service) RecoveryCode(ctx context.Context, realmID, id string, p Proof, code string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		switch {
		case r.upgrade && r.hasRecovery:
			// An upgrade proof under the phishing-resistant profile (below).
		case r.phishingResistant:
			return nil, problem.ErrUnexpectedStep.WithDetail("a phishing-resistant authenticator is required")
		case !r.hasRecovery:
			return nil, problem.ErrUnexpectedStep.WithDetail("recovery codes are not available")
		}
		if err := s.offered(ctx, tx, t, "recovery_code"); err != nil {
			return nil, err
		}
		if err := s.verifyBudget(ctx, t.RealmID, t.UserID, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		ok, remaining, err := s.ConsumeRecoveryCodeTx(ctx, tx, t.UserID, code)
		if err != nil {
			return nil, err
		}
		if !ok {
			_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.recovery_code.failed", RealmID: t.RealmID, Actor: actorFor(t),
				Subject: &audit.Ref{Type: "user", ID: t.UserID}, Outcome: audit.Failure})
			return nil, errProof(problem.ErrInvalidProof)
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.recovery_code.used", RealmID: t.RealmID, Actor: actorFor(t),
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, Metadata: map[string]any{"recovery_codes_remaining": remaining, "upgrade_proof": r.upgrade}}); err != nil {
			return nil, err
		}
		if r.upgrade {
			if err := s.recordUpgradeProof(ctx, tx, t, "recovery_code", ""); err != nil {
				return nil, err
			}
		} else {
			t.Factors = append(t.Factors, session.Factor{Type: "recovery", At: s.d.Now()})
		}
		return nil, s.notifySecurity(ctx, tx, t.RealmID, t.UserID, notification.TplRecovery, "a recovery code was used to sign in")
	})
}

// EnrollTOTP begins TOTP enrollment inside the transaction (required action).
func (s *Service) EnrollTOTP(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		if r.phishingResistant {
			// Only a passkey meets the profile (SEC-012); a TOTP enrolled
			// here would also replace the account's recovery codes.
			return nil, problem.ErrUnexpectedStep.WithDetail("a phishing-resistant authenticator is required")
		}
		if !slices.Contains(r.actions, identity.ActionConfigureTOTP) || r.totpDisallowed {
			return nil, problem.ErrUnexpectedStep
		}
		if err := s.offered(ctx, tx, t, "enroll_totp"); err != nil {
			return nil, err
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		account := r.user.Username()
		if e := r.user.PrimaryEmail(); e != nil {
			account = e.Value
		}
		en, err := s.BeginTOTPTx(ctx, tx, t.RealmID, t.UserID, rlm.DisplayName, account)
		if err != nil {
			return nil, err
		}
		t.Pending.PendingTOTPCredential = en.CredentialID
		return map[string]any{"totp": en}, nil
	})
}

// ActivateTOTP completes enrollment with a proof; it also counts as the second factor.
func (s *Service) ActivateTOTP(ctx context.Context, realmID, id string, p Proof, code string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) || t.Pending.PendingTOTPCredential == "" {
			return nil, problem.ErrUnexpectedStep
		}
		// Activation replaces the account's TOTP and recovery codes: it is
		// open only while enrollment is (the profile and the factor policy
		// can change after totp/enroll).
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		if r.phishingResistant {
			return nil, problem.ErrUnexpectedStep.WithDetail("a phishing-resistant authenticator is required")
		}
		if err := s.offered(ctx, tx, t, "enroll_totp"); err != nil {
			return nil, err
		}
		codes, credID, err := s.ActivateTOTPTx(ctx, tx, t.RealmID, t.UserID, code, s.d.Cfg.Security.RecoveryCodeCount)
		if err != nil {
			return nil, err
		}
		t.Pending.PendingTOTPCredential = ""
		t.Factors = append(t.Factors, session.Factor{Type: "totp", At: s.d.Now(), CredentialID: credID})
		t.ActionsDone = append(t.ActionsDone, identity.ActionConfigureTOTP)
		return map[string]any{"recovery_codes": codes}, nil
	})
}

// UpdatePassword satisfies the update_password required action.
func (s *Service) UpdatePassword(ctx context.Context, realmID, id string, p Proof, newPassword string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		if r.user == nil || !slices.Contains(r.actions, identity.ActionUpdatePassword) {
			return nil, problem.ErrUnexpectedStep
		}
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		words := []string{r.user.Username()}
		if e := r.user.PrimaryEmail(); e != nil {
			words = append(words, e.Value, strings.Split(e.Value, "@")[0])
		}
		if err := s.SetPasswordTx(ctx, tx, t.RealmID, t.UserID, newPassword, rlm.Policy.Password.MinLength, rlm.Policy.Password.HistoryCount, words...); err != nil {
			return nil, err
		}
		t.ActionsDone = append(t.ActionsDone, identity.ActionUpdatePassword)
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.changed", RealmID: t.RealmID, Actor: actorFor(t),
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, ReasonCode: "REQUIRED_ACTION"}); err != nil {
			return nil, err
		}
		return nil, s.notifySecurity(ctx, tx, t.RealmID, t.UserID, notification.TplPasswordChanged, "password updated")
	})
}

// AcceptTerms records terms acceptance with provenance (REG-006).
func (s *Service) AcceptTerms(ctx context.Context, realmID, id string, p Proof, version string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if t.UserID == "" || !primaryDone(t) || rlm.Policy.Registration.TermsVersion == "" {
			return nil, problem.ErrUnexpectedStep
		}
		// A pending-deletion account can only cancel the deletion (USR-012).
		if u, err := s.Users.User(ctx, tx, t.RealmID, t.UserID); err != nil {
			return nil, err
		} else if u.State == identity.StatePendingDeletion {
			return nil, problem.ErrUnexpectedStep
		}
		if version != rlm.Policy.Registration.TermsVersion {
			return nil, problem.ErrValidation.WithField("version", "must match the current terms version")
		}
		if err := s.recordTerms(ctx, tx, t, version, "required_action"); err != nil {
			return nil, err
		}
		t.ActionsDone = append(t.ActionsDone, identity.ActionAcceptTerms)
		return nil, nil
	})
}

func (s *Service) recordTerms(ctx context.Context, tx pgx.Tx, t *Transaction, version, provenance string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO terms_acceptances (id, realm_id, user_id, document, version, provenance, client_id, accepted_at)
		VALUES ($1,$2,$3,'terms',$4,$5,$6,$7)`, ids.New(ids.Terms), t.RealmID, t.UserID, version, provenance, t.ClientRef, s.d.Now()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET required_actions=array_remove(required_actions, 'accept_terms') WHERE id=$1`, t.UserID); err != nil {
		return err
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.terms.accepted", RealmID: t.RealmID, Actor: actorFor(t),
		Subject: &audit.Ref{Type: "user", ID: t.UserID}, Category: "account", Metadata: map[string]any{"version": version, "provenance": provenance}})
	return err
}

// CompleteProfile supplies missing user-editable attributes (REG-007).
func (s *Service) CompleteProfile(ctx context.Context, realmID, id string, p Proof, fields map[string]any) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		schema := s.schema(t.RealmID)
		if schema == nil {
			return nil, problem.ErrUnexpectedStep
		}
		u, err := s.Users.LockUser(ctx, tx, t.RealmID, t.UserID)
		if err != nil {
			return nil, err
		}
		if u.State == identity.StatePendingDeletion {
			return nil, problem.ErrUnexpectedStep // only cancel_deletion (USR-012)
		}
		if perr := schema.ValidateSelfEdit(u.Profile, fields); perr != nil {
			return nil, perr
		}
		if s.Hooks != nil {
			if err := s.Hooks.CheckProfile(ctx, t.RealmID, t.UserID, fields); err != nil {
				return nil, err
			}
		}
		for k, v := range fields {
			u.Profile[k] = v
		}
		if !schema.Complete(u.Profile) {
			return nil, problem.ErrValidation.WithDetail("required attributes are still missing")
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET profile=$2, required_actions=array_remove(required_actions, 'complete_profile'), version=version+1 WHERE id=$1`,
			t.UserID, u.Profile); err != nil {
			return nil, err
		}
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		slices.Sort(names)
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.profile.completed", RealmID: t.RealmID, Category: "account",
			Actor: audit.Ref{Type: "user", ID: t.UserID}, Subject: &audit.Ref{Type: "user", ID: t.UserID},
			Metadata: map[string]any{"attributes": names}}); err != nil {
			return nil, err
		}
		t.ActionsDone = append(t.ActionsDone, identity.ActionCompleteProfile)
		return nil, nil
	})
}

// SelectOrganization binds the transaction to one organization after checking
// active membership (TEN-005). The list offered contains only the caller's own
// memberships and only after authentication (DOM-008).
func (s *Service) SelectOrganization(ctx context.Context, realmID, id string, p Proof, orgID string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		if _, err := s.Orgs.ActiveMembership(ctx, tx, t.RealmID, orgID, t.UserID); err != nil {
			return nil, problem.ErrForbidden.WithDetail("no active membership in that organization")
		}
		if s.ForeignConnection(ctx, tx, t.RealmID, t.Factors, orgID) {
			return nil, problem.ErrForbidden.WithDetail("the connection used to sign in belongs to another organization")
		}
		t.SelectedOrgID = orgID
		return nil, nil
	})
}

// Consent records the user's decision. Granted scopes must be a subset of the
// requested scopes; consent never expands the request (§27.3).
func (s *Service) Consent(ctx context.Context, realmID, id string, p Proof, approve bool, scopes []string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		if !approve {
			t.Status = StatusCancelled
			t.Pending.ErrorCode = "access_denied"
			if t.DeviceCodeID != "" {
				if _, err := tx.Exec(ctx, `UPDATE device_codes SET state='denied' WHERE id=$1 AND state='pending'`, t.DeviceCodeID); err != nil {
					return nil, err
				}
			}
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "consent.denied", RealmID: t.RealmID, Actor: actorFor(t),
				Subject: &audit.Ref{Type: "user", ID: t.UserID}, ClientID: t.ClientRef})
			return nil, err
		}
		granted := t.Scopes
		if len(scopes) > 0 {
			for _, sc := range scopes {
				if !slices.Contains(t.Scopes, sc) {
					return nil, problem.ErrValidation.WithField("scopes", "cannot grant scopes that were not requested")
				}
			}
			granted = scopes
			if slices.Contains(t.Scopes, "openid") && !slices.Contains(granted, "openid") {
				granted = append([]string{"openid"}, granted...)
			}
		}
		t.GrantedScopes = granted
		t.ConsentDecided = true
		return nil, nil
	})
}

// Cancel cancels the transaction (AUT-008).
func (s *Service) Cancel(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		t.Status = StatusCancelled
		t.Pending.ErrorCode = "access_denied"
		return nil, nil
	})
}

// TransientSessionMax bounds transient session lifetime.
const TransientSessionMax = time.Hour

// SelectAccount answers prompt=select_account: continue with the signed-in
// account, or switch to sign in as someone else (OIDC-005).
func (s *Service) SelectAccount(ctx context.Context, realmID, id string, p Proof, keep bool) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if !t.hasPrompt("select_account") || t.ReusedSessionID == "" || slices.Contains(t.ActionsDone, "select_account") {
			return nil, problem.ErrUnexpectedStep
		}
		if keep {
			t.ActionsDone = append(t.ActionsDone, "select_account")
			return nil, nil
		}
		t.UserID, t.Factors, t.AuthTime, t.ReusedSessionID = "", nil, nil, ""
		t.Pending.Identifier, t.Pending.IdentifierType = "", ""
		t.ActionsDone = append(t.ActionsDone, "select_account")
		return nil, nil
	})
}

// SetTransient requests a transient (non-persistent) session (SES-020).
func (s *Service) SetTransient(ctx context.Context, realmID, id string, p Proof, transient bool) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		t.Pending.Transient = transient
		if transient {
			t.RememberMe = false
		}
		return nil, nil
	})
}

// SetRememberMe records an explicit remember-me request (SES-012).
func (s *Service) SetRememberMe(ctx context.Context, realmID, id string, p Proof, remember bool) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		t.RememberMe = remember
		return nil, nil
	})
}

// ErrorRedirect builds the error redirect for a cancelled/failed transaction.
func (s *Service) ErrorRedirect(ctx context.Context, realmID, id string, p Proof) (string, error) {
	t, err := s.get(ctx, s.d.DB.Pool, realmID, id)
	if err != nil {
		return "", err
	}
	if !matchesContinuation(t, p) {
		return "", problem.ErrTransactionInvalid
	}
	if t.Status != StatusCancelled && t.Status != StatusFailed || t.RedirectURI == "" {
		return "", nil
	}
	rlm, err := s.Realms.ByID(ctx, nil, realmID)
	if err != nil {
		return "", err
	}
	code := t.Pending.ErrorCode
	if code == "" || code == "too_many_failures" {
		code = "access_denied"
	}
	return s.respond(ctx, t, map[string]string{"error": code, "state": t.State, "iss": rlm.Issuer})
}

// respond builds the client's authorization response in the transaction's
// response mode: query parameters, or a JWT for JARM modes (ADV-002).
func (s *Service) respond(ctx context.Context, t *Transaction, params map[string]string) (string, error) {
	if s.AuthorizationResponse != nil && t.ResponseMode != "" && t.ResponseMode != "query" {
		return s.AuthorizationResponse(ctx, t.RealmID, t.ClientRef, t.ResponseMode, t.RedirectURI, params)
	}
	return BuildRedirect(t.RedirectURI, params), nil
}

func matchesContinuation(t *Transaction, p Proof) bool {
	return p.Continuation != "" && t.ContinuationDigest == digest(p.Continuation)
}

// loginMethodOf maps a primary factor to the organization policy method name.
// LoginMethodOf names the sign-in method a primary factor belongs to, as
// used by organization allowed_login_methods (TEN-012).
func LoginMethodOf(factor string) string { return loginMethodOf(factor) }

func loginMethodOf(factor string) string {
	switch factor {
	case "pwd":
		return "password"
	case "hwk", "swk":
		return "passkey"
	case "otp":
		return "email_otp"
	case "magic_link":
		return "magic_link"
	case "sms":
		return "sms_otp"
	case "fed":
		return "sso"
	case "x509":
		return "certificate"
	}
	return ""
}

func primaryDone(t *Transaction) bool {
	for _, f := range t.Factors {
		switch f.Type {
		case "pwd", "otp", "magic_link", "fed", "hwk", "swk", "sms", "anon", "x509":
			return true
		}
	}
	return false
}

// BuildRedirect appends response parameters to a prevalidated redirect URI (AUT-020).
func BuildRedirect(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ---------- completion ----------

// complete creates/reuses the session, persists the grant and issues the
// authorization code, all in the caller's transaction (AUT-006).
func (s *Service) complete(ctx context.Context, tx pgx.Tx, t *Transaction) (*Completion, error) {
	rlm, err := s.Realms.LockActive(ctx, tx, t.RealmID)
	if err != nil {
		return nil, err
	}
	client, err := s.Apps.ClientByRef(ctx, tx, t.RealmID, t.ClientRef)
	if err != nil {
		return nil, err
	}
	if !client.Active() {
		return nil, problem.ErrTransactionInvalid.WithDetail("client is not active")
	}
	u, err := s.Users.LockUser(ctx, tx, t.RealmID, t.UserID)
	if err != nil {
		return nil, err
	}
	if !u.CanAuthenticate(s.d.Now()) {
		return nil, problem.ErrAccountState
	}
	// Defense in depth: re-evaluate every requirement before issuing anything.
	r, err := s.evaluate(ctx, tx, t)
	if err != nil {
		return nil, err
	}
	if !r.primaryDone || r.selectAccount || len(r.actions) > 0 || r.needOrg || r.needConsent || r.ssoRequired || r.blocked != "" || r.challenge ||
		r.cancelDeletion || (r.mfaRequired && !r.mfaDone) {
		return nil, problem.ErrTransactionInvalid.WithDetail("authentication requirements are incomplete")
	}
	if err := s.acceptPendingInvitation(ctx, tx, t); err != nil {
		return nil, err
	}
	var orgPolicyIdle, orgPolicyAbs time.Duration
	if t.SelectedOrgID != "" {
		org, err := s.Orgs.LockActiveTx(ctx, tx, t.RealmID, t.SelectedOrgID)
		if err != nil {
			return nil, err
		}
		if _, err := s.Orgs.ActiveMembership(ctx, tx, t.RealmID, t.SelectedOrgID, t.UserID); err != nil {
			return nil, problem.ErrForbidden.WithDetail("membership is not active")
		}
		orgPolicyIdle = time.Duration(org.Policy.SessionIdleSeconds) * time.Second
		orgPolicyAbs = time.Duration(org.Policy.SessionAbsoluteSeconds) * time.Second
	}
	now := s.d.Now()
	idle, abs := rlm.Policy.SessionBounds(s.d.Cfg.Sessions.IdleTimeout, s.d.Cfg.Sessions.AbsoluteTimeout)
	remember := t.RememberMe && client.AllowRememberMe
	if remember {
		// Remember-me lengthens the operator defaults but never an explicit
		// realm bound (SES-002, SES-012).
		idle, abs = rlm.Policy.SessionBounds(s.d.Cfg.Sessions.RememberMeIdle, s.d.Cfg.Sessions.RememberMeAbsolute)
	}
	if orgPolicyIdle > 0 && orgPolicyIdle < idle {
		idle = orgPolicyIdle
	}
	if orgPolicyAbs > 0 && orgPolicyAbs < abs {
		abs = orgPolicyAbs
	}
	// A session whose second factor was a recovery code is restricted, and so
	// is the account until a strong factor is used again (MFA-010, USR-003).
	usedRecovery := slices.ContainsFunc(t.Factors, func(f session.Factor) bool { return f.Type == "recovery" })
	strongFactor := slices.ContainsFunc(t.Factors, func(f session.Factor) bool {
		return f.Type == "totp" || f.Type == "hotp" || f.Type == "hwk" || f.Type == "swk"
	})
	recoveryRestricted := usedRecovery && !strongFactor
	if acct, err := s.Users.User(ctx, tx, t.RealmID, t.UserID); err != nil {
		return nil, err
	} else if recoveryRestricted && acct.State == identity.StateActive {
		if _, err := s.Users.SetStateTx(ctx, tx, t.RealmID, t.UserID, identity.StateRecoveryRestricted, audit.Ref{Type: "user", ID: t.UserID}, "RECOVERY_CODE_USED"); err != nil {
			return nil, err
		}
	} else if strongFactor && acct.State == identity.StateRecoveryRestricted {
		if _, err := s.Users.SetStateTx(ctx, tx, t.RealmID, t.UserID, identity.StateActive, audit.Ref{Type: "user", ID: t.UserID}, "FACTOR_ASSURANCE_RESTORED"); err != nil {
			return nil, err
		}
	}
	var sess *session.Session
	var cookie string
	if t.ReusedSessionID != "" {
		existing, err := s.Sessions.Active(ctx, tx, t.RealmID, t.ReusedSessionID)
		if err == nil && existing.UserID == t.UserID {
			newFactors := []session.Factor{}
			for _, f := range t.Factors {
				if f.At.After(existing.AuthTime) && !slices.ContainsFunc(existing.Factors, func(e session.Factor) bool { return e.Type == f.Type && e.At.Equal(f.At) }) {
					newFactors = append(newFactors, f)
				}
			}
			if len(newFactors) > 0 {
				fresh := slices.ContainsFunc(newFactors, func(f session.Factor) bool {
					return f.Type == "pwd" || f.Type == "otp" || f.Type == "hwk" || f.Type == "swk"
				})
				if sess, err = s.Sessions.StepUpTx(ctx, tx, existing.ID, newFactors, fresh); err != nil {
					return nil, err
				}
				// Privilege change: rotate the browser handle (AUT-007).
				if t.Mode == "browser" {
					if cookie, err = s.Sessions.RotateCookieTx(ctx, tx, existing.ID); err != nil {
						return nil, err
					}
				}
			} else {
				sess = existing
				if err := s.Sessions.TouchTx(ctx, tx, existing.ID, idle); err != nil {
					return nil, err
				}
			}
		}
	}
	if sess == nil {
		authTime := now
		if t.AuthTime != nil {
			authTime = *t.AuthTime
		}
		if t.Pending.Transient {
			// Transient sessions are short and never persistent (SES-020).
			remember = false
			if abs > TransientSessionMax {
				abs = TransientSessionMax
			}
			if idle > abs {
				idle = abs
			}
		}
		sess, cookie, err = s.Sessions.CreateTx(ctx, tx, session.CreateInput{RealmID: t.RealmID, UserID: t.UserID, AuthTime: authTime,
			Factors: t.Factors, RecoveryRestricted: recoveryRestricted, RememberMe: remember, Idle: idle, Absolute: abs, Transient: t.Pending.Transient,
			MaxConcurrent: rlm.Policy.MaxConcurrentSessions(s.d.Cfg.Sessions.MaxConcurrent), ClientIP: t.ClientIP, UserAgent: t.UserAgent, WithCookie: t.Mode == "browser"})
		if err != nil {
			return nil, err
		}
	}
	granted := t.Scopes
	if t.GrantedScopes != nil {
		granted = t.GrantedScopes
	}
	consentID := ""
	if t.ConsentDecided {
		if _, err := tx.Exec(ctx, `UPDATE consents SET revoked_at=$3 WHERE user_id=$1 AND client_ref=$2 AND revoked_at IS NULL`, t.UserID, t.ClientRef, now); err != nil {
			return nil, err
		}
		consentID = ids.New(ids.Consent)
		if _, err := tx.Exec(ctx, `INSERT INTO consents (id, realm_id, user_id, client_ref, scopes, resource_ids, granted_at, terms_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, consentID, t.RealmID, t.UserID, t.ClientRef, granted, nonNil(t.ResourceIDs), now,
			nilIfEmpty(client.ConsentTermsVersion)); err != nil {
			return nil, err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "consent.granted", RealmID: t.RealmID, Actor: actorFor(t),
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, Metadata: map[string]any{"client_ref": t.ClientRef, "scopes": granted}}); err != nil {
			return nil, err
		}
	}
	if !t.ConsentDecided && client.ConsentMode == "required" {
		// Covered without asking: the grant rests on the user's own live
		// consent, or on a consent recorded for the administrative
		// pre-authorization that covers it, so revoking either ends the grant
		// (APP-013; ConsentBasisTx, shared with the organization switch).
		req := t.consentRequest(client, t.UserID, granted)
		cov, err := s.CheckConsentCoverage(ctx, tx, req)
		if err != nil {
			return nil, err
		}
		if consentID, err = s.ConsentBasisTx(ctx, tx, req, cov, t.ResourceIDs); err != nil {
			return nil, err
		}
	}
	// A transient session ("this is a shared computer") never yields offline
	// access, which would outlive it (SES-020).
	// That holds for a sign-in that reused a transient SSO session too.
	offline := slices.Contains(granted, "offline_access") && client.AllowOfflineAccess && !t.Pending.Transient && !sess.Transient
	if !offline {
		granted = slices.DeleteFunc(slices.Clone(granted), func(s string) bool { return s == "offline_access" })
	}
	expires := sess.AbsoluteExpiresAt
	if offline {
		expires = now.Add(s.d.Cfg.Sessions.OfflineAbsolute)
	}
	authTime := sess.AuthTime
	g := &session.Grant{RealmID: t.RealmID, SubjectType: "user", SubjectID: t.UserID, ClientRef: t.ClientRef, OrgID: t.SelectedOrgID,
		SessionID: sess.ID, ResourceIDs: nonNil(t.ResourceIDs), Scopes: granted, Offline: offline, ConsentID: consentID,
		AuthTime: &authTime, AMR: sess.AMR, ACR: sess.ACR, ExpiresAt: expires, ClaimsRequest: t.Pending.ClaimsRequest}
	if err := s.Sessions.CreateGrantTx(ctx, tx, g); err != nil {
		return nil, err
	}
	comp := &Completion{SessionID: sess.ID, SessionCookie: cookie, GrantID: g.ID, Transient: sess.Transient}
	if r.deviceRemembered != "" {
		if _, err := tx.Exec(ctx, `UPDATE remembered_devices SET last_used_at=$2 WHERE id=$1`, r.deviceRemembered, now); err != nil {
			return nil, err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.device.used", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: t.UserID},
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, Target: &audit.Ref{Type: "remembered_device", ID: r.deviceRemembered}}); err != nil {
			return nil, err
		}
	}
	if rd, err := s.issueRememberedDevice(ctx, tx, t, rlm); err != nil {
		return nil, err
	} else {
		comp.RememberedDevice = rd
	}
	if t.DeviceCodeID != "" {
		tag, err := tx.Exec(ctx, `UPDATE device_codes SET state='approved', grant_id=$2, user_id=$3 WHERE id=$1 AND state='pending' AND expires_at > $4`,
			t.DeviceCodeID, g.ID, t.UserID, now)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, problem.ErrTransactionExpired.WithDetail("the device request expired")
		}
	} else {
		codeTTL := s.d.Cfg.Tokens.AuthorizationCodeTTL
		if client.FAPI2() && codeTTL > time.Minute {
			codeTTL = time.Minute // FAPI 2.0: codes live at most 60 seconds (ADV-001)
		}
		code, err := s.Sessions.IssueCodeTx(ctx, tx, t.RealmID, session.Code{ClientRef: t.ClientRef, TransactionID: t.ID, GrantID: g.ID,
			RedirectURI: t.RedirectURI, Challenge: t.CodeChallenge, Method: t.CodeChallengeMethod, Nonce: t.Nonce, DPoPJKT: t.Pending.DPoPJKT}, codeTTL)
		if err != nil {
			return nil, err
		}
		comp.Code = code
		params := map[string]string{"code": code, "state": t.State, "iss": rlm.Issuer}
		if rlm.Policy.Sessions.CheckSessionIframe {
			// OpenID Connect Session Management (OIDC-014).
			params["session_state"] = session.SessionState(client.ClientID, t.RedirectURI, session.BrowserState(s.d.Keys, sess.ID))
		}
		if comp.RedirectTo, err = s.respond(ctx, t, params); err != nil {
			return nil, err
		}
	}
	if err := s.Sessions.RecordClientSessionTx(ctx, tx, t.RealmID, sess.ID, t.ClientRef); err != nil {
		return nil, err
	}
	if err := s.Users.RecordLoginTx(ctx, tx, t.UserID); err != nil {
		return nil, err
	}
	amr, _ := session.AMRFromFactors(t.Factors)
	// Sign-ins of protected (platform administrator, break-glass) accounts are
	// alertable (AUD-012).
	var protected bool
	_ = tx.QueryRow(ctx, `SELECT protected FROM users WHERE id=$1`, t.UserID).Scan(&protected)
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.succeeded", RealmID: t.RealmID, OrgID: t.SelectedOrgID,
		Actor: audit.Ref{Type: "user", ID: t.UserID, SessionID: sess.ID}, Subject: &audit.Ref{Type: "user", ID: t.UserID},
		ClientID: client.ClientID, SessionID: sess.ID, GrantID: g.ID, Metadata: map[string]any{"amr": amr, "acr": sess.ACR,
			"session_reused": t.ReusedSessionID != "" && sess.ID == t.ReusedSessionID, "recovery_restricted": sess.RecoveryRestricted,
			"protected": protected}}); err != nil {
		return nil, err
	}
	// Required actions completed during the sign-in are evidence of their own
	// (AUT-018): which forced changes the account went through, and when.
	var done []string
	for _, a := range t.ActionsDone {
		if identity.ValidRequiredAction(a) && !slices.Contains(done, a) {
			done = append(done, a)
		}
	}
	if len(done) > 0 {
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.required_actions.completed", RealmID: t.RealmID, OrgID: t.SelectedOrgID,
			Actor: audit.Ref{Type: "user", ID: t.UserID, SessionID: sess.ID}, Subject: &audit.Ref{Type: "user", ID: t.UserID}, ClientID: client.ClientID,
			SessionID: sess.ID, Category: "account", Metadata: map[string]any{"actions": done, "transaction_id": t.ID}}); err != nil {
			return nil, err
		}
	}
	if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "user.signed_in", RealmID: t.RealmID, OrgID: t.SelectedOrgID,
		AggregateType: "user", AggregateID: t.UserID, Data: map[string]any{"user_id": t.UserID, "session_id": sess.ID, "client_id": client.ClientID}}); err != nil {
		return nil, err
	}
	if rlm.Policy.Notifications.NewLoginAlerts && sess.ID != t.ReusedSessionID {
		info := reqctx.From(ctx)
		_ = s.notifySecurityData(ctx, tx, t.RealmID, t.UserID, notification.TplNewLogin, map[string]string{
			"time": notification.Timestamp(now), "network": reqctx.NetworkContext(info.ClientIP, false), "device": truncate(t.UserAgent, 80)})
	}
	t.Status = StatusCompleted
	t.SessionID = sess.ID
	t.CompletedAt = &now
	if err := s.save(ctx, tx, t); err != nil {
		return nil, err
	}
	return comp, nil
}

func (s *Service) notifySecurityData(ctx context.Context, tx pgx.Tx, realmID, userID, tpl string, data map[string]string) error {
	var email, realmName string
	if err := tx.QueryRow(ctx, `SELECT i.original_value, r.display_name FROM user_identifiers i JOIN realms r ON r.id=i.realm_id
		WHERE i.user_id=$1 AND i.type='email' AND i.verified_at IS NOT NULL ORDER BY i.is_primary DESC LIMIT 1`, userID).Scan(&email, &realmName); err != nil {
		return nil
	}
	data["realm"] = realmName
	_, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, Template: tpl, Recipient: email, Mandatory: false,
		ReferenceType: "user", ReferenceID: userID, Data: data})
	return err
}

// afterRegistrationVerified performs one-time registration effects: organization
// creation (§27.1) and invitation acceptance for new accounts (INV-006).
func (s *Service) afterRegistrationVerified(ctx context.Context, tx pgx.Tx, t *Transaction) error {
	if t.Intent != "register" {
		return nil
	}
	if t.Pending.CreateOrganization != nil {
		in := *t.Pending.CreateOrganization
		org, err := s.Orgs.CreateTx(ctx, tx, t.RealmID, in, t.UserID, audit.Ref{Type: "user", ID: t.UserID})
		if err != nil {
			return err
		}
		t.Pending.CreateOrganization = nil // a retried completion cannot create another organization
		if t.SelectedOrgID == "" {
			t.SelectedOrgID = org.ID
		}
	}
	return nil
}

// acceptPendingInvitation accepts a registration invitation once every other
// requirement of the transaction is met (INV-006): membership never precedes
// MFA, required actions or consent.
func (s *Service) acceptPendingInvitation(ctx context.Context, tx pgx.Tx, t *Transaction) error {
	if len(t.Pending.InvitationSecretCT) > 0 {
		pt, err := s.d.Keys.Decrypt(keys.PurposeData, t.Pending.InvitationSecretCT, []byte("invitation:"+t.ID))
		if err != nil {
			return err
		}
		res, err := s.Orgs.AcceptTx(ctx, tx, t.RealmID, string(pt), t.UserID, audit.Ref{Type: "user", ID: t.UserID})
		t.Pending.InvitationSecretCT = nil
		if err != nil {
			// An invitation that is no longer valid does not block account creation;
			// the denial is audited and no membership is granted.
			if problem.Is(err, problem.ErrInvitationInvalid) {
				return nil
			}
			return err
		}
		if t.SelectedOrgID == "" && res.MembershipID != "" {
			t.SelectedOrgID = res.OrganizationID
		}
	}
	return nil
}

var _ = application.KindBusiness
