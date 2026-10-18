package authentication

import (
	"context"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

// MagicLinkTTL bounds magic-link validity.
const MagicLinkTTL = 10 * time.Minute

// magicLinkBase returns the login UI that receives magic links, or "".
func (s *Service) magicLinkBase(ctx context.Context, q storage.Querier, t *Transaction, rlm *realm.Realm) string {
	if c, err := s.Apps.ClientByRef(ctx, q, t.RealmID, t.ClientRef); err == nil && c.LoginUIURL != "" {
		return c.LoginUIURL
	}
	return rlm.Policy.Interaction.LoginUIURL
}

// sendMagicLink issues a single-use, high-entropy sign-in link bound to this
// transaction (PWDLESS-002, PWDLESS-003). The secret travels in the URL fragment,
// so link scanners that fetch the page never see or consume it; the login UI
// must post it back with the transaction's continuation proof after the user
// confirms. A link opened in another browser therefore cannot complete the
// sign-in (no silent cross-device relaxation). Responses are identical whether
// or not an account exists, and padded to the same minimum time (padSend,
// SEC-005).
func (s *Service) sendMagicLink(ctx context.Context, tx pgx.Tx, t *Transaction, rlm *realm.Realm) error {
	if !rlm.Policy.Login.MagicLink || t.Pending.IdentifierType != "email" {
		return problem.ErrUnexpectedStep
	}
	base := s.magicLinkBase(ctx, tx, t, rlm)
	if base == "" {
		return problem.ErrFeatureDisabled.WithDetail("magic links require a configured login UI")
	}
	defer s.padSend(time.Now())
	if err := s.sendBudget(ctx, t.RealmID, t.Pending.Identifier, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
		return err
	}
	userID := ""
	// A pending-deletion account may sign in to cancel (USR-012).
	if u, err := s.Users.FindByLogin(ctx, t.RealmID, "email", t.Pending.Identifier); err == nil && (u.CanAuthenticate(s.d.Now()) || u.MayCancelDeletion(s.d.Now())) {
		userID = u.ID
	}
	// While an external identity waits to be linked, the link is bound to
	// that link and its message says so (PWDLESS-008).
	tpl, data, meta, err := s.linkProof(ctx, tx, t, notification.TplMagicLink, map[string]string{"realm": rlm.DisplayName,
		"expires_minutes": minutes(MagicLinkTTL)})
	if err != nil {
		return err
	}
	cid, plain, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: t.RealmID, Purpose: PurposeMagicLink, TransactionID: t.ID, UserID: userID,
		IdentifierType: "email", Identifier: t.Pending.Identifier, Kind: "link", TTL: MagicLinkTTL, MaxAttempts: 3, Metadata: meta})
	if err != nil {
		return err
	}
	if userID == "" {
		return nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return problem.ErrInternal
	}
	q := u.Query()
	q.Set("transaction_id", t.ID)
	u.RawQuery = q.Encode()
	u.Fragment = "magic_link=" + url.QueryEscape(plain)
	data["link"] = u.String()
	_, err = s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: t.RealmID, Template: tpl, Locale: t.UILocales,
		Recipient: t.Pending.Identifier, Mandatory: true, ReferenceType: "challenge", ReferenceID: cid, TTL: MagicLinkTTL, UserID: userID,
		Data: data})
	return err
}

// padSend pads an emailed or texted sign-in code or a magic link
// (otp/send with purpose login or magic_link) to security.min_auth_response,
// so the work done only for a known account (rendering, localizing,
// encrypting and queueing the message) does not tell it from an unknown
// identifier, as the password step and reset requests are padded (SEC-005).
func (s *Service) padSend(start time.Time) {
	if s.TimingPad != nil {
		s.TimingPad(start, s.d.Cfg.Security.MinAuthResponse)
		return
	}
	padTiming(start, s.d.Cfg.Security.MinAuthResponse)
}

// ConsumeMagicLink completes sign-in with a magic-link secret presented to the
// same transaction that requested it.
func (s *Service) ConsumeMagicLink(ctx context.Context, realmID, id string, p Proof, token string) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		subject := t.UserID
		if subject == "" {
			subject = t.Pending.Identifier
		}
		if err := s.verifyBudget(ctx, t.RealmID, subject, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		c, err := s.ConsumeLinkTx(ctx, tx, t.RealmID, PurposeMagicLink, token)
		if err != nil {
			return nil, err
		}
		if c.TransactionID != t.ID || c.UserID == "" || !linkProofMatches(t, c) {
			// A link from another transaction (or for an unknown address, or
			// sent for another purpose than a pending account link) is burned
			// and refused.
			return nil, errProof(problem.ErrInvalidProof)
		}
		if t.UserID != "" && t.UserID != c.UserID {
			return nil, problem.ErrTransactionInvalid
		}
		u, err := s.Users.User(ctx, tx, t.RealmID, c.UserID)
		if err != nil {
			return nil, err
		}
		if !u.CanAuthenticate(s.d.Now()) && !u.MayCancelDeletion(s.d.Now()) {
			return nil, errProof(problem.ErrInvalidCredentials)
		}
		now := s.d.Now()
		t.UserID = c.UserID
		t.IdentifiedVia = "email"
		t.Factors = append(t.Factors, session.Factor{Type: "magic_link", At: now})
		t.AuthTime = &now
		return nil, nil
	})
}
