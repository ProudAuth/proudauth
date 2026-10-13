package authentication

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
)

// RegistrationApproval is a queued self-registration (REG-008).
type RegistrationApproval struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	EmailHint  string     `json:"email_hint,omitempty"`
	State      string     `json:"state"`
	ReviewerID string     `json:"reviewer_id,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// RegistrationApprovals lists the queue, optionally by state.
func (s *Service) RegistrationApprovals(ctx context.Context, realmID, state string) ([]RegistrationApproval, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT a.id, a.user_id, coalesce((SELECT original_value FROM user_identifiers i WHERE i.user_id=a.user_id AND i.type='email'
		ORDER BY i.is_primary DESC LIMIT 1),''), a.state, coalesce(a.reviewer_id,''), coalesce(a.reason,''), a.expires_at, a.decided_at, a.created_at
		FROM registration_approvals a WHERE a.realm_id=$1 AND ($2='' OR a.state=$2) ORDER BY a.created_at LIMIT 500`, realmID, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RegistrationApproval{}
	for rows.Next() {
		var a RegistrationApproval
		var email string
		if err := rows.Scan(&a.ID, &a.UserID, &email, &a.State, &a.ReviewerID, &a.Reason, &a.ExpiresAt, &a.DecidedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.EmailHint = identity.Mask("email", email)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideRegistration approves or denies a queued registration. A denied
// account is suspended; the applicant is told the outcome (REG-008).
func (s *Service) DecideRegistration(ctx context.Context, rlm *realm.Realm, id string, approve bool, reason, reviewerID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var userID, state string
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT user_id, state, expires_at FROM registration_approvals WHERE realm_id=$1 AND id=$2 FOR UPDATE`, rlm.ID, id).
			Scan(&userID, &state, &expires); err != nil {
			return problem.ErrNotFound
		}
		if state != "pending" || !s.d.Now().Before(expires) {
			return problem.ErrConflict.WithDetail("the registration is not awaiting review")
		}
		if reviewerID == userID {
			return problem.ErrForbidden.WithDetail("applicants cannot review their own registration")
		}
		decision := map[bool]string{true: "approved", false: "denied"}[approve]
		if _, err := tx.Exec(ctx, `UPDATE registration_approvals SET state=$2, reviewer_id=$3, reason=$4, decided_at=$5 WHERE id=$1`,
			id, decision, reviewerID, nilIfEmpty(reason), s.d.Now()); err != nil {
			return err
		}
		if !approve {
			if _, err := s.Users.SetStateTx(ctx, tx, rlm.ID, userID, identity.StateSuspended, actor, "registration_denied"); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "registration." + decision, RealmID: rlm.ID, Actor: actor, Category: "account",
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "registration_approval", ID: id}, ReasonCode: reason}); err != nil {
			return err
		}
		var email string
		if err := tx.QueryRow(ctx, `SELECT original_value FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL
			ORDER BY is_primary DESC LIMIT 1`, userID).Scan(&email); err == nil {
			_, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: rlm.ID, Template: notification.TplRegistrationReview, Recipient: email,
				Mandatory: true, ReferenceType: "user", ReferenceID: userID, Data: map[string]string{"realm": rlm.DisplayName, "decision": decision}})
			return err
		}
		return nil
	})
}

// ExpireRegistrationApprovals ends reviews nobody decided in time; the
// account stays unusable (suspended), never silently approved.
func (s *Service) ExpireRegistrationApprovals(ctx context.Context) (int, error) {
	n := 0
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE registration_approvals SET state='expired', decided_at=$1 WHERE id IN (SELECT id FROM registration_approvals
			WHERE state='pending' AND expires_at <= $1 LIMIT 200 FOR UPDATE SKIP LOCKED) RETURNING realm_id, user_id`, s.d.Now())
		if err != nil {
			return err
		}
		type ex struct{ realm, user string }
		var list []ex
		for rows.Next() {
			var e ex
			if err := rows.Scan(&e.realm, &e.user); err != nil {
				rows.Close()
				return err
			}
			list = append(list, e)
		}
		rows.Close()
		for _, e := range list {
			if _, err := s.Users.SetStateTx(ctx, tx, e.realm, e.user, identity.StateSuspended, audit.System, "registration_review_expired"); err != nil {
				return err
			}
		}
		n = len(list)
		return nil
	})
	return n, err
}
