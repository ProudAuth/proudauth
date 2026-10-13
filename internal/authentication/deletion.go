package authentication

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// CancelDeletion is the cancel_deletion step (USR-012). A self-service
// deletion request revokes every session, and a pending-deletion account can
// never hold a session or a token, so its owner cancels while signing in: the
// account completes authentication as usual (every factor it needs, MFA
// included) and the transaction then offers only this step, with the
// scheduled time. Cancelling makes the account active again and the same
// transaction continues to its normal completion (session, code, tokens).
// Abandoning it leaves the deletion scheduled; the worker completes it at
// deletion_scheduled_at.
func (s *Service) CancelDeletion(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		if t.UserID == "" || !primaryDone(t) {
			return nil, problem.ErrUnexpectedStep
		}
		r, err := s.evaluate(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		if !r.cancelDeletion {
			// Not pending deletion, or factors still missing.
			return nil, problem.ErrUnexpectedStep
		}
		if _, err := s.Users.LockUser(ctx, tx, t.RealmID, t.UserID); err != nil {
			return nil, err
		}
		return nil, s.Users.CancelDeletionTx(ctx, tx, t.RealmID, t.UserID, audit.Ref{Type: "user", ID: t.UserID}, "sign_in")
	})
}
