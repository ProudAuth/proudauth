package workflow

import (
	"context"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// MyApprovals lists the approvals a user is named on (self-service).
func (s *Service) MyApprovals(ctx context.Context, realmID, userID, state string) ([]Approval, error) {
	if state == "" {
		state = "pending"
	}
	if !slices.Contains([]string{"pending", "approved", "rejected", "expired", "cancelled"}, state) {
		return nil, problem.ErrValidation.WithField("state", "pending, approved, rejected, expired or cancelled")
	}
	return s.approvals(ctx, `realm_id=$1 AND $2 = ANY(approver_ids) AND state=$3`, realmID, userID, state)
}

// Decide records a named approver's decision. Only a named approver who is
// not the subject decides, once, before the expiry (AZ-018); the run resumes
// at once.
func (s *Service) Decide(ctx context.Context, realmID, approverID, approvalID, decision, comment string) (*Approval, error) {
	if decision != "approve" && decision != "reject" {
		return nil, problem.ErrValidation.WithField("decision", "approve or reject")
	}
	comment = strings.TrimSpace(comment)
	if len(comment) > 500 {
		return nil, problem.ErrValidation.WithField("comment", "at most 500 characters")
	}
	var out *Approval
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		a, err := scanApproval(tx.QueryRow(ctx, `SELECT `+approvalCols+` FROM workflow_approvals WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, approvalID))
		if storage.IsNoRows(err) || err == nil && !slices.Contains(a.ApproverIDs, approverID) {
			// Not named: the approval's existence is not disclosed.
			return problem.ErrNotFound
		}
		if err != nil {
			return err
		}
		if approverID == a.SubjectID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		if a.State != "pending" {
			return problem.ErrConflict.WithDetail("the approval was already " + a.State)
		}
		if !s.d.Now().Before(a.ExpiresAt) {
			return problem.ErrConflict.WithDetail("the approval expired")
		}
		state := map[string]string{"approve": "approved", "reject": "rejected"}[decision]
		if _, err := tx.Exec(ctx, `UPDATE workflow_approvals SET state=$2, decided_by_id=$3, decided_at=$4, comment=$5 WHERE id=$1`, a.ID, state,
			approverID, s.d.Now(), nilIfEmpty(comment)); err != nil {
			return err
		}
		// The run resumes on the next worker pass.
		if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET next_run_at=$2 WHERE id=$1 AND state='awaiting_approval'`, a.RunID, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.approval." + state, RealmID: realmID, Actor: audit.Ref{Type: "user", ID: approverID},
			Subject: &audit.Ref{Type: "user", ID: a.SubjectID}, Target: &audit.Ref{Type: "workflow_approval", ID: a.ID}, Category: "authorization",
			Metadata: map[string]any{"run_id": a.RunID, "workflow_id": a.WorkflowID}}); err != nil {
			return err
		}
		out, err = scanApproval(tx.QueryRow(ctx, `SELECT `+approvalCols+` FROM workflow_approvals WHERE id=$1`, a.ID))
		return err
	})
	return out, err
}
