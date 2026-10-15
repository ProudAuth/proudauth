package authorization

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// AssignmentRequestTTL bounds how long an approval request stays open.
const AssignmentRequestTTL = 7 * 24 * time.Hour

// AssignmentRequest is a pending grant of a role that requires an independent
// approver (AZ-018). The approver is always the authenticated caller of the
// approve operation, never an identifier asserted by the requester.
type AssignmentRequest struct {
	ID           string         `json:"id"`
	RoleID       string         `json:"role_id"`
	Subject      Subject        `json:"subject"`
	Scope        Scope          `json:"scope"`
	Conditions   map[string]any `json:"conditions,omitempty"`
	ValidFrom    *time.Time     `json:"valid_from,omitempty"`
	ExpiresAt    *time.Time     `json:"assignment_expires_at,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	RequestedBy  string         `json:"requested_by"`
	State        string         `json:"state"`
	DecidedBy    string         `json:"decided_by,omitempty"`
	DecidedAt    *time.Time     `json:"decided_at,omitempty"`
	AssignmentID string         `json:"assignment_id,omitempty"`
	RequestTTL   time.Time      `json:"expires_at"`
	CreatedAt    time.Time      `json:"created_at"`
	requesterTyp string
}

const requestCols = `id, role_id, subject_type, subject_id, scope_type, scope_id, conditions, valid_from, assignment_expires_at, coalesce(reason,''),
	requested_by_type, requested_by_id, state, coalesce(decided_by_id,''), decided_at, coalesce(assignment_id,''), expires_at, created_at`

func scanRequest(row pgx.Row) (*AssignmentRequest, error) {
	var r AssignmentRequest
	var cond []byte
	if err := row.Scan(&r.ID, &r.RoleID, &r.Subject.Type, &r.Subject.ID, &r.Scope.Type, &r.Scope.ID, &cond, &r.ValidFrom, &r.ExpiresAt, &r.Reason,
		&r.requesterTyp, &r.RequestedBy, &r.State, &r.DecidedBy, &r.DecidedAt, &r.AssignmentID, &r.RequestTTL, &r.CreatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cond, &r.Conditions)
	return &r, nil
}

// AssignmentNeedsApproval reports whether granting the role to the subject
// needs an independent approver: the role demands it, or the subject is an
// autonomous agent and the role is privileged (MCH-017: agents get no
// privileged authority on one administrator's say-so, and never bypass
// ordinary authorization).
func (s *Service) AssignmentNeedsApproval(ctx context.Context, realmID, roleID string, subj Subject) (bool, error) {
	return s.AssignmentNeedsApprovalTx(ctx, nil, realmID, roleID, subj)
}

// AssignmentNeedsApprovalTx is AssignmentNeedsApproval inside a transaction
// (nil q uses the pool), for assignments made by other paths such as
// organization templates, which apply the same rule (MCH-017).
func (s *Service) AssignmentNeedsApprovalTx(ctx context.Context, q storage.Querier, realmID, roleID string, subj Subject) (bool, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	role, err := s.Role(ctx, q, realmID, roleID)
	if err != nil {
		return false, err
	}
	if role.RequiresApproval {
		return true, nil
	}
	if subj.Type != SubjectService || subj.ID == "" {
		return false, nil
	}
	var agent bool
	if err := q.QueryRow(ctx, `SELECT is_agent FROM service_principals WHERE realm_id=$1 AND id=$2`, realmID, subj.ID).Scan(&agent); err != nil {
		if storage.IsNoRows(err) {
			return false, nil // the assignment itself reports the unknown subject
		}
		return false, err
	}
	return agent && s.IsPrivilegedRole(ctx, q, realmID, role), nil
}

// RequiresApproval reports whether assigning the role needs a second party.
func (s *Service) RequiresApproval(ctx context.Context, realmID, roleID string) (bool, error) {
	role, err := s.Role(ctx, nil, realmID, roleID)
	if err != nil {
		return false, problem.ErrValidation.WithField("role_id", "unknown role")
	}
	return role.RequiresApproval, nil
}

// RequestAssignment records a pending assignment after validating the
// requester's own authority (the requester must be able to grant the role).
func (s *Service) RequestAssignment(ctx context.Context, realmID string, requester Subject, in AssignInput, auditActor audit.Ref) (*AssignmentRequest, error) {
	var out *AssignmentRequest
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		role, err := s.Role(ctx, tx, realmID, in.RoleID)
		if err != nil {
			return problem.ErrValidation.WithField("role_id", "unknown role")
		}
		if !roleFitsScope(role, in.Scope) {
			return problem.ErrValidation.WithField("scope", "role boundary does not match the assignment scope")
		}
		if _, err := ParseConditions(in.Conditions); err != nil {
			return err
		}
		if err := s.CheckAssignable(ctx, tx, realmID, requester, role, in.Scope); err != nil {
			return err
		}
		if requester.ID == in.Subject.ID {
			return problem.ErrForbidden.WithDetail("administrators cannot request privileged roles for themselves")
		}
		cond, _ := json.Marshal(nonNilMap(in.Conditions))
		id, now := ids.New("rar"), s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO role_assignment_requests (id, realm_id, role_id, subject_type, subject_id, scope_type, scope_id, conditions,
			valid_from, assignment_expires_at, reason, requested_by_type, requested_by_id, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, id, realmID, in.RoleID, in.Subject.Type, in.Subject.ID, in.Scope.Type, in.Scope.ID,
			cond, in.ValidFrom, in.ExpiresAt, nilIfEmpty(in.Reason), requester.Type, requester.ID, now.Add(AssignmentRequestTTL), now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.assignment.requested", RealmID: realmID, Actor: auditActor, Category: "authorization",
			Subject: &audit.Ref{Type: in.Subject.Type, ID: in.Subject.ID}, Target: &audit.Ref{Type: "role", ID: in.RoleID},
			Metadata: map[string]any{"request_id": id, "scope_type": in.Scope.Type, "scope_id": in.Scope.ID, "reason": in.Reason}}); err != nil {
			return err
		}
		out, err = scanRequest(tx.QueryRow(ctx, `SELECT `+requestCols+` FROM role_assignment_requests WHERE id=$1`, id))
		return err
	})
	return out, err
}

// DecideAssignmentRequest approves or rejects a pending request. The approver is
// the authenticated caller; they must differ from the requester and the subject
// and must be able to grant the role themselves. The requester's authority is
// re-validated at approval time.
func (s *Service) DecideAssignmentRequest(ctx context.Context, realmID, requestID string, approver Subject, approve bool, auditActor audit.Ref) (*AssignmentRequest, error) {
	var out *AssignmentRequest
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		r, err := scanRequest(tx.QueryRow(ctx, `SELECT `+requestCols+` FROM role_assignment_requests WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, requestID))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		now := s.d.Now()
		if r.State != "pending" {
			return problem.ErrConflict.WithDetail("the request is no longer pending")
		}
		if !now.Before(r.RequestTTL) {
			_, _ = tx.Exec(ctx, `UPDATE role_assignment_requests SET state='expired' WHERE id=$1`, r.ID)
			return problem.ErrConflict.WithDetail("the request expired")
		}
		if approver.ID == r.RequestedBy || approver.ID == r.Subject.ID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		role, err := s.Role(ctx, tx, realmID, r.RoleID)
		if err != nil {
			return err
		}
		if err := s.CheckAssignable(ctx, tx, realmID, approver, role, r.Scope); err != nil {
			return problem.ErrForbidden.WithDetail("approver lacks authority for this role")
		}
		assignmentID := ""
		state := "rejected"
		if approve {
			requester := Subject{Type: r.requesterTyp, ID: r.RequestedBy}
			as, err := s.AssignTx(ctx, tx, realmID, &requester, AssignInput{RoleID: r.RoleID, Subject: r.Subject, Scope: r.Scope, ValidFrom: r.ValidFrom,
				ExpiresAt: r.ExpiresAt, Conditions: r.Conditions, Reason: r.Reason, ApproverID: approver.ID, Source: "approval"}, auditActor)
			if err != nil {
				return err
			}
			assignmentID, state = as.ID, "approved"
		}
		if _, err := tx.Exec(ctx, `UPDATE role_assignment_requests SET state=$2, decided_by_id=$3, decided_at=$4, assignment_id=$5 WHERE id=$1`,
			r.ID, state, approver.ID, now, nilIfEmpty(assignmentID)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.assignment." + state, RealmID: realmID, Actor: auditActor, Category: "authorization",
			Subject: &audit.Ref{Type: r.Subject.Type, ID: r.Subject.ID}, Target: &audit.Ref{Type: "role", ID: r.RoleID},
			Metadata: map[string]any{"request_id": r.ID, "requested_by": r.RequestedBy, "assignment_id": assignmentID}}); err != nil {
			return err
		}
		out, err = scanRequest(tx.QueryRow(ctx, `SELECT `+requestCols+` FROM role_assignment_requests WHERE id=$1`, r.ID))
		return err
	})
	return out, err
}

// ListAssignmentRequests lists requests by state ("" for all).
func (s *Service) ListAssignmentRequests(ctx context.Context, realmID, state string) ([]*AssignmentRequest, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+requestCols+` FROM role_assignment_requests WHERE realm_id=$1 AND ($2='' OR state=$2)
		ORDER BY created_at DESC LIMIT 200`, realmID, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AssignmentRequest{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
