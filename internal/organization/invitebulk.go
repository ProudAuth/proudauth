package organization

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// projectRoleBasis decides whether actor, acting for organization orgID, may
// hand out project role roleID (INV-012). It returns the project grant that
// delegates the role ("" when the actor holds project-level assignment
// authority directly or the organization owns the project).
//
// Project invitations never widen an organization's reach: the project must be
// active and either owned by the organization or covered by an active,
// unexpired grant that lists the role.
func (s *Service) projectRoleBasis(ctx context.Context, q storage.Querier, realmID, orgID, projectID string, actor authorization.Subject, roleID string) (string, error) {
	var state, owner string
	if err := q.QueryRow(ctx, `SELECT state, coalesce(owner_organization_id,'') FROM projects WHERE realm_id=$1 AND id=$2`, realmID, projectID).
		Scan(&state, &owner); err != nil {
		if storage.IsNoRows(err) {
			return "", problem.ErrValidation.WithField("project_id", "unknown project")
		}
		return "", err
	}
	if state != "active" {
		return "", problem.ErrValidation.WithField("project_id", "project is not active")
	}
	role, err := s.Authz.Role(ctx, q, realmID, roleID)
	if err != nil || role.Boundary != "project" || role.ProjectID != projectID {
		return "", problem.ErrValidation.WithField("role_ids", "every role must be a role of the invited project")
	}
	projectScope := authorization.Scope{Type: authorization.ScopeProject, ID: projectID}
	if s.Authz.CheckAssignable(ctx, q, realmID, actor, role, projectScope) == nil {
		return "", nil
	}
	orgScope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
	if !s.Authz.Check(ctx, q, realmID, actor, "org.roles.assign", orgScope) {
		return "", problem.ErrForbidden.WithDetail("assigning project roles requires role-assignment authority")
	}
	if owner == orgID {
		return "", nil
	}
	var grantID string
	var allowed []string
	err = q.QueryRow(ctx, `SELECT id, allowed_role_ids FROM project_grants WHERE realm_id=$1 AND project_id=$2 AND organization_id=$3
		AND state='active' AND (valid_until IS NULL OR valid_until > $4)`, realmID, projectID, orgID, s.d.Now()).Scan(&grantID, &allowed)
	if storage.IsNoRows(err) {
		return "", problem.ErrForbidden.WithDetail("the organization has no access to this project")
	}
	if err != nil {
		return "", err
	}
	if !slices.Contains(allowed, roleID) {
		return "", problem.ErrGrantCeiling.WithDetail("the project grant does not delegate this role")
	}
	return grantID, nil
}

// acceptProjectTx completes a project invitation (INV-012): it assigns the
// project roles directly to the user, re-validating the inviter's current
// basis for each, and creates no organization membership.
func (s *Service) acceptProjectTx(ctx context.Context, tx pgx.Tx, realmID string, inv *Invitation, userID string, auditActor audit.Ref,
	deny func(string) (*AcceptResult, error)) (*AcceptResult, error) {
	inviter := authorization.Subject{Type: inv.InviterType, ID: inv.InviterID}
	scope := authorization.Scope{Type: authorization.ScopeProject, ID: inv.ProjectID}
	var assigned []string
	for _, rid := range inv.RoleIDs {
		grantID, err := s.projectRoleBasis(ctx, tx, realmID, inv.OrganizationID, inv.ProjectID, inviter, rid)
		if err != nil {
			if problem.Is(err, problem.ErrValidation) {
				return deny("ROLE_UNAVAILABLE")
			}
			return deny("ROLE_CEILING_EXCEEDED")
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_assignments WHERE role_id=$1 AND subject_type='user' AND subject_id=$2
			AND scope_type='project' AND scope_id=$3)`, rid, userID, inv.ProjectID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			continue
		}
		source, reason := "invitation", inv.ID
		if grantID != "" {
			source, reason = "project_grant", grantID+":"+inv.ID // revoked with the grant
		}
		a, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: rid,
			Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID}, Scope: scope, Source: source,
			Reason: reason, SkipCeiling: true}, auditActor)
		if err != nil {
			return nil, err
		}
		assigned = append(assigned, a.ID)
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE invitations SET state='accepted', use_count=use_count+1, accepted_by_user_id=$2, accepted_at=$3,
		version=version+1, updated_at=$3 WHERE id=$1`, inv.ID, userID, now); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.accepted", RealmID: realmID, OrgID: inv.OrganizationID, Actor: auditActor,
		Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "invitation", ID: inv.ID},
		Metadata: map[string]any{"project_id": inv.ProjectID, "role_ids": inv.RoleIDs, "assignment_ids": assigned, "inviter_id": inv.InviterID}}); err != nil {
		return nil, err
	}
	return &AcceptResult{InvitationID: inv.ID, OrganizationID: inv.OrganizationID, ProjectID: inv.ProjectID, AssignmentIDs: assigned}, nil
}

// ReassignInput is an administrator-reviewed redirection of a pending
// invitation to a different address or account (INV-014).
type ReassignInput struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
	Locale string `json:"locale"`
}

// ReassignInvitation supersedes a pending invitation with a fresh one for a new
// target. The old secret stops working in the same transaction, the new
// invitation goes through every creation check again (current roles,
// ceilings, domain policy), and the review reason is audited.
func (s *Service) ReassignInvitation(ctx context.Context, realmID, orgID, id string, in ReassignInput, actor authorization.Subject, auditActor audit.Ref, ic InviteContext) (*Invitation, error) {
	if len(in.Reason) < 3 || len(in.Reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "a review reason (3..500 characters) is required")
	}
	var out *Invitation
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		old, err := scanInvitation(tx.QueryRow(ctx, `SELECT `+invCols+` FROM invitations WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if old.Purpose == "shared_link" {
			return problem.ErrConflict.WithDetail("shared links have no single target")
		}
		if old.State != "pending_delivery" && old.State != "pending_acceptance" && old.State != "created" {
			return problem.ErrConflict.WithDetail("only pending invitations can be reassigned; create a new invitation instead")
		}
		now := s.d.Now()
		ttl := old.ExpiresAt.Sub(now)
		if ttl <= 0 {
			return problem.ErrConflict.WithDetail("invitation expired; create a new one")
		}
		fresh, _, err := s.createInvitationTx(ctx, tx, realmID, orgID, InviteInput{Email: in.Email, UserID: in.UserID, RoleIDs: old.RoleIDs,
			Purpose: old.Purpose, ProjectID: old.ProjectID, TTLHours: max(1, int(ttl.Hours())), Locale: in.Locale}, actor, auditActor, ic)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE invitations SET state='revoked', superseded_by=$2, version=version+1, updated_at=$3 WHERE id=$1`,
			old.ID, fresh.ID, now); err != nil {
			return err
		}
		if err := s.releasePendingMembershipTx(ctx, tx, orgID, "invited", old.ID); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.reassigned", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "invitation", ID: old.ID}, Metadata: map[string]any{"new_invitation_id": fresh.ID,
				"previous_recipient": maskEmail(old.TargetEmail), "new_recipient": maskEmail(fresh.TargetEmail), "reason": in.Reason}}); err != nil {
			return err
		}
		out = fresh
		return nil
	})
	return out, err
}

// BatchItemResult is the outcome of one entry of a bulk invitation.
type BatchItemResult struct {
	Index        int    `json:"index"`
	Status       int    `json:"status"`
	InvitationID string `json:"invitation_id,omitempty"`
	Error        any    `json:"error,omitempty"`
}

// CreateInvitationBatch validates and creates each entry independently
// (INV-011): one failing entry never rolls back the others, every entry gets
// its own result, and delivery is queued per invitation. Shared links are not
// accepted in batches because their one-time secrets would be returned in bulk.
func (s *Service) CreateInvitationBatch(ctx context.Context, realmID, orgID string, items []InviteInput, actor authorization.Subject, auditActor audit.Ref, ic InviteContext) (string, []BatchItemResult, error) {
	if max := s.d.Cfg.Limits.MaxBatchSize; len(items) == 0 || len(items) > max {
		return "", nil, problem.ErrValidation.WithField("items", "1.."+strconv.Itoa(max)+" invitations (limits.max_batch_size)")
	}
	batchID := ids.New(ids.InviteBatch)
	seen := map[string]bool{}
	out := make([]BatchItemResult, len(items))
	created := 0
	for i, in := range items {
		out[i].Index = i
		if in.Purpose == "shared_link" {
			out[i].Status, out[i].Error = 422, itemProblem(problem.ErrValidation.WithField("purpose", "shared links cannot be created in bulk"))
			continue
		}
		key := in.Email + "|" + in.UserID + "|" + in.ProjectID
		if seen[key] {
			out[i].Status, out[i].Error = 409, itemProblem(problem.ErrConflict.WithDetail("duplicate entry in this batch"))
			continue
		}
		seen[key] = true
		in.batchID = batchID
		inv, _, err := s.CreateInvitation(ctx, realmID, orgID, in, actor, auditActor, ic)
		if err != nil {
			pe, ok := problem.As(err)
			if !ok {
				return "", nil, err // infrastructure failure: stop rather than report half-truths
			}
			out[i].Status, out[i].Error = pe.Status, itemProblem(pe)
			continue
		}
		created++
		out[i].Status, out[i].InvitationID = 201, inv.ID
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.batch.created", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "invitation_batch", ID: batchID}, Metadata: map[string]any{"entries": len(items), "created": created,
				"failed": len(items) - created, "at": s.d.Now().Format(time.RFC3339)}})
		return err
	})
	return batchID, out, err
}

func itemProblem(pe *problem.Error) map[string]any {
	m := map[string]any{"code": pe.Code, "title": pe.Title}
	if pe.Detail != "" {
		m["detail"] = pe.Detail
	}
	if len(pe.Fields) > 0 {
		m["errors"] = pe.Fields
	}
	return m
}
