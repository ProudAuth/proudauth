package organization

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// Relationship links two organizations explicitly (TEN-021): parent_child
// (source is the parent) or partner. It never grants access by itself: no
// role, membership or permission follows from it. Cross-organization access
// needs a project grant (TEN-020) or an explicit role assignment, and
// tenant administrators can share projects only with organizations they
// have an active relationship with.
type Relationship struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	SourceOrgID string     `json:"source_organization_id"`
	TargetOrgID string     `json:"target_organization_id"`
	State       string     `json:"state"`
	Note        string     `json:"note,omitempty"`
	CreatedBy   audit.Ref  `json:"created_by"`
	DecidedByID string     `json:"decided_by_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
}

const relCols = `id, kind, source_org_id, target_org_id, state, note, created_by_type, created_by_id, coalesce(decided_by_id,''), created_at, decided_at, ended_at`

func scanRelationship(row pgx.Row) (*Relationship, error) {
	var r Relationship
	if err := row.Scan(&r.ID, &r.Kind, &r.SourceOrgID, &r.TargetOrgID, &r.State, &r.Note, &r.CreatedBy.Type, &r.CreatedBy.ID, &r.DecidedByID,
		&r.CreatedAt, &r.DecidedAt, &r.EndedAt); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// maxParentDepth bounds organization hierarchies.
const maxParentDepth = 10

// ProposeRelationship records a relationship from source to target. A realm
// administrator's relationship is active at once (direct); a tenant
// administrator's is proposed until the target organization accepts.
func (s *Service) ProposeRelationship(ctx context.Context, realmID, kind, sourceOrg, targetOrg, note string, direct bool, actor audit.Ref) (*Relationship, error) {
	if kind != "parent_child" && kind != "partner" {
		return nil, problem.ErrValidation.WithField("kind", "parent_child or partner")
	}
	if targetOrg == "" || targetOrg == sourceOrg {
		return nil, problem.ErrValidation.WithField("target_organization_id", "another organization of this realm")
	}
	if len(note) > 500 {
		return nil, problem.ErrValidation.WithField("note", "at most 500 characters")
	}
	id := ids.New("orl")
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE realm_id=$1 AND id = ANY($2) AND state='active'`,
			realmID, []string{sourceOrg, targetOrg}).Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			return problem.ErrValidation.WithField("target_organization_id", "an active organization of this realm")
		}
		if kind == "parent_child" {
			// The child must not be an ancestor of the parent, and the
			// hierarchy stays shallow.
			var cycle bool
			var depth int
			if err := tx.QueryRow(ctx, `WITH RECURSIVE up(org, depth) AS (
					SELECT $1::text, 0
					UNION ALL
					SELECT r.source_org_id, up.depth + 1 FROM organization_relationships r JOIN up ON r.target_org_id = up.org
					WHERE r.kind='parent_child' AND r.state IN ('proposed','active') AND up.depth < 50)
				SELECT coalesce(bool_or(org = $2), false), coalesce(max(depth), 0) FROM up`, sourceOrg, targetOrg).Scan(&cycle, &depth); err != nil {
				return err
			}
			if cycle {
				return problem.ErrConflict.WithDetail("the child organization is an ancestor of the parent")
			}
			if depth+1 >= maxParentDepth {
				return problem.ErrConflict.WithDetailf("organization hierarchies are at most %d levels deep", maxParentDepth)
			}
		}
		state, now := "proposed", s.d.Now()
		var decidedBy *string
		var decidedAt *time.Time
		if direct {
			state, decidedBy, decidedAt = "active", &actor.ID, &now
		}
		if _, err := tx.Exec(ctx, `INSERT INTO organization_relationships (id, realm_id, kind, source_org_id, target_org_id, state, note, created_by_type,
			created_by_id, decided_by_id, created_at, decided_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			id, realmID, kind, sourceOrg, targetOrg, state, note, actor.Type, actor.ID, decidedBy, now, decidedAt); err != nil {
			if storage.IsUniqueViolation(err) {
				if kind == "parent_child" {
					return problem.ErrConflict.WithDetail("the organizations are already related, or the child already has a parent")
				}
				return problem.ErrConflict.WithDetail("the organizations are already related")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.relationship." + map[bool]string{true: "created", false: "proposed"}[direct],
			RealmID: realmID, OrgID: sourceOrg, Actor: actor, Target: &audit.Ref{Type: "organization_relationship", ID: id}, Category: "authorization",
			Metadata: map[string]any{"kind": kind, "source_organization_id": sourceOrg, "target_organization_id": targetOrg}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Relationship(ctx, realmID, id)
}

// Relationship returns one relationship.
func (s *Service) Relationship(ctx context.Context, realmID, id string) (*Relationship, error) {
	return scanRelationship(s.d.DB.Pool.QueryRow(ctx, `SELECT `+relCols+` FROM organization_relationships WHERE realm_id=$1 AND id=$2`, realmID, id))
}

// Relationships lists an organization's relationships in both directions
// (orgID "" lists the realm's).
func (s *Service) Relationships(ctx context.Context, realmID, orgID string) ([]*Relationship, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+relCols+` FROM organization_relationships WHERE realm_id=$1
		AND ($2='' OR source_org_id=$2 OR target_org_id=$2) ORDER BY created_at DESC LIMIT 500`, realmID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Relationship{}
	for rows.Next() {
		r, err := scanRelationship(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideRelationship accepts or declines a proposal on behalf of the
// target organization.
func (s *Service) DecideRelationship(ctx context.Context, realmID, orgID, id string, accept bool, actor audit.Ref) (*Relationship, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		r, err := scanRelationship(tx.QueryRow(ctx, `SELECT `+relCols+` FROM organization_relationships WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if r.TargetOrgID != orgID {
			if r.SourceOrgID == orgID {
				return problem.ErrForbidden.WithDetail("the other organization decides on a proposal")
			}
			return problem.ErrNotFound
		}
		if r.State != "proposed" {
			return problem.ErrConflict.WithDetail("only a proposal can be accepted or declined")
		}
		state := "declined"
		if accept {
			state = "active"
		}
		if _, err := tx.Exec(ctx, `UPDATE organization_relationships SET state=$2, decided_by_id=$3, decided_at=$4 WHERE id=$1`, id, state, actor.ID, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.relationship." + map[bool]string{true: "accepted", false: "declined"}[accept],
			RealmID: realmID, OrgID: orgID, Actor: actor, Target: &audit.Ref{Type: "organization_relationship", ID: id}, Category: "authorization",
			Metadata: map[string]any{"kind": r.Kind, "source_organization_id": r.SourceOrgID}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Relationship(ctx, realmID, id)
}

// EndRelationship ends a relationship from either side (orgID "" for a
// realm administrator). Project grants made because of it stay until their
// owners revoke them; ending the relationship stops new tenant grants.
func (s *Service) EndRelationship(ctx context.Context, realmID, orgID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		r, err := scanRelationship(tx.QueryRow(ctx, `SELECT `+relCols+` FROM organization_relationships WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if orgID != "" && r.SourceOrgID != orgID && r.TargetOrgID != orgID {
			return problem.ErrNotFound
		}
		if r.State != "proposed" && r.State != "active" {
			return problem.ErrConflict.WithDetail("the relationship has already ended")
		}
		if _, err := tx.Exec(ctx, `UPDATE organization_relationships SET state='ended', ended_at=$2 WHERE id=$1`, id, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.relationship.ended", RealmID: realmID, OrgID: orgID, Actor: actor,
			Target: &audit.Ref{Type: "organization_relationship", ID: id}, Category: "authorization",
			Metadata: map[string]any{"kind": r.Kind, "source_organization_id": r.SourceOrgID, "target_organization_id": r.TargetOrgID}})
		return err
	})
}

// Related reports whether two organizations have an active relationship of
// any kind, in either direction.
func (s *Service) Related(ctx context.Context, q storage.Querier, realmID, a, b string) (bool, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organization_relationships WHERE realm_id=$1 AND state='active'
		AND ((source_org_id=$2 AND target_org_id=$3) OR (source_org_id=$3 AND target_org_id=$2)))`, realmID, a, b).Scan(&ok)
	return ok, err
}

// ---------- partner project roles (TEN-020) ----------

// ProjectRoleAssignment is a project role an organization assigned to one
// of its members through a project grant.
type ProjectRoleAssignment struct {
	ID        string     `json:"id"`
	ProjectID string     `json:"project_id"`
	RoleID    string     `json:"role_id"`
	UserID    string     `json:"user_id"`
	GrantID   string     `json:"project_grant_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// AssignProjectRole assigns a project role to a member of the organization.
// For a project the organization does not own, the role must be in the
// subset its active project grant delegates; the assignment is removed when
// the grant is revoked or the membership ends.
func (s *Service) AssignProjectRole(ctx context.Context, realmID, orgID, projectID, roleID, userID string, expiresAt *time.Time,
	actor authorization.Subject, auditActor audit.Ref) (*ProjectRoleAssignment, error) {
	var out *ProjectRoleAssignment
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var member bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active')`,
			orgID, userID).Scan(&member); err != nil {
			return err
		}
		if !member {
			return problem.ErrValidation.WithField("user_id", "an active member of the organization")
		}
		grantID, err := s.projectRoleBasis(ctx, tx, realmID, orgID, projectID, actor, roleID)
		if err != nil {
			return err
		}
		source, reason := "admin", "organization:"+orgID
		if grantID != "" {
			source, reason = "project_grant", grantID+":direct:"+orgID // removed with the grant
		}
		a, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: roleID,
			Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID},
			Scope:   authorization.Scope{Type: authorization.ScopeProject, ID: projectID}, ExpiresAt: expiresAt, Source: source, Reason: reason,
			SkipCeiling: true}, auditActor)
		if err != nil {
			return err
		}
		out = &ProjectRoleAssignment{ID: a.ID, ProjectID: projectID, RoleID: roleID, UserID: userID, GrantID: grantID, ExpiresAt: expiresAt, CreatedAt: s.d.Now()}
		return nil
	})
	return out, err
}

// ProjectRoleAssignments lists the project roles an organization assigned
// through its project grants.
func (s *Service) ProjectRoleAssignments(ctx context.Context, realmID, orgID string) ([]ProjectRoleAssignment, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT ra.id, ra.scope_id, ra.role_id, ra.subject_id, split_part(ra.reason, ':', 1), ra.expires_at, ra.created_at
		FROM role_assignments ra WHERE ra.realm_id=$1 AND ra.scope_type='project' AND ra.subject_type='user'
		AND ((ra.source='project_grant' AND ra.reason LIKE '%:direct:' || $2) OR (ra.source='admin' AND ra.reason = 'organization:' || $2))
		ORDER BY ra.created_at LIMIT 1000`, realmID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProjectRoleAssignment{}
	for rows.Next() {
		var a ProjectRoleAssignment
		var grant string
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.RoleID, &a.UserID, &grant, &a.ExpiresAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		if len(grant) > 4 && grant[:4] == "pgr_" {
			a.GrantID = grant
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RemoveProjectRole removes a project role the organization assigned.
func (s *Service) RemoveProjectRole(ctx context.Context, realmID, orgID, assignmentID string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var projectID, userID string
		err := tx.QueryRow(ctx, `DELETE FROM role_assignments WHERE realm_id=$1 AND id=$2 AND scope_type='project'
			AND ((source='project_grant' AND reason LIKE '%:direct:' || $3) OR (source='admin' AND reason = 'organization:' || $3))
			RETURNING scope_id, subject_id`, realmID, assignmentID, orgID).Scan(&projectID, &userID)
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET authz_revision=authz_revision+1 WHERE id=$1`, userID); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.role.unassigned", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "role_assignment", ID: assignmentID}, Category: "authorization",
			Metadata: map[string]any{"scope_type": "project", "scope_id": projectID}})
		return err
	})
}
