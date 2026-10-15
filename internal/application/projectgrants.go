package application

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// ProjectGrant lets an organization that does not own a project hand out a
// bounded set of that project's roles (INV-012). The allowed roles are the
// organization's delegation ceiling for the project; an empty grant permits none.
type ProjectGrant struct {
	ID             string     `json:"id"`
	ProjectID      string     `json:"project_id"`
	OrganizationID string     `json:"organization_id"`
	AllowedRoleIDs []string   `json:"allowed_role_ids"`
	State          string     `json:"state"`
	ValidUntil     *time.Time `json:"valid_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

const pgCols = `id, project_id, organization_id, allowed_role_ids, state, valid_until, created_at`

func scanProjectGrant(row pgx.Row) (*ProjectGrant, error) {
	var g ProjectGrant
	err := row.Scan(&g.ID, &g.ProjectID, &g.OrganizationID, &g.AllowedRoleIDs, &g.State, &g.ValidUntil, &g.CreatedAt)
	return &g, err
}

// CreateProjectGrant grants an organization access to a project's roles. Every
// allowed role must be a project-boundary role of that project.
func (s *Service) CreateProjectGrant(ctx context.Context, realmID, projectID, orgID string, roleIDs []string, validUntil *time.Time, actor audit.Ref) (*ProjectGrant, error) {
	if orgID == "" {
		return nil, problem.ErrValidation.WithField("organization_id", "required")
	}
	if len(roleIDs) > 50 {
		return nil, problem.ErrValidation.WithField("allowed_role_ids", "at most 50 roles")
	}
	if validUntil != nil && !validUntil.After(s.d.Now()) {
		return nil, problem.ErrValidation.WithField("valid_until", "must be in the future")
	}
	var out *ProjectGrant
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var state, owner string
		if err := tx.QueryRow(ctx, `SELECT state, coalesce(owner_organization_id,'') FROM projects WHERE realm_id=$1 AND id=$2 FOR UPDATE`,
			realmID, projectID).Scan(&state, &owner); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if state != "active" {
			return problem.ErrConflict.WithDetail("project is not active")
		}
		if owner == orgID {
			return problem.ErrValidation.WithField("organization_id", "the owning organization does not need a grant")
		}
		for _, rid := range roleIDs {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM roles WHERE realm_id=$1 AND id=$2 AND boundary_type='project' AND project_id=$3)`,
				realmID, rid, projectID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return problem.ErrValidation.WithField("allowed_role_ids", "every role must belong to this project")
			}
		}
		id := ids.New(ids.ProjectGrant)
		if roleIDs == nil {
			roleIDs = []string{}
		}
		_, err := tx.Exec(ctx, `INSERT INTO project_grants (id, realm_id, project_id, organization_id, allowed_role_ids, valid_until, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, id, realmID, projectID, orgID, roleIDs, validUntil, s.d.Now())
		if err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("the organization already has a grant for this project")
			}
			if storage.IsForeignKeyViolation(err) {
				return problem.ErrValidation.WithField("organization_id", "unknown organization")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "project.grant.created", RealmID: realmID, OrgID: orgID, Actor: actor,
			Target: &audit.Ref{Type: "project_grant", ID: id}, Category: "authorization",
			Metadata: map[string]any{"project_id": projectID, "allowed_role_ids": roleIDs}}); err != nil {
			return err
		}
		out, err = scanProjectGrant(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM project_grants WHERE id=$1`, id))
		return err
	})
	return out, err
}

// ListProjectGrants lists a project's grants.
func (s *Service) ListProjectGrants(ctx context.Context, realmID, projectID string) ([]*ProjectGrant, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+pgCols+` FROM project_grants WHERE realm_id=$1 AND project_id=$2 ORDER BY id`, realmID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProjectGrant{}
	for rows.Next() {
		g, err := scanProjectGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeProjectGrant revokes a grant. Role assignments already made through it
// (source project_grant, reason "<grant id>:<invitation id>") are removed in the same transaction so the organization's delegated access
// ends with the grant.
func (s *Service) RevokeProjectGrant(ctx context.Context, realmID, projectID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.endProjectGrantTx(ctx, tx, realmID, projectID, id, actor, "project.grant.revoked")
	})
}

// ExpireProjectGrants ends grants whose valid_until has passed, with the
// role assignments made through them (TEN-020).
func (s *Service) ExpireProjectGrants(ctx context.Context) (int, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT realm_id, project_id, id FROM project_grants WHERE state='active' AND valid_until IS NOT NULL
		AND valid_until <= $1 ORDER BY valid_until LIMIT 500`, s.d.Now())
	if err != nil {
		return 0, err
	}
	type due struct{ realm, project, id string }
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.realm, &d.project, &d.id); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	n := 0
	for _, d := range list {
		if err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			return s.endProjectGrantTx(ctx, tx, d.realm, d.project, d.id, audit.System, "project.grant.expired")
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Service) endProjectGrantTx(ctx context.Context, tx pgx.Tx, realmID, projectID, id string, actor audit.Ref, event string) error {

	g, err := scanProjectGrant(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM project_grants WHERE realm_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`,
		realmID, projectID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	if g.State == "revoked" {
		return nil
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE project_grants SET state='revoked', updated_at=$2 WHERE id=$1`, id, now); err != nil {
		return err
	}
	// The holders' authorization changes now: cached decisions and
	// tokens carrying the revision are re-evaluated.
	rows, err := tx.Query(ctx, `DELETE FROM role_assignments WHERE realm_id=$1 AND scope_type='project' AND scope_id=$2 AND source='project_grant'
		AND split_part(reason, ':', 1)=$3 RETURNING subject_type, subject_id`, realmID, projectID, id)
	if err != nil {
		return err
	}
	removed := 0
	var users, principals []string
	for rows.Next() {
		var typ, sid string
		if err := rows.Scan(&typ, &sid); err != nil {
			rows.Close()
			return err
		}
		removed++
		if typ == "user" {
			users = append(users, sid)
		} else if typ == "service_principal" {
			principals = append(principals, sid)
		}
	}
	rows.Close()
	if len(users) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE users SET authz_revision=authz_revision+1 WHERE id = ANY($1)`, users); err != nil {
			return err
		}
	}
	if len(principals) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE service_principals SET permission_revision=permission_revision+1 WHERE id = ANY($1)`, principals); err != nil {
			return err
		}
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, OrgID: g.OrganizationID, Actor: actor,
		Target: &audit.Ref{Type: "project_grant", ID: id}, Category: "authorization",
		Metadata: map[string]any{"project_id": projectID, "assignments_removed": removed}})
	return err
}

// ReceivedProjectGrants lists the live project grants an organization holds
// (TEN-020).
func (s *Service) ReceivedProjectGrants(ctx context.Context, realmID, orgID string) ([]*ProjectGrant, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+pgCols+` FROM project_grants WHERE realm_id=$1 AND organization_id=$2 AND state='active'
		AND (valid_until IS NULL OR valid_until > $3) ORDER BY created_at`, realmID, orgID, s.d.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProjectGrant{}
	for rows.Next() {
		g, err := scanProjectGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
