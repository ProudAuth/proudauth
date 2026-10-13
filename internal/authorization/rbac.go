package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
)

// Scope types.
const (
	ScopeRealm        = "realm"
	ScopeOrganization = "organization"
	ScopeProject      = "project"
)

// Subject types.
const (
	SubjectUser    = "user"
	SubjectService = "service_principal"
	SubjectGroup   = "group"
)

// Scope is an authorization boundary.
type Scope struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Subject is a principal receiving permissions.
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ErrGraphTooLarge is returned when role/group expansion exceeds bounds (TEST-014).
var ErrGraphTooLarge = errors.New("authorization: role or group graph exceeds evaluation bounds")

// PermissionSet is an evaluated, deterministic permission set (AZ-004): explicit
// denies always override allows, regardless of assignment order.
type PermissionSet struct {
	Allow     map[string][]string `json:"-"` // permission -> granting role names (provenance)
	Deny      map[string][]string `json:"-"`
	RoleNames []string            `json:"roles"`
	Truncated bool                `json:"-"`
}

// Has reports whether perm is effectively allowed.
func (p *PermissionSet) Has(perm string) bool {
	if p == nil {
		return false
	}
	if _, denied := p.Deny[perm]; denied {
		return false
	}
	_, ok := p.Allow[perm]
	return ok
}

// List returns allowed permissions sorted.
func (p *PermissionSet) List() []string {
	var out []string
	for k := range p.Allow {
		if _, d := p.Deny[k]; !d {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Provenance returns the roles granting perm (AZ-009).
func (p *PermissionSet) Provenance(perm string) []string { return p.Allow[perm] }

// Service is the RBAC engine.
type Service struct {
	d             *runtime.Deps
	MaxExpansion  int
	MaxGroupDepth int
}

// NewService returns the authorization service.
func NewService(d *runtime.Deps) *Service {
	return &Service{d: d, MaxExpansion: d.Cfg.Limits.MaxRoleExpansion, MaxGroupDepth: d.Cfg.Limits.MaxGroupDepth}
}

// Role is a named permission bundle.
type Role struct {
	ID                  string    `json:"id"`
	RealmID             string    `json:"realm_id"`
	Boundary            string    `json:"boundary_type"`
	OrganizationID      string    `json:"organization_id,omitempty"`
	ProjectID           string    `json:"project_id,omitempty"`
	Name                string    `json:"name"`
	Description         string    `json:"description,omitempty"`
	Protected           bool      `json:"protected"`
	BuiltIn             bool      `json:"built_in"`
	IsOwnerRole         bool      `json:"is_owner_role"`
	CompositeRoleIDs    []string  `json:"composite_role_ids"`
	IncompatibleRoleIDs []string  `json:"incompatible_role_ids"`
	RequiresApproval    bool      `json:"requires_approval"`
	Permissions         []string  `json:"permissions"`
	DeniedPermissions   []string  `json:"denied_permissions,omitempty"`
	Version             int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
}

const roleCols = `id, realm_id, boundary_type, coalesce(organization_id,''), coalesce(project_id,''), name, coalesce(description,''),
	protected, built_in, is_owner_role, composite_role_ids, incompatible_role_ids, requires_approval, version, created_at`

func scanRole(row pgx.Row) (*Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.RealmID, &r.Boundary, &r.OrganizationID, &r.ProjectID, &r.Name, &r.Description, &r.Protected, &r.BuiltIn,
		&r.IsOwnerRole, &r.CompositeRoleIDs, &r.IncompatibleRoleIDs, &r.RequiresApproval, &r.Version, &r.CreatedAt)
	return &r, err
}

// Role loads a role with its direct permissions.
func (s *Service) Role(ctx context.Context, q storage.Querier, realmID, id string) (*Role, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := scanRole(q.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE realm_id=$1 AND id=$2`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return r, s.loadRolePerms(ctx, q, r)
}

// RoleByName loads a built-in or realm role by name and boundary.
func (s *Service) RoleByName(ctx context.Context, q storage.Querier, realmID, boundary, name string) (*Role, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := scanRole(q.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE realm_id=$1 AND boundary_type=$2 AND organization_id IS NULL
		AND project_id IS NULL AND lower(name)=lower($3)`, realmID, boundary, name))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return r, s.loadRolePerms(ctx, q, r)
}

func (s *Service) loadRolePerms(ctx context.Context, q storage.Querier, r *Role) error {
	rows, err := q.Query(ctx, `SELECT p.name, rp.effect FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id
		WHERE rp.role_id=$1 ORDER BY p.name`, r.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	r.Permissions, r.DeniedPermissions = []string{}, []string{}
	for rows.Next() {
		var name, effect string
		if err := rows.Scan(&name, &effect); err != nil {
			return err
		}
		if effect == "deny" {
			r.DeniedPermissions = append(r.DeniedPermissions, name)
		} else {
			r.Permissions = append(r.Permissions, name)
		}
	}
	return rows.Err()
}

// Privileged reports whether holding the role, on its own, is a privileged
// grant: an owner role, a realm-boundary (identity administration) role, or
// a role carrying a permission the catalog marks privileged. Built-in roles
// are protected from edits; that alone does not make them privileged.
func (r *Role) Privileged() bool {
	if r.IsOwnerRole || r.Boundary == "realm" {
		return true
	}
	for _, p := range r.Permissions {
		if PermissionSensitivity(p) == "privileged" || p == "*" || strings.HasSuffix(p, ".*") {
			return true
		}
	}
	return false
}

// holdsPrivilegedPermission reports a role allowing a permission registered
// as privileged, custom permissions included (the built-in catalog only knows
// its own). A lookup failure counts as privileged.
func (s *Service) holdsPrivilegedPermission(ctx context.Context, q storage.Querier, roleID string) bool {
	if q == nil {
		q = s.d.DB.Pool
	}
	var held bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id
		WHERE rp.role_id=$1 AND rp.effect<>'deny' AND p.sensitivity='privileged')`, roleID).Scan(&held); err != nil {
		return true
	}
	return held
}

// IsPrivilegedRole reports whether the role or any role it composes, at any
// depth, is privileged. A composition of more than MaxInspectedRoles roles
// (the role and the existing roles it reaches; a deleted component grants
// nothing and is not counted) is too large to inspect and counts as
// privileged: the answer gates reviews, elevation, approvals and exports, so
// it fails closed. PrivilegedRoleSQL decides the same in SQL.
func (s *Service) IsPrivilegedRole(ctx context.Context, q storage.Querier, realmID string, role *Role) bool {
	seen := map[string]bool{role.ID: true}
	queue := []*Role{role}
	reached := 1
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		if r.Privileged() || s.holdsPrivilegedPermission(ctx, q, r.ID) {
			return true
		}
		for _, id := range r.CompositeRoleIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			c, err := s.Role(ctx, q, realmID, id)
			if err != nil {
				if storage.IsNoRows(err) || errors.Is(err, problem.ErrNotFound) {
					continue // a deleted component grants nothing
				}
				return true
			}
			if reached++; reached > MaxInspectedRoles {
				return true
			}
			queue = append(queue, c)
		}
	}
	return false
}

// ListRoles lists roles visible within a boundary filter.
func (s *Service) ListRoles(ctx context.Context, realmID, boundary, orgID, projectID string) ([]*Role, error) {
	sql := `SELECT ` + roleCols + ` FROM roles WHERE realm_id=$1`
	args := []any{realmID}
	if boundary != "" {
		args = append(args, boundary)
		sql += ` AND boundary_type=$2`
	}
	if orgID != "" {
		args = append(args, orgID)
		sql += ` AND (organization_id IS NULL OR organization_id=$` + itoa(len(args)) + `)`
		if boundary == "" {
			sql += ` AND boundary_type='organization'`
		}
	}
	if projectID != "" {
		args = append(args, projectID)
		sql += ` AND project_id=$` + itoa(len(args))
	}
	sql += ` ORDER BY boundary_type, name`
	rows, err := s.d.DB.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	var out []*Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	for _, r := range out {
		if err := s.loadRolePerms(ctx, s.d.DB.Pool, r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// expandRoles returns the role IDs reachable through composites, bounded and cycle-safe.
func (s *Service) expandRoles(ctx context.Context, q storage.Querier, start []string) ([]string, error) {
	seen := map[string]bool{}
	queue := slices.Clone(start)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		if len(seen) > s.MaxExpansion {
			return nil, ErrGraphTooLarge
		}
		var composites []string
		if err := q.QueryRow(ctx, `SELECT composite_role_ids FROM roles WHERE id=$1`, id).Scan(&composites); err != nil {
			if storage.IsNoRows(err) {
				continue
			}
			return nil, err
		}
		queue = append(queue, composites...)
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// groupClosure returns the groups containing a membership, including ancestors of
// nested groups, with depth and cycle limits.
func (s *Service) groupClosure(ctx context.Context, q storage.Querier, orgID, membershipID string, now time.Time) ([]string, error) {
	// Stale directory state (AZ-010): a rule-derived membership counts only
	// while its dynamic group was recomputed recently and without error, so a
	// stopped worker or a broken rule fails closed instead of freezing access.
	stale := s.d.Cfg.Security.DynamicGroupMaxStaleness
	if stale <= 0 {
		stale = time.Hour
	}
	rows, err := q.Query(ctx, `SELECT gm.group_id FROM group_memberships gm JOIN groups g ON g.id=gm.group_id
		WHERE gm.organization_id=$1 AND gm.membership_id=$2
		AND (gm.valid_from IS NULL OR gm.valid_from <= $3) AND (gm.valid_until IS NULL OR gm.valid_until > $3)
		AND NOT (gm.source='dynamic' AND (g.dynamic_rule IS NULL OR g.rule_error IS NOT NULL OR g.rule_recomputed_at IS NULL
			OR g.rule_recomputed_at < $4))`, orgID, membershipID, now, now.Add(-stale))
	if err != nil {
		return nil, err
	}
	var frontier []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return nil, err
		}
		frontier = append(frontier, g)
	}
	rows.Close()
	seen := map[string]bool{}
	for depth := 0; len(frontier) > 0; depth++ {
		if depth > s.MaxGroupDepth {
			return nil, ErrGraphTooLarge
		}
		var next []string
		for _, g := range frontier {
			if seen[g] {
				continue
			}
			seen[g] = true
			var parent *string
			if err := q.QueryRow(ctx, `SELECT parent_id FROM groups WHERE id=$1 AND organization_id=$2`, g, orgID).Scan(&parent); err != nil {
				if storage.IsNoRows(err) {
					continue
				}
				return nil, err
			}
			if parent != nil && !seen[*parent] {
				next = append(next, *parent)
			}
		}
		frontier = next
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	return out, nil
}

// bumpGroupMembersTx invalidates cached decisions of everyone a group's
// grants reach: members of the group and of its descendants (AZ-019).
func bumpGroupMembersTx(ctx context.Context, tx pgx.Tx, groupID string) error {
	_, err := tx.Exec(ctx, `WITH RECURSIVE d(id, depth) AS (
			SELECT $1::text, 0
			UNION SELECT g.id, d.depth+1 FROM groups g JOIN d ON g.parent_id=d.id WHERE d.depth < 64)
		UPDATE memberships SET revision=revision+1 WHERE id IN (SELECT membership_id FROM group_memberships WHERE group_id IN (SELECT id FROM d))`, groupID)
	return err
}

// HeldRoles returns every role a subject holds anywhere in the realm —
// direct and membership-bound assignments and, for users, the roles of their
// groups and the groups' ancestors — expanded through composites.
func (s *Service) HeldRoles(ctx context.Context, q storage.Querier, realmID string, subj Subject) ([]string, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	now := s.d.Now()
	var start []string
	collect := func(sql string, args ...any) error {
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			start = append(start, id)
		}
		return rows.Err()
	}
	if err := collect(`SELECT role_id FROM role_assignments WHERE realm_id=$1 AND subject_type=$2 AND subject_id=$3
		AND (expires_at IS NULL OR expires_at > $4)`, realmID, subj.Type, subj.ID, now); err != nil {
		return nil, err
	}
	if subj.Type == SubjectUser {
		if err := collect(`WITH RECURSIVE g(id, depth) AS (
				SELECT gm.group_id, 0 FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
				WHERE m.realm_id=$1 AND m.user_id=$2 AND m.state <> 'removed'
				UNION SELECT gr.parent_id, g.depth+1 FROM groups gr JOIN g ON gr.id=g.id WHERE gr.parent_id IS NOT NULL AND g.depth < 64)
			SELECT DISTINCT ra.role_id FROM role_assignments ra WHERE ra.subject_type='group' AND ra.subject_id IN (SELECT id FROM g)
			AND (ra.expires_at IS NULL OR ra.expires_at > $3)`, realmID, subj.ID, now); err != nil {
			return nil, err
		}
	}
	return s.expandRoles(ctx, q, start)
}

// groupMemberUsers lists the users in a group or any of its descendants.
func (s *Service) groupMemberUsers(ctx context.Context, q storage.Querier, groupID string) ([]string, error) {
	rows, err := q.Query(ctx, `WITH RECURSIVE d(id, depth) AS (
			SELECT $1::text, 0
			UNION SELECT g.id, d.depth+1 FROM groups g JOIN d ON g.parent_id=d.id WHERE d.depth < 64)
		SELECT DISTINCT m.user_id FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
		WHERE gm.group_id IN (SELECT id FROM d) AND m.state <> 'removed'`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ErrIncompatibleRoles is the separation-of-duties refusal (AZ-018). It is
// returned as is, so callers can tell the conflict (errors.Is) from a
// failure to evaluate it.
var ErrIncompatibleRoles = problem.ErrConflict.WithDetail("the subject would hold roles that are incompatible with each other (AZ-018)")

// CheckSeparation refuses giving roles (and everything they compose) to
// subjects that would then hold two incompatible roles (AZ-018); the refusal
// is ErrIncompatibleRoles, any other error means the check could not run.
func (s *Service) CheckSeparation(ctx context.Context, q storage.Querier, realmID string, userIDs, roleIDs []string) error {
	holders := make([]Subject, len(userIDs))
	for i, u := range userIDs {
		holders[i] = Subject{Type: SubjectUser, ID: u}
	}
	return s.checkSeparation(ctx, q, realmID, holders, roleIDs)
}

func (s *Service) checkSeparation(ctx context.Context, q storage.Querier, realmID string, holders []Subject, roleIDs []string) error {
	if q == nil {
		q = s.d.DB.Pool
	}
	if len(holders) == 0 || len(roleIDs) == 0 {
		return nil
	}
	added, err := s.expandRoles(ctx, q, roleIDs)
	if err != nil {
		return err
	}
	for _, h := range holders {
		held, err := s.HeldRoles(ctx, q, realmID, h)
		if err != nil {
			return err
		}
		all := append(slices.Clone(held), added...)
		rows, err := q.Query(ctx, `SELECT id, incompatible_role_ids FROM roles WHERE id = ANY($1) AND cardinality(incompatible_role_ids) > 0`, all)
		if err != nil {
			return err
		}
		inc := map[string][]string{}
		for rows.Next() {
			var id string
			var ids []string
			if err := rows.Scan(&id, &ids); err != nil {
				rows.Close()
				return err
			}
			inc[id] = ids
		}
		rows.Close()
		// The incoming set itself, and the incoming set against what is held.
		for i, a := range added {
			for _, b := range append(slices.Clone(added[i+1:]), held...) {
				if a != b && (slices.Contains(inc[a], b) || slices.Contains(inc[b], a)) {
					return ErrIncompatibleRoles
				}
			}
		}
	}
	return nil
}

// Effective computes the subject's effective permissions in scope. Realm-scoped
// assignments apply to every organization and project in the realm; organization
// assignments apply only while the membership and organization are active.
// A subject that cannot act holds nothing in any scope: a user account that is
// not active (suspended, locked, pending verification or deletion, deleted;
// recovery_restricted accounts keep their access) or a service principal that
// is disabled or deleted. Check and every decision built on Effective then
// deny, including a job re-checking its requester's authority (INT-006).
func (s *Service) Effective(ctx context.Context, q storage.Querier, realmID string, subj Subject, scope Scope) (*PermissionSet, error) {
	return s.effective(ctx, q, realmID, subj, scope, "", false)
}

// EffectiveInProject is Effective for a resource that belongs to project
// projectID (AZ-002): the subject's project-scoped assignments for that
// project count in addition to the realm-wide ones and, in an organization
// scope, the organization's. They count only while the project is active
// and, in an organization's context, only when the project belongs to that
// organization (ProjectContext), so a project role grants nothing outside
// its project, at organization or realm level, or in another tenant's
// context. Explicit denies of any held role still override every allow
// (AZ-004). An empty projectID is Effective.
func (s *Service) EffectiveInProject(ctx context.Context, q storage.Querier, realmID string, subj Subject, scope Scope, projectID string) (*PermissionSet, error) {
	return s.effective(ctx, q, realmID, subj, scope, projectID, false)
}

// ProjectContext reports whether project projectID exists in the realm and,
// when orgID is not empty, whether it belongs to that organization: the
// organization owns it, or holds an active, unexpired project grant for it
// (INV-012). Without an organization, an existing project belongs.
func (s *Service) ProjectContext(ctx context.Context, q storage.Querier, realmID, projectID, orgID string) (exists, belongs bool, err error) {
	exists, _, belongs, err = s.projectStatus(ctx, q, realmID, projectID, orgID)
	return exists, belongs, err
}

func (s *Service) projectStatus(ctx context.Context, q storage.Querier, realmID, projectID, orgID string) (exists, active, belongs bool, err error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	err = q.QueryRow(ctx, `SELECT p.state='active', ($3 = '' OR coalesce(p.owner_organization_id,'') = $3
			OR EXISTS (SELECT 1 FROM project_grants g WHERE g.realm_id=p.realm_id AND g.project_id=p.id AND g.organization_id=$3
				AND g.state='active' AND (g.valid_until IS NULL OR g.valid_until > $4)))
		FROM projects p WHERE p.realm_id=$1 AND p.id=$2`, realmID, projectID, orgID, s.d.Now()).Scan(&active, &belongs)
	if storage.IsNoRows(err) {
		return false, false, false, nil
	}
	if err != nil {
		return false, false, false, err
	}
	return true, active, belongs, nil
}

// HeldForOrganizationDeletion reports whether subj may still finish deleting
// organization orgID, re-checked when the deletion job runs (TEN-024,
// INT-006): org.delete is evaluated as if the organization, which beginning
// the deletion already closed, were still active. Everything else (the
// subject's state, membership and assignments) counts as it is now.
func (s *Service) HeldForOrganizationDeletion(ctx context.Context, realmID string, subj Subject, orgID string) (bool, error) {
	ps, err := s.effective(ctx, nil, realmID, subj, Scope{Type: ScopeOrganization, ID: orgID}, "", true)
	if err != nil {
		return false, err
	}
	return ps.Has("org.delete"), nil
}

// effective is Effective, with the project-scoped assignments of projectID
// (EffectiveInProject; a project scope names its project itself); deleting
// also counts an organization that is being deleted as active (only for
// HeldForOrganizationDeletion).
func (s *Service) effective(ctx context.Context, q storage.Querier, realmID string, subj Subject, scope Scope, projectID string, deleting bool) (*PermissionSet, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	if ok, err := s.subjectActive(ctx, q, realmID, subj); err != nil {
		return nil, err
	} else if !ok {
		return s.permissionsForRoles(ctx, q, nil)
	}
	now := s.d.Now()
	roleIDs := []string{}
	// Every query selects (role_id, conditions); conditional grants apply only
	// when their conditions hold for the trusted request context (AZ-012).
	add := func(sql string, args ...any) error {
		sql = strings.Replace(sql, "SELECT ra.role_id FROM", "SELECT ra.role_id, ra.conditions FROM", 1)
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var raw []byte
			if err := rows.Scan(&id, &raw); err != nil {
				return err
			}
			if len(raw) > 2 {
				var m map[string]any
				if json.Unmarshal(raw, &m) != nil {
					continue // unreadable conditions never grant (AZ-007)
				}
				c, err := ParseConditions(m)
				if err != nil || !c.Holds(ctx, now) {
					continue
				}
			}
			roleIDs = append(roleIDs, id)
		}
		return rows.Err()
	}
	validity := ` AND (ra.valid_from IS NULL OR ra.valid_from <= $4) AND (ra.expires_at IS NULL OR ra.expires_at > $4)`
	if err := add(`SELECT ra.role_id FROM role_assignments ra WHERE ra.realm_id=$1 AND ra.subject_type=$2 AND ra.subject_id=$3
		AND ra.scope_type='realm'`+validity, realmID, subj.Type, subj.ID, now); err != nil {
		return nil, err
	}
	switch scope.Type {
	case ScopeOrganization:
		if subj.Type == SubjectUser {
			var membershipID string
			err := q.QueryRow(ctx, `SELECT m.id FROM memberships m JOIN organizations o ON o.id=m.organization_id
				WHERE m.realm_id=$1 AND m.organization_id=$2 AND m.user_id=$3 AND m.state='active'
				AND (o.state='active' OR ($5 AND o.state='deleting'))
				AND (m.expires_at IS NULL OR m.expires_at > $4)`, realmID, scope.ID, subj.ID, now, deleting).Scan(&membershipID)
			if err == nil {
				if err := add(`SELECT ra.role_id FROM role_assignments ra WHERE ra.realm_id=$1 AND ra.scope_type='organization'
					AND ra.scope_id=$2 AND ra.membership_id=$3`+validity, realmID, scope.ID, membershipID, now); err != nil {
					return nil, err
				}
				groups, err := s.groupClosure(ctx, q, scope.ID, membershipID, now)
				if err != nil {
					return nil, err
				}
				if len(groups) > 0 {
					if err := add(`SELECT ra.role_id FROM role_assignments ra WHERE ra.realm_id=$1 AND ra.scope_type='organization'
						AND ra.scope_id=$2 AND ra.subject_type='group' AND ra.subject_id = ANY($3)`+validity,
						realmID, scope.ID, groups, now); err != nil {
						return nil, err
					}
				}
			} else if !storage.IsNoRows(err) {
				return nil, err
			}
		} else if subj.Type == SubjectService {
			if err := add(`SELECT ra.role_id FROM role_assignments ra JOIN service_principals sp ON sp.id=ra.subject_id
				WHERE ra.realm_id=$1 AND ra.scope_type='organization' AND ra.scope_id=$2 AND ra.subject_type='service_principal'
				AND ra.subject_id=$3 AND sp.state='active'`+validity, realmID, scope.ID, subj.ID, now); err != nil {
				return nil, err
			}
		}
	case ScopeProject:
		projectID = scope.ID
	}
	// Project-scoped assignments (AZ-002) apply only to their own project,
	// while it is active and, in an organization scope, belongs to that
	// organization; they are the subject's own assignments (users and
	// service principals).
	if projectID != "" {
		orgID := ""
		if scope.Type == ScopeOrganization {
			orgID = scope.ID
		}
		_, active, belongs, err := s.projectStatus(ctx, q, realmID, projectID, orgID)
		if err != nil {
			return nil, err
		}
		if active && belongs {
			if err := add(`SELECT ra.role_id FROM role_assignments ra WHERE ra.realm_id=$1 AND ra.subject_type=$2 AND ra.subject_id=$3
				AND ra.scope_type='project' AND ra.scope_id=$5`+validity, realmID, subj.Type, subj.ID, now, projectID); err != nil {
				return nil, err
			}
		}
	}
	return s.permissionsForRoles(ctx, q, roleIDs)
}

// subjectActive reports whether a user or service principal may hold
// permissions now (see Effective); a missing subject may not. Other subject
// types (groups) have no account state of their own.
func (s *Service) subjectActive(ctx context.Context, q storage.Querier, realmID string, subj Subject) (bool, error) {
	var sql string
	switch subj.Type {
	case SubjectUser:
		sql = `SELECT state IN ('active','recovery_restricted') FROM users WHERE realm_id=$1 AND id=$2`
	case SubjectService:
		sql = `SELECT state='active' FROM service_principals WHERE realm_id=$1 AND id=$2`
	default:
		return true, nil
	}
	var ok bool
	err := q.QueryRow(ctx, sql, realmID, subj.ID).Scan(&ok)
	if storage.IsNoRows(err) {
		return false, nil
	}
	return ok, err
}

func (s *Service) permissionsForRoles(ctx context.Context, q storage.Querier, roleIDs []string) (*PermissionSet, error) {
	ps := &PermissionSet{Allow: map[string][]string{}, Deny: map[string][]string{}, RoleNames: []string{}}
	if len(roleIDs) == 0 {
		return ps, nil
	}
	expanded, err := s.expandRoles(ctx, q, roleIDs)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT r.name, p.name, rp.effect FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id=r.id LEFT JOIN permissions p ON p.id=rp.permission_id
		WHERE r.id = ANY($1) ORDER BY r.name, p.name`, expanded)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var role string
		var perm, effect *string
		if err := rows.Scan(&role, &perm, &effect); err != nil {
			return nil, err
		}
		names[role] = true
		if perm == nil {
			continue
		}
		if effect != nil && *effect == "deny" {
			ps.Deny[*perm] = append(ps.Deny[*perm], role)
		} else {
			ps.Allow[*perm] = append(ps.Allow[*perm], role)
		}
	}
	for n := range names {
		ps.RoleNames = append(ps.RoleNames, n)
	}
	sort.Strings(ps.RoleNames)
	return ps, rows.Err()
}

// Check evaluates one permission. Errors and missing data deny (AZ-007).
func (s *Service) Check(ctx context.Context, q storage.Querier, realmID string, subj Subject, perm string, scope Scope) bool {
	ps, err := s.Effective(ctx, q, realmID, subj, scope)
	if err != nil {
		s.d.Log.Warn("authorization evaluation failed; denying", "error", err, "permission", perm)
		return false
	}
	return ps.Has(perm)
}

// Require returns ErrForbidden unless the permission is held.
func (s *Service) Require(ctx context.Context, q storage.Querier, realmID string, subj Subject, perm string, scope Scope) error {
	if !s.Check(ctx, q, realmID, subj, perm, scope) {
		return problem.ErrForbidden
	}
	return nil
}

// RolePermissions returns the expanded allowed permission set of a role.
func (s *Service) RolePermissions(ctx context.Context, q storage.Querier, roleID string) (*PermissionSet, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	return s.permissionsForRoles(ctx, q, []string{roleID})
}

// withinCeiling checks that every permission is effectively held by the actor in
// scope (TEN-008, AZ-006). Identity-provider permissions (realm., org., support.,
// platform.) must always be held. Application permissions are owned by realm role
// administrators (realm.roles.write), who may delegate them; everyone else, such as
// organization administrators, may delegate only application permissions they hold.
func withinCeiling(actor *PermissionSet, perms []string) (string, bool) {
	appAuthority := actor.Has("realm.roles.write")
	for _, p := range perms {
		if !isReservedNamespace(p) && appAuthority {
			continue
		}
		if !actor.Has(p) {
			return p, false
		}
	}
	return "", true
}

// HoldsPrivilegedRealmRole reports whether a user holds any realm-boundary role with
// privileged permissions; such administrators must use MFA (MFA-003).
func (s *Service) HoldsPrivilegedRealmRole(ctx context.Context, q storage.Querier, realmID, userID string) (bool, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		WHERE ra.realm_id=$1 AND ra.subject_type='user' AND ra.subject_id=$2 AND ra.scope_type='realm'
		AND (ra.expires_at IS NULL OR ra.expires_at > $3))`, realmID, userID, s.d.Now()).Scan(&exists)
	return exists, err
}

// ---------- role management ----------

// RoleInput creates a role.
type RoleInput struct {
	Boundary            string   `json:"boundary_type"`
	OrganizationID      string   `json:"organization_id"`
	ProjectID           string   `json:"project_id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Permissions         []string `json:"permissions"`
	DeniedPermissions   []string `json:"denied_permissions"`
	CompositeRoleIDs    []string `json:"composite_role_ids"`
	IncompatibleRoleIDs []string `json:"incompatible_role_ids"`
	RequiresApproval    bool     `json:"requires_approval"`
}

func (in *RoleInput) scope(realmID string) Scope {
	switch in.Boundary {
	case "organization":
		if in.OrganizationID == "" {
			return Scope{ScopeRealm, realmID}
		}
		return Scope{ScopeOrganization, in.OrganizationID}
	case "project":
		return Scope{ScopeProject, in.ProjectID}
	default:
		return Scope{ScopeRealm, realmID}
	}
}

func writePermForRole(boundary, orgID string) string {
	if boundary == "organization" && orgID != "" {
		return "org.roles.write"
	}
	return "realm.roles.write"
}

// CreateRole creates a role after checking the actor's ceiling, including permissions
// reachable through composites (TEST-010 direct and indirect escalation).
func (s *Service) CreateRole(ctx context.Context, realmID string, actor Subject, in RoleInput, auditActor audit.Ref) (*Role, error) {
	var out *Role
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.createRoleTx(ctx, tx, realmID, &actor, in, auditActor, false)
		return err
	})
	return out, err
}

// CreateRoleTx creates a role inside tx with the actor's ceiling check.
func (s *Service) CreateRoleTx(ctx context.Context, tx pgx.Tx, realmID string, actor Subject, in RoleInput, auditActor audit.Ref) (*Role, error) {
	return s.createRoleTx(ctx, tx, realmID, &actor, in, auditActor, false)
}

// CreateBuiltInRoleTx seeds a built-in role without a ceiling check (bootstrap only).
func (s *Service) CreateBuiltInRoleTx(ctx context.Context, tx pgx.Tx, realmID string, def RoleDef) (*Role, error) {
	return s.createRoleTx(ctx, tx, realmID, nil, RoleInput{Boundary: def.Boundary, Name: def.Name, Description: def.Description,
		Permissions: ExpandPatterns(def.Permissions)}, audit.System, true, def.Owner, def.Protected)
}

func (s *Service) createRoleTx(ctx context.Context, tx pgx.Tx, realmID string, actor *Subject, in RoleInput, auditActor audit.Ref, builtIn bool, flags ...bool) (*Role, error) {
	owner, protected := false, false
	if len(flags) == 2 {
		owner, protected = flags[0], flags[1]
	}
	if in.Boundary == "" {
		in.Boundary = "realm"
	}
	if in.Name == "" || len(in.Name) > 100 || strings.ContainsAny(in.Name, "\r\n\t") {
		return nil, problem.ErrValidation.WithField("name", "required, at most 100 characters")
	}
	switch in.Boundary {
	case "realm":
		in.OrganizationID, in.ProjectID = "", ""
	case "organization":
		in.ProjectID = ""
		if !builtIn && in.OrganizationID == "" && actor != nil {
			// Realm-wide organization role templates are realm configuration.
			eff, err := s.Effective(ctx, tx, realmID, *actor, Scope{Type: ScopeRealm, ID: realmID})
			if err != nil {
				return nil, err
			}
			if !eff.Has("realm.roles.write") {
				return nil, problem.ErrValidation.WithField("organization_id", "organization roles belong to one organization")
			}
		}
	case "project":
		in.OrganizationID = ""
		if in.ProjectID == "" {
			return nil, problem.ErrValidation.WithField("project_id", "required for project roles")
		}
	default:
		return nil, problem.ErrValidation.WithField("boundary_type", "realm, organization or project")
	}
	permIDs, err := s.resolvePermissions(ctx, tx, realmID, append(slices.Clone(in.Permissions), in.DeniedPermissions...))
	if err != nil {
		return nil, err
	}
	if in.Boundary == "organization" {
		for _, p := range in.Permissions {
			if strings.HasPrefix(p, "realm.") || strings.HasPrefix(p, "support.") || strings.HasPrefix(p, "platform.") {
				return nil, problem.ErrValidation.WithField("permissions", "organization roles cannot carry realm, support or platform permissions (DOM-005)")
			}
		}
	}
	if in.Boundary == "project" {
		for _, p := range in.Permissions {
			if isReservedNamespace(p) {
				return nil, problem.ErrValidation.WithField("permissions", "application roles cannot imply identity-provider administration (AZ-005)")
			}
		}
	}
	scope := in.scope(realmID)
	if actor != nil {
		eff, err := s.Effective(ctx, tx, realmID, *actor, scope)
		if err != nil {
			return nil, err
		}
		if !eff.Has(writePermForRole(in.Boundary, in.OrganizationID)) {
			return nil, problem.ErrForbidden
		}
		if p, ok := withinCeiling(eff, in.Permissions); !ok {
			return nil, problem.ErrGrantCeiling.WithDetailf("permission %s exceeds your delegable set", p)
		}
		if len(in.CompositeRoleIDs) > 0 {
			composite, err := s.permissionsForRoles(ctx, tx, in.CompositeRoleIDs)
			if errors.Is(err, ErrGraphTooLarge) {
				return nil, errRoleGraphTooLarge
			}
			if err != nil {
				return nil, err
			}
			if p, ok := withinCeiling(eff, composite.List()); !ok {
				return nil, problem.ErrGrantCeiling.WithDetailf("composite role grants %s which exceeds your delegable set", p)
			}
		}
	}
	if err := s.validateRoleRefs(ctx, tx, realmID, in); err != nil {
		return nil, err
	}
	id := ids.New(ids.Role)
	_, err = tx.Exec(ctx, `INSERT INTO roles (id, realm_id, boundary_type, organization_id, project_id, name, description, protected, built_in,
		is_owner_role, composite_role_ids, incompatible_role_ids, requires_approval, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`, id, realmID, in.Boundary, nilIfEmpty(in.OrganizationID),
		nilIfEmpty(in.ProjectID), in.Name, nilIfEmpty(in.Description), protected, builtIn, owner, nonNilStrings(in.CompositeRoleIDs),
		nonNilStrings(in.IncompatibleRoleIDs), in.RequiresApproval, s.d.Now())
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, problem.ErrConflict.WithDetail("a role with this name already exists in the boundary")
		}
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithDetail("unknown organization or project")
		}
		return nil, err
	}
	for i, pid := range permIDs {
		effect := "allow"
		if i >= len(in.Permissions) {
			effect = "deny"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions (realm_id, role_id, permission_id, effect, granted_by_type, granted_by_id)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, realmID, id, pid, effect, auditActor.Type, auditActor.ID); err != nil {
			return nil, err
		}
	}
	// Reject cycles introduced through composites.
	if len(in.CompositeRoleIDs) > 0 {
		if err := s.assertAcyclic(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	if !builtIn {
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "role.created", RealmID: realmID, OrgID: in.OrganizationID, Actor: auditActor,
			Target: &audit.Ref{Type: "role", ID: id}, Category: "authorization", Metadata: map[string]any{"name": in.Name, "boundary": in.Boundary,
				"permissions": in.Permissions, "denied_permissions": in.DeniedPermissions, "composites": in.CompositeRoleIDs}}); err != nil {
			return nil, err
		}
	}
	return s.Role(ctx, tx, realmID, id)
}

func isReservedNamespace(p string) bool {
	return strings.HasPrefix(p, "realm.") || strings.HasPrefix(p, "org.") || strings.HasPrefix(p, "support.") || strings.HasPrefix(p, "platform.")
}

func (s *Service) validateRoleRefs(ctx context.Context, tx pgx.Tx, realmID string, in RoleInput) error {
	for _, rid := range append(slices.Clone(in.CompositeRoleIDs), in.IncompatibleRoleIDs...) {
		r, err := s.Role(ctx, tx, realmID, rid)
		if err != nil {
			return problem.ErrValidation.WithField("composite_role_ids", "unknown role "+rid)
		}
		if r.Boundary != in.Boundary {
			return problem.ErrValidation.WithField("composite_role_ids", "composite roles must share the boundary type")
		}
		if r.OrganizationID != "" && r.OrganizationID != in.OrganizationID {
			return problem.ErrValidation.WithField("composite_role_ids", "cannot compose another organization's role")
		}
	}
	// A project role composes only roles of its own project, so it never
	// carries another project's grants (AZ-011, AZ-002).
	for _, rid := range in.CompositeRoleIDs {
		if r, err := s.Role(ctx, tx, realmID, rid); err == nil && r.ProjectID != in.ProjectID {
			return problem.ErrValidation.WithField("composite_role_ids", "cannot compose another project's role")
		}
	}
	return nil
}

// errRoleGraphTooLarge refuses a composite role whose expansion would exceed
// limits.max_role_expansion: evaluating it could only fail closed (AZ-011).
var errRoleGraphTooLarge = problem.ErrValidation.WithField("composite_role_ids", "role graph exceeds evaluation bounds (limits.max_role_expansion)")

// errRoleCycle refuses composites that would form a cycle (TEST-014).
var errRoleCycle = problem.ErrValidation.WithField("composite_role_ids", "composite roles must not form a cycle (TEST-014)")

// assertAcyclic checks the composite graph of a newly created role: no
// cycle, and no more roles than limits.max_role_expansion, counted as
// evaluation counts them (the role and every role it reaches).
func (s *Service) assertAcyclic(ctx context.Context, tx pgx.Tx, start string) error {
	err := checkCompositeGraph(start, s.MaxExpansion, func(id string) ([]string, error) {
		var composites []string
		err := tx.QueryRow(ctx, `SELECT composite_role_ids FROM roles WHERE id=$1`, id).Scan(&composites)
		if storage.IsNoRows(err) {
			return nil, nil // as in expandRoles: a missing role composes nothing
		}
		return composites, err
	})
	if errors.Is(err, ErrGraphTooLarge) {
		return errRoleGraphTooLarge
	}
	return err
}

// checkCompositeGraph walks the composite roles reachable from start depth
// first, each role once, and returns errRoleCycle when one leads back to a
// role on the current path, or ErrGraphTooLarge when more than max roles
// (start included) are reachable (AZ-011, TEST-014). The walk is linear in
// the graph's size, so a wide, diamond-shaped composition cannot make it
// expensive.
func checkCompositeGraph(start string, max int, composites func(id string) ([]string, error)) error {
	const onPath, finished = 1, 2
	state := map[string]int{}
	var visit func(id string) error
	visit = func(id string) error {
		state[id] = onPath
		if len(state) > max {
			return ErrGraphTooLarge
		}
		next, err := composites(id)
		if err != nil {
			return err
		}
		for _, c := range next {
			switch state[c] {
			case onPath:
				return errRoleCycle
			case finished:
				continue
			}
			if err := visit(c); err != nil {
				return err
			}
		}
		state[id] = finished
		return nil
	}
	return visit(start)
}

func (s *Service) resolvePermissions(ctx context.Context, q storage.Querier, realmID string, names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, n := range names {
		var id string
		if err := q.QueryRow(ctx, `SELECT id FROM permissions WHERE realm_id=$1 AND name=$2`, realmID, n).Scan(&id); err != nil {
			if storage.IsNoRows(err) {
				return nil, problem.ErrValidation.WithField("permissions", "unknown permission "+n)
			}
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// ModifyRolePermissions adds or removes permissions with ceiling checks. Protected
// built-in roles are immutable through the API.
//
// expectedVersion, when not zero, must match the role's version (API-010).
func (s *Service) ModifyRolePermissions(ctx context.Context, realmID, roleID string, expectedVersion int64, actor Subject, add, remove []string, auditActor audit.Ref) (*Role, error) {
	var out *Role
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.ModifyRolePermissionsTx(ctx, tx, realmID, roleID, expectedVersion, actor, add, remove, auditActor)
		return err
	})
	return out, err
}

// ModifyRolePermissionsTx is ModifyRolePermissions inside tx.
func (s *Service) ModifyRolePermissionsTx(ctx context.Context, tx pgx.Tx, realmID, roleID string, expectedVersion int64, actor Subject, add, remove []string, auditActor audit.Ref) (*Role, error) {
	var out *Role
	err := func() error {
		r, err := scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, roleID))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && r.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if r.BuiltIn || r.Protected {
			return problem.ErrForbidden.WithDetail("built-in roles cannot be modified")
		}
		scope := (&RoleInput{Boundary: r.Boundary, OrganizationID: r.OrganizationID, ProjectID: r.ProjectID}).scope(realmID)
		eff, err := s.Effective(ctx, tx, realmID, actor, scope)
		if err != nil {
			return err
		}
		if !eff.Has(writePermForRole(r.Boundary, r.OrganizationID)) {
			return problem.ErrForbidden
		}
		// Adding needs the ceiling; removing needs it too, otherwise an administrator could
		// strip an explicit deny or alter a role they could not have created.
		if p, ok := withinCeiling(eff, append(slices.Clone(add), remove...)); !ok {
			return problem.ErrGrantCeiling.WithDetailf("permission %s exceeds your delegable set", p)
		}
		for _, p := range add {
			if r.Boundary == "organization" && (strings.HasPrefix(p, "realm.") || strings.HasPrefix(p, "support.")) ||
				r.Boundary == "project" && isReservedNamespace(p) {
				return problem.ErrValidation.WithField("permissions", "permission not allowed in this boundary")
			}
		}
		addIDs, err := s.resolvePermissions(ctx, tx, realmID, add)
		if err != nil {
			return err
		}
		remIDs, err := s.resolvePermissions(ctx, tx, realmID, remove)
		if err != nil {
			return err
		}
		for _, pid := range addIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO role_permissions (realm_id, role_id, permission_id, effect, granted_by_type, granted_by_id)
				VALUES ($1,$2,$3,'allow',$4,$5) ON CONFLICT DO NOTHING`, realmID, roleID, pid, auditActor.Type, auditActor.ID); err != nil {
				return err
			}
		}
		for _, pid := range remIDs {
			if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND permission_id=$2`, roleID, pid); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE roles SET version=version+1, updated_at=$2 WHERE id=$1`, roleID, s.d.Now()); err != nil {
			return err
		}
		if err := s.bumpHoldersTx(ctx, tx, roleID); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "role.permissions.changed", RealmID: realmID, OrgID: r.OrganizationID,
			Actor: auditActor, Target: &audit.Ref{Type: "role", ID: roleID}, Category: "authorization",
			Metadata: map[string]any{"added": add, "removed": remove}}); err != nil {
			return err
		}
		out, err = s.Role(ctx, tx, realmID, roleID)
		return err
	}()
	return out, err
}

// DeleteRole deletes a custom role and its assignments.
func (s *Service) DeleteRole(ctx context.Context, realmID, roleID string, actor Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		r, err := scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, roleID))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if r.BuiltIn || r.Protected {
			return problem.ErrForbidden.WithDetail("built-in roles cannot be deleted")
		}
		scope := (&RoleInput{Boundary: r.Boundary, OrganizationID: r.OrganizationID, ProjectID: r.ProjectID}).scope(realmID)
		eff, err := s.Effective(ctx, tx, realmID, actor, scope)
		if err != nil {
			return err
		}
		if !eff.Has(writePermForRole(r.Boundary, r.OrganizationID)) {
			return problem.ErrForbidden
		}
		rp, err := s.permissionsForRoles(ctx, tx, []string{roleID})
		if err != nil {
			return err
		}
		if p, ok := withinCeiling(eff, rp.List()); !ok {
			return problem.ErrGrantCeiling.WithDetailf("permission %s exceeds your delegable set", p)
		}
		var users int
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM roles WHERE realm_id=$1 AND $2 = ANY(composite_role_ids)`, realmID, roleID).Scan(&users)
		if users > 0 {
			return problem.ErrConflict.WithDetail("role is used by a composite role")
		}
		if err := s.bumpHoldersTx(ctx, tx, roleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE role_id=$1`, roleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM roles WHERE id=$1`, roleID); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "role.deleted", RealmID: realmID, OrgID: r.OrganizationID, Actor: auditActor,
			Target: &audit.Ref{Type: "role", ID: roleID}, Category: "authorization", Metadata: map[string]any{"name": r.Name}})
		return err
	})
}

// bumpHoldersTx invalidates cached decisions of everyone a change to roleID
// reaches: holders of the role and of every role composing it, at any depth,
// whether assigned directly, through a membership, or through a group or one
// of its ancestors.
func (s *Service) bumpHoldersTx(ctx context.Context, tx pgx.Tx, roleID string) error {
	const affected = `WITH RECURSIVE up(id) AS (SELECT $1::text
			UNION SELECT r.id FROM roles r JOIN up ON up.id = ANY(r.composite_role_ids))`
	if _, err := tx.Exec(ctx, affected+` UPDATE memberships SET revision=revision+1 WHERE id IN (SELECT membership_id FROM role_assignments
		WHERE role_id IN (SELECT id FROM up) AND membership_id IS NOT NULL)`, roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, affected+` UPDATE service_principals SET permission_revision=permission_revision+1
		WHERE id IN (SELECT subject_id FROM role_assignments WHERE role_id IN (SELECT id FROM up) AND subject_type='service_principal')`, roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, affected+` UPDATE users SET authz_revision=authz_revision+1
		WHERE id IN (SELECT subject_id FROM role_assignments WHERE role_id IN (SELECT id FROM up) AND subject_type='user')`, roleID); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, affected+` SELECT DISTINCT subject_id FROM role_assignments WHERE role_id IN (SELECT id FROM up) AND subject_type='group'`, roleID)
	if err != nil {
		return err
	}
	var groups []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, g := range groups {
		if err := bumpGroupMembersTx(ctx, tx, g); err != nil {
			return err
		}
	}
	return nil
}

// ---------- permissions registry ----------

// Permission is a registered permission.
type Permission struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	Description     string `json:"description,omitempty"`
	ResourceType    string `json:"resource_type,omitempty"`
	OwnerResourceID string `json:"owner_resource_id,omitempty"`
	Sensitivity     string `json:"sensitivity"`
	BuiltIn         bool   `json:"built_in"`
}

// SeedBuiltInsTx creates the built-in permissions and roles for a realm.
func (s *Service) SeedBuiltInsTx(ctx context.Context, tx pgx.Tx, realmID string) error {
	for _, p := range BuiltInPermissions {
		if _, err := tx.Exec(ctx, `INSERT INTO permissions (id, realm_id, name, namespace, description, sensitivity, built_in)
			VALUES ($1,$2,$3,$4,$5,$6,true) ON CONFLICT (realm_id, name) DO NOTHING`, ids.New(ids.Permission), realmID, p.Name, p.Namespace, p.Description, p.Sensitivity); err != nil {
			return err
		}
	}
	for _, def := range BuiltInRoles {
		if _, err := s.RoleByName(ctx, tx, realmID, def.Boundary, def.Name); err == nil {
			continue
		}
		if _, err := s.CreateBuiltInRoleTx(ctx, tx, realmID, def); err != nil {
			return err
		}
	}
	return nil
}

// SyncBuiltIns brings every realm's built-in permissions and built-in role
// grants up to this release (additive only), so permissions introduced by an
// upgrade reach existing realms. It is idempotent and safe to run on every
// startup.
func (s *Service) SyncBuiltIns(ctx context.Context) error {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id FROM realms`)
	if err != nil {
		return err
	}
	var realms []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		realms = append(realms, id)
	}
	rows.Close()
	for _, realmID := range realms {
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if err := s.SeedBuiltInsTx(ctx, tx, realmID); err != nil {
				return err
			}
			for _, def := range BuiltInRoles {
				role, err := s.RoleByName(ctx, tx, realmID, def.Boundary, def.Name)
				if err != nil || !role.BuiltIn {
					continue
				}
				ids, err := s.resolvePermissions(ctx, tx, realmID, ExpandPatterns(def.Permissions))
				if err != nil {
					return err
				}
				for _, pid := range ids {
					if _, err := tx.Exec(ctx, `INSERT INTO role_permissions (realm_id, role_id, permission_id, effect, granted_by_type) VALUES ($1,$2,$3,'allow','system')
						ON CONFLICT DO NOTHING`, realmID, role.ID, pid); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// RegisterPermission registers an application permission (AZ-001, AZ-022).
func (s *Service) RegisterPermission(ctx context.Context, realmID string, p Permission, auditActor audit.Ref) (*Permission, error) {
	if p.Name == "" || len(p.Name) > 128 || strings.ContainsAny(p.Name, " \t\r\n*") || !strings.Contains(p.Name, ".") {
		return nil, problem.ErrValidation.WithField("name", "namespaced name such as orders.refund required")
	}
	if isReservedNamespace(p.Name) {
		return nil, problem.ErrValidation.WithField("name", "realm., org., support. and platform. namespaces are reserved (DOM-005)")
	}
	if p.Sensitivity == "" {
		p.Sensitivity = "normal"
	}
	switch p.Sensitivity {
	case "low", "normal", "high", "privileged":
	default:
		return nil, problem.ErrValidation.WithField("sensitivity", "low, normal, high or privileged")
	}
	if len(p.Description) > 1000 {
		return nil, problem.ErrValidation.WithField("description", "too long")
	}
	p.ID = ids.New(ids.Permission)
	p.Namespace = "application"
	p.BuiltIn = false
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.registerPermissionTx(ctx, tx, realmID, &p, auditActor)
	})
	return &p, err
}

// RegisterPermissionTx registers an application permission inside tx.
func (s *Service) RegisterPermissionTx(ctx context.Context, tx pgx.Tx, realmID string, p Permission, auditActor audit.Ref) (*Permission, error) {
	if p.Name == "" || len(p.Name) > 128 || strings.ContainsAny(p.Name, " \t\r\n*") || !strings.Contains(p.Name, ".") || isReservedNamespace(p.Name) {
		return nil, problem.ErrValidation.WithField("name", "a non-reserved namespaced name such as orders.refund is required")
	}
	if p.Sensitivity == "" {
		p.Sensitivity = "normal"
	}
	switch p.Sensitivity {
	case "low", "normal", "high", "privileged":
	default:
		return nil, problem.ErrValidation.WithField("sensitivity", "low, normal, high or privileged")
	}
	p.ID, p.Namespace, p.BuiltIn = ids.New(ids.Permission), "application", false
	return &p, s.registerPermissionTx(ctx, tx, realmID, &p, auditActor)
}

func (s *Service) registerPermissionTx(ctx context.Context, tx pgx.Tx, realmID string, p *Permission, auditActor audit.Ref) error {
	{
		_, err := tx.Exec(ctx, `INSERT INTO permissions (id, realm_id, name, namespace, description, resource_type, owner_resource_id, sensitivity)
			VALUES ($1,$2,$3,'application',$4,$5,$6,$7)`, p.ID, realmID, p.Name, nilIfEmpty(p.Description), nilIfEmpty(p.ResourceType),
			nilIfEmpty(p.OwnerResourceID), p.Sensitivity)
		if storage.IsUniqueViolation(err) {
			return problem.ErrConflict.WithDetail("permission already registered")
		}
		if err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "permission.registered", RealmID: realmID, Actor: auditActor,
			Target: &audit.Ref{Type: "permission", ID: p.ID}, Category: "authorization", Metadata: map[string]any{"name": p.Name}})
		return err
	}
}

// ListPermissions lists registered permissions.
func (s *Service) ListPermissions(ctx context.Context, realmID string) ([]Permission, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, name, namespace, coalesce(description,''), coalesce(resource_type,''), coalesce(owner_resource_id,''),
		sensitivity, built_in FROM permissions WHERE realm_id=$1 ORDER BY name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Permission{}
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Namespace, &p.Description, &p.ResourceType, &p.OwnerResourceID, &p.Sensitivity, &p.BuiltIn); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------- assignments ----------

// Assignment is a scoped role assignment.
type Assignment struct {
	ID           string         `json:"id"`
	RoleID       string         `json:"role_id"`
	RoleName     string         `json:"role_name,omitempty"`
	Subject      Subject        `json:"subject"`
	MembershipID string         `json:"membership_id,omitempty"`
	Scope        Scope          `json:"scope"`
	Conditions   map[string]any `json:"conditions,omitempty"`
	ValidFrom    *time.Time     `json:"valid_from,omitempty"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	GrantedBy    string         `json:"granted_by,omitempty"`
	ApprovedBy   string         `json:"approved_by,omitempty"`
	Source       string         `json:"source"`
	Reason       string         `json:"reason,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// AssignInput requests a role assignment.
type AssignInput struct {
	RoleID     string
	Subject    Subject
	Scope      Scope
	ValidFrom  *time.Time
	ExpiresAt  *time.Time
	Reason     string
	ApproverID string
	Source     string
	Conditions map[string]any
	// SkipCeiling is used only by trusted internal workflows that already
	// re-validated the authorization basis (e.g. invitation acceptance, bootstrap).
	SkipCeiling bool
}

// Assign creates an assignment with ceiling and separation-of-duty checks.
func (s *Service) Assign(ctx context.Context, realmID string, actor Subject, in AssignInput, auditActor audit.Ref) (*Assignment, error) {
	var out *Assignment
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.AssignTx(ctx, tx, realmID, &actor, in, auditActor)
		return err
	})
	return out, err
}

// CheckAssignable verifies that actor may grant role in scope (ceiling, boundary, SoD).
func (s *Service) CheckAssignable(ctx context.Context, q storage.Querier, realmID string, actor Subject, role *Role, scope Scope) error {
	eff, err := s.Effective(ctx, q, realmID, actor, scope)
	if err != nil {
		return err
	}
	assignPerm := "realm.roles.assign"
	if scope.Type == ScopeOrganization {
		assignPerm = "org.roles.assign"
	}
	if !eff.Has(assignPerm) {
		return problem.ErrForbidden
	}
	rp, err := s.permissionsForRoles(ctx, q, []string{role.ID})
	if err != nil {
		return err
	}
	if p, ok := withinCeiling(eff, rp.List()); !ok {
		return problem.ErrGrantCeiling.WithDetailf("role %s grants %s which exceeds your delegable set", role.Name, p)
	}
	if role.IsOwnerRole && !eff.Has("org.ownership.transfer") {
		return problem.ErrGrantCeiling.WithDetail("only owners can grant ownership")
	}
	return nil
}

func roleFitsScope(role *Role, scope Scope) bool {
	switch scope.Type {
	case ScopeRealm:
		return role.Boundary == "realm"
	case ScopeOrganization:
		return role.Boundary == "organization" && (role.OrganizationID == "" || role.OrganizationID == scope.ID)
	case ScopeProject:
		return role.Boundary == "project" && role.ProjectID == scope.ID
	}
	return false
}

// AssignTx creates an assignment inside tx. actor may be nil only with SkipCeiling.
func (s *Service) AssignTx(ctx context.Context, tx pgx.Tx, realmID string, actor *Subject, in AssignInput, auditActor audit.Ref) (*Assignment, error) {
	role, err := s.Role(ctx, tx, realmID, in.RoleID)
	if err != nil {
		return nil, problem.ErrValidation.WithField("role_id", "unknown role")
	}
	if !roleFitsScope(role, in.Scope) {
		return nil, problem.ErrValidation.WithField("scope", "role boundary does not match the assignment scope")
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.d.Now()) {
		return nil, problem.ErrValidation.WithField("expires_at", "must be in the future")
	}
	if !in.SkipCeiling {
		if actor == nil {
			return nil, problem.ErrForbidden
		}
		if err := s.CheckAssignable(ctx, tx, realmID, *actor, role, in.Scope); err != nil {
			return nil, err
		}
		if role.RequiresApproval {
			// Separation of duties: an independent approver who could also grant it (AZ-018).
			if in.ApproverID == "" {
				return nil, problem.ErrForbidden.WithDetail("this role requires an independent approver")
			}
			if in.ApproverID == actor.ID || in.ApproverID == in.Subject.ID {
				return nil, problem.ErrForbidden.WithDetail("self-approval is not permitted")
			}
			if err := s.CheckAssignable(ctx, tx, realmID, Subject{SubjectUser, in.ApproverID}, role, in.Scope); err != nil {
				return nil, problem.ErrForbidden.WithDetail("approver lacks authority for this role")
			}
		}
	}
	var membershipID *string
	if in.Scope.Type == ScopeOrganization && in.Subject.Type == SubjectUser {
		var mid string
		if err := tx.QueryRow(ctx, `SELECT id FROM memberships WHERE realm_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active' FOR UPDATE`,
			realmID, in.Scope.ID, in.Subject.ID).Scan(&mid); err != nil {
			if storage.IsNoRows(err) {
				return nil, problem.ErrValidation.WithDetail("organization roles require an active membership (AZ-003)")
			}
			return nil, err
		}
		membershipID = &mid
	}
	if in.Subject.Type == SubjectGroup && in.Scope.Type != ScopeOrganization {
		// Groups belong to one organization and hold that organization's
		// roles (AZ-010); a realm or project assignment to a group would be
		// stored but never evaluated, so it is refused.
		return nil, problem.ErrValidation.WithField("scope", "groups hold organization roles only")
	}
	if in.Scope.Type == ScopeOrganization && in.Subject.Type == SubjectGroup {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM groups WHERE id=$1 AND organization_id=$2`, in.Subject.ID, in.Scope.ID).Scan(&ok); err != nil {
			return nil, problem.ErrValidation.WithDetail("group does not belong to the organization")
		}
	}
	if in.Subject.Type == SubjectService {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM service_principals WHERE id=$1 AND realm_id=$2 AND state='active'`, in.Subject.ID, realmID).Scan(&ok); err != nil {
			return nil, problem.ErrValidation.WithDetail("unknown or inactive service principal")
		}
	}
	if in.Subject.Type == SubjectUser && in.Scope.Type != ScopeOrganization {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM users WHERE id=$1 AND realm_id=$2 AND state NOT IN ('deleted','pending_deletion')`, in.Subject.ID, realmID).Scan(&ok); err != nil {
			return nil, problem.ErrValidation.WithDetail("unknown user")
		}
	}
	if in.Subject.Type == SubjectUser {
		var guest bool
		_ = tx.QueryRow(ctx, `SELECT is_guest FROM users WHERE id=$1 AND realm_id=$2`, in.Subject.ID, realmID).Scan(&guest)
		if guest {
			return nil, problem.ErrValidation.WithDetail("guest accounts cannot hold roles (REG-010)")
		}
	}
	// Incompatible roles (separation of duties, AZ-018): the roles the subject
	// would hold anywhere — directly, through organization memberships and
	// groups with their ancestors, expanded through composites — never
	// combine incompatible ones. A group grant is checked for every member of
	// the group and of its descendants.
	holders := []Subject{in.Subject}
	if in.Subject.Type == SubjectGroup {
		users, err := s.groupMemberUsers(ctx, tx, in.Subject.ID)
		if err != nil {
			return nil, err
		}
		holders = holders[:0]
		for _, u := range users {
			holders = append(holders, Subject{Type: SubjectUser, ID: u})
		}
	}
	if err := s.checkSeparation(ctx, tx, realmID, holders, []string{role.ID}); err != nil {
		return nil, err
	}
	if in.Source == "" {
		in.Source = "admin"
	}
	if _, err := ParseConditions(in.Conditions); err != nil {
		return nil, err
	}
	cond, _ := json.Marshal(nonNilMap(in.Conditions))
	a := &Assignment{ID: ids.New(ids.Assignment), RoleID: role.ID, RoleName: role.Name, Subject: in.Subject, Scope: in.Scope,
		ValidFrom: in.ValidFrom, ExpiresAt: in.ExpiresAt, Source: in.Source, Reason: in.Reason, CreatedAt: s.d.Now(), ApprovedBy: in.ApproverID}
	if actor != nil {
		a.GrantedBy = actor.ID
	}
	if membershipID != nil {
		a.MembershipID = *membershipID
	}
	_, err = tx.Exec(ctx, `INSERT INTO role_assignments (id, realm_id, role_id, subject_type, subject_id, membership_id, scope_type, scope_id,
		conditions, valid_from, expires_at, granted_by_type, granted_by_id, approved_by_id, source, reason, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, a.ID, realmID, role.ID, in.Subject.Type, in.Subject.ID, membershipID,
		in.Scope.Type, in.Scope.ID, cond, in.ValidFrom, in.ExpiresAt, auditActor.Type, auditActor.ID, nilIfEmpty(in.ApproverID), in.Source,
		nilIfEmpty(in.Reason), a.CreatedAt)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, problem.ErrConflict.WithDetail("role already assigned")
		}
		return nil, err
	}
	if membershipID != nil {
		if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1, updated_at=$2 WHERE id=$1`, *membershipID, s.d.Now()); err != nil {
			return nil, err
		}
	}
	if in.Subject.Type == SubjectGroup {
		if err := bumpGroupMembersTx(ctx, tx, in.Subject.ID); err != nil {
			return nil, err
		}
	}
	if in.Subject.Type == SubjectUser {
		if _, err := tx.Exec(ctx, `UPDATE users SET authz_revision=authz_revision+1 WHERE id=$1`, in.Subject.ID); err != nil {
			return nil, err
		}
	} else if in.Subject.Type == SubjectService {
		if _, err := tx.Exec(ctx, `UPDATE service_principals SET permission_revision=permission_revision+1 WHERE id=$1`, in.Subject.ID); err != nil {
			return nil, err
		}
	}
	orgID := ""
	if in.Scope.Type == ScopeOrganization {
		orgID = in.Scope.ID
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "role.assigned", RealmID: realmID, OrgID: orgID, Actor: auditActor,
		Subject: &audit.Ref{Type: in.Subject.Type, ID: in.Subject.ID}, Target: &audit.Ref{Type: "role_assignment", ID: a.ID}, Category: "authorization",
		Metadata: map[string]any{"role_id": role.ID, "role_name": role.Name, "scope_type": in.Scope.Type, "scope_id": in.Scope.ID,
			"expires_at": in.ExpiresAt, "approved_by": in.ApproverID, "source": in.Source,
			"privileged": s.IsPrivilegedRole(ctx, tx, realmID, role)}}); err != nil {
		return nil, err
	}
	if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "authorization.role.assigned", RealmID: realmID, OrgID: orgID,
		AggregateType: in.Subject.Type, AggregateID: in.Subject.ID, Data: map[string]any{"subject_id": in.Subject.ID, "role_id": role.ID,
			"assignment_id": a.ID}}); err != nil {
		return nil, err
	}
	return a, nil
}

// Unassign removes an assignment. Removing the last active owner of an organization
// is refused; the organization row is locked so concurrent removals serialize
// (TEN-006, DB-007, TEST-011).
func (s *Service) Unassign(ctx context.Context, realmID, assignmentID string, actor Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.UnassignTx(ctx, tx, realmID, assignmentID, &actor, auditActor, false)
	})
}

// UnassignTx removes an assignment inside tx.
func (s *Service) UnassignTx(ctx context.Context, tx pgx.Tx, realmID, assignmentID string, actor *Subject, auditActor audit.Ref, skipCeiling bool) error {
	var a Assignment
	var membershipID *string
	err := tx.QueryRow(ctx, `SELECT id, role_id, subject_type, subject_id, membership_id, scope_type, scope_id FROM role_assignments
		WHERE realm_id=$1 AND id=$2`, realmID, assignmentID).Scan(&a.ID, &a.RoleID, &a.Subject.Type, &a.Subject.ID, &membershipID, &a.Scope.Type, &a.Scope.ID)
	if err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	role, err := s.Role(ctx, tx, realmID, a.RoleID)
	if err != nil {
		return err
	}
	if a.Scope.Type == ScopeOrganization {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, a.Scope.ID); err != nil {
			return err
		}
	}
	if !skipCeiling {
		if actor == nil {
			return problem.ErrForbidden
		}
		if err := s.CheckAssignable(ctx, tx, realmID, *actor, role, a.Scope); err != nil {
			return err
		}
	}
	if role.IsOwnerRole && a.Scope.Type == ScopeOrganization {
		n, err := s.ActiveOwnerCountTx(ctx, tx, a.Scope.ID, assignmentID)
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.ErrLastOwner
		}
	}
	tag, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE id=$1`, assignmentID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Another transaction may have removed it after the initial read.
		// Only a real deletion changes revisions or emits transition evidence.
		return problem.ErrNotFound
	}
	if membershipID != nil {
		if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, *membershipID); err != nil {
			return err
		}
	}
	if a.Subject.Type == SubjectGroup {
		if err := bumpGroupMembersTx(ctx, tx, a.Subject.ID); err != nil {
			return err
		}
	}
	if a.Subject.Type == SubjectUser {
		if _, err := tx.Exec(ctx, `UPDATE users SET authz_revision=authz_revision+1 WHERE id=$1`, a.Subject.ID); err != nil {
			return err
		}
	} else if a.Subject.Type == SubjectService {
		if _, err := tx.Exec(ctx, `UPDATE service_principals SET permission_revision=permission_revision+1 WHERE id=$1`, a.Subject.ID); err != nil {
			return err
		}
	}
	orgID := ""
	if a.Scope.Type == ScopeOrganization {
		orgID = a.Scope.ID
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "role.unassigned", RealmID: realmID, OrgID: orgID, Actor: auditActor,
		Subject: &audit.Ref{Type: a.Subject.Type, ID: a.Subject.ID}, Target: &audit.Ref{Type: "role_assignment", ID: assignmentID},
		Category: "authorization", Metadata: map[string]any{"role_id": role.ID, "role_name": role.Name}}); err != nil {
		return err
	}
	_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "authorization.role.unassigned", RealmID: realmID, OrgID: orgID,
		AggregateType: a.Subject.Type, AggregateID: a.Subject.ID, Data: map[string]any{"subject_id": a.Subject.ID, "role_id": role.ID}})
	return err
}

// ActiveOwnerCountTx counts active owners of an organization, excluding one
// assignment. The caller must hold the organization row lock.
func (s *Service) ActiveOwnerCountTx(ctx context.Context, tx pgx.Tx, orgID, excludeAssignment string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(DISTINCT m.user_id) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		JOIN memberships m ON m.id=ra.membership_id JOIN users u ON u.id=m.user_id
		WHERE ra.scope_type='organization' AND ra.scope_id=$1 AND r.is_owner_role AND m.state='active' AND u.state='active'
		AND ra.id <> $2 AND (ra.expires_at IS NULL OR ra.expires_at > $3)`, orgID, excludeAssignment, s.d.Now()).Scan(&n)
	return n, err
}

// IsOrgOwnerTx reports whether the membership currently holds an owner role.
func (s *Service) IsOrgOwnerTx(ctx context.Context, q storage.Querier, membershipID string) (bool, error) {
	var b bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		WHERE ra.membership_id=$1 AND r.is_owner_role AND (ra.expires_at IS NULL OR ra.expires_at > $2))`, membershipID, s.d.Now()).Scan(&b)
	return b, err
}

// ListAssignments lists assignments with optional filters.
func (s *Service) ListAssignments(ctx context.Context, realmID string, subj *Subject, scope *Scope) ([]Assignment, error) {
	sql := `SELECT ra.id, ra.role_id, r.name, ra.subject_type, ra.subject_id, coalesce(ra.membership_id,''), ra.scope_type, ra.scope_id,
		ra.valid_from, ra.expires_at, coalesce(ra.granted_by_id,''), coalesce(ra.approved_by_id,''), ra.source, coalesce(ra.reason,''), ra.created_at
		FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.realm_id=$1`
	args := []any{realmID}
	if subj != nil {
		args = append(args, subj.Type, subj.ID)
		sql += ` AND ra.subject_type=$2 AND ra.subject_id=$3`
	}
	if scope != nil {
		args = append(args, scope.Type, scope.ID)
		sql += ` AND ra.scope_type=$` + itoa(len(args)-1) + ` AND ra.scope_id=$` + itoa(len(args))
	}
	sql += ` ORDER BY ra.created_at, ra.id LIMIT 1000`
	rows, err := s.d.DB.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.ID, &a.RoleID, &a.RoleName, &a.Subject.Type, &a.Subject.ID, &a.MembershipID, &a.Scope.Type, &a.Scope.ID,
			&a.ValidFrom, &a.ExpiresAt, &a.GrantedBy, &a.ApprovedBy, &a.Source, &a.Reason, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Assignment loads one assignment.
func (s *Service) Assignment(ctx context.Context, realmID, id string) (*Assignment, error) {
	list, err := s.ListAssignments(ctx, realmID, nil, nil)
	if err != nil {
		return nil, err
	}
	for _, a := range list {
		if a.ID == id {
			aa := a
			return &aa, nil
		}
	}
	return nil, problem.ErrNotFound
}

// ExpireAssignments removes assignments past expiry (just-in-time elevation, AZ-024).
func (s *Service) ExpireAssignments(ctx context.Context) (int, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, realm_id FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at <= $1 LIMIT 500`, s.d.Now())
	if err != nil {
		return 0, err
	}
	type item struct{ id, realm string }
	var list []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.realm); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, it)
	}
	rows.Close()
	n := 0
	for _, it := range list {
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if err := s.UnassignTx(ctx, tx, it.realm, it.id, nil, audit.System, true); err != nil {
				return err
			}
			// A just-in-time elevation ends with its assignment (AZ-024).
			return s.MarkElevationExpiredTx(ctx, tx, it.id)
		})
		if err == nil {
			n++
		} else if !problem.Is(err, problem.ErrLastOwner) && !problem.Is(err, problem.ErrNotFound) {
			return n, err
		}
	}
	return n, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}
