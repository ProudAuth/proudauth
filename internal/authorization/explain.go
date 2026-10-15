package authorization

import (
	"context"
	"encoding/json"
	"time"

	"github.com/proudauth/proudauth/internal/storage"
)

// GrantSource is one assignment contributing to a subject's permissions in a
// scope, with how it applies (AZ-009 provenance).
type GrantSource struct {
	AssignmentID string     `json:"assignment_id,omitempty"`
	RoleID       string     `json:"role_id,omitempty"`
	RoleName     string     `json:"role_name"`
	Via          string     `json:"via"` // realm | organization | group | project
	GroupID      string     `json:"group_id,omitempty"`
	Conditional  bool       `json:"conditional"`
	Applies      bool       `json:"applies"` // false when conditions do not hold for this request context
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Permissions  []string   `json:"permissions"`
	Redacted     bool       `json:"redacted,omitempty"`
}

// PolicyRef names a published ABAC policy that may restrict decisions in the
// scope. Definitions are never included (sensitive-policy redaction).
type PolicyRef struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int    `json:"version,omitempty"`
	Scope   string `json:"scope"`
}

// Explanation is the inspection view of a subject's authorization in a scope.
type Explanation struct {
	Scope       Scope               `json:"scope"`
	Permissions []string            `json:"permissions"`
	Denied      []string            `json:"denied_permissions"`
	Provenance  map[string][]string `json:"provenance"`
	Sources     []GrantSource       `json:"sources"`
	Policies    []PolicyRef         `json:"policies"`
	PolicyCount int                 `json:"restricting_policies"`
	// ProjectID is the project whose project-scoped assignments were
	// evaluated with the scope (AZ-002), if any.
	ProjectID string `json:"project_id,omitempty"`
}

// ExplainOptions controls redaction for the caller (AZ-009).
type ExplainOptions struct {
	// HideRealmSources reports realm-level grants without naming their roles
	// (organization administrators never see realm administration, DOM-005).
	HideRealmSources bool
	// ShowPolicies names restricting policies; otherwise only a count is given.
	ShowPolicies bool
	// ProjectID evaluates the scope for a resource of that project: the
	// subject's assignments scoped to the project count too, as in
	// EffectiveInProject (AZ-002).
	ProjectID string
}

// Explain returns the subject's effective permissions in scope with the
// assignments that produce them and the policies that may further restrict
// decisions. It reuses Effective for the permission set, so inspection and
// enforcement never disagree.
func (s *Service) Explain(ctx context.Context, q storage.Querier, realmID string, subj Subject, scope Scope, opt ExplainOptions) (*Explanation, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	ps, err := s.EffectiveInProject(ctx, q, realmID, subj, scope, opt.ProjectID)
	if err != nil {
		return nil, err
	}
	out := &Explanation{Scope: scope, Permissions: ps.List(), Denied: []string{}, Provenance: map[string][]string{}, Sources: []GrantSource{}, Policies: []PolicyRef{},
		ProjectID: opt.ProjectID}
	for _, p := range out.Permissions {
		out.Provenance[p] = ps.Provenance(p)
	}
	for p := range ps.Deny {
		out.Denied = append(out.Denied, p)
	}
	now := s.d.Now()
	type row struct {
		id, roleID, via, group string
		cond                   []byte
		exp                    *time.Time
	}
	var rows []row
	collect := func(via, sql string, args ...any) error {
		rs, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			r := row{via: via}
			if err := rs.Scan(&r.id, &r.roleID, &r.group, &r.cond, &r.exp); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	}
	live := ` AND (ra.valid_from IS NULL OR ra.valid_from <= $4) AND (ra.expires_at IS NULL OR ra.expires_at > $4)`
	if err := collect("realm", `SELECT ra.id, ra.role_id, '', ra.conditions, ra.expires_at FROM role_assignments ra WHERE ra.realm_id=$1
		AND ra.subject_type=$2 AND ra.subject_id=$3 AND ra.scope_type='realm'`+live, realmID, subj.Type, subj.ID, now); err != nil {
		return nil, err
	}
	switch scope.Type {
	case ScopeOrganization:
		if subj.Type == SubjectUser {
			var mid string
			if err := q.QueryRow(ctx, `SELECT m.id FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.realm_id=$1
				AND m.organization_id=$2 AND m.user_id=$3 AND m.state='active' AND o.state='active'
				AND (m.expires_at IS NULL OR m.expires_at > $4)`, realmID, scope.ID, subj.ID, now).Scan(&mid); err == nil {
				if err := collect("organization", `SELECT ra.id, ra.role_id, '', ra.conditions, ra.expires_at FROM role_assignments ra
					WHERE ra.realm_id=$1 AND ra.scope_type='organization' AND ra.scope_id=$2 AND ra.membership_id=$3`+live,
					realmID, scope.ID, mid, now); err != nil {
					return nil, err
				}
				groups, err := s.groupClosure(ctx, q, scope.ID, mid, now)
				if err != nil {
					return nil, err
				}
				if len(groups) > 0 {
					if err := collect("group", `SELECT ra.id, ra.role_id, ra.subject_id, ra.conditions, ra.expires_at FROM role_assignments ra
						WHERE ra.realm_id=$1 AND ra.scope_type='organization' AND ra.scope_id=$2 AND ra.subject_type='group'
						AND ra.subject_id = ANY($3)`+live, realmID, scope.ID, groups, now); err != nil {
						return nil, err
					}
				}
			} else if !storage.IsNoRows(err) {
				return nil, err
			}
		} else {
			if err := collect("organization", `SELECT ra.id, ra.role_id, '', ra.conditions, ra.expires_at FROM role_assignments ra
				WHERE ra.realm_id=$1 AND ra.scope_type='organization' AND ra.scope_id=$5 AND ra.subject_type=$2 AND ra.subject_id=$3`+live,
				realmID, subj.Type, subj.ID, now, scope.ID); err != nil {
				return nil, err
			}
		}
	}
	// Project-scoped assignments, under the same conditions as in effective.
	projectID, orgID := opt.ProjectID, ""
	switch scope.Type {
	case ScopeProject:
		projectID = scope.ID
	case ScopeOrganization:
		orgID = scope.ID
	}
	if projectID != "" {
		_, active, belongs, err := s.projectStatus(ctx, q, realmID, projectID, orgID)
		if err != nil {
			return nil, err
		}
		if active && belongs {
			if err := collect("project", `SELECT ra.id, ra.role_id, '', ra.conditions, ra.expires_at FROM role_assignments ra WHERE ra.realm_id=$1
				AND ra.subject_type=$2 AND ra.subject_id=$3 AND ra.scope_type='project' AND ra.scope_id=$5`+live, realmID, subj.Type, subj.ID, now, projectID); err != nil {
				return nil, err
			}
		}
	}
	for _, r := range rows {
		src := GrantSource{AssignmentID: r.id, RoleID: r.roleID, Via: r.via, GroupID: r.group, ExpiresAt: r.exp, Applies: true}
		if len(r.cond) > 2 {
			src.Conditional = true
			var m map[string]any
			if json.Unmarshal(r.cond, &m) != nil {
				src.Applies = false
			} else if c, err := ParseConditions(m); err != nil || !c.Holds(ctx, now) {
				src.Applies = false
			}
		}
		if r.via == "realm" && opt.HideRealmSources {
			out.Sources = append(out.Sources, GrantSource{Via: "realm", RoleName: "(realm-level grant)", Redacted: true,
				Conditional: src.Conditional, Applies: src.Applies, Permissions: []string{}})
			continue
		}
		if role, err := s.Role(ctx, q, realmID, r.roleID); err == nil {
			src.RoleName = role.Name
		}
		rp, err := s.permissionsForRoles(ctx, q, []string{r.roleID})
		if err != nil {
			return nil, err
		}
		src.Permissions = rp.List()
		out.Sources = append(out.Sources, src)
	}
	if opt.HideRealmSources {
		// Provenance must not name realm roles either.
		for p, roles := range out.Provenance {
			kept := []string{}
			for _, name := range roles {
				for _, src := range out.Sources {
					if !src.Redacted && src.RoleName == name {
						kept = append(kept, name)
						break
					}
				}
			}
			out.Provenance[p] = kept
		}
	}
	pols, err := s.ActivePolicies(ctx, realmID)
	if err != nil {
		return nil, err
	}
	for _, ap := range pols {
		applies := ap.ScopeType == "realm" || (ap.ScopeType == "organization" && scope.Type == ScopeOrganization && ap.ScopeID == scope.ID)
		if !applies {
			continue
		}
		out.PolicyCount++
		if opt.ShowPolicies {
			out.Policies = append(out.Policies, PolicyRef{ID: ap.ID, Name: ap.Name, Version: ap.Version, Scope: ap.ScopeType})
		}
	}
	return out, nil
}
