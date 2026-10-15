package httpapi

import (
	"net/http"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// orgRelationshipRoutes serve organization relationships (TEN-021) and
// partner project access (TEN-020): owner organizations share selected
// project roles with related organizations, which assign only that subset
// to their own members.
func (a *App) orgRelationshipRoutes(mux *http.ServeMux) {
	O := "/api/v1/realms/{realm}/organizations/{org}"
	mux.HandleFunc("GET /api/v1/realms/{realm}/organization-relationships", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.organizations.read"); err != nil {
			return err
		}
		list, err := a.Orgs.Relationships(r.Context(), p.Realm.ID, "")
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+O+"/organization-relationships", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.relationships.read"); err != nil {
			return err
		}
		list, err := a.Orgs.Relationships(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+O+"/organization-relationships", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.relationships.write"); err != nil {
			return err
		}
		var b struct {
			Kind                 string `json:"kind"`
			TargetOrganizationID string `json:"target_organization_id"`
			Note                 string `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// A realm administrator records the relationship directly; an
		// organization's own administrator proposes it to the other one.
		direct := a.can(r.Context(), p, "realm.organizations.write", a.realmScope(p))
		rel, err := a.Orgs.ProposeRelationship(r.Context(), p.Realm.ID, b.Kind, r.PathValue("org"), b.TargetOrganizationID, b.Note, direct, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, rel)
		return nil
	}))
	decide := func(accept bool) http.HandlerFunc {
		return a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if _, err := a.orgGuard(p, r, "org.relationships.write"); err != nil {
				return err
			}
			rel, err := a.Orgs.DecideRelationship(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), accept, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, rel)
			return nil
		})
	}
	mux.HandleFunc("POST "+O+"/organization-relationships/{id}/accept", decide(true))
	mux.HandleFunc("POST "+O+"/organization-relationships/{id}/decline", decide(false))
	mux.HandleFunc("POST "+O+"/organization-relationships/{id}/end", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.relationships.write"); err != nil {
			return err
		}
		if err := a.Orgs.EndRelationship(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))

	// ---------- partner project access (TEN-020) ----------
	ownedProject := func(r *http.Request, p *Principal) (*application.Project, error) {
		if _, err := a.orgGuard(p, r, "org.projects.share"); err != nil {
			return nil, err
		}
		pr, err := a.Apps.Project(r.Context(), p.Realm.ID, r.PathValue("project"))
		if err != nil || pr.OwnerOrganizationID != r.PathValue("org") {
			return nil, problem.ErrNotFound
		}
		return pr, nil
	}
	mux.HandleFunc("GET "+O+"/projects/{project}/grants", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		pr, err := ownedProject(r, p)
		if err != nil {
			return err
		}
		list, err := a.Apps.ListProjectGrants(r.Context(), p.Realm.ID, pr.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+O+"/projects/{project}/grants", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		pr, err := ownedProject(r, p)
		if err != nil {
			return err
		}
		var b struct {
			OrganizationID string     `json:"organization_id"`
			AllowedRoleIDs []string   `json:"allowed_role_ids"`
			ValidUntil     *time.Time `json:"valid_until"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// An owner organization shares only with organizations it has an
		// active relationship with; the relationship itself shares nothing.
		if !a.can(r.Context(), p, "realm.projects.write", a.realmScope(p)) {
			related, err := a.Orgs.Related(r.Context(), nil, p.Realm.ID, pr.OwnerOrganizationID, b.OrganizationID)
			if err != nil {
				return err
			}
			if !related {
				return problem.ErrValidation.WithField("organization_id", "an organization with an active relationship to the project owner")
			}
		}
		g, err := a.Apps.CreateProjectGrant(r.Context(), p.Realm.ID, pr.ID, b.OrganizationID, b.AllowedRoleIDs, b.ValidUntil, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, g)
		return nil
	}))
	mux.HandleFunc("POST "+O+"/projects/{project}/grants/{id}/revoke", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		pr, err := ownedProject(r, p)
		if err != nil {
			return err
		}
		if err := a.Apps.RevokeProjectGrant(r.Context(), p.Realm.ID, pr.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+O+"/project-grants", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.read"); err != nil {
			return err
		}
		list, err := a.Apps.ReceivedProjectGrants(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+O+"/project-role-assignments", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.read"); err != nil {
			return err
		}
		list, err := a.Orgs.ProjectRoleAssignments(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+O+"/project-role-assignments", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.assign"); err != nil {
			return err
		}
		var b struct {
			ProjectID string     `json:"project_id"`
			RoleID    string     `json:"role_id"`
			UserID    string     `json:"user_id"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		out, err := a.Orgs.AssignProjectRole(r.Context(), p.Realm.ID, r.PathValue("org"), b.ProjectID, b.RoleID, b.UserID, b.ExpiresAt, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+O+"/project-role-assignments/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.assign"); err != nil {
			return err
		}
		if err := a.Orgs.RemoveProjectRole(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
