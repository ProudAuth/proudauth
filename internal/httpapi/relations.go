package httpapi

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/token"
)

// relationRoutes serve relationship-based authorization (AZ-021..AZ-023,
// AZ-027): resource types and relationships for services, object listing
// for resource servers, and user-managed sharing for members.
func (a *App) relationRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/resource-types", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resource_types.read"); err != nil {
			return err
		}
		list, err := a.Authz.ListResourceTypes(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+R+"/resource-types/{name}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resource_types.read"); err != nil {
			return err
		}
		t, err := a.Authz.ResourceTypeByName(r.Context(), nil, p.Realm.ID, r.PathValue("name"))
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/resource-types/{name}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resource_types.write"); err != nil {
			return err
		}
		var in authorization.ResourceTypeInput
		if err := decode(r, &in); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		t, created, err := a.Authz.PutResourceType(r.Context(), p.Realm.ID, r.PathValue("name"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSON(w, status, t)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/resource-types/{name}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resource_types.write"); err != nil {
			return err
		}
		if err := a.Authz.DeleteResourceType(r.Context(), p.Realm.ID, r.PathValue("name"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/organizations/{org}/relationships", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.relationships.write"); err != nil {
			return err
		}
		var b struct {
			Writes []authorization.RelationshipWrite `json:"writes"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Authz.WriteRelationships(r.Context(), p.Realm.ID, r.PathValue("org"), b.Writes, "api", p.AuditRef()); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "written", "writes": len(b.Writes)})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/organizations/{org}/relationships", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.relationships.read"); err != nil {
			return err
		}
		q := r.URL.Query()
		limit := 100
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 500 {
			limit = n
		}
		list, err := a.Authz.ListRelationships(r.Context(), p.Realm.ID, r.PathValue("org"), q.Get("object_type"), q.Get("object_id"),
			q.Get("subject_type"), q.Get("subject_id"), q.Get("cursor"), limit+1)
		if err != nil {
			return err
		}
		out := map[string]any{"items": list}
		if len(list) > limit {
			out["items"], out["next_cursor"] = list[:limit], list[limit-1].ID
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/authorization/list-objects", a.admin(a.listObjects))

	// User-managed sharing (AZ-027).
	me := R + "/me/shares"
	mux.HandleFunc("POST "+me, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var in authorization.ShareInput
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		sh, err := a.Authz.OfferShare(r.Context(), p.Realm.ID, p.SubjectID, in)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, sh)
		return nil
	}))
	mux.HandleFunc("GET "+me, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		dir := r.URL.Query().Get("direction")
		if dir == "" {
			dir = "received"
		}
		if dir != "sent" && dir != "received" {
			return problem.ErrValidation.WithField("direction", "sent or received")
		}
		list, err := a.Authz.ListShares(r.Context(), nil, p.Realm.ID, p.SubjectID, dir, r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	respond := func(accept bool) http.HandlerFunc {
		return a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := decode(r, &struct{}{}); err != nil {
				return err
			}
			sh, err := a.Authz.RespondShare(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), accept)
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, sh)
			return nil
		})
	}
	mux.HandleFunc("POST "+me+"/{id}/accept", respond(true))
	mux.HandleFunc("POST "+me+"/{id}/decline", respond(false))
	mux.HandleFunc("DELETE "+me+"/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Authz.RevokeShare(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}

// listObjects answers which objects of a type a subject may act on (AZ-023):
// "all" when an organization-wide grant (RBAC) covers the action, otherwise
// the objects verified through relationships. Unverified objects are never
// returned; truncated says a bound was reached.
func (a *App) listObjects(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req struct {
		DecisionRequest
		Limit  int    `json:"limit"`
		Cursor string `json:"cursor"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !a.can(r.Context(), p, "realm.authorization.check", a.realmScope(p)) {
		return problem.ErrForbidden
	}
	if req.Action == "" || req.Resource.Type == "" {
		return problem.ErrValidation.WithDetail("action and resource.type are required")
	}
	// 1–500; a larger limit is clamped to 500, none means 100.
	if req.Limit <= 0 {
		req.Limit = 100
	} else if req.Limit > 500 {
		req.Limit = 500
	}
	sc, code := a.resolveSubject(r.Context(), p, req.DecisionRequest)
	if sc == nil {
		return problem.ErrForbidden.WithDetail(strings.ToLower(code))
	}
	orgID := req.Resource.OrgID
	if sc.orgID != "" && orgID != "" && sc.orgID != orgID {
		return problem.ErrForbidden.WithDetail("organization mismatch")
	}
	if orgID == "" {
		orgID = sc.orgID
	}
	if orgID == "" {
		return problem.ErrValidation.WithField("resource.org_id", "objects are listed within one organization")
	}
	if sc.kind == token.KindImpersonationAccess && (authorization.IsWriteAction(req.Action) ||
		!slices.ContainsFunc(readOnlySuffixes, func(s string) bool { return strings.HasSuffix(strings.ToLower(req.Action), s) })) {
		return problem.ErrForbidden.WithDetail("support access lists for read actions only")
	}
	dctx := authorization.WithDecisionContext(r.Context(), authorization.DecisionContext{ClientID: sc.clientID, ACR: sc.acr, AuthTime: sc.authTime,
		Resources: []string{sc.audience}})
	ps, err := a.Authz.Effective(dctx, nil, p.Realm.ID, sc.subject, orgScope(orgID))
	if err != nil {
		return err
	}
	if ps.Has(req.Action) {
		writeJSON(w, http.StatusOK, map[string]any{"all": true, "objects": []string{}, "organization_id": orgID})
		return nil
	}
	objects, truncated, err := a.Authz.ListObjects(r.Context(), p.Realm.ID, orgID, sc.subject, req.Resource.Type, req.Action, req.Cursor, req.Limit)
	if err != nil {
		return err
	}
	out := map[string]any{"all": false, "objects": objects, "organization_id": orgID, "truncated": truncated}
	if len(objects) == req.Limit {
		out["next_cursor"] = objects[len(objects)-1]
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
