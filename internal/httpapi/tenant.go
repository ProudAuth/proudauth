package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/impersonation"
	"github.com/proudauth/proudauth/internal/machine"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

func machineInput(name, aud string, scopes []string, org string, ttl int) machine.CredentialInput {
	return machine.CredentialInput{Name: name, Audience: aud, Scopes: scopes, OrganizationID: org, TTLDays: ttl}
}

func impActor(p *Principal) impersonation.Actor {
	return impersonation.Actor{UserID: p.SubjectID, SessionID: p.SessionID, TokenKind: p.TokenKind}
}

// orgGuard authorizes perm on the organization named in the path. The path ID is
// only a selector; existence is concealed from callers without any permission in
// it (API-008, TEST-007/008).
// orgAuthorityPermissions change who holds authority in an organization or its
// security configuration; users exercising them must act from an MFA session
// (MFA-003) unless the realm explicitly waived it.
var orgAuthorityPermissions = map[string]bool{"org.roles.write": true, "org.roles.assign": true, "org.ownership.transfer": true,
	"org.delete": true, "org.domains.write": true, "org.update": true, "org.projects.share": true, "org.relationships.write": true}

func (a *App) orgGuard(p *Principal, r *http.Request, perm string) (*organization.Organization, error) {
	id := r.PathValue("org")
	if !a.can(r.Context(), p, perm, orgScope(id)) {
		// Denials are evidence even when existence is concealed (AZ-020).
		concealed := !a.can(r.Context(), p, "org.read", orgScope(id))
		a.recordDenial(r, p, perm, id, concealed)
		if !concealed {
			return nil, problem.ErrForbidden
		}
		return nil, problem.ErrNotFound
	}
	if orgAuthorityPermissions[perm] && p.IsUser() && (!p.Realm.Policy.MFA.OrgAdminMFAOptional || a.D.Cfg.Security.MFAFloor.ForbidOrgAdminWaiver) {
		if err := a.requireMFASession(p); err != nil {
			return nil, err
		}
	}
	org, err := a.Orgs.Get(r.Context(), nil, p.Realm.ID, id)
	if err != nil {
		return nil, problem.ErrNotFound
	}
	return org, nil
}

func (a *App) inviteContext(ctx context.Context, p *Principal, org *organization.Organization) organization.InviteContext {
	name := p.SubjectID
	if p.IsUser() {
		if u, err := a.Users.User(ctx, nil, p.Realm.ID, p.SubjectID); err == nil && u.DisplayName != "" {
			name = u.DisplayName
		}
	}
	link := p.Realm.Policy.Interaction.LoginUIURL
	if link != "" {
		link += "/invitations"
	}
	return organization.InviteContext{RealmName: p.Realm.DisplayName, OrgName: org.DisplayName, InviterName: name, LinkBase: link,
		DefaultTTL: a.D.Cfg.Tokens.InvitationTTL}
}

func (a *App) tenantRoutes(mux *http.ServeMux) {
	base := "/api/v1/realms/{realm}/organizations"
	mux.HandleFunc("GET "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.can(r.Context(), p, "realm.organizations.read", a.realmScope(p)) {
			after, err := a.decodeCursor(p.Realm.ID+"|orgs", r.URL.Query().Get("cursor"))
			if err != nil {
				return err
			}
			limit := a.pageLimit(r)
			list, err := a.Orgs.List(r.Context(), p.Realm.ID, after, limit, r.URL.Query().Get("q"))
			if err != nil {
				return err
			}
			next := ""
			if len(list) == limit {
				next = a.encodeCursor(p.Realm.ID+"|orgs", list[len(list)-1].ID)
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
			return nil
		}
		if !p.IsUser() {
			return problem.ErrForbidden
		}
		list, err := a.Orgs.UserMemberships(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var in organization.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		creator := ""
		switch {
		case a.can(r.Context(), p, "realm.organizations.create", a.realmScope(p)):
			if p.IsUser() && r.URL.Query().Get("join") == "true" {
				creator = p.SubjectID
			}
		case p.IsUser() && p.Realm.Policy.Registration.AllowOrganizationCreation:
			creator = p.SubjectID // self-service creation makes the creator the owner (§27.1)
		default:
			return problem.ErrForbidden
		}
		org, err := a.Orgs.Create(r.Context(), p.Realm.ID, in, creator, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, org.Version)
		writeJSON(w, http.StatusCreated, org)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		org, err := a.orgGuard(p, r, "org.read")
		if err != nil {
			return err
		}
		setETag(w, org.Version)
		writeJSON(w, http.StatusOK, org)
		return nil
	}))
	mux.HandleFunc("PATCH "+base+"/{org}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.update"); err != nil {
			return err
		}
		// A partial update: members the body omits keep their values.
		var body struct {
			organization.Input
			Locale     *string `json:"locale"`
			TimeZone   *string `json:"time_zone"`
			ExternalID *string `json:"external_id"`
		}
		if err := decode(r, &body); err != nil {
			return err
		}
		in := body.Input
		for name, v := range map[string]*string{"locale": body.Locale, "time_zone": body.TimeZone, "external_id": body.ExternalID} {
			if v == nil {
				in.Omitted = append(in.Omitted, name)
				continue
			}
			switch name {
			case "locale":
				in.Locale = *v
			case "time_zone":
				in.TimeZone = *v
			case "external_id":
				in.ExternalID = *v
			}
		}
		// Policy is security configuration: changing it requires the version
		// the caller reviewed (API-010), so concurrent edits never silently
		// overwrite each other.
		ver, err := ifMatch(r, in.Policy != nil)
		if err != nil {
			return err
		}
		org, err := a.Orgs.Update(r.Context(), p.Realm.ID, r.PathValue("org"), ver, in, p.AuditRef(), p.Realm.Policy)
		if err != nil {
			return err
		}
		setETag(w, org.Version)
		writeJSON(w, http.StatusOK, org)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/deletion-preview", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.delete"); err != nil {
			return err
		}
		prev, err := a.Orgs.PreviewDeletion(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, prev)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.delete"); err != nil {
			return err
		}
		if p.IsUser() {
			if err := a.requireRecentAuth(p, 0); err != nil {
				return err
			}
		}
		job, err := a.beginOrgDeletion(r, p)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "deleting", "job_id": job})
		return nil
	}))
	// Lifecycle (TEN-001): suspend and archive revoke the organization's grants;
	// archived organizations keep their records and audit history.
	for _, st := range []struct{ path, state string }{{"suspend", "suspended"}, {"reactivate", "active"}, {"archive", "archived"}} {
		state := st.state
		mux.HandleFunc("POST "+base+"/{org}/"+st.path, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if !a.can(r.Context(), p, "realm.organizations.suspend", a.realmScope(p)) {
				return problem.ErrForbidden
			}
			if err := a.requireMFASession(p); err != nil {
				return err
			}
			var b struct {
				Reason string `json:"reason"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			if err := a.Orgs.SetState(r.Context(), p.Realm.ID, r.PathValue("org"), state, p.AuditRef(), b.Reason); err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, map[string]any{"state": state})
			return nil
		}))
	}
	mux.HandleFunc("POST "+base+"/{org}/ownership-transfers", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.ownership.transfer"); err != nil {
			return err
		}
		if p.IsUser() {
			if err := a.requireRecentAuth(p, 0); err != nil {
				return err
			}
		}
		var b struct {
			MembershipID   string `json:"membership_id"`
			ReleaseCurrent bool   `json:"release_current_owner"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.TransferOwnership(r.Context(), p.Realm.ID, r.PathValue("org"), b.MembershipID, b.ReleaseCurrent, p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "transferred"})
		return nil
	}))
	// Members (TEN-003, TEN-007).
	mux.HandleFunc("GET "+base+"/{org}/members", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.members.read"); err != nil {
			return err
		}
		scope := p.Realm.ID + "|members|" + r.PathValue("org")
		after, err := a.decodeCursor(scope, r.URL.Query().Get("cursor"))
		if err != nil {
			return err
		}
		limit := a.pageLimit(r)
		// Membership metadata (USR-009) is for those who manage members.
		withMetadata := a.can(r.Context(), p, "org.members.write", orgScope(r.PathValue("org")))
		list, err := a.Orgs.ListMembers(r.Context(), r.PathValue("org"), after, limit, r.URL.Query().Get("state"), withMetadata)
		if err != nil {
			return err
		}
		next := ""
		if len(list) == limit {
			next = a.encodeCursor(scope, list[len(list)-1].ID)
		}
		if !a.can(r.Context(), p, "realm.users.read", a.realmScope(p)) {
			for _, m := range list {
				m.Email = maskEmailLocal(m.Email)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/members", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.members.write"); err != nil {
			return err
		}
		var b struct {
			UserID  string   `json:"user_id"`
			RoleIDs []string `json:"role_ids"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		m, err := a.Orgs.AddMember(r.Context(), p.Realm.ID, r.PathValue("org"), b.UserID, b.RoleIDs, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		m.Metadata = json.RawMessage(`{}`) // a new membership has none yet (USR-009)
		writeJSON(w, http.StatusCreated, m)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/members/{membership}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.members.read"); err != nil {
			return err
		}
		m, err := a.Orgs.Membership(r.Context(), nil, r.PathValue("org"), r.PathValue("membership"))
		if err != nil {
			return err
		}
		if a.can(r.Context(), p, "org.members.write", orgScope(m.OrganizationID)) {
			if m.Metadata, err = a.Orgs.MembershipMetadata(r.Context(), nil, m.OrganizationID, m.ID); err != nil {
				return err
			}
		}
		as, _ := a.Authz.ListAssignments(r.Context(), p.Realm.ID, &authorization.Subject{Type: authorization.SubjectUser, ID: m.UserID}, ptrScope(orgScope(m.OrganizationID)))
		writeJSON(w, http.StatusOK, map[string]any{"membership": m, "role_assignments": as})
		return nil
	}))
	// Scoped administrator inspection (AZ-009): an organization administrator
	// sees a member's effective permissions in that organization with
	// provenance; realm-level grants are reported without naming realm roles.
	mux.HandleFunc("GET "+base+"/{org}/members/{membership}/permissions", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.read"); err != nil {
			return err
		}
		m, err := a.Orgs.Membership(r.Context(), nil, r.PathValue("org"), r.PathValue("membership"))
		if err != nil {
			return err
		}
		ex, err := a.Authz.Explain(r.Context(), nil, p.Realm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: m.UserID},
			orgScope(m.OrganizationID), authorization.ExplainOptions{HideRealmSources: true})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, explanationView(ex))
		return nil
	}))
	mux.HandleFunc("PATCH "+base+"/{org}/members/{membership}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.members.write"); err != nil {
			return err
		}
		var b struct {
			State string `json:"state"`
			// Metadata merges into the membership metadata (USR-009): null
			// removes a key.
			Metadata map[string]any `json:"metadata"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.State == "" && b.Metadata == nil {
			return problem.ErrValidation.WithDetail("state or metadata is required")
		}
		org, mid := r.PathValue("org"), r.PathValue("membership")
		subj := p.Subject()
		if err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			if b.State != "" {
				if err := a.Orgs.SetMembershipStateTx(r.Context(), tx, p.Realm.ID, org, mid, b.State, &subj, p.AuditRef()); err != nil {
					return err
				}
			}
			if b.Metadata != nil {
				return a.Orgs.SetMembershipMetadataTx(r.Context(), tx, p.Realm.ID, org, mid, b.Metadata, subj, p.AuditRef())
			}
			return nil
		}); err != nil {
			return err
		}
		m, err := a.Orgs.Membership(r.Context(), nil, org, mid)
		if err != nil {
			return err
		}
		if m.Metadata, err = a.Orgs.MembershipMetadata(r.Context(), nil, org, mid); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, m)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/members/{membership}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		m, err := a.Orgs.Membership(r.Context(), nil, r.PathValue("org"), r.PathValue("membership"))
		self := err == nil && p.IsUser() && m.UserID == p.SubjectID
		if !self {
			if _, err := a.orgGuard(p, r, "org.members.write"); err != nil {
				return err
			}
		}
		subj := p.Subject()
		if err := a.Orgs.RemoveMember(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("membership"), &subj, p.AuditRef(), "removed"); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/members/{membership}/roles", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.assign"); err != nil {
			return err
		}
		m, err := a.Orgs.Membership(r.Context(), nil, r.PathValue("org"), r.PathValue("membership"))
		if err != nil {
			return err
		}
		var b struct {
			RoleID    string  `json:"role_id"`
			ExpiresAt *string `json:"expires_at"`
			Reason    string  `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		exp, err := parseTimePtr(b.ExpiresAt)
		if err != nil {
			return err
		}
		in := authorization.AssignInput{RoleID: b.RoleID, Subject: authorization.Subject{Type: authorization.SubjectUser, ID: m.UserID},
			Scope: orgScope(m.OrganizationID), ExpiresAt: exp, Reason: b.Reason}
		if needs, err := a.Authz.RequiresApproval(r.Context(), p.Realm.ID, b.RoleID); err != nil {
			return err
		} else if needs {
			req, err := a.Authz.RequestAssignment(r.Context(), p.Realm.ID, p.Subject(), in, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "request": req})
			return nil
		}
		as, err := a.Authz.Assign(r.Context(), p.Realm.ID, p.Subject(), in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, as)
		return nil
	}))
	// Organization administrators decide approval requests for their
	// organization; authority is re-checked by the authorization service.
	orgDecide := func(approve bool) http.HandlerFunc {
		return a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if _, err := a.orgGuard(p, r, "org.roles.assign"); err != nil {
				return err
			}
			if err := a.requireRecentAuth(p, 0); err != nil {
				return err
			}
			if err := decode(r, &struct{}{}); err != nil {
				return err
			}
			reqs, err := a.Authz.ListAssignmentRequests(r.Context(), p.Realm.ID, "")
			if err != nil {
				return err
			}
			found := false
			for _, q := range reqs {
				if q.ID == r.PathValue("id") && q.Scope.Type == authorization.ScopeOrganization && q.Scope.ID == r.PathValue("org") {
					found = true
				}
			}
			if !found {
				return problem.ErrNotFound
			}
			out, err := a.Authz.DecideAssignmentRequest(r.Context(), p.Realm.ID, r.PathValue("id"), p.Subject(), approve, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, out)
			return nil
		})
	}
	mux.HandleFunc("POST "+base+"/{org}/role-assignment-requests/{id}/approve", orgDecide(true))
	mux.HandleFunc("POST "+base+"/{org}/role-assignment-requests/{id}/reject", orgDecide(false))
	mux.HandleFunc("DELETE "+base+"/{org}/members/{membership}/roles/{assignment}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.assign"); err != nil {
			return err
		}
		as, err := a.Authz.Assignment(r.Context(), p.Realm.ID, r.PathValue("assignment"))
		if err != nil || as.MembershipID != r.PathValue("membership") || as.Scope.ID != r.PathValue("org") {
			return problem.ErrNotFound
		}
		if err := a.Authz.Unassign(r.Context(), p.Realm.ID, as.ID, p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Organization roles.
	mux.HandleFunc("GET "+base+"/{org}/roles", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.read"); err != nil {
			return err
		}
		list, err := a.Authz.ListRoles(r.Context(), p.Realm.ID, "organization", r.PathValue("org"), "")
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/{org}/roles", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.write"); err != nil {
			return err
		}
		var in authorization.RoleInput
		if err := decode(r, &in); err != nil {
			return err
		}
		in.Boundary, in.OrganizationID = "organization", r.PathValue("org")
		role, err := a.Authz.CreateRole(r.Context(), p.Realm.ID, p.Subject(), in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, role)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/roles/{role}/permissions", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.write"); err != nil {
			return err
		}
		role, err := a.Authz.Role(r.Context(), nil, p.Realm.ID, r.PathValue("role"))
		if err != nil || role.OrganizationID != r.PathValue("org") {
			return problem.ErrNotFound
		}
		var b struct {
			Add    []string `json:"add"`
			Remove []string `json:"remove"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		out, err := a.Authz.ModifyRolePermissions(r.Context(), p.Realm.ID, role.ID, ver, p.Subject(), b.Add, b.Remove, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	// Invitations (INV-001...).
	mux.HandleFunc("GET "+base+"/{org}/invitations", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.invites.read"); err != nil {
			return err
		}
		// The cursor is bound to the organization and to the filters (state),
		// like other paged lists, so it cannot be replayed with another filter.
		scope := p.Realm.ID + "|invitations|" + r.PathValue("org") + "|" + listScope(r)
		after, err := a.decodeCursor(scope, r.URL.Query().Get("cursor"))
		if err != nil {
			return err
		}
		limit := a.pageLimit(r)
		list, err := a.Orgs.ListInvitations(r.Context(), r.PathValue("org"), r.URL.Query().Get("state"), after, limit)
		if err != nil {
			return err
		}
		next := ""
		if len(list) == limit {
			next = a.encodeCursor(scope, list[len(list)-1].ID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/invitations/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.invites.read"); err != nil {
			return err
		}
		inv, err := a.Orgs.Invitation(r.Context(), nil, r.PathValue("org"), r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, inv.Version)
		writeJSON(w, http.StatusOK, inv)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/invitations", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		org, err := a.orgGuard(p, r, "org.invites.create")
		if err != nil {
			return err
		}
		var in organization.InviteInput
		if err := decode(r, &in); err != nil {
			return err
		}
		inv, secret, err := a.Orgs.CreateInvitation(r.Context(), p.Realm.ID, org.ID, in, p.Subject(), p.AuditRef(), a.inviteContext(r.Context(), p, org))
		if err != nil {
			return err
		}
		resp := map[string]any{"invitation": inv}
		if in.Purpose == "shared_link" {
			resp["invitation_secret"] = secret // shared links have no mailbox; shown once to the creator
		}
		writeJSON(w, http.StatusCreated, resp)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/invitations/batch", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		org, err := a.orgGuard(p, r, "org.invites.create")
		if err != nil {
			return err
		}
		var b struct {
			Items []organization.InviteInput `json:"items"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		batchID, results, err := a.Orgs.CreateInvitationBatch(r.Context(), p.Realm.ID, org.ID, b.Items, p.Subject(), p.AuditRef(), a.inviteContext(r.Context(), p, org))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"batch_id": batchID, "results": results})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/invitations/{id}/reassign", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		org, err := a.orgGuard(p, r, "org.invites.create")
		if err != nil {
			return err
		}
		if !a.Authz.Check(r.Context(), nil, p.Realm.ID, p.Subject(), "org.invites.revoke", authorization.Scope{Type: authorization.ScopeOrganization, ID: org.ID}) {
			return problem.ErrForbidden
		}
		var in organization.ReassignInput
		if err := decode(r, &in); err != nil {
			return err
		}
		inv, err := a.Orgs.ReassignInvitation(r.Context(), p.Realm.ID, org.ID, r.PathValue("id"), in, p.Subject(), p.AuditRef(), a.inviteContext(r.Context(), p, org))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"invitation": inv})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/invitations/{id}/resend", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		org, err := a.orgGuard(p, r, "org.invites.create")
		if err != nil {
			return err
		}
		if _, err := a.Orgs.ResendInvitation(r.Context(), p.Realm.ID, org.ID, r.PathValue("id"), p.Subject(), p.AuditRef(), a.inviteContext(r.Context(), p, org)); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "resent"})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/invitations/{id}/revoke", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.invites.revoke"); err != nil {
			return err
		}
		if err := a.Orgs.RevokeInvitation(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/invitations/inspect", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realmT) error {
		a.applyCORS(w, r, rlm, false)
		var b struct {
			Invitation string `json:"invitation"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		res, err := a.Orgs.Inspect(r.Context(), rlm.ID, b.Invitation)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/invitations/accept", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Invitation string `json:"invitation"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		res, err := a.Orgs.Accept(r.Context(), p.Realm.ID, b.Invitation, p.SubjectID, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/invitations/decline", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Invitation string `json:"invitation"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.Decline(r.Context(), p.Realm.ID, b.Invitation, p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Join requests (INV-013).
	mux.HandleFunc("POST "+base+"/{org}/join-requests", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		jr, err := a.Orgs.RequestJoin(r.Context(), p.Realm.ID, r.PathValue("org"), p.SubjectID, b.Reason, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, jr)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/join-requests", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.join_requests.review"); err != nil {
			return err
		}
		list, err := a.Orgs.ListJoinRequests(r.Context(), r.PathValue("org"), r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/{org}/join-requests/{id}/decision", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.join_requests.review"); err != nil {
			return err
		}
		var b struct {
			Approve bool   `json:"approve"`
			Reason  string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.DecideJoinRequest(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), b.Approve, b.Reason, p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/join-requests/{id}/reviewers", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.members.write"); err != nil {
			return err
		}
		var b struct {
			ReviewerIDs []string `json:"reviewer_ids"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.AssignJoinReviewers(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), b.ReviewerIDs, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/join-requests/{id}/withdraw", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Orgs.WithdrawJoinRequest(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET /api/v1/realms/{realm}/me/join-requests", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Orgs.MyJoinRequests(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	// Organization aliases and subdomain routing (TEN-011).
	mux.HandleFunc("GET "+base+"/{org}/aliases", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.read"); err != nil {
			return err
		}
		list, err := a.Orgs.Aliases(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/aliases", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.update"); err != nil {
			return err
		}
		var b struct {
			Alias string `json:"alias"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.AddAlias(r.Context(), p.Realm.ID, r.PathValue("org"), b.Alias, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/aliases/{alias}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.update"); err != nil {
			return err
		}
		if err := a.Orgs.RemoveAlias(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("alias"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("PATCH "+base+"/{org}/domains/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.domains.write"); err != nil {
			return err
		}
		var b struct {
			IncludeSubdomains bool `json:"include_subdomains"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.SetIncludeSubdomains(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), b.IncludeSubdomains, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Dynamic groups (TEN-014).
	mux.HandleFunc("GET "+base+"/{org}/groups/{group}/dynamic-rule", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.read"); err != nil {
			return err
		}
		st, err := a.Orgs.RuleStatusOf(r.Context(), r.PathValue("org"), r.PathValue("group"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	}))
	mux.HandleFunc("PUT "+base+"/{org}/groups/{group}/dynamic-rule", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		var rule organization.DynamicRule
		if err := decode(r, &rule); err != nil {
			return err
		}
		st, err := a.Orgs.SetDynamicRule(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("group"), &rule, p.Realm.Policy.Profile.Attributes,
			p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/groups/{group}/dynamic-rule", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		if _, err := a.Orgs.SetDynamicRule(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("group"), nil, p.Realm.Policy.Profile.Attributes,
			p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Customer-owned mail server (TEN-022).
	mux.HandleFunc("GET "+base+"/{org}/notification-settings/smtp", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		t, err := a.Notify.GetTenantSMTP(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		w.Header().Set("ETag", contentTag(t))
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("PUT "+base+"/{org}/notification-settings/smtp", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var b struct {
			notification.TenantSMTP
			Password *string `json:"password"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if r.Header.Get("If-Match") != "" {
			cur, err := a.Notify.GetTenantSMTP(r.Context(), p.Realm.ID, r.PathValue("org"))
			if err != nil {
				return problem.ErrPrecondition
			}
			if err := checkContentTag(r, cur); err != nil {
				return err
			}
		}
		if err := a.Notify.SetTenantSMTP(r.Context(), p.Realm.ID, r.PathValue("org"), b.TenantSMTP, b.Password, p.AuditRef()); err != nil {
			return err
		}
		t, err := a.Notify.GetTenantSMTP(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		w.Header().Set("ETag", contentTag(t))
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/notification-settings/smtp", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		if err := a.Notify.ClearTenantSMTP(r.Context(), p.Realm.ID, r.PathValue("org"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Groups (TEN-013).
	mux.HandleFunc("GET "+base+"/{org}/groups", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.read"); err != nil {
			return err
		}
		list, err := a.Orgs.ListGroups(r.Context(), r.PathValue("org"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/{org}/groups", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		var in organization.GroupInput
		if err := decode(r, &in); err != nil {
			return err
		}
		var g *organization.Group
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			g, err = a.Orgs.CreateGroupTx(r.Context(), tx, p.Realm.ID, r.PathValue("org"), in, p.AuditRef())
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, g)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/groups/{group}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.read"); err != nil {
			return err
		}
		g, err := a.Orgs.GetGroup(r.Context(), r.PathValue("org"), r.PathValue("group"))
		if err != nil {
			return err
		}
		setETag(w, g.Version)
		writeJSON(w, http.StatusOK, g)
		return nil
	}))
	mux.HandleFunc("PATCH "+base+"/{org}/groups/{group}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		var in organization.GroupInput
		if err := decode(r, &in); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		actor := p.Subject()
		g, err := a.Orgs.UpdateGroup(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("group"), ver, in, &actor, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, g.Version)
		writeJSON(w, http.StatusOK, g)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/groups/{group}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		if err := a.Orgs.DeleteGroup(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("group"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/groups/{group}/members", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.read"); err != nil {
			return err
		}
		list, err := a.Orgs.GroupMembers(r.Context(), r.PathValue("org"), r.PathValue("group"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/{org}/groups/{group}/members", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		var b struct {
			MembershipID string `json:"membership_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Orgs.AddGroupMember(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("group"), b.MembershipID, p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/groups/{group}/members/{member}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.groups.write"); err != nil {
			return err
		}
		if err := a.Orgs.RemoveGroupMember(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("group"), r.PathValue("member"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/groups/{group}/roles", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.roles.assign"); err != nil {
			return err
		}
		var b struct {
			RoleID string `json:"role_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		as, err := a.Authz.Assign(r.Context(), p.Realm.ID, p.Subject(), authorization.AssignInput{RoleID: b.RoleID,
			Subject: authorization.Subject{Type: authorization.SubjectGroup, ID: r.PathValue("group")}, Scope: orgScope(r.PathValue("org"))}, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, as)
		return nil
	}))
	// Domains (TEN-009).
	mux.HandleFunc("GET "+base+"/{org}/domains", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.domains.read"); err != nil {
			return err
		}
		list, err := a.Orgs.ListDomains(r.Context(), r.PathValue("org"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/{org}/domains", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.domains.write"); err != nil {
			return err
		}
		var b struct {
			Domain string `json:"domain"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		ch, err := a.Orgs.AddDomain(r.Context(), p.Realm.ID, r.PathValue("org"), b.Domain, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, ch)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{org}/domains/{id}/verify", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.domains.write"); err != nil {
			return err
		}
		d, err := a.Orgs.VerifyDomain(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, d)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{org}/domains/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.domains.write"); err != nil {
			return err
		}
		if err := a.Orgs.RemoveDomain(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{org}/audit-events", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.audit.read"); err != nil {
			return err
		}
		return a.auditQuery(w, r, p, r.PathValue("org"))
	}))
}

func ptrScope(s authorization.Scope) *authorization.Scope { return &s }

func maskEmailLocal(e string) string {
	for i := 0; i < len(e); i++ {
		if e[i] == '@' {
			if i <= 1 {
				return "***" + e[i:]
			}
			return e[:1] + "***" + e[i:]
		}
	}
	return e
}

func (a *App) beginOrgDeletion(r *http.Request, p *Principal) (string, error) {
	orgID := r.PathValue("org")
	var jobID string
	err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		if err := a.Orgs.BeginDeletionTx(r.Context(), tx, p.Realm.ID, orgID, p.AuditRef(), "requested"); err != nil {
			// A deletion whose job ended without finishing (its requester
			// lost the authority before it ran, INT-006) is finished by a
			// caller who holds it now: the organization is already closed,
			// so only a new job is queued.
			var resumable bool
			if qerr := tx.QueryRow(r.Context(), `SELECT o.state='deleting' AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.type='organization.delete'
				AND j.organization_id=o.id AND j.state IN ('queued','running')) FROM organizations o WHERE o.realm_id=$1 AND o.id=$2 FOR UPDATE OF o`,
				p.Realm.ID, orgID).Scan(&resumable); qerr != nil || !resumable {
				return err
			}
		}
		var err error
		jobID, err = a.enqueueJobTx(r.Context(), tx, p.Realm.ID, orgID, "organization.delete", map[string]any{"organization_id": orgID}, p.AuditRef())
		return err
	})
	return jobID, err
}

var _ = audit.System
