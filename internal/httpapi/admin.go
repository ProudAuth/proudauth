package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/impersonation"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/machine"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/token"
)

type realmT = realm.Realm

func parseTimePtr(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, problem.ErrValidation.WithDetail("timestamps must be RFC 3339")
	}
	return &t, nil
}

func (a *App) enqueueJobTx(ctx context.Context, tx pgx.Tx, realmID, orgID, typ string, input map[string]any, actor audit.Ref) (string, error) {
	return jobs.NewService(a.D).CreateTx(ctx, tx, jobs.Spec{RealmID: realmID, OrganizationID: orgID, Type: typ, Input: input, Requester: actor})
}

// requirePerm checks a realm-level permission.
func (a *App) requirePerm(r *http.Request, p *Principal, perm string) error {
	if !a.can(r.Context(), p, perm, a.realmScope(p)) {
		a.recordDenial(r, p, perm, "", false)
		return problem.ErrForbidden
	}
	return nil
}

type denialKey struct{}

// recordDenial audits a refused request (AZ-020): the permission and the route
// pattern, never the request body or query. A request is recorded once.
func (a *App) recordDenial(r *http.Request, p *Principal, perm, orgID string, concealed bool) {
	if done, _ := r.Context().Value(denialKey{}).(*bool); done != nil {
		if *done {
			return
		}
		*done = true
	}
	meta := map[string]any{"method": r.Method, "route": a.routeOf(r)}
	if perm != "" {
		meta["permission"] = perm
	}
	if concealed {
		meta["concealed"] = true
	}
	_, _ = a.D.Audit.Record(r.Context(), a.D.DB.Pool, audit.Event{Type: "authorization.denied", RealmID: p.Realm.ID, OrgID: orgID, Actor: p.AuditRef(),
		Category: "authorization", Outcome: audit.Denied, ReasonCode: "PERMISSION_REQUIRED", Metadata: meta})
}

// recordIdentityRead records a read of identity data (USR-018, AUD-015).
func (a *App) recordIdentityRead(ctx context.Context, p *Principal, typ, userID string, masked bool, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["masked"] = masked
	ev := audit.Event{Type: typ, RealmID: p.Realm.ID, Actor: p.AuditRef(), Category: "data_access", Metadata: meta}
	if userID != "" {
		ev.Subject = &audit.Ref{Type: "user", ID: userID}
	}
	_, err := a.D.Audit.Record(ctx, a.D.DB.Pool, ev)
	return err
}

func adminUserView(u *identity.User, schema *identity.AttributeSchema) map[string]any {
	v := selfView(u, nil)
	v["profile"] = schema.Visible(u.Profile, "admin")
	v["admin_metadata"] = u.AdminMetadata
	v["protected"] = u.Protected
	v["authz_revision"] = u.AuthzRevision
	v["last_login_at"] = u.LastLoginAt
	v["created_via"] = u.CreatedVia
	v["locked_until"] = u.LockedUntil
	if u.DeactivateAt != nil {
		v["deactivate_at"] = u.DeactivateAt
	}
	return v
}

func (a *App) adminRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	// ---------- users (USR-001) ----------
	mux.HandleFunc("GET "+R+"/users", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		masked := false
		if !a.can(r.Context(), p, "realm.users.read", a.realmScope(p)) {
			if !a.can(r.Context(), p, "support.users.read", a.realmScope(p)) {
				return problem.ErrForbidden
			}
			masked = true // support operators see masked views only (USR-018)
		}
		scope := p.Realm.ID + "|users"
		after, err := a.decodeCursor(scope, r.URL.Query().Get("cursor"))
		if err != nil {
			return err
		}
		limit := a.pageLimit(r)
		list, err := a.Users.Search(r.Context(), p.Realm.ID, identity.SearchFilter{Query: r.URL.Query().Get("q"), State: r.URL.Query().Get("state"),
			After: after, Limit: limit, OrgID: r.URL.Query().Get("organization_id")})
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, u := range list {
			if masked {
				items = append(items, identity.MaskedView(u))
			} else {
				items = append(items, adminUserView(u, a.schemaFor(p.Realm.ID)))
			}
		}
		next := ""
		if len(list) == limit {
			next = a.encodeCursor(scope, list[len(list)-1].ID)
		}
		if p.Realm.Policy.DataAccess.LogIdentityReads {
			if err := a.recordIdentityRead(r.Context(), p, "user.search", "", masked, map[string]any{"result_count": len(items),
				"filtered": r.URL.Query().Get("q") != ""}); err != nil {
				return err
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/users", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		var b struct {
			Email           string         `json:"email"`
			Username        string         `json:"username"`
			Phone           string         `json:"phone"`
			DisplayName     string         `json:"display_name"`
			GivenName       string         `json:"given_name"`
			FamilyName      string         `json:"family_name"`
			Locale          string         `json:"locale"`
			AdminMetadata   map[string]any `json:"admin_metadata"`
			SendSetupEmail  *bool          `json:"send_setup_email"`
			RequiredActions []string       `json:"required_actions"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		for _, act := range b.RequiredActions {
			if !identity.ValidRequiredAction(act) {
				return problem.ErrValidation.WithField("required_actions", "unsupported action "+act)
			}
			// Forcing a credential change or factor enrollment needs the same
			// authority at creation as later (AUT-018).
			if perm := identity.RequiredActionPermission(act); perm != "" {
				if err := a.requirePerm(r, p, perm); err != nil {
					return err
				}
			}
		}
		send := b.SendSetupEmail == nil || *b.SendSetupEmail
		var out *identity.User
		var setup string
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			out, err = a.Users.CreateTx(r.Context(), tx, p.Realm.ID, identity.CreateInput{Email: b.Email, Username: b.Username, Phone: b.Phone,
				DisplayName: b.DisplayName, GivenName: b.GivenName, FamilyName: b.FamilyName, Locale: b.Locale, AdminMetadata: b.AdminMetadata,
				State: identity.StateActive, CreatedVia: "admin", RequiredActions: b.RequiredActions})
			if err != nil {
				return err
			}
			st, err := a.Auth.IssueAccountSetupTx(r.Context(), tx, p.Realm.ID, out.ID, 72*time.Hour, send && b.Email != "", p.Realm.DisplayName)
			if err != nil {
				return err
			}
			if !send || b.Email == "" {
				setup = st.Token
			}
			_, err = a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "user.created", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: out.ID}, Metadata: map[string]any{"created_via": "admin", "setup_emailed": send && b.Email != ""}})
			return err
		})
		if err != nil {
			return err
		}
		resp := map[string]any{"user": adminUserView(out, a.schemaFor(p.Realm.ID))}
		if setup != "" {
			resp["setup_token"] = setup
			resp["notice"] = "Deliver this one-time setup token through a trusted channel. It is shown once."
		}
		writeJSON(w, http.StatusCreated, resp)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/users/{user}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		masked := false
		if !a.can(r.Context(), p, "realm.users.read", a.realmScope(p)) {
			if !a.can(r.Context(), p, "support.users.read", a.realmScope(p)) {
				return problem.ErrForbidden
			}
			masked = true
		}
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		if p.Realm.Policy.DataAccess.LogIdentityReads {
			// Evidence is written before the data is released (fail closed).
			if err := a.recordIdentityRead(r.Context(), p, "user.read", u.ID, masked, nil); err != nil {
				return err
			}
		}
		setETag(w, u.Version)
		if masked {
			writeJSON(w, http.StatusOK, identity.MaskedView(u))
			return nil
		}
		writeJSON(w, http.StatusOK, adminUserView(u, a.schemaFor(p.Realm.ID)))
		return nil
	}))
	mux.HandleFunc("PATCH "+R+"/users/{user}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		var patch identity.AdminPatch
		if err := decode(r, &patch); err != nil {
			return err
		}
		if perr := a.schemaFor(p.Realm.ID).ValidateAdminEdit(patch.Profile); perr != nil {
			return perr
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		u, err := a.Users.AdminUpdate(r.Context(), p.Realm.ID, r.PathValue("user"), ver, patch, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, u.Version)
		writeJSON(w, http.StatusOK, adminUserView(u, a.schemaFor(p.Realm.ID)))
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/users/{user}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.delete"); err != nil {
			return err
		}
		if r.PathValue("user") == p.SubjectID {
			return problem.ErrConflict.WithDetail("administrators cannot delete themselves")
		}
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			// An administrative deletion never leaves an organization ownerless
			// (USR-020): ownership is transferred first.
			sole, err := a.Orgs.SoleOwnerships(r.Context(), tx, r.PathValue("user"))
			if err != nil {
				return err
			}
			if len(sole) > 0 {
				return problem.ErrLastOwner.WithDetail("transfer ownership first: the user is the only owner of organizations").WithExtension("organizations", sole)
			}
			if owned, err := a.Orgs.OwnedResources(r.Context(), tx, r.PathValue("user")); err != nil {
				return err
			} else if len(owned) > 0 {
				return problem.ErrLastOwner.WithDetail("transfer ownership first: the user owns projects, clients or other resources").WithExtension("owned", owned)
			}
			return a.Users.DeleteNowTx(r.Context(), tx, p.Realm.ID, r.PathValue("user"), p.AuditRef(), "admin_deleted")
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	for _, st := range []struct{ path, state string }{{"suspend", identity.StateSuspended}, {"reactivate", identity.StateActive}, {"lock", identity.StateLocked}} {
		state := st.state
		mux.HandleFunc("POST "+R+"/users/{user}/"+st.path, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			// Global-account authority, not ordinary tenant membership administration (TEN-023).
			if err := a.requirePerm(r, p, "realm.users.suspend"); err != nil {
				return err
			}
			var b struct {
				Reason string `json:"reason"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			if r.PathValue("user") == p.SubjectID {
				return problem.ErrConflict.WithDetail("administrators cannot change their own account state")
			}
			var u *identity.User
			err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
				var err error
				if u, err = a.Users.SetStateTx(r.Context(), tx, p.Realm.ID, r.PathValue("user"), state, p.AuditRef(), b.Reason); err != nil {
					return err
				}
				if state == identity.StateSuspended {
					// The notice is queued with the change it reports (MSG-002).
					return a.notifyUserTx(r.Context(), tx, p.Realm, u, notification.TplAccountSuspended, nil)
				}
				return nil
			})
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, adminUserView(u, a.schemaFor(p.Realm.ID)))
			return nil
		}))
	}
	mux.HandleFunc("POST "+R+"/users/{user}/required-actions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.required_actions"); err != nil {
			return err
		}
		var b struct {
			Actions []string `json:"actions"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// If-Match names the account version the caller read the list at
		// (API-010): a read-modify-write from a stale read is refused (412)
		// instead of overwriting a concurrent change (SEC-008).
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		// Every action added or removed needs its own permission (AUT-018).
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		if ver != 0 && u.Version != ver {
			return problem.ErrPrecondition
		}
		for _, act := range append(slices.Clone(b.Actions), u.RequiredActions...) {
			if slices.Contains(b.Actions, act) == slices.Contains(u.RequiredActions, act) {
				continue
			}
			if perm := identity.RequiredActionPermission(act); perm != "" {
				if err := a.requirePerm(r, p, perm); err != nil {
					return err
				}
			}
		}
		version, err := a.Users.SetRequiredActions(r.Context(), p.Realm.ID, r.PathValue("user"), ver, u.RequiredActions, b.Actions, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, version)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/users/{user}/revoke-sessions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.sessions.revoke"); err != nil {
			return err
		}
		var n int
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			n, err = a.Sessions.RevokeUserTx(r.Context(), tx, p.Realm.ID, r.PathValue("user"), "admin_revoked", true)
			if err != nil {
				return err
			}
			_, err = a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "session.revoked_by_admin", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: r.PathValue("user")}, Metadata: map[string]any{"count": n}})
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked_sessions": n})
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/users/{user}/sessions/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.sessions.revoke"); err != nil {
			return err
		}
		sess, err := a.Sessions.Get(r.Context(), nil, p.Realm.ID, r.PathValue("id"))
		if err != nil || sess.UserID != r.PathValue("user") {
			return problem.ErrNotFound
		}
		err = a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			if err := a.Sessions.RevokeTx(r.Context(), tx, p.Realm.ID, sess.ID, "admin_revoked"); err != nil {
				return err
			}
			_, err := a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "session.revoked_by_admin", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: sess.UserID}, SessionID: sess.ID, Metadata: map[string]any{"count": 1}})
			return err
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/users/{user}/sessions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		list, err := a.Sessions.ListForUser(r.Context(), p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/users/{user}/verification-overrides", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.verification.override"); err != nil {
			return err
		}
		var b struct {
			IdentifierID string `json:"identifier_id"`
			Reason       string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Users.OverrideVerification(r.Context(), p.Realm.ID, r.PathValue("user"), b.IdentifierID, p.AuditRef(), b.Reason); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/users/{user}/credentials/password/compromised", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.credentials.manage"); err != nil {
			return err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Auth.MarkPasswordCompromised(r.Context(), p.Realm.ID, r.PathValue("user"), p.AuditRef(), b.Reason); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Account merges (USR-011): proposed by an administrator, confirmed by both
	// owners, executed by an administrator with an MFA session.
	mux.HandleFunc("POST "+R+"/users/{user}/merges", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var b struct {
			SourceUserID string `json:"source_user_id"`
			Reason       string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		m, err := a.Auth.ProposeMerge(r.Context(), p.Realm.ID, r.PathValue("user"), b.SourceUserID, b.Reason, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, m)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/account-merges/{id}/execute", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		m, err := a.Auth.ExecuteMerge(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, m)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/account-merges/{id}/cancel", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		if err := a.Auth.CancelMerge(r.Context(), p.Realm.ID, r.PathValue("id"), "", p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/me/account-merges/{id}/decline", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Auth.CancelMerge(r.Context(), p.Realm.ID, r.PathValue("id"), p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/subject-aliases/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		user, err := a.Auth.SubjectAlias(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"alias_id": r.PathValue("id"), "user_id": user})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/me/account-merges", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Auth.MergesFor(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/me/account-merges/{id}/confirm", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.Auth.ConfirmMerge(r.Context(), p.Realm.ID, r.PathValue("id"), p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Registration approval queue (REG-008).
	mux.HandleFunc("GET "+R+"/registration-approvals", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.registrations.review"); err != nil {
			return err
		}
		list, err := a.Auth.RegistrationApprovals(r.Context(), p.Realm.ID, r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/registration-approvals/{id}/decision", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.registrations.review"); err != nil {
			return err
		}
		var b struct {
			Approve bool   `json:"approve"`
			Reason  string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Auth.DecideRegistration(r.Context(), p.Realm, r.PathValue("id"), b.Approve, b.Reason, p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/assisted-recoveries/{id}/approve", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "support.recovery.assist"); err != nil {
			return err
		}
		mayReset := a.can(r.Context(), p, "realm.users.credentials.manage", a.realmScope(p))
		if err := a.Auth.ApproveAssistedRecovery(r.Context(), p.Realm.ID, r.PathValue("id"), p.SubjectID, mayReset, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/me/assisted-recoveries", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Auth.PendingAssistedRecoveries(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/me/assisted-recoveries/{id}/cancel", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Auth.CancelAssistedRecovery(r.Context(), p.Realm.ID, r.PathValue("id"), p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/users/{user}/recovery-requests", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		// Assisted recovery (MFA-009): explicit permission, reason, notification, no secret disclosure.
		if !a.can(r.Context(), p, "support.recovery.assist", a.realmScope(p)) && !a.can(r.Context(), p, "realm.users.credentials.manage", a.realmScope(p)) {
			return problem.ErrForbidden
		}
		var b struct {
			Reason   string `json:"reason"`
			Evidence string `json:"evidence_reference"`
			ResetMFA bool   `json:"reset_mfa"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if len(strings.TrimSpace(b.Reason)) < 10 || b.Evidence == "" {
			return problem.ErrValidation.WithDetail("a reason and an evidence reference are required")
		}
		if b.ResetMFA && !a.can(r.Context(), p, "realm.users.credentials.manage", a.realmScope(p)) {
			return problem.ErrForbidden.WithDetail("resetting MFA requires realm credential authority")
		}
		userID := r.PathValue("user")
		if userID == p.SubjectID {
			return problem.ErrForbidden.WithDetail("operators cannot assist their own recovery")
		}
		in := authentication.AssistedRecoveryInput{UserID: userID, Reason: b.Reason, Evidence: b.Evidence, ResetMFA: b.ResetMFA}
		if pol := p.Realm.Policy.Recovery; pol.CoolingOffHours > 0 || pol.RequireApproval {
			// Configured cooling-off or approval: the owner is warned now and the
			// recovery runs later unless cancelled (MFA-009).
			id, effective, err := a.Auth.ScheduleAssistedRecovery(r.Context(), p.Realm, in, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "recovery_scheduled", "recovery_id": id, "effective_at": effective,
				"approval_required": pol.RequireApproval})
			return nil
		}
		var setup string
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			setup, err = a.Auth.ExecuteAssistedRecoveryTx(r.Context(), tx, p.Realm, in, p.AuditRef(), "")
			return err
		})
		if err != nil {
			return err
		}
		resp := map[string]any{"status": "recovery_started"}
		if setup != "" {
			resp["setup_token"] = setup
		}
		writeJSON(w, http.StatusAccepted, resp)
		return nil
	}))
	// ---------- projects ----------
	mux.HandleFunc("GET "+R+"/projects", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.read"); err != nil {
			return err
		}
		list, err := a.Apps.ListProjects(r.Context(), p.Realm.ID, "", a.pageLimit(r))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/projects", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.write"); err != nil {
			return err
		}
		// Only client-settable fields are accepted; identifiers, state and versions
		// are server-managed (API-004).
		var b struct {
			Name                string `json:"name"`
			Description         string `json:"description"`
			Environment         string `json:"environment"`
			OwnerOrganizationID string `json:"owner_organization_id"`
			OwnerUserID         string `json:"owner_user_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		in := application.Project{Name: b.Name, Description: b.Description, Environment: b.Environment,
			OwnerOrganizationID: b.OwnerOrganizationID, OwnerUserID: b.OwnerUserID}
		out, err := a.Apps.CreateProject(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/projects/{project}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.read"); err != nil {
			return err
		}
		out, err := a.Apps.Project(r.Context(), p.Realm.ID, r.PathValue("project"))
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	// Ownership report (DOM-009, APP-014, MCH-007): live objects without an
	// accountable owner, or whose owner is no longer active.
	mux.HandleFunc("GET "+R+"/ownership-report", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		rows, err := a.D.DB.Pool.Query(r.Context(), `WITH owned AS (
				SELECT 'client' AS kind, id, client_id AS name, owner_user_id, NULL::text AS owner_org, cardinality(contacts) > 0 AS has_contacts
					FROM clients WHERE realm_id=$1 AND state='active' AND client_id <> 'proudauth-cli'
				UNION ALL SELECT 'project', id, name, owner_user_id, owner_organization_id, false FROM projects WHERE realm_id=$1 AND state <> 'archived'
				UNION ALL SELECT 'service_principal', id, name, owner_user_id, owner_organization_id, false FROM service_principals WHERE realm_id=$1 AND state='active'
				UNION ALL SELECT 'resource', id, name, owner_user_id, NULL, false FROM api_resources WHERE realm_id=$1 AND state='active' AND kind='business'
				UNION ALL SELECT 'identity_provider', id, alias, owner_user_id, organization_id, false FROM identity_providers WHERE realm_id=$1 AND state='active'
				UNION ALL SELECT 'webhook', id, name, owner_user_id, organization_id, false FROM webhook_subscriptions WHERE realm_id=$1 AND state <> 'disabled'
				UNION ALL SELECT 'hook', id, name, owner_user_id, NULL, false FROM hooks WHERE realm_id=$1 AND state='active'
				UNION ALL SELECT 'authorization_policy', id, name, owner_user_id, CASE WHEN scope_type='organization' THEN scope_id END, false
					FROM policies WHERE realm_id=$1 AND state <> 'disabled')
			SELECT o.kind, o.id, o.name, coalesce(o.owner_user_id,''), coalesce(o.owner_org,''),
				o.owner_user_id IS NULL AND o.owner_org IS NULL AND NOT o.has_contacts,
				o.owner_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=o.owner_user_id AND u.state IN ('active','recovery_restricted'))
			FROM owned o ORDER BY o.kind, o.name`, p.Realm.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var kind, id, name, owner, org string
			var ownerless, departed bool
			if err := rows.Scan(&kind, &id, &name, &owner, &org, &ownerless, &departed); err != nil {
				return err
			}
			var flags []string
			if ownerless {
				flags = append(flags, "ownerless")
			}
			if departed {
				flags = append(flags, "owner_departed")
			}
			if len(flags) == 0 {
				continue
			}
			items = append(items, map[string]any{"kind": kind, "id": id, "name": name, "owner_user_id": owner, "owner_organization_id": org, "flags": flags})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	// Offboarding (USR-020): move everything a user owns to another account.
	mux.HandleFunc("POST "+R+"/users/{user}/ownership-transfer", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		for _, k := range application.OwnedKinds {
			if err := a.requirePerm(r, p, k.Permission); err != nil {
				return err
			}
		}
		var b struct {
			ToUserID string `json:"to_user_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.ToUserID == "" || b.ToUserID == r.PathValue("user") {
			return problem.ErrValidation.WithField("to_user_id", "another account is required")
		}
		moved, err := a.Apps.TransferOwnership(r.Context(), p.Realm.ID, r.PathValue("user"), b.ToUserID, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"transferred": moved})
		return nil
	}))
	// Owner changes of single objects that have no other owner path
	// (DOM-009): pre-action hooks, webhook subscriptions and authorization
	// policies, also plugin-managed ones (they stay with their plugin).
	for _, o := range []struct{ kind, path, param, perm string }{
		{"hook", "/hooks/{id}", "id", "realm.hooks.write"},
		{"webhook", "/webhooks/{id}", "id", "realm.webhooks.write"},
		{"authorization_policy", "/policies/{policy}", "policy", "realm.policies.write"},
	} {
		mux.HandleFunc("POST "+R+o.path+"/ownership-transfer", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, o.perm); err != nil {
				return err
			}
			var b struct {
				OwnerUserID string `json:"owner_user_id"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			ver, err := ifMatch(r, false)
			if err != nil {
				return err
			}
			out, err := a.Apps.TransferObjectOwner(r.Context(), p.Realm.ID, o.kind, r.PathValue(o.param), b.OwnerUserID, ver, p.AuditRef())
			if err != nil {
				return err
			}
			setETag(w, out.Version)
			writeJSON(w, http.StatusOK, out)
			return nil
		}))
	}
	mux.HandleFunc("PATCH "+R+"/projects/{project}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.write"); err != nil {
			return err
		}
		var b struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			State       string `json:"state"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		out, err := a.Apps.UpdateProject(r.Context(), p.Realm.ID, r.PathValue("project"), ver, b.Name, b.Description, b.State, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	// Project ownership and attached applications (APP-001).
	mux.HandleFunc("POST "+R+"/projects/{project}/ownership-transfer", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.write"); err != nil {
			return err
		}
		var b struct {
			OwnerUserID         string `json:"owner_user_id"`
			OwnerOrganizationID string `json:"owner_organization_id"`
			Reason              string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		out, err := a.Apps.TransferProject(r.Context(), p.Realm.ID, r.PathValue("project"), ver,
			application.ProjectOwnerChange{OwnerUserID: b.OwnerUserID, OwnerOrganizationID: b.OwnerOrganizationID, Reason: b.Reason}, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/projects/{project}/applications", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.read"); err != nil {
			return err
		}
		clients, resources, err := a.Apps.ProjectApplications(r.Context(), p.Realm.ID, r.PathValue("project"))
		if err != nil {
			return err
		}
		grants, err := a.Apps.ListProjectGrants(r.Context(), p.Realm.ID, r.PathValue("project"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"clients": clients, "resources": resources, "organization_grants": grants})
		return nil
	}))
	// Project grants delegate a bounded set of project roles to an organization (INV-012).
	mux.HandleFunc("GET "+R+"/projects/{project}/grants", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.read"); err != nil {
			return err
		}
		list, err := a.Apps.ListProjectGrants(r.Context(), p.Realm.ID, r.PathValue("project"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/projects/{project}/grants", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.write"); err != nil {
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
		out, err := a.Apps.CreateProjectGrant(r.Context(), p.Realm.ID, r.PathValue("project"), b.OrganizationID, b.AllowedRoleIDs, b.ValidUntil, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/projects/{project}/grants/{id}/revoke", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.projects.write"); err != nil {
			return err
		}
		if err := a.Apps.RevokeProjectGrant(r.Context(), p.Realm.ID, r.PathValue("project"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// ---------- clients (APP-*) ----------
	mux.HandleFunc("GET "+R+"/clients", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		scope := p.Realm.ID + "|clients"
		after, err := a.decodeCursor(scope, r.URL.Query().Get("cursor"))
		if err != nil {
			return err
		}
		limit := a.pageLimit(r)
		list, err := a.Apps.ListClients(r.Context(), p.Realm.ID, after, limit)
		if err != nil {
			return err
		}
		next := ""
		if len(list) == limit {
			next = a.encodeCursor(scope, list[len(list)-1].Ref)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/clients", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		var in application.ClientInput
		if err := decode(r, &in); err != nil {
			return err
		}
		c, secret, err := a.Apps.CreateClient(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		resp := map[string]any{"client": c}
		if secret != "" {
			resp["client_secret"] = secret
			resp["notice"] = "The client secret is shown only once."
		}
		setETag(w, c.Version)
		writeJSON(w, http.StatusCreated, resp)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/clients/{client}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		c, err := a.Apps.ClientByRef(r.Context(), nil, p.Realm.ID, r.PathValue("client"))
		if err != nil {
			return err
		}
		grants, _ := a.Apps.ResourceGrants(r.Context(), nil, c.Ref)
		creds, _ := a.Apps.ListCredentials(r.Context(), p.Realm.ID, c.Ref)
		setETag(w, c.Version)
		writeJSON(w, http.StatusOK, map[string]any{"client": c, "resource_grants": grants, "credentials": creds})
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/clients/{client}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		var in application.ClientInput
		if err := decode(r, &in); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		c, err := a.Apps.UpdateClient(r.Context(), p.Realm.ID, r.PathValue("client"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, c.Version)
		writeJSON(w, http.StatusOK, c)
		return nil
	}))
	for _, st := range []struct{ path, state string }{{"suspend", "suspended"}, {"reactivate", "active"}, {"decommission", "decommissioned"}} {
		state := st.state
		mux.HandleFunc("POST "+R+"/clients/{client}/"+st.path, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
				return err
			}
			var b struct {
				Reason string `json:"reason"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			if err := a.Apps.SetClientState(r.Context(), p.Realm.ID, r.PathValue("client"), state, p.AuditRef(), b.Reason); err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, map[string]any{"state": state})
			return nil
		}))
	}
	mux.HandleFunc("POST "+R+"/clients/{client}/credentials", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		var b struct {
			RetireOthersAfterSeconds int             `json:"retire_others_after_seconds"`
			JWKS                     json.RawMessage `json:"jwks"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if len(b.JWKS) > 0 {
			if err := a.Apps.AddPublicKeys(r.Context(), p.Realm.ID, r.PathValue("client"), b.JWKS, p.AuditRef()); err != nil {
				if _, ok := problem.As(err); ok {
					return err
				}
				a.D.Log.Warn("client key registration failed", "error", err)
				return problem.ErrValidation.WithField("jwks", "the key set could not be accepted")
			}
			writeJSON(w, http.StatusCreated, map[string]any{"status": "keys_added"})
			return nil
		}
		plain, meta, err := a.Apps.IssueSecret(r.Context(), p.Realm.ID, r.PathValue("client"), time.Duration(b.RetireOthersAfterSeconds)*time.Second, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"client_secret": plain, "credential": meta, "notice": "The client secret is shown only once."})
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/clients/{client}/credentials/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		if err := a.Apps.RevokeCredential(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/clients/{client}/resource-grants/{resource}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		var b struct {
			AllowedScopes  []string                   `json:"allowed_scopes"`
			SubjectTypes   []string                   `json:"subject_types"`
			ExchangePolicy application.ExchangePolicy `json:"exchange_policy"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Apps.SetResourceGrantIf(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("resource"), r.Header.Get("If-Match"),
			b.AllowedScopes, b.SubjectTypes, b.ExchangePolicy, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/clients/{client}/resource-grants/{resource}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		c, err := a.Apps.ClientByRef(r.Context(), nil, p.Realm.ID, r.PathValue("client"))
		if err != nil {
			return problem.ErrNotFound
		}
		g, err := a.Apps.ResourceGrant(r.Context(), nil, c.Ref, r.PathValue("resource"))
		if err != nil {
			return err
		}
		w.Header().Set("ETag", g.ETag())
		writeJSON(w, http.StatusOK, g)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/clients/{client}/resource-grants/{resource}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		if err := a.Apps.RemoveResourceGrant(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("resource"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// ---------- resources and scopes ----------
	mux.HandleFunc("GET "+R+"/resources", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.read"); err != nil {
			return err
		}
		list, err := a.Apps.ListResources(r.Context(), p.Realm.ID, "", a.D.Cfg.Limits.MaxPageSize)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/resources", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		var in application.ResourceInput
		if err := decode(r, &in); err != nil {
			return err
		}
		res, err := a.Apps.CreateResource(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, res.Version)
		writeJSON(w, http.StatusCreated, res)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/resources/{resource}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.read"); err != nil {
			return err
		}
		res, err := a.Apps.Resource(r.Context(), nil, p.Realm.ID, r.PathValue("resource"))
		if err != nil {
			return err
		}
		setETag(w, res.Version)
		writeJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/resources/{resource}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		var in application.ResourceInput
		if err := decode(r, &in); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		res, err := a.Apps.UpdateResource(r.Context(), p.Realm.ID, r.PathValue("resource"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, res.Version)
		writeJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/resources/{resource}/scopes", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		var in application.ScopeInput
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := a.Apps.AddScope(r.Context(), p.Realm.ID, r.PathValue("resource"), in, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusCreated)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/scopes/{scope}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		if err := a.Apps.DeleteScope(r.Context(), p.Realm.ID, r.PathValue("scope"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/resources/{resource}/introspectors", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		var b struct {
			ClientRef string `json:"client"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Apps.AddResourceServerClient(r.Context(), p.Realm.ID, r.PathValue("resource"), b.ClientRef, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// ---------- permissions, roles and assignments (AZ-*) ----------
	mux.HandleFunc("GET "+R+"/permissions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		list, err := a.Authz.ListPermissions(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/permissions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.write"); err != nil {
			return err
		}
		var b struct {
			Name            string `json:"name"`
			Description     string `json:"description"`
			ResourceType    string `json:"resource_type"`
			OwnerResourceID string `json:"owner_resource_id"`
			Sensitivity     string `json:"sensitivity"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		in := authorization.Permission{Name: b.Name, Description: b.Description, ResourceType: b.ResourceType,
			OwnerResourceID: b.OwnerResourceID, Sensitivity: b.Sensitivity}
		out, err := a.Authz.RegisterPermission(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/roles", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		q := r.URL.Query()
		list, err := a.Authz.ListRoles(r.Context(), p.Realm.ID, q.Get("boundary_type"), q.Get("organization_id"), q.Get("project_id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/roles", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var in authorization.RoleInput
		if err := decode(r, &in); err != nil {
			return err
		}
		role, err := a.Authz.CreateRole(r.Context(), p.Realm.ID, p.Subject(), in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, role.Version)
		writeJSON(w, http.StatusCreated, role)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/roles/{role}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		role, err := a.Authz.Role(r.Context(), nil, p.Realm.ID, r.PathValue("role"))
		if err != nil {
			return err
		}
		setETag(w, role.Version)
		writeJSON(w, http.StatusOK, role)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/roles/{role}/permissions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
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
		out, err := a.Authz.ModifyRolePermissions(r.Context(), p.Realm.ID, r.PathValue("role"), ver, p.Subject(), b.Add, b.Remove, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/roles/{role}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Authz.DeleteRole(r.Context(), p.Realm.ID, r.PathValue("role"), p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/role-assignments", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		q := r.URL.Query()
		var subj *authorization.Subject
		if q.Get("subject_id") != "" {
			subj = &authorization.Subject{Type: q.Get("subject_type"), ID: q.Get("subject_id")}
			if subj.Type == "" {
				subj.Type = authorization.SubjectUser
			}
		}
		var scope *authorization.Scope
		if q.Get("scope_id") != "" {
			scope = &authorization.Scope{Type: q.Get("scope_type"), ID: q.Get("scope_id")}
		}
		list, err := a.Authz.ListAssignments(r.Context(), p.Realm.ID, subj, scope)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/role-assignments", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			RoleID     string                `json:"role_id"`
			Subject    authorization.Subject `json:"subject"`
			Scope      authorization.Scope   `json:"scope"`
			ExpiresAt  *string               `json:"expires_at"`
			ValidFrom  *string               `json:"valid_from"`
			Conditions map[string]any        `json:"conditions"`
			Reason     string                `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Scope.Type == "" {
			b.Scope = a.realmScope(p)
		}
		from, err := parseTimePtr(b.ValidFrom)
		if err != nil {
			return err
		}
		if b.Scope.Type == authorization.ScopeRealm && b.Scope.ID != p.Realm.ID {
			return problem.ErrValidation.WithField("scope", "realm scope must be this realm")
		}
		exp, err := parseTimePtr(b.ExpiresAt)
		if err != nil {
			return err
		}
		in := authorization.AssignInput{RoleID: b.RoleID, Subject: b.Subject, Scope: b.Scope, ExpiresAt: exp, ValidFrom: from, Conditions: b.Conditions, Reason: b.Reason}
		// Roles that require an independent approver go through the two-party
		// workflow: the approver is whoever authenticates the approval (AZ-018).
		if needs, err := a.Authz.AssignmentNeedsApproval(r.Context(), p.Realm.ID, b.RoleID, b.Subject); err != nil {
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
	mux.HandleFunc("GET "+R+"/role-assignment-requests", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		list, err := a.Authz.ListAssignmentRequests(r.Context(), p.Realm.ID, r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	decideRequest := func(approve bool) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
				return err
			}
			if err := decode(r, &struct{}{}); err != nil {
				return err
			}
			out, err := a.Authz.DecideAssignmentRequest(r.Context(), p.Realm.ID, r.PathValue("id"), p.Subject(), approve, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, out)
			return nil
		})
	}
	mux.HandleFunc("POST "+R+"/role-assignment-requests/{id}/approve", decideRequest(true))
	mux.HandleFunc("POST "+R+"/role-assignment-requests/{id}/reject", decideRequest(false))
	mux.HandleFunc("DELETE "+R+"/role-assignments/{assignment}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Authz.Unassign(r.Context(), p.Realm.ID, r.PathValue("assignment"), p.Subject(), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/subjects/{subject}/permissions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		scope := a.realmScope(p)
		org := r.URL.Query().Get("organization_id")
		if org != "" {
			scope = orgScope(org)
		}
		project, err := a.projectParam(r, p, org)
		if err != nil {
			return err
		}
		typ := authorization.SubjectUser
		if strings.HasPrefix(r.PathValue("subject"), "svc_") {
			typ = authorization.SubjectService
		}
		ex, err := a.Authz.Explain(r.Context(), nil, p.Realm.ID, authorization.Subject{Type: typ, ID: r.PathValue("subject")}, scope,
			authorization.ExplainOptions{ShowPolicies: a.can(r.Context(), p, "realm.policies.read", a.realmScope(p)), ProjectID: project})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, explanationView(ex))
		return nil
	}))
	// ---------- service principals and API keys (MCH-*) ----------
	mux.HandleFunc("GET "+R+"/service-principals", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.service_principals.read"); err != nil {
			return err
		}
		list, err := a.Machine.List(r.Context(), p.Realm.ID, "", a.pageLimit(r))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/service-principals", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.service_principals.write"); err != nil {
			return err
		}
		var in machine.SPInput
		if err := decode(r, &in); err != nil {
			return err
		}
		sp, err := a.Machine.Create(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, sp)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/service-principals/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.service_principals.read"); err != nil {
			return err
		}
		sp, err := a.Machine.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, sp.Version)
		writeJSON(w, http.StatusOK, sp)
		return nil
	}))
	mux.HandleFunc("PATCH "+R+"/service-principals/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.service_principals.write"); err != nil {
			return err
		}
		var in machine.SPInput
		if err := decode(r, &in); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		sp, err := a.Machine.Update(r.Context(), p.Realm.ID, r.PathValue("id"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, sp.Version)
		writeJSON(w, http.StatusOK, sp)
		return nil
	}))
	for _, st := range []struct {
		method, path, state string
	}{{"POST", "/disable", "disabled"}, {"POST", "/enable", "active"}, {"DELETE", "", "deleted"}} {
		state := st.state
		mux.HandleFunc(st.method+" "+R+"/service-principals/{id}"+st.path, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.service_principals.write"); err != nil {
				return err
			}
			if err := a.Machine.SetState(r.Context(), p.Realm.ID, r.PathValue("id"), state, p.AuditRef()); err != nil {
				return err
			}
			w.WriteHeader(http.StatusNoContent)
			return nil
		}))
	}
	mux.HandleFunc("GET "+R+"/api-keys", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.api_keys.manage"); err != nil {
			return err
		}
		list, err := a.Machine.ListCredentials(r.Context(), p.Realm.ID, r.URL.Query().Get("owner_type"), r.URL.Query().Get("owner_id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/api-keys", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.api_keys.manage"); err != nil {
			return err
		}
		var b struct {
			ServicePrincipalID string `json:"service_principal_id"`
			machine.CredentialInput
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		plain, c, err := a.Machine.CreateCredential(r.Context(), p.Realm.ID, "api_key", "service_principal", b.ServicePrincipalID, b.CredentialInput, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"api_key": plain, "credential": c, "notice": "The API key is shown only once."})
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/api-keys/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.api_keys.manage"); err != nil {
			return err
		}
		if err := a.Machine.RevokeCredential(r.Context(), p.Realm.ID, r.PathValue("id"), "", "", p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/credential-inventory", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.credentials.inventory"); err != nil {
			return err
		}
		list, err := a.Machine.Inventory(r.Context(), p.Realm.ID, 14*24*time.Hour, 60*24*time.Hour)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	// Bulk revocation from the inventory (MCH-016): each credential is revoked
	// in its own transaction with its own audit record; results are per item.
	mux.HandleFunc("POST "+R+"/credential-inventory/revocations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.credentials.inventory"); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
			return err
		}
		var b struct {
			IDs    []string `json:"ids"`
			Reason string   `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if len(b.IDs) == 0 || len(b.IDs) > 100 || len(b.Reason) < 3 {
			return problem.ErrValidation.WithDetail("1..100 ids and a reason are required")
		}
		results := []map[string]any{}
		for _, id := range b.IDs {
			var err error
			switch {
			case strings.HasPrefix(id, ids.Automation+"_"):
				if err = a.requirePerm(r, p, "realm.api_keys.manage"); err == nil {
					err = a.Machine.RevokeCredential(r.Context(), p.Realm.ID, id, "", "", p.AuditRef())
				}
			case strings.HasPrefix(id, ids.ClientCred+"_"):
				if err = a.requirePerm(r, p, "realm.clients.credentials"); err == nil {
					var ref string
					if qerr := a.D.DB.Pool.QueryRow(r.Context(), `SELECT client_ref FROM client_credentials WHERE realm_id=$1 AND id=$2`, p.Realm.ID, id).Scan(&ref); qerr != nil {
						err = problem.ErrNotFound
					} else {
						err = a.Apps.RevokeCredential(r.Context(), p.Realm.ID, ref, id, p.AuditRef())
					}
				}
			default:
				err = problem.ErrNotFound
			}
			item := map[string]any{"id": id, "status": "revoked"}
			if err != nil {
				pe, ok := problem.As(err)
				if !ok {
					return err
				}
				item["status"], item["error"] = "failed", pe.Code
			}
			results = append(results, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results, "reason": b.Reason})
		return nil
	}))
	// ---------- realm settings (ARC-008) ----------
	mux.HandleFunc("GET "+R+"/settings", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		setETag(w, p.Realm.Version)
		writeJSON(w, http.StatusOK, map[string]any{"realm": p.Realm.Name, "issuer": p.Realm.Issuer, "state": p.Realm.State,
			"policy": p.Realm.Policy, "policy_revision": p.Realm.PolicyRevision, "version": p.Realm.Version})
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/settings", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var b struct {
			Policy realm.Policy `json:"policy"`
			Reason string       `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		out, err := a.Realms.UpdatePolicy(r.Context(), p.Realm.ID, ver, b.Policy, p.AuditRef(), b.Reason)
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, map[string]any{"policy": out.Policy, "policy_revision": out.PolicyRevision, "version": out.Version})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/emergency/realm-state", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.emergency"); err != nil {
			return err
		}
		var b struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Realms.SetState(r.Context(), p.Realm.ID, b.State, p.AuditRef(), b.Reason); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"state": b.State})
		return nil
	}))
	// ---------- signing keys (TOK-011..013) ----------
	mux.HandleFunc("GET "+R+"/signing-keys", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.keys.read"); err != nil {
			return err
		}
		list, err := a.KeyMgr.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/signing-key-rotations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.keys.rotate"); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 5*time.Minute); err != nil {
			return err
		}
		var b struct {
			Mode      string `json:"mode"`
			Algorithm string `json:"algorithm"`
			Reason    string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		mode := token.RotationPlanned
		if b.Mode == "emergency" {
			mode = token.RotationEmergency
		}
		// Without an algorithm the new key keeps the realm's, that of its
		// active key. Rotate refuses, with 409 naming them, an algorithm that
		// pinned resources (TOK-005) or fapi2 clients (ADV-001) do not accept:
		// re-pin those resources first.
		kid, err := a.KeyMgr.Rotate(r.Context(), p.Realm.ID, b.Algorithm, mode, p.AuditRef(), b.Reason)
		if err != nil {
			if _, ok := problem.As(err); ok {
				return err
			}
			// Internal detail is logged for operators, not returned (SEC-015).
			a.D.Log.Error("signing key rotation failed", "error", err)
			return problem.ErrConflict.WithDetail("the signing key rotation could not be completed")
		}
		writeJSON(w, http.StatusCreated, map[string]any{"kid": kid, "mode": mode})
		return nil
	}))
	// ---------- audit (AUD-006, AUD-011) ----------
	mux.HandleFunc("GET "+R+"/audit-events", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.read"); err != nil {
			return err
		}
		return a.auditQuery(w, r, p, r.URL.Query().Get("organization_id"))
	}))
	// Corrections (AUD-007): evidence is never edited; a correction is a new
	// event that names the event it corrects, and both stay queryable.
	mux.HandleFunc("POST "+R+"/audit-events/{id}/corrections", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.correct"); err != nil {
			return err
		}
		var b struct {
			Reason     string         `json:"reason"`
			Correction map[string]any `json:"correction"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if l := len(strings.TrimSpace(b.Reason)); l < 5 || l > 1000 {
			return problem.ErrValidation.WithField("reason", "5..1000 characters")
		}
		if raw, _ := json.Marshal(b.Correction); len(raw) > 8<<10 {
			return problem.ErrValidation.WithField("correction", "at most 8 KiB")
		}
		orig, _, err := audit.Query(r.Context(), a.D.DB.Pool, audit.Filter{RealmID: p.Realm.ID, EventID: r.PathValue("id"), Limit: 1})
		if err != nil {
			return err
		}
		if len(orig) == 0 {
			return problem.ErrNotFound
		}
		ev, err := a.D.Audit.Record(r.Context(), a.D.DB.Pool, audit.Event{Type: "audit.correction", RealmID: p.Realm.ID, OrgID: orig[0].OrgID,
			Actor: p.AuditRef(), Category: "configuration", Target: &audit.Ref{Type: "audit_event", ID: orig[0].ID},
			Metadata: map[string]any{"corrects_event_id": orig[0].ID, "corrects_type": orig[0].Type, "reason": b.Reason, "correction": b.Correction}})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"event_id": ev, "corrects_event_id": orig[0].ID})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/audit-integrity", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.read"); err != nil {
			return err
		}
		// The evidence chain spans the deployment. Realm administrators see a
		// cached summary (no other realm's batch identifiers), recomputed at most
		// every ten minutes so the endpoint cannot be used to force full scans.
		// Operators run the detailed check with `identity-cli verify-audit`.
		sum, err := a.auditIntegritySummary(r.Context())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, sum)
		return nil
	}))
	// ---------- jobs ----------
	mux.HandleFunc("GET "+R+"/jobs/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		j, err := jobs.NewService(a.D).Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		if j.RequestedByID != p.SubjectID && !a.can(r.Context(), p, "realm.jobs.read", a.realmScope(p)) {
			return problem.ErrNotFound
		}
		writeJSON(w, http.StatusOK, j)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/jobs/{id}/cancel", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		svc := jobs.NewService(a.D)
		j, err := svc.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		if j.RequestedByID != p.SubjectID && !a.can(r.Context(), p, "realm.jobs.cancel", a.realmScope(p)) {
			return problem.ErrNotFound
		}
		if j.Type == "organization.delete" {
			return problem.ErrConflict.WithDetail("organization deletion cannot be cancelled after access was revoked")
		}
		if err := svc.Cancel(r.Context(), p.Realm.ID, j.ID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusAccepted)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/jobs/{id}/downloads", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if p.IsUser() {
			if err := a.requireRecentAuth(p, 0); err != nil {
				return err
			}
		}
		// The requester must still hold the permission the job needed (INT-006).
		if j, err := jobs.NewService(a.D).Get(r.Context(), p.Realm.ID, r.PathValue("id")); err == nil && j.RequestedByID == p.SubjectID {
			if perm := jobs.RequiredPermission(j.Type); perm != "" {
				if err := a.requirePerm(r, p, perm); err != nil {
					return err
				}
			}
		}
		tok, err := jobs.NewService(a.D).IssueDownload(r.Context(), p.Realm.ID, r.PathValue("id"), p.SubjectID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"download_token": tok, "expires_in": 300})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/job-downloads", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Token string `json:"download_token"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// The permission is checked again when the credential is redeemed: it
		// may have been revoked in the minutes since it was issued (INT-006).
		res, err := jobs.NewService(a.D).Download(r.Context(), p.Realm.ID, b.Token, p.AuditRef(), func(jobType string) error {
			if perm := jobs.RequiredPermission(jobType); perm != "" {
				return a.requirePerm(r, p, perm)
			}
			return nil
		})
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", res.ContentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+res.Filename+`"`)
		_, _ = w.Write(res.Data)
		return nil
	}))
	// ---------- support impersonation (§16) ----------
	mux.HandleFunc("POST "+R+"/impersonation-requests", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if !p.IsUser() {
			return problem.ErrForbidden.WithDetail("support access requires a human operator")
		}
		var in impersonation.RequestInput
		if err := decode(r, &in); err != nil {
			return err
		}
		req, err := a.Imp.RequestAccess(r.Context(), p.Realm, impActor(p), in)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, req)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/impersonation-requests/{id}/approve", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if !p.IsUser() {
			return problem.ErrForbidden
		}
		if err := a.Imp.Approve(r.Context(), p.Realm, impActor(p), r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/impersonation-requests/{id}/deny", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Imp.Deny(r.Context(), p.Realm, impActor(p), r.PathValue("id"), b.Reason); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/me/impersonation-requests", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Imp.PendingForCustomer(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/impersonation-requests/{id}/issue", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if !p.IsUser() {
			return problem.ErrForbidden
		}
		out, err := a.Imp.Issue(r.Context(), p.Realm, impActor(p), r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/impersonation-grants", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		q := r.URL.Query()
		actor := q.Get("actor_user_id")
		if !a.can(r.Context(), p, "support.impersonation.read", a.realmScope(p)) {
			actor = p.SubjectID // operators see their own grants
		}
		list, err := a.Imp.List(r.Context(), p.Realm.ID, actor, q.Get("target_user_id"), q.Get("organization_id"), q.Get("state"), q.Get("ticket_reference"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/impersonation-grants/{id}/revoke", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Imp.Revoke(r.Context(), p.Realm, impActor(p), r.PathValue("id"), b.Reason); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/impersonation-grants/{id}/handoffs", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			DestinationClientID string `json:"destination_client_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		code, exp, err := a.Imp.CreateHandoff(r.Context(), p.Realm, impActor(p), r.PathValue("id"), b.DestinationClientID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"handoff_code": code, "expires_at": exp})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/impersonation-handoffs/redeem", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		if err := parseForm(r); err != nil {
			return err
		}
		// private_key_jwt assertions target the exact URL of this endpoint.
		c, err := a.Apps.Authenticate(r.Context(), rlm.ID, rlm.Issuer, strings.TrimSuffix(a.D.Cfg.Server.PublicOrigin, "/")+"/api/v1/realms/"+rlm.Name+"/impersonation-handoffs/redeem", a.clientAuthFrom(r))
		if err != nil || c.Public() {
			return problem.ErrUnauthenticated
		}
		out, err := a.Imp.RedeemHandoff(r.Context(), rlm, c, r.PostForm.Get("handoff_code"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	// ---------- policy decision (AZ-013) ----------
	mux.HandleFunc("POST "+R+"/authorization/check", a.admin(a.authorizationCheck))
	mux.HandleFunc("POST "+R+"/authorization/check-batch", a.admin(a.authorizationCheckBatch))
}

func (a *App) auditQuery(w http.ResponseWriter, r *http.Request, p *Principal, orgID string) error {
	q := r.URL.Query()
	f := audit.Filter{RealmID: p.Realm.ID, OrgID: orgID, EventID: q.Get("id"), ActorID: q.Get("actor_id"), SubjectID: q.Get("subject_id"), Type: q.Get("type"),
		TypePrefix: q.Get("type_prefix"), Outcome: q.Get("outcome"), ClientID: q.Get("client_id"), RequestID: q.Get("request_id"),
		ImpersonationGrantID: q.Get("impersonation_grant_id"), GrantID: q.Get("grant_id"), SessionID: q.Get("session_id"),
		TargetID: q.Get("target_id"), Category: q.Get("category"), Limit: a.pageLimit(r)}
	if v := q.Get("network"); v != "" {
		// IP-derived context (AUD-011): an address or prefix, matched against
		// the truncated network context stored with each event.
		if ip, err := netip.ParseAddr(v); err == nil {
			v = netip.PrefixFrom(ip, ip.BitLen()).String()
		}
		pfx, err := netip.ParsePrefix(v)
		if err != nil {
			return problem.ErrValidation.WithField("network", "an IP address or CIDR prefix")
		}
		f.Network = pfx.Masked().String()
	}
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return problem.ErrValidation.WithField("from", "RFC 3339")
		}
		f.From = &t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return problem.ErrValidation.WithField("to", "RFC 3339")
		}
		f.To = &t
	}
	// API-004: sequence positions belong to this route and filter set.
	// Canonical URL encoding keeps delimiters/duplicate values unambiguous;
	// page size may change, and the authorized organization remains a hard
	// boundary independently of any supplied organization_id parameter.
	filters := r.URL.Query()
	filters.Del("cursor")
	filters.Del("limit")
	scope := p.Realm.ID + "|audit|" + orgID + "|" + r.Pattern + "|" + filters.Encode()
	if c := q.Get("cursor"); c != "" {
		raw, err := a.decodeCursor(scope, c)
		if err != nil {
			return err
		}
		f.BeforeSeq, _ = strconv.ParseInt(raw, 10, 64)
	}
	events, last, err := audit.Query(r.Context(), a.D.DB.Pool, f)
	if err != nil {
		return err
	}
	next := ""
	if last > 0 {
		next = a.encodeCursor(scope, strconv.FormatInt(last, 10))
	}
	if events == nil {
		events = []audit.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events, "next_cursor": next})
	return nil
}

// notifyUserTx queues a mandatory security notice in the same transaction as
// the change it reports (MSG-002): the change and its notice commit together.
func (a *App) notifyUserTx(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, u *identity.User, tpl string, data map[string]string) error {
	e := u.PrimaryEmail()
	if e == nil || !e.Verified() {
		return nil
	}
	if data == nil {
		data = map[string]string{}
	}
	data["realm"] = rlm.DisplayName
	data["time"] = notification.Timestamp(a.D.Now())
	_, err := a.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: rlm.ID, Template: tpl, Recipient: e.Value, Mandatory: true,
		ReferenceType: "user", ReferenceID: u.ID, Data: data})
	return err
}

type integritySummary struct {
	OK        bool      `json:"ok"`
	Batches   int       `json:"batches_checked"`
	Events    int       `json:"events_checked"`
	Problems  int       `json:"problems"`
	Scope     string    `json:"scope"`
	CheckedAt time.Time `json:"checked_at"`
}

func (a *App) auditIntegritySummary(ctx context.Context) (*integritySummary, error) {
	a.integrityMu.Lock()
	defer a.integrityMu.Unlock()
	if a.integrity != nil && a.D.Now().Sub(a.integrity.CheckedAt) < 10*time.Minute {
		return a.integrity, nil
	}
	rep, err := audit.VerifyChain(ctx, a.D.DB.Pool)
	if err != nil {
		return nil, err
	}
	a.integrity = &integritySummary{OK: rep.OK, Batches: rep.Batches, Events: rep.Events, Problems: len(rep.Problems), Scope: "deployment", CheckedAt: a.D.Now()}
	return a.integrity, nil
}
