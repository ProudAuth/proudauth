package httpapi

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// adminIdentifierRoutes are the administrator's part of recovering a lost
// contact address (MFA-008): add the address the owner can still reach,
// verify it with the audited override (USR-005,
// POST /users/{user}/verification-overrides), then make it the primary
// address, which assisted recovery delivers the setup link to. An unverified
// address never becomes primary, so recovery can never be redirected to an
// address nobody proved control of. The address the account had before is
// told about each change (USR-004).
func (a *App) adminIdentifierRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("POST "+R+"/users/{user}/identifiers", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.authorizeIdentifierAdministration(r, p); err != nil {
			return err
		}
		var b struct {
			Type   string `json:"type"`
			Value  string `json:"value"`
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Type != "email" {
			return problem.ErrValidation.WithField("type", "administrators add email addresses only")
		}
		if err := identifierChangeReason(b.Reason); err != nil {
			return err
		}
		var out *identity.Identifier
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			u, err := a.Users.LockUser(r.Context(), tx, p.Realm.ID, r.PathValue("user"))
			if err != nil {
				return err
			}
			if u.State == identity.StateDeleted {
				return problem.ErrNotFound
			}
			if out, err = a.Users.AdminAddEmailTx(r.Context(), tx, p.Realm.ID, u.ID, b.Value); err != nil {
				return err
			}
			if _, err := a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "user.identifier.added", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: u.ID}, ReasonCode: "ADMIN_CHANGE",
				Metadata: map[string]any{"identifier_id": out.ID, "identifier_type": out.Type, "reason": b.Reason}}); err != nil {
				return err
			}
			// u was read before the change: its verified primary address is the
			// contact the owner had until now. The notice never names the new one.
			return a.notifyUserTx(r.Context(), tx, p.Realm, u, notification.TplIdentifierChanged,
				map[string]string{"change": "an administrator added an email address to your account (not verified yet)"})
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": out.ID, "type": out.Type, "value": out.Value, "verified": false, "is_primary": false,
			"next": "POST /users/{user}/verification-overrides with a reason, then POST /users/{user}/identifiers/{id}/primary"})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/users/{user}/identifiers/{id}/primary", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.authorizeIdentifierAdministration(r, p); err != nil {
			return err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := identifierChangeReason(b.Reason); err != nil {
			return err
		}
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			u, err := a.Users.LockUser(r.Context(), tx, p.Realm.ID, r.PathValue("user"))
			if err != nil {
				return err
			}
			if u.State == identity.StateDeleted {
				return problem.ErrNotFound
			}
			var target *identity.Identifier
			for i := range u.Identifiers {
				if u.Identifiers[i].ID == r.PathValue("id") {
					target = &u.Identifiers[i]
				}
			}
			switch {
			case target == nil:
				return problem.ErrNotFound
			case target.Type != "email":
				return problem.ErrValidation.WithDetail("administrators change the primary email address only")
			case !target.Verified():
				return problem.ErrValidation.WithDetail("only verified identifiers can become primary; verify it first with POST /users/{user}/verification-overrides")
			case target.IsPrimary:
				return problem.ErrConflict.WithDetail("the identifier is already primary")
			}
			previous := u.PrimaryEmail()
			if err := a.Users.PromoteIdentifierTx(r.Context(), tx, u.ID, target.ID); err != nil {
				return err
			}
			meta := map[string]any{"identifier_id": target.ID, "identifier_type": target.Type, "reason": b.Reason}
			if previous != nil && previous.ID != target.ID {
				meta["previous_identifier_id"] = previous.ID
			}
			if _, err := a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "user.identifier.primary_changed", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: u.ID}, ReasonCode: "ADMIN_CHANGE", Metadata: meta}); err != nil {
				return err
			}
			if previous == nil || previous.ID == target.ID {
				return nil
			}
			// The previous primary address, when verified, learns of the change
			// (USR-004); u still names it, and the notice never names the new one.
			return a.notifyUserTx(r.Context(), tx, p.Realm, u, notification.TplIdentifierChanged,
				map[string]string{"change": "an administrator made another email address the primary contact of your account"})
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}

// authorizeIdentifierAdministration admits an administrative identifier
// change: it needs both realm.users.verification.override and
// realm.users.credentials.manage, the authority the lost contact address path
// already requires; a recent sign-in of a user caller (the a.admin wrapper
// already requires an MFA session); and another account than the caller's
// own, whose identifiers change through self-service with proof of control.
func (a *App) authorizeIdentifierAdministration(r *http.Request, p *Principal) error {
	for _, perm := range []string{"realm.users.verification.override", "realm.users.credentials.manage"} {
		if err := a.requirePerm(r, p, perm); err != nil {
			return err
		}
	}
	if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
		return err
	}
	if r.PathValue("user") == p.SubjectID {
		return problem.ErrForbidden.WithDetail("administrators change their own identifiers through self-service")
	}
	return nil
}

// identifierChangeReason requires the reason recorded with an administrative
// identifier change.
func identifierChangeReason(reason string) error {
	if l := len(strings.TrimSpace(reason)); l < 5 || l > 500 {
		return problem.ErrValidation.WithField("reason", "a reason of 5 to 500 characters is required")
	}
	return nil
}
