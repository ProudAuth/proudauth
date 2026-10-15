package httpapi

import (
	"net/http"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// elevationRoutes serve just-in-time elevation (AZ-024): administrators
// manage eligibilities and decide requests; people ask for and end their own
// elevations.
func (a *App) elevationRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("POST "+R+"/elevation-eligibilities", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var in authorization.EligibilityInput
		if err := decode(r, &in); err != nil {
			return err
		}
		// The delegation ceiling decides who may make someone eligible.
		e, err := a.Authz.CreateEligibility(r.Context(), p.Realm.ID, p.Subject(), in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, e)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/elevation-eligibilities", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		list, err := a.Authz.ListEligibilities(r.Context(), p.Realm.ID, r.URL.Query().Get("user_id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("DELETE "+R+"/elevation-eligibilities/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.assign"); err != nil {
			return err
		}
		if err := a.Authz.RevokeEligibility(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/elevations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.read"); err != nil {
			return err
		}
		q := r.URL.Query()
		list, err := a.Authz.ListElevations(r.Context(), nil, p.Realm.ID, q.Get("user_id"), q.Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	decide := func(approve bool) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
				return err
			}
			if err := decode(r, &struct{}{}); err != nil {
				return err
			}
			el, err := a.Authz.DecideElevation(r.Context(), p.Realm.ID, p.Subject(), r.PathValue("id"), approve, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, el)
			return nil
		})
	}
	mux.HandleFunc("POST "+R+"/elevations/{id}/approve", decide(true))
	mux.HandleFunc("POST "+R+"/elevations/{id}/reject", decide(false))
	mux.HandleFunc("POST "+R+"/elevations/{id}/end", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.roles.assign"); err != nil {
			return err
		}
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		if err := a.Authz.EndElevation(r.Context(), p.Realm.ID, r.PathValue("id"), "", p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))

	me := R + "/me"
	mux.HandleFunc("GET "+me+"/elevation-eligibilities", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Authz.ListEligibilities(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+me+"/elevations", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		// Asking for privilege is itself sensitive: a fresh, multi-factor
		// session only.
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if p.Session == nil || !p.Session.HasMFA() {
			return problem.ErrStepUpRequired.WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "required_profile": "mfa"}})
		}
		var in authorization.ElevationRequest
		if err := decode(r, &in); err != nil {
			return err
		}
		el, err := a.Authz.RequestElevation(r.Context(), p.Realm.ID, p.SubjectID, in)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, el)
		return nil
	}))
	mux.HandleFunc("GET "+me+"/elevations", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Authz.ListElevations(r.Context(), nil, p.Realm.ID, p.SubjectID, r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+me+"/elevations/{id}/end", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		if err := a.Authz.EndElevation(r.Context(), p.Realm.ID, r.PathValue("id"), p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
