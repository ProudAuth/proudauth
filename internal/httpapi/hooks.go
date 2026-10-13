package httpapi

import (
	"net/http"

	"github.com/proudbase/proudauth/internal/hooks"
)

// hookRoutes administers pre-action hooks (EXT-009, EXT-017).
func (a *App) hookRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/realms/{realm}/hooks/{id}/diagnostics", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.hooks.read"); err != nil {
			return err
		}
		d, err := a.Hooks.Diagnose(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, d)
		return nil
	}))
	H := "/api/v1/realms/{realm}/hooks"
	mux.HandleFunc("GET "+H, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.hooks.read"); err != nil {
			return err
		}
		list, err := a.Hooks.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+H, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.hooks.write"); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
			return err
		}
		var in hooks.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		h, secretValue, err := a.Hooks.Create(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, h.Version)
		writeJSON(w, http.StatusCreated, map[string]any{"hook": h, "signing_secret": secretValue})
		return nil
	}))
	mux.HandleFunc("GET "+H+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.hooks.read"); err != nil {
			return err
		}
		h, err := a.Hooks.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, h.Version)
		writeJSON(w, http.StatusOK, h)
		return nil
	}))
	mux.HandleFunc("PUT "+H+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.hooks.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in hooks.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		// Plugin parts change with their plugin (EXT-014).
		if err := a.Hooks.GuardManual(r.Context(), p.Realm.ID, r.PathValue("id")); err != nil {
			return err
		}
		h, err := a.Hooks.Update(r.Context(), p.Realm.ID, r.PathValue("id"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, h.Version)
		writeJSON(w, http.StatusOK, h)
		return nil
	}))
	mux.HandleFunc("DELETE "+H+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.hooks.write"); err != nil {
			return err
		}
		if err := a.Hooks.GuardManual(r.Context(), p.Realm.ID, r.PathValue("id")); err != nil {
			return err
		}
		if err := a.Hooks.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
