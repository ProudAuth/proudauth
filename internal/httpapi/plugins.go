package httpapi

import (
	"net/http"

	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/plugin"
)

// pluginRoutes administers plugin packages (EXT-014): upload, second-
// administrator review, installation, upgrade, rollback, enable, disable and
// uninstall.
func (a *App) pluginRoutes(mux *http.ServeMux) {
	P := "/api/v1/realms/{realm}/plugins"
	guard := func(perm string, recent bool, h handlerFunc) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, perm); err != nil {
				return err
			}
			if recent && p.IsUser() {
				if err := a.requireRecentAuth(p, 0); err != nil {
					return err
				}
			}
			return h(w, r, p)
		})
	}
	mux.HandleFunc("GET "+P, guard("realm.plugins.read", false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Plugins.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+P, guard("realm.plugins.manage", true, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var pkg plugin.Package
		if err := decode(r, &pkg); err != nil {
			return err
		}
		plug, ver, err := a.Plugins.Upload(r.Context(), p.Realm.ID, pkg, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"plugin": plug, "version": ver})
		return nil
	}))
	mux.HandleFunc("GET "+P+"/{id}", guard("realm.plugins.read", false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		plug, err := a.Plugins.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, plug.Version)
		writeJSON(w, http.StatusOK, plug)
		return nil
	}))
	mux.HandleFunc("DELETE "+P+"/{id}", guard("realm.plugins.manage", true, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		plug, err := a.Plugins.Uninstall(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, plug)
		return nil
	}))
	mux.HandleFunc("GET "+P+"/{id}/versions", guard("realm.plugins.read", false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Plugins.Versions(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+P+"/{id}/versions/{version}", guard("realm.plugins.read", false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		v, err := a.Plugins.GetVersion(r.Context(), p.Realm.ID, r.PathValue("id"), r.PathValue("version"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, v)
		return nil
	}))
	for _, d := range []struct{ path, decision string }{{"approve", "approve"}, {"reject", "reject"}} {
		approve := d.decision == "approve"
		mux.HandleFunc("POST "+P+"/{id}/versions/{version}/"+d.path, guard("realm.plugins.approve", approve, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			var b struct {
				Note string `json:"note"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			v, err := a.Plugins.Review(r.Context(), p.Realm.ID, r.PathValue("id"), r.PathValue("version"), approve, b.Note, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, v)
			return nil
		}))
	}
	mux.HandleFunc("POST "+P+"/{id}/versions/{version}/install", guard("realm.plugins.manage", true, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		res, err := a.Plugins.Install(r.Context(), p.Realm.ID, r.PathValue("id"), r.PathValue("version"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.HandleFunc("POST "+P+"/{id}/rollback", guard("realm.plugins.manage", true, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		res, err := a.Plugins.Rollback(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, res)
		return nil
	}))
	for _, st := range []struct{ path, state string }{{"enable", "enabled"}, {"disable", "disabled"}} {
		state := st.state
		mux.HandleFunc("POST "+P+"/{id}/"+st.path, guard("realm.plugins.manage", false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			var b struct {
				Reason string `json:"reason"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			if len(b.Reason) > 64 {
				return problem.ErrValidation.WithField("reason", "at most 64 characters")
			}
			plug, err := a.Plugins.SetState(r.Context(), p.Realm.ID, r.PathValue("id"), state, b.Reason, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, plug)
			return nil
		}))
	}
}
