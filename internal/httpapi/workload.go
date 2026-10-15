package httpapi

import (
	"net/http"

	"github.com/proudauth/proudauth/internal/workload"
)

// workloadRoutes manages workload federation trusts (MCH-011..MCH-013): who,
// outside this deployment, may act as a client's service principal. Changing
// them is a credential change.
func (a *App) workloadRoutes(mux *http.ServeMux) {
	base := "/api/v1/realms/{realm}/clients/{client}/workload-trusts"
	mux.HandleFunc("GET "+base, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		list, err := a.Workload.List(r.Context(), p.Realm.ID, r.PathValue("client"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		var in workload.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		t, err := a.Workload.Create(r.Context(), p.Realm.ID, r.PathValue("client"), in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusCreated, t)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		t, err := a.Workload.Get(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("PUT "+base+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in workload.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		t, err := a.Workload.Update(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("id"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		if err := a.Workload.Delete(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
