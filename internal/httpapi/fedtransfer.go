package httpapi

import (
	"net/http"
	"strconv"

	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// federationTransferRoutes serve federation transfers (FED-016): a
// reviewed migration map moves account links between provider connections.
func (a *App) federationTransferRoutes(mux *http.ServeMux) {
	F := "/api/v1/realms/{realm}/federation-transfers"
	guard := func(perm string, h handlerFunc) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if a.Federation == nil {
				return problem.ErrFeatureDisabled.WithDetail("federation is not enabled")
			}
			if err := a.requirePerm(r, p, perm); err != nil {
				return err
			}
			return h(w, r, p)
		})
	}
	mux.HandleFunc("GET "+F, guard("realm.identity_providers.read", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Federation.Transfers(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+F, guard("realm.identity_providers.write", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var in federation.TransferInput
		if err := decode(r, &in); err != nil {
			return err
		}
		t, err := a.Federation.CreateTransfer(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusCreated, t)
		return nil
	}))
	mux.HandleFunc("GET "+F+"/{id}", guard("realm.identity_providers.read", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		t, err := a.Federation.Transfer(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("GET "+F+"/{id}/entries", guard("realm.identity_providers.read", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		q := r.URL.Query()
		after, _ := strconv.Atoi(q.Get("after"))
		limit := a.pageLimit(r)
		list, err := a.Federation.TransferEntries(r.Context(), p.Realm.ID, r.PathValue("id"), q.Get("outcome"), after, limit)
		if err != nil {
			return err
		}
		out := map[string]any{"items": list}
		if len(list) == limit {
			out["next_after"] = list[len(list)-1].Seq
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("POST "+F+"/{id}/entries", guard("realm.identity_providers.write", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Entries []federation.TransferEntry `json:"entries"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		t, err := a.Federation.AddTransferEntries(r.Context(), p.Realm.ID, r.PathValue("id"), b.Entries, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("POST "+F+"/{id}/approve", guard("realm.identity_providers.write", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		t, err := a.Federation.ApproveTransfer(r.Context(), p.Realm.ID, r.PathValue("id"), ver, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("POST "+F+"/{id}/apply", guard("realm.identity_providers.write", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		t, err := a.Federation.ApplyTransfer(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("POST "+F+"/{id}/cancel", guard("realm.identity_providers.write", func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Federation.CancelTransfer(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
