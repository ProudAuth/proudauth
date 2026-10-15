package httpapi

import (
	"net/http"
	"strconv"

	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
)

// flowRevisionRoutes version the authentication flow (AUT-019): drafts carry
// a reachability and bypass analysis, simulation compares a draft with the
// live flow, publishing refuses stale drafts and bypass paths, and rollback
// republishes an earlier revision as a new one.
func (a *App) flowRevisionRoutes(mux *http.ServeMux) {
	F := "/api/v1/realms/{realm}/authentication-flow/revisions"
	revision := func(r *http.Request) (int, error) {
		n, err := strconv.Atoi(r.PathValue("revision"))
		if err != nil || n < 1 {
			return 0, problem.ErrNotFound
		}
		return n, nil
	}
	mux.HandleFunc("GET "+F, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		list, err := a.Realms.FlowRevisions(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+F, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		var b struct {
			Definition realm.AuthFlowPolicy `json:"definition"`
			Note       string               `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		fr, err := a.Realms.CreateFlowDraft(r.Context(), p.Realm.ID, b.Definition, b.Note, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, fr)
		return nil
	}))
	mux.HandleFunc("GET "+F+"/{revision}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		n, err := revision(r)
		if err != nil {
			return err
		}
		fr, err := a.Realms.FlowRevision(r.Context(), p.Realm.ID, n)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, fr)
		return nil
	}))
	mux.HandleFunc("DELETE "+F+"/{revision}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		n, err := revision(r)
		if err != nil {
			return err
		}
		if err := a.Realms.DiscardFlowDraft(r.Context(), p.Realm.ID, n, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+F+"/{revision}/simulate", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		n, err := revision(r)
		if err != nil {
			return err
		}
		var b struct {
			Cases []authentication.FlowCase `json:"cases"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		fr, err := a.Realms.FlowRevision(r.Context(), p.Realm.ID, n)
		if err != nil {
			return err
		}
		results, err := authentication.SimulateFlow(p.Realm.Policy.AuthFlow, fr.Definition, b.Cases)
		if err != nil {
			return err
		}
		summary := map[string]int{"unchanged": 0, "stricter": 0, "weaker": 0, "rule_changed": 0}
		for _, s := range results {
			summary[s.Change]++
		}
		writeJSON(w, http.StatusOK, map[string]any{"revision": fr.Revision, "live_policy_revision": p.Realm.PolicyRevision,
			"results": results, "summary": summary, "analysis": realm.AnalyzeFlow(fr.Definition)})
		return nil
	}))
	publish := func(rollback bool) func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		return func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
				return err
			}
			n, err := revision(r)
			if err != nil {
				return err
			}
			var b struct {
				AcknowledgeWarnings bool   `json:"acknowledge_warnings"`
				Reason              string `json:"reason"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			do, status := a.Realms.PublishFlowRevision, http.StatusOK
			if rollback {
				do, status = a.Realms.RollbackFlow, http.StatusCreated
			}
			fr, out, err := do(r.Context(), p.Realm.ID, n, b.AcknowledgeWarnings, p.AuditRef(), b.Reason)
			if err != nil {
				return err
			}
			setETag(w, out.Version)
			writeJSON(w, status, map[string]any{"revision": fr, "policy_revision": out.PolicyRevision, "version": out.Version})
			return nil
		}
	}
	mux.HandleFunc("POST "+F+"/{revision}/publish", a.admin(publish(false)))
	mux.HandleFunc("POST "+F+"/{revision}/rollback", a.admin(publish(true)))
}
