package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/proudbase/proudauth/internal/contracts"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/workflow"
)

// extensibilityRoutes registers lifecycle workflows (EXT-015, EXT-016),
// plugins (EXT-014) and the extension contract catalog (EXT-018).
func (a *App) extensibilityRoutes(mux *http.ServeMux) {
	a.workflowRoutes(mux)
	a.pluginRoutes(mux)
	mux.HandleFunc("GET /api/v1/realms/{realm}/extension-contracts", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		// Every reader of extension configuration may see which contract
		// versions this server speaks (EXT-018).
		for _, perm := range []string{"realm.plugins.read", "realm.webhooks.read", "realm.hooks.read", "realm.workflows.read"} {
			if a.can(r.Context(), p, perm, a.realmScope(p)) {
				writeJSON(w, http.StatusOK, map[string]any{"items": contracts.Registry, "support_window_months": contracts.SupportWindowMonths})
				return nil
			}
		}
		return a.requirePerm(r, p, "realm.plugins.read")
	}))
}

// revisionNumber parses the {revision} path segment.
func revisionNumber(r *http.Request) (int, error) {
	n, err := strconv.Atoi(r.PathValue("revision"))
	if err != nil || n < 1 {
		return 0, problem.ErrNotFound
	}
	return n, nil
}

func (a *App) workflowRoutes(mux *http.ServeMux) {
	W := "/api/v1/realms/{realm}/workflows"
	read := func(h handlerFunc) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.workflows.read"); err != nil {
				return err
			}
			return h(w, r, p)
		})
	}
	// publish guards changes that make a definition act: approving,
	// publishing, rolling back, enabling and disabling.
	publish := func(recent bool, h handlerFunc) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.workflows.publish"); err != nil {
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
	mux.HandleFunc("GET "+W, read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Workflows.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+W, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.workflows.write"); err != nil {
			return err
		}
		var in workflow.CreateInput
		if err := decode(r, &in); err != nil {
			return err
		}
		wf, rev, err := a.Workflows.Create(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, wf.Version)
		writeJSON(w, http.StatusCreated, map[string]any{"workflow": wf, "revision": rev})
		return nil
	}))
	mux.HandleFunc("GET "+W+"/{id}", read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		wf, err := a.Workflows.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, wf.Version)
		writeJSON(w, http.StatusOK, wf)
		return nil
	}))
	mux.HandleFunc("DELETE "+W+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.workflows.write"); err != nil {
			return err
		}
		if err := a.Workflows.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+W+"/{id}/diagnostics", read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		d, err := a.Workflows.Diagnose(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, d)
		return nil
	}))
	mux.HandleFunc("GET "+W+"/{id}/revisions", read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Workflows.Revisions(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+W+"/{id}/revisions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.workflows.write"); err != nil {
			return err
		}
		var b struct {
			Definition json.RawMessage `json:"definition"`
			Note       string          `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		rev, err := a.Workflows.StageRevision(r.Context(), p.Realm.ID, r.PathValue("id"), b.Definition, b.Note, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, rev)
		return nil
	}))
	mux.HandleFunc("GET "+W+"/{id}/revisions/{revision}", read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		n, err := revisionNumber(r)
		if err != nil {
			return err
		}
		rev, err := a.Workflows.Revision(r.Context(), p.Realm.ID, r.PathValue("id"), n)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, rev)
		return nil
	}))
	for _, d := range []struct{ path, decision string }{{"approve", "approve"}, {"reject", "reject"}} {
		approve := d.decision == "approve"
		mux.HandleFunc("POST "+W+"/{id}/revisions/{revision}/"+d.path, publish(false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			n, err := revisionNumber(r)
			if err != nil {
				return err
			}
			var b struct {
				Note string `json:"note"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			rev, err := a.Workflows.DecideRevision(r.Context(), p.Realm.ID, r.PathValue("id"), n, approve, b.Note, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, rev)
			return nil
		}))
	}
	mux.HandleFunc("POST "+W+"/{id}/revisions/{revision}/publish", publish(true, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		n, err := revisionNumber(r)
		if err != nil {
			return err
		}
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		wf, err := a.Workflows.Publish(r.Context(), p.Realm.ID, r.PathValue("id"), n, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, wf.Version)
		writeJSON(w, http.StatusOK, wf)
		return nil
	}))
	mux.HandleFunc("POST "+W+"/{id}/rollback", publish(true, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Revision int `json:"revision"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Revision < 1 {
			return problem.ErrValidation.WithField("revision", "a previously published revision number")
		}
		wf, err := a.Workflows.Rollback(r.Context(), p.Realm.ID, r.PathValue("id"), b.Revision, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, wf.Version)
		writeJSON(w, http.StatusOK, wf)
		return nil
	}))
	for _, st := range []struct{ path, state string }{{"enable", "active"}, {"disable", "disabled"}} {
		state := st.state
		mux.HandleFunc("POST "+W+"/{id}/"+st.path, publish(false, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			var b struct {
				Reason string `json:"reason"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			if len(b.Reason) > 64 {
				return problem.ErrValidation.WithField("reason", "at most 64 characters")
			}
			wf, err := a.Workflows.SetState(r.Context(), p.Realm.ID, r.PathValue("id"), state, p.AuditRef(), b.Reason)
			if err != nil {
				return err
			}
			setETag(w, wf.Version)
			writeJSON(w, http.StatusOK, wf)
			return nil
		}))
	}
	runs := func(w http.ResponseWriter, r *http.Request, p *Principal, workflowID string) error {
		q := r.URL.Query()
		f := workflow.RunFilter{WorkflowID: workflowID, SubjectID: q.Get("subject_id"), State: q.Get("state"), Limit: a.pageLimit(r)}
		if c := q.Get("cursor"); c != "" {
			raw, err := a.decodeCursor(listScope(r), c)
			if err != nil {
				return err
			}
			at, id, ok := cutCursor(raw)
			if !ok {
				return problem.ErrBadRequest.WithDetail("invalid cursor")
			}
			f.BeforeAt, f.BeforeID = &at, id
		}
		list, err := a.Workflows.ListRuns(r.Context(), p.Realm.ID, f)
		if err != nil {
			return err
		}
		next := ""
		if len(list) == f.Limit && len(list) > 0 {
			last := list[len(list)-1]
			next = a.encodeCursor(listScope(r), last.CreatedAt.Format(time.RFC3339Nano)+"|"+last.ID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
		return nil
	}
	mux.HandleFunc("GET "+W+"/{id}/runs", read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.Workflows.Get(r.Context(), p.Realm.ID, r.PathValue("id")); err != nil {
			return err
		}
		return runs(w, r, p, r.PathValue("id"))
	}))
	mux.HandleFunc("POST "+W+"/{id}/runs", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.workflows.run"); err != nil {
			return err
		}
		var in workflow.StartInput
		if err := decode(r, &in); err != nil {
			return err
		}
		run, err := a.Workflows.Start(r.Context(), p.Realm.ID, r.PathValue("id"), in, r.Header.Get("Idempotency-Key"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, run)
		return nil
	}))
	R := "/api/v1/realms/{realm}/workflow-runs"
	mux.HandleFunc("GET "+R, read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		return runs(w, r, p, r.URL.Query().Get("workflow_id"))
	}))
	mux.HandleFunc("GET "+R+"/{id}", read(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		run, err := a.Workflows.GetRun(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, run)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/{id}/cancel", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.workflows.run"); err != nil {
			return err
		}
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		run, err := a.Workflows.CancelRun(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, run)
		return nil
	}))

	// Named approvers decide through their own account (EXT-015, AZ-018).
	me := "/api/v1/realms/{realm}/me/workflow-approvals"
	mux.HandleFunc("GET "+me, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Workflows.MyApprovals(r.Context(), p.Realm.ID, p.SubjectID, r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+me+"/{id}/decision", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Decision string `json:"decision"`
			Comment  string `json:"comment"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		ap, err := a.Workflows.Decide(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), b.Decision, b.Comment)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, ap)
		return nil
	}))
}

// cutCursor splits a "<RFC 3339 time>|<id>" keyset cursor.
func cutCursor(raw string) (time.Time, string, bool) {
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] == '|' {
			t, err := time.Parse(time.RFC3339Nano, raw[:i])
			return t, raw[i+1:], err == nil && raw[i+1:] != ""
		}
	}
	return time.Time{}, "", false
}
