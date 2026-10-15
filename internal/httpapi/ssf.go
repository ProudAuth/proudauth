package httpapi

import (
	"net/http"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/ssf"
)

// ssfRoutes serve the Shared Signals Framework transmitter (AUD-016):
// metadata, the stream management API for receivers, RFC 8936 polling, and
// an administrator's view of every stream.
func (a *App) ssfRoutes(mux *http.ServeMux) {
	meta := func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		if !ssf.Enabled(rlm) {
			return problem.ErrNotFound
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(w, http.StatusOK, ssf.Configuration(rlm))
		return nil
	}
	mux.HandleFunc("GET /.well-known/ssf-configuration/realms/{realm}", a.public(meta))
	mux.HandleFunc("GET /realms/{realm}/.well-known/ssf-configuration", a.public(meta))

	S := "/realms/{realm}/ssf/streams"
	// receiver authenticates a stream-management call: a machine client of
	// the realm holding realm.ssf_streams.manage, on a realm that declared
	// the transmitter. Streams belong to the calling client.
	receiver := func(h func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error) http.HandlerFunc {
		return a.protected(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if !ssf.Enabled(p.Realm) {
				return problem.ErrNotFound
			}
			if p.Kind != "service_principal" {
				return problem.ErrForbidden.WithDetail("security-event receivers are machine clients")
			}
			if err := a.requirePerm(r, p, "realm.ssf_streams.manage"); err != nil {
				return err
			}
			c, err := a.Apps.ClientByRef(r.Context(), nil, p.Realm.ID, p.ClientRef)
			if err != nil {
				return problem.ErrUnauthenticated
			}
			return h(w, r, p, c)
		}, application.KindAdmin)
	}
	mux.HandleFunc("POST "+S, receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		var in ssf.StreamInput
		if err := decode(r, &in); err != nil {
			return err
		}
		st, err := a.SSF.Create(r.Context(), p.Realm, c, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, st)
		return nil
	}))
	mux.HandleFunc("GET "+S, receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		if id := r.URL.Query().Get("stream_id"); id != "" {
			st, err := a.SSF.Stream(r.Context(), p.Realm, c.Ref, id)
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, st)
			return nil
		}
		list, err := a.SSF.Streams(r.Context(), p.Realm, c.Ref)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, list)
		return nil
	}))
	update := func(replace bool) http.HandlerFunc {
		return receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
			var in ssf.StreamInput
			if err := decode(r, &in); err != nil {
				return err
			}
			st, err := a.SSF.Update(r.Context(), p.Realm, c.Ref, in, replace, false, p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, st)
			return nil
		})
	}
	mux.HandleFunc("PATCH "+S, update(false))
	mux.HandleFunc("PUT "+S, update(true))
	mux.HandleFunc("DELETE "+S, receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		if err := a.SSF.Delete(r.Context(), p.Realm, c.Ref, r.URL.Query().Get("stream_id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	status := func(st *ssf.Stream) map[string]any {
		out := map[string]any{"stream_id": st.ID, "status": st.Status}
		if st.StatusReason != "" {
			out["reason"] = st.StatusReason
		}
		return out
	}
	mux.HandleFunc("GET "+S+"/status", receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		st, err := a.SSF.Stream(r.Context(), p.Realm, c.Ref, r.URL.Query().Get("stream_id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, status(st))
		return nil
	}))
	mux.HandleFunc("POST "+S+"/status", receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		var b struct {
			StreamID string `json:"stream_id"`
			Status   string `json:"status"`
			Reason   string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		st, err := a.SSF.SetStatus(r.Context(), p.Realm, c.Ref, b.StreamID, b.Status, b.Reason, false, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, status(st))
		return nil
	}))
	subject := func(add bool) http.HandlerFunc {
		return receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
			var b struct {
				StreamID string      `json:"stream_id"`
				Subject  ssf.Subject `json:"subject"`
				Verified *bool       `json:"verified"`
			}
			if err := decode(r, &b); err != nil {
				return err
			}
			if b.Subject == nil {
				return problem.ErrValidation.WithField("subject", "required")
			}
			do := a.SSF.RemoveSubject
			if add {
				do = a.SSF.AddSubject
			}
			if err := do(r.Context(), p.Realm, c, b.StreamID, b.Subject); err != nil {
				return err
			}
			if add {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
			return nil
		})
	}
	mux.HandleFunc("POST "+S+"/subjects/add", subject(true))
	mux.HandleFunc("POST "+S+"/subjects/remove", subject(false))
	mux.HandleFunc("POST "+S+"/verify", receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		var b struct {
			StreamID string `json:"stream_id"`
			State    string `json:"state"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.SSF.Verify(r.Context(), p.Realm, c.Ref, b.StreamID, b.State); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+S+"/{id}/poll", receiver(func(w http.ResponseWriter, r *http.Request, p *Principal, c *application.Client) error {
		var in ssf.PollRequest
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.SSF.Poll(r.Context(), p.Realm, c.Ref, r.PathValue("id"), in)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))

	// ---------- administration ----------
	A := "/api/v1/realms/{realm}/ssf-streams"
	mux.HandleFunc("GET "+A, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.ssf_streams.read"); err != nil {
			return err
		}
		list, err := a.SSF.Streams(r.Context(), p.Realm, "")
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+A+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.ssf_streams.read"); err != nil {
			return err
		}
		st, err := a.SSF.Stream(r.Context(), p.Realm, "", r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	}))
	mux.HandleFunc("GET "+A+"/{id}/events", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.ssf_streams.read"); err != nil {
			return err
		}
		list, err := a.SSF.Events(r.Context(), p.Realm, r.PathValue("id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("PATCH "+A+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		var b struct {
			SubjectScope *string `json:"subject_scope"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		st, err := a.SSF.Update(r.Context(), p.Realm, "", ssf.StreamInput{StreamID: r.PathValue("id"), SubjectScope: b.SubjectScope}, false, true, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	}))
	mux.HandleFunc("POST "+A+"/{id}/status", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		var b struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// The receiver learns of a change it did not make (stream-updated).
		st, err := a.SSF.SetStatus(r.Context(), p.Realm, "", r.PathValue("id"), b.Status, b.Reason, true, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	}))
	mux.HandleFunc("DELETE "+A+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		if err := a.SSF.Delete(r.Context(), p.Realm, "", r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
