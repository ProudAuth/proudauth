package httpapi

import (
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
)

// federationRoutes registers upstream federation endpoints (FED-001..013,
// USR-010).
func (a *App) federationRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	tx := R + "/auth/transactions"
	mux.HandleFunc("POST "+tx+"/{id}/federation/start", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Provider string `json:"provider"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		if b.Provider == "" {
			return nil, problem.ErrValidation.WithField("provider", "required")
		}
		return a.Auth.StartFederation(r.Context(), rlm.ID, id, p, b.Provider)
	}))
	// Resume re-evaluates a transaction after an out-of-band step (upstream
	// callback, SSO reuse) and completes it when nothing remains.
	mux.HandleFunc("POST "+tx+"/{id}/resume", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		if err := decode(r, &struct{}{}); err != nil {
			return nil, err
		}
		return a.Auth.Resume(r.Context(), rlm.ID, id, p)
	}))
	callback := func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		q := r.URL.Query()
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				return problem.ErrBadRequest
			}
			q = r.PostForm
		}
		res, err := a.Auth.FederationCallback(r.Context(), rlm.ID, r.PathValue("connection"), q)
		if err != nil {
			return err
		}
		ui := rlm.Policy.Interaction.LoginUIURL
		if ui == "" {
			// Headless deployments without a login UI receive the outcome as JSON;
			// the application resumes the transaction with its continuation token.
			out := map[string]any{"transaction_id": res.TransactionID, "status": "ok"}
			if res.Error != "" {
				out["status"], out["error"] = "error", res.Error
			}
			if res.LinkCode != "" {
				out = map[string]any{"status": "link_pending_confirmation", "link_code": res.LinkCode}
			}
			writeJSON(w, http.StatusOK, out)
			return nil
		}
		u, err := url.Parse(ui)
		if err != nil {
			return problem.ErrInternal
		}
		v := u.Query()
		if res.TransactionID != "" {
			v.Set("transaction_id", res.TransactionID)
		}
		if res.Error != "" {
			v.Set("federation_error", res.Error)
		}
		u.RawQuery = v.Encode()
		if res.LinkCode != "" {
			// The confirmation code travels in the fragment, which browsers do not
			// send to servers or proxies (SEC-007).
			u.Fragment = "federation_link_code=" + url.QueryEscape(res.LinkCode)
		}
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return nil
	}
	mux.HandleFunc("GET "+R+"/federation/{connection}/callback", a.public(callback))
	mux.HandleFunc("POST "+R+"/federation/{connection}/callback", a.public(callback))

	// Self-service linked identities (USR-010, FED-011).
	me := R + "/me/linked-identities"
	mux.HandleFunc("GET "+me, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return nil
		}
		items, err := a.Federation.Linked(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("POST "+me, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		var b struct {
			Provider string `json:"provider"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		prov, err := a.Federation.Get(r.Context(), nil, p.Realm.ID, b.Provider)
		if err != nil || prov.State != "active" {
			return problem.ErrValidation.WithField("provider", "unknown or disabled connection")
		}
		var redirect string
		err = a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			redirect, err = a.Federation.BeginTx(r.Context(), tx, p.Realm.ID, p.Realm.Name, prov, "link", "", p.SubjectID, p.SessionID, "")
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"authorization_url": redirect, "expires_in": int(federation.RequestTTL.Seconds())})
		return nil
	}))
	mux.HandleFunc("POST "+me+"/confirm", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		var b struct {
			Code string `json:"code"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		l, err := a.Federation.ConfirmLink(r.Context(), p.Realm.ID, p.SubjectID, b.Code, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, l)
		return nil
	}))
	mux.HandleFunc("DELETE "+me+"/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrNotFound
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.Federation.Unlink(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))

	// Administration of connections (§26.5 identity-providers).
	idp := R + "/identity-providers"
	mux.HandleFunc("GET "+idp, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.read"); err != nil {
			return err
		}
		items, err := a.Federation.List(r.Context(), nil, p.Realm.ID, false)
		if err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("POST "+idp, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		var in federation.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.Federation.Create(r.Context(), p.Realm.ID, in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+idp+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.read"); err != nil {
			return err
		}
		out, err := a.Federation.Get(r.Context(), nil, p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("PUT "+idp+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in federation.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.Federation.Update(r.Context(), p.Realm.ID, r.PathValue("id"), ver, in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+idp+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		if err := a.Federation.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+idp+"/{id}/test", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		prov, err := a.Federation.Get(r.Context(), nil, p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, a.Federation.Test(r.Context(), prov))
		return nil
	}))
	mux.HandleFunc("GET "+R+"/users/{user}/linked-identities", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		items, err := a.Federation.Linked(r.Context(), p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("DELETE "+R+"/users/{user}/linked-identities/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		if err := a.Federation.Unlink(r.Context(), p.Realm.ID, r.PathValue("user"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
