package httpapi

import (
	"net/http"

	"github.com/proudbase/proudauth/internal/certauth"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// certificateRoutes manage realm certificate trust anchors (MCH-014,
// PROV-016): authorities trusted for mutual-TLS client authentication
// (purpose client) or for X.509 user sign-in (purpose user), with optional
// revocation lists.
func (a *App) certificateRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}/certificate-trust-anchors"
	perm := func(purpose string) string {
		if purpose == certauth.PurposeUser {
			return "realm.settings.write"
		}
		return "realm.clients.credentials"
	}
	mux.HandleFunc("POST "+R, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var in certauth.AnchorInput
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Purpose != certauth.PurposeClient && in.Purpose != certauth.PurposeUser {
			return problem.ErrValidation.WithField("purpose", "client or user")
		}
		if err := a.requirePerm(r, p, perm(in.Purpose)); err != nil {
			return err
		}
		an, err := a.Certs.AddAnchor(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, an)
		return nil
	}))
	mux.HandleFunc("GET "+R, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		list, err := a.Certs.Anchors(r.Context(), nil, p.Realm.ID, r.URL.Query().Get("purpose"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("PUT "+R+"/{id}/crl", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		an, err := a.Certs.Anchor(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		if err := a.requirePerm(r, p, perm(an.Purpose)); err != nil {
			return err
		}
		var b struct {
			CRLPEM string `json:"crl_pem"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		an, err = a.Certs.UpdateCRL(r.Context(), p.Realm.ID, an.ID, b.CRLPEM, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, an)
		return nil
	}))
	// Bindings of user certificates to accounts (PROV-016).
	U := "/api/v1/realms/{realm}/users/{user}/certificate-bindings"
	mux.HandleFunc("POST "+U, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.credentials.manage"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var in certauth.BindingInput
		if err := decode(r, &in); err != nil {
			return err
		}
		b, err := a.Certs.Bind(r.Context(), p.Realm.ID, r.PathValue("user"), in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, b)
		return nil
	}))
	mux.HandleFunc("GET "+U, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		list, err := a.Certs.Bindings(r.Context(), p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("DELETE "+U+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.credentials.manage"); err != nil {
			return err
		}
		if err := a.Certs.Unbind(r.Context(), p.Realm.ID, r.PathValue("user"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		an, err := a.Certs.Anchor(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		if err := a.requirePerm(r, p, perm(an.Purpose)); err != nil {
			return err
		}
		if err := a.Certs.RemoveAnchor(r.Context(), p.Realm.ID, an.ID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
