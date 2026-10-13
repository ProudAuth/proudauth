package httpapi

import (
	"net"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/proudbase/proudauth/internal/passkey"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// webauthnTrustRoutes serve passkey attestation trust (PASS-009) and the
// WebAuthn Level 3 related origins document (PASS-010).
func (a *App) webauthnTrustRoutes(mux *http.ServeMux) {
	T := "/api/v1/realms/{realm}/webauthn/trusted-authenticators"
	mux.HandleFunc("GET "+T, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		list, err := a.Passkeys.TrustedAuthenticators(r.Context(), nil, p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+T, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		var in passkey.TrustedAuthenticatorInput
		if err := decode(r, &in); err != nil {
			return err
		}
		t, err := a.Passkeys.AddTrustedAuthenticator(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, t)
		return nil
	}))
	mux.HandleFunc("DELETE "+T+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		if err := a.Passkeys.RemoveTrustedAuthenticator(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET /.well-known/webauthn", a.relatedOrigins)
}

// relatedOrigins serves https://{rp_id}/.well-known/webauthn: the origins of
// every realm whose explicit RP ID is this host and that declared related
// origins, when the operator allows them. Anything else is 404, so a client
// never learns of origins the operator did not approve.
func (a *App) relatedOrigins(w http.ResponseWriter, r *http.Request) {
	if !a.D.Cfg.WebAuthn.RelatedOrigins {
		a.fail(w, r, problem.ErrNotFound)
		return
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	rows, err := a.D.DB.Pool.Query(r.Context(), `SELECT name FROM realms WHERE settings->'webauthn'->>'rp_id' = $1
		AND jsonb_array_length(coalesce(settings->'webauthn'->'related_origins', '[]'::jsonb)) > 0 ORDER BY name`, host)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	rows.Close()
	var origins []string
	for _, n := range names {
		rlm, err := a.Realms.ByName(r.Context(), n)
		if err != nil || !rlm.Active() {
			continue
		}
		rp, err := a.Passkeys.RelyingPartyFor(rlm)
		if err != nil {
			continue
		}
		origins = append(origins, rp.Origins...)
		origins = append(origins, rlm.Policy.WebAuthn.RelatedOrigins...)
	}
	if len(origins) == 0 {
		a.fail(w, r, problem.ErrNotFound)
		return
	}
	doc, err := protocol.NewRelatedOrigins(origins...)
	if err != nil {
		a.fail(w, r, problem.ErrNotFound)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}
