package httpapi

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/directory"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// buildDirectory wires the directory integration module (PROV-010..PROV-018,
// FED-015, USR-022): password verification by directory bind, the attribute
// authority that refuses local edits of externally managed attributes, and
// the connector APIs. directory.enabled=false leaves it nil.
func (a *App) buildDirectory() error {
	cfg := a.D.Cfg.Directory
	a.Directory = directory.New(a.D, a.Users, a.Orgs, a.Authz, a.Metrics)
	// A disabled module still guards the accounts directories sourced: no
	// local password fallback and no local edits of managed attributes.
	a.Directory.Disabled = !cfg.Enabled
	if f := cfg.CAFile; f != "" && cfg.Enabled {
		pem, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("directory.ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("directory.ca_file: no certificates found")
		}
		a.Directory.RootCAs = pool
	}
	a.Users.Authority = a.Directory
	a.Auth.Directory = a.Directory
	return nil
}

// dirScope authorizes a directory connector request. The realm family needs
// realm.provisioning.manage (realm.provisioning.read suffices for reads) and
// sees every connector of the realm; the organization family needs
// org.integrations.write in that organization and sees only its own
// connectors (tenant isolation). Changes need an MFA session.
func (a *App) dirScope(r *http.Request, p *Principal, write bool) (string, error) {
	if a.Directory == nil || a.Directory.Disabled {
		return "", problem.ErrFeatureDisabled
	}
	if org := r.PathValue("org"); org != "" {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return "", err
		}
		if write {
			if err := a.requireMFASession(p); err != nil {
				return "", err
			}
		}
		return org, nil
	}
	// Realm-wide connectors are realm administration: the administration
	// audience and an MFA session, like every realm administration route.
	if p.Audience != application.KindAdmin {
		return "", problem.ErrForbidden.WithDetail("realm directory connectors require an administration token")
	}
	if err := a.requireMFASession(p); err != nil {
		return "", err
	}
	if !write && a.can(r.Context(), p, "realm.provisioning.read", a.realmScope(p)) {
		return "", nil
	}
	return "", a.requirePerm(r, p, "realm.provisioning.manage")
}

// directoryRoutes serve directory and outbound provisioning connectors at
// realm and organization scope, and the attribute authority declaration of
// accounts (USR-022).
func (a *App) directoryRoutes(mux *http.ServeMux) {
	for _, fam := range []struct{ base string }{
		{"/api/v1/realms/{realm}/directory-connectors"},
		{"/api/v1/realms/{realm}/organizations/{org}/directory-connectors"},
	} {
		base := fam.base
		mux.HandleFunc("GET "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			list, err := a.Directory.List(r.Context(), p.Realm.ID, org)
			if err != nil {
				return err
			}
			return a.writeList(w, r, list)
		}))
		mux.HandleFunc("POST "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			var in directory.Input
			if err := decode(r, &in); err != nil {
				return err
			}
			c, err := a.Directory.Create(r.Context(), p.Realm.ID, org, in, p.Subject(), p.AuditRef())
			if err != nil {
				return err
			}
			setETag(w, c.Version)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusCreated, c)
			return nil
		}))
		mux.HandleFunc("GET "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			c, err := a.Directory.Get(r.Context(), p.Realm.ID, org, r.PathValue("id"))
			if err != nil {
				return err
			}
			setETag(w, c.Version)
			writeJSON(w, http.StatusOK, c)
			return nil
		}))
		mux.HandleFunc("PUT "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			version, err := ifMatch(r, true)
			if err != nil {
				return err
			}
			var in struct {
				directory.Input
				State string `json:"state"`
			}
			if err := decode(r, &in); err != nil {
				return err
			}
			c, err := a.Directory.Update(r.Context(), p.Realm.ID, org, r.PathValue("id"), version, in.Input, in.State, p.Subject(), p.AuditRef())
			if err != nil {
				return err
			}
			setETag(w, c.Version)
			writeJSON(w, http.StatusOK, c)
			return nil
		}))
		mux.HandleFunc("DELETE "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			if err := a.Directory.Delete(r.Context(), p.Realm.ID, org, r.PathValue("id"), p.AuditRef()); err != nil {
				return err
			}
			w.WriteHeader(http.StatusNoContent)
			return nil
		}))
		mux.HandleFunc("PUT "+base+"/{id}/credential", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			var in struct {
				Credential string `json:"credential"`
			}
			if err := decode(r, &in); err != nil {
				return err
			}
			c, err := a.Directory.SetCredential(r.Context(), p.Realm.ID, org, r.PathValue("id"), in.Credential, p.AuditRef())
			if err != nil {
				return err
			}
			setETag(w, c.Version)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, c)
			return nil
		}))
		mux.HandleFunc("POST "+base+"/{id}/test", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			res, err := a.Directory.Test(r.Context(), p.Realm.ID, org, r.PathValue("id"), p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, res)
			return nil
		}))
		mux.HandleFunc("POST "+base+"/{id}/runs", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			var in directory.RunRequest
			if err := decode(r, &in); err != nil {
				return err
			}
			run, err := a.Directory.RequestRun(r.Context(), p.Realm.ID, org, r.PathValue("id"), in, "manual", p.AuditRef())
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusAccepted, run)
			return nil
		}))
		mux.HandleFunc("GET "+base+"/{id}/runs", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			runs, err := a.Directory.Runs(r.Context(), p.Realm.ID, org, r.PathValue("id"), 200)
			if err != nil {
				return err
			}
			return a.writeList(w, r, runs)
		}))
		mux.HandleFunc("GET "+base+"/{id}/runs/{run}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			run, err := a.Directory.GetRun(r.Context(), p.Realm.ID, org, r.PathValue("id"), r.PathValue("run"))
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, run)
			return nil
		}))
		mux.HandleFunc("GET "+base+"/{id}/runs/{run}/findings", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			after, _ := strconv.Atoi(r.URL.Query().Get("after"))
			limit := a.pageLimit(r)
			items, err := a.Directory.Findings(r.Context(), p.Realm.ID, org, r.PathValue("id"), r.PathValue("run"), r.URL.Query().Get("kind"), after, limit)
			if err != nil {
				return err
			}
			next := ""
			if len(items) == limit {
				next = strconv.Itoa(items[len(items)-1].Seq)
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_after": next})
			return nil
		}))
		mux.HandleFunc("GET "+base+"/{id}/health", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			h, err := a.Directory.Health(r.Context(), p.Realm.ID, org, r.PathValue("id"))
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, h)
			return nil
		}))
		mux.HandleFunc("GET "+base+"/{id}/deliveries", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, false)
			if err != nil {
				return err
			}
			list, err := a.Directory.Deliveries(r.Context(), p.Realm.ID, org, r.PathValue("id"), r.URL.Query().Get("state"), 200)
			if err != nil {
				return err
			}
			return a.writeList(w, r, list)
		}))
		mux.HandleFunc("POST "+base+"/{id}/deliveries/{delivery}/replay", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			org, err := a.dirScope(r, p, true)
			if err != nil {
				return err
			}
			if err := a.Directory.Replay(r.Context(), p.Realm.ID, org, r.PathValue("id"), r.PathValue("delivery"), p.AuditRef()); err != nil {
				return err
			}
			w.WriteHeader(http.StatusAccepted)
			return nil
		}))
	}
	// Attribute authority declarations (USR-022): which attributes and
	// operations are locally editable, externally managed or written back.
	mux.HandleFunc("GET /api/v1/realms/{realm}/me/attribute-authority", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		out, err := a.Directory.Declare(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("GET /api/v1/realms/{realm}/users/{user}/attribute-authority", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		out, err := a.Directory.Declare(r.Context(), p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
