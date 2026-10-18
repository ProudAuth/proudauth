package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/registry"
)

// registryRoutes serve the container-registry token bridge (ADV-010).
func (a *App) registryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /realms/{realm}/registry/token", a.public(a.registryToken))
	G := "/api/v1/realms/{realm}/registry-services"
	mux.HandleFunc("GET "+G, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.read"); err != nil {
			return err
		}
		list, err := a.Registry.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+G, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		var in registry.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		s, err := a.Registry.Create(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, s.Version)
		writeJSON(w, http.StatusCreated, s)
		return nil
	}))
	mux.HandleFunc("GET "+G+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.read"); err != nil {
			return err
		}
		s, err := a.Registry.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, s.Version)
		writeJSON(w, http.StatusOK, s)
		return nil
	}))
	mux.HandleFunc("PUT "+G+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		var in registry.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		s, err := a.Registry.Update(r.Context(), p.Realm.ID, r.PathValue("id"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, s.Version)
		writeJSON(w, http.StatusOK, s)
		return nil
	}))
	mux.HandleFunc("DELETE "+G+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.resources.write"); err != nil {
			return err
		}
		if err := a.Registry.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}

// registryError answers in the Distribution error format.
func registryError(w http.ResponseWriter, status int, code, message, issuer string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+issuer+`"`)
	}
	problem.SetRetryAfter(w.Header(), status, 0) // every 429 and 503
	writeJSON(w, status, map[string]any{"errors": []map[string]string{{"code": code, "message": message}}})
}

// registryToken implements the Distribution token endpoint. Credentials
// arrive as HTTP Basic (docker login): the password is a personal access
// token or API key minted for the registry's resource, or a machine
// client's secret with the client ID as user name. Without credentials the
// caller is anonymous and can only receive anonymous pulls.
func (a *App) registryToken(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	ip := reqctx.From(r.Context()).ClientIP
	failures := ratelimit.Budget{Key: "registry-fail:" + ip, Limit: 20, Window: 15 * time.Minute}
	if ok, err := a.Limiter.Peek(r.Context(), failures); err != nil || !ok {
		registryError(w, http.StatusTooManyRequests, "TOOMANYREQUESTS", "too many failed sign-ins; try again later", rlm.Issuer)
		return nil
	}
	if d, err := a.Limiter.Hit(r.Context(), ratelimit.Budget{Key: "registry-ip:" + ip, Limit: 600, Window: time.Minute}); err != nil || !d.Allowed {
		registryError(w, http.StatusTooManyRequests, "TOOMANYREQUESTS", "too many requests; try again later", rlm.Issuer)
		return nil
	}
	q := r.URL.Query()
	svc, err := a.Registry.ByService(r.Context(), rlm.ID, q.Get("service"))
	if err != nil {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "unknown registry service", rlm.Issuer)
		return nil
	}
	var requested []registry.Access
	for _, raw := range q["scope"] {
		for _, s := range strings.Fields(raw) {
			if acc, ok := registry.ParseScope(s); ok && len(requested) < 50 {
				requested = append(requested, acc)
			}
		}
	}
	p := registry.Principal{}
	if user, pass, ok := r.BasicAuth(); ok {
		var authErr bool
		p, authErr = a.registryPrincipal(r, rlm, svc, user, pass)
		if authErr {
			_, _ = a.Limiter.Hit(r.Context(), failures)
			_, _ = a.D.Audit.Record(r.Context(), a.D.DB.Pool, audit.Event{Type: "registry.token.denied", RealmID: rlm.ID, Outcome: audit.Failure,
				Actor: audit.Ref{Type: "anonymous", ID: "anonymous"}, Target: &audit.Ref{Type: "registry_service", ID: svc.ID}, Category: "token",
				ReasonCode: "invalid_credentials"})
			registryError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", rlm.Issuer)
			return nil
		}
	}
	access := a.Registry.Grant(r.Context(), rlm.ID, svc, p, requested)
	tok, _, err := a.Registry.Issue(r.Context(), rlm.ID, rlm.Issuer, svc, p, access)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "access_token": tok, "expires_in": svc.TokenTTLSeconds,
		"issued_at": a.D.Now().UTC().Format(time.RFC3339)})
	return nil
}

// registryPrincipal authenticates Basic credentials for a registry; the
// second result is true when they are invalid.
func (a *App) registryPrincipal(r *http.Request, rlm *realm.Realm, svc *registry.Service, user, pass string) (registry.Principal, bool) {
	ctx := r.Context()
	if strings.HasPrefix(pass, secret.PrefixPAT) || strings.HasPrefix(pass, secret.PrefixAPIKey) {
		info := a.Machine.Introspect(ctx, rlm.ID, rlm.Issuer, pass, map[string]bool{svc.ResourceID: true})
		if info["active"] != true {
			return registry.Principal{}, true
		}
		p := registry.Principal{SubjectType: info["subject_type"].(string), SubjectID: info["sub"].(string), Scopes: strings.Fields(info["scope"].(string))}
		if org, ok := info["org_id"].(string); ok {
			p.OrgID = org
		}
		return p, false
	}
	c, err := a.Apps.Authenticate(ctx, rlm.ID, rlm.Issuer, rlm.Issuer+"/registry/token", application.ClientAuthInput{HasBasic: true, BasicID: user, BasicSecret: pass})
	if err != nil || c.ServicePrincipalID == "" {
		return registry.Principal{}, true
	}
	var state string
	if err := a.D.DB.Pool.QueryRow(ctx, `SELECT state FROM service_principals WHERE realm_id=$1 AND id=$2`, rlm.ID, c.ServicePrincipalID).Scan(&state); err != nil || state != "active" {
		return registry.Principal{}, true
	}
	grants, err := a.Apps.ResourceGrants(ctx, nil, c.Ref)
	if err != nil {
		return registry.Principal{}, true
	}
	for _, g := range grants {
		if g.ResourceID == svc.ResourceID && slices.Contains(g.SubjectTypes, "service_principal") {
			return registry.Principal{SubjectType: "service_principal", SubjectID: c.ServicePrincipalID, Scopes: g.AllowedScopes}, false
		}
	}
	// A client without a grant to the registry authenticates but gets no
	// actions beyond anonymous ones.
	return registry.Principal{SubjectType: "service_principal", SubjectID: c.ServicePrincipalID}, false
}
