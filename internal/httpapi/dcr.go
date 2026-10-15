package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
)

// dcrRoutes serves dynamic client registration (APP-016, APP-017, ADV-003):
// the RFC 7591 registration endpoint, the RFC 7592 management endpoint
// authenticated by the registration access token, and the administrative
// side (initial access tokens and approvals).
func (a *App) dcrRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /realms/{realm}/oauth/register", a.public(a.dcrRegister))
	mux.HandleFunc("GET /realms/{realm}/oauth/register/{client_id}", a.public(a.dcrManage))
	mux.HandleFunc("PUT /realms/{realm}/oauth/register/{client_id}", a.public(a.dcrManage))
	mux.HandleFunc("DELETE /realms/{realm}/oauth/register/{client_id}", a.public(a.dcrManage))

	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("POST "+R+"/client-registration-tokens", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		var in application.InitialTokenInput
		if err := decode(r, &in); err != nil {
			return err
		}
		plain, t, err := a.Apps.CreateInitialAccessToken(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"initial_access_token": plain, "token": t, "notice": "The initial access token is shown only once."})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/client-registration-tokens", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		list, err := a.Apps.ListInitialAccessTokens(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("DELETE "+R+"/client-registration-tokens/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.credentials"); err != nil {
			return err
		}
		if err := a.Apps.RevokeInitialAccessToken(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/client-registrations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		state := r.URL.Query().Get("approval_state")
		if state != "" && state != "pending" && state != "approved" && state != "rejected" {
			return problem.ErrValidation.WithField("approval_state", "pending, approved or rejected")
		}
		list, err := a.Apps.ListRegistrations(r.Context(), p.Realm.ID, state)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	decide := func(approve bool) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
				return err
			}
			if err := decode(r, &struct{}{}); err != nil {
				return err
			}
			if err := a.Apps.DecideRegistration(r.Context(), p.Realm.ID, r.PathValue("client"), approve, p.AuditRef()); err != nil {
				return err
			}
			w.WriteHeader(http.StatusNoContent)
			return nil
		})
	}
	mux.HandleFunc("POST "+R+"/client-registrations/{client}/approve", decide(true))
	mux.HandleFunc("POST "+R+"/client-registrations/{client}/reject", decide(false))
}

func writeRegistrationError(w http.ResponseWriter, err error) bool {
	var re *application.RegistrationError
	if !errors.As(err, &re) {
		return false
	}
	if re.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	writeJSON(w, re.Status, re)
	return true
}

// readMetadata reads registration metadata: JSON, bounded, unknown members
// ignored as RFC 7591 requires.
func readMetadata(r *http.Request) (*application.RegistrationMetadata, error) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, &application.RegistrationError{Status: 400, Code: "invalid_client_metadata", Description: "application/json is required"}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(body) > 64<<10 {
		return nil, &application.RegistrationError{Status: 400, Code: "invalid_client_metadata", Description: "metadata too large"}
	}
	var m application.RegistrationMetadata
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, &application.RegistrationError{Status: 400, Code: "invalid_client_metadata", Description: "metadata is not a JSON object of the expected types"}
	}
	return &m, nil
}

func (a *App) dcrRegister(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	pol := rlm.Policy.ClientRegistration
	if !pol.Enabled || !rlm.Active() {
		return problem.ErrNotFound
	}
	info := reqctx.From(r.Context())
	// Registration budgets fail closed (SEC-006): per network and per realm.
	d, err := a.Limiter.Hit(r.Context(), ratelimit.Budget{Key: "dcr-ip:" + info.ClientIP, Limit: 20, Window: time.Hour},
		ratelimit.Budget{Key: "dcr-realm:" + rlm.ID, Limit: 500, Window: time.Hour})
	if err != nil {
		return problem.ErrUnavailable
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	m, err := readMetadata(r)
	if writeRegistrationError(w, err) {
		return nil
	}
	iat := bearer(r)
	reg, err := a.Apps.Register(r.Context(), rlm.ID, *m, application.RegistrationContext{Open: pol.Open, RequireApproval: pol.RequireApproval || (pol.Open && iat == ""),
		OpenScopes: pol.RegistrationScopes(), InitialToken: iat, ClientIP: info.ClientIP})
	if writeRegistrationError(w, err) {
		return nil
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, registrationView(rlm, reg))
	return nil
}

func (a *App) dcrManage(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if !rlm.Policy.ClientRegistration.Enabled {
		return problem.ErrNotFound
	}
	c, err := a.Apps.AuthenticateRegistration(r.Context(), rlm.ID, r.PathValue("client_id"), bearer(r))
	if writeRegistrationError(w, err) {
		return nil
	}
	if err != nil {
		return err
	}
	switch r.Method {
	case http.MethodGet:
		reg, err := a.Apps.RegistrationOf(r.Context(), nil, c)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, registrationView(rlm, reg))
	case http.MethodPut:
		m, err := readMetadata(r)
		if writeRegistrationError(w, err) {
			return nil
		}
		reg, err := a.Apps.UpdateRegistration(r.Context(), rlm.ID, c, *m, m.RotateSecret)
		if writeRegistrationError(w, err) {
			return nil
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, registrationView(rlm, reg))
	case http.MethodDelete:
		if err := a.Apps.DeleteRegistration(r.Context(), rlm.ID, c); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
	}
	return nil
}

// registrationView is the RFC 7591 client information response.
func registrationView(rlm *realm.Realm, reg *application.Registration) map[string]any {
	c := reg.Client
	out := map[string]any{
		"client_id": c.ClientID, "client_id_issued_at": c.CreatedAt.Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": c.GrantTypes, "response_types": []string{"code"},
		"token_endpoint_auth_method": c.AuthMethod, "scope": strings.Join(reg.GrantedScopes, " "),
		"registration_client_uri":  rlm.Issuer + "/oauth/register/" + c.ClientID,
		"proudauth_approval_state": reg.ApprovalState, "proudauth_client_state": c.State,
	}
	if len(c.PostLogoutRedirects) > 0 {
		out["post_logout_redirect_uris"] = c.PostLogoutRedirects
	}
	if len(c.Contacts) > 0 {
		out["contacts"] = c.Contacts
	}
	if reg.SoftwareID != "" {
		out["software_id"] = reg.SoftwareID
	}
	if reg.SoftwareVersion != "" {
		out["software_version"] = reg.SoftwareVersion
	}
	if reg.Secret != "" {
		out["client_secret"] = reg.Secret
		out["client_secret_expires_at"] = 0
	}
	if reg.AccessToken != "" {
		out["registration_access_token"] = reg.AccessToken
	}
	opts, _ := json.Marshal(c.ProtocolOptions)
	var extra map[string]any
	_ = json.Unmarshal(opts, &extra)
	for k, v := range extra {
		out[k] = v
	}
	return out
}
