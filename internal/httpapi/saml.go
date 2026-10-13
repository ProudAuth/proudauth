package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/proudbase/proudauth/internal/federation"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/reqctx"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/saml"
	samlidp "github.com/proudbase/proudauth/internal/saml/idp"
)

// cookieSAMLBinding binds a SAML sign-in to the browser that started it: the
// assertion is released only to a browser holding the secret.
const cookieSAMLBinding = "pa_saml"

// samlRoutes registers the SAML 2.0 endpoints (APP-018, FED-014, §26.2):
// the identity provider protocol endpoints under the issuer, the broker's
// service provider endpoints per connection, and their administration.
func (a *App) samlRoutes(mux *http.ServeMux) {
	I := "/realms/{realm}/saml"
	// Identity provider (trust class: public metadata / public protocol initiation).
	mux.HandleFunc("GET "+I+"/metadata", a.public(a.samlMetadata))
	mux.HandleFunc("GET "+I+"/sso", a.public(a.samlSSO))
	mux.HandleFunc("POST "+I+"/sso", a.public(a.samlSSO))
	mux.HandleFunc("GET "+I+"/sso/continue", a.public(a.samlContinue))
	mux.HandleFunc("GET "+I+"/idp-initiated", a.public(a.samlIdPInitiated))
	mux.HandleFunc("GET "+I+"/slo", a.public(a.samlSLO))
	mux.HandleFunc("POST "+I+"/slo", a.public(a.samlSLO))
	// Broker (service provider side of SAML connections).
	mux.HandleFunc("GET "+I+"/sp/{connection}", a.public(a.samlSPMetadata))
	mux.HandleFunc("POST "+I+"/acs/{connection}", a.public(a.samlACS))

	R := "/api/v1/realms/{realm}/saml"
	idpOnly := func() error {
		if a.SAML == nil {
			return problem.ErrFeatureDisabled
		}
		return nil
	}
	brokerOnly := func() error {
		if a.Federation == nil || a.Federation.SAML == nil {
			return problem.ErrFeatureDisabled
		}
		return nil
	}
	// SAML applications (registered service providers).
	mux.HandleFunc("GET "+R+"/applications", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := idpOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		items, err := a.SAML.List(r.Context(), p.Realm)
		if err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("POST "+R+"/applications", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := idpOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		var in samlidp.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.SAML.Create(r.Context(), p.Realm, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/applications/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := idpOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		out, err := a.SAML.Get(r.Context(), nil, p.Realm, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/applications/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := idpOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in samlidp.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.SAML.Update(r.Context(), p.Realm, r.PathValue("id"), ver, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/applications/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := idpOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		if err := a.SAML.Delete(r.Context(), p.Realm, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// SAML connections (upstream identity providers).
	mux.HandleFunc("GET "+R+"/connections", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := brokerOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.read"); err != nil {
			return err
		}
		items, err := a.Federation.SAML.List(r.Context(), p.Realm.ID, p.Realm.Name)
		if err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("POST "+R+"/connections", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := brokerOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		var in federation.SAMLInput
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.Federation.SAML.Create(r.Context(), p.Realm.ID, p.Realm.Name, in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/connections/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := brokerOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.read"); err != nil {
			return err
		}
		out, err := a.Federation.SAML.Get(r.Context(), p.Realm.ID, p.Realm.Name, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/connections/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := brokerOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in federation.SAMLInput
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := a.Federation.SAML.Update(r.Context(), p.Realm.ID, p.Realm.Name, r.PathValue("id"), ver, in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/connections/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := brokerOnly(); err != nil {
			return err
		}
		if err := a.requirePerm(r, p, "realm.identity_providers.write"); err != nil {
			return err
		}
		if err := a.Federation.SAML.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Realm SAML signing keys: list, publish the next key, activate it
	// (controlled rollover, SAML-002).
	mux.HandleFunc("GET "+R+"/signing-keys", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.SAMLKeys == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.keys.read"); err != nil {
			return err
		}
		items, err := a.SAMLKeys.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/signing-keys", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.SAMLKeys == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.keys.rotate"); err != nil {
			return err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		out, err := a.SAMLKeys.Prepare(r.Context(), p.Realm.ID, p.AuditRef(), b.Reason)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/signing-keys/{id}/activate", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if a.SAMLKeys == nil {
			return problem.ErrFeatureDisabled
		}
		if err := a.requirePerm(r, p, "realm.keys.rotate"); err != nil {
			return err
		}
		var b struct {
			Force  bool   `json:"force"`
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Force && len(strings.TrimSpace(b.Reason)) < 10 {
			return problem.ErrValidation.WithField("reason", "a forced activation needs a reason of at least 10 characters")
		}
		cfg := a.D.Cfg.SAML
		if err := a.SAMLKeys.Activate(r.Context(), p.Realm.ID, r.PathValue("id"), cfg.KeyPrepublish, cfg.RetiredKeyPublication, b.Force,
			p.AuditRef(), b.Reason); err != nil {
			return err
		}
		items, err := a.SAMLKeys.List(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return nil
	}))
}

// samlMessage reads a protocol message from its binding: the query of a GET
// (HTTP-Redirect) or the form body of a POST (HTTP-POST). Repeated
// parameters are refused.
func (a *App) samlMessage(w http.ResponseWriter, r *http.Request, param string) (samlidp.Message, error) {
	if r.Method == http.MethodGet {
		return samlidp.Message{Binding: saml.BindingRedirect, RawQuery: r.URL.RawQuery}, nil
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return samlidp.Message{}, problem.ErrUnsupportedMedia.WithDetail("Content-Type must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(base64.StdEncoding.EncodedLen(a.D.Cfg.SAML.MaxMessageBytes))+8<<10)
	if err := r.ParseForm(); err != nil {
		return samlidp.Message{}, problem.ErrTooLarge
	}
	if len(r.PostForm[param]) != 1 || len(r.PostForm["RelayState"]) > 1 {
		return samlidp.Message{}, problem.ErrBadRequest.WithDetail(param + " is required once")
	}
	return samlidp.Message{Binding: saml.BindingPOST, Encoded: r.PostForm.Get(param), RelayState: r.PostForm.Get("RelayState")}, nil
}

func (a *App) samlBinding(r *http.Request) string {
	if c, err := r.Cookie(cookieSAMLBinding); err == nil {
		return c.Value
	}
	return ""
}

func (a *App) setSAMLBinding(w http.ResponseWriter, rlm *realm.Realm, value string) {
	// Lax whatever sessions.cookie_same_site says: the browser comes back to
	// the continuation endpoint by a top-level GET from a login interface
	// that may be on another site. The cookie only lets that browser
	// receive the assertion it asked for.
	c := a.cookie(cookieSAMLBinding, value, realmPath(rlm)+"saml/", a.D.Cfg.Tokens.TransactionTTL)
	c.SameSite = http.SameSiteLaxMode
	http.SetCookie(w, c)
}

func (a *App) samlMetadata(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	b, err := a.SAML.Metadata(r.Context(), rlm)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, err = w.Write(b)
	return err
}

// samlSSO receives an AuthnRequest. A request over HTTP-Redirect continues
// at once; one over HTTP-POST arrives by a cross-site form post, which
// carries no SameSite=Lax cookies, so the browser is first sent on to the
// continuation endpoint by a GET, which carries the SSO session cookie.
func (a *App) samlSSO(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	m, err := a.samlMessage(w, r, "SAMLRequest")
	if err != nil {
		return err
	}
	binding := a.samlBinding(r)
	rec, d, err := a.SAML.Receive(r.Context(), rlm, m, binding)
	if err != nil {
		return err
	}
	if d != nil {
		return a.samlDeliver(w, r, rlm, d)
	}
	if rec.BindingCookie != "" {
		a.setSAMLBinding(w, rlm, rec.BindingCookie)
		binding = rec.BindingCookie
	}
	if r.Method == http.MethodPost {
		http.Redirect(w, r, rlm.Issuer+"/saml/sso/continue?"+url.Values{"request": {rec.Ref}}.Encode(), http.StatusSeeOther)
		return nil
	}
	return a.samlStart(w, r, rlm, rec.Ref, binding)
}

func (a *App) samlStart(w http.ResponseWriter, r *http.Request, rlm *realm.Realm, ref, binding string) error {
	in := samlidp.StartInput{Ref: ref, BindingCookie: binding}
	if c, err := r.Cookie(cookieSession); err == nil {
		in.SessionCookie = c.Value
	}
	info := reqctx.From(r.Context())
	in.ClientIP, in.UserAgent = info.ClientIP, info.UserAgent
	d, err := a.SAML.Start(r.Context(), rlm, in)
	if err != nil {
		return err
	}
	return a.samlDeliver(w, r, rlm, d)
}

// samlContinue starts a recorded request (?request=) or completes it with
// the authentication transaction's response (?code&state or ?error&state).
func (a *App) samlContinue(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	q := r.URL.Query()
	binding := a.samlBinding(r)
	if ref := q.Get("request"); ref != "" {
		return a.samlStart(w, r, rlm, ref, binding)
	}
	d, err := a.SAML.Continue(r.Context(), rlm, q, binding)
	if err != nil {
		return err
	}
	return a.samlDeliver(w, r, rlm, d)
}

// samlIdPInitiated starts an unsolicited sign-in to ?sp=<entity ID or
// application ID>, when that application allows it (SAML-007).
func (a *App) samlIdPInitiated(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	binding := a.samlBinding(r)
	rec, err := a.SAML.IdPInitiated(r.Context(), rlm, r.URL.Query().Get("sp"), binding)
	if err != nil {
		return err
	}
	if rec.BindingCookie != "" {
		a.setSAMLBinding(w, rlm, rec.BindingCookie)
		binding = rec.BindingCookie
	}
	return a.samlStart(w, r, rlm, rec.Ref, binding)
}

func (a *App) samlSLO(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	m, err := a.samlMessage(w, r, "SAMLRequest")
	if err != nil {
		if r.Method == http.MethodPost && r.PostForm.Get("SAMLResponse") != "" {
			return problem.ErrBadRequest.WithDetail("logout responses are not expected: this identity provider does not send logout requests")
		}
		return err
	}
	cookie := ""
	if c, err := r.Cookie(cookieSession); err == nil {
		cookie = c.Value
	}
	d, err := a.SAML.Logout(r.Context(), rlm, m, cookie)
	if err != nil {
		return err
	}
	return a.samlDeliver(w, r, rlm, d)
}

// samlDeliver sends the browser on: an auto-submitting form (HTTP-POST
// binding) whose only script is allowed by a per-response nonce, or a
// redirect (HTTP-Redirect binding, login interface).
func (a *App) samlDeliver(w http.ResponseWriter, r *http.Request, rlm *realm.Realm, d *samlidp.Delivery) error {
	if d.TransactionCookie != "" {
		http.SetCookie(w, a.cookie(cookieTransaction, d.TransactionCookie, txCookiePath(rlm, d.TransactionID), a.D.Cfg.Tokens.TransactionTTL))
	}
	maxAge := a.D.Cfg.Sessions.AbsoluteTimeout
	if d.SessionTransient {
		maxAge = 0 // browser-session cookie (SES-020)
	}
	if d.SessionCookie != "" {
		http.SetCookie(w, a.cookie(cookieSession, d.SessionCookie, realmPath(rlm), maxAge))
	}
	if d.SessionID != "" {
		// As for OAuth completions: OIDC session management sees the session.
		a.setBrowserState(w, rlm, d.SessionID, maxAge)
	}
	if d.ClearSession {
		http.SetCookie(w, a.cookie(cookieSession, "", realmPath(rlm), -1))
		a.clearBrowserState(w, rlm)
	}
	if d.Form != nil {
		nonce := base64.RawStdEncoding.EncodeToString(secret.Random(18))
		d.Form.Nonce = nonce
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")
		w.WriteHeader(http.StatusOK)
		return d.Form.Render(w)
	}
	http.Redirect(w, r, d.RedirectURL, http.StatusFound)
	return nil
}

func (a *App) samlSPMetadata(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.Federation == nil || a.Federation.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	b, err := a.Federation.SAML.SPMetadata(r.Context(), rlm.ID, rlm.Name, r.PathValue("connection"))
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, err = w.Write(b)
	return err
}

// samlACS receives an upstream SAML response (HTTP-POST binding) and
// reports the outcome like an OIDC callback: to the login interface with
// the transaction ID, or as JSON in headless deployments.
func (a *App) samlACS(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if a.Federation == nil || a.Federation.SAML == nil {
		return problem.ErrFeatureDisabled
	}
	m, err := a.samlMessage(w, r, "SAMLResponse")
	if err != nil {
		return err
	}
	res, err := a.Auth.SAMLCallback(r.Context(), rlm.ID, rlm.Name, r.PathValue("connection"), m.Encoded, m.RelayState)
	if err != nil {
		return err
	}
	ui := rlm.Policy.Interaction.LoginUIURL
	if ui == "" {
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
		// The confirmation code travels in the fragment (SEC-007).
		u.Fragment = "federation_link_code=" + url.QueryEscape(res.LinkCode)
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}
