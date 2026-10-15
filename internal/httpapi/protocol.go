package httpapi

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/oauth"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/restore"
)

const (
	cookieTransaction      = "pa_tx"
	cookieSession          = "pa_sid"
	cookieRememberedDevice = "pa_rd"
)

func (a *App) cookie(name, value, path string, maxAge time.Duration) *http.Cookie {
	same := http.SameSiteLaxMode
	switch strings.ToLower(a.D.Cfg.Sessions.CookieSameSite) {
	case "strict":
		same = http.SameSiteStrictMode
	case "none":
		same = http.SameSiteNoneMode
	}
	c := &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: !a.D.Cfg.Sessions.CookieInsecureDev, SameSite: same}
	if maxAge > 0 {
		c.MaxAge = int(maxAge.Seconds())
	} else if maxAge < 0 {
		c.MaxAge = -1
	}
	return c
}

func realmPath(rlm *realm.Realm) string { return "/realms/" + rlm.Name + "/" }

func txPath(rlm *realm.Realm) string { return "/api/v1/realms/" + rlm.Name + "/auth/" }

// txCookiePath scopes a browser transaction cookie to that transaction's own
// API paths, so concurrent transactions in several tabs each keep their own
// continuation instead of overwriting one shared cookie (AUT-016).
func txCookiePath(rlm *realm.Realm, txID string) string {
	return "/api/v1/realms/" + rlm.Name + "/auth/transactions/" + txID
}

// ---------- CORS (SEC-003) ----------

type originCache struct {
	mu   sync.Mutex
	data map[string]originEntry
}

type originEntry struct {
	origins []string
	at      time.Time
}

var origins = &originCache{data: map[string]originEntry{}}

func (a *App) allowedOrigins(r *http.Request, realmID string) []string {
	origins.mu.Lock()
	e, ok := origins.data[realmID]
	origins.mu.Unlock()
	if ok && time.Since(e.at) < 5*time.Second {
		return e.origins
	}
	rows, err := a.D.DB.Pool.Query(r.Context(), `SELECT DISTINCT co.origin FROM client_origins co JOIN clients c ON c.id=co.client_ref
		WHERE co.realm_id=$1 AND c.state='active'`, realmID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var o string
		_ = rows.Scan(&o)
		out = append(out, o)
	}
	origins.mu.Lock()
	origins.data[realmID] = originEntry{origins: out, at: time.Now()}
	origins.mu.Unlock()
	return out
}

// applyCORS reflects only registered origins; wildcard origins are never combined
// with credentials.
func (a *App) applyCORS(w http.ResponseWriter, r *http.Request, rlm *realm.Realm, credentials bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	if !slices.Contains(a.allowedOrigins(r, rlm.ID), strings.ToLower(origin)) {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	if credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	h.Set("Access-Control-Expose-Headers", "ETag, X-Request-Id, Retry-After, WWW-Authenticate")
	return true
}

func (a *App) preflight(w http.ResponseWriter, r *http.Request) {
	rlm, err := a.Realms.ByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if a.applyCORS(w, r, rlm, strings.Contains(r.URL.Path, "/auth/")) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, Idempotency-Key, X-CSRF-Token, X-Transaction-Token, DPoP, X-Request-Id")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// originAllowed checks the Origin of cookie-authenticated state changes (SEC-002).
func (a *App) originAllowed(r *http.Request, rlm *realm.Realm) bool {
	origin := strings.ToLower(r.Header.Get("Origin"))
	if origin == "" {
		// Browsers always send Origin on cross-site POSTs; a missing Origin with a cookie is refused.
		return false
	}
	publicPort := ""
	if u, err := url.Parse(a.D.Cfg.Server.PublicOrigin); err == nil {
		if strings.ToLower(u.Scheme+"://"+u.Host) == origin {
			return true
		}
		publicPort = u.Port()
	}
	// A verified custom domain of this realm is its own origin (DEP-014), on
	// the default port or the public origin's: another port on that host is
	// another origin, possibly another service.
	if u, err := url.Parse(origin); err == nil && u.Scheme == "https" && (u.Port() == "" || u.Port() == "443" || u.Port() == publicPort) &&
		a.Realms.RealmForHost(r.Context(), u.Hostname()) == rlm.ID {
		return true
	}
	return slices.Contains(a.allowedOrigins(r, rlm.ID), origin)
}

// ---------- protocol endpoints ----------

func (a *App) writeOAuthError(w http.ResponseWriter, e *oauth.Error) {
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token", error="invalid_client"`)
	}
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(e.RetryAfter.Seconds())+1))
	}
	status := e.Status
	if status == 0 {
		status = 400
	}
	writeJSON(w, status, e)
}

func (a *App) clientAuthFrom(r *http.Request) application.ClientAuthInput {
	in := application.ClientAuthInput{FormClientID: r.PostForm.Get("client_id"), FormSecret: r.PostForm.Get("client_secret"),
		AssertionType: r.PostForm.Get("client_assertion_type"), Assertion: r.PostForm.Get("client_assertion")}
	in.Certificate, in.Intermediates = a.peerCertificate(r)
	if id, sec, ok := r.BasicAuth(); ok {
		in.HasBasic = true
		in.BasicID, _ = url.QueryUnescape(id)
		in.BasicSecret, _ = url.QueryUnescape(sec)
	}
	return in
}

func parseForm(r *http.Request) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return problem.ErrUnsupportedMedia.WithDetail("Content-Type must be application/x-www-form-urlencoded")
	}
	if err := r.ParseForm(); err != nil {
		return problem.ErrBadRequest
	}
	return nil
}

func (a *App) discovery(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	f := a.Features
	// Dynamic client registration is advertised only where the realm offers it.
	f.Registration = rlm.Policy.ClientRegistration.Enabled
	m, err := a.OAuth.Discovery(r.Context(), rlm, f)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, m)
	return nil
}

func (a *App) jwks(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	b, err := a.KeyMgr.JWKS(r.Context(), rlm.ID)
	if err != nil {
		return problem.ErrUnavailable
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
	return nil
}

func (a *App) authorize(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	var values url.Values
	if r.Method == http.MethodPost {
		if err := parseForm(r); err != nil {
			return err
		}
		values = r.PostForm
	} else {
		values = r.URL.Query()
	}
	req, oe := oauth.ParseAuthorize(values)
	if oe != nil {
		writeJSON(w, http.StatusBadRequest, oe)
		return nil
	}
	sessionCookie := ""
	if c, err := r.Cookie(cookieSession); err == nil {
		sessionCookie = c.Value
	}
	info := reqctx.From(r.Context())
	res := a.OAuth.Authorize(r.Context(), rlm, req, sessionCookie, info.ClientIP, info.UserAgent)
	if res.LocalError != nil {
		writeJSON(w, res.LocalError.Status, res.LocalError)
		return nil
	}
	if res.TransactionCookie != "" {
		http.SetCookie(w, a.cookie(cookieTransaction, res.TransactionCookie, txCookiePath(rlm, res.TransactionID), a.D.Cfg.Tokens.TransactionTTL))
	}
	if res.SessionCookie != "" {
		http.SetCookie(w, a.cookie(cookieSession, res.SessionCookie, realmPath(rlm), a.D.Cfg.Sessions.AbsoluteTimeout))
	}
	a.setBrowserState(w, rlm, res.SessionID, a.D.Cfg.Sessions.AbsoluteTimeout)
	http.Redirect(w, r, res.Redirect, http.StatusFound)
	return nil
}

func (a *App) tokenEndpoint(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	a.applyCORS(w, r, rlm, false)
	if len(r.Header.Values("DPoP")) > 1 {
		writeJSON(w, http.StatusBadRequest, &oauth.Error{Code: "invalid_dpop_proof", Description: "one DPoP proof header is required", Status: http.StatusBadRequest})
		return nil
	}
	if err := parseForm(r); err != nil {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest("form encoding required"))
		return nil
	}
	if len(r.URL.RawQuery) > 0 {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest("parameters must be sent in the request body"))
		return nil
	}
	endpoint := rlm.Issuer + "/oauth/token"
	res, oe := a.OAuth.Token(r.Context(), rlm, oauth.TokenRequest{Form: r.PostForm, Auth: a.clientAuthFrom(r), Endpoint: endpoint,
		DPoPProof: r.Header.Get("DPoP"), HTTPMethod: r.Method, HTTPURL: endpoint, ClientIP: reqctx.From(r.Context()).ClientIP})
	grant := r.PostForm.Get("grant_type")
	if len(grant) > 64 {
		grant = "invalid"
	}
	if oe != nil {
		a.Metrics.Tokens.Inc(grant, oe.Code)
		a.writeOAuthError(w, oe)
		return nil
	}
	a.Metrics.Tokens.Inc(grant, "success")
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (a *App) introspect(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if err := parseForm(r); err != nil {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest("form encoding required"))
		return nil
	}
	raw := r.PostForm.Get("token")
	endpoint := rlm.Issuer + "/oauth/introspect"
	if strings.HasPrefix(raw, "pa_key_") || strings.HasPrefix(raw, "pa_pat_") {
		caller, err := a.Apps.Authenticate(r.Context(), rlm.ID, rlm.Issuer, endpoint, a.clientAuthFrom(r))
		if err != nil || caller.Public() {
			a.writeOAuthError(w, oauth.ErrInvalidClient)
			return nil
		}
		allowed, err := a.Apps.IntrospectableResources(r.Context(), caller.Ref)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, a.Machine.Introspect(r.Context(), rlm.ID, rlm.Issuer, raw, allowed))
		return nil
	}
	res, oe := a.OAuth.Introspect(r.Context(), rlm, a.clientAuthFrom(r), endpoint, raw)
	if oe != nil {
		a.writeOAuthError(w, oe)
		return nil
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (a *App) revoke(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	a.applyCORS(w, r, rlm, false)
	if err := parseForm(r); err != nil {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest("form encoding required"))
		return nil
	}
	if oe := a.OAuth.Revoke(r.Context(), rlm, a.clientAuthFrom(r), rlm.Issuer+"/oauth/revoke", r.PostForm.Get("token"), r.PostForm.Get("token_type_hint")); oe != nil {
		a.writeOAuthError(w, oe)
		return nil
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (a *App) userinfo(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	a.applyCORS(w, r, rlm, false)
	raw := bearer(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	body, ctype, cnf, err := a.OAuth.UserInfoResponse(r.Context(), rlm, raw)
	if err == nil {
		// A sender-constrained token is usable only by its holder (TOK-019).
		if cerr := a.checkSenderConstraint(r, rlm, raw, cnf); cerr != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}
	}
	if errors.Is(err, oauth.ErrNoEncryptionKey) {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest(err.Error()))
		return nil
	}
	if err != nil {
		var pe *problem.Error
		if errors.As(err, &pe) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}
		return err
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(body)
	return err
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	var v url.Values
	if r.Method == http.MethodPost {
		if err := parseForm(r); err != nil {
			return err
		}
		v = r.PostForm
	} else {
		v = r.URL.Query()
	}
	cookie := ""
	if c, err := r.Cookie(cookieSession); err == nil {
		cookie = c.Value
	}
	// GET without an ID token hint is not allowed to end the browser session silently:
	// the client must POST (confirmation behavior, SES-016).
	if r.Method == http.MethodGet && v.Get("id_token_hint") == "" {
		cookie = ""
	}
	res, err := a.OAuth.Logout(r.Context(), rlm, oauth.LogoutRequest{IDTokenHint: v.Get("id_token_hint"), ClientID: v.Get("client_id"),
		PostLogoutRedirectURI: v.Get("post_logout_redirect_uri"), State: v.Get("state"), SessionCookie: cookie,
		UpstreamLogout: v.Get("upstream_logout") == "true"})
	if err != nil {
		return err
	}
	if res.ClearCookie && cookie != "" {
		http.SetCookie(w, a.cookie(cookieSession, "", realmPath(rlm), -1))
		a.clearBrowserState(w, rlm)
	}
	if len(res.FrontChannel) > 0 {
		// Front-channel logout (SES-018): a caller that asks for JSON (an
		// external login UI) renders the frames itself; a browser gets a page
		// that loads them and then continues. Neither confirms delivery.
		if wantsJSON(r) {
			out := map[string]any{"session_ended": res.SessionEnded, "upstream_logout": res.Upstream, "frontchannel_logout_uris": res.FrontChannel}
			if res.Redirect != "" {
				out["redirect_to"] = res.Redirect
			}
			writeJSON(w, http.StatusOK, out)
			return nil
		}
		return writeFrontChannelPage(w, res.FrontChannel, res.Redirect)
	}
	if res.Redirect != "" {
		http.Redirect(w, r, res.Redirect, http.StatusFound)
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_ended": res.SessionEnded, "upstream_logout": res.Upstream})
	return nil
}

// wantsJSON reports a caller that prefers JSON over HTML.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

var frontChannelPage = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Signed out</title>
{{if .Next}}<meta http-equiv="refresh" content="2;url={{.Next}}">{{end}}
</head><body>
<p>You have been signed out.</p>
{{range .Frames}}<iframe src="{{.}}" title="Sign-out notification" width="0" height="0" hidden></iframe>
{{end}}{{if .Next}}<p><a href="{{.Next}}">Continue</a></p>{{end}}
</body></html>
`))

// writeFrontChannelPage renders the front-channel logout page. Its content
// policy allows framing only the listed clients' origins and runs no script;
// the browser continues by a timed refresh.
func writeFrontChannelPage(w http.ResponseWriter, frames []string, next string) error {
	origins := []string{}
	for _, f := range frames {
		if u, err := url.Parse(f); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			if o := u.Scheme + "://" + u.Host; !slices.Contains(origins, o) {
				origins = append(origins, o)
			}
		}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-src "+strings.Join(origins, " ")+"; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.WriteHeader(http.StatusOK)
	return frontChannelPage.Execute(w, map[string]any{"Frames": frames, "Next": next})
}

// logoutUpstreamReturn is where a federated provider sends the browser after
// its own logout (FED-013).
func (a *App) logoutUpstreamReturn(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	dest, err := a.OAuth.UpstreamLogoutReturn(r.Context(), rlm, r.URL.Query().Get("state"))
	if err != nil {
		return err
	}
	if dest != "" {
		http.Redirect(w, r, dest, http.StatusFound)
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_ended": true, "upstream_logout": map[string]any{"status": "returned"}})
	return nil
}

func (a *App) deviceAuthorization(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if err := parseForm(r); err != nil {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest("form encoding required"))
		return nil
	}
	res, oe := a.OAuth.DeviceAuthorize(r.Context(), rlm, a.clientAuthFrom(r), rlm.Issuer+"/oauth/device_authorization", r.PostForm)
	if oe != nil {
		a.writeOAuthError(w, oe)
		return nil
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (a *App) par(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if err := parseForm(r); err != nil {
		writeJSON(w, http.StatusBadRequest, oauth.ErrInvalidRequest("form encoding required"))
		return nil
	}
	c, err := a.Apps.Authenticate(r.Context(), rlm.ID, rlm.Issuer, rlm.Issuer+"/oauth/par", a.clientAuthFrom(r))
	if err != nil {
		a.writeOAuthError(w, oauth.ErrInvalidClient)
		return nil
	}
	res, oe := a.OAuth.PushAuthorizationRequest(r.Context(), rlm, c, r.PostForm)
	if oe != nil {
		a.writeOAuthError(w, oe)
		return nil
	}
	writeJSON(w, http.StatusCreated, res)
	return nil
}

func (a *App) rfc8414(w http.ResponseWriter, r *http.Request) {
	rlm, err := a.Realms.ByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		a.fail(w, r, problem.ErrNotFound)
		return
	}
	if err := a.discovery(w, r, rlm); err != nil {
		a.fail(w, r, err)
	}
}

// health endpoints (DEP-009): liveness never touches dependencies; readiness checks
// the database, schema version, the restore marker (TEST-060) and signing-key
// availability.
func (a *App) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if a.Draining.Load() {
		// Shutting down (OPS-012): report not-ready so load balancers stop
		// routing here while in-flight requests finish.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	if err := a.D.DB.Ping(ctx); err != nil {
		a.Metrics.DBUp.Set(0)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	a.Metrics.DBUp.Set(1)
	if ok, err := a.D.DB.SchemaCurrent(ctx); err != nil || !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	// A restored database marked by `identity-cli restore-begin` serves no
	// traffic until `identity-cli restore-reconcile` has re-applied what the
	// backup predates and cleared the marker (TEST-060, OPS-014).
	if m, err := restore.Pending(ctx, a.D.DB.Pool); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	} else if m != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "reason": "restore_pending"})
		return
	}
	realms, err := a.Realms.List(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	for _, rl := range realms {
		if rl.Active() {
			if _, err := a.KeyMgr.Active(ctx, rl.ID); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded"})
				return
			}
		}
	}
	// Token validity depends on agreeing clocks: an instance whose clock drifts
	// from the database beyond the configured bound leaves rotation without being
	// restarted (DEP-009, OPS-015).
	if maxSkew := a.D.Cfg.Observability.MaxClockSkew; maxSkew > 0 {
		var dbNow time.Time
		if err := a.D.DB.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err == nil {
			if skew := time.Since(dbNow); skew > maxSkew || skew < -maxSkew {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "reason": "clock_skew"})
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

var _ = json.Marshal
