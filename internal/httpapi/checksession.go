package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
)

// cookieBrowserState holds the OP browser state that the check-session
// iframe reads (OIDC-014). It is the only cookie page scripts can read; it
// carries a keyed digest of the session ID, never the session secret.
const cookieBrowserState = "pa_opbs"

// setBrowserState writes the browser-state cookie for a session when the
// realm turned session management on. It is readable by the iframe in a
// third-party context, so it is SameSite=None (on secure deployments).
func (a *App) setBrowserState(w http.ResponseWriter, rlm *realm.Realm, sessionID string, maxAge time.Duration) {
	if !rlm.Policy.Sessions.CheckSessionIframe || sessionID == "" {
		return
	}
	c := a.cookie(cookieBrowserState, session.BrowserState(a.D.Keys, sessionID), realmPath(rlm), maxAge)
	c.HttpOnly = false
	if c.Secure {
		c.SameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, c)
}

// clearBrowserState removes the cookie at logout, which the iframe then
// reports as a change.
func (a *App) clearBrowserState(w http.ResponseWriter, rlm *realm.Realm) {
	c := a.cookie(cookieBrowserState, "", realmPath(rlm), -1)
	c.HttpOnly = false
	if c.Secure {
		c.SameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, c)
}

// checkSessionScript is the check_session_iframe logic of OpenID Connect
// Session Management 1.0. It answers "client_id session_state" messages
// with changed, unchanged or error, only to an origin registered for that
// client (a redirect URI or allowed origin), and recomputes the state with
// the message's own origin so a value never matches for another origin.
const checkSessionScript = `(function () {
  var cache = {};
  function opbs() { var m = document.cookie.match(/(?:^|;\s*)pa_opbs=([^;]*)/); return m ? m[1] : ""; }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
  function allowed(clientID, origin) {
    var k = clientID + " " + origin;
    if (!cache[k]) {
      cache[k] = fetch(location.pathname + "/origin?client_id=" + encodeURIComponent(clientID) + "&origin=" + encodeURIComponent(origin), { credentials: "omit" })
        .then(function (r) { return r.ok ? r.json() : { allowed: false }; })
        .then(function (j) { return j.allowed === true; }, function () { return false; });
    }
    return cache[k];
  }
  window.addEventListener("message", function (e) {
    var src = e.source, origin = e.origin;
    if (!src || origin === "null" || typeof e.data !== "string") { return; }
    var parts = e.data.split(" "), dot = parts.length === 2 ? parts[1].lastIndexOf(".") : -1;
    if (dot < 1) { src.postMessage("error", origin); return; }
    var clientID = parts[0], state = parts[1], salt = state.slice(dot + 1);
    allowed(clientID, origin).then(function (ok) {
      if (!ok) { src.postMessage("error", origin); return; }
      var data = new TextEncoder().encode(clientID + " " + origin + " " + opbs() + " " + salt);
      return crypto.subtle.digest("SHA-256", data).then(function (d) {
        src.postMessage(hex(d) + "." + salt === state ? "unchanged" : "changed", origin);
      });
    }).catch(function () { src.postMessage("error", origin); });
  });
})();`

var checkSessionPage = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Session check</title></head><body><script>" +
	checkSessionScript + "</script></body></html>"

var checkSessionCSP = func() string {
	sum := sha256.Sum256([]byte(checkSessionScript))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; connect-src 'self'; frame-ancestors *; base-uri 'none'; form-action 'none'"
}()

// checkSessionIframe serves the iframe RPs embed (OIDC-014). It exists only
// when the realm turned session management on.
func (a *App) checkSessionIframe(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if !rlm.Policy.Sessions.CheckSessionIframe {
		return problem.ErrNotFound
	}
	h := w.Header()
	h.Del("X-Frame-Options")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", checkSessionCSP)
	h.Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(checkSessionPage))
	return err
}

// checkSessionOrigin tells the iframe whether an origin is registered for
// a client: one of its allowed origins or the origin of a redirect URI.
func (a *App) checkSessionOrigin(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	if !rlm.Policy.Sessions.CheckSessionIframe {
		return problem.ErrNotFound
	}
	d, err := a.Limiter.Hit(r.Context(), ratelimit.Budget{Key: "check-session-origin:" + ratelimit.NetworkKey(reqctx.From(r.Context()).ClientIP), Limit: 300, Window: time.Minute})
	if err != nil {
		return problem.ErrUnavailable
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	q := r.URL.Query()
	origin := strings.ToLower(q.Get("origin"))
	ok := false
	if c, err := a.Apps.ClientByClientID(r.Context(), a.D.DB.Pool, rlm.ID, q.Get("client_id")); err == nil && c.State == "active" && origin != "" {
		ok = slices.ContainsFunc(c.Origins, func(o string) bool { return strings.ToLower(o) == origin }) ||
			slices.ContainsFunc(c.RedirectURIs, func(u string) bool { return strings.ToLower(session.Origin(u)) == origin })
	}
	w.Header().Set("Cache-Control", "private, max-age=60")
	writeJSON(w, http.StatusOK, map[string]any{"allowed": ok})
	return nil
}
