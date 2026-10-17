package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/maintenance"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/platform/tracing"
	"github.com/proudauth/proudauth/internal/token"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

// clientIP derives the client address, trusting forwarded headers only from
// configured proxies (SEC-001). The right-most untrusted hop is the client.
// fromTrustedProxy reports whether the request's peer is a configured
// trusted proxy.
func (a *App) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	return err == nil && a.trusted(remote)
}

func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	xff := r.Header.Values("X-Forwarded-For")
	if !a.trusted(remote) {
		if len(xff) > 0 {
			a.warnUntrustedForwarder(remote)
		}
		return remote.String()
	}
	hops := []string{}
	for _, v := range xff {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				hops = append(hops, p)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(hops[i])
		if err != nil {
			return remote.String()
		}
		if !a.trusted(ip) {
			return ip.String()
		}
	}
	return remote.String()
}

// warnUntrustedForwarder logs, at most once a minute, that a peer outside
// server.trusted_proxies sent X-Forwarded-For, which is ignored. In
// production that is almost always a reverse proxy the configuration does
// not name: every client behind it then shares the proxy's address for the
// per-address budgets and in audit and session records, so one busy or
// abusive client locks everyone out (ABU-001, SEC-001). Development stacks
// have no proxy and stay quiet.
func (a *App) warnUntrustedForwarder(peer netip.Addr) {
	if a.D.Cfg.Mode != configuration.ModeProduction {
		return
	}
	now := a.D.Now().Unix()
	last := a.forwardWarnedAt.Load()
	if now-last < 60 || !a.forwardWarnedAt.CompareAndSwap(last, now) {
		return
	}
	a.D.Log.Warn("X-Forwarded-For from a peer outside server.trusted_proxies is ignored: every client behind it shares one address for rate limits and audit records; set PROUDAUTH_TRUSTED_PROXIES (server.trusted_proxies) to the proxy's address or network",
		"component", "http", "peer_network", reqctx.NetworkContext(peer.String(), false))
}

func (a *App) trusted(ip netip.Addr) bool {
	for _, p := range a.D.Cfg.Server.TrustedProxies {
		p = strings.TrimSpace(p)
		if pfx, err := netip.ParsePrefix(p); err == nil && pfx.Contains(ip) {
			return true
		}
		if single, err := netip.ParseAddr(p); err == nil && single == ip {
			return true
		}
	}
	return false
}

func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-Id")
		if len(reqID) > 64 || strings.ContainsFunc(reqID, func(c rune) bool { return c < 0x21 || c > 0x7e }) || reqID == "" {
			reqID = ids.New(ids.Request)
		}
		info := reqctx.Info{RequestID: reqID, ClientIP: a.clientIP(r), UserAgent: r.UserAgent(), Origin: r.Header.Get("Origin")}
		// W3C trace context (OPS-003): continue a valid incoming trace, otherwise
		// start one; sampling applies only to new traces. Trace IDs are random and
		// carry no request data.
		// The sampled flag of an incoming trace is honored only from a trusted
		// proxy: any client could otherwise force span export for every
		// request it sends.
		parentSpan := ""
		localSample := func() bool {
			return a.D.Cfg.Observability.TraceSampling > 0 && mrand.Float64() < a.D.Cfg.Observability.TraceSampling
		}
		if tid, sampled, ok := reqctx.ParseTraceparent(r.Header.Get("Traceparent")); ok {
			info.TraceID, info.Sampled = tid, sampled && a.fromTrustedProxy(r)
			if !info.Sampled {
				info.Sampled = localSample()
			}
			if parts := strings.Split(r.Header.Get("Traceparent"), "-"); len(parts) == 4 {
				parentSpan = parts[2]
			}
		} else {
			info.TraceID = hex.EncodeToString(secret.Random(16))
			info.Sampled = localSample()
		}
		info.SpanID = hex.EncodeToString(secret.Random(8))
		ctx, cancel := context.WithTimeout(reqctx.With(r.Context(), info), requestTimeout)
		defer cancel()
		r = r.WithContext(ctx)
		h := w.Header()
		h.Set("X-Request-Id", reqID)
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		if a.D.Cfg.Mode == "production" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		sw := &statusWriter{ResponseWriter: w}
		route := a.routeOf(r)
		defer func() {
			if rec := recover(); rec != nil {
				a.D.Log.Error("panic", "request_id", reqID, "route", route, "panic", rec)
				problem.Write(sw, reqID, problem.ErrInternal)
			}
			status := sw.status
			if status == 0 {
				status = 200
			}
			elapsed := time.Since(start)
			a.Metrics.HTTPRequests.Inc(route, strconv.Itoa(status/100)+"xx")
			a.Metrics.HTTPLatency.Observe(elapsed.Seconds(), route)
			// Paths and query strings are not logged in full: they can carry codes.
			outcome := "success"
			switch {
			case status >= 500:
				outcome = "server_error"
			case status == 429:
				outcome = "rate_limited"
			case status >= 400:
				outcome = "client_error"
			}
			a.D.Log.Info("http", "component", "http", "event_code", "http.request", "outcome", outcome, "request_id", reqID,
				"trace_id", info.TraceID, "span_id", info.SpanID, "method", r.Method, "route", route, "status", status,
				"duration_ms", elapsed.Milliseconds(), "network", reqctx.NetworkContext(info.ClientIP, false))
			if info.Sampled {
				// Sampled spans carry only route-level attributes; no headers,
				// bodies, identifiers or tokens are captured.
				a.D.Log.Info("span", "trace_id", info.TraceID, "span_id", info.SpanID, "name", r.Method+" "+route, "status", status,
					"start", start.UTC().Format(time.RFC3339Nano), "duration_ms", elapsed.Milliseconds())
				st := tracing.StatusOK
				if status >= 500 {
					st = tracing.StatusError
				}
				tracing.Export(tracing.Span{TraceID: info.TraceID, SpanID: info.SpanID, ParentID: parentSpan, Name: r.Method + " " + route,
					Kind: tracing.KindServer, Start: start, End: start.Add(elapsed), Status: st,
					Attributes: map[string]any{"http.request.method": r.Method, "http.route": route, "http.response.status_code": status}})
			}
		}()
		// Load shedding with a reserved pool for administration and health (NFR-002).
		// The reserve serves health probes and credentialed administration only:
		// anonymous floods against administrative paths compete in the ordinary
		// pool (they would be rejected by authentication anyway).
		pool := a.inflight
		if isHealthPath(r.URL.Path) || (isAdminPath(r.URL.Path) && r.Header.Get("Authorization") != "") {
			pool = a.adminSlots
		}
		select {
		case pool <- struct{}{}:
			defer func() { <-pool }()
		default:
			a.Metrics.Shed.Inc(route)
			problem.Write(sw, reqID, problem.ErrUnavailable.WithDetail("server is shedding load").WithRetryAfter(2*time.Second))
			return
		}
		if r.ContentLength > a.D.Cfg.Limits.MaxBodyBytes {
			problem.Write(sw, reqID, problem.ErrTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(sw, r.Body, a.D.Cfg.Limits.MaxBodyBytes)
		if a.Maintenance != nil {
			if st := a.Maintenance.Current(ctx, a.D.DB.Pool); !maintenance.Allowed(st.Mode, r.Method, r.URL.Path) {
				pe := problem.ErrMaintenance.WithRetryAfter(time.Duration(st.RetryAfterSeconds) * time.Second)
				if st.Message != "" {
					pe = pe.WithDetail(st.Message)
				}
				problem.Write(sw, reqID, pe)
				return
			}
		}
		next.ServeHTTP(sw, r)
	})
}

// routeOf is the bounded label of a request's route for metrics, spans, logs
// and audit metadata (OPS-002): the registered pattern it matches (for
// example /api/v1/realms/{realm}/users/{user}), so no path segment a caller
// chose, such as a name, an email address or an alias, reaches a label;
// requests that match no route share one label.
func (a *App) routeOf(r *http.Request) string {
	pat := r.Pattern
	if pat == "" && a.mux != nil {
		_, pat = a.mux.Handler(r)
		if pat == "" {
			return "unmatched"
		}
	}
	if pat == "" {
		return routeLabel(r.URL.Path)
	}
	if i := strings.IndexByte(pat, ' '); i >= 0 {
		pat = pat[i+1:]
	}
	return pat
}

// routeLabel maps a path to a bounded label: identifiers and realm names are
// replaced by placeholders.
func routeLabel(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if ids.Valid(s) || (i > 0 && (parts[i-1] == "realms")) {
			parts[i] = "{id}"
		}
	}
	l := strings.Join(parts, "/")
	if len(l) > 120 {
		l = canonical.Truncate(l, 120)
	}
	return l
}

// ---------- JSON helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// decode reads a strict JSON body: application/json, bounded size, no duplicate
// members, bounded depth and no unknown fields (SEC-004).
// maxJSONDepth is set from limits.max_json_depth when the app is built.
var maxJSONDepth atomicInt

type atomicInt struct{ v atomic.Int64 }

func (a *atomicInt) Load() int   { return int(a.v.Load()) }
func (a *atomicInt) Store(n int) { a.v.Store(int64(n)) }

func decode(r *http.Request, v any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return problem.ErrTooLarge
		}
		return problem.ErrBadRequest
	}
	if len(bytes.TrimSpace(body)) == 0 {
		// An empty body means "no fields" and needs no media type.
		body = []byte("{}")
	} else if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return problem.ErrUnsupportedMedia
	}
	if err := token.RejectDuplicateKeysDepth(body, maxJSONDepth.Load()); err != nil {
		return problem.ErrBadRequest.WithDetail("malformed JSON or duplicate members")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return problem.ErrBadRequest.WithDetail("invalid JSON body: " + sanitizeJSONErr(err))
	}
	return nil
}

func sanitizeJSONErr(err error) string {
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return strings.ReplaceAll(msg, "\"", "'")
}

// ---------- cursors ----------

// encodeCursor returns an opaque cursor bound to realm and route, so a cursor from
// one tenant or listing cannot be replayed elsewhere (TEST-009).
func (a *App) encodeCursor(scope, last string) string {
	if last == "" {
		return ""
	}
	mac := hmac.New(sha256.New, a.D.Keys.DeriveBytes(keys.PurposeLookup, "cursor"))
	mac.Write([]byte(scope + "|" + last))
	return base64.RawURLEncoding.EncodeToString([]byte(last)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
}

func (a *App) decodeCursor(scope, c string) (string, error) {
	if c == "" {
		return "", nil
	}
	parts := strings.Split(c, ".")
	if len(parts) != 2 {
		return "", problem.ErrBadRequest.WithDetail("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", problem.ErrBadRequest.WithDetail("invalid cursor")
	}
	if a.encodeCursor(scope, string(raw)) != c {
		return "", problem.ErrBadRequest.WithDetail("invalid cursor")
	}
	return string(raw), nil
}

func (a *App) pageLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return a.D.Cfg.Limits.DefaultPageSize
	}
	if n > a.D.Cfg.Limits.MaxPageSize {
		return a.D.Cfg.Limits.MaxPageSize
	}
	return n
}

// ifMatch extracts the expected version from If-Match ("v12" or W/"v12").
func ifMatch(r *http.Request, required bool) (int64, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		if required {
			return 0, problem.ErrPreconditionNeeded
		}
		return 0, nil
	}
	v = strings.TrimPrefix(strings.Trim(strings.TrimPrefix(v, "W/"), `"`), "v")
	n, err := strconv.ParseInt(v, 10, 64)
	// Versions start at 1. Zero would read as "no precondition" to the update
	// queries (version=$n OR $n=0), so it never matches.
	if err != nil || n < 1 {
		return 0, problem.ErrPrecondition
	}
	return n, nil
}

// contentTag is an entity tag derived from a resource's state, for settings
// that carry no version column (API-010).
func contentTag(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return `W/"c` + hex.EncodeToString(sum[:8]) + `"`
}

// checkContentTag rejects an update whose If-Match no longer matches the
// current state; without If-Match the update proceeds.
func checkContentTag(r *http.Request, current any) error {
	if v := r.Header.Get("If-Match"); v != "" && v != contentTag(current) {
		return problem.ErrPrecondition
	}
	return nil
}

func setETag(w http.ResponseWriter, version int64) {
	w.Header().Set("ETag", `W/"v`+strconv.FormatInt(version, 10)+`"`)
}

var _ = observability.Timer
