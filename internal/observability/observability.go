// Package observability provides structured logging with redaction applied before
// serialization (OPS-001) and a dependency-free metrics registry exposed in the
// Prometheus text format (OPS-002). Metric labels are bounded: no user IDs,
// emails or raw tenant names are ever used as labels.
package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var sensitiveKey = regexp.MustCompile(`(?i)(password|secret|token|authorization|cookie|otp|code_verifier|^code$|seed|private|assertion|pepper|api_key)`)
var bearerValue = regexp.MustCompile(`(pa_[a-z]+_[A-Za-z0-9_\-]{8,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*)`)

// NewLogger builds the process logger with redaction.
func NewLogger(w io.Writer, level, format string) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	// The wrapped handler accepts every level; standardHandler applies the
	// configured level and opens lower levels only inside a debug window.
	opts := &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: Redact}
	if format == "text" {
		return slog.New(&standardHandler{next: slog.NewTextHandler(w, opts), min: lvl})
	}
	return slog.New(&standardHandler{next: slog.NewJSONHandler(w, opts), min: lvl})
}

// Debug windows (SEC-015): debug logging below the configured level is
// enabled only for a bounded time, optionally for one component, and never
// bypasses redaction (records still pass through Redact before serialization).
var (
	debugUntil atomic.Int64 // unix nanoseconds; 0 = closed
	debugScope atomic.Pointer[string]
)

// SetDebugWindow opens a debug window until the given time for one component
// ("" for all); a zero time closes it.
func SetDebugWindow(until time.Time, component string) {
	if until.IsZero() {
		debugUntil.Store(0)
		return
	}
	debugScope.Store(&component)
	debugUntil.Store(until.UnixNano())
}

// DebugWindow reports the open window, if any.
func DebugWindow() (time.Time, string, bool) {
	u := debugUntil.Load()
	if u == 0 || time.Now().UnixNano() >= u {
		return time.Time{}, "", false
	}
	scope := ""
	if p := debugScope.Load(); p != nil {
		scope = *p
	}
	return time.Unix(0, u), scope, true
}

func debugAllows(component string) bool {
	_, scope, open := DebugWindow()
	return open && (scope == "" || scope == component)
}

// standardHandler guarantees the machine-readable fields of OPS-001 on every
// record: component (default "server") and event_code (default: the message).
// Redaction still happens in the wrapped handler, before serialization.
type standardHandler struct {
	next      slog.Handler
	min       slog.Level
	component string
}

func (h *standardHandler) Enabled(ctx context.Context, l slog.Level) bool {
	if l >= h.min {
		return h.next.Enabled(ctx, l)
	}
	_, _, open := DebugWindow()
	return open
}

func (h *standardHandler) Handle(ctx context.Context, r slog.Record) error {
	component, hasCode := h.component, false
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "component":
			component = a.Value.String()
		case "event_code":
			hasCode = true
		}
		return true
	})
	if r.Level < h.min && !debugAllows(firstNonEmpty(component, "server")) {
		return nil
	}
	if component == "" {
		r.AddAttrs(slog.String("component", "server"))
	}
	if !hasCode {
		r.AddAttrs(slog.String("event_code", r.Message))
	}
	return h.next.Handle(ctx, r)
}

func (h *standardHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	comp := h.component
	for _, a := range attrs {
		if a.Key == "component" {
			comp = a.Value.String()
		}
	}
	return &standardHandler{next: h.next.WithAttrs(attrs), min: h.min, component: comp}
}

func (h *standardHandler) WithGroup(name string) slog.Handler {
	return &standardHandler{next: h.next.WithGroup(name), min: h.min, component: h.component}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Redact replaces secret-bearing attributes before they are written.
func Redact(_ []string, a slog.Attr) slog.Attr {
	if sensitiveKey.MatchString(a.Key) && a.Key != "token_kind" && a.Key != "grant_type" {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindString {
		s := a.Value.String()
		if bearerValue.MatchString(s) {
			return slog.String(a.Key, bearerValue.ReplaceAllString(s, "[REDACTED]"))
		}
	}
	return a
}

// ---------- metrics ----------

type labelSet string

// Series caps (OPS-002): a counter keeps at most MaxCounterSeries label sets
// and a histogram MaxHistogramSeries. An update that would open a series past
// the cap is dropped; proudauth_metrics_series_dropped_total{metric} counts
// it, and the first one of each metric logs a warning.
const (
	MaxCounterSeries   = 1000
	MaxHistogramSeries = 500
	// SeriesDroppedMetric is the counter of dropped updates, one series per
	// capped metric of the registry, so it is bounded by the metrics
	// registered and never drops anything itself.
	SeriesDroppedMetric = "proudauth_metrics_series_dropped_total"
)

// capGuard is what a capped metric (counter or histogram) shares with its
// registry: the count of its dropped updates and whether the cap was logged.
type capGuard struct {
	reg     *Registry
	dropped atomic.Uint64
	warned  atomic.Bool
}

// drop counts an update dropped at the cap of metric name and logs the
// first one.
func (g *capGuard) drop(name string, max int) {
	g.dropped.Add(1)
	if g.warned.CompareAndSwap(false, true) {
		g.reg.logger().Warn("metric series cap reached; updates with new label sets are dropped", "component", "observability",
			"event_code", "metrics.series_dropped", "metric", name, "max_series", max)
	}
}

// Counter is a monotonically increasing counter with bounded labels.
type Counter struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	values     map[labelSet]*atomic.Uint64
	guard      *capGuard
}

// Inc increments with label values (must match label names).
func (c *Counter) Inc(vals ...string) { c.Add(1, vals...) }

// Add adds n. A label set that would be the counter's series number
// MaxCounterSeries+1 is dropped and counted (SeriesDroppedMetric).
func (c *Counter) Add(n uint64, vals ...string) {
	key := labelSet(strings.Join(vals, "\x00"))
	c.mu.Lock()
	v, ok := c.values[key]
	if !ok {
		if len(c.values) >= MaxCounterSeries { // cardinality guard
			c.mu.Unlock()
			c.guard.drop(c.name, MaxCounterSeries)
			return
		}
		v = &atomic.Uint64{}
		c.values[key] = v
	}
	c.mu.Unlock()
	v.Add(n)
}

// Gauge is a settable value.
type Gauge struct {
	name, help string
	v          atomic.Int64
	fn         func() float64
}

// Set sets the gauge.
func (g *Gauge) Set(v int64) { g.v.Store(v) }

// GaugeVec is a gauge with one label whose values are fixed when it is
// registered, so its series are bounded whatever happens at run time; fn
// computes each series at scrape time.
type GaugeVec struct {
	name, help, label string
	values            []string
	fn                func(value string) float64
}

// Histogram tracks latency distributions.
type Histogram struct {
	name, help string
	labels     []string
	buckets    []float64
	mu         sync.Mutex
	series     map[labelSet]*hseries
	guard      *capGuard
}

type hseries struct {
	counts []uint64
	sum    float64
	count  uint64
}

// Observe records a value with labels. A label set that would be the
// histogram's series number MaxHistogramSeries+1 is dropped and counted
// (SeriesDroppedMetric).
func (h *Histogram) Observe(v float64, vals ...string) {
	key := labelSet(strings.Join(vals, "\x00"))
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.series[key]
	if !ok {
		if len(h.series) >= MaxHistogramSeries {
			h.guard.drop(h.name, MaxHistogramSeries)
			return
		}
		s = &hseries{counts: make([]uint64, len(h.buckets))}
		h.series[key] = s
	}
	for i, b := range h.buckets {
		if v <= b {
			s.counts[i]++
		}
	}
	s.sum += v
	s.count++
}

// Registry holds metrics.
type Registry struct {
	mu         sync.Mutex
	counters   []*Counter
	gauges     []*Gauge
	gaugeVecs  []*GaugeVec
	histograms []*Histogram
	// guards are the dropped-update counts of the capped metrics, by name.
	guards map[string]*capGuard
	log    atomic.Pointer[slog.Logger]
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// SetLogger sets the logger of the registry's warnings (a series cap
// reached); without one they go to slog.Default().
func (r *Registry) SetLogger(l *slog.Logger) { r.log.Store(l) }

func (r *Registry) logger() *slog.Logger {
	if l := r.log.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// guard returns the dropped-update count of the capped metric name; metrics
// registered twice under one name share it. The caller holds r.mu.
func (r *Registry) guard(name string) *capGuard {
	if r.guards == nil {
		r.guards = map[string]*capGuard{}
	}
	g, ok := r.guards[name]
	if !ok {
		g = &capGuard{reg: r}
		r.guards[name] = g
	}
	return g
}

// Counter registers a counter.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	c := &Counter{name: name, help: help, labels: labels, values: map[labelSet]*atomic.Uint64{}}
	r.mu.Lock()
	c.guard = r.guard(name)
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// Gauge registers a gauge; fn (optional) computes the value at scrape time.
func (r *Registry) Gauge(name, help string, fn func() float64) *Gauge {
	g := &Gauge{name: name, help: help, fn: fn}
	r.mu.Lock()
	r.gauges = append(r.gauges, g)
	r.mu.Unlock()
	return g
}

// GaugeVec registers a gauge with one label: one series per value of values
// (copied and sorted), computed by fn at scrape time.
func (r *Registry) GaugeVec(name, help, label string, values []string, fn func(value string) float64) *GaugeVec {
	vals := append([]string(nil), values...)
	sort.Strings(vals)
	g := &GaugeVec{name: name, help: help, label: label, values: vals, fn: fn}
	r.mu.Lock()
	r.gaugeVecs = append(r.gaugeVecs, g)
	r.mu.Unlock()
	return g
}

// Histogram registers a histogram with default latency buckets (seconds).
func (r *Registry) Histogram(name, help string, labels ...string) *Histogram {
	h := &Histogram{name: name, help: help, labels: labels, series: map[labelSet]*hseries{},
		buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}}
	r.mu.Lock()
	h.guard = r.guard(name)
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
	return h
}

func fmtLabels(names []string, key labelSet, extra ...string) string {
	vals := []string{}
	if key != "" || len(names) > 0 {
		vals = strings.Split(string(key), "\x00")
	}
	parts := []string{}
	for i, n := range names {
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		parts = append(parts, fmt.Sprintf(`%s=%q`, n, v))
	}
	parts = append(parts, extra...)
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// WriteText writes the Prometheus text exposition format.
func (r *Registry) WriteText(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.counters {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
		c.mu.Lock()
		keys := make([]string, 0, len(c.values))
		for k := range c.values {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%s%s %d\n", c.name, fmtLabels(c.labels, labelSet(k)), c.values[labelSet(k)].Load())
		}
		c.mu.Unlock()
	}
	if len(r.guards) > 0 {
		// One series per capped metric, 0 until it drops an update, so an
		// alert on its increase sees the first drop.
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", SeriesDroppedMetric,
			"Metric updates dropped because they would have opened a series past the metric's cap (OPS-002)", SeriesDroppedMetric)
		names := make([]string, 0, len(r.guards))
		for n := range r.guards {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(w, "%s{metric=%q} %d\n", SeriesDroppedMetric, n, r.guards[n].dropped.Load())
		}
	}
	for _, g := range r.gauges {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
		v := float64(g.v.Load())
		if g.fn != nil {
			v = g.fn()
		}
		if math.IsNaN(v) {
			v = 0
		}
		fmt.Fprintf(w, "%s %g\n", g.name, v)
	}
	for _, g := range r.gaugeVecs {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
		for _, val := range g.values {
			v := g.fn(val)
			if math.IsNaN(v) || math.IsInf(v, 0) {
				v = 0
			}
			fmt.Fprintf(w, "%s{%s=%q} %g\n", g.name, g.label, val, v)
		}
	}
	for _, h := range r.histograms {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
		h.mu.Lock()
		for k, s := range h.series {
			for i, b := range h.buckets {
				fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, fmtLabels(h.labels, k, fmt.Sprintf(`le="%g"`, b)), s.counts[i])
			}
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, fmtLabels(h.labels, k, `le="+Inf"`), s.count)
			fmt.Fprintf(w, "%s_sum%s %g\n%s_count%s %d\n", h.name, fmtLabels(h.labels, k), s.sum, h.name, fmtLabels(h.labels, k), s.count)
		}
		h.mu.Unlock()
	}
}

// Metrics are the product's standard metrics.
type Metrics struct {
	Registry         *Registry
	HTTPRequests     *Counter
	HTTPLatency      *Histogram
	Logins           *Counter
	RateLimited      *Counter
	SecurityEvents   *Counter
	Shed             *Counter
	WorkerRuns       *Counter
	DeliveryOutcomes *Counter
	HookCalls        *Counter
	SecuritySignals  *Counter
	SigningFailures  *Counter
	RotationsRefused *Counter
	ActiveLeases     *Gauge
	AuditUnsealed    *Gauge
	AuditUnsealedAge *Gauge
	AuditIntegrity   *Gauge
	JobsFailed       *Counter
	DBUp             *Gauge
	QueueAge         *Gauge
	NotificationAge  *Gauge
	WebhookAge       *Gauge
	JobAge           *Gauge
	ClockSkew        *Gauge

	// tokens is proudauth_tokens_total; TokenResult maps its labels to
	// their fixed sets.
	tokens *Counter
}

// NewMetrics registers the standard metrics.
func NewMetrics() *Metrics {
	r := NewRegistry()
	return &Metrics{
		Registry:         r,
		HTTPRequests:     r.Counter("proudauth_http_requests_total", "HTTP requests by route and status class", "route", "status"),
		HTTPLatency:      r.Histogram("proudauth_http_request_duration_seconds", "HTTP latency by route", "route"),
		Logins:           r.Counter("proudauth_authentications_total", "Authentication outcomes", "outcome"),
		tokens:           r.Counter("proudauth_tokens_total", "Token endpoint outcomes", "grant_type", "outcome"),
		RateLimited:      r.Counter("proudauth_rate_limited_total", "Requests rejected by abuse budgets", "surface"),
		SecurityEvents:   r.Counter("proudauth_security_events_total", "Alertable security events", "type"),
		Shed:             r.Counter("proudauth_load_shed_total", "Requests shed under load", "pool"),
		WorkerRuns:       r.Counter("proudauth_worker_runs_total", "Worker task runs", "task", "outcome"),
		DeliveryOutcomes: r.Counter("proudauth_delivery_total", "Final outcomes of outbound deliveries by channel (webhook, notification, backchannel_logout) and outcome; updated by identity-worker", "channel", "outcome"),
		HookCalls:        r.Counter("proudauth_hook_calls_total", "Pre-action hook invocations", "kind", "outcome"),
		SecuritySignals:  r.Counter("proudauth_security_signals_total", "Alertable security signals from audit evidence (OPS-004)", "signal"),
		SigningFailures:  r.Counter("proudauth_signing_failures_total", "Token signing and key-provider failures (OPS-002)", "reason"),
		RotationsRefused: r.Counter("proudauth_key_rotations_refused_total", "Scheduled signing-key rotations refused because pinned resources or fapi2 clients do not accept the realm's algorithm (TOK-005, TOK-012); updated by identity-worker", "reason"),
		ActiveLeases:     r.Gauge("proudauth_worker_active_leases", "Unexpired worker leases across job, notification and webhook queues (OPS-002)", nil),
		AuditUnsealed:    r.Gauge("proudauth_audit_unsealed_events", "Audit events not yet sealed into a hash-linked batch (AUD-014)", nil),
		AuditUnsealedAge: r.Gauge("proudauth_audit_unsealed_oldest_seconds", "Age of the oldest unsealed audit event (AUD-014)", nil),
		AuditIntegrity:   r.Gauge("proudauth_audit_integrity_problems", "Problems found by the last scheduled audit chain verification (AUD-014)", nil),
		JobsFailed:       r.Counter("proudauth_jobs_failed_total", "Background jobs that exhausted their attempts and were dead-lettered, by type (AUD-014); updated by identity-worker", "type"),
		DBUp:             r.Gauge("proudauth_database_up", "1 when the authoritative database is reachable", nil),
		QueueAge:         r.Gauge("proudauth_outbox_oldest_pending_seconds", "Age of the oldest pending outbox event", nil),
		NotificationAge:  r.Gauge("proudauth_notification_oldest_due_seconds", "How long the oldest due notification has waited for delivery (OPS-002)", nil),
		WebhookAge:       r.Gauge("proudauth_webhook_oldest_due_seconds", "How long the oldest due webhook delivery has waited (OPS-002, EXT-005)", nil),
		JobAge:           r.Gauge("proudauth_jobs_oldest_queued_seconds", "How long the oldest runnable background job has waited (OPS-002)", nil),
		ClockSkew:        r.Gauge("proudauth_clock_skew_milliseconds", "Observed clock skew versus the database", nil),
	}
}

// tokenGrantTypes are the grant_type label values of proudauth_tokens_total
// besides "other": the grants the token endpoint implements.
var tokenGrantTypes = map[string]bool{
	"authorization_code": true, "refresh_token": true, "client_credentials": true,
	"urn:ietf:params:oauth:grant-type:device_code":    true,
	"urn:ietf:params:oauth:grant-type:token-exchange": true,
	"urn:ietf:params:oauth:grant-type:jwt-bearer":     true,
}

// tokenOutcomes are the outcome label values of proudauth_tokens_total
// besides "other": success and the OAuth error codes of the token endpoint
// (RFC 6749, 8628, 8693, 8707, 9449, OpenID Connect).
var tokenOutcomes = map[string]bool{
	"success": true, "invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true,
	"unsupported_grant_type": true, "invalid_scope": true, "invalid_target": true, "invalid_dpop_proof": true, "use_dpop_nonce": true,
	"invalid_client_metadata": true, "unmet_authentication_requirements": true, "authorization_pending": true, "slow_down": true,
	"expired_token": true, "access_denied": true, "temporarily_unavailable": true, "server_error": true,
}

// TokenGrantLabel is the grant_type label of a token request: its grant_type
// when the token endpoint implements it, otherwise "other" (a missing,
// unknown or refused one, whatever its length), so a request can never open
// a series of its choosing (OPS-002; the finding
// httpapi-surface/metrics-silent-drops).
func TokenGrantLabel(grant string) string {
	if tokenGrantTypes[grant] {
		return grant
	}
	return "other"
}

// TokenOutcomeLabel is the outcome label of a token response: "success", a
// known OAuth error code, or "other".
func TokenOutcomeLabel(outcome string) string {
	if tokenOutcomes[outcome] {
		return outcome
	}
	return "other"
}

// TokenResult counts a token endpoint response in proudauth_tokens_total,
// with labels from the fixed sets of TokenGrantLabel and TokenOutcomeLabel:
// at most 7 × 19 series.
func (m *Metrics) TokenResult(grant, outcome string) {
	m.tokens.Inc(TokenGrantLabel(grant), TokenOutcomeLabel(outcome))
}

// Timer measures a duration.
func Timer() func() float64 {
	start := time.Now()
	return func() float64 { return time.Since(start).Seconds() }
}

type ctxKey int

// WithLogger stores a logger in ctx.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey(1), l)
}
