package observability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// TestLogRedactionAndStandardFields covers OPS-001: secrets are redacted before
// serialization and every record carries component and event_code.
func TestLogRedactionAndStandardFields(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "info", "json")
	log.Info("token.issued", "client_secret", "s3cr3t-value", "note", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "outcome", "success")
	log.With("component", "worker").Warn("task failed", "event_code", "worker.task_failed", "refresh_token", "pa_rt_abcdef0123456789abcdef")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two records: %q", buf.String())
	}
	for _, l := range lines {
		if strings.Contains(l, "s3cr3t-value") || strings.Contains(l, "eyJzdWIiOiIxIn0") || strings.Contains(l, "pa_rt_abcdef") {
			t.Fatalf("secret serialized: %s", l)
		}
	}
	var first, second map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if first["component"] != "server" || first["event_code"] != "token.issued" || first["outcome"] != "success" {
		t.Fatalf("standard fields: %v", first)
	}
	if second["component"] != "worker" || second["event_code"] != "worker.task_failed" {
		t.Fatalf("explicit fields overridden: %v", second)
	}
}

// TestDebugWindow covers SEC-015: debug records are written only inside a
// time-limited window, only for its component, and still redacted.
func TestDebugWindow(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "info", "json")
	worker := log.With("component", "worker")
	log.Debug("closed window")
	if buf.Len() != 0 {
		t.Fatalf("debug record written without a window: %s", buf.String())
	}
	SetDebugWindow(time.Now().Add(time.Minute), "worker")
	defer SetDebugWindow(time.Time{}, "")
	log.Debug("other component")
	worker.Debug("scoped", "password", "hunter2")
	out := buf.String()
	if strings.Contains(out, "other component") || !strings.Contains(out, "scoped") {
		t.Fatalf("debug scope not applied: %s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("debug window bypassed redaction: %s", out)
	}
	buf.Reset()
	SetDebugWindow(time.Now().Add(-time.Second), "")
	worker.Debug("expired")
	if buf.Len() != 0 {
		t.Fatalf("expired window still logs: %s", buf.String())
	}
}

// TestGaugeVecFixedLabels covers OPS-002: a labelled gauge exposes exactly the
// label values it was registered with, sorted, each computed at scrape time,
// so a value the function was not registered for never opens a series; NaN
// and infinities are written as 0.
func TestGaugeVecFixedLabels(t *testing.T) {
	r := NewRegistry()
	asked := []string{}
	r.GaugeVec("proudauth_test_utilization", "Test utilization", "budget", []string{"pwd-realm", "pwd-client", "verify-realm"}, func(v string) float64 {
		asked = append(asked, v)
		switch v {
		case "pwd-client":
			return 0.25
		case "verify-realm":
			return math.NaN()
		}
		return 0
	})
	var buf bytes.Buffer
	r.WriteText(&buf)
	want := "# HELP proudauth_test_utilization Test utilization\n# TYPE proudauth_test_utilization gauge\n" +
		"proudauth_test_utilization{budget=\"pwd-client\"} 0.25\n" +
		"proudauth_test_utilization{budget=\"pwd-realm\"} 0\n" +
		"proudauth_test_utilization{budget=\"verify-realm\"} 0\n"
	if buf.String() != want {
		t.Fatalf("exposition:\n%s\nwant:\n%s", buf.String(), want)
	}
	if strings.Join(asked, ",") != "pwd-client,pwd-realm,verify-realm" {
		t.Fatalf("scrape asked for %v", asked)
	}
}

// TestTokenMetricFixedLabels covers OPS-002 and SEC-006 (the finding
// httpapi-surface/metrics-silent-drops): proudauth_tokens_total used the
// request's raw grant_type (up to 64 characters) as a label, before client
// authentication, so an unauthenticated caller could fill the counter's 1000
// series with junk and every later legitimate series was dropped until a
// restart. grant_type is now one of the implemented grants or "other", and
// outcome success, a known OAuth error code or "other", so junk opens no
// series and nothing is dropped.
func TestTokenMetricFixedLabels(t *testing.T) {
	m := NewMetrics()
	for i := range 5000 {
		m.TokenResult(fmt.Sprintf("junk-grant-%d", i), "invalid_client")
		m.TokenResult(strings.Repeat("g", 64)+fmt.Sprint(i), fmt.Sprintf("made_up_error_%d", i))
	}
	m.TokenResult("", "invalid_request")
	m.TokenResult("password", "unsupported_grant_type")
	m.TokenResult("authorization_code", "success")
	m.TokenResult("urn:ietf:params:oauth:grant-type:device_code", "authorization_pending")
	m.TokenResult("refresh_token", "slow_down")
	var buf bytes.Buffer
	m.Registry.WriteText(&buf)
	series := []string{}
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, "proudauth_tokens_total{") {
			series = append(series, l)
		}
	}
	want := []string{
		`proudauth_tokens_total{grant_type="authorization_code",outcome="success"} 1`,
		`proudauth_tokens_total{grant_type="other",outcome="invalid_client"} 5000`,
		`proudauth_tokens_total{grant_type="other",outcome="invalid_request"} 1`,
		`proudauth_tokens_total{grant_type="other",outcome="other"} 5000`,
		`proudauth_tokens_total{grant_type="other",outcome="unsupported_grant_type"} 1`,
		`proudauth_tokens_total{grant_type="refresh_token",outcome="slow_down"} 1`,
		`proudauth_tokens_total{grant_type="urn:ietf:params:oauth:grant-type:device_code",outcome="authorization_pending"} 1`,
	}
	if strings.Join(series, "\n") != strings.Join(want, "\n") {
		t.Fatalf("token series:\n%s\nwant:\n%s", strings.Join(series, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(buf.String(), SeriesDroppedMetric+`{metric="proudauth_tokens_total"} 0`) {
		t.Fatalf("token updates dropped:\n%s", buf.String())
	}
	for _, g := range []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code",
		"urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer"} {
		if TokenGrantLabel(g) != g {
			t.Errorf("grant %s labelled %s", g, TokenGrantLabel(g))
		}
	}
	for _, g := range []string{"", "password", "implicit", "AUTHORIZATION_CODE", "authorization_code ", "urn:ietf:params:oauth:grant-type:saml2-bearer"} {
		if TokenGrantLabel(g) != "other" {
			t.Errorf("grant %q labelled %s", g, TokenGrantLabel(g))
		}
	}
}

// TestDroppedSeriesCounted covers OPS-002 (the finding
// httpapi-surface/metrics-silent-drops): an update that would open a series
// past a counter's 1000 or a histogram's 500 was dropped without a trace.
// proudauth_metrics_series_dropped_total{metric} now counts every such
// update, with one series per capped metric of the registry (0 until it
// drops), and the first drop of each metric logs one warning naming the
// metric, never the label values.
func TestDroppedSeriesCounted(t *testing.T) {
	var logs bytes.Buffer
	r := NewRegistry()
	r.SetLogger(NewLogger(&logs, "info", "json"))
	c := r.Counter("proudauth_test_total", "Test", "key")
	h := r.Histogram("proudauth_test_seconds", "Test", "key")
	r.Counter("proudauth_quiet_total", "Quiet", "key").Inc("a")
	var buf bytes.Buffer
	r.WriteText(&buf)
	for _, line := range []string{
		"# TYPE " + SeriesDroppedMetric + " counter",
		SeriesDroppedMetric + `{metric="proudauth_quiet_total"} 0`,
		SeriesDroppedMetric + `{metric="proudauth_test_seconds"} 0`,
		SeriesDroppedMetric + `{metric="proudauth_test_total"} 0`,
	} {
		if !strings.Contains(buf.String(), line+"\n") {
			t.Fatalf("exposition lacks %q:\n%s", line, buf.String())
		}
	}

	for i := range MaxCounterSeries + 7 {
		c.Inc(fmt.Sprintf("secret-label-%d", i))
	}
	c.Inc("secret-label-0") // an existing series keeps counting
	for i := range MaxHistogramSeries + 3 {
		h.Observe(0.1, fmt.Sprintf("h%d", i))
	}
	buf.Reset()
	r.WriteText(&buf)
	out := buf.String()
	if n := strings.Count(out, "proudauth_test_total{"); n != MaxCounterSeries {
		t.Fatalf("%d counter series, want %d", n, MaxCounterSeries)
	}
	if n := strings.Count(out, "proudauth_test_seconds_count{"); n != MaxHistogramSeries {
		t.Fatalf("%d histogram series, want %d", n, MaxHistogramSeries)
	}
	for _, line := range []string{
		`proudauth_test_total{key="secret-label-0"} 2`,
		SeriesDroppedMetric + `{metric="proudauth_test_total"} 7`,
		SeriesDroppedMetric + `{metric="proudauth_test_seconds"} 3`,
		SeriesDroppedMetric + `{metric="proudauth_quiet_total"} 0`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Fatalf("exposition lacks %q", line)
		}
	}
	// The same dropped label set counts again: updates, not distinct sets.
	c.Inc(fmt.Sprintf("secret-label-%d", MaxCounterSeries+1))
	buf.Reset()
	r.WriteText(&buf)
	if !strings.Contains(buf.String(), SeriesDroppedMetric+`{metric="proudauth_test_total"} 8`+"\n") {
		t.Fatal("a repeated dropped update is not counted")
	}

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one warning per capped metric, got %d:\n%s", len(lines), logs.String())
	}
	seen := map[string]bool{}
	for _, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["level"] != "WARN" || rec["event_code"] != "metrics.series_dropped" || rec["component"] != "observability" {
			t.Fatalf("warning: %s", l)
		}
		seen[rec["metric"].(string)] = true
		if strings.Contains(l, "secret-label") || strings.Contains(l, `"h50`) {
			t.Fatalf("warning names a label value: %s", l)
		}
	}
	if !seen["proudauth_test_total"] || !seen["proudauth_test_seconds"] {
		t.Fatalf("warnings: %v", seen)
	}

	// The standard metrics expose the counter for every capped metric.
	buf.Reset()
	NewMetrics().Registry.WriteText(&buf)
	for _, name := range []string{"proudauth_tokens_total", "proudauth_http_requests_total", "proudauth_http_request_duration_seconds"} {
		if !strings.Contains(buf.String(), SeriesDroppedMetric+`{metric="`+name+`"} 0`+"\n") {
			t.Fatalf("standard metrics lack the dropped counter of %s", name)
		}
	}
}
