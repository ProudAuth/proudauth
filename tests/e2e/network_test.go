package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/platform/reqctx"
	"github.com/proudbase/proudauth/internal/platform/tracing"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestForgedProxyAndIdentityHeaders covers TEST-055: forwarded-for headers
// from untrusted peers are ignored (abuse budgets keep using the real peer),
// and identity headers never stand in for credentials.
func TestForgedProxyAndIdentityHeaders(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	// Tight per-IP budget for the attack phase only (the fixture setup itself
	// signs in several users from the same loopback address).
	h.App.D.Cfg.Security.RateLimits.LoginPerIP = 3
	h.App.D.Cfg.Security.RateLimits.LoginPerIdentifier = 100
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	attempt := func(xff string) *Resp {
		start, _, cont := h.StartTx(cli)
		tx := start.Str("transaction_id")
		hdr := map[string]string{"X-Transaction-Token": cont, "X-Forwarded-For": xff, "X-Real-IP": xff}
		if r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/identify", JSON: map[string]any{"identifier": "bob@example.test"},
			Headers: hdr}); r.Status != 200 {
			return r // the identify step shares the per-IP budget
		}
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/password", JSON: map[string]any{"password": "wrong-password-1"}, Headers: hdr})
	}
	h.Clock.Advance(16 * time.Minute) // a fresh budget window
	statuses := []int{}
	for _, ip := range []string{"203.0.113.1", "198.51.100.2", "192.0.2.3", "203.0.113.4"} {
		statuses = append(statuses, attempt(ip).Status)
	}
	if statuses[0] != 401 || statuses[3] != 429 {
		t.Fatalf("rotating X-Forwarded-For from an untrusted peer must not evade the per-IP budget: %v", statuses)
	}
	// Identity assertions in headers are never authentication.
	for _, path := range []string{"/api/v1/realms/main/me", "/api/v1/realms/main/users"} {
		r := h.Do(Req{Method: "GET", Path: path, Headers: map[string]string{"X-User-Id": f.Users["alice"], "X-Forwarded-User": "root-admin",
			"X-Remote-User": "root-admin", "X-Authenticated-Userid": f.Users["alice"], "X-Forwarded-Email": "alice@example.test"}})
		if r.Status != 401 {
			t.Fatalf("%s accepted identity headers: %d", path, r.Status)
		}
	}
}

// TestTrustedProxyForwarding shows forwarded addresses are honored only from a
// configured proxy (SEC-001), producing privacy-reduced network context.
func TestTrustedProxyForwarding(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"} })
	fixtureOn(t, h)
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	tx := start.Str("transaction_id")
	hdr := map[string]string{"X-Transaction-Token": cont, "X-Forwarded-For": "203.0.113.77"}
	h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/identify", JSON: map[string]any{"identifier": "bob@example.test"}, Headers: hdr})
	h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/password", JSON: map[string]any{"password": "wrong-password-1"}, Headers: hdr})
	var ipctx string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT coalesce(ip_context,'') FROM audit_events WHERE type='authentication.password.failed' ORDER BY seq DESC LIMIT 1`).Scan(&ipctx)
	if ipctx != "203.0.113.0/24" {
		t.Fatalf("forwarded address from a trusted proxy not used (or not minimized): %q", ipctx)
	}
}

// TestOfflineOperation covers TEST-072 and OSS-003/OSS-005/OSS-006: bootstrap,
// sign-in, token issuance, administration and every worker task run with all
// non-loopback network access blocked; nothing phones home.
func TestOfflineOperation(t *testing.T) {
	var mu sync.Mutex
	var blocked []string
	record := func(what string) {
		mu.Lock()
		blocked = append(blocked, what)
		mu.Unlock()
	}
	baseDial := (&net.Dialer{}).DialContext
	origTransport := http.DefaultTransport
	tr := origTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
			record(addr)
			return nil, errors.New("outbound network blocked")
		}
		return baseDial(ctx, network, addr)
	}
	http.DefaultTransport = tr
	origResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		record("dns:" + address)
		return nil, errors.New("DNS blocked")
	}}
	defer func() {
		http.DefaultTransport = origTransport
		net.DefaultResolver = origResolver
	}()

	f := NewFixture(t) // bootstrap, realm, organizations, users, roles, clients
	mustStatus(t, f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens, 200, "sign-in")
	mustStatus(t, f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme), 200, "machine token")
	f.must(f.AdminAPI("GET", "/users", nil), 200, "administration")
	w := worker.New(f.H.App, "offline")
	for name, err := range w.RunOnce(context.Background()) {
		if err != nil {
			t.Fatalf("worker task %s failed offline: %v", name, err)
		}
	}
	if len(blocked) > 0 {
		t.Fatalf("core operation attempted outbound network access: %v", blocked)
	}
}

// TestSecuritySignalsMetrics covers OPS-004: security-relevant evidence
// produces bounded, alertable signals without identifiers in labels.
func TestSecuritySignalsMetrics(t *testing.T) {
	f := NewFixture(t)
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/recovery-requests", map[string]any{"reason": "verified by phone callback per runbook",
		"evidence_reference": "ticket 991"}), 202, "assisted recovery")
	var buf strings.Builder
	f.H.App.Metrics.Registry.WriteText(&buf)
	out := buf.String()
	if !strings.Contains(out, `proudauth_security_signals_total{signal="factor_recovery"}`) {
		t.Fatalf("factor recovery signal missing:\n%s", out)
	}
	if strings.Contains(out, f.Users["bob"]) || strings.Contains(out, "@example.test") {
		t.Fatal("metrics labels carry user identifiers")
	}
}

// TestCorrelationPropagation covers API-012: outbound calls made while serving
// a request carry its W3C trace context, and events caused by a request carry
// its request ID for correlation with the audit log.
func TestCorrelationPropagation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/users/" + f.Users["bob"] + "/suspend", Token: f.AdminToken,
		JSON: map[string]any{"reason": "correlation"}, Headers: map[string]string{"X-Request-Id": "req-correlation-test-1"}}), 200, "suspend")
	var payload []byte
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT payload FROM outbox_events WHERE event_type='user.suspended' ORDER BY occurred_at DESC LIMIT 1`).Scan(&payload)
	var ev map[string]any
	_ = json.Unmarshal(payload, &ev)
	if ev["correlation_id"] != "req-correlation-test-1" {
		t.Fatalf("event correlation: %s", payload)
	}
	var audited int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='user.suspended' AND request_id='req-correlation-test-1'`).Scan(&audited)
	if audited != 1 {
		t.Fatal("audit event not correlated with the same request ID")
	}
	// Outbound trace context.
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("traceparent"):
		default:
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	pol := egress.Policy{AllowPrivate: true}
	info := reqctx.Info{RequestID: "r1", TraceID: strings.Repeat("ab", 16), SpanID: strings.Repeat("cd", 8), Sampled: true}
	req, _ := http.NewRequestWithContext(reqctx.With(ctx, info), "GET", srv.URL, nil)
	res, err := pol.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if tp := <-got; tp != "00-"+strings.Repeat("ab", 16)+"-"+strings.Repeat("cd", 8)+"-01" {
		t.Fatalf("outbound traceparent: %q", tp)
	}
}

type spanRecorder struct {
	mu    sync.Mutex
	spans []tracing.Span
}

func (r *spanRecorder) Export(s tracing.Span) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, s)
}

// TestTraceExport covers OPS-003: sampled requests produce a server span
// linked to the caller's span, outbound calls a client span linked to it,
// with route-level attributes only; the OTLP encoding is collector-ready.
func TestTraceExport(t *testing.T) {
	// The test client stands in for a trusted proxy that made the sampling decision.
	h := NewHarness(t, func(c *configuration.Config) { c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"} })
	f := fixtureOn(t, h)
	rec := &spanRecorder{}
	tracing.SetTracer(rec)
	defer tracing.SetTracer(nil)
	trace, parent := strings.Repeat("1a", 16), strings.Repeat("2b", 8)
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users?q=secret-query", Token: f.AdminToken,
		Headers: map[string]string{"Traceparent": "00-" + trace + "-" + parent + "-01"}}), 200, "sampled request")
	unsampled := strings.Repeat("3c", 16)
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users", Token: f.AdminToken,
		Headers: map[string]string{"Traceparent": "00-" + unsampled + "-" + parent + "-00"}}), 200, "unsampled request")
	rec.mu.Lock()
	spans := append([]tracing.Span{}, rec.spans...)
	rec.mu.Unlock()
	var server *tracing.Span
	for i := range spans {
		if spans[i].TraceID == unsampled {
			t.Fatal("unsampled request exported")
		}
		if spans[i].TraceID == trace && spans[i].Kind == tracing.KindServer {
			server = &spans[i]
		}
	}
	if server == nil || server.ParentID != parent || server.Attributes["http.route"] == nil || server.Attributes["http.response.status_code"] != 200 {
		t.Fatalf("server span: %+v", server)
	}
	for _, s := range spans {
		for k, v := range s.Attributes {
			if strings.Contains(fmt.Sprint(v), "secret-query") || strings.Contains(k, "header") {
				t.Fatalf("sensitive attribute exported: %s=%v", k, v)
			}
		}
	}
	// An outbound call made while serving a sampled request is a child span.
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("traceparent")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	info := reqctx.Info{TraceID: trace, SpanID: server.SpanID, Sampled: true}
	req, _ := http.NewRequestWithContext(reqctx.With(context.Background(), info), "GET", srv.URL+"/path?token=x", nil)
	res, err := (egress.Policy{AllowPrivate: true}).Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	tp := <-got
	rec.mu.Lock()
	client := rec.spans[len(rec.spans)-1]
	rec.mu.Unlock()
	if client.Kind != tracing.KindClient || client.ParentID != server.SpanID || !strings.Contains(tp, "-"+client.SpanID+"-01") ||
		client.Attributes["http.response.status_code"] != 204 || strings.Contains(fmt.Sprint(client.Attributes), "token=x") {
		t.Fatalf("client span %+v, traceparent %q", client, tp)
	}
	enc, _ := json.Marshal(tracing.Encode("proudauth", []tracing.Span{client}))
	if !strings.Contains(string(enc), `"resourceSpans"`) || !strings.Contains(string(enc), `"parentSpanId":"`+server.SpanID+`"`) {
		t.Fatalf("OTLP encoding: %s", enc)
	}
}

// TestCustomDomains covers DEP-014: under a strict host policy only the
// public origin's host and verified custom domains are served, a custom
// domain serves only its realm, and the issuer never changes with the host.
// Requirements: PASS-008 (a custom login host does not move the passkey RP
// ID; passkeys are usable there only once an explicit RP ID covers it).
func TestCustomDomains(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Server.HostPolicy = "strict" })
	f := fixtureOn(t, h)
	disco := func(host string) *Resp {
		return h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration", Headers: map[string]string{"Host": host}})
	}
	canonical := f.must(disco(strings.TrimPrefix(h.Srv.URL, "http://")), 200, "public origin").Str("issuer")
	mustStatus(t, disco("login.acme.test"), 421, "unverified host")
	ch := f.must(f.AdminAPI("POST", "/custom-domains", map[string]any{"host": "Login.Acme.Test"}), 201, "add domain")
	if ch.Str("dns_record_name") != "_proudauth-challenge.login.acme.test" || ch.Str("domain.state") != "pending" {
		t.Fatalf("challenge: %s", ch.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/custom-domains", map[string]any{"host": "login.acme.test"}), 409, "duplicate host")
	// Another realm's pending claim neither blocks nor reveals this one;
	// only DNS proof decides, and the first verified claim wins.
	ctx := context.Background()
	other, err := h.App.Provision.CreateRealm(ctx, "squatter", "Squatter", realm.Policy{}, audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	squat, err := h.App.Realms.AddCustomDomain(ctx, other, "login.acme.test", audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatalf("pending claim in another realm: %v", err)
	}
	saved := realm.CustomDomainTXT
	defer func() { realm.CustomDomainTXT = saved }()
	realm.CustomDomainTXT = func(context.Context, string) ([]string, error) { return []string{"wrong"}, nil }
	mustStatus(t, f.AdminAPI("POST", "/custom-domains/"+ch.Str("domain.id")+"/verify", nil), 422, "wrong proof")
	realm.CustomDomainTXT = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/custom-domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify")
	realm.CustomDomainTXT = func(context.Context, string) ([]string, error) { return []string{squat.Value}, nil }
	if _, err := h.App.Realms.VerifyCustomDomain(ctx, other, squat.Domain.ID, audit.Ref{Type: "operator", ID: "test"}); err == nil {
		t.Fatal("a second realm verified a host already in use")
	}
	if iss := f.must(disco("login.acme.test:443"), 200, "custom domain").Str("issuer"); iss != canonical {
		t.Fatalf("issuer changed with the host: %s vs %s", iss, canonical)
	}
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/api/v1/realms/other/users", Headers: map[string]string{"Host": "login.acme.test"}}), 421,
		"another realm on a custom domain")
	// Passkeys follow the realm's RP ID, not the host (PASS-008): the derived
	// RP ID stays the public origin's host, so the new login host cannot use
	// the realm's passkeys until an explicit RP ID covers it.
	passkeysUsable := func() any {
		for _, it := range f.must(f.AdminAPI("GET", "/custom-domains", nil), 200, "domains").Get("items").([]any) {
			if m := it.(map[string]any); m["host"] == "login.acme.test" {
				return m["passkeys_usable"]
			}
		}
		return nil
	}
	if v := passkeysUsable(); v != false {
		t.Fatalf("passkeys reported usable on a host outside the RP ID: %v", v)
	}
	f.must(f.SetPolicy(func(p *realm.Policy) {
		p.WebAuthn.RPID, p.WebAuthn.Origins = "acme.test", []string{"https://login.acme.test"}
	}), 200, "explicit RP ID covering the host")
	if v := passkeysUsable(); v != true {
		t.Fatalf("passkeys not reported usable on a host under the RP ID: %v", v)
	}
	f.must(f.AdminAPI("DELETE", "/custom-domains/"+ch.Str("domain.id"), nil), 204, "remove")
	mustStatus(t, disco("login.acme.test"), 421, "removed host")
}

// TestUntrustedTraceSampling covers OPS-003 hardening: a client that is not a
// trusted proxy cannot force span export by marking its traceparent sampled.
func TestUntrustedTraceSampling(t *testing.T) {
	f := NewFixture(t)
	rec := &spanRecorder{}
	tracing.SetTracer(rec)
	defer tracing.SetTracer(nil)
	trace := strings.Repeat("4d", 16)
	mustStatus(t, f.H.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users", Token: f.AdminToken,
		Headers: map[string]string{"Traceparent": "00-" + trace + "-" + strings.Repeat("5e", 8) + "-01"}}), 200, "request")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, s := range rec.spans {
		if s.TraceID == trace {
			t.Fatal("an untrusted client forced span export")
		}
	}
}

// TestResidencyAtSave covers PRV-003: tenant mail servers and federation
// connections outside the destination residency policy are refused when
// saved, not only when contacted.
func TestResidencyAtSave(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Privacy.Residency.AllowedDestinations = []string{".eu.test", "127.0.0.1", "localhost"}
	})
	defer egress.SetResidency(nil)
	f := fixtureOn(t, h)
	smtp := f.AdminAPI("PUT", "/organizations/"+f.Acme+"/notification-settings/smtp", map[string]any{"host": "smtp.us.test", "port": 587,
		"tls_mode": "starttls"})
	mustStatus(t, smtp, 422, "mail server outside the residency policy")
	f.must(f.AdminAPI("PUT", "/organizations/"+f.Acme+"/notification-settings/smtp", map[string]any{"host": "smtp.eu.test", "port": 587,
		"tls_mode": "starttls"}), 200, "mail server inside the residency policy")
	idp := f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "us", "display_name": "US", "issuer": "https://idp.us.test",
		"config": map[string]any{"client_id": "c"}})
	mustStatus(t, idp, 422, "provider outside the residency policy")
	if !strings.Contains(string(idp.Raw), "residency") {
		t.Fatalf("refusal does not name the residency policy: %s", idp.Raw)
	}
}
