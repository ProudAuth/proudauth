package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
)

// TestUntrustedForwardedForWarnsOnceAMinute covers ABU-001 and SEC-001 for a
// production deployment whose reverse proxy is not in server.trusted_proxies:
// the forwarded address is ignored (the client address stays the peer's), a
// warning names the condition at most once a minute, a trusted proxy's
// header is honoured silently, and development mode stays quiet.
func TestUntrustedForwardedForWarnsOnceAMinute(t *testing.T) {
	cfg := configuration.Defaults()
	cfg.Mode = configuration.ModeProduction
	var buf bytes.Buffer
	clk := clock.NewFake(time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	a := &App{D: &runtime.Deps{Cfg: &cfg, Clock: clk, Log: slog.New(slog.NewTextHandler(&buf, nil))}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.30.0.1:40000"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	warnings := func() int { return strings.Count(buf.String(), "X-Forwarded-For") }
	if ip := a.clientIP(req); ip != "172.30.0.1" {
		t.Fatalf("client IP %q, want the untrusted peer's address", ip)
	}
	a.clientIP(req)
	if warnings() != 1 || !strings.Contains(buf.String(), "peer_network=172.30.0.0/24") {
		t.Fatalf("want exactly one warning naming the peer network within a minute, got:\n%s", buf.String())
	}
	clk.Advance(61 * time.Second)
	a.clientIP(req)
	if warnings() != 2 {
		t.Fatalf("want a second warning after a minute, got:\n%s", buf.String())
	}

	buf.Reset()
	cfg.Server.TrustedProxies = []string{"172.30.0.0/24"}
	if ip := a.clientIP(req); ip != "203.0.113.9" {
		t.Fatalf("client IP %q behind a trusted proxy, want the forwarded address", ip)
	}
	if buf.Len() != 0 {
		t.Fatalf("a trusted proxy must not warn:\n%s", buf.String())
	}

	cfg.Server.TrustedProxies = nil
	cfg.Mode = configuration.ModeDevelopment
	clk.Advance(61 * time.Second)
	a.clientIP(req)
	if buf.Len() != 0 {
		t.Fatalf("development mode must not warn:\n%s", buf.String())
	}
}
