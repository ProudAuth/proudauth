package directory

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/slots"
	"github.com/proudauth/proudauth/internal/testutil"
)

// TestSignInDeadlineAcrossEndpoints covers NFR-002 and PROV-014: the
// directory work of one sign-in attempt ends at directory.sign_in_timeout
// in total, however many endpoints accept the connection and then never
// answer. Each blackholed endpoint alone would hold the attempt for the
// whole operation timeout, one after the other.
func TestSignInDeadlineAcrossEndpoints(t *testing.T) {
	s := testService(t)
	s.d.Cfg.Directory.OperationTimeout = 3 * time.Second
	s.d.Cfg.Directory.SignInTimeout = time.Second
	var endpoints []string
	for range 3 {
		endpoints = append(endpoints, "ldap://"+testutil.BlackholeTCP(t).Addr)
	}
	cfg := &LDAPConfig{Endpoints: endpoints, StartTLS: boolp(false), BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
	c := testConnector(t, s, cfg, "service secret")
	l := &link{ConnectorID: c.ID, ExternalID: "u-alice", DN: "uid=alice,dc=corp,dc=test"}

	start := time.Now()
	dctx, done, err := s.signIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := s.bindAs(dctx, c, l, "alice password")
	done()
	elapsed := time.Since(start)
	if ok || !errors.Is(err, errUnavailable) {
		t.Fatalf("blackholed directory: ok %v err %v", ok, err)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("sign-in directory work took %s, past the 1s sign_in_timeout", elapsed)
	}

	// The same bound covers StartTLS, which waits on the socket deadline.
	tlsCfg := &LDAPConfig{Endpoints: endpoints, BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
	ct := testConnector(t, s, tlsCfg, "service secret")
	start = time.Now()
	dctx, done, _ = s.signIn(context.Background())
	_, _, err = s.bindAs(dctx, ct, l, "alice password")
	done()
	if elapsed := time.Since(start); !errors.Is(err, errUnavailable) || elapsed > 2500*time.Millisecond {
		t.Fatalf("StartTLS against a blackholed directory: %v after %s", err, elapsed)
	}
}

// TestSignInBindSlotsFailFast covers NFR-002: with every bind slot in use a
// sign-in is refused at once with 503 unavailable and
// Retry-After, instead of waiting for a directory that is already slow.
func TestSignInBindSlotsFailFast(t *testing.T) {
	s := testService(t)
	s.bindSlots = slots.New(1)
	_, done, err := s.signIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, err = s.signIn(context.Background())
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("a full bound waited %s", time.Since(start))
	}
	pe, ok := problem.As(err)
	if !ok || pe.Status != http.StatusServiceUnavailable || pe.Code != "unavailable" || pe.RetryAfter <= 0 {
		t.Fatalf("full bound: %v", err)
	}
	rec := httptest.NewRecorder()
	problem.Write(rec, "req", err)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("rendered: %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	done()
	if _, done, err := s.signIn(context.Background()); err != nil {
		t.Fatalf("a released slot was not reusable: %v", err)
	} else {
		done()
	}
}

// TestBindSlotsDefault: half the transaction slots unless configured.
func TestBindSlotsDefault(t *testing.T) {
	s := testService(t)
	cfg := s.d.Cfg
	cfg.Storage.MaxConns = 20
	if n := BindSlots(cfg); n != 7 {
		t.Fatalf("default with 20 connections: %d", n)
	}
	cfg.Directory.MaxConcurrentBinds = 3
	if n := BindSlots(cfg); n != 3 {
		t.Fatalf("configured: %d", n)
	}
}
