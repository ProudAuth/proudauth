package federation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
)

func fetchBudgetService(t *testing.T, handler http.Handler) (*Service, *httptest.Server, *clock.Fake) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	cfg := configuration.Defaults()
	clk := clock.NewFake(time.Unix(1700000000, 0))
	s := New(&runtime.Deps{Cfg: &cfg, Clock: clk})
	s.Egress.AllowCIDRs = []string{"127.0.0.1/32"}
	s.Egress.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return s, srv, clk
}

func fetchBudgetBurst(t *testing.T, call func(int) error) []error {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 32)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs[i] = call(i) }()
	}
	close(start)
	wg.Wait()
	return errs
}

// TestFederationFetchBudgets covers FED-017 and NFR-006: independent
// concurrency-32 bursts must share one fetch, including cold/expired
// discovery, unknown keys and failed responses. Failures never amplify
// retries before one minute, and a later complete response recovers.
func TestFederationFetchBudgets(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kind string
		failed     bool
	}{
		{"discovery cold", "discovery", false}, {"discovery invalid JSON", "discovery", true},
		{"JWKS unknown key", "jwks", false}, {"JWKS invalid JSON", "jwks", true},
		{"discovery issuer mismatch", "discovery", true}, {"discovery redirect", "discovery", true},
		{"JWKS oversized", "jwks", true}, {"JWKS HTTP failure", "jwks", true}, {"JWKS timeout", "jwks", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			var failed atomic.Bool
			var redirects atomic.Int64
			failed.Store(tc.failed)
			var base string
			s, srv, clk := fetchBudgetService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/must-not-fetch" {
					redirects.Add(1)
					return
				}
				calls.Add(1)
				// Keep the first response open so competing callers actually
				// arrive during its fetch rather than only hitting a warm cache.
				if tc.name != "JWKS timeout" {
					time.Sleep(75 * time.Millisecond)
				}
				if failed.Load() {
					switch tc.name {
					case "discovery issuer mismatch":
						_ = json.NewEncoder(w).Encode(discovery{Issuer: "https://foreign.example.test"})
						return
					case "discovery redirect":
						http.Redirect(w, r, base+"/must-not-fetch", http.StatusFound)
						return
					case "JWKS oversized":
						_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
						return
					case "JWKS HTTP failure":
						w.WriteHeader(503)
						return
					case "JWKS timeout":
						<-r.Context().Done()
						return
					}
					_, _ = w.Write([]byte(`{"incomplete":`))
					return
				}
				if tc.kind == "discovery" {
					_ = json.NewEncoder(w).Encode(discovery{Issuer: base, AuthorizationEndpoint: base + "/authorize", TokenEndpoint: base + "/token", JWKSURI: base + "/jwks"})
				} else {
					_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known", Algorithm: "ES256", Use: "sig"}}})
				}
			}))
			base = srv.URL
			if tc.name == "JWKS timeout" {
				s.Egress.Timeout = 100 * time.Millisecond
			}
			p := &Provider{ID: "owned-provider", Adapter: AdapterOIDC, Issuer: base}
			call := func(i int) error {
				if tc.kind == "discovery" {
					_, err := s.endpoints(context.Background(), p, p.Issuer)
					return err
				}
				_, err := s.key(context.Background(), p, base+"/jwks", fmt.Sprintf("unknown-%d", i), "ES256")
				return err
			}
			for _, err := range fetchBudgetBurst(t, call) {
				if tc.kind == "discovery" && !tc.failed && err != nil {
					t.Error(err)
				} else if (tc.failed || tc.kind == "jwks") && err == nil {
					t.Error("failed metadata or unknown key accepted")
				}
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("first concurrency-32 burst made %d outbound fetches, want 1", n)
			}
			fetchBudgetBurst(t, call)
			if n := calls.Load(); n != 1 {
				t.Errorf("same-window retry burst made %d cumulative fetches, want 1", n)
			}
			failed.Store(false)
			if tc.kind == "discovery" && !tc.failed {
				clk.Advance(discoTTL + time.Second)
			} else {
				clk.Advance(time.Minute)
			}
			fetchBudgetBurst(t, call)
			if n := calls.Load(); n != 2 {
				t.Errorf("next eligible burst made %d cumulative fetches, want 2", n)
			}
			if tc.kind == "jwks" {
				if _, err := s.key(context.Background(), p, base+"/jwks", "known", "ES256"); err != nil {
					t.Errorf("complete response did not restore valid key: %v", err)
				}
			}
			if redirects.Load() != 0 {
				t.Fatal("metadata fetch followed a redirect")
			}
		})
	}
}
