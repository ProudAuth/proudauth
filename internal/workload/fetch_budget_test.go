package workload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
)

// MCH-011, ADV-004, NFR-006: cold/unknown/error bursts share one fetch,
// transport fallback preserves only the last good set, and bad JSON cannot
// authenticate through that fallback after expiry.
func TestWorkloadFetchBudgetAndFallback(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var mode atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(25 * time.Millisecond)
		switch mode.Load() {
		case 1:
			w.WriteHeader(503)
			return
		case 2:
			_, _ = w.Write([]byte(`{"broken":`))
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known", Algorithm: "ES256", Use: "sig"}}})
	}))
	defer srv.Close()
	cfg := configuration.Defaults()
	clk := clock.NewFake(time.Unix(1700000000, 0))
	s := NewService(&runtime.Deps{Cfg: &cfg, Clock: clk})
	s.Egress = egress.Policy{RequireHTTPS: true, AllowCIDRs: []string{"127.0.0.1/32"}, RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	trust := &Trust{JWKSURI: srv.URL}
	burst := func(kid string, wantErr bool) {
		t.Helper()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				set, err := s.keys(context.Background(), trust, kid)
				if (err != nil) != wantErr || (!wantErr && len(set.Key("known")) != 1) {
					t.Errorf("key set/error mismatch: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
	burst("unknown", false)
	burst("unknown", false)
	if calls.Load() != 1 {
		t.Fatalf("cold/unknown bursts fetched %d times", calls.Load())
	}
	clk.Advance(time.Minute)
	burst("unknown", false)
	if calls.Load() != 2 {
		t.Fatalf("eligible unknown-key burst fetched %d times", calls.Load())
	}
	mode.Store(1)
	clk.Advance(5 * time.Minute)
	burst("known", false)
	burst("known", false)
	if calls.Load() != 3 {
		t.Fatal("transport outage amplified fetches")
	}
	mode.Store(2)
	clk.Advance(time.Minute)
	burst("known", true)
	burst("known", true)
	if calls.Load() != 4 {
		t.Fatal("malformed response amplified fetches")
	}
	mode.Store(0)
	clk.Advance(time.Minute)
	burst("known", false)
	if calls.Load() != 5 {
		t.Fatal("recovery did not share one eligible fetch")
	}
}
