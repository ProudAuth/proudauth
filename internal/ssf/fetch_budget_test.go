package ssf

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
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
)

// ADV-007, NFR-006: bad-signature refresh requests and malformed key sets
// cannot bypass the per-transmitter retry budget under concurrency 32.
func TestSignalKeyFetchBudget(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var failed atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(25 * time.Millisecond)
		if failed.Load() {
			_, _ = w.Write([]byte(`{"broken":`))
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known", Algorithm: "ES256", Use: "sig"}}})
	}))
	defer srv.Close()
	cfg := configuration.Defaults()
	clk := clock.NewFake(time.Unix(1700000000, 0))
	s := New(&runtime.Deps{Cfg: &cfg, Clock: clk})
	s.Egress.AllowCIDRs = []string{"127.0.0.1/32"}
	s.Egress.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tx := &Transmitter{ID: "owned-transmitter", JWKSURI: srv.URL}
	burst := func(refresh, wantErr bool) {
		t.Helper()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				set, err := s.keysFor(context.Background(), tx, refresh)
				if (err != nil) != wantErr || (!wantErr && len(set.Key("known")) != 1) {
					t.Errorf("key set/error mismatch: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
	burst(false, false)
	burst(true, false)
	if calls.Load() != 1 {
		t.Fatal("immediate signature retries amplified fetches")
	}
	clk.Advance(time.Minute)
	burst(true, false)
	if calls.Load() != 2 {
		t.Fatal("eligible signature retries did not share one fetch")
	}
	clk.Advance(jwksCacheTTL)
	failed.Store(true)
	burst(false, true)
	burst(true, true)
	if calls.Load() != 3 {
		t.Fatal("malformed key sets amplified fetches")
	}
	clk.Advance(time.Minute)
	failed.Store(false)
	burst(false, false)
	if calls.Load() != 4 {
		t.Fatal("complete recovery did not share one fetch")
	}
}
