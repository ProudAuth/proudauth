package ordersapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestAPI serves the token endpoint and the decision endpoint from one
// httptest server, because both URLs are derived from Config.Issuer.
func newTestAPI(t *testing.T, token, decision http.HandlerFunc) *API {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/test/oauth/token", token)
	mux.HandleFunc("POST /api/v1/realms/test/authorization/check", decision)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, err := New(Config{Issuer: srv.URL + "/realms/test", Audience: "orders", ClientID: "orders-rs", ClientSecret: "secret",
		HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func allow(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"allowed":true}`))
}

func issueToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"svc","token_type":"Bearer","expires_in":300}`))
}

// A burst of refunds on a cold cache must share one client-credentials fetch.
// The token endpoint is slow so that, without single-flight, every caller would
// find the cache empty and issue its own request.
func TestServiceTokenSingleFlight(t *testing.T) {
	var tokenRequests atomic.Int32
	var a *API
	a = newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		tokenRequests.Add(1)
		// The order store must stay usable while the fetch is in flight: a.mu
		// guards the orders map and must not be held across the network call.
		stored := make(chan struct{})
		go func() { a.Put(Order{ID: "ord_during_fetch", OrgID: "org_1"}); close(stored) }()
		select {
		case <-stored:
		case <-time.After(5 * time.Second):
			t.Error("Put blocked while the service token was being fetched")
		}
		time.Sleep(100 * time.Millisecond)
		issueToken(w, r)
	}, allow)

	const callers = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := a.decide(context.Background(), "subject", "orders.refund", &Order{ID: "ord_1", OrgID: "org_1", AmountMinor: 100})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
	}
	if n := tokenRequests.Load(); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
}

// Responses larger than the bound are rejected rather than buffered whole or
// parsed truncated. The oversized bodies are otherwise valid JSON, so an
// unbounded read would accept them.
func TestOversizedResponsesRejected(t *testing.T) {
	pad := strings.Repeat("x", maxResponseBytes)
	order := &Order{ID: "ord_1", OrgID: "org_1", AmountMinor: 100}

	t.Run("decision", func(t *testing.T) {
		a := newTestAPI(t, issueToken, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"allowed":true,"pad":"` + pad + `"}`))
		})
		dec, err := a.decide(context.Background(), "subject", "orders.refund", order)
		if err == nil {
			t.Fatalf("decide accepted an oversized decision body: allowed=%v", dec["allowed"])
		}
	})

	t.Run("token", func(t *testing.T) {
		a := newTestAPI(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"svc","expires_in":300,"pad":"` + pad + `"}`))
		}, allow)
		if _, err := a.decide(context.Background(), "subject", "orders.refund", order); err == nil {
			t.Fatal("decide accepted an oversized token response")
		}
	})
}
