package bench

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestReplicaProxyPreservesRequests covers NFR-007, NFR-008: routing follows
// requests on a reused connection, preserves public Host/body/cookies and does
// not retain private paths, headers or bodies in its metadata.
func TestReplicaProxyPreservesRequests(t *testing.T) {
	urls := []string{}
	for range 3 {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != "private-one-use-body" || r.Host != "public.bench.test" ||
				r.Header.Get("Authorization") != "Bearer private-token" || r.Header.Get("Cookie") != "pa_sid=private-cookie" ||
				r.URL.RequestURI() != "/private-path?proof=private-proof" {
				t.Error("proxy changed an authentication request")
			}
			w.Header().Add("Set-Cookie", "first=1")
			w.Header().Add("Set-Cookie", "second=2")
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("private-response"))
		}))
		t.Cleanup(s.Close)
		urls = append(urls, s.URL)
	}
	p, err := NewReplicaProxy(urls)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.transport.CloseIdleConnections)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	client := srv.Client()
	for range 12 {
		r, err := http.NewRequest("POST", srv.URL+"/private-path?proof=private-proof", strings.NewReader("private-one-use-body"))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "public.bench.test"
		r.Header.Set("Authorization", "Bearer private-token")
		r.Header.Set("Cookie", "pa_sid=private-cookie")
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 201 || string(body) != "private-response" || len(res.Cookies()) != 2 {
			t.Fatal("proxy changed the response or cookie headers")
		}
	}
	s := p.Snapshot(false)
	for _, b := range s.Backends {
		if b.Assigned != 4 || b.Responses["201"] != 4 || b.TransportErrors != 0 || b.ResponseAborts != 0 {
			t.Fatalf("round-robin counts: %+v", b)
		}
		b.Responses["201"] = 999 // a snapshot must not alias live counters
	}
	res, err := client.Get(srv.URL + ReplicaProxyStatsPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || strings.Contains(string(raw), "private-") {
		t.Fatal("routing metadata retained request/response authority")
	}
	var after ReplicaProxyStats
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	for _, b := range after.Backends {
		if b.Assigned != 4 || b.Responses["201"] != 4 {
			t.Fatal("stats lookup changed or aliased routing counters")
		}
	}
}

// TestReplicaProxyNeverFailsOverOneUsePOST covers NFR-007: a transport failure
// has one observable 502, never a second backend's consumption of the proof.
func TestReplicaProxyNeverFailsOverOneUsePOST(t *testing.T) {
	var brokenCalls, healthyCalls atomic.Int64
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		brokenCalls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	}))
	t.Cleanup(broken.Close)
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { healthyCalls.Add(1); w.WriteHeader(204) }))
	t.Cleanup(healthy.Close)
	p, err := NewReplicaProxy([]string{broken.URL, healthy.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.transport.CloseIdleConnections)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	res, err := srv.Client().Post(srv.URL+"/consume", "application/x-www-form-urlencoded", strings.NewReader("proof=one-use"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	s := p.Snapshot(false)
	if res.StatusCode != 502 || brokenCalls.Load() != 1 || healthyCalls.Load() != 0 || s.Backends[0].TransportErrors != 1 || s.Backends[1].Assigned != 0 {
		t.Fatal("failed proof request was replayed or its transport failure hidden")
	}
}

func TestReplicaProxyBoundsAndShutdown(t *testing.T) {
	for _, urls := range [][]string{{"http://127.0.0.1:10"}, {"https://127.0.0.1:10", "http://127.0.0.1:11"},
		{"http://example.com:10", "http://127.0.0.1:11"}, {"http://127.0.0.1:10/path", "http://127.0.0.1:11"},
		{"http://user:pass@127.0.0.1:10", "http://127.0.0.1:11"}, {"http://127.0.0.1:10", "http://127.0.0.1:10"}} {
		if _, err := NewReplicaProxy(urls); err == nil {
			t.Fatal("unsafe or ambiguous proxy backends accepted")
		}
	}
	p, err := NewReplicaProxy([]string{"http://127.0.0.1:10", "http://127.0.0.1:11"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, ln) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled proxy retained its listener")
	}
	if conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("proxy listener survived shutdown")
	}
}
