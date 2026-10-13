package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// NFR-006: one caller cannot cancel a shared fetch, unrelated destinations
// progress independently, and invalidation fences returning old responses.
func TestFetchCacheCancellationAndInvalidation(t *testing.T) {
	var cache FetchCache[int]
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	opt := FetchOptions[int]{TTL: time.Hour, Timeout: time.Second, Fetch: func(ctx context.Context) (int, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return 1, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := cache.Load(ctx, "provider|old", opt); done <- err }()
	<-entered
	cache.mu.Lock()
	oldFetchDone := cache.entries["provider|old"].done
	cache.mu.Unlock()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	fast := FetchOptions[int]{TTL: time.Hour, Timeout: time.Second, Fetch: func(context.Context) (int, error) { return 2, nil }}
	if value, err := cache.Load(context.Background(), "unrelated", fast); err != nil || value != 2 {
		t.Fatal("unrelated key blocked or failed")
	}
	cache.ForgetPrefix("provider|")
	if value, err := cache.Load(context.Background(), "provider|old", fast); err != nil || value != 2 {
		t.Fatal("new generation failed")
	}
	close(release)
	// Wait for the old bounded fetch to finish before observing the cache.
	<-oldFetchDone
	if value, err := cache.Load(context.Background(), "provider|old", fast); err != nil || value != 2 || calls.Load() != 1 {
		t.Fatal("returning old fetch overwrote its invalidated generation")
	}
}

func TestFetchCacheCancelledLeaderKeepsOtherWaiter(t *testing.T) {
	var cache FetchCache[int]
	entered, release := make(chan struct{}), make(chan struct{})
	opt := FetchOptions[int]{TTL: time.Hour, Timeout: time.Second, Fetch: func(ctx context.Context) (int, error) {
		close(entered)
		select {
		case <-release:
			return 7, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() { _, err := cache.Load(ctx, "shared", opt); leader <- err }()
	<-entered
	follower := make(chan int, 1)
	go func() {
		v, err := cache.Load(context.Background(), "shared", opt)
		if err != nil {
			v = -1
		}
		follower <- v
	}()
	cancel()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if v := <-follower; v != 7 {
		t.Fatalf("healthy waiter got %d", v)
	}
}

func TestFetchCacheTimeoutConsumesRetryBudget(t *testing.T) {
	var cache FetchCache[int]
	var calls atomic.Int64
	opt := FetchOptions[int]{TTL: time.Hour, Timeout: 25 * time.Millisecond, Fetch: func(ctx context.Context) (int, error) {
		calls.Add(1)
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	for range 2 {
		if _, err := cache.Load(context.Background(), "slow", opt); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("timeout retried before the cooldown")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.Load(ctx, "not-started", opt); !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatal("cancelled request spent fetch resources")
	}
}

func TestPolicyClientClosesIdleTracedConnections(t *testing.T) {
	closed := make(chan struct{}, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.Start()
	defer srv.Close()
	client := (Policy{AllowCIDRs: []string{"127.0.0.1/32"}}).Client()
	res, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	client.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("trace wrapper kept an idle connection after close")
	}
}

// FED-017, NFR-006: registration's three-second DNS ceiling must not
// override a shorter shared-fetch deadline. The resolver is local/fake.
func TestMetadataURLValidationUsesFetchDeadline(t *testing.T) {
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	defer func() { net.DefaultResolver = original }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := (Policy{RequireHTTPS: true}).ValidateURLContext(ctx, "https://slow-metadata.example.test/jwks")
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("DNS ignored the shared fetch deadline: %v", err)
	}
}
