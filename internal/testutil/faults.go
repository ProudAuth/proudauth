package testutil

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Endpoint is a fault-injecting TCP listener for reliability tests: a
// destination that accepts connections and then misbehaves. Its connections
// close when the test ends.
type Endpoint struct {
	// Addr is the host:port to connect to.
	Addr     string
	accepted atomic.Int64
}

// Accepted counts the connections the endpoint has accepted.
func (e *Endpoint) Accepted() int { return int(e.accepted.Load()) }

// BlackholeTCP accepts every connection and never reads from or writes to it:
// a destination that is up but hangs.
func BlackholeTCP(t testing.TB) *Endpoint {
	t.Helper()
	return listen(t, nil)
}

// SilentSMTPRelay is a mail relay that accepts the connection and never sends
// its 220 greeting.
func SilentSMTPRelay(t testing.TB) *Endpoint {
	t.Helper()
	return listen(t, nil)
}

// StallingSMTPRelay sends the 220 greeting and then never answers again: the
// client's EHLO, STARTTLS, AUTH or DATA waits forever.
func StallingSMTPRelay(t testing.TB) *Endpoint {
	t.Helper()
	return listen(t, func(c net.Conn) { _, _ = c.Write([]byte("220 stall.invalid ESMTP\r\n")) })
}

func listen(t testing.TB, onAccept func(net.Conn)) *Endpoint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e := &Endpoint{Addr: ln.Addr().String()}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.accepted.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			if onAccept != nil {
				onAccept(c)
			}
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return e
}

// RefusedTCP returns an address nothing listens on, so connecting is refused.
func RefusedTCP(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// SlowHTTP answers every request with status after delay, or gives up as soon
// as the request is cancelled: a destination whose latency exceeds the
// caller's budget.
func SlowHTTP(t testing.TB, delay time.Duration, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}
