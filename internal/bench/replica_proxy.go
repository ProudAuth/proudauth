package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// ReplicaProxy distributes local benchmark requests across independent server
// processes (NFR-007, NFR-008). It retains counts, never request paths, headers,
// bodies or credentials. Each request chooses one backend without failover:
// one-use POST bodies are never buffered or replayed to another server.
type ReplicaProxy struct {
	mu        sync.Mutex
	next      uint64
	inflight  int64
	started   time.Time
	backends  []ReplicaBackendStats
	proxies   []*httputil.ReverseProxy
	transport *http.Transport
}

type ReplicaBackendStats struct {
	URL                 string           `json:"url"`
	Assigned            int64            `json:"assigned_requests"`
	Responses           map[string]int64 `json:"response_statuses"`
	TransportErrors     int64            `json:"transport_errors"`
	ResponseAborts      int64            `json:"response_aborts"`
	ClientCancellations int64            `json:"client_cancellations"`
}

type ReplicaProxyStats struct {
	Complete   bool                  `json:"complete"`
	StartedAt  time.Time             `json:"started_at"`
	ObservedAt time.Time             `json:"observed_at"`
	Inflight   int64                 `json:"inflight_requests"`
	Backends   []ReplicaBackendStats `json:"backends"`
}

const ReplicaProxyStatsPath = "/_pa_bench_proxy/stats"

func NewReplicaProxy(backends []string) (*ReplicaProxy, error) {
	if len(backends) < 2 || len(backends) > 16 {
		return nil, fmt.Errorf("replica proxy requires 2..16 distinct loopback backends")
	}
	p := &ReplicaProxy{started: time.Now().UTC(), transport: &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 256, MaxIdleConnsPerHost: 128, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 35 * time.Second,
	}}
	seen := map[string]bool{}
	for i, raw := range backends {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
			u.Opaque != "" || u.ForceQuery || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" {
			return nil, fmt.Errorf("replica backend must be a plain HTTP loopback-IP origin with a port")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("replica backend ports must be valid and origins distinct")
		}
		u.Host = net.JoinHostPort(net.ParseIP(u.Hostname()).String(), strconv.Itoa(port))
		if seen[u.String()] {
			return nil, fmt.Errorf("replica backend ports must be valid and origins distinct")
		}
		seen[u.String()] = true
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.Transport = p.transport
		proxy.ErrorLog = log.New(io.Discard, "", 0)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
			p.mu.Lock()
			if r.Context().Err() != nil {
				p.backends[i].ClientCancellations++
			} else {
				p.backends[i].TransportErrors++
			}
			p.mu.Unlock()
			http.Error(w, "benchmark upstream unavailable", http.StatusBadGateway)
		}
		p.proxies = append(p.proxies, proxy)
		p.backends = append(p.backends, ReplicaBackendStats{URL: u.String(), Responses: map[string]int64{}})
	}
	return p, nil
}

func (p *ReplicaProxy) Snapshot(complete bool) ReplicaProxyStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := ReplicaProxyStats{Complete: complete, StartedAt: p.started, ObservedAt: time.Now().UTC(), Inflight: p.inflight}
	for _, b := range p.backends {
		copy := b
		copy.Responses = map[string]int64{}
		for code, n := range b.Responses {
			copy.Responses[code] = n
		}
		s.Backends = append(s.Backends, copy)
	}
	return s
}

type replicaStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *replicaStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *replicaStatusWriter) WriteHeader(status int) {
	if w.status == 0 && (status == http.StatusSwitchingProtocols || status >= 200) {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *replicaStatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (p *ReplicaProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == ReplicaProxyStatsPath {
		// This loopback tool endpoint is not forwarded or counted as load.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.Snapshot(false))
		return
	}
	p.mu.Lock()
	index := int(p.next % uint64(len(p.proxies)))
	p.next++
	p.inflight++
	p.backends[index].Assigned++
	p.mu.Unlock()
	sw := &replicaStatusWriter{ResponseWriter: w}
	defer func() {
		aborted := recover()
		p.mu.Lock()
		p.inflight--
		if aborted != nil {
			if r.Context().Err() != nil {
				p.backends[index].ClientCancellations++
			} else {
				p.backends[index].ResponseAborts++
			}
		}
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		p.backends[index].Responses[strconv.Itoa(status)]++
		p.mu.Unlock()
		if aborted != nil {
			panic(aborted)
		}
	}()
	p.proxies[index].ServeHTTP(sw, r)
}

// Serve owns the listener and upstream idle connections. Cancellation stops
// acceptance and drains current requests; errors are returned to the launcher.
func (p *ReplicaProxy) Serve(ctx context.Context, ln net.Listener) error {
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		ln.Close()
		return fmt.Errorf("replica proxy must listen on a loopback IP")
	}
	defer p.transport.CloseIdleConnections()
	defer ln.Close()
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	done := make(chan struct{})
	shutdown := make(chan error, 1)
	go func() {
		var shutdownErr error
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			shutdownErr = srv.Shutdown(stop)
			if shutdownErr != nil {
				_ = srv.Close()
			}
		case <-done:
		}
		shutdown <- shutdownErr
	}()
	err = srv.Serve(ln)
	close(done)
	shutdownErr := <-shutdown
	if ctx.Err() != nil {
		return shutdownErr
	}
	return err
}
