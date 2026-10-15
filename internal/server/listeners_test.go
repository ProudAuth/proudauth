package server

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
)

// TestPublicServerBounds covers NFR-001 at the connection level: the public
// and mutual-TLS listeners bound header size (limits.max_header_bytes, a
// larger header block answers 431), header arrival, request reading,
// response writing and idle keep-alive time.
func TestPublicServerBounds(t *testing.T) {
	cfg := configuration.Defaults()
	cfg.Limits.MaxHeaderBytes = 8 << 10
	cfg.Server.ReadTimeout = 7 * time.Second
	cfg.Server.WriteTimeout = 11 * time.Second
	cfg.Server.MTLSListen = "127.0.0.1:0"
	for _, s := range []*http.Server{PublicServer(&cfg, nil), MutualTLSServer(&cfg, nil)} {
		if s.MaxHeaderBytes != 8<<10 || s.ReadTimeout != 7*time.Second || s.WriteTimeout != 11*time.Second ||
			s.ReadHeaderTimeout != ReadHeaderTimeout || s.IdleTimeout != IdleTimeout {
			t.Fatalf("listener bounds not applied: %+v", s)
		}
	}
	if m := MutualTLSServer(&cfg, nil); m.TLSConfig == nil || m.TLSConfig.MinVersion == 0 || m.Addr != "127.0.0.1:0" {
		t.Fatal("mutual-TLS listener without its TLS settings")
	}

	srv := PublicServer(&cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	get := func(header string) int {
		req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
		req.Header.Set("X-Filler", header)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if got := get("small"); got != http.StatusNoContent {
		t.Fatalf("ordinary request: %d", got)
	}
	// net/http allows a 4096-byte slack above MaxHeaderBytes.
	if got := get(strings.Repeat("x", 16<<10)); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header block: %d, want 431", got)
	}
}
