package server

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
)

// Connection bounds of the public listeners (NFR-001): headers must arrive
// within ReadHeaderTimeout, the whole request within server.read_timeout,
// the response within server.write_timeout, and idle keep-alive connections
// close after IdleTimeout; headers are bounded by limits.max_header_bytes.
const (
	ReadHeaderTimeout = 5 * time.Second
	IdleTimeout       = 120 * time.Second
)

// PublicServer is the public listener's HTTP server.
func PublicServer(cfg *configuration.Config, h http.Handler) *http.Server {
	return &http.Server{Addr: cfg.Server.PublicListen, Handler: h, ReadTimeout: cfg.Server.ReadTimeout,
		ReadHeaderTimeout: ReadHeaderTimeout, WriteTimeout: cfg.Server.WriteTimeout, IdleTimeout: IdleTimeout,
		MaxHeaderBytes: cfg.Limits.MaxHeaderBytes}
}

// MutualTLSServer is the mutual-TLS listener's HTTP server. It asks for
// client certificates without verifying them at the TLS layer: which
// certificates authenticate a client is per-client registration and realm
// trust anchors (RFC 8705).
func MutualTLSServer(cfg *configuration.Config, h http.Handler) *http.Server {
	s := PublicServer(cfg, h)
	s.Addr = cfg.Server.MTLSListen
	s.TLSConfig = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	return s
}
