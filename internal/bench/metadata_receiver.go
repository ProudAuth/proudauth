package bench

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var metadataProfiles = []string{"valid", "unknown-key", "malformed", "oversized", "http-failure", "redirect", "timeout", "private"}

// MetadataContact retains counts and request times, never assertions or keys.
type MetadataContact struct {
	Requests int64       `json:"requests"`
	Bytes    int64       `json:"response_bytes"`
	Starts   []time.Time `json:"request_starts"`
}

type MetadataStats struct {
	Profiles map[string]MetadataContact `json:"profiles"`
	Inflight int                        `json:"inflight"`
}

// MetadataReceiver is a disposable HTTPS upstream for NFR-006. The second
// loopback listener proves that a denied IPv6 destination is actually live.
// Private TLS/signing keys are generated in memory and are never serialized.
type MetadataReceiver struct {
	url, privateURL string
	ca              []byte
	key             *ecdsa.PrivateKey
	jwks            []byte
	listeners       []net.Listener
	servers         []*http.Server
	mu              sync.Mutex
	stats           MetadataStats
}

func NewMetadataReceiver(addr string) (*MetadataReceiver, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return nil, errors.New("metadata receiver requires 127.0.0.1 and a port")
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln6, err := net.Listen("tcp6", "[::1]:"+port)
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &MetadataReceiver{url: "https://127.0.0.1:" + port, privateURL: "https://[::1]:" + port,
		listeners: []net.Listener{ln, ln6}, stats: MetadataStats{Profiles: map[string]MetadataContact{}}}
	failed := true
	defer func() {
		if failed {
			s.Close()
		}
	}()
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ProudAuth disposable metadata benchmark"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		return nil, err
	}
	s.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	s.jwks, err = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: "known", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: tlsKey}}}
	for i, listener := range s.listeners {
		s.listeners[i] = tls.NewListener(listener, config)
		s.servers = append(s.servers, &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 15 * time.Second, ErrorLog: log.New(io.Discard, "", 0)})
	}
	for _, name := range append(append([]string{}, metadataProfiles...), "redirect-trap") {
		s.stats.Profiles[name] = MetadataContact{Starts: []time.Time{}}
	}
	failed = false
	return s, nil
}

func (s *MetadataReceiver) URL() string        { return s.url }
func (s *MetadataReceiver) PrivateURL() string { return s.privateURL }
func (s *MetadataReceiver) CAPEM() []byte      { return append([]byte{}, s.ca...) }
func (s *MetadataReceiver) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(s.ca)
	return p
}
func (s *MetadataReceiver) Close() {
	for _, server := range s.servers {
		_ = server.Close()
	}
	for _, listener := range s.listeners {
		_ = listener.Close()
	}
}
func (s *MetadataReceiver) Serve(ctx context.Context) error {
	done := make(chan error, len(s.servers))
	for i, server := range s.servers {
		go func() { done <- server.Serve(s.listeners[i]) }()
	}
	var first error
	remaining := len(s.servers)
	select {
	case <-ctx.Done():
	case first = <-done:
		remaining--
	}
	s.Close()
	if errors.Is(first, http.ErrServerClosed) || errors.Is(first, net.ErrClosed) {
		first = nil
	}
	for range remaining {
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			first = errors.Join(first, err)
		}
	}
	return first
}
func (s *MetadataReceiver) Snapshot() MetadataStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := MetadataStats{Profiles: map[string]MetadataContact{}, Inflight: s.stats.Inflight}
	for name, contact := range s.stats.Profiles {
		contact.Starts = append([]time.Time{}, contact.Starts...)
		out.Profiles[name] = contact
	}
	return out
}
func (s *MetadataReceiver) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" && r.URL.Path == "/ready" {
		w.WriteHeader(204)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/stats" {
		_ = json.NewEncoder(w).Encode(s.Snapshot())
		return
	}
	if r.Method == "POST" && r.URL.Path == "/issue" {
		var in struct {
			Profile, Audience, Subject string
			Now                        time.Time
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil || !metadataProfile(in.Profile) ||
			in.Audience == "" || in.Subject == "" || len(in.Audience) > 512 || len(in.Subject) > 512 || in.Now.IsZero() {
			w.WriteHeader(400)
			return
		}
		kid := "known"
		if in.Profile == "unknown-key" {
			kid = "missing"
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			w.WriteHeader(500)
			return
		}
		token, err := jwt.Signed(signer).Claims(map[string]any{"iss": s.url + "/issuer/" + in.Profile, "sub": in.Subject, "aud": in.Audience,
			"iat": in.Now.Unix(), "exp": in.Now.Add(20 * time.Minute).Unix()}).Serialize()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"assertion": token})
		return
	}
	profile := strings.TrimPrefix(r.URL.Path, "/jwks/")
	if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/jwks/") || (!metadataProfile(profile) && profile != "redirect-trap") {
		w.WriteHeader(404)
		return
	}
	s.mu.Lock()
	contact := s.stats.Profiles[profile]
	contact.Requests++
	contact.Starts = append(contact.Starts, time.Now().UTC())
	s.stats.Profiles[profile] = contact
	s.stats.Inflight++
	s.mu.Unlock()
	var written int
	defer func() {
		s.mu.Lock()
		c := s.stats.Profiles[profile]
		c.Bytes += int64(written)
		s.stats.Profiles[profile] = c
		s.stats.Inflight--
		s.mu.Unlock()
	}()
	body := s.jwks
	switch profile {
	case "malformed":
		body = []byte(`{"keys":`)
	case "oversized":
		body = append(append([]byte{}, body...), []byte(strings.Repeat(" ", (1<<20)+1-len(body)))...)
	case "http-failure":
		w.WriteHeader(503)
		return
	case "redirect":
		w.Header().Set("Location", s.url+"/jwks/redirect-trap")
		w.WriteHeader(302)
		return
	case "timeout":
		timer := time.NewTimer(13 * time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
	}
	written, _ = w.Write(body)
}
func metadataProfile(name string) bool {
	for _, n := range metadataProfiles {
		if n == name {
			return true
		}
	}
	return false
}

// ValidateMetadataStats proves all intended upstream contacts and the minute
// per-URI bounds. The 100 ms tolerance allows independent wall-clock sampling.
func ValidateMetadataStats(stats MetadataStats) error {
	if len(stats.Profiles) != 9 || stats.Inflight != 0 {
		return errors.New("metadata receiver incomplete or still inflight")
	}
	for name, c := range stats.Profiles {
		if name == "private" || name == "redirect-trap" {
			if c.Requests != 0 || c.Bytes != 0 || len(c.Starts) != 0 {
				return errors.New("metadata forbidden destination contacted")
			}
			continue
		}
		if !metadataProfile(name) || c.Requests < 1 || int64(len(c.Starts)) != c.Requests {
			return errors.New("metadata profile was not observed")
		}
		for i := 1; i < len(c.Starts); i++ {
			if c.Starts[i].Sub(c.Starts[i-1]) < time.Minute-100*time.Millisecond {
				return errors.New("metadata fetch cooldown exceeded")
			}
		}
	}
	return nil
}
