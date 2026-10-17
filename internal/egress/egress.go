// Package egress provides the outbound HTTP client used for webhooks, federation
// metadata/JWKS fetches and back-channel logout (EXT-006, EXT-007, FED-017).
//
// Address policy is enforced on the actual connection: the dialer resolves the host,
// rejects private, loopback, link-local, multicast and other special ranges unless
// the operator explicitly allowed them, and connects to the vetted IP. Checking at
// connect time (not only at registration) defeats DNS-rebinding (TEST-052).
// Redirects are refused, and response sizes and timeouts are bounded.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/tracing"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrForbiddenDestination is returned for disallowed destinations.
var ErrForbiddenDestination = errors.New("egress: destination not allowed by egress policy")

// Policy controls outbound connections.
type Policy struct {
	// AllowPrivate permits private and loopback ranges (development or explicitly
	// approved internal destinations only).
	AllowPrivate bool
	// AllowCIDRs permits specific internal ranges without opening all private space.
	AllowCIDRs []string
	// RequireHTTPS refuses plain http destinations.
	RequireHTTPS bool
	Timeout      time.Duration
	MaxBytes     int64
	// RootCAs replaces the system trust store (operator-supplied private CA for
	// internal identity providers); nil uses the system roots.
	RootCAs *x509.CertPool
}

var blocked = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"255.255.255.255/32", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	// Transition mechanisms that embed an IPv4 address the policy would
	// otherwise not see: 6to4, Teredo and local-use NAT64.
	"2002::/16", "2001::/32", "64:ff9b:1::/48",
}

var blockedPrefixes = func() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(blocked))
	for _, b := range blocked {
		out = append(out, netip.MustParsePrefix(b))
	}
	return out
}()

// residencyHosts, when set, is the deployment's destination residency policy
// (PRV-003): every outbound connector host must equal an entry or end with an
// entry that starts with a dot. It applies to every Policy.
var (
	residencyMu    sync.RWMutex
	residencyHosts []string
)

// SetResidency installs the destination residency policy; nil or empty
// removes it.
func SetResidency(hosts []string) {
	residencyMu.Lock()
	defer residencyMu.Unlock()
	residencyHosts = nil
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			residencyHosts = append(residencyHosts, h)
		}
	}
}

// ErrResidency is returned for a destination outside the residency policy.
var ErrResidency = fmt.Errorf("%w: outside the destination residency policy", ErrForbiddenDestination)

// HostAllowed reports whether a host name or address may be contacted under
// the residency policy.
func HostAllowed(host string) bool {
	residencyMu.RLock()
	defer residencyMu.RUnlock()
	if len(residencyHosts) == 0 {
		return true
	}
	return HostMatches(host, residencyHosts)
}

// HostMatches reports whether host equals an entry or lies under a ".suffix"
// entry of list.
func HostMatches(host string, list []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, r := range list {
		r = strings.ToLower(strings.TrimSpace(r))
		if host == strings.TrimPrefix(r, ".") || strings.HasPrefix(r, ".") && strings.HasSuffix(host, r) {
			return true
		}
	}
	return false
}

// Allowed reports whether ip may be contacted under the policy.
//
// A zone (fe80::1%eth0, fc00::%0) scopes an address to one link. netip
// prefixes never contain a zoned address, so comparing the address as given
// would let a zoned private or loopback literal past every blocked range
// (SEC-007; found by FuzzAllowed). The ranges are compared without the zone,
// and a zoned address is never public: it is reachable only with
// allow_private_network or an explicit CIDR.
func (p Policy) Allowed(ip netip.Addr) bool {
	zoned := ip.Zone() != ""
	ip = ip.Unmap().WithZone("")
	for _, c := range p.AllowCIDRs {
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil && pfx.Contains(ip) {
			return true
		}
	}
	if p.AllowPrivate {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	if zoned {
		return false
	}
	for _, b := range blockedPrefixes {
		if b.Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}

// ValidateURL checks a destination at registration time (scheme, userinfo, host).
func (p Policy) ValidateURL(raw string) error {
	return p.ValidateURLContext(context.Background(), raw)
}

// ValidateURLContext shares the caller's deadline with DNS validation.
func (p Policy) ValidateURLContext(ctx context.Context, raw string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: invalid URL", ErrForbiddenDestination)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || p.RequireHTTPS) {
		return fmt.Errorf("%w: scheme %s", ErrForbiddenDestination, u.Scheme)
	}
	host := u.Hostname()
	if !HostAllowed(host) {
		return ErrResidency
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !p.Allowed(ip) {
			return ErrForbiddenDestination
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("%w: cannot resolve host", ErrForbiddenDestination)
	}
	for _, a := range addrs {
		if !p.Allowed(a) {
			return ErrForbiddenDestination
		}
	}
	return nil
}

// Client returns an HTTP client enforcing the policy on every connection.
func (p Policy) Client() *http.Client {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // never route through ambient proxies that bypass the address policy
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !HostAllowed(host) {
				return nil, ErrResidency
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !p.Allowed(ip) {
					return nil, ErrForbiddenDestination
				}
			}
			var lastErr error = ErrForbiddenDestination
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSClientConfig:       &tls.Config{RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
	}
	return &http.Client{Transport: traceTransport{tr}, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// traceTransport propagates W3C trace context on outbound calls made while
// serving a request (API-012): only the traceparent header, never baggage,
// request identifiers or credentials.
type traceTransport struct{ next http.RoundTripper }

func (t traceTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t traceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	info := reqctx.From(r.Context())
	if r.Header.Get("traceparent") != "" || info.TraceID == "" || info.SpanID == "" {
		return t.next.RoundTrip(r)
	}
	if !info.Sampled || !tracing.Enabled() {
		r = r.Clone(r.Context())
		r.Header.Set("traceparent", info.Traceparent())
		return t.next.RoundTrip(r)
	}
	// A client span (OPS-003): the callee continues it; its attributes are
	// the method, host and status only, never paths, queries or headers.
	child := info
	child.SpanID = tracing.NewSpanID()
	r = r.Clone(r.Context())
	r.Header.Set("traceparent", child.Traceparent())
	start := time.Now()
	res, err := t.next.RoundTrip(r)
	span := tracing.Span{TraceID: info.TraceID, SpanID: child.SpanID, ParentID: info.SpanID, Name: r.Method, Kind: tracing.KindClient,
		Start: start, End: time.Now(), Status: tracing.StatusOK,
		Attributes: map[string]any{"http.request.method": r.Method, "server.address": r.URL.Hostname()}}
	if err != nil {
		span.Status = tracing.StatusError
	} else {
		span.Attributes["http.response.status_code"] = res.StatusCode
		if res.StatusCode >= 500 {
			span.Status = tracing.StatusError
		}
	}
	tracing.Export(span)
	return res, err
}

// ReadLimited reads at most MaxBytes from a response body.
func (p Policy) ReadLimited(r io.Reader) ([]byte, error) {
	max := p.MaxBytes
	if max <= 0 {
		max = 1 << 20
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("egress: response too large")
	}
	return b, nil
}
