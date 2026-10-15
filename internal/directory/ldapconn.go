package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/proudauth/proudauth/internal/egress"
)

// transportError marks a failure that says nothing about credentials or
// data: the endpoint could not be reached, did not complete TLS, timed out
// or reported itself unavailable. Only such failures move an operation to
// the next configured endpoint (PROV-014); an answer such as "invalid
// credentials" is final and is never retried elsewhere.
type transportError struct {
	endpoint string
	category string
	err      error
}

func (e *transportError) Error() string {
	return "directory endpoint " + e.endpoint + " unavailable (" + e.category + "): " + e.err.Error()
}

func (e *transportError) Unwrap() error { return e.err }

// errUnavailable is returned when every configured endpoint failed at the
// transport level.
var errUnavailable = errors.New("no configured directory endpoint is reachable")

// isTransport reports whether err is a transport failure and its category.
// Only errors the LDAP client layer classified (classify) count, so a
// failure of the caller's own work is never mistaken for an endpoint fault.
func isTransport(err error) (string, bool) {
	var te *transportError
	if errors.As(err, &te) {
		return te.category, true
	}
	return "", false
}

// classify turns an LDAP client error into a transportError when it says
// nothing about the request: a broken or closed connection, a timeout, a
// malformed response, or a server that reports itself busy or unavailable.
// A result code the server returned for the request itself (invalid
// credentials, no such object, insufficient access, ...) stays final.
func classify(endpoint string, err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	var te *transportError
	if errors.As(err, &te) {
		return err
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultBusy, ldap.LDAPResultUnavailable:
			return &transportError{endpoint, "server_unavailable", err}
		case ldap.LDAPResultTimeout:
			return &transportError{endpoint, "timeout", err}
		case ldap.ErrorFilterCompile, ldap.ErrorFilterDecompile, ldap.ErrorEmptyPassword, ldap.ErrorDebugging:
			return err
		}
		if le.ResultCode < ldap.ErrorNetwork && le.ResultCode != ldap.LDAPResultServerDown && le.ResultCode != ldap.LDAPResultConnectError {
			return err
		}
		if strings.Contains(strings.ToLower(le.Error()), "timed out") || strings.Contains(strings.ToLower(le.Error()), "timeout") {
			return &transportError{endpoint, "timeout", err}
		}
		return &transportError{endpoint, "network", err}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &transportError{endpoint, "timeout", err}
	}
	// Anything else from the client layer is a connection-level failure
	// (for example "unable to read LDAP response packet: EOF").
	return &transportError{endpoint, "network", err}
}

// conn is an open, TLS-protected directory connection.
type conn struct {
	l        *ldap.Conn
	endpoint string
	op       time.Duration
}

func (c *conn) close() { _ = c.l.Close() }

// bind binds as dn; the error is classified (classify).
func (c *conn) bind(dn, password string) error { return classify(c.endpoint, c.l.Bind(dn, password)) }

// modify runs a modify request; the error is classified.
func (c *conn) modify(req *ldap.ModifyRequest) error { return classify(c.endpoint, c.l.Modify(req)) }

func (s *Service) timeouts(cfg *LDAPConfig) (connect, op time.Duration) {
	connect, op = s.d.Cfg.Directory.ConnectTimeout, s.d.Cfg.Directory.OperationTimeout
	if cfg.ConnectTimeoutSeconds > 0 {
		connect = time.Duration(cfg.ConnectTimeoutSeconds) * time.Second
	}
	if cfg.OperationTimeoutSeconds > 0 {
		op = time.Duration(cfg.OperationTimeoutSeconds) * time.Second
	}
	if connect <= 0 {
		connect = 5 * time.Second
	}
	if op <= 0 {
		op = 10 * time.Second
	}
	return connect, op
}

// tlsConfig trusts the deployment roots plus the connector's own and
// verifies the endpoint's host name; no option disables verification.
func (s *Service) tlsConfig(cfg *LDAPConfig, host string) *tls.Config {
	pool := s.RootCAs
	if cfg.CACertificatesPEM != "" {
		if pool == nil {
			if sys, err := x509.SystemCertPool(); err == nil && sys != nil {
				pool = sys
			} else {
				pool = x509.NewCertPool()
			}
		} else {
			pool = pool.Clone()
		}
		pool.AppendCertsFromPEM([]byte(cfg.CACertificatesPEM))
	}
	return &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// dialEndpoint opens one endpoint. The address policy is checked against
// every resolved address at connection time, so a configured host name
// cannot be re-pointed into a forbidden network (TEST-052).
func (s *Service) dialEndpoint(ctx context.Context, cfg *LDAPConfig, endpoint string) (*conn, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, &transportError{endpoint, "invalid_endpoint", err}
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	connectTO, opTO := s.timeouts(cfg)
	if !egress.HostAllowed(host) {
		return nil, &transportError{endpoint, "egress_denied", egress.ErrResidency}
	}
	dctx, cancel := context.WithTimeout(ctx, connectTO)
	defer cancel()
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = net.DefaultResolver.LookupNetIP(dctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			return nil, &transportError{endpoint, "dns", fmt.Errorf("cannot resolve %s", host)}
		}
	}
	for _, a := range addrs {
		if !s.Egress.Allowed(a) {
			return nil, &transportError{endpoint, "egress_denied", egress.ErrForbiddenDestination}
		}
	}
	dialer := &net.Dialer{}
	var raw net.Conn
	var lastErr error = errUnavailable
	for _, a := range addrs {
		raw, lastErr = dialer.DialContext(dctx, "tcp", net.JoinHostPort(a.String(), port))
		if lastErr == nil {
			break
		}
	}
	if raw == nil {
		category := "connect"
		var ne net.Error
		if errors.As(lastErr, &ne) && ne.Timeout() {
			category = "timeout"
		}
		return nil, &transportError{endpoint, category, lastErr}
	}
	tlsCfg := s.tlsConfig(cfg, host)
	isTLS := u.Scheme == "ldaps"
	if isTLS {
		tc := tls.Client(raw, tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(connectTO))
		if err := tc.HandshakeContext(dctx); err != nil {
			_ = raw.Close()
			return nil, &transportError{endpoint, "tls", err}
		}
		_ = tc.SetDeadline(time.Time{})
		raw = tc
	}
	l := ldap.NewConn(raw, isTLS)
	l.Start()
	l.SetTimeout(opTO)
	if !isTLS && (cfg.StartTLS == nil || *cfg.StartTLS) {
		// The handshake is bounded: the deadline on the socket is cleared
		// once StartTLS returns, before the reader needs it unbounded.
		_ = raw.SetDeadline(time.Now().Add(connectTO + opTO))
		err := l.StartTLS(tlsCfg)
		_ = raw.SetDeadline(time.Time{})
		if err != nil {
			_ = l.Close()
			category := "tls"
			if c, ok := isTransport(classify(endpoint, err)); ok && c == "timeout" {
				category = "timeout"
			}
			return nil, &transportError{endpoint, category, err}
		}
	}
	return &conn{l: l, endpoint: endpoint, op: opTO}, nil
}

// withDirectory runs fn against the first endpoint that works, in the
// configured order. A transport failure (connect, TLS, timeout, server
// unavailable) — while connecting or inside fn — moves to the next
// configured endpoint; any other result is final. Referrals are never
// followed, so an operation never reaches a server that is not configured
// (PROV-014). serviceBind binds as the connector's service account first.
func (s *Service) withDirectory(ctx context.Context, c *Connector, serviceBind bool, fn func(*conn) error) error {
	cfg := c.ldap
	var password string
	if serviceBind {
		var err error
		if password, err = s.credential(c); err != nil {
			return fmt.Errorf("service credential unavailable: %w", err)
		}
	}
	var last error = errUnavailable
	for i, ep := range cfg.Endpoints {
		cn, err := s.dialEndpoint(ctx, cfg, ep)
		if err == nil {
			if serviceBind {
				if berr := cn.bind(cfg.BindDN, password); berr != nil {
					if cat, ok := isTransport(berr); ok {
						err = &transportError{ep, cat, berr}
					} else {
						cn.close()
						s.recordHealth(c, ep, "service_bind_failed")
						return fmt.Errorf("service bind refused by %s: %w", hostOf(ep), berr)
					}
					cn.close()
				}
			}
			if err == nil {
				ferr := fn(cn)
				cn.close()
				if ferr == nil {
					s.recordHealth(c, ep, "")
					return nil
				}
				cat, transport := isTransport(ferr)
				if !transport {
					s.recordHealth(c, ep, "")
					return ferr
				}
				err = &transportError{ep, cat, ferr}
			}
		}
		cat, _ := isTransport(err)
		s.recordHealth(c, ep, cat)
		last = err
		if i < len(cfg.Endpoints)-1 {
			s.m.failovers.Inc(cat)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("%w: %w", errUnavailable, last)
}

// searchPaged runs a search with the simple paged results control (RFC
// 2696), handing each page to fn. Referrals in results are ignored, never
// chased.
func (cn *conn) searchPaged(base string, scope int, filter string, attrs []string, pageSize int, fn func([]*ldap.Entry) error) error {
	paging := ldap.NewControlPaging(uint32(pageSize))
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, int(cn.op.Seconds()), false, filter, attrs, []ldap.Control{paging})
	for {
		res, err := cn.l.Search(req)
		if err != nil {
			return classify(cn.endpoint, err)
		}
		if err := fn(res.Entries); err != nil {
			return err
		}
		ctrl := ldap.FindControl(res.Controls, ldap.ControlTypePaging)
		pc, ok := ctrl.(*ldap.ControlPaging)
		if !ok || len(pc.Cookie) == 0 {
			return nil
		}
		paging.SetCookie(pc.Cookie)
	}
}

// searchOne runs a bounded search that must match at most limit entries.
func (cn *conn) search(base string, scope int, filter string, attrs []string, limit int) ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, limit, int(cn.op.Seconds()), false, filter, attrs, nil)
	res, err := cn.l.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) && res != nil {
			return res.Entries, nil
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, classify(cn.endpoint, err)
	}
	return res.Entries, nil
}

func scopeOf(s string) int {
	if s == "one" {
		return ldap.ScopeSingleLevel
	}
	return ldap.ScopeWholeSubtree
}

// idValue returns an entry's immutable identifier. Binary GUIDs are hex
// encoded; Active Directory's objectGUID is always binary.
func idValue(cfg *LDAPConfig, e *ldap.Entry) string {
	if strings.EqualFold(cfg.IDAttribute, "objectGUID") || strings.EqualFold(cfg.IDAttribute, "objectSid") {
		raw := e.GetEqualFoldRawAttributeValue(cfg.IDAttribute)
		if len(raw) == 0 {
			return ""
		}
		return hex.EncodeToString(raw)
	}
	return e.GetEqualFoldAttributeValue(cfg.IDAttribute)
}

// idFilter builds an equality assertion for a stored identifier. Every value
// placed in a filter is escaped (RFC 4515): binary identifiers byte by byte,
// text with ldap.EscapeFilter, so no stored or user-supplied value can change
// the filter's structure.
func idFilter(cfg *LDAPConfig, id string) string {
	if strings.EqualFold(cfg.IDAttribute, "objectGUID") || strings.EqualFold(cfg.IDAttribute, "objectSid") {
		raw, err := hex.DecodeString(id)
		if err != nil {
			return "(" + cfg.IDAttribute + "=\\00\\invalid)"
		}
		var b strings.Builder
		for _, x := range raw {
			fmt.Fprintf(&b, "\\%02x", x)
		}
		return "(" + cfg.IDAttribute + "=" + b.String() + ")"
	}
	return "(" + cfg.IDAttribute + "=" + ldap.EscapeFilter(id) + ")"
}

// loginFilter matches a sign-in identifier against the login attributes
// within the user filter. The identifier is user input: it is escaped, never
// interpolated raw (RFC 4515).
func loginFilter(cfg *LDAPConfig, identifier string) string {
	esc := ldap.EscapeFilter(identifier)
	var b strings.Builder
	b.WriteString("(&")
	b.WriteString(cfg.UserFilter)
	b.WriteString("(|")
	for _, a := range cfg.LoginAttributes {
		b.WriteString("(" + a + "=" + esc + ")")
	}
	b.WriteString("))")
	return b.String()
}

// userAttributes lists the attributes a user search requests.
func userAttributes(cfg *LDAPConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a != "" && !seen[strings.ToLower(a)] {
			seen[strings.ToLower(a)] = true
			out = append(out, a)
		}
	}
	add(cfg.IDAttribute)
	for _, a := range cfg.AttributeMapping {
		add(a)
	}
	for _, a := range cfg.LoginAttributes {
		add(a)
	}
	if cfg.Dialect == DialectActiveDirectory {
		add("userAccountControl")
		add("uSNChanged")
	}
	add(cfg.DisabledAttribute)
	add("modifyTimestamp")
	return out
}

// disabled reports whether a directory entry is disabled: Active Directory's
// ACCOUNTDISABLE bit, or the configured attribute.
func disabled(cfg *LDAPConfig, e *ldap.Entry) bool {
	if cfg.Dialect == DialectActiveDirectory {
		var uac int64
		if _, err := fmt.Sscan(e.GetEqualFoldAttributeValue("userAccountControl"), &uac); err == nil && uac&0x2 != 0 {
			return true
		}
	}
	if cfg.DisabledAttribute != "" {
		vals := e.GetEqualFoldAttributeValues(cfg.DisabledAttribute)
		if len(vals) == 0 {
			return false
		}
		if len(cfg.DisabledValues) == 0 {
			return true
		}
		for _, v := range vals {
			for _, d := range cfg.DisabledValues {
				if strings.EqualFold(v, d) {
					return true
				}
			}
		}
	}
	return false
}

// rootDSE reads the server's identity and change marker (Active Directory:
// dsServiceName and highestCommittedUSN).
func (cn *conn) rootDSE() (server string, usn int64, err error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(cn.op.Seconds()), false, "(objectClass=*)",
		[]string{"dsServiceName", "highestCommittedUSN", "serverName"}, nil)
	res, err := cn.l.Search(req)
	if err != nil {
		return "", 0, classify(cn.endpoint, err)
	}
	if len(res.Entries) == 0 {
		return "", 0, errors.New("root DSE not readable")
	}
	e := res.Entries[0]
	server = e.GetAttributeValue("dsServiceName")
	if server == "" {
		server = e.GetAttributeValue("serverName")
	}
	if v := e.GetAttributeValue("highestCommittedUSN"); v != "" {
		_, _ = fmt.Sscan(v, &usn)
	}
	return server, usn, nil
}
