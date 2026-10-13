// Package ldaptest runs a small in-process LDAP v3 server for tests of the
// directory integration (PROV-011..PROV-014): simple binds, searches with
// RFC 4515 filters and the simple paged results control, modify, StartTLS
// and LDAPS, Active Directory style uSNChanged/highestCommittedUSN change
// tracking, and fault injection (outage, latency). It is test tooling only:
// passwords are kept in memory in plain text.
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Entry is one directory object.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Get returns an attribute's values (case-insensitive name).
func (e *Entry) Get(name string) []string {
	for k, v := range e.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func (e *Entry) set(name string, vals []string) {
	for k := range e.Attrs {
		if strings.EqualFold(k, name) {
			delete(e.Attrs, k)
		}
	}
	if len(vals) > 0 {
		e.Attrs[name] = vals
	}
}

// Server is an in-process LDAP server.
type Server struct {
	// ServerName is reported as dsServiceName in the root DSE.
	ServerName string
	// Delay is added before every response (timeout tests).
	Delay time.Duration

	mu        sync.Mutex
	entries   map[string]*Entry
	passwords map[string]string
	writers   map[string]bool
	usn       int64
	ln        net.Listener
	tlsLn     net.Listener
	tlsConfig *tls.Config
	caPEM     []byte
	conns     map[net.Conn]bool
	down      bool
	// Filters records every search filter received (decompiled), so tests
	// can assert that user input arrived escaped (RFC 4515).
	Filters  []string
	Binds    int
	Searches int
	Modifies []string
}

// New starts a server on 127.0.0.1 with a plain listener and an LDAPS
// listener sharing one generated certificate authority.
func New() (*Server, error) {
	s := &Server{ServerName: "CN=NTDS Settings,CN=DC1", entries: map[string]*Entry{}, passwords: map[string]string{}, writers: map[string]bool{},
		conns: map[net.Conn]bool{}, usn: 1000}
	if err := s.makeTLS(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.ln = ln
	tln, err := tls.Listen("tcp", "127.0.0.1:0", s.tlsConfig)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	s.tlsLn = tln
	go s.accept(ln, false)
	go s.accept(tln, true)
	return s, nil
}

// URL is the ldap:// endpoint (StartTLS capable).
func (s *Server) URL() string { return "ldap://" + s.ln.Addr().String() }

// LDAPSURL is the ldaps:// endpoint.
func (s *Server) LDAPSURL() string { return "ldaps://" + s.tlsLn.Addr().String() }

// CAPEM is the PEM of the certificate authority that issued the server
// certificate.
func (s *Server) CAPEM() string { return string(s.caPEM) }

// Close stops the server.
func (s *Server) Close() {
	s.SetDown(true)
	_ = s.ln.Close()
	_ = s.tlsLn.Close()
}

// SetDown simulates an outage: open connections are dropped and new ones
// are closed at once.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	s.down = down
	var open []net.Conn
	if down {
		for c := range s.conns {
			open = append(open, c)
		}
	}
	s.mu.Unlock()
	for _, c := range open {
		_ = c.Close()
	}
}

func norm(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	var parts []string
	for _, rdn := range parsed.RDNs {
		var avas []string
		for _, a := range rdn.Attributes {
			avas = append(avas, strings.ToLower(a.Type)+"="+strings.ToLower(a.Value))
		}
		sort.Strings(avas)
		parts = append(parts, strings.Join(avas, "+"))
	}
	return strings.Join(parts, ",")
}

// Add stores an entry (replacing one with the same DN) and bumps the USN.
func (s *Server) Add(dn string, attrs map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &Entry{DN: dn, Attrs: map[string][]string{}}
	for k, v := range attrs {
		e.Attrs[k] = append([]string(nil), v...)
	}
	s.touch(e)
	s.entries[norm(dn)] = e
}

// touch records a change on an entry (caller holds mu).
func (s *Server) touch(e *Entry) {
	s.usn++
	e.set("uSNChanged", []string{strconv.FormatInt(s.usn, 10)})
	e.set("modifyTimestamp", []string{time.Now().UTC().Format("20060102150405Z")})
}

// Update changes attributes of an entry (nil values delete) and bumps the
// USN.
func (s *Server) Update(dn string, attrs map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[norm(dn)]
	if e == nil {
		return
	}
	for k, v := range attrs {
		e.set(k, v)
	}
	s.touch(e)
}

// Delete removes an entry.
func (s *Server) Delete(dn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, norm(dn))
}

// Entry returns a copy of an entry.
func (s *Server) Entry(dn string) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[norm(dn)]
	if e == nil {
		return nil
	}
	c := &Entry{DN: e.DN, Attrs: map[string][]string{}}
	for k, v := range e.Attrs {
		c.Attrs[k] = append([]string(nil), v...)
	}
	return c
}

// SetPassword sets the password a DN binds with; writer allows modify.
func (s *Server) SetPassword(dn, password string, writer bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwords[norm(dn)] = password
	if writer {
		s.writers[norm(dn)] = true
	}
}

// ResetCounters clears the request records.
func (s *Server) ResetCounters() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Filters, s.Binds, s.Searches, s.Modifies = nil, 0, 0, nil
}

// Stats returns request counters.
func (s *Server) Stats() (binds, searches int, filters []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Binds, s.Searches, append([]string(nil), s.Filters...)
}

func (s *Server) accept(ln net.Listener, isTLS bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.down {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.conns[c] = true
		s.mu.Unlock()
		go s.serve(c, isTLS)
	}
}

// session is one client connection.
type session struct {
	s     *Server
	c     net.Conn
	bound string
	isTLS bool
}

func (s *Server) serve(c net.Conn, isTLS bool) {
	ss := &session{s: s, c: c, isTLS: isTLS}
	defer func() {
		s.mu.Lock()
		delete(s.conns, ss.c)
		s.mu.Unlock()
		_ = ss.c.Close()
	}()
	for {
		p, err := ber.ReadPacket(ss.c)
		if err != nil {
			return
		}
		if len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		var controls []ldap.Control
		if len(p.Children) > 2 {
			for _, ch := range p.Children[2].Children {
				if ctl, err := ldap.DecodeControl(ch); err == nil {
					controls = append(controls, ctl)
				}
			}
		}
		if s.Delay > 0 {
			time.Sleep(s.Delay)
		}
		s.mu.Lock()
		down := s.down
		s.mu.Unlock()
		if down {
			return
		}
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			ss.bind(id, op)
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationSearchRequest:
			ss.search(id, op, controls)
		case ldap.ApplicationModifyRequest:
			ss.modify(id, op)
		case ldap.ApplicationExtendedRequest:
			if !ss.extended(id, op) {
				return
			}
		case ldap.ApplicationAbandonRequest:
		default:
			ss.result(id, ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError, "unsupported operation")
		}
	}
}

func envelope(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	return p
}

func ldapResult(app ber.Tag, code uint16, diag string) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "Result")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	return r
}

func (ss *session) send(p *ber.Packet) {
	_, _ = ss.c.Write(p.Bytes())
}

func (ss *session) result(id int64, app ber.Tag, code uint16, diag string) {
	p := envelope(id)
	p.AppendChild(ldapResult(app, code, diag))
	ss.send(p)
}

func str(p *ber.Packet) string {
	if p == nil {
		return ""
	}
	if v, ok := p.Value.(string); ok {
		return v
	}
	if p.Data != nil {
		return p.Data.String()
	}
	return ""
}

func (ss *session) bind(id int64, op *ber.Packet) {
	s := ss.s
	if len(op.Children) < 3 {
		ss.result(id, ldap.ApplicationBindResponse, ldap.LDAPResultProtocolError, "malformed bind")
		return
	}
	name := str(op.Children[1])
	password := ""
	if op.Children[2].Data != nil {
		password = op.Children[2].Data.String()
	}
	s.mu.Lock()
	s.Binds++
	want, known := s.passwords[norm(name)]
	s.mu.Unlock()
	switch {
	case name == "" && password == "":
		ss.bound = ""
		ss.result(id, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "")
	case password == "":
		// RFC 4513 §5.1.2: an unauthenticated bind; this server refuses it
		// (a client that sent one would be a bug).
		ss.result(id, ldap.ApplicationBindResponse, ldap.LDAPResultUnwillingToPerform, "unauthenticated bind refused")
	case known && want == password:
		ss.bound = norm(name)
		ss.result(id, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "")
	default:
		ss.bound = ""
		ss.result(id, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "80090308: LdapErr: DSID-0C09044E, data 52e")
	}
}

func (ss *session) extended(id int64, op *ber.Packet) bool {
	name := ""
	if len(op.Children) > 0 {
		name = str(op.Children[0])
	}
	if name != "1.3.6.1.4.1.1466.20037" || ss.isTLS {
		ss.result(id, ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError, "unsupported extended operation")
		return true
	}
	ss.result(id, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess, "")
	tc := tls.Server(ss.c, ss.s.tlsConfig)
	if err := tc.Handshake(); err != nil {
		return false
	}
	ss.s.mu.Lock()
	delete(ss.s.conns, ss.c)
	ss.s.conns[tc] = true
	ss.s.mu.Unlock()
	ss.c, ss.isTLS = tc, true
	return true
}

func (ss *session) modify(id int64, op *ber.Packet) {
	s := ss.s
	if len(op.Children) < 2 {
		ss.result(id, ldap.ApplicationModifyResponse, ldap.LDAPResultProtocolError, "malformed modify")
		return
	}
	dn := str(op.Children[0])
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss.bound == "" || !s.writers[ss.bound] {
		p := envelope(id)
		p.AppendChild(ldapResult(ldap.ApplicationModifyResponse, ldap.LDAPResultInsufficientAccessRights, "write access denied"))
		ss.send(p)
		return
	}
	e := s.entries[norm(dn)]
	if e == nil {
		p := envelope(id)
		p.AppendChild(ldapResult(ldap.ApplicationModifyResponse, ldap.LDAPResultNoSuchObject, "no such object"))
		ss.send(p)
		return
	}
	for _, ch := range op.Children[1].Children {
		if len(ch.Children) < 2 || len(ch.Children[1].Children) < 1 {
			continue
		}
		kind, _ := ch.Children[0].Value.(int64)
		attr := str(ch.Children[1].Children[0])
		var vals []string
		if len(ch.Children[1].Children) > 1 {
			for _, v := range ch.Children[1].Children[1].Children {
				vals = append(vals, str(v))
			}
		}
		switch kind {
		case 0: // add
			e.set(attr, append(e.Get(attr), vals...))
		case 1: // delete
			e.set(attr, nil)
		case 2: // replace
			e.set(attr, vals)
		}
		s.Modifies = append(s.Modifies, attr)
	}
	s.touch(e)
	p := envelope(id)
	p.AppendChild(ldapResult(ldap.ApplicationModifyResponse, ldap.LDAPResultSuccess, ""))
	ss.send(p)
}

func (ss *session) search(id int64, op *ber.Packet, controls []ldap.Control) {
	s := ss.s
	if len(op.Children) < 8 {
		ss.result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError, "malformed search")
		return
	}
	base := str(op.Children[0])
	scope, _ := op.Children[1].Value.(int64)
	sizeLimit, _ := op.Children[3].Value.(int64)
	filter := op.Children[6]
	var attrs []string
	for _, a := range op.Children[7].Children {
		attrs = append(attrs, str(a))
	}
	fs, _ := ldap.DecompileFilter(filter)
	s.mu.Lock()
	s.Searches++
	s.Filters = append(s.Filters, fs)
	bound := ss.bound
	var root *Entry
	if base == "" && scope == ldap.ScopeBaseObject {
		root = &Entry{DN: "", Attrs: map[string][]string{"highestCommittedUSN": {strconv.FormatInt(s.usn, 10)}, "dsServiceName": {s.ServerName},
			"supportedControl": {ldap.ControlTypePaging}, "supportedExtension": {"1.3.6.1.4.1.1466.20037"}}}
	}
	var matched []*Entry
	if root != nil {
		matched = []*Entry{root}
	} else if bound != "" {
		b := norm(base)
		for k, e := range s.entries {
			inScope := false
			switch scope {
			case ldap.ScopeBaseObject:
				inScope = k == b
			case ldap.ScopeSingleLevel:
				inScope = strings.HasSuffix(k, ","+b) && strings.Count(k, ",") == strings.Count(b, ",")+1
			default:
				inScope = k == b || strings.HasSuffix(k, ","+b)
			}
			if inScope && match(filter, e) {
				matched = append(matched, e)
			}
		}
		sort.Slice(matched, func(i, j int) bool { return norm(matched[i].DN) < norm(matched[j].DN) })
	}
	var copies []*Entry
	for _, e := range matched {
		c := &Entry{DN: e.DN, Attrs: map[string][]string{}}
		for k, v := range e.Attrs {
			c.Attrs[k] = append([]string(nil), v...)
		}
		copies = append(copies, c)
	}
	_, baseExists := s.entries[norm(base)]
	s.mu.Unlock()
	if root == nil && bound == "" {
		ss.result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights, "bind first")
		return
	}
	if root == nil && !baseExists {
		ss.result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultNoSuchObject, "no such object")
		return
	}
	// Simple paged results (RFC 2696): the cookie is the offset.
	var paging *ldap.ControlPaging
	if c, ok := ldap.FindControl(controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok {
		paging = c
	}
	start, end := 0, len(copies)
	if paging != nil && paging.PagingSize > 0 {
		if len(paging.Cookie) > 0 {
			start, _ = strconv.Atoi(string(paging.Cookie))
		}
		end = min(start+int(paging.PagingSize), len(copies))
		start = min(start, end)
	}
	code := uint16(ldap.LDAPResultSuccess)
	if sizeLimit > 0 && int64(end-start) > sizeLimit {
		end, code = start+int(sizeLimit), ldap.LDAPResultSizeLimitExceeded
	}
	for _, e := range copies[start:end] {
		p := envelope(id)
		re := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Entry")
		re.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "DN"))
		list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
		names := make([]string, 0, len(e.Attrs))
		for k := range e.Attrs {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if !wanted(attrs, k) {
				continue
			}
			a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
			a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, "Type"))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
			for _, v := range e.Attrs[k] {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Value"))
			}
			a.AppendChild(set)
			list.AppendChild(a)
		}
		re.AppendChild(list)
		p.AppendChild(re)
		ss.send(p)
	}
	p := envelope(id)
	p.AppendChild(ldapResult(ldap.ApplicationSearchResultDone, code, ""))
	if paging != nil {
		resp := ldap.NewControlPaging(0)
		if end < len(copies) {
			resp.SetCookie([]byte(strconv.Itoa(end)))
		}
		ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		ctls.AppendChild(resp.Encode())
		p.AppendChild(ctls)
	}
	ss.send(p)
}

func wanted(attrs []string, name string) bool {
	if len(attrs) == 0 {
		return true
	}
	for _, a := range attrs {
		if a == "*" || strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

// match evaluates an RFC 4511 filter against an entry.
func match(f *ber.Packet, e *Entry) bool {
	switch f.Tag {
	case ldap.FilterAnd:
		for _, c := range f.Children {
			if !match(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range f.Children {
			if match(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(f.Children) == 1 && !match(f.Children[0], e)
	case ldap.FilterPresent:
		return len(e.Get(f.Data.String())) > 0 || strings.EqualFold(f.Data.String(), "objectClass")
	case ldap.FilterEqualityMatch, ldap.FilterApproxMatch:
		if len(f.Children) < 2 {
			return false
		}
		attr, val := str(f.Children[0]), str(f.Children[1])
		for _, v := range e.Get(attr) {
			if equalValue(attr, v, val) {
				return true
			}
		}
		return false
	case ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		if len(f.Children) < 2 {
			return false
		}
		attr, val := str(f.Children[0]), str(f.Children[1])
		for _, v := range e.Get(attr) {
			c := compare(v, val)
			if (f.Tag == ldap.FilterGreaterOrEqual && c >= 0) || (f.Tag == ldap.FilterLessOrEqual && c <= 0) {
				return true
			}
		}
		return false
	case ldap.FilterSubstrings:
		if len(f.Children) < 2 {
			return false
		}
		attr := str(f.Children[0])
		for _, v := range e.Get(attr) {
			if substrings(strings.ToLower(v), f.Children[1].Children) {
				return true
			}
		}
		return false
	}
	return false
}

func equalValue(attr, a, b string) bool {
	if strings.EqualFold(attr, "objectGUID") || strings.EqualFold(attr, "objectSid") {
		return a == b
	}
	return strings.EqualFold(a, b)
}

func compare(a, b string) int {
	x, err1 := strconv.ParseInt(a, 10, 64)
	y, err2 := strconv.ParseInt(b, 10, 64)
	if err1 == nil && err2 == nil {
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

func substrings(v string, parts []*ber.Packet) bool {
	pos := 0
	for _, p := range parts {
		sub := strings.ToLower(p.Data.String())
		switch p.Tag {
		case 0: // initial
			if !strings.HasPrefix(v, sub) {
				return false
			}
			pos = len(sub)
		case 1: // any
			i := strings.Index(v[pos:], sub)
			if i < 0 {
				return false
			}
			pos += i + len(sub)
		case 2: // final
			if !strings.HasSuffix(v[pos:], sub) {
				return false
			}
		}
	}
	return true
}

// makeTLS creates a CA and a server certificate for 127.0.0.1/localhost.
func (s *Server) makeTLS() error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ldaptest CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	return nil
}
