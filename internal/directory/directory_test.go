package directory

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/directory/ldaptest"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
)

func testService(t *testing.T) *Service {
	t.Helper()
	cfg := configuration.Defaults()
	cfg.Mode = configuration.ModeDevelopment
	cfg.Directory.AllowPrivateNetwork = true
	cfg.Directory.ConnectTimeout = 2 * time.Second
	cfg.Directory.OperationTimeout = 2 * time.Second
	d := &runtime.Deps{Cfg: &cfg, Clock: clock.NewFake(time.Now()), Keys: keys.NewRandom()}
	s := &Service{d: d, health: map[string]*endpointHealth{}, m: newMetrics(observability.NewRegistry())}
	s.Egress.AllowPrivate = true
	return s
}

func testConnector(t *testing.T, s *Service, cfg *LDAPConfig, password string) *Connector {
	t.Helper()
	if perr := cfg.normalize(false, false); perr != nil {
		t.Fatalf("normalize: %v", perr)
	}
	c := &Connector{ID: "con_test", Kind: KindLDAP, State: "active", ldap: cfg}
	ct, _, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(password), credentialAAD(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	c.secretCT = ct
	return c
}

func directoryServer(t *testing.T) *ldaptest.Server {
	t.Helper()
	srv, err := ldaptest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.Add("dc=corp,dc=test", map[string][]string{"objectClass": {"domain"}})
	srv.Add("cn=svc,dc=corp,dc=test", map[string][]string{"objectClass": {"person"}})
	srv.SetPassword("cn=svc,dc=corp,dc=test", "service secret", true)
	srv.Add("uid=alice,dc=corp,dc=test", map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "entryUUID": {"u-alice"},
		"mail": {"alice@corp.test"}})
	srv.SetPassword("uid=alice,dc=corp,dc=test", "alice password", false)
	return srv
}

// closedPort returns an address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestFiltersEscapeInput: user input never changes a filter's structure
// (RFC 4515).
func TestFiltersEscapeInput(t *testing.T) {
	cfg := &LDAPConfig{UserFilter: "(objectClass=inetOrgPerson)", LoginAttributes: []string{"uid", "mail"}, IDAttribute: "entryUUID"}
	f := loginFilter(cfg, "*)(uid=*))(|(uid=*")
	if strings.Contains(f, "*)(") || !strings.Contains(f, `\2a\29\28uid=\2a\29\29\28|\28uid=\2a`) {
		t.Fatalf("identifier not escaped: %s", f)
	}
	pkt, err := ldap.CompileFilter(f)
	if err != nil {
		t.Fatalf("escaped filter does not compile: %v", err)
	}
	if len(pkt.Children) != 2 || len(pkt.Children[1].Children) != 2 {
		t.Fatalf("filter structure changed by input: %s", f)
	}
	ad := &LDAPConfig{IDAttribute: "objectGUID"}
	if got := idFilter(ad, "0aff2a29"); got != `(objectGUID=\0a\ff\2a\29)` {
		t.Fatalf("binary id filter: %s", got)
	}
	if got := idFilter(cfg, "x)(uid=*"); got != `(entryUUID=x\29\28uid=\2a)` {
		t.Fatalf("text id filter: %s", got)
	}
}

// TestLDAPConfigRules covers the configuration rules of PROV-011/PROV-013.
func TestLDAPConfigRules(t *testing.T) {
	base := func() *LDAPConfig {
		return &LDAPConfig{Endpoints: []string{"ldap://dc1.corp.test"}, BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
	}
	c := base()
	c.StartTLS = boolp(false)
	if perr := c.normalize(false, true); perr == nil || perr.Fields["config.start_tls"] == "" {
		t.Fatalf("cleartext ldap:// accepted in production: %v", perr)
	}
	if perr := c.normalize(false, false); perr != nil {
		t.Fatalf("cleartext ldap:// refused in development: %v", perr)
	}
	c = base()
	c.WriteBackAttributes = []string{"display_name"}
	if perr := c.normalize(false, false); perr == nil {
		t.Fatal("write-back attributes accepted outside write_back mode")
	}
	c = base()
	c.Mode, c.WriteBackAttributes = ModeWriteBack, []string{"email"}
	if perr := c.normalize(false, false); perr == nil {
		t.Fatal("identifier write-back accepted")
	}
	c = base()
	c.UserFilter = "(uid=*"
	if perr := c.normalize(false, false); perr == nil {
		t.Fatal("malformed filter accepted")
	}
	c = base()
	c.Endpoints = []string{"ldap://user:pw@dc1.corp.test"}
	if perr := c.normalize(false, false); perr == nil {
		t.Fatal("credentials in an endpoint URL accepted")
	}
	c = base()
	c.JITProvisioning = true
	if perr := c.normalize(true, false); perr == nil {
		t.Fatal("an organization directory may not receive first sign-in attempts")
	}
	c = base()
	c.Dialect = DialectActiveDirectory
	if perr := c.normalize(true, false); perr != nil {
		t.Fatal(perr)
	}
	if c.IDAttribute != "objectGUID" || c.ChangeTracking != "usn" || c.AttributeMapping["username"] != "sAMAccountName" || c.DeprovisionAction != "remove_membership" {
		t.Fatalf("Active Directory defaults: %+v", c)
	}
	c = base()
	c.Mode, c.WriteBackAttributes, c.AttributeAuthority = ModeWriteBack, []string{"display_name"}, map[string]string{"family_name": AuthorityLocal}
	if perr := c.normalize(false, false); perr != nil {
		t.Fatal(perr)
	}
	for attr, want := range map[string]string{"display_name": AuthorityWriteBack, "given_name": AuthorityDirectory, "family_name": AuthorityLocal,
		"locale": AuthorityLocal, "username": AuthorityDirectory} {
		if got := c.authority(attr); got != want {
			t.Errorf("authority(%s) = %s, want %s", attr, got, want)
		}
	}
	c.Mode, c.WriteBackAttributes = ModeImportOnly, nil
	if c.authority("display_name") != AuthorityLocal {
		t.Fatal("import_only attributes are locally owned")
	}
}

// TestFailoverOnTransportErrorsOnly: an unreachable endpoint moves the
// operation to the next configured one; a refusal is final (PROV-014).
func TestFailoverOnTransportErrorsOnly(t *testing.T) {
	s := testService(t)
	srv := directoryServer(t)
	cfg := &LDAPConfig{Endpoints: []string{"ldap://" + closedPort(t), srv.URL()}, StartTLS: boolp(false), BindDN: "cn=svc,dc=corp,dc=test",
		UserBaseDN: "dc=corp,dc=test"}
	c := testConnector(t, s, cfg, "service secret")
	var used string
	if err := s.withDirectory(context.Background(), c, true, func(cn *conn) error { used = cn.endpoint; return nil }); err != nil {
		t.Fatalf("failover: %v", err)
	}
	if used != srv.URL() {
		t.Fatalf("used %s", used)
	}
	// A wrong service password on the first endpoint is not retried on the
	// second, which would accept it.
	other := directoryServer(t)
	other.SetPassword("cn=svc,dc=corp,dc=test", "other secret", true)
	cfg2 := &LDAPConfig{Endpoints: []string{srv.URL(), other.URL()}, StartTLS: boolp(false), BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
	c2 := testConnector(t, s, cfg2, "other secret")
	err := s.withDirectory(context.Background(), c2, true, func(cn *conn) error { return nil })
	if err == nil || errors.Is(err, errUnavailable) || !strings.Contains(err.Error(), "service bind refused") {
		t.Fatalf("refusal must be final: %v", err)
	}
	if b, _, _ := other.Stats(); b != 0 {
		t.Fatalf("second endpoint was asked after a refusal (%d binds)", b)
	}
	// Every endpoint down: unavailable, never another source.
	srv.SetDown(true)
	cfg3 := &LDAPConfig{Endpoints: []string{"ldap://" + closedPort(t), srv.URL()}, StartTLS: boolp(false), BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
	c3 := testConnector(t, s, cfg3, "service secret")
	if err := s.withDirectory(context.Background(), c3, true, func(cn *conn) error { return nil }); !errors.Is(err, errUnavailable) {
		t.Fatalf("outage: %v", err)
	}
}

// TestTLS: LDAPS and StartTLS verify the server against the configured
// roots; an untrusted certificate is a transport failure, never a downgrade.
func TestTLS(t *testing.T) {
	s := testService(t)
	srv := directoryServer(t)
	for _, ep := range []string{srv.LDAPSURL(), srv.URL()} {
		cfg := &LDAPConfig{Endpoints: []string{ep}, CACertificatesPEM: srv.CAPEM(), BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
		c := testConnector(t, s, cfg, "service secret")
		var encrypted bool
		if err := s.withDirectory(context.Background(), c, true, func(cn *conn) error {
			_, encrypted = cn.l.TLSConnectionState()
			return nil
		}); err != nil || !encrypted {
			t.Fatalf("%s: tls %v err %v", ep, encrypted, err)
		}
		untrusted := &LDAPConfig{Endpoints: []string{ep}, BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test"}
		cu := testConnector(t, s, untrusted, "service secret")
		err := s.withDirectory(context.Background(), cu, true, func(cn *conn) error { return nil })
		if cat, _ := isTransport(err); !errors.Is(err, errUnavailable) || (cat != "tls" && !strings.Contains(err.Error(), "tls")) {
			t.Fatalf("%s: untrusted certificate accepted or misreported: %v", ep, err)
		}
	}
}

// TestOperationTimeout: a server that stops answering is a transport
// failure after the operation timeout.
func TestOperationTimeout(t *testing.T) {
	s := testService(t)
	srv := directoryServer(t)
	srv.Delay = 1500 * time.Millisecond
	cfg := &LDAPConfig{Endpoints: []string{srv.URL()}, StartTLS: boolp(false), BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test",
		OperationTimeoutSeconds: 1}
	c := testConnector(t, s, cfg, "service secret")
	start := time.Now()
	err := s.withDirectory(context.Background(), c, true, func(cn *conn) error { return nil })
	if !errors.Is(err, errUnavailable) || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %v after %s", err, time.Since(start))
	}
}

// TestPagedSearch reads every page through the paged results control.
func TestPagedSearch(t *testing.T) {
	s := testService(t)
	srv := directoryServer(t)
	for i := 0; i < 25; i++ {
		id := "u" + string(rune('a'+i))
		srv.Add("uid="+id+",dc=corp,dc=test", map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {id}, "entryUUID": {"id-" + id}})
	}
	cfg := &LDAPConfig{Endpoints: []string{srv.URL()}, StartTLS: boolp(false), BindDN: "cn=svc,dc=corp,dc=test", UserBaseDN: "dc=corp,dc=test", PageSize: 10}
	c := testConnector(t, s, cfg, "service secret")
	pages, total := 0, 0
	err := s.withDirectory(context.Background(), c, true, func(cn *conn) error {
		return cn.searchPaged(cfg.UserBaseDN, ldap.ScopeWholeSubtree, cfg.UserFilter, userAttributes(cfg), cfg.PageSize, func(es []*ldap.Entry) error {
			pages++
			total += len(es)
			return nil
		})
	})
	if err != nil || total != 26 || pages != 3 {
		t.Fatalf("paged search: %d entries in %d pages, %v", total, pages, err)
	}
}

// TestClassify: only connection-level failures move to another endpoint;
// answers about the request are final (PROV-014).
func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		err       error
		transport bool
	}{
		{ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid")), false},
		{ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied")), false},
		{ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("none")), false},
		{ldap.NewError(ldap.LDAPResultBusy, errors.New("busy")), true},
		{ldap.NewError(ldap.LDAPResultUnavailable, errors.New("unavailable")), true},
		{ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: connection timed out")), true},
		{errors.New("unable to read LDAP response packet: EOF"), true},
		{ldap.NewError(ldap.ErrorFilterCompile, errors.New("bad filter")), false},
		{context.Canceled, false},
	} {
		_, transport := isTransport(classify("ldap://x", tc.err))
		if transport != tc.transport {
			t.Errorf("%v: transport %v, want %v", tc.err, transport, tc.transport)
		}
	}
}

func TestNormDN(t *testing.T) {
	if normDN("CN=Jane Doe, OU=People,DC=Corp,DC=Test") != normDN("cn=jane doe,ou=people,dc=corp,dc=test") {
		t.Fatal("DN comparison is not case- and space-insensitive")
	}
	if normDN("cn=a,dc=x") == normDN("cn=b,dc=x") {
		t.Fatal("different DNs compare equal")
	}
}

// TestOutboundDocument: externalId is always the account ID and only
// verified emails leave the identity domain.
func TestOutboundDocument(t *testing.T) {
	cfg := &OutboundConfig{BaseURL: "https://127.0.0.1/v2", AllowPrivateNetwork: true}
	if perr := cfg.normalize(true, egress.Policy{AllowPrivate: true}); perr != nil {
		t.Fatal(perr)
	}
	now := time.Now()
	u := &identity.User{ID: "usr_1", DisplayName: "Jane", Identifiers: []identity.Identifier{{Type: "email", Value: "jane@corp.test", IsPrimary: true},
		{Type: "username", Value: "jane"}}}
	doc := buildUserDoc(cfg, u, true)
	if doc["externalId"] != "usr_1" || doc["emails"] != nil || doc["userName"] != "jane" || doc["active"] != true {
		t.Fatalf("document: %v", doc)
	}
	u.Identifiers[0].VerifiedAt = &now
	if doc := buildUserDoc(cfg, u, false); doc["emails"] == nil || doc["active"] != false {
		t.Fatalf("verified email or inactive state missing: %v", doc)
	}
	cfg2 := &OutboundConfig{BaseURL: "https://127.0.0.1/v2", AllowPrivateNetwork: true, AttributeMapping: map[string]string{"userName": "email", "externalId": "email"}}
	if perr := cfg2.normalize(false, egress.Policy{AllowPrivate: true}); perr != nil || cfg2.AttributeMapping["externalId"] != "user_id" {
		t.Fatalf("externalId mapping must stay the account ID: %v %v", perr, cfg2.AttributeMapping)
	}
	if attrs := driftAttributes(map[string]any{"userName": "Jane", "active": true, "name": map[string]any{"givenName": "J"}},
		map[string]any{"userName": "jane", "active": false, "name": map[string]any{"givenName": "J"}}); len(attrs) != 1 || attrs[0] != "active" {
		t.Fatalf("drift: %v", attrs)
	}
}

// TestConnectorMaxEntriesBound: a connector's max_entries can only lower
// directory.max_entries_per_run. A higher value is refused when it is saved
// and clamped when a run executes; an update that keeps a value the
// operator has since lowered the bound below still goes through.
func TestConnectorMaxEntriesBound(t *testing.T) {
	s := testService(t)
	s.d.Cfg.Directory.MaxEntriesPerRun = 1000
	for _, tc := range []struct{ own, want int }{{0, 1000}, {10, 10}, {1000, 1000}, {5000, 1000}} {
		if got := s.maxEntries(&LDAPConfig{MaxEntries: tc.own}); got != tc.want {
			t.Errorf("max_entries %d: effective %d, want %d", tc.own, got, tc.want)
		}
	}
	if err := s.checkMaxEntries(&LDAPConfig{MaxEntries: 5000}, nil); err == nil || !strings.Contains(err.Error(), "max_entries") {
		t.Fatalf("max_entries above the operator bound accepted: %v", err)
	}
	if err := s.checkMaxEntries(&LDAPConfig{MaxEntries: 500}, nil); err != nil {
		t.Fatal(err)
	}
	cur := &Connector{Kind: KindLDAP, ldap: &LDAPConfig{MaxEntries: 5000}}
	if err := s.checkMaxEntries(&LDAPConfig{MaxEntries: 5000}, cur); err != nil {
		t.Fatalf("unchanged max_entries refused on update: %v", err)
	}
	if err := s.checkMaxEntries(&LDAPConfig{MaxEntries: 6000}, cur); err == nil {
		t.Fatal("raised max_entries above the operator bound accepted on update")
	}
	s.d.Cfg.Directory.MaxEntriesPerRun = 0
	if got := s.maxEntries(&LDAPConfig{MaxEntries: 200000}); got != defaultMaxEntriesPerRun {
		t.Fatalf("deployment default bound: %d", got)
	}
}

// TestOutboundConnectorUsability: a scim_outbound row created through the
// old /provisioning-connectors API (empty configuration, no encrypted
// credential) is not usable, so it gets no deliveries and its health says
// why; a connector created through /directory-connectors is.
func TestOutboundConnectorUsability(t *testing.T) {
	s := testService(t)
	var legacyCfg OutboundConfig
	if err := json.Unmarshal([]byte(`{}`), &legacyCfg); err != nil {
		t.Fatal(err)
	}
	legacy := &Connector{ID: "con_legacy", Kind: KindOutbound, State: "active", out: &legacyCfg}
	if legacy.outboundIssue() == "" || legacy.outboundConfigIssue() == "" {
		t.Fatal("a legacy outbound row without a destination counts as usable")
	}
	cfg := &OutboundConfig{BaseURL: "https://127.0.0.1/v2", AllowPrivateNetwork: true}
	if perr := cfg.normalize(false, egress.Policy{AllowPrivate: true}); perr != nil {
		t.Fatal(perr)
	}
	c := &Connector{ID: "con_out", Kind: KindOutbound, State: "active", out: cfg}
	if c.outboundConfigIssue() != "" || c.outboundIssue() != "the credential is not set" {
		t.Fatalf("connector without credential: config %q, issue %q", c.outboundConfigIssue(), c.outboundIssue())
	}
	ct, _, err := s.d.Keys.Encrypt(keys.PurposeData, []byte("token"), credentialAAD(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	c.secretCT = ct
	if issue := c.outboundIssue(); issue != "" {
		t.Fatalf("complete connector: %q", issue)
	}
	if (&Connector{Kind: KindLDAP}).outboundIssue() != "" {
		t.Fatal("directory connectors have no outbound configuration")
	}
}
