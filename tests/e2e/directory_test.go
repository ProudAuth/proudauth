package e2e

import (
	"context"
	"crypto/rand"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/directory/ldaptest"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/worker"
)

// directoryHarness enables private-network egress for the in-process
// directory and downstream test servers (development mode only).
func directoryHarness(t *testing.T) *Fixture {
	t.Helper()
	h := NewHarness(t, func(c *configuration.Config) {
		c.Directory.AllowPrivateNetwork = true
		c.Directory.ConnectTimeout = 2 * time.Second
		c.Directory.OperationTimeout = 3 * time.Second
		c.Delivery.AllowPrivateWebhooks = true
	})
	return fixtureOn(t, h)
}

const corpBase = "dc=corp,dc=test"

// corpDirectory is an OpenLDAP-style directory with a service account.
func corpDirectory(t *testing.T) *ldaptest.Server {
	t.Helper()
	srv, err := ldaptest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.Add(corpBase, map[string][]string{"objectClass": {"domain"}})
	srv.Add("ou=people,"+corpBase, map[string][]string{"objectClass": {"organizationalUnit"}})
	srv.Add("ou=groups,"+corpBase, map[string][]string{"objectClass": {"organizationalUnit"}})
	srv.Add("cn=svc,"+corpBase, map[string][]string{"objectClass": {"person"}})
	srv.SetPassword("cn=svc,"+corpBase, "service secret", true)
	return srv
}

func personDN(uid string) string { return "uid=" + uid + ",ou=people," + corpBase }

func addPerson(srv *ldaptest.Server, uid, given, family, mail, password string) {
	srv.Add(personDN(uid), map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {uid}, "entryUUID": {"uuid-" + uid},
		"givenName": {given}, "sn": {family}, "displayName": {given + " " + family}, "mail": {mail}})
	srv.SetPassword(personDN(uid), password, false)
}

func closedEndpoint(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "ldap://" + addr
}

// dirRun requests a run and lets the worker execute it.
func (f *Fixture) dirRun(t *testing.T, w *worker.Worker, path string, body map[string]any) *Resp {
	t.Helper()
	r := f.must(f.AdminAPI("POST", path+"/runs", body), 202, "request run")
	runWorker(t, w)
	return f.must(f.AdminAPI("GET", path+"/runs/"+r.Str("id"), nil), 200, "run")
}

func (f *Fixture) findings(t *testing.T, path, runID, kind string) []map[string]any {
	t.Helper()
	q := ""
	if kind != "" {
		q = "?kind=" + kind
	}
	r := f.must(f.AdminAPI("GET", path+"/runs/"+runID+"/findings"+q, nil), 200, "findings")
	var out []map[string]any
	for _, it := range r.Get("items").([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func count(r *Resp, key string) int {
	v, _ := r.Get("counts." + key).(float64)
	return int(v)
}

// passwordStep identifies and submits a password in a fresh transaction.
func passwordStep(h *Harness, identifier, password string) *Resp {
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	txID := start.Str("transaction_id")
	h.Step(txID, cont, "identify", map[string]any{"identifier": identifier})
	return h.Step(txID, cont, "password", map[string]any{"password": password})
}

func directoryLogin(h *Harness, identifier, password string) string {
	h.t.Helper()
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: identifier, Password: password})
	return lr.Tokens.Str("access_token")
}

func userIDByUsername(t *testing.T, h *Harness, username string) string {
	t.Helper()
	var id string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='username' AND canonical_value=$2`,
		h.Realm.ID, strings.ToLower(username)).Scan(&id)
	return id
}

// TestLDAPDirectorySignIn covers PROV-011, PROV-014, FED-015 and TEST-027:
// a workforce directory sources realm accounts; their passwords are verified
// by a bind as the user (never a local hash), an outage fails closed with a
// clear retryable state, failover uses only configured endpoints, first
// sign-in provisioning escapes the identifier into the filter, and the
// connector never reveals its credential.
func TestLDAPDirectorySignIn(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "dir-worker")
	srv := corpDirectory(t)
	addPerson(srv, "jdoe", "Jane", "Doe", "jdoe@corp.test", "jdoe directory pass")
	addPerson(srv, "msmith", "Mark", "Smith", "msmith@corp.test", "msmith directory pass")

	cfg := map[string]any{"endpoints": []string{srv.LDAPSURL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase,
		"user_base_dn": "ou=people," + corpBase, "dialect": "openldap"}
	// An unverifiable server is refused: no TLS bypass exists.
	untrusted := f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Untrusted", "kind": "ldap", "credential": "service secret",
		"config": map[string]any{"endpoints": []string{srv.LDAPSURL()}, "bind_dn": "cn=svc," + corpBase, "user_base_dn": corpBase}}), 201, "untrusted connector")
	if r := f.must(f.AdminAPI("POST", "/directory-connectors/"+untrusted.Str("id")+"/test", nil), 200, "test"); r.Get("ok") != false || !strings.Contains(r.Str("error"), "tls") {
		t.Fatalf("untrusted certificate accepted: %s", r.Raw)
	}
	created := f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Corp LDAP", "kind": "ldap", "config": cfg,
		"credential": "service secret"}), 201, "create connector")
	if strings.Contains(string(created.Raw), "service secret") || created.Get("credential_set") != true || created.Str("organization_id") != "" {
		t.Fatalf("connector view: %s", created.Raw)
	}
	connID := created.Str("id")
	path := "/directory-connectors/" + connID
	// The realm connector grants no organization access (FED-015).
	if r := f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "x", "kind": "ldap", "config": cfg, "credential": "s",
		"role_ceiling_ids": []string{f.Roles["orders-viewer"]}}); r.Status != 422 {
		t.Fatalf("realm connector with roles: %d %s", r.Status, r.Raw)
	}
	if r := f.must(f.AdminAPI("POST", path+"/test", nil), 200, "test"); r.Get("ok") != true || r.Str("details.tls_version") == "" {
		t.Fatalf("connection test: %s", r.Raw)
	}

	// A dry run plans without changing anything.
	dry := f.dirRun(t, w, path, map[string]any{"mode": "full", "dry_run": true})
	if dry.Str("state") != "succeeded" || count(dry, "create") != 2 || userIDByUsername(t, h, "jdoe") != "" {
		t.Fatalf("dry run: %s (jdoe %q)", dry.Raw, userIDByUsername(t, h, "jdoe"))
	}
	for _, fd := range f.findings(t, path, dry.Str("id"), "create") {
		if fd["applied"] != false {
			t.Fatalf("dry-run finding applied: %v", fd)
		}
	}
	run := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if run.Str("state") != "succeeded" || count(run, "create") != 2 {
		t.Fatalf("full sync: %s", run.Raw)
	}
	jdoe := userIDByUsername(t, h, "jdoe")
	var via string
	var verified bool
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT u.created_via, i.verified_at IS NOT NULL FROM users u JOIN user_identifiers i ON i.user_id=u.id AND i.type='email'
		WHERE u.id=$1`, jdoe).Scan(&via, &verified)
	if jdoe == "" || via != "directory:"+connID || verified {
		t.Fatalf("imported account: %s via %q verified %v", jdoe, via, verified)
	}
	var memberships int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE user_id=$1`, jdoe).Scan(&memberships)
	if memberships != 0 {
		t.Fatalf("a workforce account was given organization memberships: %d", memberships)
	}

	// Sign-in: the directory decides (PROV-011).
	if tok := directoryLogin(h, "jdoe", "jdoe directory pass"); tok == "" {
		t.Fatal("directory sign-in failed")
	}
	if r := passwordStep(h, "jdoe", "wrong password"); r.Status != 401 || r.Str("code") != "invalid_credentials" {
		t.Fatalf("wrong password: %d %s", r.Status, r.Raw)
	}
	// A stale local password is never consulted for a directory account.
	verifier, err := h.App.Auth.Hasher.Hash("a stale local password 2026")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO credentials (id, realm_id, user_id, type, state, verifier, algorithm) VALUES ('crd_stale', $1, $2, 'password', 'active', $3, 'argon2id')`,
		h.Realm.ID, jdoe, verifier); err != nil {
		t.Fatal(err)
	}
	if r := passwordStep(h, "jdoe", "a stale local password 2026"); r.Status != 401 {
		t.Fatalf("local password accepted for a directory account: %d %s", r.Status, r.Raw)
	}
	// Outage: fail closed with a clear, retryable state; no fallback to the
	// local password (TEST-027, FED-012).
	srv.SetDown(true)
	for _, pw := range []string{"jdoe directory pass", "a stale local password 2026"} {
		r := passwordStep(h, "jdoe", pw)
		if r.Status != 503 || r.Str("code") != "upstream_unavailable" || r.Header.Get("Retry-After") == "" {
			t.Fatalf("outage: %d %s", r.Status, r.Raw)
		}
	}
	// Local accounts keep signing in with local credentials during the outage.
	if lr := f.AccountToken("alice"); lr.Tokens.Str("access_token") == "" {
		t.Fatal("local account affected by a directory outage")
	}
	srv.SetDown(false)

	// Failover (PROV-014): a dead first endpoint moves to the next
	// configured one, over StartTLS this time.
	cur := f.must(f.AdminAPI("GET", path, nil), 200, "get")
	cfg["endpoints"] = []string{closedEndpoint(t), srv.URL()}
	upd := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: map[string]any{"name": "Corp LDAP", "config": cfg,
		"jit_provisioning": nil}, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
	if upd.Status != 400 {
		t.Fatalf("unknown member accepted: %d", upd.Status)
	}
	cfg["jit_provisioning"] = true
	upd = h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: map[string]any{"name": "Corp LDAP", "config": cfg},
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
	mustStatus(t, upd, 200, "update endpoints")
	if tok := directoryLogin(h, "jdoe", "jdoe directory pass"); tok == "" {
		t.Fatal("sign-in after failover failed")
	}
	health := f.must(f.AdminAPI("GET", path+"/health", nil), 200, "health")
	eps, _ := health.Get("endpoints").(map[string]any)
	dead := strings.TrimPrefix(closedEndpointHost(cfg), "ldap://")
	if ep, _ := eps[dead].(map[string]any); ep == nil || ep["last_failure_category"] != "connect" {
		t.Fatalf("endpoint health: %s", health.Raw)
	}
	metrics := h.App.Metrics.Registry
	var sb strings.Builder
	metrics.WriteText(&sb)
	if !strings.Contains(sb.String(), `proudauth_directory_failovers_total{category="connect"}`) ||
		!strings.Contains(sb.String(), `proudauth_directory_binds_total{outcome="unavailable"}`) {
		t.Fatalf("metrics missing failover or outage evidence")
	}

	// First sign-in provisioning (FED-015) with an escaped identifier.
	addPerson(srv, "newbie", "New", "Bie", "newbie@corp.test", "newbie directory pass")
	srv.ResetCounters()
	if r := passwordStep(h, "*@corp.test", "newbie directory pass"); r.Status != 401 {
		t.Fatalf("wildcard identifier: %d %s", r.Status, r.Raw)
	}
	_, _, filters := srv.Stats()
	escaped := false
	for _, fl := range filters {
		if strings.Contains(fl, `mail=\2a@corp.test`) {
			escaped = true
		}
		if strings.Contains(fl, "mail=*@corp.test") {
			t.Fatalf("identifier reached the directory unescaped: %s", fl)
		}
	}
	if !escaped {
		t.Fatalf("login filter not observed: %v", filters)
	}
	if tok := directoryLogin(h, "newbie", "newbie directory pass"); tok == "" {
		t.Fatal("first sign-in provisioning failed")
	}
	if userIDByUsername(t, h, "newbie") == "" {
		t.Fatal("account not provisioned at first sign-in")
	}
	if r := passwordStep(h, "unknown.person", "whatever password"); r.Status != 401 {
		t.Fatalf("unknown identifier: %d", r.Status)
	}

	// A disabled entry suspends the realm account; local reactivation is
	// refused while the directory disables it (USR-022).
	srv.Update(personDN("msmith"), map[string][]string{"nsAccountLock": {"TRUE"}})
	cur = f.must(f.AdminAPI("GET", path, nil), 200, "get")
	cfg["disabled_attribute"], cfg["disabled_values"] = "nsAccountLock", []string{"TRUE"}
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: map[string]any{"name": "Corp LDAP", "config": cfg},
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "disabled attribute")
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	msmith := userIDByUsername(t, h, "msmith")
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, msmith).Scan(&state)
	if count(run, "suspend") != 1 || state != "suspended" {
		t.Fatalf("disabled entry: %s state %s", run.Raw, state)
	}
	if r := f.AdminAPI("POST", "/users/"+msmith+"/reactivate", map[string]any{"reason": "test"}); r.Status != 409 || !slices.Contains(toStrings(r.Get("externally_managed")), "state") {
		t.Fatalf("local reactivation of a directory-disabled account: %d %s", r.Status, r.Raw)
	}
	if r := passwordStep(h, "msmith", "msmith directory pass"); r.Status != 401 {
		t.Fatalf("disabled entry signed in: %d", r.Status)
	}
	srv.Update(personDN("msmith"), map[string][]string{"nsAccountLock": nil})
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, msmith).Scan(&state)
	if count(run, "reactivate") != 1 || state != "active" {
		t.Fatalf("re-enabled entry: %s state %s", run.Raw, state)
	}

	// Disabling the connector fails directory sign-in closed.
	cur = f.must(f.AdminAPI("GET", path, nil), 200, "get")
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: map[string]any{"name": "Corp LDAP", "config": cfg,
		"state": "disabled"}, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "disable")
	if r := passwordStep(h, "jdoe", "jdoe directory pass"); r.Status != 503 {
		t.Fatalf("disabled connector: %d %s", r.Status, r.Raw)
	}

	// Credentials never appear in responses or audit evidence (PROV-018).
	var leaked int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%service secret%' OR metadata::text LIKE '%directory pass%'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("credentials in audit evidence: %d", leaked)
	}
	for _, p := range []string{path, path + "/health", path + "/runs"} {
		if r := f.AdminAPI("GET", p, nil); strings.Contains(string(r.Raw), "service secret") {
			t.Fatalf("%s leaks the credential", p)
		}
	}
	if health.Str("status") == "" || health.Get("last_success_at") == nil || len(health.Get("operator_actions").([]any)) == 0 {
		t.Fatalf("health evidence: %s", health.Raw)
	}
}

func closedEndpointHost(cfg map[string]any) string {
	eps := cfg["endpoints"].([]string)
	return strings.TrimPrefix(eps[0], "ldap://")
}

func toStrings(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// adGUID is a random 16-byte objectGUID.
func adGUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return string(b)
}

func addADUser(srv *ldaptest.Server, sam, mail string) string {
	dn := "CN=" + sam + ",ou=people," + corpBase
	srv.Add(dn, map[string][]string{"objectClass": {"user"}, "objectCategory": {"person"}, "objectGUID": {adGUID()}, "sAMAccountName": {sam},
		"mail": {mail}, "givenName": {strings.ToUpper(sam[:1]) + sam[1:]}, "sn": {"Corp"}, "displayName": {sam + " Corp"}, "userAccountControl": {"512"}})
	srv.SetPassword(dn, sam+" ad password", false)
	return dn
}

// TestDirectorySynchronization covers PROV-012, PROV-017, PROV-005,
// PROV-006, PROV-007, TEST-048 and TEST-049 with an organization-bound
// Active Directory connector: dry-run plans, conflict reports instead of
// merges, adoption only through a verified domain, USN change cursors bound
// to their domain controller, group mapping within the role ceiling,
// deletion detection behind the safety threshold, and deprovisioning that
// removes only the organization's access.
func TestDirectorySynchronization(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "dir-worker")
	viewer := f.Roles["orders-viewer"]
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	ch := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains", map[string]any{"domain": "example.test"}), 201, "domain")
	organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify domain")

	srv := corpDirectory(t)
	var dns []string
	for i := 1; i <= 8; i++ {
		sam := "u0" + string(rune('0'+i))
		dns = append(dns, addADUser(srv, sam, sam+"@example.test"))
	}
	bobDN := addADUser(srv, "bob", "bob@example.test")
	addADUser(srv, "alice", "alice.other@elsewhere.test")
	addADUser(srv, "root-admin", "admin@example.test")
	srv.Add("CN=Support,ou=groups,"+corpBase, map[string][]string{"objectClass": {"group"}, "cn": {"Support"}, "member": {dns[0], dns[1]}})

	cfg := map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "dialect": "active_directory",
		"bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase, "group_base_dn": "ou=groups," + corpBase}
	orgPath := "/organizations/" + f.Acme + "/directory-connectors"
	// Approved group mappings stay within the ceiling (TEST-049).
	if r := f.AdminAPI("POST", orgPath, map[string]any{"name": "Corp AD", "kind": "ldap", "config": cfg, "credential": "service secret",
		"role_ceiling_ids": []string{viewer}, "group_role_mappings": map[string]any{"Support": []string{f.Roles["owner"]}}}); r.Status != 422 {
		t.Fatalf("out-of-ceiling group mapping accepted: %d %s", r.Status, r.Raw)
	}
	created := f.must(f.AdminAPI("POST", orgPath, map[string]any{"name": "Corp AD", "kind": "ldap", "config": cfg, "credential": "service secret",
		"role_ceiling_ids": []string{viewer}, "default_role_id": viewer, "group_role_mappings": map[string]any{"Support": []string{viewer}}}), 201, "connector")
	connID := created.Str("id")
	path := orgPath + "/" + connID
	if created.Str("organization_id") != f.Acme {
		t.Fatalf("binding: %s", created.Raw)
	}

	dry := f.dirRun(t, w, path, map[string]any{"mode": "full", "dry_run": true})
	if dry.Str("state") != "succeeded" || count(dry, "create") != 8 || count(dry, "link") != 1 || count(dry, "conflict") != 2 {
		t.Fatalf("plan: %s", dry.Raw)
	}
	if userIDByUsername(t, h, "u01") != "" {
		t.Fatal("dry run created an account")
	}
	run := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if run.Str("state") != "succeeded" || count(run, "create") != 8 || count(run, "link") != 1 || count(run, "conflict") != 2 || run.Str("cursor_after") == "" {
		t.Fatalf("full sync: %s", run.Raw)
	}
	reasons := map[string]bool{}
	for _, fd := range f.findings(t, path, run.Str("id"), "conflict") {
		reasons[fd["reason"].(string)] = true
	}
	// Existing accounts are never merged silently: a username collision
	// without a verified-domain email match, and a protected account, are
	// reported (FED-005, PROV-006).
	if !reasons["domain_not_verified"] || !reasons["protected_account"] {
		t.Fatalf("conflict reasons: %v", reasons)
	}
	u01 := userIDByUsername(t, h, "u01")
	var verified bool
	var mstate string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT i.verified_at IS NOT NULL, m.state FROM user_identifiers i JOIN memberships m ON m.user_id=i.user_id
		AND m.organization_id=$2 WHERE i.user_id=$1 AND i.type='email'`, u01, f.Acme).Scan(&verified, &mstate)
	if u01 == "" || !verified || mstate != "active" {
		t.Fatalf("organization import: user %q verified %v membership %q", u01, verified, mstate)
	}
	var bobPassword int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, f.Users["bob"]).Scan(&bobPassword)
	if bobPassword != 0 {
		t.Fatal("an adopted account kept its local password")
	}
	if tok := directoryLogin(h, "bob", "bob ad password"); tok == "" {
		t.Fatal("adopted account cannot sign in through the directory")
	}
	// Groups: an approved mapping creates the group with its members and
	// roles (PROV-007).
	var groupID string
	var members, roles int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM groups WHERE organization_id=$1 AND name='Support' AND source='directory'`, f.Acme).Scan(&groupID)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM group_memberships WHERE group_id=$1`, groupID).Scan(&members)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1 AND role_id=$2 AND source='directory'`,
		groupID, viewer).Scan(&roles)
	if groupID == "" || members != 2 || roles != 1 {
		t.Fatalf("group mapping: group %q members %d roles %d", groupID, members, roles)
	}

	// Incremental: only changes after the USN cursor are read.
	srv.ResetCounters()
	srv.Update(dns[2], map[string][]string{"displayName": {"Changed Name"}})
	srv.Update("CN=Support,ou=groups,"+corpBase, map[string][]string{"member": {dns[0]}})
	inc := f.dirRun(t, w, path, map[string]any{"mode": "incremental"})
	_, _, filters := srv.Stats()
	if inc.Str("state") != "succeeded" || count(inc, "entries_seen") != 1 || count(inc, "update") != 1 || !strings.Contains(strings.Join(filters, " "), "uSNChanged>=") {
		t.Fatalf("incremental: %s filters %v", inc.Raw, filters)
	}
	var display string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id=$1`, userIDByUsername(t, h, "u03")).Scan(&display)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM group_memberships WHERE group_id=$1`, groupID).Scan(&members)
	if display != "Changed Name" || members != 1 {
		t.Fatalf("incremental changes: display %q members %d", display, members)
	}
	// The shared account's identity is the account's own; only its
	// membership in this organization is the connector's (PROV-005).
	srv.Update(bobDN, map[string][]string{"givenName": {"Robert"}})
	inc = f.dirRun(t, w, path, map[string]any{"mode": "incremental"})
	if count(inc, "divergence") != 1 {
		t.Fatalf("shared account divergence: %s", inc.Raw)
	}
	// A USN means nothing on another domain controller: a cursor from a
	// different server forces a full run.
	srv.ServerName = "CN=NTDS Settings,CN=DC2"
	inc = f.dirRun(t, w, path, map[string]any{"mode": "incremental"})
	if count(inc, "incremental_promoted_to_full") != 1 || count(inc, "entries_seen") != 11 || inc.Str("mode") != "full" {
		t.Fatalf("cursor from another server: %s", inc.Raw)
	}
	// A disabled entry suspends only this organization's membership.
	srv.Update(dns[3], map[string][]string{"userAccountControl": {"514"}})
	inc = f.dirRun(t, w, path, map[string]any{"mode": "incremental"})
	u04 := userIDByUsername(t, h, "u04")
	var ustate string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT m.state, u.state FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND m.organization_id=$2`,
		u04, f.Acme).Scan(&mstate, &ustate)
	if count(inc, "suspend") != 1 || mstate != "suspended" || ustate != "active" {
		t.Fatalf("disabled entry: %s membership %s account %s", inc.Raw, mstate, ustate)
	}

	// Deletion safety (PROV-012): 4 of 9 linked accounts missing exceeds
	// the 20% threshold, so nothing is deprovisioned.
	for _, dn := range []string{dns[4], dns[5], dns[6], bobDN} {
		srv.Delete(dn)
	}
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if run.Str("state") != "refused" || count(run, "deprovision_refused") != 4 {
		t.Fatalf("threshold: %s", run.Raw)
	}
	acmeState := func(user string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM memberships WHERE organization_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 1`, f.Acme, user).Scan(&s)
		return s
	}
	if acmeState(f.Users["bob"]) != "active" || acmeState(userIDByUsername(t, h, "u05")) != "active" {
		t.Fatal("a refused run deprovisioned accounts")
	}
	// The override needs a reason and is an audited operator action.
	if r := f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full", "allow_mass_deprovision": true}); r.Status != 422 {
		t.Fatalf("override without reason: %d", r.Status)
	}
	run = f.dirRun(t, w, path, map[string]any{"mode": "full", "allow_mass_deprovision": true, "reason": "decommissioned the contractors OU"})
	if run.Str("state") != "succeeded" || count(run, "deprovision") != 4 {
		t.Fatalf("override: %s", run.Raw)
	}
	var globex, account string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
		f.Globex, f.Users["bob"]).Scan(&globex)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["bob"]).Scan(&account)
	if acmeState(f.Users["bob"]) != "removed" || globex != "active" || account != "active" {
		t.Fatalf("deprovisioning scope (TEST-048): acme %s globex %s account %s", acmeState(f.Users["bob"]), globex, account)
	}
	var overrideAudited int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='directory.sync.requested' AND reason_code='MASS_DEPROVISION_OVERRIDE'`).Scan(&overrideAudited)
	if overrideAudited != 1 {
		t.Fatal("override not audited")
	}
	// A single deletion is below the threshold.
	srv.Delete(dns[7])
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if run.Str("state") != "succeeded" || count(run, "deprovision") != 1 || acmeState(userIDByUsername(t, h, "u08")) != "removed" {
		t.Fatalf("single deletion: %s", run.Raw)
	}
	// A returning entry is relinked by its immutable ID and regains access.
	addADUser(srv, "u05r", "u05@example.test")
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if count(run, "conflict") < 2 {
		t.Fatalf("a different object with a reused email is not the same account: %s", run.Raw)
	}
	// One run at a time.
	f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "queue")
	if r := f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}); r.Status != 409 || r.Str("run_id") == "" {
		t.Fatalf("concurrent run: %d %s", r.Status, r.Raw)
	}
	runWorker(t, w)
	health := f.must(f.AdminAPI("GET", path+"/health", nil), 200, "health")
	if health.Get("managed_accounts.active") == nil || health.Get("managed_groups") != float64(1) || health.Get("last_run") == nil {
		t.Fatalf("health: %s", health.Raw)
	}
}

// TestDirectoryAuthority covers USR-022, PROV-013 and PROV-017: attributes
// a directory manages are refused through self-service and administration
// APIs with a clear error, the account declares which attributes are local,
// externally managed or written back, write-back writes the directory first
// and refuses the edit when it cannot, and import-only attributes are
// reported as divergence instead of being overwritten back and forth.
func TestDirectoryAuthority(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "dir-worker")
	srv := corpDirectory(t)
	addPerson(srv, "jdoe", "Jane", "Doe", "jdoe@corp.test", "jdoe directory pass")
	cfg := map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase,
		"user_base_dn": "ou=people," + corpBase}
	created := f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Corp LDAP", "kind": "ldap", "config": cfg,
		"credential": "service secret"}), 201, "connector")
	path := "/directory-connectors/" + created.Str("id")
	f.dirRun(t, w, path, map[string]any{"mode": "full"})
	jdoe := userIDByUsername(t, h, "jdoe")
	tok := directoryLogin(h, "jdoe", "jdoe directory pass")

	decl := f.must(h.API("GET", "/me/attribute-authority", tok, nil), 200, "declaration")
	if decl.Str("attributes.display_name") != "externally_managed" || decl.Str("attributes.locale") != "local" ||
		decl.Str("operations.password_change") != "externally_managed" || decl.Str("source.connector_id") != created.Str("id") {
		t.Fatalf("declaration: %s", decl.Raw)
	}
	if r := f.must(f.AdminAPI("GET", "/users/"+f.Users["alice"]+"/attribute-authority", nil), 200, "local declaration"); r.Get("source") != nil ||
		r.Str("attributes.display_name") != "local" {
		t.Fatalf("local account declaration: %s", r.Raw)
	}
	// Externally managed attributes are refused, naming them.
	r := h.API("PATCH", "/me", tok, map[string]any{"display_name": "Self Edited", "locale": "fr"})
	if r.Status != 409 || r.Str("code") != "conflict" || !slices.Contains(toStrings(r.Get("externally_managed")), "display_name") || r.Str("errors.display_name") == "" {
		t.Fatalf("self-service edit of a managed attribute: %d %s", r.Status, r.Raw)
	}
	// Sending the current value is not a change; local attributes stay editable.
	f.must(h.API("PATCH", "/me", tok, map[string]any{"display_name": "Jane Doe", "locale": "fr"}), 200, "local edit")
	if r := f.AdminAPI("PATCH", "/users/"+jdoe, map[string]any{"given_name": "Janet"}); r.Status != 409 {
		t.Fatalf("administrative edit of a managed attribute: %d %s", r.Status, r.Raw)
	}
	f.must(f.AdminAPI("PATCH", "/users/"+jdoe, map[string]any{"admin_metadata": map[string]any{"cost_center": "42"}}), 200, "admin metadata")
	if r := h.API("POST", "/me/identifiers", tok, map[string]any{"type": "email", "value": "other@corp.test"}); r.Status != 409 {
		t.Fatalf("identifier change: %d %s", r.Status, r.Raw)
	}
	if r := h.API("POST", "/me/password", tok, map[string]any{"current_password": "jdoe directory pass", "new_password": "a brand new password 2026"}); r.Status != 409 ||
		!slices.Contains(toStrings(r.Get("externally_managed")), "password") {
		t.Fatalf("password change: %d %s", r.Status, r.Raw)
	}

	// Write-back mode (PROV-013): the permitted attribute is written to the
	// directory first; others stay refused.
	cur := f.must(f.AdminAPI("GET", path, nil), 200, "get")
	cfg["mode"], cfg["write_back_attributes"] = "write_back", []string{"display_name"}
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: map[string]any{"name": "Corp LDAP", "config": cfg},
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "write_back mode")
	if d := f.must(h.API("GET", "/me/attribute-authority", tok, nil), 200, "declaration"); d.Str("attributes.display_name") != "write_back" ||
		d.Str("attributes.given_name") != "externally_managed" {
		t.Fatalf("write-back declaration: %s", d.Raw)
	}
	f.must(h.API("PATCH", "/me", tok, map[string]any{"display_name": "Jane Q. Doe"}), 200, "write-back edit")
	if e := srv.Entry(personDN("jdoe")); e == nil || e.Get("displayName")[0] != "Jane Q. Doe" {
		t.Fatalf("not written back: %+v", e)
	}
	// The next synchronization sees the value it wrote: no change to apply,
	// no flip-flop (PROV-017).
	run := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if count(run, "update") != 0 {
		t.Fatalf("write-back oscillated: %s", run.Raw)
	}
	// A directory that cannot take the write refuses the local edit too.
	srv.SetDown(true)
	if r := h.API("PATCH", "/me", tok, map[string]any{"display_name": "Never Stored"}); r.Status != 503 {
		t.Fatalf("write-back during an outage: %d %s", r.Status, r.Raw)
	}
	srv.SetDown(false)
	var display string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id=$1`, jdoe).Scan(&display)
	if display != "Jane Q. Doe" {
		t.Fatalf("local value diverged after a failed write-back: %q", display)
	}

	// Import-only: locally owned after import; directory changes are
	// reported as divergence and never overwrite the local value.
	cur = f.must(f.AdminAPI("GET", path, nil), 200, "get")
	cfg["mode"], cfg["write_back_attributes"] = "import_only", nil
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: map[string]any{"name": "Corp LDAP", "config": cfg},
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "import_only mode")
	f.must(h.API("PATCH", "/me", tok, map[string]any{"given_name": "Janie"}), 200, "import-only edit")
	srv.Update(personDN("jdoe"), map[string][]string{"givenName": {"Janine"}})
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	var given string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT given_name FROM users WHERE id=$1`, jdoe).Scan(&given)
	if given != "Janie" || count(run, "divergence") != 1 || srv.Entry(personDN("jdoe")).Get("givenName")[0] != "Janine" {
		t.Fatalf("import-only: local %q %s", given, run.Raw)
	}
	// OpenLDAP-style change tracking: an incremental run filters on
	// modifyTimestamp (with an overlap), and reports divergence only on full
	// runs.
	srv.ResetCounters()
	inc := f.dirRun(t, w, path, map[string]any{"mode": "incremental"})
	_, _, filters := srv.Stats()
	if inc.Str("mode") != "incremental" || !strings.Contains(strings.Join(filters, " "), "modifyTimestamp>=") || count(inc, "divergence") != 0 {
		t.Fatalf("modifyTimestamp incremental: %s %v", inc.Raw, filters)
	}
	// The password stays the directory's in every mode.
	if r := h.API("POST", "/me/password", tok, map[string]any{"current_password": "jdoe directory pass", "new_password": "a brand new password 2026"}); r.Status != 409 {
		t.Fatalf("password change in import_only mode: %d", r.Status)
	}

	// directory.enabled=false stops connectors but keeps the accounts they
	// sourced failing closed: no local password, no password reset.
	h.App.Directory.Disabled = true
	defer func() { h.App.Directory.Disabled = false }()
	if r := f.AdminAPI("GET", "/directory-connectors", nil); r.Status != 404 || r.Str("code") != "feature_disabled" {
		t.Fatalf("disabled module API: %d %s", r.Status, r.Raw)
	}
	if r := passwordStep(h, "jdoe", "jdoe directory pass"); r.Status != 503 {
		t.Fatalf("disabled module sign-in: %d %s", r.Status, r.Raw)
	}
	if r := h.API("POST", "/me/password", tok, map[string]any{"current_password": "x", "new_password": "a brand new password 2026"}); r.Status == 200 {
		t.Fatal("password set while the module is disabled")
	}
	if n, err := w.App.Directory.Schedule(ctx); err != nil || n != 0 {
		t.Fatalf("disabled module scheduled work: %d %v", n, err)
	}
}

// TestDirectoryTenantIsolation: organization connectors, their runs and
// health are visible only within their organization; realm connectors need
// realm authority (TEST-007, TEST-009).
func TestDirectoryTenantIsolation(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	srv := corpDirectory(t)
	cfg := map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase, "user_base_dn": corpBase}
	acme := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/directory-connectors", map[string]any{"name": "Acme AD", "kind": "ldap", "config": cfg,
		"credential": "service secret"}), 201, "acme connector")
	realmConn := f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Workforce", "kind": "ldap", "config": cfg,
		"credential": "service secret"}), 201, "realm connector")
	// carol owns Globex, so she manages Globex's integrations — and nothing else.
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["carol"]+"/roles", map[string]any{"role_id": f.Roles["owner"]}), 201, "owner")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	for _, p := range []string{
		"/organizations/" + f.Globex + "/directory-connectors/" + acme.Str("id"),
		"/organizations/" + f.Globex + "/directory-connectors/" + acme.Str("id") + "/health",
		"/organizations/" + f.Globex + "/directory-connectors/" + realmConn.Str("id"),
	} {
		if r := h.API("GET", p, carol, nil); r.Status != 404 && r.Status != 403 {
			t.Fatalf("%s visible across tenants: %d %s", p, r.Status, r.Raw)
		}
	}
	if r := h.API("GET", "/organizations/"+f.Acme+"/directory-connectors", carol, nil); r.Status != 404 && r.Status != 403 {
		t.Fatalf("another organization's connectors listed: %d", r.Status)
	}
	if r := h.API("GET", "/directory-connectors", carol, nil); r.Status != 403 {
		t.Fatalf("realm connectors without realm authority: %d", r.Status)
	}
	if r := h.API("POST", "/organizations/"+f.Globex+"/directory-connectors/"+acme.Str("id")+"/runs", carol, map[string]any{"mode": "full"}); r.Status != 404 && r.Status != 403 {
		t.Fatalf("run requested across tenants: %d", r.Status)
	}
	list := f.must(h.API("GET", "/organizations/"+f.Globex+"/directory-connectors", carol, nil), 200, "own list")
	if items, _ := list.Get("items").([]any); len(items) != 0 {
		t.Fatalf("Globex sees foreign connectors: %s", list.Raw)
	}
	// The realm view lists both; the Acme view only its own.
	all := f.must(f.AdminAPI("GET", "/directory-connectors", nil), 200, "realm list")
	own := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/directory-connectors", nil), 200, "acme list")
	if n := len(all.Get("items").([]any)); n != 2 {
		t.Fatalf("realm list: %d", n)
	}
	if items := own.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["id"] != acme.Str("id") {
		t.Fatalf("organization list: %s", own.Raw)
	}
	// The SCIM connector API manages only inbound SCIM connectors.
	if r := f.AdminAPI("GET", "/organizations/"+f.Acme+"/provisioning-connectors/"+acme.Str("id"), nil); r.Status != 404 {
		t.Fatalf("directory connector reachable through the SCIM API: %d", r.Status)
	}
	if r := f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "x", "kind": "scim_outbound"}); r.Status != 422 {
		t.Fatalf("outbound connector created through the SCIM API: %d", r.Status)
	}
	// A tenant's directory never receives sign-in attempts for identifiers
	// it does not own (first sign-in provisioning is realm-only).
	jit := map[string]any{"endpoints": []string{srv.URL()}, "bind_dn": "cn=svc," + corpBase, "user_base_dn": corpBase, "jit_provisioning": true}
	if r := f.AdminAPI("POST", "/organizations/"+f.Acme+"/directory-connectors", map[string]any{"name": "JIT", "kind": "ldap", "config": jit,
		"credential": "service secret"}); r.Status != 422 {
		t.Fatalf("organization connector with first sign-in provisioning: %d %s", r.Status, r.Raw)
	}
	// Deleting needs a disabled connector first.
	if r := f.AdminAPI("DELETE", "/directory-connectors/"+realmConn.Str("id"), nil); r.Status != 409 {
		t.Fatalf("delete of an active connector: %d", r.Status)
	}
}
