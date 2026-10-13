package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/directory/ldaptest"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/worker"
)

// runState reads a run straight from the database (the connector API
// answers 404 while the module is disabled).
func runState(t *testing.T, h *Harness, runID string) (state, reason string) {
	t.Helper()
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state, coalesce(error,'') FROM directory_sync_runs WHERE id=$1`, runID).
		Scan(&state, &reason); err != nil {
		t.Fatalf("run %s: %v", runID, err)
	}
	return state, reason
}

// TestDirectoryQueuedRunWhileDisabled: a run queued when directory.enabled
// is switched off ends cancelled with a reason instead of staying queued,
// a run whose job ended without it (as earlier releases left behind) no
// longer blocks the connector, and a connector's max_entries can only lower
// directory.max_entries_per_run.
func TestDirectoryQueuedRunWhileDisabled(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "dir-worker")
	srv := corpDirectory(t)
	addPerson(srv, "jdoe", "Jane", "Doe", "jdoe@corp.test", "jdoe directory pass")
	cfg := map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase,
		"user_base_dn": "ou=people," + corpBase, "max_entries": 5}
	// A connector cannot raise the operator's bound (100000 by default).
	tooMany := map[string]any{}
	for k, v := range cfg {
		tooMany[k] = v
	}
	tooMany["max_entries"] = 200000
	if r := f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Too many", "kind": "ldap", "config": tooMany,
		"credential": "service secret"}); r.Status != 422 || !strings.Contains(string(r.Raw), "max_entries_per_run") {
		t.Fatalf("max_entries above directory.max_entries_per_run: %d %s", r.Status, r.Raw)
	}
	created := f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Corp LDAP", "kind": "ldap", "config": cfg,
		"credential": "service secret"}), 201, "connector")
	path := "/directory-connectors/" + created.Str("id")

	queued := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "queue")
	h.App.Directory.Disabled = true
	runWorker(t, w)
	state, reason := runState(t, h, queued.Str("id"))
	if state != "cancelled" || !strings.Contains(reason, "disabled") {
		t.Fatalf("run queued while the module was switched off: %s (%s)", state, reason)
	}
	var jobState string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT j.state FROM jobs j JOIN directory_sync_runs r ON r.job_id=j.id WHERE r.id=$1`, queued.Str("id")).Scan(&jobState)
	if jobState != "succeeded" {
		t.Fatalf("job of the cancelled run: %s", jobState)
	}
	h.App.Directory.Disabled = false
	if run := f.dirRun(t, w, path, map[string]any{"mode": "full"}); run.Str("state") != "succeeded" || count(run, "create") != 1 {
		t.Fatalf("run after re-enabling the module: %s", run.Raw)
	}

	// A run left queued after its job ended (dead-lettered, cancelled) is
	// closed when the next run is requested, instead of answering 409.
	stuck := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "queue")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE jobs SET state='dead_letter', finished_at=now() WHERE id=(SELECT job_id FROM directory_sync_runs WHERE id=$1)`,
		stuck.Str("id")); err != nil {
		t.Fatal(err)
	}
	next := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "run after an orphaned one")
	if state, reason := runState(t, h, stuck.Str("id")); state != "cancelled" || reason == "" {
		t.Fatalf("orphaned run: %s (%s)", state, reason)
	}
	runWorker(t, w)
	if state, _ := runState(t, h, next.Str("id")); state != "succeeded" {
		t.Fatalf("run after the orphaned one: %s", state)
	}
	// The scheduler's pass closes orphaned runs too.
	orphan := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "queue")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE jobs SET state='cancelled', finished_at=now() WHERE id=(SELECT job_id FROM directory_sync_runs WHERE id=$1)`,
		orphan.Str("id")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.Directory.Schedule(ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := runState(t, h, orphan.Str("id")); state != "cancelled" {
		t.Fatalf("orphaned run after a scheduler pass: %s", state)
	}

	// max_entries (5) is clamped to a lower operator bound.
	addPerson(srv, "rroe", "Richard", "Roe", "rroe@corp.test", "rroe directory pass")
	saved := h.Cfg.Directory.MaxEntriesPerRun
	h.Cfg.Directory.MaxEntriesPerRun = 1
	defer func() { h.Cfg.Directory.MaxEntriesPerRun = saved }()
	run := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if run.Str("state") != "failed" || !strings.Contains(run.Str("error"), "more than 1 entries") {
		t.Fatalf("connector max_entries above the operator bound: %s", run.Raw)
	}
}

// TestDirectoryErasureAndRetention: erasing an account removes the
// directory data that names it (the link's DN and attribute snapshot, DNs in
// run findings) without letting the next synchronization recreate it, and
// retention prunes old findings, finished runs (each connector keeps its
// latest) and finished outbound deliveries.
func TestDirectoryErasureAndRetention(t *testing.T) {
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
	connID := created.Str("id")
	path := "/directory-connectors/" + connID
	first := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	jdoe := userIDByUsername(t, h, "jdoe")
	if jdoe == "" || count(first, "create") != 1 {
		t.Fatalf("import: %s", first.Raw)
	}
	var named int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_findings WHERE local_id=$1 AND source_dn IS NOT NULL`, jdoe).Scan(&named)
	if named == 0 {
		t.Fatal("expected a finding naming the account's entry")
	}

	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		return h.App.Users.DeleteNowTx(ctx, tx, h.Realm.ID, jdoe, audit.System, "test")
	}); err != nil {
		t.Fatal(err)
	}
	var dn, snapshot *string
	var linkState string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT source_dn, snapshot::text, source_state FROM connector_external_ids WHERE local_id=$1 AND link_kind='directory'`,
		jdoe).Scan(&dn, &snapshot, &linkState); err != nil {
		t.Fatal(err)
	}
	if dn != nil || snapshot != nil || linkState != "deleted" {
		t.Fatalf("directory link after erasure: dn %v snapshot %v state %s", dn, snapshot, linkState)
	}
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_findings WHERE local_id=$1 AND source_dn IS NOT NULL`, jdoe).Scan(&named)
	if named != 0 {
		t.Fatalf("%d findings still name the erased account's entry", named)
	}
	// The entry is still in the directory: it is reported, without its
	// DN, and not imported again; deletion detection leaves it alone.
	second := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if second.Str("state") != "succeeded" || count(second, "create") != 0 {
		t.Fatalf("synchronization after erasure: %s", second.Raw)
	}
	for _, fd := range f.findings(t, path, second.Str("id"), "error") {
		if fd["reason"] == "linked_account_deleted" && fd["source_dn"] != nil {
			t.Fatalf("finding names the erased account's entry: %v", fd)
		}
	}
	var live int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE created_via=$1 AND state<>'deleted'`, "directory:"+connID).Scan(&live)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT source_dn, source_state FROM connector_external_ids WHERE local_id=$1 AND link_kind='directory'`, jdoe).
		Scan(&dn, &linkState)
	if live != 0 || dn != nil || linkState != "deleted" {
		t.Fatalf("erased account recreated or relinked: live %d dn %v state %s", live, dn, linkState)
	}

	// Retention: findings and finished runs older than 90 days go, except
	// each connector's latest run; finished deliveries go, open ones stay.
	old := h.App.D.Now().Add(-100 * 24 * time.Hour)
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE directory_sync_runs SET created_at=created_at-interval '100 days', finished_at=$2 WHERE connector_id=$1`,
		connID, old); err != nil {
		t.Fatal(err)
	}
	for i, st := range []string{"delivered", "dead_letter", "replayed", "pending", "delivered"} {
		at := old
		if i == 4 {
			at = h.App.D.Now()
		}
		if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO outbound_deliveries (id, realm_id, connector_id, resource_type, local_id, trigger, state,
			next_attempt_at, created_at, updated_at) VALUES ($1,$2,$3,'User',$4,'test',$5,$6,$6,$6)`, ids.New(ids.Delivery), h.Realm.ID, connID,
			"usr_"+st+string(rune('a'+i)), st, at); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Retention(ctx); err != nil {
		t.Logf("retention reported (other steps): %v", err)
	}
	var runs, findings, deliveries int
	var kept string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*), max(id) FROM directory_sync_runs WHERE connector_id=$1`, connID).Scan(&runs, &kept)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_findings f JOIN directory_sync_runs r ON r.id=f.run_id WHERE r.connector_id=$1`,
		connID).Scan(&findings)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries WHERE connector_id=$1`, connID).Scan(&deliveries)
	if runs != 1 || kept != second.Str("id") || findings != 0 || deliveries != 2 {
		t.Fatalf("retention: runs %d (kept %s, latest %s) findings %d deliveries %d", runs, kept, second.Str("id"), findings, deliveries)
	}
	if h := f.must(f.AdminAPI("GET", path+"/health", nil), 200, "health"); h.Str("last_run.id") != second.Str("id") {
		t.Fatalf("latest run pruned: %s", h.Raw)
	}
}

// addADUserGUID adds an Active Directory user with a fixed objectGUID, so
// the entry can return with the same immutable ID.
func addADUserGUID(srv *ldaptest.Server, sam, mail, guid string) string {
	dn := "CN=" + sam + ",ou=people," + corpBase
	srv.Add(dn, map[string][]string{"objectClass": {"user"}, "objectCategory": {"person"}, "objectGUID": {guid}, "sAMAccountName": {sam},
		"mail": {mail}, "givenName": {sam}, "sn": {"Corp"}, "displayName": {sam + " Corp"}, "userAccountControl": {"512"}})
	srv.SetPassword(dn, sam+" ad password", false)
	return dn
}

// TestDirectoryMembershipReactivation (PROV-005): an organization connector
// that re-enables an entry undoes only its own suspension or removal of the
// membership; a membership an administrator suspended or removed stays so,
// reported as divergence.
func TestDirectoryMembershipReactivation(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "dir-worker")
	srv := corpDirectory(t)
	daveDN := addADUser(srv, "dave", "dave@corp.test")
	erinDN := addADUser(srv, "erin", "erin@corp.test")
	fredDN := addADUser(srv, "fred", "fred@corp.test")
	ginaDN := addADUserGUID(srv, "gina", "gina@corp.test", "gina-guid-0123456")
	cfg := map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "dialect": "active_directory",
		"bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase, "deletion_threshold_percent": 100}
	orgPath := "/organizations/" + f.Acme + "/directory-connectors"
	created := f.must(f.AdminAPI("POST", orgPath, map[string]any{"name": "Acme AD", "kind": "ldap", "config": cfg, "credential": "service secret"}),
		201, "connector")
	path := orgPath + "/" + created.Str("id")
	if run := f.dirRun(t, w, path, map[string]any{"mode": "full"}); count(run, "create") != 4 {
		t.Fatalf("import: %s", run.Raw)
	}
	membership := func(user string) (id, state string) {
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id, state FROM memberships WHERE organization_id=$1 AND user_id=$2 ORDER BY created_at DESC, id DESC LIMIT 1`,
			f.Acme, user).Scan(&id, &state)
		return id, state
	}
	dave, erin, fred, gina := userIDByUsername(t, h, "dave"), userIDByUsername(t, h, "erin"), userIDByUsername(t, h, "fred"), userIDByUsername(t, h, "gina")

	// An administrator suspends erin's membership and removes fred's.
	erinM, _ := membership(erin)
	f.must(f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/members/"+erinM, map[string]any{"state": "suspended"}), 200, "suspend erin")
	fredM, _ := membership(fred)
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+fredM, nil), 204, "remove fred")
	// The directory disables dave, erin and fred: only dave's membership
	// was active, so only it is suspended by the directory.
	for _, dn := range []string{daveDN, erinDN, fredDN} {
		srv.Update(dn, map[string][]string{"userAccountControl": {"514"}})
	}
	run := f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if _, st := membership(dave); count(run, "suspend") != 1 || st != "suspended" {
		t.Fatalf("directory disable: dave %s, %s", st, run.Raw)
	}
	// ... and enables them again.
	for _, dn := range []string{daveDN, erinDN, fredDN} {
		srv.Update(dn, map[string][]string{"userAccountControl": {"512"}})
	}
	run = f.dirRun(t, w, path, map[string]any{"mode": "full"})
	_, daveState := membership(dave)
	_, erinState := membership(erin)
	_, fredState := membership(fred)
	if daveState != "active" || erinState != "suspended" || fredState != "removed" {
		t.Fatalf("re-enable: dave %s (directory suspended), erin %s (administrator suspended), fred %s (administrator removed)", daveState, erinState, fredState)
	}
	reasons := map[string]string{}
	for _, fd := range f.findings(t, path, run.Str("id"), "divergence") {
		reasons[fd["local_id"].(string)], _ = fd["reason"].(string)
	}
	if reasons[erin] != "suspended_locally" || reasons[fred] != "removed_locally" || count(run, "reactivate") != 1 {
		t.Fatalf("re-enable findings: %v %s", reasons, run.Raw)
	}
	// An administrator who re-suspends a membership the directory had
	// suspended and lifted takes it over: the next re-enable leaves it.
	daveM, _ := membership(dave)
	srv.Update(daveDN, map[string][]string{"userAccountControl": {"514"}})
	f.dirRun(t, w, path, map[string]any{"mode": "full"})
	f.must(f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/members/"+daveM, map[string]any{"state": "active"}), 200, "reactivate dave")
	f.must(f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/members/"+daveM, map[string]any{"state": "suspended"}), 200, "suspend dave")
	srv.Update(daveDN, map[string][]string{"userAccountControl": {"512"}})
	f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if _, st := membership(dave); st != "suspended" {
		t.Fatalf("membership an administrator suspended last: %s", st)
	}

	// The directory removed gina's membership when her entry disappeared;
	// it returns when the entry does (same immutable ID).
	srv.Delete(ginaDN)
	if run := f.dirRun(t, w, path, map[string]any{"mode": "full"}); count(run, "deprovision") != 1 {
		t.Fatalf("deprovisioning: %s", run.Raw)
	}
	if _, st := membership(gina); st != "removed" {
		t.Fatalf("gina after deprovisioning: %s", st)
	}
	addADUserGUID(srv, "gina", "gina@corp.test", "gina-guid-0123456")
	f.dirRun(t, w, path, map[string]any{"mode": "full"})
	if _, st := membership(gina); st != "active" {
		t.Fatalf("returning entry: gina %s", st)
	}
}

// TestOutboundLegacyConnector (PROV-010): a scim_outbound row created
// through the old /provisioning-connectors API (no destination, no
// encrypted credential) gets no deliveries and no runs, and its health
// says it needs configuration; once configured through
// /directory-connectors it delivers normally.
func TestOutboundLegacyConnector(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "out-worker")
	down := newFakeSCIM(t, "downstream token")
	legacy := ids.New(ids.Connector)
	now := h.App.D.Now()
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO provisioning_connectors (id, realm_id, organization_id, name, kind, token_digest, config, created_at, updated_at)
		VALUES ($1,$2,$3,'Legacy outbound','scim_outbound','legacy-digest','{}',$4,$4)`, legacy, h.Realm.ID, f.Acme, now); err != nil {
		t.Fatal(err)
	}
	// A delivery an earlier release queued for it is not attempted.
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO outbound_deliveries (id, realm_id, organization_id, connector_id, resource_type, local_id, trigger,
		next_attempt_at, created_at, updated_at) VALUES ($1,$2,$3,$4,'User',$5,'user.created',$6,$6,$6)`, ids.New(ids.Delivery), h.Realm.ID, f.Acme, legacy,
		f.Users["alice"], now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Events and profile edits that would reach an outbound connector.
	zoe := f.CreateUser("zoe")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": zoe, "role_ids": []string{}}), 201, "add zoe")
	h.Clock.Advance(time.Second)
	f.must(f.AdminAPI("PATCH", "/users/"+f.Users["alice"], map[string]any{"given_name": "Alicia"}), 200, "edit")
	runWorker(t, w)
	runWorker(t, w)
	var deliveries, attempted, runs int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE attempts > 0 OR state <> 'pending') FROM outbound_deliveries WHERE connector_id=$1`,
		legacy).Scan(&deliveries, &attempted)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_runs WHERE connector_id=$1`, legacy).Scan(&runs)
	if deliveries != 1 || attempted != 0 || runs != 0 || len(down.reqs()) != 0 {
		t.Fatalf("legacy connector: %d deliveries (%d attempted), %d runs, downstream %v", deliveries, attempted, runs, down.reqs())
	}
	cpath := "/organizations/" + f.Acme + "/directory-connectors/" + legacy
	health := f.must(f.AdminAPI("GET", cpath+"/health", nil), 200, "health")
	if health.Str("status") != "needs_configuration" || !strings.Contains(health.Str("configuration_error"), "base_url") {
		t.Fatalf("legacy connector health: %s", health.Raw)
	}
	if r := f.AdminAPI("POST", cpath+"/runs", map[string]any{"mode": "reconcile"}); r.Status != 409 {
		t.Fatalf("run of a legacy connector: %d %s", r.Status, r.Raw)
	}

	// Configured through /directory-connectors, it works like any other.
	cur := f.must(f.AdminAPI("GET", cpath, nil), 200, "get")
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + cpath, Token: f.AdminToken, JSON: map[string]any{"name": "Legacy outbound",
		"config": map[string]any{"base_url": down.srv.URL, "allow_private_network": true}}, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}),
		200, "configure")
	f.must(f.AdminAPI("PUT", cpath+"/credential", map[string]any{"credential": "downstream token"}), 200, "credential")
	runWorker(t, w)
	runWorker(t, w)
	if down.byExternal(f.Users["alice"]) == nil || down.byExternal(zoe) == nil {
		t.Fatalf("configured legacy connector did not deliver: %v", down.reqs())
	}
	if h := f.must(f.AdminAPI("GET", cpath+"/health", nil), 200, "health"); h.Str("status") != "healthy" || h.Get("configuration_error") != nil {
		t.Fatalf("configured connector health: %s", h.Raw)
	}
	// Configured, it must be disabled before deletion like any other; an
	// unconfigured legacy row can be retired at once.
	if r := f.AdminAPI("DELETE", cpath, nil); r.Status != 409 {
		t.Fatalf("delete of a configured active connector: %d", r.Status)
	}
	other := ids.New(ids.Connector)
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO provisioning_connectors (id, realm_id, organization_id, name, kind, token_digest, config, created_at, updated_at)
		VALUES ($1,$2,$3,'Another legacy','scim_outbound','legacy-digest-2','{}',$4,$4)`, other, h.Realm.ID, f.Acme, now); err != nil {
		t.Fatal(err)
	}
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/directory-connectors/"+other, nil), 204, "retire a legacy row")
}
