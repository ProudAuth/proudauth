package e2e

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/directory"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/worker"
)

func replicaDirectoryRequest(t *testing.T, f *Fixture, nodes []*Harness, path, mode string, dry bool) *Resp {
	t.Helper()
	results := replicaBurst(t, nodes, 32, func(_ int, n *Harness) *Resp {
		return n.API("POST", path+"/runs", f.AdminToken, map[string]any{"mode": mode, "dry_run": dry})
	})
	var accepted *Resp
	for _, r := range results {
		if r.Status == 202 && accepted == nil {
			accepted = r
		} else if r.Status != 409 || r.Str("code") != "conflict" {
			t.Fatalf("directory request: %d/%s; require one accepted run and 31 conflicts", r.Status, r.Str("code"))
		}
	}
	if accepted == nil || accepted.Str("id") == "" || accepted.Str("job_id") == "" {
		t.Fatal("directory burst created no durable run/job")
	}
	for _, r := range results {
		if r.Status == 409 && r.Str("run_id") != accepted.Str("id") {
			t.Fatal("losing requester did not identify the sole active run")
		}
	}
	return accepted
}

// Hold the first committed page at the handler's real progress boundary.
// Other workers must finish without claiming it; public run requests during
// this partial scan must still conflict. No directory handler bypasses leases.
func replicaDirectoryWorkers(t *testing.T, f *Fixture, nodes []*Harness, path string, run *Resp, attempts ...int) {
	t.Helper()
	wantAttempts := 1
	if len(attempts) != 0 {
		wantAttempts = attempts[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	release, entered := make(chan struct{}), make(chan *jobs.Job, len(nodes))
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var held atomic.Bool
	var calls atomic.Int32
	type result struct {
		n   int
		err error
	}
	done := make(chan result, len(nodes))
	start := make(chan struct{})
	var all sync.WaitGroup
	for i, n := range nodes {
		w := worker.New(n.App, fmt.Sprintf("directory-replica-%d", i))
		handler := w.Handlers[directory.JobType]
		w.Handlers[directory.JobType] = func(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
			calls.Add(1)
			return handler(ctx, j, func(p map[string]any) error {
				if held.CompareAndSwap(false, true) {
					entered <- j
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return progress(p)
			})
		}
		all.Add(1)
		go func() {
			defer all.Done()
			<-start
			n, err := w.RunJobs(ctx)
			done <- result{n, err}
		}()
	}
	defer func() { unblock(); cancel(); all.Wait() }()
	close(start)
	select {
	case j := <-entered:
		if j.ID != run.Str("job_id") {
			t.Fatal("worker reached an unrelated job")
		}
	case <-ctx.Done():
		t.Fatal("directory worker did not reach its first page")
	}
	for range len(nodes) - 1 {
		select {
		case r := <-done:
			if r.n != 0 || r.err != nil {
				t.Fatalf("competing worker claimed leased directory work: %d/%v", r.n, r.err)
			}
		case <-ctx.Done():
			t.Fatal("non-owning worker did not finish its claim attempt")
		}
	}
	for _, n := range nodes {
		var active bool
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT r.state='running' AND j.state='running' AND j.attempts=$3
			AND j.lease_owner IS NOT NULL AND j.lease_expires_at>$2
			FROM directory_sync_runs r JOIN jobs j ON j.id=r.job_id WHERE r.id=$1`, run.Str("id"), n.Clock.Now(), wantAttempts).Scan(&active); err != nil || !active {
			t.Fatalf("replica lost the sole running lease: %v", err)
		}
	}
	for _, r := range replicaBurst(t, nodes, 32, func(_ int, n *Harness) *Resp {
		return n.API("POST", path+"/runs", f.AdminToken, map[string]any{"mode": "full"})
	}) {
		if r.Status != 409 || r.Str("code") != "conflict" || r.Str("run_id") != run.Str("id") {
			t.Fatalf("request during partial scan: %d/%s", r.Status, r.Str("code"))
		}
	}
	unblock()
	select {
	case r := <-done:
		if r.n != 1 || r.err != nil || calls.Load() != 1 {
			t.Fatalf("directory handlers/claims %d/%d: %v", calls.Load(), r.n, r.err)
		}
	case <-ctx.Done():
		t.Fatal("directory scan did not finish after release")
	}
}

func replicaDirectorySnapshot(t *testing.T, n *Harness, connector string) string {
	t.Helper()
	var snapshot string
	err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT jsonb_build_object(
		'cursor',p.cursor,
		'links',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.resource_type,x.external_id) FROM connector_external_ids x WHERE x.connector_id=p.id),
		'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY u.id) FROM users u JOIN connector_external_ids x ON x.local_id=u.id AND x.resource_type='User' WHERE x.connector_id=p.id),
		'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) FROM memberships m JOIN connector_external_ids x ON x.local_id=m.user_id AND x.resource_type='User' WHERE x.connector_id=p.id AND m.organization_id=p.organization_id),
		'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM groups g JOIN connector_external_ids x ON x.local_id=g.id AND x.resource_type='Group' WHERE x.connector_id=p.id),
		'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.group_id,m.membership_id) FROM group_memberships m JOIN connector_external_ids x ON x.local_id=m.group_id AND x.resource_type='Group' WHERE x.connector_id=p.id),
		'roles',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM role_assignments a JOIN connector_external_ids x ON x.local_id=a.subject_id AND x.resource_type='Group' WHERE x.connector_id=p.id)
		)::text FROM provisioning_connectors p WHERE p.id=$1`, connector).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// TestReplicaDirectorySynchronizationStress covers PROV-007, PROV-012,
// PROV-017, PROV-018, TEST-048, TEST-049 and NFR-007. Public concurrency-32
// requests create one run; three independent workers compete through actual
// job leases. Paged full, incremental dry-run, applied incremental and repeat
// full scans preserve exact source identity, Group authority and admin state.
func TestReplicaDirectorySynchronizationStress(t *testing.T) {
	f, nodes := replicaStressFixtureWithOptions(t, []Option{func(c *configuration.Config) {
		c.Directory.AllowPrivateNetwork = true
		c.Directory.ConnectTimeout = 2 * time.Second
		c.Directory.OperationTimeout = 10 * time.Second
	}})
	h := f.H
	ctx := context.Background()
	srv := corpDirectory(t)
	dns := make([]string, 8)
	for i := range dns {
		sam := fmt.Sprintf("replica-dir-%02d", i)
		dns[i] = addADUser(srv, sam, sam+"@directory.example.test")
	}
	groupDN := "CN=Replica Support,ou=groups," + corpBase
	srv.Add(groupDN, map[string][]string{"objectClass": {"group"}, "cn": {"Replica Support"}, "member": {dns[0], dns[1]}})
	base := "/organizations/" + f.Acme + "/directory-connectors"
	created := f.must(f.AdminAPI("POST", base, map[string]any{"name": "Replica AD", "kind": "ldap", "credential": "service secret",
		"config": map[string]any{"endpoints": []string{srv.LDAPSURL()}, "ca_certificates_pem": srv.CAPEM(), "dialect": "active_directory",
			"bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase, "group_base_dn": "ou=groups," + corpBase, "page_size": 2},
		"role_ceiling_ids":    []string{f.Roles["orders-viewer"], f.Roles["member"]},
		"group_role_mappings": map[string]any{"Replica Support": []string{f.Roles["orders-viewer"]}}}), 201, "replica directory connector")
	connector, path := created.Str("id"), base+"/"+created.Str("id")
	var group, user0, user1, user2, fullCursor, beforeDry string
	for phase, profile := range []struct {
		mode string
		dry  bool
		seen int
	}{{"full", false, 8}, {"incremental", true, 1}, {"incremental", false, 1}, {"full", false, 8}} {
		if phase == 1 {
			f.must(f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/groups/"+group, map[string]any{
				"description": "Preserve administrator state", "metadata": map[string]any{"proof": "preserved"}}), 200, "group metadata")
			f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+group+"/roles", map[string]any{"role_id": f.Roles["member"]}), 201, "administrator role")
			srv.Update(dns[2], map[string][]string{"displayName": {"Incremental Display"}})
			srv.Update(groupDN, map[string][]string{"member": {dns[0]}})
			beforeDry = replicaDirectorySnapshot(t, h, connector)
		}
		srv.ResetCounters()
		run := replicaDirectoryRequest(t, f, nodes, path, profile.mode, profile.dry)
		replicaDirectoryWorkers(t, f, nodes, path, run)
		_, searches, filters := srv.Stats()
		if profile.mode == "incremental" && !strings.Contains(strings.Join(filters, " "), "uSNChanged>=") {
			t.Fatal("incremental scan ignored its domain-controller cursor")
		}
		if profile.mode == "full" && searches < 6 {
			t.Fatalf("full scan did not cross page boundaries: %d searches", searches)
		}
		if phase == 0 {
			user0, user1, user2 = userIDByUsername(t, h, "replica-dir-00"), userIDByUsername(t, h, "replica-dir-01"), userIDByUsername(t, h, "replica-dir-02")
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT local_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group'`, connector).Scan(&group); err != nil {
				t.Fatal(err)
			}
		}
		for _, n := range nodes {
			result := n.API("GET", path+"/runs/"+run.Str("id"), f.AdminToken, nil)
			mustStatus(t, result, 200, "replica run result")
			wantCreate, wantUpdate := 0, 0
			if phase == 0 {
				wantCreate = 8
			}
			if phase == 1 || phase == 2 {
				wantUpdate = 1
			}
			if result.Str("state") != "succeeded" || result.Str("mode") != profile.mode || count(result, "entries_seen") != profile.seen ||
				count(result, "create") != wantCreate || count(result, "update") != wantUpdate || count(result, "error") != 0 || count(result, "conflict") != 0 {
				t.Fatalf("phase %d: unexpected directory effects: %s", phase, result.Raw)
			}
			var runs, complete, requests, completions, attempts int
			var jobOK bool
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM directory_sync_runs WHERE connector_id=$1),
				(SELECT count(*) FROM directory_sync_runs WHERE connector_id=$1 AND state='succeeded'),
				(SELECT count(*) FROM audit_events WHERE type='directory.sync.requested' AND metadata->>'run_id'=$2),
				(SELECT count(*) FROM audit_events WHERE type='directory.sync.completed' AND metadata->>'run_id'=$2),
				j.attempts,j.state='succeeded' AND j.lease_owner IS NULL AND j.lease_expires_at IS NULL FROM jobs j WHERE j.id=$3`,
				connector, run.Str("id"), run.Str("job_id")).Scan(&runs, &complete, &requests, &completions, &attempts, &jobOK); err != nil {
				t.Fatal(err)
			}
			wantCompletedAudit := 1
			if profile.dry {
				wantCompletedAudit = 0
			}
			if runs != phase+1 || complete != runs || requests != 1 || completions != wantCompletedAudit || attempts != 1 || !jobOK {
				t.Fatalf("phase %d durable runs/jobs/audits: %d/%d/%d/%d/%d/%v", phase, runs, complete, requests, completions, attempts, jobOK)
			}
			var links, users, memberships, groups, groupMembers, directoryRoles, adminRoles, provisions, updates, adds, removes, operatorRuns int
			var display, cursor string
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1),
				(SELECT count(*) FROM users WHERE created_via='directory:' || $1),
				(SELECT count(*) FROM memberships m JOIN connector_external_ids x ON x.local_id=m.user_id AND x.resource_type='User' WHERE x.connector_id=$1 AND m.organization_id=$2 AND m.state='active'),
				(SELECT count(*) FROM groups WHERE id=$3),
				(SELECT count(*) FROM group_memberships WHERE group_id=$3),
				(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$3 AND source='directory' AND role_id=$4),
				(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$3 AND source='admin' AND role_id=$5),
				(SELECT count(*) FROM audit_events WHERE type='directory.user.provisioned' AND actor_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='directory.user.updated' AND actor_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='group.member.added' AND target_id=$3),
				(SELECT count(*) FROM audit_events WHERE type='group.member.removed' AND target_id=$3),
				(SELECT count(*) FROM jsonb_array_elements(p.evidence->'operator_actions') a WHERE a->>'action' LIKE 'run_%'),
				(SELECT display_name FROM users WHERE id=$6),coalesce(p.cursor,'') FROM provisioning_connectors p WHERE p.id=$1`,
				connector, f.Acme, group, f.Roles["orders-viewer"], f.Roles["member"], user2).Scan(&links, &users, &memberships, &groups, &groupMembers,
				&directoryRoles, &adminRoles, &provisions, &updates, &adds, &removes, &operatorRuns, &display, &cursor); err != nil {
				t.Fatal(err)
			}
			wantMembers, wantUpdates, wantRemoves, wantAdmin := 2, 0, 0, 0
			wantDisplay := "replica-dir-02 Corp"
			if phase > 0 {
				wantAdmin = 1
			}
			if phase >= 2 {
				wantMembers, wantUpdates, wantRemoves, wantDisplay = 1, 1, 1, "Incremental Display"
			}
			if links != 9 || users != 8 || memberships != 8 || groups != 1 || groupMembers != wantMembers || directoryRoles != 1 || adminRoles != wantAdmin ||
				provisions != 8 || updates != wantUpdates || adds != 2 || removes != wantRemoves || operatorRuns != phase+1 || display != wantDisplay || cursor == "" {
				t.Fatalf("phase %d: links/users/memberships/groups/members/roles/admin/provisions/updates/adds/removes/requests/display: %d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%q",
					phase, links, users, memberships, groups, groupMembers, directoryRoles, adminRoles, provisions, updates, adds, removes, operatorRuns, display)
			}
			if phase == 0 {
				fullCursor = cursor
			}
			if phase == 1 && (cursor != fullCursor || replicaDirectorySnapshot(t, n, connector) != beforeDry) {
				t.Fatal("dry-run changed a cursor, source link, account, membership, group or role")
			}
			if phase >= 2 && (cursor == fullCursor || result.Str("cursor_after") != cursor) {
				t.Fatal("applied incremental cursor was not durable on every replica")
			}
			if phase > 0 {
				local := n.API("GET", "/organizations/"+f.Acme+"/groups/"+group, f.AdminToken, nil)
				mustStatus(t, local, 200, "preserved group")
				if local.Str("description") != "Preserve administrator state" || local.Str("metadata.proof") != "preserved" {
					t.Fatal("directory scan overwrote administrator group metadata")
				}
			}
			replicaGroupPermission(t, n, f, user0, true)
			replicaGroupPermission(t, n, f, user1, phase < 2)
			replicaGroupPermission(t, n, f, user2, false)
		}
		t.Logf("phase %d %s dry=%v: one request/job/handler, 63 conflicts, exact users/groups/cursor and authority on all three pools", phase+1, profile.mode, profile.dry)
	}
}
