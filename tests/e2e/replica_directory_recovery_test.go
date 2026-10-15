package e2e

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/directory"
	"github.com/proudauth/proudauth/internal/directory/ldaptest"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/worker"
)

func replicaScheduledDirectory(t *testing.T, scheduled bool, root ...[]byte) (*Fixture, []*Harness, *ldaptest.Server, string, string) {
	t.Helper()
	opts := []Option{func(c *configuration.Config) {
		c.Directory.AllowPrivateNetwork = true
		c.Directory.ConnectTimeout = 2 * time.Second
		c.Directory.OperationTimeout = 10 * time.Second
	}}
	var f *Fixture
	var nodes []*Harness
	if len(root) == 0 {
		f, nodes = replicaStressFixtureWithOptions(t, opts)
	} else {
		f, nodes = replicaStressFixtureWithRoot(t, root[0], opts)
	}
	srv := corpDirectory(t)
	var dns []string
	for i := range 8 {
		sam := fmt.Sprintf("scheduled-dir-%02d", i)
		dns = append(dns, addADUser(srv, sam, sam+"@directory.example.test"))
	}
	srv.Add("CN=Scheduled Support,ou=groups,"+corpBase, map[string][]string{
		"objectClass": {"group"}, "cn": {"Scheduled Support"}, "member": {dns[0], dns[1]}})
	cfg := map[string]any{"endpoints": []string{srv.LDAPSURL()}, "ca_certificates_pem": srv.CAPEM(), "dialect": "active_directory",
		"bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase, "group_base_dn": "ou=groups," + corpBase, "page_size": 2}
	if scheduled {
		cfg["full_interval_seconds"], cfg["incremental_interval_seconds"] = 300, 60
	}
	base := "/organizations/" + f.Acme + "/directory-connectors"
	r := f.must(f.AdminAPI("POST", base, map[string]any{"name": "Scheduled AD", "kind": "ldap", "config": cfg, "credential": "service secret",
		"role_ceiling_ids":    []string{f.Roles["orders-viewer"]},
		"group_role_mappings": map[string]any{"Scheduled Support": []string{f.Roles["orders-viewer"]}}}), 201, "scheduled connector")
	return f, nodes, srv, r.Str("id"), base + "/" + r.Str("id")
}

func replicaDirectoryScheduleBurst(t *testing.T, nodes []*Harness) int {
	t.Helper()
	const concurrency = 32
	type result struct {
		n   int
		err error
	}
	out := make([]result, concurrency)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(concurrency)
	done.Add(concurrency)
	for i := range out {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			out[i].n, out[i].err = nodes[i%len(nodes)].App.Directory.Schedule(context.Background())
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	total := 0
	for _, r := range out {
		if r.err != nil {
			t.Fatal(r.err)
		}
		total += r.n
	}
	return total
}

// TestReplicaDirectoryScheduleStress covers PROV-012, PROV-018, DEP-011
// and NFR-007: 32 schedulers competing across independent pools claim one
// full/incremental slot, roll back blocked claims and never replay overdue slots.
func TestReplicaDirectoryScheduleStress(t *testing.T) {
	f, nodes, srv, connector, path := replicaScheduledDirectory(t, true)
	ctx := context.Background()
	manual := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "initial manual sync")
	if n := replicaDirectoryScheduleBurst(t, nodes); n != 0 {
		t.Fatalf("scheduled over an active manual run: %d", n)
	}
	for _, n := range nodes {
		var unchanged bool
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT next_sync_at IS NULL AND next_full_sync_at IS NULL FROM provisioning_connectors WHERE id=$1`, connector).Scan(&unchanged); err != nil || !unchanged {
			t.Fatalf("blocked schedule did not roll back its slot: %v", err)
		}
	}
	replicaDirectoryWorkers(t, f, nodes, path, manual)
	wantRuns := 1
	for step, profile := range []struct {
		advance time.Duration
		mode    string
		seen    int
	}{
		{0, "full", 8}, {59 * time.Second, "", 0}, {time.Second, "incremental", 1}, {240 * time.Second, "full", 8},
	} {
		f.H.Clock.Advance(profile.advance)
		if step == 2 {
			srv.Update("CN=scheduled-dir-02,ou=people,"+corpBase, map[string][]string{"displayName": {"Scheduled Change"}})
		}
		if step == 3 {
			f.ReloginAdmin()
		}
		want := 1
		if profile.mode == "" {
			want = 0
		}
		if n := replicaDirectoryScheduleBurst(t, nodes); n != want {
			t.Fatalf("schedule step %d accepted %d slots, want %d", step, n, want)
		}
		if want == 0 {
			continue
		}
		wantRuns++
		if n := replicaDirectoryScheduleBurst(t, nodes); n != 0 {
			t.Fatalf("claimed scheduled slot replayed: %d", n)
		}
		listed := f.must(f.AdminAPI("GET", path+"/runs", nil), 200, "scheduled runs")
		var active *Resp
		for _, item := range listed.Get("items").([]any) {
			it := item.(map[string]any)
			if it["state"] == "queued" {
				active = f.must(f.AdminAPI("GET", path+"/runs/"+it["id"].(string), nil), 200, "queued schedule")
			}
		}
		if active == nil || active.Str("mode") != profile.mode || active.Str("trigger") != "schedule" {
			t.Fatal("scheduler did not publish its sole expected run")
		}
		replicaDirectoryWorkers(t, f, nodes, path, active)
		for _, n := range nodes {
			var next, nextFull time.Time
			var runs, completions, requests, users, links, provisions int
			var cursor string
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT p.next_sync_at,p.next_full_sync_at,coalesce(p.cursor,''),
				(SELECT count(*) FROM directory_sync_runs WHERE connector_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='directory.sync.completed' AND metadata->>'run_id'=$2),
				(SELECT count(*) FROM audit_events WHERE type='directory.sync.requested' AND metadata->>'run_id'=$2),
				(SELECT count(*) FROM users WHERE created_via='directory:' || $1),
				(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='directory.user.provisioned' AND actor_id=$1)
				FROM provisioning_connectors p WHERE p.id=$1`, connector, active.Str("id")).Scan(&next, &nextFull, &cursor, &runs, &completions, &requests, &users, &links, &provisions); err != nil {
				t.Fatal(err)
			}
			wantFull := f.H.Clock.Now().Add(300 * time.Second)
			if profile.mode == "incremental" {
				wantFull = f.H.Clock.Now().Add(240 * time.Second)
			}
			result := n.API("GET", path+"/runs/"+active.Str("id"), f.AdminToken, nil)
			mustStatus(t, result, 200, "completed schedule")
			if !next.Equal(n.Clock.Now().Add(60*time.Second)) || !nextFull.Equal(wantFull) || cursor == "" || runs != wantRuns || completions != 1 || requests != 0 || users != 8 || links != 9 || provisions != 8 ||
				result.Str("state") != "succeeded" || count(result, "entries_seen") != profile.seen || count(result, "create") != 0 || count(result, "error") != 0 || count(result, "conflict") != 0 {
				t.Fatalf("schedule step %d: next=%v full=%v runs/completions/manual-requests/users/links/provisions=%d/%d/%d/%d/%d/%d result=%s",
					step, next, nextFull, runs, completions, requests, users, links, provisions, result.Raw)
			}
		}
	}
	if n := replicaDirectoryScheduleBurst(t, nodes); n != 0 {
		t.Fatalf("scheduler replayed completed current slots: %d", n)
	}
}

// TestReplicaDirectoryExpiredLeaseRecovery covers PROV-007, PROV-012,
// PROV-018, DEP-011, TEST-058 and NFR-007. A real handler pauses after two
// committed users, its lease expires and another worker repeats the scan.
// The late original worker must not overwrite the recovered run or job.
func TestReplicaDirectoryExpiredLeaseRecovery(t *testing.T) {
	f, nodes, _, connector, path := replicaScheduledDirectory(t, false)
	h := f.H
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "recovery run")
	old := worker.New(nodes[0].App, "directory-stalled")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	handler := old.Handlers[directory.JobType]
	old.Handlers[directory.JobType] = func(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
		first := true
		return handler(ctx, j, func(p map[string]any) error {
			if first {
				first = false
				if err := progress(p); err != nil {
					return err
				}
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				// Resume without a heartbeat: the next domain transaction,
				// rather than progress renewal, must fence the stale worker.
				return nil
			}
			return progress(p)
		})
	}
	done := make(chan error, 1)
	var all sync.WaitGroup
	all.Add(1)
	go func() { defer all.Done(); _, err := old.RunJobs(ctx); done <- err }()
	defer func() { unblock(); cancel(); all.Wait() }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original directory worker did not commit its first page")
	}
	var imported, checkpoint int
	var cursor string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User'),
		(j.checkpoint->>'processed')::int,coalesce(p.cursor,'')
		FROM jobs j JOIN provisioning_connectors p ON p.id=$1 WHERE j.id=$2`, connector, run.Str("job_id")).Scan(&imported, &checkpoint, &cursor); err != nil {
		t.Fatal(err)
	}
	if imported != 2 || checkpoint != 2 || cursor != "" {
		t.Fatalf("partial scan state: %d imports, checkpoint %d, cursor %q", imported, checkpoint, cursor)
	}
	var firstUsers []string
	rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT local_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' ORDER BY local_id`, connector)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		firstUsers = append(firstUsers, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	h.Clock.Advance(h.Cfg.Workers.LeaseDuration + time.Second)
	replacement := worker.New(nodes[1].App, "directory-replacement")
	if n, err := replacement.RunJobs(ctx); n != 1 || err != nil {
		t.Fatalf("expired lease recovery: %d/%v", n, err)
	}
	completed := nodes[2].API("GET", path+"/runs/"+run.Str("id"), f.AdminToken, nil)
	mustStatus(t, completed, 200, "recovered run")
	if completed.Str("state") != "succeeded" || count(completed, "create") != 6 || count(completed, "entries_seen") != 8 || completed.Str("cursor_after") == "" {
		t.Fatalf("recovered directory scan: %s", completed.Raw)
	}
	beforeLate := replicaDirectorySnapshot(t, h, connector)
	unblock()
	select {
	case err := <-done:
		if err == nil {
			t.Error("late worker reported success after losing its lease")
		}
	case <-ctx.Done():
		t.Fatal("late worker did not stop")
	}
	for _, n := range nodes {
		var state, jobState, jobRunState, finalCursor string
		var attempts, users, links, groups, members, roles, audits, provisions, retained int
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT r.state,j.state,j.result->>'state',coalesce(p.cursor,''),j.attempts,
			(SELECT count(*) FROM users WHERE created_via='directory:' || $1),
			(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1),
			(SELECT count(*) FROM groups g JOIN connector_external_ids x ON x.local_id=g.id AND x.resource_type='Group' WHERE x.connector_id=$1),
			(SELECT count(*) FROM group_memberships m JOIN connector_external_ids x ON x.local_id=m.group_id AND x.resource_type='Group' WHERE x.connector_id=$1),
			(SELECT count(*) FROM role_assignments a JOIN connector_external_ids x ON x.local_id=a.subject_id AND x.resource_type='Group' WHERE x.connector_id=$1 AND a.source='directory'),
			(SELECT count(*) FROM audit_events WHERE type='directory.sync.completed' AND metadata->>'run_id'=r.id),
			(SELECT count(*) FROM audit_events WHERE type='directory.user.provisioned' AND actor_id=$1),
			(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=ANY($3))
			FROM directory_sync_runs r JOIN jobs j ON j.id=r.job_id JOIN provisioning_connectors p ON p.id=r.connector_id WHERE p.id=$1 AND r.id=$2`,
			connector, run.Str("id"), firstUsers).Scan(&state, &jobState, &jobRunState, &finalCursor, &attempts, &users, &links, &groups, &members, &roles, &audits, &provisions, &retained); err != nil {
			t.Fatal(err)
		}
		if state != "succeeded" || jobState != "succeeded" || jobRunState != "succeeded" || finalCursor != completed.Str("cursor_after") ||
			attempts != 2 || users != 8 || links != 9 || groups != 1 || members != 2 || roles != 1 || audits != 1 || provisions != 8 || retained != 2 {
			t.Errorf("late worker corrupted recovery: run/job/result=%s/%s/%s, attempts/users/links/groups/members/roles/completions/provisions/retained=%d/%d/%d/%d/%d/%d/%d/%d/%d",
				state, jobState, jobRunState, attempts, users, links, groups, members, roles, audits, provisions, retained)
		}
		if replicaDirectorySnapshot(t, n, connector) != beforeLate {
			t.Error("late worker changed recovered directory state")
		}
	}
}
