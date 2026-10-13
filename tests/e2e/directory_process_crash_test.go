package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/directory"
	"github.com/proudbase/proudauth/internal/httpapi"
	"github.com/proudbase/proudauth/internal/jobs"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/observability"
	"github.com/proudbase/proudauth/internal/platform/clock"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/server"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/worker"
)

const directoryCrashChildEnv = "PROUDAUTH_DIRECTORY_CRASH_CHILD"
const directoryCrashPageMarker = "directory-page-committed"

// This packet remains in the child's environment, never in published evidence.
type directoryCrashPacket struct {
	Config  configuration.Config
	RootKey string
	Now     time.Time
	JobID   string
}

func directoryCrashChild(t *testing.T, packet string) {
	t.Helper()
	var p directoryCrashPacket
	if err := json.Unmarshal([]byte(packet), &p); err != nil {
		t.Fatal("invalid crash-worker packet")
	}
	root, err := hex.DecodeString(p.RootKey)
	if err != nil || len(root) != 32 {
		t.Fatal("invalid crash-worker root material")
	}
	if err := p.Config.Validate(); err != nil {
		t.Fatalf("crash-worker config: %v", err)
	}
	db, err := storage.Open(t.Context(), p.Config.Storage.DatabaseURL, storage.Options{MaxConns: 10})
	if err != nil {
		t.Fatalf("crash-worker database: %v", err)
	}
	defer db.Close()
	keyring, err := keys.New(map[uint32][]byte{1: root}, 1)
	if err != nil {
		t.Fatal(err)
	}
	deps := runtime.New(db, &p.Config, clock.NewFake(p.Now), keyring, observability.NewLogger(io.Discard, "error", "json"))
	app, err := httpapi.Build(deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.KeyMgr.RSABits = 2048
	server.RegisterModules(app)
	w := worker.New(app, "directory-native-crash")
	handler := w.Handlers[directory.JobType]
	// Run the production jobs task, limited to the requested fixture job type.
	w.Handlers = map[string]jobs.Handler{directory.JobType: func(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
		if j.ID != p.JobID {
			return nil, nil, errors.New("unexpected crash-worker job")
		}
		return handler(ctx, j, func(page map[string]any) error {
			if err := progress(page); err != nil {
				return err
			}
			fmt.Println(directoryCrashPageMarker)
			<-ctx.Done()
			return ctx.Err()
		})
	}}
	if _, err := w.RunJobs(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash worker ended without being killed")
}

func directoryWorkerAtFirstPage(t *testing.T, f *Fixture, root []byte, jobID string) func() {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := *f.H.Cfg
	cfg.Storage.DatabaseURL = f.H.App.D.DB.Pool.Config().ConnString()
	packet, err := json.Marshal(directoryCrashPacket{Config: cfg, RootKey: hex.EncodeToString(root), Now: f.H.Clock.Now(), JobID: jobID})
	if err != nil {
		t.Fatal("cannot encode crash-worker packet")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestDirectoryProcessCrashRecovery$", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), directoryCrashChildEnv+"="+string(packet))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		cancel()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
		}
	})
	ready := make(chan error, 1)
	go func() {
		scan := bufio.NewScanner(out)
		for scan.Scan() {
			if scan.Text() == directoryCrashPageMarker {
				ready <- nil
				return
			}
		}
		err := scan.Err()
		if err == nil {
			err = errors.New("worker exited before its first page")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
			t.Fatalf("crash-worker readiness: %v; %s", err, stderr.String())
		}
	case <-ctx.Done():
		t.Fatal("native worker did not commit a first page")
	}
	return func() {
		t.Helper()
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("kill native worker: %v", err)
		}
		err := cmd.Wait()
		waited = true
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != -1 {
			t.Fatalf("worker did not end from the explicit OS kill: %v", err)
		}
		cancel()
	}
}

// TestDirectoryProcessCrashRecovery covers PROV-007, PROV-012, PROV-018,
// DEP-011, TEST-058 and NFR-007: a separately exec'd real jobs task is killed
// after committing/checkpointing one LDAP page. Independent replicas cannot
// reclaim its unexpired lease; after expiry, one worker safely repeats full or
// incremental scans without replacing accounts or duplicating mutation audits.
func TestDirectoryProcessCrashRecovery(t *testing.T) {
	if packet := os.Getenv(directoryCrashChildEnv); packet != "" {
		directoryCrashChild(t, packet)
		return
	}
	for _, mode := range []string{"full", "incremental"} {
		t.Run(mode, func(t *testing.T) {
			root := secret.Random(32)
			f, nodes, srv, connector, path := replicaScheduledDirectory(t, false, root)
			ctx := context.Background()
			var beforeCursor string
			if mode == "incremental" {
				baseline := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "baseline full sync")
				replicaDirectoryWorkers(t, f, nodes, path, baseline)
				if err := f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT cursor FROM provisioning_connectors WHERE id=$1`, connector).Scan(&beforeCursor); err != nil {
					t.Fatal(err)
				}
				for i := range 4 {
					srv.Update(fmt.Sprintf("CN=scheduled-dir-%02d,ou=people,%s", i, corpBase), map[string][]string{"displayName": {fmt.Sprintf("Crash Incremental %d", i)}})
				}
				srv.Update("CN=Scheduled Support,ou=groups,"+corpBase, map[string][]string{"member": {"CN=scheduled-dir-00,ou=people," + corpBase}})
			}
			srv.ResetCounters()
			run := replicaDirectoryRequest(t, f, nodes, path, mode, false)
			kill := directoryWorkerAtFirstPage(t, f, root, run.Str("job_id"))
			var imports, updates, checkpoint int
			var cursor string
			if err := f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM audit_events WHERE type='directory.user.provisioned' AND actor_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='directory.user.updated' AND actor_id=$1),
				(j.checkpoint->>'processed')::int,coalesce(p.cursor,'')
				FROM provisioning_connectors p JOIN jobs j ON j.id=$2 WHERE p.id=$1`, connector, run.Str("job_id")).Scan(&imports, &updates, &checkpoint, &cursor); err != nil {
				t.Fatal(err)
			}
			wantImports, wantUpdates := 2, 0
			if mode == "incremental" {
				wantImports, wantUpdates = 8, 2
			}
			if imports != wantImports || updates != wantUpdates || checkpoint != 2 || cursor != beforeCursor {
				t.Fatalf("native partial scan: imports/updates/checkpoint %d/%d/%d, cursor advanced=%v", imports, updates, checkpoint, cursor != beforeCursor)
			}
			var originalIDs []string
			rows, err := f.H.App.D.DB.Pool.Query(ctx, `SELECT local_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' ORDER BY local_id`, connector)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				originalIDs = append(originalIDs, id)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			kill()
			for _, n := range nodes {
				var stranded bool
				if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT j.state='running' AND r.state='running' AND j.attempts=1
					AND j.lease_owner='directory-native-crash' AND j.lease_expires_at>$2
					AND r.finished_at IS NULL FROM jobs j JOIN directory_sync_runs r ON r.job_id=j.id WHERE j.id=$1`, run.Str("job_id"), n.Clock.Now()).Scan(&stranded); err != nil || !stranded {
					t.Fatalf("OS kill performed graceful finalization: %v", err)
				}
				if count, err := worker.New(n.App, "early-replacement").RunJobs(ctx); err != nil || count != 0 {
					t.Fatalf("reclaimed a live crash lease: %d/%v", count, err)
				}
			}
			for _, r := range replicaBurst(t, nodes, 32, func(_ int, n *Harness) *Resp {
				return n.API("POST", path+"/runs", f.AdminToken, map[string]any{"mode": mode})
			}) {
				if r.Status != 409 || r.Str("run_id") != run.Str("id") {
					t.Fatalf("new run bypassed crashed job's active lease: %d", r.Status)
				}
			}
			f.H.Clock.Advance(f.H.Cfg.Workers.LeaseDuration + time.Second)
			replicaDirectoryWorkers(t, f, nodes, path, run, 2)
			_, _, filters := srv.Stats()
			if mode == "incremental" && !strings.Contains(strings.Join(filters, " "), "uSNChanged>=") {
				t.Fatal("crash recovery discarded the incremental cursor")
			}
			for _, n := range nodes {
				result := n.API("GET", path+"/runs/"+run.Str("id"), f.AdminToken, nil)
				mustStatus(t, result, 200, "native crash recovery result")
				seen, creates, changes, members, removed := 8, 6, 0, 2, 0
				if mode == "incremental" {
					seen, creates, changes, members, removed = 4, 0, 2, 1, 1
				}
				if result.Str("state") != "succeeded" || result.Str("mode") != mode || count(result, "entries_seen") != seen || count(result, "create") != creates || count(result, "update") != changes || count(result, "error") != 0 || count(result, "conflict") != 0 || result.Str("cursor_after") == "" || result.Str("cursor_after") == beforeCursor {
					t.Fatalf("native %s recovery: %s", mode, result.Raw)
				}
				var users, links, groups, groupMembers, roles, provisions, mutations, adds, removes, completions, retained, attempts int
				var jobOK, cursorOK bool
				if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT
					(SELECT count(*) FROM users WHERE created_via='directory:' || $1),
					(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1),
					(SELECT count(*) FROM groups g JOIN connector_external_ids x ON x.local_id=g.id AND x.resource_type='Group' WHERE x.connector_id=$1),
					(SELECT count(*) FROM group_memberships m JOIN connector_external_ids x ON x.local_id=m.group_id AND x.resource_type='Group' WHERE x.connector_id=$1),
					(SELECT count(*) FROM role_assignments a JOIN connector_external_ids x ON x.local_id=a.subject_id AND x.resource_type='Group' WHERE x.connector_id=$1 AND a.source='directory'),
					(SELECT count(*) FROM audit_events WHERE type='directory.user.provisioned' AND actor_id=$1),
					(SELECT count(*) FROM audit_events WHERE type='directory.user.updated' AND actor_id=$1),
					(SELECT count(*) FROM audit_events a JOIN connector_external_ids x ON x.local_id=a.target_id AND x.resource_type='Group' WHERE x.connector_id=$1 AND a.type='group.member.added'),
					(SELECT count(*) FROM audit_events a JOIN connector_external_ids x ON x.local_id=a.target_id AND x.resource_type='Group' WHERE x.connector_id=$1 AND a.type='group.member.removed'),
					(SELECT count(*) FROM audit_events WHERE type='directory.sync.completed' AND metadata->>'run_id'=r.id),
					(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=ANY($3)),
					j.attempts,j.state='succeeded' AND j.result->>'state'='succeeded' AND j.lease_owner IS NULL AND j.lease_expires_at IS NULL,
					p.cursor=r.cursor_after FROM directory_sync_runs r JOIN jobs j ON j.id=r.job_id JOIN provisioning_connectors p ON p.id=r.connector_id WHERE p.id=$1 AND r.id=$2`, connector, run.Str("id"), originalIDs).
					Scan(&users, &links, &groups, &groupMembers, &roles, &provisions, &mutations, &adds, &removes, &completions, &retained, &attempts, &jobOK, &cursorOK); err != nil {
					t.Fatal(err)
				}
				wantMutations := 0
				if mode == "incremental" {
					wantMutations = 4
				}
				if users != 8 || links != 9 || groups != 1 || groupMembers != members || roles != 1 || provisions != 8 || mutations != wantMutations || adds != 2 || removes != removed || completions != 1 || retained != len(originalIDs) || attempts != 2 || !jobOK || !cursorOK {
					t.Fatalf("native %s recovery lost identity/group/audit/job/cursor invariants", mode)
				}
				var activeMemberships int
				if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN connector_external_ids x ON x.local_id=m.user_id AND x.resource_type='User'
					WHERE x.connector_id=$1 AND m.organization_id=$2 AND m.state='active'`, connector, f.Acme).Scan(&activeMemberships); err != nil || activeMemberships != 8 {
					t.Fatalf("native crash lost organization memberships: %d/%v", activeMemberships, err)
				}
				if mode == "incremental" {
					for i := range 4 {
						var display string
						if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id=$1`, userIDByUsername(t, n, fmt.Sprintf("scheduled-dir-%02d", i))).Scan(&display); err != nil || display != fmt.Sprintf("Crash Incremental %d", i) {
							t.Fatalf("recovered incremental attribute %d: %q/%v", i, display, err)
						}
					}
				}
				replicaGroupPermission(t, n, f, userIDByUsername(t, n, "scheduled-dir-00"), true)
				replicaGroupPermission(t, n, f, userIDByUsername(t, n, "scheduled-dir-01"), mode == "full")
			}
			t.Logf("%s: native worker killed after page 1, lease reclaimed at attempt 2; exact accounts, Group authority, cursor and audits on three pools", mode)
		})
	}
}
