package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/directory"
	"github.com/proudauth/proudauth/internal/directory/ldaptest"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestDirectoryTransportScanConsistency covers PROV-007, PROV-012,
// PROV-014, PROV-017, PROV-018, TEST-058 and NFR-007. Actual LDAPS connections
// are dropped after a committed page. A complete replacement endpoint alone
// determines deletion; exhaustion cannot deprovision from a partial scan.
func TestDirectoryTransportScanConsistency(t *testing.T) {
	for _, profile := range []string{"full-failover", "incremental-failover", "exhausted-then-recover"} {
		t.Run(profile, func(t *testing.T) {
			f, nodes, primary, connector, path := replicaScheduledDirectory(t, false)
			ctx := context.Background()
			baseline := f.must(f.AdminAPI("POST", path+"/runs", map[string]any{"mode": "full"}), 202, "transport baseline")
			replicaDirectoryWorkers(t, f, nodes, path, baseline)
			missing := userIDByUsername(t, f.H, "scheduled-dir-00")
			retained := userIDByUsername(t, f.H, "scheduled-dir-01")
			var beforeCursor string
			if err := f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT cursor FROM provisioning_connectors WHERE id=$1`, connector).Scan(&beforeCursor); err != nil {
				t.Fatal(err)
			}
			mode := "full"
			if profile == "incremental-failover" {
				mode = "incremental"
				for i := range 4 {
					primary.Update(fmt.Sprintf("CN=scheduled-dir-%02d,ou=people,%s", i, corpBase), map[string][]string{"displayName": {fmt.Sprintf("Transport Change %d", i)}})
				}
			}
			endpoints := []string{primary.LDAPSURL()}
			roots := primary.CAPEM()
			var secondary *ldaptest.Server
			if profile != "exhausted-then-recover" {
				secondary = corpDirectory(t)
				secondary.ServerName = "CN=NTDS Settings,CN=DC2"
				// The configured replacement has a complete, newer source view
				// without user 00; immutable external IDs remain equivalent.
				for i := 1; i < 8; i++ {
					dn := fmt.Sprintf("CN=scheduled-dir-%02d,ou=people,%s", i, corpBase)
					e := primary.Entry(dn)
					if e == nil {
						t.Fatal("missing mirror entry")
					}
					secondary.Add(dn, e.Attrs)
				}
				secondary.Add("CN=Scheduled Support,ou=groups,"+corpBase, map[string][]string{"objectClass": {"group"}, "cn": {"Scheduled Support"}, "member": {"CN=scheduled-dir-01,ou=people," + corpBase}})
				endpoints = append(endpoints, secondary.LDAPSURL())
				roots += secondary.CAPEM()
			} else {
				primary.Delete("CN=scheduled-dir-00,ou=people," + corpBase)
				primary.Update("CN=Scheduled Support,ou=groups,"+corpBase, map[string][]string{"member": {"CN=scheduled-dir-01,ou=people," + corpBase}})
			}
			current := f.must(f.AdminAPI("GET", path, nil), 200, "connector before endpoints")
			updated := f.H.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, Headers: map[string]string{"If-Match": current.Header.Get("ETag")}, JSON: map[string]any{
				"name": current.Str("name"), "config": map[string]any{"endpoints": endpoints, "ca_certificates_pem": roots, "dialect": "active_directory",
					"bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase, "group_base_dn": "ou=groups," + corpBase,
					"page_size": 2, "deprovision_action": "remove_membership", "deletion_threshold_percent": 20},
				"role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "group_role_mappings": map[string]any{"Scheduled Support": []string{f.Roles["orders-viewer"]}},
			}})
			mustStatus(t, updated, 200, "configure approved transport endpoints")
			run := replicaDirectoryRequest(t, f, nodes, path, mode, false)
			primary.ResetCounters()
			w := worker.New(nodes[1].App, "directory-transport-cut")
			handler := w.Handlers[directory.JobType]
			cut := false
			w.Handlers[directory.JobType] = func(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
				return handler(ctx, j, func(page map[string]any) error {
					if err := progress(page); err != nil {
						return err
					}
					if !cut {
						cut = true
						primary.SetDown(true)
					}
					return nil
				})
			}
			if count, err := w.RunJobs(ctx); err != nil || count != 1 || !cut {
				t.Fatalf("transport cut execution: %d/%v/%v", count, err, cut)
			}
			for _, n := range nodes {
				result := n.API("GET", path+"/runs/"+run.Str("id"), f.AdminToken, nil)
				mustStatus(t, result, 200, "transport run")
				if profile == "exhausted-then-recover" {
					if result.Str("state") != "failed" || count(result, "entries_seen") != 2 || count(result, "deprovision") != 0 || result.Str("cursor_after") != "" {
						t.Fatalf("partial exhausted scan: %s", result.Raw)
					}
				} else {
					endpoint, err := url.Parse(secondary.LDAPSURL())
					if err != nil {
						t.Fatal(err)
					}
					if result.Str("state") != "succeeded" || result.Str("mode") != "full" || result.Str("endpoint") != endpoint.Host || count(result, "entries_seen") != 7 || count(result, "deprovision") != 1 || count(result, "error") != 0 || count(result, "conflict") != 0 {
						t.Errorf("complete replacement scan failed source/deletion semantics: %s", result.Raw)
					}
					if profile == "incremental-failover" && count(result, "incremental_promoted_to_full") != 1 {
						t.Error("domain-controller switch did not promote incremental scan")
					}
				}
				wantActive, wantMissingState, wantMembers, wantDeprovision := 7, "removed", 1, 1
				if profile == "exhausted-then-recover" {
					wantActive, wantMissingState, wantMembers, wantDeprovision = 8, "active", 2, 0
				}
				var active, links, provisions, deprovisions, members, completions int
				var state, cursor, linkState string
				if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT
					(SELECT count(*) FROM memberships m JOIN connector_external_ids x ON x.local_id=m.user_id AND x.resource_type='User' WHERE x.connector_id=$1 AND m.organization_id=$2 AND m.state='active'),
					(SELECT state FROM memberships WHERE organization_id=$2 AND user_id=$3),
					(SELECT source_state FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=$3),
					(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1),
					(SELECT count(*) FROM audit_events WHERE type='directory.user.provisioned' AND actor_id=$1),
					(SELECT count(*) FROM audit_events WHERE type='directory.user.deprovisioned' AND actor_id=$1),
					(SELECT count(*) FROM group_memberships m JOIN connector_external_ids x ON x.local_id=m.group_id AND x.resource_type='Group' WHERE x.connector_id=$1),
					(SELECT count(*) FROM audit_events WHERE type='directory.sync.completed' AND metadata->>'run_id'=$4),
					coalesce(p.cursor,'') FROM provisioning_connectors p WHERE p.id=$1`, connector, f.Acme, missing, run.Str("id")).
					Scan(&active, &state, &linkState, &links, &provisions, &deprovisions, &members, &completions, &cursor); err != nil {
					t.Fatal(err)
				}
				if active != wantActive || state != wantMissingState || links != 9 || provisions != 8 || deprovisions != wantDeprovision || members != wantMembers || completions != 1 {
					t.Errorf("%s: active/missing/linkstate/links/provisions/deprovisions/members/completions %d/%s/%s/%d/%d/%d/%d/%d", profile, active, state, linkState, links, provisions, deprovisions, members, completions)
				}
				if profile == "exhausted-then-recover" {
					if cursor != beforeCursor {
						t.Error("failed partial scan advanced the cursor")
					}
				} else if !strings.Contains(cursor, "DC2") || cursor != result.Str("cursor_after") || linkState != "missing" {
					t.Error("replacement authority/cursor not persisted on every pool")
				}
				replicaGroupPermission(t, n, f, missing, profile == "exhausted-then-recover")
				replicaGroupPermission(t, n, f, retained, true)
			}
			if profile == "exhausted-then-recover" {
				primary.SetDown(false)
				retry := replicaDirectoryRequest(t, f, nodes, path, "full", false)
				replicaDirectoryWorkers(t, f, nodes, path, retry)
				for _, n := range nodes {
					result := n.API("GET", path+"/runs/"+retry.Str("id"), f.AdminToken, nil)
					mustStatus(t, result, 200, "recovered exhausted run")
					if result.Str("state") != "succeeded" || count(result, "entries_seen") != 7 || count(result, "deprovision") != 1 || count(result, "create") != 0 {
						t.Fatalf("complete retry after outage: %s", result.Raw)
					}
					replicaGroupPermission(t, n, f, missing, false)
					replicaGroupPermission(t, n, f, retained, true)
				}
			}
		})
	}
}
