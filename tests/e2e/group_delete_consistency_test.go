package e2e

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/provisioning"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestGroupDeletionWaitsBeforeLockingMembers covers TEN-013, PROV-008,
// DB-014, TEST-050 and QA-008: a deletion waiting for the group must not
// already hold its members while a connector holds the group before members.
// The independent member edit must commit, avoiding opposite lock orders.
func TestGroupDeletionWaitsBeforeLockingMembers(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	token, _ := replicaGroupConnector(t, f)
	u := replicaSCIMRequest(h, token, "POST", "/Users", "", map[string]any{"userName": "delete-lock-member", "active": true})
	mustStatus(t, u, 201, "managed member")
	g := replicaSCIMRequest(h, token, "POST", "/Groups", "", map[string]any{"displayName": "Delete Lock Team", "externalId": "replica-group",
		"members": []map[string]any{{"value": u.Str("id")}}})
	mustStatus(t, g, 201, "mapped group")
	ctx := context.Background()
	var member string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active'`, f.Acme, u.Str("id")).Scan(&member); err != nil {
		t.Fatal(err)
	}
	group, err := h.App.D.DB.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer group.Rollback(ctx)
	if _, err := group.Exec(ctx, `SELECT 1 FROM groups WHERE id=$1 FOR UPDATE`, g.Str("id")); err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := group.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Resp, 1)
	finished := false
	go func() {
		done <- nodes[1].API("DELETE", "/organizations/"+f.Acme+"/groups/"+g.Str("id"), f.AdminToken, nil)
	}()
	defer func() {
		_ = group.Rollback(ctx)
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("deletion did not drain after the held group was released")
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1::int=ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("administrator deletion never waited for the held group")
		}
		time.Sleep(10 * time.Millisecond)
	}
	edit, err := nodes[2].App.D.DB.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer edit.Rollback(ctx)
	if _, err := edit.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := edit.Exec(ctx, `UPDATE memberships SET metadata=metadata || '{"independent_edit":true}'::jsonb WHERE id=$1`, member); err != nil {
		t.Fatalf("deletion waiting for its group already locked a membership: %v", err)
	}
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := group.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		finished = true
		mustStatus(t, r, 204, "ordered group deletion")
	case <-time.After(5 * time.Second):
		t.Fatal("ordered deletion did not finish")
	}
	for _, n := range nodes {
		var state string
		var preserved bool
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT state,metadata->>'independent_edit'='true' FROM memberships WHERE id=$1`, member).Scan(&state, &preserved); err != nil {
			t.Fatal(err)
		}
		if state != "active" || !preserved {
			t.Fatal("group deletion lost the independent membership edit")
		}
	}
}

// TestGroupDeletionReleasesConnectorExternalID covers PROV-004, PROV-007,
// TEN-013 and QA-008: an administrator deletion cannot leave a connector's
// external ID pointing to a nonexistent group and permanently block recreation.
func TestGroupDeletionReleasesConnectorExternalID(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	token, connector := replicaGroupConnector(t, f)
	doc := map[string]any{"displayName": "Deleted Connector Team", "externalId": "replica-group"}
	g := replicaSCIMRequest(h, token, "POST", "/Groups", "", doc)
	mustStatus(t, g, 201, "mapped group")
	mustStatus(t, nodes[1].API("DELETE", "/organizations/"+f.Acme+"/groups/"+g.Str("id"), f.AdminToken, nil), 204, "administrator deletion")
	for _, n := range nodes {
		var stale int
		if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group' AND local_id=$2`, connector, g.Str("id")).Scan(&stale); err != nil {
			t.Fatal(err)
		}
		if stale != 0 {
			t.Error("administrator deletion left a stale connector Group mapping")
		}
	}
	recreated := replicaSCIMRequest(nodes[2], token, "POST", "/Groups", "", doc)
	mustStatus(t, recreated, 201, "recreate the same external Group ID")
	if recreated.Str("id") == "" || recreated.Str("id") == g.Str("id") {
		t.Fatal("recreation did not create a distinct live group")
	}
	// Reproduce the stored state of an earlier development build. A fresh
	// create repairs that orphan rather than requiring a production SQL fix.
	old := recreated.Str("id")
	mustStatus(t, nodes[1].API("DELETE", "/organizations/"+f.Acme+"/groups/"+old, f.AdminToken, nil), 204, "delete before legacy fixture")
	if _, err := h.App.D.DB.Pool.Exec(context.Background(), `INSERT INTO connector_external_ids (connector_id,resource_type,external_id,local_id)
		VALUES ($1,'Group','replica-group',$2)`, connector, old); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, replicaSCIMRequest(nodes[2], token, "POST", "/Groups", "", doc), 201, "repair legacy orphan on reprovisioning")
}

// TestDirectoryGroupRepairsDeletedLocalMapping covers PROV-004, PROV-007,
// PROV-012 and QA-008: a full directory sync repairs a legacy orphan Group
// reference without adopting any live group or duplicating its replacement.
func TestDirectoryGroupRepairsDeletedLocalMapping(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	srv := corpDirectory(t)
	dn := addADUser(srv, "group-repair", "group-repair@corp.test")
	srv.Add("CN=Support,ou=groups,"+corpBase, map[string][]string{"objectClass": {"group"}, "cn": {"Support"}, "member": {dn}})
	path := "/organizations/" + f.Acme + "/directory-connectors"
	c := f.must(f.AdminAPI("POST", path, map[string]any{"name": "Group repair AD", "kind": "ldap", "credential": "service secret",
		"role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "group_role_mappings": map[string]any{"Support": []string{f.Roles["orders-viewer"]}},
		"config": map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "dialect": "active_directory",
			"bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase, "group_base_dn": "ou=groups," + corpBase}}), 201, "directory connector")
	path += "/" + c.Str("id")
	w := worker.New(h.App, "group-repair-directory")
	if r := f.dirRun(t, w, path, map[string]any{"mode": "full"}); r.Str("state") != "succeeded" || count(r, "error") != 0 {
		t.Fatal("directory fixture did not synchronize")
	}
	var old, ext string
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT local_id,external_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group'`, c.Str("id")).Scan(&old, &ext); err != nil {
		t.Fatal(err)
	}
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/groups/"+old, nil), 204, "local directory group deletion")
	if _, err := h.App.D.DB.Pool.Exec(context.Background(), `INSERT INTO connector_external_ids (connector_id,resource_type,external_id,local_id,link_kind,source_dn)
		VALUES ($1,'Group',$2,$3,'directory','Support')`, c.Str("id"), ext, old); err != nil {
		t.Fatal(err)
	}
	var replacement string
	for round := range 2 {
		r := f.dirRun(t, w, path, map[string]any{"mode": "full"})
		if r.Str("state") != "succeeded" || count(r, "error") != 0 || count(r, "conflict") != 0 {
			t.Fatal("full sync did not repair the deleted local group")
		}
		var id string
		var groups, links, roles, members int
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT x.local_id,
			(SELECT count(*) FROM groups WHERE organization_id=$2 AND name='Support'),
			(SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group'),
			(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=x.local_id AND source='directory'),
			(SELECT count(*) FROM group_memberships WHERE group_id=x.local_id)
			FROM connector_external_ids x WHERE connector_id=$1 AND resource_type='Group'`, c.Str("id"), f.Acme).
			Scan(&id, &groups, &links, &roles, &members); err != nil {
			t.Fatal(err)
		}
		if id == old || groups != 1 || links != 1 || roles != 1 || members != 1 || (round == 1 && id != replacement) {
			t.Fatal("directory repair duplicated or lost the mapped group")
		}
		replacement = id
	}
}

// TestGroupDeletionPreservesOutboundCleanup covers PROV-010, PROV-017 and
// QA-008: inbound links can end with a group, but its downstream reference
// must remain until the real outbound adapter acknowledges remote deletion.
func TestGroupDeletionPreservesOutboundCleanup(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	down := newFakeSCIM(t, "downstream deletion fixture")
	group := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Outbound Delete Team"}), 201, "group").Str("id")
	path := "/organizations/" + f.Acme + "/directory-connectors"
	c := f.must(f.AdminAPI("POST", path, map[string]any{"name": "Deletion downstream", "kind": "scim_outbound", "credential": "downstream deletion fixture",
		"config": map[string]any{"base_url": down.srv.URL, "allow_private_network": true, "push_group_ids": []string{group}}}), 201, "outbound connector")
	w := worker.New(h.App, "group-delete-outbound")
	runWorker(t, w)
	runWorker(t, w)
	down.mu.Lock()
	created := len(down.groups)
	down.mu.Unlock()
	if created != 1 {
		t.Fatal("fixture did not create its downstream group")
	}
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/groups/"+group, nil), 204, "local deletion")
	var retained int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group'
		AND local_id=$2 AND link_kind='outbound'`, c.Str("id"), group).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("local deletion discarded the authority needed to delete downstream")
	}
	r := f.dirRun(t, w, path+"/"+c.Str("id"), map[string]any{"mode": "reconcile"})
	mustStatus(t, r, 200, "outbound reconciliation")
	if r.Str("state") != "succeeded" {
		t.Fatal("outbound deletion reconciliation did not finish")
	}
	runWorker(t, w)
	down.mu.Lock()
	remaining := len(down.groups)
	down.mu.Unlock()
	if remaining != 0 {
		t.Fatal("outbound adapter did not delete the retired group")
	}
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group' AND local_id=$2`,
		c.Str("id"), group).Scan(&retained); err != nil || retained != 0 {
		t.Fatal("acknowledged remote deletion retained its obsolete outbound mapping")
	}
}

// TestReplicaMixedGroupDeletionStress covers TEN-013, PROV-004, PROV-007,
// PROV-008, DB-014, NFR-007 and TEST-050: 16 administrator deletions race 16
// conditional connector removals. One deletion commits, every pool sees the
// same atomic cleanup, and the owned external ID can be reused next round.
func TestReplicaMixedGroupDeletionStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	token, connector := replicaGroupConnector(t, f)
	u := replicaSCIMRequest(h, token, "POST", "/Users", "", map[string]any{"userName": "mixed-delete-member", "active": true})
	mustStatus(t, u, 201, "managed member")
	var member string
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active'`, f.Acme, u.Str("id")).Scan(&member); err != nil {
		t.Fatal(err)
	}
	const rounds, concurrency = 6, 32
	for round := range rounds {
		g := replicaSCIMRequest(h, token, "POST", "/Groups", "", map[string]any{"displayName": "Mixed Delete Team", "externalId": "replica-group",
			"members": []map[string]any{{"value": u.Str("id")}}})
		mustStatus(t, g, 201, "reusable external group ID")
		id := g.Str("id")
		path := "/organizations/" + f.Acme + "/groups/" + id
		f.must(f.AdminAPI("POST", path+"/roles", map[string]any{"role_id": f.Roles["member"]}), 201, "administrator role")
		var before int64
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT revision FROM memberships WHERE id=$1`, member).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, n := range nodes {
			replicaGroupPermission(t, n, f, u.Str("id"), true)
		}
		tag := replicaSCIMRequest(h, token, "GET", "/Groups/"+id, "", nil).Header.Get("ETag")
		results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
			if i%2 == 0 {
				return n.API("DELETE", path, f.AdminToken, nil)
			}
			return replicaSCIMRequest(n, token, "PATCH", "/Groups/"+id, tag, map[string]any{"Operations": []map[string]any{{"op": "remove", "path": "members"}}})
		})
		deleted, updated := 0, 0
		for i, r := range results {
			if i%2 == 0 {
				if r.Status == 204 {
					deleted++
				} else if r.Status != 404 || r.Str("code") != "not_found" {
					t.Fatalf("administrator deletion: %d/%s", r.Status, r.Str("code"))
				}
			} else if r.Status == 200 {
				updated++
			} else if !replicaSCIMStale(r) && !(r.Status == 404 && r.Str("status") == "404" && slices.Equal(raceStrings(r.Get("schemas")), []string{provisioning.SchemaError})) {
				t.Fatalf("connector removal: %d/%s", r.Status, r.Str("status"))
			}
		}
		if deleted != 1 || updated > 1 {
			t.Fatalf("mixed deletion has %d deletes and %d visible connector updates", deleted, updated)
		}
		for _, n := range nodes {
			var groups, mappings, roles, members, audits, unassigned, removed int
			if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT
				(SELECT count(*) FROM groups WHERE id=$1),
				(SELECT count(*) FROM connector_external_ids WHERE connector_id=$2 AND resource_type='Group' AND local_id=$1),
				(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1),
				(SELECT count(*) FROM group_memberships WHERE group_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='group.deleted' AND target_id=$1),
				(SELECT count(*) FROM audit_events WHERE type='role.unassigned' AND reason_code='GROUP_DELETED' AND metadata->>'subject_id'=$1),
				(SELECT count(*) FROM audit_events WHERE type='group.member.removed' AND target_id=$1)`, id, connector).
				Scan(&groups, &mappings, &roles, &members, &audits, &unassigned, &removed); err != nil {
				t.Fatal(err)
			}
			// PATCH's post-commit representation read may encounter the
			// deletion and return 404; committed effects come from SQL/audit.
			if groups != 0 || mappings != 0 || roles != 0 || members != 0 || audits != 1 || unassigned != 2 || removed < updated || removed > 1 {
				t.Fatalf("mixed cleanup group/mapping/role/member/audit/unassign/remove %d/%d/%d/%d/%d/%d/%d", groups, mappings, roles, members, audits, unassigned, removed)
			}
			var state string
			var revision int64
			if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state,revision FROM memberships WHERE id=$1`, member).Scan(&state, &revision); err != nil {
				t.Fatal(err)
			}
			if state != "active" || revision != before+1 {
				t.Fatal("mixed deletion ended or repeatedly bumped the organization membership")
			}
			replicaGroupPermission(t, n, f, u.Str("id"), false)
		}
		t.Logf("round %d: one deletion, at most one committed connector removal, clean mapping/role/member state on every pool", round+1)
	}
}
