package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/provisioning"
)

func replicaSCIMRequest(n *Harness, token, method, path, tag string, body any) *Resp {
	headers := map[string]string{"Authorization": "Bearer " + token}
	if tag != "" {
		headers["If-Match"] = tag
	}
	return n.Do(Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: headers, JSON: body})
}

func replicaGroupConnector(t *testing.T, f *Fixture) (token, id string) {
	t.Helper()
	r := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{
		"name": "replica-group-sync", "role_ceiling_ids": []string{f.Roles["orders-viewer"], f.Roles["member"]},
		"group_role_mappings": map[string]any{"replica-group": []string{f.Roles["orders-viewer"]}},
	}), 201, "group connector")
	return r.Str("token"), r.Str("connector.id")
}

func replicaSCIMStale(r *Resp) bool {
	return r.Status == 412 && r.Str("status") == "412" && slices.Equal(raceStrings(r.Get("schemas")), []string{provisioning.SchemaError})
}

func replicaGroupPermission(t *testing.T, n *Harness, f *Fixture, user string, want bool) {
	t.Helper()
	ps, err := n.App.Authz.Effective(context.Background(), nil, f.H.Realm.ID,
		authorization.Subject{Type: authorization.SubjectUser, ID: user},
		authorization.Scope{Type: authorization.ScopeOrganization, ID: f.Acme})
	if err != nil {
		t.Fatal(err)
	}
	allowed := ps.Has("orders.read")
	if allowed != want {
		t.Fatalf("replica group-derived authority = %v, want %v", allowed, want)
	}
}

// TestReplicaSCIMGroupConditionalStress covers PROV-007, PROV-008, API-010,
// TEN-013, AZ-010, TEST-050 and NFR-007: 16 SCIM and 16 administrator renames
// with their respective read tags require one winner across independent pools.
// Membership, metadata and both connector/admin role assignments survive.
func TestReplicaSCIMGroupConditionalStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	token, connector := replicaGroupConnector(t, f)
	u := replicaSCIMRequest(h, token, "POST", "/Users", "", map[string]any{"userName": "replica-group-member", "active": true})
	mustStatus(t, u, 201, "managed member")
	user := u.Str("id")
	g := replicaSCIMRequest(h, token, "POST", "/Groups", "", map[string]any{"displayName": "Replica Team", "externalId": "replica-group",
		"members": []map[string]any{{"value": user}}})
	mustStatus(t, g, 201, "mapped group")
	id := g.Str("id")
	path := "/organizations/" + f.Acme + "/groups/" + id
	f.must(f.AdminAPI("PATCH", path, map[string]any{"description": "Untouched description", "metadata": map[string]any{"proof": "preserved"}}), 200, "metadata")
	f.must(f.AdminAPI("POST", path+"/roles", map[string]any{"role_id": f.Roles["member"]}), 201, "administrator role")
	const rounds, concurrency = 6, 32
	for round := range rounds {
		current := replicaSCIMRequest(h, token, "GET", "/Groups/"+id, "", nil)
		mustStatus(t, current, 200, "SCIM precondition")
		admin := f.must(f.AdminAPI("GET", path, nil), 200, "admin precondition")
		scimTag, adminTag := current.Header.Get("ETag"), admin.Header.Get("ETag")
		if scimTag == "" || adminTag == "" {
			t.Fatal("group preconditions have no tags")
		}
		var beforeGroup, beforeMapping int64
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT g.version,x.resource_version FROM groups g JOIN connector_external_ids x ON x.local_id=g.id
			WHERE g.id=$1 AND x.connector_id=$2 AND x.resource_type='Group'`, id, connector).Scan(&beforeGroup, &beforeMapping); err != nil {
			t.Fatal(err)
		}
		results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
			name := fmt.Sprintf("group-round-%d-writer-%d", round, i)
			if i%2 == 0 {
				return replicaSCIMRequest(n, token, "PATCH", "/Groups/"+id, scimTag, map[string]any{
					"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": name}}})
			}
			return n.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main" + path, Token: f.AdminToken,
				Headers: map[string]string{"If-Match": adminTag}, JSON: map[string]any{"name": name}})
		})
		winner, accepted, stale := -1, 0, 0
		for i, r := range results {
			switch {
			case r.Status == 200:
				winner, accepted = i, accepted+1
			case i%2 == 0 && replicaSCIMStale(r):
				stale++
			case i%2 == 1 && r.Status == 412 && r.Str("code") == "precondition_failed":
				stale++
			default:
				t.Fatalf("group writer %d: %d/%s", i, r.Status, r.Str("code"))
			}
		}
		if accepted != 1 || stale != concurrency-1 {
			t.Fatalf("group race has %d winners/%d stale writers", accepted, stale)
		}
		wantName := fmt.Sprintf("group-round-%d-writer-%d", round, winner)
		wantMapping := beforeMapping
		if winner%2 == 0 {
			wantMapping++
		}
		for _, n := range nodes {
			after := replicaSCIMRequest(n, token, "GET", "/Groups/"+id, "", nil)
			mustStatus(t, after, 200, "SCIM group after race")
			members, ok := after.Get("members").([]any)
			if after.Str("displayName") != wantName || after.Str("externalId") != "replica-group" || after.Header.Get("ETag") == scimTag ||
				!ok || len(members) != 1 || members[0].(map[string]any)["value"] != user {
				t.Fatal("sole group winner or original member/external ID lost")
			}
			local := n.API("GET", path, f.AdminToken, nil)
			mustStatus(t, local, 200, "admin group after race")
			if local.Str("name") != wantName || local.Str("description") != "Untouched description" || local.Str("metadata.proof") != "preserved" || local.Header.Get("ETag") == adminTag {
				t.Fatal("replica administrator view lost name, metadata or version")
			}
			var version, mapping int64
			var mapped, administrator int
			if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT g.version,x.resource_version,
				(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=g.id AND source='scim' AND role_id=$3),
				(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=g.id AND source='admin' AND role_id=$4)
				FROM groups g JOIN connector_external_ids x ON x.local_id=g.id WHERE g.id=$1 AND x.connector_id=$2 AND x.resource_type='Group'`,
				id, connector, f.Roles["orders-viewer"], f.Roles["member"]).Scan(&version, &mapping, &mapped, &administrator); err != nil {
				t.Fatal(err)
			}
			if version != beforeGroup+1 || mapping != wantMapping || mapped != 1 || administrator != 1 {
				t.Fatalf("group/mapping versions %d/%d roles %d/%d", version-beforeGroup, mapping-beforeMapping, mapped, administrator)
			}
			replicaGroupPermission(t, n, f, user, true)
		}
		t.Logf("round %d: one group rename, 31 stale writers; membership, metadata and both role sources retained on every pool", round+1)
	}
}

// TestReplicaSCIMGroupMembershipStress covers PROV-003, PROV-007, PROV-008,
// TEN-013, AZ-010, TEST-050 and NFR-007. Conditional SCIM replacement races an
// idempotent administrator addition; both causal orders are also forced through
// public APIs. Controlled concurrent deletion ends both role sources once and
// keeps every organization membership alive.
func TestReplicaSCIMGroupMembershipStress(t *testing.T) {
	for _, order := range []string{"concurrent", "scim-first", "admin-first"} {
		t.Run(order, func(t *testing.T) {
			f, nodes := replicaStressFixture(t)
			h := f.H
			token, connector := replicaGroupConnector(t, f)
			var users, memberships []string
			for _, name := range []string{"group-original", "group-replacement"} {
				u := replicaSCIMRequest(h, token, "POST", "/Users", "", map[string]any{"userName": name, "active": true})
				mustStatus(t, u, 201, "managed member")
				users = append(users, u.Str("id"))
				var mid string
				if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active'`, f.Acme, u.Str("id")).Scan(&mid); err != nil {
					t.Fatal(err)
				}
				memberships = append(memberships, mid)
			}
			users = append(users, f.Users["sam"])
			memberships = append(memberships, f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members",
				map[string]any{"user_id": f.Users["sam"], "role_ids": []string{f.Roles["member"]}}), 201, "administrator's member").Str("id"))
			const rounds, concurrency = 4, 32
			for round := range rounds {
				g := replicaSCIMRequest(h, token, "POST", "/Groups", "", map[string]any{"displayName": "Replica Members", "externalId": "replica-group",
					"members": []map[string]any{{"value": users[0]}}})
				mustStatus(t, g, 201, "mapped group")
				id := g.Str("id")
				path := "/organizations/" + f.Acme + "/groups/" + id
				f.must(f.AdminAPI("POST", path+"/roles", map[string]any{"role_id": f.Roles["member"]}), 201, "administrator group role")
				before := make([]int64, len(memberships))
				for i, mid := range memberships {
					if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT revision FROM memberships WHERE id=$1`, mid).Scan(&before[i]); err != nil {
						t.Fatal(err)
					}
				}
				tag := replicaSCIMRequest(h, token, "GET", "/Groups/"+id, "", nil).Header.Get("ETag")
				if tag == "" {
					t.Fatal("missing member-replacement precondition")
				}
				replace := func(n *Harness) *Resp {
					return replicaSCIMRequest(n, token, "PATCH", "/Groups/"+id, tag, map[string]any{
						"Operations": []map[string]any{{"op": "replace", "path": "members", "value": []map[string]any{{"value": users[1]}}}}})
				}
				add := func(n *Harness) *Resp {
					return n.API("POST", path+"/members", f.AdminToken, map[string]any{"membership_id": memberships[2]})
				}
				scimWins := 0
				if order == "scim-first" {
					mustStatus(t, replace(nodes[1]), 200, "SCIM first receipt")
					scimWins = 1
				} else if order == "admin-first" {
					mustStatus(t, add(nodes[2]), 204, "administrator first receipt")
				}
				results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
					if order == "admin-first" || (order == "concurrent" && i%2 == 0) {
						return replace(n)
					}
					return add(n)
				})
				for i, r := range results {
					if order == "admin-first" || (order == "concurrent" && i%2 == 0) {
						if r.Status == 200 {
							scimWins++
						} else if !replicaSCIMStale(r) {
							t.Fatalf("member replacement %d/%s", r.Status, r.Str("status"))
						}
					} else {
						mustStatus(t, r, 204, "idempotent administrator addition")
					}
				}
				if scimWins > 1 || (order == "admin-first" && scimWins != 0) {
					t.Fatalf("unexpected replacement winners %d for %s", scimWins, order)
				}
				wantMember := users[0]
				if scimWins == 1 {
					wantMember = users[1]
				}
				wantUsers := []string{wantMember, users[2]}
				slices.Sort(wantUsers)
				for _, n := range nodes {
					after := replicaSCIMRequest(n, token, "GET", "/Groups/"+id, "", nil)
					mustStatus(t, after, 200, "group after member race")
					var got []string
					for _, member := range after.Get("members").([]any) {
						got = append(got, member.(map[string]any)["value"].(string))
					}
					slices.Sort(got)
					if !slices.Equal(got, wantUsers) || after.Str("externalId") != "replica-group" || after.Str("displayName") != "Replica Members" || after.Header.Get("ETag") == tag {
						t.Fatal("SCIM overwrote an acknowledged administrator addition or retained the wrong members")
					}
					var mapping int64
					var roles, added, removed int
					if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT x.resource_version,
						(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1),
						(SELECT count(*) FROM audit_events WHERE target_id=$1 AND type='group.member.added'),
						(SELECT count(*) FROM audit_events WHERE target_id=$1 AND type='group.member.removed')
						FROM connector_external_ids x WHERE connector_id=$2 AND resource_type='Group' AND local_id=$1`, id, connector).
						Scan(&mapping, &roles, &added, &removed); err != nil {
						t.Fatal(err)
					}
					if mapping != int64(1+scimWins) || roles != 2 || added != 2+scimWins || removed != scimWins {
						t.Fatalf("member race mapping/roles/add/remove = %d/%d/%d/%d", mapping, roles, added, removed)
					}
					for i, mid := range memberships {
						var revision int64
						if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT revision FROM memberships WHERE id=$1`, mid).Scan(&revision); err != nil {
							t.Fatal(err)
						}
						wantDelta := scimWins
						if i == 2 {
							wantDelta = 1
						}
						if revision != before[i]+int64(wantDelta) {
							t.Fatalf("member %d revision changed %d times, want %d", i, revision-before[i], wantDelta)
						}
						replicaGroupPermission(t, n, f, users[i], slices.Contains(wantUsers, users[i]))
					}
				}
				deleteTag := replicaSCIMRequest(h, token, "GET", "/Groups/"+id, "", nil).Header.Get("ETag")
				deletes := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
					return replicaSCIMRequest(n, token, "DELETE", "/Groups/"+id, deleteTag, nil)
				})
				deleted := 0
				for _, r := range deletes {
					if r.Status == 204 {
						deleted++
					} else if r.Status != 404 || r.Str("status") != "404" || !slices.Equal(raceStrings(r.Get("schemas")), []string{provisioning.SchemaError}) {
						t.Fatalf("controlled deletion outcome %d/%s", r.Status, r.Str("status"))
					}
				}
				if deleted != 1 {
					t.Fatalf("%d committed group deletions", deleted)
				}
				for _, n := range nodes {
					var groups, mappings, roles, members, audits, unassigned int
					if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT
						(SELECT count(*) FROM groups WHERE id=$1),
						(SELECT count(*) FROM connector_external_ids WHERE connector_id=$2 AND resource_type='Group' AND local_id=$1),
						(SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1),
						(SELECT count(*) FROM group_memberships WHERE group_id=$1),
						(SELECT count(*) FROM audit_events WHERE type='group.deleted' AND target_id=$1),
						(SELECT count(*) FROM audit_events WHERE type='role.unassigned' AND reason_code='GROUP_DELETED' AND metadata->>'subject_id'=$1)`, id, connector).
						Scan(&groups, &mappings, &roles, &members, &audits, &unassigned); err != nil {
						t.Fatal(err)
					}
					if groups != 0 || mappings != 0 || roles != 0 || members != 0 || audits != 1 || unassigned != 2 {
						t.Fatalf("delete group/mapping/role/member/audit/unassigned = %d/%d/%d/%d/%d/%d", groups, mappings, roles, members, audits, unassigned)
					}
					for i, mid := range memberships {
						var state string
						if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state FROM memberships WHERE id=$1`, mid).Scan(&state); err != nil || state != "active" {
							t.Fatal("deleting the group ended an organization membership")
						}
						replicaGroupPermission(t, n, f, users[i], false)
					}
				}
				t.Logf("round %d: %s, %d connector winner; administrator addition preserved, one deletion and two unassignment audits on every pool", round+1, order, scimWins)
			}
		})
	}
}
