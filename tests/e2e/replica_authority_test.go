package e2e

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

func replicaPermissions(t *testing.T, n *Harness, org, token string) []string {
	t.Helper()
	r := n.API("GET", "/me/permissions?organization_id="+org, token, nil)
	mustStatus(t, r, 200, "replica effective permissions")
	return raceStrings(r.Get("permissions"))
}

// TestReplicaOwnershipTransferStress covers TEN-006, DB-007 and NFR-007:
// one owner offers ownership to two candidates in a concurrency-32 burst
// across three independent replicas, releasing their own ownership. Exactly
// one transfer commits; every replica sees one active owner, denies the
// former owner's further transfers and prevents removal of the last owner.
func TestReplicaOwnershipTransferStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	org := "/organizations/" + f.Acme
	sam := f.must(f.AdminAPI("POST", org+"/members", map[string]any{"user_id": f.Users["sam"], "role_ids": []string{f.Roles["member"]}}), 201, "second ownership candidate").Str("id")
	// Retain ordinary org.read after releasing ownership, so further
	// requests have an explicit forbidden result rather than concealment.
	f.must(f.AdminAPI("POST", org+"/members/"+f.MemberAcme["alice"]+"/roles", map[string]any{"role_id": f.Roles["member"]}), 201, "ordinary owner membership")
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	candidates := []string{f.MemberAcme["bob"], sam}
	users := []string{f.Users["bob"], f.Users["sam"]}
	const rounds, concurrency = 6, 32
	for round := range rounds {
		if round > 0 {
			// Reestablish the next fixture using authorized public APIs,
			// always adding the replacement before removing the old owner.
			f.must(f.AdminAPI("POST", org+"/members/"+f.MemberAcme["alice"]+"/roles", map[string]any{"role_id": f.Roles["owner"]}), 201, "restore initial owner")
			var assignment string
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT ra.id FROM role_assignments ra JOIN memberships m ON m.id=ra.membership_id
				WHERE ra.realm_id=$1 AND m.organization_id=$2 AND ra.role_id=$3 AND m.id<>$4`, h.Realm.ID, f.Acme, f.Roles["owner"], f.MemberAcme["alice"]).Scan(&assignment); err != nil {
				t.Fatal(err)
			}
			f.must(f.AdminAPI("DELETE", "/role-assignments/"+assignment, nil), 204, "release previous candidate")
		}
		results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
			return n.API("POST", org+"/ownership-transfers", alice, map[string]any{"membership_id": candidates[i%2], "release_current_owner": true})
		})
		accepted, refused, winner := 0, 0, -1
		for i, r := range results {
			switch {
			case r.Status == 200 && r.Str("status") == "transferred":
				accepted++
				winner = i % 2
			case r.Status == 403 && r.Str("code") == "forbidden":
				refused++
			default:
				t.Fatalf("round %d: unexpected transfer outcome %d/%s", round, r.Status, r.Str("code"))
			}
		}
		if accepted != 1 || refused != concurrency-1 {
			t.Fatalf("round %d: %d transfers and %d refusals", round, accepted, refused)
		}
		for i, n := range nodes {
			var ownerUser, assignment string
			var owners, audits int
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments ra JOIN memberships m ON m.id=ra.membership_id
				JOIN roles r ON r.id=ra.role_id JOIN users u ON u.id=m.user_id WHERE ra.realm_id=$1 AND m.organization_id=$2
				AND r.is_owner_role AND m.state='active' AND u.state='active'`, h.Realm.ID, f.Acme).Scan(&owners); err != nil {
				t.Fatal(err)
			}
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT m.user_id, ra.id FROM role_assignments ra JOIN memberships m ON m.id=ra.membership_id
				WHERE ra.realm_id=$1 AND m.organization_id=$2 AND ra.role_id=$3`, h.Realm.ID, f.Acme, f.Roles["owner"]).Scan(&ownerUser, &assignment); err != nil {
				t.Fatal(err)
			}
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND organization_id=$2 AND type='organization.ownership.transferred'`, h.Realm.ID, f.Acme).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if owners != 1 || ownerUser != users[winner] || audits != round+1 {
				t.Fatalf("round %d node %d: owners %d, wrong acceptor %v, transfer audits %d", round, i, owners, ownerUser != users[winner], audits)
			}
			if slices.Contains(replicaPermissions(t, n, f.Acme, alice), "org.ownership.transfer") {
				t.Fatal("former owner retains ownership-transfer authority")
			}
			r := n.API("DELETE", "/role-assignments/"+assignment, f.AdminToken, nil)
			if r.Status != 409 || r.Str("code") != "last_owner" {
				t.Fatalf("node %d: last-owner removal outcome %d/%s", i, r.Status, r.Str("code"))
			}
		}
		t.Logf("round %d across three independent pools: one transfer, 31 forbidden, one protected active owner", round+1)
	}
}

// TestReplicaRoleChangesStress covers API-010, DB-010, TEST-050 and NFR-007:
// concurrent grant, conditional permission edit and revoke bursts must each
// produce one durable transition, matching revisions/audits/outbox evidence,
// and current holder permissions on all three replicas.
func TestReplicaRoleChangesStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	const rounds, concurrency = 6, 32
	choices := []string{"orders.refund", "billing.read"}
	for round := range rounds {
		name := fmt.Sprintf("replica-role-holder-%d", round)
		userID := f.CreateUser(name)
		mid := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": userID, "role_ids": []string{f.Roles["member"]}}), 201, "role holder").Str("id")
		account := f.AccountToken(name).Tokens.Str("access_token")
		role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "organization_id": f.Acme, "name": fmt.Sprintf("replica-role-%d", round), "permissions": []string{"orders.read"}}), 201, "editable role")
		roleID, tag := role.Str("id"), role.Header.Get("ETag")
		if tag == "" {
			t.Fatal("role lacks a conditional-update tag")
		}
		path := "/organizations/" + f.Acme + "/members/" + mid + "/roles"
		for _, n := range nodes {
			if got := replicaPermissions(t, n, f.Acme, account); !slices.Equal(got, []string{"org.read"}) {
				t.Fatalf("unexpected fixture permissions %v", got)
			}
		}
		grants := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
			return n.API("POST", path, f.AdminToken, map[string]any{"role_id": roleID})
		})
		accepted, refused, assignment := 0, 0, ""
		for _, r := range grants {
			switch {
			case r.Status == 201 && r.Str("id") != "":
				accepted++
				assignment = r.Str("id")
			case r.Status == 409 && r.Str("code") == "conflict":
				refused++
			default:
				t.Fatalf("round %d: unexpected grant outcome %d/%s", round, r.Status, r.Str("code"))
			}
		}
		if accepted != 1 || refused != concurrency-1 {
			t.Fatalf("round %d: %d grants and %d conflicts", round, accepted, refused)
		}
		var beforeUser, beforeMember int64
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT u.authz_revision, m.revision FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.id=$2`, userID, mid).Scan(&beforeUser, &beforeMember); err != nil {
			t.Fatal(err)
		}
		edits := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
			return n.Do(Req{Method: "POST", Path: "/api/v1/realms/main/roles/" + roleID + "/permissions", Token: f.AdminToken, Headers: map[string]string{"If-Match": tag}, JSON: map[string]any{"add": []string{choices[i%2]}, "remove": []string{"orders.read"}}})
		})
		accepted, refused, winner := 0, 0, -1
		var winningTag string
		for i, r := range edits {
			switch {
			case r.Status == 200 && r.Header.Get("ETag") != "":
				accepted++
				winner, winningTag = i%2, r.Header.Get("ETag")
			case r.Status == 412 && r.Str("code") == "precondition_failed":
				refused++
			default:
				t.Fatalf("round %d: unexpected role-edit outcome %d/%s", round, r.Status, r.Str("code"))
			}
		}
		if accepted != 1 || refused != concurrency-1 {
			t.Fatalf("round %d: %d edits and %d precondition refusals", round, accepted, refused)
		}
		for _, n := range nodes {
			current := n.API("GET", "/roles/"+roleID, f.AdminToken, nil)
			mustStatus(t, current, 200, "role after race")
			if current.Header.Get("ETag") != winningTag || current.Get("version") != role.Get("version").(float64)+1 || !slices.Equal(raceStrings(current.Get("permissions")), []string{choices[winner]}) {
				t.Fatal("replica role version/permissions differ from the sole winner")
			}
			want := []string{"org.read", choices[winner]}
			slices.Sort(want)
			if got := replicaPermissions(t, n, f.Acme, account); !slices.Equal(got, want) {
				t.Fatalf("holder permissions %v differ from winning role %v", got, want)
			}
			var ur, mr int64
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT u.authz_revision, m.revision FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.id=$2`, userID, mid).Scan(&ur, &mr); err != nil {
				t.Fatal(err)
			}
			if ur != beforeUser+1 || mr != beforeMember+1 {
				t.Fatal("conditional role edit bumped holder revisions more than once")
			}
		}
		revokes := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
			return n.API("DELETE", path+"/"+assignment, f.AdminToken, nil)
		})
		accepted, refused = 0, 0
		for _, r := range revokes {
			switch {
			case r.Status == 204:
				accepted++
			case r.Status == 404 && r.Str("code") == "not_found":
				refused++
			default:
				t.Fatalf("round %d: unexpected revoke outcome %d/%s", round, r.Status, r.Str("code"))
			}
		}
		if accepted != 1 || refused != concurrency-1 {
			t.Fatalf("round %d: %d revoke successes, %d missing-assignment refusals; require one transition", round, accepted, refused)
		}
		for _, n := range nodes {
			q := n.App.D.DB.Pool
			var assignments, assigned, edited, revoked, assignedEvents, revokedEvents int
			var ur, mr int64
			if err := q.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE realm_id=$1 AND role_id=$2`, h.Realm.ID, roleID).Scan(&assignments); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE type='role.assigned'), count(*) FILTER (WHERE type='role.unassigned') FROM audit_events WHERE realm_id=$1 AND target_id=$2`, h.Realm.ID, assignment).Scan(&assigned, &revoked); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND target_id=$2 AND type='role.permissions.changed'`, h.Realm.ID, roleID).Scan(&edited); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE event_type='authorization.role.assigned'), count(*) FILTER (WHERE event_type='authorization.role.unassigned') FROM outbox_events WHERE realm_id=$1 AND aggregate_id=$2 AND payload->'data'->>'role_id'=$3`, h.Realm.ID, userID, roleID).Scan(&assignedEvents, &revokedEvents); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT u.authz_revision, m.revision FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.id=$2`, userID, mid).Scan(&ur, &mr); err != nil {
				t.Fatal(err)
			}
			if assignments != 0 || assigned != 1 || edited != 1 || revoked != 1 || assignedEvents != 1 || revokedEvents != 1 || ur != beforeUser+2 || mr != beforeMember+2 {
				t.Fatalf("round %d: inconsistent role transition counts: grants %d audits %d/%d/%d outbox %d/%d revisions %d/%d", round, assignments, assigned, edited, revoked, assignedEvents, revokedEvents, ur-beforeUser, mr-beforeMember)
			}
			if got := replicaPermissions(t, n, f.Acme, account); !slices.Equal(got, []string{"org.read"}) {
				t.Fatalf("revoked role still contributes permissions %v", got)
			}
		}
		t.Logf("round %d across three independent pools: one grant, edit and revoke; exact holder revisions, audit and outbox", round+1)
	}
}

// TestReplicaSCIMAdminSyncStress covers PROV-008, API-010, TEST-050 and
// NFR-007: 16 connector and 16 administrator conditional changes compete
// on one owned account. One writer commits, every loser is stale, and all
// replicas retain the untouched field and observe exact versions/audits.
func TestReplicaSCIMAdminSyncStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	connector := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "replica-sync", "role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "default_role_id": f.Roles["orders-viewer"]}), 201, "connector")
	token, connectorID := connector.Str("token"), connector.Str("connector.id")
	scim := func(n *Harness, method, path, tag string, body any) *Resp {
		headers := map[string]string{"Authorization": "Bearer " + token}
		if tag != "" {
			headers["If-Match"] = tag
		}
		return n.Do(Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: headers, JSON: body})
	}
	u := scim(h, "POST", "/Users", "", map[string]any{"userName": "replica.sync", "externalId": "replica-sync-owned", "displayName": "Initial Display", "name": map[string]any{"givenName": "Initial Given", "familyName": "Untouched"}, "active": true})
	mustStatus(t, u, 201, "managed user")
	id := u.Str("id")
	const rounds, concurrency = 6, 32
	for round := range rounds {
		current := scim(h, "GET", "/Users/"+id, "", nil)
		mustStatus(t, current, 200, "SCIM precondition")
		admin := f.must(f.AdminAPI("GET", "/users/"+id, nil), 200, "admin precondition")
		scimTag, adminTag := current.Header.Get("ETag"), admin.Header.Get("ETag")
		if scimTag == "" || adminTag == "" {
			t.Fatal("missing conditional account tags")
		}
		var beforeVersion, beforeMapping int64
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT u.version, x.resource_version FROM users u JOIN connector_external_ids x ON x.local_id=u.id WHERE u.id=$1 AND x.connector_id=$2 AND x.resource_type='User'`, id, connectorID).Scan(&beforeVersion, &beforeMapping); err != nil {
			t.Fatal(err)
		}
		results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
			value := fmt.Sprintf("round-%d-writer-%d", round, i)
			if i%2 == 0 {
				return scim(n, "PATCH", "/Users/"+id, scimTag, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": value}}})
			}
			return n.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/users/" + id, Token: f.AdminToken, Headers: map[string]string{"If-Match": adminTag}, JSON: map[string]any{"given_name": value}})
		})
		accepted, refused, winner := 0, 0, -1
		for i, r := range results {
			switch {
			case r.Status == 200:
				accepted++
				winner = i
			case i%2 == 0 && r.Status == 412 && r.Str("status") == "412" && slices.Equal(raceStrings(r.Get("schemas")), []string{"urn:ietf:params:scim:api:messages:2.0:Error"}):
				refused++
			case i%2 == 1 && r.Status == 412 && r.Str("code") == "precondition_failed":
				refused++
			default:
				t.Fatalf("round %d writer %d: unexpected sync outcome %d/%s", round, i, r.Status, r.Str("code"))
			}
		}
		if accepted != 1 || refused != concurrency-1 {
			t.Fatalf("round %d: %d sync writes and %d stale refusals", round, accepted, refused)
		}
		wantGiven, wantDisplay := current.Str("name.givenName"), current.Str("displayName")
		wantMapping := beforeMapping
		if winner%2 == 0 {
			wantDisplay = fmt.Sprintf("round-%d-writer-%d", round, winner)
			wantMapping++
		} else {
			wantGiven = fmt.Sprintf("round-%d-writer-%d", round, winner)
		}
		for _, n := range nodes {
			after := scim(n, "GET", "/Users/"+id, "", nil)
			mustStatus(t, after, 200, "SCIM after race")
			if after.Str("name.givenName") != wantGiven || after.Str("displayName") != wantDisplay || after.Str("name.familyName") != "Untouched" || after.Str("externalId") != "replica-sync-owned" || after.Get("active") != true || after.Header.Get("ETag") == scimTag {
				t.Fatal("replica SCIM fields/version do not preserve the sole winner and untouched data")
			}
			var version, mapping int64
			var audits int
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT u.version, x.resource_version FROM users u JOIN connector_external_ids x ON x.local_id=u.id WHERE u.id=$1 AND x.connector_id=$2 AND x.resource_type='User'`, id, connectorID).Scan(&version, &mapping); err != nil {
				t.Fatal(err)
			}
			if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND subject_id=$2 AND type IN ('scim.user.updated','user.admin_updated')`, h.Realm.ID, id).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if version != beforeVersion+1 || mapping != wantMapping || audits != round+1 {
				t.Fatalf("round %d: user/mapping/audit versions %d/%d/%d", round, version-beforeVersion, mapping-beforeMapping, audits)
			}
		}
		t.Logf("round %d across three independent pools: one sync/admin write, 31 stale refusals, untouched fields preserved", round+1)
	}
}

// TestReplicaTemplateApplicationStress covers TEN-017 and NFR-007: concurrent
// applications take an exclusive organization lock directly, avoiding a
// shared-lock upgrade storm while creating each role/group/grant only once.
func TestReplicaTemplateApplicationStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	doc := map[string]any{"policy": map[string]any{"mfa_required": true}, "roles": []map[string]any{{"name": "replica-template-viewer", "permissions": []string{"orders.read"}}}, "groups": []map[string]any{{"name": "Replica Template Group", "role_names": []string{"replica-template-viewer"}}}}
	f.must(f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "replica-template", "document": doc}), 201, "template")
	var beforeVersion int64
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT version FROM organizations WHERE realm_id=$1 AND id=$2`, h.Realm.ID, f.Acme).Scan(&beforeVersion); err != nil {
		t.Fatal(err)
	}
	const concurrency = 32
	results := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
		return n.API("POST", "/organizations/"+f.Acme+"/template-applications", f.AdminToken, map[string]any{"template": "replica-template"})
	})
	changed := 0
	for _, r := range results {
		if r.Status != 200 || r.Get("applied") != true || len(raceStrings(r.Get("conflicts"))) != 0 {
			t.Fatalf("unexpected template result %d/%s", r.Status, r.Str("code"))
		}
		creates, updates := len(raceStrings(r.Get("create"))), len(raceStrings(r.Get("update")))
		if creates == 3 && updates == 1 {
			changed++
		} else if creates != 0 || updates != 0 {
			t.Fatalf("partial or repeated template mutation: %d creates, %d updates", creates, updates)
		}
	}
	if changed != 1 {
		t.Fatalf("%d template requests changed the organization", changed)
	}
	for _, n := range nodes {
		var roles, groups, grants int
		var version int64
		var required bool
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT version, (policy->>'mfa_required')::boolean FROM organizations WHERE realm_id=$1 AND id=$2`, h.Realm.ID, f.Acme).Scan(&version, &required); err != nil {
			t.Fatal(err)
		}
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE realm_id=$1 AND organization_id=$2 AND name='replica-template-viewer'`, h.Realm.ID, f.Acme).Scan(&roles); err != nil {
			t.Fatal(err)
		}
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE realm_id=$1 AND organization_id=$2 AND name='Replica Template Group'`, h.Realm.ID, f.Acme).Scan(&groups); err != nil {
			t.Fatal(err)
		}
		if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.realm_id=$1 AND r.organization_id=$2 AND r.name='replica-template-viewer' AND ra.subject_type='group'`, h.Realm.ID, f.Acme).Scan(&grants); err != nil {
			t.Fatal(err)
		}
		if version != beforeVersion+1 || !required || roles != 1 || groups != 1 || grants != 1 {
			t.Fatalf("template invariants: version delta %d required %v roles/groups/grants %d/%d/%d", version-beforeVersion, required, roles, groups, grants)
		}
	}
	t.Log("32 completed template applications: one policy/role/group/grant change, 31 unchanged plans")
}

// TestReplicaExpiredRoleCleanupStress covers AZ-024 and NFR-007:
// competing cleanup workers tolerate another worker deleting an assignment,
// count only their actual transitions and emit one audit/outbox per expiry.
func TestReplicaExpiredRoleCleanupStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	mid := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["sam"], "role_ids": []string{f.Roles["member"]}}), 201, "expiry holder").Str("id")
	const grants, workers = 32, 6
	expires := h.Clock.Now().Add(time.Minute).Format(time.RFC3339Nano)
	roleIDs := make([]string, grants)
	for i := range roleIDs {
		roleIDs[i] = f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "organization_id": f.Acme, "name": fmt.Sprintf("replica-expiry-%d", i), "permissions": []string{"orders.read"}}), 201, "expiring role").Str("id")
		f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+mid+"/roles", map[string]any{"role_id": roleIDs[i], "expires_at": expires}), 201, "expiring grant")
	}
	h.Clock.Advance(2 * time.Minute)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(workers)
	done.Add(workers)
	counts, errors := make([]int, workers), make([]error, workers)
	for i := range counts {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			counts[i], errors[i] = nodes[i%len(nodes)].App.Authz.ExpireAssignments(ctx)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	total := 0
	for i, count := range counts {
		if errors[i] != nil {
			t.Fatalf("expiry worker %d failed: %v", i, errors[i])
		}
		total += count
	}
	if total != grants {
		t.Fatalf("workers counted %d expirations for %d grants", total, grants)
	}
	for _, n := range nodes {
		var remaining, audits, events int
		q := n.App.D.DB.Pool
		if err := q.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE realm_id=$1 AND role_id=ANY($2)`, h.Realm.ID, roleIDs).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='role.unassigned' AND subject_id=$2`, h.Realm.ID, f.Users["sam"]).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if err := q.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='authorization.role.unassigned' AND aggregate_id=$2 AND payload->'data'->>'role_id'=ANY($3)`, h.Realm.ID, f.Users["sam"], roleIDs).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if remaining != 0 || audits != grants || events != grants {
			t.Fatalf("expiry evidence: remaining %d audits %d events %d", remaining, audits, events)
		}
	}
	t.Log("six cleanup workers across three pools: exactly 32 expiry transitions/audits/outbox events")
}
