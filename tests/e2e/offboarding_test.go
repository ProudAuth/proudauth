package e2e

import (
	"context"
	"strings"
	"testing"
)

// TestOwnershipTransferCoversExtensions covers DOM-009, APP-014 and MCH-007
// for extensions: the offboarding transfer moves pre-action hooks, webhook
// subscriptions and authorization policies with everything else (a
// plugin-managed part keeps its plugin), and each of them has an owner
// change path of its own, also for objects without an owner.
func TestOwnershipTransferCoversExtensions(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	dina := f.CreateUser("dina")
	hook := func(name string) string {
		return f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": name, "kind": "profile.validation", "url": "https://1.1.1.1/" + name,
			"state": "disabled", "owner_user_id": dina}), 201, "hook "+name).Str("hook.id")
	}
	own, managed := hook("dina-profile"), hook("dina-plugin-part")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE hooks SET plugin_id='plg_offboarding' WHERE id=$1`, managed); err != nil {
		t.Fatal(err)
	}
	pol := f.must(f.AdminAPI("POST", "/policies", map[string]any{"name": "dina-policy", "owner_user_id": dina, "definition": map[string]any{
		"target": map[string]any{"actions": []string{"orders.*"}}, "rules": []map[string]any{{"id": "r1", "effect": "deny", "reason_code": "X",
			"when": map[string]any{"op": "eq", "attr": "context.risk", "value": "high"}}}}}), 201, "policy").Str("policy.id")
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "dina feed", "destination_url": "https://1.1.1.1/feed",
		"event_types": []string{"user.deleted"}}), 201, "webhook").Str("subscription.id")
	// The webhook's creator owns it; its owner changes through its own path.
	moved := f.must(f.AdminAPI("POST", "/webhooks/"+sub+"/ownership-transfer", map[string]any{"owner_user_id": dina}), 200, "webhook owner change")
	if moved.Str("owner_user_id") != dina || moved.Str("previous_owner_user_id") == "" || moved.Header.Get("ETag") == "" {
		t.Fatalf("webhook owner change: %s", moved.Raw)
	}

	// Offboarding moves all of them.
	out := f.must(f.AdminAPI("POST", "/users/"+dina+"/ownership-transfer", map[string]any{"to_user_id": f.Users["alice"]}), 200, "offboarding transfer")
	if out.Get("transferred.hook") != float64(2) || out.Get("transferred.webhook") != float64(1) || out.Get("transferred.authorization_policy") != float64(1) {
		t.Fatalf("offboarding transfer: %s", out.Raw)
	}
	owner := func(table, id string) (string, string) {
		var o, plugin string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(owner_user_id,''), `+map[bool]string{true: "coalesce(plugin_id,'')", false: "''"}[table != "policies"]+
			` FROM `+table+` WHERE id=$1`, id).Scan(&o, &plugin)
		return o, plugin
	}
	for _, x := range [][2]string{{"hooks", own}, {"hooks", managed}, {"policies", pol}, {"webhook_subscriptions", sub}} {
		if o, _ := owner(x[0], x[1]); o != f.Users["alice"] {
			t.Fatalf("%s %s still owned by %q", x[0], x[1], o)
		}
	}
	if _, plugin := owner("hooks", managed); plugin != "plg_offboarding" {
		t.Fatalf("a plugin part left its plugin: %q", plugin)
	}
	var events int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type IN ('hook.ownership_transferred','webhook.ownership_transferred',
		'authorization_policy.ownership_transferred')`).Scan(&events)
	if events != 5 {
		t.Fatalf("owner changes audited: %d", events)
	}
	// Nothing of dina's is left to report.
	mustStatus(t, f.AdminAPI("POST", "/users/"+dina+"/suspend", map[string]any{"reason": "left"}), 200, "dina leaves")
	if rep := f.must(f.AdminAPI("GET", "/ownership-report?limit=200", nil), 200, "report"); strings.Contains(string(rep.Raw), dina) {
		t.Fatalf("objects of the departed owner remain: %s", rep.Raw)
	}

	// The single-object path: an active account only, If-Match honored, and
	// an object without an owner gets one.
	mustStatus(t, f.AdminAPI("POST", "/hooks/"+own+"/ownership-transfer", map[string]any{"owner_user_id": dina}), 422, "a departed account")
	mustStatus(t, f.AdminAPI("POST", "/hooks/"+own+"/ownership-transfer", map[string]any{}), 422, "no owner")
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/hooks/" + own + "/ownership-transfer", Token: f.AdminToken,
		JSON: map[string]any{"owner_user_id": f.Users["bob"]}, Headers: map[string]string{"If-Match": `W/"v1"`}}), 412, "stale If-Match")
	f.must(f.AdminAPI("POST", "/hooks/"+managed+"/ownership-transfer", map[string]any{"owner_user_id": f.Users["bob"]}), 200, "plugin part owner change")
	if o, plugin := owner("hooks", managed); o != f.Users["bob"] || plugin != "plg_offboarding" {
		t.Fatalf("plugin part after owner change: %q %q", o, plugin)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE policies SET owner_user_id=NULL WHERE id=$1`, pol); err != nil {
		t.Fatal(err)
	}
	if rep := f.must(f.AdminAPI("GET", "/ownership-report?limit=200", nil), 200, "report"); !strings.Contains(string(rep.Raw), pol) {
		t.Fatalf("ownerless policy not reported: %s", rep.Raw)
	}
	f.must(f.AdminAPI("POST", "/policies/"+pol+"/ownership-transfer", map[string]any{"owner_user_id": f.Users["alice"]}), 200, "ownerless policy gets an owner")
	if rep := f.must(f.AdminAPI("GET", "/ownership-report?limit=200", nil), 200, "report"); strings.Contains(string(rep.Raw), pol) {
		t.Fatalf("policy with an owner still reported: %s", rep.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/policies/pol_missing/ownership-transfer", map[string]any{"owner_user_id": f.Users["alice"]}), 404, "unknown policy")
}

// TestAccountDeletionCoverage covers PRV-005 for data other features keep
// about an account: every message about it records it (password reset
// included) and is purged at deletion; certificate bindings, relationship
// tuples naming it, shares to or from it and elevation eligibilities and
// requests are removed or ended.
func TestAccountDeletionCoverage(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	bob, alice := f.Users["bob"], f.Users["alice"]
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Messages: a password reset is recorded as being about the account.
	f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"}), 202, "password reset")
	if n := count(`SELECT count(*) FROM notification_jobs WHERE template='password_reset' AND user_id=$1 AND payload_ciphertext IS NOT NULL`, bob); n != 1 {
		t.Fatalf("password-reset message about bob: %d", n)
	}

	// A certificate binding.
	ca := newTestCA(t, "Deletion Cards")
	anchor := f.must(f.AdminAPI("POST", "/certificate-trust-anchors", map[string]any{"purpose": "user", "name": "Cards", "certificate_pem": ca.pem}), 201,
		"anchor").Str("id")
	f.must(f.AdminAPI("POST", "/users/"+bob+"/certificate-bindings", map[string]any{"anchor_id": anchor, "issuer_dn": "CN=Deletion Cards",
		"subject_dn": "CN=Bob"}), 201, "binding")

	// Relationships and shares in both directions.
	for _, perm := range []string{"notes.read", "notes.share"} {
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": perm}), 201, "permission "+perm)
	}
	f.must(f.AdminAPI("PUT", "/resource-types/note", map[string]any{"resource_id": f.Orders, "relations": []map[string]any{
		{"name": "owner", "subject_types": []string{"user"}}, {"name": "viewer", "subject_types": []string{"user"}, "implied_by": []string{"owner"}}},
		"permissions": map[string][]string{"notes.read": {"viewer"}, "notes.share": {"owner"}}, "shareable_relations": []string{"viewer"},
		"share_permission": "notes.share"}), 201, "note type")
	tuple := func(id, rel, user string) map[string]any {
		return map[string]any{"op": "add", "object_type": "note", "object_id": id, "relation": rel, "subject_type": "user", "subject_id": user}
	}
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/relationships", map[string]any{"writes": []map[string]any{tuple("n-bob", "owner", bob),
		tuple("n-alice", "owner", alice), tuple("n-alice2", "owner", alice)}}), 200, "tuples")
	bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
	aliceAcct := f.AccountToken("alice").Tokens.Str("access_token")
	share := func(tok, object, recipient string) string {
		return f.must(h.API("POST", "/me/shares", tok, map[string]any{"organization_id": f.Acme, "resource_type": "note", "object_id": object,
			"relation": "viewer", "recipient_user_id": recipient, "message": "for your review"}), 201, "share "+object).Str("id")
	}
	fromBob := share(bobAcct, "n-bob", alice)
	f.must(h.API("POST", "/me/shares/"+fromBob+"/accept", aliceAcct, nil), 200, "alice accepts")
	toBob := share(aliceAcct, "n-alice", bob)
	f.must(h.API("POST", "/me/shares/"+toBob+"/accept", bobAcct, nil), 200, "bob accepts")
	pendingToBob := share(aliceAcct, "n-alice2", bob)

	// Elevation: one eligibility with an active elevation, one with a
	// pending request.
	acme := map[string]any{"type": "organization", "id": f.Acme}
	viewer := f.must(f.AdminAPI("POST", "/elevation-eligibilities", map[string]any{"user_id": bob, "role_id": f.Roles["billing-viewer"], "scope": acme,
		"requires_approval": false}), 201, "ordinary eligibility").Str("id")
	refund := f.must(f.AdminAPI("POST", "/elevation-eligibilities", map[string]any{"user_id": bob, "role_id": f.Roles["orders-refunder"], "scope": acme}),
		201, "privileged eligibility").Str("id")
	f.EnrollTOTP("bob")
	mfa := f.AccountToken("bob").Tokens.Str("access_token")
	active := f.must(h.API("POST", "/me/elevations", mfa, map[string]any{"eligibility_id": viewer, "reason": "quarter close"}), 201, "active elevation")
	f.must(h.API("POST", "/me/elevations", mfa, map[string]any{"eligibility_id": refund, "reason": "refund backlog"}), 201, "pending request")
	if active.Str("state") != "active" {
		t.Fatalf("elevation: %s", active.Raw)
	}

	mustStatus(t, f.AdminAPI("DELETE", "/users/"+bob, nil), 204, "delete bob")

	if n := count(`SELECT count(*) FROM notification_jobs WHERE user_id=$1 AND (payload_ciphertext IS NOT NULL OR recipient_ciphertext IS NOT NULL)`, bob); n != 0 {
		t.Fatalf("messages about bob kept their payload: %d", n)
	}
	if n := count(`SELECT count(*) FROM notification_jobs WHERE template='password_reset' AND user_id=$1 AND payload_purged_at IS NOT NULL`, bob); n != 1 {
		t.Fatalf("password-reset message not purged: %d", n)
	}
	if n := count(`SELECT count(*) FROM user_certificate_bindings WHERE user_id=$1`, bob); n != 0 {
		t.Fatalf("certificate bindings kept: %d", n)
	}
	if n := count(`SELECT count(*) FROM resource_relationships WHERE subject_type='user' AND subject_id=$1`, bob); n != 0 {
		t.Fatalf("tuples naming bob kept: %d", n)
	}
	if n := count(`SELECT count(*) FROM resource_relationships WHERE source=$1`, "share:"+fromBob); n != 0 {
		t.Fatalf("the tuple of bob's share kept: %d", n)
	}
	if n := count(`SELECT count(*) FROM resource_relationships WHERE subject_id=$1`, alice); n != 2 {
		t.Fatalf("alice's own tuples: %d", n)
	}
	if n := count(`SELECT count(*) FROM resource_shares WHERE (owner_user_id=$1 OR recipient_user_id=$1) AND (state IN ('pending','accepted') OR message IS NOT NULL)`,
		bob); n != 0 {
		t.Fatalf("shares naming bob not ended: %d", n)
	}
	var st string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM resource_shares WHERE id=$1`, pendingToBob).Scan(&st)
	if st != "revoked" {
		t.Fatalf("pending share to bob: %q", st)
	}
	if n := count(`SELECT count(*) FROM elevation_eligibilities WHERE user_id=$1 AND state='active'`, bob); n != 0 {
		t.Fatalf("eligibilities kept: %d", n)
	}
	if n := count(`SELECT count(*) FROM elevations WHERE user_id=$1 AND state IN ('pending','active')`, bob); n != 0 {
		t.Fatalf("elevations not ended: %d", n)
	}
	// The ended elevation's assignment is due: the sweep removes it.
	if _, err := h.App.Authz.ExpireAssignments(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM role_assignments WHERE id=$1`, active.Str("assignment_id")); n != 0 {
		t.Fatalf("elevation assignment kept: %d", n)
	}
}
