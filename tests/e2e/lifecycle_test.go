package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestUserLifecycleJobs covers USR-015: a dry-run preview lists what the
// lifecycle job would do without changing anything; scheduled deactivation,
// dormant-account review and suspension run in bounded, audited batches.
func TestUserLifecycleJobs(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	rule := func(name string) map[string]any {
		t.Helper()
		pv := f.must(f.AdminAPI("GET", "/lifecycle/preview", nil), 200, "preview")
		if pv.Get("dry_run") != true {
			t.Fatalf("preview is not a dry run: %s", pv.Raw)
		}
		for _, r := range pv.Get("rules").([]any) {
			if m := r.(map[string]any); m["name"] == name {
				return m
			}
		}
		return nil
	}
	state := func(user string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users[user]).Scan(&s)
		return s
	}

	// Scheduled deactivation.
	dana := f.CreateUser("dana")
	mustStatus(t, f.AdminAPI("PUT", "/users/"+dana+"/scheduled-deactivation", map[string]any{"at": h.Clock.Now().Add(-time.Hour), "reason": "x"}), 422, "past time")
	mustStatus(t, f.AdminAPI("PUT", "/users/"+dana+"/scheduled-deactivation", map[string]any{"at": h.Clock.Now().Add(time.Hour), "reason": "contract ends"}),
		200, "schedule")
	if u := f.must(f.AdminAPI("GET", "/users/"+dana, nil), 200, "user"); u.Str("deactivate_at") == "" {
		t.Fatalf("scheduled deactivation not visible: %s", u.Raw)
	}
	h.Clock.Advance(2 * time.Hour)
	f.ReloginAdmin()
	if r := rule("scheduled_deactivation"); r == nil || r["due"].(float64) != 1 {
		t.Fatalf("preview: %v", r)
	}
	if state("dana") != "active" {
		t.Fatal("preview changed state")
	}
	runWorker(t, w)
	if state("dana") != "suspended" {
		t.Fatalf("scheduled deactivation not applied: %s", state("dana"))
	}

	// Dormant accounts: reported once, then suspended when the realm asks.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Lifecycle.DormantDays = 30 }), 200, "dormant review")
	h.Clock.Advance(31 * 24 * time.Hour)
	f.ReloginAdmin()
	r := rule("dormant")
	if r == nil || r["action"] != "report" || r["due"].(float64) == 0 {
		t.Fatalf("dormant preview: %v", r)
	}
	runWorker(t, w)
	if state("bob") != "active" {
		t.Fatal("report-only dormant rule suspended an account")
	}
	var reported int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='user.dormant_detected' AND subject_id=$1`, f.Users["bob"]).Scan(&reported)
	if reported != 1 {
		t.Fatalf("dormancy not reported once: %d", reported)
	}
	if r := rule("dormant"); r["due"].(float64) != 0 {
		t.Fatalf("flagged accounts reported again: %v", r)
	}
	// A sign-in ends dormancy; the next dormant period suspends under the
	// suspend action. Protected accounts are never touched.
	mustStatus(t, f.AccountToken("bob").Tokens, 200, "bob signs in")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Lifecycle.DormantAction = "suspend" }), 200, "suspend dormant")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Lifecycle.DormantAction = "archive" }), 422, "unknown action")
	h.Clock.Advance(31 * 24 * time.Hour)
	f.ReloginAdmin()
	runWorker(t, w)
	if state("bob") != "suspended" {
		t.Fatalf("dormant account not suspended: %s", state("bob"))
	}
	var adminState string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["admin"]).Scan(&adminState)
	if adminState != "active" {
		t.Fatalf("protected administrator suspended by the lifecycle job: %s", adminState)
	}
}

// TestUserAdministration covers USR-001: an administrator creates,
// retrieves, searches, updates the permitted fields of, suspends,
// reactivates and deletes a user through the admin API; fields outside the
// administrative patch are refused; and an organization administrator, even
// from an MFA session, holds none of this realm-wide authority.
func TestUserAdministration(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	created := f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "erin@example.test", "username": "erin", "display_name": "Erin",
		"send_setup_email": false}), 201, "create")
	id := created.Str("user.id")
	if id == "" || created.Str("user.state") != "active" || created.Str("setup_token") == "" {
		t.Fatalf("created user: %s", created.Raw)
	}
	got := f.must(f.AdminAPI("GET", "/users/"+id, nil), 200, "retrieve")
	if got.Str("display_name") != "Erin" || got.Header.Get("ETag") == "" {
		t.Fatalf("retrieved user: %s", got.Raw)
	}
	found := func(query string) bool {
		t.Helper()
		for _, it := range f.must(f.AdminAPI("GET", "/users?"+query, nil), 200, "search "+query).Get("items").([]any) {
			if it.(map[string]any)["id"] == id {
				return true
			}
		}
		return false
	}
	if !found("q=erin@example.test") || !found("q=erin") || !found("q="+id) || found("q=nobody@example.test") {
		t.Fatal("search by email, username and ID")
	}

	// Permitted fields change under a precondition; others are refused.
	patch := func(etag string, body map[string]any) *Resp {
		return h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/users/" + id, Token: f.AdminToken, JSON: body, Headers: map[string]string{"If-Match": etag}})
	}
	upd := patch(got.Header.Get("ETag"), map[string]any{"family_name": "Example", "admin_metadata": map[string]any{"cost_center": "42"}})
	mustStatus(t, upd, 200, "update")
	if upd.Str("family_name") != "Example" || upd.Str("admin_metadata.cost_center") != "42" {
		t.Fatalf("updated user: %s", upd.Raw)
	}
	mustStatus(t, patch(got.Header.Get("ETag"), map[string]any{"family_name": "Stale"}), 412, "stale version")
	for _, field := range []string{"state", "internal_metadata", "identifiers", "protected"} {
		if r := patch(upd.Header.Get("ETag"), map[string]any{field: map[string]any{}}); r.Status != 400 {
			t.Fatalf("administrative patch of %s: %d %s", field, r.Status, r.Raw)
		}
	}

	if r := f.must(f.AdminAPI("POST", "/users/"+id+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend"); r.Str("state") != "suspended" {
		t.Fatalf("suspended user: %s", r.Raw)
	}
	if !found("state=suspended&q=erin") || found("state=active&q=erin") {
		t.Fatal("search by state after suspension")
	}
	if r := f.must(f.AdminAPI("POST", "/users/"+id+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate"); r.Str("state") != "active" {
		t.Fatalf("reactivated user: %s", r.Raw)
	}

	// Scoped: carol administers globex, where bob is a member, and still
	// cannot reach the realm's user administration.
	f.EnrollTOTP("carol")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	bob := f.Users["bob"]
	for name, call := range map[string][3]any{
		"create":     {"POST", "/users", map[string]any{"email": "mallory@example.test"}},
		"retrieve":   {"GET", "/users/" + bob, nil},
		"search":     {"GET", "/users?organization_id=" + f.Globex, nil},
		"update":     {"PATCH", "/users/" + bob, map[string]any{"display_name": "Bobby"}},
		"suspend":    {"POST", "/users/" + bob + "/suspend", map[string]any{"reason": "x"}},
		"reactivate": {"POST", "/users/" + bob + "/reactivate", map[string]any{"reason": "x"}},
		"delete":     {"DELETE", "/users/" + bob, nil},
	} {
		if r := h.API(call[0].(string), call[1].(string), carol, call[2]); r.Status != 403 || r.Str("code") != "forbidden" {
			t.Fatalf("%s by an organization administrator: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := f.must(f.AdminAPI("GET", "/users/"+bob, nil), 200, "bob"); r.Str("state") != "active" || r.Str("display_name") == "Bobby" {
		t.Fatalf("refused calls changed the account: %s", r.Raw)
	}

	mustStatus(t, f.AdminAPI("DELETE", "/users/"+id, nil), 204, "delete")
	if found("q=" + id) {
		t.Fatal("deleted user still found by search")
	}
	if r := f.AdminAPI("GET", "/users/"+id, nil); r.Status != 404 && r.Str("state") != "deleted" {
		t.Fatalf("deleted user: %d %s", r.Status, r.Raw)
	}
}

// TestBulkUserOperations covers USR-016: bulk actions run as checkpointed jobs
// with a dry run, per-record outcomes, protected-account and self skips,
// idempotent submission and execution-time permission checks.
func TestBulkUserOperations(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	ids := []string{f.Users["bob"], f.Users["carol"], f.Users["admin"], "usr_doesnotexist0000000000"}
	submit := func(body map[string]any, key string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/user-bulk-operations", Token: f.AdminToken, JSON: body,
			Headers: map[string]string{"Idempotency-Key": key}})
	}
	mustStatus(t, submit(map[string]any{"action": "delete", "user_ids": ids, "reason": "cleanup"}, "k0"), 422, "unsupported action")
	mustStatus(t, submit(map[string]any{"action": "suspend", "user_ids": []string{f.Users["bob"], f.Users["bob"]}, "reason": "cleanup"}, "k0b"), 422, "duplicate IDs")
	mustStatus(t, submit(map[string]any{"action": "suspend", "user_ids": ids}, "k0c"), 422, "missing reason")
	state := func(user string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users[user]).Scan(&s)
		return s
	}
	result := func(job string) map[string]any {
		t.Helper()
		runWorker(t, w)
		r := f.must(f.AdminAPI("GET", "/jobs/"+job, nil), 200, "job")
		if r.Str("state") != "succeeded" {
			t.Fatalf("bulk job: %s", r.Raw)
		}
		return r.Get("result").(map[string]any)
	}

	dry := f.must(submit(map[string]any{"action": "suspend", "user_ids": ids, "reason": "contractor offboarding", "dry_run": true}, "k1"), 202, "dry run")
	res := result(dry.Str("job_id"))
	if state("bob") != "active" {
		t.Fatal("dry run changed an account")
	}
	if c := res["counts"].(map[string]any); c["valid"].(float64) != 2 || c["skipped"].(float64) != 1 || c["failed"].(float64) != 1 {
		t.Fatalf("dry-run report: %v", res)
	}

	job := f.must(submit(map[string]any{"action": "suspend", "user_ids": ids, "reason": "contractor offboarding"}, "k2"), 202, "suspend")
	again := f.must(submit(map[string]any{"action": "suspend", "user_ids": ids, "reason": "contractor offboarding"}, "k2"), 202, "retried submission")
	if again.Str("job_id") != job.Str("job_id") {
		t.Fatalf("idempotent submission created a second job: %s vs %s", again.Str("job_id"), job.Str("job_id"))
	}
	res = result(job.Str("job_id"))
	if state("bob") != "suspended" || state("carol") != "suspended" || state("admin") != "active" {
		t.Fatalf("bulk suspend effects: bob=%s carol=%s admin=%s", state("bob"), state("carol"), state("admin"))
	}
	for _, it := range res["results"].([]any) {
		m := it.(map[string]any)
		if m["user_id"] == f.Users["admin"] && m["outcome"] != "skipped" {
			t.Fatalf("protected account not skipped: %v", m)
		}
		if m["user_id"] == "usr_doesnotexist0000000000" && (m["outcome"] != "failed" || m["code"] != "not_found") {
			t.Fatalf("missing account: %v", m)
		}
		for k := range m {
			if k != "user_id" && k != "outcome" && k != "code" {
				t.Fatalf("report carries more than IDs and codes: %v", m)
			}
		}
	}
	reactivate := f.must(submit(map[string]any{"action": "reactivate", "user_ids": []string{f.Users["bob"], f.Users["carol"]}, "reason": "back on contract"}, "k3"),
		202, "reactivate")
	result(reactivate.Str("job_id"))
	if state("bob") != "active" || state("carol") != "active" {
		t.Fatal("bulk reactivation not applied")
	}
}

// TestExternalIDs covers USR-017: external IDs are unique per source system
// only, resolvable, replaceable and audited.
func TestExternalIDs(t *testing.T) {
	f := NewFixture(t)
	bob, carol := f.Users["bob"], f.Users["carol"]
	mustStatus(t, f.AdminAPI("PUT", "/users/"+bob+"/external-ids/hr", map[string]any{"external_id": "E-1001"}), 200, "set")
	mustStatus(t, f.AdminAPI("PUT", "/users/"+carol+"/external-ids/hr", map[string]any{"external_id": "E-1001"}), 409, "same ID in the same system")
	mustStatus(t, f.AdminAPI("PUT", "/users/"+carol+"/external-ids/crm", map[string]any{"external_id": "E-1001"}), 200, "same value in another system")
	mustStatus(t, f.AdminAPI("PUT", "/users/"+bob+"/external-ids/HR%20System", map[string]any{"external_id": "x"}), 422, "invalid source name")
	if r := f.must(f.AdminAPI("GET", "/external-ids/hr/E-1001", nil), 200, "lookup"); r.Str("user_id") != bob {
		t.Fatalf("lookup: %s", r.Raw)
	}
	if r := f.must(f.AdminAPI("GET", "/external-ids/crm/E-1001", nil), 200, "lookup"); r.Str("user_id") != carol {
		t.Fatalf("lookup in another system: %s", r.Raw)
	}
	// Replacing the value frees the old one.
	mustStatus(t, f.AdminAPI("PUT", "/users/"+bob+"/external-ids/hr", map[string]any{"external_id": "E-2002"}), 200, "replace")
	mustStatus(t, f.AdminAPI("GET", "/external-ids/hr/E-1001", nil), 404, "old value released")
	list := f.must(f.AdminAPI("GET", "/users/"+bob+"/external-ids", nil), 200, "list")
	if items := list.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["external_id"] != "E-2002" {
		t.Fatalf("list: %s", list.Raw)
	}
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+bob+"/external-ids/hr", nil), 204, "remove")
	mustStatus(t, f.AdminAPI("GET", "/external-ids/hr/E-2002", nil), 404, "removed")
	audit := f.must(f.AdminAPI("GET", "/audit-events?type_prefix=user.external_id.", nil), 200, "audit")
	if len(audit.Get("items").([]any)) != 4 {
		t.Fatalf("external ID changes not audited: %s", audit.Raw)
	}
}

// TestIdentityReadEvidence covers USR-018 and AUD-015: support operators see
// masked records, and realms that require it get audit evidence of every
// identity read (masked or not) without the data itself.
func TestIdentityReadEvidence(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	support := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "helpdesk",
		"permissions": []string{"support.users.read"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": support, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	count := func() int {
		r := f.must(f.AdminAPI("GET", "/audit-events?category=data_access&subject_id="+f.Users["bob"], nil), 200, "audit")
		return len(r.Get("items").([]any))
	}
	mustStatus(t, f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "read")
	if count() != 0 {
		t.Fatal("reads logged although the realm does not require it")
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.DataAccess.LogIdentityReads = true }), 200, "log reads")
	full := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "unmasked read")
	masked := f.must(h.API("GET", "/users/"+f.Users["bob"], carol, nil), 200, "masked read")
	if string(masked.Raw) == string(full.Raw) || strings.Contains(string(masked.Raw), "bob@example.test") {
		t.Fatalf("support operator saw an unmasked record: %s", masked.Raw)
	}
	ev := f.must(f.AdminAPI("GET", "/audit-events?category=data_access&subject_id="+f.Users["bob"], nil), 200, "audit")
	items := ev.Get("items").([]any)
	if len(items) != 2 {
		t.Fatalf("identity reads not evidenced: %s", ev.Raw)
	}
	if strings.Contains(string(ev.Raw), "bob@example.test") {
		t.Fatal("read evidence copied identity data")
	}
	sawMasked := false
	for _, it := range items {
		if it.(map[string]any)["metadata"].(map[string]any)["masked"] == true {
			sawMasked = true
		}
	}
	if !sawMasked {
		t.Fatal("masked support read not distinguished")
	}
}

// TestServiceOwnerDeparture covers MCH-007: a service principal whose
// accountable owner leaves is reported once, and under the disable policy is
// disabled with its credentials after the grace period; personal credentials
// of a suspended user stop working at once.
func TestServiceOwnerDeparture(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	dana := f.CreateUser("dana")
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "dana-sync", "owner_user_id": dana, "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	c := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "dana-sync", "name": "Dana sync", "client_type": "machine",
		"service_principal_id": sp}), 201, "client")
	cl := Client{Ref: c.Str("client.id"), ID: "dana-sync", Secret: c.Str("client_secret")}
	f.must(f.AdminAPI("PUT", "/clients/"+cl.Ref+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"service_principal"}}), 204, "grant")
	mustStatus(t, f.MachineToken(cl, f.BillingAud, "billing:read", f.Acme), 200, "token while the owner is active")
	departed := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='service_principal.owner_departed' AND target_id=$1`, sp).Scan(&n)
		return n
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+dana+"/suspend", map[string]any{"reason": "left the company"}), 200, "suspend owner")
	runWorker(t, w)
	runWorker(t, w)
	if departed() != 1 {
		t.Fatalf("owner departure not reported exactly once: %d", departed())
	}
	mustStatus(t, f.MachineToken(cl, f.BillingAud, "billing:read", f.Acme), 200, "flag policy keeps the service running")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Machine.OwnerDeparture = "delete" }), 422, "unknown policy")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Machine.OwnerDeparture = "disable"; p.Machine.OwnerDepartureGraceDays = 2 }), 200, "disable policy")
	runWorker(t, w)
	mustStatus(t, f.MachineToken(cl, f.BillingAud, "billing:read", f.Acme), 200, "within the grace period")
	h.Clock.Advance(3 * 24 * time.Hour)
	f.ReloginAdmin()
	runWorker(t, w)
	if r := f.MachineToken(cl, f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
		t.Fatal("service principal of a departed owner kept issuing tokens past the grace period")
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM service_principals WHERE id=$1`, sp).Scan(&state)
	if state != "disabled" {
		t.Fatalf("service principal state: %s", state)
	}
}

// TestDeletionPropagationStatus covers PRV-005: after an account deletion the
// report shows each place its data lived, derived from what is stored now,
// and dates backups from the operator's retention instead of claiming them
// erased.
func TestDeletionPropagationStatus(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Privacy.BackupRetention = 30 * 24 * time.Hour })
	f := fixtureOn(t, h)
	bob := f.Users["bob"]
	f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	mustStatus(t, f.AdminAPI("GET", "/users/"+bob+"/deletion-status", nil), 409, "account not deleted")
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+bob, nil), 204, "delete")
	stage := func(r *Resp, name string) map[string]any {
		for _, s := range r.Get("stages").([]any) {
			if m := s.(map[string]any); m["stage"] == name {
				return m
			}
		}
		t.Fatalf("stage %s missing: %s", name, r.Raw)
		return nil
	}
	rep := f.must(f.AdminAPI("GET", "/users/"+bob+"/deletion-status", nil), 200, "status")
	if stage(rep, "primary_storage")["state"] != "done" || stage(rep, "sessions_and_grants")["state"] != "done" {
		t.Fatalf("primary deletion: %s", rep.Raw)
	}
	if b := stage(rep, "backups"); b["state"] != "retained" || b["until"] == nil || !strings.Contains(b["details"].(string), "reconciliation") {
		t.Fatalf("backups must not be claimed erased: %v", b)
	}
	if a := stage(rep, "audit_evidence"); a["state"] != "retained" || a["count"].(float64) < 1 {
		t.Fatalf("audit evidence: %v", a)
	}
	if stage(rep, "connectors")["state"] != "pending" {
		t.Fatalf("user.deleted not yet published: %v", stage(rep, "connectors"))
	}
	// Messages about the account were purged with it (PRV-005).
	if n := stage(rep, "notifications"); n["state"] != "done" {
		t.Fatalf("notification payloads about the account: %v", n)
	}
	var left int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM notification_jobs WHERE user_id=$1 AND payload_ciphertext IS NOT NULL`, bob).Scan(&left)
	if left != 0 {
		t.Fatalf("payloads left: %d", left)
	}
	runWorker(t, worker.New(h.App, "test"))
	rep = f.must(f.AdminAPI("GET", "/users/"+bob+"/deletion-status", nil), 200, "status after dispatch")
	if stage(rep, "connectors")["state"] != "done" {
		t.Fatalf("connectors after dispatch: %v", stage(rep, "connectors"))
	}
}

// TestDeletionNeedsOwnershipTransfer covers USR-020: an account that owns
// projects (or clients, service principals, resources, connections) cannot be
// deleted, by itself or by an administrator, until ownership moves.
func TestDeletionNeedsOwnershipTransfer(t *testing.T) {
	f := NewFixture(t)
	prj := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Carol's App", "owner_user_id": f.Users["carol"]}), 201, "project")
	r := f.AdminAPI("DELETE", "/users/"+f.Users["carol"], nil)
	if r.Status != 409 || !strings.Contains(string(r.Raw), prj.Str("id")) {
		t.Fatalf("owner deleted without transfer: %d %s", r.Status, r.Raw)
	}
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	if r := f.H.API("POST", "/me/deletion-request", carol, nil); r.Status != 409 {
		t.Fatalf("owner requested deletion without transfer: %d %s", r.Status, r.Raw)
	}
	// After the transfer the deletion goes ahead.
	moved := f.must(f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/ownership-transfer", map[string]any{"to_user_id": f.Users["alice"]}), 200, "offboarding transfer")
	if moved.Get("transferred.project") != float64(1) {
		t.Fatalf("offboarding transfer: %s", moved.Raw)
	}
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["carol"], nil), 204, "delete after transfer")
	if ev := f.must(f.AdminAPI("GET", "/audit-events?type=project.ownership_transferred", nil), 200, "audit"); len(ev.Get("items").([]any)) != 1 {
		t.Fatalf("owner changes not audited: %s", ev.Raw)
	}
	// Ownership acquired during the grace period postpones the scheduled deletion.
	dina := f.CreateUser("dina")
	dtok := f.AccountToken("dina").Tokens.Str("access_token")
	mustStatus(t, f.H.API("POST", "/me/deletion-request", dtok, nil), 202, "deletion request")
	f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Dina's App", "owner_user_id": dina}), 201, "project acquired in grace")
	f.H.Clock.Advance(f.H.App.D.Cfg.Privacy.DeletionGracePeriod + time.Hour)
	if _, err := worker.New(f.H.App, "test").CompleteDeletions(context.Background()); err != nil {
		t.Fatal(err)
	}
	var st string
	_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state FROM users WHERE id=$1`, dina).Scan(&st)
	if st != "pending_deletion" {
		t.Fatalf("owner deleted at the end of the grace period: %s", st)
	}
}

// TestOwnershipReport covers DOM-009 and APP-014: live objects without an
// accountable owner, or whose owner left, are reported — clients whether or
// not they hold a secret — and new hooks and policies record their creator.
func TestOwnershipReport(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	dina := f.CreateUser("dina")
	f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Dina's", "owner_user_id": dina}), 201, "owned project")
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+dina, nil), 409, "owner cannot be deleted")
	mustStatus(t, f.AdminAPI("POST", "/users/"+dina+"/suspend", map[string]any{"reason": "left the company"}), 200, "owner leaves")
	rep := f.must(f.AdminAPI("GET", "/ownership-report?limit=200", nil), 200, "report")
	raw := string(rep.Raw)
	if !strings.Contains(raw, `"owner_departed"`) || !strings.Contains(raw, "Dina's") {
		t.Fatalf("departed owner not reported: %s", raw)
	}
	if !strings.Contains(raw, `"kind":"client"`) || !strings.Contains(raw, `"ownerless"`) {
		t.Fatalf("ownerless clients not reported: %s", raw)
	}
	pol := f.must(f.AdminAPI("POST", "/policies", map[string]any{"name": "owned-policy", "definition": map[string]any{
		"target": map[string]any{"actions": []string{"orders.*"}}, "rules": []map[string]any{{"id": "r1", "effect": "deny", "reason_code": "X",
			"when": map[string]any{"op": "eq", "attr": "context.risk", "value": "high"}}}}}), 201, "policy")
	var owner string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT coalesce(owner_user_id,'') FROM policies WHERE id=$1`, pol.Str("policy.id")).Scan(&owner)
	if owner == "" {
		t.Fatalf("policy without an owner: %s", pol.Raw)
	}
}
