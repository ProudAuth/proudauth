package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestTenantFairness covers TEN-018 and DEP-015 (fair tenant quotas for
// notification bursts and token issuance): one organization's notification backlog
// does not delay another organization's messages, and per-organization token
// budgets stop one tenant without affecting the others.
func TestTenantFairness(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Workers.TenantBatchShare = 5
		c.Security.RateLimits.OrganizationPerWindow = 3
	})
	f := fixtureOn(t, h)
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		if _, err := h.App.Notify.EnqueueTx(ctx, h.App.D.DB.Pool, notification.Message{RealmID: h.Realm.ID, OrgID: f.Acme, Template: notification.TplRecovery,
			Recipient: "flood@example.test", Mandatory: true, Data: map[string]string{"realm": "main"}}); err != nil {
			t.Fatal(err)
		}
	}
	h.Clock.Advance(time.Second)
	if _, err := h.App.Notify.EnqueueTx(ctx, h.App.D.DB.Pool, notification.Message{RealmID: h.Realm.ID, OrgID: f.Globex, Template: notification.TplRecovery,
		Recipient: "quiet@example.test", Mandatory: true, Data: map[string]string{"realm": "main"}}); err != nil {
		t.Fatal(err)
	}
	h.Clock.Advance(time.Second)
	if _, err := h.App.Notify.DeliverDue(ctx, "fair-worker", 10, time.Minute); err != nil {
		t.Fatal(err)
	}
	var quiet string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM notification_jobs WHERE organization_id=$1`, f.Globex).Scan(&quiet)
	if quiet == "queued" {
		t.Fatal("another organization's backlog starved this organization's message")
	}
	var floodHandled int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_jobs WHERE organization_id=$1 AND state <> 'queued'`, f.Acme).Scan(&floodHandled)
	if floodHandled > 5 {
		t.Fatalf("one organization took %d of the batch beyond its share", floodHandled)
	}

	// Token budget per organization.
	limited := false
	for i := 0; i < 5 && !limited; i++ {
		r := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)
		limited = r.Status == 429 && r.Str("error") == "slow_down"
	}
	if !limited {
		t.Fatal("organization token budget not enforced")
	}
	mustStatus(t, f.LoginWeb("carol", f.Globex, f.OrdersAud, "orders:read").Tokens, 200, "another organization unaffected")
}

// TestDomainReverification covers TEN-009: verified domains are re-checked
// periodically against the accepted DNS proof; a proof that stays missing for
// the allowed number of retries makes the verification lapse.
func TestDomainReverification(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Domains.RecheckDays = 0; p.Domains.LapseAfterFailures = 99 }), 422, "too many failures")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Domains.RecheckDays = 7; p.Domains.LapseAfterFailures = 2 }), 200, "recheck policy")
	ch := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains", map[string]any{"domain": "acme-recheck.test"}), 201, "domain")
	published := []string{ch.Str("dns_record_value")}
	saved := organization.TXTResolver
	organization.TXTResolver = func(context.Context, string) ([]string, error) { return published, nil }
	defer func() { organization.TXTResolver = saved }()
	id := ch.Str("domain.id")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains/"+id+"/verify", nil), 200, "verify")
	// Another organization proving the same domain is marked conflicting and
	// audited; the verified claim is untouched.
	other := f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/domains", map[string]any{"domain": "acme-recheck.test"}), 201, "competing claim")
	published = append(published, other.Str("dns_record_value"))
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Globex+"/domains/"+other.Str("domain.id")+"/verify", nil), 409, "conflicting verification")
	var conflictState string
	var conflictAudits int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM organization_domains WHERE id=$1`, other.Str("domain.id")).Scan(&conflictState)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='organization.domain.conflict' AND organization_id=$1`, f.Globex).Scan(&conflictAudits)
	if conflictState != "conflict" || conflictAudits != 1 {
		t.Fatalf("conflict not recorded: state %q audits %d", conflictState, conflictAudits)
	}
	published = published[:1]
	state := func() (string, int) {
		var s string
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, recheck_failures FROM organization_domains WHERE id=$1`, id).Scan(&s, &n)
		return s, n
	}
	recheck := func() {
		t.Helper()
		if _, err := h.App.Orgs.RecheckDomains(ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
	h.Clock.Advance(8 * 24 * time.Hour)
	recheck()
	if s, n := state(); s != "verified" || n != 0 {
		t.Fatalf("published proof: %s %d", s, n)
	}
	published = nil // the proof record was removed
	h.Clock.Advance(8 * 24 * time.Hour)
	recheck()
	if s, n := state(); s != "verified" || n != 1 {
		t.Fatalf("first failure: %s %d", s, n)
	}
	h.Clock.Advance(25 * time.Hour)
	recheck()
	if s, _ := state(); s != "expired" {
		t.Fatalf("verification did not lapse: %s", s)
	}
	var lapsed int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='organization.domain.verification_lapsed' AND target_id=$1`, id).Scan(&lapsed)
	if lapsed != 1 {
		t.Fatal("lapse not audited")
	}
}

// TestDecisionAuditSampling covers AZ-020: ordinary allowed decisions are
// audited only when the realm samples them (marked as sampled), denials are
// always audited, and denied administrative requests leave evidence.
func TestDecisionAuditSampling(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	check := func() {
		t.Helper()
		r := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": "orders.read",
			"resource": map[string]any{"type": "order", "id": "ord_acme_1", "org_id": f.Acme}})
		if r.Status != 200 || r.Get("allowed") != true {
			t.Fatalf("decision: %d %s", r.Status, r.Raw)
		}
	}
	allows := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='authorization.decision' AND outcome='success'
			AND metadata->>'sampled'='true'`).Scan(&n)
		return n
	}
	check()
	if allows() != 0 {
		t.Fatal("ordinary allow audited without sampling")
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.DataAccess.SampleAllowedDecisionsPercent = 101 }), 422, "invalid sample rate")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.DataAccess.SampleAllowedDecisionsPercent = 100 }), 200, "sample all")
	check()
	if allows() != 1 {
		t.Fatalf("sampled allow not audited: %d", allows())
	}
	// A denied administrative request is recorded with the permission only.
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	if r := h.API("GET", "/signing-keys", carol, nil); r.Status != 403 {
		t.Fatalf("expected a denial: %d", r.Status)
	}
	var denied int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='authorization.denied' AND actor_id=$1
		AND metadata->>'permission'='realm.keys.read'`, f.Users["carol"]).Scan(&denied)
	if denied != 1 {
		t.Fatalf("administrative denial not audited: %d", denied)
	}
}

// TestDecisionCacheContract covers AZ-019: pure RBAC decisions carry a cache
// key and a bounded TTL; the key changes when the subject's authorization
// changes, and privileged decisions are never cacheable.
func TestDecisionCacheContract(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	check := func(action string) *Resp {
		t.Helper()
		return f.must(h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": action,
			"resource": map[string]any{"type": "order", "id": "ord_acme_1", "org_id": f.Acme}}), 200, "decision")
	}
	a := check("orders.read")
	if a.Get("allowed") != true || a.Str("cache_key") == "" || a.Get("cache_ttl_seconds").(float64) <= 0 || a.Get("cache_ttl_seconds").(float64) > 30 {
		t.Fatalf("cacheable allow: %s", a.Raw)
	}
	if b := check("orders.read"); b.Str("cache_key") != a.Str("cache_key") {
		t.Fatal("cache key is not stable for the same request")
	}
	if d := check("orders.refund"); d.Get("allowed") != false || d.Str("cache_key") == "" || d.Str("cache_key") == a.Str("cache_key") {
		t.Fatalf("denial cache hint: %s", d.Raw)
	}
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": f.Roles["orders-refunder"]}), 201,
		"grant")
	c := check("orders.read")
	if c.Str("cache_key") == a.Str("cache_key") {
		t.Fatal("cache key survived an authorization change")
	}
	// A role granted to one of the subject's groups changes the key too, even
	// though the user's own revision does not move.
	grp := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Cache"}), 201, "group").Str("id")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/members", map[string]any{"membership_id": f.MemberAcme["bob"]}), 204, "member")
	k1 := check("orders.read").Str("cache_key")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/roles", map[string]any{"role_id": f.Roles["orders-viewer"]}), 201, "group grant")
	if check("orders.read").Str("cache_key") == k1 {
		t.Fatal("cache key survived a group grant")
	}
	// So does a grant to an ancestor of that group, and a change to a role
	// composed by a held role.
	parent := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Cache parent"}), 201, "parent").Str("id")
	if r := f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/groups/"+grp, map[string]any{"parent_id": parent}); r.Status >= 300 {
		t.Fatalf("nest group: %d %s", r.Status, r.Raw)
	}
	k2 := check("orders.read").Str("cache_key")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+parent+"/roles", map[string]any{"role_id": f.Roles["orders-viewer"]}), 201, "ancestor grant")
	if check("orders.read").Str("cache_key") == k2 {
		t.Fatal("cache key survived a grant to an ancestor group")
	}
	inner := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles", map[string]any{"name": "cache-inner", "permissions": []string{"orders.read"}}), 201,
		"inner role").Str("id")
	outer := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles", map[string]any{"name": "cache-outer", "permissions": []string{"orders.read"},
		"composite_role_ids": []string{inner}}), 201, "outer role").Str("id")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/roles", map[string]any{"role_id": outer}), 201, "composite grant")
	k3 := check("orders.read").Str("cache_key")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/roles/"+inner+"/permissions", map[string]any{"add": []string{"orders.refund"}}), 200,
		"edit composed role")
	if check("orders.read").Str("cache_key") == k3 {
		t.Fatal("cache key survived a change to a composed role")
	}
	// The same subject presented with a different audience or assurance is a
	// different key: a decision is never reused across token evidence.
	bobBilling := f.LoginWeb("bob", f.Acme, f.BillingAud, "billing:read").Tokens.Str("access_token")
	other := f.must(h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bobBilling, "action": "orders.read",
		"resource": map[string]any{"type": "order", "id": "ord_acme_1", "org_id": f.Acme}}), 200, "decision")
	if other.Str("cache_key") != "" && other.Str("cache_key") == check("orders.read").Str("cache_key") {
		t.Fatal("cache key shared across token audiences")
	}
}
