package e2e

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestJustInTimeElevation covers AZ-024: administrators who could assign a
// role make someone eligible for it; the person asks with a reason and a
// duration from a fresh MFA session; privileged roles always need an
// independent approver; the assignment ends at the deadline on its own, or
// earlier when the person ends it or the eligibility is revoked.
func TestJustInTimeElevation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	acme := map[string]any{"type": "organization", "id": f.Acme}
	mustStatus(t, f.AdminAPI("POST", "/elevation-eligibilities", map[string]any{"user_id": f.Users["bob"], "role_id": f.Roles["orders-refunder"],
		"scope": acme, "requires_approval": false}), 422, "privileged role without approval")
	refund := f.must(f.AdminAPI("POST", "/elevation-eligibilities", map[string]any{"user_id": f.Users["bob"], "role_id": f.Roles["orders-refunder"],
		"scope": acme, "max_duration_seconds": 3600}), 201, "privileged eligibility")
	viewer := f.must(f.AdminAPI("POST", "/elevation-eligibilities", map[string]any{"user_id": f.Users["bob"], "role_id": f.Roles["billing-viewer"],
		"scope": acme, "requires_approval": false, "max_duration_seconds": 1800}), 201, "ordinary eligibility")
	perms := func() string {
		return string(f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"]+"/permissions", nil), 200, "permissions").Raw)
	}
	if strings.Contains(perms(), "billing.read") || strings.Contains(perms(), "orders.refund") {
		t.Fatal("eligibility alone granted permissions")
	}

	single := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/elevations", single, map[string]any{"eligibility_id": viewer.Str("id"), "reason": "quarter close"}), 403,
		"elevation from a single-factor session")
	f.EnrollTOTP("bob")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": viewer.Str("id"), "reason": ""}), 422, "reason required")
	mustStatus(t, h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": viewer.Str("id"), "reason": "quarter close",
		"duration_seconds": 7200}), 422, "longer than the eligibility allows")
	v := f.must(h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": viewer.Str("id"), "reason": "quarter close",
		"duration_seconds": 600}), 201, "ordinary elevation")
	if v.Str("state") != "active" || !strings.Contains(perms(), "billing.read") {
		t.Fatalf("ordinary elevation: %s", v.Raw)
	}
	mustStatus(t, h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": viewer.Str("id"), "reason": "again"}), 409, "already active")
	f.must(h.API("POST", "/me/elevations/"+v.Str("id")+"/end", bob, nil), 204, "end early")
	if strings.Contains(perms(), "billing.read") {
		t.Fatal("ended elevation still grants")
	}

	req := f.must(h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": refund.Str("id"), "reason": "refund backlog INC-42"}), 201, "privileged request")
	if req.Str("state") != "pending" || strings.Contains(perms(), "orders.refund") {
		t.Fatalf("privileged request: %s", req.Raw)
	}
	pending := f.must(f.AdminAPI("GET", "/elevations?state=pending", nil), 200, "pending")
	if len(pending.Get("items").([]any)) != 1 {
		t.Fatalf("pending list: %s", pending.Raw)
	}
	approved := f.must(f.AdminAPI("POST", "/elevations/"+req.Str("id")+"/approve", nil), 200, "approve")
	if approved.Str("state") != "active" || approved.Str("ends_at") == "" || !strings.Contains(perms(), "orders.refund") {
		t.Fatalf("approved elevation: %s", approved.Raw)
	}
	var source string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT source FROM role_assignments WHERE id=$1`, approved.Str("assignment_id")).Scan(&source)
	if source != "elevation" {
		t.Fatalf("assignment source: %q", source)
	}
	// The deadline passes: the sweep removes the role and records the end.
	h.Clock.Advance(2 * time.Hour)
	f.ReloginAdmin()
	if _, err := h.App.Authz.ExpireAssignments(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(perms(), "orders.refund") {
		t.Fatal("expired elevation still grants")
	}
	mine := f.must(h.API("GET", "/me/elevations?state=expired", f.AccountToken("bob").Tokens.Str("access_token"), nil), 200, "my elevations")
	if len(mine.Get("items").([]any)) != 1 {
		t.Fatalf("expired elevation: %s", mine.Raw)
	}
	// The end at the deadline has its own evidence, as documented.
	var expiredBy, expiredSubject string
	var expiredMeta []byte
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT actor_type, coalesce(subject_id,''), metadata FROM audit_events WHERE type='authorization.elevation.expired'`).
		Scan(&expiredBy, &expiredSubject, &expiredMeta); err != nil {
		t.Fatalf("authorization.elevation.expired not recorded: %v", err)
	}
	if expiredBy != "system" || expiredSubject != f.Users["bob"] || !strings.Contains(string(expiredMeta), req.Str("id")) {
		t.Fatalf("elevation expiry evidence: actor %s, subject %s, metadata %s", expiredBy, expiredSubject, expiredMeta)
	}
	// Rejection, and revoking an eligibility cancels what is pending.
	bob = f.AccountToken("bob").Tokens.Str("access_token")
	r2 := f.must(h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": refund.Str("id"), "reason": "second try"}), 201, "second request")
	f.must(f.AdminAPI("POST", "/elevations/"+r2.Str("id")+"/reject", nil), 200, "reject")
	r3 := f.must(h.API("POST", "/me/elevations", bob, map[string]any{"eligibility_id": refund.Str("id"), "reason": "third try"}), 201, "third request")
	mustStatus(t, f.AdminAPI("DELETE", "/elevation-eligibilities/"+refund.Str("id"), nil), 204, "revoke eligibility")
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM elevations WHERE id=$1`, r3.Str("id")).Scan(&state)
	if state != "cancelled" {
		t.Fatalf("pending request after revocation: %s", state)
	}
	var events int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type LIKE 'authorization.elevation.%'`).Scan(&events)
	if events < 8 {
		t.Fatalf("elevation evidence: %d events", events)
	}
}
