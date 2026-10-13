package e2e

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestAccessReviews covers AZ-025: a campaign snapshots the assignments in
// scope; only its named reviewers decide, never on their own access, with a
// reason to revoke; closing applies decisions (and the undecided rule) and
// keeps per-item outcomes, including revocations the platform refuses (the
// last owner); campaigns close on their own at the due date; the evidence
// export says what it is and what it is not.
func TestAccessReviews(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	due := h.Clock.Now().Add(7 * 24 * time.Hour)
	mustStatus(t, f.AdminAPI("POST", "/access-reviews", map[string]any{"name": "x", "reviewer_ids": []string{}, "due_at": due}), 422, "no reviewers")
	rv := f.must(f.AdminAPI("POST", "/access-reviews", map[string]any{"name": "Acme Q4", "organization_id": f.Acme,
		"reviewer_ids": []string{f.Users["carol"], f.Users["bob"]}, "due_at": due}), 201, "campaign")
	if rv.Get("items_total").(float64) < 4 {
		t.Fatalf("snapshot: %s", rv.Raw)
	}
	id := rv.Str("id")
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	mine := f.must(h.API("GET", "/me/access-reviews", carol, nil), 200, "reviewer campaigns")
	if len(mine.Get("items").([]any)) != 1 {
		t.Fatalf("reviewer view: %s", mine.Raw)
	}
	mustStatus(t, h.API("GET", "/me/access-reviews/"+id+"/items", alice, nil), 404, "not a reviewer")
	items := f.must(h.API("GET", "/me/access-reviews/"+id+"/items?limit=500", carol, nil), 200, "items").Get("items").([]any)
	find := func(subject, role string) string {
		for _, it := range items {
			m := it.(map[string]any)
			if m["subject"].(map[string]any)["id"] == subject && m["role_name"] == role {
				return m["id"].(string)
			}
		}
		t.Fatalf("no item %s/%s", subject, role)
		return ""
	}
	decide := func(tok, item, decision, comment string) *Resp {
		return h.API("POST", "/me/access-reviews/"+id+"/items/"+item+"/decision", tok, map[string]any{"decision": decision, "comment": comment})
	}
	bobViewer, aliceOwner, aliceRefunder := find(f.Users["bob"], "orders-viewer"), find(f.Users["alice"], "owner"), find(f.Users["alice"], "orders-refunder")
	mustStatus(t, decide(carol, bobViewer, "revoke", ""), 422, "revoking needs a reason")
	mustStatus(t, decide(bob, bobViewer, "keep", ""), 403, "deciding on one's own access")
	f.must(decide(carol, bobViewer, "revoke", "left the orders team"), 200, "revoke")
	f.must(decide(bob, aliceOwner, "revoke", "testing last-owner protection"), 200, "revoke the owner")
	f.must(decide(carol, aliceRefunder, "keep", ""), 200, "keep")
	closed := f.must(f.AdminAPI("POST", "/access-reviews/"+id+"/close", nil), 200, "close")
	if closed.Str("state") != "closed" || closed.Get("summary.revoked") != float64(1) || closed.Get("summary.revoke_failed") != float64(1) {
		t.Fatalf("closed campaign: %s", closed.Raw)
	}
	mustStatus(t, decide(carol, bobViewer, "keep", ""), 409, "deciding after close")
	perms := string(f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"]+"/permissions", nil), 200, "bob permissions").Raw)
	if strings.Contains(perms, "orders.read") {
		t.Fatalf("revoked assignment still grants: %s", perms)
	}
	ev := f.must(f.AdminAPI("GET", "/access-reviews/"+id+"/evidence", nil), 200, "evidence")
	if !strings.Contains(ev.Str("statement"), "not a regulatory certification") || len(ev.Get("items").([]any)) != int(rv.Get("items_total").(float64)) {
		t.Fatalf("evidence: %s", ev.Raw)
	}
	outcomes := map[string]string{}
	for _, it := range ev.Get("items").([]any) {
		m := it.(map[string]any)
		outcomes[m["id"].(string)] = m["outcome"].(string)
	}
	if outcomes[bobViewer] != "revoked" || outcomes[aliceOwner] != "revoke_failed" || outcomes[aliceRefunder] != "kept" {
		t.Fatalf("outcomes: %v", outcomes)
	}

	// Privileged-only campaign whose undecided items are revoked at the due date.
	rv2 := f.must(f.AdminAPI("POST", "/access-reviews", map[string]any{"name": "Privileged", "organization_id": f.Acme, "privileged_only": true,
		"on_no_decision": "revoke", "reviewer_ids": []string{f.Users["carol"]}, "due_at": h.Clock.Now().Add(time.Hour)}), 201, "privileged campaign")
	for _, it := range f.must(f.AdminAPI("GET", "/access-reviews/"+rv2.Str("id")+"/items", nil), 200, "items").Get("items").([]any) {
		if it.(map[string]any)["privileged"] != true {
			t.Fatalf("non-privileged item in a privileged-only campaign: %v", it)
		}
	}
	h.Clock.Advance(2 * time.Hour)
	if n, err := h.App.Authz.CloseDueReviews(ctx); err != nil || n != 1 {
		t.Fatalf("due sweep: %d %v", n, err)
	}
	f.ReloginAdmin()
	got := f.must(f.AdminAPI("GET", "/access-reviews/"+rv2.Str("id"), nil), 200, "after sweep")
	if got.Str("state") != "closed" || got.Get("summary.undecided").(float64) < 1 {
		t.Fatalf("swept campaign: %s", got.Raw)
	}
	perms = string(f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["alice"]+"/permissions", nil), 200, "alice permissions").Raw)
	if strings.Contains(perms, "orders.refund") {
		t.Fatal("undecided privileged assignment survived a revoke-by-default campaign")
	}
}
