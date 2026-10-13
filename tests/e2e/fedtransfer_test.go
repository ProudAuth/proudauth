package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestFederationTransfer covers FED-016: account links move from one
// provider connection to another (a new upstream tenant) through a reviewed
// migration map with collision reporting, never by email.
func TestFederationTransfer(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	oldIdP, newIdP := newFakeIdP(t, h.Clock.Now), newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	pool := oldIdP.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
	pool.AddCert(newIdP.srv.Certificate())
	h.App.Federation.Egress.RootCAs = pool

	create := func(alias string, idp *fakeIdP) string {
		return f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": alias, "display_name": alias, "issuer": idp.srv.URL,
			"client_secret": "upstream-secret", "config": map[string]any{"client_id": "proudauth"}, "jit_provisioning": true}), 201, "provider "+alias).Str("id")
	}
	oldID, newID := create("old-tenant", oldIdP), create("new-tenant", newIdP)
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	login := func(provider string, idp *fakeIdP, claims map[string]any) *Resp {
		t.Helper()
		idp.next = claims
		start, _, cont := h.StartTx(acct)
		tx := start.Str("transaction_id")
		st := h.Step(tx, cont, "federation/start", map[string]any{"provider": provider})
		mustStatus(t, st, 200, "federation start")
		mustStatus(t, h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}), 200, "callback")
		return h.Step(tx, cont, "resume", nil)
	}
	for _, sub := range []string{"ann", "ben", "cy", "dee"} {
		if st := login("old-tenant", oldIdP, map[string]any{"sub": "old-" + sub, "email": sub + "@corp.test", "email_verified": true}); st.Str("redirect_to") == "" {
			t.Fatalf("old sign-in %s: %s", sub, st.Raw)
		}
	}
	// Someone already signed in through the new tenant as new-cy: a collision.
	login("new-tenant", newIdP, map[string]any{"sub": "new-cy", "email": "other@corp.test", "email_verified": true})
	userOf := func(provider, sub string) string {
		var u string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT user_id FROM external_identities WHERE provider_id=$1 AND upstream_subject=$2`, provider, sub).Scan(&u)
		return u
	}
	ann := userOf(oldID, "old-ann")

	// Validation: same connection, no reason, unknown mode.
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers", map[string]any{"source_provider_id": oldID, "target_provider_id": oldID, "mode": "map",
		"reason": "x"}), 422, "same connection")
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers", map[string]any{"source_provider_id": oldID, "target_provider_id": newID, "mode": "email",
		"reason": "x"}), 422, "email mode")

	plan := f.must(f.AdminAPI("POST", "/federation-transfers", map[string]any{"source_provider_id": oldID, "target_provider_id": newID, "mode": "map",
		"reason": "tenant migration CHG-42", "entries": []map[string]any{
			{"source_subject": "old-ann", "target_subject": "new-ann"},
			{"source_subject": "old-ben", "target_subject": "new-shared"},
			{"source_subject": "old-dee", "target_subject": "new-shared"},
			{"source_subject": "old-cy", "target_subject": "new-cy"},
			{"source_subject": "old-zed", "target_subject": "new-zed"},
		}}), 201, "plan")
	id := plan.Str("id")
	sum := func(r *Resp, k string) int { n, _ := r.Get("summary." + k).(float64); return int(n) }
	if sum(plan, "ready") != 1 || sum(plan, "duplicate_target") != 2 || sum(plan, "collision_target") != 1 || sum(plan, "missing_source") != 1 {
		t.Fatalf("analysis: %s", plan.Raw)
	}
	coll := f.must(f.AdminAPI("GET", "/federation-transfers/"+id+"/entries?outcome=collision_target", nil), 200, "collisions")
	if items := coll.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["source_subject"] != "old-cy" {
		t.Fatalf("collision report: %s", coll.Raw)
	}
	// Entries can be appended to a draft; a second entry for old-dee makes
	// both of its entries duplicates.
	more := f.must(f.AdminAPI("POST", "/federation-transfers/"+id+"/entries", map[string]any{"entries": []map[string]any{
		{"source_subject": "old-dee", "target_subject": "new-dee"}}}), 200, "add entries")
	if sum(more, "duplicate_source") != 2 || sum(more, "total") != 6 {
		t.Fatalf("re-analysis: %s", more.Raw)
	}

	// The author cannot approve; nothing applies before approval.
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers/"+id+"/apply", nil), 409, "apply draft")
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers/"+id+"/approve", nil), 403, "self approval")
	second := f.CreateUser("tina")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["realm-admin"], "subject": map[string]any{"type": "user", "id": second}}),
		201, "second administrator")
	tina := f.AdminTokenFor("tina").Tokens.Str("access_token")
	approved := h.API("POST", "/federation-transfers/"+id+"/approve", tina, nil)
	mustStatus(t, approved, 200, "approve")
	if approved.Str("state") != "approved" {
		t.Fatalf("approve: %s", approved.Raw)
	}
	// Only entries still ready move; collisions and duplicates stay put.
	applied := f.must(f.AdminAPI("POST", "/federation-transfers/"+id+"/apply", nil), 200, "apply")
	if applied.Str("state") != "applied" || sum(applied, "applied") != 1 {
		t.Fatalf("apply: %s", applied.Raw)
	}
	// ann's link moved: same account, new connection and subject; the old
	// link is gone; nothing else moved.
	if userOf(newID, "new-ann") != ann || userOf(oldID, "old-ann") != "" || userOf(oldID, "old-cy") == "" || userOf(oldID, "old-ben") == "" {
		t.Fatal("links after transfer")
	}
	// ann now signs in through the new tenant into her existing account.
	if st := login("new-tenant", newIdP, map[string]any{"sub": "new-ann", "email": "ann@corp.test", "email_verified": true}); st.Str("redirect_to") == "" {
		t.Fatalf("sign-in through the new tenant: %s", st.Raw)
	}
	if n := userOf(newID, "new-ann"); n != ann {
		t.Fatal("a new account was created instead of using the transferred link")
	}
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers/"+id+"/apply", nil), 409, "apply twice")
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers/"+id+"/cancel", nil), 409, "cancel applied")

	// same_subject mode derives the map from the source links.
	same := f.must(f.AdminAPI("POST", "/federation-transfers", map[string]any{"source_provider_id": oldID, "target_provider_id": newID,
		"mode": "same_subject", "reason": "subjects kept"}), 201, "same subject plan")
	if sum(same, "total") != 3 || sum(same, "ready") != 3 {
		t.Fatalf("same_subject analysis: %s", same.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/federation-transfers/"+same.Str("id")+"/cancel", nil), 204, "cancel")
	list := f.must(f.AdminAPI("GET", "/federation-transfers", nil), 200, "list")
	if len(list.Get("items").([]any)) != 2 {
		t.Fatalf("list: %s", list.Raw)
	}
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=federation.transfer.applied", nil), 200, "audit")
	if !strings.Contains(string(ev.Raw), `"moved"`) {
		t.Fatalf("transfer not audited: %s", ev.Raw)
	}
}
