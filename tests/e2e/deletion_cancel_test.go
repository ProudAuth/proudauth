package e2e

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/worker"
)

// deletionLogin starts an account-console sign-in for user and returns the
// transaction, its continuation, the PKCE verifier and the initial state.
func deletionLogin(t *testing.T, h *Harness, user string) (LoginOpts, string, string, string, *Resp) {
	t.Helper()
	opts := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: user + "@example.test"}
	start, verifier, cont := h.StartTx(opts)
	mustStatus(t, start, 201, "start sign-in")
	return opts, start.Str("transaction_id"), cont, verifier, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}
}

// TestDeletionCancelAtSignIn covers USR-012's cancellation path: a
// self-service deletion request (recent authentication, dependency checks)
// queues the deletion_scheduled notice and ends every session; signing in
// during the delay takes the account's usual factors (password and TOTP) and
// then offers only cancel_deletion with the scheduled time: no session, code
// or token exists while the deletion is pending. Cancelling makes the account
// active and the same sign-in completes, so the account is usable again.
func TestDeletionCancelAtSignIn(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	dina := f.CreateUser("dina")
	f.EnrollTOTP("dina")
	before := f.AccountToken("dina").Tokens.Str("access_token")
	req := f.must(h.API("POST", "/me/deletion-request", before, nil), 202, "deletion request")
	if req.Str("state") != "pending_deletion" || req.Str("deletion_scheduled_at") == "" {
		t.Fatalf("deletion request: %s", req.Raw)
	}
	// The notice says when, and that signing in cancels it.
	if mail := h.Mail("dina@example.test", "deletion_scheduled"); !strings.Contains(mail, "scheduled for deletion") || !strings.Contains(mail, "Sign in and cancel") {
		t.Fatalf("deletion_scheduled notice: %q", mail)
	}
	mustStatus(t, h.API("GET", "/me", before, nil), 401, "session ended by the request")

	// The password alone does not reach the cancellation: TOTP is still due.
	opts, tx, cont, verifier, _ := deletionLogin(t, h, "dina")
	st := h.Step(tx, cont, "password", map[string]any{"identifier": opts.Identifier, "password": h.passwords[opts.Identifier]})
	mustStatus(t, st, 200, "password")
	if types := actionTypes(st); !slices.Contains(types, "totp") || slices.Contains(types, "cancel_deletion") {
		t.Fatalf("after the password: %v %s", types, st.Raw)
	}
	if r := h.Step(tx, cont, "cancel-deletion", nil); r.Status < 400 {
		t.Fatalf("cancel_deletion before the second factor: %d %s", r.Status, r.Raw)
	}
	st = h.Step(tx, cont, "totp", map[string]any{"code": h.TOTPNow(opts.Identifier)})
	mustStatus(t, st, 200, "totp")
	if types := actionTypes(st); !slices.Equal(types, []string{"cancel_deletion"}) || st.Str("status") != "pending" || st.Str("redirect_to") != "" {
		t.Fatalf("a pending-deletion account must reach only cancel_deletion: %v %s", types, st.Raw)
	}
	acts, _ := st.Get("next_actions").([]any)
	opt, _ := acts[0].(map[string]any)["options"].(map[string]any)
	if opt["deletion_scheduled_at"] != req.Str("deletion_scheduled_at") {
		t.Fatalf("deletion status not shown: %v (want %s)", opt, req.Str("deletion_scheduled_at"))
	}
	// Nothing was issued: no session, and other steps do not complete it.
	if n := sesCount(t, h, `SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, dina); n != 0 {
		t.Fatalf("%d sessions for a pending-deletion account", n)
	}
	if r := h.Step(tx, cont, "consent", map[string]any{"approve": true}); r.Str("redirect_to") != "" {
		t.Fatalf("another step completed the sign-in: %s", r.Raw)
	}
	if n := sesCount(t, h, `SELECT count(*) FROM authorization_codes WHERE transaction_id=$1`, tx); n != 0 {
		t.Fatalf("%d authorization codes for a pending-deletion account", n)
	}

	// Cancel: the account is active again and the sign-in completes.
	st = h.Step(tx, cont, "cancel-deletion", nil)
	mustStatus(t, st, 200, "cancel deletion")
	st = h.Drive(tx, cont, st, opts)
	redirect := st.Str("redirect_to")
	u, _ := url.Parse(redirect)
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("sign-in did not complete after cancelling: %s", st.Raw)
	}
	toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {"http://127.0.0.1/callback"}, "resource": {h.Realm.Issuer + "/account"}}, "proudauth-cli", "")
	mustStatus(t, toks, 200, "token exchange after cancelling")
	me := f.must(h.API("GET", "/me", toks.Str("access_token"), nil), 200, "account usable again")
	if me.Str("state") != "active" || me.Get("deletion_scheduled_at") != nil {
		t.Fatalf("account after cancelling: %s", me.Raw)
	}
	mustStatus(t, h.API("GET", "/me", before, nil), 401, "the old session stays ended")
	var via string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(metadata->>'via','') FROM audit_events WHERE type='user.deletion.cancelled'
		AND subject_id=$1`, dina).Scan(&via)
	if via != "sign_in" {
		t.Fatalf("cancellation audit: via=%q", via)
	}
	// Nothing is pending any more: the worker leaves the account alone.
	h.Clock.Advance(h.App.D.Cfg.Privacy.DeletionGracePeriod + time.Hour)
	if _, err := worker.New(h.App, "test").CompleteDeletions(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, dina).Scan(&state)
	if state != "active" {
		t.Fatalf("cancelled deletion completed anyway: %s", state)
	}
}

// TestDeletionCompletesWithoutCancel covers USR-012's other branch: a
// sign-in during the delay that does not cancel (the user abandons it)
// changes nothing, and the deletion completes at the scheduled time; the
// erased account can no longer sign in, not even to the cancel step.
func TestDeletionCompletesWithoutCancel(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	erin := f.CreateUser("erin")
	tok := f.AccountToken("erin").Tokens.Str("access_token")
	f.must(h.API("POST", "/me/deletion-request", tok, nil), 202, "deletion request")

	opts, tx, cont, _, st := deletionLogin(t, h, "erin")
	st = h.Drive(tx, cont, st, opts)
	if !slices.Equal(actionTypes(st), []string{"cancel_deletion"}) {
		t.Fatalf("sign-in during the delay: %s", st.Raw)
	}
	if r := h.Step(tx, cont, "cancel", nil); r.Str("status") != "cancelled" {
		t.Fatalf("abandon the sign-in: %s", r.Raw)
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, erin).Scan(&state)
	if state != "pending_deletion" {
		t.Fatalf("an abandoned sign-in changed the account: %s", state)
	}

	// Not due yet: the worker waits for the delay.
	if _, err := worker.New(h.App, "test").CompleteDeletions(ctx); err != nil {
		t.Fatal(err)
	}
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, erin).Scan(&state)
	if state != "pending_deletion" {
		t.Fatalf("deleted before the delay: %s", state)
	}
	h.Clock.Advance(h.App.D.Cfg.Privacy.DeletionGracePeriod + time.Hour)
	if _, err := worker.New(h.App, "test").CompleteDeletions(ctx); err != nil {
		t.Fatal(err)
	}
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, erin).Scan(&state)
	if state != "deleted" {
		t.Fatalf("deletion not completed after the delay: %s", state)
	}
	_, tx, cont, _, _ = deletionLogin(t, h, "erin")
	if r := h.Step(tx, cont, "password", map[string]any{"identifier": opts.Identifier, "password": h.passwords[opts.Identifier]}); r.Status != 401 {
		t.Fatalf("erased account signed in: %d %s", r.Status, r.Raw)
	}
}
