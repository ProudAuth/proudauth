package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/httpapi"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/provision"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/server"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestAuditAndOutboxCommitWithMutation covers ARC-003, AUD-004 and DB-009: a
// privileged change, its audit event and its outbox event commit in one
// database transaction. When the audit or the outbox write fails, the change
// does not happen at all; when they succeed, all three rows carry the same
// transaction ID, and the outbox event is delivered by a worker only after
// the commit.
func TestAuditAndOutboxCommitWithMutation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	pool := h.App.D.DB.Pool
	bob := f.Users["bob"]
	f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	activeSessions := count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, bob)
	if activeSessions == 0 {
		t.Fatal("fixture: bob has no session")
	}
	unchanged := func(what string) {
		t.Helper()
		if n := count(`SELECT count(*) FROM users WHERE id=$1 AND state='active'`, bob); n != 1 {
			t.Fatalf("%s: the account was suspended without its evidence", what)
		}
		if n := count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, bob); n != activeSessions {
			t.Fatalf("%s: sessions were revoked without evidence (%d of %d left)", what, n, activeSessions)
		}
		if n := count(`SELECT count(*) FROM audit_events WHERE type='user.suspended' AND subject_id=$1`, bob) +
			count(`SELECT count(*) FROM outbox_events WHERE event_type='user.suspended' AND aggregate_id=$1`, bob); n != 0 {
			t.Fatalf("%s: %d evidence rows survived the failed change", what, n)
		}
	}

	// The audit store refuses the event: no unaudited success.
	exec(`CREATE FUNCTION pa_test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.type = 'user.suspended' THEN RAISE EXCEPTION 'audit storage unavailable'; END IF; RETURN NEW; END $$`)
	exec(`CREATE TRIGGER pa_test_fail_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION pa_test_fail_audit()`)
	if r := f.AdminAPI("POST", "/users/"+bob+"/suspend", map[string]any{"reason": "investigation"}); r.Status < 500 {
		t.Fatalf("suspension succeeded without its audit event: %d %s", r.Status, r.Raw)
	}
	unchanged("audit failure")
	exec(`DROP TRIGGER pa_test_fail_audit ON audit_events`)

	// The outbox refuses the event: neither the change nor its audit event commit.
	exec(`CREATE FUNCTION pa_test_fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.event_type = 'user.suspended' THEN RAISE EXCEPTION 'outbox unavailable'; END IF; RETURN NEW; END $$`)
	exec(`CREATE TRIGGER pa_test_fail_outbox BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION pa_test_fail_outbox()`)
	if r := f.AdminAPI("POST", "/users/"+bob+"/suspend", map[string]any{"reason": "investigation"}); r.Status < 500 {
		t.Fatalf("suspension succeeded without its outbox event: %d %s", r.Status, r.Raw)
	}
	unchanged("outbox failure")
	exec(`DROP TRIGGER pa_test_fail_outbox ON outbox_events`)

	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
	var userTx, auditTx, outboxTx, outboxState string
	if err := pool.QueryRow(ctx, `SELECT xmin::text FROM users WHERE id=$1`, bob).Scan(&userTx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT xmin::text FROM audit_events WHERE type='user.suspended' AND subject_id=$1`, bob).Scan(&auditTx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT xmin::text, state FROM outbox_events WHERE event_type='user.suspended' AND aggregate_id=$1`, bob).
		Scan(&outboxTx, &outboxState); err != nil {
		t.Fatal(err)
	}
	if userTx != auditTx || userTx != outboxTx {
		t.Fatalf("mutation, audit and outbox committed in different transactions: %s %s %s", userTx, auditTx, outboxTx)
	}
	if outboxState != "pending" {
		t.Fatalf("outbox event dispatched inside the request: %s", outboxState)
	}
	runWorker(t, worker.New(h.App, "test"))
	if n := count(`SELECT count(*) FROM outbox_events WHERE event_type='user.suspended' AND aggregate_id=$1 AND state='dispatched'`, bob); n != 1 {
		t.Fatal("worker did not deliver the committed event")
	}
}

type failingMail struct{ sent int }

func (m *failingMail) Send(context.Context, notification.Email) (string, error) {
	m.sent++
	return "", errors.New("smtp: connection refused")
}

// TestDeliveryFailureLeavesRecoverableState covers ARC-004: an invitation is
// created completely even though its email cannot be delivered; delivery is
// a persisted job that is retried, ends as failed with its status exposed on
// the invitation and in the audit log, and the invitation can be resent and
// accepted once mail works again.
func TestDeliveryFailureLeavesRecoverableState(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	f.CreateUser("dave")
	mail := &failingMail{}
	h.App.Notify.DevSink, h.App.Notify.Email = false, mail
	defer func() { h.App.Notify.DevSink = true }()

	alice := f.AccountToken("alice").Tokens.Str("access_token")
	inv := f.must(h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "dave@example.test"}), 201,
		"invite while mail is down")
	id := inv.Str("invitation.id")
	invitation := func() map[string]any {
		t.Helper()
		list := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/invitations", nil), 200, "invitations")
		for _, it := range list.Get("items").([]any) {
			if m := it.(map[string]any); m["id"] == id {
				return m
			}
		}
		t.Fatalf("invitation %s not listed: %s", id, list.Raw)
		return nil
	}
	if m := invitation(); m["state"] != "pending_delivery" {
		t.Fatalf("invitation not recorded completely: %v", m)
	}
	for i := 0; i < 8; i++ {
		h.Clock.Advance(20 * time.Minute)
		if _, err := h.App.Notify.DeliverDue(ctx, "test", 100, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	var state, lastError string
	var attempts int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, attempts, coalesce(last_error,'') FROM notification_jobs
		WHERE reference_type='invitation' AND reference_id=$1`, id).Scan(&state, &attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if mail.sent < 2 || attempts != mail.sent || state != "failed" || lastError == "" {
		t.Fatalf("delivery job: state=%s attempts=%d sends=%d error=%q", state, attempts, mail.sent, lastError)
	}
	if _, err := h.App.Orgs.SyncDeliveryStates(ctx); err != nil {
		t.Fatal(err)
	}
	f.ReloginAdmin()
	if m := invitation(); m["delivery_state"] != "failed" || m["state"] != "pending_delivery" {
		t.Fatalf("delivery failure not exposed, or the invitation changed: %v", m)
	}
	var audited int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='invitation.delivery.failed' AND target_id=$1`, id).Scan(&audited)
	if audited != 1 {
		t.Fatal("delivery failure not audited")
	}

	// Mail works again: the invitation is resent and accepted.
	h.App.Notify.DevSink = true
	alice = f.AccountToken("alice").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/invitations/"+id+"/resend", alice, nil), 200, "resend")
	secret := invitationFromMail(h.Mail("dave@example.test", "invitation"))
	if secret == "" {
		t.Fatal("resent invitation not delivered")
	}
	mustStatus(t, h.API("POST", "/invitations/accept", f.AccountToken("dave").Tokens.Str("access_token"), map[string]any{"invitation": secret}), 200, "accept")
}

// TestRequestsAcrossNodes covers ARC-006: two server nodes share only the
// database and the root keys. A sign-in transaction started on one node
// continues on the other, a code issued by one is redeemed on the other,
// refresh, introspection, refresh-family compromise and membership removal
// are seen by both nodes at once, so neither needs sticky routing.
func TestRequestsAcrossNodes(t *testing.T) {
	f := NewFixture(t)
	a := f.H
	cfg := *a.Cfg
	app, err := httpapi.Build(runtime.New(a.App.D.DB, &cfg, a.Clock, a.App.D.Keys, observability.NewLogger(io.Discard, "error", "json")), nil)
	if err != nil {
		t.Fatal(err)
	}
	app.KeyMgr.RSABits = 2048
	server.RegisterModules(app)
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	nodeB := *a
	nodeB.App, nodeB.Srv, nodeB.Base = app, srv, srv.URL
	b := &nodeB

	start, verifier, cont := a.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme})
	mustStatus(t, start, 201, "start on node A")
	st := b.Drive(start.Str("transaction_id"), cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)},
		LoginOpts{Identifier: "bob@example.test", SelectOrg: f.Acme})
	u, _ := url.Parse(st.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("transaction did not complete on node B: %s", st.Raw)
	}
	tokens := a.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {webRedirect}, "resource": {f.OrdersAud}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, tokens, 200, "code from node B redeemed on node A")
	refreshed := b.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, refreshed, 200, "refresh on node B")
	access := refreshed.Str("access_token")
	if in := a.Introspect("orders-rs", f.Clients["orders-rs"].Secret, access); in.Get("active") != true {
		t.Fatalf("node A does not recognize a token from node B: %s", in.Raw)
	}
	// Replaying the rotated refresh token on node A compromises the family
	// node B continued.
	if r := a.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret); r.Status != 400 {
		t.Fatalf("rotated refresh token accepted by node A: %d %s", r.Status, r.Raw)
	}
	if r := b.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret); r.Status != 400 {
		t.Fatalf("node B kept a family that node A found compromised: %d", r.Status)
	}
	if in := b.Introspect("orders-rs", f.Clients["orders-rs"].Secret, access); in.Get("active") != false {
		t.Fatalf("node B still accepts a token of the compromised family: %s", in.Raw)
	}
	// Administration on one node is effective on the other at once.
	fresh := b.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"}).Tokens.Str("access_token")
	if in := b.Introspect("orders-rs", f.Clients["orders-rs"].Secret, fresh); in.Get("active") != true {
		t.Fatalf("fresh token from node B: %s", in.Raw)
	}
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "remove bob on node A")
	if in := b.Introspect("orders-rs", f.Clients["orders-rs"].Secret, fresh); in.Get("active") != false {
		t.Fatalf("node B still accepts a token after the membership was removed on node A: %s", in.Raw)
	}
}

// TestCORSAllowlist covers SEC-003: cross-origin responses name only origins
// registered by an active client, never a wildcard; credentialed CORS is
// offered only on the interaction API, and preflights from unregistered
// origins get no methods.
func TestCORSAllowlist(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	preflight := func(origin, path string) *Resp {
		return h.Do(Req{Method: "OPTIONS", Path: path, Headers: map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST",
			"Access-Control-Request-Headers": "content-type"}})
	}
	r := preflight("https://app.test", "/api/v1/realms/main/auth/transactions")
	if r.Header.Get("Access-Control-Allow-Origin") != "https://app.test" || r.Header.Get("Access-Control-Allow-Credentials") != "true" ||
		!strings.Contains(r.Header.Get("Access-Control-Allow-Methods"), "POST") || !strings.Contains(r.Header.Get("Vary"), "Origin") {
		t.Fatalf("registered origin preflight: %v", r.Header)
	}
	for _, origin := range []string{"https://evil.test", "https://app.test.evil.test", "null", "*"} {
		r := preflight(origin, "/api/v1/realms/main/auth/transactions")
		if v := r.Header.Get("Access-Control-Allow-Origin"); v != "" || r.Header.Get("Access-Control-Allow-Methods") != "" {
			t.Fatalf("unregistered origin %q allowed: %v", origin, r.Header)
		}
	}
	token := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: url.Values{"grant_type": {"client_credentials"}},
		Headers: map[string]string{"Origin": "https://partner.test"}})
	if token.Header.Get("Access-Control-Allow-Origin") != "https://partner.test" || token.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("token endpoint CORS: %v", token.Header)
	}
	if v := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: url.Values{"grant_type": {"client_credentials"}},
		Headers: map[string]string{"Origin": "https://evil.test"}}).Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("token endpoint allowed an unregistered origin: %q", v)
	}
	// The administration API is not offered cross-origin at all.
	if v := h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users", Token: f.AdminToken,
		Headers: map[string]string{"Origin": "https://app.test"}}).Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("administration API answered a cross-origin request: %q", v)
	}
}

// TestIssuanceFailsClosedWithoutKeyIntegrity covers SEC-009: when the active
// signing key cannot be decrypted and authenticated, token issuance stops
// instead of signing with anything else, and resumes once the key is intact.
func TestIssuanceFailsClosedWithoutKeyIntegrity(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	pool := h.App.D.DB.Pool
	var kid string
	var ct []byte
	if err := pool.QueryRow(ctx, `SELECT kid, private_ciphertext FROM signing_keys WHERE realm_id=$1 AND purpose='token' AND state='active'`,
		h.Realm.ID).Scan(&kid, &ct); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET private_ciphertext=$2 WHERE kid=$1`, kid, tampered); err != nil {
		t.Fatal(err)
	}
	h.App.KeyMgr.Invalidate(h.Realm.ID)
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "openid orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", ExpectFail: true})
	if lr.Tokens == nil || lr.Tokens.Status < 500 || lr.Tokens.Str("access_token") != "" || lr.Tokens.Str("id_token") != "" {
		t.Fatalf("tokens issued with a key whose integrity cannot be established: %+v", lr.Tokens)
	}
	if m := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme); m.Status < 500 || m.Str("access_token") != "" {
		t.Fatalf("client-credentials issuance did not fail closed: %d %s", m.Status, m.Raw)
	}
	var keys int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE realm_id=$1 AND purpose='token'`, h.Realm.ID).Scan(&keys)
	if keys != 1 {
		t.Fatalf("a replacement key was created silently: %d keys", keys)
	}
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET private_ciphertext=$2 WHERE kid=$1`, kid, ct); err != nil {
		t.Fatal(err)
	}
	h.App.KeyMgr.Invalidate(h.Realm.ID)
	if tok := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token"); kidOf(tok) != kid {
		t.Fatal("issuance did not resume with the intact key")
	}
}

// TestBootstrapLockdown covers SEC-011: the first administrator of a realm
// is created only through the operator channel, without a password (a
// one-time, expiring setup token sets it), and once a realm has its first
// administrator a repeated bootstrap is refused and creates nothing; only the
// audited break-glass procedure can add another.
func TestBootstrapLockdown(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	pool := h.App.D.DB.Pool
	if _, err := h.App.Provision.BootstrapAdmin(ctx, "main", "second@example.test", "second-admin", time.Hour, false, "tester"); !errors.Is(err, provision.ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap of an initialized realm: %v", err)
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM user_identifiers WHERE realm_id=$1 AND canonical_value IN ('second@example.test','second-admin')`, h.Realm.ID); n != 0 {
		t.Fatal("refused bootstrap created an account")
	}

	other, err := h.App.Provision.CreateRealm(ctx, "other", "Other", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.App.Provision.BootstrapAdmin(ctx, "other", "first@example.test", "first-admin", time.Hour, false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM credentials WHERE user_id=$1`, res.UserID); n != 0 {
		t.Fatalf("bootstrap administrator created with %d credentials (a default password)", n)
	}
	if _, err := h.App.Provision.BootstrapAdmin(ctx, "other", "again@example.test", "again-admin", time.Hour, false, "tester"); !errors.Is(err, provision.ErrAlreadyBootstrapped) {
		t.Fatalf("repeated bootstrap: %v", err)
	}
	setup := func(token string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/other/account-setup", JSON: map[string]any{"setup_token": token, "password": "the first administrator passphrase"}})
	}
	mustStatus(t, setup(res.SetupToken), 200, "account setup with the one-time token")
	if r := setup(res.SetupToken); r.Status < 400 {
		t.Fatalf("setup token reused: %d", r.Status)
	}
	if _, err := h.App.Provision.BootstrapAdmin(ctx, "other", "glass@example.test", "glass-admin", time.Hour, true, "tester"); err != nil {
		t.Fatalf("break-glass bootstrap: %v", err)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='bootstrap.break_glass_admin_created' AND category='emergency'`, other.ID); n != 1 {
		t.Fatal("break-glass bootstrap not audited as an emergency action")
	}
}

// TestAuditExportRange covers AUD-010: an audit export covers exactly the
// requested time range as NDJSON with a SHA-256 checksum and progress,
// downloads once through a short-lived credential of the requester, and is
// refused to callers without audit export authority.
func TestAuditExportRange(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "BEFORE_RANGE"}), 200, "event before the range")
	h.Clock.Advance(2 * time.Hour)
	from := h.Clock.Now().Add(-time.Minute)
	f.ReloginAdmin()
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["sam"]+"/suspend", map[string]any{"reason": "IN_RANGE"}), 200, "event in the range")
	to := h.Clock.Now().Add(time.Minute)

	bob := f.AccountToken("bob").Tokens.Str("access_token")
	if r := h.API("POST", "/audit-exports", bob, map[string]any{"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339)}); r.Status != 401 && r.Status != 403 {
		t.Fatalf("export without audit export authority: %d", r.Status)
	}
	job := f.must(f.AdminAPI("POST", "/audit-exports", map[string]any{"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339)}), 202, "export")
	runWorker(t, worker.New(h.App, "test"))
	done := f.must(f.AdminAPI("GET", "/jobs/"+job.Str("job_id"), nil), 200, "job")
	if done.Str("state") != "succeeded" || done.Str("result.format") != "application/x-ndjson" || done.Get("progress.events") == nil {
		t.Fatalf("export job: %s", done.Raw)
	}
	dl := f.must(f.AdminAPI("POST", "/jobs/"+job.Str("job_id")+"/downloads", nil), 201, "download credential")
	data := f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	if ct := data.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
		t.Fatalf("content type %q", ct)
	}
	sum := sha256.Sum256(data.Raw)
	if hex.EncodeToString(sum[:]) != done.Str("result.sha256") {
		t.Fatal("download does not match the published checksum")
	}
	lines := strings.Split(strings.TrimSpace(string(data.Raw)), "\n")
	if float64(len(lines)) != done.Get("result.events").(float64) {
		t.Fatalf("%d lines for %v events", len(lines), done.Get("result.events"))
	}
	inRange := false
	for _, l := range lines {
		var ev struct {
			OccurredAt time.Time `json:"occurred_at"`
			ReasonCode string    `json:"reason_code"`
		}
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("not NDJSON: %q", l)
		}
		if ev.OccurredAt.Before(from) || ev.OccurredAt.After(to) || ev.ReasonCode == "BEFORE_RANGE" {
			t.Fatalf("event outside the requested range: %s", l)
		}
		inRange = inRange || ev.ReasonCode == "IN_RANGE"
	}
	if !inRange {
		t.Fatal("event inside the range missing")
	}
	mustStatus(t, f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 404, "download credential reuse")
	// The same range streams page by page through the audit API.
	rng := "&from=" + url.QueryEscape(from.Format(time.RFC3339)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339))
	first := f.must(f.AdminAPI("GET", "/audit-events?limit=1"+rng, nil), 200, "first page")
	cursor := first.Str("next_cursor")
	if len(first.Get("items").([]any)) != 1 || cursor == "" {
		t.Fatalf("first page: %s", first.Raw)
	}
	second := f.must(f.AdminAPI("GET", "/audit-events?limit=1"+rng+"&cursor="+url.QueryEscape(cursor), nil), 200, "second page")
	if items := second.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["id"] == first.Get("items").([]any)[0].(map[string]any)["id"] {
		t.Fatalf("second page: %s", second.Raw)
	}
	mustStatus(t, f.AdminAPI("GET", "/organizations/"+f.Acme+"/audit-events?cursor="+url.QueryEscape(cursor), nil), 400, "cursor replayed in another scope")
	// Another administrator cannot download the requester's export.
	tina := f.CreateUser("tina")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["realm-admin"], "subject": map[string]any{"type": "user", "id": tina}}), 201, "second admin")
	other := f.AdminTokenFor("tina").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", other, nil), 404, "another administrator's download")
}

// TestAsyncJobContract covers API-011 and PRV-008: a long-running export
// returns a job reference whose status only the requester sees, can be
// cancelled while queued (and not twice), and on success holds its result
// encrypted at rest, released only through a single-use download credential.
func TestAsyncJobContract(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	queued := f.must(h.API("POST", "/me/exports", bob, nil), 202, "export").Str("job_id")
	if !strings.HasPrefix(queued, "job_") {
		t.Fatalf("job reference %q", queued)
	}
	st := f.must(h.API("GET", "/jobs/"+queued, bob, nil), 200, "status")
	if st.Str("state") != "queued" || st.Str("type") != "user.export" || st.Get("cancel_requested") != false {
		t.Fatalf("queued job: %s", st.Raw)
	}
	mustStatus(t, h.API("GET", "/jobs/"+queued, alice, nil), 404, "another user's job status")
	mustStatus(t, h.API("POST", "/jobs/"+queued+"/cancel", alice, nil), 404, "another user cancels")
	mustStatus(t, h.API("POST", "/jobs/"+queued+"/cancel", bob, nil), 202, "cancel")
	mustStatus(t, h.API("POST", "/jobs/"+queued+"/cancel", bob, nil), 409, "cancel twice")
	w := worker.New(h.App, "test")
	runWorker(t, w)
	if st := f.must(h.API("GET", "/jobs/"+queued, bob, nil), 200, "status"); st.Str("state") != "cancelled" || st.Get("cancel_requested") != true {
		t.Fatalf("cancelled job ran: %s", st.Raw)
	}
	mustStatus(t, h.API("POST", "/jobs/"+queued+"/downloads", bob, nil), 409, "no result of a cancelled job")

	id := f.must(h.API("POST", "/me/exports", bob, nil), 202, "export").Str("job_id")
	runWorker(t, w)
	done := f.must(h.API("GET", "/jobs/"+id, bob, nil), 200, "status")
	if done.Str("state") != "succeeded" || done.Get("has_protected_result") != true || done.Str("result.sha256") == "" {
		t.Fatalf("finished job: %s", done.Raw)
	}
	if strings.Contains(string(done.Raw), "bob@example.test") {
		t.Fatal("job status exposes the protected result")
	}
	var ct []byte
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT result_ciphertext FROM jobs WHERE id=$1`, id).Scan(&ct); err != nil || len(ct) == 0 {
		t.Fatalf("no stored result: %v", err)
	}
	if strings.Contains(string(ct), "bob@example.test") || strings.Contains(string(ct), f.Users["bob"]) {
		t.Fatal("export result stored in plaintext")
	}
	dl := f.must(h.API("POST", "/jobs/"+id+"/downloads", bob, nil), 201, "download credential")
	data := f.must(h.API("POST", "/job-downloads", bob, map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	if sum := sha256.Sum256(data.Raw); hex.EncodeToString(sum[:]) != done.Str("result.sha256") || !strings.Contains(string(data.Raw), "bob@example.test") {
		t.Fatal("downloaded result does not match the job")
	}
	mustStatus(t, h.API("POST", "/job-downloads", bob, map[string]any{"download_token": dl.Str("download_token")}), 404, "credential reuse")
	other := f.must(h.API("POST", "/jobs/"+id+"/downloads", bob, nil), 201, "second credential")
	h.Clock.Advance(10 * time.Minute)
	bob = f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/job-downloads", bob, map[string]any{"download_token": other.Str("download_token")}), 404, "expired credential")
}

// TestErrorContracts covers API-001, API-007 and API-008: custom APIs live
// under /api/v1 and answer with RFC 9457 problem details carrying a stable
// code and no internals; missing or invalid credentials get 401 with a
// challenge, an authenticated caller without permission gets 403, and
// another organization's resources are concealed with 404. The OAuth token
// endpoint keeps its standard error format.
func TestErrorContracts(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	problemOf := func(r *Resp, status int, code, what string) {
		t.Helper()
		mustStatus(t, r, status, what)
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
			t.Fatalf("%s: content type %q", what, ct)
		}
		if r.Str("code") != code || r.Get("status") != float64(status) || r.Str("title") == "" || r.Str("request_id") == "" {
			t.Fatalf("%s: problem details %s", what, r.Raw)
		}
		for _, leak := range []string{"goroutine", ".go:", "panic", "pgx", "SQLSTATE", "runtime."} {
			if strings.Contains(string(r.Raw), leak) {
				t.Fatalf("%s: internals in the error: %s", what, r.Raw)
			}
		}
	}
	none := h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users"})
	problemOf(none, 401, "unauthenticated", "no credentials")
	if !strings.HasPrefix(none.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("401 without a challenge: %v", none.Header)
	}
	problemOf(h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users", Token: "pa_at_not-a-real-token"}), 401, "unauthenticated", "invalid token")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	problemOf(h.API("PATCH", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["carol"], bob, map[string]any{"state": "suspended"}),
		403, "forbidden", "member without the permission")
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	problemOf(h.API("GET", "/organizations/"+f.Acme+"/members", carol, nil), 404, "not_found", "another organization concealed")
	problemOf(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "Not A Slug!"}), 422, "validation_failed", "validation")

	// Standard protocol endpoints keep their own error format.
	tok := h.TokenRequest(url.Values{"grant_type": {"password"}, "username": {"bob"}, "password": {"x"}}, "web-bff", f.Clients["web"].Secret)
	if tok.Status != 400 || tok.Str("error") == "" || tok.Str("code") != "" || strings.HasPrefix(tok.Header.Get("Content-Type"), "application/problem+json") {
		t.Fatalf("token endpoint error format: %d %v %s", tok.Status, tok.Header.Get("Content-Type"), tok.Raw)
	}
}

// TestSecretStorageClasses covers DB-008: passwords are stored as Argon2id
// verifiers, bearer tokens as SHA-256 digests, one-time codes as keyed
// verifiers that a different key cannot check, and TOTP seeds as
// authenticated ciphertext; no raw secret is stored.
func TestSecretStorageClasses(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	pool := h.App.D.DB.Pool
	var verifier string
	if err := pool.QueryRow(ctx, `SELECT verifier FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, f.Users["bob"]).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(verifier, "$argon2id$") || strings.Contains(verifier, h.passwords["bob@example.test"]) {
		t.Fatalf("password verifier class: %s", verifier)
	}

	tokens := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens
	rt := tokens.Str("refresh_token")
	var digested, raw int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE token_digest=$1`, secret.Digest(rt)).Scan(&digested)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE token_digest=$1`, rt).Scan(&raw)
	if digested != 1 || raw != 0 {
		t.Fatalf("refresh token storage: digest rows %d, raw rows %d", digested, raw)
	}

	tok := f.AccountToken("bob").Tokens.Str("access_token")
	added := f.must(h.API("POST", "/me/identifiers", tok, map[string]any{"type": "email", "value": "bob.alt@example.test"}), 201, "identifier")
	chID := f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": added.Str("id")}), 201, "challenge").Str("challenge_id")
	code := emailCode(h, "bob.alt@example.test")
	var purpose, codeVerifier string
	var version int
	if err := pool.QueryRow(ctx, `SELECT purpose, verifier, key_version FROM challenges WHERE id=$1`, chID).Scan(&purpose, &codeVerifier, &version); err != nil {
		t.Fatal(err)
	}
	if code == "" || strings.Contains(codeVerifier, code) || codeVerifier == secret.Digest(code) {
		t.Fatalf("one-time code stored raw or as a plain hash: %q", codeVerifier)
	}
	if !h.App.D.Keys.VerifyMAC(keys.PurposeOTP, version, codeVerifier, "challenge", chID, purpose, code) ||
		keys.NewRandom().VerifyMAC(keys.PurposeOTP, version, codeVerifier, "challenge", chID, purpose, code) {
		t.Fatal("one-time code verifier is not keyed")
	}

	f.EnrollTOTP("alice")
	seed := h.Seed("alice@example.test")
	var ct []byte
	var plainVerifier *string
	if err := pool.QueryRow(ctx, `SELECT secret_ciphertext, verifier FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'`,
		f.Users["alice"]).Scan(&ct, &plainVerifier); err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || plainVerifier != nil || strings.Contains(string(ct), seed) {
		t.Fatal("TOTP seed not stored as ciphertext")
	}
	if _, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("tampered-binding")); err == nil {
		t.Fatal("TOTP ciphertext is not bound to its owner")
	}
}

// TestConsentAndTermsAreSeparateRecords covers PRV-007: accepting the realm's
// terms and consenting to an application's scopes are separate records with
// separate lifecycles. New terms ask for terms again without asking for
// consent; revoking the consent leaves the terms acceptance in place and asks
// only for consent. (The identity provider keeps no marketing preferences.)
func TestConsentAndTermsAreSeparateRecords(t *testing.T) {
	f := NewFixture(t, func(p *realmPolicy) { p.Registration.TermsVersion = "2026-10" })
	h := f.H
	ctx := context.Background()
	login := func() {
		t.Helper()
		lr := h.Login(LoginOpts{ClientID: "partner-app", RedirectURI: "https://partner.test/cb", Scope: "orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
		mustStatus(t, lr.Tokens, 200, "partner login")
	}
	counts := func() (terms, consents int) {
		t.Helper()
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM terms_acceptances WHERE user_id=$1 AND document='terms'`, f.Users["bob"]).Scan(&terms)
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='consent.granted' AND subject_id=$1`, f.Users["bob"]).Scan(&consents)
		return
	}
	terms0, _ := counts()
	login()
	terms1, consents1 := counts()
	if consents1 != 1 {
		t.Fatalf("third-party consent not recorded: %d", consents1)
	}
	var scopes []string
	var termsVersion *string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT scopes, terms_version FROM consents WHERE user_id=$1 AND client_ref=$2 AND revoked_at IS NULL`,
		f.Users["bob"], f.Clients["partner"].Ref).Scan(&scopes, &termsVersion); err != nil {
		t.Fatal(err)
	}
	if strings.Join(scopes, " ") != "orders:read" || termsVersion != nil {
		t.Fatalf("consent record mixes in other purposes: scopes=%v terms=%v", scopes, termsVersion)
	}

	mustStatus(t, f.SetPolicy(func(p *realmPolicy) { p.Registration.TermsVersion = "2026-11" }), 200, "new terms")
	login()
	terms2, consents2 := counts()
	if terms2 != terms1+1 || consents2 != consents1 {
		t.Fatalf("new terms: terms %d->%d, consents %d->%d", terms1, terms2, consents1, consents2)
	}

	bob := f.AccountToken("bob").Tokens.Str("access_token")
	for _, it := range f.must(h.API("GET", "/me/consents", bob, nil), 200, "consents").Get("items").([]any) {
		mustStatus(t, h.API("DELETE", "/me/consents/"+it.(map[string]any)["id"].(string), bob, nil), 204, "revoke consent")
	}
	terms3, _ := counts()
	if terms3 != terms2 {
		t.Fatal("revoking consent touched terms acceptance")
	}
	login()
	terms4, consents4 := counts()
	if consents4 != consents2+1 || terms4 != terms3 || terms0 > terms1 {
		t.Fatalf("after revocation: terms %d->%d, consents %d->%d", terms3, terms4, consents2, consents4)
	}
}
