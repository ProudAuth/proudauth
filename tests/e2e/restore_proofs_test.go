package e2e

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/restore"
)

// TestRestoreProofConsumption covers TEST-060 for proof consumption and the
// readiness gate (OPS-014): a backup taken before refresh tokens were rotated
// or revoked, recovery codes consumed or replaced, an HOTP counter advanced,
// initial access tokens used up or revoked, a registration access token
// rotated, a password reset completed, an invitation accepted, a client
// secret and a personal access token revoked and a membership suspended is
// restored; the restored database, marked with restore.Begin (identity-cli
// restore-begin), is not ready until reconciliation has run, and afterwards
// none of those consumed or revoked proofs works on the restored instance
// while the factors themselves still do. Outstanding one-time proofs of the
// restore are ended wholesale.
func TestRestoreProofConsumption(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	signedIn := func(lr *LoginResult) bool { return lr.Tokens != nil && lr.Tokens.Status == 200 }
	accountLogin := func(hh *Harness, ident string, mut func(*LoginOpts)) *LoginResult {
		t.Helper()
		o := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: ident, ExpectFail: true}
		if mut != nil {
			mut(&o)
		}
		return hh.Login(o)
	}

	// ---- State before the backup. ----
	// Refresh families: bob's is rotated after the backup, alice's revoked.
	bobRefresh := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	aliceRefresh := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	if bobRefresh == "" || aliceRefresh == "" {
		t.Fatal("no refresh tokens issued")
	}
	// HOTP with recovery codes for dave.
	f.must(f.SetPolicy(func(p *realm.Policy) {
		p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, "hotp")
		p.MFA.HOTP = realm.HOTPPolicy{LookAhead: 5, ResyncWindow: 50}
	}), 200, "allow hotp")
	f.CreateUser("dave")
	const dave = "dave@example.test"
	daveTok := f.AccountToken("dave").Tokens.Str("access_token")
	seed := f.must(h.API("POST", "/me/hotp/enroll", daveTok, nil), 201, "enroll hotp").Str("secret")
	hotp := func(c int64) string {
		t.Helper()
		s, err := credential.HOTPCode(seed, c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	act := f.must(h.API("POST", "/me/hotp/activate", daveTok, map[string]any{"code": hotp(1)}), 200, "activate hotp")
	var recovery []string
	for _, c := range act.Get("recovery_codes").([]any) {
		recovery = append(recovery, c.(string))
	}
	if len(recovery) < 3 {
		t.Fatalf("recovery codes: %s", act.Raw)
	}
	// Dynamic registration: an initial access token for two clients (one used
	// before the backup), another one revoked after it.
	f.must(f.SetPolicy(func(p *realm.Policy) { p.ClientRegistration.Enabled = true }), 200, "enable registration")
	newIAT := func(uses int) *Resp {
		return f.must(f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"description": "restore drill", "max_uses": uses,
			"allowed_scopes": []map[string]any{{"resource_id": f.Orders, "scopes": []string{"orders:read"}}}}), 201, "initial access token")
	}
	iat := newIAT(2).Str("initial_access_token")
	iat2 := newIAT(5)
	register := func(hh *Harness, token, name string) *Resp {
		return hh.Do(Req{Method: "POST", Path: "/realms/main/oauth/register", Token: token, JSON: map[string]any{"redirect_uris": []string{"https://dcr.test/cb"},
			"client_name": name, "scope": "openid orders:read", "grant_types": []string{"authorization_code", "refresh_token"}}})
	}
	manage := func(hh *Harness, method, id, tok string, body any) *Resp {
		return hh.Do(Req{Method: method, Path: "/realms/main/oauth/register/" + id, Token: tok, JSON: body})
	}
	regX := register(h, iat, "Client X")
	mustStatus(t, regX, 201, "register client X")
	clientX, rat1 := regX.Str("client_id"), regX.Str("registration_access_token")
	// A password reset requested but completed only after the backup.
	const carol = "carol@example.test"
	reset := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": carol}), 202, "request reset")
	resetID, resetCode := reset.Str("reset_id"), CodeFrom(h.Mail(carol, "password_reset"))
	if resetID == "" || resetCode == "" {
		t.Fatalf("no reset code: %s", reset.Raw)
	}
	// An invitation accepted after the backup.
	f.CreateUser("erin")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "erin@example.test"}), 201, "invite erin")
	invitation := invitationFromMail(h.Mail("erin@example.test", "invitation"))
	// A second client secret and a personal access token, revoked after the backup.
	batch := f.Clients["batch"]
	extra := f.must(f.AdminAPI("POST", "/clients/"+batch.Ref+"/credentials", map[string]any{}), 201, "second secret")
	batch2 := Client{Ref: batch.Ref, ID: batch.ID, Secret: extra.Str("client_secret")}
	mustStatus(t, f.MachineToken(batch2, f.BillingAud, "billing:read", f.Acme), 200, "second secret works")
	bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
	pat := f.must(h.API("POST", "/me/personal-tokens", bobAcct, map[string]any{"name": "cli", "audience": f.OrdersAud, "scopes": []string{"orders:read"},
		"organization_id": f.Acme, "ttl_days": 30}), 201, "personal access token")

	// ---- The backup. The fake clock may run ahead of the database's own
	// clock (some columns default to now()), so the log starts at the
	// earlier of both. ----
	since := h.Clock.Now()
	if real := time.Now(); real.Before(since) {
		since = real
	}
	since = since.Add(-time.Second)
	backup := snapshotDatabase(t, h, "proofs")
	// The operator marks the restored database before any server starts on it.
	marker, err := restore.Begin(ctx, backup.Pool, "local:restore-drill", h.Clock.Now())
	if err != nil || marker == nil {
		t.Fatalf("restore-begin: %v %v", marker, err)
	}
	if again, err := restore.Begin(ctx, backup.Pool, "local:someone-else", h.Clock.Now().Add(time.Minute)); err != nil || !again.Since.Equal(marker.Since) || again.By != "local:restore-drill" {
		t.Fatalf("a second restore-begin replaced the marker: %v %v", again, err)
	}

	// ---- Proofs consumed and credentials revoked after the backup. ----
	rot := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {bobRefresh}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, rot, 200, "rotate bob's refresh token")
	if rot.Str("refresh_token") == bobRefresh {
		t.Fatal("refresh token not rotated")
	}
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {aliceRefresh}, "token_type_hint": {"refresh_token"}},
		Basic: [2]string{"web-bff", f.Clients["web"].Secret}}), 200, "revoke alice's refresh token")
	mfa := accountLogin(h, dave, func(o *LoginOpts) { o.HOTPCode = hotp(2) })
	if !signedIn(mfa) {
		t.Fatalf("hotp sign-in: %s", mfa.State.Raw)
	}
	if !signedIn(accountLogin(h, dave, func(o *LoginOpts) { o.UseRecovery = recovery[0] })) {
		t.Fatal("recovery-code sign-in failed")
	}
	f.must(h.API("POST", "/me/recovery-codes/regenerate", mfa.Tokens.Str("access_token"), nil), 200, "regenerate recovery codes")
	mustStatus(t, register(h, iat, "Client Y"), 201, "register client Y (exhausts the token)")
	upd := manage(h, "PUT", clientX, rat1, map[string]any{"client_id": clientX, "redirect_uris": []string{"https://dcr.test/cb"}, "client_name": "Client X v2",
		"scope": "openid orders:read", "grant_types": []string{"authorization_code", "refresh_token"}})
	mustStatus(t, upd, 200, "rotate the registration access token")
	mustStatus(t, f.AdminAPI("DELETE", "/client-registration-tokens/"+iat2.Str("token.id"), nil), 204, "revoke the second initial access token")
	h.Clock.Advance(2 * time.Second)
	f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": resetID, "code": resetCode,
		"new_password": "Carol-Resets-Her-Password-42"}), 200, "complete reset")
	mustStatus(t, h.API("POST", "/invitations/accept", f.AccountToken("erin").Tokens.Str("access_token"), map[string]any{"invitation": invitation}), 200, "erin accepts")
	mustStatus(t, f.AdminAPI("DELETE", "/clients/"+batch.Ref+"/credentials/"+extra.Str("credential.id"), nil), 204, "revoke the second secret")
	mustStatus(t, h.API("DELETE", "/me/personal-tokens/"+pat.Str("credential.id"), bobAcct, nil), 204, "revoke the personal access token")
	f.must(f.AdminAPI("PATCH", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["carol"], map[string]any{"state": "suspended"}), 200, "suspend carol in globex")

	var log bytes.Buffer
	if _, err := restore.Export(ctx, h.App.D.DB, since, &log); err != nil {
		t.Fatal(err)
	}

	// ---- The restored instance: not ready while the marker is set. A
	// deployment never marked is unaffected. ----
	restored := replica(t, h, backup, h.App.D.Keys)
	if st, body := probe(restored, "/health/ready"); st != 503 || body["reason"] != "restore_pending" {
		t.Fatalf("restored database reported ready before reconciliation: %d %v", st, body)
	}
	if st, body := probe(h, "/health/ready"); st != 200 {
		t.Fatalf("an unmarked deployment is not ready: %d %v", st, body)
	}

	// Without reconciliation every consumed proof would be live again.
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := backup.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, pre := range []struct{ what, sql, arg string }{
		{"rotated refresh token current", `SELECT count(*) FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id
			WHERE t.token_digest=$1 AND t.consumed_at IS NULL AND f.state='active'`, secret.Digest(bobRefresh)},
		{"revoked refresh family active", `SELECT count(*) FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id
			WHERE t.token_digest=$1 AND f.state='active'`, secret.Digest(aliceRefresh)},
		{"recovery codes active", `SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active'`, f.Users["dave"]},
		{"hotp counter behind", `SELECT count(*) FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active' AND counter=2`, f.Users["dave"]},
		{"initial access token usable", `SELECT count(*) FROM client_registration_tokens WHERE kind='initial' AND state='active' AND uses=1 AND token_digest=$1`, secret.Digest(iat)},
		{"reset code outstanding", `SELECT count(*) FROM challenges WHERE id=$1 AND consumed_at IS NULL AND superseded_at IS NULL`, resetID},
		{"invitation pending", `SELECT count(*) FROM invitations WHERE state IN ('created','pending_delivery','pending_acceptance') AND target_email_canonical=$1`, "erin@example.test"},
	} {
		if count(pre.sql, pre.arg) == 0 {
			t.Fatalf("precondition: the backup should have the %s", pre.what)
		}
	}

	// ---- Reconcile, then traffic may resume. ----
	rep, err := restore.Reconcile(ctx, backup, bytes.NewReader(log.Bytes()), restore.Options{}, h.Clock.Now(), h.App.D.Audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"refresh_rotated", "refresh_family_revoked", "grant_revoked", "recovery_code_consumed", "recovery_codes_replaced",
		"hotp_counter", "initial_access_token", "registration_token_rotated", "password_changed", "invitation_consumed",
		"client_credential_revoked", "automation_credential_revoked", "membership_state"} {
		if rep.Applied[kind] == 0 {
			t.Errorf("no %s record reconciled: %+v", kind, rep.Applied)
		}
	}
	if !rep.RestoreMarkerCleared || rep.ProofsInvalidated["challenges"] == 0 {
		t.Fatalf("report: %+v", rep)
	}
	// Outstanding one-time proofs of the restore are gone.
	if n := count(`SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND superseded_at IS NULL AND expires_at > $1`, h.Clock.Now()); n != 0 {
		t.Fatalf("%d one-time challenges still outstanding", n)
	}
	if n := count(`SELECT count(*) FROM auth_transactions WHERE status='pending'`); n != 0 {
		t.Fatalf("%d sign-in transactions still pending", n)
	}
	if st, body := probe(restored, "/health/ready"); st != 200 {
		t.Fatalf("reconciled database not ready: %d %v", st, body)
	}
	var evidence int
	_ = backup.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='operations.restore.reconciled' AND metadata->>'restore_marker_cleared'='true'`).Scan(&evidence)
	if evidence != 1 {
		t.Fatal("reconciliation not audited with its marker")
	}

	// ---- Nothing consumed or revoked after the backup works again. ----
	web := f.Clients["web"]
	if r := restored.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {bobRefresh}}, "web-bff", web.Secret); r.Status == 200 {
		t.Fatal("a refresh token rotated after the backup was redeemed again")
	}
	if r := restored.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {aliceRefresh}}, "web-bff", web.Secret); r.Status == 200 {
		t.Fatal("a refresh token revoked after the backup was redeemed")
	}
	// /oauth/revoke ended both the family and the grant; each record alone
	// re-applies the revocation.
	if n := count(`SELECT count(*) FROM authorization_grants g JOIN refresh_families f ON f.grant_id=g.id JOIN refresh_tokens t ON t.family_id=f.id
		WHERE t.token_digest=$1 AND g.state='revoked' AND f.state='revoked'`, secret.Digest(aliceRefresh)); n != 1 {
		t.Fatal("grant or refresh family revoked after the backup is active again")
	}
	// Bob's restored family is revoked, but his session (no password change)
	// is not: he signs in again only for the client whose token rotated.
	if n := count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, f.Users["bob"]); n == 0 {
		t.Fatal("reconciliation revoked sessions it had no reason to")
	}
	if signedIn(accountLogin(restored, dave, func(o *LoginOpts) { o.HOTPCode = hotp(2) })) {
		t.Fatal("an HOTP code used after the backup was accepted again")
	}
	if signedIn(accountLogin(restored, dave, func(o *LoginOpts) { o.UseRecovery = recovery[0] })) {
		t.Fatal("a recovery code consumed after the backup was accepted again")
	}
	if signedIn(accountLogin(restored, dave, func(o *LoginOpts) { o.UseRecovery = recovery[1] })) {
		t.Fatal("a recovery code replaced after the backup was accepted")
	}
	if n := count(`SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='consumed'`, f.Users["dave"]); n != 1 {
		t.Fatalf("%d consumed recovery codes after reconciliation", n)
	}
	// The factor itself still works with the next code.
	if !signedIn(accountLogin(restored, dave, func(o *LoginOpts) { o.HOTPCode = hotp(3) })) {
		t.Fatal("the next HOTP code is refused after reconciliation")
	}
	if r := register(restored, iat, "Client Z"); r.Status != 401 {
		t.Fatalf("an initial access token used up after the backup registered again: %d %s", r.Status, r.Raw)
	}
	if r := register(restored, iat2.Str("initial_access_token"), "Client Z"); r.Status != 401 {
		t.Fatalf("an initial access token revoked after the backup registered: %d %s", r.Status, r.Raw)
	}
	if r := manage(restored, "GET", clientX, rat1, nil); r.Status != 401 {
		t.Fatalf("a registration access token rotated after the backup works: %d %s", r.Status, r.Raw)
	}
	if r := restored.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": resetID, "code": resetCode,
		"new_password": "Someone-Else-Replays-It-42"}); r.Status == 200 {
		t.Fatal("a password-reset code consumed after the backup was accepted again")
	}
	if r := restored.API("POST", "/invitations/inspect", "", map[string]any{"invitation": invitation}); r.Status == 200 {
		t.Fatalf("an invitation accepted after the backup is open again: %s", r.Raw)
	}
	if r := f.MachineToken(batch2, f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
		t.Fatal("precondition: the revoked secret fails on the live instance")
	}
	rf := *f
	rf.H = restored
	if r := rf.MachineToken(batch2, f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
		t.Fatal("a client secret revoked after the backup works again")
	}
	if in := restored.Introspect("orders-rs", f.Clients["orders-rs"].Secret, pat.Str("token")); in.Get("active") != false {
		t.Fatalf("a personal access token revoked after the backup is active: %s", in.Raw)
	}
	if n := count(`SELECT count(*) FROM memberships WHERE id=$1 AND state='suspended'`, f.MemberGlobex["carol"]); n != 1 {
		t.Fatal("membership suspension not re-applied")
	}
	// Running it again changes nothing and the instance stays ready.
	again, err := restore.Reconcile(ctx, backup, bytes.NewReader(log.Bytes()), restore.Options{}, h.Clock.Now(), nil)
	if err != nil || again.RestoreMarkerCleared {
		t.Fatalf("second reconciliation: %+v %v", again, err)
	}
	if st, _ := probe(restored, "/health/ready"); st != 200 {
		t.Fatal("not ready after a repeated reconciliation")
	}
}
