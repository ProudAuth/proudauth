package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/machine"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/realm"
)

// patCredential is a minted automation credential as a test sees it.
type patCredential struct{ id, name, prefix, token string }

// patOrg is the organization a user's test tokens are bound to: the Orders
// API requires one.
func patOrg(f *Fixture, user string) string {
	if _, ok := f.MemberAcme[user]; ok {
		return f.Acme
	}
	return f.Globex
}

// mintPAT mints a personal access token for the Orders API from a fresh
// account session of user.
func mintPAT(f *Fixture, user, name string) patCredential {
	f.H.t.Helper()
	acct := f.AccountToken(user).Tokens.Str("access_token")
	r := f.must(f.H.API("POST", "/me/personal-tokens", acct, map[string]any{"name": name, "audience": f.OrdersAud,
		"scopes": []string{"orders:read"}, "organization_id": patOrg(f, user), "ttl_days": 30}), 201, "mint "+name)
	return patCredential{id: r.Str("credential.id"), name: name, prefix: r.Str("credential.display_prefix"), token: r.Str("token")}
}

// TestPersonalAccessTokensEndWithAccountRecovery covers CRED-008, MCH-007
// and CRED-007 (owner decision 11 of 0.2.0-alpha.6): a password reset,
// marking the password compromised and assisted recovery each revoke the
// user's personal access tokens and user-owned API keys in their own
// transaction (state revoked, the flow's revoke_reason, inactive at
// introspection), audit each as automation_credential.revoked with the flow's
// reason, and name them (name and display prefix) in a credentials_revoked
// notice. Another user's token stays active, and a token minted after the
// recovery works.
func TestPersonalAccessTokensEndWithAccountRecovery(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	rs := f.Clients["orders-rs"]
	f.CreateUser("dave")
	f.MemberAcme["dave"] = f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["dave"],
		"role_ids": []string{f.Roles["member"]}}), 201, "member dave").Str("id")
	active := func(tok string) bool {
		t.Helper()
		return h.Introspect("orders-rs", rs.Secret, tok).Get("active") == true
	}
	bystander := mintPAT(f, "alice", "alice-cli")

	cases := []struct {
		user, reason, actorType, actorID string
		// recover runs the flow and returns the password to sign in with
		// afterwards.
		recover func(t *testing.T) string
	}{
		{"bob", "password_reset", "user", f.Users["bob"], func(t *testing.T) string {
			h.Clock.Advance(2 * time.Second)
			req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"}), 202, "request reset")
			code := CodeFrom(h.Mail("bob@example.test", "password_reset"))
			pw := "bob resets after a breach 2026"
			f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code,
				"new_password": pw}), 200, "complete reset")
			return pw
		}},
		{"carol", "credential_compromised", "user", f.Users["admin"], func(t *testing.T) string {
			f.must(f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/credentials/password/compromised",
				map[string]any{"reason": "BREACH_CORPUS_MATCH"}), 204, "mark compromised")
			h.Clock.Advance(2 * time.Second)
			req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "carol@example.test"}), 202, "request reset")
			code := CodeFrom(h.Mail("carol@example.test", "password_reset"))
			pw := "carol recovers from a breach 2026"
			f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code,
				"new_password": pw}), 200, "reset after compromise")
			return pw
		}},
		{"dave", "assisted_recovery", "user", f.Users["admin"], func(t *testing.T) string {
			r := f.must(f.AdminAPI("POST", "/users/"+f.Users["dave"]+"/recovery-requests", map[string]any{
				"reason": "lost access, identity verified in person", "evidence_reference": "ticket 7001"}), 202, "assisted recovery")
			if r.Str("status") != "recovery_started" {
				t.Fatalf("assisted recovery did not run at once: %s", r.Raw)
			}
			setup := CodeFrom(h.Mail("dave@example.test", "account_setup"))
			pw := "dave sets a fresh passphrase 2026"
			f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": setup, "password": pw}), 200, "setup after recovery")
			return pw
		}},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			userID := f.Users[c.user]
			pat := mintPAT(f, c.user, c.user+"-cli")
			// An API key the user owns (owner_type user; imports create them).
			plain, key, err := h.App.Machine.CreateCredential(ctx, h.Realm.ID, "api_key", "user", userID, machine.CredentialInput{
				Name: c.user + "-sync", Audience: f.OrdersAud, Scopes: []string{"orders:read"}, OrganizationID: patOrg(f, c.user), TTLDays: 30},
				audit.Ref{Type: "user", ID: userID})
			if err != nil {
				t.Fatal(err)
			}
			creds := []patCredential{pat, {id: key.ID, name: key.Name, prefix: key.DisplayPrefix, token: plain}}
			for _, cr := range creds {
				if !active(cr.token) {
					t.Fatalf("%s inactive before the recovery", cr.name)
				}
			}
			h.Clock.Advance(2 * time.Second)
			pw := c.recover(t)

			notice := h.Mail(c.user+"@example.test", "credentials_revoked")
			for _, cr := range creds {
				var state, reason string
				_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, coalesce(revoke_reason,'') FROM automation_credentials WHERE id=$1`, cr.id).Scan(&state, &reason)
				if state != "revoked" || reason != c.reason {
					t.Fatalf("%s after %s: state %q, revoke_reason %q", cr.name, c.reason, state, reason)
				}
				if in := h.Introspect("orders-rs", rs.Secret, cr.token); in.Get("active") != false {
					t.Fatalf("%s still active at introspection after %s: %s", cr.name, c.reason, in.Raw)
				}
				if want := cr.name + " (" + cr.prefix + ")"; cr.prefix == "" || !strings.Contains(notice, want) {
					t.Fatalf("the credentials_revoked notice does not name %q:\n%s", want, notice)
				}
				var audited int
				_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='automation_credential.revoked' AND target_id=$1
					AND subject_id=$2 AND reason_code=$3 AND actor_type=$4 AND actor_id=$5`, cr.id, userID, c.reason, c.actorType, c.actorID).Scan(&audited)
				if audited != 1 {
					t.Fatalf("%s revocation audited %d times with reason %s and actor %s", cr.name, audited, c.reason, c.actorID)
				}
			}
			if strings.Contains(notice, bystander.prefix) {
				t.Fatalf("the notice names another user's token:\n%s", notice)
			}
			if !active(bystander.token) {
				t.Fatalf("%s ended another user's personal access token", c.reason)
			}
			// The owner signs in again and mints a token that works.
			h.SetPassword(c.user+"@example.test", pw)
			h.Clock.Advance(time.Second)
			if fresh := mintPAT(f, c.user, c.user+"-new"); !active(fresh.token) {
				t.Fatalf("a token minted after %s is inactive", c.reason)
			}
		})
	}
}

// TestPersonalAccessTokenMintingNeedsFactorProof covers MCH-006 and MFA-006
// (owner decision 11-b of 0.2.0-alpha.6): on an account with an enrolled
// second factor, POST /me/personal-tokens refuses a session that did not
// prove it (one created before the factor, or one that skipped MFA through a
// remembered device) with 403 step_up_required and a reauthenticate
// obligation, and mints nothing; a session that completed MFA mints. An
// account without a second factor keeps minting from a password session.
func TestPersonalAccessTokenMintingNeedsFactorProof(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Login.RememberDevices = true })
	h := f.H
	ctx := context.Background()
	body := map[string]any{"name": "ci", "audience": f.OrdersAud, "scopes": []string{"orders:read"}, "organization_id": f.Acme, "ttl_days": 30}
	f.must(h.API("POST", "/me/personal-tokens", f.AccountToken("alice").Tokens.Str("access_token"), body), 201,
		"password session on an account without a second factor")

	before := f.AccountToken("bob").Tokens.Str("access_token") // password only, before the factor
	f.EnrollTOTP("bob")
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	step := func(tx, cont, path string, body any, device string) *Resp {
		t.Helper()
		hdr := map[string]string{"X-Transaction-Token": cont}
		if device != "" {
			hdr["X-Remembered-Device"] = device
		}
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/" + path, JSON: body, Headers: hdr})
	}
	start, _, cont := h.StartTx(cli)
	tx := start.Str("transaction_id")
	step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}, "")
	step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}, "")
	mustStatus(t, step(tx, cont, "remember-device", map[string]any{"remember": true}, ""), 200, "remember the device")
	device := step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("bob@example.test")}, "").Str("one_time.remembered_device_token")
	if device == "" {
		t.Fatal("no remembered device")
	}
	start, verifier, cont := h.StartTx(cli)
	tx = start.Str("transaction_id")
	step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}, device)
	st := step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}, device)
	u, _ := url.Parse(st.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("remembered device did not skip the MFA prompt: %s", st.Raw)
	}
	remembered := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {h.Realm.Issuer + "/account"}}, "", "")
	mustStatus(t, remembered, 200, "token through the remembered device")

	for name, tok := range map[string]string{"session older than the factor": before, "remembered-device session": remembered.Str("access_token")} {
		r := h.API("POST", "/me/personal-tokens", tok, body)
		if r.Status != 403 || r.Str("code") != "step_up_required" || !strings.Contains(string(r.Raw), `"required_profile":"mfa"`) {
			t.Fatalf("%s minted a personal access token without proving the second factor: %d %s", name, r.Status, r.Raw)
		}
	}
	var minted int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM automation_credentials WHERE owner_type='user' AND owner_id=$1`, f.Users["bob"]).Scan(&minted)
	if minted != 0 {
		t.Fatalf("refused requests minted %d credentials", minted)
	}
	mfa := f.AccountToken("bob").Tokens.Str("access_token")
	f.must(h.API("POST", "/me/personal-tokens", mfa, body), 201, "MFA session")
}

// TestPersonalAccessTokenIntrospectionHonoursUserRevocation covers CRED-008,
// MCH-007 and SES-005 (owner decision 11 of 0.2.0-alpha.6, defence in
// depth): introspection treats a user-owned credential created before the
// owner's latest password-reset, compromise or assisted-recovery revocation
// record as inactive even while its row still says active, and keeps a
// credential minted afterwards active. "Log out everywhere" ends sessions and
// grants but not personal access tokens.
func TestPersonalAccessTokenIntrospectionHonoursUserRevocation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	rs := f.Clients["orders-rs"]
	bob := f.Users["bob"]
	active := func(tok string) bool {
		t.Helper()
		return h.Introspect("orders-rs", rs.Secret, tok).Get("active") == true
	}
	older := mintPAT(f, "bob", "older")
	if !active(older.token) {
		t.Fatal("new personal access token inactive")
	}

	h.Clock.Advance(2 * time.Second)
	mustStatus(t, h.API("POST", "/me/sessions/revoke-all", f.AccountToken("bob").Tokens.Str("access_token"), nil), 200, "log out everywhere")
	if !active(older.token) {
		t.Fatal("log out everywhere ended a personal access token")
	}

	// A compromise revocation whose credential update was missed (a
	// concurrent mint, a restored row): only the user-level record exists.
	h.Clock.Advance(2 * time.Second)
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
		VALUES ($1,$2,'user',$3,'credential_compromised',$4)`, ids.New(ids.Revocation), h.Realm.ID, bob, h.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	if in := h.Introspect("orders-rs", rs.Secret, older.token); in.Get("active") != false {
		t.Fatalf("a token created before the owner's compromise revocation is active: %s", in.Raw)
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM automation_credentials WHERE id=$1`, older.id).Scan(&state)
	if state != "active" {
		t.Fatalf("the row changed (%q); the check under test is introspection's", state)
	}

	h.Clock.Advance(2 * time.Second)
	if newer := mintPAT(f, "bob", "newer"); !active(newer.token) {
		t.Fatal("a token minted after the revocation is inactive")
	}
}
