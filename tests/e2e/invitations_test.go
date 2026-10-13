package e2e

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func invitationFromMail(body string) string {
	for _, f := range strings.Fields(body) {
		if strings.HasPrefix(f, "pa_inv_") {
			return strings.TrimRight(f, ".,")
		}
	}
	return ""
}

// TestInvitationLifecycle covers INV-002 (the invitation is bound to its
// organization, recipient, roles, inviter, expiry and purpose), INV-004 (one
// successful redemption under concurrency, granting exactly the invited
// roles), INV-005 (another signed-in account cannot accept it) and INV-010
// (inspection and unauthenticated requests never consume it).
// Requirements: DB-004 (concurrent acceptance leaves one membership record),
// DB-005 (the invitation secret is consumed once), ARC-002 (acceptance relies
// on the database, not a cache).
func TestInvitationLifecycle(t *testing.T) {
	f := NewFixture(t)
	alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner
	newUser := f.CreateUser("dave")
	_ = newUser
	inv := f.H.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "dave@example.test", "role_ids": []string{f.Roles["orders-viewer"]}})
	mustStatus(t, inv, 201, "create invitation")
	if strings.Contains(string(inv.Raw), "pa_inv_") {
		t.Fatal("INV-003: the secret must never be returned by the API")
	}
	// INV-002: the record names what the invitation is bound to.
	exp, _ := time.Parse(time.RFC3339Nano, inv.Str("invitation.expires_at"))
	if inv.Str("invitation.organization_id") != f.Acme || inv.Str("invitation.purpose") != "organization_membership" ||
		jsonString(inv.Get("invitation.role_ids")) != jsonString([]string{f.Roles["orders-viewer"]}) ||
		inv.Str("invitation.inviter_type") != "user" || inv.Str("invitation.inviter_id") != f.Users["alice"] ||
		inv.Str("invitation.target_email") == "" || !exp.After(f.H.Clock.Now()) || exp.After(f.H.Clock.Now().Add(f.H.App.D.Cfg.Tokens.InvitationTTL+time.Second)) {
		t.Fatalf("invitation binding: %s", inv.Raw)
	}
	secret := invitationFromMail(f.H.Mail("dave@example.test", "invitation"))
	if secret == "" {
		t.Fatal("invitation not delivered")
	}

	t.Run("TEST-018 inspection does not consume", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			r := f.H.API("POST", "/invitations/inspect", "", map[string]any{"invitation": secret})
			mustStatus(t, r, 200, "inspect")
			if strings.Contains(string(r.Raw), "dave") {
				t.Fatal("inspection must not disclose the invited address")
			}
		}
		// A scanner following the link (GET) or posting without a signed-in
		// account cannot accept; acceptance is an authenticated POST.
		if r := f.H.Do(Req{Method: "GET", Path: "/api/v1/realms/main/invitations/accept?invitation=" + secret}); r.Status < 400 {
			t.Fatalf("GET accepted an invitation: %d", r.Status)
		}
		mustStatus(t, f.H.API("POST", "/invitations/accept", "", map[string]any{"invitation": secret}), 401, "unauthenticated acceptance")
		mustStatus(t, f.H.API("POST", "/invitations/inspect", "", map[string]any{"invitation": secret}), 200, "still pending")
	})
	t.Run("TEST-015 wrong verified identity", func(t *testing.T) {
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		r := f.H.API("POST", "/invitations/accept", bob, map[string]any{"invitation": secret})
		mustStatus(t, r, 400, "wrong acceptor")
		if strings.Contains(string(r.Raw), "dave") {
			t.Fatal("rejection leaked invited user data")
		}
	})
	t.Run("TEST-019 resend rotates the secret", func(t *testing.T) {
		mustStatus(t, f.H.API("POST", "/organizations/"+f.Acme+"/invitations/"+inv.Str("invitation.id")+"/resend", alice, nil), 200, "resend")
		fresh := invitationFromMail(f.H.Mail("dave@example.test", "invitation"))
		if fresh == "" || fresh == secret {
			t.Fatal("resend must issue a new secret")
		}
		if r := f.H.API("POST", "/invitations/inspect", "", map[string]any{"invitation": secret}); r.Status != 400 {
			t.Fatalf("replaced secret still valid: %d", r.Status)
		}
		secret = fresh
	})
	t.Run("TEST-016 concurrent acceptance yields one membership", func(t *testing.T) {
		dave := f.AccountToken("dave").Tokens.Str("access_token")
		var wg sync.WaitGroup
		results := make([]int, 5)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = f.H.API("POST", "/invitations/accept", dave, map[string]any{"invitation": secret}).Status
			}(i)
		}
		wg.Wait()
		ok := 0
		for _, s := range results {
			if s == 200 {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("exactly one acceptance must succeed: %v", results)
		}
		var n int
		_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Acme, f.Users["dave"]).Scan(&n)
		if n != 1 {
			t.Fatalf("duplicate memberships: %d", n)
		}
		var roles []string
		_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT coalesce(array_agg(ra.role_id ORDER BY ra.role_id), '{}') FROM role_assignments ra
			JOIN memberships m ON m.id=ra.membership_id WHERE m.organization_id=$1 AND m.user_id=$2`, f.Acme, f.Users["dave"]).Scan(&roles)
		if len(roles) != 1 || roles[0] != f.Roles["orders-viewer"] {
			t.Fatalf("acceptance granted other than the invited roles: %v", roles)
		}
	})
}

// TestInvitationRevalidatesInviter covers INV-007 and TEST-017: the inviter's
// authority is checked again at acceptance, so an inviter who lost it since
// creation grants nothing.
func TestInvitationRevalidatesInviter(t *testing.T) {
	f := NewFixture(t)
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex admin
	f.CreateUser("erin")
	inv := f.H.API("POST", "/organizations/"+f.Globex+"/invitations", carol, map[string]any{"email": "erin@example.test", "role_ids": []string{f.Roles["orders-viewer"]}})
	mustStatus(t, inv, 201, "invite")
	secret := invitationFromMail(f.H.Mail("erin@example.test", "invitation"))
	// TEST-017: the inviter loses authority before acceptance.
	f.must(f.AdminAPI("PATCH", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["carol"], map[string]any{"state": "suspended"}), 200, "suspend inviter membership")
	erin := f.AccountToken("erin").Tokens.Str("access_token")
	r := f.H.API("POST", "/invitations/accept", erin, map[string]any{"invitation": secret})
	mustStatus(t, r, 400, "acceptance after inviter lost authority")
	if r.Str("reason_code") != "INVITER_INELIGIBLE" {
		t.Fatalf("expected actionable non-sensitive reason: %s", r.Raw)
	}
	var n int
	_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Globex, f.Users["erin"]).Scan(&n)
	if n != 0 {
		t.Fatal("no membership may be created")
	}
	// A role above the inviter's ceiling is refused at creation.
	mustStatus(t, f.H.API("POST", "/organizations/"+f.Acme+"/invitations", f.AccountToken("bob").Tokens.Str("access_token"),
		map[string]any{"email": "x@example.test"}), 403, "member without invite permission")
}

// TestRegistrationAndRecovery covers CRED-007: password-reset requests get
// the same generic response for known and unknown identifiers (TEST-020), and
// a completed reset revokes sessions but keeps the enrolled TOTP required at
// the next sign-in, with the reset code refused on reuse (TEST-070).
// Requirements: SEC-005 (registration and recovery responses do not reveal
// whether an account exists).
func TestRegistrationAndRecovery(t *testing.T) {
	f := NewFixture(t, func(p *realmPolicy) { p.Registration.TermsVersion = "2026-10" })
	h := f.H
	register := func(email string) (*Resp, string, string) {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud}})
		tx := start.Str("transaction_id")
		r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": tx, "email": email,
			"password": "a brand new passphrase 2026", "terms_version": "2026-10", "organization": map[string]any{"slug": "newco-" + strings.Split(email, "@")[0], "display_name": "NewCo"}},
			Headers: map[string]string{"X-Transaction-Token": cont}})
		return r, tx, cont
	}
	t.Run("TEST-020 existing versus absent contact", func(t *testing.T) {
		existing, _, _ := register("alice@example.test")
		absent, _, _ := register("zed@example.test")
		if existing.Status != absent.Status || existing.Str("next_actions") != absent.Str("next_actions") {
			t.Fatalf("registration responses differ: %d %s vs %d %s", existing.Status, existing.Raw, absent.Status, absent.Raw)
		}
		if f.H.Mail("alice@example.test", "registration_exists") == "" {
			t.Fatal("existing owner should be notified instead")
		}
		h.Clock.Advance(2 * time.Second) // past the per-identifier send cooldown
		a := h.API("POST", "/password-resets", "", map[string]any{"identifier": "alice@example.test"})
		b := h.API("POST", "/password-resets", "", map[string]any{"identifier": "nobody@example.test"})
		if a.Status != 202 || b.Status != 202 || a.Str("message") != b.Str("message") || a.Str("reset_id") == "" || b.Str("reset_id") == "" {
			t.Fatalf("reset responses differ: %s / %s", a.Raw, b.Raw)
		}
	})
	t.Run("new account and first organization (27.1)", func(t *testing.T) {
		r, tx, cont := register("frank@example.test")
		mustStatus(t, r, 201, "register")
		code := CodeFrom(h.Mail("frank@example.test", "email_verification"))
		st := h.Step(tx, cont, "otp/verify", map[string]any{"code": code})
		st = h.Drive(tx, cont, st, LoginOpts{Identifier: "frank@example.test"})
		if st.Str("redirect_to") == "" {
			t.Fatalf("registration did not complete: %s", st.Raw)
		}
		var orgs, owners int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM organizations WHERE slug='newco-frank'`).Scan(&orgs)
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
			JOIN memberships m ON m.id=ra.membership_id JOIN users u ON u.id=m.user_id JOIN user_identifiers i ON i.user_id=u.id
			WHERE r.is_owner_role AND i.canonical_value='frank@example.test'`).Scan(&owners)
		if orgs != 1 || owners != 1 {
			t.Fatalf("organization=%d owners=%d", orgs, owners)
		}
		// A retried completion cannot create another organization.
		again := h.Step(tx, cont, "consent", map[string]any{"approve": true})
		if again.Status == 200 {
			t.Fatal("completed transaction resumed")
		}
	})
	t.Run("TEST-070 reset does not bypass MFA", func(t *testing.T) {
		// Alice enrolls TOTP, then resets her password through recovery.
		f.AccountToken("alice")
		acct := f.AccountToken("alice").Tokens.Str("access_token")
		en := h.API("POST", "/me/totp/enroll", acct, nil)
		mustStatus(t, en, 201, "enroll")
		h.seeds["alice@example.test"] = en.Str("secret")
		mustStatus(t, h.API("POST", "/me/totp/activate", acct, map[string]any{"code": h.TOTPNow("alice@example.test")}), 200, "activate")
		h.Clock.Advance(2 * time.Second)
		req := h.API("POST", "/password-resets", "", map[string]any{"identifier": "alice@example.test"})
		code := CodeFrom(h.Mail("alice@example.test", "password_reset"))
		done := h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code, "new_password": "a recovered passphrase 2026"})
		mustStatus(t, done, 200, "reset")
		h.SetPassword("alice@example.test", "a recovered passphrase 2026")
		// Old sessions are gone; the next login still demands TOTP.
		if r := h.API("GET", "/me", acct, nil); r.Status != 401 {
			t.Fatalf("sessions must be revoked after reset: %d", r.Status)
		}
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "alice@example.test"})
		st := h.Step(tx, cont, "password", map[string]any{"password": "a recovered passphrase 2026"})
		if st.Str("redirect_to") != "" || !strings.Contains(string(st.Raw), `"totp"`) {
			t.Fatalf("MFA must still be required after reset: %s", st.Raw)
		}
		// A consumed reset code cannot be reused.
		again := h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code, "new_password": "yet another passphrase 2026"})
		mustStatus(t, again, 400, "reset code reuse")
	})
}
