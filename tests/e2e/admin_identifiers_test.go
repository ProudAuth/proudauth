package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/realm"
)

// TestAdminIdentifierChangeGuards covers the refusals of the administrator's
// lost contact address path (MFA-008, USR-004, USR-005;
// TestLostContactAndFactorRecovery covers the path itself). Adding an address
// to an account and making one primary need both
// realm.users.verification.override and realm.users.credentials.manage (each
// alone is refused, and the refusal audited), a reason and a recent sign-in,
// never apply to the caller's own account, and never take an address another
// account verified. Assisted recovery is never delivered to an unverified
// address: an unverified address cannot become primary, recovery of an
// account whose primary address is unverified is refused whether immediate or
// scheduled, and a due request whose primary address is no longer verified is
// cancelled.
func TestAdminIdentifierChangeGuards(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	const reason = "identity proofed by video call, ticket 9100"
	count := func(q string, args ...any) int {
		t.Helper()
		h.Deliver()
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	mails := func(addr, tpl string) int {
		return count(`SELECT count(*) FROM dev_mailbox WHERE lower(recipient)=lower($1) AND template=$2`, addr, tpl)
	}
	identifierID := func(user, addr string) string {
		t.Helper()
		var id string
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM user_identifiers WHERE user_id=$1 AND canonical_value=$2`, user, addr).Scan(&id); err != nil {
			t.Fatalf("identifier %s: %v", addr, err)
		}
		return id
	}
	addBody := func(addr string) map[string]any {
		return map[string]any{"type": "email", "value": addr, "reason": reason}
	}
	nora := f.CreateUser("nora")
	noraIDs := "/users/" + nora + "/identifiers"

	t.Run("both permissions", func(t *testing.T) {
		role := func(name, perm string) string {
			return f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": name, "permissions": []string{perm}}), 201,
				"role "+name).Str("id")
		}
		assign := func(roleID, user string) {
			f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": roleID, "subject": map[string]any{"type": "user", "id": f.Users[user]}}),
				201, "assign "+user)
		}
		denials := func(user, perm string) int {
			return count(`SELECT count(*) FROM audit_events WHERE type='authorization.denied' AND actor_id=$1 AND metadata->>'permission'=$2`,
				f.Users[user], perm)
		}
		refused := func(call func() *Resp, user, missing, what string) {
			t.Helper()
			before := denials(user, missing)
			if r := call(); r.Status != 403 || r.Str("code") != "forbidden" {
				t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
			}
			if denials(user, missing) != before+1 {
				t.Fatalf("%s: refusal for %s not audited", what, missing)
			}
		}
		add := func(tok string) func() *Resp {
			return func() *Resp { return h.API("POST", noraIDs, tok, addBody("nora.alt@example.test")) }
		}
		override := role("identifier-override", "realm.users.verification.override")
		creds := role("credential-manager", "realm.users.credentials.manage")
		carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
		sam := f.AdminTokenFor("sam").Tokens.Str("access_token")
		refused(add(sam), "sam", "realm.users.verification.override", "a support operator")
		assign(override, "carol")
		refused(add(carol), "carol", "realm.users.credentials.manage", "verification override authority alone")
		primary := noraIDs + "/" + identifierID(nora, "nora@example.test") + "/primary"
		refused(func() *Resp { return h.API("POST", primary, carol, map[string]any{"reason": reason}) }, "carol", "realm.users.credentials.manage",
			"primary change with verification override authority alone")
		assign(creds, "sam")
		refused(add(sam), "sam", "realm.users.verification.override", "credential authority alone")
		assign(creds, "carol")
		f.must(add(carol)(), 201, "both permissions")
	})

	t.Run("reason, type, own account and recent authentication", func(t *testing.T) {
		for _, b := range []map[string]any{
			{"type": "email", "value": "nora.r@example.test"},
			{"type": "email", "value": "nora.r@example.test", "reason": "ok"},
			{"type": "phone", "value": "+14155550100", "reason": reason},
			{"type": "username", "value": "nora2", "reason": reason},
			{"type": "email", "value": "not an address", "reason": reason},
		} {
			if r := f.AdminAPI("POST", noraIDs, b); r.Status != 422 {
				t.Fatalf("%v: %d %s", b, r.Status, r.Raw)
			}
		}
		mustStatus(t, f.AdminAPI("POST", noraIDs, addBody("nora.alt@example.test")), 409, "address already on the account")
		mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["admin"]+"/identifiers", addBody("root.alt@example.test")), 403, "own account")
		prev := h.App.D.Cfg.Security.RecentAuthWindow
		defer func() { h.App.D.Cfg.Security.RecentAuthWindow = prev }()
		h.App.D.Cfg.Security.RecentAuthWindow = time.Minute
		h.Clock.Advance(2 * time.Minute)
		if r := f.AdminAPI("POST", noraIDs, addBody("nora.r@example.test")); r.Status != 403 || r.Str("code") != "recent_authentication_required" {
			t.Fatalf("change without recent authentication: %d %s", r.Status, r.Raw)
		}
		h.App.D.Cfg.Security.RecentAuthWindow = prev
		f.ReloginAdmin()
		if n := count(`SELECT count(*) FROM user_identifiers WHERE user_id=$1 AND canonical_value='nora.r@example.test'`, nora); n != 0 {
			t.Fatalf("a refused request added the address (%d)", n)
		}
	})

	t.Run("another account's verified address", func(t *testing.T) {
		mustStatus(t, f.AdminAPI("POST", noraIDs, addBody("alice@example.test")), 409, "address verified by alice")
		if n := count(`SELECT count(*) FROM user_identifiers WHERE user_id=$1 AND canonical_value='alice@example.test'`, nora); n != 0 {
			t.Fatalf("nora holds alice's address (%d)", n)
		}
	})

	t.Run("unverified address is never the recovery target", func(t *testing.T) {
		// nora's added address is unverified: it cannot become primary, and
		// recovery still goes to her verified primary address.
		mustStatus(t, f.AdminAPI("POST", noraIDs+"/"+identifierID(nora, "nora.alt@example.test")+"/primary", map[string]any{"reason": reason}), 422,
			"unverified address made primary")
		before := mails("nora@example.test", "account_setup")
		f.must(f.AdminAPI("POST", "/users/"+nora+"/recovery-requests", map[string]any{"reason": "lost phone, identity verified in person",
			"evidence_reference": "ticket 9101"}), 202, "recovery")
		if mails("nora.alt@example.test", "account_setup") != 0 || mails("nora@example.test", "account_setup") != before+1 {
			t.Fatal("setup link not sent to the verified primary address only")
		}

		// olga was created by an administrator and never set up: her primary
		// address is unverified. A verified second address does not make it a
		// recovery target, immediately or scheduled.
		olga := f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "olga@example.test", "username": "olga"}), 201, "create olga").Str("user.id")
		olgaIDs := "/users/" + olga + "/identifiers"
		work := f.must(f.AdminAPI("POST", olgaIDs, addBody("olga.work@example.test")), 201, "add olga's work address").Str("id")
		mustStatus(t, f.AdminAPI("POST", "/users/"+olga+"/verification-overrides", map[string]any{"identifier_id": work, "reason": reason}), 204, "override")
		recoverOlga := func() *Resp {
			return f.AdminAPI("POST", "/users/"+olga+"/recovery-requests", map[string]any{"reason": "lost access, identity verified in person",
				"evidence_reference": "ticket 9102"})
		}
		mustStatus(t, recoverOlga(), 409, "recovery to an unverified primary address")
		mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Recovery.CoolingOffHours = 24 }), 200, "cooling-off")
		mustStatus(t, recoverOlga(), 409, "scheduled recovery to an unverified primary address")
		mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Recovery.CoolingOffHours = 0 }), 200, "no cooling-off")
		if n := count(`SELECT count(*) FROM audit_events WHERE type IN ('recovery.assisted','recovery.assisted.scheduled') AND subject_id=$1`, olga); n != 0 {
			t.Fatalf("refused recovery recorded %d recovery events", n)
		}
		if mails("olga@example.test", "account_setup") != 1 || mails("olga.work@example.test", "account_setup") != 0 {
			t.Fatal("a refused recovery sent a setup link")
		}
		// Once the verified address is primary, recovery is delivered there;
		// the unverified former primary address receives nothing.
		mustStatus(t, f.AdminAPI("POST", olgaIDs+"/"+work+"/primary", map[string]any{"reason": reason}), 204, "verified address becomes primary")
		f.must(recoverOlga(), 202, "recovery to the verified primary address")
		if mails("olga.work@example.test", "account_setup") != 1 || mails("olga@example.test", "account_setup") != 1 ||
			mails("olga@example.test", "identifier_changed") != 0 {
			t.Fatal("recovery not delivered to the verified primary address only")
		}
	})

	t.Run("due request whose primary address is no longer verified", func(t *testing.T) {
		pia := f.CreateUser("pia")
		f.must(f.AdminAPI("POST", "/users/"+pia+"/identifiers", addBody("pia.alt@example.test")), 201, "add pia's new address")
		mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Recovery.CoolingOffHours = 24 }), 200, "cooling-off")
		f.must(f.AdminAPI("POST", "/users/"+pia+"/recovery-requests", map[string]any{"reason": "lost access, identity verified in person",
			"evidence_reference": "ticket 9103"}), 202, "schedule")
		// The owner removes her verified address, so the unverified one the
		// administrator added is the only email address left.
		tok := f.AccountToken("pia").Tokens.Str("access_token")
		mustStatus(t, h.API("DELETE", "/me/identifiers/"+identifierID(pia, "pia@example.test"), tok, nil), 204, "remove the verified address")
		h.Clock.Advance(25 * time.Hour)
		if n, err := h.App.Auth.ExecuteDueRecoveries(ctx); err != nil || n != 0 {
			t.Fatalf("due recovery with an unverified primary address: executed %d, %v", n, err)
		}
		var code string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(reason_code,'') FROM audit_events WHERE type='recovery.assisted.cancelled' AND subject_id=$1`,
			pia).Scan(&code)
		if code != "contact_unverified" {
			t.Fatalf("cancellation reason %q", code)
		}
		if mails("pia.alt@example.test", "account_setup") != 0 {
			t.Fatal("setup link delivered to the unverified address")
		}
	})
}
