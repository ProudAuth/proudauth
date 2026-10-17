package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestBulkAndProjectInvitations covers INV-011 (bulk), INV-012 (project
// invitations with separate grant semantics), INV-014 and USR-021 (changed or
// recycled invited addresses).
func TestBulkAndProjectInvitations(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	// Granting roles by invitation needs an MFA session (TestOrgAuthorityGrantsNeedMFA).
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner
	inviteURL := "/organizations/" + f.Acme + "/invitations"

	t.Run("INV-011 bulk invitations report per-item results", func(t *testing.T) {
		items := []map[string]any{{"email": "erin@example.test"}, {"email": "not-an-email"}, {"email": "erin@example.test"},
			{"email": "shared@example.test", "purpose": "shared_link"}}
		do := func() *Resp {
			return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main" + inviteURL + "/batch", Token: alice,
				Headers: map[string]string{"Idempotency-Key": "bulk-1"}, JSON: map[string]any{"items": items}})
		}
		r := do()
		mustStatus(t, r, 200, "batch")
		want := []float64{201, 422, 409, 422}
		res := r.Get("results").([]any)
		for i, w := range want {
			if got := res[i].(map[string]any)["status"].(float64); got != w {
				t.Fatalf("item %d: status %v, want %v: %s", i, got, w, r.Raw)
			}
		}
		if invitationFromMail(h.Mail("erin@example.test", "invitation")) == "" {
			t.Fatal("bulk entry delivery not queued")
		}
		again := do()
		if again.Str("batch_id") != r.Str("batch_id") {
			t.Fatalf("idempotent replay created a new batch: %s", again.Raw)
		}
		var n int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM invitations WHERE target_email_canonical='erin@example.test'`).Scan(&n)
		if n != 1 {
			t.Fatalf("replay duplicated invitations: %d", n)
		}
		big := make([]map[string]any, 101)
		for i := range big {
			big[i] = map[string]any{"email": "x@example.test"}
		}
		mustStatus(t, h.API("POST", inviteURL+"/batch", alice, map[string]any{"items": big}), 422, "oversized batch")
	})

	t.Run("INV-012 project invitations grant project roles only", func(t *testing.T) {
		project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Partner Portal"}), 201, "project").Str("id")
		role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "portal-user",
			"permissions": []string{"orders.read"}}), 201, "project role").Str("id")
		body := map[string]any{"email": "dave@example.test", "purpose": "project_access", "project_id": project, "role_ids": []string{role}}
		if r := h.API("POST", inviteURL, alice, body); r.Status != 403 {
			t.Fatalf("organization without a project grant invited to the project: %d %s", r.Status, r.Raw)
		}
		grant := f.must(f.AdminAPI("POST", "/projects/"+project+"/grants", map[string]any{"organization_id": f.Acme, "allowed_role_ids": []string{role}}), 201, "grant")
		bob := f.AccountToken("bob").Tokens.Str("access_token") // acme member without role-assignment authority
		if r := h.API("POST", inviteURL, bob, body); r.Status != 403 {
			t.Fatalf("member without assignment authority invited to a project: %d", r.Status)
		}
		mustStatus(t, h.API("POST", inviteURL, alice, body), 201, "project invitation")
		f.CreateUser("dave")
		secret := invitationFromMail(h.Mail("dave@example.test", "invitation"))
		dave := f.AccountToken("dave").Tokens.Str("access_token")
		acc := h.API("POST", "/invitations/accept", dave, map[string]any{"invitation": secret})
		mustStatus(t, acc, 200, "accept project invitation")
		if acc.Str("project_id") != project || acc.Str("membership_id") != "" {
			t.Fatalf("project acceptance semantics: %s", acc.Raw)
		}
		var members, assignments int
		ctx := context.Background()
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Acme, f.Users["dave"]).Scan(&members)
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE subject_id=$1 AND scope_type='project' AND scope_id=$2`,
			f.Users["dave"], project).Scan(&assignments)
		if members != 0 || assignments != 1 {
			t.Fatalf("project invitation created membership=%d project assignments=%d", members, assignments)
		}
		// Revoking the grant ends access delegated through it.
		mustStatus(t, f.AdminAPI("POST", "/projects/"+project+"/grants/"+grant.Str("id")+"/revoke", nil), 204, "revoke grant")
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE subject_id=$1 AND scope_type='project'`, f.Users["dave"]).Scan(&assignments)
		if assignments != 0 {
			t.Fatal("project roles survived revocation of the grant that delegated them")
		}
		if r := h.API("POST", inviteURL, alice, body); r.Status != 403 {
			t.Fatalf("invitation allowed after grant revocation: %d", r.Status)
		}
	})

	t.Run("INV-014 administrator-reviewed reassignment", func(t *testing.T) {
		inv := f.must(h.API("POST", inviteURL, alice, map[string]any{"email": "frank@example.test"}), 201, "invite")
		old := invitationFromMail(h.Mail("frank@example.test", "invitation"))
		id := inv.Str("invitation.id")
		mustStatus(t, h.API("POST", inviteURL+"/"+id+"/reassign", alice, map[string]any{"email": "frank.new@example.test"}), 422, "reason required")
		re := h.API("POST", inviteURL+"/"+id+"/reassign", alice, map[string]any{"email": "frank.new@example.test", "reason": "ticket 4411: address changed"})
		mustStatus(t, re, 201, "reassign")
		if r := h.API("POST", "/invitations/inspect", "", map[string]any{"invitation": old}); r.Status != 400 {
			t.Fatalf("superseded secret still valid: %d", r.Status)
		}
		if invitationFromMail(h.Mail("frank.new@example.test", "invitation")) == "" {
			t.Fatal("fresh invitation not delivered")
		}
		if r := h.API("POST", inviteURL+"/"+id+"/reassign", alice, map[string]any{"email": "x@example.test", "reason": "again"}); r.Status != 409 {
			t.Fatalf("superseded invitation reassigned again: %d", r.Status)
		}
	})

	t.Run("USR-021 recycled address does not inherit the invitation", func(t *testing.T) {
		f.CreateUser("gina")
		mustStatus(t, h.API("POST", inviteURL, alice, map[string]any{"email": "gina@example.test"}), 201, "invite gina")
		secret := invitationFromMail(h.Mail("gina@example.test", "invitation"))
		// The address moves to a different account (changed, then recycled).
		f.CreateUser("hank")
		if _, err := h.App.D.DB.Pool.Exec(context.Background(), `UPDATE user_identifiers SET user_id=$1, is_primary=false WHERE canonical_value='gina@example.test'`,
			f.Users["hank"]); err != nil {
			t.Fatal(err)
		}
		hank := f.AccountToken("hank").Tokens.Str("access_token")
		r := h.API("POST", "/invitations/accept", hank, map[string]any{"invitation": secret})
		if r.Status != 400 || r.Str("reason_code") != "IDENTIFIER_REASSIGNED" {
			t.Fatalf("recycled address accepted an invitation bound to its previous owner: %d %s", r.Status, r.Raw)
		}
		if got := h.API("GET", inviteURL+"?state=pending_acceptance", alice, nil); containsRaw(got, f.Users["gina"]) {
			t.Fatal("invitation listing discloses the bound account")
		}
	})
}

func containsRaw(r *Resp, s string) bool {
	return s != "" && strings.Contains(string(r.Raw), s)
}

// TestInvitedRegistrationWaitsForPolicy covers INV-006: an invitation used at
// registration grants membership only after every policy-required step (here
// MFA enrollment) has completed, not at email verification.
func TestInvitedRegistrationWaitsForPolicy(t *testing.T) {
	f := NewFixture(t, func(p *realmPolicy) { p.MFA.Requirement = "required" })
	h := f.H
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "ivy@example.test"}), 201, "invite")
	secret := invitationFromMail(h.Mail("ivy@example.test", "invitation"))
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud}})
	tx := start.Str("transaction_id")
	r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": tx, "email": "ivy@example.test",
		"password": "ivy has a long passphrase 2026", "invitation": secret}, Headers: map[string]string{"X-Transaction-Token": cont}})
	mustStatus(t, r, 201, "register with invitation")
	h.SetPassword("ivy@example.test", "ivy has a long passphrase 2026")
	st := h.Step(tx, cont, "otp/verify", map[string]any{"code": CodeFrom(h.Mail("ivy@example.test", "email_verification"))})
	members := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM memberships m JOIN user_identifiers i ON i.user_id=m.user_id
			WHERE m.organization_id=$1 AND i.canonical_value='ivy@example.test' AND m.state='active'`, f.Acme).Scan(&n)
		return n
	}
	if !hasAction(st, "enroll_totp") {
		t.Fatalf("MFA enrollment not required: %s", st.Raw)
	}
	if members() != 0 {
		t.Fatal("membership granted before MFA enrollment completed")
	}
	st = h.Drive(tx, cont, st, LoginOpts{Identifier: "ivy@example.test"})
	if st.Str("redirect_to") == "" {
		t.Fatalf("registration did not complete: %s", st.Raw)
	}
	if members() != 1 {
		t.Fatal("invitation not accepted at completion")
	}
}

// TestInvitationPolicyBudgetsAndEvidence covers INV-008 (organization policy
// re-checked at acceptance), INV-009 (aggregate per-recipient budget that
// revoke/recreate cannot reset) and INV-016 (expiry is audited).
func TestInvitationPolicyBudgetsAndEvidence(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	inviteURL := "/organizations/" + f.Acme + "/invitations"

	t.Run("INV-008 acceptance re-checks the organization's policy", func(t *testing.T) {
		mustStatus(t, h.API("POST", inviteURL, alice, map[string]any{"email": "kim@example.test"}), 201, "invite")
		secret := invitationFromMail(h.Mail("kim@example.test", "invitation"))
		org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"invitations_enabled": false}}}), 200, "disable invitations")
		f.CreateUser("kim")
		kim := f.AccountToken("kim").Tokens.Str("access_token")
		r := h.API("POST", "/invitations/accept", kim, map[string]any{"invitation": secret})
		if r.Status != 400 || r.Str("reason_code") != "INVITATIONS_DISABLED" {
			t.Fatalf("invitation accepted after the organization disabled invitations: %d %s", r.Status, r.Raw)
		}
		org = f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
		mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"invitations_enabled": true}}}), 200, "re-enable")
	})

	t.Run("INV-009 per-recipient budget survives revoke and recreate", func(t *testing.T) {
		h.App.D.Cfg.Security.RateLimits.InvitationsPerRecipient = 3
		defer func() { h.App.D.Cfg.Security.RateLimits.InvitationsPerRecipient = 10 }()
		statuses := []int{}
		for i := 0; i < 4; i++ {
			r := h.API("POST", inviteURL, alice, map[string]any{"email": "spam-target@example.test"})
			statuses = append(statuses, r.Status)
			if r.Status == 201 {
				mustStatus(t, h.API("POST", inviteURL+"/"+r.Str("invitation.id")+"/revoke", alice, nil), 204, "revoke")
			}
		}
		if statuses[3] != 429 {
			t.Fatalf("recipient budget reset by revoke/recreate: %v", statuses)
		}
	})

	t.Run("INV-016 expiry transitions are audited", func(t *testing.T) {
		inv := f.must(h.API("POST", inviteURL, alice, map[string]any{"email": "late@example.test", "ttl_hours": 1}), 201, "invite")
		h.Clock.Advance(2 * time.Hour)
		if _, err := h.App.Orgs.ExpireInvitations(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.ReloginAdmin()
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=invitation.expired", nil), 200, "audit")
		if !strings.Contains(string(ev.Raw), inv.Str("invitation.id")) {
			t.Fatalf("expiry not audited: %s", ev.Raw)
		}
	})
}

// TestInvitationDecline covers INV-001: the recipient can decline; a declined
// invitation can no longer be accepted, and administrators see its state.
func TestInvitationDecline(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.CreateUser("dina")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	inv := f.must(h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "dina@example.test"}), 201, "invite")
	secret := invitationFromMail(h.Mail("dina@example.test", "invitation"))
	dina := f.AccountToken("dina").Tokens.Str("access_token")
	if r := h.API("POST", "/invitations/decline", f.AccountToken("bob").Tokens.Str("access_token"), map[string]any{"invitation": secret}); r.Status != 400 ||
		r.Str("code") != "invitation_invalid" {
		t.Fatalf("someone else declining: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, h.API("POST", "/invitations/decline", dina, map[string]any{"invitation": secret}), 204, "decline")
	if r := h.API("POST", "/invitations/accept", dina, map[string]any{"invitation": secret}); r.Status == 200 {
		t.Fatal("declined invitation accepted")
	}
	got := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/invitations/"+inv.Str("invitation.id"), nil), 200, "admin view")
	if got.Str("state") != "declined" || got.Header.Get("ETag") == "" {
		t.Fatalf("invitation state: %s", got.Raw)
	}
	mustStatus(t, f.AdminAPI("GET", "/organizations/"+f.Globex+"/invitations/"+inv.Str("invitation.id"), nil), 404, "another organization's invitation")
}

// TestInvitationLimitsAndExpiry covers INV-009 and INV-001 edges: the resend
// limit counts resends (not the first send), a negative lifetime is refused
// instead of falling back to a default that may exceed the maximum, the list
// cursor is bound to its state filter, and an expired invitation can no
// longer be declined.
func TestInvitationLimitsAndExpiry(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	inviteURL := "/organizations/" + f.Acme + "/invitations"

	h.App.D.Cfg.Limits.InvitationResends = 2
	defer func() { h.App.D.Cfg.Limits.InvitationResends = 5 }()
	inv := f.must(h.API("POST", inviteURL, alice, map[string]any{"email": "resent@example.test"}), 201, "invite")
	for i := 1; i <= 2; i++ {
		mustStatus(t, h.API("POST", inviteURL+"/"+inv.Str("invitation.id")+"/resend", alice, nil), 200, fmt.Sprintf("resend %d", i))
	}
	mustStatus(t, h.API("POST", inviteURL+"/"+inv.Str("invitation.id")+"/resend", alice, nil), 429, "resend beyond the limit")

	mustStatus(t, h.API("POST", inviteURL, alice, map[string]any{"email": "negative@example.test", "ttl_hours": -5}), 422, "negative lifetime")
	mustStatus(t, h.API("POST", inviteURL, alice, map[string]any{"purpose": "shared_link", "max_uses": 5, "allowed_domains": []string{"example.test"},
		"ttl_hours": -1}), 422, "negative shared-link lifetime")

	f.must(h.API("POST", inviteURL, alice, map[string]any{"email": "second@example.test"}), 201, "second invite")
	page := f.must(h.API("GET", inviteURL+"?state=pending_delivery&limit=1", alice, nil), 200, "first page")
	cursor := page.Str("next_cursor")
	if cursor == "" {
		t.Fatalf("no next page: %s", page.Raw)
	}
	mustStatus(t, h.API("GET", inviteURL+"?state=pending_delivery&limit=1&cursor="+cursor, alice, nil), 200, "next page, same filter")
	mustStatus(t, h.API("GET", inviteURL+"?state=revoked&limit=1&cursor="+cursor, alice, nil), 400, "cursor replayed with another filter")

	f.CreateUser("lena")
	late := f.must(h.API("POST", inviteURL, alice, map[string]any{"email": "lena@example.test", "ttl_hours": 1}), 201, "short invite")
	secret := invitationFromMail(h.Mail("lena@example.test", "invitation"))
	h.Clock.Advance(2 * time.Hour)
	lena := f.AccountToken("lena").Tokens.Str("access_token")
	if r := h.API("POST", "/invitations/decline", lena, map[string]any{"invitation": secret}); r.Status != 400 || r.Str("code") != "invitation_invalid" {
		t.Fatalf("expired invitation declined: %d %s", r.Status, r.Raw)
	}
	f.ReloginAdmin()
	if got := f.must(f.AdminAPI("GET", inviteURL+"/"+late.Str("invitation.id"), nil), 200, "admin view"); got.Str("state") != "expired" {
		t.Fatalf("expired invitation state: %s", got.Raw)
	}
}

// TestInvitationRoleCeiling covers INV-007 and TEST-017: an inviter can offer
// only roles within their own delegable set (ownership included), and a role
// whose definition grew beyond that set after the invitation was created is
// refused at acceptance.
func TestInvitationRoleCeiling(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	// Granting roles by invitation needs an MFA session (TestOrgAuthorityGrantsNeedMFA).
	f.EnrollTOTP("carol")
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex admin holding orders-viewer
	inviteURL := "/organizations/" + f.Globex + "/invitations"
	f.CreateUser("erin")
	for _, role := range []string{"orders-refunder", "owner"} {
		if r := h.API("POST", inviteURL, carol, map[string]any{"email": "erin@example.test", "role_ids": []string{f.Roles[role]}}); r.Status != 403 ||
			r.Str("code") != "grant_ceiling_exceeded" {
			t.Fatalf("invitation offering %s above the inviter's ceiling: %d %s", role, r.Status, r.Raw)
		}
	}
	auditor := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "orders-auditor",
		"permissions": []string{"orders.read"}}), 201, "role within carol's ceiling").Str("id")
	f.must(h.API("POST", inviteURL, carol, map[string]any{"email": "erin@example.test", "role_ids": []string{auditor}}), 201, "invite within the ceiling")
	secret := invitationFromMail(h.Mail("erin@example.test", "invitation"))
	f.must(f.AdminAPI("POST", "/roles/"+auditor+"/permissions", map[string]any{"add": []string{"orders.refund"}}), 200, "role definition expands")
	erin := f.AccountToken("erin").Tokens.Str("access_token")
	r := h.API("POST", "/invitations/accept", erin, map[string]any{"invitation": secret})
	mustStatus(t, r, 400, "acceptance of a role now above the inviter's ceiling")
	if r.Str("reason_code") != "ROLE_CEILING_EXCEEDED" {
		t.Fatalf("reason: %s", r.Raw)
	}
	var n int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Globex, f.Users["erin"]).Scan(&n)
	if n != 0 {
		t.Fatal("membership granted for an expanded role")
	}
}

// TestSharedInvitationLinks covers INV-015: a multi-use link needs an
// explicit use limit and audience domain policy, cannot grant owner or admin
// roles (and grants plain membership by default), gets a short lifetime,
// admits only verified addresses in its domains and stops after its last use.
func TestSharedInvitationLinks(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	// Granting roles by invitation needs an MFA session (TestOrgAuthorityGrantsNeedMFA).
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner
	inviteURL := "/organizations/" + f.Acme + "/invitations"
	link := func(change map[string]any) *Resp {
		body := map[string]any{"purpose": "shared_link", "max_uses": 2, "allowed_domains": []string{"example.test"}, "role_ids": []string{f.Roles["orders-viewer"]}}
		for k, v := range change {
			if v == nil {
				delete(body, k)
			} else {
				body[k] = v
			}
		}
		return h.API("POST", inviteURL, alice, body)
	}
	mustStatus(t, link(map[string]any{"allowed_domains": nil}), 422, "no audience domain policy")
	mustStatus(t, link(map[string]any{"max_uses": nil}), 422, "no use limit")
	mustStatus(t, link(map[string]any{"max_uses": h.App.D.Cfg.Limits.SharedInvitationMaxUses + 1}), 422, "uses above the limit")
	for _, role := range []string{"owner", "admin"} {
		mustStatus(t, link(map[string]any{"role_ids": []string{f.Roles[role]}}), 422, role+" role on a shared link")
	}
	if r := f.must(link(map[string]any{"role_ids": nil}), 201, "link without roles"); jsonString(r.Get("invitation.role_ids")) != jsonString([]string{f.Roles["member"]}) {
		t.Fatalf("default shared-link roles: %s", r.Raw)
	}

	r := f.must(link(map[string]any{"ttl_hours": 24 * 30}), 201, "shared link")
	exp, _ := time.Parse(time.RFC3339Nano, r.Str("invitation.expires_at"))
	if !exp.After(h.Clock.Now()) || exp.After(h.Clock.Now().Add(h.App.D.Cfg.Limits.SharedInvitationMaxTTL)) {
		t.Fatalf("shared link lifetime not bounded: %s", r.Raw)
	}
	secret := r.Str("invitation_secret")
	if secret == "" {
		t.Fatalf("shared link secret not shown to its creator: %s", r.Raw)
	}
	accept := func(identifier string) *Resp {
		tok := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
			Identifier: identifier}).Tokens.Str("access_token")
		return h.API("POST", "/invitations/accept", tok, map[string]any{"invitation": secret})
	}

	// An address outside the audience domains is refused.
	f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "olga@other.test", "username": "olga", "display_name": "olga"}), 201, "outsider")
	f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": CodeFrom(h.Mail("olga@other.test", "account_setup")),
		"password": "olga has a long passphrase 2026"}), 200, "outsider setup")
	h.SetPassword("olga@other.test", "olga has a long passphrase 2026")
	if r := accept("olga@other.test"); r.Status != 400 || r.Str("reason_code") != "IDENTIFIER_MISMATCH" {
		t.Fatalf("shared link accepted outside its domains: %d %s", r.Status, r.Raw)
	}
	// Two uses within the domain; the third is refused.
	for _, u := range []string{"dave", "erin"} {
		f.CreateUser(u)
		mustStatus(t, accept(u+"@example.test"), 200, u+" uses the link")
	}
	f.CreateUser("finn")
	if r := accept("finn@example.test"); r.Status != 400 || r.Str("code") != "invitation_invalid" {
		t.Fatalf("shared link used beyond its limit: %d %s", r.Status, r.Raw)
	}
	var members int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id = ANY($2) AND state='active'`,
		f.Acme, []string{f.Users["dave"], f.Users["erin"], f.Users["finn"]}).Scan(&members)
	if members != 2 {
		t.Fatalf("shared-link memberships: %d", members)
	}
}
