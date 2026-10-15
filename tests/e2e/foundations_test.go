package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/organization"
)

// emailCode returns the newest verification code mailed to addr.
func emailCode(h *Harness, addr string) string {
	if c := CodeFrom(h.Mail(addr, "identifier_challenge")); c != "" {
		return c
	}
	return CodeFrom(h.Mail(addr, "email_verification"))
}

// TestStableIdentifiers covers DOM-001: user, organization, membership and
// client IDs are opaque prefixed values that carry no email, and replacing a
// user's email (add, verify, make primary, remove the old one) keeps the user
// ID and the token subject.
func TestStableIdentifiers(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	bob := f.Users["bob"]
	for prefix, id := range map[string]string{"usr_": bob, "org_": f.Acme, "mem_": f.MemberAcme["bob"], "cli_": f.Clients["web"].Ref} {
		if !strings.HasPrefix(id, prefix) || strings.Contains(strings.ToLower(id), "bob") || strings.Contains(id, "@") {
			t.Fatalf("identifier %q is not an opaque %s identifier", id, prefix)
		}
	}
	subject := func(identifier string) string {
		t.Helper()
		lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: identifier})
		sub, _ := jwtPayload(lr.Tokens.Str("access_token"))["sub"].(string)
		return sub
	}
	if sub := subject("bob@example.test"); sub != bob {
		t.Fatalf("token subject %q is not the user ID %q", sub, bob)
	}

	tok := f.AccountToken("bob").Tokens.Str("access_token")
	added := f.must(h.API("POST", "/me/identifiers", tok, map[string]any{"type": "email", "value": "robert@example.test"}), 201, "new email")
	ch := f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": added.Str("id")}), 201, "challenge")
	mustStatus(t, h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok,
		map[string]any{"code": emailCode(h, "robert@example.test")}), 200, "verify new email")
	mustStatus(t, h.API("POST", "/me/identifiers/"+added.Str("id")+"/primary", tok, nil), 204, "make it primary")
	old := ""
	for _, it := range f.must(h.API("GET", "/me/identifiers", tok, nil), 200, "identifiers").Get("items").([]any) {
		if m := it.(map[string]any); m["value"] == "bob@example.test" {
			old, _ = m["id"].(string)
		}
	}
	if old == "" {
		t.Fatal("old email not listed")
	}
	mustStatus(t, h.API("DELETE", "/me/identifiers/"+old, tok, nil), 204, "remove old email")

	h.SetPassword("robert@example.test", h.passwords["bob@example.test"])
	if sub := subject("robert@example.test"); sub != bob {
		t.Fatalf("email change changed the token subject: %q -> %q", bob, sub)
	}
	me := f.must(h.API("GET", "/me", f.H.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account",
		Resources: []string{h.Realm.Issuer + "/account"}, Identifier: "robert@example.test"}).Tokens.Str("access_token"), nil), 200, "me")
	if me.Str("id") != bob {
		t.Fatalf("email change changed the user ID: %s", me.Raw)
	}
	if m := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 200, "membership"); m.Str("membership.user_id") != bob {
		t.Fatalf("membership no longer names the same user: %s", m.Raw)
	}
}

// TestPermissionNamespacesSeparated covers DOM-005: realm administration,
// organization administration, support and platform permissions live in
// reserved namespaces that applications cannot register, organization roles
// cannot carry realm, support or platform permissions, and each built-in
// trust class holds only its own namespace.
func TestPermissionNamespacesSeparated(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	for _, name := range []string{"realm.backdoor", "org.backdoor", "support.backdoor", "platform.backdoor"} {
		mustStatus(t, f.AdminAPI("POST", "/permissions", map[string]any{"name": name}), 422, "application permission "+name)
	}
	for _, perm := range []string{"realm.users.read", "support.users.read"} {
		mustStatus(t, f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "mixed-" + strings.Split(perm, ".")[0],
			"permissions": []string{perm}}), 422, "organization role carrying "+perm)
	}
	held := func(user string, scope authorization.Scope) []string {
		t.Helper()
		ps, err := h.App.Authz.Effective(ctx, nil, h.Realm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: f.Users[user]}, scope)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for p := range ps.Allow {
			out = append(out, p)
		}
		return out
	}
	only := func(who string, perms []string, allowed ...string) {
		t.Helper()
		if len(perms) == 0 {
			t.Fatalf("%s holds no permissions", who)
		}
		for _, p := range perms {
			ns := strings.SplitN(p, ".", 2)[0]
			for _, reserved := range []string{"realm", "org", "support", "platform"} {
				if ns == reserved && !strings.Contains(" "+strings.Join(allowed, " ")+" ", " "+reserved+" ") {
					t.Fatalf("%s holds %s outside its trust class", who, p)
				}
			}
		}
	}
	acme := authorization.Scope{Type: authorization.ScopeOrganization, ID: f.Acme}
	globex := authorization.Scope{Type: authorization.ScopeOrganization, ID: f.Globex}
	realmScope := authorization.Scope{Type: authorization.ScopeRealm, ID: h.Realm.ID}
	only("acme owner", held("alice", acme), "org")
	only("globex administrator", held("carol", globex), "org")
	only("support operator", held("sam", realmScope), "support")
	if perms := held("carol", realmScope); len(perms) != 0 {
		t.Fatalf("organization administrator holds realm permissions: %v", perms)
	}
}

// TestMembershipSuspensionStaysScoped covers TEN-004 and TEN-006: suspending
// a shared user's membership in one organization ends access there only; the
// user's other membership keeps working. The last active owner can be neither
// suspended nor demoted until another owner exists.
func TestMembershipSuspensionStaysScoped(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	member := "/organizations/" + f.Acme + "/members/"
	mustStatus(t, f.AdminAPI("PATCH", member+f.MemberAcme["bob"], map[string]any{"state": "suspended"}), 200, "suspend bob in acme")
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", ExpectFail: true})
	if lr.Tokens != nil && lr.Tokens.Status == 200 {
		t.Fatal("suspended membership produced an acme token")
	}
	globex := f.LoginWeb("bob", f.Globex, f.OrdersAud, "orders:read").Tokens
	mustStatus(t, globex, 200, "globex sign-in while suspended in acme")
	if org := jwtPayload(globex.Str("access_token"))["org_id"]; org != f.Globex {
		t.Fatalf("globex token names %v", org)
	}
	if m := f.must(f.AdminAPI("GET", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"], nil), 200, "globex membership"); m.Str("membership.state") != "active" {
		t.Fatalf("suspension in acme changed the globex membership: %s", m.Raw)
	}
	if u := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "user"); u.Str("state") != "active" {
		t.Fatalf("membership suspension changed the realm-wide account: %s", u.Raw)
	}
	mustStatus(t, f.AdminAPI("PATCH", member+f.MemberAcme["bob"], map[string]any{"state": "active"}), 200, "reactivate")
	mustStatus(t, f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens, 200, "acme sign-in after reactivation")

	// Alice is acme's only owner.
	if r := f.AdminAPI("PATCH", member+f.MemberAcme["alice"], map[string]any{"state": "suspended"}); r.Status != 409 || r.Str("code") != "last_owner" {
		t.Fatalf("last owner suspended: %d %s", r.Status, r.Raw)
	}
	ownerAssignment := func(membership string) string {
		t.Helper()
		m := f.must(f.AdminAPI("GET", member+membership, nil), 200, "membership")
		for _, it := range m.Get("role_assignments").([]any) {
			if a := it.(map[string]any); a["role_id"] == f.Roles["owner"] {
				return a["id"].(string)
			}
		}
		t.Fatalf("no owner assignment: %s", m.Raw)
		return ""
	}
	aliceOwner := ownerAssignment(f.MemberAcme["alice"])
	if r := f.AdminAPI("DELETE", member+f.MemberAcme["alice"]+"/roles/"+aliceOwner, nil); r.Status != 409 || r.Str("code") != "last_owner" {
		t.Fatalf("last owner demoted: %d %s", r.Status, r.Raw)
	}
	f.must(f.AdminAPI("POST", member+f.MemberAcme["bob"]+"/roles", map[string]any{"role_id": f.Roles["owner"]}), 201, "second owner")
	mustStatus(t, f.AdminAPI("DELETE", member+f.MemberAcme["alice"]+"/roles/"+aliceOwner, nil), 204, "demotion once another owner exists")
	if r := f.AdminAPI("PATCH", member+f.MemberAcme["bob"], map[string]any{"state": "suspended"}); r.Status != 409 {
		t.Fatalf("the new last owner suspended: %d %s", r.Status, r.Raw)
	}
}

// TestDomainRoutingIsNotMembership covers TEN-010: sign-in is routed to an
// organization by an email domain only once the organization has verified
// it, and a matching domain never makes the user a member.
func TestDomainRoutingIsNotMembership(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	route := func(domain string) string {
		t.Helper()
		id, _, _, err := h.App.Orgs.DiscoverByEmailDomain(ctx, h.Realm.ID, domain)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	ch := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains", map[string]any{"domain": "acme-staff.test"}), 201, "claim domain")
	if id := route("acme-staff.test"); id != "" {
		t.Fatalf("an unverified domain routes sign-in to %s", id)
	}
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify domain")
	if id := route("acme-staff.test"); id != f.Acme {
		t.Fatalf("verified domain routes to %q", id)
	}

	// Zed has an address in acme's domain but is not a member.
	zed := f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "zed@acme-staff.test", "username": "zed", "display_name": "Zed"}), 201, "zed").Str("user.id")
	pw := "zed has a long passphrase 2026"
	f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": CodeFrom(h.Mail("zed@acme-staff.test", "account_setup")), "password": pw}), 200, "setup zed")
	h.SetPassword("zed@acme-staff.test", pw)
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Identifier: "zed@acme-staff.test", SelectOrg: f.Acme, ExpectFail: true})
	if lr.Tokens != nil && lr.Tokens.Status == 200 && jwtPayload(lr.Tokens.Str("access_token"))["org_id"] == f.Acme {
		t.Fatal("a matching email domain produced an acme token")
	}
	var n int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Acme, zed).Scan(&n)
	if n != 0 {
		t.Fatalf("domain routing created %d memberships", n)
	}
	// Membership comes from an explicit decision.
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": zed, "role_ids": []string{f.Roles["orders-viewer"]}}), 201, "add zed")
	ok := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Identifier: "zed@acme-staff.test", SelectOrg: f.Acme})
	if org := jwtPayload(ok.Tokens.Str("access_token"))["org_id"]; org != f.Acme {
		t.Fatalf("member signed in through domain routing got org %v", org)
	}
}

// TestMembershipProvenance covers TEN-015: each membership records how it was
// created (administrator assignment, invitation, approved self-join) with a
// reference to its source.
func TestMembershipProvenance(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	membership := func(org, user string) map[string]any {
		t.Helper()
		var id string
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active'`,
			org, f.Users[user]).Scan(&id)
		if id == "" {
			t.Fatalf("%s has no active membership", user)
		}
		return f.must(f.AdminAPI("GET", "/organizations/"+org+"/members/"+id, nil), 200, "membership").Get("membership").(map[string]any)
	}
	if m := membership(f.Acme, "bob"); m["source"] != "admin" || m["source_reference"] != f.Users["admin"] {
		t.Fatalf("administrator assignment provenance: %v", m)
	}

	alice := f.AccountToken("alice").Tokens.Str("access_token")
	f.CreateUser("dave")
	inv := f.must(h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "dave@example.test"}), 201, "invite dave")
	secret := invitationFromMail(h.Mail("dave@example.test", "invitation"))
	mustStatus(t, h.API("POST", "/invitations/accept", f.AccountToken("dave").Tokens.Str("access_token"), map[string]any{"invitation": secret}), 200, "accept")
	if m := membership(f.Acme, "dave"); m["source"] != "invitation" || m["source_reference"] != inv.Str("invitation.id") {
		t.Fatalf("invitation provenance: %v", m)
	}

	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Globex, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Globex, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"join_requests_enabled": true}}}), 200, "enable joins")
	f.CreateUser("erin")
	jr := f.must(h.API("POST", "/organizations/"+f.Globex+"/join-requests", f.AccountToken("erin").Tokens.Str("access_token"),
		map[string]any{"reason": "new hire"}), 201, "join request")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Globex+"/join-requests/"+jr.Str("id")+"/decision", map[string]any{"approve": true, "reason": "ok"}), 204, "approve")
	if m := membership(f.Globex, "erin"); m["source"] != "self_join" || m["source_reference"] != jr.Str("id") {
		t.Fatalf("approved self-join provenance: %v", m)
	}
}

// TestStructuredAuditEvents covers AUD-001: stored audit events carry their
// ID, schema version, occurred and recorded times, realm, organization,
// actor (with its session), subject, target, action, result, reason code,
// request ID and the grant, session and client of token events.
func TestStructuredAuditEvents(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	var org, client, grant, session string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(organization_id,''), coalesce(client_id,''), coalesce(grant_id,''), coalesce(session_id,'')
		FROM audit_events WHERE type='token.issued' AND subject_id=$1 ORDER BY seq DESC LIMIT 1`, f.Users["bob"]).Scan(&org, &client, &grant, &session); err != nil {
		t.Fatal(err)
	}
	if org != f.Acme || client != "web-bff" || !strings.HasPrefix(grant, "gnt_") || !strings.HasPrefix(session, "ses_") {
		t.Fatalf("token event context: org=%q client=%q grant=%q session=%q", org, client, grant, session)
	}

	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme + "/members/" + f.MemberAcme["bob"], Token: f.AdminToken,
		JSON: map[string]any{"state": "suspended"}, Headers: map[string]string{"X-Request-Id": "req-aud-001-membership"}}), 200, "suspend membership")
	var ev struct {
		id, realm, org, actorType, actor, actorSession, subjType, subj, tgtType, tgt, outcome, request, category, hash string
		version                                                                                                        int
		occurred, recorded                                                                                             time.Time
	}
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id, schema_version, occurred_at, recorded_at, realm_id, organization_id, actor_type, actor_id,
		coalesce(actor_session_id,''), subject_type, subject_id, target_type, target_id, outcome, request_id, category, content_hash
		FROM audit_events WHERE type='organization.membership.suspended' AND request_id='req-aud-001-membership'`).Scan(&ev.id, &ev.version,
		&ev.occurred, &ev.recorded, &ev.realm, &ev.org, &ev.actorType, &ev.actor, &ev.actorSession, &ev.subjType, &ev.subj, &ev.tgtType, &ev.tgt,
		&ev.outcome, &ev.request, &ev.category, &ev.hash); err != nil {
		t.Fatal(err)
	}
	switch {
	case !strings.HasPrefix(ev.id, "evt_") || ev.version != 1 || ev.occurred.IsZero() || ev.recorded.IsZero():
		t.Fatalf("event identity and times: %+v", ev)
	case ev.realm != h.Realm.ID || ev.org != f.Acme:
		t.Fatalf("event scope: %+v", ev)
	case ev.actorType != "user" || ev.actor != f.Users["admin"] || ev.actorSession == "":
		t.Fatalf("event actor: %+v", ev)
	case ev.subjType != "user" || ev.subj != f.Users["bob"] || ev.tgtType != "membership" || ev.tgt != f.MemberAcme["bob"]:
		t.Fatalf("event subject and target: %+v", ev)
	case ev.outcome != "success" || ev.category == "" || ev.hash == "":
		t.Fatalf("event result: %+v", ev)
	}

	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "INVESTIGATION"}), 200, "suspend carol")
	var reason, outcome string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(reason_code,''), outcome FROM audit_events WHERE type='user.suspended' AND subject_id=$1`,
		f.Users["carol"]).Scan(&reason, &outcome)
	if reason != "INVESTIGATION" || outcome != "success" {
		t.Fatalf("reason code %q outcome %q", reason, outcome)
	}
	// A refused action is recorded with its result.
	bobTok := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("PATCH", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["carol"], bobTok, map[string]any{"state": "suspended"}), 403, "member suspends admin")
	var denied int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_id=$1 AND outcome='denied'`, f.Users["bob"]).Scan(&denied)
	if denied == 0 {
		t.Fatal("denied action not recorded with its result")
	}
}
