package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/realm"
)

// TestIdentifierVerificationSendBudget covers REG-012: identifier
// verification codes count against the requesting client's send budget,
// like every other code send.
func TestIdentifierVerificationSendBudget(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	tok := f.AccountToken("bob").Tokens.Str("access_token")
	challenge := func(addr string) int {
		id := f.must(h.API("POST", "/me/identifiers", tok, map[string]any{"type": "email", "value": addr}), 201, "identifier").Str("id")
		return h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": id}).Status
	}
	prev := h.App.D.Cfg.Security.RateLimits.SendPerClient
	defer func() { h.App.D.Cfg.Security.RateLimits.SendPerClient = prev }()
	// With a budget of one send per client (the fixture may already have
	// spent it), the second send at the latest is refused; with the
	// configured budget the next one goes through, so the refusal came from
	// the per-client budget.
	h.App.D.Cfg.Security.RateLimits.SendPerClient = 1
	if s := []int{challenge("bob.one@example.test"), challenge("bob.two@example.test")}; s[1] != 429 {
		t.Fatalf("per-client send budget not applied to identifier verification: %v", s)
	}
	h.App.D.Cfg.Security.RateLimits.SendPerClient = prev
	if s := challenge("bob.three@example.test"); s != 201 {
		t.Fatalf("identifier verification within the budget: %d", s)
	}
}

// TestIdentifierChangeProof covers USR-004: changing a sign-in identifier
// needs recent authentication; the new address starts unverified (it neither
// signs in nor becomes primary) until the code sent to that address is
// consumed; and the verified old contact, not the new one, is told about the
// change.
func TestIdentifierChangeProof(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	const oldAddr, newAddr = "bob@example.test", "bob.new@example.test"
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}

	// A valid session whose authentication is no longer recent is refused.
	prev := h.App.D.Cfg.Security.RecentAuthWindow
	defer func() { h.App.D.Cfg.Security.RecentAuthWindow = prev }()
	h.App.D.Cfg.Security.RecentAuthWindow = time.Minute
	stale := f.AccountToken("bob").Tokens.Str("access_token")
	h.Clock.Advance(2 * time.Minute)
	mustStatus(t, h.API("GET", "/me", stale, nil), 200, "the stale session is still valid")
	if r := h.API("POST", "/me/identifiers", stale, map[string]any{"type": "email", "value": newAddr}); r.Status != 403 ||
		r.Str("code") != "recent_authentication_required" {
		t.Fatalf("identifier change without recent authentication: %d %s", r.Status, r.Raw)
	}
	h.App.D.Cfg.Security.RecentAuthWindow = prev

	tok := f.AccountToken("bob").Tokens.Str("access_token")
	add := f.must(h.API("POST", "/me/identifiers", tok, map[string]any{"type": "email", "value": newAddr}), 201, "add identifier")
	id := add.Str("id")
	if add.Get("verified") != false {
		t.Fatalf("changed identifier verified automatically: %s", add.Raw)
	}
	mustStatus(t, h.API("POST", "/me/identifiers/"+id+"/primary", tok, nil), 422, "unverified identifier made primary")
	h.SetPassword(newAddr, h.passwords[oldAddr])
	acct.Identifier = newAddr
	acct.ExpectFail = true
	if lr := h.Login(acct); lr.Code != "" {
		t.Fatal("an unverified address signed in")
	}

	// Proof of control: a code sent to the new address. A wrong code proves
	// nothing; the right one verifies it.
	ch := f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": id}), 201, "challenge")
	code := CodeFrom(h.Mail(newAddr, "email_verification"))
	if code == "" || CodeFrom(h.Mail(oldAddr, "email_verification")) == code {
		t.Fatalf("verification code not sent (only) to the new address: %q", code)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	mustStatus(t, h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok, map[string]any{"code": wrong}), 400, "wrong code")
	if h.Mail(oldAddr, "identifier_changed") != "" {
		t.Fatal("change notice sent before the new address was proven")
	}
	for _, it := range f.must(h.API("GET", "/me/identifiers", tok, nil), 200, "identifiers").Get("items").([]any) {
		if m := it.(map[string]any); m["id"] == id && m["verified"] != false {
			t.Fatalf("identifier verified by a wrong code: %v", m)
		}
	}
	mustStatus(t, h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok, map[string]any{"code": code}), 200, "verify")

	// The old contact is notified; the new address does not get the notice.
	if !strings.Contains(h.Mail(oldAddr, "identifier_changed"), "email") || h.Mail(newAddr, "identifier_changed") != "" {
		t.Fatal("the old contact was not notified of the verified change")
	}
	acct.ExpectFail = false
	lr := h.Login(acct)
	if f.must(h.API("GET", "/me", lr.Tokens.Str("access_token"), nil), 200, "me").Str("id") != f.Users["bob"] {
		t.Fatal("verified address signs in to another account")
	}
}

// TestMultipleVerifiedIdentifiers covers USR-008: an account holds several
// verified email addresses, each of which signs in; exactly one is primary
// and only a verified one can become primary; a verified address belongs to
// one account, and an unverified claim never blocks its owner; password-reset
// codes go to the primary verified address whichever address was typed;
// removing the primary promotes another verified address, and the last
// verified sign-in identifier cannot be removed.
func TestMultipleVerifiedIdentifiers(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	const mainAddr, work, home = "bob@example.test", "bob.work@example.test", "bob.home@example.test"
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	add := func(tok, addr string) string {
		t.Helper()
		return f.must(h.API("POST", "/me/identifiers", tok, map[string]any{"type": "email", "value": addr}), 201, "add "+addr).Str("id")
	}
	verify := func(tok, id, addr string) *Resp {
		t.Helper()
		ch := f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": id}), 201, "challenge "+addr)
		return h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok,
			map[string]any{"code": CodeFrom(h.Mail(addr, "email_verification"))})
	}
	list := func() map[string]map[string]any {
		t.Helper()
		out := map[string]map[string]any{}
		for _, it := range f.must(h.API("GET", "/me/identifiers", bob, nil), 200, "identifiers").Get("items").([]any) {
			m := it.(map[string]any)
			out[m["value"].(string)] = m
		}
		return out
	}
	primaryEmail := func(ids map[string]map[string]any) []string {
		var out []string
		for v, m := range ids {
			if m["type"] == "email" && m["is_primary"] == true {
				out = append(out, v)
			}
		}
		return out
	}

	// Alice claims one of bob's addresses first; unverified, it blocks nobody.
	aliceClaim := add(alice, home)
	workID, homeID := add(bob, work), add(bob, home)
	mustStatus(t, h.API("POST", "/me/identifiers/"+workID+"/primary", bob, nil), 422, "unverified address made primary")
	mustStatus(t, verify(bob, workID, work), 200, "verify work")
	mustStatus(t, verify(bob, homeID, home), 200, "verify home despite another account's unverified claim")
	ids := list()
	for _, addr := range []string{mainAddr, work, home} {
		if ids[addr]["verified"] != true {
			t.Fatalf("%s not verified: %v", addr, ids[addr])
		}
	}
	if p := primaryEmail(ids); len(p) != 1 || p[0] != mainAddr {
		t.Fatalf("primary email after adding addresses: %v", p)
	}
	// Each verified address signs in to the same account.
	h.SetPassword(work, h.passwords[mainAddr])
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: work})
	if f.must(h.API("GET", "/me", lr.Tokens.Str("access_token"), nil), 200, "me").Str("id") != f.Users["bob"] {
		t.Fatal("second verified address signs in to another account")
	}

	// Promotion moves the single primary.
	mustStatus(t, h.API("POST", "/me/identifiers/"+workID+"/primary", bob, nil), 204, "promote")
	if p := primaryEmail(list()); len(p) != 1 || p[0] != work {
		t.Fatalf("primary email after promotion: %v", p)
	}

	// Recovery: a reset requested through any address goes to the primary one.
	h.Clock.Advance(31 * time.Second) // per-address send cooldown
	f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": home}), 202, "password reset")
	if h.Mail(work, "password_reset") == "" || h.Mail(home, "password_reset") != "" || h.Mail(mainAddr, "password_reset") != "" {
		t.Fatal("password-reset code not sent to the primary verified address only")
	}

	// Uniqueness: the address bob verified cannot be verified by alice.
	h.Clock.Advance(31 * time.Second)
	if r := verify(alice, aliceClaim, home); r.Status != 409 {
		t.Fatalf("a second account verified an address already verified: %d %s", r.Status, r.Raw)
	}

	// Removing the primary promotes another verified address; the last
	// verified sign-in identifier stays.
	mustStatus(t, h.API("DELETE", "/me/identifiers/"+workID, bob, nil), 204, "remove the primary")
	if p := primaryEmail(list()); len(p) != 1 || (p[0] != mainAddr && p[0] != home) {
		t.Fatalf("primary email after removing the primary: %v", p)
	}
	mustStatus(t, h.API("DELETE", "/me/identifiers/"+homeID, bob, nil), 204, "remove another address")
	ids = list()
	if p := primaryEmail(ids); len(p) != 1 || p[0] != mainAddr {
		t.Fatalf("primary email with one address left: %v", p)
	}
	mustStatus(t, h.API("DELETE", "/me/identifiers/"+ids["bob"]["id"].(string), bob, nil), 204, "remove the username")
	if r := h.API("DELETE", "/me/identifiers/"+ids[mainAddr]["id"].(string), bob, nil); r.Status != 409 || r.Str("code") != "last_sign_in_method" {
		t.Fatalf("last verified identifier removed: %d %s", r.Status, r.Raw)
	}
}

// TestAccountActivity covers USR-019: the owner sees recent sign-ins, sessions,
// authenticator activity, security changes and support access, minimized.
func TestAccountActivity(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	// A failed attempt from somewhere else, then a successful sign-in.
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	h.Step(tx, cont, "password", map[string]any{"password": "definitely-not-it"})
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Bobby"}), 200, "profile change")

	r := h.API("GET", "/me/activity?days=7", bob, nil)
	mustStatus(t, r, 200, "activity")
	types := func(section string) string {
		var out []string
		for _, ev := range r.Get(section).([]any) {
			out = append(out, ev.(map[string]any)["type"].(string))
		}
		return strings.Join(out, ",")
	}
	if s := types("sign_ins"); !strings.Contains(s, "authentication.succeeded") || !strings.Contains(s, "authentication.password.failed") {
		t.Fatalf("sign-ins: %s", s)
	}
	if len(r.Get("sessions").([]any)) == 0 || len(r.Get("authenticators").([]any)) == 0 {
		t.Fatalf("sessions/authenticators missing: %s", r.Raw)
	}
	for _, leak := range []string{"actor_id", "request_id", "metadata", f.Users["alice"], "session_id"} {
		if strings.Contains(string(r.Raw), `"`+leak+`"`) {
			t.Fatalf("activity leaks %q: %s", leak, r.Raw)
		}
	}
	if r := h.API("GET", "/me/activity?days=9999", bob, nil); r.Status != 400 && r.Status != 422 {
		t.Fatalf("unbounded window accepted: %d", r.Status)
	}
	// Another user's activity is never visible.
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	if r := h.API("GET", "/me/activity", alice, nil); strings.Contains(string(r.Raw), "authentication.password.failed") {
		t.Fatalf("alice sees bob's failures: %s", r.Raw)
	}
}

// TestPermittedIdentifiers covers REG-002/AUT-005: only the realm's permitted
// identifier types are accepted, with a refusal that depends on the input's
// form and never on account existence.
func TestPermittedIdentifiers(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Login.Identifiers = []string{"email"} }), 200, "email only")
	identify := func(id string) *Resp {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		return h.Step(start.Str("transaction_id"), cont, "identify", map[string]any{"identifier": id})
	}
	known, unknown := identify("bob"), identify("nobody-at-all")
	if known.Status != 422 || unknown.Status != 422 || string(known.Raw[:40]) != string(unknown.Raw[:40]) {
		t.Fatalf("username sign-in not refused uniformly: %d %s / %d %s", known.Status, known.Raw, unknown.Status, unknown.Raw)
	}
	mustStatus(t, identify("bob@example.test"), 200, "email identifier")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Login.Identifiers = []string{"fingerprint"} }), 422, "unknown identifier type")
}

// TestPasswordChangePolicy covers CRED-006: recent authentication, an MFA
// session for MFA-enrolled accounts, revocation of other sessions per the
// documented rule, and an owner notice.
func TestPasswordChangePolicy(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	pw := h.passwords["bob@example.test"]
	newPw := "bob chose a brand new passphrase 2026"
	h.Clock.Advance(h.App.D.Cfg.Security.RecentAuthWindow + time.Minute)
	if r := h.API("POST", "/me/password", bob, map[string]any{"current_password": pw, "new_password": newPw}); r.Status != 403 && r.Status != 401 {
		t.Fatalf("password change without recent authentication: %d %s", r.Status, r.Raw)
	}
	bob = f.AccountToken("bob").Tokens.Str("access_token")
	other := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/password", bob, map[string]any{"current_password": pw, "new_password": newPw}), 200, "change password")
	h.SetPassword("bob@example.test", newPw)
	h.SetPassword("bob", newPw)
	if r := h.API("GET", "/me", other, nil); r.Status != 401 {
		t.Fatalf("other session survived the password change (realm rule revoke_sessions_on_change): %d", r.Status)
	}
	mustStatus(t, h.API("GET", "/me", bob, nil), 200, "the changing session stays")
	if h.Mail("bob@example.test", "password_changed") == "" {
		t.Fatal("owner not notified of the password change")
	}
	// After MFA enrollment, a single-factor session cannot change the password.
	single := f.AccountToken("bob").Tokens.Str("access_token")
	f.EnrollTOTP("bob")
	r := h.API("POST", "/me/password", single, map[string]any{"current_password": newPw, "new_password": "yet another long passphrase 2026"})
	if r.Status != 403 || r.Str("code") != "step_up_required" {
		t.Fatalf("single-factor session changed an MFA account's password: %d %s", r.Status, r.Raw)
	}
}

// TestFactorAndMethodPolicy covers MFA-005 (factors the realm does not allow
// never satisfy MFA), TEN-012 (organization sign-in methods) and CRED-010
// (bounded password history).
func TestFactorAndMethodPolicy(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	f.EnrollTOTP("bob")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Password.HistoryCount = 500 }), 422, "unbounded password history")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.AllowedFactors = []string{"webauthn", "recovery_code"} }), 200, "TOTP not allowed")
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if hasAction(st, "totp") || hasAction(st, "enroll_totp") {
		t.Fatalf("disallowed factor offered: %s", st.Raw)
	}
	if r := h.Step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("bob@example.test")}); r.Status < 400 {
		t.Fatalf("disallowed TOTP accepted: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.AllowedFactors = nil }), 200, "reset factors")
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, f.AdminAPI("PATCH", "/organizations/"+f.Acme, map[string]any{"policy": map[string]any{"allowed_login_methods": []string{"passkey"}}}), 428,
		"policy change without If-Match")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_login_methods": []string{"fax"}}}}),
		422, "unknown method")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_login_methods": []string{"passkey"}}}}), 200, "passkeys only")
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "alice@example.test", ExpectFail: true})
	if lr.State.Str("error") != "login_method_not_allowed" {
		t.Fatalf("password sign-in into a passkey-only organization: %s", lr.State.Raw)
	}
}

// TestScheduledAssistedRecovery covers MFA-009: with a cooling-off period and
// second-operator approval configured, assisted recovery is announced to the
// owner at once, waits, needs an independent approver, and can be cancelled.
func TestScheduledAssistedRecovery(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	ctx := context.Background()
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Recovery.CoolingOffHours = 24; p.Recovery.RequireApproval = true }), 200, "recovery policy")
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "recovery-approver",
		"permissions": []string{"support.recovery.assist"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	req := f.must(f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/recovery-requests", map[string]any{"reason": "lost phone, identity verified by video call",
		"evidence_reference": "ticket 5521", "reset_mfa": true}), 202, "schedule")
	if req.Str("status") != "recovery_scheduled" {
		t.Fatalf("recovery not scheduled: %s", req.Raw)
	}
	if h.Mail("bob@example.test", "recovery_notice") == "" {
		t.Fatal("owner not warned at scheduling time")
	}
	mustStatus(t, h.API("GET", "/me", bob, nil), 200, "sessions untouched during cooling-off")
	mustStatus(t, f.AdminAPI("POST", "/assisted-recoveries/"+req.Str("recovery_id")+"/approve", nil), 403, "requester approving own request")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	// Approving a factor reset needs the same authority as requesting one.
	mustStatus(t, h.API("POST", "/assisted-recoveries/"+req.Str("recovery_id")+"/approve", carol, nil), 403, "approval without credential authority")
	creds := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "credential-manager",
		"permissions": []string{"realm.users.credentials.manage"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": creds, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	mustStatus(t, h.API("POST", "/assisted-recoveries/"+req.Str("recovery_id")+"/approve", carol, nil), 204, "independent approval")
	if n, _ := h.App.Auth.ExecuteDueRecoveries(ctx); n != 0 {
		t.Fatal("recovery ran before the cooling-off period ended")
	}
	h.Clock.Advance(25 * time.Hour)
	if n, err := h.App.Auth.ExecuteDueRecoveries(ctx); err != nil || n != 1 {
		t.Fatalf("due recovery did not run: %d %v", n, err)
	}
	if r := h.API("GET", "/me", bob, nil); r.Status != 401 {
		t.Fatalf("sessions survived assisted recovery: %d", r.Status)
	}
	// A second request is cancelled by the owner.
	f.ReloginAdmin()
	bob = f.AccountToken("bob").Tokens.Str("access_token")
	second := f.must(f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/recovery-requests", map[string]any{"reason": "suspicious call claiming to be bob",
		"evidence_reference": "ticket 5522"}), 202, "schedule again")
	pending := f.must(h.API("GET", "/me/assisted-recoveries", bob, nil), 200, "pending")
	if len(pending.Get("items").([]any)) != 1 {
		t.Fatalf("owner cannot see the scheduled recovery: %s", pending.Raw)
	}
	mustStatus(t, h.API("POST", "/me/assisted-recoveries/"+second.Str("recovery_id")+"/cancel", bob, nil), 204, "owner cancels")
	h.Clock.Advance(25 * time.Hour)
	if n, _ := h.App.Auth.ExecuteDueRecoveries(ctx); n != 0 {
		t.Fatal("cancelled recovery executed")
	}
}

// TestRegistrationApprovalQueue covers REG-008: self-registrations wait for a
// reviewer after email verification; approval enables sign-in, denial
// suspends the account, and both are audited.
func TestRegistrationApprovalQueue(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.Mode = "public"; p.Registration.RequireApproval = true }), 200, "approval queue")
	register := func(email string) *Resp {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid", Resources: []string{h.Realm.Issuer + "/userinfo"}})
		tx := start.Str("transaction_id")
		pw := strings.Split(email, "@")[0] + " has a long passphrase 2026"
		mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": tx, "email": email,
			"password": pw}, Headers: map[string]string{"X-Transaction-Token": cont}}), 201, "register "+email)
		h.SetPassword(email, pw)
		return h.Step(tx, cont, "otp/verify", map[string]any{"code": CodeFrom(h.Mail(email, "email_verification"))})
	}
	st := register("zoe@example.test")
	if st.Str("error") != "registration_pending_approval" {
		t.Fatalf("registration completed without review: %s", st.Raw)
	}
	queue := f.must(f.AdminAPI("GET", "/registration-approvals?state=pending", nil), 200, "queue")
	items := queue.Get("items").([]any)
	if len(items) != 1 || strings.Contains(string(queue.Raw), "zoe@example.test") {
		t.Fatalf("queue (address must be masked): %s", queue.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/registration-approvals/"+items[0].(map[string]any)["id"].(string)+"/decision", map[string]any{"approve": true}), 204, "approve")
	mustStatus(t, h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "zoe@example.test"}).Tokens, 200, "approved account signs in")
	register("yan@example.test")
	queue = f.must(f.AdminAPI("GET", "/registration-approvals?state=pending", nil), 200, "queue")
	mustStatus(t, f.AdminAPI("POST", "/registration-approvals/"+queue.Get("items").([]any)[0].(map[string]any)["id"].(string)+"/decision",
		map[string]any{"approve": false, "reason": "not an employee"}), 204, "deny")
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "yan@example.test", ExpectFail: true})
	if lr.Tokens != nil && lr.Tokens.Status == 200 {
		t.Fatal("denied registration signed in")
	}
	if h.Mail("yan@example.test", "registration_review") == "" {
		t.Fatal("applicant not told the outcome")
	}
}

// TestGuestIdentities covers REG-010: low-privilege guest identities that can
// upgrade in place without taking over another account.
func TestGuestIdentities(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	ctx := context.Background()
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	{
		start, _, cont := h.StartTx(acct)
		if st := h.Step(start.Str("transaction_id"), cont, "guest", nil); st.Status < 400 {
			t.Fatalf("guest access while disabled: %d", st.Status)
		}
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.AllowGuests = true }), 200, "enable guests")
	start, verifier, cont := h.StartTx(acct)
	tx := start.Str("transaction_id")
	st := h.Step(tx, cont, "guest", nil)
	if st.Str("redirect_to") == "" {
		t.Fatalf("guest sign-in did not complete: %s", st.Raw)
	}
	u, _ := url.Parse(st.Str("redirect_to"))
	tokens := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
		"code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1/callback"}, "resource": {acct.Resources[0]}, "client_id": {acct.ClientID}}})
	mustStatus(t, tokens, 200, "guest tokens")
	tok := tokens.Str("access_token")
	me := f.must(h.API("GET", "/me", tok, nil), 200, "guest me")
	guestID := me.Str("id")
	if claims := jwtPayload(tok); claims["acr"] != nil && claims["acr"] != "urn:proudauth:acr:anonymous" {
		t.Fatalf("guest assurance: %v", claims["acr"])
	}
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": guestID}), 422, "guest joins organization")
	// An upgrade is a registration: a closed or domain-restricted realm refuses
	// it like any other sign-up.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.Mode = "closed" }), 200, "close registration")
	mustStatus(t, h.API("POST", "/me/upgrade", tok, map[string]any{"email": "sneaky@example.test", "password": "guest passphrase that is long 2026"}),
		403, "upgrade while registration is closed")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Registration.Mode = "domain_restricted"
		p.Registration.AllowedDomains = []string{"corp.test"}
	}),
		200, "restrict registration")
	mustStatus(t, h.API("POST", "/me/upgrade", tok, map[string]any{"email": "sneaky@example.test", "password": "guest passphrase that is long 2026"}),
		403, "upgrade outside the allowed domains")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.Mode = "public"; p.Registration.AllowedDomains = nil }), 200, "reopen registration")
	// Upgrading to an address that already belongs to bob never links bob.
	up := h.API("POST", "/me/upgrade", tok, map[string]any{"email": "bob@example.test", "password": "guest passphrase that is long 2026"})
	mustStatus(t, up, 202, "upgrade to an existing address")
	ch := f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": up.Str("identifier_id")}), 201, "challenge")
	code := CodeFrom(h.Mail("bob@example.test", "identifier_challenge"))
	if code == "" {
		code = CodeFrom(h.Mail("bob@example.test", "email_verification"))
	}
	if r := h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok, map[string]any{"code": code}); r.Status < 400 {
		t.Fatalf("guest verified an address owned by another account: %d %s", r.Status, r.Raw)
	}
	var stillGuest bool
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT is_guest FROM users WHERE id=$1`, guestID).Scan(&stillGuest)
	if !stillGuest {
		t.Fatal("guest upgraded by claiming another account's address")
	}
	// A fresh address upgrades the same account in place.
	up = h.API("POST", "/me/upgrade", tok, map[string]any{"email": "newbie@example.test", "password": "guest passphrase that is long 2026"})
	mustStatus(t, up, 202, "upgrade")
	ch = f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": up.Str("identifier_id")}), 201, "challenge")
	code = CodeFrom(h.Mail("newbie@example.test", "identifier_challenge"))
	if code == "" {
		code = CodeFrom(h.Mail("newbie@example.test", "email_verification"))
	}
	mustStatus(t, h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok, map[string]any{"code": code}), 200, "verify")
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT is_guest FROM users WHERE id=$1`, guestID).Scan(&stillGuest)
	if stillGuest {
		t.Fatal("verified upgrade left the account a guest")
	}
	h.SetPassword("newbie@example.test", "guest passphrase that is long 2026")
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: "newbie@example.test"})
	mustStatus(t, lr.Tokens, 200, "upgraded account signs in with its password")
	if f.must(h.API("GET", "/me", lr.Tokens.Str("access_token"), nil), 200, "me").Str("id") != guestID {
		t.Fatal("upgrade changed the account identity")
	}

	// In realms that review registrations, a completed upgrade waits for a
	// reviewer: the guest session ends and sign-in is refused until approval.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.RequireApproval = true }), 200, "approval queue")
	start, verifier, cont = h.StartTx(acct)
	st = h.Step(start.Str("transaction_id"), cont, "guest", nil)
	u, _ = url.Parse(st.Str("redirect_to"))
	tok = f.must(h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
		"code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1/callback"}, "resource": {acct.Resources[0]}, "client_id": {acct.ClientID}}}),
		200, "second guest").Str("access_token")
	up = f.must(h.API("POST", "/me/upgrade", tok, map[string]any{"email": "queued@example.test", "password": "queued passphrase that is long 2026"}), 202, "upgrade")
	ch = f.must(h.API("POST", "/verification-challenges", tok, map[string]any{"identifier_id": up.Str("identifier_id")}), 201, "challenge")
	code = CodeFrom(h.Mail("queued@example.test", "identifier_challenge"))
	if code == "" {
		code = CodeFrom(h.Mail("queued@example.test", "email_verification"))
	}
	mustStatus(t, h.API("POST", "/verification-challenges/"+ch.Str("challenge_id")+"/consume", tok, map[string]any{"code": code}), 200, "verify")
	if r := h.API("GET", "/me", tok, nil); r.Status != 401 {
		t.Fatalf("guest session survived an upgrade awaiting approval: %d", r.Status)
	}
	queue := f.must(f.AdminAPI("GET", "/registration-approvals?state=pending", nil), 200, "queue")
	if len(queue.Get("items").([]any)) != 1 {
		t.Fatalf("upgrade not queued for review: %s", queue.Raw)
	}
	h.SetPassword("queued@example.test", "queued passphrase that is long 2026")
	if lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "queued@example.test", ExpectFail: true}); lr.Tokens != nil && lr.Tokens.Status == 200 {
		t.Fatal("upgraded account signed in before approval")
	}
}

// TestAccountMerge covers USR-011: an administrator proposes a merge with a
// reviewed plan, both owners confirm, execution moves identifiers and
// memberships without copying roles, and the source becomes an alias.
func TestAccountMerge(t *testing.T) {
	h := NewHarness(t)
	f := fixtureOn(t, h)
	ctx := context.Background()
	f.CreateUser("maya")
	f.CreateUser("milo")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["maya"]}), 201, "maya in acme")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/members", map[string]any{"user_id": f.Users["milo"],
		"role_ids": []string{f.Roles["orders-viewer"]}}), 201, "milo in globex")
	propose := func() *Resp {
		return f.AdminAPI("POST", "/users/"+f.Users["maya"]+"/merges", map[string]any{"source_user_id": f.Users["milo"], "reason": "same person, two sign-ups (ticket 77)"})
	}
	// Declined, cancelled and lapsed proposals never block a new one.
	first := f.must(propose(), 201, "first proposal")
	mustStatus(t, propose(), 409, "second pending proposal")
	milo := f.AccountToken("milo").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/account-merges/"+first.Str("id")+"/decline", milo, nil), 204, "milo declines")
	second := f.must(propose(), 201, "proposal after a decline")
	mustStatus(t, f.AdminAPI("POST", "/account-merges/"+second.Str("id")+"/cancel", nil), 204, "administrator cancels")
	third := f.must(propose(), 201, "proposal after a cancel")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE account_merges SET expires_at=now() - interval '1 minute' WHERE id=$1`, third.Str("id")); err != nil {
		t.Fatal(err)
	}
	prop := propose()
	mustStatus(t, prop, 201, "proposal after the previous one lapsed")
	id := prop.Str("id")
	plan := prop.Get("plan").(map[string]any)
	if len(plan["move_memberships_as_member"].([]any)) != 1 || plan["source_roles_for_review"].(map[string]any)[f.Globex] == nil {
		t.Fatalf("plan: %s", prop.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/account-merges/"+id+"/execute", nil), 409, "execute before both owners confirm")
	for _, u := range []string{"maya", "milo"} {
		tok := f.AccountToken(u).Tokens.Str("access_token")
		list := f.must(h.API("GET", "/me/account-merges", tok, nil), 200, "pending merges")
		if len(list.Get("items").([]any)) != 1 {
			t.Fatalf("%s cannot see the merge: %s", u, list.Raw)
		}
		mustStatus(t, h.API("POST", "/me/account-merges/"+id+"/confirm", tok, nil), 204, u+" confirms")
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/account-merges/"+id+"/confirm", bob, nil), 404, "unrelated user")
	f.ReloginAdmin()
	done := f.AdminAPI("POST", "/account-merges/"+id+"/execute", nil)
	mustStatus(t, done, 200, "execute")
	var mayaHasMiloEmail, viewerRoles, aliasRows int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM user_identifiers WHERE user_id=$1 AND canonical_value='milo@example.test'`, f.Users["maya"]).Scan(&mayaHasMiloEmail)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.subject_id=$1 AND r.name='orders-viewer'`,
		f.Users["maya"]).Scan(&viewerRoles)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM subject_aliases WHERE alias_id=$1 AND user_id=$2`, f.Users["milo"], f.Users["maya"]).Scan(&aliasRows)
	if mayaHasMiloEmail != 1 || viewerRoles != 0 || aliasRows != 1 {
		t.Fatalf("merge effects: identifier=%d copied roles=%d alias=%d", mayaHasMiloEmail, viewerRoles, aliasRows)
	}
	alias := f.must(f.AdminAPI("GET", "/subject-aliases/"+f.Users["milo"], nil), 200, "alias")
	if alias.Str("user_id") != f.Users["maya"] {
		t.Fatalf("alias lookup: %s", alias.Raw)
	}
	var events int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_type='user.merged'`).Scan(&events)
	if events != 1 {
		t.Fatal("applications not told about the merge")
	}
	mustStatus(t, f.AdminAPI("POST", "/account-merges/"+id+"/execute", nil), 409, "replay")
}
