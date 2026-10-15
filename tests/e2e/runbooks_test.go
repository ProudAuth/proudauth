package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/server"
	"github.com/proudauth/proudauth/internal/webhooks"
	"github.com/proudauth/proudauth/internal/worker"
)

// Runbook tests (OPS-016): each test executes the API calls a runbook in
// docs/operations/incidents.md documents, in the documented order, and checks
// the documented outcome. Steps that need infrastructure outside the process
// (a real KMS, an SMS gateway, the operator's file system and restarts) are
// simulated in-process where the code allows it and say so.

// runbookControl calls the emergency-control endpoint (SEC-020).
func runbookControl(f *Fixture, typ, id, action, reason string) *Resp {
	f.H.t.Helper()
	return f.AdminAPI("POST", "/emergency/controls", map[string]any{"target_type": typ, "target_id": id, "action": action, "reason": reason})
}

// TestRunbookOrganizationOwnerRecovery covers OPS-016 for "Organization owner
// recovery", step 2 (incidents.md): a realm administrator finds the new
// owner's membership, transfers ownership to that active member (owner role,
// audit organization.ownership.transferred), and then removes the former
// owner's owner role through the role-assignment API, which last-owner
// protection refused before the transfer.
func TestRunbookOrganizationOwnerRecovery(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ownerOf := func(user string) string {
		t.Helper()
		list := f.must(f.AdminAPI("GET", "/role-assignments?subject_type=user&subject_id="+f.Users[user], nil), 200, "assignments")
		for _, it := range list.Get("items").([]any) {
			a := it.(map[string]any)
			scope, _ := a["scope"].(map[string]any)
			if a["role_id"] == f.Roles["owner"] && scope["id"] == f.Acme {
				return a["id"].(string)
			}
		}
		return ""
	}
	// Alice, Acme's only owner, has lost access; last-owner protection keeps
	// her owner role in place.
	aliceOwner := ownerOf("alice")
	if aliceOwner == "" || ownerOf("bob") != "" {
		t.Fatal("precondition: alice is Acme's only owner")
	}
	if r := f.AdminAPI("DELETE", "/role-assignments/"+aliceOwner, nil); r.Status != 409 {
		t.Fatalf("last owner's role removed before a transfer: %d %s", r.Status, r.Raw)
	}
	// identity-cli api GET /organizations/{org}/members — find the new owner.
	members := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme+"/members", nil), 200, "members")
	bobMembership := ""
	for _, it := range members.Get("items").([]any) {
		if m := it.(map[string]any); m["user_id"] == f.Users["bob"] {
			bobMembership, _ = m["id"].(string)
		}
	}
	if bobMembership != f.MemberAcme["bob"] {
		t.Fatalf("bob's membership not listed: %s", members.Raw)
	}
	// identity-cli api POST /organizations/{org}/ownership-transfers '{"membership_id":"mem_..."}'
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/ownership-transfers", map[string]any{"membership_id": bobMembership}), 200, "ownership transfer")
	if ownerOf("bob") == "" {
		t.Fatal("the new owner did not receive the owner role")
	}
	if ownerOf("alice") == "" {
		t.Fatal("a realm administrator's transfer must not release the former owner's role by itself")
	}
	if n := auditCount(t, h, "organization.ownership.transferred", ""); n != 1 {
		t.Fatalf("organization.ownership.transferred events: %d", n)
	}
	// The former owner is no longer the last owner: her role can be removed.
	f.must(f.AdminAPI("DELETE", "/role-assignments/"+aliceOwner, nil), 204, "remove the former owner's role")
	if ownerOf("alice") != "" {
		t.Fatal("former owner kept the owner role")
	}
	// The new owner administers the organization.
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("GET", "/organizations/"+f.Acme+"/members", bob, nil), 200, "new owner administers the organization")
	// release_current_owner releases only the caller's own ownership: an
	// owner handing over to another member leaves the organization with
	// exactly the new owner.
	if r := f.AdminAPI("DELETE", "/role-assignments/"+ownerOf("bob"), nil); r.Status != 409 {
		t.Fatalf("new sole owner's role removable: %d %s", r.Status, r.Raw)
	}
}

// runbookFedLogin runs a federated sign-in through the fake upstream and
// returns the transaction state after the callback.
func runbookFedLogin(t *testing.T, h *Harness, idp *fakeIdP, provider string, claims map[string]any) (*Resp, *Resp) {
	t.Helper()
	idp.next = claims
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	txID := start.Str("transaction_id")
	st := h.Step(txID, cont, "federation/start", map[string]any{"provider": provider})
	if st.Status != 200 {
		return st, nil
	}
	if cb := h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}); cb.Status != 200 {
		return cb, nil
	}
	return st, h.Step(txID, cont, "resume", nil)
}

// TestRunbookConnectorCompromise covers OPS-016 for "Compromised connector"
// (incidents.md) beyond the client and organization controls of
// TestEmergencyControls: step 1 switches off an upstream identity provider, a
// pre-action hook, a webhook subscription and a service principal with the
// audited emergency control (each refusing or stopping as documented, and
// reversible); step 2 finds the sign-ins through the identity provider in the
// audit log, revokes those users' sessions, removes the link the attacker
// created and sends the client secret again with If-Match before enabling the
// connection; step 3 rotates the webhook signing secret; step 4 checks hook
// diagnostics and replaces the hook (delete and re-create: a new secret).
func TestRunbookConnectorCompromise(t *testing.T) {
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	ctx := context.Background()
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	from := h.Clock.Now().Add(-time.Minute).UTC().Format(time.RFC3339)

	// --- Upstream identity provider. ---
	conn := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "corp", "display_name": "Corp SSO", "issuer": idp.srv.URL,
		"client_secret": "upstream-secret", "config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true}), 201, "connection")
	connID := conn.Str("id")
	_, st := runbookFedLogin(t, h, idp, "corp", map[string]any{"sub": "u-mallory", "email": "mallory@corp.test", "email_verified": true, "name": "Mallory"})
	if st == nil || st.Str("redirect_to") == "" {
		t.Fatalf("federated sign-in before the incident: %v", st)
	}
	var mallory string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE canonical_value='mallory@corp.test'`).Scan(&mallory); err != nil {
		t.Fatalf("JIT account: %v", err)
	}
	session := f.must(f.AdminAPI("GET", "/users/"+mallory+"/sessions", nil), 200, "sessions")
	if len(session.Get("items").([]any)) == 0 {
		t.Fatalf("no session from the federated sign-in: %s", session.Raw)
	}
	// The attacker also linked an upstream identity to bob's existing account
	// (through a session of bob's).
	bobLink := f.AccountToken("bob").Tokens.Str("access_token")
	idp.next = map[string]any{"sub": "u-evil", "email": "evil@corp.test", "email_verified": true}
	link := f.must(h.API("POST", "/me/linked-identities", bobLink, map[string]any{"provider": "corp"}), 200, "start link")
	linkCB := f.must(h.Do(Req{Method: "GET", Path: idp.browse(t, link.Str("authorization_url"))}), 200, "link callback")
	f.must(h.API("POST", "/me/linked-identities/confirm", bobLink, map[string]any{"code": linkCB.Str("link_code")}), 201, "confirm link")

	// An upstream round trip is in flight when the operator acts.
	idp.next = map[string]any{"sub": "u-mallory", "email": "mallory@corp.test", "email_verified": true}
	inflight, _, inflightCont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	inflightTx := inflight.Str("transaction_id")
	pending := f.must(h.Step(inflightTx, inflightCont, "federation/start", map[string]any{"provider": "corp"}), 200, "federation start")

	// Step 1: switch the connection off; sign-ins and links through it stop.
	f.must(runbookControl(f, "identity_provider", connID, "disable", "INC-7 upstream compromise"), 200, "disable connection")
	if r, _ := runbookFedLogin(t, h, idp, "corp", map[string]any{"sub": "u-mallory"}); r.Status != 422 || !strings.Contains(string(r.Raw), "disabled connection") {
		t.Fatalf("sign-in through a disabled connection: %d %s", r.Status, r.Raw)
	}
	if r := h.API("POST", "/me/linked-identities", bobLink, map[string]any{"provider": "corp"}); r.Status != 422 || !strings.Contains(string(r.Raw), "disabled connection") {
		t.Fatalf("link through a disabled connection: %d %s", r.Status, r.Raw)
	}
	// The round trip started before the control cannot complete through the
	// disabled connection either.
	cb := h.Do(Req{Method: "GET", Path: idp.browse(t, pending.Str("external_redirect"))})
	if cb.Str("status") != "error" || cb.Str("error") != "connection_disabled" {
		t.Fatalf("in-flight callback through a disabled connection: %d %s", cb.Status, cb.Raw)
	}
	if st := h.Step(inflightTx, inflightCont, "resume", nil); st.Str("redirect_to") != "" {
		t.Fatalf("in-flight sign-in completed through a disabled connection: %s", st.Raw)
	}
	// Step 2: sign-ins in the window, the accounts created just in time, and
	// the links.
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=federation.login.succeeded&from="+url.QueryEscape(from)+"&to="+
		url.QueryEscape(h.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339)), nil), 200, "federated sign-ins")
	items := ev.Get("items").([]any)
	if len(items) != 1 {
		t.Fatalf("federated sign-ins in the window: %s", ev.Raw)
	}
	if e := items[0].(map[string]any); jsonString(e["metadata"]) == "" || !strings.Contains(jsonString(e), connID) && !strings.Contains(jsonString(e), "corp") {
		t.Fatalf("sign-in event does not name the connection: %v", e)
	}
	if !strings.Contains(string(ev.Raw), mallory) || !strings.Contains(string(ev.Raw), `"created":true`) {
		t.Fatalf("sign-in event does not name the account it created just in time: %s", ev.Raw)
	}
	linked := f.must(f.AdminAPI("GET", "/audit-events?type=federation.identity.linked", nil), 200, "links")
	if !strings.Contains(string(linked.Raw), mallory) || !strings.Contains(string(linked.Raw), f.Users["bob"]) {
		t.Fatalf("links not identifiable from the link events: %s", linked.Raw)
	}
	for _, u := range []string{mallory, f.Users["bob"]} {
		f.must(f.AdminAPI("POST", "/users/"+u+"/revoke-sessions", map[string]any{}), 200, "revoke the account's sessions")
		for _, it := range f.must(f.AdminAPI("GET", "/users/"+u+"/sessions", nil), 200, "sessions").Get("items").([]any) {
			if s := it.(map[string]any); s["state"] == "active" {
				t.Fatalf("session still active: %v", s)
			}
		}
	}
	if r := h.API("GET", "/me", bobLink, nil); r.Status != 401 {
		t.Fatalf("revoked session still usable: %d", r.Status)
	}
	// The link the attacker added to bob's account is removed.
	links := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"]+"/linked-identities", nil), 200, "linked identities")
	if len(links.Get("items").([]any)) != 1 {
		t.Fatalf("linked identities: %s", links.Raw)
	}
	f.must(f.AdminAPI("DELETE", "/users/"+f.Users["bob"]+"/linked-identities/"+links.Get("items").([]any)[0].(map[string]any)["id"].(string), nil), 204, "remove link")
	if n := len(f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"]+"/linked-identities", nil), 200, "links").Get("items").([]any)); n != 0 {
		t.Fatalf("link not removed: %d", n)
	}
	// An account created just in time has no other sign-in method: its link
	// cannot be removed, so the account is suspended instead.
	jit := f.must(f.AdminAPI("GET", "/users/"+mallory+"/linked-identities", nil), 200, "linked identities").Get("items").([]any)
	if r := f.AdminAPI("DELETE", "/users/"+mallory+"/linked-identities/"+jit[0].(map[string]any)["id"].(string), nil); r.Status != 409 || r.Str("code") != "last_sign_in_method" {
		t.Fatalf("removing a just-in-time account's only link: %d %s", r.Status, r.Raw)
	}
	f.must(f.AdminAPI("POST", "/users/"+mallory+"/suspend", map[string]any{"reason": "INC-7 created through a compromised connection"}), 200, "suspend JIT account")
	// Send the client secret (rotated at the provider) again with If-Match,
	// keeping the connection disabled, then enable it.
	var before []byte
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT secret_ciphertext FROM identity_providers WHERE id=$1`, connID).Scan(&before)
	update := map[string]any{"alias": "corp", "display_name": "Corp SSO", "issuer": idp.srv.URL, "client_secret": "upstream-secret",
		"config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true, "state": "disabled"}
	mustStatus(t, f.AdminAPI("PUT", "/identity-providers/"+connID, update), 428, "secret replacement without If-Match")
	cur := f.must(f.AdminAPI("GET", "/identity-providers/"+connID, nil), 200, "connection")
	put := f.must(h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + connID, Token: f.AdminToken, JSON: update,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "send the client secret again")
	if put.Str("state") != "disabled" {
		t.Fatalf("secret replacement re-enabled the connection: %s", put.Raw)
	}
	var after []byte
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT secret_ciphertext FROM identity_providers WHERE id=$1`, connID).Scan(&after)
	if len(after) == 0 || string(after) == string(before) {
		t.Fatal("client secret not replaced")
	}
	f.must(runbookControl(f, "identity_provider", connID, "enable", "INC-7 secret rotated"), 200, "enable connection")
	if _, st := runbookFedLogin(t, h, idp, "corp", map[string]any{"sub": "u-zed", "email": "zed@corp.test", "email_verified": true}); st == nil || st.Str("redirect_to") == "" {
		t.Fatalf("sign-in after re-enabling: %v", st)
	}
	if _, st := runbookFedLogin(t, h, idp, "corp", map[string]any{"sub": "u-mallory", "email": "mallory@corp.test", "email_verified": true}); st == nil || st.Str("redirect_to") != "" {
		t.Fatalf("suspended just-in-time account signed in again: %v", st)
	}

	// --- Webhook receiver: disable (nothing queued while disabled), enable,
	// then rotate its signing secret (step 3). ---
	w := worker.New(h.App, "runbook")
	if _, err := w.DispatchOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	ep := newEndpoint(t)
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "crm feed", "destination_url": ep.srv.URL + "/feed",
		"event_types": []string{"organization.membership.added"}, "allow_private_network": true}), 201, "webhook")
	subID, oldSecret := sub.Str("subscription.id"), sub.Str("signing_secret")
	f.must(runbookControl(f, "webhook", subID, "disable", "INC-7 receiver compromised"), 200, "disable webhook")
	f.CreateUser("dora")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["dora"]}), 201, "member while disabled")
	deliverWebhooks(t, w)
	if n := len(ep.received("")); n != 0 {
		t.Fatalf("disabled subscription received %d deliveries", n)
	}
	f.must(runbookControl(f, "webhook", subID, "enable", "INC-7 receiver rebuilt"), 200, "enable webhook")
	deliverWebhooks(t, w)
	if n := len(ep.received("")); n != 0 {
		t.Fatalf("events published while disabled were delivered later: %d", n)
	}
	rot := f.must(f.AdminAPI("POST", "/webhooks/"+subID+"/rotate-secret", nil), 200, "rotate secret")
	if rot.Str("signing_secret") == "" || rot.Str("signing_secret") == oldSecret || rot.Get("previous_secret_valid_for_seconds") != float64(86400) {
		t.Fatalf("rotation: %s", rot.Raw)
	}
	f.CreateUser("eli")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["eli"]}), 201, "member after rotation")
	deliverWebhooks(t, w)
	if calls := ep.received("/feed"); len(calls) != 1 || len(strings.Fields(calls[0].Header.Get("Webhook-Signature"))) != 2 {
		t.Fatalf("delivery after re-enabling and rotation: %v", calls)
	}

	// --- Pre-action hook: diagnostics, disable (the restriction is lifted),
	// then delete and re-create with a new secret (step 4). ---
	hooks := newEndpoint(t)
	hooks.setAnswer(func(r *http.Request, body []byte) (int, http.Header, []byte) {
		if strings.Contains(string(body), "Staff") {
			return 200, nil, []byte(`{"allow":false,"errors":{"display_name":"may not impersonate staff"}}`)
		}
		return 200, nil, []byte(`{"allow":true}`)
	})
	hk := f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "profile", "kind": "profile.validation", "url": hooks.srv.URL + "/profile",
		"allow_private_network": true}), 201, "hook")
	hookID, hookSecret := hk.Str("hook.id"), hk.Str("signing_secret")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Staff Bob"}), 422, "hook enforces")
	diag := f.must(f.AdminAPI("GET", "/hooks/"+hookID+"/diagnostics", nil), 200, "hook diagnostics")
	if diag.Get("recent_invocations").(float64) < 1 {
		t.Fatalf("diagnostics: %s", diag.Raw)
	}
	f.must(runbookControl(f, "hook", hookID, "disable", "INC-7 hook endpoint compromised"), 200, "disable hook")
	calls := len(hooks.received(""))
	mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Staff Bob"}), 200, "disabled validation hook lifts its restriction")
	if len(hooks.received("")) != calls {
		t.Fatal("disabled hook still called")
	}
	f.must(f.AdminAPI("DELETE", "/hooks/"+hookID, nil), 204, "delete hook")
	re := f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "profile", "kind": "profile.validation", "url": hooks.srv.URL + "/profile",
		"allow_private_network": true}), 201, "re-create hook")
	if re.Str("signing_secret") == "" || re.Str("signing_secret") == hookSecret {
		t.Fatal("re-created hook kept the old secret")
	}
	mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Staff Robert"}), 422, "re-created hook enforces")
	last := hooks.received("/profile")
	if !validHookSignature(re.Str("signing_secret"), last[len(last)-1]) || validHookSignature(hookSecret, last[len(last)-1]) {
		t.Fatal("re-created hook not signed with its new secret only")
	}

	// --- Service principal: disable stops issuance and revokes its API keys. ---
	batch := f.Clients["batch"]
	key := f.must(f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": batch.SP, "name": "batch-key", "audience": f.BillingAud,
		"scopes": []string{"billing:read"}, "organization_id": f.Acme}), 201, "api key").Str("api_key")
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, key); in.Get("active") != true {
		t.Fatalf("api key before the control: %s", in.Raw)
	}
	f.must(runbookControl(f, "service_principal", batch.SP, "disable", "INC-7 workload credential leak"), 200, "disable service principal")
	if r := f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme); r.Status == 200 {
		t.Fatal("disabled service principal still obtained tokens")
	}
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, key); in.Get("active") != false {
		t.Fatalf("api key of a disabled service principal still active: %s", in.Raw)
	}
	f.must(runbookControl(f, "service_principal", batch.SP, "enable", "INC-7 resolved"), 200, "enable service principal")
	mustStatus(t, f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme), 200, "issuance after enabling")
	if in := h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, key); in.Get("active") != false {
		t.Fatal("revoked api key came back when the service principal was enabled")
	}
	// Every control is evidence in the emergency category.
	var n int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND category='emergency' AND reason_code LIKE 'INC-7%'`, h.Realm.ID).Scan(&n)
	if n < 7 {
		t.Fatalf("emergency controls not filed as emergency evidence: %d", n)
	}
}

// failingRelay returns an SMTP sender for a port nothing listens on: the
// deployment relay is down.
func failingRelay(t *testing.T) *notification.SMTPSender {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return &notification.SMTPSender{Host: "127.0.0.1", Port: port, TLSMode: "none"}
}

// TestRunbookEmailOutage covers OPS-016 for the email half of "Email or
// webhook delivery outage" (incidents.md): while the relay is down, the
// notification-job API shows state, attempts, the last error and a masked
// recipient, jobs retry with backoff (10 s x 2^attempt) for 5 attempts and
// then fail, jobs past their expiry become expired, the relay check names
// the failing stage; after the relay is fixed the check passes, a test
// message reaches the administrator's own verified address, and users
// request new codes that are delivered.
func TestRunbookEmailOutage(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	devSink, sender := h.App.Notify.DevSink, h.App.Notify.Email
	h.App.Notify.DevSink, h.App.Notify.Email = false, failingRelay(t)

	// Step 2: the relay check names the failing stage.
	chk := f.must(f.AdminAPI("POST", "/notification-settings/check", nil), 200, "relay check during the outage")
	if chk.Get("ok") != false || chk.Str("stage") != "connect" {
		t.Fatalf("relay check: %s", chk.Raw)
	}
	// Mail queued during the outage: a test message and a reset code.
	test := f.must(f.AdminAPI("POST", "/notification-tests", nil), 202, "test message").Str("job_id")
	f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"}), 202, "reset during the outage")
	h.Deliver()

	// Step 1: inspect the jobs.
	jobs := func() map[string]map[string]any {
		t.Helper()
		out := map[string]map[string]any{}
		for _, it := range f.must(f.AdminAPI("GET", "/notification-jobs", nil), 200, "notification jobs").Get("items").([]any) {
			j := it.(map[string]any)
			out[j["id"].(string)] = j
		}
		return out
	}
	byRef := f.must(f.AdminAPI("GET", "/notification-jobs?reference_type=notification_test&reference_id="+f.Users["admin"], nil), 200, "jobs by reference")
	if items := byRef.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["id"] != test {
		t.Fatalf("jobs by reference: %s", byRef.Raw)
	}
	if strings.Contains(string(byRef.Raw), "admin@example.test") {
		t.Fatalf("recipient not masked: %s", byRef.Raw)
	}
	j := jobs()[test]
	if j["attempts"] != float64(1) || j["last_error"] == nil || j["last_error"] == "" || j["state"] == "sent" || j["state"] == "failed" {
		t.Fatalf("job during the outage: %v", j)
	}
	var reset string
	for id, job := range jobs() {
		if job["template"] == "password_reset" {
			reset = id
		}
	}
	if reset == "" {
		t.Fatalf("reset job not listed: %v", jobs())
	}
	// Retries with backoff; after 5 attempts the test message fails. The
	// reset code's job expires with its code (tokens.challenge_ttl) first.
	for attempt := 1; attempt < 5; attempt++ {
		h.Clock.Advance(time.Duration(1<<attempt)*10*time.Second + time.Second)
		h.Deliver()
	}
	f.ReloginAdmin()
	if j := jobs()[test]; j["state"] != "failed" || j["attempts"] != float64(5) {
		t.Fatalf("job after 5 attempts: %v", j)
	}
	h.Clock.Advance(h.Cfg.Tokens.ChallengeTTL)
	h.Deliver()
	f.ReloginAdmin()
	if j := jobs()[reset]; j["state"] != "expired" && j["state"] != "failed" {
		t.Fatalf("code job after its expiry: %v", j)
	}

	// The relay is fixed: the check passes and a test message arrives.
	h.App.Notify.DevSink, h.App.Notify.Email = devSink, sender
	f.ReloginAdmin()
	chk = f.must(f.AdminAPI("POST", "/notification-settings/check", nil), 200, "relay check after the outage")
	if chk.Get("ok") != true {
		t.Fatalf("relay check after the fix: %s", chk.Raw)
	}
	f.must(f.AdminAPI("POST", "/notification-tests", nil), 202, "test message after the outage")
	if h.Mail("admin@example.test", notification.TplTest) == "" {
		t.Fatal("test message not delivered after the fix")
	}
	// Step 3: users request a new code (the cooldown still applies).
	h.Clock.Advance(2 * time.Second)
	req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"}), 202, "new code")
	code := CodeFrom(h.Mail("bob@example.test", "password_reset"))
	if code == "" {
		t.Fatal("new code not delivered")
	}
	f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code,
		"new_password": "bob recovered after the outage 2026"}), 200, "reset with the new code")
}

// TestRunbookWebhookOutage covers OPS-016 for the webhook and back-channel
// half of "Email or webhook delivery outage" (incidents.md): the backlog and
// delivery APIs show the outage (counts, oldest due, failure category, named
// after the status class such as http_500), deliveries dead-letter after
// delivery.webhook_max_attempts (and at once on HTTP 410), a fixed receiver
// gets them through replay with the original event_id, events published while
// a subscription is paused are not queued, and back-channel logout
// deliveries stop as failed after 8 attempts.
func TestRunbookWebhookOutage(t *testing.T) {
	h := NewHarness(t, allowPrivate, func(c *configuration.Config) { c.Delivery.WebhookMaxAttempts = 3 })
	f := fixtureOn(t, h)
	ctx := context.Background()
	w := worker.New(h.App, "runbook")
	if _, err := w.DispatchOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	ep := newEndpoint(t)
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "crm feed", "destination_url": ep.srv.URL + "/feed",
		"event_types": []string{"organization.membership.added", "organization.membership.removed"}, "allow_private_network": true}), 201, "webhook")
	subID := sub.Str("subscription.id")
	deliveries := func() []map[string]any {
		t.Helper()
		var out []map[string]any
		for _, it := range f.must(f.AdminAPI("GET", "/webhooks/"+subID+"/deliveries", nil), 200, "deliveries").Get("items").([]any) {
			out = append(out, it.(map[string]any))
		}
		return out
	}
	retryAll := func() {
		t.Helper()
		h.Clock.Advance(10 * time.Minute)
		if _, err := w.Webhooks.DeliverDue(ctx, w.ID, 100); err != nil {
			t.Fatal(err)
		}
		f.ReloginAdmin()
	}

	// Outage: the receiver answers 503.
	ep.status(http.StatusServiceUnavailable)
	f.CreateUser("dora")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["dora"]}), 201, "event during the outage")
	deliverWebhooks(t, w)
	// Step 1: backlog and deliveries.
	bl := f.must(f.AdminAPI("GET", "/webhooks/"+subID+"/backlog", nil), 200, "backlog")
	if bl.Get("retrying") != float64(1) || bl.Get("delivered") != float64(0) || bl.Str("last_failure_category") != "http_500" || bl.Get("oldest_due_seconds") == nil {
		t.Fatalf("backlog during the outage: %s", bl.Raw)
	}
	if d := deliveries(); len(d) != 1 || d[0]["state"] != "retrying" || d[0]["last_response_category"] != "http_500" || d[0]["attempts"] != float64(1) {
		t.Fatalf("delivery during the outage: %v", d)
	}
	retryAll()
	retryAll()
	if d := deliveries(); d[0]["state"] != "dead_letter" || d[0]["attempts"] != float64(3) {
		t.Fatalf("delivery after delivery.webhook_max_attempts: %v", d)
	}
	// HTTP 410 dead-letters at once.
	ep.status(http.StatusGone)
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "event answered with 410")
	deliverWebhooks(t, w)
	bl = f.must(f.AdminAPI("GET", "/webhooks/"+subID+"/backlog", nil), 200, "backlog")
	if bl.Get("dead_letter") != float64(2) || bl.Get("retrying") != float64(0) {
		t.Fatalf("backlog after 410: %s", bl.Raw)
	}
	original := map[string]string{}
	for _, c := range ep.received("/feed") {
		original[c.Header.Get("Webhook-Id")] = string(c.Body)
	}

	// Step 2: the receiver is fixed; replay keeps the original event_id.
	ep.reset()
	ep.status(http.StatusNoContent)
	for _, d := range deliveries() {
		mustStatus(t, f.AdminAPI("POST", "/webhooks/"+subID+"/deliveries/"+d["id"].(string)+"/replay", nil), 202, "replay")
	}
	retryAll()
	replayed := ep.received("/feed")
	if len(replayed) != 2 {
		t.Fatalf("replayed deliveries: %d", len(replayed))
	}
	for _, c := range replayed {
		if _, ok := original[c.Header.Get("Webhook-Id")]; !ok {
			t.Fatalf("replay changed the event ID: %s", c.Header.Get("Webhook-Id"))
		}
	}
	if bl := f.must(f.AdminAPI("GET", "/webhooks/"+subID+"/backlog", nil), 200, "backlog"); bl.Get("delivered") != float64(2) || bl.Get("dead_letter") != float64(0) {
		t.Fatalf("backlog after replay: %s", bl.Raw)
	}

	// Step 3: events published while paused are not queued for later.
	ep.reset()
	f.must(f.AdminAPI("PATCH", "/webhooks/"+subID, map[string]any{"state": "paused"}), 200, "pause")
	f.CreateUser("eli")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["eli"]}), 201, "event while paused")
	deliverWebhooks(t, w)
	f.must(f.AdminAPI("PATCH", "/webhooks/"+subID, map[string]any{"state": "active"}), 200, "resume")
	deliverWebhooks(t, w)
	retryAll()
	if n := len(ep.received("")); n != 0 {
		t.Fatalf("events published while paused were delivered: %d", n)
	}

	// Step 4: back-channel logout deliveries retry up to 8 times, then stay
	// failed (there is no replay API).
	logout := newEndpoint(t)
	logout.status(http.StatusInternalServerError)
	dev := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "dev-bff", "name": "Dev BFF", "client_type": "confidential", "first_party": true,
		"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{webRedirect},
		"backchannel_logout_uri": logout.srv.URL + "/logout", "environment": "development"}), 201, "development client")
	f.must(f.AdminAPI("PUT", "/clients/"+dev.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	mustStatus(t, h.Login(LoginOpts{ClientID: "dev-bff", ClientSecret: dev.Str("client_secret"), RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "alice@example.test"}).Tokens, 200, "sign-in")
	f.must(f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/revoke-sessions", map[string]any{}), 200, "end alice's sessions")
	state := func() (string, int) {
		var st string
		var attempts int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, attempts FROM logout_deliveries WHERE realm_id=$1 ORDER BY created_at DESC LIMIT 1`,
			h.Realm.ID).Scan(&st, &attempts); err != nil {
			t.Fatalf("logout delivery: %v", err)
		}
		return st, attempts
	}
	for i := 0; i < 10; i++ {
		if _, err := w.DeliverBackchannelLogout(ctx); err != nil {
			t.Fatal(err)
		}
		h.Clock.Advance(time.Hour)
	}
	if st, attempts := state(); st != "failed" || attempts != 8 {
		t.Fatalf("back-channel logout after the retries: %s after %d attempts", st, attempts)
	}
	if n := len(logout.received("/logout")); n != 8 {
		t.Fatalf("back-channel logout attempts at the receiver: %d", n)
	}
}

// runbookKeyring builds the key material a restarted process loads: root
// keys (active version) and optional dedicated pepper keys.
func runbookKeyring(t *testing.T, roots map[uint32][]byte, active uint32, pepper map[uint32][]byte) *keys.Keyring {
	t.Helper()
	kr, err := keys.New(roots, active)
	if err != nil {
		t.Fatal(err)
	}
	if pepper != nil {
		if err := kr.SetDedicated(keys.PurposePepper, pepper); err != nil {
			t.Fatal(err)
		}
	}
	return kr
}

// runbookKeyRefs is the keys.root_keys / keys.pepper_keys list of a restart.
func runbookKeyRefs(versions ...uint32) []configuration.KeyRef {
	var out []configuration.KeyRef
	for _, v := range versions {
		out = append(out, configuration.KeyRef{Version: v, Ref: "test"})
	}
	return out
}

// runbookDrainQueries are the checks of docs/operations/keys.md "Root-key
// rotation" step 5 ($1 is the version to drain, $2 the current time).
var runbookDrainQueries = map[string]string{
	"signing_keys":          `SELECT count(*) FROM signing_keys WHERE enc_key_version = $1 AND state NOT IN ('retired','compromised') AND $2::timestamptz IS NOT NULL`,
	"saml_signing_keys":     `SELECT count(*) FROM saml_signing_keys WHERE enc_key_version = $1 AND state <> 'retired' AND $2::timestamptz IS NOT NULL`,
	"otp_credentials":       `SELECT count(*) FROM credentials WHERE type IN ('totp','hotp') AND state IN ('active','pending') AND key_version = $1 AND $2::timestamptz IS NOT NULL`,
	"recovery_codes":        `SELECT count(*) FROM recovery_codes WHERE state = 'active' AND key_version = $1 AND $2::timestamptz IS NOT NULL`,
	"webhook_subscriptions": `SELECT count(*) FROM webhook_subscriptions WHERE key_version = $1 OR previous_secret_expires_at > $2`,
	"hooks":                 `SELECT count(*) FROM hooks WHERE key_version = $1 AND $2::timestamptz IS NOT NULL`,
	"identity_providers":    `SELECT count(*) FROM identity_providers WHERE secret_ciphertext IS NOT NULL AND key_version = $1 AND $2::timestamptz IS NOT NULL`,
	"organization_smtp":     `SELECT count(*) FROM notification_settings WHERE smtp_secret_ciphertext IS NOT NULL AND key_version = $1 AND $2::timestamptz IS NOT NULL`,
	"provisioning":          `SELECT count(*) FROM provisioning_connectors WHERE secret_ciphertext IS NOT NULL AND key_version = $1 AND $2::timestamptz IS NOT NULL`,
	"ssf_streams":           `SELECT count(*) FROM ssf_streams WHERE substring(authorization_ciphertext from 2 for 4) = int4send($1::int) AND $2::timestamptz IS NOT NULL`,
	"challenges":            `SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND expires_at > $2 AND key_version = $1`,
}

func runbookDrain(t *testing.T, h *Harness, version int) map[string]int {
	t.Helper()
	out := map[string]int{}
	for name, q := range runbookDrainQueries {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), q, version, h.Clock.Now()).Scan(&n); err != nil {
			t.Fatalf("drain check %s: %v", name, err)
		}
		out[name] = n
	}
	return out
}

// runbookReenrollTOTP replaces a user's authenticator: enrolling again and
// activating replaces the active TOTP and regenerates recovery codes.
func runbookReenrollTOTP(t *testing.T, f *Fixture, identifier string) {
	t.Helper()
	h := f.H
	tok := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: identifier}).Tokens.Str("access_token")
	en := f.must(h.API("POST", "/me/totp/enroll", tok, nil), 201, "enroll TOTP again")
	h.seeds[identifier] = en.Str("secret")
	f.must(h.API("POST", "/me/totp/activate", tok, map[string]any{"code": h.TOTPNow(identifier)}), 200, "activate the new TOTP")
}

// TestRunbookKMSAccessRevoked covers OPS-016 for "Compromised root key,
// pepper or KMS access", step 1 (KMS access only), with a stand-in unwrap
// command in place of a real KMS (keys.kms.command, DEP-016): after the
// exposed KMS credential is revoked, the running process keeps signing and
// verifying with the keys it unwrapped at start, a new start fails without
// naming the key, and a start with the remaining authorized identity loads
// the same key hierarchy (same doctor fingerprint). Revoking access in a
// real KMS and its audit log cannot be exercised in-process.
func TestRunbookKMSAccessRevoked(t *testing.T) {
	dir := t.TempDir()
	rootHex := hex.EncodeToString(secret.Random(32))
	wrapped := filepath.Join(dir, "root_key_v1.wrapped")
	if err := os.WriteFile(wrapped, []byte("WRAPPED:"+rootHex), 0o600); err != nil {
		t.Fatal(err)
	}
	// The stand-in KMS unwraps only for identities whose credential exists.
	exposed, other := filepath.Join(dir, "exposed-credential"), filepath.Join(dir, "other-host-credential")
	for _, c := range []string{exposed, other} {
		if err := os.WriteFile(c, []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kmsAs := func(credential string) configuration.KMSConfig {
		return configuration.KMSConfig{Command: []string{"sh", "-c", `test -f "$0" && sed 's/^WRAPPED://'`, credential}, Timeout: 10 * time.Second}
	}
	t.Cleanup(func() { configuration.ConfigureKMS(configuration.KMSConfig{}) })
	start := func(credential string) (*keys.Keyring, error) {
		cfg := configuration.Defaults()
		cfg.Keys.KMS = kmsAs(credential)
		cfg.Keys.RootKeys = []configuration.KeyRef{{Version: 1, Ref: "kms:" + wrapped}}
		cfg.Keys.ActiveVersion = 1
		configuration.ConfigureKMS(cfg.Keys.KMS)
		return server.LoadKeyring(&cfg)
	}
	kr, err := start(exposed)
	if err != nil {
		t.Fatalf("start with KMS access: %v", err)
	}
	base := NewHarness(t)
	h := startNode(t, base, kr, nil)
	f := fixtureOn(t, h)
	tok := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")

	// Revoke the exposed credential in the KMS.
	if err := os.Remove(exposed); err != nil {
		t.Fatal(err)
	}
	// The running process is unaffected.
	fresh := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	for _, x := range []string{tok, fresh} {
		if in := h.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, x); in.Get("active") != true {
			t.Fatalf("running process stopped verifying after KMS revocation: %s", in.Raw)
		}
	}
	// A new start with the revoked identity fails and names the file, not the key.
	if _, err := start(exposed); err == nil || !strings.Contains(err.Error(), wrapped) || strings.Contains(err.Error(), rootHex) {
		t.Fatalf("start after KMS revocation: %v", err)
	}
	// The remaining authorized identity starts with the same key hierarchy.
	kr2, err := start(other)
	if err != nil || kr2.Fingerprint() != kr.Fingerprint() {
		t.Fatalf("start with the remaining identity: %v", err)
	}
}

// TestRunbookRootKeyCompromise covers OPS-016 for "Compromised root key,
// pepper or KMS access", step 2 (an unwrapped root key leaked), with the
// procedure of keys.md "Root-key rotation": a new version is distributed and
// made active (a restart of the process with versions 1 and 2), an emergency
// signing-key rotation wraps the new signing key under it, webhook secrets
// are rotated, hooks re-created, the identity-provider client secret and an
// organization's mail-server password sent again, and authenticators
// re-enrolled; the drain checks then find nothing left under version 1, and
// after a restart without version 1 sign-in with TOTP, issuance,
// introspection, webhooks, hooks, federation and the organization's mail
// credential keep working. Generating and distributing the key file are
// operator steps (identity-cli generate-root-key, configuration, restart);
// restarts are simulated by new nodes on the same database.
func TestRunbookRootKeyCompromise(t *testing.T) {
	k1, k2 := secret.Random(32), secret.Random(32)
	ctx := context.Background()
	base := NewHarness(t, allowPrivate)
	h := startNode(t, base, runbookKeyring(t, map[uint32][]byte{1: k1}, 1, nil), nil)
	f := fixtureOn(t, h)
	idp := newFakeIdP(t, h.Clock.Now)
	trust := func(n *Harness) {
		n.App.Federation.Egress.AllowPrivate = true
		n.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	trust(h)

	// Secrets of every kind the runbook names, under version 1.
	f.EnrollTOTP("bob")
	ep := newEndpoint(t)
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "crm feed", "destination_url": ep.srv.URL + "/feed",
		"event_types": []string{"organization.membership.added"}, "allow_private_network": true}), 201, "webhook")
	subID := sub.Str("subscription.id")
	hooks := newEndpoint(t)
	hooks.setAnswer(func(r *http.Request, body []byte) (int, http.Header, []byte) {
		if strings.Contains(string(body), "Staff") {
			return 200, nil, []byte(`{"allow":false,"errors":{"display_name":"may not impersonate staff"}}`)
		}
		return 200, nil, []byte(`{"allow":true}`)
	})
	hookBody := map[string]any{"name": "profile", "kind": "profile.validation", "url": hooks.srv.URL + "/profile", "allow_private_network": true}
	hookID := f.must(f.AdminAPI("POST", "/hooks", hookBody), 201, "hook").Str("hook.id")
	connBody := map[string]any{"alias": "corp", "display_name": "Corp SSO", "issuer": idp.srv.URL, "client_secret": "upstream-secret",
		"config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true}
	connID := f.must(f.AdminAPI("POST", "/identity-providers", connBody), 201, "connection").Str("id")
	smtpPath := "/organizations/" + f.Acme + "/notification-settings/smtp"
	smtpBody := map[string]any{"host": "smtp.acme.test", "port": 587, "tls_mode": "starttls", "username": "mailer", "password": "acme-smtp-secret-123"}
	f.must(f.AdminAPI("PUT", smtpPath, smtpBody), 200, "organization mail server")
	before := runbookDrain(t, h, 1)
	for _, src := range []string{"signing_keys", "otp_credentials", "recovery_codes", "webhook_subscriptions", "hooks", "identity_providers", "organization_smtp"} {
		if before[src] == 0 {
			t.Fatalf("precondition: nothing under version 1 in %s: %v", src, before)
		}
	}

	// Distribute and activate version 2 (every process restarts with both).
	n2 := startNode(t, h, runbookKeyring(t, map[uint32][]byte{1: k1, 2: k2}, 2, nil), func(c *configuration.Config) {
		c.Keys.RootKeys, c.Keys.ActiveVersion = runbookKeyRefs(1, 2), 2
	})
	trust(n2)
	f.H = n2
	if n2.App.D.Keys.Fingerprint() == h.App.D.Keys.Fingerprint() {
		t.Fatal("doctor fingerprint unchanged after activating a new root key version")
	}
	// Emergency signing-key rotation: the new key is wrapped under version 2.
	f.ReloginAdmin()
	rot := f.must(f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"mode": "emergency", "reason": "INC-9 root key exposure"}), 201, "emergency rotation")
	var wrapVersion int
	if err := n2.App.D.DB.Pool.QueryRow(ctx, `SELECT enc_key_version FROM signing_keys WHERE kid=$1`, rot.Str("kid")).Scan(&wrapVersion); err != nil || wrapVersion != 2 {
		t.Fatalf("new signing key wrapped under version %d: %v", wrapVersion, err)
	}
	f.ReloginAdmin() // the administrator token was signed with the compromised key
	// Rotate every webhook secret.
	newSecret := f.must(f.AdminAPI("POST", "/webhooks/"+subID+"/rotate-secret", nil), 200, "rotate webhook secret").Str("signing_secret")
	// Re-create hooks.
	f.must(f.AdminAPI("DELETE", "/hooks/"+hookID, nil), 204, "delete hook")
	re := f.must(f.AdminAPI("POST", "/hooks", hookBody), 201, "re-create hook")
	// Send the identity-provider client secret again.
	cur := f.must(f.AdminAPI("GET", "/identity-providers/"+connID, nil), 200, "connection")
	f.must(n2.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/identity-providers/" + connID, Token: f.AdminToken, JSON: connBody,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "send the client secret again")
	// Send the organization's mail-server password again.
	f.must(f.AdminAPI("PUT", smtpPath, smtpBody), 200, "send the mail-server password again")
	// TOTP re-enrollment (activation also regenerates recovery codes).
	runbookReenrollTOTP(t, f, "root-admin")
	runbookReenrollTOTP(t, f, "bob@example.test")
	f.ReloginAdmin()

	// Drain: after the 24-hour webhook rollover nothing references version 1.
	n2.Clock.Advance(24*time.Hour + time.Minute)
	if left := runbookDrain(t, n2, 1); left["signing_keys"]+left["otp_credentials"]+left["recovery_codes"]+left["webhook_subscriptions"]+
		left["hooks"]+left["identity_providers"]+left["organization_smtp"]+left["challenges"] != 0 {
		t.Fatalf("still under version 1 after the procedure: %v", left)
	}

	// Remove version 1 (every process restarts with version 2 only).
	n3 := startNode(t, n2, runbookKeyring(t, map[uint32][]byte{2: k2}, 2, nil), func(c *configuration.Config) {
		c.Keys.RootKeys, c.Keys.ActiveVersion = runbookKeyRefs(2), 2
	})
	trust(n3)
	f.H = n3
	f.ReloginAdmin() // administrator TOTP and the signing key
	mustStatus(t, f.AccountToken("bob").Tokens, 200, "bob signs in with his new TOTP")
	tok := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	if in := n3.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, tok); in.Get("active") != true {
		t.Fatalf("introspection without version 1: %s", in.Raw)
	}
	w := worker.New(n3.App, "runbook")
	deliverWebhooks(t, w) // what was queued before
	ep.reset()
	f.CreateUser("dora")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["dora"]}), 201, "event")
	deliverWebhooks(t, w)
	calls := ep.received("/feed")
	if len(calls) != 1 || webhooks.VerifySignature(newSecret, calls[0].Header.Get("Webhook-Id"), calls[0].Header.Get("Webhook-Timestamp"),
		calls[0].Header.Get("Webhook-Signature"), calls[0].Body, n3.Clock.Now(), 5*time.Minute) != nil {
		t.Fatalf("webhook delivery without version 1: %d calls", len(calls))
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, n3.API("PATCH", "/me", bob, map[string]any{"display_name": "Staff Bob"}), 422, "re-created hook called without version 1")
	last := hooks.received("/profile")
	if !validHookSignature(re.Str("signing_secret"), last[len(last)-1]) {
		t.Fatal("hook request not signed with the re-created hook's secret")
	}
	if _, st := runbookFedLogin(t, n3, idp, "corp", map[string]any{"sub": "u-zed", "email": "zed@corp.test", "email_verified": true}); st == nil || st.Str("redirect_to") == "" {
		t.Fatalf("federated sign-in without version 1: %v", st)
	}
	var ct []byte
	_ = n3.App.D.DB.Pool.QueryRow(ctx, `SELECT smtp_secret_ciphertext FROM notification_settings WHERE organization_id=$1`, f.Acme).Scan(&ct)
	if pt, err := n3.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("smtp:"+n3.Realm.ID+":"+f.Acme)); err != nil || string(pt) != "acme-smtp-secret-123" {
		t.Fatalf("organization mail-server password without version 1: %v", err)
	}
}

// TestRunbookPepperCompromise covers OPS-016 for "Compromised root key,
// pepper or KMS access", step 3 (keys.md "Password pepper"): a new pepper
// version is added (restart), verifiers are re-peppered at each user's next
// sign-in, the documented query finds the accounts still on the old
// version, forced resets for them bring it to zero, and the old version can
// then be removed: re-peppered users still sign in and the reset users set a
// new password through the reset flow.
func TestRunbookPepperCompromise(t *testing.T) {
	root, p1, p2 := secret.Random(32), secret.Random(32), secret.Random(32)
	ctx := context.Background()
	base := NewHarness(t)
	h := startNode(t, base, runbookKeyring(t, map[uint32][]byte{1: root}, 1, map[uint32][]byte{1: p1}), func(c *configuration.Config) {
		c.Keys.PepperKeys = runbookKeyRefs(1)
	})
	f := fixtureOn(t, h)
	onPepper := func(n *Harness, v int) map[string]bool {
		t.Helper()
		rows, err := n.App.D.DB.Pool.Query(ctx, `SELECT user_id FROM credentials WHERE type='password' AND state='active' AND verifier LIKE $1`,
			fmt.Sprintf("%%,k=%d$%%", v))
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			out[id] = true
		}
		return out
	}
	if n := len(onPepper(h, 1)); n < 5 {
		t.Fatalf("precondition: verifiers on pepper version 1: %d", n)
	}

	// Add pepper version 2 (restart with both versions).
	n2 := startNode(t, h, runbookKeyring(t, map[uint32][]byte{1: root}, 1, map[uint32][]byte{1: p1, 2: p2}), func(c *configuration.Config) {
		c.Keys.PepperKeys = runbookKeyRefs(1, 2)
	})
	f.H = n2
	f.ReloginAdmin()
	mustStatus(t, f.AccountToken("alice").Tokens, 200, "alice signs in")
	old := onPepper(n2, 1)
	if old[f.Users["admin"]] || old[f.Users["alice"]] || !onPepper(n2, 2)[f.Users["alice"]] {
		t.Fatal("verifiers not re-peppered at sign-in")
	}
	if !old[f.Users["bob"]] || !old[f.Users["carol"]] {
		t.Fatalf("the query must still find users who did not sign in: %v", old)
	}
	// Force resets for the accounts the query still finds.
	for id := range old {
		f.must(f.AdminAPI("POST", "/users/"+id+"/credentials/password/compromised", map[string]any{"reason": "INC-11 pepper exposure"}), 204, "force reset")
	}
	if left := onPepper(n2, 1); len(left) != 0 {
		t.Fatalf("still on pepper version 1: %v", left)
	}

	// Remove pepper version 1 (restart with version 2 only).
	n3 := startNode(t, n2, runbookKeyring(t, map[uint32][]byte{1: root}, 1, map[uint32][]byte{2: p2}), func(c *configuration.Config) {
		c.Keys.PepperKeys = runbookKeyRefs(2)
	})
	f.H = n3
	f.ReloginAdmin()
	mustStatus(t, f.AccountToken("alice").Tokens, 200, "re-peppered user signs in without version 1")
	if lr := n3.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{n3.Realm.Issuer + "/account"},
		Identifier: "bob@example.test", ExpectFail: true}); lr.Tokens != nil && lr.Tokens.Status == 200 {
		t.Fatal("a reset password still works")
	}
	n3.Clock.Advance(2 * time.Second)
	req := f.must(n3.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"}), 202, "bob requests a reset")
	code := CodeFrom(n3.Mail("bob@example.test", "password_reset"))
	pw := "bob after the pepper rotation 2026"
	f.must(n3.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code, "new_password": pw}), 200, "reset")
	n3.SetPassword("bob@example.test", pw)
	mustStatus(t, f.AccountToken("bob").Tokens, 200, "bob signs in with the new password")
	if !onPepper(n3, 2)[f.Users["bob"]] {
		t.Fatal("new verifier not on pepper version 2")
	}
}
