package e2e

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

type supportCtx struct {
	f      *Fixture
	samTok string
	samLR  *LoginResult
}

func (f *Fixture) support(t *testing.T) *supportCtx {
	t.Helper()
	lr := f.AdminTokenFor("sam")
	return &supportCtx{f: f, samTok: lr.Tokens.Str("access_token"), samLR: lr}
}

// refreshed obtains a new access token from the same session without new MFA.
func (s *supportCtx) refreshed(t *testing.T) {
	t.Helper()
	r := s.f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.samLR.Tokens.Str("refresh_token")}}, "proudauth-cli", "")
	mustStatus(t, r, 200, "refresh sam")
	s.samLR.Tokens = r
	s.samTok = r.Str("access_token")
}

func (s *supportCtx) request(target, org string, extra map[string]any) *Resp {
	body := map[string]any{"target_user_id": target, "organization_id": org, "client_id": "support-bff", "audience": s.f.OrdersAud,
		"reason": "Customer reports missing order history in dashboard", "ticket_reference": "SUP-1042"}
	for k, v := range extra {
		body[k] = v
	}
	return s.f.H.API("POST", "/impersonation-requests", s.samTok, body)
}

func (s *supportCtx) issue(t *testing.T, target, org string) *Resp {
	t.Helper()
	req := s.request(target, org, nil)
	mustStatus(t, req, 201, "impersonation request")
	out := s.f.H.API("POST", "/impersonation-requests/"+req.Str("id")+"/issue", s.samTok, nil)
	mustStatus(t, out, 201, "issue")
	return out
}

// TestSupportImpersonation covers the support-access lifecycle (TEST-042 to
// TEST-046, TEST-071) and IMP-009 (opaque support tokens live at most five
// minutes, are never refreshable or exchangeable, and expire), IMP-010 (every
// use is checked online, so revocation applies to the very next request),
// IMP-016 (the operator and the target end the grant; the operator's lost
// support permission invalidates it) and IMP-017 (suspending the target's
// membership ends access immediately).
func TestSupportImpersonation(t *testing.T) {
	f := NewFixture(t)
	svc := f.StartServices(t)
	s := f.support(t)
	bob := f.Users["bob"]

	t.Run("happy path with actor-aware evidence", func(t *testing.T) {
		out := s.issue(t, bob, f.Acme)
		tok := out.Str("access_token")
		if !strings.HasPrefix(tok, "pa_it_") || out.Get("refresh_token") != nil {
			t.Fatalf("support tokens are opaque and never refreshable: %s", out.Raw)
		}
		if exp := out.Get("expires_in").(float64); exp > 300 {
			t.Fatalf("support token lifetime %v exceeds 5 minutes", exp)
		}
		st, body := call(t, "GET", svc.OrdersURL+"/orders", tok)
		if st != 200 || body["actor"] != f.Users["sam"] {
			t.Fatalf("support read: %d %v", st, body)
		}
		in := f.H.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok)
		if in.Str("token_kind") != "impersonation_access" || in.Str("act.sub") != f.Users["sam"] || in.Str("sub") != bob || in.Str("support_mode") != "read_only" {
			t.Fatalf("introspection must carry actor and subject: %s", in.Raw)
		}
		// TEST-045: the resource recorded the real actor.
		if len(svc.Orders.Audit) == 0 || svc.Orders.Audit[0].Actor != f.Users["sam"] || svc.Orders.Audit[0].Subject != bob {
			t.Fatalf("downstream audit lost the actor: %+v", svc.Orders.Audit)
		}
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=support.impersonation.started", nil), 200, "audit")
		item := ev.Get("items").([]any)[0].(map[string]any)
		if item["actor"].(map[string]any)["id"] != f.Users["sam"] || item["subject"].(map[string]any)["id"] != bob {
			t.Fatalf("IdP audit must preserve actor and subject: %v", item)
		}
		// The customer can see the support access.
		bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
		list := f.H.API("GET", "/me/impersonation-grants", bobAcct, nil)
		if len(list.Get("items").([]any)) == 0 {
			t.Fatal("customer visibility (IMP-021)")
		}
	})
	t.Run("TEST-042 protected and state-changing operations are denied", func(t *testing.T) {
		tok := s.issue(t, bob, f.Acme).Str("access_token")
		if st, _ := call(t, "POST", svc.OrdersURL+"/orders/ord_acme_1/refund", tok); st != 403 && st != 401 {
			t.Fatalf("support refund allowed: %d", st)
		}
		for _, path := range []string{"/me", "/me/password", "/me/totp/enroll", "/me/personal-tokens", "/users"} {
			r := f.H.API("POST", path, tok, map[string]any{})
			if r.Status != 403 && r.Status != 401 && r.Status != 405 {
				t.Fatalf("support token reached %s: %d", path, r.Status)
			}
		}
		r := f.H.API("GET", "/me", tok, nil)
		if r.Status != 403 || r.Str("code") != "impersonation_restricted" {
			t.Fatalf("identity API must reject support tokens: %d %s", r.Status, r.Raw)
		}
		// The refusal is evidence about the operator, the customer and the grant (IMP-006).
		var actor, subject, grant string
		_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT actor_id, coalesce(subject_id,''), coalesce(impersonation_grant_id,'')
			FROM audit_events WHERE type='support.token.rejected' ORDER BY seq DESC LIMIT 1`).Scan(&actor, &subject, &grant)
		if actor != f.Users["sam"] || subject != bob || grant == "" {
			t.Fatalf("support token refusal evidence: actor %q subject %q grant %q", actor, subject, grant)
		}
	})
	t.Run("TEST-043 no refresh, replay after revoke, expiry", func(t *testing.T) {
		out := s.issue(t, bob, f.Acme)
		tok := out.Str("access_token")
		r := f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}}, "support-bff", f.Clients["support"].Secret)
		if r.Status == 200 {
			t.Fatal("support token refreshed")
		}
		// Exchange cannot extend or launder support access (IMP-014).
		ex := f.H.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {tok},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}}, "web-bff", f.Clients["web"].Secret)
		if ex.Status == 200 {
			t.Fatal("support token exchanged")
		}
		mustStatus(t, f.H.API("POST", "/impersonation-grants/"+out.Str("grant.id")+"/revoke", s.samTok, map[string]any{"reason": "done"}), 204, "revoke")
		if st, _ := call(t, "GET", svc.OrdersURL+"/orders", tok); st != 401 {
			t.Fatalf("support token used after revoke: %d", st)
		}
		out2 := s.issue(t, bob, f.Acme)
		f.H.Clock.Advance(6 * time.Minute)
		if st, _ := call(t, "GET", svc.OrdersURL+"/orders", out2.Str("access_token")); st != 401 {
			t.Fatalf("support token used after expiry: %d", st)
		}
		f.ReloginAdmin()
		s = f.support(t) // fresh MFA after the clock jump
	})
	t.Run("TEST-044 actor or target changes end access", func(t *testing.T) {
		tok := s.issue(t, bob, f.Acme).Str("access_token")
		f.must(f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], map[string]any{"state": "suspended"}), 200, "suspend target membership")
		if st, _ := call(t, "GET", svc.OrdersURL+"/orders", tok); st != 401 {
			t.Fatalf("support continued after target membership suspension: %d", st)
		}
		f.must(f.AdminAPI("PATCH", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], map[string]any{"state": "active"}), 200, "reactivate")
		tok2 := s.issue(t, bob, f.Acme).Str("access_token")
		assignments := f.must(f.AdminAPI("GET", "/role-assignments?subject_type=user&subject_id="+f.Users["sam"], nil), 200, "assignments")
		for _, a := range assignments.Get("items").([]any) {
			f.must(f.AdminAPI("DELETE", "/role-assignments/"+a.(map[string]any)["id"].(string), nil), 204, "remove support role")
		}
		if st, _ := call(t, "GET", svc.OrdersURL+"/orders", tok2); st != 401 {
			t.Fatalf("support continued after actor lost permission: %d", st)
		}
		f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["support-operator"], "subject": map[string]any{"type": "user", "id": f.Users["sam"]}}), 201, "restore")
	})
	t.Run("TEST-046 handoff codes are single use and destination bound", func(t *testing.T) {
		out := s.issue(t, bob, f.Acme)
		h := f.H.API("POST", "/impersonation-grants/"+out.Str("grant.id")+"/handoffs", s.samTok, map[string]any{"destination_client_id": "support-bff"})
		mustStatus(t, h, 201, "handoff")
		code := h.Str("handoff_code")
		redeem := func(client, secret string) *Resp {
			return f.H.Do(Req{Method: "POST", Path: "/api/v1/realms/main/impersonation-handoffs/redeem", Form: url.Values{"handoff_code": {code}}, Basic: [2]string{client, secret}})
		}
		if r := redeem("orders-rs", f.Clients["orders-rs"].Secret); r.Status == 200 {
			t.Fatal("handoff redeemed by another destination")
		}
		r := redeem("support-bff", f.Clients["support"].Secret)
		mustStatus(t, r, 200, "redeem")
		if !strings.HasPrefix(r.Str("access_token"), "pa_it_") {
			t.Fatal("handoff must yield a support token")
		}
		if r := redeem("support-bff", f.Clients["support"].Secret); r.Status == 200 {
			t.Fatal("handoff replayed")
		}
	})
	t.Run("TEST-071 customer opt-out and revoke", func(t *testing.T) {
		out := s.issue(t, bob, f.Acme)
		bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
		mustStatus(t, f.H.API("POST", "/me/impersonation-grants/"+out.Str("grant.id")+"/revoke", bobAcct, nil), 204, "customer revoke")
		if st, _ := call(t, "GET", svc.OrdersURL+"/orders", out.Str("access_token")); st != 401 {
			t.Fatal("customer revocation ignored")
		}
		mustStatus(t, f.H.API("PUT", "/me/support-access", bobAcct, map[string]any{"opt_out": true}), 200, "opt out")
		if r := s.request(bob, f.Acme, nil); r.Status != 403 {
			t.Fatalf("request after opt-out: %d", r.Status)
		}
		mustStatus(t, f.H.API("PUT", "/me/support-access", bobAcct, map[string]any{"opt_out": false}), 200, "opt in")
	})
}

// Requirements: AUD-004 (when the audit write fails, no support grant is
// persisted or returned; TEST-047 subtest), IMP-003 (a live administrator
// session and token with MFA older than the limit get step_up_required),
// IMP-005 (a request without a meaningful reason is refused), IMP-015
// (realm administrators, organization owners and administrators, service
// principals and the operator themselves cannot be impersonated).
func TestImpersonationDenials(t *testing.T) {
	f := NewFixture(t)
	s := f.support(t)
	t.Run("TEST-040 missing permission, MFA or reason", func(t *testing.T) {
		alice := f.AdminTokenFor("alice").Tokens.Str("access_token") // admin API access but no support permission
		r := f.H.API("POST", "/impersonation-requests", alice, map[string]any{"target_user_id": f.Users["bob"], "organization_id": f.Acme,
			"client_id": "support-bff", "audience": f.OrdersAud, "reason": "Investigating reported problem"})
		mustStatus(t, r, 403, "no permission")
		r = s.request(f.Users["bob"], f.Acme, map[string]any{"reason": "x"})
		mustStatus(t, r, 422, "no reason")
		f.H.Clock.Advance(6 * time.Minute) // MFA evidence older than 5 minutes
		s.refreshed(t)                     // a live session and token, but stale MFA
		r = s.request(f.Users["bob"], f.Acme, nil)
		if r.Status != 403 || r.Str("code") != "step_up_required" {
			t.Fatalf("stale MFA: %d %s", r.Status, r.Raw)
		}
		f.ReloginAdmin()
		s = f.support(t)
	})
	t.Run("TEST-041 forbidden targets", func(t *testing.T) {
		cases := map[string][2]string{
			"another tenant":      {f.Users["alice"], f.Globex},
			"organization admin":  {f.Users["carol"], f.Globex},
			"realm administrator": {f.Users["admin"], f.Acme},
			"self":                {f.Users["sam"], f.Acme},
			"service principal":   {f.Clients["batch"].SP, f.Acme},
			"organization owner":  {f.Users["alice"], f.Acme},
		}
		for name, c := range cases {
			if r := s.request(c[0], c[1], nil); r.Status == 201 {
				t.Fatalf("%s: impersonation allowed", name)
			}
		}
		// Nested impersonation: a support token cannot start support access.
		tok := s.issue(t, f.Users["bob"], f.Acme).Str("access_token")
		r := f.H.API("POST", "/impersonation-requests", tok, map[string]any{"target_user_id": f.Users["bob"], "organization_id": f.Acme,
			"client_id": "support-bff", "audience": f.OrdersAud, "reason": "nested request attempt here"})
		if r.Status != 403 && r.Status != 401 {
			t.Fatalf("nested impersonation: %d", r.Status)
		}
		// Write scopes in read-only mode are refused.
		if r := s.request(f.Users["bob"], f.Acme, map[string]any{"scopes": []string{"orders:write"}}); r.Status == 201 {
			t.Fatal("read-only support access included a write scope")
		}
		// Machine tokens cannot use support routes (TEST-039).
		svc := f.MachineToken(f.Clients["orders-rs"], f.H.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		r = f.H.API("POST", "/impersonation-requests", svc, map[string]any{"target_user_id": f.Users["bob"], "organization_id": f.Acme,
			"client_id": "support-bff", "audience": f.OrdersAud, "reason": "machine attempting support access"})
		mustStatus(t, r, 403, "machine support request")
	})
	t.Run("TEST-047 audit failure prevents access", func(t *testing.T) {
		req := s.request(f.Users["bob"], f.Acme, nil)
		mustStatus(t, req, 201, "request")
		f.H.App.Imp.FailAudit = func() error { return errors.New("audit storage unavailable") }
		r := f.H.API("POST", "/impersonation-requests/"+req.Str("id")+"/issue", s.samTok, nil)
		f.H.App.Imp.FailAudit = nil
		if r.Status != 500 || strings.Contains(string(r.Raw), "pa_it_") {
			t.Fatalf("grant issued without durable audit: %d %s", r.Status, r.Raw)
		}
		var n int
		_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM impersonation_grants WHERE request_id=$1`, req.Str("id")).Scan(&n)
		if n != 0 {
			t.Fatal("grant persisted without its audit record")
		}
	})
	t.Run("IMP-001 disabled until a resource opts in", func(t *testing.T) {
		cur := f.must(f.AdminAPI("GET", "/resources/"+f.Orders, nil), 200, "resource")
		upd := f.H.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resources/" + f.Orders, Token: f.AdminToken,
			JSON: map[string]any{"name": "Orders API", "verification_mode": "strict_online"}, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
		mustStatus(t, upd, 200, "opt out of support contract")
		r := s.request(f.Users["bob"], f.Acme, nil)
		if r.Status != 404 || r.Str("code") != "feature_disabled" {
			t.Fatalf("impersonation must be unavailable without an opted-in resource: %d %s", r.Status, r.Raw)
		}
		stale := f.H.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resources/" + f.Orders, Token: f.AdminToken,
			JSON: map[string]any{"name": "Orders API", "verification_mode": "strict_online"}, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
		mustStatus(t, stale, 412, "stale If-Match (API-010)")
	})
}

// TestSupportCapabilityProfile covers IMP-002 and IMP-007: an operator's
// support permission is scoped to organizations, target categories, modes and
// scopes by conditions on the operator's assignment, enforced at request,
// issuance and on every use of a live grant.
func TestSupportCapabilityProfile(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	reassign := func(cond map[string]any) {
		t.Helper()
		list := f.must(f.AdminAPI("GET", "/role-assignments?subject_id="+f.Users["sam"], nil), 200, "assignments")
		for _, it := range list.Get("items").([]any) {
			if m := it.(map[string]any); m["role_id"] == f.Roles["support-operator"] {
				f.must(f.AdminAPI("DELETE", "/role-assignments/"+m["id"].(string), nil), 204, "remove support role")
			}
		}
		f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["support-operator"],
			"subject": map[string]any{"type": "user", "id": f.Users["sam"]}, "conditions": cond}), 201, "scoped support role")
	}
	mustStatus(t, f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["support-operator"],
		"subject": map[string]any{"type": "user", "id": f.Users["carol"]}, "conditions": map[string]any{"support_modes": []string{"root"}}}), 422, "unknown mode")

	reassign(map[string]any{"organization_ids": []string{f.Globex}})
	s := f.support(t)
	if r := s.request(f.Users["bob"], f.Acme, nil); r.Status != 403 {
		t.Fatalf("operator scoped to Globex reached Acme: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, s.request(f.Users["bob"], f.Globex, nil), 201, "permitted organization")

	reassign(map[string]any{"organization_ids": []string{f.Acme}, "support_scopes": []string{"orders:write"}})
	if r := s.request(f.Users["bob"], f.Acme, map[string]any{"scopes": []string{"orders:read"}}); r.Status != 403 {
		t.Fatalf("scope outside the operator's support capabilities: %d %s", r.Status, r.Raw)
	}

	reassign(map[string]any{"organization_ids": []string{f.Acme}, "support_scopes": []string{"orders:read"}, "support_modes": []string{"read_only"},
		"subject_categories": []string{"member"}})
	out := s.issue(t, f.Users["bob"], f.Acme)
	tok := out.Str("access_token")
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok); in.Get("active") != true {
		t.Fatalf("grant within the capability profile: %s", in.Raw)
	}
	// Narrowing the profile ends the live grant on its next use.
	reassign(map[string]any{"organization_ids": []string{f.Globex}})
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok); in.Get("active") != false {
		t.Fatalf("grant outlived the operator's narrowed capabilities: %s", in.Raw)
	}
}

// TestCustomerApprovedSupportAccess covers IMP-022 (customer discovers,
// approves or denies requests), IMP-023 (grant reporting by ticket and reason)
// and IMP-024 (evidence linked by grant: decisions, expiry, export filter).
func TestCustomerApprovedSupportAccess(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.SetPolicy(func(p *realmPolicy) { p.Impersonation.Approval = "customer" }), 200, "customer approval")
	s := f.support(t)
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	req := s.request(f.Users["bob"], f.Acme, nil)
	mustStatus(t, req, 201, "request")
	if req.Str("state") != "pending" {
		t.Fatalf("customer approval must leave the request pending: %s", req.Raw)
	}
	if h.Mail("bob@example.test", "support_access_approval") == "" {
		t.Fatal("customer not told about the pending request")
	}
	pending := h.API("GET", "/me/impersonation-requests", bob, nil)
	mustStatus(t, pending, 200, "pending list")
	items := pending.Get("items").([]any)
	if len(items) != 1 || items[0].(map[string]any)["reason"] == "" || items[0].(map[string]any)["ticket_reference"] != "SUP-1042" {
		t.Fatalf("customer cannot see the request context: %s", pending.Raw)
	}
	mustStatus(t, h.API("POST", "/impersonation-requests/"+req.Str("id")+"/issue", s.samTok, nil), 409, "issue before approval")
	mustStatus(t, h.API("POST", "/impersonation-requests/"+req.Str("id")+"/approve", bob, nil), 204, "customer approves")
	out := h.API("POST", "/impersonation-requests/"+req.Str("id")+"/issue", s.samTok, nil)
	mustStatus(t, out, 201, "issue after approval")
	grantID := out.Str("grant_id")
	byTicket := f.must(f.AdminAPI("GET", "/impersonation-grants?ticket_reference=SUP-1042", nil), 200, "grants by ticket")
	g := byTicket.Get("items").([]any)
	if len(g) != 1 || g[0].(map[string]any)["reason"] == "" {
		t.Fatalf("grant reporting by ticket: %s", byTicket.Raw)
	}
	if grantID == "" {
		grantID = g[0].(map[string]any)["id"].(string)
	}
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	mustStatus(t, h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": out.Str("access_token"), "action": "orders.read",
		"resource": map[string]any{"type": "order", "org_id": f.Acme}}), 200, "support decision")
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=authorization.decision&impersonation_grant_id="+grantID, nil), 200, "decision evidence")
	if len(ev.Get("items").([]any)) == 0 {
		t.Fatal("support decision not linked to its grant")
	}
	// The grant's evidence includes the request it was issued from (IMP-024).
	reqEv := f.must(f.AdminAPI("GET", "/audit-events?type=support.impersonation.requested&impersonation_grant_id="+grantID, nil), 200, "request evidence")
	if len(reqEv.Get("items").([]any)) != 1 {
		t.Fatalf("grant evidence lacks its request: %s", reqEv.Raw)
	}
	// A second request is denied by the customer.
	second := s.request(f.Users["bob"], f.Acme, nil)
	mustStatus(t, second, 201, "second request")
	mustStatus(t, h.API("POST", "/impersonation-requests/"+second.Str("id")+"/deny", bob, map[string]any{"reason": "not now"}), 204, "customer denies")
	mustStatus(t, h.API("POST", "/impersonation-requests/"+second.Str("id")+"/issue", s.samTok, nil), 409, "issue after denial")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/impersonation-requests/"+second.Str("id")+"/deny", alice, nil), 404, "unrelated user cannot deny")
	// Expiry is evidence too.
	h.Clock.Advance(10 * time.Minute)
	if _, err := h.App.Imp.ExpireGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.ReloginAdmin()
	exp := f.must(f.AdminAPI("GET", "/audit-events?type=support.impersonation.expired&impersonation_grant_id="+grantID, nil), 200, "expiry evidence")
	if len(exp.Get("items").([]any)) != 1 {
		t.Fatalf("grant expiry not audited: %s", exp.Raw)
	}
}
