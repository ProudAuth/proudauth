package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/authorization"
)

// TestSupportRequestTargetValidation covers IMP-004 and IMP-005: every
// element of a support request is checked against authoritative state — the
// target account and its active membership, the organization, a
// confidential support client approved for the resource, and a resource that
// implements the support contract — and each denial is recorded with its
// reason. A meaningful reason (and a ticket where policy requires one) is
// mandatory and is kept server-side, never in the support token.
func TestSupportRequestTargetValidation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	s := f.support(t)
	bob := f.Users["bob"]
	lastDenial := func() string {
		var code string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(reason_code,'') FROM audit_events WHERE realm_id=$1 AND type='support.impersonation.denied'
			ORDER BY seq DESC LIMIT 1`, h.Realm.ID).Scan(&code)
		return code
	}
	denied := func(name string, r *Resp, reason string) {
		t.Helper()
		if r.Status != 403 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
			return
		}
		if got := lastDenial(); got != reason {
			t.Errorf("%s: denial recorded as %q, want %q", name, got, reason)
		}
	}
	denied("unknown target", s.request("usr_unknown", f.Acme, nil), "TARGET_NOT_ELIGIBLE")
	denied("target outside the organization", s.request(f.Users["alice"], f.Globex, nil), "TARGET_NOT_MEMBER")
	denied("confidential client not approved for the resource", s.request(bob, f.Acme, map[string]any{"client_id": "web-bff"}), "CLIENT_NOT_ELIGIBLE")
	denied("public client", s.request(bob, f.Acme, map[string]any{"client_id": "partner-app"}), "CLIENT_NOT_ELIGIBLE")
	denied("resource without the support contract", s.request(bob, f.Acme, map[string]any{"audience": f.BillingAud}), "RESOURCE_NOT_OPTED_IN")
	denied("unregistered audience", s.request(bob, f.Acme, map[string]any{"audience": "https://unregistered.test"}), "RESOURCE_NOT_OPTED_IN")

	member := "/organizations/" + f.Acme + "/members/" + f.MemberAcme["bob"]
	f.must(f.AdminAPI("PATCH", member, map[string]any{"state": "suspended"}), 200, "suspend membership")
	denied("suspended membership", s.request(bob, f.Acme, nil), "TARGET_NOT_MEMBER")
	f.must(f.AdminAPI("PATCH", member, map[string]any{"state": "active"}), 200, "reactivate membership")
	f.must(f.AdminAPI("POST", "/users/"+bob+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend target")
	denied("suspended target account", s.request(bob, f.Acme, nil), "TARGET_PROTECTED")
	f.must(f.AdminAPI("POST", "/users/"+bob+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate target")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/suspend", map[string]any{"reason": "billing hold"}), 200, "suspend globex")
	denied("suspended organization", s.request(bob, f.Globex, nil), "ORGANIZATION_NOT_ELIGIBLE")

	// IMP-005: reason and ticket.
	for _, reason := range []string{"", "   ", "help"} {
		if r := s.request(bob, f.Acme, map[string]any{"reason": reason}); r.Status != 422 {
			t.Errorf("reason %q: %d", reason, r.Status)
		}
	}
	mustStatus(t, f.SetPolicy(func(p *realmPolicy) { p.Impersonation.RequireTicket = true }), 200, "require tickets")
	if r := s.request(bob, f.Acme, map[string]any{"ticket_reference": ""}); r.Status != 422 || r.Get("errors.ticket_reference") == nil {
		t.Fatalf("missing ticket under a ticket policy: %d %s", r.Status, r.Raw)
	}
	req := s.request(bob, f.Acme, nil)
	mustStatus(t, req, 201, "request with reason and ticket")
	var reason, ticket string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT reason, coalesce(ticket_reference,'') FROM impersonation_requests WHERE id=$1`, req.Str("id")).Scan(&reason, &ticket); err != nil ||
		reason != "Customer reports missing order history in dashboard" || ticket != "SUP-1042" {
		t.Fatalf("support reason stored server-side: %q %q %v", reason, ticket, err)
	}
	out := h.API("POST", "/impersonation-requests/"+req.Str("id")+"/issue", s.samTok, nil)
	mustStatus(t, out, 201, "issue")
	in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, out.Str("access_token"))
	if in.Get("active") != true || strings.Contains(string(in.Raw), "SUP-1042") || strings.Contains(string(in.Raw), "missing order history") {
		t.Fatalf("support token exposes the reason or ticket: %s", in.Raw)
	}
}

// TestSupportSessionHonesty covers IMP-008 and IMP-018: a support token
// carries only the target's own authority — permissions the operator holds in
// the organization are never added — and it claims no authentication by the
// target: no auth_time, acr or amr, while the operator's own MFA time is
// recorded separately on the grant.
func TestSupportSessionHonesty(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	sam, bob := f.Users["sam"], f.Users["bob"]
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": sam,
		"role_ids": []string{f.Roles["orders-refunder"], f.Roles["billing-viewer"]}}), 201, "sam joins acme")
	if eff, err := h.App.Authz.Effective(ctx, nil, h.Realm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: sam},
		authorization.Scope{Type: authorization.ScopeOrganization, ID: f.Acme}); err != nil || !eff.Has("billing.read") {
		t.Fatalf("fixture: the operator holds billing.read in acme: %v", err)
	}
	f.EnrollTOTP("bob")
	f.AccountToken("bob") // the target has fresh MFA evidence of their own
	s := f.support(t)
	out := s.issue(t, bob, f.Acme)
	tok := out.Str("access_token")
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	decide := func(action string) *Resp {
		r := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": tok, "action": action,
			"resource": map[string]any{"type": "order", "org_id": f.Acme}})
		mustStatus(t, r, 200, "decision "+action)
		return r
	}
	if r := decide("orders.read"); r.Get("allowed") != true {
		t.Fatalf("the target's own permission: %s", r.Raw)
	}
	if r := decide("billing.read"); r.Get("allowed") != false || r.Str("reason_code") != "NOT_PERMITTED" {
		t.Fatalf("the operator's permission was added to the support token: %s", r.Raw)
	}

	in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok)
	if in.Get("active") != true || in.Str("sub") != bob || in.Str("act.sub") != sam {
		t.Fatalf("support introspection: %s", in.Raw)
	}
	for _, k := range []string{"auth_time", "acr", "amr"} {
		if in.Get(k) != nil {
			t.Errorf("support token claims the target authenticated: %s=%v", k, in.Get(k))
		}
	}
	var authTime, acr *string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT auth_time::text, acr FROM opaque_access_tokens WHERE impersonation_grant_id=$1`, out.Str("grant.id")).Scan(&authTime, &acr); err != nil ||
		authTime != nil || acr != nil {
		t.Fatalf("support token stores target authentication evidence: %v %v %v", authTime, acr, err)
	}
	var actorMFA, sessionMFA *time.Time
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT g.actor_mfa_time, s.mfa_time FROM impersonation_grants g JOIN sessions s ON s.id=g.actor_session_id
		WHERE g.id=$1`, out.Str("grant.id")).Scan(&actorMFA, &sessionMFA); err != nil || actorMFA == nil || sessionMFA == nil || !actorMFA.Equal(*sessionMFA) {
		t.Fatalf("operator assurance must be recorded on the grant: %v %v %v", actorMFA, sessionMFA, err)
	}
}

// TestSupportGrantEndings covers IMP-016 and IMP-017: an authorized
// administrator can end a support grant and an unrelated user cannot; the
// operator's suspension ends it; and the target's lost permission, account
// suspension or organization suspension affects the very next check under
// the strict-online contract.
func TestSupportGrantEndings(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	s := f.support(t)
	bob := f.Users["bob"]
	active := func(tok string) bool {
		return h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok).Get("active") == true
	}

	byAdmin := s.issue(t, bob, f.Acme)
	alice := f.AdminTokenFor("alice").Tokens.Str("access_token")
	if r := h.API("POST", "/impersonation-grants/"+byAdmin.Str("grant.id")+"/revoke", alice, map[string]any{"reason": "not mine"}); r.Status == 204 {
		t.Fatal("an unrelated user ended a support grant")
	}
	if !active(byAdmin.Str("access_token")) {
		t.Fatal("grant ended by an unrelated user")
	}
	mustStatus(t, f.AdminAPI("POST", "/impersonation-grants/"+byAdmin.Str("grant.id")+"/revoke", map[string]any{"reason": "policy review"}), 204, "administrator revokes")
	if active(byAdmin.Str("access_token")) {
		t.Fatal("support grant survived an administrator's revocation")
	}

	// IMP-017: the target loses the permission behind the support read.
	tok := s.issue(t, bob, f.Acme).Str("access_token")
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	read := func() any {
		r := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": tok, "action": "orders.read",
			"resource": map[string]any{"type": "order", "org_id": f.Acme}})
		mustStatus(t, r, 200, "decision")
		return r.Get("allowed")
	}
	if read() != true {
		t.Fatal("fixture: bob reads acme orders")
	}
	list := f.must(f.AdminAPI("GET", "/role-assignments?subject_type=user&subject_id="+bob, nil), 200, "assignments")
	for _, it := range list.Get("items").([]any) {
		a := it.(map[string]any)
		if a["role_id"] == f.Roles["orders-viewer"] && a["scope"].(map[string]any)["id"] == f.Acme {
			mustStatus(t, f.AdminAPI("DELETE", "/role-assignments/"+a["id"].(string), nil), 204, "remove orders-viewer")
		}
	}
	if read() != false {
		t.Fatal("support access kept a permission the target lost")
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend target")
	if active(tok) {
		t.Fatal("support grant survived the target's suspension")
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate target")

	// IMP-016: the operator's suspension ends the grant.
	tok = s.issue(t, bob, f.Acme).Str("access_token")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["sam"]+"/suspend", map[string]any{"reason": "offboarding"}), 200, "suspend operator")
	if active(tok) {
		t.Fatal("support grant survived the operator's suspension")
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["sam"]+"/reactivate", map[string]any{"reason": "back"}), 200, "reactivate operator")

	// IMP-017: suspending the organization ends it.
	s = f.support(t)
	tok = s.issue(t, bob, f.Acme).Str("access_token")
	mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/suspend", map[string]any{"reason": "billing hold"}), 200, "suspend organization")
	if active(tok) {
		t.Fatal("support grant survived the organization's suspension")
	}
}
