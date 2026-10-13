package e2e

import "testing"

// TestSignInWithoutAnyOrganization: when a request needs an organization
// (a resource with requires_organization) and the user has no active
// membership, the transaction stops with the blocking reason
// `no_organization` and no next action, instead of offering an empty
// organization choice it could never leave (TEN-005).
func TestSignInWithoutAnyOrganization(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.CreateUser("nomad")
	o := LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud},
		Identifier: "nomad@example.test"}
	start, _, cont := h.StartTx(o)
	mustStatus(t, start, 201, "start")
	st := h.Drive(start.Str("transaction_id"), cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, o)
	if st.Str("status") != "pending" || st.Str("error") != "no_organization" {
		t.Fatalf("sign-in without any organization: %s", st.Raw)
	}
	if actions, _ := st.Get("next_actions").([]any); len(actions) != 0 {
		t.Fatalf("next actions offered without an organization: %s", st.Raw)
	}
	// With a membership the same sign-in offers that organization.
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["nomad"], "role_ids": []string{}}), 201, "membership")
	o.SelectOrg, o.ClientSecret = f.Acme, f.Clients["web"].Secret
	if res := h.Login(o); res.Code == "" {
		t.Fatalf("sign-in with a membership did not complete: %s", res.State.Raw)
	}
}
