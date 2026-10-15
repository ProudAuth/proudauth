package e2e

import (
	"context"
	"net/url"
	"slices"
	"testing"

	"github.com/proudauth/proudauth-sdk-go/admin"
)

// TestAdminSDKTypedOperations covers SDK-003 against a running server: the
// typed Go administration client (which the identity-cli commands wrap)
// manages users, organizations and members, invitations, clients and their
// resource grants, roles and assignments (a realm role with the
// server-applied realm scope), sessions and support access end to end.
func TestAdminSDKTypedOperations(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	c := &admin.Client{BaseURL: h.Srv.URL, Realm: "main", Token: admin.StaticToken(f.AdminToken), HTTPClient: h.Srv.Client()}
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	// Users.
	created, err := c.CreateUser(ctx, map[string]any{"email": "dora@example.test", "username": "dora", "display_name": "Dora"})
	must("create user", err)
	dora, _ := created["user"].(map[string]any)["id"].(string)
	state := func() string {
		s := ""
		must("users", c.Users(ctx, "dora@example.test", func(u admin.User) error {
			if u.ID == dora {
				s = u.State
			}
			return nil
		}))
		return s
	}
	if state() == "" {
		t.Fatal("created user not listed")
	}
	must("suspend", c.SetUserState(ctx, dora, "suspend", "investigation"))
	if s := state(); s != "suspended" {
		t.Fatalf("state after suspend: %q", s)
	}
	must("reactivate", c.SetUserState(ctx, dora, "reactivate", "cleared"))

	// Organizations, members and invitations.
	org, err := c.CreateOrganization(ctx, "initech", "Initech")
	must("create organization", err)
	orgRoles, err := c.Roles(ctx, "organization")
	must("organization roles", err)
	memberRole := ""
	for _, r := range orgRoles {
		if r.Name == "member" {
			memberRole = r.ID
		}
	}
	m, err := c.AddMember(ctx, org.ID, dora, []string{memberRole})
	must("add member", err)
	listed := false
	must("members", c.Members(ctx, org.ID, func(x admin.Membership) error {
		listed = listed || (x.ID == m.ID && x.UserID == dora)
		return nil
	}))
	if !listed {
		t.Fatal("new member not listed")
	}
	inv, err := c.Invite(ctx, org.ID, "eve@example.test", nil)
	must("invite", err)
	invID, _ := inv["invitation"].(map[string]any)["id"].(string)
	must("revoke invitation", c.RevokeInvitation(ctx, org.ID, invID))
	revoked := false
	must("invitations", c.Invitations(ctx, org.ID, "revoked", func(i admin.Invitation) error {
		revoked = revoked || i.ID == invID
		return nil
	}))
	if !revoked {
		t.Fatal("revoked invitation not listed as revoked")
	}

	// Clients and resource grants.
	cl, err := c.CreateClient(ctx, map[string]any{"client_id": "sdk-portal", "name": "SDK portal", "client_type": "confidential",
		"redirect_uris": []string{"https://portal.test/cb"}})
	must("create client", err)
	ref, _ := cl["client"].(map[string]any)["id"].(string)
	must("resource grant", c.SetResourceGrant(ctx, ref, f.Orders, []string{"orders:read"}, []string{"user"}))
	var grant map[string]any
	_, err = c.Do(ctx, "GET", "/clients/"+ref+"/resource-grants/"+f.Orders, nil, &grant)
	must("read grant", err)
	if jsonString(grant["allowed_scopes"]) != `["orders:read"]` || jsonString(grant["subject_types"]) != `["user"]` {
		t.Fatalf("resource grant: %v", grant)
	}
	clients := []string{}
	must("clients", c.Clients(ctx, func(x admin.OAuthClient) error { clients = append(clients, x.ClientID); return nil }))
	if !slices.Contains(clients, "sdk-portal") {
		t.Fatalf("clients: %v", clients)
	}

	// Roles and assignments: a realm role without a scope, an organization role.
	realmRoles, err := c.Roles(ctx, "realm")
	must("realm roles", err)
	auditor := ""
	for _, r := range realmRoles {
		if r.Name == "realm-auditor" {
			auditor = r.ID
		}
	}
	_, err = c.Assign(ctx, auditor, "user", dora, "", "")
	must("assign realm role", err)
	_, err = c.Assign(ctx, f.Roles["billing-viewer"], "user", dora, "organization", org.ID)
	must("assign organization role", err)
	perms, err := c.SubjectPermissions(ctx, dora, org.ID)
	must("permissions", err)
	if !slices.Contains(perms.Permissions, "billing.read") {
		t.Fatalf("organization role not effective: %v", perms.Permissions)
	}
	realmPerms, err := c.SubjectPermissions(ctx, dora, "")
	must("realm permissions", err)
	if !slices.Contains(realmPerms.Permissions, "realm.audit.read") {
		t.Fatalf("realm role not effective: %v", realmPerms.Permissions)
	}

	// Sessions.
	f.AccountToken("alice")
	sessions, err := c.UserSessions(ctx, f.Users["alice"])
	must("sessions", err)
	if len(sessions) == 0 {
		t.Fatal("no sessions listed")
	}
	must("revoke session", c.RevokeSession(ctx, f.Users["alice"], sessions[0].ID))
	after, err := c.UserSessions(ctx, f.Users["alice"])
	must("sessions after revoke", err)
	if len(after) != len(sessions)-1 {
		t.Fatalf("sessions after revoking one: %d of %d", len(after), len(sessions))
	}
	if _, err := c.RevokeSessions(ctx, f.Users["alice"]); err != nil {
		t.Fatal(err)
	}

	// Support access, requested and issued by the support operator.
	s := f.support(t)
	sc := &admin.Client{BaseURL: h.Srv.URL, Realm: "main", Token: admin.StaticToken(s.samTok), HTTPClient: h.Srv.Client()}
	req, err := sc.RequestImpersonation(ctx, map[string]any{"target_user_id": f.Users["bob"], "organization_id": f.Acme, "client_id": "support-bff",
		"audience": f.OrdersAud, "reason": "Customer reports missing order history in dashboard"})
	must("request support access", err)
	issued, err := sc.IssueImpersonation(ctx, req["id"].(string))
	must("issue support access", err)
	grantID, _ := issued["grant"].(map[string]any)["id"].(string)
	active, err := c.ImpersonationGrants(ctx, url.Values{"state": {"active"}})
	must("support grants", err)
	if !slices.ContainsFunc(active, func(g admin.SupportGrant) bool { return g.ID == grantID && g.TargetUserID == f.Users["bob"] }) {
		t.Fatalf("support grant %s not listed: %+v", grantID, active)
	}
	must("revoke support access", sc.RevokeImpersonation(ctx, grantID, "done"))
	supportToken, ok := issued["access_token"].(admin.Secret) // one-time secrets stay redacted (SDK-008)
	if !ok {
		t.Fatalf("support token not wrapped as a secret: %T", issued["access_token"])
	}
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, supportToken.Reveal()); in.Get("active") != false {
		t.Fatalf("support token active after revocation: %s", in.Raw)
	}
}
