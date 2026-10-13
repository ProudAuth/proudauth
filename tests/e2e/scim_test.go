package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/organization"
)

// TestSCIMProvisioning covers PROV-001..PROV-009 and PROV-018: a connector
// bound to one organization provisions accounts and groups through SCIM 2.0;
// external IDs are its own namespace; existing accounts are adopted only
// through a verified domain; deprovisioning removes only the organization's
// access; protected accounts are out of reach; writes honor ETags; group
// roles come only from approved mappings.
func TestSCIMProvisioning(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	viewer := f.Roles["orders-viewer"]
	connPath := "/organizations/" + f.Acme + "/provisioning-connectors"
	// A connector's ceiling must be within its creator's own ceiling.
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	if r := h.API("POST", "/organizations/"+f.Globex+"/provisioning-connectors", carol, map[string]any{"name": "x", "role_ceiling_ids": []string{f.Roles["owner"]}}); r.Status == 201 {
		t.Fatalf("connector beyond its creator's ceiling: %s", r.Raw)
	}
	created := f.must(f.AdminAPI("POST", connPath, map[string]any{"name": "Okta", "role_ceiling_ids": []string{viewer}, "default_role_id": viewer,
		"group_role_mappings": map[string]any{"Support Team": []string{viewer}}}), 201, "connector")
	token, connID := created.Str("token"), created.Str("connector.id")
	if !strings.HasPrefix(token, "pa_scim_") || !strings.HasSuffix(created.Str("scim_base_url"), "/scim/v2") {
		t.Fatalf("connector: %s", created.Raw)
	}
	scim := func(method, path string, body any, headers ...string) *Resp {
		t.Helper()
		hdr := map[string]string{"Authorization": "Bearer " + token}
		for i := 0; i+1 < len(headers); i += 2 {
			hdr[headers[i]] = headers[i+1]
		}
		rq := Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: hdr}
		if body != nil {
			rq.JSON = body
		}
		return h.Do(rq)
	}
	if r := scim("GET", "/ServiceProviderConfig", nil); r.Status != 200 || r.Get("bulk.supported") != false || r.Get("patch.supported") != true {
		t.Fatalf("service provider config: %d %s", r.Status, r.Raw)
	}
	if r := h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/scim/v2/Users", Headers: map[string]string{"Authorization": "Bearer pa_scim_wrong"}}); r.Status != 401 {
		t.Fatalf("wrong token: %d", r.Status)
	}

	// Provision a new account.
	alice := scim("POST", "/Users", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "scim.newbie",
		"externalId": "okta-1", "name": map[string]any{"givenName": "New", "familyName": "Bie"}, "emails": []map[string]any{{"value": "newbie@acme-corp.test", "primary": true}},
		"active": true})
	if alice.Status != 201 || alice.Header.Get("Location") == "" || alice.Header.Get("ETag") == "" || alice.Str("externalId") != "okta-1" || alice.Get("active") != true {
		t.Fatalf("create user: %d %s", alice.Status, alice.Raw)
	}
	aliceID := alice.Str("id")
	if r := scim("POST", "/Users", map[string]any{"userName": "other", "externalId": "okta-1"}); r.Status != 409 || r.Str("scimType") != "uniqueness" {
		t.Fatalf("duplicate externalId: %d %s", r.Status, r.Raw)
	}
	var verified bool
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM user_identifiers WHERE user_id=$1 AND type='email'`, aliceID).Scan(&verified)
	if verified {
		t.Fatal("email verified without a verified organization domain")
	}
	// An existing account is not taken over without a verified domain.
	if r := scim("POST", "/Users", map[string]any{"userName": "bob", "emails": []map[string]any{{"value": "bob@example.test"}}}); r.Status != 409 {
		t.Fatalf("takeover of an existing account: %d %s", r.Status, r.Raw)
	}
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	ch := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains", map[string]any{"domain": "example.test"}), 201, "domain")
	organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify domain")
	// The deployment administrator stays out of reach even in a verified domain.
	if r := scim("POST", "/Users", map[string]any{"userName": "admin", "emails": []map[string]any{{"value": "admin@example.test"}}}); r.Status != 409 {
		t.Fatalf("protected account adopted: %d %s", r.Status, r.Raw)
	}
	bob := scim("POST", "/Users", map[string]any{"userName": "bob", "externalId": "okta-bob", "emails": []map[string]any{{"value": "bob@example.test"}}})
	if bob.Status != 201 || bob.Str("id") != f.Users["bob"] {
		t.Fatalf("adopt through a verified domain: %d %s", bob.Status, bob.Raw)
	}
	// bob also belongs to Globex: his identity is not this connector's to change.
	if r := scim("PATCH", "/Users/"+f.Users["bob"], map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Bobby"}}}); r.Status != 400 ||
		r.Str("scimType") != "mutability" {
		t.Fatalf("shared account identity changed: %d %s", r.Status, r.Raw)
	}
	// Deactivation suspends only the Acme membership (Azure AD style patch).
	if r := scim("PATCH", "/Users/"+f.Users["bob"], map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}}}); r.Status != 200 || r.Get("active") != false {
		t.Fatalf("deactivate: %d %s", r.Status, r.Raw)
	}
	state := func(org string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM memberships WHERE organization_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 1`, org, f.Users["bob"]).Scan(&s)
		return s
	}
	var userState string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["bob"]).Scan(&userState)
	if state(f.Acme) != "suspended" || state(f.Globex) != "active" || userState != "active" {
		t.Fatalf("deprovisioning scope: acme %s globex %s account %s", state(f.Acme), state(f.Globex), userState)
	}
	mustStatus(t, scim("DELETE", "/Users/"+f.Users["bob"], nil), 204, "delete")
	if state(f.Acme) != "removed" || state(f.Globex) != "active" {
		t.Fatalf("delete removed more than the organization's access: acme %s globex %s", state(f.Acme), state(f.Globex))
	}
	mustStatus(t, scim("GET", "/Users/"+f.Users["bob"], nil), 404, "deprovisioned user")

	// Filters, attribute selection and pagination.
	list := scim("GET", "/Users?filter="+url.QueryEscape(`userName eq "SCIM.NEWBIE"`)+"&attributes=userName", nil)
	res, _ := list.Get("Resources").([]any)
	if list.Get("totalResults") != float64(1) || len(res) != 1 || res[0].(map[string]any)["emails"] != nil || res[0].(map[string]any)["id"] != aliceID {
		t.Fatalf("filtered list: %s", list.Raw)
	}
	if r := scim("GET", "/Users?filter="+url.QueryEscape(`externalId eq "OKTA-1"`), nil); r.Get("totalResults") != float64(0) {
		t.Fatalf("externalId is case-exact: %s", r.Raw)
	}
	if r := scim("GET", "/Users?filter="+url.QueryEscape(`emails[type eq "work" and value co "acme-corp"]`), nil); r.Get("totalResults") != float64(1) {
		t.Fatalf("value path filter: %s", r.Raw)
	}
	mustStatus(t, scim("GET", "/Users?filter="+url.QueryEscape(`userName zz "x"`), nil), 400, "invalid filter")

	// Owned account: identity changes allowed; stale ETags refused.
	upd := scim("PUT", "/Users/"+aliceID, map[string]any{"userName": "scim.newbie", "displayName": "Newbie", "name": map[string]any{"givenName": "New", "familyName": "Bie"},
		"emails": []map[string]any{{"value": "newbie@acme-corp.test", "primary": true}}, "active": true}, "If-Match", alice.Header.Get("ETag"))
	if upd.Status != 200 || upd.Str("displayName") != "Newbie" || upd.Header.Get("ETag") == alice.Header.Get("ETag") {
		t.Fatalf("replace: %d %s", upd.Status, upd.Raw)
	}
	mustStatus(t, scim("PATCH", "/Users/"+aliceID, map[string]any{"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"displayName": "X"}}}},
		"If-Match", alice.Header.Get("ETag")), 412, "stale If-Match")
	// A change made through the administration API makes the tag stale too.
	f.must(f.AdminAPI("PATCH", "/users/"+aliceID, map[string]any{"display_name": "Changed By Admin"}), 200, "admin edit")
	mustStatus(t, scim("PATCH", "/Users/"+aliceID, map[string]any{"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"displayName": "Y"}}}},
		"If-Match", upd.Header.Get("ETag")), 412, "tag stale after an admin edit")
	// An eq filter on userName is answered without scanning.
	if r := scim("GET", "/Users?filter="+url.QueryEscape(`userName eq "scim.newbie"`), nil); r.Get("totalResults") != float64(1) {
		t.Fatalf("userName eq: %s", r.Raw)
	}

	// Groups: approved mappings grant roles; members come from provisioned users.
	g := scim("POST", "/Groups", map[string]any{"displayName": "Support Team", "externalId": "grp-1", "members": []map[string]any{{"value": aliceID}}})
	if g.Status != 201 || len(g.Get("members").([]any)) != 1 {
		t.Fatalf("create group: %d %s", g.Status, g.Raw)
	}
	var mapped int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1 AND role_id=$2 AND source='scim'`,
		g.Str("id"), viewer).Scan(&mapped)
	if mapped != 1 {
		t.Fatal("approved group mapping not applied")
	}
	if r := scim("POST", "/Groups", map[string]any{"displayName": "Strangers", "members": []map[string]any{{"value": f.Users["carol"]}}}); r.Status != 400 {
		t.Fatalf("member not provisioned by the connector: %d %s", r.Status, r.Raw)
	}
	rm := scim("PATCH", "/Groups/"+g.Str("id"), map[string]any{"Operations": []map[string]any{{"op": "Remove", "path": fmt.Sprintf(`members[value eq "%s"]`, aliceID)}}})
	if rm.Status != 200 || len(rm.Get("members").([]any)) != 0 {
		t.Fatalf("remove member: %d %s", rm.Status, rm.Raw)
	}
	// A role an administrator grants to the group puts it beyond the
	// connector's ceiling: the connector can no longer add members.
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+g.Str("id")+"/roles", map[string]any{"role_id": f.Roles["owner"]}), 201, "admin grant")
	mustStatus(t, scim("PATCH", "/Groups/"+g.Str("id"), map[string]any{"Operations": []map[string]any{{"op": "add", "path": "members",
		"value": []map[string]any{{"value": aliceID}}}}}), 403, "member add beyond the ceiling")
	mustStatus(t, scim("DELETE", "/Groups/"+g.Str("id"), nil), 204, "delete group")
	var unassigned int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='role.unassigned' AND reason_code='GROUP_DELETED'`).Scan(&unassigned)
	if unassigned < 1 {
		t.Fatal("group deletion removed role assignments without evidence")
	}

	// Operational evidence, token rotation and disabling.
	conn := f.must(f.AdminAPI("GET", connPath+"/"+connID, nil), 200, "connector")
	if conn.Str("last_sync_at") == "" || conn.Get("stats.post_user") == nil || conn.Get("stats.errors") == nil {
		t.Fatalf("connector evidence: %s", conn.Raw)
	}
	old := token
	token = f.must(f.AdminAPI("POST", connPath+"/"+connID+"/token", nil), 200, "rotate").Str("token")
	if r := h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/scim/v2/Users", Headers: map[string]string{"Authorization": "Bearer " + old}}); r.Status != 401 {
		t.Fatalf("old token after rotation: %d", r.Status)
	}
	mustStatus(t, scim("GET", "/Users", nil), 200, "new token")
	disable := map[string]any{"name": "Okta", "role_ceiling_ids": []string{viewer}, "state": "disabled"}
	mustStatus(t, f.AdminAPI("PUT", connPath+"/"+connID, disable), 428, "update without If-Match")
	cur := f.must(f.AdminAPI("GET", connPath+"/"+connID, nil), 200, "connector")
	f.must(h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + connPath + "/" + connID, Token: f.AdminToken, JSON: disable,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "disable")
	mustStatus(t, scim("GET", "/Users", nil), 401, "disabled connector")
}
