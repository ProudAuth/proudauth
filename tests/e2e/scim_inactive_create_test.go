package e2e

import (
	"context"
	"testing"
)

// TestSCIMInitiallyInactiveUserWithDefaultRole covers PROV-004, PROV-005
// and QA-008: a valid initially inactive account gets its configured default
// role atomically with a suspended membership, and later reactivation makes
// that membership active without duplicating or broadening the role.
func TestSCIMInitiallyInactiveUserWithDefaultRole(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	role := f.Roles["orders-viewer"]
	c := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "inactive-create-fixture", "role_ceiling_ids": []string{role}, "default_role_id": role}), 201, "connector")
	headers := map[string]string{"Authorization": "Bearer " + c.Str("token")}
	call := func(method, path string, body any) *Resp {
		return h.Do(Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: headers, JSON: body})
	}
	u := call("POST", "/Users", map[string]any{"userName": "initially-inactive", "active": false, "externalId": "inactive-owned"})
	if u.Status != 201 || u.Get("active") != false {
		t.Fatalf("initially inactive SCIM user: %d %s", u.Status, u.Raw)
	}
	id := u.Str("id")
	check := func(want string) {
		t.Helper()
		var state string
		var roles int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT m.state, (SELECT count(*) FROM role_assignments ra WHERE ra.membership_id=m.id AND ra.role_id=$3 AND ra.source='scim') FROM memberships m WHERE m.organization_id=$1 AND m.user_id=$2`, f.Acme, id, role).Scan(&state, &roles); err != nil {
			t.Fatal(err)
		}
		if state != want || roles != 1 {
			t.Fatalf("membership %s, default role count %d; want %s/1", state, roles, want)
		}
	}
	check("suspended")
	read := call("GET", "/Users/"+id, nil)
	if read.Status != 200 || read.Get("active") != false || read.Str("externalId") != "inactive-owned" {
		t.Fatalf("inactive read %d %s", read.Status, read.Raw)
	}
	headers["If-Match"] = read.Header.Get("ETag")
	active := call("PATCH", "/Users/"+id, map[string]any{"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": true}}})
	if active.Status != 200 || active.Get("active") != true {
		t.Fatalf("reactivation %d %s", active.Status, active.Raw)
	}
	check("active")
}
