package e2e

import "testing"

// TestGroupsHoldOrganizationRolesOnly: a group belongs to one organization
// and holds that organization's roles (AZ-010, TEN-013). Realm and project
// assignments to a group would be stored but never evaluated, so they are
// refused with 422 and nothing is stored.
func TestGroupsHoldOrganizationRolesOnly(t *testing.T) {
	f := NewFixture(t)
	group := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "auditors"}), 201, "group").Str("id")
	realmRole := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "realm-reader",
		"permissions": []string{"realm.users.read"}}), 201, "realm role").Str("id")
	project := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Ledger", "owner_organization_id": f.Acme}), 201, "project").Str("id")
	projectRole := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "project", "project_id": project, "name": "ledger-admin",
		"permissions": []string{"orders.read"}}), 201, "project role").Str("id")
	for name, body := range map[string]map[string]any{
		"realm":   {"role_id": realmRole, "subject": map[string]any{"type": "group", "id": group}},
		"project": {"role_id": projectRole, "subject": map[string]any{"type": "group", "id": group}, "scope": map[string]any{"type": "project", "id": project}},
	} {
		if r := f.AdminAPI("POST", "/role-assignments", body); r.Status != 422 || !containsRaw(r, "groups hold organization roles only") {
			t.Errorf("%s-scoped group assignment: %d %s", name, r.Status, r.Raw)
		}
	}
	var stored int
	if err := f.H.App.D.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM role_assignments WHERE subject_type='group' AND subject_id=$1`, group).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("refused group assignments stored: %d %v", stored, err)
	}
}
