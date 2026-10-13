package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestPrivilegedRoleCapConsistent covers MIG-005 and AZ-024/AZ-025: the SQL
// that migration reconciliation uses to find privileged assignments decides
// exactly as IsPrivilegedRole, including its fail-closed cap: a composition
// of more than 64 roles counts as privileged in both.
func TestPrivilegedRoleCapConsistent(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	chain := func(label string, n int) string {
		t.Helper()
		if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO roles (id, realm_id, boundary_type, name, composite_role_ids)
			SELECT 'rol_cap'||$2||'_'||g, $1, 'organization', 'cap-'||$2||'-'||g,
				CASE WHEN g < $3 THEN ARRAY['rol_cap'||$2||'_'||(g+1)] ELSE '{}'::text[] END
			FROM generate_series(1, $3::int) g`, h.Realm.ID, label, n); err != nil {
			t.Fatal(err)
		}
		return "rol_cap" + label + "_1"
	}
	decide := func(id string) (bool, bool) {
		t.Helper()
		role, err := h.App.Authz.Role(ctx, nil, h.Realm.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		var inSQL bool
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM roles ro WHERE ro.realm_id=$1 AND ro.id=$2 AND `+
			authorization.PrivilegedRoleSQL(3)+`)`, h.Realm.ID, id, authorization.PrivilegedPermissions()).Scan(&inSQL); err != nil {
			t.Fatal(err)
		}
		return h.App.Authz.IsPrivilegedRole(ctx, nil, h.Realm.ID, role), inSQL
	}
	for _, c := range []struct {
		label string
		n     int
		want  bool
	}{{"a", authorization.MaxInspectedRoles, false}, {"b", authorization.MaxInspectedRoles + 1, true}, {"c", 3, false}} {
		inGo, inSQL := decide(chain(c.label, c.n))
		if inGo != c.want || inSQL != c.want {
			t.Fatalf("composition of %d roles: IsPrivilegedRole %v, PrivilegedRoleSQL %v, want %v", c.n, inGo, inSQL, c.want)
		}
	}
	// A privileged role at the end of a short chain is found by both.
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE roles SET composite_role_ids=ARRAY[$1::text] WHERE id='rol_capc_3'`, f.Roles["orders-refunder"]); err != nil {
		t.Fatal(err)
	}
	if inGo, inSQL := decide("rol_capc_1"); !inGo || !inSQL {
		t.Fatalf("privileged component: IsPrivilegedRole %v, PrivilegedRoleSQL %v", inGo, inSQL)
	}
}

// TestConfigReconcileClientType covers SDK-012: a reconcile that would update
// a client whose client_type differs is a plan error (validation, dry run
// and import alike), not a 422 from the update that rolls the import back;
// without reconcile the difference stays drift.
func TestConfigReconcileClientType(t *testing.T) {
	f := NewFixture(t)
	w := worker.New(f.H.App, "test")
	job := f.must(f.AdminAPI("POST", "/configuration/exports", nil), 202, "export")
	runWorker(t, w)
	dl := f.must(f.AdminAPI("POST", "/jobs/"+job.Str("job_id")+"/downloads", nil), 201, "download token")
	data := f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	var doc map[string]any
	if err := json.Unmarshal(data.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "policy")
	for _, c := range doc["clients"].([]any) {
		if m := c.(map[string]any); m["client_id"] == "partner-app" {
			m["client_type"], m["name"] = "confidential", "Partner App (now confidential)"
			delete(m, "token_endpoint_auth_method")
		}
	}
	plain := f.must(f.AdminAPI("POST", "/configuration/validate", doc), 200, "plan without reconcile")
	if len(plain.Get("errors").([]any)) != 0 || !strings.Contains(jsonString(plain.Get("drift")), "client_type") {
		t.Fatalf("without reconcile a type difference is drift: %s", plain.Raw)
	}
	plan := f.must(f.AdminAPI("POST", "/configuration/validate?mode=reconcile", doc), 200, "reconcile plan")
	errs := jsonString(plan.Get("errors"))
	if !strings.Contains(errs, "partner-app") || !strings.Contains(errs, "client_type") || strings.Contains(jsonString(plan.Get("update")), "client partner-app") {
		t.Fatalf("reconcile plan for a client whose type differs: %s", plan.Raw)
	}
	imp := f.AdminAPI("POST", "/configuration/imports?mode=reconcile", doc)
	if imp.Status != 422 || !strings.Contains(string(imp.Raw), "cannot change to confidential") {
		t.Fatalf("reconcile import: %d %s", imp.Status, imp.Raw)
	}
	var name, typ string
	_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT name, client_type FROM clients WHERE client_id='partner-app'`).Scan(&name, &typ)
	if name != "Partner App" || typ != "public_browser" {
		t.Fatalf("client changed by a refused import: %q %q", name, typ)
	}
}
