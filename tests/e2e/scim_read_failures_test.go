package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/proudauth/proudauth/internal/provisioning"
)

// TestSCIMReadFailuresDoNotBecomePartialLists covers PROV-002, NFR-006
// and QA-008: a database read failure after candidate discovery cannot become
// a successful partial/empty list or a false missing-user response. Locked
// tables and a short real PostgreSQL statement timeout exercise nested user,
// identifier, membership and group reads, not a mocked service response.
func TestSCIMReadFailuresDoNotBecomePartialLists(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	c := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{
		"name": "read-failure-fixture", "role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "default_role_id": f.Roles["orders-viewer"],
	}), 201, "connector")
	headers := map[string]string{"Authorization": "Bearer " + c.Str("token")}
	call := func(method, path string, body any) *Resp {
		return h.Do(Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: headers, JSON: body})
	}
	u := call("POST", "/Users", map[string]any{"userName": "scim-read-failure", "active": true, "externalId": "read-user"})
	mustStatus(t, u, 201, "owned user")
	g := call("POST", "/Groups", map[string]any{"displayName": "read-failure-group", "externalId": "read-group"})
	mustStatus(t, g, 201, "owned group")
	for _, path := range []string{"/Users", "/Groups"} {
		r := call("GET", path, nil)
		if r.Status != 200 || r.Get("totalResults") != float64(1) {
			t.Fatalf("baseline %s: %d %s", path, r.Status, r.Raw)
		}
	}
	// Only this isolated harness uses the short timeout. The original pool
	// holds the blocking lock; all server reads use fresh bounded connections.
	old := h.App.D.DB.Pool
	cfg := old.Config()
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "100"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.App.D.DB.Pool = pool
	t.Cleanup(func() { h.App.D.DB.Pool = old; pool.Close() })
	for _, tc := range []struct{ table, list, item string }{
		{"users", "/Users", "/Users/" + u.Str("id")},
		{"user_identifiers", "/Users", "/Users/" + u.Str("id")},
		{"memberships", "/Users", "/Users/" + u.Str("id")},
		{"groups", "/Groups", "/Groups/" + g.Str("id")},
		{"group_memberships", "/Groups", "/Groups/" + g.Str("id")},
	} {
		t.Run(tc.table, func(t *testing.T) {
			tx, err := old.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			// Table names are fixed test literals; no request data enters SQL.
			if _, err := tx.Exec(ctx, "LOCK TABLE "+tc.table+" IN ACCESS EXCLUSIVE MODE"); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{tc.list, tc.item} {
				r := call("GET", path, nil)
				schemas, _ := r.Get("schemas").([]any)
				if r.Status != 500 || r.Str("status") != "500" || r.Get("totalResults") != nil || r.Get("Resources") != nil {
					t.Errorf("read failure became a successful/missing result at %s: %d %s", path, r.Status, r.Raw)
				}
				if len(schemas) != 1 || schemas[0] != provisioning.SchemaError {
					t.Error("not a SCIM error document")
				}
				if (r.Status == 500 && r.Str("detail") != "internal error") || strings.Contains(string(r.Raw), "statement timeout") {
					t.Error("database failure detail disclosed")
				}
			}
		})
	}
	// Recovering the database restores complete lists. A genuinely deleted
	// account remains invisible; its retained connector mapping is not an error.
	if _, err := old.Exec(ctx, `UPDATE users SET state='deleted' WHERE id=$1`, u.Str("id")); err != nil {
		t.Fatal(err)
	}
	list := call("GET", "/Users", nil)
	if list.Status != 200 || list.Get("totalResults") != float64(0) {
		t.Fatalf("deleted account list: %d %s", list.Status, list.Raw)
	}
	missing := call("GET", "/Users/"+u.Str("id"), nil)
	if missing.Status != 404 {
		t.Fatalf("deleted account still visible: %d %s", missing.Status, missing.Raw)
	}
	recovered := call("GET", "/Groups", nil)
	if recovered.Status != 200 || recovered.Get("totalResults") != float64(1) {
		t.Fatalf("recovered list: %d %s", recovered.Status, recovered.Raw)
	}
}
