package e2e

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSCIMScanBoundaryPreservesExactAndIndexedResults covers PROV-002,
// PROV-004, NFR-004 and NFR-006: 20000 managed resources are fully counted;
// 20001 broad/compound searches refuse instead of truncating. Indexed equality
// still returns exactly its owned resource, including at concurrency 32.
func TestSCIMScanBoundaryPreservesExactAndIndexedResults(t *testing.T) {
	for _, kind := range []string{"User", "Group"} {
		t.Run(kind, func(t *testing.T) {
			f := NewFixture(t)
			h, ctx := f.H, context.Background()
			r := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{
				"name": "scan-boundary", "role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "default_role_id": f.Roles["orders-viewer"]}), 201, "connector")
			token := r.Str("token")
			c, err := h.App.Provisioning.Authenticate(ctx, h.Realm.ID, token)
			if err != nil || c == nil || token == "" {
				t.Fatal("connector fixture incomplete")
			}
			connector := c.ID
			// Bulk rows are isolated boundary fixtures, not benchmark/API setup
			// throughput. No live state or rate counter is deleted/modified.
			seed := func(first, last int) {
				t.Helper()
				err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
					if kind == "User" {
						for _, q := range []string{
							`INSERT INTO users (id, realm_id, display_name, created_via)
							 SELECT 'usr_'||lpad(to_hex(n),26,'0'), $1, 'Scan user '||n, 'directory' FROM generate_series($3::int,$4::int) n
							 WHERE EXISTS (SELECT 1 FROM organizations WHERE id=$2 AND realm_id=$1)`,
							`INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value, is_primary, source)
							 SELECT 'idf_'||lpad(to_hex(n),26,'0'), $1, 'usr_'||lpad(to_hex(n),26,'0'), 'username', 'scan-user-'||n, 'scan-user-'||n, true, 'directory' FROM generate_series($3::int,$4::int) n
							 WHERE EXISTS (SELECT 1 FROM organizations WHERE id=$2 AND realm_id=$1)`,
							`INSERT INTO memberships (id, realm_id, organization_id, user_id, state, source)
							 SELECT 'mem_'||lpad(to_hex(n),26,'0'), $1, $2, 'usr_'||lpad(to_hex(n),26,'0'), 'active', 'directory' FROM generate_series($3::int,$4::int) n`,
						} {
							if _, err := tx.Exec(ctx, q, h.Realm.ID, f.Acme, first, last); err != nil {
								return err
							}
						}
					} else {
						if _, err := tx.Exec(ctx, `INSERT INTO groups (id, realm_id, organization_id, name, source)
						 SELECT 'grp_'||lpad(to_hex(n),26,'0'), $1, $2, 'scan-group-'||n, 'directory' FROM generate_series($3::int,$4::int) n`, h.Realm.ID, f.Acme, first, last); err != nil {
							return err
						}
					}
					prefix := "usr_"
					if kind == "Group" {
						prefix = "grp_"
					}
					_, err := tx.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id)
					 SELECT $1,$2,'scan-external-'||n,$3||lpad(to_hex(n),26,'0') FROM generate_series($4::int,$5::int) n`, connector, kind, prefix, first, last)
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			seed(1, 20000)
			old := h.App.D.DB.Pool
			counter := &scimQueryCounter{}
			cfg := old.Config()
			cfg.ConnConfig.Tracer = counter
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			h.App.D.DB.Pool = pool
			t.Cleanup(func() { h.App.D.DB.Pool = old; pool.Close() })
			call := func(filter string) *Resp {
				q := url.Values{"count": {"1000"}}
				if filter != "" {
					q.Set("filter", filter)
				}
				return h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/scim/v2/" + kind + "s?" + q.Encode(),
					Headers: map[string]string{"Authorization": "Bearer " + token}})
			}
			full := call("")
			mustStatus(t, full, 200, "exact scan boundary")
			if full.Get("totalResults") != float64(20000) || full.Get("itemsPerPage") != float64(200) || len(full.Get("Resources").([]any)) != 200 {
				t.Fatal("the 20000-resource scan was incomplete or paging was unbounded")
			}
			seed(20001, 20001)
			prefix, attr, name := "usr_", "userName", "scan-user-1"
			if kind == "Group" {
				prefix, attr, name = "grp_", "displayName", "scan-group-1"
			}
			id := fmt.Sprintf("%s%026x", prefix, 1)
			filters := []string{"", "id eq \"" + id + "\" and id pr", "id eq \"" + id + "\" or id eq \"" + id + "\"", "not (id ne \"" + id + "\")"}
			for _, filter := range filters {
				r := call(filter)
				if r.Status != 400 || r.Str("status") != "400" || r.Str("scimType") != "tooMany" || r.Get("Resources") != nil || r.Get("totalResults") != nil {
					t.Fatalf("over-limit scan did not refuse atomically: %d/%s", r.Status, r.Str("scimType"))
				}
			}
			indexed := []string{"id eq \"" + id + "\"", "externalId eq \"scan-external-1\"", attr + " eq \"" + name + "\""}
			for _, filter := range indexed {
				counter.calls.Store(0)
				r := call(filter)
				calls := counter.calls.Load()
				mustStatus(t, r, 200, "indexed over-limit lookup")
				items, ok := r.Get("Resources").([]any)
				if !ok || len(items) != 1 || r.Get("totalResults") != float64(1) || items[0].(map[string]any)["id"] != id || calls > 12 {
					t.Fatalf("indexed lookup changed scope or scanned the full set: items=%d calls=%d", len(items), calls)
				}
			}
			results := replicaBurst(t, []*Harness{h}, 32, func(i int, _ *Harness) *Resp {
				if i%2 == 0 {
					return call(filters[(i/2)%len(filters)])
				}
				return call(indexed[(i/2)%len(indexed)])
			})
			for i, r := range results {
				if i%2 == 0 {
					if r.Status != 400 || r.Str("scimType") != "tooMany" || r.Get("Resources") != nil {
						t.Fatal("concurrent broad scan became a successful/partial page")
					}
				} else if r.Status != 200 || r.Get("totalResults") != float64(1) || len(r.Get("Resources").([]any)) != 1 || r.Get("Resources").([]any)[0].(map[string]any)["id"] != id {
					t.Fatal("concurrent indexed lookup lost its exact owned resource")
				}
			}
			t.Log("20000 exact total and 200-row page; 20001 broad/compound scans refused; 16 concurrent refusals and 16 exact indexed successes")
		})
	}
}
