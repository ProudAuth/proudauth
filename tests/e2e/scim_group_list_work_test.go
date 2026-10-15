package e2e

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/proudauth/proudauth/internal/provisioning"
)

// TestSCIMGroupListsBoundDatabaseRoundTrips covers PROV-002, PROV-008,
// NFR-004 and NFR-006: Group scans, including member-dependent filters and
// excluded members, must use bounded database round trips while preserving
// complete totals, member data, ETags and connector/organization boundaries.
func TestSCIMGroupListsBoundDatabaseRoundTrips(t *testing.T) {
	f := NewFixture(t)
	h, ctx := f.H, context.Background()
	r := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{
		"name": "bounded-group-list", "role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "default_role_id": f.Roles["orders-viewer"]}), 201, "connector")
	token := r.Str("token")
	c, err := h.App.Provisioning.Authenticate(ctx, h.Realm.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/realms/main/scim/v2/"
	headers := map[string]string{"Authorization": "Bearer " + token}
	var members []map[string]any
	for i := range 2 {
		r := h.Do(Req{Method: "POST", Path: path + "Users", Headers: headers,
			JSON: map[string]any{"userName": fmt.Sprintf("bounded-group-user-%d", i), "displayName": fmt.Sprintf("Group member %d", i), "active": true}})
		mustStatus(t, r, 201, "member fixture")
		members = append(members, map[string]any{"value": r.Str("id")})
	}
	filter, err := provisioning.ParseFilter("(" + strings.TrimSuffix(strings.Repeat("members pr or ", 32), " or ") + ")")
	if err != nil {
		t.Fatal(err)
	}
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
	base := h.Base + path[:len(path)-1]
	created := 0
	for _, size := range []int{8, 64} {
		for created < size {
			m := []map[string]any{}
			if created%2 == 0 {
				m = members
			}
			r := h.Do(Req{Method: "POST", Path: path + "Groups", Headers: headers,
				JSON: map[string]any{"displayName": fmt.Sprintf("bounded-group-%d", created), "externalId": fmt.Sprintf("group-external-%d", created), "members": m}})
			mustStatus(t, r, 201, "group fixture")
			created++
		}
		for _, includeMembers := range []bool{true, false} {
			counter.calls.Store(0)
			items, total, err := h.App.Provisioning.ListGroups(ctx, c, filter, 1, 3, base, includeMembers)
			calls := counter.calls.Load()
			t.Logf("%d managed groups, members=%t: %d database round trips", size, includeMembers, calls)
			if err != nil {
				t.Fatal(err)
			}
			if total != size/2 || len(items) != 3 {
				t.Fatalf("size %d: total %d, page %d", size, total, len(items))
			}
			if calls > 8 {
				t.Errorf("%d managed groups caused %d database round trips; require bounded work <=8", size, calls)
			}
			for _, item := range items {
				single, _, err := h.App.Provisioning.GetGroup(ctx, c, item["id"].(string), base)
				if err != nil {
					t.Fatal(err)
				}
				if !includeMembers {
					delete(single, "members")
				}
				if !reflect.DeepEqual(item, single) {
					t.Fatal("list changed member data or ETag compared with the individual read")
				}
			}
		}
	}
	// Public attribute projection must happen after member-dependent matching.
	q := url.Values{"filter": {"members[value eq \"" + members[0]["value"].(string) + "\"]"}, "excludedAttributes": {"members"}, "count": {"1000"}}
	page := h.Do(Req{Method: "GET", Path: path + "Groups?" + q.Encode(), Headers: headers})
	mustStatus(t, page, 200, "filtered attribute projection")
	if page.Get("totalResults") != float64(32) || page.Get("itemsPerPage") != float64(32) {
		t.Fatal("excluding members changed filter results")
	}
	for _, raw := range page.Get("Resources").([]any) {
		if _, exists := raw.(map[string]any)["members"]; exists {
			t.Fatal("excluded members leaked through projection")
		}
	}
	// Stale/foreign mappings cannot widen the group's organization boundary.
	foreign := f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/groups", map[string]any{"name": "foreign-list-group"}), 201, "foreign group").Str("id")
	if foreign == "" {
		t.Fatal("foreign fixture has no ID")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id)
		VALUES ($1,'Group','foreign-list-map',$2), ($1,'Group','missing-list-map','missing-group')`, c.ID, foreign); err != nil {
		t.Fatal(err)
	}
	items, total, err := h.App.Provisioning.ListGroups(ctx, c, nil, 1, 200, base, true)
	if err != nil || total != 64 || len(items) != 64 {
		t.Fatalf("foreign/missing mappings changed totals: %d/%d, %v", total, len(items), err)
	}
	for _, item := range items {
		if item["id"] == foreign || item["id"] == "missing-group" {
			t.Fatal("foreign/missing group escaped the connector boundary")
		}
	}
}
