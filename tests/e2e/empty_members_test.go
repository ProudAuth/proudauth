package e2e

import "testing"

// API-004: empty membership pages retain the published array/cursor contract,
// both before a first membership and after removing the last live member.
func TestEmptyMembershipPagesAreArrays(t *testing.T) {
	f := NewFixture(t)
	org := f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "empty-members", "display_name": "Empty members"}), 201, "empty organization").Str("id")
	check := func() {
		t.Helper()
		for _, query := range []string{"", "?state=active"} {
			r := f.must(f.AdminAPI("GET", "/organizations/"+org+"/members"+query, nil), 200, "empty members")
			items, ok := r.Get("items").([]any)
			if !ok || len(items) != 0 || r.Str("next_cursor") != "" {
				t.Fatalf("empty page violates the array contract: %s", r.Raw)
			}
		}
	}
	check()
	m := f.must(f.AdminAPI("POST", "/organizations/"+org+"/members", map[string]any{"user_id": f.Users["carol"], "role_ids": []string{f.Roles["member"]}}), 201, "add member").Str("id")
	page := f.must(f.AdminAPI("GET", "/organizations/"+org+"/members", nil), 200, "nonempty members")
	if items, ok := page.Get("items").([]any); !ok || len(items) != 1 {
		t.Fatalf("member not listed: %s", page.Raw)
	}
	f.must(f.AdminAPI("DELETE", "/organizations/"+org+"/members/"+m, nil), 204, "remove member")
	check()
}
