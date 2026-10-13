package e2e

import (
	"fmt"
	"testing"
)

// TestIdempotencyKeys covers API-005: a retried create with the same key and
// body returns the original result, the same key with another body is
// refused, and keys are bound to the actor and the route, so another
// administrator or another route using the same key is a fresh request.
// Secret-bearing responses are never replayed (API-006).
func TestIdempotencyKeys(t *testing.T) {
	f := NewFixture(t)
	postAs := func(token, path, key string, body map[string]any) *Resp {
		return f.H.Do(Req{Method: "POST", Path: "/api/v1/realms/main" + path, Token: token, JSON: body,
			Headers: map[string]string{"Idempotency-Key": key}})
	}
	post := func(key string, body map[string]any) *Resp { return postAs(f.AdminToken, "/organizations", key, body) }
	a := post("k1", map[string]any{"slug": "idem", "display_name": "Idem"})
	mustStatus(t, a, 201, "create")
	b := post("k1", map[string]any{"slug": "idem", "display_name": "Idem"})
	mustStatus(t, b, 201, "replay")
	if b.Str("id") != a.Str("id") || b.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatal("retry must return the original result without creating another organization")
	}
	mustStatus(t, post("k1", map[string]any{"slug": "other", "display_name": "Other"}), 422, "key reused with different body")
	// The key is bound to its actor and route.
	tina := f.CreateUser("tina")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["realm-admin"], "subject": map[string]any{"type": "user", "id": tina}}), 201, "second admin")
	other := postAs(f.AdminTokenFor("tina").Tokens.Str("access_token"), "/organizations", "k1", map[string]any{"slug": "idem-tina", "display_name": "Tina"})
	mustStatus(t, other, 201, "same key, another actor")
	if other.Header.Get("Idempotent-Replayed") != "" || other.Str("id") == a.Str("id") {
		t.Fatal("another actor's request was matched to the first actor's key")
	}
	mustStatus(t, postAs(f.AdminToken, "/permissions", "k1", map[string]any{"name": "idem.read"}), 201, "same key, another route")
	// Secret-bearing responses are never replayed (API-006).
	c := f.H.Do(Req{Method: "POST", Path: "/api/v1/realms/main/clients", Token: f.AdminToken, Headers: map[string]string{"Idempotency-Key": "c1"},
		JSON: map[string]any{"client_id": "idem-client", "name": "x", "client_type": "confidential", "redirect_uris": []string{"https://x.test/cb"}}})
	mustStatus(t, c, 201, "client")
	again := f.H.Do(Req{Method: "POST", Path: "/api/v1/realms/main/clients", Token: f.AdminToken, Headers: map[string]string{"Idempotency-Key": "c1"},
		JSON: map[string]any{"client_id": "idem-client", "name": "x", "client_type": "confidential", "redirect_uris": []string{"https://x.test/cb"}}})
	mustStatus(t, again, 409, "secret response not replayed")
	if again.Str("client_secret") != "" {
		t.Fatal("secret replayed")
	}
}

// TestListPagination covers API-004 for lists paged by the generic helper:
// bounded pages, stable cursors bound to the route and filters, and rejection
// of tampered or replayed cursors.
func TestListPagination(t *testing.T) {
	f := NewFixture(t)
	for i := 0; i < 5; i++ {
		f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": fmt.Sprintf("paged-%d", i),
			"permissions": []string{"realm.users.read"}}), 201, "role")
	}
	seen := map[string]bool{}
	cursor, pages := "", 0
	for {
		q := "/roles?boundary_type=realm&limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		page := f.must(f.AdminAPI("GET", q, nil), 200, "page")
		items := page.Get("items").([]any)
		if len(items) > 2 {
			t.Fatalf("page exceeds limit: %d", len(items))
		}
		for _, it := range items {
			id := it.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("item %s repeated across pages", id)
			}
			seen[id] = true
		}
		pages++
		cursor = page.Str("next_cursor")
		if cursor == "" || pages > 20 {
			break
		}
	}
	all := f.must(f.AdminAPI("GET", "/roles?boundary_type=realm&limit=200", nil), 200, "all")
	if len(seen) != len(all.Get("items").([]any)) || pages < 3 {
		t.Fatalf("pagination lost items: %d seen, %d total, %d pages", len(seen), len(all.Get("items").([]any)), pages)
	}
	first := f.must(f.AdminAPI("GET", "/roles?boundary_type=realm&limit=2", nil), 200, "first")
	next := first.Str("next_cursor")
	mustStatus(t, f.AdminAPI("GET", "/roles?boundary_type=organization&limit=2&cursor="+next, nil), 400, "cursor replayed with another filter")
	mustStatus(t, f.AdminAPI("GET", "/projects?limit=2&cursor="+next, nil), 400, "cursor replayed on another route")
	mustStatus(t, f.AdminAPI("GET", "/roles?boundary_type=realm&limit=2&cursor=x"+next, nil), 400, "tampered cursor")
}
