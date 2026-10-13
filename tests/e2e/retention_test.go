package e2e

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/worker"
)

// TestOperationalRetention covers PRV-004/OPS-009: ended grants with their
// refresh tokens and the sessions they kept alive are removed after
// session_retention; a live grant is untouched.
func TestOperationalRetention(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/revoke-sessions", map[string]any{"reason": "test"}), 200, "end bob's sessions")
	count := func(sql string, args ...any) int {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	bobGrants := `SELECT count(*) FROM authorization_grants WHERE subject_id=$1`
	if count(bobGrants, f.Users["bob"]) == 0 {
		t.Fatal("no grant to purge")
	}
	// Finished sign-in transactions keep no full address or user agent (PRV-002).
	if _, err := h.App.Auth.CleanupChallenges(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM auth_transactions WHERE status <> 'pending' AND (client_ip IS NOT NULL OR user_agent IS NOT NULL)`); n != 0 {
		t.Fatalf("finished transactions keep network data: %d", n)
	}
	h.Clock.Advance(h.App.D.Cfg.Privacy.SessionRetention + 24*time.Hour)
	if _, err := w.Retention(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(bobGrants, f.Users["bob"]); n != 0 {
		t.Fatalf("ended grants kept: %d", n)
	}
	if n := count(`SELECT count(*) FROM sessions WHERE user_id=$1`, f.Users["bob"]); n != 0 {
		t.Fatalf("ended sessions kept: %d", n)
	}
	// A grant created now is untouched by the same run.
	fresh := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	if _, err := w.Retention(ctx); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {fresh}}, "web-bff", f.Clients["web"].Secret), 200, "live grant kept")
}

// TestDatabasePagedLists covers API-004 for lists paged in the database:
// cursors reach every item, pages do not overlap, and a cursor is bound to
// its list.
func TestDatabasePagedLists(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	for i := 0; i < 3; i++ {
		f.AccountToken("bob")
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	walk := func(get func(cursor string) *Resp) []string {
		t.Helper()
		var ids []string
		cursor := ""
		for page := 0; page < 50; page++ {
			r := get(cursor)
			mustStatus(t, r, 200, "page")
			items := r.Get("items").([]any)
			for _, it := range items {
				ids = append(ids, it.(map[string]any)["id"].(string))
			}
			cursor = r.Str("next_cursor")
			if cursor == "" {
				return ids
			}
			if len(items) != 2 {
				t.Fatalf("short page with a cursor: %s", r.Raw)
			}
		}
		t.Fatal("cursor never ended")
		return nil
	}
	events := walk(func(c string) *Resp {
		return h.API("GET", "/me/security-events?limit=2&cursor="+url.QueryEscape(c), bob, nil)
	})
	seen := map[string]bool{}
	for _, id := range events {
		if seen[id] {
			t.Fatalf("pages overlap at %s", id)
		}
		seen[id] = true
	}
	if len(events) < 4 {
		t.Fatalf("security events: %d", len(events))
	}
	jobs := walk(func(c string) *Resp {
		return f.AdminAPI("GET", "/notification-jobs?limit=2&cursor="+url.QueryEscape(c), nil)
	})
	if len(jobs) < 3 {
		t.Fatalf("notification jobs: %d", len(jobs))
	}
	// A cursor from one list is refused by another.
	first := h.API("GET", "/me/security-events?limit=2", bob, nil)
	mustStatus(t, f.AdminAPI("GET", "/notification-jobs?limit=2&cursor="+url.QueryEscape(first.Str("next_cursor")), nil), 400, "foreign cursor")
}
