package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
)

// TestFailureBudgetsStopAuditAmplification covers SEC-006, AUD-001, IMP-012
// and ABU-001 (the finding httpapi-surface/unauth-audit-amplification).
// Unauthenticated requests wrote audit records, with an identifier of the
// sender's choosing, before any budget applied: every failed client
// authentication at the token endpoint, and every bearer starting with
// pa_it_ on the identity and administration APIs (support.token.rejected,
// after a token lookup). Now introspection and revocation read the token
// endpoint's failure budget per network (token_failures_per_network) before
// client authentication, and their failed client authentications count
// against it with the token endpoint's: once a network has spent it, its
// token, introspection and revocation requests get 429 slow_down and write
// no audit record, valid ones included, while another network's succeed,
// and the network recovers in the next window. A client_id longer than any
// client can have (255 bytes) is refused with invalid_client before it is
// looked up or audited and counts as a failure. Support tokens on the APIs
// count against api_token_failures_per_network before they are looked up:
// once it is spent, the network's get 429 rate_limited and write nothing,
// while its other bearer tokens and another network's support tokens are
// unaffected.
func TestFailureBudgetsStopAuditAmplification(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h)
	rl := &h.App.D.Cfg.Security.RateLimits
	ctx := context.Background()
	rows := func(typ string) int {
		t.Helper()
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE $1='' OR type=$1`, typ).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ordersRS, web := f.Clients["orders-rs"], f.Clients["web"]
	introspect := func(addr, secret, tok string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/introspect", Basic: [2]string{"orders-rs", secret}, Headers: from(addr),
			Form: url.Values{"token": {tok}}})
	}
	revoke := func(addr, secret, tok string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Basic: [2]string{"web-bff", secret}, Headers: from(addr),
			Form: url.Values{"token": {tok}}})
	}
	junkClient := func(addr, id string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Headers: from(addr),
			Form: url.Values{"grant_type": {"client_credentials"}, "client_id": {id}}})
	}
	invalidClient := func(r *Resp, what string) {
		t.Helper()
		if r.Status != 401 || r.Str("error") != "invalid_client" {
			t.Fatalf("%s: want 401 invalid_client, got %d %s", what, r.Status, r.Raw)
		}
	}

	t.Run("token, introspection and revocation share the network's failure budget", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenFailuresPerNetwork = 3
		at := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		before := rows("")
		// One failed client authentication at each endpoint, from rotating
		// addresses of one /64; none of them is audited.
		invalidClient(introspect("2001:db8:60:1::1", "wrong-secret", at), "introspection with a wrong secret")
		invalidClient(revoke("2001:db8:60:1::2", "wrong-secret", at), "revocation with a wrong secret")
		invalidClient(junkClient("2001:db8:60:1::3", strings.Repeat("x", 256)), "a 256-byte client_id")
		if n := rows("") - before; n != 0 {
			t.Fatalf("%d audit records for failures that are not audited (a client_id over 255 bytes is never looked up)", n)
		}
		// The budget is spent: requests that would be audited (an unknown
		// client, a revocation), and valid ones, are refused before client
		// authentication and write nothing.
		refused := map[string]*Resp{
			"an unknown client from the exhausted network":     junkClient("2001:db8:60:1::4", "no-such-client"),
			"a 10 KB client_id from the exhausted network":     junkClient("2001:db8:60:1:ffff::1", strings.Repeat("y", 10*1024)),
			"a valid introspection from the exhausted network": introspect("2001:db8:60:1::5", ordersRS.Secret, at),
			"a valid revocation from the exhausted network":    revoke("2001:db8:60:1::6", web.Secret, at),
		}
		if n := rows("") - before; n != 0 {
			t.Fatalf("requests from the exhausted network wrote %d audit records", n)
		}
		for what, r := range refused {
			mustSlowDown(t, r, what)
		}
		// Another network is served: introspection, then a revocation that
		// is audited.
		if r := introspect("2001:db8:61:1::1", ordersRS.Secret, at); r.Status != 200 || r.Get("active") != true {
			t.Fatalf("introspection from another network: %d %s", r.Status, r.Raw)
		}
		revoked := rows("token.access.revoked")
		mustStatus(t, revoke("2001:db8:61:1::1", web.Secret, at), 200, "revocation from another network")
		if n := rows("token.access.revoked") - revoked; n != 1 {
			t.Fatalf("%d token.access.revoked records, want 1", n)
		}
		if r := introspect("2001:db8:61:1::1", ordersRS.Secret, at); r.Get("active") != false {
			t.Fatalf("revoked token still active: %s", r.Raw)
		}
		// The next window restores the network.
		h.Clock.Advance(time.Minute)
		next := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		if r := introspect("2001:db8:60:1::5", ordersRS.Secret, next); r.Status != 200 || r.Get("active") != true {
			t.Fatalf("introspection in the next window: %d %s", r.Status, r.Raw)
		}
		mustStatus(t, revoke("2001:db8:60:1::6", web.Secret, next), 200, "revocation in the next window")
		invalidClient(junkClient("2001:db8:60:1::4", "no-such-client"), "an unknown client in the next window")
	})

	t.Run("support tokens on the APIs", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.APITokenFailuresPerNetwork = 3
		account := f.AccountToken("bob").Tokens.Str("access_token")
		me := func(addr, tok string) *Resp {
			return h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/me", Token: tok, Headers: from(addr)})
		}
		support := func(i int) string { return fmt.Sprintf("pa_it_bogus%032d", i) }
		before := rows("support.token.rejected")
		for i := 1; i <= 3; i++ {
			if r := me(fmt.Sprintf("2001:db8:62:1::%x", i), support(i)); r.Status != 403 || r.Str("code") != "impersonation_restricted" {
				t.Fatalf("support token %d: %d %s", i, r.Status, r.Raw)
			}
		}
		if n := rows("support.token.rejected") - before; n != 3 {
			t.Fatalf("%d support.token.rejected records, want 3", n)
		}
		all := rows("")
		fourth, long := me("2001:db8:62:1::4", support(4)), me("2001:db8:62:1:ffff::1", "pa_it_"+strings.Repeat("z", 8000))
		if n := rows("") - all; n != 0 {
			t.Fatalf("support tokens from the exhausted network wrote %d audit records", n)
		}
		mustRateLimited(t, fourth, "a fourth support token from the /64")
		mustRateLimited(t, long, "a long support token from the /64")
		// Other bearer tokens from the network are not affected, nor are
		// another network's support tokens.
		mustStatus(t, me("2001:db8:62:1::5", account), 200, "an account token from the exhausted network")
		before = rows("support.token.rejected")
		if r := me("2001:db8:63:1::1", support(5)); r.Status != 403 || r.Str("code") != "impersonation_restricted" {
			t.Fatalf("support token from another network: %d %s", r.Status, r.Raw)
		}
		if n := rows("support.token.rejected") - before; n != 1 {
			t.Fatalf("%d support.token.rejected records from another network, want 1", n)
		}
		h.Clock.Advance(time.Minute)
		if r := me("2001:db8:62:1::4", support(6)); r.Status != 403 || r.Str("code") != "impersonation_restricted" {
			t.Fatalf("support token in the next window: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("audit identifiers are stored bounded", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenFailuresPerNetwork = 10000
		// 253 bytes, under the client_id bound, with a forged line.
		id := strings.Repeat("j", 200) + "\r\nforged: yes" + strings.Repeat("k", 40)
		invalidClient(junkClient("198.51.100.90", id), "a junk client_id with a line break")
		var stored string
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT actor_id FROM audit_events WHERE type='client.authentication.failed'
			ORDER BY seq DESC LIMIT 1`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != audit.BoundID(id) || len(stored) > audit.MaxIDBytes+17 || strings.ContainsAny(stored, "\r\n") ||
			!strings.HasPrefix(stored, strings.Repeat("j", 128)) {
			t.Fatalf("actor ID stored as %q (%d bytes)", stored, len(stored))
		}
		// The audit API finds the record by the original value.
		list := f.must(f.AdminAPI("GET", "/audit-events?type=client.authentication.failed&actor_id="+url.QueryEscape(id), nil), 200, "audit search")
		items, _ := list.Get("items").([]any)
		if len(items) != 1 || items[0].(map[string]any)["actor"].(map[string]any)["id"] != stored {
			t.Fatalf("audit search by the original client_id: %s", list.Raw)
		}
	})
}
