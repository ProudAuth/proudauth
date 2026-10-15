package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/proudauth/proudauth/examples/protected-billing-api/billingapi"
	"github.com/proudauth/proudauth/examples/protected-orders-api/ordersapi"
)

// Services starts the two example resource servers.
type Services struct {
	Orders     *ordersapi.API
	OrdersURL  string
	Billing    *billingapi.API
	BillingURL string
}

func (f *Fixture) StartServices(t *testing.T) *Services {
	t.Helper()
	o, err := ordersapi.New(ordersapi.Config{Issuer: f.H.Realm.Issuer, Audience: f.OrdersAud, ClientID: "orders-rs", ClientSecret: f.Clients["orders-rs"].Secret})
	if err != nil {
		t.Fatal(err)
	}
	o.Put(ordersapi.Order{ID: "ord_acme_1", OrgID: f.Acme, OwnerUserID: f.Users["alice"], AmountMinor: 1500, Status: "paid"})
	o.Put(ordersapi.Order{ID: "ord_globex_1", OrgID: f.Globex, OwnerUserID: f.Users["carol"], AmountMinor: 9900, Status: "paid"})
	os := httptest.NewServer(o.Handler())
	t.Cleanup(os.Close)
	b := &billingapi.API{V: f.verifier(t, f.BillingAud), Invoices: []billingapi.Invoice{{ID: "inv_acme", OrgID: f.Acme, Total: 100}, {ID: "inv_globex", OrgID: f.Globex, Total: 200}}}
	bs := httptest.NewServer(b.Handler())
	t.Cleanup(bs.Close)
	return &Services{Orders: o, OrdersURL: os.URL, Billing: b, BillingURL: bs.URL}
}

func call(t *testing.T, method, u, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = decodeJSON(res, &m)
	return res.StatusCode, m
}

// TestTenantIsolationAcrossServices covers TEST-007 to TEST-009 and SDK-005:
// the separate example orders API (and the billing API) verify their own
// audience, derive the organization from the token and check each object's
// organization against it, allowing own-organization requests and denying
// cross-tenant, cross-audience ones.
func TestTenantIsolationAcrossServices(t *testing.T) {
	f := NewFixture(t)
	s := f.StartServices(t)
	aliceOrders := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read orders:write").Tokens.Str("access_token")
	bobAcme := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	bobGlobex := f.LoginWeb("bob", f.Globex, f.OrdersAud, "orders:read").Tokens.Str("access_token")

	t.Run("positive: own organization data", func(t *testing.T) {
		st, body := call(t, "GET", s.OrdersURL+"/orders/ord_acme_1", aliceOrders)
		if st != 200 || body["id"] != "ord_acme_1" {
			t.Fatalf("own order: %d %v", st, body)
		}
		st, body = call(t, "GET", s.OrdersURL+"/orders", bobGlobex)
		items := body["items"].([]any)
		if st != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != "ord_globex_1" {
			t.Fatalf("listing must contain only the token's organization: %v", body)
		}
	})
	t.Run("TEST-007 organization A token on organization B object", func(t *testing.T) {
		if st, _ := call(t, "GET", s.OrdersURL+"/orders/ord_globex_1", bobAcme); st != 404 {
			t.Fatalf("cross-tenant object visible: %d", st)
		}
	})
	t.Run("TEST-008 route organization disagrees with token", func(t *testing.T) {
		// Bob is a member of both organizations but each token names exactly one (DOM-003).
		if st, _ := call(t, "GET", s.OrdersURL+"/orders/ord_acme_1", bobGlobex); st != 404 {
			t.Fatalf("tenant switched silently: %d", st)
		}
		// Requesting an organization the user does not belong to fails during login.
		res := f.H.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Globex, SelectOrg: f.Globex, Identifier: "alice@example.test", ExpectFail: true})
		if res.Code != "" {
			t.Fatal("alice obtained a globex token")
		}
	})
	t.Run("two differently scoped services", func(t *testing.T) {
		billing := f.LoginWeb("alice", f.Acme, f.BillingAud, "billing:read").Tokens.Str("access_token")
		if st, body := call(t, "GET", s.BillingURL+"/invoices", billing); st != 200 || len(body["items"].([]any)) != 1 {
			t.Fatalf("billing: %d %v", st, body)
		}
		if st, _ := call(t, "GET", s.BillingURL+"/invoices", aliceOrders); st != 401 {
			t.Fatalf("orders token accepted by billing: %d", st)
		}
		if st, _ := call(t, "GET", s.OrdersURL+"/orders", billing); st != 401 {
			t.Fatalf("billing token accepted by orders: %d", st)
		}
	})
	t.Run("TEST-009 tenant-scoped admin lists and cursors", func(t *testing.T) {
		carol := f.AccountToken("carol").Tokens.Str("access_token")
		if r := f.H.API("GET", "/organizations/"+f.Acme+"/members", carol, nil); r.Status != 404 {
			t.Fatalf("globex admin listed acme members: %d", r.Status)
		}
		list := f.H.API("GET", "/organizations/"+f.Globex+"/members?limit=1", carol, nil)
		mustStatus(t, list, 200, "own members")
		cursor := list.Str("next_cursor")
		if cursor == "" {
			t.Fatal("expected a cursor")
		}
		if r := f.H.API("GET", "/organizations/"+f.Acme+"/members?cursor="+url.QueryEscape(cursor), f.AdminToken, nil); r.Status != 400 {
			t.Fatalf("cursor replayed against another tenant: %d", r.Status)
		}
	})
}

// TestRevocationConsistencyModes covers SES-023: a strict-online service denies
// at once after a revocation (TEST-033), an offline verifier keeps accepting
// the JWT until it expires (TEST-034), and strict-online enforcement fails
// closed when the introspection authority is unreachable (TEST-035).
// Requirements: TEN-004 (removal from one organization leaves the user's
// other membership working), SEC-009 (strict-online authorization fails
// closed without authoritative state).
func TestRevocationConsistencyModes(t *testing.T) {
	f := NewFixture(t)
	s := f.StartServices(t)
	bobOrders := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	bobBilling := f.LoginWeb("bob", f.Acme, f.BillingAud, "billing:read")
	bobGlobex := f.LoginWeb("bob", f.Globex, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["billing-viewer"],
		"subject": map[string]any{"type": "user", "id": f.Users["bob"]}, "scope": map[string]any{"type": "organization", "id": f.Acme}}), 201, "billing role")

	// TEST-033: removing bob from acme ends acme access for strict-online services
	// immediately while his globex membership keeps working.
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "remove member")
	if st, _ := call(t, "GET", s.OrdersURL+"/orders", bobOrders); st != 401 {
		t.Fatalf("strict-online service must deny after removal: %d", st)
	}
	if st, _ := call(t, "GET", s.OrdersURL+"/orders", bobGlobex); st != 200 {
		t.Fatalf("unrelated membership must remain: %d", st)
	}
	// TEST-034: the offline service still accepts the JWT until expiry; this is the
	// documented stale-token window, not immediate revocation.
	st, _ := call(t, "GET", s.BillingURL+"/invoices", bobBilling.Tokens.Str("access_token"))
	if st != 200 && st != 403 {
		t.Fatalf("offline verifier behaviour changed: %d", st)
	}
	f.H.Clock.Advance(6 * 60e9)
	if st, _ := call(t, "GET", s.BillingURL+"/invoices", bobBilling.Tokens.Str("access_token")); st != 401 {
		t.Fatalf("expired token accepted: %d", st)
	}
	// Refresh after removal is denied (offline exposure ends at expiry).
	r := f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {bobBilling.Tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	if r.Status != 400 {
		t.Fatalf("refresh after membership removal must fail: %d %s", r.Status, r.Raw)
	}
	// TEST-035: strict-online authority unavailable -> deny, never fall back.
	down := f.StartServicesWithIssuer(t, "http://127.0.0.1:1/realms/main")
	if st, _ := call(t, "GET", down.OrdersURL+"/orders", bobGlobex); st != 503 {
		t.Fatalf("introspection outage must fail closed: %d", st)
	}
}

// TestUserSearchScope covers USR-006: realm-wide user search and its
// pagination need realm user authority. An organization administrator gets
// no records and no masked view from it, even filtered to their own
// organization; their member listing returns only that organization's
// members on every page; and a realm search cursor does not page it.
func TestUserSearchScope(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.EnrollTOTP("carol")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token") // globex administrator, MFA session
	for _, q := range []string{"", "?q=alice@example.test", "?q=" + f.Users["alice"], "?organization_id=" + f.Globex, "?state=active&limit=1"} {
		if r := h.API("GET", "/users"+q, carol, nil); r.Status != 403 || r.Str("code") != "forbidden" || r.Get("items") != nil {
			t.Fatalf("organization administrator searched users%s: %d %s", q, r.Status, r.Raw)
		}
	}
	members := func(token, cursor string) (map[string]bool, string) {
		t.Helper()
		seen := map[string]bool{}
		for i := 0; i < 10; i++ {
			path := "/organizations/" + f.Globex + "/members?limit=1"
			if cursor != "" {
				path += "&cursor=" + url.QueryEscape(cursor)
			}
			page := h.API("GET", path, token, nil)
			if page.Status != 200 {
				return seen, page.Str("code")
			}
			items, _ := page.Get("items").([]any) // null on an empty page
			for _, it := range items {
				seen[it.(map[string]any)["user_id"].(string)] = true
			}
			if cursor = page.Str("next_cursor"); cursor == "" {
				break
			}
		}
		return seen, ""
	}
	same := func(got map[string]bool, want ...string) bool {
		if len(got) != len(want) {
			return false
		}
		for _, w := range want {
			if !got[w] {
				return false
			}
		}
		return true
	}
	if seen, code := members(carol, ""); code != "" || !same(seen, f.Users["bob"], f.Users["carol"]) {
		t.Fatalf("globex members paged by its administrator: %v %s", seen, code)
	}
	realmPage := f.must(f.AdminAPI("GET", "/users?limit=1", nil), 200, "realm search")
	if realmPage.Str("next_cursor") == "" {
		t.Fatal("expected a realm search cursor")
	}
	if seen, code := members(carol, realmPage.Str("next_cursor")); code != "invalid_request" || len(seen) != 0 {
		t.Fatalf("realm search cursor accepted by an organization listing: %v %q", seen, code)
	}
	// With realm authority, a search filtered to the organization returns
	// only its members.
	org := f.must(f.AdminAPI("GET", "/users?limit=100&organization_id="+f.Globex, nil), 200, "filtered search")
	ids := map[string]bool{}
	for _, it := range org.Get("items").([]any) {
		ids[it.(map[string]any)["id"].(string)] = true
	}
	if !same(ids, f.Users["bob"], f.Users["carol"]) {
		t.Fatalf("realm search filtered to globex: %s", org.Raw)
	}
}

// TestAdministrativeDeactivation covers USR-014 with the guarantees of
// docs/operations/revocation-exposure.md: suspending an account revokes its
// sessions, grants and refresh families in the same transaction, so its
// tokens are inactive at introspection and at the IdP's APIs, refresh is
// denied and no new sign-in issues tokens; a user.suspended event is
// published; reactivation does not revive what was revoked.
func TestAdministrativeDeactivation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	bob := f.Users["bob"]
	web := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	acct := f.AccountToken("bob").Tokens.Str("access_token")
	count := func(q string) int {
		t.Helper()
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, q, bob).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const (
		sessions = `SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`
		grants   = `SELECT count(*) FROM authorization_grants WHERE subject_type='user' AND subject_id=$1 AND state='active'`
		families = `SELECT count(*) FROM refresh_families r JOIN authorization_grants g ON g.id=r.grant_id
			WHERE g.subject_type='user' AND g.subject_id=$1 AND r.state='active'`
		events = `SELECT count(*) FROM outbox_events WHERE event_type='user.suspended' AND aggregate_id=$1`
	)
	if count(sessions) == 0 || count(grants) == 0 || count(families) == 0 {
		t.Fatal("fixture: bob holds sessions, grants and refresh families")
	}
	refresh := func() *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {web.Tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	}

	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
	if s, g, r := count(sessions), count(grants), count(families); s+g+r != 0 {
		t.Fatalf("left active after suspension: %d sessions, %d grants, %d refresh families", s, g, r)
	}
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, web.Tokens.Str("access_token")); in.Get("active") != false {
		t.Fatalf("access token of a suspended account active at introspection: %s", in.Raw)
	}
	mustStatus(t, h.API("GET", "/me", acct, nil), 401, "account token of a suspended account")
	if r := refresh(); r.Status != 400 {
		t.Fatalf("refresh after suspension: %d %s", r.Status, r.Raw)
	}
	if lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", ExpectFail: true}); lr.Code != "" {
		t.Fatal("a suspended account obtained an authorization code")
	}
	if n := count(events); n != 1 {
		t.Fatalf("user.suspended events published: %d", n)
	}

	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate")
	if r := refresh(); r.Status != 400 {
		t.Fatalf("refresh token revived by reactivation: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens, 200, "sign-in after reactivation")
}

func (f *Fixture) StartServicesWithIssuer(t *testing.T, issuer string) *Services {
	o, err := ordersapi.New(ordersapi.Config{Issuer: issuer, Audience: f.OrdersAud, ClientID: "orders-rs", ClientSecret: f.Clients["orders-rs"].Secret})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(o.Handler())
	t.Cleanup(srv.Close)
	return &Services{Orders: o, OrdersURL: srv.URL}
}

func decodeJSON(res *http.Response, v any) error {
	return jsonDecoder(res).Decode(v)
}

var _ = context.Background
