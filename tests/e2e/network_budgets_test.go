package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/worker"
)

// Network-normalized abuse budgets, the transaction-start budget and the
// known-device quota (owner decision 9 of the 0.2.0-alpha.6 decisions; the
// finding httpapi-surface/ipv6-per-ip-budgets-realm-lockout).

// behindProxy trusts the loopback test client as a reverse proxy, so
// X-Forwarded-For names the client address (SEC-001).
func behindProxy(c *configuration.Config) {
	c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
}

// netClient makes headless sign-in requests from addr through the trusted
// proxy, optionally presenting a remembered device.
type netClient struct {
	h      *Harness
	addr   string
	device string
}

func (n netClient) headers(cont string) map[string]string {
	hdr := map[string]string{"X-Forwarded-For": n.addr}
	if cont != "" {
		hdr["X-Transaction-Token"] = cont
	}
	if n.device != "" {
		hdr["X-Remembered-Device"] = n.device
	}
	return hdr
}

// start begins a headless CLI transaction from n's address.
func (n netClient) start() (*Resp, string, string) {
	_, challenge := PKCE()
	r := n.h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions", Headers: n.headers(""),
		JSON: map[string]any{"client_id": "proudauth-cli", "redirect_uri": "http://127.0.0.1/callback", "scope": "proudauth:account",
			"resource": []string{n.h.Realm.Issuer + "/account"}, "code_challenge": challenge, "code_challenge_method": "S256"}})
	return r, r.Str("transaction_id"), r.Str("continuation_token")
}

func (n netClient) step(tx, cont, path string, body any) *Resp {
	return n.h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/" + path, JSON: body, Headers: n.headers(cont)})
}

// signIn starts a transaction and answers every step from n's address:
// identify, password, then TOTP (opting in to remember the device when
// remember is set), terms and consent when asked. It returns the first
// refusal or the last state.
func (n netClient) signIn(identifier, password string, remember bool) *Resp {
	start, tx, cont := n.start()
	if start.Status != 201 {
		return start
	}
	if r := n.step(tx, cont, "identify", map[string]any{"identifier": identifier}); r.Status != 200 {
		return r
	}
	st := n.step(tx, cont, "password", map[string]any{"password": password})
	for i := 0; i < 5 && st.Status == 200 && st.Str("status") == "pending"; i++ {
		types := actionTypes(st)
		switch {
		case has(types, "totp"):
			if remember && has(types, "remember_device") {
				mustStatus(n.h.t, n.step(tx, cont, "remember-device", map[string]any{"remember": true}), 200, "remember device")
			}
			st = n.step(tx, cont, "totp", map[string]any{"code": n.h.TOTPNow(identifier)})
		case has(types, "accept_terms"):
			acts, _ := st.Get("next_actions").([]any)
			st = n.step(tx, cont, "terms", map[string]any{"version": acts[0].(map[string]any)["options"].(map[string]any)["version"]})
		case has(types, "consent"):
			st = n.step(tx, cont, "consent", map[string]any{"approve": true})
		default:
			return st
		}
	}
	return st
}

// mustRateLimited checks a 429 rate_limited answer with a positive Retry-After.
func mustRateLimited(t *testing.T, r *Resp, what string) {
	t.Helper()
	if r.Status != 429 || r.Str("code") != "rate_limited" {
		t.Fatalf("%s: want 429 rate_limited, got %d %s", what, r.Status, r.Raw)
	}
	if s, err := strconv.Atoi(r.Header.Get("Retry-After")); err != nil || s <= 0 {
		t.Fatalf("%s: Retry-After %q", what, r.Header.Get("Retry-After"))
	}
}

// mustSignedIn checks that a sign-in completed with a redirect to the client.
func mustSignedIn(t *testing.T, r *Resp, what string) {
	t.Helper()
	if r.Status != 200 || r.Str("redirect_to") == "" {
		t.Fatalf("%s: sign-in did not complete: %d %s", what, r.Status, r.Raw)
	}
}

// TestNetworkNormalizedBudgets covers SEC-006 and ABU-001 (the finding
// httpapi-surface/ipv6-per-ip-budgets-realm-lockout, owner decision 9 of
// 0.2.0-alpha.6). Behind a trusted proxy, every address of one IPv6 /64
// shares one per-network sign-in budget: before, each address had a budget
// of its own, so an attacker rotating addresses inside one /64 escaped every
// per-IP budget and only the realm and client caps were left. Distinct IPv4
// addresses stay distinct networks. Many /64s of one /48 run into the wider
// /48 budget (network_coarse_factor times the per-network limit) while the
// realm budget still admits everyone else.
func TestNetworkNormalizedBudgets(t *testing.T) {
	h := NewHarness(t, behindProxy)
	fixtureOn(t, h)
	rl := &h.App.D.Cfg.Security.RateLimits
	rl.LoginPerIP, rl.LoginPerIdentifier, rl.NetworkCoarseFactor = 3, 100, 2
	probe := 0
	attempt := func(addr string) *Resp {
		probe++
		return netClient{h: h, addr: addr}.signIn(fmt.Sprintf("probe-%d@example.test", probe), "wrong-password-1", false)
	}

	t.Run("one /64 is one network", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute) // a fresh budget window
		for i := 1; i <= 3; i++ {
			mustStatus(t, attempt(fmt.Sprintf("2001:db8:a:1::%x", i)), 401, "attempt inside the /64's budget")
		}
		mustRateLimited(t, attempt("2001:db8:a:1:ffff::4"), "fourth address of the same /64")
		mustStatus(t, attempt("2001:db8:b:1::1"), 401, "another site's /64")
		for i := 1; i <= 4; i++ {
			mustStatus(t, attempt(fmt.Sprintf("198.51.100.%d", i)), 401, "a distinct IPv4 address is its own network")
		}
	})

	t.Run("the /48 budget trips before the realm budget", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute)
		rl.LoginPerRealm = 20
		statuses := []int{}
		for net := 1; net <= 4; net++ {
			for i := 1; i <= 2; i++ {
				statuses = append(statuses, attempt(fmt.Sprintf("2001:db8:c:%x::%x", net, i)).Status)
			}
		}
		// Two attempts per /64 stay inside the per-network budget of 3; the
		// /48 admits 3 x 2 = 6, so the fourth /64 is refused.
		if fmt.Sprint(statuses) != "[401 401 401 401 401 401 429 429]" {
			t.Fatalf("many /64s of one /48: %v", statuses)
		}
		mustRateLimited(t, attempt("2001:db8:c:5::1"), "a fifth /64 of the same /48")
		// Six password attempts in the realm are far from login_per_realm.
		mustStatus(t, attempt("2001:db8:d:1::1"), 401, "another site while one /48 is refused")
	})
}

// TestTransactionStartBudget covers SEC-006 and ABU-001: starting an
// authentication transaction is budgeted per network (start_per_network),
// so a fresh transaction per attempt buys no fresh budgets; the headless
// start answers 429 rate_limited with Retry-After and the browser
// authorization endpoint redirects with error=temporarily_unavailable. A
// start that reuses a valid SSO session is not counted. Every step is charged
// to the network of the request that makes it, not to the address the
// transaction started from, so steps sent from one network through
// transactions started elsewhere still exhaust that network's budget.
func TestTransactionStartBudget(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	rl := &h.App.D.Cfg.Security.RateLimits

	t.Run("start is budgeted per network", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute)
		rl.StartPerNetwork = 3
		const site = "2001:db8:5:1::"
		b := newBrowser(h)
		_, challenge := PKCE()
		authorize := func(b *browser, addr string, extra url.Values) *Resp {
			q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
				"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud},
				"organization": {f.Acme}}
			for k, v := range extra {
				q[k] = v
			}
			return b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, map[string]string{"X-Forwarded-For": addr})
		}
		// A browser signs in from the network: its start is the first unit.
		r := authorize(b, site+"50", nil)
		mustStatus(t, r, 302, "authorize")
		loc, _ := url.Parse(r.Header.Get("Location"))
		tx := loc.Query().Get("transaction_id")
		if loc.Host != "login.test" || tx == "" {
			t.Fatalf("expected the login UI: %s", loc)
		}
		view := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, map[string]string{"X-Forwarded-For": site + "50"})
		hdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": view.Str("csrf_token"), "X-Forwarded-For": site + "50"}
		mustStatus(t, b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "alice@example.test"}, hdr), 200, "identify")
		done := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/password", map[string]any{"password": h.passwords["alice@example.test"]}, hdr)
		mustSignedIn(t, done, "browser sign-in")

		// Headless starts from rotating addresses of the same /64.
		for i := 1; i <= 2; i++ {
			r, _, _ = netClient{h: h, addr: fmt.Sprintf("%s%x", site, i)}.start()
			mustStatus(t, r, 201, "start inside the budget")
		}
		r, _, _ = netClient{h: h, addr: site + "ffff"}.start()
		mustRateLimited(t, r, "fourth start from the network")
		r, _, _ = netClient{h: h, addr: "2001:db8:6:1::1"}.start()
		mustStatus(t, r, 201, "start from another network")

		// The browser authorization endpoint redirects to the client.
		r = authorize(newBrowser(h), site+"77", url.Values{"state": {"s2"}})
		mustStatus(t, r, 302, "authorize from the exhausted network")
		loc, _ = url.Parse(r.Header.Get("Location"))
		if loc.Host != "app.test" || loc.Query().Get("error") != "temporarily_unavailable" || loc.Query().Get("state") != "s2" {
			t.Fatalf("exhausted start budget at the authorization endpoint: %s", r.Header.Get("Location"))
		}
		// Silent SSO through the session is not counted.
		r = authorize(b, site+"50", url.Values{"prompt": {"none"}, "state": {"s3"}})
		loc, _ = url.Parse(r.Header.Get("Location"))
		if loc.Host != "app.test" || loc.Query().Get("code") == "" {
			t.Fatalf("SSO from the exhausted network refused: %s", r.Header.Get("Location"))
		}
	})

	t.Run("steps are charged to the request's network", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute)
		rl.StartPerNetwork, rl.LoginPerIP, rl.LoginPerIdentifier = 10000, 3, 100
		stepper := netClient{h: h, addr: "198.51.100.9"}
		type started struct{ tx, cont string }
		var txs []started
		statuses := []int{}
		for i := 1; i <= 4; i++ {
			// Each transaction starts from a network of its own ...
			_, tx, cont := netClient{h: h, addr: fmt.Sprintf("203.0.113.%d", i)}.start()
			txs = append(txs, started{tx, cont})
			// ... and is driven from one other network.
			statuses = append(statuses, stepper.step(tx, cont, "identify", map[string]any{"identifier": fmt.Sprintf("probe-%d@example.test", i)}).Status)
		}
		if fmt.Sprint(statuses) != "[200 200 200 429]" {
			t.Fatalf("steps from one network through transactions started elsewhere: %v", statuses)
		}
		// The networks the transactions started from were not charged.
		mustStatus(t, netClient{h: h, addr: "203.0.113.1"}.step(txs[0].tx, txs[0].cont, "identify", map[string]any{"identifier": "probe-9@example.test"}),
			200, "identify from the start network")
	})
}

// TestKnownDeviceQuota covers SEC-006, REG-012 and owner decision 9 of
// 0.2.0-alpha.6: once the client-wide password budget (login_per_client) is
// exhausted by other traffic, a sign-in from a network, a remembered device
// or an identifier with a successful sign-in in the last known_quota_days
// still proceeds under a quota of its own, while an unknown requester gets
// 429 rate_limited with Retry-After. Before, everyone got 429: an attacker
// who exhausted the aggregate budget locked every password sign-in through
// the client out, window after window. An identifier counts only from the
// wider network (/24, /48) it signed in from, so the 429 still does not tell
// recently active accounts from others (SEC-005, API-009). Facts are stored
// only as keyed digests and the worker deletes them after known_quota_days.
func TestKnownDeviceQuota(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Login.RememberDevices = true })
	f.CreateUser("dana")
	f.EnrollTOTP("dana")
	f.CreateUser("erin")
	f.CreateUser("frank")
	rl := &h.App.D.Cfg.Security.RateLimits
	pw := func(user string) string { return h.passwords[user+"@example.test"] }
	h.Clock.Advance(16 * time.Minute) // a fresh budget window

	// Successful sign-ins make networks, a device and identifiers known.
	mustSignedIn(t, netClient{h: h, addr: "2001:db8:100:1::1"}.signIn("bob@example.test", pw("bob"), false), "bob from his network")
	remembered := netClient{h: h, addr: "2001:db8:200:1::1"}.signIn("dana@example.test", pw("dana"), true)
	mustSignedIn(t, remembered, "dana remembers her device")
	device := remembered.Str("one_time.remembered_device_token")
	if device == "" {
		t.Fatalf("no remembered device: %s", remembered.Raw)
	}

	// Other traffic exhausts the client's password budget.
	rl.LoginPerClient = 6
	attacker := netClient{h: h, addr: "203.0.113.50"}
	exhausted := false
	for i := 0; i < 20 && !exhausted; i++ {
		r := attacker.signIn(fmt.Sprintf("probe-%d@example.test", i), "wrong-password-1", false)
		switch r.Status {
		case 401:
		case 429:
			mustRateLimited(t, r, "attacker")
			exhausted = true
		default:
			t.Fatalf("attacker attempt: %d %s", r.Status, r.Raw)
		}
	}
	if !exhausted {
		t.Fatal("the client's password budget was never exhausted")
	}

	// An unknown network, without a device, for an identifier that never
	// signed in: 429.
	mustRateLimited(t, netClient{h: h, addr: "198.51.100.77"}.signIn("erin@example.test", pw("erin"), false), "unknown requester")
	// The same account from another address of bob's /64: a known network.
	mustSignedIn(t, netClient{h: h, addr: "2001:db8:100:1::2"}.signIn("erin@example.test", pw("erin"), false), "known network")
	// bob's identifier alone, from a network nobody signed in from, is not
	// enough: otherwise anyone could tell recently active accounts (admitted)
	// from all others (429) while the budget is exhausted.
	mustRateLimited(t, netClient{h: h, addr: "198.51.100.88"}.signIn("bob@example.test", pw("bob"), false), "identifier from an unrelated network")
	// bob from a new /64 of the /48 he signed in from: a known identifier.
	mustSignedIn(t, netClient{h: h, addr: "2001:db8:100:2::1"}.signIn("bob@example.test", pw("bob"), false), "known identifier")
	// frank on dana's remembered device, from an unknown network.
	mustRateLimited(t, netClient{h: h, addr: "198.51.100.99"}.signIn("frank@example.test", pw("frank"), false), "frank without the device")
	mustSignedIn(t, netClient{h: h, addr: "198.51.100.99", device: device}.signIn("frank@example.test", pw("frank"), false), "known device")
	// A made-up device secret is not a known device.
	mustRateLimited(t, netClient{h: h, addr: "198.51.100.100", device: secret.Token(secret.PrefixRemember)}.signIn("probe-x@example.test", "wrong-password-1", false),
		"made-up device")

	// Facts are keyed digests, gone after known_quota_days.
	ctx := context.Background()
	var facts, raw int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE digest LIKE '%example%' OR digest LIKE '%2001:db8%'
		OR digest LIKE '%198.51.100%' OR digest LIKE $1) FROM known_sign_ins`, "%"+device+"%").Scan(&facts, &raw); err != nil {
		t.Fatal(err)
	}
	if facts == 0 || raw != 0 {
		t.Fatalf("known_sign_ins: %d facts, %d with raw values", facts, raw)
	}
	h.Clock.Advance(time.Duration(rl.KnownQuotaDays+1) * 24 * time.Hour)
	if _, err := worker.New(h.App, "test").Retention(ctx); err != nil {
		t.Logf("retention reported: %v", err)
	}
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM known_sign_ins`).Scan(&facts); err != nil || facts != 0 {
		t.Fatalf("facts older than known_quota_days kept: %d %v", facts, err)
	}
}
