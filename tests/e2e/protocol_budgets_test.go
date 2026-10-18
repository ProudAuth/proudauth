package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/realm"
)

// Budgets of the protocol endpoints (owner decision 9 of the 0.2.0-alpha.6
// decisions; the finding core-oauth-oidc/token-endpoint-rate-limit): the
// token endpoint, PAR and device authorization count every request against
// the requesting network before client authentication; a public client's
// token budget counts only failed grants, and each network's share of them;
// PAR counts a public client's pushed requests; wrong device user codes are
// budgeted per network; dynamic client registration's network budget is
// configurable.

// from returns the headers of a request that a trusted proxy forwards from
// addr (behindProxy).
func from(addr string) map[string]string { return map[string]string{"X-Forwarded-For": addr} }

// mustSlowDown checks the OAuth form of a spent protocol budget: 429 with
// error=slow_down, a positive Retry-After, and nothing but the OAuth error
// members.
func mustSlowDown(t *testing.T, r *Resp, what string) {
	t.Helper()
	if r.Status != 429 || r.Str("error") != "slow_down" {
		t.Fatalf("%s: want 429 slow_down, got %d %s", what, r.Status, r.Raw)
	}
	if s, err := strconv.Atoi(r.Header.Get("Retry-After")); err != nil || s <= 0 {
		t.Fatalf("%s: Retry-After %q", what, r.Header.Get("Retry-After"))
	}
	for k := range r.Body {
		if k != "error" && k != "error_description" {
			t.Fatalf("%s: member %q in an OAuth error: %s", what, k, r.Raw)
		}
	}
}

// cliCode signs a user in through the public operator CLI client and returns
// the authorization code and its PKCE verifier.
func cliCode(t *testing.T, f *Fixture, user string) (string, string) {
	t.Helper()
	h := f.H
	start, verifier, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	if start.Status != 201 {
		t.Fatalf("start: %d %s", start.Status, start.Raw)
	}
	st := h.Drive(start.Str("transaction_id"), cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, LoginOpts{Identifier: user + "@example.test"})
	u, _ := url.Parse(st.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("no code: %d %s", st.Status, st.Raw)
	}
	return u.Query().Get("code"), verifier
}

// cliToken posts a token request of the public operator CLI client from addr.
func cliToken(h *Harness, addr string, form url.Values) *Resp {
	form.Set("client_id", "proudauth-cli")
	return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form, Headers: from(addr)})
}

// exchange redeems a code of the operator CLI client from addr.
func exchange(h *Harness, addr, code, verifier string) *Resp {
	return cliToken(h, addr, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {"http://127.0.0.1/callback"}})
}

// TestTokenEndpointNetworkBudgets covers SEC-006, ABU-001 and REG-012 (the
// finding core-oauth-oidc/token-endpoint-rate-limit, owner decision 9 of
// 0.2.0-alpha.6). The token endpoint keeps a failure budget per requesting
// network (token_failures_per_network, IPv6 /64), read before the client is
// authenticated: once one network's failed client authentications or failed
// grants have spent it, its requests get 429 slow_down with Retry-After and
// write no further audit records, valid clients from it included, while
// other networks are served. Successful requests never count, so a
// confidential client's backend or a public client's users on one network
// are never refused by it, however many they send. A public client
// authenticates with its client_id alone, so anyone could use up its token
// budget: one network's failed grants through it are bounded by
// token_per_network_client, after which that network gets 429 while a code
// exchange from another network of the same client succeeds. Before, the
// only budget was token_per_client per client, counted after authentication
// for every request, so one sender put every user of a public client into
// 429.
func TestTokenEndpointNetworkBudgets(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h)
	rl := &h.App.D.Cfg.Security.RateLimits
	batch, web := f.Clients["batch"], f.Clients["web"]
	machine := func(addr string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{batch.ID, batch.Secret}, Headers: from(addr),
			Form: url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}}})
	}
	unknownClient := func(addr string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Headers: from(addr),
			Form: url.Values{"grant_type": {"client_credentials"}, "client_id": {"no-such-client"}}})
	}

	t.Run("failed client authentication is cut off before authentication", func(t *testing.T) {
		h.Clock.Advance(time.Minute) // a fresh budget window
		rl.TokenFailuresPerNetwork = 3
		ctx := context.Background()
		failures := func() int {
			var n int
			if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='client.authentication.failed'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := failures()
		for i := 1; i <= 2; i++ {
			if r := unknownClient(fmt.Sprintf("2001:db8:7:1::%x", i)); r.Status != 401 || r.Str("error") != "invalid_client" {
				t.Fatalf("unknown client %d: %d %s", i, r.Status, r.Raw)
			}
		}
		wrong := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"web-bff", "wrong-secret"}, Headers: from("2001:db8:7:1::3"),
			Form: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"pa_rt_bogus"}}})
		if wrong.Status != 401 || wrong.Str("error") != "invalid_client" {
			t.Fatalf("wrong client secret: %d %s", wrong.Status, wrong.Raw)
		}
		if n := failures() - before; n != 3 {
			t.Fatalf("%d client.authentication.failed records, want 3", n)
		}
		for _, addr := range []string{"2001:db8:7:1:ffff::1", "2001:db8:7:1::2"} {
			mustSlowDown(t, unknownClient(addr), "a fourth failing request from the /64")
		}
		// Refused before client authentication: nothing more is audited, and
		// a valid client from the exhausted network is refused as well.
		if n := failures() - before; n != 3 {
			t.Fatalf("refused requests audited: %d records, want 3", n)
		}
		mustSlowDown(t, machine("2001:db8:7:1::9"), "a valid client from the exhausted network")
		mustStatus(t, machine("2001:db8:8:1::1"), 200, "a valid client from another network")
		h.Clock.Advance(time.Minute)
		mustStatus(t, machine("2001:db8:7:1::9"), 200, "the network in the next window")
	})

	t.Run("successful requests never use the network's failure budget", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenFailuresPerNetwork = 3
		const backend = "198.51.100.60"
		// A confidential backend refreshing for its users and fetching
		// machine tokens, and a public client's users, all from one network:
		// far more successful requests than the failure budget.
		refresh := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("refresh_token")
		for i := 1; i <= 5; i++ {
			r := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"web-bff", web.Secret}, Headers: from(backend),
				Form: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}})
			mustStatus(t, r, 200, fmt.Sprintf("confidential refresh %d", i))
			refresh = r.Str("refresh_token")
		}
		for i := 1; i <= 3; i++ {
			mustStatus(t, machine(backend), 200, fmt.Sprintf("machine token %d", i))
		}
		code, verifier := cliCode(t, f, "bob")
		tokens := exchange(h, backend, code, verifier)
		mustStatus(t, tokens, 200, "public code exchange")
		public := tokens.Str("refresh_token")
		for i := 1; i <= 5; i++ {
			r := cliToken(h, backend, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {public}})
			mustStatus(t, r, 200, fmt.Sprintf("public refresh %d", i))
			public = r.Str("refresh_token")
		}
		// The budget is still whole: three failures spend it, not one.
		for i := 1; i <= 2; i++ {
			if r := exchange(h, backend, fmt.Sprintf("pa_code_bogus%d", i), "x"); r.Str("error") != "invalid_grant" {
				t.Fatalf("bad code %d: %d %s", i, r.Status, r.Raw)
			}
		}
		mustStatus(t, machine(backend), 200, "a success after two failures")
		if r := exchange(h, backend, "pa_code_bogus3", "x"); r.Str("error") != "invalid_grant" {
			t.Fatalf("third bad code: %d %s", r.Status, r.Raw)
		}
		mustSlowDown(t, machine(backend), "the network once three requests failed")
	})

	t.Run("bad codes from one network are cut off before authentication", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenFailuresPerNetwork, rl.TokenPerNetworkClient = 3, 10000
		const attacker = "203.0.113.9"
		for i := 1; i <= 3; i++ {
			if r := exchange(h, attacker, fmt.Sprintf("pa_code_bogus%d", i), "x"); r.Str("error") != "invalid_grant" {
				t.Fatalf("bad code %d: %d %s", i, r.Status, r.Raw)
			}
		}
		mustSlowDown(t, exchange(h, attacker, "pa_code_bogus4", "x"), "fourth bad code from the network")
		mustSlowDown(t, machine(attacker), "a confidential client from the attacker's network")
		code, verifier := cliCode(t, f, "bob")
		mustStatus(t, exchange(h, "203.0.114.9", code, verifier), 200, "code exchange from another network")
	})

	t.Run("one network cannot use up a public client's budget", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenFailuresPerNetwork, rl.TokenPerClient, rl.TokenPerNetworkClient = 10000, 6, 3
		const attacker = "203.0.113.7"
		statuses := []int{}
		for i := range 10 {
			r := exchange(h, attacker, fmt.Sprintf("pa_code_bogus%d", i), "x")
			if r.Status == 429 {
				mustSlowDown(t, r, "attacker")
			} else if r.Str("error") != "invalid_grant" {
				t.Fatalf("bad code exchange: %d %s", r.Status, r.Raw)
			}
			statuses = append(statuses, r.Status)
		}
		// Three failed grants are the network's share; the rest are refused
		// before the grant runs and do not count against the client.
		if fmt.Sprint(statuses) != "[400 400 400 429 429 429 429 429 429 429]" {
			t.Fatalf("bad code exchanges from one network: %v", statuses)
		}
		code, verifier := cliCode(t, f, "bob")
		r := exchange(h, "198.51.100.20", code, verifier)
		mustStatus(t, r, 200, "code exchange from another network of the same public client")
		if r.Str("access_token") == "" {
			t.Fatalf("no access token: %s", r.Raw)
		}
	})
}

// TestPublicClientTokenBudgetCountsFailedGrants covers REG-012 and SEC-006
// (owner decision 9 of 0.2.0-alpha.6): for a public client, token_per_client
// counts only failed grants (invalid_grant, invalid_request and the other
// errors of an invalid request), so its users' successful refreshes never
// use it up, and device-flow polling (authorization_pending, slow_down) does
// not count either; once failed grants have spent it, the aggregate cap
// fails closed and every request of the client gets 429 slow_down until the
// window ends. A confidential client's budget still counts every request.
func TestPublicClientTokenBudgetCountsFailedGrants(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	rl := &h.App.D.Cfg.Security.RateLimits
	const user = "198.51.100.30"

	t.Run("public client", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenPerClient = 3
		code, verifier := cliCode(t, f, "bob")
		tokens := exchange(h, user, code, verifier)
		mustStatus(t, tokens, 200, "code exchange")
		refresh := tokens.Str("refresh_token")
		if refresh == "" {
			t.Fatalf("no refresh token: %s", tokens.Raw)
		}
		for i := 1; i <= 5; i++ {
			r := cliToken(h, user, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
			mustStatus(t, r, 200, fmt.Sprintf("successful refresh %d", i))
			refresh = r.Str("refresh_token")
		}
		da := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/device_authorization", Headers: from(user), Form: url.Values{"client_id": {"proudauth-cli"},
			"scope": {"proudauth:account"}, "resource": {h.Realm.Issuer + "/account"}}})
		mustStatus(t, da, 200, "device authorization")
		for i := 1; i <= 4; i++ {
			r := cliToken(h, user, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da.Str("device_code")}})
			if e := r.Str("error"); r.Status != 400 || (e != "authorization_pending" && e != "slow_down") {
				t.Fatalf("device poll %d: %d %s", i, r.Status, r.Raw)
			}
		}
		for i := 1; i <= 3; i++ {
			r := cliToken(h, user, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {fmt.Sprintf("pa_rt_bogus%d", i)}})
			if r.Status != 400 || r.Str("error") != "invalid_grant" {
				t.Fatalf("failed grant %d: %d %s", i, r.Status, r.Raw)
			}
		}
		mustSlowDown(t, cliToken(h, "198.51.100.31", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}),
			"valid refresh once failed grants spent the client's budget")
		h.Clock.Advance(time.Minute)
		mustStatus(t, cliToken(h, user, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}), 200, "refresh in the next window")
	})

	t.Run("confidential client", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.TokenPerClient = 3
		batch := f.Clients["batch"]
		for i := 1; i <= 3; i++ {
			mustStatus(t, f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme), 200, fmt.Sprintf("machine token %d", i))
		}
		mustSlowDown(t, f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme), "fourth successful request of a confidential client")
	})
}

// TestPARAndDeviceNetworkBudgets covers SEC-006 and ABU-001 (the finding
// core-oauth-oidc/token-endpoint-rate-limit, owner decision 9 of
// 0.2.0-alpha.6): pushed authorization requests keep a failure budget per
// requesting network (par_failures_per_network), read before client
// authentication: successful pushes never count, and once one network's
// failed pushes (client authentication, invalid requests) have spent it, its
// pushes get 429 slow_down while another network proceeds. A public client's
// pushes count against par_per_client from every network. Device
// authorization stores a row per request and counts every request against
// the network (device_per_network). Wrong device user codes are budgeted per
// network (user_code_failures_per_network): after N lookups that find no
// code, the network gets 429 rate_limited with Retry-After, even for a right
// code, while the right code from another network still starts the
// approval; lookups that find their code do not count. The browser
// authorization endpoint writes a row only by starting a transaction, which
// start_per_network already counts: a flood from one network redirects with
// temporarily_unavailable, not counted twice.
func TestPARAndDeviceNetworkBudgets(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	rl := &h.App.D.Cfg.Security.RateLimits
	web := f.Clients["web"]
	pushAs := func(addr, secret, redirect string, public bool) *Resp {
		_, challenge := PKCE()
		form := url.Values{"redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"orders:read"}, "code_challenge": {challenge},
			"code_challenge_method": {"S256"}, "resource": {f.OrdersAud}}
		rq := Req{Method: "POST", Path: "/realms/main/oauth/par", Headers: from(addr), Basic: [2]string{"web-bff", secret}, Form: form}
		if public {
			form.Set("client_id", "proudauth-cli")
			form.Set("redirect_uri", "http://127.0.0.1/callback")
			form.Set("scope", "proudauth:account")
			form.Set("resource", h.Realm.Issuer+"/account")
			rq.Basic = [2]string{}
		}
		return h.Do(rq)
	}
	push := func(addr string, public bool) *Resp { return pushAs(addr, web.Secret, webRedirect, public) }
	device := func(addr string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/device_authorization", Headers: from(addr), Form: url.Values{"client_id": {"proudauth-cli"},
			"scope": {"proudauth:account"}, "resource": {h.Realm.Issuer + "/account"}}})
	}
	enter := func(addr, code string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions", Headers: from(addr), JSON: map[string]any{"device_user_code": code}})
	}

	t.Run("PAR failures per network", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.PARFailuresPerNetwork = 2
		// A backend pushing for its users: successes never count.
		for i := 1; i <= 4; i++ {
			mustStatus(t, push(fmt.Sprintf("2001:db8:20:1::%x", i), false), 201, "successful PAR")
		}
		if r := pushAs("2001:db8:20:1::5", "wrong-secret", webRedirect, false); r.Status != 401 || r.Str("error") != "invalid_client" {
			t.Fatalf("PAR with a wrong secret: %d %s", r.Status, r.Raw)
		}
		if r := pushAs("2001:db8:20:1::6", web.Secret, "https://evil.test/cb", false); r.Status != 400 || r.Str("error") != "invalid_request" {
			t.Fatalf("PAR with an unregistered redirect: %d %s", r.Status, r.Raw)
		}
		mustSlowDown(t, push("2001:db8:20:1::7", false), "a valid PAR once two failed from the /64")
		mustStatus(t, push("2001:db8:21:1::1", false), 201, "PAR from another network")
	})

	t.Run("PAR per public client", func(t *testing.T) {
		h.Clock.Advance(time.Minute)
		rl.PARFailuresPerNetwork, rl.PARPerClient = 10000, 2
		mustStatus(t, push("198.51.100.40", true), 201, "public PAR from one network")
		mustStatus(t, push("198.51.100.41", true), 201, "public PAR from another network")
		mustSlowDown(t, push("198.51.100.42", true), "third PAR of the public client")
		mustStatus(t, push("198.51.100.42", false), 201, "a confidential client's PAR")
	})

	t.Run("device authorization per network", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute)
		rl.DevicePerNetwork = 2
		for i := 1; i <= 2; i++ {
			mustStatus(t, device("192.0.2.10"), 200, "device authorization inside the budget")
		}
		mustSlowDown(t, device("192.0.2.10"), "third device authorization from the network")
		mustStatus(t, device("192.0.2.11"), 200, "device authorization from another network")
	})

	t.Run("wrong user codes per network", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute)
		rl.DevicePerNetwork, rl.UserCodeFailuresPerNetwork = 10000, 3
		da := device("192.0.2.20")
		mustStatus(t, da, 200, "device authorization")
		right := da.Str("user_code")
		wrongs := []string{}
		for _, c := range []string{"BCDF-GHJK", "BCDF-GHJM", "BCDF-GHJN"} {
			if normalizeCode(c) != normalizeCode(right) {
				wrongs = append(wrongs, c)
			}
		}
		// Lookups that find their code do not count.
		for i := 1; i <= 3; i++ {
			mustStatus(t, enter("2001:db8:30:1::1", right), 201, "right code")
		}
		mustStatus(t, enter("2001:db8:30:1::1", wrongs[0]), 400, "a wrong code after right ones")
		// Two wrong codes and a malformed one from rotating addresses of
		// one /64 spend its budget.
		for i, c := range []string{wrongs[0], wrongs[1], "short"} {
			mustStatus(t, enter(fmt.Sprintf("2001:db8:31:1::%x", i+1), c), 400, "wrong code inside the budget")
		}
		mustRateLimited(t, enter("2001:db8:31:1::4", wrongs[0]), "fourth wrong code from the /64")
		mustRateLimited(t, enter("2001:db8:31:1::5", right), "the right code from the exhausted network")
		st := enter("2001:db8:32:1::1", right)
		mustStatus(t, st, 201, "the right code from another network")
		if st.Str("device_request.client_id") != "proudauth-cli" {
			t.Fatalf("device request: %s", st.Raw)
		}
	})

	t.Run("authorize floods meet the start budget", func(t *testing.T) {
		h.Clock.Advance(16 * time.Minute)
		rl.StartPerNetwork = 2
		_, challenge := PKCE()
		authorize := func(addr string) *url.URL {
			q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
				"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud},
				"organization": {f.Acme}}
			r := h.Do(Req{Method: "GET", Path: "/realms/main/oauth/authorize?" + q.Encode(), Headers: from(addr)})
			mustStatus(t, r, 302, "authorize")
			loc, _ := url.Parse(r.Header.Get("Location"))
			return loc
		}
		for i := 1; i <= 2; i++ {
			if loc := authorize(fmt.Sprintf("2001:db8:40:1::%x", i)); loc.Host != "login.test" {
				t.Fatalf("authorize inside the budget: %s", loc)
			}
		}
		if loc := authorize("2001:db8:40:1::3"); loc.Host != "app.test" || loc.Query().Get("error") != "temporarily_unavailable" {
			t.Fatalf("third authorize from the /64: %s", loc)
		}
		if loc := authorize("2001:db8:41:1::1"); loc.Host != "login.test" {
			t.Fatalf("authorize from another network: %s", loc)
		}
	})
}

// normalizeCode is a user code without separators, upper case.
func normalizeCode(c string) string {
	out := []rune{}
	for _, r := range c {
		if r != '-' && r != ' ' {
			if r >= 'a' && r <= 'z' {
				r -= 'a' - 'A'
			}
			out = append(out, r)
		}
	}
	return string(out)
}

// TestDynamicClientRegistrationNetworkBudget covers SEC-006 and ABU-001:
// dynamic client registration's per-network budget is the configuration key
// security.rate_limits.dcr_per_network per dcr_window (default 20 per hour,
// which used to be fixed in code), counted before the request is
// authenticated; a spent budget answers 429 slow_down with Retry-After on
// this protocol route while another network proceeds, and 0 disables it.
func TestDynamicClientRegistrationNetworkBudget(t *testing.T) {
	h := NewHarness(t, behindProxy)
	f := fixtureOn(t, h)
	rl := &h.App.D.Cfg.Security.RateLimits
	f.must(f.SetPolicy(func(p *realm.Policy) { p.ClientRegistration.Enabled = true }), 200, "enable registration")
	register := func(addr string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/register", Headers: from(addr),
			JSON: map[string]any{"redirect_uris": []string{"https://dcr.test/cb"}, "client_name": "Probe"}})
	}
	h.Clock.Advance(time.Hour)
	rl.DCRPerNetwork = 2
	for i := 1; i <= 2; i++ {
		if r := register(fmt.Sprintf("2001:db8:50:1::%x", i)); r.Status != 401 {
			t.Fatalf("registration without a token inside the budget: %d %s", r.Status, r.Raw)
		}
	}
	mustSlowDown(t, register("2001:db8:50:1::3"), "third registration from the /64")
	if r := register("2001:db8:51:1::1"); r.Status != 401 {
		t.Fatalf("registration from another network: %d %s", r.Status, r.Raw)
	}
	rl.DCRPerNetwork = 0
	if r := register("2001:db8:50:1::4"); r.Status != 401 {
		t.Fatalf("registration with the budget disabled: %d %s", r.Status, r.Raw)
	}
}
