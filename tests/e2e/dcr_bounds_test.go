package e2e

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestDynamicClientRegistrationBounds covers TEST-066 (APP-016, APP-017,
// ADV-003) beyond TestDynamicClientRegistration: registration policy
// rejects privilege and egress escalation.
//
//   - An initial access token is re-checked at use: a scope it allowed while
//     the scope was ordinary, and that became privileged since, is not
//     granted to a client registered with it (and the registered client
//     cannot obtain it), while the token's other scopes still are.
//   - Metadata members ProudAuth does not support that name URLs
//     (sector_identifier_uri, request_uris, initiate_login_uri,
//     backchannel_logout_uri) are ignored, never stored and never fetched;
//     jwks_uri is refused; the display URLs (logo_uri, client_uri,
//     policy_uri, tos_uri) are stored as given and never fetched. No
//     connection reaches the URLs' host during registration, sign-in with the
//     client, an authorization request naming one of its request_uris, or
//     session revocation with the worker's deliveries, although private
//     destinations are allowed by the egress policy.
func TestDynamicClientRegistrationBounds(t *testing.T) {
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	ctx := context.Background()
	f.must(f.SetPolicy(func(p *realm.Policy) { p.ClientRegistration.Enabled = true }), 200, "enable registration")
	register := func(token string, meta map[string]any) *Resp {
		t.Helper()
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/register", Token: token, JSON: meta})
	}
	meta := func(scope string, extra map[string]any) map[string]any {
		m := map[string]any{"redirect_uris": []string{"https://dcr.test/cb"}, "client_name": "Partner integration", "scope": scope,
			"grant_types": []string{"authorization_code", "refresh_token"}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	grantedScopes := func(clientID string) []string {
		t.Helper()
		rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT g.allowed_scopes FROM client_resource_grants g JOIN clients c ON c.id=g.client_ref WHERE c.client_id=$1`, clientID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var s []string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s...)
		}
		return out
	}

	t.Run("a scope made privileged after the initial access token was issued is not granted", func(t *testing.T) {
		mustStatus(t, f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:export"}), 201, "ordinary scope")
		iat := f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"max_uses": 3,
			"allowed_scopes": []map[string]any{{"resource_id": f.Orders, "scopes": []string{"orders:read", "orders:export"}}}})
		mustStatus(t, iat, 201, "initial access token with the ordinary scope")
		token := iat.Str("initial_access_token")

		// The scope becomes privileged: its definition is replaced.
		res := f.AdminAPI("GET", "/resources/"+f.Orders, nil)
		mustStatus(t, res, 200, "orders resource")
		scopeID := ""
		for _, it := range res.Get("scopes").([]any) {
			if m := it.(map[string]any); m["name"] == "orders:export" {
				scopeID, _ = m["id"].(string)
			}
		}
		if scopeID == "" {
			t.Fatalf("scope not found: %s", res.Raw)
		}
		mustStatus(t, f.AdminAPI("DELETE", "/scopes/"+scopeID, nil), 204, "remove the ordinary definition")
		mustStatus(t, f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:export", "sensitivity": "privileged"}), 201,
			"declare the scope privileged")
		mustStatus(t, f.AdminAPI("POST", "/client-registration-tokens", map[string]any{
			"allowed_scopes": []map[string]any{{"resource_id": f.Orders, "scopes": []string{"orders:export"}}}}), 422, "a new token naming the privileged scope")

		reg := register(token, meta("openid orders:read orders:export", nil))
		mustStatus(t, reg, 201, "registration with the earlier token")
		clientID, secret := reg.Str("client_id"), reg.Str("client_secret")
		if reg.Str("scope") != "openid orders:read" {
			t.Fatalf("granted scopes: %q", reg.Str("scope"))
		}
		if g := grantedScopes(clientID); slices.Contains(g, "orders:export") || !slices.Contains(g, "orders:read") {
			t.Fatalf("resource grants of the registered client: %v", g)
		}
		if g := h.Do(Req{Method: "GET", Path: "/realms/main/oauth/register/" + clientID, Token: reg.Str("registration_access_token")}); g.Status != 200 ||
			strings.Contains(g.Str("scope"), "orders:export") {
			t.Fatalf("registration read: %d %s", g.Status, g.Raw)
		}
		// Asking for the privileged scope alone grants nothing of it.
		only := register(token, meta("orders:export", nil))
		mustStatus(t, only, 201, "registration asking only for the privileged scope")
		if only.Str("scope") != "" || slices.Contains(grantedScopes(only.Str("client_id")), "orders:export") {
			t.Fatalf("privileged scope granted: %s", only.Raw)
		}
		// The registered client cannot obtain it at authorization either.
		st, _, _ := h.StartTx(LoginOpts{ClientID: clientID, RedirectURI: "https://dcr.test/cb", Scope: "orders:read orders:export",
			Resources: []string{f.OrdersAud}, Organization: f.Acme})
		if st.Status != 400 || !strings.Contains(st.Str("detail"), "invalid_scope") {
			t.Fatalf("authorization for the privileged scope: %d %s", st.Status, st.Raw)
		}
		lr := h.Login(LoginOpts{ClientID: clientID, ClientSecret: secret, RedirectURI: "https://dcr.test/cb", Scope: "orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
		if c := jwtPayload(lr.Tokens.Str("access_token")); c["scope"] != "orders:read" {
			t.Fatalf("registered client token: %v", c)
		}
	})

	t.Run("unsupported URL members are ignored and nothing is fetched", func(t *testing.T) {
		var conns, requests atomic.Int32
		target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(200)
		}))
		// Every TCP connection counts, also one whose TLS handshake fails.
		target.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				conns.Add(1)
			}
		}
		target.StartTLS()
		t.Cleanup(target.Close)
		u := target.URL
		iat := f.AdminAPI("POST", "/client-registration-tokens", map[string]any{"max_uses": 2,
			"allowed_scopes": []map[string]any{{"resource_id": f.Orders, "scopes": []string{"orders:read"}}}})
		mustStatus(t, iat, 201, "initial access token")
		token := iat.Str("initial_access_token")

		if r := register(token, meta("openid orders:read", map[string]any{"jwks_uri": u + "/jwks"})); r.Status != 400 || r.Str("error") != "invalid_client_metadata" {
			t.Fatalf("jwks_uri: %d %s", r.Status, r.Raw)
		}
		ignored := map[string]any{"sector_identifier_uri": u + "/sector.json", "request_uris": []string{u + "/request.jwt"},
			"initiate_login_uri": u + "/initiate", "backchannel_logout_uri": u + "/bcl", "subject_type": "pairwise"}
		display := map[string]any{"logo_uri": u + "/logo.png", "client_uri": u + "/", "policy_uri": u + "/policy", "tos_uri": u + "/tos"}
		extra := map[string]any{}
		for k, v := range ignored {
			extra[k] = v
		}
		for k, v := range display {
			extra[k] = v
		}
		reg := register(token, meta("openid orders:read", extra))
		mustStatus(t, reg, 201, "registration with URL members")
		clientID, secret := reg.Str("client_id"), reg.Str("client_secret")
		for k := range ignored {
			if reg.Get(k) != nil {
				t.Errorf("unsupported member %s was registered: %s", k, reg.Raw)
			}
		}
		for k, v := range display {
			if reg.Get(k) != v {
				t.Errorf("display URL %s not stored as given: %s", k, reg.Raw)
			}
		}
		var ref string
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM clients WHERE client_id=$1`, clientID).Scan(&ref); err != nil {
			t.Fatal(err)
		}
		c := f.AdminAPI("GET", "/clients/"+ref, nil)
		mustStatus(t, c, 200, "registered client")
		if c.Str("client.subject_type") != "public" || c.Str("client.sector_identifier") != "" || c.Str("client.backchannel_logout_uri") != "" ||
			c.Str("client.login_ui_url") != "" || strings.Contains(string(c.Raw), u+"/sector.json") || strings.Contains(string(c.Raw), u+"/request.jwt") ||
			strings.Contains(string(c.Raw), u+"/bcl") || strings.Contains(string(c.Raw), u+"/initiate") {
			t.Fatalf("unsupported members reached the client: %s", c.Raw)
		}

		// Use the client: sign-in, an authorization request naming one of the
		// request_uris it tried to register, and the end of the session with
		// the worker's deliveries.
		h.Login(LoginOpts{ClientID: clientID, ClientSecret: secret, RedirectURI: "https://dcr.test/cb", Scope: "openid orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
		if r := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": clientID, "request_uri": u + "/request.jwt"}); r.Status != 400 {
			t.Fatalf("request_uri by reference: %d %s", r.Status, r.Raw)
		}
		mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/revoke-sessions", map[string]any{}), 200, "end bob's sessions")
		runWorker(t, worker.New(h.App, "test"))
		if n, m := conns.Load(), requests.Load(); n != 0 || m != 0 {
			t.Fatalf("the identity provider contacted a registrant-supplied URL: %d connections, %d requests", n, m)
		}
		// Control: the counters do see a connection.
		if res, err := target.Client().Get(u + "/logo.png"); err != nil {
			t.Fatal(err)
		} else {
			res.Body.Close()
		}
		if conns.Load() != 1 || requests.Load() != 1 {
			t.Fatalf("connection counter control: %d connections, %d requests", conns.Load(), requests.Load())
		}
	})
}
