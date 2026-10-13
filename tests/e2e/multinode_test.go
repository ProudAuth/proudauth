package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/httpapi"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/observability"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/server"
	"github.com/proudbase/proudauth/internal/storage"
)

// startPeerNode starts a second API node next to h, the way a multi-node
// deployment runs identical processes behind one public origin (ARC-005,
// ADR 0005): its own connection pool to the same database, its own
// in-process caches (realm, signing-key set, origins, maintenance), the same
// root keys and configuration, and the same (fake) wall clock. The returned
// harness sends every request to the peer's listener while keeping the public
// origin in the URL and Host header, so issuers and audiences match node A's.
func startPeerNode(t *testing.T, h *Harness) *Harness {
	t.Helper()
	return startNode(t, h, h.App.D.Keys, nil)
}

// startNode starts an API node on h's database with the given keyring and a
// copy of h's configuration changed by mutate: a restart of the deployment
// with new key material (OPS-016 key runbooks) or a peer node (ARC-005).
func startNode(t *testing.T, h *Harness, kr *keys.Keyring, mutate func(*configuration.Config)) *Harness {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, h.App.D.DB.Pool.Config().ConnString(), storage.Options{MaxConns: 10})
	if err != nil {
		t.Fatalf("peer node database: %v", err)
	}
	t.Cleanup(db.Close)
	cfg := *h.Cfg
	if mutate != nil {
		mutate(&cfg)
	}
	deps := runtime.New(db, &cfg, h.Clock, kr, observability.NewLogger(io.Discard, "error", "json"))
	app, err := httpapi.Build(deps, nil)
	if err != nil {
		t.Fatalf("peer node: %v", err)
	}
	app.KeyMgr.RSABits = 2048
	server.RegisterModules(app)
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	peer := *h
	peer.App, peer.Srv, peer.Cfg = app, srv, &cfg
	peer.HTTP = &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &peer
}

// loginWebOn signs a user into the web BFF through a given node.
func loginWebOn(n *Harness, f *Fixture, user, org, resource, scope string) *Resp {
	n.t.Helper()
	return n.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: scope,
		Resources: []string{resource}, Organization: org, SelectOrg: org, Identifier: user + "@example.test"}).Tokens
}

// accountTokenOn returns a self-service (account audience) token obtained through a node.
func accountTokenOn(n *Harness, user string) string {
	n.t.Helper()
	return n.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{n.Realm.Issuer + "/account"},
		Identifier: user + "@example.test"}).Tokens.Str("access_token")
}

func peerKID(tok string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var hdr map[string]any
	_ = json.Unmarshal(raw, &hdr)
	kid, _ := hdr["kid"].(string)
	return kid
}

// TestSharedRevocationAcrossNodes covers ARC-005 (shared revocation
// authority): a session, a grant with its refresh family, an access token
// (JTI) and an organization membership revoked through node A are rejected
// at once by node B's introspection, token endpoint and IdP APIs
// (strict-online, no in-memory revocation state), and node B honours the
// emergency rotation of a compromised signing key within the documented
// 5-second signing-key cache window (docs/operations/keys.md,
// docs/operations/revocation-exposure.md) without any cache invalidation by
// hand. Node B is a separate httpapi.App with its own pool and caches on the
// same database (startPeerNode).
func TestSharedRevocationAcrossNodes(t *testing.T) {
	f := NewFixture(t)
	a := f.H
	b := startPeerNode(t, a)
	rs := f.Clients["orders-rs"]
	web := f.Clients["web"]
	activeOn := func(n *Harness, tok string) bool {
		t.Helper()
		r := n.Introspect(rs.ID, rs.Secret, tok)
		mustStatus(t, r, 200, "introspection")
		return r.Get("active") == true
	}
	refreshOn := func(n *Harness, rt string) *Resp {
		t.Helper()
		return n.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", web.Secret)
	}

	// --- Sessions: one session revoked by an administrator on node A. ---
	bobOrders := loginWebOn(a, f, "bob", f.Acme, f.OrdersAud, "orders:read")
	bobAcct := accountTokenOn(b, "bob") // a second session, signed in through node B
	sid, _ := jwtPayload(bobOrders.Str("access_token"))["sid"].(string)
	if sid == "" {
		t.Fatalf("orders token carries no sid: %s", bobOrders.Raw)
	}
	if !activeOn(b, bobOrders.Str("access_token")) {
		t.Fatal("node B: token inactive before any revocation")
	}
	mustStatus(t, b.API("GET", "/me", bobAcct, nil), 200, "node B: account API before revocation")
	mustStatus(t, a.API("DELETE", "/users/"+f.Users["bob"]+"/sessions/"+sid, f.AdminToken, nil), 204, "node A: revoke one session")
	if activeOn(b, bobOrders.Str("access_token")) {
		t.Fatal("node B: token of a session revoked on node A still active at introspection")
	}
	if r := refreshOn(b, bobOrders.Str("refresh_token")); r.Status == 200 {
		t.Fatalf("node B: refreshed a grant of a session revoked on node A: %s", r.Raw)
	}
	mustStatus(t, b.API("GET", "/me", bobAcct, nil), 200, "node B: bob's other session is unaffected")
	// Logout everywhere through node A ends the session node B signed in.
	f.must(a.API("POST", "/users/"+f.Users["bob"]+"/revoke-sessions", f.AdminToken, map[string]any{}), 200, "node A: revoke all sessions")
	if r := b.API("GET", "/me", bobAcct, nil); r.Status != 401 {
		t.Fatalf("node B: account API accepted a session revoked on node A: %d %s", r.Status, r.Raw)
	}

	// --- Grant and refresh family, through an opaque-token resource whose
	// introspection checks the grant, and a JWT access token's JTI. ---
	ledger := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Ledger API", "audience": "https://ledger.test",
		"token_format": "opaque", "verification_mode": "strict_online", "scopes": []map[string]any{{"name": "ledger:read"}}}), 201, "ledger resource").Str("id")
	f.must(f.AdminAPI("PUT", "/clients/"+web.Ref+"/resource-grants/"+ledger, map[string]any{"allowed_scopes": []string{"ledger:read"},
		"subject_types": []string{"user"}}), 204, "ledger grant")
	f.must(f.AdminAPI("POST", "/resources/"+ledger+"/introspectors", map[string]any{"client": rs.Ref}), 204, "ledger introspector")
	alice := loginWebOn(a, f, "alice", f.Acme, "https://ledger.test", "ledger:read")
	if !strings.HasPrefix(alice.Str("access_token"), "pa_at_") || alice.Str("refresh_token") == "" {
		t.Fatalf("expected an opaque access token and a refresh token: %s", alice.Raw)
	}
	// Node B rotates the family; node A revokes the rotated refresh token.
	rotated := refreshOn(b, alice.Str("refresh_token"))
	mustStatus(t, rotated, 200, "node B: refresh")
	if !activeOn(b, rotated.Str("access_token")) {
		t.Fatal("node B: fresh opaque token inactive")
	}
	mustStatus(t, a.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {rotated.Str("refresh_token")},
		"token_type_hint": {"refresh_token"}}, Basic: [2]string{web.ID, web.Secret}}), 200, "node A: revoke refresh token")
	if r := refreshOn(b, rotated.Str("refresh_token")); r.Status == 200 || r.Str("error") != "invalid_grant" {
		t.Fatalf("node B: refresh family revoked on node A still refreshes: %d %s", r.Status, r.Raw)
	}
	if r := refreshOn(b, alice.Str("refresh_token")); r.Status == 200 {
		t.Fatalf("node B: superseded refresh token of a revoked family refreshed: %s", r.Raw)
	}
	if activeOn(b, rotated.Str("access_token")) {
		t.Fatal("node B: opaque token of a grant revoked on node A still active")
	}
	// A JWT access token revoked on node A (RFC 7009, JTI) is inactive on node B.
	aliceOrders := loginWebOn(a, f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
	if !activeOn(b, aliceOrders) {
		t.Fatal("node B: JWT inactive before revocation")
	}
	mustStatus(t, a.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {aliceOrders}},
		Basic: [2]string{web.ID, web.Secret}}), 200, "node A: revoke access token")
	if activeOn(b, aliceOrders) {
		t.Fatal("node B: JWT revoked on node A still active at introspection")
	}

	// --- Organization membership removed on node A. ---
	carolOrders := loginWebOn(b, f, "carol", f.Globex, f.OrdersAud, "orders:read")
	carolAcct := accountTokenOn(b, "carol")
	if !activeOn(b, carolOrders.Str("access_token")) {
		t.Fatal("node B: organization token inactive before removal")
	}
	mustStatus(t, b.API("GET", "/organizations/"+f.Globex+"/members", carolAcct, nil), 200, "node B: tenant API before removal")
	mustStatus(t, a.API("DELETE", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["carol"], f.AdminToken, nil), 204, "node A: remove member")
	if activeOn(b, carolOrders.Str("access_token")) {
		t.Fatal("node B: token of a membership removed on node A still active")
	}
	if r := refreshOn(b, carolOrders.Str("refresh_token")); r.Status == 200 {
		t.Fatalf("node B: refreshed a grant of a membership removed on node A: %s", r.Raw)
	}
	if r := b.API("GET", "/organizations/"+f.Globex+"/members", carolAcct, nil); r.Status != 403 && r.Status != 404 {
		t.Fatalf("node B: tenant API accepted a membership removed on node A: %d %s", r.Status, r.Raw)
	}

	// --- Emergency signing-key rotation on node A. ---
	if ttl := b.App.KeyMgr.CacheTTL; ttl != 5*time.Second {
		t.Fatalf("signing-key cache window is %s; docs/operations/keys.md documents 5 s", ttl)
	}
	f.ReloginAdmin() // realm.keys.rotate needs authentication within 5 minutes
	keyTok := loginWebOn(a, f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
	keyAcct := accountTokenOn(a, "alice")
	compromised := peerKID(keyTok)
	// Node B has the key set cached when the rotation commits.
	if !activeOn(b, keyTok) {
		t.Fatal("node B: token inactive before the rotation")
	}
	mustStatus(t, b.API("GET", "/me", keyAcct, nil), 200, "node B: account API before the rotation")
	rot := f.must(f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"mode": "emergency", "reason": "INC-ARC-005 key exposure"}), 201, "node A: emergency rotation")
	if rot.Str("kid") == "" || rot.Str("kid") == compromised {
		t.Fatalf("emergency rotation: %s", rot.Raw)
	}
	if activeOn(a, keyTok) {
		t.Fatal("node A: compromised key still accepted after its own rotation")
	}
	// Within the window node B may still serve its cached key set; record what
	// it does without depending on it.
	inWindow := loginWebOn(b, f, "bob", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
	t.Logf("node B within the cache window: compromised-key token active=%v, new token signed with the compromised key=%v",
		activeOn(b, keyTok), peerKID(inWindow) == compromised)
	a.Clock.Advance(b.App.KeyMgr.CacheTTL)
	if activeOn(b, keyTok) {
		t.Fatal("node B: token signed by the compromised key still active after the 5 s key-cache window")
	}
	// Tokens node B signed from its cached key set during the window do not
	// outlive it either.
	if peerKID(inWindow) == compromised && (activeOn(b, inWindow) || activeOn(a, inWindow)) {
		t.Fatal("token node B signed with the compromised key during the window still active after it")
	}
	if r := b.API("GET", "/me", keyAcct, nil); r.Status != 401 {
		t.Fatalf("node B: account API accepted a token signed by the compromised key after the window: %d %s", r.Status, r.Raw)
	}
	jwks := b.Do(Req{Method: "GET", Path: "/realms/main/jwks"})
	mustStatus(t, jwks, 200, "node B: JWKS")
	for _, k := range jwks.Get("keys").([]any) {
		if k.(map[string]any)["kid"] == compromised {
			t.Fatal("node B: compromised key still published after the window")
		}
	}
	fresh := loginWebOn(b, f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
	if kid := peerKID(fresh); kid != rot.Str("kid") {
		t.Fatalf("node B signs with %q after the window, want the new key %q", kid, rot.Str("kid"))
	}
	if !activeOn(b, fresh) || !activeOn(a, fresh) {
		t.Fatal("token signed by the new key not accepted on both nodes")
	}
}
