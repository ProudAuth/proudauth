package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/maintenance"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// mustOAuthError fails unless r is an OAuth error response (RFC 6749 §5.2)
// with this status and error code: a JSON body with error (and optionally
// error_description) and none of the problem-details members.
func mustOAuthError(t *testing.T, r *Resp, status int, code, what string) {
	t.Helper()
	if r.Status != status || r.Str("error") != code || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("%s: %d %q %s, want %d OAuth error %s", what, r.Status, r.Header.Get("Content-Type"), r.Raw, status, code)
	}
	for k := range r.Body {
		if k != "error" && k != "error_description" {
			t.Fatalf("%s: member %q outside the OAuth error format: %s", what, k, r.Raw)
		}
	}
}

// TestRevocationStorageFailure covers TOK-010 with RFC 7009 §2.2.1: when the
// revocation of a refresh token, an opaque access token or a JWT access
// token (or the JWT revocation's audit event) cannot be written, the
// revocation endpoint answers 503 temporarily_unavailable with Retry-After
// in the OAuth error format, so the client retries instead of believing the
// token dead, and the token stays active. Unknown tokens, malformed ones and
// another client's tokens still answer 200 without telling the caller
// anything. Once storage recovers the same requests revoke the tokens.
// Failures are injected with triggers in this test's own database.
func TestRevocationStorageFailure(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	web, rs := f.Clients["web"], f.Clients["orders-rs"]
	ledger := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Ledger API", "audience": "https://ledger.test",
		"token_format": "opaque", "verification_mode": "strict_online", "scopes": []map[string]any{{"name": "ledger:read"}}}), 201, "ledger").Str("id")
	f.must(f.AdminAPI("PUT", "/clients/"+web.Ref+"/resource-grants/"+ledger, map[string]any{"allowed_scopes": []string{"ledger:read"},
		"subject_types": []string{"user"}}), 204, "ledger grant")
	f.must(f.AdminAPI("POST", "/resources/"+ledger+"/introspectors", map[string]any{"client": rs.Ref}), 204, "ledger introspector")

	jwtLogin := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read").Tokens
	refresh, access := jwtLogin.Str("refresh_token"), jwtLogin.Str("access_token")
	opaque := f.LoginWeb("bob", f.Acme, "https://ledger.test", "ledger:read").Tokens.Str("access_token")
	if !strings.HasPrefix(opaque, secret.PrefixOpaqueAccess) || strings.Count(access, ".") != 2 {
		t.Fatalf("want an opaque and a JWT access token: %q %q", opaque, access)
	}
	machine := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme).Str("access_token")

	revoke := func(c Client, tok string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Basic: [2]string{c.ID, c.Secret}, Form: url.Values{"token": {tok}}})
	}
	active := func(tok string) bool {
		return h.Introspect("orders-rs", rs.Secret, tok).Get("active") == true
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := h.App.D.DB.Pool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	unavailable := func(what string, r *Resp) {
		t.Helper()
		mustOAuthError(t, r, 503, "temporarily_unavailable", what)
		if r.Header.Get("Retry-After") == "" {
			t.Fatalf("%s: 503 without Retry-After", what)
		}
	}
	harmless := func(phase string) {
		t.Helper()
		for what, tok := range map[string]string{
			"unknown refresh token": secret.PrefixRefresh + "unknown-000000000000000000000000",
			"unknown opaque token":  secret.PrefixOpaqueAccess + "unknown-000000000000000000000000",
			"malformed JWT":         "a.b.c",
			"another client's JWT":  machine,
			"unrecognized token":    "not-a-token",
		} {
			if r := revoke(web, tok); r.Status != 200 || len(r.Raw) != 0 {
				t.Fatalf("%s: %s: %d %s", phase, what, r.Status, r.Raw)
			}
		}
		// Tokens of web-bff presented by another client are not revoked
		// and answer like unknown ones.
		for what, tok := range map[string]string{"refresh token": refresh, "opaque token": opaque, "JWT": access} {
			if r := revoke(rs, tok); r.Status != 200 || len(r.Raw) != 0 {
				t.Fatalf("%s: web-bff's %s revoked by orders-rs: %d %s", phase, what, r.Status, r.Raw)
			}
		}
	}

	// Every revocation write fails.
	exec(`CREATE FUNCTION test_fail_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected revocation failure'; END $$`)
	exec(`CREATE TRIGGER test_fail_grant BEFORE UPDATE ON authorization_grants FOR EACH ROW EXECUTE FUNCTION test_fail_revocation()`)
	exec(`CREATE TRIGGER test_fail_opaque BEFORE UPDATE ON opaque_access_tokens FOR EACH ROW EXECUTE FUNCTION test_fail_revocation()`)
	exec(`CREATE TRIGGER test_fail_jti BEFORE INSERT ON token_revocations FOR EACH ROW EXECUTE FUNCTION test_fail_revocation()`)
	unavailable("refresh token revocation that cannot be stored", revoke(web, refresh))
	unavailable("opaque token revocation that cannot be stored", revoke(web, opaque))
	unavailable("JWT revocation that cannot be stored", revoke(web, access))
	harmless("storage failing")
	if !active(access) || !active(opaque) {
		t.Fatal("a failed revocation left a token inactive")
	}

	// The JWT revocation's audit event fails: the revocation record is
	// rolled back with it.
	exec(`DROP TRIGGER test_fail_jti ON token_revocations`)
	exec(`CREATE TRIGGER test_fail_audit BEFORE INSERT ON audit_events FOR EACH ROW
		WHEN (NEW.type = 'token.access.revoked') EXECUTE FUNCTION test_fail_revocation()`)
	unavailable("JWT revocation whose audit event cannot be stored", revoke(web, access))
	if !active(access) {
		t.Fatal("a JWT revocation without its audit event took effect")
	}

	// Storage recovers: the client's retries revoke the tokens.
	for _, trg := range []string{"test_fail_grant ON authorization_grants", "test_fail_opaque ON opaque_access_tokens", "test_fail_audit ON audit_events"} {
		exec(`DROP TRIGGER ` + trg)
	}
	harmless("storage recovered")
	for what, tok := range map[string]string{"refresh token": refresh, "opaque token": opaque, "JWT": access} {
		if r := revoke(web, tok); r.Status != 200 || len(r.Raw) != 0 {
			t.Fatalf("retried %s revocation: %d %s", what, r.Status, r.Raw)
		}
	}
	if active(access) || active(opaque) {
		t.Fatal("tokens still active after the retried revocation")
	}
	r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, "web-bff", web.Secret)
	mustOAuthError(t, r, 400, "invalid_grant", "refresh after the retried revocation")
}

// TestProtocolErrorFormat covers API-001, API-007 and API-009 for the
// errors decided before a protocol handler runs: on /realms/{realm}/oauth/*
// and /realms/{realm}/oidc/* a body over limits.max_body_bytes, an unknown
// realm, a host the host policy does not serve and maintenance mode answer in
// the OAuth error format, while the custom APIs and the metadata documents
// keep problem details. Every 429 and 503 carries Retry-After: maintenance
// with retry_after_seconds 0 is clamped to the default delay, and a 503
// written through problem details without a delay of its own (an identity
// domain that is not active) gets the default too. Load shedding on a
// protocol endpoint is covered by TestLoadShedding.
func TestProtocolErrorFormat(t *testing.T) {
	f := limitsFixture(t, func(c *configuration.Config) {
		c.Limits.MaxBodyBytes = 256 << 10 // the smallest allowed limit
		c.Server.HostPolicy = "strict"
	})
	h := f.H
	ctx := context.Background()
	token := func(rq Req) *Resp {
		rq.Method = "POST"
		if rq.Path == "" {
			rq.Path = "/realms/main/oauth/token"
		}
		if rq.Form == nil {
			rq.Form = url.Values{"grant_type": {"client_credentials"}}
		}
		return h.Do(rq)
	}
	problemCode := func(what string, r *Resp, status int, code string) {
		t.Helper()
		if r.Status != status || r.Str("code") != code || r.Header.Get("Content-Type") != "application/problem+json" {
			t.Fatalf("%s: %d %q %s, want %d problem %s", what, r.Status, r.Header.Get("Content-Type"), r.Raw, status, code)
		}
	}

	// A body over limits.max_body_bytes, declared up front.
	big := url.Values{"grant_type": {"client_credentials"}, "client_id": {"proudauth-cli"}, "pad": {strings.Repeat("x", 300<<10)}}
	mustOAuthError(t, token(Req{Form: big}), 413, "invalid_request", "oversized token request")
	mustOAuthError(t, token(Req{Path: "/realms/main/oauth/revoke", Form: big}), 413, "invalid_request", "oversized revocation request")
	mustOAuthError(t, token(Req{Path: "/realms/main/oidc/userinfo", Form: big}), 413, "invalid_request", "oversized UserInfo request")

	// An unknown realm.
	mustOAuthError(t, token(Req{Path: "/realms/nowhere/oauth/token"}), 404, "invalid_request", "token endpoint of an unknown realm")
	mustOAuthError(t, token(Req{Path: "/realms/nowhere/oauth/revoke", Form: url.Values{"token": {"x"}}}), 404, "invalid_request",
		"revocation endpoint of an unknown realm")
	mustOAuthError(t, h.Do(Req{Method: "GET", Path: "/realms/nowhere/oidc/userinfo"}), 404, "invalid_request", "UserInfo of an unknown realm")
	problemCode("discovery of an unknown realm", h.Do(Req{Method: "GET", Path: "/realms/nowhere/.well-known/openid-configuration"}), 404, "not_found")

	// A host the strict host policy does not serve.
	elsewhere := map[string]string{"Host": "elsewhere.test"}
	mustOAuthError(t, token(Req{Headers: elsewhere}), 421, "invalid_request", "token request on another host")
	problemCode("custom API on another host", h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users", Token: f.AdminToken, Headers: elsewhere}),
		421, "misdirected_request")

	// Maintenance with retry_after_seconds 0 (the default) still names a delay.
	setMode := func(mode string) {
		t.Helper()
		if err := maintenance.Set(ctx, h.App.D.DB.Pool, maintenance.State{Mode: mode, Message: "Upgrading"}, "local:test", time.Now()); err != nil {
			t.Fatal(err)
		}
		h.App.Maintenance.Invalidate()
	}
	setMode(maintenance.Unavailable)
	r := token(Req{})
	mustOAuthError(t, r, 503, "temporarily_unavailable", "token request during maintenance")
	if r.Str("error_description") != "Upgrading" || r.Header.Get("Retry-After") != "2" {
		t.Fatalf("token request during maintenance: Retry-After %q %s", r.Header.Get("Retry-After"), r.Raw)
	}
	r = h.API("GET", "/users", f.AdminToken, nil)
	problemCode("custom API during maintenance", r, 503, "maintenance")
	if r.Header.Get("Retry-After") != "2" {
		t.Fatalf("custom API during maintenance: Retry-After %q", r.Header.Get("Retry-After"))
	}
	setMode(maintenance.Off)
	mustStatus(t, h.API("GET", "/users", f.AdminToken, nil), 200, "after maintenance")

	// A 503 without its own delay, written as problem details: an identity
	// domain that is not active.
	if _, err := h.App.Provision.CreateRealm(ctx, "dormant", "Dormant", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE realms SET state='suspended' WHERE name='dormant'`); err != nil {
		t.Fatal(err)
	}
	h.App.Realms.Invalidate("dormant")
	r = h.Do(Req{Method: "GET", Path: "/api/v1/realms/dormant/users", Token: f.AdminToken})
	problemCode("custom API of a suspended realm", r, 503, "unavailable")
	if r.Header.Get("Retry-After") != "2" {
		t.Fatalf("503 without its own delay: Retry-After %q", r.Header.Get("Retry-After"))
	}
}

// TestUserInfoDPoPChallenge covers TOK-019 with RFC 9449 §7.1 at UserInfo:
// a DPoP-bound token presented with the Bearer scheme, without a proof, with
// an invalid proof or with another key's proof is refused with a DPoP
// challenge (invalid_token or invalid_dpop_proof) naming the accepted proof
// algorithms, not a Bearer one; a request without credentials is offered
// both schemes; a valid proof is served.
func TestUserInfoDPoPChallenge(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := func(k *ecdsa.PrivateKey, method, htu, at string) string {
		claims := map[string]any{"jti": secret.Numeric(12), "htm": method, "htu": htu, "iat": h.Clock.Now().Unix()}
		if at != "" {
			sum := sha256.Sum256([]byte(at))
			claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		out, _ := jwt.Signed(s).Claims(claims).Serialize()
		return out
	}
	login := f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	tokenURL := h.Realm.Issuer + "/oauth/token"
	ui := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Basic: [2]string{"web-bff", f.Clients["web"].Secret},
		Headers: map[string]string{"DPoP": proof(key, "POST", tokenURL, "")},
		Form:    url.Values{"grant_type": {"refresh_token"}, "refresh_token": {login.Tokens.Str("refresh_token")}, "resource": {h.Realm.Issuer + "/userinfo"}}})
	mustStatus(t, ui, 200, "DPoP-bound UserInfo token")
	at := ui.Str("access_token")
	if ui.Str("token_type") != "DPoP" {
		t.Fatalf("UserInfo token is not DPoP-bound: %s", ui.Raw)
	}
	userinfoURL := h.Base + "/realms/main/oidc/userinfo"
	get := func(headers map[string]string) *Resp {
		return h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Headers: headers})
	}
	const algs = `algs="RS256 PS256 ES256 EdDSA"`
	for _, tc := range []struct {
		what    string
		headers map[string]string
		code    string
	}{
		{"Bearer scheme", map[string]string{"Authorization": "Bearer " + at}, "invalid_token"},
		{"DPoP scheme without a proof", map[string]string{"Authorization": "DPoP " + at}, "invalid_dpop_proof"},
		{"malformed proof", map[string]string{"Authorization": "DPoP " + at, "DPoP": "not-a-proof"}, "invalid_dpop_proof"},
		{"proof for another URI", map[string]string{"Authorization": "DPoP " + at, "DPoP": proof(key, "GET", tokenURL, at)}, "invalid_dpop_proof"},
		{"proof without the token hash", map[string]string{"Authorization": "DPoP " + at, "DPoP": proof(key, "GET", userinfoURL, "")}, "invalid_dpop_proof"},
		{"proof of another key", map[string]string{"Authorization": "DPoP " + at, "DPoP": proof(other, "GET", userinfoURL, at)}, "invalid_token"},
	} {
		r := get(tc.headers)
		challenge := r.Header.Get("WWW-Authenticate")
		if r.Status != 401 || !strings.HasPrefix(challenge, `DPoP error="`+tc.code+`"`) || !strings.HasSuffix(challenge, algs) {
			t.Fatalf("%s: %d WWW-Authenticate %q, want a DPoP %s challenge with %s", tc.what, r.Status, challenge, tc.code, algs)
		}
	}
	// A token that is not valid at all, presented with the DPoP scheme.
	if r := get(map[string]string{"Authorization": "DPoP pa_at_forged-token-000000000000000000", "DPoP": proof(key, "GET", userinfoURL, "")}); r.Status != 401 ||
		!strings.HasPrefix(r.Header.Get("WWW-Authenticate"), `DPoP error="invalid_token"`) {
		t.Fatalf("invalid token with the DPoP scheme: %d %q", r.Status, r.Header.Get("WWW-Authenticate"))
	}
	// Without credentials both schemes are offered.
	if r := get(nil); r.Status != 401 || !slices.Equal(r.Header.Values("WWW-Authenticate"), []string{"Bearer", "DPoP " + algs}) {
		t.Fatalf("UserInfo without credentials: %d %q", r.Status, r.Header.Values("WWW-Authenticate"))
	}
	ok := get(map[string]string{"Authorization": "DPoP " + at, "DPoP": proof(key, "GET", userinfoURL, at)})
	if ok.Status != 200 || ok.Str("sub") != f.Users["alice"] {
		t.Fatalf("DPoP-bound token with a valid proof: %d %s", ok.Status, ok.Raw)
	}
}
