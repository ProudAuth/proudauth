package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth-sdk-go/verifier"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/token"
)

func (f *Fixture) verifier(t *testing.T, aud string) *verifier.Verifier {
	v, err := verifier.New(verifier.Config{Issuer: f.H.Realm.Issuer, Audience: aud, Now: f.H.Clock.Now, MinRefreshInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestTokenVerificationNegatives covers TEST-001 to TEST-006 with the Go
// verifier against a running server, and OIDC-003: an ID token authenticates
// the user to its client and is refused as an API access token.
func TestTokenVerificationNegatives(t *testing.T) {
	f := NewFixture(t)
	ctx := context.Background()
	billing := f.LoginWeb("alice", f.Acme, f.BillingAud, "openid billing:read")
	billingAT := billing.Tokens.Str("access_token")
	billingV := f.verifier(t, f.BillingAud)
	if _, err := billingV.Verify(ctx, billingAT); err != nil {
		t.Fatalf("valid billing token rejected: %v", err)
	}

	t.Run("TEST-001 wrong audience", func(t *testing.T) {
		ordersV := f.verifier(t, f.OrdersAud)
		if _, err := ordersV.Verify(ctx, billingAT); !errors.Is(err, verifier.ErrAudience) {
			t.Fatalf("want ErrAudience, got %v", err)
		}
	})
	t.Run("TEST-002 ID token sent to an API", func(t *testing.T) {
		if _, err := billingV.Verify(ctx, billing.Tokens.Str("id_token")); !errors.Is(err, verifier.ErrTokenType) {
			t.Fatalf("want ErrTokenType, got %v", err)
		}
	})
	t.Run("TEST-003 unconfigured issuer with familiar subject", func(t *testing.T) {
		before := billingV.FetchCount()
		forged := forge(t, map[string]any{"iss": "https://evil.test/realms/main", "sub": f.Users["alice"], "aud": f.BillingAud,
			"exp": time.Now().Add(time.Minute).Unix(), "token_kind": "user_access", "client_id": "web-bff", "jti": "x"}, "at+jwt", "evil-kid")
		if _, err := billingV.Verify(ctx, forged); !errors.Is(err, verifier.ErrIssuer) {
			t.Fatalf("want ErrIssuer, got %v", err)
		}
		if billingV.FetchCount() != before {
			t.Fatal("an untrusted issuer must not trigger metadata fetching")
		}
	})
	t.Run("TEST-004 algorithm confusion and malformed headers", func(t *testing.T) {
		claims := map[string]any{"iss": f.H.Realm.Issuer, "sub": f.Users["alice"], "aud": f.BillingAud, "exp": time.Now().Add(time.Minute).Unix(),
			"token_kind": "user_access", "client_id": "web-bff", "jti": "x"}
		none := unsigned(claims, `{"alg":"none","typ":"at+jwt"}`)
		hs := hmacToken(t, claims)
		badHeader := "e30." + strings.Split(billingAT, ".")[1] + "." + strings.Split(billingAT, ".")[2]
		dup := dupHeader(billingAT)
		for name, tok := range map[string]string{"none": none, "hs256": hs, "empty-header": badHeader, "duplicate-member": dup} {
			if _, err := billingV.Verify(ctx, tok); err == nil {
				t.Fatalf("%s token accepted", name)
			}
		}
		if _, err := verifier.New(verifier.Config{Issuer: "x", Audience: "y", Algorithms: []string{"HS256"}}); err == nil {
			t.Fatal("HMAC algorithms must be refused in configuration")
		}
	})
	t.Run("TEST-005 unknown kid flood is bounded", func(t *testing.T) {
		v := f.verifier(t, f.BillingAud)
		if _, err := v.Verify(ctx, billingAT); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 50; i++ {
			tok := forge(t, map[string]any{"iss": f.H.Realm.Issuer, "sub": "usr", "aud": f.BillingAud, "exp": time.Now().Add(time.Minute).Unix(),
				"token_kind": "user_access", "client_id": "c", "jti": "j"}, "at+jwt", "random-kid-"+string(rune('a'+i%26))+time.Now().String())
			if _, err := v.Verify(ctx, tok); !errors.Is(err, verifier.ErrUnknownKey) {
				t.Fatalf("want ErrUnknownKey, got %v", err)
			}
		}
		if n := v.FetchCount(); n > 2 {
			t.Fatalf("unknown kids caused %d JWKS fetches; refreshes must be bounded", n)
		}
	})
	t.Run("TEST-006 time validity", func(t *testing.T) {
		v := f.verifier(t, f.BillingAud)
		f.H.Clock.Advance(10 * time.Minute)
		defer f.H.Clock.Advance(-10 * time.Minute)
		if _, err := v.Verify(ctx, billingAT); !errors.Is(err, verifier.ErrExpired) {
			t.Fatalf("want ErrExpired, got %v", err)
		}
		f.H.Clock.Advance(-20 * time.Minute)
		if _, err := v.Verify(ctx, billingAT); !errors.Is(err, verifier.ErrNotYetValid) && !errors.Is(err, verifier.ErrFutureIssued) {
			t.Fatalf("want not-yet-valid, got %v", err)
		}
		f.H.Clock.Advance(10 * time.Minute)
	})
	t.Run("TOK-023 query-string tokens are refused", func(t *testing.T) {
		r := f.H.Do(Req{Method: "GET", Path: "/api/v1/realms/main/me?access_token=" + billingAT, Token: billingAT})
		if r.Status != 400 && r.Status != 401 {
			t.Fatalf("query token accepted: %d", r.Status)
		}
	})
}

// TestSigningKeyRotation covers TEST-036 and TOK-011 (cacheable JWKS with
// stable key IDs and no private members), TOK-012 (planned rotation
// prepublishes the new key, switches issuance, and keeps the previous key
// published while its tokens age out) and TOK-013 (emergency rotation
// rejects the compromised key's tokens at once, withdraws it and notifies
// verifiers through a signing_key.rotated event).
func TestSigningKeyRotation(t *testing.T) {
	f := NewFixture(t)
	ctx := context.Background()
	old := f.LoginWeb("alice", f.Acme, f.BillingAud, "billing:read").Tokens.Str("access_token")
	v := f.verifier(t, f.BillingAud)
	if _, err := v.Verify(ctx, old); err != nil {
		t.Fatal(err)
	}
	// Planned rotation: the new key is prepublished, then activated; the old key keeps
	// verifying during its retirement window (TEST-036).
	if _, err := f.H.App.KeyMgr.Rotate(ctx, f.H.Realm.ID, "RS256", token.RotationPlanned, audit.System, "scheduled"); err != nil {
		t.Fatal(err)
	}
	jwks := f.H.Do(Req{Method: "GET", Path: "/realms/main/jwks"})
	if n := len(jwks.Get("keys").([]any)); n != 2 {
		t.Fatalf("prepublished key missing: %d keys", n)
	}
	// TOK-011: cacheable, stable key IDs, public members only.
	if cc := jwks.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=") || strings.Contains(cc, "no-store") {
		t.Fatalf("JWKS Cache-Control: %q", cc)
	}
	for _, k := range jwks.Get("keys").([]any) {
		key := k.(map[string]any)
		if kid, _ := key["kid"].(string); kid == "" {
			t.Fatalf("JWKS key without a kid: %v", key)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := key[private]; ok {
				t.Fatalf("JWKS publishes the private member %q", private)
			}
		}
	}
	if again := f.H.Do(Req{Method: "GET", Path: "/realms/main/jwks"}); jsonString(again.Get("keys")) != jsonString(jwks.Get("keys")) {
		t.Fatal("JWKS changed between fetches without a rotation")
	}
	if _, err := f.H.App.KeyMgr.ActivateDue(ctx, 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.H.App.KeyMgr.Invalidate(f.H.Realm.ID)
	// TOK-012: the previous key stays published while its tokens and verifier caches age out.
	if keys := jsonString(f.H.Do(Req{Method: "GET", Path: "/realms/main/jwks"}).Get("keys")); !strings.Contains(keys, kidOf(old)) {
		t.Fatalf("retiring key withdrawn at activation: %s", keys)
	}
	f.H.Clock.Advance(2 * time.Minute)
	fresh := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	_ = fresh
	newTok := f.LoginWeb("alice", f.Acme, f.BillingAud, "billing:read").Tokens.Str("access_token")
	if kidOf(newTok) == kidOf(old) {
		t.Fatal("new tokens must use the new key")
	}
	if _, err := v.Verify(ctx, newTok); err != nil {
		t.Fatalf("verifier must refresh for the new kid: %v", err)
	}
	if _, err := v.Verify(ctx, old); err != nil && !errors.Is(err, verifier.ErrExpired) {
		t.Fatalf("planned-overlap token must still verify: %v", err)
	}
	// Emergency rotation: the compromised key leaves JWKS and the server rejects its tokens.
	if _, err := f.H.App.KeyMgr.Rotate(ctx, f.H.Realm.ID, "RS256", token.RotationEmergency, audit.System, "compromise"); err != nil {
		t.Fatal(err)
	}
	f.H.App.KeyMgr.Invalidate(f.H.Realm.ID)
	in := f.H.Introspect("billing-rs", f.Clients["billing-rs"].Secret, newTok)
	if in.Get("active") != false {
		t.Fatalf("tokens signed by a compromised key must be inactive: %s", in.Raw)
	}
	jwks = f.H.Do(Req{Method: "GET", Path: "/realms/main/jwks"})
	for _, k := range jwks.Get("keys").([]any) {
		if k.(map[string]any)["kid"] == kidOf(newTok) {
			t.Fatal("compromised key still published")
		}
	}
	// TOK-013: leaving JWKS does not purge verifier caches, so relying services
	// are notified that the previous key is compromised.
	var notified int
	if err := f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='signing_key.rotated'
		AND payload->'data'->>'previous_kid'=$2 AND payload->'data'->>'previous_key_compromised'='true'`, f.H.Realm.ID, kidOf(newTok)).Scan(&notified); err != nil || notified != 1 {
		t.Fatalf("compromise notification events: %d %v", notified, err)
	}
}

func kidOf(tok string) string {
	h, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var m map[string]any
	_ = json.Unmarshal(h, &m)
	s, _ := m["kid"].(string)
	return s
}

func forge(t *testing.T, claims map[string]any, typ, kid string) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k, KeyID: kid}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func unsigned(claims map[string]any, header string) string {
	b, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(b) + "."
}

func hmacToken(t *testing.T, claims map[string]any) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jwt.Signed(s).Claims(claims).Serialize()
	return out
}

func dupHeader(tok string) string {
	parts := strings.Split(tok, ".")
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	dup := strings.Replace(string(h), `"alg":`, `"alg":"none","alg":`, 1)
	return base64.RawURLEncoding.EncodeToString([]byte(dup)) + "." + parts[1] + "." + parts[2]
}

// TestResourceAlgorithmProfile covers TOK-005: a resource pins its access-token
// algorithm from the operator allowlist (asymmetric only); issuance fails closed
// when the active key does not match, and key rotation to another algorithm is
// refused while resources pin the current one.
func TestResourceAlgorithmProfile(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	put := func(alg string) *Resp {
		cur := f.must(f.AdminAPI("GET", "/resources/"+f.Orders, nil), 200, "resource")
		return h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resources/" + f.Orders, Token: f.AdminToken,
			JSON:    map[string]any{"name": "Orders API", "verification_mode": "strict_online", "signing_algorithm": alg},
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
	}
	mustStatus(t, put("HS256"), 422, "symmetric algorithm")
	mustStatus(t, put("none"), 422, "unsigned")
	mustStatus(t, put("ES256"), 200, "pin a different allowed algorithm")
	lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", ExpectFail: true})
	if lr.Tokens == nil || lr.Tokens.Status == 200 {
		t.Fatal("token signed with a key outside the resource's algorithm profile")
	}
	mustStatus(t, put("RS256"), 200, "re-pin to the active algorithm")
	mustStatus(t, f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens, 200, "issuance with matching profile")
	f.ReloginAdmin()
	r := f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"algorithm": "ES256", "reason": "algorithm migration"})
	if r.Status != 409 || !strings.Contains(string(r.Raw), f.OrdersAud) {
		t.Fatalf("rotation to an algorithm pinned resources reject: %d %s", r.Status, r.Raw)
	}
}

// TestScopeSubjectAndOrganizationPolicy covers TOK-008: scopes are a subset of
// client, consent, resource, subject and organization policy, and refresh
// cannot keep a scope the subject no longer qualifies for. Requirements:
// APP-007 (requesting a declared scope does not grant it).
func TestScopeSubjectAndOrganizationPolicy(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:refund", "required_permissions": []string{"no.such.permission"}}),
		422, "unknown required permission")
	f.must(f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:refund", "required_permissions": []string{"orders.refund"}}),
		201, "scope with subject policy")
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+f.Orders,
		map[string]any{"allowed_scopes": []string{"orders:read", "orders:write", "orders:refund"}, "subject_types": []string{"user"}}), 204, "grant")
	scopesOf := func(user string) string {
		lr := f.LoginWeb(user, f.Acme, f.OrdersAud, "orders:read orders:refund")
		mustStatus(t, lr.Tokens, 200, "token for "+user)
		return lr.Tokens.Str("scope")
	}
	if s := scopesOf("bob"); s != "orders:read" {
		t.Fatalf("subject without orders.refund received %q", s)
	}
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read orders:refund").Tokens
	if s := alice.Str("scope"); s != "orders:read orders:refund" {
		t.Fatalf("qualified subject: %q", s)
	}
	// Organization ceiling.
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_scopes": []string{"orders:read"}}}}), 200, "org scope ceiling")
	refreshed := h.TokenRequest(map[string][]string{"grant_type": {"refresh_token"}, "refresh_token": {alice.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, refreshed, 200, "refresh")
	if s := refreshed.Str("scope"); s != "orders:read" {
		t.Fatalf("refresh kept a scope the organization no longer allows: %q", s)
	}
}

// TestClaimsRequestAndStaticClaims covers OIDC-007 (static client mappings
// never replace user claims with verified provenance) and OIDC-008 (the claims
// parameter narrows ID-token and UserInfo release separately, within scope).
func TestClaimsRequestAndStaticClaims(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "spoofer", "name": "x", "client_type": "confidential",
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://spoof.test/cb"},
		"id_token_claims": map[string]any{"email_verified": true}}), 422, "static email_verified mapping")
	login := func(claims string) (map[string]any, map[string]any) {
		lr := h.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "openid profile email orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", Claims: claims})
		mustStatus(t, lr.Tokens, 200, "login")
		idt := jwtPayload(lr.Tokens.Str("id_token"))
		ui := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")},
			"resource": {h.Realm.Issuer + "/userinfo"}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, ui, 200, "userinfo token")
		info := h.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: ui.Str("access_token")})
		mustStatus(t, info, 200, "userinfo")
		return idt, info.Body
	}
	idt, info := login(`{"id_token":{"email":null}}`)
	if idt["email"] == nil || idt["email_verified"] == nil || idt["preferred_username"] != nil {
		t.Fatalf("id_token member must narrow ID-token claims to email: %v", idt)
	}
	if info["email"] == nil || info["preferred_username"] == nil {
		t.Fatalf("UserInfo without a userinfo member releases by scope: %v", info)
	}
	idt, info = login(`{"userinfo":{"email":null}}`)
	if idt["preferred_username"] == nil {
		t.Fatalf("ID token without an id_token member releases by scope: %v", idt)
	}
	if info["email"] == nil || info["preferred_username"] != nil || info["sub"] == nil {
		t.Fatalf("userinfo member must narrow UserInfo to email: %v", info)
	}
}

// TestPairwiseSubjects covers OIDC-010/APP-012: reviewed sectors, stable
// durable pairwise identifiers, and separation between sectors.
func TestPairwiseSubjects(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	userinfo := ""
	for _, it := range f.must(f.AdminAPI("GET", "/resources?limit=200", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			userinfo = m["id"].(string)
		}
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "squatter", "name": "x", "client_type": "confidential",
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://evil.test/cb"}, "subject_type": "pairwise",
		"sector_identifier": "rp-one.test"}), 422, "sector not owning the redirect URIs")
	mk := func(id, host string) Client {
		r := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": id, "name": id, "client_type": "confidential", "first_party": true,
			"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{"https://" + host + "/cb"}, "subject_type": "pairwise"}), 201, id)
		c := Client{Ref: r.Str("client.id"), ID: id, Secret: r.Str("client_secret")}
		f.must(f.AdminAPI("PUT", "/clients/"+c.Ref+"/resource-grants/"+userinfo, map[string]any{"allowed_scopes": []string{"openid"}, "subject_types": []string{"user"}}), 204, "grant")
		return c
	}
	one, two := mk("rp-one", "rp-one.test"), mk("rp-two", "rp-two.test")
	sub := func(c Client) string {
		lr := h.Login(LoginOpts{ClientID: c.ID, ClientSecret: c.Secret, RedirectURI: "https://" + c.ID + ".test/cb", Scope: "openid",
			Resources: []string{h.Realm.Issuer + "/userinfo"}, Identifier: "bob@example.test"})
		mustStatus(t, lr.Tokens, 200, "login "+c.ID)
		return jwtPayload(lr.Tokens.Str("id_token"))["sub"].(string)
	}
	s1 := sub(one)
	if !strings.HasPrefix(s1, "pws_") || s1 == f.Users["bob"] {
		t.Fatalf("pairwise subject exposes the internal ID: %q", s1)
	}
	if again := sub(one); again != s1 {
		t.Fatalf("pairwise subject not stable: %q vs %q", s1, again)
	}
	if s2 := sub(two); s2 == s1 {
		t.Fatal("two sectors share a pairwise subject")
	}
	var stored int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM pairwise_subjects WHERE user_id=$1`, f.Users["bob"]).Scan(&stored)
	if stored != 2 {
		t.Fatalf("pairwise mappings are not durable: %d rows", stored)
	}
	// Deletion erases the mappings with the account (PRV-005): the users row
	// survives as a tombstone, so nothing cascades on its own.
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["bob"], nil), 204, "delete bob")
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM pairwise_subjects WHERE user_id=$1`, f.Users["bob"]).Scan(&stored)
	if stored != 0 {
		t.Fatalf("pairwise mappings survived account deletion: %d rows", stored)
	}
}

// TestScopeStepUp covers AUT-010: a sensitive scope requires a stronger and
// fresher authentication than the SSO session has; the session is stepped up
// (never downgraded) and refresh drops the scope once the authentication is
// older than the scope allows. Requirements: OIDC-004 (a refresh alone never
// satisfies a fresh-authentication requirement).
func TestScopeStepUp(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:refund", "step_up_acr": "urn:proudauth:acr:gold"}),
		422, "unknown step-up assurance")
	mustStatus(t, f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:refund", "max_auth_age_seconds": 5}), 422, "too short")
	f.must(f.AdminAPI("POST", "/resources/"+f.Orders+"/scopes", map[string]any{"name": "orders:refund", "step_up_acr": "urn:proudauth:acr:mfa",
		"max_auth_age_seconds": 300}), 201, "step-up scope")
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+f.Orders,
		map[string]any{"allowed_scopes": []string{"orders:read", "orders:refund"}, "subject_types": []string{"user"}}), 204, "grant")

	// Without a second factor the scope cannot be granted: the transaction
	// asks for MFA enrollment instead of completing at single-factor assurance.
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read orders:refund",
		Resources: []string{f.OrdersAud}, Organization: f.Acme})
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if st.Str("redirect_to") != "" || !hasAction(st, "enroll_totp") {
		t.Fatalf("step-up scope did not require a second factor: %s", st.Raw)
	}
	// The same user without the sensitive scope signs in at single factor.
	bobTok := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens
	mustStatus(t, bobTok, 200, "ordinary scope")
	// Token exchange: a default (scope-less) request drops scopes the subject
	// token's authentication cannot carry; naming one is refused.
	f.must(f.AdminAPI("POST", "/resources/"+f.Billing+"/scopes", map[string]any{"name": "billing:approve", "step_up_acr": "urn:proudauth:acr:mfa"}), 201, "billing step-up scope")
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["orders-rs"].Ref+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read", "billing:approve"},
		"subject_types": []string{"service_principal", "user"}, "exchange_policy": map[string]any{"accept_from_audiences": []string{f.OrdersAud}}}), 204, "exchange grant")
	exchange := func(scope string) *Resp {
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {bobTok.Str("access_token")},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}}
		if scope != "" {
			form.Set("scope", scope)
		}
		return h.TokenRequest(form, "orders-rs", f.Clients["orders-rs"].Secret)
	}
	if ex := exchange(""); ex.Status != 200 || ex.Str("scope") != "billing:read" {
		t.Fatalf("default exchange with a step-up scope in the ceiling: %d %s", ex.Status, ex.Raw)
	}
	mustStatus(t, exchange("billing:approve"), 400, "explicit step-up scope in exchange")
	// The organization's scope ceiling applies to exchanged tokens (TOK-008).
	org := f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"allowed_scopes": []string{"orders:read"}}}}),
		200, "organization scope ceiling")
	mustStatus(t, exchange("billing:read"), 400, "exchange beyond the organization scope ceiling")
	mustStatus(t, exchange(""), 400, "default exchange with nothing permitted")
	org = f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + f.Acme, Token: f.AdminToken,
		Headers: map[string]string{"If-Match": org.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{}}}), 200, "remove the ceiling")

	// An MFA user gets the scope; a refresh after the maximum authentication
	// age keeps the ordinary scope and drops the sensitive one.
	f.EnrollTOTP("alice")
	tok := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read orders:refund").Tokens
	mustStatus(t, tok, 200, "stepped-up token")
	if s := tok.Str("scope"); s != "orders:read orders:refund" {
		t.Fatalf("stepped-up scopes: %q", s)
	}
	if acr := jwtPayload(tok.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:mfa" && acr != "urn:proudauth:acr:phishing_resistant" {
		t.Fatalf("token assurance: %v", acr)
	}
	h.Clock.Advance(6 * time.Minute)
	ref := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, ref, 200, "refresh")
	if s := ref.Str("scope"); s != "orders:read" {
		t.Fatalf("refresh carried a step-up scope past its authentication age: %q", s)
	}
}

// TestConsentManagement covers APP-013: consents record the client's terms
// version and are asked again when the terms change; administrators can
// pre-authorize a third-party client for an organization, see and revoke
// users' consents, and revoking a pre-authorization ends grants built on it.
func TestConsentManagement(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	body := map[string]any{"client_id": "terms-app", "name": "Terms App", "client_type": "confidential", "first_party": false,
		"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{"https://terms.test/cb"}, "consent_terms_version": "v1"}
	created := f.must(f.AdminAPI("POST", "/clients", body), 201, "client")
	ref, sec := created.Str("client.id"), created.Str("client_secret")
	f.must(f.AdminAPI("PUT", "/clients/"+ref+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"}, "subject_types": []string{"user"}}),
		204, "grant")
	login := func(user string) *LoginResult {
		t.Helper()
		lr := h.Login(LoginOpts{ClientID: "terms-app", ClientSecret: sec, RedirectURI: "https://terms.test/cb", Scope: "orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: user + "@example.test"})
		mustStatus(t, lr.Tokens, 200, "login "+user)
		return lr
	}
	consentsGranted := func(user string) int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type='consent.granted' AND subject_id=$1`, f.Users[user]).Scan(&n)
		return n
	}
	login("bob")
	login("bob")
	if n := consentsGranted("bob"); n != 1 {
		t.Fatalf("consent asked again for unchanged terms: %d", n)
	}
	// Exchanging the third-party client's token cannot reach scopes the user
	// never consented to for it, even where the exchange policy allows them (TOK-008).
	ex := h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {login("bob").Tokens.Str("access_token")},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}, "scope": {"billing:read"}},
		"orders-rs", f.Clients["orders-rs"].Secret)
	if ex.Status != 400 || ex.Str("error") != "invalid_scope" {
		t.Fatalf("exchange beyond the user's consent: %d %s", ex.Status, ex.Raw)
	}
	bobTok := f.AccountToken("bob").Tokens.Str("access_token")
	mine := f.must(h.API("GET", "/me/consents", bobTok, nil), 200, "my consents")
	if it := mine.Get("items").([]any); len(it) != 1 || it[0].(map[string]any)["terms_version"] != "v1" || it[0].(map[string]any)["mode"] != "user" {
		t.Fatalf("consent record: %s", mine.Raw)
	}
	// New terms: the consent no longer covers the client.
	cur := f.must(f.AdminAPI("GET", "/clients/"+ref, nil), 200, "client")
	body["consent_terms_version"] = "v2"
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/clients/" + ref, Token: f.AdminToken, JSON: body,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "new terms")
	login("bob")
	if n := consentsGranted("bob"); n != 2 {
		t.Fatalf("changed terms did not ask for consent again: %d", n)
	}
	hist := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"]+"/consents?history=true", nil), 200, "admin consent view")
	if len(hist.Get("items").([]any)) != 2 {
		t.Fatalf("consent history: %s", hist.Raw)
	}

	// Organization pre-authorization: alice in Acme is not asked; the consent
	// basis is recorded and ends with the pre-authorization.
	mustStatus(t, f.AdminAPI("POST", "/clients/"+ref+"/consent-preauthorizations", map[string]any{"organization_id": f.Acme,
		"scopes": []string{"offline_access"}, "reason": "procurement approved"}), 422, "offline access cannot be pre-authorized")
	pre := f.must(f.AdminAPI("POST", "/clients/"+ref+"/consent-preauthorizations", map[string]any{"organization_id": f.Acme,
		"scopes": []string{"orders:read"}, "reason": "procurement ticket 81"}), 201, "pre-authorize")
	lr := login("alice")
	if n := consentsGranted("alice"); n != 0 {
		t.Fatalf("pre-authorized client still asked for consent: %d", n)
	}
	ac := f.must(f.AdminAPI("GET", "/users/"+f.Users["alice"]+"/consents", nil), 200, "alice consents")
	if it := ac.Get("items").([]any); len(it) != 1 || it[0].(map[string]any)["mode"] != "preauthorized" {
		t.Fatalf("pre-authorized consent basis: %s", ac.Raw)
	}
	mustStatus(t, f.AdminAPI("DELETE", "/clients/"+ref+"/consent-preauthorizations/"+pre.Str("id"), nil), 204, "revoke pre-authorization")
	ref2 := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}}, "terms-app", sec)
	if ref2.Status == 200 {
		t.Fatal("grant survived the revoked pre-authorization")
	}
	// Administrators revoke a user's consent.
	live := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"]+"/consents", nil), 200, "bob consents").Get("items").([]any)
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["bob"]+"/consents/"+live[0].(map[string]any)["id"].(string), nil), 204, "admin revokes consent")
	if left := f.must(h.API("GET", "/me/consents", bobTok, nil), 200, "after").Get("items").([]any); len(left) != 0 {
		t.Fatal("revoked consent still live")
	}
}

// TestTokenLifetimePolicy covers TOK-018: realm limits on access-token
// lifetimes overall, by subject type and by assurance, on top of resource and
// client lifetimes and within the operator maximum.
func TestTokenLifetimePolicy(t *testing.T) {
	f := NewFixture(t)
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Tokens.AccessTokenTTLSeconds = 5 }), 422, "below the safety floor")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Tokens = realm.TokenLifetimePolicy{AccessTokenTTLSeconds: 1200, ServiceAccessTokenTTLSeconds: 120, SingleFactorAccessTokenTTLSeconds: 300}
	}), 200, "lifetimes")
	expires := func(r *Resp) float64 {
		t.Helper()
		mustStatus(t, r, 200, "token")
		return r.Get("expires_in").(float64)
	}
	if e := expires(f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)); e > 120 {
		t.Fatalf("service principal token lifetime %v exceeds the realm limit", e)
	}
	if e := expires(f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens); e > 300 {
		t.Fatalf("single-factor token lifetime %v exceeds the realm limit", e)
	}
	f.EnrollTOTP("alice")
	if e := expires(f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens); e != 300 {
		t.Fatalf("MFA token lifetime %v: the resource lifetime applies under a looser realm limit", e)
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Tokens.AccessTokenTTLSeconds = 240 }), 200, "realm maximum")
	if e := expires(f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens); e > 240 {
		t.Fatalf("token lifetime %v exceeds the realm maximum", e)
	}
}

// TestPairwiseSectors covers OIDC-010: a sector must contain every redirect
// URI of the client, and clients registered in the same sector share a
// pairwise subject while other sectors do not.
func TestPairwiseSectors(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mk := func(id, host, sector string) *Resp {
		return f.AdminAPI("POST", "/clients", map[string]any{"client_id": id, "name": id, "client_type": "confidential", "first_party": true,
			"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://" + host + "/cb"}, "subject_type": "pairwise",
			"sector_identifier": sector})
	}
	mustStatus(t, mk("thief", "evil.test", "shop.test"), 422, "sector that does not contain the redirect URIs")
	var userinfo string
	res := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	for _, it := range res.Get("items").([]any) {
		if m := it.(map[string]any); m["audience"] == h.Realm.Issuer+"/userinfo" {
			userinfo = m["id"].(string)
		}
	}
	sub := func(id, host, sector string) string {
		t.Helper()
		c := f.must(mk(id, host, sector), 201, id)
		f.must(f.AdminAPI("PUT", "/clients/"+c.Str("client.id")+"/resource-grants/"+userinfo, map[string]any{"allowed_scopes": []string{"openid"},
			"subject_types": []string{"user"}}), 204, "grant")
		lr := h.Login(LoginOpts{ClientID: id, ClientSecret: c.Str("client_secret"), RedirectURI: "https://" + host + "/cb", Scope: "openid",
			Resources: []string{h.Realm.Issuer + "/userinfo"}, Identifier: "bob@example.test"})
		mustStatus(t, lr.Tokens, 200, "login "+id)
		return jwtPayload(lr.Tokens.Str("id_token"))["sub"].(string)
	}
	a := sub("shop-web", "web.shop.test", "shop.test")
	b := sub("shop-admin", "admin.shop.test", "shop.test")
	c := sub("other", "other.test", "")
	if a != b {
		t.Fatalf("clients in one sector disagree on the pairwise subject: %s vs %s", a, b)
	}
	if a == c {
		t.Fatal("different sectors share a pairwise subject")
	}
}

// TestEnvironmentSeparation covers APP-015: client environments are fixed at
// registration and must match their project's, and a token minted for a
// development client is never accepted by a production client's exchange.
func TestEnvironmentSeparation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	prj := f.must(f.AdminAPI("POST", "/projects", map[string]any{"name": "Payments", "environment": "production"}), 201, "project").Str("id")
	mustStatus(t, f.AdminAPI("POST", "/clients", map[string]any{"client_id": "pay-dev", "name": "x", "client_type": "confidential", "project_id": prj,
		"environment": "development", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://pay.test/cb"}}), 422,
		"development client in a production project")
	dev := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "orders-dev", "name": "Orders dev", "client_type": "confidential",
		"first_party": true, "environment": "development", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{webRedirect}}), 201, "dev client")
	cur := f.must(f.AdminAPI("GET", "/clients/"+dev.Str("client.id"), nil), 200, "client")
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/clients/" + dev.Str("client.id"), Token: f.AdminToken,
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: map[string]any{"name": "Orders dev", "client_type": "confidential",
			"first_party": true, "environment": "production", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{webRedirect}}}),
		422, "promote a development client in place")
	f.must(f.AdminAPI("PUT", "/clients/"+dev.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	lr := h.Login(LoginOpts{ClientID: "orders-dev", ClientSecret: dev.Str("client_secret"), RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "alice@example.test"})
	mustStatus(t, lr.Tokens, 200, "development token")
	exchange := func(at string) *Resp {
		return h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {at},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {f.BillingAud}, "scope": {"billing:read"}},
			"orders-rs", f.Clients["orders-rs"].Secret)
	}
	if r := exchange(lr.Tokens.Str("access_token")); r.Status != 400 || r.Str("error") != "invalid_grant" {
		t.Fatalf("production client exchanged a development token: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, exchange(f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")), 200, "production token exchanges")
}

// TestClaimMappings covers APP-011: clients map approved attributes to claims
// with bounded expressions, separately for ID and access tokens; only
// claimable profile attributes are released, and reserved names stay
// protected (TOK-015: a mapping onto sub is refused).
func TestClaimMappings(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{
			{Name: "department", Type: "string", MaxLength: 64, Visibility: "admin", Source: "directory", Claimable: true},
			{Name: "team", Type: "string", MaxLength: 64, UserEditable: true, Visibility: "self", Source: "local"},
		}
	}), 200, "profile schema")
	// Values users set themselves are never released in token claims.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = append(p.Profile.Attributes, identity.AttributeDef{Name: "nick", Type: "string", MaxLength: 64, UserEditable: true,
			Visibility: "self", Source: "local", Claimable: true})
	}), 422, "claimable user-editable attribute")
	u := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "user")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/users/" + f.Users["bob"], Token: f.AdminToken,
		Headers: map[string]string{"If-Match": u.Header.Get("ETag")}, JSON: map[string]any{"profile": map[string]any{"department": "sales", "team": "blue"}}}), 200, "profile")
	base := map[string]any{"client_id": "mapped", "name": "Mapped", "client_type": "confidential", "first_party": true,
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://mapped.test/cb"}}
	withClaims := func(id, at map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m["id_token_claims"], m["access_token_claims"] = id, at
		return m
	}
	mustStatus(t, f.AdminAPI("POST", "/clients", withClaims(map[string]any{"x": map[string]any{"$attr": "user.email"}}, nil)), 422, "unapproved attribute")
	mustStatus(t, f.AdminAPI("POST", "/clients", withClaims(nil, map[string]any{"sub": map[string]any{"$attr": "user.locale"}})), 422, "reserved claim")
	c := f.must(f.AdminAPI("POST", "/clients", withClaims(
		map[string]any{"dept": map[string]any{"$attr": "profile.department", "transform": "upper"}, "tier": "gold"},
		map[string]any{"team": map[string]any{"$attr": "profile.team", "default": "unknown"}, "dept": map[string]any{"$attr": "profile.department"}})), 201, "client")
	f.must(f.AdminAPI("PUT", "/clients/"+c.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	var userinfo string
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["audience"] == h.Realm.Issuer+"/userinfo" {
			userinfo = m["id"].(string)
		}
	}
	f.must(f.AdminAPI("PUT", "/clients/"+c.Str("client.id")+"/resource-grants/"+userinfo, map[string]any{"allowed_scopes": []string{"openid", "profile"},
		"subject_types": []string{"user"}}), 204, "oidc grant")
	// Without the profile scope, mappings release no attribute values; static
	// values and defaults still apply.
	lr := h.Login(LoginOpts{ClientID: "mapped", ClientSecret: c.Str("client_secret"), RedirectURI: "https://mapped.test/cb", Scope: "openid orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	mustStatus(t, lr.Tokens, 200, "login without profile")
	if idt, at := jwtPayload(lr.Tokens.Str("id_token")), jwtPayload(lr.Tokens.Str("access_token")); idt["dept"] != nil || at["dept"] != nil || idt["tier"] != "gold" {
		t.Fatalf("attribute released without the profile scope: %v %v", idt, at)
	}
	lr = h.Login(LoginOpts{ClientID: "mapped", ClientSecret: c.Str("client_secret"), RedirectURI: "https://mapped.test/cb", Scope: "openid profile orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	mustStatus(t, lr.Tokens, 200, "login")
	idt := jwtPayload(lr.Tokens.Str("id_token"))
	if idt["dept"] != "SALES" || idt["tier"] != "gold" {
		t.Fatalf("ID token mappings: %v", idt)
	}
	at := jwtPayload(lr.Tokens.Str("access_token"))
	if at["dept"] != "sales" || at["team"] != "unknown" || idt["team"] != nil {
		t.Fatalf("access token mappings (team is not claimable): %v", at)
	}
}
