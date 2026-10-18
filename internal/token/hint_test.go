package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
)

// TestIDTokenHintTypes covers SES-016 and §14.1 (logout-hint-typ-confusion,
// decision 15): the realm key signs ID tokens, JARM responses and signed
// UserInfo, and only an ID token passes as id_token_hint. JARM responses and
// signed UserInfo get their own typ; a hint must carry typ JWT (an absent typ
// is refused) and the shape of an ID token (sub, aud, exp and iat, no code,
// error or state), so JARM and UserInfo JWTs signed before the new types
// existed are refused too. An expired ID token is still a valid hint.
func TestIDTokenHintTypes(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Unix(1_800_000_000, 0))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := PublicKey{KID: "k1", Algorithm: "ES256", State: StateActive, JWK: jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}
	km := &KeyManager{d: &runtime.Deps{Clock: clk}, CacheTTL: 1000 * time.Hour, cache: map[string]*realmKeys{"rlm": {loadedAt: clk.Now(),
		active: &SigningKey{KID: "k1", Algorithm: "ES256", State: StateActive, Private: key, Public: pub.JWK},
		public: []PublicKey{pub}, byKID: map[string]PublicKey{"k1": pub}, compromised: map[string]bool{}}}}
	v := &Verifier{Keys: km, Algorithms: []jose.SignatureAlgorithm{jose.ES256}, Now: clk.Now}
	const iss = "https://id.test/realms/main"
	now := clk.Now().Unix()
	// sign signs claims with the realm key; an empty typ leaves the header out.
	sign := func(typ string, claims map[string]any) string {
		t.Helper()
		opts := (&jose.SignerOptions{}).WithHeader("kid", "k1")
		if typ != "" {
			opts = opts.WithType(jose.ContentType(typ))
		}
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
		if err != nil {
			t.Fatal(err)
		}
		out, err := jwt.Signed(s).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	idToken := map[string]any{"iss": iss, "sub": "usr_1", "aud": "web", "azp": "web", "exp": now + 300, "iat": now, "sid": "ses_1", "nonce": "n"}
	with := func(base map[string]any, set map[string]any, drop ...string) map[string]any {
		out := maps.Clone(base)
		maps.Copy(out, set)
		for _, k := range drop {
			delete(out, k)
		}
		return out
	}

	// The ID token the Signer mints is accepted, also long after it expired.
	minted, err := (&Signer{Keys: km}).Sign(ctx, "rlm", TypeID, IDClaims{Issuer: iss, Subject: "usr_1", Audience: jwt.Audience{"web"},
		Expiry: now + 300, IssuedAt: now, SessionID: "ses_1"})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(48 * time.Hour)
	if c, err := v.VerifyIDTokenHint(ctx, "rlm", iss, minted); err != nil || c.Subject != "usr_1" || c.SessionID != "ses_1" {
		t.Fatalf("expired ID token as hint: %v %+v", err, c)
	}
	if _, err := v.VerifyIDTokenHint(ctx, "rlm", iss, sign("jwt", idToken)); err != nil {
		t.Fatalf("typ is compared case-insensitively: %v", err)
	}
	if _, err := v.VerifyIDTokenHint(ctx, "rlm", "https://other.test", minted); !errors.Is(err, ErrIssuer) {
		t.Fatalf("hint from another issuer: %v", err)
	}

	jarmError := map[string]any{"iss": iss, "aud": "web", "exp": now + 600, "error": "invalid_request",
		"error_description": "code_challenge required", "state": "s"}
	jarmCode := map[string]any{"iss": iss, "aud": "web", "exp": now + 600, "code": "pa_ac_x", "state": "s"}
	userInfo := map[string]any{"iss": iss, "aud": "web", "sub": "usr_1", "email": "a@example.test"}
	for name, raw := range map[string]string{
		"JARM response":                  sign(TypeJARM, jarmError),
		"signed UserInfo":                sign(TypeUserInfo, userInfo),
		"ID token claims typed for JARM": sign(TypeJARM, idToken),
		"ID token claims typed UserInfo": sign(TypeUserInfo, idToken),
		"access token type":              sign(TypeAccess, idToken),
		"logout token type":              sign(TypeLogout, idToken),
		"no typ":                         sign("", idToken),
		// Typed JWT, as JARM and signed UserInfo were before they had types.
		"legacy JARM error":         sign(TypeID, jarmError),
		"legacy JARM code":          sign(TypeID, jarmCode),
		"legacy signed UserInfo":    sign(TypeID, userInfo),
		"ID token claims with code": sign(TypeID, with(idToken, map[string]any{"code": "pa_ac_x"})),
		"with error":                sign(TypeID, with(idToken, map[string]any{"error": "access_denied"})),
		"with state":                sign(TypeID, with(idToken, map[string]any{"state": "s"})),
		"without sub":               sign(TypeID, with(idToken, nil, "sub")),
		"empty sub":                 sign(TypeID, with(idToken, map[string]any{"sub": ""})),
		"without aud":               sign(TypeID, with(idToken, nil, "aud")),
		"without exp":               sign(TypeID, with(idToken, nil, "exp")),
		"without iat":               sign(TypeID, with(idToken, nil, "iat")),
	} {
		if c, err := v.VerifyIDTokenHint(ctx, "rlm", iss, raw); !errors.Is(err, ErrWrongType) {
			t.Errorf("%s accepted as an ID token hint: %v %+v", name, err, c)
		}
	}
}

// TestIDTokenLeavesOutAuthorizationResponseMembers covers TOK-015: a claim
// mapping that names code, error or state never puts it into an ID token,
// which would then be refused as a logout hint (IDTokenShaped).
func TestIDTokenLeavesOutAuthorizationResponseMembers(t *testing.T) {
	b, err := json.Marshal(IDClaims{Issuer: "https://id.test", Subject: "usr_1", Audience: jwt.Audience{"web"}, Expiry: 2, IssuedAt: 1,
		Claims: map[string]any{"code": "x", "error": "y", "state": "CA", "department": "sales"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range AuthorizationResponseMembers {
		if _, ok := m[k]; ok {
			t.Errorf("ID token carries %s: %s", k, b)
		}
	}
	if string(m["department"]) != `"sales"` {
		t.Errorf("other mapped claims must stay: %s", b)
	}
	var c IDClaims
	_ = json.Unmarshal(b, &c)
	if !IDTokenShaped(&c, m) {
		t.Errorf("a minted ID token is not ID-token shaped: %s", b)
	}
}
