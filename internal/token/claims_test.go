package token

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
)

// TestReservedClaimsCannotBeOverridden covers TOK-015: tenant-defined claims
// (mappings, hooks) are merged into access and ID tokens without ever
// replacing or adding the subject, actor, issuer, audience, expiry, client
// ID, token type or other security-critical claims; other names pass through.
func TestReservedClaimsCannotBeOverridden(t *testing.T) {
	critical := []string{"sub", "act", "iss", "aud", "exp", "client_id", "token_kind", "typ", "azp", "scope", "org_id", "acr", "auth_time", "jti", "cnf", "nonce", "grant_id"}
	for _, name := range critical {
		if !ReservedClaims[name] {
			t.Errorf("%s is not reserved", name)
		}
	}
	forged := map[string]any{"department": "sales"}
	for _, name := range critical {
		forged[name] = "forged"
	}
	decode := func(v any) map[string]any {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	at := decode(AccessClaims{Issuer: "https://id.test/realms/main", Subject: "usr_1", Audience: jwt.Audience{"https://orders.test"},
		ClientID: "web", IssuedAt: 100, Expiry: 400, JTI: "at_1", TokenKind: KindUserAccess, Scope: "orders:read", Extra: forged})
	want := map[string]any{"iss": "https://id.test/realms/main", "sub": "usr_1", "aud": "https://orders.test", "client_id": "web",
		"exp": float64(400), "jti": "at_1", "token_kind": KindUserAccess, "scope": "orders:read"}
	for k, v := range want {
		if at[k] != v {
			t.Errorf("access token %s = %v, want %v", k, at[k], v)
		}
	}
	for _, absent := range []string{"act", "typ", "azp", "org_id", "acr", "auth_time", "cnf", "nonce", "grant_id"} {
		if _, ok := at[absent]; ok {
			t.Errorf("a tenant claim introduced the reserved %s claim: %v", absent, at[absent])
		}
	}
	if at["department"] != "sales" {
		t.Errorf("non-reserved claim dropped: %v", at)
	}
	linked := decode(AccessClaims{GrantID: "gnt_original", Extra: forged})
	if linked["grant_id"] != "gnt_original" {
		t.Fatal("tenant claims replaced the authoritative grant link")
	}

	id := decode(IDClaims{Issuer: "https://id.test/realms/main", Subject: "usr_1", Audience: jwt.Audience{"web"}, Expiry: 400, IssuedAt: 100,
		AZP: "web", Nonce: "n-1", Claims: forged})
	wantID := map[string]any{"iss": "https://id.test/realms/main", "sub": "usr_1", "aud": "web", "exp": float64(400), "azp": "web", "nonce": "n-1"}
	for k, v := range wantID {
		if id[k] != v {
			t.Errorf("ID token %s = %v, want %v", k, id[k], v)
		}
	}
	for _, absent := range []string{"act", "client_id", "token_kind", "typ", "scope", "grant_id"} {
		if _, ok := id[absent]; ok {
			t.Errorf("a released claim introduced the reserved %s claim in an ID token", absent)
		}
	}
	if id["department"] != "sales" {
		t.Errorf("non-reserved ID-token claim dropped: %v", id)
	}
}
