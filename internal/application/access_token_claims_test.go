package application

import (
	"net/http"
	"testing"
)

// TestAccessTokenClaimsRefuseStandardClaims covers QA-008, OIDC-007 and
// APP-011: a client's access_token_claims cannot put a static value, contact
// data (email*, phone_number*, address) or a mapped attribute under an OIDC
// standard user claim name, which resource servers may read as verified user
// data; registration refuses such a map with 422 on access_token_claims.
// Other claim names keep static values and attribute mappings.
func TestAccessTokenClaimsRefuseStandardClaims(t *testing.T) {
	withClaims := func(at map[string]any) ClientInput {
		return clientOf(TypeConfidential, func(in *ClientInput) { in.AccessTokenClaims = at })
	}
	refused := map[string]map[string]any{
		"static email":                    {"email": "ceo@example.test"},
		"static email_verified":           {"email_verified": true},
		"static phone_number":             {"phone_number": "+15550100"},
		"static phone_number_verified":    {"phone_number_verified": true},
		"static address":                  {"address": "1 Main St"},
		"static name":                     {"name": "Chief Executive"},
		"static locale":                   {"locale": "en"},
		"mapped email":                    {"email": map[string]any{"$attr": "user.display_name"}},
		"mapped phone_number":             {"phone_number": map[string]any{"$attr": "profile.mobile"}},
		"mapped address":                  {"address": map[string]any{"$attr": "profile.office"}},
		"mapped locale":                   {"locale": map[string]any{"$attr": "user.locale"}},
		"mapped name":                     {"name": map[string]any{"$attr": "user.display_name"}},
		"standard among accepted claims":  {"tier": "gold", "email": "ceo@example.test"},
		"mapped standard with a fallback": {"zoneinfo": map[string]any{"$attr": "user.zoneinfo", "default": "UTC"}},
	}
	for name, at := range refused {
		in := withClaims(at)
		err := in.Normalize()
		if err == nil {
			t.Errorf("%s: accepted %v", name, at)
			continue
		}
		if _, ok := err.Fields["access_token_claims"]; !ok || err.Status != http.StatusUnprocessableEntity {
			t.Errorf("%s: refused with %d on %v, want 422 on access_token_claims", name, err.Status, err.Fields)
		}
	}
	accepted := withClaims(map[string]any{"tier": "gold", "lang": map[string]any{"$attr": "user.locale"},
		"dept": map[string]any{"$attr": "profile.department", "transform": "upper"}})
	if err := accepted.Normalize(); err != nil {
		t.Fatalf("non-standard claim names refused: %v", err)
	}
}
