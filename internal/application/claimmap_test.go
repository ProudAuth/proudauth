package application

import "testing"

func TestClaimMappings(t *testing.T) {
	bad := []map[string]any{
		{"x": map[string]any{"$attr": "user.email"}},
		{"x": map[string]any{"$attr": "profile.a.b"}},
		{"x": map[string]any{"$attr": "profile.a", "transform": "reverse"}},
		{"x": map[string]any{"$attr": "profile.a", "eval": "1+1"}},
		{"x": map[string]any{"value": 1}},
	}
	for _, m := range bad {
		if err := validateClaimMap("id_token_claims", m); err == nil {
			t.Errorf("accepted %v", m)
		}
	}
	m := map[string]any{"tier": "gold", "dept": map[string]any{"$attr": "profile.department", "transform": "upper"},
		"team": map[string]any{"$attr": "profile.team", "default": "none"}, "lang": map[string]any{"$attr": "user.locale"},
		"missing": map[string]any{"$attr": "user.zoneinfo"}}
	if err := validateClaimMap("id_token_claims", m); err != nil {
		t.Fatal(err)
	}
	out := ResolveClaims(m, ClaimSource{User: map[string]string{"locale": "es"}, Profile: map[string]any{"department": "sales", "team": "blue"},
		Claimable: map[string]bool{"department": true}})
	if out["tier"] != "gold" || out["dept"] != "SALES" || out["team"] != "none" || out["lang"] != "es" {
		t.Fatalf("resolved: %v", out)
	}
	if _, ok := out["missing"]; ok {
		t.Fatal("absent attribute without default was emitted")
	}
}
