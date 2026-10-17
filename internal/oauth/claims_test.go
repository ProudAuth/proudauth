package oauth

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	acrMFA      = "urn:proudauth:acr:mfa"
	acrPhishing = "urn:proudauth:acr:phishing_resistant"
)

// TestParseClaimsParameter covers the OIDC claims parameter profile
// (OIDC-008, OIDC-009): members are userinfo and id_token, claim names are
// the standard ones, each request is null or {essential, value, values},
// and only acr requests have an effect: their supported values join the
// assurance requirement, an unsupported essential one fails.
func TestParseClaimsParameter(t *testing.T) {
	pad := func(doc string, n int) string { return doc + strings.Repeat(" ", n-len(doc)) }
	const small = `{"id_token":{"sub":null}}`
	type want struct {
		acr    []string
		status int
		code   string
		desc   string
	}
	invalid := func(desc string) want { return want{status: 400, code: "invalid_request", desc: desc} }
	cases := []struct {
		name string
		raw  string
		want want
	}{
		{"absent", "", want{}},
		{"empty object", `{}`, want{}},
		{"null document", `null`, want{}},
		{"null member", `{"id_token":null}`, want{}},
		{"null claim requests", `{"userinfo":{"email":null,"name":null},"id_token":{"auth_time":null}}`, want{}},
		{"essential non-acr claim", `{"id_token":{"email":{"essential":true}}}`, want{}},
		{"value and values for a non-acr claim", `{"id_token":{"sub":{"value":"usr_1","values":["usr_1"]}}}`, want{}},
		{"4096 bytes", pad(small, 4096), want{}},
		{"4097 bytes", pad(small, 4097), invalid("claims parameter too large")},
		{"not JSON", `claims`, invalid("claims must be a JSON object")},
		{"array", `[]`, invalid("claims must be a JSON object")},
		{"string", `"id_token"`, invalid("claims must be a JSON object")},
		{"truncated", `{"id_token":`, invalid("claims must be a JSON object")},
		// Only the first JSON value is decoded; requestedClaims, which
		// narrows release, refuses the same input (see TestRequestedClaims).
		{"trailing data after the object", `{"id_token":{"email":null}} trailing`, want{}},
		{"unknown member", `{"access_token":{}}`, invalid("claims members are userinfo and id_token")},
		{"member names are exact", `{"ID_Token":{}}`, invalid("claims members are userinfo and id_token")},
		{"member is an array", `{"id_token":[]}`, invalid("claims.id_token must be an object")},
		{"member is a string", `{"userinfo":"email"}`, invalid("claims.userinfo must be an object")},
		{"unsupported claim", `{"id_token":{"org_id":null}}`, invalid("unsupported claim org_id")},
		{"claim names are exact", `{"userinfo":{"Email":null}}`, invalid("unsupported claim Email")},
		{"unknown request field", `{"id_token":{"email":{"essential":true,"purpose":"x"}}}`, invalid("invalid request for claim email")},
		{"request is a string", `{"id_token":{"email":"yes"}}`, invalid("invalid request for claim email")},
		{"values is not a list", `{"id_token":{"acr":{"values":"` + acrMFA + `"}}}`, invalid("invalid request for claim acr")},
		{"essential is not a boolean", `{"id_token":{"acr":{"essential":"true"}}}`, invalid("invalid request for claim acr")},
		{"acr value", `{"id_token":{"acr":{"value":"` + acrMFA + `"}}}`, want{acr: []string{acrMFA}}},
		{"acr values in order", `{"id_token":{"acr":{"values":["` + acrPhishing + `","` + acrMFA + `"]}}}`, want{acr: []string{acrPhishing, acrMFA}}},
		{"acr values then value, deduplicated", `{"id_token":{"acr":{"values":["` + acrMFA + `","` + acrPhishing + `"],"value":"` + acrMFA + `"}}}`,
			want{acr: []string{acrMFA, acrPhishing}}},
		{"same acr in both members", `{"userinfo":{"acr":{"value":"` + acrMFA + `"}},"id_token":{"acr":{"value":"` + acrMFA + `"}}}`,
			want{acr: []string{acrMFA}}},
		{"unsupported voluntary acr is skipped", `{"id_token":{"acr":{"values":["urn:example:loa:3","` + acrMFA + `"]}}}`, want{acr: []string{acrMFA}}},
		{"unsupported essential acr", `{"id_token":{"acr":{"essential":true,"values":["` + acrMFA + `","urn:example:loa:3"]}}}`,
			want{status: 400, code: "unmet_authentication_requirements", desc: "essential acr urn:example:loa:3 is not supported"}},
		{"essential acr without values", `{"id_token":{"acr":{"essential":true}}}`, want{}},
		{"non-string acr value is ignored", `{"id_token":{"acr":{"value":3}}}`, want{}},
		{"null acr request", `{"id_token":{"acr":null}}`, want{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acr, oe := parseClaimsParameter(tc.raw)
			if tc.want.code != "" {
				checkError(t, oe, tc.want.status, tc.want.code, tc.want.desc)
				if acr != nil {
					t.Fatalf("acr %q returned with an error", acr)
				}
				return
			}
			if oe != nil {
				t.Fatalf("unexpected error %v", oe)
			}
			if !slices.Equal(acr, tc.want.acr) {
				t.Fatalf("acr %q, want %q", acr, tc.want.acr)
			}
		})
	}
}

// TestParseClaimsParameterAcrAcrossMembers checks that acr values requested
// in both members are all collected (member order is not significant).
func TestParseClaimsParameterAcrAcrossMembers(t *testing.T) {
	acr, oe := parseClaimsParameter(`{"userinfo":{"acr":{"value":"` + acrPhishing + `"}},"id_token":{"acr":{"value":"` + acrMFA + `"}}}`)
	if oe != nil {
		t.Fatal(oe)
	}
	slices.Sort(acr)
	if want := []string{acrMFA, acrPhishing}; !slices.Equal(acr, want) {
		t.Fatalf("acr %q, want %q", acr, want)
	}
}

func TestRequestedClaims(t *testing.T) {
	const both = `{"userinfo":{"email":null},"id_token":{"name":null,"acr":{"essential":true}}}`
	cases := []struct {
		name, raw, member string
		want              map[string]bool
		present           bool
	}{
		{"absent", "", "id_token", nil, false},
		{"id_token member", both, "id_token", map[string]bool{"name": true, "acr": true}, true},
		{"userinfo member", both, "userinfo", map[string]bool{"email": true}, true},
		{"member not requested", `{"userinfo":{"email":null}}`, "id_token", nil, false},
		{"empty member", `{"id_token":{}}`, "id_token", map[string]bool{}, true},
		{"null member asks for nothing", `{"id_token":null}`, "id_token", map[string]bool{}, true},
		{"not JSON", `claims`, "id_token", nil, false},
		// parseClaimsParameter accepts this input (TestParseClaimsParameter).
		{"trailing data after the object", `{"id_token":{"email":null}} trailing`, "id_token", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, present := requestedClaims(tc.raw, tc.member)
			if present != tc.present || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("requestedClaims = %v, %v; want %v, %v", got, present, tc.want, tc.present)
			}
		})
	}
}

// TestReleaseFor checks that a claims request only narrows the
// scope-authorized claims (OIDC-008): it never adds a claim, and asking for
// email or phone_number keeps the matching verification flag.
func TestReleaseFor(t *testing.T) {
	claims := map[string]any{"name": "Jo Doe", "locale": "ar-JO", "email": "jo@example.com", "email_verified": true,
		"phone_number": "+962700000002", "phone_number_verified": false}
	cases := []struct {
		name, raw, member string
		want              map[string]any
	}{
		{"no claims request", "", "id_token", claims},
		{"member not requested", `{"userinfo":{"name":null}}`, "id_token", claims},
		{"unparsable request", `{"id_token":`, "id_token", claims},
		{"one claim", `{"id_token":{"name":null}}`, "id_token", map[string]any{"name": "Jo Doe"}},
		{"email keeps email_verified", `{"userinfo":{"email":null}}`, "userinfo", map[string]any{"email": "jo@example.com", "email_verified": true}},
		{"phone_number keeps its flag", `{"userinfo":{"phone_number":{"essential":true}}}`, "userinfo",
			map[string]any{"phone_number": "+962700000002", "phone_number_verified": false}},
		{"flag alone", `{"id_token":{"email_verified":null}}`, "id_token", map[string]any{"email_verified": true}},
		{"claim the scopes do not authorize", `{"id_token":{"picture":null,"birthdate":null}}`, "id_token", map[string]any{}},
		{"empty member releases nothing", `{"id_token":{}}`, "id_token", map[string]any{}},
		{"null member releases nothing", `{"id_token":null}`, "id_token", map[string]any{}},
		{"trailing data disables narrowing", `{"id_token":{"name":null}} trailing`, "id_token", claims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := releaseFor(claims, tc.raw, tc.member); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("releaseFor = %v, want %v", got, tc.want)
			}
		})
	}
}
