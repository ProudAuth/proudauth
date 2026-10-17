package oauth

import (
	"context"
	"testing"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestResponseModes pins the response modes the authorization endpoint
// accepts (ADV-002): the default, query, and the JWT modes jwt and
// query.jwt. Fragment and form_post modes, their JWT variants and any other
// spelling are refused; names are compared exactly.
func TestResponseModes(t *testing.T) {
	cases := []struct {
		mode        string
		valid, jarm bool
	}{
		{"", true, false},
		{"query", true, false},
		{"jwt", true, true},
		{"query.jwt", true, true},
		{"fragment", false, false},
		{"form_post", false, false},
		{"fragment.jwt", false, false},
		{"form_post.jwt", false, false},
		{"web_message", false, false},
		{"none", false, false},
		{"QUERY", false, false},
		{"Query", false, false},
		{"JWT", false, false},
		{"query.JWT", false, false},
		{" query", false, false},
		{"query ", false, false},
		{"jwt ", false, false},
		{"query.jwt\x00", false, false},
		{"jwt.query", false, false},
		{"query jwt", false, false},
		{"query,jwt", false, false},
		{".jwt", false, false},
	}
	for _, tc := range cases {
		if got := ValidResponseMode(tc.mode); got != tc.valid {
			t.Errorf("ValidResponseMode(%q) = %v, want %v", tc.mode, got, tc.valid)
		}
		if got := IsJARM(tc.mode); got != tc.jarm {
			t.Errorf("IsJARM(%q) = %v, want %v", tc.mode, got, tc.jarm)
		}
	}
}

// TestPlainAuthorizationResponse covers the redirect built for a query-mode
// response, and for a JWT mode when no client is known (respond falls back
// to it when the client cannot be resolved): parameters are added to the
// redirect's query, empty ones are left out, and an unparsable redirect
// yields "".
func TestPlainAuthorizationResponse(t *testing.T) {
	s := &Service{}
	rlm := &realm.Realm{ID: "rlm_1", Issuer: "https://idp.example/realms/acme"}
	client := &application.Client{ClientID: "app"}
	params := map[string]string{"code": "pa_ac_1", "state": "s 1&x=y", "iss": rlm.Issuer, "error_description": ""}
	const want = "https://app.example/cb?code=pa_ac_1&iss=https%3A%2F%2Fidp.example%2Frealms%2Facme&state=s+1%26x%3Dy"
	cases := []struct {
		name     string
		client   *application.Client
		mode     string
		redirect string
		params   map[string]string
		want     string
	}{
		{"default mode", client, "", "https://app.example/cb", params, want},
		{"query mode", client, "query", "https://app.example/cb", params, want},
		{"jwt mode without a client", nil, "jwt", "https://app.example/cb", params, want},
		{"query.jwt mode without a client", nil, "query.jwt", "https://app.example/cb", params, want},
		{"registered query is kept", client, "query", "https://app.example/cb?tenant=a", map[string]string{"code": "c", "state": "s"},
			"https://app.example/cb?code=c&state=s&tenant=a"},
		{"response parameter replaces a registered one", client, "query", "https://app.example/cb?state=old", map[string]string{"state": "new"},
			"https://app.example/cb?state=new"},
		{"error response", client, "", "https://app.example/cb", map[string]string{"error": "access_denied", "error_description": "denied by user",
			"state": "", "iss": rlm.Issuer}, "https://app.example/cb?error=access_denied&error_description=denied+by+user&iss=https%3A%2F%2Fidp.example%2Frealms%2Facme"},
		{"unparsable redirect", client, "query", "https://app.example/%zz", map[string]string{"code": "c"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.AuthorizationResponse(context.Background(), rlm, tc.client, tc.mode, tc.redirect, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("redirect %q, want %q", got, tc.want)
			}
		})
	}
}
