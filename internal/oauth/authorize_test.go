package oauth

import (
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// authorizeParams maps each single-valued authorization parameter to its
// field. "resource" is the only parameter that may repeat (RFC 8707) and
// maps to Resources.
func authorizeParams(r *AuthorizeRequest) map[string]*string {
	return map[string]*string{
		"client_id": &r.ClientID, "redirect_uri": &r.RedirectURI, "response_type": &r.ResponseType, "response_mode": &r.ResponseMode,
		"scope": &r.Scope, "state": &r.State, "nonce": &r.Nonce, "code_challenge": &r.CodeChallenge,
		"code_challenge_method": &r.CodeChallengeMethod, "prompt": &r.Prompt, "max_age": &r.MaxAge, "acr_values": &r.ACRValues,
		"login_hint": &r.LoginHint, "ui_locales": &r.UILocales, "organization": &r.Organization, "request_uri": &r.RequestURI,
		"request": &r.Request, "intent": &r.Intent, "claims": &r.Claims,
	}
}

// encodeAuthorize is the inverse of ParseAuthorize for an accepted request.
func encodeAuthorize(r AuthorizeRequest) url.Values {
	v := url.Values{}
	for k, p := range authorizeParams(&r) {
		if *p != "" {
			v.Set(k, *p)
		}
	}
	if r.Resources != nil {
		v["resource"] = slices.Clone(r.Resources)
	}
	return v
}

// TestAuthorizeParamsCoverRequest keeps authorizeParams (and with it the
// fuzz round trip) in step with AuthorizeRequest: every string field has a
// parameter, and Resources is the only other field.
func TestAuthorizeParamsCoverRequest(t *testing.T) {
	var r AuthorizeRequest
	mapped := map[uintptr]bool{}
	for _, p := range authorizeParams(&r) {
		mapped[reflect.ValueOf(p).Pointer()] = true
	}
	rv := reflect.ValueOf(&r).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Type().Field(i)
		switch {
		case f.Name == "Resources":
		case f.Type.Kind() == reflect.String && mapped[rv.Field(i).Addr().Pointer()]:
		default:
			t.Errorf("AuthorizeRequest.%s has no authorization parameter in authorizeParams", f.Name)
		}
	}
	if len(mapped) != rv.NumField()-1 {
		t.Errorf("authorizeParams maps %d fields, AuthorizeRequest has %d besides Resources", len(mapped), rv.NumField()-1)
	}
}

// TestParseAuthorize covers parameter extraction at the authorization and
// PAR endpoints: every parameter is taken verbatim, a parameter other than
// resource must not repeat (SEC-004), and state, nonce, scope, login_hint
// and the number of resources are bounded. Everything else (client,
// redirect, response type and mode, PKCE) is validated later, against the
// registered client, in validateInteractive.
func TestParseAuthorize(t *testing.T) {
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	full := url.Values{
		"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "response_mode": {"query.jwt"},
		"scope": {"openid profile orders:read"}, "state": {"af0ifjsldkj"}, "nonce": {"n-0S6_WzA2Mj"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "prompt": {"login consent"}, "max_age": {"300"}, "acr_values": {"urn:proudauth:acr:mfa"},
		"login_hint": {"jo@example.com"}, "ui_locales": {"ar en"}, "organization": {"acme"},
		"resource": {"https://orders.example", "https://billing.example"}, "request_uri": {"urn:ietf:params:oauth:request_uri:x"},
		"request": {"eyJ.e30.sig"}, "intent": {"register"}, "claims": {`{"id_token":{"email":null}}`},
	}
	fullReq := AuthorizeRequest{ClientID: "app", RedirectURI: "https://app.example/cb", ResponseType: "code", ResponseMode: "query.jwt",
		Scope: "openid profile orders:read", State: "af0ifjsldkj", Nonce: "n-0S6_WzA2Mj", CodeChallenge: challenge, CodeChallengeMethod: "S256",
		Prompt: "login consent", MaxAge: "300", ACRValues: "urn:proudauth:acr:mfa", LoginHint: "jo@example.com", UILocales: "ar en",
		Organization: "acme", Resources: []string{"https://orders.example", "https://billing.example"},
		RequestURI: "urn:ietf:params:oauth:request_uri:x", Request: "eyJ.e30.sig", Intent: "register", Claims: `{"id_token":{"email":null}}`}
	with := func(k string, vals ...string) url.Values {
		v := url.Values{"client_id": {"app"}, "response_type": {"code"}}
		v[k] = vals
		return v
	}
	base := func(r AuthorizeRequest) AuthorizeRequest { r.ClientID, r.ResponseType = "app", "code"; return r }
	resources := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("https://api%d.example", i)
		}
		return out
	}
	tooLong := "parameter too long"
	cases := []struct {
		name    string
		in      url.Values
		want    AuthorizeRequest
		wantErr string
	}{
		{"every parameter", full, fullReq, ""},
		{"no parameters", url.Values{}, AuthorizeRequest{}, ""},
		{"nil values", nil, AuthorizeRequest{}, ""},
		{"without PKCE", url.Values{"client_id": {"app"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb"}},
			AuthorizeRequest{ClientID: "app", ResponseType: "code", RedirectURI: "https://app.example/cb"}, ""},
		// The parser does not judge values; validateInteractive does.
		{"unregistered redirect", with("redirect_uri", "javascript:alert(1)"), base(AuthorizeRequest{RedirectURI: "javascript:alert(1)"}), ""},
		{"implicit response type", with("response_type", "token"), AuthorizeRequest{ClientID: "app", ResponseType: "token"}, ""},
		{"unsupported response mode", with("response_mode", "fragment"), base(AuthorizeRequest{ResponseMode: "fragment"}), ""},
		{"plain PKCE", with("code_challenge_method", "plain"), base(AuthorizeRequest{CodeChallengeMethod: "plain"}), ""},
		{"values are not trimmed", with("state", " s "), base(AuthorizeRequest{State: " s "}), ""},
		{"invalid UTF-8 is kept", with("state", "\xff\xfe"), base(AuthorizeRequest{State: "\xff\xfe"}), ""},
		{"unknown parameters are ignored", with("display", "popup"), base(AuthorizeRequest{}), ""},
		{"parameter names are exact", with("Client_ID", "evil"), base(AuthorizeRequest{}), ""},
		{"empty single value", with("state", ""), base(AuthorizeRequest{}), ""},
		{"empty resource", with("resource", ""), base(AuthorizeRequest{Resources: []string{""}}), ""},
		{"repeated resource keeps order", with("resource", "https://b.example", "https://a.example", "https://b.example"),
			base(AuthorizeRequest{Resources: []string{"https://b.example", "https://a.example", "https://b.example"}}), ""},
		{"five resources", with("resource", resources(5)...), base(AuthorizeRequest{Resources: resources(5)}), ""},
		{"six resources", with("resource", resources(6)...), AuthorizeRequest{}, tooLong},
		{"state of 1024 bytes", with("state", strings.Repeat("s", 1024)), base(AuthorizeRequest{State: strings.Repeat("s", 1024)}), ""},
		{"state of 1025 bytes", with("state", strings.Repeat("s", 1025)), AuthorizeRequest{}, tooLong},
		{"state length counts bytes", with("state", strings.Repeat("é", 513)), AuthorizeRequest{}, tooLong},
		{"state of 512 two-byte characters", with("state", strings.Repeat("é", 512)), base(AuthorizeRequest{State: strings.Repeat("é", 512)}), ""},
		{"nonce of 512 bytes", with("nonce", strings.Repeat("n", 512)), base(AuthorizeRequest{Nonce: strings.Repeat("n", 512)}), ""},
		{"nonce of 513 bytes", with("nonce", strings.Repeat("n", 513)), AuthorizeRequest{}, tooLong},
		{"scope of 2048 bytes", with("scope", strings.Repeat("x", 2048)), base(AuthorizeRequest{Scope: strings.Repeat("x", 2048)}), ""},
		{"scope of 2049 bytes", with("scope", strings.Repeat("x", 2049)), AuthorizeRequest{}, tooLong},
		{"login_hint of 512 bytes", with("login_hint", strings.Repeat("h", 512)), base(AuthorizeRequest{LoginHint: strings.Repeat("h", 512)}), ""},
		{"login_hint of 513 bytes", with("login_hint", strings.Repeat("h", 513)), AuthorizeRequest{}, tooLong},
		{"repeated identical values", with("state", "a", "a"), AuthorizeRequest{}, "parameter state must not repeat"},
		{"repeated empty values", with("state", "", ""), AuthorizeRequest{}, "parameter state must not repeat"},
		{"repeated unknown parameter", with("display", "page", "popup"), AuthorizeRequest{}, "parameter display must not repeat"},
		{"repetition is checked before length", func() url.Values {
			v := with("state", "a", "b")
			v.Set("nonce", strings.Repeat("n", 513))
			return v
		}(), AuthorizeRequest{}, "parameter state must not repeat"},
	}
	for name := range authorizeParams(&AuthorizeRequest{}) {
		v := url.Values{name: {"a", "b"}}
		if name != "client_id" {
			v.Set("client_id", "app")
		}
		cases = append(cases, struct {
			name    string
			in      url.Values
			want    AuthorizeRequest
			wantErr string
		}{"repeated " + name, v, AuthorizeRequest{}, "parameter " + name + " must not repeat"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, oe := ParseAuthorize(tc.in)
			if tc.wantErr != "" {
				checkError(t, oe, 400, "invalid_request", tc.wantErr)
				if strings.HasSuffix(tc.wantErr, "must not repeat") && !reflect.DeepEqual(got, AuthorizeRequest{}) {
					t.Fatalf("a refused repetition returned %+v", got)
				}
				return
			}
			if oe != nil {
				t.Fatalf("unexpected error %v", oe)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseAuthorize = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestParseAuthorizeQueryRoundTrip checks the encoding helper the fuzz
// target relies on against the full request.
func TestParseAuthorizeQueryRoundTrip(t *testing.T) {
	in := AuthorizeRequest{ClientID: "app&x=y", RedirectURI: "https://app.example/cb?a=1#f", ResponseType: "code", State: "s+t %20",
		Nonce: "\xff", Resources: []string{"", "https://api.example"}, Claims: `{"id_token":{"acr":null}}`}
	q, err := url.ParseQuery(encodeAuthorize(in).Encode())
	if err != nil {
		t.Fatal(err)
	}
	got, oe := ParseAuthorize(q)
	if oe != nil || !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip = %+v, %v; want %+v", got, oe, in)
	}
}

func TestDedupe(t *testing.T) {
	cases := []struct{ in, want []string }{
		{nil, []string{}},
		{[]string{}, []string{}},
		{[]string{"openid"}, []string{"openid"}},
		{[]string{"openid", "profile", "openid", "email", "profile"}, []string{"openid", "profile", "email"}},
		{[]string{"b", "a", "b", "a"}, []string{"b", "a"}},
		{[]string{"Openid", "openid"}, []string{"Openid", "openid"}},
		{[]string{"", ""}, []string{""}},
	}
	for _, tc := range cases {
		got := dedupe(tc.in)
		if got == nil || !slices.Equal(got, tc.want) {
			t.Errorf("dedupe(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}
