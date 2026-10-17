package oauth

import (
	"net/url"
	"testing"
)

// TestURLEscape pins the escaping of values appended to logout redirects:
// the characters that would end or alter a query parameter are encoded
// (every "%" too, so an already encoded value stays literal) and
// everything else passes through unchanged.
func TestURLEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain-._~AZaz09", "plain-._~AZaz09"},
		{"%", "%25"},
		{"&", "%26"},
		{"=", "%3D"},
		{"#", "%23"},
		{"+", "%2B"},
		{" ", "%20"},
		{"?", "%3F"},
		{"a&b=c#d", "a%26b%3Dc%23d"},
		{"%26", "%2526"},
		{"100% sure?", "100%25%20sure%3F"},
		{"x+y z", "x%2By%20z"},
		// Not escaped: path and sub-delimiter characters, including ";",
		// which Go's url.ParseQuery refuses as a separator.
		{"/:@!$'()*,;", "/:@!$'()*,;"},
		{"é", "é"},
	}
	for _, tc := range cases {
		got := urlEscape(tc.in)
		if got != tc.want {
			t.Errorf("urlEscape(%q) = %q, want %q", tc.in, got, tc.want)
			continue
		}
		if back, err := url.QueryUnescape(got); err != nil || back != tc.in {
			t.Errorf("url.QueryUnescape(%q) = %q, %v; want %q", got, back, err, tc.in)
		}
	}
}

// TestAppendParam covers the redirect construction used for logout state,
// front-channel logout iss/sid (SES-018) and upstream logout status
// (FED-013).
func TestAppendParam(t *testing.T) {
	cases := []struct {
		name    string
		u, k, v string
		want    string
	}{
		{"first parameter", "https://rp.example/out", "state", "abc", "https://rp.example/out?state=abc"},
		{"after an existing query", "https://rp.example/out?x=1", "state", "abc", "https://rp.example/out?x=1&state=abc"},
		{"after a bare question mark", "https://rp.example/out?", "state", "abc", "https://rp.example/out?&state=abc"},
		{"reserved characters in the value", "https://rp.example/out", "state", "a&b=c#d?e+f g%", "https://rp.example/out?state=a%26b%3Dc%23d%3Fe%2Bf%20g%25"},
		{"empty value", "https://rp.example/out", "state", "", "https://rp.example/out?state="},
		{"upstream status", "https://rp.example/out?state=s", "upstream_logout", "unsupported", "https://rp.example/out?state=s&upstream_logout=unsupported"},
		{"issuer value", "https://rp.example/fc", "iss", "https://idp.example/realms/acme", "https://rp.example/fc?iss=https://idp.example/realms/acme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appendParam(tc.u, tc.k, tc.v)
			if got != tc.want {
				t.Fatalf("appendParam = %q, want %q", got, tc.want)
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			if q, err := url.ParseQuery(u.RawQuery); err != nil || q.Get(tc.k) != tc.v || len(q[tc.k]) != 1 {
				t.Fatalf("parsed %s = %q (%v), want exactly %q", tc.k, q[tc.k], err, tc.v)
			}
		})
	}
	// Front-channel logout appends iss, then sid (frontChannelURIs).
	got := appendParam(appendParam("https://rp.example/fc", "iss", "https://idp.example/realms/acme"), "sid", "ses_1")
	if want := "https://rp.example/fc?iss=https://idp.example/realms/acme&sid=ses_1"; got != want {
		t.Fatalf("front-channel URI %q, want %q", got, want)
	}
}
