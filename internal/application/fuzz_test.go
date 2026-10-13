package application

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// FuzzMatchRedirect checks the exact-match property of redirect validation
// (APP-004, TEST-028): a requested redirect is only accepted when it is byte-equal
// to a registration, or (native clients only) a loopback redirect differing only in
// port.
func FuzzMatchRedirect(f *testing.F) {
	seeds := [][3]string{
		{"https://app.example/cb", "https://app.example/cb", "confidential"},
		{"https://app.example/cb", "https://app.example/cb/../evil", "confidential"},
		{"https://app.example/cb", "https://APP.example/cb", "public"},
		{"http://127.0.0.1/callback", "http://127.0.0.1:53111/callback", "native"},
		{"http://127.0.0.1/callback", "http://127.0.0.1:53111/callback?x=1", "native"},
		{"http://[::1]/cb", "http://[::1]:1/cb", "native"},
		{"com.example.app:/cb", "com.example.app:/cb#x", "native"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, registered, requested, clientType string) {
		if !MatchRedirect([]string{registered}, requested, clientType) {
			return
		}
		if requested == registered {
			return
		}
		if clientType != "native" && clientType != "device" {
			t.Fatalf("non-native client matched non-identical redirect %q vs %q", requested, registered)
		}
		ru, err1 := url.Parse(requested)
		gu, err2 := url.Parse(registered)
		if err1 != nil || err2 != nil {
			t.Fatalf("unparseable redirect matched: %q vs %q", requested, registered)
		}
		if ru.Scheme != "http" || ru.Hostname() != gu.Hostname() || ru.EscapedPath() != gu.EscapedPath() || ru.RawQuery != gu.RawQuery {
			t.Fatalf("loopback exception widened: %q vs %q", requested, registered)
		}
		if ru.User != nil || ru.Fragment != "" {
			t.Fatalf("userinfo or fragment accepted: %q", requested)
		}
		if h := ru.Hostname(); h != "127.0.0.1" && h != "::1" && !strings.HasPrefix(h, "127.") && !strings.HasPrefix(h, "::ffff:127.") {
			t.Fatalf("non-loopback host accepted via loopback rule: %q", requested)
		}
	})
}

// FuzzValidateRedirectRegistration checks that accepted registrations never carry
// fragments, userinfo, wildcards, whitespace or encoded separators.
func FuzzValidateRedirectRegistration(f *testing.F) {
	for _, s := range []string{"https://app.example/cb", "https://*.example/cb", "http://localhost:3000/cb",
		"https://a.example/%2e%2e/x", "https://u:p@a.example/", "com.example:/cb", "javascript:alert(1)"} {
		f.Add(s, "confidential", "production")
		f.Add(s, "native", "development")
	}
	f.Fuzz(func(t *testing.T, raw, clientType, env string) {
		if ValidateRedirectRegistration(raw, clientType, env) != "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			t.Fatalf("accepted non-absolute redirect %q", raw)
		}
		if strings.ContainsAny(raw, "#*\\ \t\r\n") || u.User != nil {
			t.Fatalf("accepted unsafe redirect %q", raw)
		}
		low := strings.ToLower(raw)
		if strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") {
			t.Fatalf("accepted encoded separator %q", raw)
		}
		switch u.Scheme {
		case "https":
		case "http":
			if env == "production" && clientType != "native" && clientType != "device" {
				t.Fatalf("accepted plain http in production: %q", raw)
			}
		default:
			if clientType != "native" || !strings.Contains(u.Scheme, ".") {
				t.Fatalf("accepted scheme %q for %s", u.Scheme, clientType)
			}
		}
	})
}

// FuzzClaimMappings (QA-003, APP-011): any claim map that passes validation
// resolves without panicking and never emits a value for a profile attribute
// that is not claimable.
func FuzzClaimMappings(f *testing.F) {
	f.Add([]byte(`{"dept":{"$attr":"profile.department","transform":"upper"},"x":"static"}`), "department", "sales")
	f.Add([]byte(`{"a":{"$attr":"user.locale","default":"en"}}`), "secret", "x")
	f.Fuzz(func(t *testing.T, raw []byte, attr, value string) {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil || validateClaimMap("id_token_claims", m) != nil {
			return
		}
		out := ResolveClaims(m, ClaimSource{Profile: map[string]any{attr: value}, Claimable: map[string]bool{}})
		for k, v := range m {
			spec, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if p, _ := spec["$attr"].(string); p == "profile."+attr {
				if got, ok := out[k]; ok && got != spec["default"] {
					t.Fatalf("non-claimable attribute released: %v", got)
				}
			}
		}
	})
}
