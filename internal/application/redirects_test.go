package application

import "testing"

func TestRedirectRegistration(t *testing.T) {
	bad := []string{
		"https://*.example.com/cb", "https://example.com/cb#frag", "https://user:pw@example.com/cb",
		"/relative", "http://example.com/cb", "javascript:alert(1)", "https://example.com/a/../b",
		"https://example.com/a%2Fb", "https://localhost/cb",
	}
	for _, b := range bad {
		if ValidateRedirectRegistration(b, "confidential", "production") == "" {
			t.Errorf("must reject %q", b)
		}
	}
	good := map[string]string{
		"https://app.example.com/callback": "confidential",
		"http://127.0.0.1/callback":        "native",
		"com.example.app:/oauth2redirect":  "native",
	}
	for g, typ := range good {
		if msg := ValidateRedirectRegistration(g, typ, "production"); msg != "" {
			t.Errorf("must accept %q: %s", g, msg)
		}
	}
}

func TestExactRedirectMatching(t *testing.T) {
	reg := []string{"https://app.example.com/callback"}
	attacks := []string{
		"https://app.example.com/callback/", "https://app.example.com/callback?x=1",
		"https://app.example.com.evil.com/callback", "https://APP.example.com/callback",
		"https://app.example.com/Callback", "https://app.example.com/callback#", "https://evil@app.example.com/callback",
		"https://app.example.com/callback%2F..%2Fevil", "https://app.example.com:443/callback",
	}
	for _, a := range attacks {
		if MatchRedirect(reg, a, "confidential") {
			t.Errorf("must not match %q (TEST-029)", a)
		}
	}
	if !MatchRedirect(reg, "https://app.example.com/callback", "confidential") {
		t.Fatal("exact match")
	}
	loop := []string{"http://127.0.0.1/callback"}
	if !MatchRedirect(loop, "http://127.0.0.1:51234/callback", "native") {
		t.Fatal("native loopback port variation allowed (RFC 8252)")
	}
	if MatchRedirect(loop, "http://127.0.0.1:51234/other", "native") {
		t.Fatal("path must still match")
	}
	if MatchRedirect(loop, "http://127.0.0.1:51234/callback", "confidential") {
		t.Fatal("loopback exception is only for native clients")
	}
	if MatchRedirect(loop, "http://localhost:51234/callback", "native") {
		t.Fatal("localhost name is not the registered loopback IP")
	}
}
