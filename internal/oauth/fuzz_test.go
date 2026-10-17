package oauth

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseAuthorize checks the authorization request parser on raw query
// strings, the first code that sees an untrusted authorization request
// (SEC-004). Only the pure parsing layer is fuzzed: the client, redirect
// URI, response type and mode and PKCE are validated afterwards in
// validateInteractive against the registered client, which needs the
// database. The parser does not refuse an empty client_id or a response
// type other than code; the target asserts instead that it hands both,
// like every other parameter, to those checks byte for byte. It asserts
// that the parser
//   - never panics;
//   - refuses exactly the requests that repeat a parameter other than
//     resource or exceed a bound, always with invalid_request;
//   - returns every parameter of an accepted request verbatim;
//   - returns a request that survives re-encoding as a query string and
//     re-parsing, and (for valid UTF-8, see below) the JSON form that PAR
//     stores and consumePAR reads back.
func FuzzParseAuthorize(f *testing.F) {
	const valid = "client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=openid+profile" +
		"&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256" +
		"&resource=https%3A%2F%2Fapi.example"
	for _, seed := range []string{
		valid,
		"client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=openid&state=xyz",
		valid + "&client_id=evil",
		strings.Replace(valid, "https%3A%2F%2Fapp.example%2Fcb", "javascript:alert(1)//%0a", 1),
		"client_id=app&redirect_uri=https://app.example/cb;evil&state=%zz&response_type=code",
		valid + strings.Repeat("&resource=https%3A%2F%2Fapi.example", 5),
		// Every bound at its limit, then each one past it.
		"client_id=app&response_type=code&state=" + strings.Repeat("s", 1024) + "&nonce=" + strings.Repeat("n", 512) +
			"&scope=" + strings.Repeat("x", 2048) + "&login_hint=" + strings.Repeat("h", 512) + strings.Repeat("&resource=r", 5),
		"client_id=app&response_type=code&state=" + strings.Repeat("s", 1025),
		"client_id=app&response_type=code&nonce=" + strings.Repeat("n", 513),
		"client_id=app&response_type=code&scope=" + strings.Repeat("x", 2049),
		"client_id=app&response_type=code&login_hint=" + strings.Repeat("h", 513),
		"client_id=&response_type=token&response_mode=fragment&claims=%7B%22id_token%22%3Anull%7D&state=%FF",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// As r.URL.Query() does for the GET endpoint, malformed pairs are
		// dropped and the rest is parsed.
		v, _ := url.ParseQuery(raw)
		req, oe := ParseAuthorize(v)

		repeated := false
		for k, vals := range v {
			if k != "resource" && len(vals) > 1 {
				repeated = true
			}
		}
		tooLong := len(v.Get("state")) > 1024 || len(v.Get("nonce")) > 512 || len(v.Get("scope")) > 2048 ||
			len(v.Get("login_hint")) > 512 || len(v["resource"]) > 5
		switch {
		case repeated:
			if oe == nil || oe.Status != 400 || oe.Code != "invalid_request" {
				t.Fatalf("repeated parameter accepted or refused with %v: %q", oe, raw)
			}
			k, ok := strings.CutSuffix(strings.TrimPrefix(oe.Description, "parameter "), " must not repeat")
			if !ok || k == "resource" || len(v[k]) < 2 {
				t.Fatalf("refusal %q does not name a repeated parameter: %q", oe.Description, raw)
			}
			return
		case tooLong:
			if oe == nil || oe.Status != 400 || oe.Code != "invalid_request" || oe.Description != "parameter too long" {
				t.Fatalf("oversized request accepted or refused with %v: %q", oe, raw)
			}
			return
		case oe != nil:
			t.Fatalf("request refused with %v: %q", oe, raw)
		}

		for k, p := range authorizeParams(&req) {
			if *p != v.Get(k) {
				t.Fatalf("%s = %q, sent %q", k, *p, v.Get(k))
			}
		}
		if !reflect.DeepEqual(req.Resources, v["resource"]) {
			t.Fatalf("resources %q, sent %q", req.Resources, v["resource"])
		}

		q, err := url.ParseQuery(encodeAuthorize(req).Encode())
		if err != nil {
			t.Fatalf("re-encoded request does not parse: %v", err)
		}
		back, oe := ParseAuthorize(q)
		if oe != nil || !reflect.DeepEqual(back, req) {
			t.Fatalf("query round trip = %+v, %v; want %+v", back, oe, req)
		}

		// encoding/json replaces invalid UTF-8 with U+FFFD, so a pushed
		// request with such a value comes back from consumePAR altered;
		// the round trip is asserted for UTF-8 input only.
		if !utf8Request(req) {
			return
		}
		b, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		var stored AuthorizeRequest
		if err := json.Unmarshal(b, &stored); err != nil || !reflect.DeepEqual(stored, req) {
			t.Fatalf("PAR round trip = %+v, %v; want %+v", stored, err, req)
		}
	})
}

// utf8Request reports whether every parameter of r is valid UTF-8.
func utf8Request(r AuthorizeRequest) bool {
	for _, p := range authorizeParams(&r) {
		if !utf8.ValidString(*p) {
			return false
		}
	}
	for _, s := range r.Resources {
		if !utf8.ValidString(s) {
			return false
		}
	}
	return true
}
