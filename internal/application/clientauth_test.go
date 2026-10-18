package application

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestAssertionAudience covers APP-009 and MCH-010 with decision 16: a
// private_key_jwt assertion's aud is read from the raw claim, because a JWT
// library turns "aud":"x" and "aud":["x"] into the same list. By default the
// only accepted audience is the issuer as a single JSON string; the realm
// setting client_auth.allow_endpoint_audience re-admits the receiving
// endpoint's URL and arrays of one or two values naming this server, never
// another party.
func TestAssertionAudience(t *testing.T) {
	const iss = "https://id.test/realms/main"
	const endpoint = iss + "/oauth/token"
	cases := []struct {
		aud            string
		strict, legacy bool
	}{
		{`"` + iss + `"`, true, true},
		{` "` + iss + `" `, true, true},
		{`["` + iss + `"]`, false, true},
		{`"` + endpoint + `"`, false, true},
		{`["` + endpoint + `"]`, false, true},
		{`["` + endpoint + `","` + iss + `"]`, false, true},
		{`["` + iss + `","https://other.test"]`, false, false},
		{`["` + iss + `","` + endpoint + `","` + iss + `"]`, false, false},
		{`"https://other.test"`, false, false},
		{`"` + iss + `/"`, false, false},
		{`""`, false, false},
		{`[""]`, false, false},
		{`[]`, false, false},
		{`null`, false, false},
		{``, false, false},
		{`42`, false, false},
		{`{"aud":"` + iss + `"}`, false, false},
		{`[["` + iss + `"]]`, false, false},
	}
	for _, c := range cases {
		raw := json.RawMessage(c.aud)
		if got := assertionAudience(raw, iss, endpoint, false); got != c.strict {
			t.Errorf("aud %s by default: %v, want %v", c.aud, got, c.strict)
		}
		if got := assertionAudience(raw, iss, endpoint, true); got != c.legacy {
			t.Errorf("aud %s with allow_endpoint_audience: %v, want %v", c.aud, got, c.legacy)
		}
	}
}

// TestAuthenticateRefusesOversizedClientID covers SEC-006 (the finding
// httpapi-surface/unauth-audit-amplification): every protocol endpoint that
// authenticates clients (token, PAR, device authorization, introspection,
// revocation, support handoff redemption) refuses a client_id over
// MaxClientIDBytes, in the form or as the Basic user name, before anything
// is looked up. The service here has no database: a lookup would panic.
func TestAuthenticateRefusesOversizedClientID(t *testing.T) {
	var s *Service
	long := strings.Repeat("k", MaxClientIDBytes+1)
	for _, in := range []ClientAuthInput{{FormClientID: long}, {HasBasic: true, BasicID: long, BasicSecret: "pa_cs_x"},
		{FormClientID: long, FormSecret: "pa_cs_x"}, {FormClientID: strings.Repeat("k", 256*1024)}} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("a %d-byte client_id was looked up: %v", max(len(in.FormClientID), len(in.BasicID)), p)
				}
			}()
			if c, err := s.Authenticate(context.Background(), "rlm_1", "https://id.test", "https://id.test/oauth/token", in); err != ErrClientAuth || c != nil {
				t.Fatalf("got %v, %v", c, err)
			}
		}()
	}
}
