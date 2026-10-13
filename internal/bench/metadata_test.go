package bench

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TestBenchMetadataReceiver verifies the real TLS source, live IPv6 denial
// control, signed assertions, valid-but-oversized body and counts-only export
// independently of ProudAuth's workload verification (NFR-006, NFR-008).
func TestBenchMetadataReceiver(t *testing.T) {
	s, err := NewMetadataReceiver("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("receiver did not stop")
		}
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.Roots()}}, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, base := range []string{s.URL(), s.PrivateURL()} {
		r, err := client.Get(base + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 204 {
			t.Fatal(r.StatusCode)
		}
	}
	if _, err := http.Get(s.URL() + "/ready"); err == nil {
		t.Fatal("ephemeral CA trusted without explicit roots")
	}
	var set jose.JSONWebKeySet
	for profile, status := range map[string]int{"valid": 200, "unknown-key": 200, "malformed": 200, "oversized": 200, "http-failure": 503, "redirect": 302} {
		r, err := client.Get(s.URL() + "/jwks/" + profile)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || r.StatusCode != status {
			t.Fatalf("%s status %d: %v", profile, r.StatusCode, err)
		}
		switch profile {
		case "valid":
			if json.Unmarshal(body, &set) != nil || len(set.Keys) != 1 || !set.Keys[0].IsPublic() {
				t.Fatal("invalid public JWKS")
			}
		case "oversized":
			var oversized jose.JSONWebKeySet
			if len(body) != (1<<20)+1 || json.Unmarshal(body, &oversized) != nil || len(oversized.Keys) != 1 {
				t.Fatal("oversized fixture must otherwise be valid JWKS")
			}
		case "malformed":
			if json.Valid(body) {
				t.Fatal("malformed fixture valid")
			}
		case "redirect":
			if r.Header.Get("Location") != s.URL()+"/jwks/redirect-trap" {
				t.Fatal("redirect target missing")
			}
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, profile := range []string{"valid", "unknown-key"} {
		body, _ := json.Marshal(map[string]any{"profile": profile, "audience": "bench-audience", "subject": "bench-subject", "now": now})
		r, err := client.Post(s.URL()+"/issue", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]string
		err = json.NewDecoder(r.Body).Decode(&doc)
		r.Body.Close()
		if err != nil || r.StatusCode != 200 {
			t.Fatal("issue failed", err)
		}
		token, err := jwt.ParseSigned(doc["assertion"], []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		wantKid := "known"
		if profile == "unknown-key" {
			wantKid = "missing"
		}
		if token.Headers[0].KeyID != wantKid {
			t.Fatal("wrong kid")
		}
		var claims jwt.Claims
		if err := token.Claims(set.Keys[0].Key, &claims); err != nil {
			t.Fatal(err)
		}
		if err := claims.Validate(jwt.Expected{Issuer: s.URL() + "/issuer/" + profile, Subject: "bench-subject", AnyAudience: jwt.Audience{"bench-audience"}, Time: now}); err != nil {
			t.Fatal(err)
		}
		if claims.Expiry.Time().Sub(claims.IssuedAt.Time()) != 20*time.Minute {
			t.Fatal("wrong lifetime")
		}
		published, _ := json.Marshal(s.Snapshot())
		if strings.Contains(string(published), doc["assertion"]) {
			t.Fatal("assertion leaked")
		}
	}
	requestCtx, stop := context.WithCancel(ctx)
	request, err := http.NewRequestWithContext(requestCtx, "GET", s.URL()+"/jwks/timeout", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		r, err := client.Do(request)
		if r != nil {
			r.Body.Close()
		}
		requestDone <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for s.Snapshot().Profiles["timeout"].Requests == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop()
	if err := <-requestDone; err == nil {
		t.Fatal("timeout fixture responded before cancellation")
	}
	for s.Snapshot().Inflight != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := s.Snapshot()
	if err := ValidateMetadataStats(stats); err != nil {
		t.Fatal(err)
	}
	contact := stats.Profiles["valid"]
	contact.Starts[0] = time.Time{}
	stats.Profiles["valid"] = contact
	if s.Snapshot().Profiles["valid"].Starts[0].IsZero() {
		t.Fatal("snapshot aliases receiver timestamps")
	}
	published, _ := json.Marshal(s.Snapshot())
	for _, private := range []string{"PRIVATE KEY", `"assertion"`, `"kid"`, "bench-subject", "bench-audience", `"known"`, `"missing"`} {
		if strings.Contains(string(published), private) {
			t.Fatal("private data in counts", private)
		}
	}
	if _, err := NewMetadataReceiver("0.0.0.0:0"); err == nil {
		t.Fatal("non-loopback listener accepted")
	}
}

// TestBenchMetadataOutcome rejects OAuth configuration refusals, accidental
// token issuance and incomplete valid controls; HTTP 400 alone is not proof.
func TestBenchMetadataOutcome(t *testing.T) {
	good := func() *Response {
		return &Response{Status: 200, Body: map[string]any{"access_token": "owned-token", "token_type": "Bearer", "expires_in": float64(300)}}
	}
	bad := func() *Response { return &Response{Status: 400, Body: map[string]any{"error": "invalid_grant"}} }
	for _, profile := range metadataProfiles {
		r := bad()
		if profile == "valid" {
			r = good()
		}
		if out := metadataOutcome(profile, r, nil); out != metadataLabel(profile) {
			t.Fatal(profile, out)
		}
		wrong := good()
		if profile == "valid" {
			wrong = bad()
		}
		if out := metadataOutcome(profile, wrong, nil); !strings.HasPrefix(out, "invariant_") {
			t.Fatal("opposite outcome accepted", profile, out)
		}
	}
	for _, mutate := range []func(*Response){func(r *Response) { r.Status = 401 }, func(r *Response) { r.Body["error"] = "invalid_client" }, func(r *Response) { r.Body["access_token"] = "leak" }, func(r *Response) { r.Body["refresh_token"] = "leak" }, func(r *Response) { r.Body["id_token"] = "leak" }} {
		r := bad()
		mutate(r)
		if metadataOutcome("malformed", r, nil) == metadataLabel("malformed") {
			t.Fatal("invalid refusal accepted")
		}
	}
	for _, mutate := range []func(*Response){func(r *Response) { r.Status = 201 }, func(r *Response) { delete(r.Body, "access_token") }, func(r *Response) { r.Body["token_type"] = "DPoP" }, func(r *Response) { r.Body["refresh_token"] = "leak" }, func(r *Response) { r.Body["expires_in"] = float64(0) }} {
		r := good()
		mutate(r)
		if metadataOutcome("valid", r, nil) == metadataLabel("valid") {
			t.Fatal("invalid control accepted")
		}
	}
	if metadataOutcome("valid", nil, errors.New("transport")) != "transport_error" {
		t.Fatal("transport failure hidden")
	}
}

func TestBenchMetadataFetchCountValidation(t *testing.T) {
	base := func() MetadataStats {
		s := MetadataStats{Profiles: map[string]MetadataContact{}}
		for _, profile := range append(append([]string{}, metadataProfiles...), "redirect-trap") {
			c := MetadataContact{}
			if profile != "private" && profile != "redirect-trap" {
				c.Requests = 2
				c.Starts = []time.Time{time.Unix(1000, 0), time.Unix(1060, 0)}
			}
			s.Profiles[profile] = c
		}
		return s
	}
	if err := ValidateMetadataStats(base()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MetadataStats){
		"cooldown": func(s *MetadataStats) {
			c := s.Profiles["unknown-key"]
			c.Starts[1] = c.Starts[0].Add(59 * time.Second)
			s.Profiles["unknown-key"] = c
		},
		"private":           func(s *MetadataStats) { s.Profiles["private"] = MetadataContact{Requests: 1} },
		"redirect-followed": func(s *MetadataStats) { s.Profiles["redirect-trap"] = MetadataContact{Requests: 1} },
		"missing-profile":   func(s *MetadataStats) { delete(s.Profiles, "malformed") },
		"unobserved":        func(s *MetadataStats) { s.Profiles["timeout"] = MetadataContact{} },
		"missing-times":     func(s *MetadataStats) { c := s.Profiles["oversized"]; c.Starts = nil; s.Profiles["oversized"] = c },
		"inflight":          func(s *MetadataStats) { s.Inflight = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(&s)
			if ValidateMetadataStats(s) == nil {
				t.Fatal("invalid counts accepted")
			}
		})
	}
}
