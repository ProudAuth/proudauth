package bench

import (
	"context"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRaceTallyOutcome(t *testing.T) {
	cases := []struct {
		name string
		t    raceTally
		want string
	}{
		{"one winner", raceTally{wins: 1, rejected: 7}, "ok"},
		{"one winner, others limited", raceTally{wins: 1, rateLimited: 7}, "ok"},
		{"two winners", raceTally{wins: 2, rejected: 6}, "invariant_violation_2_successes"},
		{"two winners despite limits", raceTally{wins: 2, rateLimited: 6}, "invariant_violation_2_successes"},
		{"all rejected", raceTally{rejected: 8}, "invariant_violation_0_successes"},
		{"rate limited", raceTally{rejected: 3, rateLimited: 5}, "inconclusive_rate_limited"},
		{"all rate limited", raceTally{rateLimited: 8}, "inconclusive_rate_limited"},
		{"server errors", raceTally{rejected: 7, serverErrors: 1}, "inconclusive_http_5xx"},
		{"transport errors", raceTally{rejected: 4, transportErrors: 4}, "inconclusive_transport_error"},
		// One success while other attempts failed on the server (lock waits
		// cancelled by statement_timeout answered 500) is not ok.
		{"one winner, server errors", raceTally{wins: 1, rejected: 3, serverErrors: 4}, "one_success_with_http_5xx"},
		{"one winner, transport errors", raceTally{wins: 1, rejected: 6, transportErrors: 1}, "one_success_with_transport_error"},
		{"two winners and server errors", raceTally{wins: 2, serverErrors: 6}, "invariant_violation_2_successes"},
	}
	for _, c := range cases {
		if got := c.t.outcome(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	var tally raceTally
	tally.add(&Response{Status: 200}, nil)
	tally.add(&Response{Status: 400}, nil)
	tally.add(&Response{Status: 429}, nil)
	tally.add(&Response{Status: 503}, nil)
	tally.add(nil, context.DeadlineExceeded)
	if tally != (raceTally{wins: 1, rejected: 1, rateLimited: 1, serverErrors: 1, transportErrors: 1}) {
		t.Fatalf("tally %+v", tally)
	}
}

// fakeScenario records which workers ran operations.
type fakeScenario struct {
	adversarial bool
	mu          sync.Mutex
	ops         int
	workers     map[int]bool
}

func (s *fakeScenario) Name() string                        { return "fake" }
func (s *fakeScenario) Prepare(context.Context, *Env) error { return nil }
func (s *fakeScenario) Adversarial() bool                   { return s.adversarial }
func (s *fakeScenario) Op(ctx context.Context, _ *Env, worker int, _ *rand.Rand) string {
	s.mu.Lock()
	s.ops++
	if s.workers == nil {
		s.workers = map[int]bool{}
	}
	s.workers[worker] = true
	s.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(time.Millisecond):
	}
	return "ok"
}

func TestWarmup(t *testing.T) {
	var discovery atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/bench/.well-known/openid-configuration" {
			discovery.Add(1)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	env := &Env{Client: NewClient(srv.URL, "bench", 4)}
	opt := Options{Concurrency: 4, Operations: 5, Warmup: 50 * time.Millisecond, Seed: 1}

	// Adversarial scenarios never run their own operations during warm-up.
	adv := &fakeScenario{adversarial: true}
	res, err := Run(context.Background(), env, adv, opt)
	if err != nil {
		t.Fatal(err)
	}
	if adv.ops != 5 || res.Operations != 5 {
		t.Fatalf("adversarial scenario ran %d operations (%d measured), want exactly the 5 measured", adv.ops, res.Operations)
	}
	if discovery.Load() == 0 {
		t.Fatal("adversarial warm-up sent no benign requests")
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "benign") {
		t.Fatalf("notes %q", res.Notes)
	}

	// Ordinary scenarios warm up with their own operations at full concurrency.
	before := discovery.Load()
	ord := &fakeScenario{}
	res, err = Run(context.Background(), env, ord, opt)
	if err != nil {
		t.Fatal(err)
	}
	if ord.ops <= 5 || len(ord.workers) < 2 {
		t.Fatalf("warm-up ran %d operations on %d workers", ord.ops-5, len(ord.workers))
	}
	if discovery.Load() != before || len(res.Notes) != 0 {
		t.Fatalf("ordinary warm-up used benign requests (notes %q)", res.Notes)
	}
}

func TestAdversarialScenariosSkipOwnWarmup(t *testing.T) {
	for _, name := range []string{"unknown-key", "failed-password", "oversized-input", "notification-flood", "refresh-race"} {
		if !isAdversarial(Scenarios()[name]()) {
			t.Errorf("%s warms up with its own operations", name)
		}
	}
	for _, name := range []string{"client-credentials", "introspection", "password-login", "refresh", "policy", "audit-query", "import", "mixed"} {
		if isAdversarial(Scenarios()[name]()) {
			t.Errorf("%s is marked adversarial", name)
		}
	}
}

func TestSeedPrefix(t *testing.T) {
	// The old prefix used seed % 0xfffff, so these collided.
	if seedPrefix(42) == seedPrefix(42+0xfffff) {
		t.Fatal("distinct seeds share a prefix")
	}
	if p := seedPrefix(^uint64(0)); len(p) > 18 || !strings.HasPrefix(p, "b") || !strings.HasSuffix(p, "-") {
		t.Fatalf("prefix %q", p)
	}
	seen := map[string]bool{}
	for s := uint64(0); s < 5000; s++ {
		p := seedPrefix(s * 0xfffff)
		if seen[p] {
			t.Fatalf("collision at seed %d", s*0xfffff)
		}
		seen[p] = true
	}
}

func TestClientRef(t *testing.T) {
	if id, err := clientRef(&Response{Body: map[string]any{"client": map[string]any{"id": "cl_1"}}}); err != nil || id != "cl_1" {
		t.Fatalf("%q %v", id, err)
	}
	for _, body := range []map[string]any{nil, {"client": "cl_1"}, {"client": map[string]any{"id": 7}}} {
		if _, err := clientRef(&Response{Body: body}); err == nil {
			t.Errorf("%v: no error", body)
		}
	}
}

// Exercise the complete seed with the documented laptop cardinalities and
// the server's default body limit: count-only batches of 1000 users were 413.
func TestSeedImportsFitDefaultBodyLimit(t *testing.T) {
	const users = 10000
	seen := map[string]bool{}
	batches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/realms/bench")
		switch {
		case r.Method == "POST" && path == "/user-imports":
			raw, _ := io.ReadAll(io.LimitReader(r.Body, (256<<10)+1))
			if len(raw) > 256<<10 {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			var doc struct {
				Users []struct {
					SourceID string `json:"source_id"`
				} `json:"users"`
				Trust bool `json:"trust_email_verification"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil || !doc.Trust || len(doc.Users) == 0 || len(doc.Users) > 1000 {
				t.Errorf("invalid import: %v (%d users)", err, len(doc.Users))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for _, u := range doc.Users {
				if seen[u.SourceID] {
					t.Errorf("duplicate imported user %s", u.SourceID)
				}
				seen[u.SourceID] = true
			}
			batches++
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"job_id":"job"}`))
		case r.Method == "GET" && strings.HasPrefix(path, "/jobs/"):
			_, _ = w.Write([]byte(`{"state":"succeeded"}`))
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case r.Method == "PUT" || strings.HasSuffix(path, "/introspectors"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"object","client":{"id":"client"},"client_secret":"test-secret"}`))
		}
	}))
	defer srv.Close()
	_, err := Seed(context.Background(), NewClient(srv.URL, "bench", 8), StaticToken("test-admin"), SeedSpec{
		Seed: ^uint64(0), Users: users, Organizations: 500, LargeOrgUsers: 5000, MachineClients: 20, RoleDepth: 3,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != users || batches <= users/1000 {
		t.Fatalf("imported %d/%d users in %d batches", len(seen), users, batches)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedBody struct {
	io.ReadCloser
	bytes *atomic.Int64
}

func (b observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}

// A busy server may need more than Go's default one-second continue wait to
// return 413. The benchmark must never fall back to uploading the body.
func TestOversizedWaitsForHeaderRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength <= 2<<20 || r.Header.Get("Expect") != "100-continue" {
			t.Errorf("offer: length %d, Expect %q", r.ContentLength, r.Header.Get("Expect"))
		}
		time.Sleep(1200 * time.Millisecond)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "bench", 1)
	transport := c.HTTP.Transport
	var sent atomic.Int64
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.Body = observedBody{r.Body, &sent}
		return transport.RoundTrip(r)
	})
	env := &Env{Client: c}
	s := &oversized{}
	if err := s.Prepare(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if got := s.Op(context.Background(), env, 0, nil); got != "http_413" {
		t.Errorf("outcome %s", got)
	}
	if n := sent.Load(); n != 0 {
		t.Errorf("uploaded %d bytes before the header refusal", n)
	}
}

func TestOversizedDetectsContinue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reading asks the transport for a body with HTTP 100 Continue.
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()
	env := &Env{Client: NewClient(srv.URL, "bench", 1)}
	s := &oversized{}
	if err := s.Prepare(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if got := s.Op(context.Background(), env, 0, nil); got != "invariant_violation_body_requested" {
		t.Fatalf("outcome %s: must detect a server asking for the oversized body", got)
	}
}
