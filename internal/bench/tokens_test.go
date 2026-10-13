package bench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRenewableRenewsBeforeExpiry: a held token is renewed in the background
// once less than a fifth of its lifetime is left, the old token is used until
// the new one arrives, and an expired token is renewed while the caller
// waits.
func TestRenewableRenewsBeforeExpiry(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	var fetches atomic.Int64
	fail := atomic.Bool{}
	r := &renewable{now: clock, fetch: func(context.Context) (string, time.Duration, error) {
		if fail.Load() {
			return "", 0, errors.New("refused")
		}
		return fmt.Sprintf("t%d", fetches.Add(1)), 100 * time.Second, nil
	}}
	ctx := context.Background()
	get := func() string {
		t.Helper()
		tok, err := r.get(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	waitFetches := func(n int64) {
		t.Helper()
		for i := 0; fetches.Load() < n || r.renewing(); i++ {
			if i > 1000 {
				t.Fatalf("%d fetches, want %d", fetches.Load(), n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if tok := get(); tok != "t1" {
		t.Fatalf("first token %q", tok)
	}
	advance(79 * time.Second)
	if tok := get(); tok != "t1" || fetches.Load() != 1 {
		t.Fatalf("renewed early: %q after %d fetches", tok, fetches.Load())
	}
	advance(2 * time.Second) // 81 s: within the last fifth
	if tok := get(); tok != "t1" {
		t.Fatalf("the still valid token was not used while renewing: %q", tok)
	}
	waitFetches(2)
	if tok := get(); tok != "t2" {
		t.Fatalf("renewed token %q", tok)
	}
	// A failed renewal keeps the valid token; an expired token whose
	// renewal fails is an error, not a stale token.
	fail.Store(true)
	advance(90 * time.Second)
	if tok := get(); tok != "t2" {
		t.Fatalf("token %q while the renewal fails", tok)
	}
	for r.renewing() {
		time.Sleep(time.Millisecond)
	}
	advance(20 * time.Second)
	if tok, err := r.get(ctx); err == nil {
		t.Fatalf("expired token %q returned", tok)
	}
	fail.Store(false)
	if tok := get(); tok != "t3" {
		t.Fatalf("token after recovery %q", tok)
	}
}

// renewing reports a renewal in flight (tests only).
func (r *renewable) renewing() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inflight != nil
}

// TestRenewableSingleFlight: concurrent callers of an expired token share one
// renewal; a refresh token must never be presented twice.
func TestRenewableSingleFlight(t *testing.T) {
	var running, most, fetches atomic.Int64
	r := &renewable{fetch: func(context.Context) (string, time.Duration, error) {
		n := running.Add(1)
		defer running.Add(-1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		fetches.Add(1)
		time.Sleep(20 * time.Millisecond)
		return "tok", time.Hour, nil
	}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := r.get(context.Background()); err != nil || tok != "tok" {
				t.Errorf("%q %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if most.Load() != 1 || fetches.Load() != 1 {
		t.Fatalf("%d fetches, at most %d at once; want exactly one", fetches.Load(), most.Load())
	}
}

// tokenServer is a fake token and introspection endpoint whose tokens live
// ttl and whose refresh tokens rotate with reuse detection.
type tokenServer struct {
	ttl time.Duration

	mu       sync.Mutex
	n        int
	expiry   map[string]time.Time
	refresh  string // the current refresh token
	reused   bool
	inactive int
}

func (s *tokenServer) issue() map[string]any {
	s.n++
	tok := fmt.Sprintf("at-%d", s.n)
	s.expiry[tok] = time.Now().Add(s.ttl)
	return map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": s.ttl.Seconds()}
}

func (s *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/realms/bench/oauth/token" && r.Form.Get("grant_type") == "client_credentials":
		_ = json.NewEncoder(w).Encode(s.issue())
	case r.URL.Path == "/realms/bench/oauth/token" && r.Form.Get("grant_type") == "refresh_token":
		if r.Form.Get("refresh_token") != s.refresh || r.Form.Get("client_id") != "proudauth-cli" {
			s.reused = true
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		out := s.issue()
		s.refresh = fmt.Sprintf("rt-%d", s.n)
		out["refresh_token"] = s.refresh
		_ = json.NewEncoder(w).Encode(out)
	case r.URL.Path == "/realms/bench/oauth/introspect":
		active := time.Now().Before(s.expiry[r.Form.Get("token")])
		if !active {
			s.inactive++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": active})
	case r.URL.Path == "/api/v1/realms/bench/audit-events":
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !time.Now().Before(s.expiry[tok]) {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	default:
		w.WriteHeader(404)
	}
}

// TestRunOutlastsTokenLifetime: a run longer than the lifetime of the
// tokens a scenario prepared (as a soak run is) still introspects active
// tokens and calls the administration API with valid tokens. Before
// renewal, every operation after the first token lifetime came back
// "inactive" or 401: an artifact of the tool, not of the server.
func TestRunOutlastsTokenLifetime(t *testing.T) {
	if testing.Short() {
		t.Skip("runs for seconds")
	}
	ts := &tokenServer{ttl: time.Second, expiry: map[string]time.Time{}, refresh: "rt-0"}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	c := NewClient(srv.URL, "bench", 4)
	creds := filepath.Join(t.TempDir(), "bench-admin.json")
	expired, _ := json.Marshal(credentialsFile{URL: srv.URL, Realm: "bench", Audience: "admin", AccessToken: "stale",
		RefreshToken: "rt-0", Expiry: time.Now().Add(-time.Minute)})
	if err := os.WriteFile(creds, expired, 0o600); err != nil {
		t.Fatal(err)
	}
	admin, err := LoadAdminCredentials(creds, c)
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{Client: c, Admin: admin, Seed: &SeedData{Spec: SeedSpec{Users: 10}, Audience: "https://api.bench.test",
		Machine: []SeedClient{{ClientID: "m1", Secret: "s"}, {ClientID: "m2", Secret: "s"}}, ResourceSrv: SeedClient{ClientID: "rs", Secret: "s"}}}
	for _, sc := range []Scenario{&introspection{}, &auditQuery{}} {
		res, err := Run(context.Background(), env, sc, Options{Concurrency: 4, Duration: 2500 * time.Millisecond, Seed: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Outcomes) != 1 || res.Outcomes["ok"] == 0 {
			t.Errorf("%s across token expiry: outcomes %v", sc.Name(), res.Outcomes)
		}
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.reused {
		t.Fatal("a refresh token was presented twice")
	}
	// The rotated refresh token is in the file, so the next command (or
	// identity-cli) goes on with it.
	raw, err := os.ReadFile(creds)
	if err != nil {
		t.Fatal(err)
	}
	var saved credentialsFile
	if err := json.Unmarshal(raw, &saved); err != nil || saved.RefreshToken != ts.refresh || saved.Realm != "bench" || saved.URL != srv.URL {
		t.Fatalf("saved credentials %+v (%v), current refresh token %s", saved, err, ts.refresh)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(creds); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("credentials file mode %v %v", fi.Mode().Perm(), err)
		}
	}
	if admin.SaveError() != nil {
		t.Fatal(admin.SaveError())
	}
}

func TestLoadAdminCredentialsRefusals(t *testing.T) {
	dir := t.TempDir()
	c := NewClient("http://127.0.0.1:1", "bench", 1)
	for name, body := range map[string]string{
		"missing refresh token": `{"realm":"bench","access_token":"a"}`,
		"other realm":           `{"realm":"main","access_token":"a","refresh_token":"r"}`,
		"malformed":             `{`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAdminCredentials(p, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestNextUserTakesTurns: sign-ins go to every user in turn, so no account
// gets a second sign-in before every other one had its first, and the policy
// subjects and the attacked account are left out.
func TestNextUserTakesTurns(t *testing.T) {
	env := &Env{Seed: &SeedData{Spec: SeedSpec{Users: 1000, LargeOrgUsers: 500}}}
	seen := map[int]int{}
	for i := 0; i < 2*(999-policySubjects); i++ {
		seen[env.nextUser()]++
	}
	for u := 0; u < 1000; u++ {
		want := 2
		if u < policySubjects || u == 999 {
			want = 0
		}
		if seen[u] != want {
			t.Fatalf("user %d signed in %d times, want %d", u, seen[u], want)
		}
	}
	tiny := &Env{Seed: &SeedData{Spec: SeedSpec{Users: 5, LargeOrgUsers: 4}}}
	for i := 0; i < 20; i++ {
		if u := tiny.nextUser(); u < 0 || u > 3 {
			t.Fatalf("tiny dataset: user %d", u)
		}
	}
}

// countingListener counts the bytes the server reads.
type countingListener struct {
	net.Listener
	n *atomic.Int64
}

type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return countingConn{c, l.n}, err
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// TestOversizedInputSendsNoBody: the oversized-input scenario declares its
// 2 MiB body and waits for the server, which refuses it from the declared
// length (413), so the body is never transferred. Transferring it from one
// host at full concurrency exhausted the load generator's network buffers.
func TestOversizedInputSendsNoBody(t *testing.T) {
	var read atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Expect") != "100-continue" || r.ContentLength <= 2<<20 {
			t.Errorf("expect %q, length %d", r.Header.Get("Expect"), r.ContentLength)
		}
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = io.WriteString(w, `{"code":"payload_too_large"}`)
	}))
	srv.Listener = countingListener{srv.Listener, &read}
	srv.Start()
	defer srv.Close()
	env := &Env{Client: NewClient(srv.URL, "bench", 4)}
	res, err := Run(context.Background(), env, &oversized{}, Options{Concurrency: 4, Operations: 40, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 1 || res.Outcomes["http_413"] != 40 {
		t.Fatalf("outcomes %v", res.Outcomes)
	}
	if n := read.Load(); n > 40*4096 {
		t.Fatalf("the server read %d bytes for 40 refused requests: the bodies were sent", n)
	}
}
