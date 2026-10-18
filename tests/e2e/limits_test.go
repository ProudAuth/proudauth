package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/realm"
)

// limitsFixture is a realm with only the bootstrap administrator: the small
// limits below would otherwise truncate the lists the full fixture reads.
func limitsFixture(t *testing.T, opts ...Option) *Fixture {
	t.Helper()
	h := NewHarness(t, opts...)
	h.CreateRealm(func(p *realm.Policy) { p.Login.EmailOTP = true })
	f := &Fixture{H: h, Users: map[string]string{}, Clients: map[string]Client{}, Roles: map[string]string{}, MemberAcme: map[string]string{}, MemberGlobex: map[string]string{}}
	f.AdminToken = f.bootstrapAdmin()
	return f
}

// TestExplicitRequestLimits covers NFR-001 at the HTTP boundary: request
// bodies (limits.max_body_bytes, with and without a declared length), JSON
// nesting (limits.max_json_depth), page size (limits.max_page_size and
// limits.default_page_size) and batch size (limits.max_batch_size) are
// bounded by the configured values, with a request at each limit accepted
// and one past it refused predictably.
func TestExplicitRequestLimits(t *testing.T) {
	f := limitsFixture(t, func(c *configuration.Config) {
		c.Limits.MaxBodyBytes = 256 << 10
		c.Limits.MaxJSONDepth = 32
		c.Limits.MaxPageSize = 3
		c.Limits.DefaultPageSize = 2
		c.Limits.MaxBatchSize = 4
	})
	h := f.H

	// Body size: refused with 413 whether the length is declared up front or
	// only discovered while reading a chunked body.
	big, _ := json.Marshal(map[string]any{"slug": "big", "display_name": "Big", "metadata": map[string]any{"blob": strings.Repeat("x", 300<<10)}})
	r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/organizations", Token: f.AdminToken, RawBody: big})
	if r.Status != 413 || r.Str("code") != "payload_too_large" {
		t.Fatalf("declared-length body over max_body_bytes: %d %s", r.Status, r.Raw)
	}
	req, err := http.NewRequest("POST", h.Base+"/api/v1/realms/main/organizations", io.MultiReader(bytes.NewReader(big)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.AdminToken)
	res, err := h.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 413 || req.ContentLength != 0 {
		t.Fatalf("chunked body over max_body_bytes: %d (declared length %d)", res.StatusCode, req.ContentLength)
	}

	// JSON depth: the request object is depth 0 and metadata depth 1, so m
	// nested objects in metadata put the innermost value at depth m+1.
	nest := func(m int) any {
		var v any = 1
		for i := 0; i < m; i++ {
			v = map[string]any{"a": v}
		}
		return v
	}
	r = f.AdminAPI("POST", "/organizations", map[string]any{"slug": "too-deep", "display_name": "Too deep", "metadata": nest(32)})
	if r.Status != 400 || !strings.Contains(r.Str("detail"), "malformed JSON") {
		t.Fatalf("body nested past max_json_depth: %d %s", r.Status, r.Raw)
	}
	f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "deep-enough", "display_name": "Deep enough", "metadata": nest(31)}), 201,
		"body nested to max_json_depth")
	if r := f.AdminAPI("GET", "/organizations?limit=3", nil); strings.Contains(string(r.Raw), "too-deep") {
		t.Fatal("a refused body created an organization")
	}

	// Page size: a larger limit is reduced to max_page_size, a missing one
	// is default_page_size, and the rest stays reachable through the cursor.
	for i := 0; i < 4; i++ {
		f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": fmt.Sprintf("limit-%d", i),
			"permissions": []string{"realm.users.read"}}), 201, "role")
	}
	page := f.must(f.AdminAPI("GET", "/roles?boundary_type=realm&limit=1000", nil), 200, "oversized page")
	if n := len(page.Get("items").([]any)); n != 3 || page.Str("next_cursor") == "" {
		t.Fatalf("limit=1000 returned %d items (cursor %q), want max_page_size 3 and a cursor", n, page.Str("next_cursor"))
	}
	for _, q := range []string{"", "&limit=0", "&limit=-5", "&limit=x"} {
		page = f.must(f.AdminAPI("GET", "/roles?boundary_type=realm"+q, nil), 200, "default page")
		if n := len(page.Get("items").([]any)); n != 2 {
			t.Fatalf("roles?%s returned %d items, want default_page_size 2", q, n)
		}
	}

	// Batch size: max_batch_size checks are evaluated, one more is refused
	// as a whole before any is evaluated.
	checks := func(n int) map[string]any {
		cs := make([]map[string]any, n)
		for i := range cs {
			cs[i] = map[string]any{"subject": map[string]any{"type": "user", "id": f.Users["admin"]}, "action": "realm.users.read",
				"resource": map[string]any{"type": "realm"}}
		}
		return map[string]any{"checks": cs}
	}
	ok := f.must(f.AdminAPI("POST", "/authorization/check-batch", checks(4)), 200, "batch at max_batch_size")
	if n := len(ok.Get("decisions").([]any)); n != 4 {
		t.Fatalf("batch of 4 returned %d decisions", n)
	}
	r = f.AdminAPI("POST", "/authorization/check-batch", checks(5))
	if r.Status != 422 || !strings.Contains(string(r.Raw), "max_batch_size") || r.Get("decisions") != nil {
		t.Fatalf("batch over max_batch_size: %d %s", r.Status, r.Raw)
	}
}

// TestLoadShedding covers NFR-002: when every ordinary request slot
// (limits.max_inflight_requests) is taken, further ordinary requests are
// refused at once with 503 and Retry-After instead of queueing (problem
// details, or an OAuth temporarily_unavailable error on a protocol
// endpoint, API-007), while health
// probes and authenticated administration still run from the reserved pool.
// Anonymous requests to administrative paths do not get the reserve. Once
// the load is gone, ordinary requests are served again.
func TestLoadShedding(t *testing.T) {
	f := limitsFixture(t, func(c *configuration.Config) { c.Limits.MaxInflightRequests = 1 })
	h := f.H
	discovery := Req{Method: "GET", Path: "/realms/main/.well-known/openid-configuration"}
	mustStatus(t, h.Do(discovery), 200, "discovery before the load")

	// hold occupies the only ordinary slot with a token request whose body
	// never ends: the handler waits for the rest of the form.
	hold := func() (func(), chan int) {
		pr, pw := io.Pipe()
		done := make(chan int, 1)
		req, err := http.NewRequest("POST", h.Base+"/realms/main/oauth/token", pr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{Transport: &http.Transport{}, Timeout: 30 * time.Second}
		go func() {
			res, err := client.Do(req)
			if err != nil {
				done <- 0
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			done <- res.StatusCode
		}()
		go func() { _, _ = pw.Write([]byte("grant_type=client_credentials&client_id=")) }()
		var once bool
		release := func() {
			if !once {
				once = true
				_ = pw.Close()
			}
		}
		t.Cleanup(release) // before the server shuts down
		return release, done
	}

	var shed *Resp
	var release func()
	var done chan int
	for attempt := 0; attempt < 3 && shed == nil; attempt++ {
		release, done = hold()
		time.Sleep(300 * time.Millisecond)
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
			select {
			case st := <-done:
				// The held request itself lost the race for the slot.
				t.Logf("held request finished early with %d; retrying", st)
				deadline = time.Time{}
				continue
			default:
			}
			if r := h.Do(discovery); r.Status == 503 {
				shed = r
				break
			}
		}
	}
	if shed == nil {
		t.Fatal("ordinary requests were not shed while every ordinary slot was busy")
	}
	if shed.Str("code") != "unavailable" || shed.Header.Get("Retry-After") != "2" || !strings.Contains(shed.Str("detail"), "shedding load") {
		t.Fatalf("shed response lacks retry guidance: %s Retry-After=%q", shed.Raw, shed.Header.Get("Retry-After"))
	}
	// On a protocol endpoint the same refusal is an OAuth error (API-007),
	// so relying-party retry logic sees temporarily_unavailable.
	tok := h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: url.Values{"grant_type": {"client_credentials"}}})
	if tok.Status != 503 || tok.Str("error") != "temporarily_unavailable" || tok.Str("error_description") != "server is shedding load" ||
		tok.Header.Get("Retry-After") != "2" || tok.Get("code") != nil || tok.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("shed token request: %d %q %s Retry-After=%q", tok.Status, tok.Header.Get("Content-Type"), tok.Raw, tok.Header.Get("Retry-After"))
	}
	// The reserve keeps health probes and authenticated administration
	// working during the overload.
	mustStatus(t, h.Do(Req{Method: "GET", Path: "/health/live"}), 200, "liveness under load")
	mustStatus(t, f.AdminAPI("GET", "/users", nil), 200, "authenticated administration under load")
	// Without credentials an administrative path competes for the ordinary
	// pool and is shed like any other request.
	if r := h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/users"}); r.Status != 503 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("anonymous administrative request used the reserve: %d", r.Status)
	}
	// Ordinary requests are served again once the load is gone.
	release()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("held request did not finish after its body ended")
	}
	mustStatus(t, h.Do(discovery), 200, "discovery after the load")
}
