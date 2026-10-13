package bench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Registration's requested credProps result must not leak into an assertion
// that did not request it: the real server correctly rejects that response.
func TestSoftwarePasskeyDoesNotReturnUnrequestedExtensions(t *testing.T) {
	k, err := newSoftwarePasskey("login.test", "https://login.test")
	if err != nil {
		t.Fatal(err)
	}
	register, err := k.credential(map[string]any{"challenge": "register", "user": map[string]any{"id": base64.RawURLEncoding.EncodeToString([]byte("test-user-handle"))},
		"extensions": map[string]any{"credProps": true}}, true)
	if err != nil || object(register["clientExtensionResults"])["credProps"] == nil {
		t.Fatalf("registration extension: %v", err)
	}
	assertion, err := k.credential(map[string]any{"challenge": "assert", "rpId": "login.test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(object(assertion["clientExtensionResults"])) != 0 {
		t.Fatal("assertion emitted an unrequested registration extension")
	}
}

func TestPasskeyPreparationFollowsImportJobID(t *testing.T) {
	for _, missing := range []bool{false, true} {
		jobs := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body any
			switch {
			case strings.HasSuffix(r.URL.Path, "/settings"):
				body = map[string]any{"policy": map[string]any{"login": map[string]any{"passkeys": true}}}
			case strings.HasSuffix(r.URL.Path, "/user-imports"):
				w.WriteHeader(202)
				body = map[string]any{}
				if !missing {
					body = map[string]any{"job_id": "job-1"}
				}
			case strings.Contains(r.URL.Path, "/jobs/"):
				jobs++
				if !strings.HasSuffix(r.URL.Path, "/jobs/job-1") {
					t.Error("polled the wrong import job")
				}
				body = map[string]any{"state": "failed", "last_error": "controlled fixture stop"}
			default:
				t.Error("unexpected preparation request")
			}
			_ = json.NewEncoder(w).Encode(body)
		}))
		e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("fixture"), Concurrency: 1,
			Seed: &SeedData{Prefix: "test-", AccountAudience: "account"}}
		err := (&passkeyAssertion{}).Prepare(context.Background(), e)
		srv.Close()
		if missing {
			if err == nil || !strings.Contains(err.Error(), "no job_id") || jobs != 0 {
				t.Fatalf("missing job ID: %v, polls %d", err, jobs)
			}
		} else if err == nil || !strings.Contains(err.Error(), "job job-1 failed") || jobs != 1 {
			t.Fatalf("import job: %v, polls %d", err, jobs)
		}
	}
}

func TestImportPollingFailsOnHTTPError(t *testing.T) {
	for _, status := range []int{401, 404, 503} {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := waitJob(ctx, NewClient(srv.URL, "bench", 1), StaticToken("fixture"), "job-1")
		cancel()
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "HTTP") || calls != 1 {
			t.Fatalf("HTTP %d: %v, calls %d", status, err, calls)
		}
	}
}
