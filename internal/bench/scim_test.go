package bench

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Successful HTTP status alone cannot prove the SCIM lifecycle workload
// completed correctly (NFR-003). Every contract failure must fail the run's
// criteria rather than becoming a misleading reference number.
func TestSCIMLifecycleChecksCompletedOperations(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"valid", "ok"}, {"wrong create status", "invariant_violation_create_status"},
		{"missing etag", "invariant_violation_read_user"}, {"patch wrong user", "invariant_violation_patched_user"},
		{"patch error", "http_503"}, {"delete not effective", "invariant_violation_deleted_user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			username := ""
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "Bearer test-connector" {
					t.Error("missing connector credential")
				}
				status := 200
				var body map[string]any
				switch calls {
				case 1:
					if r.Method != "POST" {
						t.Error("missing create")
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("bad create body")
					}
					username = stringValue(body, "userName")
					status = 201
					if tc.name == "wrong create status" {
						status = 202
					}
					body = map[string]any{"id": "user-1", "userName": username, "externalId": username, "active": true}
				case 2:
					if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/user-1") {
						t.Error("wrong read")
					}
					if tc.name != "missing etag" {
						w.Header().Set("ETag", `W/"7"`)
					}
					body = map[string]any{"id": "user-1", "userName": username}
				case 3:
					if r.Method != "PATCH" || r.Header.Get("If-Match") != `W/"7"` {
						t.Error("patch was not ETag-bound")
					}
					body = map[string]any{"id": "user-1", "displayName": "benchmark updated"}
					if tc.name == "patch wrong user" {
						body["id"] = "other"
					}
					if tc.name == "patch error" {
						status = 503
					}
				case 4:
					if r.Method != "DELETE" {
						t.Error("missing delete")
					}
					status = 204
				case 5:
					if r.Method != "GET" {
						t.Error("missing absence check")
					}
					status = 404
					if tc.name == "delete not effective" {
						status = 200
						body = map[string]any{"id": "user-1"}
					}
				default:
					t.Error("unexpected request")
				}
				w.WriteHeader(status)
				if status != 204 {
					_ = json.NewEncoder(w).Encode(body)
				}
			}))
			defer srv.Close()
			s := &scimLifecycle{prefix: "cycle", clients: []scimWorker{{token: "test-connector"}}}
			e := &Env{Client: NewClient(srv.URL, "bench", 1)}
			if got := s.Op(context.Background(), e, 0, nil); got != tc.want {
				t.Errorf("outcome %s, want %s", got, tc.want)
			}
			if tc.name == "valid" && calls != 5 {
				t.Errorf("lifecycle made %d requests, want 5", calls)
			}
		})
	}
}
