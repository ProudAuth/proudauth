package bench

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// NFR-003: enqueue acceptance is not completion. Fail closed for wrong jobs,
// malformed pages, unexpected success statuses and terminal delivery failures.
func TestEmailDeliveryChecksWorkerAcceptance(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"accepted", "ok"}, {"failed", "delivery_failed"}, {"suppressed", "delivery_suppressed"},
		{"expired", "delivery_expired"}, {"wrong channel", "invariant_wrong_job"},
		{"wrong reference", "invariant_wrong_job"}, {"missing job", "invariant_job_not_found"},
		{"no job id", "invariant_missing_job_id"}, {"wrong enqueue status", "invariant_unexpected_http_200"},
		{"list failure", "http_503"}, {"bad page", "invariant_invalid_job_page"},
		{"pagination", "ok"}, {"repeated cursor", "invariant_repeated_cursor"},
		{"queued then accepted", "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			polls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-admin" {
					t.Error("administrator authentication missing")
				}
				if r.Method == "POST" {
					status, id := 202, "job-1"
					if tc.name == "wrong enqueue status" {
						status = 200
					}
					if tc.name == "no job id" {
						id = ""
					}
					w.WriteHeader(status)
					_ = json.NewEncoder(w).Encode(map[string]any{"job_id": id})
					return
				}
				polls++
				if r.URL.Query().Get("reference_type") != "notification_test" || r.URL.Query().Get("reference_id") != "admin-1" {
					t.Error("job listing lost its reference filter")
				}
				if tc.name == "list failure" {
					w.WriteHeader(503)
					return
				}
				if tc.name == "bad page" {
					_, _ = w.Write([]byte(`{"items":null}`))
					return
				}
				if tc.name == "pagination" && polls == 1 || tc.name == "repeated cursor" {
					_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "next_cursor": "page-2"})
					return
				}
				if tc.name == "pagination" && r.URL.Query().Get("cursor") != "page-2" {
					t.Error("cursor not followed")
				}
				state := "accepted"
				if tc.name == "queued then accepted" && polls == 1 {
					state = "queued"
				}
				if tc.name == "failed" || tc.name == "suppressed" || tc.name == "expired" {
					state = tc.name
				}
				j := map[string]any{"id": "job-1", "state": state, "channel": "email", "template": "configuration_test", "reference_type": "notification_test", "reference_id": "admin-1"}
				if tc.name == "wrong channel" {
					j["channel"] = "sms"
				}
				if tc.name == "wrong reference" {
					j["reference_id"] = "another-admin"
				}
				if tc.name == "missing job" {
					j["id"] = "another-job"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{j}})
			}))
			defer srv.Close()
			e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("test-admin")}
			if got := (&emailDelivery{reference: "admin-1"}).Op(context.Background(), e, 0, nil); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEmailDeliveryRefusesUnreachableOrNonSMTPAdapter(t *testing.T) {
	for _, body := range []string{`{"email_adapter":"dev_sink","ok":true}`, `{"email_adapter":"smtp","ok":false}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		e := &Env{Client: NewClient(srv.URL, "bench", 1)}
		if err := (&emailDelivery{}).Prepare(context.Background(), e); err == nil {
			t.Error("unmeasured development mailbox/unreachable adapter accepted")
		}
		srv.Close()
	}
}
