package bench

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signedWebhook(key []byte, body []byte, id string, ts int64) *http.Request {
	r := httptest.NewRequest("POST", "http://receiver.test/worker", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Webhook-Id", id)
	r.Header.Set("Webhook-Timestamp", strconv.FormatInt(ts, 10))
	m := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(m, "%s.%d.", id, ts)
	_, _ = m.Write(body)
	r.Header.Set("Webhook-Signature", "v1,"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
	return r
}
func webhookBody() map[string]any {
	return map[string]any{"event_id": "event-1", "event_type": memberAdded, "event_version": 2, "realm_id": "realm-1", "organization_id": "org-1",
		"occurred_at":  "2023-11-14T22:13:20Z",
		"payload_form": "minimal", "correlation_id": "current-cycle", "data": map[string]any{"membership_id": "member-1", "user_id": "user-1"}}
}
func testWebhookWorker(retry bool) *webhookWorker {
	w := &webhookWorker{ready: make(chan struct{}), secret: []byte(strings.Repeat("k", 32)), realm: "realm-1", org: "org-1", user: "user-1", retry: retry,
		pending: map[string]*webhookCycle{"current-cycle": {events: map[string]*webhookReceipt{}}}}
	close(w.ready)
	return w
}

// NFR-003, NFR-005: a received callback must actually prove this committed
// operation. Wrong signatures, identities, old correlations and changed retries
// cannot become successful reference operations.
func TestBenchWebhookReceiverChecksSignaturesAndCorrelation(t *testing.T) {
	for _, name := range []string{"valid", "wrong key", "tampered body", "stale timestamp", "duplicate header", "wrong event id", "wrong realm", "wrong org", "wrong user", "wrong version", "old correlation"} {
		t.Run(name, func(t *testing.T) {
			w := testWebhookWorker(false)
			now := time.Unix(1700000000, 0)
			h := &webhookHub{routes: map[string]*webhookWorker{"/worker": w}, now: func() time.Time { return now }}
			body := webhookBody()
			if name == "wrong realm" {
				body["realm_id"] = "other"
			}
			if name == "wrong org" {
				body["organization_id"] = "other"
			}
			if name == "wrong user" {
				body["data"].(map[string]any)["user_id"] = "other"
			}
			if name == "wrong version" {
				body["event_version"] = 1
			}
			if name == "old correlation" {
				body["correlation_id"] = "abandoned-cycle"
			}
			key := w.secret
			if name == "wrong key" {
				key = []byte(strings.Repeat("x", 32))
			}
			id := "event-1"
			if name == "wrong event id" {
				id = "different"
			}
			ts := now.Unix()
			if name == "stale timestamp" {
				ts -= 301
			}
			b, _ := json.Marshal(body)
			r := signedWebhook(key, b, id, ts)
			if name == "tampered body" {
				r.Body = http.NoBody
			}
			if name == "duplicate header" {
				r.Header.Add("Webhook-Id", id)
			}
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, r)
			if name == "valid" {
				if rw.Code != 204 || !w.pending["current-cycle"].events[memberAdded].accepted || w.stats.Accepted != 1 {
					t.Fatalf("valid callback: %d %+v", rw.Code, w.stats)
				}
			} else if name == "old correlation" {
				if rw.Code != 204 || len(w.pending["current-cycle"].events) != 0 || w.stats.Accepted != 0 || w.stats.Ignored != 1 {
					t.Fatal("old callback satisfied a new operation")
				}
			} else if rw.Code < 400 || w.stats.Invalid != 1 || w.stats.Accepted != 0 {
				t.Fatalf("%s accepted: %d %+v", name, rw.Code, w.stats)
			}
		})
	}
}

func TestBenchWebhookRetryKeepsBodyIDAndRefreshesTimestamp(t *testing.T) {
	for _, name := range []string{"valid", "changed body", "changed id", "same timestamp"} {
		t.Run(name, func(t *testing.T) {
			w := testWebhookWorker(true)
			now := time.Unix(1700000015, 0)
			h := &webhookHub{routes: map[string]*webhookWorker{"/worker": w}, now: func() time.Time { return now }}
			body := webhookBody()
			b, _ := json.Marshal(body)
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, signedWebhook(w.secret, b, "event-1", now.Unix()-15))
			if rw.Code != 503 || w.stats.Intentional503 != 1 || w.stats.Accepted != 0 {
				t.Fatal("first attempt did not produce a controlled retry")
			}
			id := "event-1"
			ts := now.Unix()
			if name == "changed body" {
				body["data"].(map[string]any)["authorization_revision"] = 2
			}
			if name == "changed id" {
				body["event_id"] = "event-2"
				id = "event-2"
			}
			if name == "same timestamp" {
				ts -= 15
			}
			b, _ = json.Marshal(body)
			rw = httptest.NewRecorder()
			h.ServeHTTP(rw, signedWebhook(w.secret, b, id, ts))
			if name == "valid" {
				if rw.Code != 204 || w.stats.Recovered != 1 || w.pending["current-cycle"].events[memberAdded].attempts != 2 {
					t.Fatal("valid retry not observed")
				}
			} else if rw.Code < 400 || w.pending["current-cycle"].bad == "" || w.stats.Accepted != 0 {
				t.Fatalf("invalid retry accepted: %d", rw.Code)
			}
		})
	}
}

func TestBenchWebhookChecksExactDeliveredStates(t *testing.T) {
	for _, name := range []string{"normal", "retry", "pending", "wrong attempt count", "dead letter", "wrong event type", "wrong status", "empty page"} {
		t.Run(name, func(t *testing.T) {
			retry := name == "retry"
			attempts := 1
			if retry {
				attempts = 2
			}
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				items := []any{}
				for i, typ := range []string{memberAdded, memberRemoved} {
					d := map[string]any{"id": fmt.Sprintf("delivery-%d", i), "event_id": fmt.Sprintf("event-%d", i), "event_type": typ, "state": "delivered", "attempts": attempts, "last_status_code": 204, "delivered_at": time.Now().Format(time.RFC3339Nano)}
					if name == "pending" {
						d["state"] = "retrying"
					}
					if name == "wrong attempt count" {
						d["attempts"] = 3
					}
					if name == "dead letter" {
						d["state"] = "dead_letter"
					}
					if name == "wrong event type" {
						d["event_type"] = memberRemoved
					}
					if name == "wrong status" {
						d["last_status_code"] = 200
					}
					items = append(items, d)
				}
				if name == "empty page" {
					items = nil
				}
				_ = json.NewEncoder(rw).Encode(map[string]any{"items": items})
			}))
			defer srv.Close()
			e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("test-admin")}
			got := (&webhookDelivery{retry: retry}).deliveryStates(context.Background(), e, &webhookWorker{subscription: "sub-1"}, []webhookReceipt{{id: "event-0"}, {id: "event-1"}})
			want := "invariant_delivery_state"
			if name == "normal" || name == "retry" {
				want = "ok"
			}
			if name == "pending" {
				want = "pending"
			}
			if name == "empty page" {
				want = "invariant_delivery_page"
			}
			if got != want {
				t.Fatalf("%s, want %s", got, want)
			}
		})
	}
}

func TestBenchWebhookFailedPreparationClosesReceiver(t *testing.T) {
	var address string
	e := &Env{Admin: StaticToken("test-admin"), Seed: &SeedData{RoleID: "role-1", Prefix: "b1-"}}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		address = strings.TrimPrefix(e.webhookHub.origin, "http://")
		rw.WriteHeader(403)
	}))
	defer srv.Close()
	e.Client = NewClient(srv.URL, "bench", 1)
	if _, err := Run(context.Background(), e, &webhookDelivery{}, Options{Concurrency: 1, Operations: 1}); err == nil {
		t.Fatal("failed import accepted")
	}
	if e.webhookHub != nil || address == "" {
		t.Fatal("failed preparation retained a callback receiver")
	}
	c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatal("receiver still listening after failed preparation")
	}
}

func TestBenchWebhookFixtureLookupUsesExactIdentifier(t *testing.T) {
	email := "b1-webhook-fixture-0@bench.test"
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != email {
			t.Error("fixture lookup used a prefix instead of an exact identifier")
		}
		_ = json.NewEncoder(rw).Encode(map[string]any{"items": []any{map[string]any{"id": "user-1", "identifiers": []any{map[string]any{"type": "email", "value": email}}}}})
	}))
	defer srv.Close()
	e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("test-admin")}
	if id, err := webhookFixtureUser(context.Background(), e, email); err != nil || id != "user-1" {
		t.Fatalf("fixture lookup: %s %v", id, err)
	}
}
