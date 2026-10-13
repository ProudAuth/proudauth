package bench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A queued setup event can outlive a measured operation's deadline. The
// unmeasured readiness cycle must wait through it without relaxing the
// measured deadline or accepting an abandoned cycle's callbacks.
func TestBenchWebhookReadinessCrossesSetupBacklog(t *testing.T) {
	w := testWebhookWorker(false)
	w.pending = map[string]*webhookCycle{}
	h := &webhookHub{routes: map[string]*webhookWorker{"/worker": w}, now: time.Now}
	var delivered sync.Map
	var callbacks sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/deliveries"):
			items := []any{}
			delivered.Range(func(key, _ any) bool {
				for _, typ := range []string{memberAdded, memberRemoved} {
					items = append(items, map[string]any{"id": key.(string) + typ, "event_id": key.(string) + typ, "event_type": typ,
						"state": "delivered", "attempts": 1, "last_status_code": 204, "delivered_at": time.Now().Format(time.RFC3339Nano)})
				}
				return true
			})
			_ = json.NewEncoder(rw).Encode(map[string]any{"items": items})
		case r.Method == "GET":
			_ = json.NewEncoder(rw).Encode(map[string]any{"items": []any{}, "next_cursor": ""})
		case r.Method == "POST":
			rw.WriteHeader(201)
			_ = json.NewEncoder(rw).Encode(map[string]any{"id": "member-1", "user_id": w.user, "organization_id": w.org, "state": "active"})
		case r.Method == "DELETE":
			cid := r.Header.Get("X-Request-Id")
			callbacks.Add(1)
			go func() {
				defer callbacks.Done()
				// Simulate an event waiting behind setup work in the outbox.
				time.Sleep(150 * time.Millisecond)
				for _, typ := range []string{memberAdded, memberRemoved} {
					body := webhookBody()
					body["event_id"], body["event_type"], body["correlation_id"] = cid+typ, typ, cid
					b, _ := json.Marshal(body)
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, signedWebhook(w.secret, b, cid+typ, time.Now().Unix()))
					if rr.Code != 204 {
						t.Errorf("queued callback rejected: %d", rr.Code)
					}
				}
				delivered.Store(cid, true)
			}()
			rw.WriteHeader(204)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			rw.WriteHeader(404)
		}
	}))
	defer srv.Close()
	defer callbacks.Wait()
	e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("admin"), Seed: &SeedData{Prefix: "b1-", RoleID: "role-1"}}
	s := &webhookDelivery{workers: []*webhookWorker{w}}
	if out := s.op(context.Background(), e, 0, 50*time.Millisecond); out != "delivery_timeout" {
		t.Fatalf("short measured deadline: %s", out)
	}
	if out := s.op(context.Background(), e, 0, 2*time.Second); out != "ok" {
		t.Fatalf("readiness deadline did not cross backlog: %s", out)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stats.Accepted != 2 || w.stats.Ignored != 2 || w.stats.Invalid != 0 || len(w.pending) != 0 {
		t.Fatalf("readiness reused an abandoned operation: %+v", w.stats)
	}
}

func TestBenchWebhookPreparationCycleIsNotMeasured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := []byte(strings.Repeat("k", 32))
	var destination atomic.Value
	var delivered sync.Map
	var callbacks sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		write := func(status int, body any) { rw.WriteHeader(status); _ = json.NewEncoder(rw).Encode(body) }
		switch {
		case strings.HasSuffix(r.URL.Path, "/user-imports"):
			write(202, map[string]any{"job_id": "job-1"})
		case strings.HasSuffix(r.URL.Path, "/jobs/job-1"):
			write(200, map[string]any{"state": "succeeded"})
		case strings.HasSuffix(r.URL.Path, "/users"):
			write(200, map[string]any{"items": []any{map[string]any{"id": "user-1", "identifiers": []any{map[string]any{"type": "email", "value": r.URL.Query().Get("q")}}}}})
		case strings.HasSuffix(r.URL.Path, "/organizations"):
			write(201, map[string]any{"id": "org-1", "realm_id": "realm-1"})
		case strings.HasSuffix(r.URL.Path, "/webhooks"):
			var in struct {
				Destination string `json:"destination_url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Error(err)
			}
			destination.Store(in.Destination)
			write(201, map[string]any{"subscription": map[string]any{"id": "sub-1"}, "signing_secret": "whsec_" + base64.StdEncoding.EncodeToString(key)})
		case r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "/webhooks/sub-1"):
			rw.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/deliveries"):
			items := []any{}
			delivered.Range(func(key, _ any) bool {
				for _, typ := range []string{memberAdded, memberRemoved} {
					items = append(items, map[string]any{"id": key.(string) + typ, "event_id": key.(string) + typ, "event_type": typ,
						"state": "delivered", "attempts": 1, "last_status_code": 204, "delivered_at": time.Now().Format(time.RFC3339Nano)})
				}
				return true
			})
			write(200, map[string]any{"items": items})
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/members"):
			write(200, map[string]any{"items": []any{}, "next_cursor": ""})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/members"):
			write(201, map[string]any{"id": "member-1", "user_id": "user-1", "organization_id": "org-1", "state": "active"})
		case r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "/members/member-1"):
			cid := r.Header.Get("X-Request-Id")
			callbacks.Add(1)
			go func() {
				defer callbacks.Done()
				time.Sleep(40 * time.Millisecond)
				for _, typ := range []string{memberAdded, memberRemoved} {
					body := webhookBody()
					body["event_id"], body["event_type"], body["correlation_id"] = cid+typ, typ, cid
					b, _ := json.Marshal(body)
					req := signedWebhook(key, b, cid+typ, time.Now().Unix()).WithContext(ctx)
					req.URL, _ = url.Parse(destination.Load().(string))
					req.RequestURI, req.Host = "", req.URL.Host
					res, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Error(err)
						return
					}
					res.Body.Close()
					if res.StatusCode != 204 {
						t.Errorf("callback: HTTP %d", res.StatusCode)
						return
					}
				}
				delivered.Store(cid, true)
			}()
			rw.WriteHeader(204)
		default:
			t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
			rw.WriteHeader(404)
		}
	}))
	defer srv.Close()
	defer callbacks.Wait()
	e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("admin"), Seed: &SeedData{Prefix: "b1-", RoleID: "role-1"}}
	r, err := Run(ctx, e, &webhookDelivery{}, Options{Concurrency: 1, Operations: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.Operations != 1 || r.Outcomes["ok"] != 1 || e.webhookHub != nil {
		t.Fatalf("measurement/cleanup: %+v", r)
	}
	before := r.Observations["before"].(map[string]any)["cumulative"].(webhookStats)
	after := r.Observations["after"].(map[string]any)["cumulative"].(webhookStats)
	if before.Accepted != 2 || after.Accepted != 4 {
		t.Fatalf("readiness cycle missing or counted: before=%+v after=%+v", before, after)
	}
}
