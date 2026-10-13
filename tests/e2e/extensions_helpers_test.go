package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/contracts/schemacheck"
	"github.com/proudbase/proudauth/internal/worker"
)

// capturedCall is one request an extension endpoint received.
type capturedCall struct {
	Path   string
	Header http.Header
	Body   []byte
	Status int
	Answer []byte
}

// endpoint is a test receiver for hooks, webhooks and workflow step calls:
// it records every request and answers with the function tests switch.
type endpoint struct {
	srv    *httptest.Server
	mu     sync.Mutex
	calls  []capturedCall
	answer func(r *http.Request, body []byte) (int, http.Header, []byte)
}

func newEndpoint(t testing.TB) *endpoint {
	e := &endpoint{answer: func(*http.Request, []byte) (int, http.Header, []byte) { return 204, nil, nil }}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		answer := e.answer
		e.mu.Unlock()
		status, hdr, out := answer(r, body)
		for k, v := range hdr {
			w.Header()[k] = v
		}
		if out != nil {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = w.Write(out)
		e.mu.Lock()
		e.calls = append(e.calls, capturedCall{Path: r.URL.Path, Header: r.Header.Clone(), Body: body, Status: status, Answer: out})
		e.mu.Unlock()
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *endpoint) setAnswer(fn func(r *http.Request, body []byte) (int, http.Header, []byte)) {
	e.mu.Lock()
	e.answer = fn
	e.mu.Unlock()
}

func (e *endpoint) status(code int) {
	e.setAnswer(func(*http.Request, []byte) (int, http.Header, []byte) { return code, nil, nil })
}

// received returns the calls to a path ("" for all).
func (e *endpoint) received(path string) []capturedCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []capturedCall
	for _, c := range e.calls {
		if path == "" || c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

func (e *endpoint) reset() {
	e.mu.Lock()
	e.calls = nil
	e.mu.Unlock()
}

// pump dispatches the outbox and advances workflow runs until nothing is
// left to do at the current (fake) time.
func pump(t testing.TB, h *Harness, w *worker.Worker) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		d, err := w.DispatchOutbox(ctx)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		n, err := h.App.Workflows.RunDue(ctx, w.ID, 100, time.Minute, 0)
		if err != nil {
			t.Fatalf("workflow runs: %v", err)
		}
		if d == 0 && n == 0 {
			return
		}
	}
}

// deliverWebhooks dispatches the outbox and delivers due webhooks.
func deliverWebhooks(t testing.TB, w *worker.Worker) {
	t.Helper()
	ctx := context.Background()
	if _, err := w.DispatchOutbox(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if _, err := w.Webhooks.DeliverDue(ctx, w.ID, 100); err != nil {
		t.Fatalf("deliver: %v", err)
	}
}

// apiSchemas loads the published schemas used by the compatibility checks.
func apiSchemas(t testing.TB) *schemacheck.Set {
	t.Helper()
	set, err := schemacheck.Load(filepath.Join("..", "..", "api", "events"), filepath.Join("..", "..", "api", "hooks"),
		filepath.Join("..", "..", "api", "workflows"), filepath.Join("..", "..", "api", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func asJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// auditCount counts audit events of a type about a target.
func auditCount(t testing.TB, h *Harness, typ, targetID string) int {
	t.Helper()
	var n int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE type=$1 AND ($2='' OR target_id=$2)`, typ, targetID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func bg() context.Context { return context.Background() }

// validHookSignature verifies a hook request like a hook endpoint would.
func validHookSignature(secret string, c capturedCall) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "hksec_"))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(c.Header.Get("Webhook-Id") + "." + c.Header.Get("Webhook-Timestamp") + "."))
	mac.Write(c.Body)
	return hmac.Equal([]byte(c.Header.Get("Webhook-Signature")), []byte("v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil))))
}
