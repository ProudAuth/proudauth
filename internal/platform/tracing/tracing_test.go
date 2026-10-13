package tracing

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestOTLPExporter: spans reach the collector as OTLP/HTTP JSON when the
// exporter closes, and a failing collector drops spans instead of blocking.
func TestOTLPExporter(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies = append(bodies, m)
		st := status
		mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			st = http.StatusUnsupportedMediaType
		}
		w.WriteHeader(st)
	}))
	defer srv.Close()
	e := NewOTLPExporter(srv.URL+"/v1/traces", "")
	now := time.Now()
	for i := 0; i < 3; i++ {
		e.Export(Span{TraceID: "0102030405060708090a0b0c0d0e0f10", SpanID: NewSpanID(), Name: "GET /x", Kind: KindServer, Start: now, End: now,
			Status: StatusOK, Attributes: map[string]any{"http.response.status_code": 200}})
	}
	e.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("batches: %d", len(bodies))
	}
	rs := bodies[0]["resourceSpans"].([]any)[0].(map[string]any)
	spans := rs["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	if len(spans) != 3 || e.Dropped.Load() != 0 {
		t.Fatalf("spans %d dropped %d", len(spans), e.Dropped.Load())
	}
	status = http.StatusServiceUnavailable
	mu.Unlock()
	f := NewOTLPExporter(srv.URL, "x")
	f.Export(Span{TraceID: "0102030405060708090a0b0c0d0e0f10", SpanID: NewSpanID(), Name: "n", Start: now, End: now})
	f.Close()
	mu.Lock()
	if f.Dropped.Load() != 1 {
		t.Fatalf("failed export not counted: %d", f.Dropped.Load())
	}
	// After Close, spans are dropped, never sent on the closed queue; Close
	// is idempotent.
	f.Export(Span{TraceID: "0102030405060708090a0b0c0d0e0f10", SpanID: NewSpanID(), Name: "late", Start: now, End: now})
	f.Close()
	if f.Dropped.Load() != 2 {
		t.Fatalf("late span: %d", f.Dropped.Load())
	}
}
