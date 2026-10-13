// Package tracing is ProudAuth's open tracing interface (OPS-003): sampled
// requests produce spans that a Tracer receives. The built-in OTLPExporter
// sends them to any OpenTelemetry collector as OTLP/HTTP JSON; deployments
// can install another Tracer. Spans carry route-level attributes only: no
// headers, bodies, query strings, identifiers or credentials are captured.
package tracing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Span kinds (OTLP numbering).
const (
	KindInternal = 1
	KindServer   = 2
	KindClient   = 3
)

// Status codes (OTLP numbering).
const (
	StatusUnset = 0
	StatusOK    = 1
	StatusError = 2
)

// Span is one finished, sampled operation.
type Span struct {
	TraceID, SpanID, ParentID string
	Name                      string
	Kind                      int
	Start, End                time.Time
	Status                    int
	Attributes                map[string]any
}

// Tracer receives finished spans; Export must not block.
type Tracer interface{ Export(Span) }

var current atomic.Value // holds tracerBox

type tracerBox struct{ t Tracer }

// SetTracer installs the deployment's tracer; nil disables export.
func SetTracer(t Tracer) { current.Store(tracerBox{t}) }

// Enabled reports whether spans are exported.
func Enabled() bool {
	b, _ := current.Load().(tracerBox)
	return b.t != nil
}

// Export hands a span to the tracer, if any.
func Export(s Span) {
	if b, _ := current.Load().(tracerBox); b.t != nil {
		b.t.Export(s)
	}
}

// NewSpanID returns a random 8-byte span ID in hex.
func NewSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// OTLPExporter batches spans and posts them as OTLP/HTTP JSON
// (POST <endpoint>, normally http://collector:4318/v1/traces). A full queue
// drops spans rather than slowing requests; Dropped counts them.
type OTLPExporter struct {
	Endpoint string
	Service  string
	Client   *http.Client
	Dropped  atomic.Int64
	queue    chan Span
	done     chan struct{}
	mu       sync.RWMutex
	closed   bool
}

// NewOTLPExporter returns a running exporter; call Close to flush.
func NewOTLPExporter(endpoint, service string) *OTLPExporter {
	if service == "" {
		service = "proudauth"
	}
	// Spans go to the configured collector only: no proxy from the
	// environment and no redirects elsewhere.
	client := &http.Client{Timeout: 5 * time.Second,
		Transport:     &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 2},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	e := &OTLPExporter{Endpoint: endpoint, Service: service, Client: client,
		queue: make(chan Span, 4096), done: make(chan struct{})}
	go e.run()
	return e
}

// Export queues a span without blocking; after Close it drops the span.
func (e *OTLPExporter) Export(s Span) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		e.Dropped.Add(1)
		return
	}
	select {
	case e.queue <- s:
	default:
		e.Dropped.Add(1)
	}
}

// Close flushes queued spans and stops the exporter.
func (e *OTLPExporter) Close() {
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		close(e.queue)
	}
	e.mu.Unlock()
	<-e.done
}

func (e *OTLPExporter) run() {
	defer close(e.done)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	batch := make([]Span, 0, 256)
	flush := func() {
		if len(batch) > 0 {
			_ = e.send(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case s, ok := <-e.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, s)
			if len(batch) >= 256 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (e *OTLPExporter) send(spans []Span) error {
	body, err := json.Marshal(Encode(e.Service, spans))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := e.Client.Do(req)
	if err != nil {
		e.Dropped.Add(int64(len(spans)))
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		e.Dropped.Add(int64(len(spans)))
		return fmt.Errorf("otlp: status %d", res.StatusCode)
	}
	return nil
}

// Encode renders spans as an OTLP ExportTraceServiceRequest in JSON.
func Encode(service string, spans []Span) map[string]any {
	out := make([]map[string]any, 0, len(spans))
	for _, s := range spans {
		attrs := make([]map[string]any, 0, len(s.Attributes))
		for k, v := range s.Attributes {
			attrs = append(attrs, map[string]any{"key": k, "value": anyValue(v)})
		}
		sp := map[string]any{"traceId": s.TraceID, "spanId": s.SpanID, "name": s.Name, "kind": s.Kind,
			"startTimeUnixNano": strconv.FormatInt(s.Start.UnixNano(), 10), "endTimeUnixNano": strconv.FormatInt(s.End.UnixNano(), 10),
			"attributes": attrs, "status": map[string]any{"code": s.Status}}
		if s.ParentID != "" {
			sp["parentSpanId"] = s.ParentID
		}
		out = append(out, sp)
	}
	return map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]any{"stringValue": service}}}},
		"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": "proudauth"}, "spans": out}},
	}}}
}

func anyValue(v any) map[string]any {
	switch x := v.(type) {
	case int:
		return map[string]any{"intValue": strconv.Itoa(x)}
	case int64:
		return map[string]any{"intValue": strconv.FormatInt(x, 10)}
	case bool:
		return map[string]any{"boolValue": x}
	default:
		return map[string]any{"stringValue": fmt.Sprint(x)}
	}
}
