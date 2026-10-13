package observability

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestLogRedactionAndStandardFields covers OPS-001: secrets are redacted before
// serialization and every record carries component and event_code.
func TestLogRedactionAndStandardFields(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "info", "json")
	log.Info("token.issued", "client_secret", "s3cr3t-value", "note", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "outcome", "success")
	log.With("component", "worker").Warn("task failed", "event_code", "worker.task_failed", "refresh_token", "pa_rt_abcdef0123456789abcdef")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two records: %q", buf.String())
	}
	for _, l := range lines {
		if strings.Contains(l, "s3cr3t-value") || strings.Contains(l, "eyJzdWIiOiIxIn0") || strings.Contains(l, "pa_rt_abcdef") {
			t.Fatalf("secret serialized: %s", l)
		}
	}
	var first, second map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if first["component"] != "server" || first["event_code"] != "token.issued" || first["outcome"] != "success" {
		t.Fatalf("standard fields: %v", first)
	}
	if second["component"] != "worker" || second["event_code"] != "worker.task_failed" {
		t.Fatalf("explicit fields overridden: %v", second)
	}
}

// TestDebugWindow covers SEC-015: debug records are written only inside a
// time-limited window, only for its component, and still redacted.
func TestDebugWindow(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "info", "json")
	worker := log.With("component", "worker")
	log.Debug("closed window")
	if buf.Len() != 0 {
		t.Fatalf("debug record written without a window: %s", buf.String())
	}
	SetDebugWindow(time.Now().Add(time.Minute), "worker")
	defer SetDebugWindow(time.Time{}, "")
	log.Debug("other component")
	worker.Debug("scoped", "password", "hunter2")
	out := buf.String()
	if strings.Contains(out, "other component") || !strings.Contains(out, "scoped") {
		t.Fatalf("debug scope not applied: %s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("debug window bypassed redaction: %s", out)
	}
	buf.Reset()
	SetDebugWindow(time.Now().Add(-time.Second), "")
	worker.Debug("expired")
	if buf.Len() != 0 {
		t.Fatalf("expired window still logs: %s", buf.String())
	}
}
