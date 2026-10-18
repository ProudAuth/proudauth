package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func render(t *testing.T, err error) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	Write(rec, "req-123", err)
	var body map[string]any
	if e := json.Unmarshal(rec.Body.Bytes(), &body); e != nil {
		t.Fatalf("body is not JSON: %v: %s", e, rec.Body)
	}
	return rec, body
}

// TestProblemDetailsContract covers API-007: custom API errors render as RFC
// 9457 problem details with a stable code, the request ID and field errors;
// internal causes, unknown errors and anything secret they carry never reach
// the client.
func TestProblemDetailsContract(t *testing.T) {
	rec, body := render(t, ErrValidation.WithField("email", "not an email address"))
	if rec.Code != 422 || rec.Header().Get("Content-Type") != "application/problem+json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d headers %v", rec.Code, rec.Header())
	}
	if body["code"] != "validation_failed" || body["status"] != float64(422) || body["type"] != "https://proudauth.com/problems/validation_failed" ||
		body["title"] == "" || body["request_id"] != "req-123" {
		t.Fatalf("problem members: %v", body)
	}
	if fields, _ := body["errors"].(map[string]any); fields["email"] != "not an email address" {
		t.Fatalf("field errors: %v", body["errors"])
	}

	leak := "dial tcp 10.0.0.5:5432: password=hunter2 at storage.go:81"
	for name, err := range map[string]error{
		"unknown error":          errors.New(leak),
		"wrapped unknown error":  fmt.Errorf("query failed: %w", errors.New(leak)),
		"problem with its cause": ErrForbidden.With(errors.New(leak)),
	} {
		rec, body := render(t, err)
		if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "storage.go") || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Fatalf("%s: internals in the response: %s", name, rec.Body)
		}
		if name == "problem with its cause" {
			if rec.Code != 403 || body["code"] != "forbidden" {
				t.Fatalf("%s: %d %v", name, rec.Code, body)
			}
			continue
		}
		if rec.Code != 500 || body["code"] != "internal_error" || body["detail"] != nil {
			t.Fatalf("%s: %d %v", name, rec.Code, body)
		}
	}
	// The stable code survives wrapping, so handlers can match on it.
	if !Is(fmt.Errorf("context: %w", ErrLastOwner.WithDetail("x")), ErrLastOwner) {
		t.Fatal("stable code lost through wrapping")
	}
}

// TestAuthenticationErrorStatuses covers API-008 at the rendering layer:
// missing or invalid credentials are 401 with a Bearer challenge,
// authenticated refusals are 403 without one, and concealed resources are a
// plain 404.
func TestAuthenticationErrorStatuses(t *testing.T) {
	for _, tc := range []struct {
		err       *Error
		status    int
		challenge bool
	}{
		{ErrUnauthenticated, 401, true},
		{ErrInvalidCredentials, 401, true},
		{ErrForbidden, 403, false},
		{ErrMFARequired, 403, false},
		{ErrStepUpRequired, 403, false},
		{ErrNotFound, 404, false},
	} {
		rec, body := render(t, tc.err)
		if rec.Code != tc.status || body["code"] != tc.err.Code {
			t.Errorf("%s: status %d body %v", tc.err.Code, rec.Code, body)
		}
		if got := strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer"); got != tc.challenge {
			t.Errorf("%s: WWW-Authenticate %q", tc.err.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

// TestRetryAfterOnThrottlingAndUnavailable covers API-009 and the API
// conventions' rule that 429 and 503 responses include Retry-After: a
// problem that names a delay keeps it (rounded up to whole seconds), a 429 or
// 503 that names none gets DefaultRetryAfter, and other statuses get no
// header unless they name a delay.
func TestRetryAfterOnThrottlingAndUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *Error
		want string
	}{
		{"429 without a delay", ErrRateLimited.WithDetail("verification was requested too recently"), "2"},
		{"503 without a delay", ErrUnavailable, "2"},
		{"maintenance without a delay", ErrMaintenance, "2"},
		{"upstream unavailable without a delay", ErrUpstreamUnavailable, "2"},
		{"429 with a delay", ErrRateLimited.WithRetryAfter(90 * time.Second), "90"},
		{"503 with a fractional delay rounds up", ErrUnavailable.WithRetryAfter(1500 * time.Millisecond), "2"},
		{"a delay under a second is one second", ErrRateLimited.WithRetryAfter(time.Nanosecond), "1"},
		{"a negative delay is the default", ErrRateLimited.WithRetryAfter(-time.Second), "2"},
		{"409 without a delay", ErrConflict, ""},
		{"404 without a delay", ErrNotFound, ""},
		{"500 without a delay", ErrInternal, ""},
	} {
		rec, _ := render(t, tc.err)
		if got := rec.Header().Get("Retry-After"); got != tc.want {
			t.Errorf("%s: Retry-After %q, want %q", tc.name, got, tc.want)
		}
	}
	if DefaultRetryAfter < time.Second || DefaultRetryAfter > 5*time.Second {
		t.Fatalf("DefaultRetryAfter %v is outside 1-5 s", DefaultRetryAfter)
	}
	h := http.Header{}
	SetRetryAfter(h, http.StatusBadRequest, 0)
	if h.Get("Retry-After") != "" {
		t.Fatalf("400 without a delay got Retry-After %q", h.Get("Retry-After"))
	}
	SetRetryAfter(h, http.StatusServiceUnavailable, 0)
	if h.Get("Retry-After") != "2" {
		t.Fatalf("503 without a delay got Retry-After %q", h.Get("Retry-After"))
	}
}
