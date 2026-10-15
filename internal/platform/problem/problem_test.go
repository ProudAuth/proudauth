package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
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
