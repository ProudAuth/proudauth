// Package problem defines stable API error codes rendered as RFC 9457 problem
// details for custom APIs (API-007, API-008). Protocol endpoints use their own
// standard error formats instead.
package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// Error is a stable, client-safe error. Detail must never contain secrets.
type Error struct {
	Status     int               `json:"status"`
	Code       string            `json:"code"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail,omitempty"`
	Fields     map[string]string `json:"errors,omitempty"`
	RetryAfter time.Duration     `json:"-"`
	// Extensions carries machine-readable obligations (e.g. step-up requirements).
	Extensions map[string]any `json:"-"`
	cause      error
	// noCredentials marks a 401 for a request without credentials.
	noCredentials bool
}

func (e *Error) Error() string {
	msg := e.Code + ": " + e.Detail
	if len(e.Fields) > 0 {
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			msg += " [" + k + ": " + e.Fields[k] + "]"
		}
	}
	if e.cause != nil {
		return msg + ": " + e.cause.Error()
	}
	return msg
}

// Unwrap exposes the internal cause for logging only.
func (e *Error) Unwrap() error { return e.cause }

// With returns a copy carrying an internal cause (never rendered to clients).
func (e *Error) With(cause error) *Error {
	c := *e
	c.cause = cause
	return &c
}

// WithoutCredentials returns a copy for a request that carried no
// credentials at all: its challenge names the scheme without an error code
// (RFC 6750 section 3.1).
func (e *Error) WithoutCredentials() *Error {
	c := *e
	c.noCredentials = true
	return &c
}

// WithDetail returns a copy with a different client-safe detail.
func (e *Error) WithDetail(detail string) *Error {
	c := *e
	c.Detail = detail
	return &c
}

// WithDetailf returns a copy with a formatted client-safe detail.
func (e *Error) WithDetailf(format string, args ...any) *Error {
	c := *e
	c.Detail = fmt.Sprintf(format, args...)
	return &c
}

// WithField returns a copy with a field validation message.
func (e *Error) WithField(field, msg string) *Error {
	c := *e
	c.Fields = map[string]string{}
	for k, v := range e.Fields {
		c.Fields[k] = v
	}
	c.Fields[field] = msg
	return &c
}

// WithExtension returns a copy with an extension member.
func (e *Error) WithExtension(key string, v any) *Error {
	c := *e
	c.Extensions = map[string]any{}
	for k, val := range e.Extensions {
		c.Extensions[k] = val
	}
	c.Extensions[key] = v
	return &c
}

// WithRetryAfter returns a copy with throttling guidance.
func (e *Error) WithRetryAfter(d time.Duration) *Error {
	c := *e
	c.RetryAfter = d
	return &c
}

func newErr(status int, code, title string) *Error {
	return &Error{Status: status, Code: code, Title: title}
}

// Stable error codes.
var (
	ErrBadRequest          = newErr(http.StatusBadRequest, "invalid_request", "The request is invalid.")
	ErrValidation          = newErr(http.StatusUnprocessableEntity, "validation_failed", "One or more fields are invalid.")
	ErrUnauthenticated     = newErr(http.StatusUnauthorized, "unauthenticated", "Valid credentials are required.")
	ErrForbidden           = newErr(http.StatusForbidden, "forbidden", "The caller is not allowed to perform this action.")
	ErrNotFound            = newErr(http.StatusNotFound, "not_found", "The resource does not exist or is not visible to the caller.")
	ErrConflict            = newErr(http.StatusConflict, "conflict", "The request conflicts with current state.")
	ErrPrecondition        = newErr(http.StatusPreconditionFailed, "precondition_failed", "The resource version does not match.")
	ErrPreconditionNeeded  = newErr(http.StatusPreconditionRequired, "precondition_required", "An If-Match header is required.")
	ErrRateLimited         = newErr(http.StatusTooManyRequests, "rate_limited", "Too many requests. Retry later.")
	ErrUnavailable         = newErr(http.StatusServiceUnavailable, "unavailable", "A required dependency is unavailable.")
	ErrMaintenance         = newErr(http.StatusServiceUnavailable, "maintenance", "The service is under maintenance.")
	ErrMisdirected         = newErr(http.StatusMisdirectedRequest, "misdirected_request", "This host does not serve the requested resource.")
	ErrInternal            = newErr(http.StatusInternalServerError, "internal_error", "An internal error occurred.")
	ErrTooLarge            = newErr(http.StatusRequestEntityTooLarge, "payload_too_large", "The request is too large.")
	ErrUnsupportedMedia    = newErr(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
	ErrStepUpRequired      = newErr(http.StatusForbidden, "step_up_required", "Fresh or stronger authentication is required.")
	ErrRecentAuthRequired  = newErr(http.StatusForbidden, "recent_authentication_required", "Recent authentication is required for this action.")
	ErrConsentRequired     = newErr(http.StatusForbidden, "consent_required", "The user has not consented to this request for the client.")
	ErrMFARequired         = newErr(http.StatusForbidden, "mfa_required", "Multi-factor authentication is required.")
	ErrRecoveryRestricted  = newErr(http.StatusForbidden, "recovery_restricted", "This session started from a recovery factor: enroll a new factor and sign in with it first.")
	ErrTransactionInvalid  = newErr(http.StatusBadRequest, "transaction_invalid", "The authentication transaction cannot continue.")
	ErrTransactionExpired  = newErr(http.StatusGone, "transaction_expired", "The authentication transaction expired. Start again.")
	ErrCursorExpired       = newErr(http.StatusGone, "cursor_expired", "Events after the cursor are no longer retained. Resynchronize by reading the retained history from its beginning (no cursor).")
	ErrInvalidCredentials  = newErr(http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are not valid.")
	ErrInvalidProof        = newErr(http.StatusBadRequest, "invalid_proof", "The supplied proof is not valid.")
	ErrUnexpectedStep      = newErr(http.StatusConflict, "unexpected_step", "This step is not currently expected.")
	ErrPasswordPolicy      = newErr(http.StatusUnprocessableEntity, "password_policy", "The password does not satisfy policy.")
	ErrLastOwner           = newErr(http.StatusConflict, "last_owner", "The organization must keep at least one active owner.")
	ErrGrantCeiling        = newErr(http.StatusForbidden, "grant_ceiling_exceeded", "The requested grant exceeds the caller's delegable permissions.")
	ErrImpersonationDenied = newErr(http.StatusForbidden, "impersonation_denied", "Support access is not permitted for this request.")
	ErrImpersonationToken  = newErr(http.StatusForbidden, "impersonation_restricted", "This operation is not available during support access.")
	ErrFeatureDisabled     = newErr(http.StatusNotFound, "feature_disabled", "This capability is not enabled.")
	ErrInvitationInvalid   = newErr(http.StatusBadRequest, "invitation_invalid", "The invitation cannot be used.")
	ErrLastMethod          = newErr(http.StatusConflict, "last_sign_in_method", "The last viable sign-in or recovery method cannot be removed.")
	ErrIdempotencyMismatch = newErr(http.StatusUnprocessableEntity, "idempotency_key_reused", "The idempotency key was used with a different request.")
	ErrAccountState        = newErr(http.StatusForbidden, "account_unavailable", "The account cannot be used for this action.")
	ErrSSORequired         = newErr(http.StatusForbidden, "sso_required", "This organization requires its enterprise sign-in provider.")
	ErrUpstreamUnavailable = newErr(http.StatusServiceUnavailable, "upstream_unavailable", "The upstream identity provider is unavailable. Retry later.")
	// ErrCodeFactorsDisabled refuses a TOTP, HOTP or recovery-code proof of an
	// account whose consecutive code-factor failures reached
	// security.second_factor.failure_disable_at (SEC-006, owner decision 10).
	ErrCodeFactorsDisabled = newErr(http.StatusForbidden, "code_factors_disabled", "Code factors are turned off for this account after too many failed attempts: sign in with a passkey or reset the password from the account's email address.")
)

// DefaultRetryAfter is the Retry-After of a 429 or 503 response that names no
// delay of its own, so every throttled or unavailable answer tells the client
// when to try again (API-009).
const DefaultRetryAfter = 2 * time.Second

// SetRetryAfter sets the Retry-After header of a response with this status:
// d in whole seconds, rounded up, or DefaultRetryAfter for a 429 or 503 that
// names no positive delay. Any other status without a delay gets no header.
// Every error writer, problem details and the protocol formats alike, uses it.
func SetRetryAfter(h http.Header, status int, d time.Duration) {
	if d <= 0 {
		if status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
			return
		}
		d = DefaultRetryAfter
	}
	h.Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
}

// As extracts a *Error from err.
func As(err error) (*Error, bool) {
	var pe *Error
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// Is reports whether err carries the same stable code as target.
func Is(err error, target *Error) bool {
	pe, ok := As(err)
	return ok && pe.Code == target.Code
}

// Write renders err as application/problem+json. Unknown errors become a generic
// internal error with no detail (no stack traces or secrets).
func Write(w http.ResponseWriter, requestID string, err error) {
	pe, ok := As(err)
	if !ok {
		pe = ErrInternal
	}
	body := map[string]any{
		"type":   "https://proudauth.com/problems/" + pe.Code,
		"title":  pe.Title,
		"status": pe.Status,
		"code":   pe.Code,
	}
	if pe.Detail != "" {
		body["detail"] = pe.Detail
	}
	if len(pe.Fields) > 0 {
		body["errors"] = pe.Fields
	}
	if requestID != "" {
		body["request_id"] = requestID
	}
	for k, v := range pe.Extensions {
		if _, exists := body[k]; !exists {
			body[k] = v
		}
	}
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	SetRetryAfter(h, pe.Status, pe.RetryAfter)
	if pe.Status == http.StatusUnauthorized {
		if pe.noCredentials {
			h.Set("WWW-Authenticate", `Bearer`)
		} else {
			h.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
	}
	w.WriteHeader(pe.Status)
	_ = json.NewEncoder(w).Encode(body)
}
