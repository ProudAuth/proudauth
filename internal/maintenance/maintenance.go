// Package maintenance holds the operator maintenance switch (OPS-015).
//
// Modes:
//   - off: normal operation.
//   - restricted: sign-in, token issuance, verification, revocation and
//     emergency controls continue; administration, self-service and tenant
//     changes are refused, so configuration stays frozen during maintenance.
//   - unavailable: only health, discovery, JWKS, introspection, revocation and
//     logout are served, so resource servers keep validating existing tokens
//     and users can still end sessions.
//
// Refusals are a generic 503 problem with Retry-After and the operator's
// public message; they never describe internal topology.
package maintenance

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/proudbase/proudauth/internal/observability"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// Modes.
const (
	Off         = "off"
	Restricted  = "restricted"
	Unavailable = "unavailable"
)

// State is the current maintenance setting.
type State struct {
	Mode              string     `json:"mode"`
	Message           string     `json:"message,omitempty"`
	RetryAfterSeconds int        `json:"retry_after_seconds"`
	UpdatedAt         *time.Time `json:"updated_at,omitempty"`
	UpdatedBy         string     `json:"updated_by,omitempty"`
	// DebugUntil and DebugComponent describe the open debug logging window
	// (SEC-015); every node applies it on its next refresh.
	DebugUntil     *time.Time `json:"debug_until,omitempty"`
	DebugComponent string     `json:"debug_component,omitempty"`
}

// Get reads the state.
func Get(ctx context.Context, q storage.Querier) (State, error) {
	var s State
	var msg, by, comp *string
	err := q.QueryRow(ctx, `SELECT maintenance_mode, maintenance_message, retry_after_seconds, updated_at, updated_by, debug_until, debug_component
		FROM system_state`).Scan(&s.Mode, &msg, &s.RetryAfterSeconds, &s.UpdatedAt, &by, &s.DebugUntil, &comp)
	if err != nil {
		if storage.IsNoRows(err) {
			return State{Mode: Off}, nil
		}
		return State{Mode: Off}, err
	}
	if msg != nil {
		s.Message = *msg
	}
	if by != nil {
		s.UpdatedBy = *by
	}
	if comp != nil {
		s.DebugComponent = *comp
	}
	return s, nil
}

// MaxDebugWindow bounds a debug window: one hour in production, a day
// elsewhere (SEC-015).
func MaxDebugWindow(production bool) time.Duration {
	if production {
		return time.Hour
	}
	return 24 * time.Hour
}

// SetDebug opens a debug window for a duration and component ("" for all), or
// closes it when d is zero.
func SetDebug(ctx context.Context, q storage.Querier, d time.Duration, component string, production bool, now time.Time) error {
	if d < 0 || d > MaxDebugWindow(production) {
		return problem.ErrValidation.WithField("duration", "at most "+MaxDebugWindow(production).String())
	}
	if len(component) > 40 || strings.ContainsAny(component, " \t\r\n") {
		return problem.ErrValidation.WithField("component", "a component name")
	}
	var until *time.Time
	if d > 0 {
		u := now.Add(d)
		until = &u
	}
	_, err := q.Exec(ctx, `UPDATE system_state SET debug_until=$1, debug_component=nullif($2,'')`, until, component)
	return err
}

// Set validates and stores the state.
func Set(ctx context.Context, q storage.Querier, s State, actor string, now time.Time) error {
	if s.Mode != Off && s.Mode != Restricted && s.Mode != Unavailable {
		return problem.ErrValidation.WithField("mode", "off, restricted or unavailable")
	}
	// The message is shown to anonymous clients: plain text only, bounded.
	if utf8.RuneCountInString(s.Message) > 200 || strings.ContainsAny(s.Message, "<>\r\n") {
		return problem.ErrValidation.WithField("message", "plain text of at most 200 characters")
	}
	if s.RetryAfterSeconds < 0 || s.RetryAfterSeconds > 86400 {
		return problem.ErrValidation.WithField("retry_after_seconds", "between 0 and 86400")
	}
	_, err := q.Exec(ctx, `INSERT INTO system_state (id, maintenance_mode, maintenance_message, retry_after_seconds, updated_at, updated_by)
		VALUES (true, $1, nullif($2,''), $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET maintenance_mode=$1, maintenance_message=nullif($2,''), retry_after_seconds=$3, updated_at=$4, updated_by=$5`,
		s.Mode, s.Message, s.RetryAfterSeconds, now, actor)
	return err
}

// Cache serves the state to request handling with a short freshness bound, so
// every node observes a change within TTL without a query per request.
type Cache struct {
	TTL time.Duration
	mu  sync.Mutex
	st  State
	at  time.Time
}

// Current returns the cached state, refreshing it when stale. When the
// database cannot be read the last known state is kept.
func (c *Cache) Current(ctx context.Context, q storage.Querier) State {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < c.TTL {
		return c.st
	}
	if s, err := Get(ctx, q); err == nil {
		c.st = s
		if s.DebugUntil != nil {
			observability.SetDebugWindow(*s.DebugUntil, s.DebugComponent)
		} else {
			observability.SetDebugWindow(time.Time{}, "")
		}
	} else if c.st.Mode == "" {
		c.st = State{Mode: Off}
	}
	c.at = time.Now()
	return c.st
}

// Invalidate forces the next Current call to re-read the state.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

// Allowed reports whether a request may proceed in the mode.
func Allowed(mode, method, path string) bool {
	switch mode {
	case "", Off:
		return true
	case Restricted:
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			return true
		}
		return strings.HasPrefix(path, "/realms/") || strings.HasPrefix(path, "/.well-known/") ||
			strings.Contains(path, "/auth/transactions") || strings.Contains(path, "/emergency/") || reducesAccess(method, path)
	case Unavailable:
		if strings.HasPrefix(path, "/health/") || strings.HasPrefix(path, "/.well-known/") {
			return true
		}
		if strings.HasPrefix(path, "/realms/") {
			for _, suffix := range []string{"/jwks", "/oauth/introspect", "/oauth/revoke", "/oidc/logout"} {
				if strings.HasSuffix(path, suffix) {
					return true
				}
			}
			return strings.Contains(path, "/.well-known/")
		}
		return false
	}
	return false
}

// reducesAccess covers requests that only take access away (session and
// token revocation), which stay available while configuration is frozen.
func reducesAccess(method, path string) bool {
	if method == "DELETE" && strings.Contains(path, "/sessions") {
		return true
	}
	if method != "POST" {
		return false
	}
	for _, suffix := range []string{"/revoke", "/revocations", "/revoke-sessions", "/suspend", "/lock"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
