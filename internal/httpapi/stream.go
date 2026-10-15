package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// sessionEventRoutes exposes the session and access change stream (SES-019).
// Consistency model: at-least-once, gap-free, ordered by commit horizon;
// history is retained for 7 days after dispatch; a cursor older than the
// retained history returns 410 cursor_expired and the consumer must resync.
func (a *App) sessionEventRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/session-events", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.session_events.read"); err != nil {
			return err
		}
		q := r.URL.Query()
		ctx := r.Context()
		if q.Get("from") == "now" {
			head, err := events.Head(ctx, a.D.DB.Pool, p.Realm.ID)
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, map[string]any{"events": []any{}, "next_cursor": head.String()})
			return nil
		}
		pos, err := events.ParsePosition(q.Get("cursor"))
		if err != nil {
			return problem.ErrValidation.WithField("cursor", "invalid cursor")
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		wait, _ := strconv.Atoi(q.Get("wait"))
		if wait < 0 || wait > 25 {
			return problem.ErrValidation.WithField("wait", "0..25 seconds")
		}
		deadline := time.Now().Add(time.Duration(wait) * time.Second)
		lastCheck := time.Now()
		for {
			// A waiting consumer never outlives its authorization (TEST-062):
			// the permission and the session are re-checked while it waits,
			// and the wait ends as soon as either is gone.
			recheck := func() error {
				lastCheck = time.Now()
				if p.SessionID != "" {
					if _, err := a.Sessions.Active(ctx, nil, p.Realm.ID, p.SessionID); err != nil {
						return problem.ErrUnauthenticated
					}
				}
				if !a.can(ctx, p, "realm.session_events.read", a.realmScope(p)) {
					return problem.ErrForbidden.WithDetail("the permission to read session events was revoked")
				}
				return nil
			}
			if time.Since(lastCheck) >= 2*time.Second {
				if err := recheck(); err != nil {
					return err
				}
			}
			evs, next, err := events.Read(ctx, a.D.DB.Pool, p.Realm.ID, pos, limit)
			if errors.Is(err, events.ErrCursorExpired) {
				return problem.ErrCursorExpired
			}
			if err != nil {
				return err
			}
			// Events found after waiting are released only to a consumer
			// that is still authorized now.
			if len(evs) > 0 && wait > 0 && time.Since(lastCheck) > 0 {
				if err := recheck(); err != nil {
					return err
				}
			}
			if len(evs) > 0 || !time.Now().Before(deadline) {
				writeJSON(w, http.StatusOK, map[string]any{"events": evs, "next_cursor": next.String()})
				return nil
			}
			// Long poll: wait briefly for new commits.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
	}))
}
