package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/platform/reqctx"
	"github.com/proudbase/proudauth/internal/ratelimit"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/ssf"
)

// ssfReceiverRoutes serve the Shared Signals receiver (ADV-007): the push
// endpoint registered transmitters deliver to, and their administration.
func (a *App) ssfReceiverRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /realms/{realm}/ssf/receivers/{id}/events", a.public(a.receiveSET))
	T := "/api/v1/realms/{realm}/ssf-transmitters"
	mux.HandleFunc("GET "+T, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		list, err := a.SSF.Transmitters(r.Context(), p.Realm.ID, p.Realm.Issuer)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+T, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		var in ssf.TransmitterInput
		if err := decode(r, &in); err != nil {
			return err
		}
		t, plain, err := a.SSF.RegisterTransmitter(r.Context(), p.Realm.ID, p.Realm.Issuer, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusCreated, map[string]any{"transmitter": t, "push_secret": plain})
		return nil
	}))
	mux.HandleFunc("GET "+T+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		t, err := a.SSF.Transmitter(r.Context(), p.Realm.ID, p.Realm.Issuer, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("PUT "+T+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		var in ssf.TransmitterInput
		if err := decode(r, &in); err != nil {
			return err
		}
		t, _, err := a.SSF.UpdateTransmitter(r.Context(), p.Realm.ID, p.Realm.Issuer, r.PathValue("id"), ver, in, false, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, t)
		return nil
	}))
	mux.HandleFunc("POST "+T+"/{id}/rotate-secret", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		t, plain, err := a.SSF.UpdateTransmitter(r.Context(), p.Realm.ID, p.Realm.Issuer, r.PathValue("id"), 0, ssf.TransmitterInput{}, true, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, t.Version)
		writeJSON(w, http.StatusOK, map[string]any{"transmitter": t, "push_secret": plain})
		return nil
	}))
	mux.HandleFunc("DELETE "+T+"/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		if err := a.SSF.DeleteTransmitter(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+T+"/{id}/events", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		if _, err := a.SSF.Transmitter(r.Context(), p.Realm.ID, p.Realm.Issuer, r.PathValue("id")); err != nil {
			return err
		}
		list, err := a.SSF.ReceivedEvents(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
}

// receiveSET is the RFC 8935 push endpoint for one registered transmitter.
func (a *App) receiveSET(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	// Bounded per transmitter and per network so a misbehaving or forged
	// sender cannot load the receiver; the budget fails closed.
	d, err := a.Limiter.Hit(r.Context(), ratelimit.Budget{Key: "ssf-push:" + r.PathValue("id"), Limit: 600, Window: time.Minute},
		ratelimit.Budget{Key: "ssf-push-ip:" + reqctx.From(r.Context()).ClientIP, Limit: 1200, Window: time.Minute})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, &ssf.PushError{Err: "temporarily_unavailable", Description: "try again later"})
		return nil
	}
	if !d.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, &ssf.PushError{Err: "too_many_requests", Description: "push rate exceeded"})
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil {
		return err
	}
	bearer := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		bearer = strings.TrimSpace(h[7:])
	}
	err = a.SSF.Receive(r.Context(), rlm.ID, rlm.Issuer, r.PathValue("id"), bearer, body, a.ssfLocalActions())
	var pe *ssf.PushError
	if errors.As(err, &pe) {
		writeJSON(w, pe.Status, pe)
		return nil
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (a *App) ssfLocalActions() ssf.LocalActions {
	return ssf.LocalActions{
		RevokeUserTx: func(ctx context.Context, tx pgx.Tx, realmID, userID, reason string, offline bool) error {
			_, err := a.Sessions.RevokeUserTx(ctx, tx, realmID, userID, reason, offline)
			return err
		},
		SuspendUserTx: func(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref, reason string) error {
			_, err := a.Users.SetStateTx(ctx, tx, realmID, userID, identity.StateSuspended, actor, reason)
			return err
		},
		MarkCompromised: a.Auth.MarkPasswordCompromised,
	}
}
