package httpapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/webhooks"
)

// messagingRoutes covers notification preferences (MSG-010), provider
// delivery feedback (MSG-007) and delivery configuration checks (MSG-012).
func (a *App) messagingRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/me/notification-preferences", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		prefs, err := a.Notify.Preferences(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"preferences": prefs, "mandatory_notices_note": "security and account notices are always delivered"})
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/me/notification-preferences", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Preferences map[string]bool `json:"preferences"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Notify.SetPreferences(r.Context(), p.Realm.ID, p.SubjectID, b.Preferences, p.AuditRef()); err != nil {
			return err
		}
		prefs, err := a.Notify.Preferences(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"preferences": prefs})
		return nil
	}))
	// Provider feedback is authenticated with a Standard Webhooks signature
	// over the raw body using delivery.email.events_secret (MSG-007).
	mux.HandleFunc("POST "+R+"/delivery-events", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realmT) error {
		ref := a.D.Cfg.Delivery.Email.EventsSecret
		if ref == "" {
			return problem.ErrFeatureDisabled
		}
		sec, err := configuration.ResolveSecret(ref)
		if err != nil || sec == "" {
			return problem.ErrFeatureDisabled
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return problem.ErrTooLarge
		}
		if err := webhooks.VerifySignature(sec, r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"),
			body, a.D.Now(), 5*time.Minute); err != nil {
			return problem.ErrUnauthenticated
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var b struct {
			Events []notification.DeliveryEvent `json:"events"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		n, err := a.Notify.RecordDeliveryEvents(r.Context(), rlm.ID, b.Events)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"applied": n})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/notification-settings/check", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.write"); err != nil {
			return err
		}
		out := map[string]any{"email_adapter": a.D.Cfg.Delivery.Email.Adapter}
		switch smtp := a.Notify.Email.(type) {
		case *notification.SMTPSender:
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			stage, err := smtp.Check(ctx)
			out["ok"], out["stage"] = err == nil, stage
			if err != nil {
				// Only the failing stage is reported; server responses and
				// credentials stay in the operator log (MSG-012, SEC-015).
				a.D.Log.Warn("smtp check failed", "component", "notification", "event_code", "smtp.check_failed", "stage", stage, "error", err)
			}
		default:
			out["ok"] = a.Notify.DevSink
			out["stage"] = "not_applicable"
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}

// checkSenderDomain enforces approved sender domains (MSG-005): an
// organization sender must use one of its verified domains; a realm sender
// must use an operator-approved domain or the configured From domain.
func (a *App) checkSenderDomain(ctx context.Context, p *Principal, orgID, address string) error {
	if address == "" {
		return nil
	}
	c, _, err := canonical.Email(address)
	if err != nil {
		return problem.ErrValidation.WithField("sender_address", "invalid address")
	}
	domain := canonical.EmailDomain(c)
	if orgID != "" {
		verified, err := a.Orgs.VerifiedDomains(ctx, p.Realm.ID, orgID)
		if err != nil {
			return err
		}
		if !slices.Contains(verified, domain) {
			return problem.ErrValidation.WithField("sender_address", "use an address at one of the organization's verified domains")
		}
		return nil
	}
	var allowed []string
	for _, d := range a.D.Cfg.Delivery.Email.AllowedSenderDomains {
		allowed = append(allowed, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), "."))
	}
	if from := a.D.Cfg.Delivery.Email.From; strings.Contains(from, "@") {
		allowed = append(allowed, strings.ToLower(from[strings.LastIndexByte(from, '@')+1:]))
	}
	if !slices.Contains(allowed, domain) {
		return problem.ErrValidation.WithField("sender_address", "the sender domain is not approved by the operator (delivery.email.allowed_sender_domains)")
	}
	return nil
}
