package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/webhooks"
)

// emergencyRoutes provides one audited surface to switch off a client,
// identity provider, organization, service principal, extension or grant class
// without database edits (SEC-020). Every control needs realm.emergency and a
// reason, is recorded in the emergency audit category (retained past ordinary
// audit retention) and raises the emergency_action security signal. Signing
// keys are handled by emergency rotation (POST /signing-key-rotations with
// mode=emergency).
func (a *App) emergencyRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/emergency/controls", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.emergency"); err != nil {
			return err
		}
		out := map[string]any{"realm_state": p.Realm.State, "disabled_grant_types": nonNil(p.Realm.DisabledGrantTypes)}
		ctx := r.Context()
		lists := []struct{ key, query string }{
			{"suspended_clients", `SELECT id FROM clients WHERE realm_id=$1 AND state='suspended' ORDER BY id LIMIT 200`},
			{"disabled_identity_providers", `SELECT id FROM identity_providers WHERE realm_id=$1 AND state='disabled' ORDER BY id LIMIT 200`},
			{"suspended_organizations", `SELECT id FROM organizations WHERE realm_id=$1 AND state='suspended' ORDER BY id LIMIT 200`},
			{"disabled_service_principals", `SELECT id FROM service_principals WHERE realm_id=$1 AND state='disabled' ORDER BY id LIMIT 200`},
			{"disabled_hooks", `SELECT id FROM hooks WHERE realm_id=$1 AND state='disabled' ORDER BY id LIMIT 200`},
			{"disabled_webhooks", `SELECT id FROM webhook_subscriptions WHERE realm_id=$1 AND state='disabled' ORDER BY id LIMIT 200`},
		}
		for _, l := range lists {
			ids, err := a.idList(ctx, l.query, p.Realm.ID)
			if err != nil {
				return err
			}
			out[l.key] = ids
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/emergency/controls", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.emergency"); err != nil {
			return err
		}
		var b struct {
			TargetType string `json:"target_type"`
			TargetID   string `json:"target_id"`
			Action     string `json:"action"`
			Reason     string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Action != "disable" && b.Action != "enable" {
			return problem.ErrValidation.WithField("action", "disable or enable")
		}
		if strings.TrimSpace(b.Reason) == "" || len(b.Reason) > 500 {
			return problem.ErrValidation.WithField("reason", "a reason of at most 500 characters is required")
		}
		if b.TargetID == "" {
			return problem.ErrValidation.WithField("target_id", "required")
		}
		off := b.Action == "disable"
		pick := func(disabled, enabled string) string {
			if off {
				return disabled
			}
			return enabled
		}
		// Every event the control records is filed in the emergency category with
		// the operator's reason, whichever service performs the change.
		ctx := audit.WithOverride(r.Context(), audit.Override{Category: "emergency", Reason: b.Reason})
		rid, actor := p.Realm.ID, p.AuditRef()
		var err error
		switch b.TargetType {
		case "grant_type":
			err = a.Realms.SetGrantDisabled(ctx, rid, b.TargetID, off, actor, b.Reason)
		case "client":
			err = a.Apps.SetClientState(ctx, rid, b.TargetID, pick("suspended", "active"), actor, b.Reason)
		case "identity_provider":
			if a.Federation == nil {
				return problem.ErrFeatureDisabled
			}
			err = a.Federation.SetState(ctx, rid, b.TargetID, pick("disabled", "active"), actor, b.Reason)
		case "organization":
			err = a.Orgs.SetState(ctx, rid, b.TargetID, pick("suspended", "active"), actor, b.Reason)
		case "service_principal":
			err = a.Machine.SetState(ctx, rid, b.TargetID, pick("disabled", "active"), actor)
		case "hook":
			err = a.Hooks.SetState(ctx, rid, b.TargetID, pick("disabled", "active"), actor, b.Reason)
		case "webhook":
			err = webhooks.NewService(a.D).SetState(ctx, rid, b.TargetID, pick("disabled", "active"), actor, b.Reason)
		default:
			return problem.ErrValidation.WithField("target_type",
				"grant_type, client, identity_provider, organization, service_principal, hook or webhook")
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"target_type": b.TargetType, "target_id": b.TargetID, "state": pick("disabled", "enabled")})
		return nil
	}))
}

// lifecycleRoutes expose the account lifecycle jobs (USR-015): a dry-run
// preview of what the next run would do, and per-account scheduled
// deactivation.
func (a *App) lifecycleRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/lifecycle/preview", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		plan, err := a.Users.PlanLifecycle(r.Context(), p.Realm.ID, p.Realm.Policy.LifecycleRules())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "batch_size": 100, "rules": plan})
		return nil
	}))
	mux.HandleFunc("PUT "+R+"/users/{user}/scheduled-deactivation", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.suspend"); err != nil {
			return err
		}
		var b struct {
			At     time.Time `json:"at"`
			Reason string    `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Users.ScheduleDeactivation(r.Context(), p.Realm.ID, r.PathValue("user"), &b.At, p.AuditRef(), b.Reason); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"user_id": r.PathValue("user"), "deactivate_at": b.At.UTC()})
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/users/{user}/scheduled-deactivation", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.suspend"); err != nil {
			return err
		}
		if err := a.Users.ScheduleDeactivation(r.Context(), p.Realm.ID, r.PathValue("user"), nil, p.AuditRef(), ""); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}

// externalIDRoutes manage connector-scoped external IDs (USR-017).
func (a *App) externalIDRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/users/{user}/external-ids", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		if _, err := a.Users.User(r.Context(), nil, p.Realm.ID, r.PathValue("user")); err != nil {
			return err
		}
		list, err := a.Users.ExternalIDs(r.Context(), p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("PUT "+R+"/users/{user}/external-ids/{source}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		var b struct {
			ExternalID string `json:"external_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Users.SetExternalID(r.Context(), p.Realm.ID, r.PathValue("user"), r.PathValue("source"), b.ExternalID, p.AuditRef()); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"source_system": r.PathValue("source"), "external_id": b.ExternalID})
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/users/{user}/external-ids/{source}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		if err := a.Users.RemoveExternalID(r.Context(), p.Realm.ID, r.PathValue("user"), r.PathValue("source"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/external-ids/{source}/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		user, err := a.Users.UserByExternalID(r.Context(), p.Realm.ID, r.PathValue("source"), r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"source_system": r.PathValue("source"), "external_id": r.PathValue("id"), "user_id": user})
		return nil
	}))
}

// consentRoutes give administrators a view of users' consents and manage
// client pre-authorization (APP-013).
func (a *App) consentRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/users/{user}/consents", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		if _, err := a.Users.User(r.Context(), nil, p.Realm.ID, r.PathValue("user")); err != nil {
			return err
		}
		list, err := a.Auth.Consents(r.Context(), p.Realm.ID, r.PathValue("user"), r.URL.Query().Get("history") == "true")
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("DELETE "+R+"/users/{user}/consents/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.write"); err != nil {
			return err
		}
		if err := a.Auth.RevokeConsent(r.Context(), p.Realm.ID, r.PathValue("user"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/clients/{client}/consent-preauthorizations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.read"); err != nil {
			return err
		}
		list, err := a.Auth.Preauthorizations(r.Context(), p.Realm.ID, r.PathValue("client"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/clients/{client}/consent-preauthorizations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		var b struct {
			OrganizationID string   `json:"organization_id"`
			Scopes         []string `json:"scopes"`
			Reason         string   `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		out, err := a.Auth.Preauthorize(r.Context(), p.Realm.ID, r.PathValue("client"), b.OrganizationID, b.Scopes, b.Reason, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/clients/{client}/consent-preauthorizations/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.clients.write"); err != nil {
			return err
		}
		if _, err := a.Auth.RevokePreauthorization(r.Context(), p.Realm.ID, r.PathValue("client"), r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}

// templateRoutes manage versioned organization onboarding templates (TEN-017).
func (a *App) templateRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/organization-templates", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.organizations.read"); err != nil {
			return err
		}
		list, err := a.Orgs.Templates(r.Context(), p.Realm.ID, r.URL.Query().Get("name"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/organization-templates", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.organizations.write"); err != nil {
			return err
		}
		var b struct {
			Name        string                        `json:"name"`
			Description string                        `json:"description"`
			Document    organization.TemplateDocument `json:"document"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		t, err := a.Orgs.SaveTemplate(r.Context(), p.Realm.ID, b.Name, b.Description, b.Document, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, t)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/organizations/{org}/template-applications", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.update"); err != nil {
			return err
		}
		var b struct {
			Template string `json:"template"`
			Version  int    `json:"version"`
			DryRun   bool   `json:"dry_run"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		// Applying can create roles, grants, service principals and webhooks
		// (whose secrets it returns): an MFA session, as for each of those.
		if !b.DryRun {
			if err := a.requireMFASession(p); err != nil {
				return err
			}
		}
		plan, err := a.Orgs.ApplyTemplate(r.Context(), p.Realm.ID, r.PathValue("org"), b.Template, b.Version, b.DryRun, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		if len(plan.WebhookSecrets) > 0 {
			w.Header().Set("Cache-Control", "no-store")
		}
		writeJSON(w, http.StatusOK, plan)
		return nil
	}))
}

// legalHoldRoutes manage audit legal holds (AUD-009).
func (a *App) legalHoldRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/audit-legal-holds", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.legal_hold"); err != nil {
			return err
		}
		list, err := audit.Holds(r.Context(), a.D.DB.Pool, p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/audit-legal-holds", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.legal_hold"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var b struct {
			OrganizationID string `json:"organization_id"`
			SubjectID      string `json:"subject_id"`
			Reason         string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		h, err := a.D.Audit.PlaceHold(r.Context(), a.D.DB, p.Realm.ID, b.OrganizationID, b.SubjectID, b.Reason, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, h)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/audit-legal-holds/{id}/release", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.legal_hold"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		if err := a.D.Audit.ReleaseHold(r.Context(), a.D.DB, p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}

// importedAuditRoutes import and list historical audit records from a source
// system (MIG-016). Imported records are kept apart from the server's own
// evidence and always reported as source "import", verified false.
func (a *App) importedAuditRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("POST "+R+"/audit-imports", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.import"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var b struct {
			SourceSystem string                 `json:"source_system"`
			Events       []audit.ImportedRecord `json:"events"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		resolve := func(ctx context.Context, ref string) (string, error) {
			o, err := a.Orgs.Resolve(ctx, p.Realm.ID, ref)
			if err != nil {
				return "", err
			}
			return o.ID, nil
		}
		sum, err := a.D.Audit.ImportHistory(r.Context(), a.D.DB, p.Realm.ID, b.SourceSystem, b.Events, resolve, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, sum)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/imported-audit-events", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.read"); err != nil {
			return err
		}
		q := r.URL.Query()
		f := audit.ImportedFilter{RealmID: p.Realm.ID, SourceSystem: q.Get("source_system"), SubjectID: q.Get("subject_id"),
			OrganizationID: q.Get("organization_id"), Type: q.Get("type"), BatchID: q.Get("batch_id")}
		for name, dst := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
			if v := q.Get(name); v != "" {
				t, err := time.Parse(time.RFC3339, v)
				if err != nil {
					return problem.ErrValidation.WithField(name, "an RFC 3339 time")
				}
				*dst = &t
			}
		}
		list, err := audit.ImportedEvents(r.Context(), a.D.DB.Pool, f)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
}

// reportedActivityRoutes let services report application activity (AUD-013). Reported
// events are filed apart from the server's own evidence: source
// "application", the reporting service named, types in the "app." namespace
// and a bounded, redacted metadata object.
func (a *App) reportedActivityRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("POST "+R+"/activity-events", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if p.IsUser() {
			return problem.ErrForbidden.WithDetail("activity is reported by services")
		}
		if err := a.requirePerm(r, p, "realm.activity.report"); err != nil {
			return err
		}
		var b struct {
			Type           string         `json:"type"`
			OccurredAt     *time.Time     `json:"occurred_at"`
			OrganizationID string         `json:"organization_id"`
			Subject        *audit.Ref     `json:"subject"`
			Outcome        string         `json:"outcome"`
			Metadata       map[string]any `json:"metadata"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if !activityType.MatchString(b.Type) {
			return problem.ErrValidation.WithField("type", "app.<name> with lowercase letters, digits, dots and underscores (at most 100 characters)")
		}
		switch b.Outcome {
		case "":
			b.Outcome = audit.Success
		case audit.Success, audit.Failure, audit.Denied:
		default:
			return problem.ErrValidation.WithField("outcome", "success, failure or denied")
		}
		if raw, _ := json.Marshal(b.Metadata); len(raw) > 4096 {
			return problem.ErrValidation.WithField("metadata", "at most 4 KiB")
		}
		now := a.D.Now()
		occurred := now
		if b.OccurredAt != nil {
			// Reported times are bounded so a service cannot backdate evidence
			// into sealed history or date it in the future.
			if b.OccurredAt.Before(now.Add(-24*time.Hour)) || b.OccurredAt.After(now.Add(5*time.Minute)) {
				return problem.ErrValidation.WithField("occurred_at", "within the last 24 hours")
			}
			occurred = *b.OccurredAt
		}
		if b.Subject != nil && b.Subject.Type != "user" && b.Subject.Type != "service_principal" {
			return problem.ErrValidation.WithField("subject.type", "user or service_principal")
		}
		if b.OrganizationID != "" {
			if _, err := a.Orgs.Get(r.Context(), nil, p.Realm.ID, b.OrganizationID); err != nil {
				return problem.ErrValidation.WithField("organization_id", "unknown organization")
			}
		}
		id, err := a.D.Audit.Record(r.Context(), a.D.DB.Pool, audit.Event{Type: b.Type, OccurredAt: occurred, RealmID: p.Realm.ID, OrgID: b.OrganizationID,
			Actor: p.AuditRef(), Subject: b.Subject, Outcome: b.Outcome, Source: "application", ReportingService: p.ClientID,
			Category: "application", ClientID: p.ClientID, Metadata: b.Metadata})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "source": "application", "reporting_service": p.ClientID})
		return nil
	}))
}

var activityType = regexp.MustCompile(`^app\.[a-z0-9_.]{1,96}$`)

func (a *App) idList(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := a.D.DB.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
