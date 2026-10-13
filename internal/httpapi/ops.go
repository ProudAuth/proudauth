package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/jobs"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/webhooks"
)

func (a *App) opsRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	wh := webhooks.NewService(a.D)
	js := jobs.NewService(a.D)

	// ---------- webhooks (EXT-001..) ----------
	mux.HandleFunc("GET "+R+"/webhooks", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.read"); err != nil {
			return err
		}
		list, err := wh.List(r.Context(), p.Realm.ID, r.URL.Query().Get("organization_id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list, "event_types": webhooks.EventTypes})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/webhooks", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.write"); err != nil {
			return err
		}
		var in webhooks.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		sub, plain, err := wh.Create(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"subscription": sub, "signing_secret": plain, "notice": "The signing secret is shown only once."})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/webhooks/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.read"); err != nil {
			return err
		}
		sub, err := wh.Get(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, sub.Version)
		writeJSON(w, http.StatusOK, sub)
		return nil
	}))
	mux.HandleFunc("PATCH "+R+"/webhooks/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.write"); err != nil {
			return err
		}
		var b webhooks.Patch
		if err := decode(r, &b); err != nil {
			return err
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		// Plugin parts change with their plugin (EXT-014).
		if err := wh.GuardManual(r.Context(), p.Realm.ID, r.PathValue("id")); err != nil {
			return err
		}
		sub, err := wh.Update(r.Context(), p.Realm.ID, r.PathValue("id"), ver, b, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, sub.Version)
		writeJSON(w, http.StatusOK, sub)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/webhooks/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.write"); err != nil {
			return err
		}
		if err := wh.GuardManual(r.Context(), p.Realm.ID, r.PathValue("id")); err != nil {
			return err
		}
		if err := wh.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/webhooks/{id}/rotate-secret", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.write"); err != nil {
			return err
		}
		plain, err := wh.RotateSecret(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"signing_secret": plain, "previous_secret_valid_for_seconds": 86400})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/webhooks/{id}/backlog", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.read"); err != nil {
			return err
		}
		b, err := wh.Backlog(r.Context(), p.Realm.ID, r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, b)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/webhooks/{id}/deliveries", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.read"); err != nil {
			return err
		}
		after, err := a.pageAfter(r)
		if err != nil {
			return err
		}
		var at *time.Time
		id := ""
		if after != nil {
			at, id = &after.At, after.ID
		}
		limit := a.pageLimit(r)
		list, err := wh.Deliveries(r.Context(), p.Realm.ID, r.PathValue("id"), limit+1, at, id)
		if err != nil {
			return err
		}
		var next *keyset
		if len(list) > limit {
			list = list[:limit]
			next = &keyset{At: list[limit-1].CreatedAt, ID: list[limit-1].ID}
		}
		a.writePage(w, r, list, next)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/webhooks/{id}/deliveries/{delivery}/replay", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.webhooks.write"); err != nil {
			return err
		}
		if err := wh.Replay(r.Context(), p.Realm.ID, r.PathValue("id"), r.PathValue("delivery"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusAccepted)
		return nil
	}))

	// ---------- asynchronous jobs: exports and imports (API-011) ----------
	enqueueProtected := func(r *http.Request, p *Principal, typ, org string, input, protected map[string]any, dry bool) (string, error) {
		var id string
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			id, err = js.CreateTx(r.Context(), tx, jobs.Spec{RealmID: p.Realm.ID, OrganizationID: org, Type: typ, Input: input, DryRun: dry,
				Requester: p.AuditRef(), IdempotencyKey: r.Header.Get("Idempotency-Key"), ProtectedInput: protected})
			return err
		})
		return id, err
	}
	enqueue := func(r *http.Request, p *Principal, typ, org string, input map[string]any, dry bool) (string, error) {
		return enqueueProtected(r, p, typ, org, input, nil, dry)
	}
	mux.HandleFunc("POST "+R+"/me/exports", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		id, err := enqueue(r, p, "user.export", "", map[string]any{"user_id": p.SubjectID}, false)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/user-imports", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.import"); err != nil {
			return err
		}
		// Records are validated strictly here (unknown fields and wrong types are
		// rejected before queuing). They carry password verifiers and contact data,
		// so they travel as protected job input: encrypted at rest, never returned
		// by GET /jobs, erased when the job finishes.
		var b struct {
			Format                 string                  `json:"format"`
			SourceSystem           string                  `json:"source_system"`
			Users                  []identity.ImportRecord `json:"users"`
			DryRun                 bool                    `json:"dry_run"`
			TrustEmailVerification bool                    `json:"trust_email_verification"`
			VerificationReason     string                  `json:"verification_reason"`
			AllowOwnerRoles        bool                    `json:"allow_owner_roles"`
			// ImportTOTP authorizes carrying TOTP seeds over (MIG-007).
			ImportTOTP bool `json:"import_totp"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.SourceSystem == "" || len(b.Users) == 0 || len(b.Users) > 1000 {
			return problem.ErrValidation.WithDetail("source_system and 1..1000 users are required")
		}
		if !identity.ValidSourceSystem(b.SourceSystem) {
			return problem.ErrValidation.WithField("source_system", "lowercase letters, digits, '.', '_' or '-', at most 63 characters")
		}
		// The records' format is declared, not inferred from the source name (MIG-002).
		if b.Format == "" {
			b.Format = identity.ImportFormatV1
		}
		if _, ok := identity.LookupImportFormat(b.Format); !ok {
			return problem.ErrValidation.WithField("format", "unsupported import format; GET /user-import-formats lists the supported formats")
		}
		if b.TrustEmailVerification {
			// Trusting the source's verification is a bulk verification override (USR-005).
			if err := a.requirePerm(r, p, "realm.users.verification.override"); err != nil {
				return err
			}
			if len(b.VerificationReason) < 10 {
				return problem.ErrValidation.WithField("verification_reason", "a reason (at least 10 characters) is required to trust upstream verification")
			}
		}

		if b.ImportTOTP {
			// Factor seeds are credentials: importing them needs credential
			// authority and an MFA session.
			if err := a.requirePerm(r, p, "realm.users.credentials.manage"); err != nil {
				return err
			}
			if err := a.requireMFASession(p); err != nil {
				return err
			}
		}
		// Required actions on imported accounts need the authority they
		// need on existing ones (AUT-018); the worker checks again.
		for _, perm := range identity.ImportPermissions(b.Users) {
			if err := a.requirePerm(r, p, perm); err != nil {
				return err
			}
		}
		id, err := enqueueProtected(r, p, "user.import", "", map[string]any{"format": b.Format, "source_system": b.SourceSystem, "user_count": len(b.Users),
			"trust_email_verification": b.TrustEmailVerification, "verification_reason": b.VerificationReason, "allow_owner_roles": b.AllowOwnerRoles,
			"import_totp": b.ImportTOTP},
			map[string]any{"users": b.Users}, b.DryRun)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id, "dry_run": b.DryRun})
		return nil
	}))
	// Bulk user operations (USR-016): one action over up to 1000 accounts in a
	// checkpointed job with a per-record report; Idempotency-Key makes a
	// retried submission return the same job.
	mux.HandleFunc("POST "+R+"/user-bulk-operations", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Action         string   `json:"action"`
			UserIDs        []string `json:"user_ids"`
			Reason         string   `json:"reason"`
			RequiredAction string   `json:"required_action"`
			DryRun         bool     `json:"dry_run"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		perm, ok := identity.BulkActions[b.Action]
		if !ok {
			return problem.ErrValidation.WithField("action", "suspend, reactivate, lock, revoke_sessions or add_required_action")
		}
		if err := a.requirePerm(r, p, perm); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, id := range b.UserIDs {
			if id == "" || seen[id] {
				return problem.ErrValidation.WithField("user_ids", "IDs must be non-empty and unique")
			}
			seen[id] = true
		}
		if len(b.UserIDs) == 0 || len(b.UserIDs) > 1000 {
			return problem.ErrValidation.WithField("user_ids", "1 to 1000 accounts per job")
		}
		if len(strings.TrimSpace(b.Reason)) < 5 || len(b.Reason) > 500 {
			return problem.ErrValidation.WithField("reason", "a reason of 5 to 500 characters is required")
		}
		if b.Action == "add_required_action" && !identity.ValidRequiredAction(b.RequiredAction) {
			return problem.ErrValidation.WithField("required_action", "a supported required action")
		}
		if perm := identity.RequiredActionPermission(b.RequiredAction); b.Action == "add_required_action" && perm != "" {
			if err := a.requirePerm(r, p, perm); err != nil {
				return err
			}
		}
		ids := make([]any, len(b.UserIDs))
		for i, id := range b.UserIDs {
			ids[i] = id
		}
		id, err := enqueue(r, p, "user.bulk", "", map[string]any{"action": b.Action, "user_ids": ids, "reason": b.Reason,
			"required_action": b.RequiredAction, "user_count": len(ids)}, b.DryRun)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id, "dry_run": b.DryRun})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/audit-exports", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.export"); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
			return err
		}
		var b struct {
			OrganizationID       string `json:"organization_id"`
			From                 string `json:"from"`
			To                   string `json:"to"`
			ImpersonationGrantID string `json:"impersonation_grant_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		id, err := enqueue(r, p, "audit.export", b.OrganizationID, map[string]any{"from": b.From, "to": b.To, "impersonation_grant_id": b.ImpersonationGrantID}, false)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id})
		return nil
	}))
	// Portable exit (OSS-008, MIG-014): the realm's data as NDJSON, from a job
	// whose result downloads once the requester still holds the permission.
	mux.HandleFunc("POST "+R+"/data-exports", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.data.export"); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
			return err
		}
		id, err := enqueue(r, p, "realm.export", "", nil, false)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/configuration/exports", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.configuration.export"); err != nil {
			return err
		}
		id, err := enqueue(r, p, "config.export", "", nil, false)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/configuration/validate", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		// Validation is the read-only half of an import (dry run).
		if err := a.requirePerm(r, p, "realm.configuration.import"); err != nil {
			return err
		}
		var doc ConfigDocument
		if err := decode(r, &doc); err != nil {
			return err
		}
		// The plan reports everything the import would refuse, including
		// the reviewed policy revision and missing authority.
		plan, _ := a.reviewConfig(r, p, doc)
		writeJSON(w, http.StatusOK, plan)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/configuration/imports", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.configuration.import"); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
			return err
		}
		var doc ConfigDocument
		if err := decode(r, &doc); err != nil {
			return err
		}
		plan, denied := a.reviewConfig(r, p, doc)
		dryRun := r.URL.Query().Get("dry_run") == "true"
		// An import needs the authority each change needs through the API
		// (ARC-008): the import permission alone never stands in for it. A
		// real import is refused as the API would refuse the change; a dry
		// run reports the missing authority in its plan.
		if len(denied) > 0 && !dryRun {
			a.recordDenial(r, p, denied[0], "", false)
			return problem.ErrForbidden
		}
		if len(plan.Errors) > 0 || dryRun {
			status := http.StatusOK
			if len(plan.Errors) > 0 {
				status = http.StatusUnprocessableEntity
			}
			writeJSON(w, status, plan)
			return nil
		}
		applied, err := a.applyConfig(r, p, doc, plan)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "applied": applied.Applied, "client_secrets": applied.Secrets})
		return nil
	}))

	// ---------- notifications (MSG-005, MSG-012) ----------
	mux.HandleFunc("GET "+R+"/notification-settings", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.read"); err != nil {
			return err
		}
		// organization_id selects an organization's settings (and its tag).
		cur := a.notificationSettings(r.Context(), p.Realm.ID, r.URL.Query().Get("organization_id"))
		w.Header().Set("ETag", contentTag(cur))
		writeJSON(w, http.StatusOK, map[string]any{"sender_address": cur["sender_address"], "sender_name": cur["sender_name"], "reply_to": cur["reply_to"],
			"default_locale": cur["default_locale"], "adapter": a.D.Cfg.Delivery.Email.Adapter})
		return nil
	}))
	mux.HandleFunc("PATCH "+R+"/notification-settings", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.write"); err != nil {
			return err
		}
		// PATCH semantics: omitted fields are unchanged; an empty string clears.
		var b struct {
			SenderAddress  *string `json:"sender_address"`
			SenderName     *string `json:"sender_name"`
			ReplyTo        *string `json:"reply_to"`
			DefaultLocale  *string `json:"default_locale"`
			OrganizationID string  `json:"organization_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		for field, v := range map[string]*string{"sender_address": b.SenderAddress, "reply_to": b.ReplyTo} {
			if v != nil && *v != "" {
				if _, _, err := canonical.Email(*v); err != nil {
					return problem.ErrValidation.WithField(field, "invalid address")
				}
			}
		}
		if b.SenderAddress != nil {
			if err := a.checkSenderDomain(r.Context(), p, b.OrganizationID, *b.SenderAddress); err != nil {
				return err
			}
		}
		if b.SenderName != nil && (len(*b.SenderName) > 100 || strings.ContainsAny(*b.SenderName, "\r\n")) {
			return problem.ErrValidation.WithField("sender_name", "at most 100 characters, no line breaks")
		}
		if b.DefaultLocale != nil && (len(*b.DefaultLocale) > 35 || strings.ContainsAny(*b.DefaultLocale, " \r\n")) {
			return problem.ErrValidation.WithField("default_locale", "invalid language tag")
		}
		if err := checkContentTag(r, a.notificationSettings(r.Context(), p.Realm.ID, b.OrganizationID)); err != nil {
			return err
		}
		if err := a.Notify.UpdateSettings(r.Context(), p.Realm.ID, notification.SettingsPatch{OrganizationID: b.OrganizationID, SenderAddress: b.SenderAddress,
			SenderName: b.SenderName, ReplyTo: b.ReplyTo, DefaultLocale: b.DefaultLocale}, p.AuditRef()); err != nil {
			return err
		}
		// Respond only after the transaction committed.
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/templates", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.read"); err != nil {
			return err
		}
		rows, err := a.D.DB.Pool.Query(r.Context(), `SELECT id, coalesce(organization_id,''), event_type, locale, subject, body_text, version FROM notification_templates
			WHERE realm_id=$1 AND state='active' ORDER BY event_type, locale`, p.Realm.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, org, ev, loc, subj, body string
			var ver int
			if err := rows.Scan(&id, &org, &ev, &loc, &subj, &body, &ver); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": id, "organization_id": org, "event_type": ev, "locale": loc, "subject": subj, "body_text": body, "version": ver})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out, "variables": notification.Variables})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/templates", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.write"); err != nil {
			return err
		}
		var b struct {
			OrganizationID string `json:"organization_id"`
			EventType      string `json:"event_type"`
			Locale         string `json:"locale"`
			Subject        string `json:"subject"`
			BodyText       string `json:"body_text"`
			BodyHTML       string `json:"body_html"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		id, err := a.Notify.ReplaceTemplate(r.Context(), p.Realm.ID, notification.TemplateInput{OrganizationID: b.OrganizationID, EventType: b.EventType,
			Locale: b.Locale, Subject: b.Subject, BodyText: b.BodyText, BodyHTML: b.BodyHTML}, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/templates/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.write"); err != nil {
			return err
		}
		if err := a.Notify.DisableTemplate(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/notification-tests", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.write"); err != nil {
			return err
		}
		// Test messages go only to the administrator's own verified address (restricted destination).
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		e := u.PrimaryEmail()
		if e == nil || !e.Verified() {
			return problem.ErrValidation.WithDetail("a verified email address is required for test delivery")
		}
		id, err := a.Notify.EnqueueTx(r.Context(), a.D.DB.Pool, notification.Message{RealmID: p.Realm.ID, Template: notification.TplTest, Recipient: e.Value,
			Mandatory: true, ReferenceType: "notification_test", ReferenceID: p.SubjectID,
			Data: map[string]string{"realm": p.Realm.DisplayName, "time": notification.Timestamp(a.D.Now())}})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id, "note": "Provider acceptance does not prove inbox delivery."})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/notification-jobs", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.notifications.read"); err != nil {
			return err
		}
		after, err := a.pageAfter(r)
		if err != nil {
			return err
		}
		var at *time.Time
		afterID := ""
		if after != nil {
			at, afterID = &after.At, after.ID
		}
		limit := a.pageLimit(r)
		list, err := a.Notify.ListJobs(r.Context(), p.Realm.ID, r.URL.Query().Get("reference_type"), r.URL.Query().Get("reference_id"), limit+1, at, afterID)
		if err != nil {
			return err
		}
		var next *keyset
		if len(list) > limit {
			list = list[:limit]
			next = &keyset{At: list[limit-1].CreatedAt, ID: list[limit-1].ID}
		}
		a.writePage(w, r, list, next)
		return nil
	}))
}

// ConfigDocument is the portable realm configuration format
// (proudauth.realm-config.v1). The export job produces exactly this format, so an
// export can be validated and re-imported (OSS-008, DEP-020). Environment-bound
// identifiers (projects, owners, service principals, composite role IDs) and all
// secrets are excluded.
type ConfigDocument struct {
	Format string `json:"format"`
	// Realm is informational metadata from the exporting realm.
	Realm map[string]any `json:"realm,omitempty"`
	// Policy is merged over the target realm's current policy: omitted fields
	// keep their current values.
	Policy json.RawMessage `json:"policy,omitempty"`
	// ExpectedPolicyRevision, when set, must equal the target realm's current
	// policy revision (optimistic concurrency for reviewed changes).
	ExpectedPolicyRevision int64                                 `json:"expected_policy_revision,omitempty"`
	Resources              []ConfigResource                      `json:"resources"`
	Clients                []ConfigClient                        `json:"clients"`
	Permissions            []ConfigPermission                    `json:"permissions"`
	Roles                  []authorization.RoleInput             `json:"roles"`
	Grants                 map[string]map[string]ConfigGrantSpec `json:"client_resource_grants"` // client_id -> audience -> grant
	Excluded               []string                              `json:"excluded,omitempty"`
}

// ConfigResource is a resource definition. It remembers which members the
// document states, so a reconcile changes only those and an omitted member
// keeps its current value. impersonation_enabled matters most: read as its
// zero value, an omitted member would switch support access off (IMP-001).
type ConfigResource struct {
	application.ResourceInput
	stated map[string]bool
}

// UnmarshalJSON decodes strictly, like the rest of the document (unknown
// members are refused), and records the members present.
func (c *ConfigResource) UnmarshalJSON(b []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(b, &members); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var in application.ResourceInput
	if err := dec.Decode(&in); err != nil {
		return err
	}
	c.ResourceInput, c.stated = in, map[string]bool{}
	for k := range members {
		c.stated[strings.ToLower(k)] = true
	}
	return nil
}

// states reports whether the document states a member; a definition built
// in code rather than decoded states every member.
func (c ConfigResource) states(member string) bool { return c.stated == nil || c.stated[member] }

// reconciled is the input a reconcile applies to the existing resource: the
// members the document omits keep their current values.
func (c ConfigResource) reconciled(cur *application.Resource) application.ResourceInput {
	in := c.ResourceInput
	in.ProjectID = cur.ProjectID
	if !c.states("name") || in.Name == "" {
		in.Name = cur.Name
	}
	if !c.states("description") {
		in.Description = cur.Description
	}
	if !c.states("token_format") || in.TokenFormat == "" {
		in.TokenFormat = cur.TokenFormat
	}
	if !c.states("verification_mode") || in.VerificationMode == "" {
		in.VerificationMode = cur.VerificationMode
	}
	if !c.states("access_token_ttl_seconds") || in.AccessTokenTTL == 0 {
		in.AccessTokenTTL = cur.AccessTokenTTL
	}
	if !c.states("impersonation_enabled") {
		in.ImpersonationEnabled = cur.ImpersonationEnabled
	}
	if !c.states("impersonation_policy") {
		in.ImpersonationPolicy = cur.ImpersonationPolicy
	}
	return in
}

// ConfigClient is a client definition. A machine client references its service
// principal by name; the principal must already exist (with an accountable
// owner) in the target realm.
type ConfigClient struct {
	application.ClientInput
	ServicePrincipal string `json:"service_principal,omitempty"`
}

// resolveAudience maps a document audience to a resource in the realm. Built-in
// resources are written as "builtin:<kind>" (account, admin, userinfo) because
// their audiences contain the realm's issuer URL.
func (a *App) resolveAudience(ctx context.Context, q storage.Querier, realmID, aud string) (*application.Resource, error) {
	if kind, ok := strings.CutPrefix(aud, "builtin:"); ok {
		var id string
		if err := q.QueryRow(ctx, `SELECT id FROM api_resources WHERE realm_id=$1 AND kind=$2 LIMIT 1`, realmID, kind).Scan(&id); err != nil {
			return nil, problem.ErrNotFound
		}
		return a.Apps.Resource(ctx, q, realmID, id)
	}
	return a.Apps.ResourceByAudience(ctx, q, realmID, aud)
}

// resolveServicePrincipal maps a principal name to its ID in the realm.
func (a *App) resolveServicePrincipal(ctx context.Context, q storage.Querier, realmID, name string) (string, error) {
	rows, err := q.Query(ctx, `SELECT id FROM service_principals WHERE realm_id=$1 AND name=$2 AND state='active' LIMIT 2`, realmID, name)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		found = append(found, id)
	}
	if len(found) != 1 {
		return "", problem.ErrValidation.WithField("service_principal", "exactly one active service principal named "+name+" must exist")
	}
	return found[0], nil
}

// ConfigPermission is an application permission definition.
type ConfigPermission struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Sensitivity  string `json:"sensitivity,omitempty"`
}

// ConfigGrantSpec is a client's grant to a resource. It accepts a bare scope
// array (shorthand) or an object with subject types.
type ConfigGrantSpec struct {
	Scopes       []string `json:"scopes"`
	SubjectTypes []string `json:"subject_types,omitempty"`
	// ExchangePolicy, when present, replaces the grant's token-exchange
	// policy; omitted, an existing grant keeps its policy (TOK-016).
	ExchangePolicy *application.ExchangePolicy `json:"exchange_policy,omitempty"`
}

// UnmarshalJSON accepts ["scope", ...] or {"scopes": [...], "subject_types": [...]}.
func (g *ConfigGrantSpec) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		g.Scopes = list
		return nil
	}
	type plain ConfigGrantSpec
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p plain
	if err := dec.Decode(&p); err != nil {
		return err
	}
	*g = ConfigGrantSpec(p)
	return nil
}

// ConfigPlan is the validated diff.
type ConfigPlan struct {
	Create    []string `json:"create"`
	Unchanged []string `json:"unchanged"`
	Update    []string `json:"update"`
	Errors    []string `json:"errors"`
	Notes     []string `json:"notes"`
	// Drift lists existing objects that differ from the document (SDK-012).
	// An import never rewrites them; reconcile them through the API.
	Drift []string `json:"drift"`
}

const configFormat = "proudauth.realm-config.v1"

// mergedPolicy overlays the document's policy on the realm's current policy.
// Objects merge member by member; arrays and scalars in the document replace
// the current value whole. The merge works on JSON copies, so the cached
// realm policy is never mutated and list elements never inherit members from
// the elements they replace.
func (a *App) mergedPolicy(p *Principal, raw json.RawMessage) (*realm.Policy, error) {
	invalid := problem.ErrValidation.WithField("policy", "invalid policy document")
	var probe realm.Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&probe); err != nil {
		return nil, invalid
	}
	var overlay map[string]any
	if err := json.Unmarshal(raw, &overlay); err != nil {
		return nil, invalid
	}
	curRaw, err := json.Marshal(p.Realm.Policy)
	if err != nil {
		return nil, err
	}
	var base map[string]any
	if err := json.Unmarshal(curRaw, &base); err != nil {
		return nil, err
	}
	mergedRaw, err := json.Marshal(mergeJSON(base, overlay))
	if err != nil {
		return nil, err
	}
	var merged realm.Policy
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		return nil, invalid
	}
	return &merged, nil
}

// samePolicy compares policies by their JSON form, so an empty list and an
// absent one compare equal.
func samePolicy(a, b realm.Policy) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// mergeJSON merges overlay into base: nested objects recursively, everything
// else (arrays included) replaced.
func mergeJSON(base, overlay map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for k, v := range overlay {
		if ov, ok := v.(map[string]any); ok {
			if bv, ok := base[k].(map[string]any); ok {
				base[k] = mergeJSON(bv, ov)
				continue
			}
		}
		base[k] = v
	}
	return base
}

// reviewConfig is the plan an import acts on: planConfig plus the checks the
// import makes before changing anything. Changing the realm policy needs the
// reviewed revision, like If-Match on PUT /settings (ARC-008, API-010), and
// every change needs the authority it needs through the API (ARC-008).
// Validation, dry runs and imports share it, so a plan never reports as
// valid what the import would refuse. denied lists the permissions the
// caller lacks (each is also a plan error).
func (a *App) reviewConfig(r *http.Request, p *Principal, doc ConfigDocument) (ConfigPlan, []string) {
	plan := a.planConfig(r, p, doc)
	if slices.Contains(plan.Update, "realm policy") && doc.ExpectedPolicyRevision == 0 {
		plan.Errors = append(plan.Errors, fmt.Sprintf("policy: set expected_policy_revision (the realm is at %d) after reviewing the change", p.Realm.PolicyRevision))
	}
	var denied []string
	held := map[string]bool{}
	for _, item := range append(slices.Clone(plan.Create), plan.Update...) {
		perm := ""
		switch {
		case item == "realm policy":
			perm = "realm.settings.write"
		case strings.HasPrefix(item, "client "), strings.HasPrefix(item, "grant "):
			perm = "realm.clients.write"
		case strings.HasPrefix(item, "resource "):
			perm = "realm.resources.write"
		case strings.HasPrefix(item, "role "), strings.HasPrefix(item, "permission "):
			perm = "realm.roles.write"
		}
		if perm == "" {
			continue
		}
		ok, checked := held[perm]
		if !checked {
			ok = a.can(r.Context(), p, perm, a.realmScope(p))
			held[perm] = ok
			if !ok {
				denied = append(denied, perm)
			}
		}
		if !ok {
			plan.Errors = append(plan.Errors, item+": requires "+perm)
		}
	}
	return plan, denied
}

func (a *App) planConfig(r *http.Request, p *Principal, doc ConfigDocument) ConfigPlan {
	plan := ConfigPlan{Create: []string{}, Unchanged: []string{}, Update: []string{}, Errors: []string{}, Notes: []string{}, Drift: []string{}}
	drift := func(what string, fields []string) {
		if len(fields) > 0 {
			plan.Drift = append(plan.Drift, what+": "+strings.Join(fields, ", ")+" differ")
		}
	}
	// mode=reconcile (SDK-012): existing clients, resources and role
	// permissions that differ from the document are updated to match it;
	// otherwise they are only reported as drift. Nothing is ever deleted.
	reconcile := r.URL.Query().Get("mode") == "reconcile"
	// settle reports an existing object: updated under reconcile when it
	// differs in fields a reconcile can set, drift for the rest.
	settle := func(what string, fixable, other map[string]bool) {
		if reconcile && len(diffFields(fixable)) > 0 {
			plan.Update = append(plan.Update, what)
		} else {
			plan.Unchanged = append(plan.Unchanged, what)
			for k, v := range fixable {
				other[k] = v
			}
		}
		drift(what, diffFields(other))
	}
	ctx := r.Context()
	if doc.Format != "" && doc.Format != configFormat {
		plan.Errors = append(plan.Errors, "format: unsupported document format "+doc.Format)
		return plan
	}
	if len(doc.Policy) > 0 {
		if doc.ExpectedPolicyRevision != 0 && doc.ExpectedPolicyRevision != p.Realm.PolicyRevision {
			plan.Errors = append(plan.Errors, fmt.Sprintf("policy: expected revision %d but the realm is at %d", doc.ExpectedPolicyRevision, p.Realm.PolicyRevision))
		} else if merged, err := a.mergedPolicy(p, doc.Policy); err != nil {
			plan.Errors = append(plan.Errors, "policy: "+err.Error())
		} else if err := realm.ValidatePolicy(*merged, a.D.Cfg.Impersonation.Enabled); err != nil {
			plan.Errors = append(plan.Errors, "policy: "+err.Error())
		} else if err := realm.CheckMFAFloor(*merged, a.D.Cfg.Security.MFAFloor); err != nil {
			plan.Errors = append(plan.Errors, "policy: "+err.Error())
		} else if err := realm.CheckChallengeProvider(*merged, a.D.Cfg); err != nil {
			plan.Errors = append(plan.Errors, "policy: "+err.Error())
		} else if samePolicy(*merged, p.Realm.Policy) {
			plan.Unchanged = append(plan.Unchanged, "realm policy")
		} else {
			plan.Update = append(plan.Update, "realm policy")
			plan.Notes = append(plan.Notes, "realm policy changes can alter security boundaries; review the diff before applying")
		}
	}
	audiences := map[string]bool{}
	for _, res := range doc.Resources {
		audiences[res.Audience] = true
		if cur, err := a.Apps.ResourceByAudience(ctx, nil, p.Realm.ID, res.Audience); err == nil {
			var names []string
			_ = a.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(array_agg(name ORDER BY name), '{}') FROM scopes WHERE resource_id=$1`, cur.ID).Scan(&names)
			want := []string{}
			for _, sc := range res.Scopes {
				want = append(want, sc.Name)
			}
			settle("resource "+res.Audience, map[string]bool{
				"name":                  res.Name != "" && res.Name != cur.Name,
				"verification_mode":     res.VerificationMode != "" && res.VerificationMode != cur.VerificationMode,
				"access_token_ttl":      res.AccessTokenTTL != 0 && res.AccessTokenTTL != cur.AccessTokenTTL,
				"requires_organization": res.RequiresOrganization != nil && *res.RequiresOrganization != cur.RequiresOrganization,
				"signing_algorithm":     res.SigningAlgorithm != "" && res.SigningAlgorithm != cur.SigningAlgorithm,
				// Support access is security-relevant (IMP-001); an omitted
				// member keeps its current value and is no difference.
				"impersonation_enabled": res.states("impersonation_enabled") && res.ImpersonationEnabled != cur.ImpersonationEnabled,
				"impersonation_policy": res.states("impersonation_policy") &&
					!reflect.DeepEqual(normalizeImp(res.ImpersonationPolicy), normalizeImp(cur.ImpersonationPolicy)),
			}, map[string]bool{
				// Scopes are added and retired through the resource API.
				"scopes": len(want) > 0 && !sameSet(want, names),
			})
		} else {
			plan.Create = append(plan.Create, "resource "+res.Audience)
		}
	}
	clients := map[string]bool{}
	for _, c := range doc.Clients {
		cc := c.ClientInput
		clients[c.ClientID] = true
		if cc.ProjectID != "" || cc.DefaultResourceID != "" || cc.ServicePrincipalID != "" || cc.OwnerUserID != "" {
			plan.Errors = append(plan.Errors, "client "+c.ClientID+": environment-bound identifiers (project, default resource, service principal ID, owner) cannot be imported")
			continue
		}
		if c.ServicePrincipal != "" {
			id, err := a.resolveServicePrincipal(ctx, a.D.DB.Pool, p.Realm.ID, c.ServicePrincipal)
			if err != nil {
				plan.Errors = append(plan.Errors, "client "+c.ClientID+": "+err.Error())
				continue
			}
			cc.ServicePrincipalID = id
		}
		if perr := cc.Normalize(); perr != nil {
			plan.Errors = append(plan.Errors, "client "+c.ClientID+": "+perr.Error())
			continue
		}
		if cur, err := a.Apps.ClientByClientID(ctx, nil, p.Realm.ID, c.ClientID); err == nil {
			fixable := map[string]bool{
				"name":                       cc.Name != cur.Name,
				"grant_types":                !sameSet(cc.GrantTypes, cur.GrantTypes),
				"redirect_uris":              !sameSet(cc.RedirectURIs, cur.RedirectURIs),
				"post_logout_redirect_uris":  !sameSet(cc.PostLogoutRedirects, cur.PostLogoutRedirects),
				"first_party":                cc.FirstParty != cur.FirstParty,
				"consent_mode":               cc.ConsentMode != "" && cc.ConsentMode != cur.ConsentMode,
				"allowed_origins":            !sameSet(cc.Origins, cur.Origins),
				"backchannel_logout_uri":     cc.BackchannelLogoutURI != cur.BackchannelLogoutURI,
				"allow_offline_access":       cc.AllowOfflineAccess != cur.AllowOfflineAccess,
				"allow_remember_me":          cc.AllowRememberMe != cur.AllowRememberMe,
				"token_endpoint_auth_method": cc.AuthMethod != "" && cc.AuthMethod != cur.AuthMethod,
				"security_profile":           cc.SecurityProfile != "" && cc.SecurityProfile != cur.SecurityProfile,
				// Protocol options (front-channel logout, response signing and
				// encryption, certificate binding, display URIs) compare whole.
				"protocol_options": !reflect.DeepEqual(cc.ProtocolOptions, cur.ProtocolOptions),
			}
			// A client's type never changes; register a new client. A
			// reconcile that would update such a client is refused here,
			// in the plan, not by the update halfway through the import.
			if cc.Type != cur.Type && reconcile && len(diffFields(fixable)) > 0 {
				plan.Errors = append(plan.Errors, fmt.Sprintf("client %s: client_type is %s and cannot change to %s; register a new client (another client_id) or keep %s in the document",
					c.ClientID, cur.Type, cc.Type, cur.Type))
				continue
			}
			settle("client "+c.ClientID, fixable, map[string]bool{
				"client_type": cc.Type != cur.Type,
			})
		} else {
			plan.Create = append(plan.Create, "client "+c.ClientID)
			if strings.HasPrefix(cc.AuthMethod, "client_secret") {
				plan.Notes = append(plan.Notes, "client "+c.ClientID+": a new secret is generated, returned once, and must be stored through a secret reference, never in version control")
			}
		}
	}
	for clientID, byAud := range doc.Grants {
		if _, err := a.Apps.ClientByClientID(ctx, nil, p.Realm.ID, clientID); err != nil && !clients[clientID] {
			plan.Errors = append(plan.Errors, "grant: unknown client "+clientID)
			continue
		}
		existingClient, _ := a.Apps.ClientByClientID(ctx, nil, p.Realm.ID, clientID)
		for aud, g := range byAud {
			res, err := a.resolveAudience(ctx, a.D.DB.Pool, p.Realm.ID, aud)
			if err != nil && !audiences[aud] {
				plan.Errors = append(plan.Errors, "grant: unknown resource "+aud)
				continue
			}
			// The exchange policy is validated as the grant API validates it
			// (TOK-016), against the resource as it will be after the import.
			if g.ExchangePolicy != nil {
				declared := []string{}
				if res != nil {
					for _, sc := range res.Scopes {
						declared = append(declared, sc.Name)
					}
				} else {
					for _, dr := range doc.Resources {
						if dr.Audience == aud {
							for _, sc := range dr.Scopes {
								declared = append(declared, sc.Name)
							}
						}
					}
				}
				if err := application.CheckExchangePolicy(declared, *g.ExchangePolicy, func(src string) (bool, error) {
					if audiences[src] {
						return true, nil
					}
					_, err := a.Apps.ResourceByAudience(ctx, nil, p.Realm.ID, src)
					if problem.Is(err, problem.ErrNotFound) {
						return false, nil
					}
					return err == nil, err
				}); err != nil {
					plan.Errors = append(plan.Errors, "grant "+clientID+" -> "+aud+": "+err.Error())
					continue
				}
			}
			if existingClient != nil && res != nil {
				if cur, _ := a.Apps.ResourceGrants(ctx, nil, existingClient.Ref); slices.ContainsFunc(cur, func(x application.ResourceGrant) bool {
					return x.ResourceID == res.ID && sameSet(x.AllowedScopes, g.Scopes) && (len(g.SubjectTypes) == 0 || sameSet(x.SubjectTypes, g.SubjectTypes)) &&
						(g.ExchangePolicy == nil || sameExchange(x.ExchangePolicy, *g.ExchangePolicy))
				}) {
					plan.Unchanged = append(plan.Unchanged, "grant "+clientID+" -> "+aud)
					continue
				}
			}
			plan.Update = append(plan.Update, "grant "+clientID+" -> "+aud)
		}
	}
	existing, _ := a.Authz.ListPermissions(ctx, p.Realm.ID)
	for _, perm := range doc.Permissions {
		if slices.ContainsFunc(existing, func(e authorization.Permission) bool { return e.Name == perm.Name }) {
			plan.Unchanged = append(plan.Unchanged, "permission "+perm.Name)
		} else {
			plan.Create = append(plan.Create, "permission "+perm.Name)
		}
	}
	for _, role := range doc.Roles {
		if role.OrganizationID != "" || role.ProjectID != "" || len(role.CompositeRoleIDs) > 0 || len(role.IncompatibleRoleIDs) > 0 {
			plan.Errors = append(plan.Errors, "role "+role.Name+": environment-bound identifiers cannot be imported")
			continue
		}
		if cur, err := a.Authz.RoleByName(ctx, a.D.DB.Pool, p.Realm.ID, role.Boundary, role.Name); err == nil {
			settle("role "+role.Name, map[string]bool{
				"permissions": !sameSet(authorization.ExpandPatterns(role.Permissions), cur.Permissions),
			}, map[string]bool{
				"denied_permissions": !sameSet(nonNil(role.DeniedPermissions), cur.DeniedPermissions),
				"requires_approval":  role.RequiresApproval != cur.RequiresApproval,
			})
		} else {
			plan.Create = append(plan.Create, "role "+role.Name)
		}
	}
	return plan
}

// diffFields returns the names whose value is true, sorted.
func diffFields(m map[string]bool) []string {
	out := []string{}
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// ConfigApplied reports what an import changed; Secrets holds one-time client
// secrets for newly created confidential clients.
type ConfigApplied struct {
	Applied []string          `json:"applied"`
	Secrets map[string]string `json:"client_secrets,omitempty"`
}

// applyConfig applies a validated plan atomically: either every change commits
// or none does (DEP-020). It uses the same domain services, checks and audit path
// as the API (ARC-008). Existing objects are left untouched and reported.
func (a *App) applyConfig(r *http.Request, p *Principal, doc ConfigDocument, plan ConfigPlan) (*ConfigApplied, error) {
	ctx := r.Context()
	out := &ConfigApplied{Applied: []string{}, Secrets: map[string]string{}}
	policyChanged := false
	err := a.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		out.Applied, out.Secrets = []string{}, map[string]string{}
		if slices.Contains(plan.Update, "realm policy") {
			merged, err := a.mergedPolicy(p, doc.Policy)
			if err != nil {
				return err
			}
			if doc.ExpectedPolicyRevision != 0 {
				var rev int64
				if err := tx.QueryRow(ctx, `SELECT policy_revision FROM realms WHERE id=$1 FOR UPDATE`, p.Realm.ID).Scan(&rev); err != nil {
					return err
				}
				if rev != doc.ExpectedPolicyRevision {
					return problem.ErrPrecondition.WithDetail("the realm policy changed since the document was reviewed")
				}
			}
			if _, err := a.Realms.UpdatePolicyTx(ctx, tx, p.Realm.ID, 0, *merged, p.AuditRef(), "configuration import"); err != nil {
				return err
			}
			policyChanged = true
			out.Applied = append(out.Applied, "realm policy")
		}
		for _, perm := range doc.Permissions {
			if slices.Contains(plan.Create, "permission "+perm.Name) {
				if _, err := a.Authz.RegisterPermissionTx(ctx, tx, p.Realm.ID, authorization.Permission{Name: perm.Name, Description: perm.Description,
					ResourceType: perm.ResourceType, Sensitivity: perm.Sensitivity}, p.AuditRef()); err != nil {
					return err
				}
				out.Applied = append(out.Applied, "permission "+perm.Name)
			}
		}
		for _, res := range doc.Resources {
			if slices.Contains(plan.Create, "resource "+res.Audience) {
				if _, err := a.Apps.CreateResourceTx(ctx, tx, p.Realm.ID, res.ResourceInput, p.AuditRef()); err != nil {
					return err
				}
				out.Applied = append(out.Applied, "resource "+res.Audience)
			}
		}
		for _, c := range doc.Clients {
			if slices.Contains(plan.Create, "client "+c.ClientID) {
				in := c.ClientInput
				if c.ServicePrincipal != "" {
					id, err := a.resolveServicePrincipal(ctx, tx, p.Realm.ID, c.ServicePrincipal)
					if err != nil {
						return err
					}
					in.ServicePrincipalID = id
				}
				_, secretValue, err := a.Apps.CreateClientTx(ctx, tx, p.Realm.ID, in, p.AuditRef())
				if err != nil {
					return err
				}
				if secretValue != "" {
					out.Secrets[c.ClientID] = secretValue
				}
				out.Applied = append(out.Applied, "client "+c.ClientID)
			}
		}
		for clientID, byAud := range doc.Grants {
			c, err := a.Apps.ClientByClientID(ctx, tx, p.Realm.ID, clientID)
			if err != nil {
				return problem.ErrValidation.WithDetail("grant references unknown client " + clientID)
			}
			for aud, g := range byAud {
				if !slices.Contains(plan.Update, "grant "+clientID+" -> "+aud) {
					continue
				}
				res, err := a.resolveAudience(ctx, tx, p.Realm.ID, aud)
				if err != nil {
					return problem.ErrValidation.WithDetail("grant references unknown resource " + aud)
				}
				// An existing grant keeps the subject types and exchange policy
				// the document does not state.
				subjects, exchange := g.SubjectTypes, application.ExchangePolicy{}
				if cur, err := a.Apps.ResourceGrant(ctx, tx, c.Ref, res.ID); err == nil {
					exchange = cur.ExchangePolicy
					if len(subjects) == 0 {
						subjects = cur.SubjectTypes
					}
				}
				if g.ExchangePolicy != nil {
					exchange = *g.ExchangePolicy
				}
				if len(subjects) == 0 {
					subjects = []string{"user"}
				}
				if err := a.Apps.SetResourceGrantTx(ctx, tx, p.Realm.ID, c.Ref, res.ID, g.Scopes, subjects, exchange, p.AuditRef()); err != nil {
					return err
				}
				out.Applied = append(out.Applied, "grant "+clientID+" -> "+aud)
			}
		}
		for _, role := range doc.Roles {
			if !slices.Contains(plan.Create, "role "+role.Name) {
				continue
			}
			if _, err := a.Authz.CreateRoleTx(ctx, tx, p.Realm.ID, p.Subject(), role, p.AuditRef()); err != nil {
				return err
			}
			out.Applied = append(out.Applied, "role "+role.Name)
		}
		// Reconciliation of existing objects (SDK-012), each through the same
		// service call and checks as the API, against the version planned.
		for _, c := range doc.Clients {
			if !slices.Contains(plan.Update, "client "+c.ClientID) {
				continue
			}
			cur, err := a.Apps.ClientByClientID(ctx, tx, p.Realm.ID, c.ClientID)
			if err != nil {
				return err
			}
			cc := c.ClientInput
			// Environment-bound links stay as they are in this realm.
			cc.ProjectID, cc.OwnerUserID, cc.DefaultResourceID, cc.ServicePrincipalID = cur.ProjectID, cur.OwnerUserID, cur.DefaultResourceID, cur.ServicePrincipalID
			if _, err := a.Apps.UpdateClientTx(ctx, tx, p.Realm.ID, cur.Ref, cur.Version, cc, p.AuditRef()); err != nil {
				return err
			}
			out.Applied = append(out.Applied, "client "+c.ClientID)
		}
		for _, res := range doc.Resources {
			if !slices.Contains(plan.Update, "resource "+res.Audience) {
				continue
			}
			cur, err := a.Apps.ResourceByAudience(ctx, tx, p.Realm.ID, res.Audience)
			if err != nil {
				return err
			}
			// Members the document omits keep their current values.
			if _, err := a.Apps.UpdateResourceTx(ctx, tx, p.Realm.ID, cur.ID, cur.Version, res.reconciled(cur), p.AuditRef()); err != nil {
				return err
			}
			out.Applied = append(out.Applied, "resource "+res.Audience)
		}
		for _, role := range doc.Roles {
			if !slices.Contains(plan.Update, "role "+role.Name) {
				continue
			}
			cur, err := a.Authz.RoleByName(ctx, tx, p.Realm.ID, role.Boundary, role.Name)
			if err != nil {
				return err
			}
			want := authorization.ExpandPatterns(role.Permissions)
			add := slices.DeleteFunc(slices.Clone(want), func(x string) bool { return slices.Contains(cur.Permissions, x) })
			remove := slices.DeleteFunc(slices.Clone(cur.Permissions), func(x string) bool { return slices.Contains(want, x) })
			if _, err := a.Authz.ModifyRolePermissionsTx(ctx, tx, p.Realm.ID, cur.ID, cur.Version, p.Subject(), add, remove, p.AuditRef()); err != nil {
				return err
			}
			out.Applied = append(out.Applied, "role "+role.Name)
		}
		return nil
	})
	if policyChanged {
		a.Realms.Invalidate(p.Realm.Name)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExportConfig renders a realm's configuration as a re-importable document.
// Built-in resources and clients present in every realm are omitted.
func (a *App) ExportConfig(ctx context.Context, realmID string) (*ConfigDocument, error) {
	rlm, err := a.Realms.ByID(ctx, nil, realmID)
	if err != nil {
		return nil, err
	}
	pol, _ := json.Marshal(rlm.Policy)
	doc := &ConfigDocument{Format: configFormat, Realm: map[string]any{"name": rlm.Name, "display_name": rlm.DisplayName, "policy_revision": rlm.PolicyRevision},
		Policy: pol, ExpectedPolicyRevision: 0, Resources: []ConfigResource{}, Clients: []ConfigClient{},
		Permissions: []ConfigPermission{}, Roles: []authorization.RoleInput{}, Grants: map[string]map[string]ConfigGrantSpec{},
		Excluded: []string{"client secrets", "signing keys", "encryption keys", "connector and identity-provider credentials", "user credentials",
			"environment-bound identifiers (projects, owners, service principals, composite role links)"}}
	// Every object is exported, page by page (OSS-008): no silent cap.
	var resources []*application.Resource
	for after := ""; ; {
		page, err := a.Apps.ListResources(ctx, realmID, after, 500)
		if err != nil {
			return nil, err
		}
		resources = append(resources, page...)
		if len(page) < 500 {
			break
		}
		after = page[len(page)-1].ID
	}
	audByID := map[string]string{}
	for _, res := range resources {
		audByID[res.ID] = res.Audience
		if res.Kind != application.KindBusiness {
			audByID[res.ID] = "builtin:" + res.Kind
			continue
		}
		req := res.RequiresOrganization
		in := application.ResourceInput{Name: res.Name, Audience: res.Audience, Description: res.Description, TokenFormat: res.TokenFormat,
			VerificationMode: res.VerificationMode, AccessTokenTTL: res.AccessTokenTTL, RequiresOrganization: &req,
			ImpersonationEnabled: res.ImpersonationEnabled, ImpersonationPolicy: res.ImpersonationPolicy, Scopes: []application.ScopeInput{},
			SigningAlgorithm: res.SigningAlgorithm}
		scopes, err := a.Apps.ScopesForResource(ctx, a.D.DB.Pool, realmID, res.ID)
		if err != nil {
			return nil, err
		}
		for _, sc := range scopes {
			in.Scopes = append(in.Scopes, application.ScopeInput{Name: sc.Name, Description: sc.Description, ConsentText: sc.ConsentText,
				Sensitivity: sc.Sensitivity, IsDefault: sc.IsDefault, RequiredPermissions: sc.RequiredPermissions, StepUpACR: sc.StepUpACR,
				MaxAuthAgeSeconds: sc.MaxAuthAgeSeconds})
		}
		doc.Resources = append(doc.Resources, ConfigResource{ResourceInput: in})
	}
	var clients []*application.Client
	for after := ""; ; {
		page, err := a.Apps.ListClients(ctx, realmID, after, 500)
		if err != nil {
			return nil, err
		}
		clients = append(clients, page...)
		if len(page) < 500 {
			break
		}
		after = page[len(page)-1].Ref
	}
	for _, c := range clients {
		// SAML applications are managed and exported through /saml/applications.
		if c.ClientID == "proudauth-cli" || c.State != "active" || c.Protocol == "saml" {
			continue
		}
		spName := ""
		if c.ServicePrincipalID != "" {
			_ = a.D.DB.Pool.QueryRow(ctx, `SELECT name FROM service_principals WHERE realm_id=$1 AND id=$2`, realmID, c.ServicePrincipalID).Scan(&spName)
		}
		doc.Clients = append(doc.Clients, ConfigClient{ServicePrincipal: spName, ClientInput: application.ClientInput{ClientID: c.ClientID, Name: c.Name, Description: c.Description, Type: c.Type,
			AuthMethod: c.AuthMethod, GrantTypes: c.GrantTypes, SecurityProfile: c.SecurityProfile, FirstParty: c.FirstParty, ConsentMode: c.ConsentMode,
			AllowOfflineAccess: c.AllowOfflineAccess, AllowRememberMe: c.AllowRememberMe, Environment: c.Environment, SubjectType: c.SubjectType,
			SectorIdentifier: c.SectorIdentifier, LoginUIURL: c.LoginUIURL, BackchannelLogoutURI: c.BackchannelLogoutURI, RedirectURIs: c.RedirectURIs,
			PostLogoutRedirects: c.PostLogoutRedirects, Origins: c.Origins, IDTokenClaims: c.IDTokenClaims, AccessTokenClaims: c.AccessTokenClaims,
			TokenPolicy: c.TokenPolicy, Contacts: c.Contacts, ConsentTermsVersion: c.ConsentTermsVersion, ProtocolOptions: c.ProtocolOptions}})
		grants, err := a.Apps.ResourceGrants(ctx, nil, c.Ref)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			aud := audByID[g.ResourceID]
			if aud == "" {
				continue
			}
			if doc.Grants[c.ClientID] == nil {
				doc.Grants[c.ClientID] = map[string]ConfigGrantSpec{}
			}
			spec := ConfigGrantSpec{Scopes: g.AllowedScopes, SubjectTypes: g.SubjectTypes}
			if !reflect.ValueOf(g.ExchangePolicy).IsZero() {
				ep := g.ExchangePolicy
				spec.ExchangePolicy = &ep
			}
			doc.Grants[c.ClientID][aud] = spec
		}
	}
	perms, err := a.Authz.ListPermissions(ctx, realmID)
	if err != nil {
		return nil, err
	}
	for _, pm := range perms {
		if pm.BuiltIn || pm.Namespace != "application" {
			continue
		}
		doc.Permissions = append(doc.Permissions, ConfigPermission{Name: pm.Name, Description: pm.Description, ResourceType: pm.ResourceType, Sensitivity: pm.Sensitivity})
	}
	roles, err := a.Authz.ListRoles(ctx, realmID, "", "", "")
	if err != nil {
		return nil, err
	}
	for _, rl := range roles {
		if rl.BuiltIn || rl.OrganizationID != "" || rl.ProjectID != "" {
			continue
		}
		doc.Roles = append(doc.Roles, authorization.RoleInput{Boundary: rl.Boundary, Name: rl.Name, Description: rl.Description,
			Permissions: rl.Permissions, DeniedPermissions: rl.DeniedPermissions, RequiresApproval: rl.RequiresApproval})
	}
	return doc, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := slices.Clone(a)
	y := slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// notificationSettings reads a realm's (or organization's) sender settings.
func (a *App) notificationSettings(ctx context.Context, realmID, orgID string) map[string]any {
	var sender, name, reply, locale *string
	_ = a.D.DB.Pool.QueryRow(ctx, `SELECT sender_address, sender_name, reply_to, default_locale FROM notification_settings WHERE realm_id=$1 AND organization_id=$2`,
		realmID, orgID).Scan(&sender, &name, &reply, &locale)
	return map[string]any{"sender_address": sender, "sender_name": name, "reply_to": reply, "default_locale": locale}
}

// sameExchange compares exchange policies structurally: both lists are sets
// (the token-exchange checks only test membership), so neither the order of
// their members nor repeated members count as a difference.
func sameExchange(a, b application.ExchangePolicy) bool {
	set := func(v []string) []string {
		out := slices.Clone(v)
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(set(a.AcceptFromAudiences), set(b.AcceptFromAudiences)) && slices.Equal(set(a.MaxScopes), set(b.MaxScopes))
}

// normalizeImp compares impersonation policies without nil/empty noise.
func normalizeImp(p application.ImpersonationPolicy) string {
	b, _ := json.Marshal(p)
	return string(b)
}
