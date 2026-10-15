package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// privacyRoutes report how an account deletion has propagated (PRV-005).
func (a *App) privacyRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/users/{user}/deletion-status", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.read"); err != nil {
			return err
		}
		rep, err := a.deletionStatus(r.Context(), p.Realm.ID, r.PathValue("user"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, rep)
		return nil
	}))
}

// deletionStage is the state of one place a deleted account's data lived.
type deletionStage struct {
	Stage   string     `json:"stage"`
	State   string     `json:"state"` // done, pending, retained or unknown
	Count   int        `json:"count,omitempty"`
	Until   *time.Time `json:"until,omitempty"`
	Details string     `json:"details"`
}

// deletionStatus derives each stage from the current data rather than from a
// separate log, so the report cannot drift from what is actually stored. It
// never claims erasure from backups: those are dated from the operator's
// backup retention, and restore reconciliation re-applies the deletion.
func (a *App) deletionStatus(ctx context.Context, realmID, userID string) (map[string]any, error) {
	pool := a.D.DB.Pool
	var state string
	var deletedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT state, deleted_at FROM users WHERE realm_id=$1 AND id=$2`, realmID, userID).Scan(&state, &deletedAt); err != nil {
		return nil, problem.ErrNotFound
	}
	if state != identity.StateDeleted || deletedAt == nil {
		return nil, problem.ErrConflict.WithDetail("the account is not deleted").WithExtension("state", state)
	}
	at := deletedAt.UTC()
	cfg := a.D.Cfg
	now := a.D.Now()
	until := func(d time.Duration) *time.Time { t := at.Add(d); return &t }
	var sessions, grants, exports, events, imported, held, orgHeld, deliveries, deliveriesOpen, outboxOpen, messages int
	var tombstone bool
	err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM sessions WHERE user_id=$2 AND state='active'),
		(SELECT count(*) FROM authorization_grants WHERE subject_type='user' AND subject_id=$2 AND state='active'),
		(SELECT count(*) FROM jobs WHERE realm_id=$1 AND requested_by_id=$2 AND result_ciphertext IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE realm_id=$1 AND (subject_id=$2 OR actor_id=$2)),
		(SELECT count(*) FROM imported_audit_events WHERE realm_id=$1 AND subject_id=$2 AND redacted_at IS NULL),
		(SELECT count(*) FROM audit_legal_holds WHERE realm_id=$1 AND released_at IS NULL AND (subject_id=$2 OR (subject_id IS NULL AND organization_id IS NULL))),
		(SELECT count(*) FROM audit_legal_holds WHERE realm_id=$1 AND released_at IS NULL AND subject_id IS NULL AND organization_id IS NOT NULL),
		(SELECT count(*) FROM webhook_deliveries d JOIN outbox_events o ON o.id=d.event_id WHERE o.aggregate_id=$2 AND o.event_type='user.deleted'),
		(SELECT count(*) FROM webhook_deliveries d JOIN outbox_events o ON o.id=d.event_id WHERE o.aggregate_id=$2 AND o.event_type='user.deleted'
			AND d.state IN ('pending','retrying')),
		(SELECT count(*) FROM outbox_events WHERE aggregate_id=$2 AND event_type='user.deleted' AND state='pending'),
		EXISTS (SELECT 1 FROM deletion_tombstones WHERE realm_id=$1 AND reference_id=$2),
		(SELECT count(*) FROM notification_jobs WHERE realm_id=$1 AND user_id=$2 AND (payload_ciphertext IS NOT NULL OR recipient_ciphertext IS NOT NULL))`,
		realmID, userID).Scan(&sessions, &grants, &exports, &events, &imported, &held, &orgHeld, &deliveries, &deliveriesOpen, &outboxOpen, &tombstone, &messages)
	if err != nil {
		return nil, err
	}
	pending := func(n int) string {
		if n > 0 {
			return "pending"
		}
		return "done"
	}
	stages := []deletionStage{
		{Stage: "primary_storage", State: "done", Details: "identifiers, credentials, factors, linked identities, profile and metadata erased; the account ID remains as a deleted record"},
		{Stage: "sessions_and_grants", State: pending(sessions + grants), Count: sessions + grants, Details: "active sessions and grants still open"},
		{Stage: "exports", State: pending(exports), Count: exports, Until: until(cfg.Privacy.ExportRetention),
			Details: "export results requested by the account, purged after privacy.export_retention"},
		{Stage: "notifications", State: pending(messages), Count: messages,
			Details: "message payloads and recipients about the account are purged at deletion; queued messages are not sent"},
		{Stage: "connectors", State: pending(outboxOpen + deliveriesOpen), Count: deliveries,
			Details: "user.deleted event published to webhook subscribers; count is the number of deliveries, pending while any is undelivered"},
		{Stage: "imported_audit_history", State: pending(imported), Count: imported,
			Details: "source-supplied details of imported historical records; remaining ones are under a legal hold"},
		{Stage: "caches", State: pending(boolInt(now.Before(at.Add(cacheBound(cfg.Security.DecisionCacheTTL))))), Until: until(cacheBound(cfg.Security.DecisionCacheTTL)),
			Details: "decisions callers may have cached under security.decision_cache_ttl, and in-process caches"},
	}
	// The longest retention that can apply: the deployment default, any
	// category override and the realm's scope (AUD-009); organization
	// scopes may keep events of their organization longer still.
	keep := cfg.Privacy.AuditRetention
	for _, d := range cfg.Privacy.AuditRetentionByCategory {
		keep = max(keep, d)
	}
	if rlm, err := a.Realms.ByID(ctx, nil, realmID); err == nil && rlm.Policy.Audit.RetentionDays > 0 {
		keep = max(keep, time.Duration(rlm.Policy.Audit.RetentionDays)*24*time.Hour)
	}
	audit := deletionStage{Stage: "audit_evidence", State: "retained", Count: events, Until: until(keep),
		Details: "audit events naming the account (by ID only) are kept for the longest applicable audit retention (deployment, category, realm); organization retention policies may keep their organization's events longer"}
	if held > 0 {
		audit.Until, audit.Details = nil, audit.Details+"; an active legal hold covering the account keeps them until released"
	} else if orgHeld > 0 {
		audit.Details += "; organization legal holds keep the events of their organizations until released"
	}
	stages = append(stages, audit)
	backups := deletionStage{Stage: "backups", State: "unknown", Details: "set privacy.backup_retention to date when the last backup holding the account expires"}
	if r := cfg.Privacy.BackupRetention; r > 0 {
		backups.State, backups.Until = "retained", until(r)
		if now.After(at.Add(r)) {
			backups.State = "done"
		}
		backups.Details = "backups taken before the deletion still hold the account until they expire"
	}
	if tombstone {
		backups.Details += "; restoring one re-applies the deletion (restore reconciliation)"
	}
	stages = append(stages, backups)
	return map[string]any{"user_id": userID, "deleted_at": at, "stages": stages}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// cacheBound is the longest time a cached decision about the account may
// still be used: the decision cache TTL, or a minute for in-process caches.
func cacheBound(ttl time.Duration) time.Duration {
	if ttl < time.Minute {
		return time.Minute
	}
	return ttl
}

// customDomainRoutes manage realm custom hostnames (DEP-014).
func (a *App) customDomainRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/custom-domains", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.read"); err != nil {
			return err
		}
		list, err := a.Realms.CustomDomains(r.Context(), p.Realm)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+R+"/custom-domains", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var b struct {
			Host string `json:"host"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		ch, err := a.Realms.AddCustomDomain(r.Context(), p.Realm, b.Host, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, ch)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/custom-domains/{id}/verify", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		d, err := a.Realms.VerifyCustomDomain(r.Context(), p.Realm, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, d)
		return nil
	}))
	mux.HandleFunc("DELETE "+R+"/custom-domains/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.settings.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		if err := a.Realms.RemoveCustomDomain(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
