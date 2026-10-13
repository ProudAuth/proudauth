package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// signInTypes are the audit event types reported as sign-in activity.
var signInTypes = []string{"authentication.succeeded", "authentication.denied", "authentication.password.failed",
	"authentication.otp.failed", "authentication.password.temporarily_locked", "authentication.device.used"}

// activityMetaKeys is the allowlist of audit metadata an account owner may see
// about their own activity; everything else (risk detail, internal reason
// codes, other principals' identifiers) stays administrator-only.
var activityMetaKeys = map[string]bool{"amr": true, "acr": true, "method": true, "credential_type": true, "session_reused": true,
	"recovery_restricted": true, "provider": true, "reason": true, "mode": true}

// activityRoutes exposes the account activity API (USR-019): recent sign-ins,
// active sessions, authenticator activity, security changes and support
// access history, minimized for the account owner.
func (a *App) activityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/realms/{realm}/me/activity", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		days := 30
		if v := r.URL.Query().Get("days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 365 {
				return problem.ErrValidation.WithField("days", "between 1 and 365")
			}
			days = n
		}
		since := a.D.Clock.Now().Add(-time.Duration(days) * 24 * time.Hour)
		ctx := r.Context()
		signIns, err := a.activityEvents(ctx, p, since, `AND type = ANY($4)`, signInTypes)
		if err != nil {
			return err
		}
		changes, err := a.activityEvents(ctx, p, since, `AND NOT (type = ANY($4)) AND category IN ('security','account','privacy')`, signInTypes)
		if err != nil {
			return err
		}
		support, err := a.activityEvents(ctx, p, since, `AND (category='support' OR impersonation_grant_id IS NOT NULL)`)
		if err != nil {
			return err
		}
		sessions, err := a.Sessions.ListForUser(ctx, p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		sess := []map[string]any{}
		for _, s := range sessions {
			sess = append(sess, map[string]any{"id": s.ID, "current": s.ID == p.SessionID, "created_at": s.CreatedAt,
				"last_activity_at": s.LastActivityAt, "amr": s.AMR, "user_agent": s.UserAgent, "device": s.DeviceLabel, "network": s.ClientIP})
		}
		auths := []map[string]any{}
		rows, err := a.D.DB.Pool.Query(ctx, `SELECT id, type, coalesce(name,''), state, created_at, last_used_at FROM credentials
			WHERE user_id=$1 AND state IN ('active','compromised')
			UNION ALL SELECT id, 'webauthn', coalesce(name,''), state, created_at, last_used_at FROM webauthn_credentials
			WHERE user_id=$1 AND state='active' ORDER BY 5`, p.SubjectID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, typ, name, state string
			var created time.Time
			var used *time.Time
			if err := rows.Scan(&id, &typ, &name, &state, &created, &used); err != nil {
				rows.Close()
				return err
			}
			auths = append(auths, map[string]any{"id": id, "type": typ, "name": name, "state": state, "created_at": created, "last_used_at": used})
		}
		rows.Close()
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "sign_ins": signIns, "sessions": sess, "authenticators": auths,
			"security_changes": changes, "support_access": support})
		return nil
	}))
}

// activityEvents returns the caller's own audit events matching filter.
func (a *App) activityEvents(ctx context.Context, p *Principal, since time.Time, filter string, extra ...any) ([]map[string]any, error) {
	rows, err := a.D.DB.Pool.Query(ctx, `SELECT type, occurred_at, outcome, actor_type, actor_id, coalesce(client_id,''), coalesce(ip_context,''),
		coalesce(impersonation_grant_id,''), coalesce(reason_code,''), metadata FROM audit_events
		WHERE realm_id=$1 AND subject_id=$2 AND occurred_at >= $3 `+filter+` ORDER BY seq DESC LIMIT 50`, append([]any{p.Realm.ID, p.SubjectID, since}, extra...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var typ, outcome, actorType, actorID, client, ipc, imp, reason string
		var at time.Time
		var metaRaw []byte
		if err := rows.Scan(&typ, &at, &outcome, &actorType, &actorID, &client, &ipc, &imp, &reason, &metaRaw); err != nil {
			return nil, err
		}
		ev := map[string]any{"type": typ, "occurred_at": at, "outcome": outcome, "network": ipc}
		if client != "" {
			ev["client_id"] = client
		}
		if actorID != p.SubjectID {
			ev["performed_by"] = actorType // never the other principal's identifier
		}
		if imp != "" {
			ev["support_grant_id"] = imp
		}
		if outcome != "success" && reason != "" {
			ev["reason_code"] = reason
		}
		var meta map[string]any
		if json.Unmarshal(metaRaw, &meta) == nil {
			safe := map[string]any{}
			for k, v := range meta {
				if activityMetaKeys[k] {
					safe[k] = v
				}
			}
			if len(safe) > 0 {
				ev["details"] = safe
			}
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// explanationView renders an authorization explanation (AZ-009) keeping the
// earlier response members (scope, roles, permissions, provenance).
func explanationView(ex *authorization.Explanation) map[string]any {
	roles := []string{}
	seen := map[string]bool{}
	for _, src := range ex.Sources {
		if src.Applies && !src.Redacted && !seen[src.RoleName] {
			seen[src.RoleName] = true
			roles = append(roles, src.RoleName)
		}
	}
	out := map[string]any{"scope": ex.Scope, "roles": roles, "permissions": ex.Permissions, "denied_permissions": ex.Denied,
		"provenance": ex.Provenance, "sources": ex.Sources, "policies": ex.Policies, "restricting_policies": ex.PolicyCount}
	if ex.ProjectID != "" {
		out["project_id"] = ex.ProjectID
	}
	return out
}
