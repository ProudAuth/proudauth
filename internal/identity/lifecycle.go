package identity

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// BulkActions maps each bulk user action to the permission it needs (USR-016).
var BulkActions = map[string]string{
	"suspend":             "realm.users.suspend",
	"reactivate":          "realm.users.suspend",
	"lock":                "realm.users.suspend",
	"revoke_sessions":     "realm.users.sessions.revoke",
	"add_required_action": "realm.users.required_actions",
}

// LifecycleRules are a realm's account lifecycle settings (USR-015). A zero
// duration disables the rule.
type LifecycleRules struct {
	UnverifiedTTL time.Duration
	DormantAfter  time.Duration
	// DormantAction is "report" (flag and audit once per dormancy) or
	// "suspend".
	DormantAction string
	GuestTTL      time.Duration
}

// LifecycleRule is one rule's planned or applied effect.
type LifecycleRule struct {
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Due     int      `json:"due"`
	Sample  []string `json:"sample_user_ids"`
	Applied int      `json:"applied,omitempty"`
}

type lifecycleRule struct {
	name, action, where string
	cutoff              time.Time
}

func (s *Service) lifecycleRules(r LifecycleRules) []lifecycleRule {
	now := s.d.Now()
	var out []lifecycleRule
	if r.UnverifiedTTL > 0 {
		out = append(out, lifecycleRule{"unverified_expired", "delete", `state='pending_verification' AND created_at < $2`, now.Add(-r.UnverifiedTTL)})
	}
	if r.DormantAfter > 0 {
		action := "report"
		if r.DormantAction == "suspend" {
			action = "suspend"
		}
		out = append(out, lifecycleRule{"dormant", action, `state='active' AND NOT protected AND NOT is_guest
			AND coalesce(last_login_at, created_at) < $2
			AND (dormant_flagged_at IS NULL OR dormant_flagged_at <= coalesce(last_login_at, created_at))`, now.Add(-r.DormantAfter)})
	}
	if r.GuestTTL > 0 {
		out = append(out, lifecycleRule{"guest_expired", "delete", `is_guest AND state <> 'deleted' AND coalesce(last_login_at, created_at) < $2`, now.Add(-r.GuestTTL)})
	}
	out = append(out, lifecycleRule{"scheduled_deactivation", "suspend", `state='active' AND deactivate_at <= $2`, now})
	return out
}

// PlanLifecycle is the dry run: what each rule would do now, with a bounded
// sample of affected accounts. Nothing is changed.
func (s *Service) PlanLifecycle(ctx context.Context, realmID string, r LifecycleRules) ([]LifecycleRule, error) {
	out := []LifecycleRule{}
	for _, rule := range s.lifecycleRules(r) {
		res := LifecycleRule{Name: rule.name, Action: rule.action, Sample: []string{}}
		if err := s.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE realm_id=$1 AND `+rule.where, realmID, rule.cutoff).Scan(&res.Due); err != nil {
			return nil, err
		}
		ids, err := s.lifecycleCandidates(ctx, s.d.DB.Pool, realmID, rule, 20)
		if err != nil {
			return nil, err
		}
		res.Sample = append(res.Sample, ids...)
		out = append(out, res)
	}
	return out, nil
}

func (s *Service) lifecycleCandidates(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, realmID string, rule lifecycleRule, limit int) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT id FROM users WHERE realm_id=$1 AND `+rule.where+` ORDER BY created_at, id LIMIT $3`, realmID, rule.cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ApplyLifecycle applies every rule in bounded batches (at most batch accounts
// per rule per run). Each account is handled in its own transaction after
// re-checking the rule, so a concurrent sign-in or administrator change wins.
func (s *Service) ApplyLifecycle(ctx context.Context, realmID string, r LifecycleRules, batch int) ([]LifecycleRule, error) {
	var out []LifecycleRule
	for _, rule := range s.lifecycleRules(r) {
		ids, err := s.lifecycleCandidates(ctx, s.d.DB.Pool, realmID, rule, batch)
		if err != nil {
			return out, err
		}
		res := LifecycleRule{Name: rule.name, Action: rule.action, Due: len(ids), Sample: []string{}}
		for _, id := range ids {
			err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
				var still bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE realm_id=$1 AND id=$3 AND `+rule.where+`)`,
					realmID, rule.cutoff, id).Scan(&still); err != nil || !still {
					return err
				}
				switch {
				case rule.action == "delete":
					reason := map[string]string{"unverified_expired": "unverified_registration_expired", "guest_expired": "guest_expired"}[rule.name]
					if err := s.DeleteNowTx(ctx, tx, realmID, id, audit.System, reason); err != nil {
						return err
					}
				case rule.name == "scheduled_deactivation":
					if _, err := s.SetStateTx(ctx, tx, realmID, id, StateSuspended, audit.System, "scheduled_deactivation"); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `UPDATE users SET deactivate_at=NULL WHERE id=$1`, id); err != nil {
						return err
					}
				case rule.name == "dormant":
					if _, err := tx.Exec(ctx, `UPDATE users SET dormant_flagged_at=$2 WHERE id=$1`, id, s.d.Now()); err != nil {
						return err
					}
					if rule.action == "suspend" {
						if _, err := s.SetStateTx(ctx, tx, realmID, id, StateSuspended, audit.System, "dormant"); err != nil {
							return err
						}
					} else if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.dormant_detected", RealmID: realmID, Actor: audit.System,
						Subject: &audit.Ref{Type: "user", ID: id}, Category: "account"}); err != nil {
						return err
					}
				}
				res.Applied++
				return nil
			})
			if err != nil {
				return append(out, res), err
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// ScheduleDeactivation sets or clears (at == nil) an account's scheduled
// deactivation (USR-015).
func (s *Service) ScheduleDeactivation(ctx context.Context, realmID, userID string, at *time.Time, actor audit.Ref, reason string) error {
	if at != nil && !at.After(s.d.Now()) {
		return problem.ErrValidation.WithField("at", "must be in the future")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		u, err := s.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if u.State == StateDeleted || u.State == StatePendingDeletion {
			return problem.ErrConflict.WithDetail("account is being deleted")
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET deactivate_at=$2, version=version+1, updated_at=$3 WHERE id=$1`, userID, at, s.d.Now()); err != nil {
			return err
		}
		typ, meta := "user.deactivation_cancelled", map[string]any{}
		if at != nil {
			typ, meta = "user.deactivation_scheduled", map[string]any{"deactivate_at": at.UTC().Format(time.RFC3339)}
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: typ, RealmID: realmID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: userID},
			ReasonCode: reason, Metadata: meta})
		return err
	})
}
