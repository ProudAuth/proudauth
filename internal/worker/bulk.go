package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// bulkUsers applies one action to up to 1000 accounts (USR-016). Each record
// is validated and applied in its own transaction, progress is checkpointed
// so a retried job resumes where it stopped, and the report lists only
// account IDs and outcome codes — never profile data.
func (w *Worker) bulkUsers(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	action, _ := j.Input["action"].(string)
	reason, _ := j.Input["reason"].(string)
	requiredAction, _ := j.Input["required_action"].(string)
	rawIDs, _ := j.Input["user_ids"].([]any)
	perm, ok := identity.BulkActions[action]
	if !ok || len(rawIDs) == 0 || len(rawIDs) > 1000 {
		return nil, nil, fmt.Errorf("%w: a supported action and 1..1000 user_ids are required", jobs.ErrPermanent)
	}
	// The job acts with its requester's authority, re-checked at execution.
	requester := authorization.Subject{Type: j.RequestedByType, ID: j.RequestedByID}
	if !w.App.Authz.Check(ctx, nil, j.RealmID, requester, perm, authorization.Scope{Type: authorization.ScopeRealm, ID: j.RealmID}) {
		return nil, nil, fmt.Errorf("%w: the requester no longer holds %s", jobs.ErrPermanent, perm)
	}
	if extra := identity.RequiredActionPermission(requiredAction); action == "add_required_action" && extra != "" &&
		!w.App.Authz.Check(ctx, nil, j.RealmID, requester, extra, authorization.Scope{Type: authorization.ScopeRealm, ID: j.RealmID}) {
		return nil, nil, fmt.Errorf("%w: the requester no longer holds %s", jobs.ErrPermanent, extra)
	}
	actor := audit.Ref{Type: j.RequestedByType, ID: j.RequestedByID}
	start := 0
	if cp := j.Checkpoint(); cp != nil {
		if v, ok := cp["next_index"].(float64); ok {
			start = int(v)
		}
	}
	type result struct {
		UserID  string `json:"user_id"`
		Outcome string `json:"outcome"`
		Code    string `json:"code,omitempty"`
	}
	results := []result{}
	if prev, ok := j.Checkpoint()["results"].([]any); ok && start > 0 {
		for _, p := range prev {
			if m, ok := p.(map[string]any); ok {
				r := result{}
				r.UserID, _ = m["user_id"].(string)
				r.Outcome, _ = m["outcome"].(string)
				r.Code, _ = m["code"].(string)
				results = append(results, r)
			}
		}
	}
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Outcome]++
	}
	for i := start; i < len(rawIDs); i++ {
		id, _ := rawIDs[i].(string)
		res := result{UserID: id, Outcome: "applied"}
		err := w.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			u, err := w.App.Users.LockUser(ctx, tx, j.RealmID, id)
			if err != nil {
				return err
			}
			if u.State == identity.StateDeleted || u.State == identity.StatePendingDeletion {
				res.Outcome, res.Code = "skipped", "account_deleted"
				return nil
			}
			// Protected accounts (platform administrators, emergency accounts)
			// are never changed in bulk; they need an individual decision.
			if u.Protected && action != "revoke_sessions" {
				res.Outcome, res.Code = "skipped", "protected_account"
				return nil
			}
			if id == j.RequestedByID && (action == "suspend" || action == "lock") {
				res.Outcome, res.Code = "skipped", "requester_account"
				return nil
			}
			if j.DryRun {
				res.Outcome = "valid"
				return nil
			}
			switch action {
			case "suspend", "reactivate", "lock":
				target := map[string]string{"suspend": identity.StateSuspended, "reactivate": identity.StateActive, "lock": identity.StateLocked}[action]
				if u.State == target {
					res.Outcome, res.Code = "skipped", "already_in_state"
					return nil
				}
				_, err := w.App.Users.SetStateTx(ctx, tx, j.RealmID, id, target, actor, reason)
				return err
			case "revoke_sessions":
				_, err := w.App.Sessions.RevokeUserTx(ctx, tx, j.RealmID, id, "bulk_revocation", true)
				if err != nil {
					return err
				}
				_, err = w.App.D.Audit.Record(ctx, tx, audit.Event{Type: "user.sessions.revoked", RealmID: j.RealmID, Actor: actor,
					Subject: &audit.Ref{Type: "user", ID: id}, ReasonCode: reason, Metadata: map[string]any{"job_id": j.ID}})
				return err
			case "add_required_action":
				if err := w.App.Users.AddRequiredActionTx(ctx, tx, id, requiredAction); err != nil {
					return err
				}
				_, err := w.App.D.Audit.Record(ctx, tx, audit.Event{Type: "user.required_actions.set", RealmID: j.RealmID, Actor: actor,
					Subject: &audit.Ref{Type: "user", ID: id}, ReasonCode: reason, Metadata: map[string]any{"added": requiredAction, "job_id": j.ID}})
				return err
			}
			return nil
		})
		if err != nil {
			res.Outcome, res.Code = "failed", bulkErrorCode(err)
		}
		counts[res.Outcome]++
		results = append(results, res)
		if (i+1)%50 == 0 {
			if err := progress(map[string]any{"next_index": i + 1, "counts": counts, "results": results}); err != nil {
				return nil, nil, err
			}
		}
	}
	return map[string]any{"action": action, "dry_run": j.DryRun, "counts": counts, "results": results}, nil, nil
}

// bulkErrorCode reduces an error to a stable, non-sensitive code for the
// failure report.
func bulkErrorCode(err error) string {
	var pe *problem.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "internal_error"
}
