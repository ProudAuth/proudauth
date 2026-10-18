package authentication

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
)

// AssistedRecoveryInput is an operator's recovery request (MFA-009).
type AssistedRecoveryInput struct {
	UserID   string
	Reason   string
	Evidence string
	ResetMFA bool
}

// ExecuteAssistedRecoveryTx performs assisted recovery: optional factor reset
// (the account must re-enroll MFA), revocation of every session and grant, and
// a single-use setup link delivered to the verified primary address. It
// returns the setup token only when the account has no email address, and
// refuses when the primary one is unverified.
func (s *Service) ExecuteAssistedRecoveryTx(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, in AssistedRecoveryInput, actor audit.Ref, requestID string) (string, error) {
	u, err := s.Users.LockUser(ctx, tx, rlm.ID, in.UserID)
	if err != nil {
		return "", err
	}
	if recoveryContactUnverified(u) {
		return "", errUnverifiedRecoveryContact
	}
	if in.ResetMFA {
		if err := s.ResetFactorsTx(ctx, tx, in.UserID); err != nil {
			return "", err
		}
	}
	if _, err := s.Sessions.RevokeUserTx(ctx, tx, rlm.ID, in.UserID, session.ReasonAssistedRecovery, true); err != nil {
		return "", err
	}
	// The account's personal access tokens and API keys end with its
	// sessions: whoever controlled the account may have minted them
	// (CRED-008, MCH-007).
	if err := s.revokeUserCredentialsTx(ctx, tx, rlm.ID, in.UserID, session.ReasonAssistedRecovery, actor,
		"assisted account recovery by an administrator"); err != nil {
		return "", err
	}
	st, err := s.IssueAccountSetupTx(ctx, tx, rlm.ID, in.UserID, 2*time.Hour, true, rlm.DisplayName)
	if err != nil {
		return "", err
	}
	setup := ""
	if u.PrimaryEmail() == nil {
		setup = st.Token
	}
	meta := map[string]any{"reason": in.Reason, "evidence_reference": in.Evidence, "reset_mfa": in.ResetMFA, "operator_handoff": setup != ""}
	if requestID != "" {
		meta["recovery_request_id"] = requestID
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.assisted", RealmID: rlm.ID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: in.UserID}, Category: "security", Metadata: meta}); err != nil {
		return "", err
	}
	return setup, s.notifySecurity(ctx, tx, rlm.ID, in.UserID, notification.TplRecovery, "an administrator performed assisted account recovery")
}

// ScheduleAssistedRecovery records a recovery that takes effect after the
// realm's cooling-off period and, when configured, a second operator's
// approval. The account owner is notified at once and can cancel (MFA-009).
func (s *Service) ScheduleAssistedRecovery(ctx context.Context, rlm *realm.Realm, in AssistedRecoveryInput, actor audit.Ref) (string, time.Time, error) {
	pol := rlm.Policy.Recovery
	id := ids.New(ids.AssistedRecov)
	now := s.d.Now()
	effective := now.Add(time.Duration(pol.CoolingOffHours) * time.Hour)
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var verified bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL)`,
			in.UserID).Scan(&verified); err != nil {
			return err
		}
		if !verified {
			// Without a verified contact the owner could neither be warned nor
			// receive the setup link; the scheduled path refuses.
			return problem.ErrConflict.WithDetail("the account has no verified contact; scheduled recovery needs one")
		}
		if u, err := s.Users.User(ctx, tx, rlm.ID, in.UserID); err != nil {
			return err
		} else if recoveryContactUnverified(u) {
			return errUnverifiedRecoveryContact
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assisted_recoveries (id, realm_id, user_id, requested_by_id, reason, evidence_reference, reset_mfa,
			approval_required, effective_at, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, rlm.ID, in.UserID, actor.ID,
			in.Reason, in.Evidence, in.ResetMFA, pol.RequireApproval, effective, effective.Add(7*24*time.Hour), now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.assisted.scheduled", RealmID: rlm.ID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: in.UserID}, Target: &audit.Ref{Type: "assisted_recovery", ID: id}, Category: "security",
			Metadata: map[string]any{"reason": in.Reason, "evidence_reference": in.Evidence, "reset_mfa": in.ResetMFA, "effective_at": effective,
				"approval_required": pol.RequireApproval}}); err != nil {
			return err
		}
		return s.notifySecurity(ctx, tx, rlm.ID, in.UserID, notification.TplRecovery,
			"an administrator requested assisted recovery of your account, effective "+s.Notify.LocalTime(ctx, tx, in.UserID, effective)+
				"; if you did not ask for this, sign in and cancel it")
	})
	return id, effective, err
}

// ApproveAssistedRecovery records an independent operator's approval. An
// approval needs the same authority as the request: mayResetMFA must be true
// to approve a recovery that resets factors.
func (s *Service) ApproveAssistedRecovery(ctx context.Context, realmID, id, approverID string, mayResetMFA bool, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var requester, state, userID string
		var required, resetMFA bool
		if err := tx.QueryRow(ctx, `SELECT requested_by_id, state, user_id, approval_required, reset_mfa FROM assisted_recoveries
			WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).Scan(&requester, &state, &userID, &required, &resetMFA); err != nil {
			return problem.ErrNotFound
		}
		if resetMFA && !mayResetMFA {
			return problem.ErrForbidden.WithDetail("approving a factor reset requires realm.users.credentials.manage")
		}
		if !required || state != "pending" {
			return problem.ErrConflict.WithDetail("the recovery does not await approval")
		}
		if approverID == requester || approverID == userID {
			return problem.ErrForbidden.WithDetail("an independent operator must approve")
		}
		if _, err := tx.Exec(ctx, `UPDATE assisted_recoveries SET state='approved', approved_by_id=$2 WHERE id=$1`, id, approverID); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.assisted.approved", RealmID: realmID, Actor: actor, Category: "security",
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "assisted_recovery", ID: id}})
		return err
	})
}

// CancelAssistedRecovery lets the account owner stop a scheduled recovery.
func (s *Service) CancelAssistedRecovery(ctx context.Context, realmID, id, userID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE assisted_recoveries SET state='cancelled' WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND state IN ('pending','approved')`,
			realmID, id, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.assisted.cancelled", RealmID: realmID, Actor: actor, Category: "security",
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "assisted_recovery", ID: id}})
		return err
	})
}

// PendingAssistedRecoveries lists the owner's scheduled recoveries.
func (s *Service) PendingAssistedRecoveries(ctx context.Context, realmID, userID string) ([]map[string]any, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, state, reset_mfa, approval_required, effective_at, created_at FROM assisted_recoveries
		WHERE realm_id=$1 AND user_id=$2 AND state IN ('pending','approved') ORDER BY created_at DESC`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, state string
		var reset, approval bool
		var eff, created time.Time
		if err := rows.Scan(&id, &state, &reset, &approval, &eff, &created); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "state": state, "reset_mfa": reset, "approval_required": approval, "effective_at": eff, "created_at": created})
	}
	return out, rows.Err()
}

// ExecuteDueRecoveries runs scheduled recoveries whose cooling-off period has
// passed and whose required approval was given; stale ones expire.
func (s *Service) ExecuteDueRecoveries(ctx context.Context) (int, error) {
	now := s.d.Now()
	if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE assisted_recoveries SET state='expired' WHERE state IN ('pending','approved') AND expires_at <= $1`, now); err != nil {
		return 0, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, realm_id, user_id, requested_by_id, reason, evidence_reference, reset_mfa FROM assisted_recoveries
		WHERE effective_at <= $1 AND ((state='pending' AND NOT approval_required) OR state='approved') ORDER BY effective_at, id LIMIT 50`, now)
	if err != nil {
		return 0, err
	}
	type due struct {
		id, realm, by string
		in            AssistedRecoveryInput
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.realm, &d.in.UserID, &d.by, &d.in.Reason, &d.in.Evidence, &d.in.ResetMFA); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	// Each recovery runs in its own transaction; a failing one does not hold
	// up the others, and the first error is reported after the batch.
	n := 0
	var firstErr error
	for _, d := range list {
		rlm, err := s.Realms.ByID(ctx, nil, d.realm)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cancelled := false
		err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			// Conditions are re-checked at execution time: the account must still
			// be recoverable and the requester must still hold the authority the
			// request needed when it was made.
			cancel := ""
			var userState string
			if err := tx.QueryRow(ctx, `SELECT state FROM users WHERE realm_id=$1 AND id=$2`, d.realm, d.in.UserID).Scan(&userState); err != nil ||
				userState == "deleted" {
				cancel = "account_unavailable"
			} else {
				scope := authorization.Scope{Type: authorization.ScopeRealm, ID: d.realm}
				requester := authorization.Subject{Type: authorization.SubjectUser, ID: d.by}
				// The same rule as the request route: support.recovery.assist or
				// realm.users.credentials.manage, and the latter for a factor reset.
				manage := s.Authz.Check(ctx, tx, d.realm, requester, "realm.users.credentials.manage", scope)
				if !(manage || s.Authz.Check(ctx, tx, d.realm, requester, "support.recovery.assist", scope)) || (d.in.ResetMFA && !manage) {
					cancel = "requester_no_longer_authorized"
				} else if u, err := s.Users.User(ctx, tx, d.realm, d.in.UserID); err != nil {
					return err
				} else if recoveryContactUnverified(u) {
					// The setup link would go to an unverified address.
					cancel = "contact_unverified"
				}
			}
			if cancel != "" {
				cancelled = true
				if _, err := tx.Exec(ctx, `UPDATE assisted_recoveries SET state='cancelled' WHERE id=$1 AND state IN ('pending','approved')`, d.id); err != nil {
					return err
				}
				_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "recovery.assisted.cancelled", RealmID: d.realm, Actor: audit.System, Category: "security",
					Subject: &audit.Ref{Type: "user", ID: d.in.UserID}, Target: &audit.Ref{Type: "assisted_recovery", ID: d.id}, ReasonCode: cancel})
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE assisted_recoveries SET state='completed', completed_at=$2 WHERE id=$1 AND state IN ('pending','approved')`, d.id, now)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			_, err = s.ExecuteAssistedRecoveryTx(ctx, tx, rlm, d.in, audit.Ref{Type: "user", ID: d.by}, d.id)
			return err
		})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !cancelled {
			n++
		}
	}
	return n, firstErr
}
