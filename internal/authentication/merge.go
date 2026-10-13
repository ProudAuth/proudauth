package authentication

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// MergePlan is the reviewed effect of merging source into survivor (USR-011).
// Nothing in it grants access the survivor did not already have except plain
// organization membership; source roles are listed for administrator review,
// never copied.
type MergePlan struct {
	MoveIdentifiers []string            `json:"move_identifiers"`
	DropIdentifiers []string            `json:"drop_duplicate_identifiers"`
	MoveExternal    []string            `json:"move_external_identities"`
	MoveMemberships []string            `json:"move_memberships_as_member"`
	KeepMemberships []string            `json:"survivor_already_member"`
	RolesForReview  map[string][]string `json:"source_roles_for_review"`
	NotTransferred  []string            `json:"credentials_not_transferred"`
}

// AccountMerge is a merge request.
type AccountMerge struct {
	ID                string     `json:"id"`
	SurvivorID        string     `json:"survivor_id"`
	SourceID          string     `json:"source_id"`
	Reason            string     `json:"reason"`
	Plan              MergePlan  `json:"plan"`
	SurvivorConfirmed *time.Time `json:"survivor_confirmed_at,omitempty"`
	SourceConfirmed   *time.Time `json:"source_confirmed_at,omitempty"`
	State             string     `json:"state"`
	ExpiresAt         time.Time  `json:"expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

func (s *Service) mergePlan(ctx context.Context, q storage.Querier, survivor, source string) (MergePlan, error) {
	p := MergePlan{RolesForReview: map[string][]string{}, MoveIdentifiers: []string{}, DropIdentifiers: []string{}, MoveExternal: []string{},
		MoveMemberships: []string{}, KeepMemberships: []string{}, NotTransferred: []string{}}
	collect := func(sql string, dst *[]string, args ...any) error {
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			*dst = append(*dst, v)
		}
		return rows.Err()
	}
	if err := collect(`SELECT i.id FROM user_identifiers i WHERE i.user_id=$1 AND NOT EXISTS (SELECT 1 FROM user_identifiers j
		WHERE j.user_id=$2 AND j.type=i.type AND j.canonical_value=i.canonical_value)`, &p.MoveIdentifiers, source, survivor); err != nil {
		return p, err
	}
	if err := collect(`SELECT i.id FROM user_identifiers i WHERE i.user_id=$1 AND EXISTS (SELECT 1 FROM user_identifiers j
		WHERE j.user_id=$2 AND j.type=i.type AND j.canonical_value=i.canonical_value)`, &p.DropIdentifiers, source, survivor); err != nil {
		return p, err
	}
	if err := collect(`SELECT id FROM external_identities WHERE user_id=$1`, &p.MoveExternal, source); err != nil {
		return p, err
	}
	if err := collect(`SELECT m.organization_id FROM memberships m WHERE m.user_id=$1 AND m.state='active' AND NOT EXISTS (SELECT 1 FROM memberships s
		WHERE s.user_id=$2 AND s.organization_id=m.organization_id AND s.state NOT IN ('removed','expired'))`, &p.MoveMemberships, source, survivor); err != nil {
		return p, err
	}
	if err := collect(`SELECT m.organization_id FROM memberships m WHERE m.user_id=$1 AND m.state='active' AND EXISTS (SELECT 1 FROM memberships s
		WHERE s.user_id=$2 AND s.organization_id=m.organization_id AND s.state NOT IN ('removed','expired'))`, &p.KeepMemberships, source, survivor); err != nil {
		return p, err
	}
	rows, err := q.Query(ctx, `SELECT coalesce(ra.scope_id,''), r.name FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		WHERE ra.subject_type='user' AND ra.subject_id=$1 ORDER BY 1, 2`, source)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var scope, role string
		if err := rows.Scan(&scope, &role); err != nil {
			rows.Close()
			return p, err
		}
		p.RolesForReview[scope] = append(p.RolesForReview[scope], role)
	}
	rows.Close()
	if err := collect(`SELECT DISTINCT type FROM credentials WHERE user_id=$1 AND state='active'
		UNION SELECT 'webauthn' FROM webauthn_credentials WHERE user_id=$1 AND state='active'`, &p.NotTransferred, source); err != nil {
		return p, err
	}
	return p, nil
}

// ProposeMerge records a merge request with its plan. Both accounts must be
// active, non-guest, non-protected and distinct.
func (s *Service) ProposeMerge(ctx context.Context, realmID, survivor, source, reason string, actor audit.Ref) (*AccountMerge, error) {
	if survivor == source || len(reason) < 10 {
		return nil, problem.ErrValidation.WithDetail("two different accounts and a reason (10+ characters) are required")
	}
	var out *AccountMerge
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.mergeableTx(ctx, tx, realmID, survivor, source); err != nil {
			return err
		}
		// A lapsed proposal never blocks a new one for the same account.
		if _, err := tx.Exec(ctx, `UPDATE account_merges SET state='expired' WHERE realm_id=$1 AND source_id=$2 AND state='pending' AND expires_at <= $3`,
			realmID, source, s.d.Now()); err != nil {
			return err
		}
		plan, err := s.mergePlan(ctx, tx, survivor, source)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(plan)
		m := &AccountMerge{ID: ids.New(ids.AccountMerge), SurvivorID: survivor, SourceID: source, Reason: reason, Plan: plan, State: "pending",
			ExpiresAt: s.d.Now().Add(7 * 24 * time.Hour), CreatedAt: s.d.Now()}
		if _, err := tx.Exec(ctx, `INSERT INTO account_merges (id, realm_id, survivor_id, source_id, requested_by_id, reason, plan, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, m.ID, realmID, survivor, source, actor.ID, reason, raw, m.ExpiresAt, m.CreatedAt); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("a merge of that account is already pending")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.merge.proposed", RealmID: realmID, Actor: actor, Category: "account",
			Subject: &audit.Ref{Type: "user", ID: source}, Target: &audit.Ref{Type: "account_merge", ID: m.ID},
			Metadata: map[string]any{"survivor_id": survivor, "reason": reason}}); err != nil {
			return err
		}
		for _, id := range []string{survivor, source} {
			if err := s.notifySecurity(ctx, tx, realmID, id, "recovery_notice",
				"an administrator proposed merging two accounts including yours; confirm it in your account settings only if both accounts are yours"); err != nil {
				return err
			}
		}
		out = m
		return nil
	})
	return out, err
}

func scanMerge(row pgx.Row) (*AccountMerge, error) {
	var m AccountMerge
	var raw []byte
	err := row.Scan(&m.ID, &m.SurvivorID, &m.SourceID, &m.Reason, &raw, &m.SurvivorConfirmed, &m.SourceConfirmed, &m.State, &m.ExpiresAt, &m.CreatedAt)
	if err == nil {
		_ = json.Unmarshal(raw, &m.Plan)
	}
	return &m, err
}

const mergeCols = `id, survivor_id, source_id, reason, plan, survivor_confirmed, source_confirmed, state, expires_at, created_at`

// MergesFor lists pending merges involving the user (self-service).
func (s *Service) MergesFor(ctx context.Context, realmID, userID string) ([]*AccountMerge, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+mergeCols+` FROM account_merges WHERE realm_id=$1 AND state='pending' AND $2 IN (survivor_id, source_id)
		AND expires_at > $3`, realmID, userID, s.d.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AccountMerge{}
	for rows.Next() {
		m, err := scanMerge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// mergeableTx locks both accounts and checks they can take part in a merge:
// active, unprotected and registered (guests have nothing to merge into).
func (s *Service) mergeableTx(ctx context.Context, tx pgx.Tx, realmID string, accounts ...string) error {
	for _, id := range accounts {
		u, err := s.Users.LockUser(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if u.State != "active" || u.Protected || u.IsGuest {
			return problem.ErrConflict.WithDetail("both accounts must be active, registered and unprotected")
		}
	}
	return nil
}

// CancelMerge withdraws a pending merge: an administrator cancels it, or
// either account owner declines it (USR-011).
func (s *Service) CancelMerge(ctx context.Context, realmID, id, ownerID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE account_merges SET state='cancelled' WHERE realm_id=$1 AND id=$2 AND state='pending'
			AND ($3 = '' OR $3 IN (survivor_id, source_id))`, realmID, id, ownerID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		typ := "user.merge.cancelled"
		if ownerID != "" {
			typ = "user.merge.declined"
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: typ, RealmID: realmID, Actor: actor, Category: "account",
			Target: &audit.Ref{Type: "account_merge", ID: id}})
		return err
	})
}

// ExpireMerges marks lapsed proposals expired.
func (s *Service) ExpireMerges(ctx context.Context) (int, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE account_merges SET state='expired' WHERE state='pending' AND expires_at <= $1`, s.d.Now())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ConfirmMerge records an account owner's consent (USR-011).
func (s *Service) ConfirmMerge(ctx context.Context, realmID, id, userID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE account_merges SET
			survivor_confirmed = CASE WHEN survivor_id=$3 THEN $4 ELSE survivor_confirmed END,
			source_confirmed = CASE WHEN source_id=$3 THEN $4 ELSE source_confirmed END
			WHERE realm_id=$1 AND id=$2 AND state='pending' AND expires_at > $4 AND $3 IN (survivor_id, source_id)`, realmID, id, userID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.merge.confirmed", RealmID: realmID, Actor: actor, Category: "account",
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "account_merge", ID: id}})
		return err
	})
}

// ExecuteMerge applies a confirmed plan in one transaction: identifiers and
// federation links move to the survivor, organizations the survivor did not
// belong to are joined with the member role only, every session of both
// accounts ends, the source becomes a deleted alias of the survivor, and
// applications receive a user.merged event to remap their data.
func (s *Service) ExecuteMerge(ctx context.Context, realmID, id string, actor audit.Ref) (*AccountMerge, error) {
	var out *AccountMerge
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		m, err := scanMerge(tx.QueryRow(ctx, `SELECT `+mergeCols+` FROM account_merges WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return problem.ErrNotFound
		}
		if m.State != "pending" || !s.d.Now().Before(m.ExpiresAt) {
			return problem.ErrConflict.WithDetail("the merge is not pending")
		}
		if m.SurvivorConfirmed == nil || m.SourceConfirmed == nil {
			return problem.ErrConflict.WithDetail("both account owners must confirm the merge first")
		}
		// Either account may have been suspended, protected or deleted since
		// the proposal.
		if err := s.mergeableTx(ctx, tx, realmID, m.SurvivorID, m.SourceID); err != nil {
			return err
		}
		// Re-plan against current state; the executed plan is the one recorded.
		plan, err := s.mergePlan(ctx, tx, m.SurvivorID, m.SourceID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE user_identifiers SET user_id=$2, is_primary=false WHERE id = ANY($1)`, plan.MoveIdentifiers, m.SurvivorID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE external_identities SET user_id=$2 WHERE id = ANY($1)`, plan.MoveExternal, m.SurvivorID); err != nil {
			return err
		}
		// Connector-scoped external IDs follow the account (USR-017). Both
		// accounts' IDs in one source system are kept: the source system had
		// two records for the same person, and either now resolves to the
		// survivor.
		if _, err := tx.Exec(ctx, `UPDATE import_mappings SET local_id=$3 WHERE realm_id=$1 AND source_type='user' AND local_id=$2`,
			realmID, m.SourceID, m.SurvivorID); err != nil {
			return err
		}
		member, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgMember)
		if err != nil {
			return err
		}
		for _, org := range plan.MoveMemberships {
			mid := ids.New(ids.Membership)
			if _, err := tx.Exec(ctx, `INSERT INTO memberships (id, realm_id, organization_id, user_id, state, source, source_reference, joined_at, created_at, updated_at)
				VALUES ($1,$2,$3,$4,'active','admin',$5,$6,$6,$6)`, mid, realmID, org, m.SurvivorID, id, s.d.Now()); err != nil {
				return err
			}
			if _, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: member.ID,
				Subject: authorization.Subject{Type: authorization.SubjectUser, ID: m.SurvivorID}, Scope: authorization.Scope{Type: authorization.ScopeOrganization, ID: org},
				Source: "account_merge", Reason: id, SkipCeiling: true}, actor); err != nil {
				return err
			}
		}
		if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, m.SurvivorID, "account_merged", false); err != nil {
			return err
		}
		if err := s.Users.DeleteNowTx(ctx, tx, realmID, m.SourceID, actor, "account_merged"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO subject_aliases (realm_id, alias_id, user_id, merge_id) VALUES ($1,$2,$3,$4)`,
			realmID, m.SourceID, m.SurvivorID, id); err != nil {
			return err
		}
		raw, _ := json.Marshal(plan)
		if _, err := tx.Exec(ctx, `UPDATE account_merges SET state='completed', plan=$2, executed_by_id=$3, completed_at=$4 WHERE id=$1`,
			id, raw, actor.ID, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.merged", RealmID: realmID, Actor: actor, Category: "account",
			Subject: &audit.Ref{Type: "user", ID: m.SurvivorID}, Target: &audit.Ref{Type: "account_merge", ID: id},
			Metadata: map[string]any{"merged_user_id": m.SourceID, "plan": plan}}); err != nil {
			return err
		}
		if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "user.merged", RealmID: realmID, AggregateType: "user", AggregateID: m.SurvivorID,
			Data: map[string]any{"user_id": m.SurvivorID, "merged_user_id": m.SourceID}}); err != nil {
			return err
		}
		m.State, m.Plan = "completed", plan
		out = m
		return nil
	})
	return out, err
}

// SubjectAlias resolves a merged-away subject to its surviving account.
func (s *Service) SubjectAlias(ctx context.Context, realmID, id string) (string, error) {
	var user string
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT user_id FROM subject_aliases WHERE realm_id=$1 AND alias_id=$2`, realmID, id).Scan(&user); err != nil {
		return "", problem.ErrNotFound
	}
	return user, nil
}
