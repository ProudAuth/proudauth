// Package restore exports security-state changes to independent storage and
// re-applies them after a database restore, so restoring an old backup cannot
// silently resurrect revoked sessions, consumed invitations and proofs, deleted
// accounts or compromised keys (OPS-014, PRV-006, MIG-017, TEST-060). A
// restore marker (Begin) keeps a restored database out of traffic until the
// reconciliation has run.
package restore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/storage"
)

// Record is one security-state change. It contains identifiers and digests only.
type Record struct {
	// Kind is one of: revocation | tombstone | key_compromised | user_state |
	// invitation_consumed | password_changed | client_credential_revoked |
	// automation_credential_revoked | membership_state, and the proof
	// consumptions (TEST-060): refresh_rotated | refresh_family_revoked |
	// grant_revoked | recovery_code_consumed | recovery_codes_replaced |
	// hotp_counter | initial_access_token | registration_token_rotated.
	Kind          string `json:"kind"`
	RealmID       string `json:"realm_id"`
	ReferenceType string `json:"reference_type,omitempty"`
	ReferenceID   string `json:"reference_id"`
	Digest        string `json:"digest,omitempty"`
	State         string `json:"state,omitempty"`
	Reason        string `json:"reason,omitempty"`
	// Counter is a non-secret count: the next HOTP counter value, or the
	// uses of an initial access token.
	Counter int64     `json:"counter,omitempty"`
	At      time.Time `json:"at"`
}

// Export writes records changed since a point in time as JSON lines.
func Export(ctx context.Context, db *storage.DB, since time.Time, w io.Writer) (int, error) {
	enc := json.NewEncoder(w)
	n := 0
	emit := func(r Record) error {
		n++
		return enc.Encode(r)
	}
	queries := []struct {
		sql  string
		scan func(pgx.Rows) (Record, error)
	}{
		{`SELECT realm_id, reference_type, reference_id, reason, effective_at FROM token_revocations WHERE effective_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "revocation"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceType, &rec.ReferenceID, &rec.Reason, &rec.At)
			}},
		{`SELECT realm_id, reference_type, reference_digest, reference_id, created_at FROM deletion_tombstones WHERE created_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "tombstone"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceType, &rec.Digest, &rec.ReferenceID, &rec.At)
			}},
		{`SELECT realm_id, kid, compromised_at FROM signing_keys WHERE state='compromised' AND compromised_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "key_compromised"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.At)
			}},
		{`SELECT realm_id, id, state, updated_at FROM users WHERE state IN ('suspended','locked','deleted','pending_deletion') AND updated_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "user_state"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.State, &rec.At)
			}},
		{`SELECT realm_id, id, state, updated_at FROM invitations WHERE state IN ('accepted','revoked','declined') AND updated_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "invitation_consumed"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.State, &rec.At)
			}},
		// Password changes after the backup: the restored (older) verifier must not
		// become usable again. Only the user and time are exported, never a verifier.
		{`SELECT realm_id, user_id, id, created_at FROM credentials WHERE type='password' AND state='active' AND created_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				// Digest carries the current credential's ID (not secret material).
				rec := Record{Kind: "password_changed", ReferenceType: "user"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.Digest, &rec.At)
			}},
		{`SELECT realm_id, id, revoked_at FROM client_credentials WHERE state='revoked' AND revoked_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "client_credential_revoked"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.At)
			}},
		{`SELECT realm_id, id, revoked_at FROM automation_credentials WHERE state='revoked' AND revoked_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "automation_credential_revoked"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.At)
			}},
		{`SELECT realm_id, id, state, updated_at FROM memberships WHERE state IN ('removed','suspended','expired') AND updated_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "membership_state"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.State, &rec.At)
			}},
		// Proof consumption (TEST-060). A refresh family rotated after the
		// backup would come back with an already consumed generation as its
		// current token, while the token its holder now has is not in the
		// restore: the family is revoked when its restored generation is
		// older than the exported one (Counter).
		{`SELECT f.realm_id, f.id, f.current_generation, max(t.consumed_at) FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id
			WHERE t.consumed_at >= $1 GROUP BY f.realm_id, f.id, f.current_generation`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "refresh_rotated"}
				var gen int32
				err := r.Scan(&rec.RealmID, &rec.ReferenceID, &gen, &rec.At)
				rec.Counter = int64(gen)
				return rec, err
			}},
		// Families ended by /oauth/revoke, refresh reuse or a grant revocation.
		{`SELECT realm_id, id, state, revoked_at FROM refresh_families WHERE state IN ('revoked','compromised') AND revoked_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "refresh_family_revoked"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.State, &rec.At)
			}},
		{`SELECT realm_id, id, revoked_at FROM authorization_grants WHERE state='revoked' AND revoked_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "grant_revoked"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.At)
			}},
		{`SELECT realm_id, id, consumed_at FROM recovery_codes WHERE state='consumed' AND consumed_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "recovery_code_consumed"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.At)
			}},
		// A batch issued after the backup replaced every earlier code of the
		// user. Digest carries the newest batch ID (not secret material;
		// batch IDs are time-ordered, which breaks ties of created_at).
		{`SELECT DISTINCT ON (user_id) realm_id, user_id, batch_id, created_at FROM recovery_codes WHERE created_at >= $1 ORDER BY user_id, created_at DESC, batch_id DESC`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "recovery_codes_replaced", ReferenceType: "user"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.Digest, &rec.At)
			}},
		// The HOTP counter is the next acceptable value, not a secret; a
		// restored lower counter would accept codes already used.
		{`SELECT realm_id, id, counter, last_used_at FROM credentials WHERE type='hotp' AND counter IS NOT NULL AND last_used_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "hotp_counter"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.Counter, &rec.At)
			}},
		{`SELECT realm_id, id, uses, state, last_used_at FROM client_registration_tokens WHERE kind='initial' AND last_used_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "initial_access_token"}
				var uses int32
				err := r.Scan(&rec.RealmID, &rec.ReferenceID, &uses, &rec.State, &rec.At)
				rec.Counter = int64(uses)
				return rec, err
			}},
		// Initial access tokens carry no revocation time; the audit evidence
		// of the revocation does.
		{`SELECT realm_id, target_id, occurred_at FROM audit_events WHERE type='client_registration.initial_token.revoked' AND realm_id IS NOT NULL AND target_id IS NOT NULL AND occurred_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "initial_access_token", State: "revoked"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.At)
			}},
		// A registration access token replaced after the backup (RFC 7592
		// management rotates it): the restored older token must not work.
		// Digest carries the ID of the client's current token.
		{`SELECT realm_id, client_ref, id, created_at FROM client_registration_tokens WHERE kind='registration' AND state='active' AND client_ref IS NOT NULL AND created_at >= $1`,
			func(r pgx.Rows) (Record, error) {
				rec := Record{Kind: "registration_token_rotated", ReferenceType: "client"}
				return rec, r.Scan(&rec.RealmID, &rec.ReferenceID, &rec.Digest, &rec.At)
			}},
	}
	for _, q := range queries {
		rows, err := db.Pool.Query(ctx, q.sql, since)
		if err != nil {
			return n, err
		}
		for rows.Next() {
			rec, err := q.scan(rows)
			if err != nil {
				rows.Close()
				return n, err
			}
			if err := emit(rec); err != nil {
				rows.Close()
				return n, err
			}
		}
		rows.Close()
	}
	return n, nil
}

// Options control reconciliation.
type Options struct {
	// InvalidateAllSessions revokes every session and refresh family: use when the
	// gap between backup and incident cannot be reconstructed.
	InvalidateAllSessions bool
	// Actor is the operator running the reconciliation, recorded as the
	// actor of its audit event (default: operator "restore").
	Actor audit.Ref
}

// Report summarizes reconciliation.
type Report struct {
	Applied         map[string]int `json:"applied"`
	SessionsRevoked int64          `json:"sessions_revoked"`
	FamiliesRevoked int64          `json:"refresh_families_revoked"`
	// ProofsInvalidated counts the outstanding one-time proofs (codes, links,
	// challenges, ceremonies) ended because a restored database cannot tell
	// them from ones consumed after the backup (TEST-060).
	ProofsInvalidated map[string]int64 `json:"proofs_invalidated"`
	// RestoreMarkerCleared reports that the marker set by restore-begin was
	// cleared, so the database reports ready again.
	RestoreMarkerCleared bool `json:"restore_marker_cleared"`
}

// oneTimeProofs end every outstanding single-use secret of a restored
// database. One consumed after the backup is outstanding again in the
// restore, and nothing outside the database records the consumption, so all
// of them go; the legitimate holder asks for a new one (TEST-060). $1 is the
// reconciliation time.
var oneTimeProofs = []struct{ name, sql string }{
	// Password reset, verification, sign-in OTP, magic-link, account-setup,
	// identifier-change and registration codes and links.
	{"challenges", `UPDATE challenges SET superseded_at=$1 WHERE consumed_at IS NULL AND superseded_at IS NULL AND expires_at > $1`},
	{"authorization_codes", `UPDATE authorization_codes SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"pushed_authorization_requests", `UPDATE pushed_authorization_requests SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"device_codes", `UPDATE device_codes SET state='expired', expires_at=LEAST(expires_at, $1) WHERE state IN ('pending','approved')`},
	{"auth_transactions", `UPDATE auth_transactions SET status='expired', updated_at=$1 WHERE status='pending'`},
	{"webauthn_ceremonies", `UPDATE webauthn_ceremonies SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"federation_requests", `UPDATE federation_requests SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"saml_idp_requests", `UPDATE saml_idp_requests SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"saml_broker_requests", `UPDATE saml_broker_requests SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"impersonation_handoffs", `UPDATE impersonation_handoffs SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
	{"job_download_tokens", `UPDATE job_download_tokens SET expires_at=$1 WHERE consumed_at IS NULL AND expires_at > $1`},
}

// Reconcile re-applies records to a restored database. It is idempotent.
//
// Besides the records, it always ends every outstanding one-time proof
// (oneTimeProofs) and clears the restore marker (Begin), in the same
// transaction.
func Reconcile(ctx context.Context, db *storage.DB, r io.Reader, opts Options, now time.Time, rec *audit.Recorder) (*Report, error) {
	// The whole log is read before the transaction: a malformed line changes
	// nothing, and a retried transaction (DB-014) applies every record again
	// instead of finding the reader drained.
	var records []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var x Record
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			return nil, err
		}
		records = append(records, x)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var rep *Report
	err := db.Tx(ctx, func(tx pgx.Tx) error {
		rep = &Report{Applied: map[string]int{}, ProofsInvalidated: map[string]int64{}}
		for _, x := range records {
			var err error
			switch x.Kind {
			case "revocation":
				switch x.ReferenceType {
				case "session":
					_, err = tx.Exec(ctx, `UPDATE sessions SET state='revoked', revoked_at=$2, revoke_reason='restore_reconcile', cookie_digest=NULL WHERE id=$1 AND state='active'`, x.ReferenceID, now)
				case "family":
					_, err = tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason='restore_reconcile' WHERE id=$1 AND state='active'`, x.ReferenceID, now)
				case "grant":
					_, err = tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=$2 WHERE id=$1 AND state='active'`, x.ReferenceID, now)
				case "user":
					_, err = tx.Exec(ctx, `UPDATE sessions SET state='revoked', revoked_at=$2, revoke_reason='restore_reconcile', cookie_digest=NULL WHERE user_id=$1 AND state='active'`, x.ReferenceID, now)
					if err == nil {
						_, err = tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2 WHERE state='active' AND grant_id IN (SELECT id FROM authorization_grants WHERE subject_id=$1)`, x.ReferenceID, now)
					}
				case "client":
					_, err = tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2 WHERE client_ref=$1 AND state='active'`, x.ReferenceID, now)
				case "jti":
					// Recorded so online verifiers keep rejecting it.
				}
				if err == nil {
					_, err = tx.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
						SELECT 'rvk_restore_' || md5($2 || $3), $1, $2, $3, $4, $5 WHERE NOT EXISTS
						(SELECT 1 FROM token_revocations WHERE reference_type=$2 AND reference_id=$3)`, x.RealmID, x.ReferenceType, x.ReferenceID, x.Reason, x.At)
				}
			case "tombstone":
				_, err = tx.Exec(ctx, `INSERT INTO deletion_tombstones (id, realm_id, reference_type, reference_digest, reference_id, action)
					SELECT 'tmb_restore_' || md5($3), $1, $2, $3, $4, 'deleted' WHERE NOT EXISTS (SELECT 1 FROM deletion_tombstones WHERE reference_digest=$3)`,
					x.RealmID, x.ReferenceType, x.Digest, x.ReferenceID)
				if err == nil && x.ReferenceType == "user" {
					// The account was deleted after the backup: erase it again,
					// exactly as the deletion did (PRV-005, OPS-006).
					err = identity.EraseAccountDataTx(ctx, tx, x.RealmID, x.ReferenceID, now)
				}
			case "key_compromised":
				_, err = tx.Exec(ctx, `UPDATE signing_keys SET state='compromised', compromised_at=coalesce(compromised_at, $2) WHERE kid=$1`, x.ReferenceID, x.At)
			case "user_state":
				if x.State == "suspended" || x.State == "locked" {
					_, err = tx.Exec(ctx, `UPDATE users SET state=$2 WHERE id=$1 AND state='active'`, x.ReferenceID, x.State)
					if err == nil {
						_, err = tx.Exec(ctx, `UPDATE sessions SET state='revoked', revoked_at=$2, cookie_digest=NULL WHERE user_id=$1 AND state='active'`, x.ReferenceID, now)
					}
				}
			case "invitation_consumed":
				_, err = tx.Exec(ctx, `UPDATE invitations SET state=$2 WHERE id=$1 AND state IN ('created','pending_delivery','pending_acceptance')`, x.ReferenceID, x.State)
			case "password_changed":
				// The password in the backup predates a change: it is treated as
				// compromised and the user must set a new one; their sessions end.
				// A restore that already holds the current password (a record
				// from an overlapping log that predates the backup) changes
				// nothing, and its sessions stay.
				compromised, e := tx.Exec(ctx, `UPDATE credentials SET state='compromised', updated_at=$2 WHERE user_id=$1 AND type='password' AND state='active' AND id <> $3`,
					x.ReferenceID, now, x.Digest)
				err = e
				stale := err == nil && compromised.RowsAffected() > 0
				if err == nil {
					// The current credential is not in the restore: the user
					// sets a new password. Adding the action moves the
					// account version, as identity.AddRequiredActionTx does,
					// so a conditional required-action edit based on the
					// restored list is refused (412).
					var missing bool
					err = tx.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM credentials WHERE id=$1 AND state='active')`, x.Digest).Scan(&missing)
					if err == nil && missing {
						_, err = tx.Exec(ctx, `UPDATE users SET required_actions=array_append(required_actions, 'update_password'), version=version+1
							WHERE id=$1 AND NOT ('update_password' = ANY(required_actions))`, x.ReferenceID)
					}
					stale = stale || missing
				}
				if err == nil && stale {
					_, err = tx.Exec(ctx, `UPDATE sessions SET state='revoked', revoked_at=$2, revoke_reason='restore_reconcile', cookie_digest=NULL WHERE user_id=$1 AND state='active'`, x.ReferenceID, now)
				}
			case "client_credential_revoked":
				_, err = tx.Exec(ctx, `UPDATE client_credentials SET state='revoked', revoked_at=coalesce(revoked_at, $2) WHERE id=$1 AND state<>'revoked'`, x.ReferenceID, x.At)
			case "automation_credential_revoked":
				_, err = tx.Exec(ctx, `UPDATE automation_credentials SET state='revoked', revoked_at=coalesce(revoked_at, $2) WHERE id=$1 AND state<>'revoked'`, x.ReferenceID, x.At)
			case "membership_state":
				_, err = tx.Exec(ctx, `UPDATE memberships SET state=$2, removed_at=CASE WHEN $2='removed' THEN coalesce(removed_at, $3) ELSE removed_at END
					WHERE id=$1 AND state='active'`, x.ReferenceID, x.State, x.At)
				if err == nil && (x.State == "removed" || x.State == "expired") {
					_, err = tx.Exec(ctx, `DELETE FROM role_assignments WHERE membership_id=$1`, x.ReferenceID)
					if err == nil {
						// Membership metadata ends with the membership (USR-009).
						_, err = tx.Exec(ctx, `UPDATE memberships SET metadata='{}' WHERE id=$1`, x.ReferenceID)
					}
				}
			case "refresh_rotated":
				// The restored current generation was consumed after the backup
				// and its successor is not in the restore. A family restored at
				// the exported generation was not rotated since and stays.
				_, err = tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason='restore_reconcile'
					WHERE id=$1 AND state='active' AND current_generation < $3`, x.ReferenceID, now, int32(x.Counter))
			case "refresh_family_revoked":
				state := "revoked"
				if x.State == "compromised" {
					state = "compromised"
				}
				_, err = tx.Exec(ctx, `UPDATE refresh_families SET state=$2, revoked_at=coalesce(revoked_at, $3), revoke_reason='restore_reconcile' WHERE id=$1 AND state='active'`,
					x.ReferenceID, state, x.At)
			case "grant_revoked":
				// As session.RevokeGrantTx: the grant, its refresh families and
				// its opaque access tokens.
				_, err = tx.Exec(ctx, `UPDATE authorization_grants SET state='revoked', revoked_at=coalesce(revoked_at, $2), revoke_reason='restore_reconcile' WHERE id=$1 AND state='active'`, x.ReferenceID, x.At)
				if err == nil {
					_, err = tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason='restore_reconcile' WHERE grant_id=$1 AND state='active'`, x.ReferenceID, now)
				}
				if err == nil {
					_, err = tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE grant_id=$1 AND revoked_at IS NULL`, x.ReferenceID, now)
				}
			case "recovery_code_consumed":
				_, err = tx.Exec(ctx, `UPDATE recovery_codes SET state='consumed', consumed_at=coalesce(consumed_at, $2) WHERE id=$1 AND state='active'`, x.ReferenceID, x.At)
			case "recovery_codes_replaced":
				// Every code of an earlier batch was invalidated by the newer
				// batch, which itself is not in the restore when it came later.
				_, err = tx.Exec(ctx, `UPDATE recovery_codes SET state='invalidated' WHERE user_id=$1 AND state='active' AND batch_id <> $2`, x.ReferenceID, x.Digest)
			case "hotp_counter":
				// Counters only move forward: codes below the exported value
				// were used (or skipped) after the backup.
				_, err = tx.Exec(ctx, `UPDATE credentials SET counter=$2 WHERE id=$1 AND type='hotp' AND coalesce(counter, 0) < $2`, x.ReferenceID, x.Counter)
			case "initial_access_token":
				// Uses only grow; a token exhausted or revoked after the backup
				// stays so. An exhausted count is re-derived from max_uses.
				_, err = tx.Exec(ctx, `UPDATE client_registration_tokens SET uses=GREATEST(uses, $2),
					state = CASE WHEN state <> 'active' THEN state
						WHEN $3 = 'revoked' THEN 'revoked'
						WHEN $3 = 'exhausted' OR (max_uses IS NOT NULL AND GREATEST(uses, $2) >= max_uses) THEN 'exhausted'
						ELSE state END
					WHERE id=$1 AND kind='initial'`, x.ReferenceID, int32(x.Counter), x.State)
			case "registration_token_rotated":
				// Only the client's current token (Digest) may stay active; when
				// it is not in the restore, the registrant re-registers.
				_, err = tx.Exec(ctx, `UPDATE client_registration_tokens SET state='revoked' WHERE client_ref=$1 AND kind='registration' AND state='active' AND id <> $2`,
					x.ReferenceID, x.Digest)
			}
			if err != nil {
				return err
			}
			rep.Applied[x.Kind]++
		}
		for _, p := range oneTimeProofs {
			tag, err := tx.Exec(ctx, p.sql, now)
			if err != nil {
				return err
			}
			if n := tag.RowsAffected(); n > 0 {
				rep.ProofsInvalidated[p.name] = n
			}
		}
		// Keys left without an active key after compromise reconciliation must be rotated by the operator.
		if opts.InvalidateAllSessions {
			tag, err := tx.Exec(ctx, `UPDATE sessions SET state='revoked', revoked_at=$1, revoke_reason='restore_invalidation', cookie_digest=NULL WHERE state='active'`, now)
			if err != nil {
				return err
			}
			rep.SessionsRevoked = tag.RowsAffected()
			tag, err = tx.Exec(ctx, `UPDATE refresh_families SET state='revoked', revoked_at=$1, revoke_reason='restore_invalidation' WHERE state='active'`, now)
			if err != nil {
				return err
			}
			rep.FamiliesRevoked = tag.RowsAffected()
			if _, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$1, revoke_reason='restore_invalidation' WHERE state='active'`, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE invitations SET state='revoked' WHERE state IN ('created','pending_delivery','pending_acceptance')`); err != nil {
				return err
			}
		}
		// Reconciliation done: the database may serve traffic again.
		tag, err := tx.Exec(ctx, `UPDATE system_state SET restore_pending_since=NULL, restore_pending_by=NULL WHERE restore_pending_since IS NOT NULL`)
		if err != nil {
			return err
		}
		rep.RestoreMarkerCleared = tag.RowsAffected() > 0
		if rec != nil {
			actor := opts.Actor
			if actor.ID == "" {
				actor = audit.Ref{Type: "operator", ID: "restore"}
			}
			_, err := rec.Record(ctx, tx, audit.Event{Type: "operations.restore.reconciled", Actor: actor, Category: "emergency",
				Metadata: map[string]any{"applied": rep.Applied, "invalidate_all_sessions": opts.InvalidateAllSessions,
					"proofs_invalidated": rep.ProofsInvalidated, "restore_marker_cleared": rep.RestoreMarkerCleared}})
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// Marker is the restore marker of a database (Begin).
type Marker struct {
	Since time.Time `json:"since"`
	By    string    `json:"by"`
}

// Begin marks a restored database as not reconciled: until Reconcile runs,
// /health/ready reports "restore_pending" and identity-worker refuses to
// start, so load balancers send it no traffic (TEST-060, OPS-014). Marking an
// already marked database keeps the first marker.
func Begin(ctx context.Context, q storage.Querier, actor string, now time.Time) (*Marker, error) {
	if _, err := q.Exec(ctx, `INSERT INTO system_state (id, restore_pending_since, restore_pending_by) VALUES (true, $1, $2)
		ON CONFLICT (id) DO UPDATE SET restore_pending_since=coalesce(system_state.restore_pending_since, $1),
			restore_pending_by=CASE WHEN system_state.restore_pending_since IS NULL THEN $2 ELSE system_state.restore_pending_by END`, now, actor); err != nil {
		return nil, err
	}
	return Pending(ctx, q)
}

// Pending returns the restore marker, or nil when the database is not
// waiting for reconciliation (every database never marked).
func Pending(ctx context.Context, q storage.Querier) (*Marker, error) {
	var since *time.Time
	var by *string
	err := q.QueryRow(ctx, `SELECT restore_pending_since, restore_pending_by FROM system_state`).Scan(&since, &by)
	if storage.IsNoRows(err) || (err == nil && since == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m := &Marker{Since: *since}
	if by != nil {
		m.By = *by
	}
	return m, nil
}
