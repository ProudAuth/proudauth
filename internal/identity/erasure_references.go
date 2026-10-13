package identity

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// referenceErasure removes or ends what other features keep about an account
// (PRV-005), as part of EraseAccountDataTx. $1 is the user ID, $2 the
// deletion time (when a statement uses it).
var referenceErasure = []string{
	// Messages queued before every sender recorded the account: those that
	// reference it, or one of its challenges (password reset, verification,
	// magic link), are purged and attributed like the others.
	`UPDATE notification_jobs SET state=CASE WHEN state IN ('queued','attempted') THEN 'suppressed' ELSE state END, payload_ciphertext=NULL,
		recipient_ciphertext=NULL, payload_purged_at=now(), updated_at=now(), user_id=$1
		WHERE user_id IS NULL AND (payload_ciphertext IS NOT NULL OR recipient_ciphertext IS NOT NULL)
		AND ((reference_type='user' AND reference_id=$1) OR (reference_type='challenge' AND reference_id IN (SELECT id FROM challenges WHERE user_id=$1)))`,
	// Certificate bindings name the account's certificates by issuer and
	// subject (PROV-016).
	`DELETE FROM user_certificate_bindings WHERE user_id=$1`,
	// User-managed sharing (AZ-027): a share the account made ends as if it
	// revoked it (the tuple its acceptance wrote goes), one made to it ends
	// too, and the free-text message goes from every share naming it.
	`DELETE FROM resource_relationships r USING resource_shares s WHERE s.owner_user_id=$1 AND s.state='accepted' AND r.id=s.relationship_id
		AND r.source='share:'||s.id`,
	`UPDATE resource_shares SET decided_at=CASE WHEN state IN ('pending','accepted') THEN $2 ELSE decided_at END,
		state=CASE WHEN state IN ('pending','accepted') THEN 'revoked' ELSE state END, message=NULL
		WHERE owner_user_id=$1 OR recipient_user_id=$1`,
	// Relationship tuples with the account as subject (AZ-021).
	`DELETE FROM resource_relationships WHERE subject_type='user' AND subject_id=$1`,
	// Just-in-time elevation (AZ-024): eligibilities are revoked, pending
	// requests cancelled, and an active elevation ends now; its role
	// assignment expires at once, so the expiry sweep removes it with the
	// usual evidence.
	`UPDATE elevation_eligibilities SET state='revoked' WHERE user_id=$1 AND state='active'`,
	`UPDATE elevations SET state='cancelled', decided_at=$2 WHERE user_id=$1 AND state='pending'`,
	`UPDATE role_assignments SET expires_at=$2 WHERE id IN (SELECT assignment_id FROM elevations WHERE user_id=$1 AND state='active' AND assignment_id IS NOT NULL)
		AND (expires_at IS NULL OR expires_at > $2)`,
	`UPDATE elevations SET state='ended', ends_at=LEAST(coalesce(ends_at, $2), $2) WHERE user_id=$1 AND state='active'`,
}

// eraseReferencesTx runs referenceErasure.
func eraseReferencesTx(ctx context.Context, tx pgx.Tx, userID string, now time.Time) error {
	for _, q := range referenceErasure {
		args := []any{userID}
		if strings.Contains(q, "$2") {
			args = append(args, now)
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			return err
		}
	}
	return nil
}
