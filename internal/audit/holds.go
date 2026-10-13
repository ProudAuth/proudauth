package audit

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// LegalHold keeps matching audit events from retention pruning (AUD-009):
// every event of the realm, or of one organization, or about one subject.
type LegalHold struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id,omitempty"`
	SubjectID      string     `json:"subject_id,omitempty"`
	Reason         string     `json:"reason"`
	CreatedByID    string     `json:"created_by_id"`
	CreatedAt      time.Time  `json:"created_at"`
	ReleasedByID   string     `json:"released_by_id,omitempty"`
	ReleasedAt     *time.Time `json:"released_at,omitempty"`
}

// PlaceHold records a legal hold and its audit event.
func (r *Recorder) PlaceHold(ctx context.Context, db *storage.DB, realmID, orgID, subjectID, reason string, actor Ref) (*LegalHold, error) {
	if len(strings.TrimSpace(reason)) < 5 || len(reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "a reason of 5 to 500 characters is required")
	}
	h := &LegalHold{ID: ids.New("hld"), OrganizationID: orgID, SubjectID: subjectID, Reason: reason, CreatedByID: actor.ID, CreatedAt: r.Now().UTC()}
	err := db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_legal_holds (id, realm_id, organization_id, subject_id, reason, created_by_id, created_at)
			VALUES ($1,$2,nullif($3,''),nullif($4,''),$5,$6,$7)`, h.ID, realmID, orgID, subjectID, reason, actor.ID, h.CreatedAt); err != nil {
			return err
		}
		_, err := r.Record(ctx, tx, Event{Type: "audit.legal_hold.placed", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "audit",
			Target: &Ref{Type: "legal_hold", ID: h.ID}, ReasonCode: reason, Metadata: map[string]any{"subject_id": subjectID}})
		return err
	})
	return h, err
}

// ReleaseHold ends a legal hold; retention applies to its events again.
func (r *Recorder) ReleaseHold(ctx context.Context, db *storage.DB, realmID, id string, actor Ref) error {
	return db.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE audit_legal_holds SET released_at=$3, released_by_id=$4 WHERE realm_id=$1 AND id=$2 AND released_at IS NULL`,
			realmID, id, r.Now().UTC(), actor.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = r.Record(ctx, tx, Event{Type: "audit.legal_hold.released", RealmID: realmID, Actor: actor, Category: "audit",
			Target: &Ref{Type: "legal_hold", ID: id}})
		return err
	})
}

// Holds lists a realm's legal holds, active first.
func Holds(ctx context.Context, q storage.Querier, realmID string) ([]LegalHold, error) {
	rows, err := q.Query(ctx, `SELECT id, coalesce(organization_id,''), coalesce(subject_id,''), reason, created_by_id, created_at,
		coalesce(released_by_id,''), released_at FROM audit_legal_holds WHERE realm_id=$1 ORDER BY released_at NULLS FIRST, created_at DESC LIMIT 500`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LegalHold{}
	for rows.Next() {
		var h LegalHold
		if err := rows.Scan(&h.ID, &h.OrganizationID, &h.SubjectID, &h.Reason, &h.CreatedByID, &h.CreatedAt, &h.ReleasedByID, &h.ReleasedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
