package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// ImportedActor is the actor as the source system stated it.
type ImportedActor struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Display string `json:"display,omitempty"`
}

// ImportedRecord is one historical event submitted for import (MIG-016).
type ImportedRecord struct {
	SourceEventID   string         `json:"source_event_id"`
	OccurredAt      time.Time      `json:"occurred_at"`
	Type            string         `json:"type"`
	Organization    string         `json:"organization,omitempty"`
	Actor           *ImportedActor `json:"actor,omitempty"`
	SubjectSourceID string         `json:"subject_source_id,omitempty"`
	Outcome         string         `json:"outcome,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// ImportedEvent is historical evidence carried over from a source system. It
// is stored apart from the server's own events: never sealed into the local
// hash chain, always reported with source "import" and verified false, and it
// keeps the source's identifiers next to any local mapping.
type ImportedEvent struct {
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Verified        bool           `json:"verified"`
	SourceSystem    string         `json:"source_system"`
	SourceEventID   string         `json:"source_event_id"`
	OccurredAt      time.Time      `json:"occurred_at"`
	Type            string         `json:"type"`
	OrganizationID  string         `json:"organization_id,omitempty"`
	Actor           *ImportedActor `json:"actor,omitempty"`
	SubjectID       string         `json:"subject_id,omitempty"`
	SourceSubjectID string         `json:"source_subject_id,omitempty"`
	Outcome         string         `json:"outcome"`
	Metadata        map[string]any `json:"metadata"`
	ContentHash     string         `json:"content_hash"`
	BatchID         string         `json:"batch_id"`
	ImportedAt      time.Time      `json:"imported_at"`
	ImportedBy      Ref            `json:"imported_by"`
	RedactedAt      *time.Time     `json:"redacted_at,omitempty"`
}

// ImportResult reports one submitted record.
type ImportResult struct {
	Index         int    `json:"index"`
	SourceEventID string `json:"source_event_id"`
	Status        string `json:"status"` // imported, duplicate or error
	ID            string `json:"id,omitempty"`
	SubjectID     string `json:"subject_id,omitempty"`
	Error         string `json:"error,omitempty"`
}

// ImportSummary is the outcome of one import batch.
type ImportSummary struct {
	BatchID     string         `json:"batch_id"`
	Counts      map[string]int `json:"counts"`
	BatchDigest string         `json:"batch_digest"`
	Results     []ImportResult `json:"results"`
}

var (
	importedType   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)
	importedSource = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
)

// MaxImportBatch bounds one historical import request.
const MaxImportBatch = 500

// ImportHistory files historical events from sourceSystem (MIG-016). Each
// record is checked and inserted on its own; a source_event_id already
// imported from the same source is a duplicate and left unchanged.
// resolveOrg maps an organization ID or slug to a local ID; subjects are
// mapped through the user import mappings of the same source system. The
// import itself is the only thing this server witnessed, so it records one
// local "audit.history.imported" event whose batch_digest commits to every
// imported record's content_hash.
func (r *Recorder) ImportHistory(ctx context.Context, db *storage.DB, realmID, sourceSystem string, records []ImportedRecord,
	resolveOrg func(context.Context, string) (string, error), actor Ref) (*ImportSummary, error) {
	if !importedSource.MatchString(sourceSystem) {
		return nil, problem.ErrValidation.WithField("source_system", "lowercase letters, digits, dots, underscores and hyphens (at most 63)")
	}
	if len(records) == 0 || len(records) > MaxImportBatch {
		return nil, problem.ErrValidation.WithField("events", fmt.Sprintf("1 to %d events", MaxImportBatch))
	}
	now := r.Now().UTC()
	batchID := ids.New("aib")
	// Records are checked first; the inserts and the local event that
	// witnesses them commit together, so imported history never exists
	// without the record of its import.
	checked := make([]*ImportedEvent, len(records))
	errs := make([]error, len(records))
	for i, rec := range records {
		checked[i], errs[i] = r.checkImported(ctx, realmID, rec, now, resolveOrg)
	}
	var sum *ImportSummary
	err := db.Tx(ctx, func(tx pgx.Tx) error {
		sum = &ImportSummary{BatchID: batchID, Counts: map[string]int{}, Results: []ImportResult{}}
		digest := sha256.New()
		var first, last time.Time
		for i, rec := range records {
			res := ImportResult{Index: i, SourceEventID: rec.SourceEventID}
			if ev := checked[i]; errs[i] != nil {
				res.Status, res.Error = "error", errs[i].Error()
			} else {
				ev.ID, ev.SourceSystem, ev.BatchID, ev.ImportedAt, ev.ImportedBy, ev.SubjectID = ids.New("aie"), sourceSystem, batchID, now, actor, ""
				var subjectState string
				if rec.SubjectSourceID != "" {
					_ = tx.QueryRow(ctx, `SELECT m.local_id, u.state FROM import_mappings m JOIN users u ON u.id=m.local_id
						WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' AND m.source_id=$3`,
						realmID, sourceSystem, rec.SubjectSourceID).Scan(&ev.SubjectID, &subjectState)
				}
				var redactedAt *time.Time
				held := false
				if subjectState == "deleted" {
					// A legal hold keeps the details, as it does for events
					// imported before the deletion (RedactImportedSubjectTx).
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_legal_holds h WHERE h.released_at IS NULL AND h.realm_id=$1
						AND (h.organization_id IS NULL OR h.organization_id=$2) AND (h.subject_id IS NULL OR h.subject_id=$3))`,
						realmID, ev.OrganizationID, ev.SubjectID).Scan(&held); err != nil {
						return err
					}
				}
				if subjectState == "deleted" && !held {
					// History about an account already deleted here keeps only its
					// skeleton, as if it had been imported before the deletion.
					ev.Metadata, ev.SourceSubjectID, redactedAt = map[string]any{}, "", &now
					if ev.Actor != nil {
						a := *ev.Actor
						a.Display = ""
						ev.Actor = &a
					}
				}
				var actorJSON []byte
				if ev.Actor != nil {
					actorJSON, _ = json.Marshal(ev.Actor)
				}
				tag, err := tx.Exec(ctx, `INSERT INTO imported_audit_events (id, realm_id, source_system, source_event_id, occurred_at, event_type,
					organization_id, actor, subject_id, source_subject_id, outcome, metadata, content_hash, batch_id, imported_at, imported_by_type, imported_by_id,
					redacted_at)
					VALUES ($1,$2,$3,$4,$5,$6,nullif($7,''),$8,nullif($9,''),nullif($10,''),$11,$12,$13,$14,$15,$16,$17,$18)
					ON CONFLICT (realm_id, source_system, source_event_id) DO NOTHING`,
					ev.ID, realmID, sourceSystem, ev.SourceEventID, ev.OccurredAt, ev.Type, ev.OrganizationID, actorJSON, ev.SubjectID,
					ev.SourceSubjectID, ev.Outcome, ev.Metadata, ev.ContentHash, batchID, now, actor.Type, actor.ID, redactedAt)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					res.Status = "duplicate"
				} else {
					res.Status, res.ID, res.SubjectID = "imported", ev.ID, ev.SubjectID
					digest.Write([]byte(ev.ContentHash))
					if first.IsZero() || ev.OccurredAt.Before(first) {
						first = ev.OccurredAt
					}
					if ev.OccurredAt.After(last) {
						last = ev.OccurredAt
					}
				}
			}
			sum.Counts[res.Status]++
			sum.Results = append(sum.Results, res)
		}
		sum.BatchDigest = hex.EncodeToString(digest.Sum(nil))
		meta := map[string]any{"batch_id": batchID, "source_system": sourceSystem, "imported": sum.Counts["imported"],
			"duplicates": sum.Counts["duplicate"], "errors": sum.Counts["error"], "batch_digest": sum.BatchDigest}
		if !first.IsZero() {
			meta["earliest_occurred_at"], meta["latest_occurred_at"] = first, last
		}
		_, err := r.Record(ctx, tx, Event{Type: "audit.history.imported", RealmID: realmID, Actor: actor, Category: "audit",
			Target: &Ref{Type: "audit_import_batch", ID: batchID}, Metadata: meta})
		return err
	})
	if err != nil {
		return nil, err
	}
	return sum, nil
}

func (r *Recorder) checkImported(ctx context.Context, realmID string, rec ImportedRecord, now time.Time,
	resolveOrg func(context.Context, string) (string, error)) (*ImportedEvent, error) {
	switch {
	case rec.SourceEventID == "" || len(rec.SourceEventID) > 256 || strings.ContainsAny(rec.SourceEventID, "\x00\r\n"):
		return nil, problem.ErrValidation.WithField("source_event_id", "1 to 256 characters")
	case !importedType.MatchString(rec.Type):
		return nil, problem.ErrValidation.WithField("type", "1 to 128 letters, digits and _ . : / -")
	case rec.OccurredAt.IsZero() || rec.OccurredAt.After(now.Add(5*time.Minute)):
		return nil, problem.ErrValidation.WithField("occurred_at", "a time in the past")
	case len(rec.SubjectSourceID) > 256:
		return nil, problem.ErrValidation.WithField("subject_source_id", "at most 256 characters")
	}
	if a := rec.Actor; a != nil && (a.Type == "" || len(a.Type) > 64 || len(a.ID) > 256 || len(a.Display) > 256) {
		return nil, problem.ErrValidation.WithField("actor", "type (at most 64 characters), id and display (at most 256 each)")
	}
	switch rec.Outcome {
	case "":
		rec.Outcome = "unknown"
	case Success, Failure, Denied, "unknown":
	default:
		return nil, problem.ErrValidation.WithField("outcome", "success, failure, denied or unknown")
	}
	if rec.Metadata == nil {
		rec.Metadata = map[string]any{}
	}
	// Secret-looking members are removed as from local evidence; the content
	// hash still covers the record as submitted.
	if raw, _ := json.Marshal(rec.Metadata); len(raw) > 4096 {
		return nil, problem.ErrValidation.WithField("metadata", "at most 4 KiB")
	}
	ev := &ImportedEvent{Source: "import", SourceEventID: rec.SourceEventID, OccurredAt: rec.OccurredAt.UTC(), Type: rec.Type,
		Actor: rec.Actor, SourceSubjectID: rec.SubjectSourceID, Outcome: rec.Outcome, Metadata: Redact(rec.Metadata)}
	if rec.Organization != "" {
		id, err := resolveOrg(ctx, rec.Organization)
		if err != nil {
			return nil, problem.ErrValidation.WithField("organization", "unknown organization")
		}
		ev.OrganizationID = id
	}
	// The content hash covers the record as the source stated it, so a later
	// reader can match it against the source export.
	canon, _ := json.Marshal(rec)
	h := sha256.Sum256(canon)
	ev.ContentHash = hex.EncodeToString(h[:])
	return ev, nil
}

// ImportedFilter selects imported events.
type ImportedFilter struct {
	RealmID, SourceSystem, SubjectID, OrganizationID, Type, BatchID string
	From, To                                                        *time.Time
	Limit                                                           int
}

// ImportedEvents lists imported historical events, newest first.
func ImportedEvents(ctx context.Context, q storage.Querier, f ImportedFilter) ([]ImportedEvent, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 1000
	}
	rows, err := q.Query(ctx, `SELECT id, source_system, source_event_id, occurred_at, event_type, coalesce(organization_id,''), actor,
		coalesce(subject_id,''), coalesce(source_subject_id,''), outcome, metadata, content_hash, batch_id, imported_at, imported_by_type,
		imported_by_id, redacted_at
		FROM imported_audit_events WHERE realm_id=$1 AND ($2='' OR source_system=$2) AND ($3='' OR subject_id=$3)
		AND ($4='' OR organization_id=$4) AND ($5='' OR event_type=$5) AND ($6='' OR batch_id=$6)
		AND ($7::timestamptz IS NULL OR occurred_at >= $7) AND ($8::timestamptz IS NULL OR occurred_at < $8)
		ORDER BY occurred_at DESC, id LIMIT $9`, f.RealmID, f.SourceSystem, f.SubjectID, f.OrganizationID, f.Type, f.BatchID, f.From, f.To, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImportedEvent{}
	for rows.Next() {
		e := ImportedEvent{Source: "import"}
		var actor []byte
		if err := rows.Scan(&e.ID, &e.SourceSystem, &e.SourceEventID, &e.OccurredAt, &e.Type, &e.OrganizationID, &actor, &e.SubjectID,
			&e.SourceSubjectID, &e.Outcome, &e.Metadata, &e.ContentHash, &e.BatchID, &e.ImportedAt, &e.ImportedBy.Type, &e.ImportedBy.ID, &e.RedactedAt); err != nil {
			return nil, err
		}
		e.OccurredAt, e.ImportedAt = e.OccurredAt.UTC(), e.ImportedAt.UTC()
		if len(actor) > 0 && string(actor) != "null" {
			_ = json.Unmarshal(actor, &e.Actor)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneImported removes imported events whose retention, counted from the
// import, has passed; legal holds apply as they do to local evidence. The
// "imported" category of the retention configuration overrides the default,
// and realms and organizations that keep evidence longer keep their imported
// history longer too (AUD-009): an event goes only when every applicable
// retention has passed, as PruneExpired decides for local events.
func PruneImported(ctx context.Context, tx pgx.Tx, r Retention, max int) (int, error) {
	cutoff := r.Default
	if c, ok := r.Categories["imported"]; ok {
		cutoff = c
	}
	realmIDs, realmCuts := scopeArrays(r.Realms)
	orgIDs, orgCuts := scopeArrays(r.Orgs)
	tag, err := tx.Exec(ctx, `DELETE FROM imported_audit_events e WHERE e.id IN (SELECT e2.id FROM imported_audit_events e2
		LEFT JOIN unnest($3::text[], $4::timestamptz[]) AS rr(id, cutoff) ON rr.id = e2.realm_id
		LEFT JOIN unnest($5::text[], $6::timestamptz[]) AS oo(id, cutoff) ON oo.id = e2.organization_id
		WHERE e2.imported_at < LEAST($1::timestamptz, coalesce(rr.cutoff, 'infinity'::timestamptz), coalesce(oo.cutoff, 'infinity'::timestamptz))
		AND NOT EXISTS (SELECT 1 FROM audit_legal_holds h WHERE h.released_at IS NULL AND h.realm_id = e2.realm_id
			AND (h.organization_id IS NULL OR h.organization_id = e2.organization_id)
			AND (h.subject_id IS NULL OR h.subject_id = e2.subject_id))
		LIMIT $2)`, cutoff, max, realmIDs, realmCuts, orgIDs, orgCuts)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// RedactImportedSubjectTx removes the source-supplied details of imported
// events about a deleted account (PRV-004): the metadata, the source subject
// ID and the actor display name. The event skeleton (type, time, outcome,
// content hash) stays for the retention period. Events under a legal hold
// are left intact.
func RedactImportedSubjectTx(ctx context.Context, tx pgx.Tx, realmID, userID string, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE imported_audit_events e SET metadata='{}', source_subject_id=NULL,
		actor = CASE WHEN actor IS NULL THEN NULL ELSE actor - 'display' END, redacted_at=$3
		WHERE e.realm_id=$1 AND e.subject_id=$2 AND e.redacted_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM audit_legal_holds h WHERE h.released_at IS NULL AND h.realm_id = e.realm_id
			AND (h.organization_id IS NULL OR h.organization_id = e.organization_id)
			AND (h.subject_id IS NULL OR h.subject_id = e.subject_id))`, realmID, userID, now)
	return err
}
