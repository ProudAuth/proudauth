package identity

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// ExternalID links an account to its identifier in another system (USR-017).
// External IDs are unique only within their source system: the same value in
// two systems maps independently, and a value never doubles as a login
// identifier.
type ExternalID struct {
	SourceSystem string    `json:"source_system"`
	ExternalID   string    `json:"external_id"`
	JobID        string    `json:"job_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

var sourceSystemPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidSourceSystem reports whether a source system name is valid. Imports,
// external IDs, reconciliation and historical audit imports share one rule,
// because import mappings double as external IDs (USR-017).
func ValidSourceSystem(name string) bool { return sourceSystemPattern.MatchString(name) }

func validExternalID(source, value string) error {
	if !sourceSystemPattern.MatchString(source) {
		return problem.ErrValidation.WithField("source_system", "lowercase letters, digits, '.', '_' or '-', at most 63 characters")
	}
	if value == "" || len(value) > 256 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return problem.ErrValidation.WithField("external_id", "1 to 256 printable characters")
	}
	return nil
}

// ExternalIDs lists an account's external IDs.
func (s *Service) ExternalIDs(ctx context.Context, realmID, userID string) ([]ExternalID, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT source_system, source_id, coalesce(job_id,''), created_at FROM import_mappings
		WHERE realm_id=$1 AND source_type='user' AND local_id=$2 ORDER BY source_system`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExternalID{}
	for rows.Next() {
		var e ExternalID
		if err := rows.Scan(&e.SourceSystem, &e.ExternalID, &e.JobID, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetExternalID sets the account's ID in one source system, replacing any
// previous value there. A value already mapped to another account conflicts.
func (s *Service) SetExternalID(ctx context.Context, realmID, userID, source, value string, actor audit.Ref) error {
	if err := validExternalID(source, value); err != nil {
		return err
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		u, err := s.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if u.State == StateDeleted {
			return problem.ErrNotFound
		}
		var owner, ownerState string
		err = tx.QueryRow(ctx, `SELECT m.local_id, coalesce(u.state,'deleted') FROM import_mappings m LEFT JOIN users u ON u.id=m.local_id
			WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' AND m.source_id=$3`, realmID, source, value).Scan(&owner, &ownerState)
		if err == nil && owner != userID {
			if ownerState != StateDeleted {
				return problem.ErrConflict.WithDetail("that external ID belongs to another account in this source system")
			}
			// A deleted account's ID is free to be assigned again.
			if _, err := tx.Exec(ctx, `DELETE FROM import_mappings WHERE realm_id=$1 AND source_system=$2 AND source_type='user' AND source_id=$3`,
				realmID, source, value); err != nil {
				return err
			}
			owner = ""
		}
		if err != nil && !storage.IsNoRows(err) {
			return err
		}
		if owner == userID {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM import_mappings WHERE realm_id=$1 AND source_system=$2 AND source_type='user' AND local_id=$3`,
			realmID, source, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO import_mappings (realm_id, source_system, source_type, source_id, local_id, created_at)
			VALUES ($1,$2,'user',$3,$4,$5)`, realmID, source, value, userID, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.external_id.set", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"source_system": source}})
		return err
	})
}

// RemoveExternalID removes the account's ID in one source system.
func (s *Service) RemoveExternalID(ctx context.Context, realmID, userID, source string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM import_mappings WHERE realm_id=$1 AND source_system=$2 AND source_type='user' AND local_id=$3`,
			realmID, source, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.external_id.removed", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"source_system": source}})
		return err
	})
}

// UserByExternalID resolves an external ID within its source system.
func (s *Service) UserByExternalID(ctx context.Context, realmID, source, value string) (string, error) {
	var id string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT m.local_id FROM import_mappings m JOIN users u ON u.id=m.local_id
		WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' AND m.source_id=$3 AND u.state <> 'deleted'`, realmID, source, value).Scan(&id)
	if storage.IsNoRows(err) {
		return "", problem.ErrNotFound
	}
	return id, err
}
