package directory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/storage"
)

// link is a directory account link: a connector-scoped external ID with
// link_kind 'directory' (PROV-004). An account has at most one, enforced by
// a unique index, so two directories never both own its password or
// attributes.
type link struct {
	ConnectorID  string
	ExternalID   string
	UserID       string
	DN           string
	SourceState  string
	Snapshot     map[string]string
	MissingSince *time.Time
	LastSeenAt   *time.Time
}

const linkCols = `connector_id, external_id, local_id, coalesce(source_dn,''), coalesce(source_state,'active'), coalesce(snapshot,'{}'::jsonb),
	missing_since, last_seen_at`

func scanLink(row pgx.Row) (*link, error) {
	var l link
	var snap []byte
	if err := row.Scan(&l.ConnectorID, &l.ExternalID, &l.UserID, &l.DN, &l.SourceState, &snap, &l.MissingSince, &l.LastSeenAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(snap, &l.Snapshot)
	if l.Snapshot == nil {
		l.Snapshot = map[string]string{}
	}
	return &l, nil
}

func (s *Service) linkByExternal(ctx context.Context, q storage.Querier, connectorID, ext string, forUpdate bool) (*link, error) {
	lock := ""
	if forUpdate {
		lock = " FOR UPDATE"
	}
	l, err := scanLink(q.QueryRow(ctx, `SELECT `+linkCols+` FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User'
		AND link_kind='directory' AND external_id=$2`+lock, connectorID, ext))
	if storage.IsNoRows(err) {
		return nil, nil
	}
	return l, err
}

// linkForUser returns an account's directory link and its connector, or
// nils for an account no directory sources.
func (s *Service) linkForUser(ctx context.Context, q storage.Querier, userID string) (*link, *Connector, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	l, err := scanLink(q.QueryRow(ctx, `SELECT `+linkCols+` FROM connector_external_ids WHERE local_id=$1 AND resource_type='User'
		AND link_kind='directory'`, userID))
	if storage.IsNoRows(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	c, err := s.byID(ctx, q, l.ConnectorID)
	if err != nil {
		return nil, nil, err
	}
	return l, c, nil
}

func digest(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(values[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// saveLink inserts or updates a link after an entry was applied.
func (s *Service) saveLink(ctx context.Context, tx pgx.Tx, c *Connector, l *link, runID string) error {
	snap, _ := json.Marshal(l.Snapshot)
	now := s.d.Now()
	_, err := tx.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id, link_kind, source_dn, snapshot,
		snapshot_digest, source_state, last_seen_run, last_seen_at, created_at, updated_at)
		VALUES ($1,'User',$2,$3,'directory',$4,$5,$6,$7,nullif($8,''),$9,$9,$9)
		ON CONFLICT (connector_id, resource_type, external_id) DO UPDATE SET source_dn=$4, snapshot=$5, snapshot_digest=$6, source_state=$7,
			last_seen_run=coalesce(nullif($8,''), connector_external_ids.last_seen_run), last_seen_at=$9, missing_since=NULL,
			resource_version=connector_external_ids.resource_version+1, updated_at=$9`,
		c.ID, l.ExternalID, l.UserID, l.DN, snap, digest(l.Snapshot), l.SourceState, runID, now)
	return err
}

// managedValue reads the current local value of a mapped attribute.
func localValue(u userView, attr string) string {
	switch attr {
	case "username":
		return u.username
	case "email":
		return u.email
	case "display_name":
		return u.displayName
	case "given_name":
		return u.givenName
	case "family_name":
		return u.familyName
	case "locale":
		return u.locale
	case "zoneinfo":
		return u.zoneinfo
	}
	if k, ok := strings.CutPrefix(attr, "profile."); ok {
		if v, ok := u.profile[k]; ok && v != nil {
			if s, ok := v.(string); ok {
				return s
			}
			b, _ := json.Marshal(v)
			return string(b)
		}
	}
	return ""
}

// sameValue compares attribute values the way the attribute is matched:
// identifiers case-insensitively, everything else exactly.
func sameValue(attr, a, b string) bool {
	if attr == "username" || attr == "email" {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return a == b
}
