package events

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/storage"
)

// SessionEventTypes are the change notifications applications can follow to
// invalidate local sessions and caches (SES-019).
var SessionEventTypes = []string{
	"session.revoked", "user.suspended", "user.locked", "user.deleted", "user.password_reset", "user.recovery_restricted",
	"security.refresh_reuse_detected", "security.credential_compromised", "organization.membership.removed",
	"organization.membership.suspended", "organization.suspended", "organization.deleted", "authorization.role.unassigned",
	"support.impersonation.ended", "client.state_changed", "signing_key.rotated", "user.merged",
}

// ErrCursorExpired means stream events after the requested position were
// pruned (the position is behind the realm's pruning horizon), so reading on
// from it would skip them. A position whose own event merely aged out on a
// quiet realm stays valid. The consumer resynchronizes by replaying the
// retained history from its beginning (no cursor) while keeping what it
// already knows; continuing from "now" instead would skip the retained events
// that followed the expired cursor.
var ErrCursorExpired = errors.New("events: cursor is older than the retained history")

// StreamEvent is one delivered change.
type StreamEvent struct {
	EventID    string         `json:"event_id"`
	EventType  string         `json:"event_type"`
	OccurredAt time.Time      `json:"occurred_at"`
	OrgID      string         `json:"organization_id,omitempty"`
	Data       map[string]any `json:"data"`
	Cursor     string         `json:"cursor"`
}

// Position is a stream cursor: the commit horizon (transaction ID) and sequence.
type Position struct {
	TxID uint64
	Seq  int64
}

func (p Position) String() string {
	return strconv.FormatUint(p.TxID, 10) + "." + strconv.FormatInt(p.Seq, 10)
}

// ParsePosition parses a cursor value ("" is the beginning of history).
func ParsePosition(s string) (Position, error) {
	if s == "" {
		return Position{}, nil
	}
	a, b, ok := strings.Cut(s, ".")
	if !ok {
		return Position{}, errors.New("invalid cursor")
	}
	tx, err1 := strconv.ParseUint(a, 10, 64)
	seq, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil {
		return Position{}, errors.New("invalid cursor")
	}
	return Position{TxID: tx, Seq: seq}, nil
}

// Head returns the current end of the stream (to start following from "now").
func Head(ctx context.Context, q storage.Querier, realmID string) (Position, error) {
	var p Position
	var tx *string
	var seq *int64
	err := q.QueryRow(ctx, `SELECT tx_id::text, seq FROM outbox_events WHERE realm_id=$1 AND tx_id < pg_snapshot_xmin(pg_current_snapshot())
		ORDER BY tx_id DESC, seq DESC LIMIT 1`, realmID).Scan(&tx, &seq)
	if err != nil {
		if storage.IsNoRows(err) {
			return p, nil
		}
		return p, err
	}
	p.TxID, _ = strconv.ParseUint(*tx, 10, 64)
	p.Seq = *seq
	return p, nil
}

// Read returns up to limit session events after the position. Delivery is
// at-least-once in commit-horizon order with no gaps; history is retained for
// the outbox retention period (7 days after dispatch).
func Read(ctx context.Context, q storage.Querier, realmID string, after Position, limit int) ([]StreamEvent, Position, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if after.TxID > 0 {
		// The cursor expired when stream events after it were pruned.
		var horizonTx *string
		var horizonSeq int64
		if err := q.QueryRow(ctx, `SELECT pruned_tx::text, pruned_seq FROM event_stream_horizon WHERE realm_id=$1`, realmID).Scan(&horizonTx, &horizonSeq); err == nil && horizonTx != nil {
			ht, _ := strconv.ParseUint(*horizonTx, 10, 64)
			if after.TxID < ht || after.TxID == ht && after.Seq < horizonSeq {
				return nil, after, ErrCursorExpired
			}
			goto read
		} else if err != nil && !storage.IsNoRows(err) {
			return nil, after, err
		}
		// Without a recorded horizon: a cursor below every retained row means
		// history was pruned in between.
		var oldest *string
		if err := q.QueryRow(ctx, `SELECT min(tx_id)::text FROM outbox_events WHERE realm_id=$1`, realmID).Scan(&oldest); err != nil {
			return nil, after, err
		}
		if oldest != nil {
			if o, _ := strconv.ParseUint(*oldest, 10, 64); after.TxID+1 < o {
				var pruned bool
				_ = q.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM outbox_events WHERE realm_id=$1 AND tx_id=$2::text::xid8)`, realmID,
					strconv.FormatUint(after.TxID, 10)).Scan(&pruned)
				if pruned {
					return nil, after, ErrCursorExpired
				}
			}
		}
	}
read:
	rows, err := q.Query(ctx, `SELECT tx_id::text, seq, id, event_type, occurred_at, coalesce(organization_id,''), payload FROM outbox_events
		WHERE realm_id=$1 AND event_type = ANY($2) AND tx_id < pg_snapshot_xmin(pg_current_snapshot())
		AND (tx_id, seq) > ($3::text::xid8, $4) ORDER BY tx_id, seq LIMIT $5`,
		realmID, SessionEventTypes, strconv.FormatUint(after.TxID, 10), after.Seq, limit)
	if err != nil {
		return nil, after, err
	}
	defer rows.Close()
	out := []StreamEvent{}
	pos := after
	for rows.Next() {
		var txs string
		var ev StreamEvent
		var seq int64
		var payload []byte
		if err := rows.Scan(&txs, &seq, &ev.EventID, &ev.EventType, &ev.OccurredAt, &ev.OrgID, &payload); err != nil {
			return nil, after, err
		}
		var full struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(payload, &full)
		ev.Data = minimalData(full.Data)
		tx, _ := strconv.ParseUint(txs, 10, 64)
		pos = Position{TxID: tx, Seq: seq}
		ev.Cursor = pos.String()
		out = append(out, ev)
	}
	return out, pos, rows.Err()
}

// minimalData keeps identifiers and states only (no profile or contact data).
func minimalData(d map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range d {
		if strings.HasSuffix(k, "_id") || k == "state" || k == "reason" || k == "mode" || k == "authorization_revision" {
			out[k] = v
		}
	}
	return out
}

// PruneDispatched deletes dispatched outbox events older than before and
// records, per realm, the newest pruned stream position (SES-019). It
// returns the number of pruned events; horizon writes are not counted.
// Events without a realm (platform events) are pruned but have no stream to
// expire, so they never reach the realm-keyed horizon.
func PruneDispatched(ctx context.Context, q storage.Querier, before time.Time) (int64, error) {
	var n int64
	err := q.QueryRow(ctx, `WITH del AS (
			DELETE FROM outbox_events WHERE state='dispatched' AND dispatched_at < $1 RETURNING realm_id, tx_id, seq, event_type),
		horizon AS (
			INSERT INTO event_stream_horizon (realm_id, pruned_tx, pruned_seq)
			SELECT DISTINCT ON (realm_id) realm_id, tx_id, seq FROM del WHERE realm_id IS NOT NULL AND event_type = ANY($2)
				ORDER BY realm_id, tx_id DESC, seq DESC
			ON CONFLICT (realm_id) DO UPDATE SET pruned_tx=EXCLUDED.pruned_tx, pruned_seq=EXCLUDED.pruned_seq, updated_at=now()
				WHERE (EXCLUDED.pruned_tx, EXCLUDED.pruned_seq) > (event_stream_horizon.pruned_tx, event_stream_horizon.pruned_seq))
		SELECT count(*) FROM del`,
		before, SessionEventTypes).Scan(&n)
	return n, err
}
