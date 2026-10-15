// Package events implements the transactional outbox (ARC-003) and the versioned
// event envelope delivered to webhooks and internal workers.
package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/storage"
)

// Event is the versioned envelope (EXT-008). Consumers deduplicate by EventID (EXT-002).
type Event struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	EventVersion int       `json:"event_version"`
	OccurredAt   time.Time `json:"occurred_at"`
	RealmID      string    `json:"realm_id,omitempty"`
	OrgID        string    `json:"org_id,omitempty"`
	// CorrelationID is the request ID of the API request that caused the
	// event, matching request_id in the audit log (API-012).
	CorrelationID string         `json:"correlation_id,omitempty"`
	AggregateType string         `json:"-"`
	AggregateID   string         `json:"-"`
	Data          map[string]any `json:"data"`
}

// Outbox appends events inside the caller's transaction.
type Outbox struct {
	Now func() time.Time
}

// Publish appends ev through q (the mutation's transaction). Delivery happens after
// commit in the worker (ARC-004).
func (o *Outbox) Publish(ctx context.Context, q storage.Querier, ev Event) (string, error) {
	if ev.EventID == "" {
		ev.EventID = ids.New(ids.Outbox)
	}
	if ev.EventVersion == 0 {
		ev.EventVersion = 1
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = o.Now().UTC()
	}
	if ev.CorrelationID == "" {
		ev.CorrelationID = reqctx.From(ctx).RequestID
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	_, err = q.Exec(ctx, `INSERT INTO outbox_events (id, realm_id, organization_id, event_type, event_version,
		aggregate_type, aggregate_id, payload, occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		ev.EventID, nullable(ev.RealmID), nullable(ev.OrgID), ev.EventType, ev.EventVersion,
		nullable(ev.AggregateType), nullable(ev.AggregateID), payload, ev.OccurredAt)
	return ev.EventID, err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
