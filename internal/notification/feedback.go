package notification

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// OptionalTemplates are the notices a user may mute (MSG-010). Every other
// template is a security or account notice and is always delivered.
var OptionalTemplates = []string{TplNewLogin}

// Preferences returns the user's settings for optional notices (default on).
func (s *Service) Preferences(ctx context.Context, realmID, userID string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, t := range OptionalTemplates {
		out[t] = true
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT template, enabled FROM notification_preferences WHERE realm_id=$1 AND user_id=$2`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var on bool
		if err := rows.Scan(&t, &on); err != nil {
			return nil, err
		}
		if _, ok := out[t]; ok {
			out[t] = on
		}
	}
	return out, rows.Err()
}

// SetPreferences updates optional-notice preferences. Mandatory templates
// cannot be muted.
func (s *Service) SetPreferences(ctx context.Context, realmID, userID string, prefs map[string]bool, actor audit.Ref) error {
	for t := range prefs {
		optional := false
		for _, o := range OptionalTemplates {
			optional = optional || o == t
		}
		if !optional {
			return problem.ErrValidation.WithField(t, "security and account notices cannot be disabled")
		}
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		for t, on := range prefs {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_preferences (realm_id, user_id, template, enabled, updated_at) VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (realm_id, user_id, template) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at`,
				realmID, userID, t, on, s.d.Now()); err != nil {
				return err
			}
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.preferences.updated", RealmID: realmID, Actor: actor, Category: "account",
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"preferences": prefs}})
		return err
	})
}

// DeliveryEvent is a provider feedback event (MSG-007).
type DeliveryEvent struct {
	Type              string `json:"type"` // delivered | bounce | complaint
	Recipient         string `json:"recipient"`
	ProviderMessageID string `json:"provider_message_id"`
	Permanent         bool   `json:"permanent"`
}

// RecordDeliveryEvents applies authenticated provider feedback: permanent
// bounces and complaints suppress the address for optional mail, and bounced
// jobs are marked failed. Feedback never verifies or changes an identity.
func (s *Service) RecordDeliveryEvents(ctx context.Context, realmID string, evs []DeliveryEvent) (int, error) {
	if len(evs) == 0 || len(evs) > 500 {
		return 0, problem.ErrValidation.WithField("events", "1..500 events")
	}
	applied := 0
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		for _, ev := range evs {
			switch ev.Type {
			case "delivered":
			case "bounce":
				if ev.ProviderMessageID != "" {
					if _, err := tx.Exec(ctx, `UPDATE notification_jobs SET state='failed', last_error='bounced', updated_at=$3
						WHERE realm_id=$1 AND provider_message_id=$2`, realmID, ev.ProviderMessageID, s.d.Now()); err != nil {
						return err
					}
				}
				if ev.Permanent && ev.Recipient != "" {
					if err := s.Suppress(ctx, tx, realmID, ev.Recipient, "hard_bounce"); err != nil {
						return err
					}
				}
			case "complaint":
				if ev.Recipient != "" {
					if err := s.Suppress(ctx, tx, realmID, ev.Recipient, "complaint"); err != nil {
						return err
					}
				}
			default:
				return problem.ErrValidation.WithField("type", "delivered, bounce or complaint")
			}
			applied++
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.delivery_events.received", RealmID: realmID, Actor: audit.Ref{Type: "provider", ID: "email"},
			Category: "operations", Metadata: map[string]any{"events": applied}})
		return err
	})
	return applied, err
}

// muted reports whether the user muted an optional template.
func (s *Service) muted(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, realmID, userID, template string) bool {
	if userID == "" {
		return false
	}
	var enabled bool
	if err := q.QueryRow(ctx, `SELECT enabled FROM notification_preferences WHERE realm_id=$1 AND user_id=$2 AND template=$3`,
		realmID, userID, template).Scan(&enabled); err != nil {
		return false
	}
	return !enabled
}

var _ = strings.ToLower
