// Package runtime bundles the shared infrastructure dependencies injected into every
// domain module. Modules talk to each other through explicit service interfaces and
// never share arbitrary table access (ARC-001).
package runtime

import (
	"context"
	"log/slog"
	"time"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/clock"
	"github.com/proudbase/proudauth/internal/storage"
)

// Deps is the shared infrastructure.
type Deps struct {
	DB     *storage.DB
	Cfg    *configuration.Config
	Clock  clock.Clock
	Keys   *keys.Keyring
	Audit  *audit.Recorder
	Outbox *events.Outbox
	Log    *slog.Logger
}

// Now returns the current UTC instant from the injected clock.
func (d *Deps) Now() time.Time { return d.Clock.Now() }

// New wires the recorder and outbox to the clock.
func New(db *storage.DB, cfg *configuration.Config, clk clock.Clock, kr *keys.Keyring, log *slog.Logger) *Deps {
	if log == nil {
		log = slog.Default()
	}
	// The destination residency policy applies to every outbound connector
	// (PRV-003).
	egress.SetResidency(cfg.Privacy.Residency.AllowedDestinations)
	d := &Deps{
		DB:     db,
		Cfg:    cfg,
		Clock:  clk,
		Keys:   kr,
		Audit:  &audit.Recorder{Now: clk.Now, FullIP: cfg.Privacy.StoreFullIP},
		Outbox: &events.Outbox{Now: clk.Now},
		Log:    log,
	}
	// Security alerts (AUD-012): every signal-bearing audit event is also
	// published as a security.alert event for alerting integrations, in the
	// same transaction as its evidence. Alerts carry identifiers, never the
	// event's metadata.
	d.Audit.Alert = func(ctx context.Context, q storage.Querier, ev audit.Event, signal string) error {
		if ev.RealmID == "" {
			return nil
		}
		data := map[string]any{"signal": signal, "audit_event_id": ev.ID, "event_type": ev.Type, "actor_type": ev.Actor.Type, "actor_id": ev.Actor.ID}
		if ev.Subject != nil {
			data["subject_type"], data["subject_id"] = ev.Subject.Type, ev.Subject.ID
		}
		_, err := d.Outbox.Publish(ctx, q, events.Event{EventType: "security.alert", RealmID: ev.RealmID, OrgID: ev.OrgID, AggregateType: "audit_event",
			AggregateID: ev.ID, Data: data})
		return err
	}
	return d
}
