package directory

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// Schedule is the periodic worker task (PROV-012, PROV-010): it queues due
// synchronization and reconciliation runs, picks up account changes for
// outbound connectors that no outbox event announces (profile edits), and
// refreshes the lag and backlog gauges. Every claim is a conditional update,
// so several workers never schedule the same run twice.
func (s *Service) Schedule(ctx context.Context) (int, error) {
	if !s.active() {
		return 0, nil
	}
	// Runs whose job ended without them (for example while the module was
	// disabled) are closed, so they never block a connector's next run.
	if _, err := s.closeOrphanedRuns(ctx, s.d.DB.Pool, ""); err != nil {
		return 0, err
	}
	conns, err := s.activeConnectors(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	now := s.d.Now()
	var maxLag time.Duration
	for _, c := range conns {
		switch c.Kind {
		case KindLDAP:
			cfg := c.ldap
			if cfg.FullIntervalSeconds > 0 {
				if ok, err := s.scheduleRun(ctx, c, "next_full_sync_at", time.Duration(cfg.FullIntervalSeconds)*time.Second, "full"); err != nil {
					return n, err
				} else if ok {
					n++
					continue
				}
			}
			if cfg.IncrementalIntervalSeconds > 0 {
				if ok, err := s.scheduleRun(ctx, c, "next_sync_at", time.Duration(cfg.IncrementalIntervalSeconds)*time.Second, "incremental"); err != nil {
					return n, err
				} else if ok {
					n++
				}
			}
			if cfg.FullIntervalSeconds > 0 || cfg.IncrementalIntervalSeconds > 0 {
				since := c.CreatedAt
				if c.LastSuccessAt != nil {
					since = *c.LastSuccessAt
				}
				if lag := now.Sub(since); lag > maxLag {
					maxLag = lag
				}
			}
		case KindOutbound:
			if c.outboundIssue() != "" {
				// Nothing to reconcile or scan until the connector has a
				// usable configuration; its health reports why. Its first
				// reconciliation runs once it is configured.
				continue
			}
			if c.cursor == "" {
				// A new outbound connector starts with a reconciliation, which
				// pushes every eligible account (PROV-010).
				if ok, err := s.scheduleRun(ctx, c, "next_sync_at", 0, "reconcile"); err != nil {
					return n, err
				} else if ok {
					n++
				}
				_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE provisioning_connectors SET cursor=$2 WHERE id=$1 AND cursor IS NULL`, c.ID, now.UTC().Format(time.RFC3339Nano))
				continue
			}
			if c.out.ReconcileIntervalSeconds > 0 {
				if ok, err := s.scheduleRun(ctx, c, "next_sync_at", time.Duration(c.out.ReconcileIntervalSeconds)*time.Second, "reconcile"); err != nil {
					return n, err
				} else if ok {
					n++
				}
			}
			m, err := s.scanChanges(ctx, c)
			if err != nil {
				return n, err
			}
			n += m
		}
	}
	s.m.lag.Set(int64(maxLag.Seconds()))
	var backlog int64
	_ = s.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries WHERE state IN ('pending','retrying')`).Scan(&backlog)
	s.m.backlog.Set(backlog)
	return n, nil
}

func (s *Service) activeConnectors(ctx context.Context) ([]*Connector, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+connCols+` FROM provisioning_connectors c WHERE kind IN ('ldap','scim_outbound') AND state='active'
		AND (organization_id IS NULL OR EXISTS (SELECT 1 FROM organizations o WHERE o.id=c.organization_id AND o.state='active'))
		AND EXISTS (SELECT 1 FROM realms r WHERE r.id=c.realm_id AND r.state='active') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// scheduleRun claims a due schedule slot and queues the run in one
// transaction; when a run is already active the claim rolls back and is
// retried on the next pass.
func (s *Service) scheduleRun(ctx context.Context, c *Connector, column string, every time.Duration, mode string) (bool, error) {
	now := s.d.Now()
	claimed := false
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var id string
		q := `UPDATE provisioning_connectors SET ` + column + `=$2 WHERE id=$1 AND state='active' AND (` + column + ` IS NULL OR ` + column + ` <= $3) RETURNING id`
		if err := tx.QueryRow(ctx, q, c.ID, now.Add(every), now).Scan(&id); err != nil {
			return errNotDue
		}
		if mode == "full" {
			// A full run also satisfies the incremental schedule.
			if _, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET next_sync_at=$2 WHERE id=$1`, c.ID,
				now.Add(time.Duration(c.ldap.IncrementalIntervalSeconds)*time.Second)); err != nil {
				return err
			}
		}
		if _, err := s.requestRunTx(ctx, tx, c, RunRequest{Mode: mode}, "schedule", audit.System); err != nil {
			return err
		}
		claimed = true
		return nil
	})
	if err != nil && (errors.Is(err, errNotDue) || problem.Is(err, problem.ErrConflict)) {
		return false, nil
	}
	return claimed, err
}

var errNotDue = errors.New("not due")

// scanChanges queues outbound deliveries for accounts and memberships
// changed since the connector's change cursor (profile edits publish no
// outbox event). The cursor moves to the newest change seen; ties at the
// boundary are read again, which only re-queues an idempotent delivery.
func (s *Service) scanChanges(ctx context.Context, c *Connector) (int, error) {
	since, err := time.Parse(time.RFC3339Nano, c.cursor)
	if err != nil {
		since = s.d.Now()
	}
	const batch = 500
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, updated_at FROM (
			SELECT u.id, u.updated_at FROM users u WHERE u.realm_id=$1 AND u.updated_at > $2
				AND ($3='' OR EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$3))
			UNION ALL
			SELECT m.user_id, m.updated_at FROM memberships m WHERE m.realm_id=$1 AND m.updated_at > $2 AND ($3='' OR m.organization_id=$3)
		) changed ORDER BY updated_at LIMIT $4`, c.RealmID, since, c.OrganizationID, batch)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	last := since
	count := 0
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			rows.Close()
			return 0, err
		}
		count++
		if at.After(last) {
			last = at
		}
		seen[id] = true
	}
	rows.Close()
	for id := range seen {
		if err := s.enqueue(ctx, s.d.DB.Pool, c.ID, c.RealmID, c.OrganizationID, "User", id, "change_scan", ""); err != nil {
			return 0, err
		}
	}
	if count == batch {
		last = last.Add(-time.Microsecond)
	}
	if last.After(since) {
		_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE provisioning_connectors SET cursor=$2 WHERE id=$1`, c.ID, last.UTC().Format(time.RFC3339Nano))
	}
	return len(seen), nil
}
