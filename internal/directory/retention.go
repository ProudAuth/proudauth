package directory

import (
	"context"
	"errors"
	"time"
)

// HistoryRetention bounds how long directory run history and finished
// outbound deliveries are kept (PRV-004): 90 days, or
// privacy.history_retention when that is shorter.
const HistoryRetention = 90 * 24 * time.Hour

// pruneBatch bounds the rows one statement deletes per retention pass, so a
// first pass after an upgrade never holds long locks; the rest goes in the
// following passes.
const pruneBatch = 10000

// PruneHistory removes, once they are older than the retention period, the
// findings of finished runs, finished runs themselves (each connector keeps
// its latest run as evidence of its last outcome) and finished outbound
// deliveries (delivered, dead-lettered or replayed). Queued and running
// runs and open deliveries are never pruned. It runs whether or not the
// module is enabled. Audit events about runs and deliveries follow audit
// retention.
func (s *Service) PruneHistory(ctx context.Context) (int64, error) {
	retention := HistoryRetention
	if h := s.d.Cfg.Privacy.HistoryRetention; h > 0 && h < retention {
		retention = h
	}
	cutoff := s.d.Now().Add(-retention)
	var total int64
	var errs []error
	for _, q := range []string{
		// Findings name directory entries (DNs) and accounts: they go with
		// their run's age, including those of a connector's latest run.
		`DELETE FROM directory_sync_findings WHERE (run_id, seq) IN (SELECT f.run_id, f.seq FROM directory_sync_findings f
			JOIN directory_sync_runs r ON r.id=f.run_id WHERE r.state NOT IN ('queued','running') AND r.finished_at < $1 LIMIT $2)`,
		`DELETE FROM directory_sync_runs WHERE id IN (SELECT r.id FROM directory_sync_runs r WHERE r.state NOT IN ('queued','running')
			AND r.finished_at < $1 AND r.id <> (SELECT l.id FROM directory_sync_runs l WHERE l.connector_id=r.connector_id
				ORDER BY l.created_at DESC, l.id DESC LIMIT 1) LIMIT $2)`,
		`DELETE FROM outbound_deliveries WHERE id IN (SELECT id FROM outbound_deliveries WHERE state IN ('delivered','dead_letter','replayed')
			AND updated_at < $1 LIMIT $2)`,
	} {
		tag, err := s.d.DB.Pool.Exec(ctx, q, cutoff, pruneBatch)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		total += tag.RowsAffected()
	}
	return total, errors.Join(errs...)
}
