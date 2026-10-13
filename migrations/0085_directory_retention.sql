-- Directory integration: retention and erasure (PROV-012, PROV-018, PRV-004,
-- PRV-005). Expand-only: indexes, which older binaries ignore.

-- Erasing an account redacts the run findings that name it.
CREATE INDEX IF NOT EXISTS directory_sync_findings_local ON directory_sync_findings (local_id) WHERE local_id IS NOT NULL;
-- Retention prunes finished runs (with their findings) and finished outbound
-- deliveries by age.
CREATE INDEX IF NOT EXISTS directory_sync_runs_finished ON directory_sync_runs (finished_at) WHERE state NOT IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS outbound_deliveries_finished ON outbound_deliveries (updated_at) WHERE state IN ('delivered', 'dead_letter', 'replayed');
-- Queued and running runs: the one-run-per-connector check and the sweep
-- that closes runs whose job ended without them.
CREATE INDEX IF NOT EXISTS directory_sync_runs_active ON directory_sync_runs (connector_id) WHERE state IN ('queued', 'running');
