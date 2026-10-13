-- Restore marker (TEST-060, OPS-014): `identity-cli restore-begin` sets it on a
-- restored database; while it is set, /health/ready reports
-- "restore_pending" and identity-worker refuses to start, so the database
-- serves no traffic before `identity-cli restore-reconcile` has run, which
-- clears it in the reconciliation's transaction. NULL (the default) on every
-- database that was never marked. Additive only.
ALTER TABLE system_state ADD COLUMN IF NOT EXISTS restore_pending_since timestamptz;
ALTER TABLE system_state ADD COLUMN IF NOT EXISTS restore_pending_by text;
