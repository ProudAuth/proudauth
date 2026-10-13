-- Audit archive forks (AUD-008): after a database restore, sealed batches can
-- reuse sequence numbers already archived with other content. The archive
-- then continues in a fork directory instead of stopping.
ALTER TABLE audit_archive_state ADD COLUMN directory text NOT NULL DEFAULT '';
