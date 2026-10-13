-- Session event stream (SES-019). Each outbox row records the writing
-- transaction's ID; readers return only rows below the snapshot's xmin (every
-- older transaction has finished), ordered by (tx_id, seq). Rows that commit
-- later always sort after any returned cursor, so the stream never skips an
-- event even when sequence numbers commit out of order. Expand-only.
ALTER TABLE outbox_events ADD COLUMN tx_id xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE INDEX outbox_events_stream ON outbox_events (realm_id, tx_id, seq);
