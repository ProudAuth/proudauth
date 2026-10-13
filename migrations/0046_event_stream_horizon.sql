-- Session event stream horizon (SES-019): the last pruned stream position per
-- realm. A cursor expires only when events after it were pruned, not merely
-- because its own event aged out on a quiet realm. Additive only.
CREATE TABLE event_stream_horizon (
    realm_id    text PRIMARY KEY,
    pruned_tx   xid8 NOT NULL,
    pruned_seq  bigint NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
