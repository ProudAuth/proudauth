-- Per-invocation hook diagnostics (EXT-017): outcome, latency and a coarse
-- error category only; payloads and responses are never stored.
CREATE TABLE hook_invocations (
    hook_id        text NOT NULL,
    realm_id       text NOT NULL,
    invoked_at     timestamptz NOT NULL,
    outcome        text NOT NULL CHECK (outcome IN ('ok', 'failure')),
    latency_ms     integer NOT NULL,
    error_category text,
    status_code    integer
);
CREATE INDEX hook_invocations_recent ON hook_invocations (hook_id, invoked_at DESC);
