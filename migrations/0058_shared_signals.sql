-- Shared Signals Framework transmitter (AUD-016): receivers (machine
-- clients) create event streams; security events about their users are
-- queued as Security Event Tokens and delivered by push (RFC 8935) or poll
-- (RFC 8936). Events are queued in the transaction that records the audit
-- evidence. Additive only.
CREATE TABLE IF NOT EXISTS ssf_streams (
    id                         text PRIMARY KEY,
    realm_id                   text NOT NULL REFERENCES realms(id),
    client_ref                 text NOT NULL,
    audience                   text NOT NULL,
    delivery_method            text NOT NULL CHECK (delivery_method IN ('urn:ietf:rfc:8935', 'urn:ietf:rfc:8936')),
    endpoint_url               text,
    authorization_ciphertext   bytea,
    events_requested           text[] NOT NULL DEFAULT '{}',
    events_delivered           text[] NOT NULL DEFAULT '{}',
    description                text NOT NULL DEFAULT '',
    subject_scope              text NOT NULL DEFAULT 'client_users' CHECK (subject_scope IN ('client_users', 'listed', 'all')),
    status                     text NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'paused', 'disabled')),
    status_reason              text,
    last_verification_at       timestamptz,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ssf_streams_realm ON ssf_streams (realm_id) WHERE status <> 'disabled';
CREATE INDEX IF NOT EXISTS ssf_streams_client ON ssf_streams (client_ref);

CREATE TABLE IF NOT EXISTS ssf_stream_subjects (
    stream_id   text NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    user_id     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stream_id, user_id)
);

CREATE TABLE IF NOT EXISTS ssf_events (
    id                text PRIMARY KEY,
    stream_id         text NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    realm_id          text NOT NULL,
    event_type        text NOT NULL,
    user_id           text,
    subject           text,
    session_id        text,
    payload           jsonb NOT NULL,
    occurred_at       timestamptz NOT NULL,
    set_jwt           text,
    state             text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'acknowledged', 'failed', 'expired')),
    attempts          integer NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    last_status_code  integer,
    last_error        text,
    delivered_at      timestamptz
);
CREATE INDEX IF NOT EXISTS ssf_events_due ON ssf_events (next_attempt_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS ssf_events_stream ON ssf_events (stream_id, state, occurred_at);
