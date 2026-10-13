-- Shared Signals receiver (ADV-007): trusted transmitters an administrator
-- registered push Security Event Tokens to the realm. Each transmitter has
-- its keys, an issued push secret, a subject mapping and an explicit action
-- policy per event type (record only unless configured). Received events
-- are kept as minimal evidence (no token, no subject identifiers) and their
-- jti blocks replays. Additive only.
CREATE TABLE IF NOT EXISTS ssf_transmitters (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    name                  text NOT NULL,
    issuer                text NOT NULL,
    jwks_uri              text,
    jwks                  jsonb,
    push_secret_digest    text NOT NULL,
    provider_id           text,
    allow_email_subjects  boolean NOT NULL DEFAULT false,
    actions               jsonb NOT NULL DEFAULT '{}',
    max_event_age_seconds integer NOT NULL DEFAULT 86400,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    version               bigint NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, name),
    UNIQUE (realm_id, issuer)
);

CREATE TABLE IF NOT EXISTS ssf_received_events (
    transmitter_id  text NOT NULL REFERENCES ssf_transmitters(id) ON DELETE CASCADE,
    jti             text NOT NULL,
    realm_id        text NOT NULL,
    event_type      text NOT NULL,
    subject_format  text,
    user_id         text,
    action          text NOT NULL,
    outcome         text NOT NULL,
    received_at     timestamptz NOT NULL,
    PRIMARY KEY (transmitter_id, jti)
);
CREATE INDEX IF NOT EXISTS ssf_received_events_time ON ssf_received_events (received_at);
