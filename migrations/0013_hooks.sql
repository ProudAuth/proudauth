-- Synchronous pre-action hooks (EXT-009, EXT-011, EXT-012, EXT-017).
-- Post-action integrations use the transactional outbox and webhooks (EXT-010).
CREATE TABLE hooks (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    name                  text NOT NULL,
    kind                  text NOT NULL CHECK (kind IN ('registration.eligibility', 'profile.validation', 'token.claims', 'authorization.decision')),
    url                   text NOT NULL,
    secret_ciphertext     bytea NOT NULL,
    key_version           integer NOT NULL,
    timeout_ms            integer NOT NULL DEFAULT 1500 CHECK (timeout_ms BETWEEN 100 AND 5000),
    failure_mode          text NOT NULL DEFAULT 'deny' CHECK (failure_mode IN ('deny', 'skip')),
    client_ids            text[] NOT NULL DEFAULT '{}',
    allow_private_network boolean NOT NULL DEFAULT false,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    invocations           bigint NOT NULL DEFAULT 0,
    failures              bigint NOT NULL DEFAULT 0,
    last_latency_ms       integer,
    last_failure_at       timestamptz,
    last_error            text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, name)
);
CREATE INDEX hooks_kind ON hooks (realm_id, kind) WHERE state = 'active';
