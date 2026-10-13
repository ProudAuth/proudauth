-- Dynamic client registration (APP-016, APP-017, ADV-003). Initial access
-- tokens are issued by administrators and bound to the scopes a registered
-- client may receive; registration access tokens let a registrant manage its
-- own client without administrative credentials. Only digests are stored.
-- Additive only.
CREATE TABLE IF NOT EXISTS client_registration_tokens (
    id              text PRIMARY KEY,
    realm_id        text NOT NULL REFERENCES realms(id),
    kind            text NOT NULL CHECK (kind IN ('initial', 'registration')),
    token_digest    text NOT NULL UNIQUE,
    client_ref      text,
    description     text,
    allowed_scopes  jsonb NOT NULL DEFAULT '[]'::jsonb,
    project_id      text,
    max_uses        integer,
    uses            integer NOT NULL DEFAULT 0,
    expires_at      timestamptz,
    state           text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'exhausted')),
    created_by_id   text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX IF NOT EXISTS client_registration_tokens_realm ON client_registration_tokens (realm_id, kind) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS client_registration_tokens_client ON client_registration_tokens (client_ref) WHERE client_ref IS NOT NULL;

-- One row per dynamically registered client: how it was registered and
-- whether an administrator approved it.
CREATE TABLE IF NOT EXISTS client_registrations (
    client_ref        text PRIMARY KEY,
    realm_id          text NOT NULL,
    initial_token_id  text,
    software_id       text,
    software_version  text,
    approval_state    text NOT NULL CHECK (approval_state IN ('approved', 'pending', 'rejected')),
    registered_from   text,
    decided_by_id     text,
    decided_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);
CREATE INDEX IF NOT EXISTS client_registrations_pending ON client_registrations (realm_id) WHERE approval_state = 'pending';
