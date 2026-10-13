-- SAML 2.0 identity provider (APP-018, SAML-001..SAML-010) and broker
-- (FED-014). Additive only (DEP-012): new tables, and one defaulted column
-- on clients that older binaries never read.

-- A SAML application is backed by a client record so consent, organization
-- policy, sessions, client lifecycle and audit apply to it unchanged. The
-- backing client never authenticates at an OAuth endpoint.
ALTER TABLE clients ADD COLUMN IF NOT EXISTS protocol text NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc', 'saml'));

-- Realm SAML signing keys (RSA, self-signed certificates), separate from the
-- JWT signing keys. Private keys are envelope-encrypted with the key-wrapping
-- key. pending = published "next" key, active = signs, retiring = still
-- published until publish_until (SAML-002).
CREATE TABLE IF NOT EXISTS saml_signing_keys (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    state              text NOT NULL CHECK (state IN ('pending', 'active', 'retiring', 'retired')),
    private_ciphertext bytea NOT NULL,
    enc_key_version    integer NOT NULL,
    certificate        bytea NOT NULL,
    not_after          timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    activated_at       timestamptz,
    retiring_at        timestamptz,
    publish_until      timestamptz,
    retired_at         timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS saml_signing_keys_one_active ON saml_signing_keys (realm_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS saml_signing_keys_one_pending ON saml_signing_keys (realm_id) WHERE state = 'pending';

-- Registered service providers (SAML applications). Protocol settings live
-- in config (endpoints, certificates, attribute mappings, signing policy).
CREATE TABLE IF NOT EXISTS saml_service_providers (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    client_ref         text NOT NULL UNIQUE REFERENCES clients(id),
    entity_id          text NOT NULL,
    organization_id    text,
    config             jsonb NOT NULL,
    version            bigint NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, entity_id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);

-- One row per accepted AuthnRequest (or IdP-initiated start). The browser
-- binding secret and the state value are stored as digests, the internal
-- PKCE verifier encrypted; each row is consumed exactly once. A service
-- provider's request ID is accepted once (replayed requests are refused).
CREATE TABLE IF NOT EXISTS saml_idp_requests (
    id                  text PRIMARY KEY,
    realm_id            text NOT NULL REFERENCES realms(id),
    app_id              text NOT NULL REFERENCES saml_service_providers(id) ON DELETE CASCADE,
    request_id          text,
    acs_url             text NOT NULL,
    relay_state         text,
    transaction_id      text,
    state_digest        text NOT NULL UNIQUE,
    binding_digest      text NOT NULL,
    verifier_ciphertext bytea NOT NULL,
    key_version         integer NOT NULL,
    options             jsonb NOT NULL DEFAULT '{}'::jsonb,
    expires_at          timestamptz NOT NULL,
    consumed_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS saml_idp_requests_request_id ON saml_idp_requests (app_id, request_id) WHERE request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS saml_idp_requests_expiry ON saml_idp_requests (expires_at);

-- Service providers that received an assertion for an IdP session, with the
-- SessionIndex issued to them (SAML-008 logout). The name identifier is kept
-- only as a digest.
CREATE TABLE IF NOT EXISTS saml_idp_sessions (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    app_id             text NOT NULL REFERENCES saml_service_providers(id) ON DELETE CASCADE,
    session_id         text NOT NULL,
    user_id            text NOT NULL,
    session_index      text NOT NULL,
    name_id_digest     text NOT NULL,
    expires_at         timestamptz NOT NULL,
    ended_at           timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, session_id),
    UNIQUE (app_id, session_index)
);
CREATE INDEX IF NOT EXISTS saml_idp_sessions_session ON saml_idp_sessions (session_id);
CREATE INDEX IF NOT EXISTS saml_idp_sessions_expiry ON saml_idp_sessions (expires_at);

-- SAML broker connections: identity_providers rows of kind 'saml' carry the
-- shared federation settings (linking, JIT, organization, claim mapping);
-- the SAML protocol settings live here and go with the connection.
CREATE TABLE IF NOT EXISTS saml_connections (
    provider_id        text PRIMARY KEY,
    realm_id           text NOT NULL,
    config             jsonb NOT NULL,
    FOREIGN KEY (realm_id, provider_id) REFERENCES identity_providers (realm_id, id) ON DELETE CASCADE
);

-- AuthnRequests sent to upstream SAML identity providers. The ID is the
-- request's own ID (InResponseTo correlation); the RelayState is a bearer
-- secret stored as a digest; each request is consumed once (SAML-003).
CREATE TABLE IF NOT EXISTS saml_broker_requests (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    provider_id        text NOT NULL,
    purpose            text NOT NULL CHECK (purpose IN ('login', 'link')),
    transaction_id     text,
    user_id            text,
    session_id         text,
    relay_digest       text NOT NULL UNIQUE,
    expires_at         timestamptz NOT NULL,
    consumed_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, provider_id) REFERENCES identity_providers (realm_id, id) ON DELETE CASCADE,
    CHECK ((purpose = 'login') = (transaction_id IS NOT NULL)),
    CHECK ((purpose = 'link') = (user_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS saml_broker_requests_expiry ON saml_broker_requests (expires_at);

-- Assertion IDs accepted from each connection, kept until the assertion
-- expires: a replayed assertion is refused (SAML-003, TEST-051).
CREATE TABLE IF NOT EXISTS saml_assertion_ids (
    provider_id        text NOT NULL,
    assertion_id       text NOT NULL,
    realm_id           text NOT NULL,
    expires_at         timestamptz NOT NULL,
    PRIMARY KEY (provider_id, assertion_id),
    FOREIGN KEY (realm_id, provider_id) REFERENCES identity_providers (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS saml_assertion_ids_expiry ON saml_assertion_ids (expires_at);
