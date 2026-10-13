-- Upstream identity federation (FED-001..FED-013, REG-009, USR-010, TEN-016).
-- Expand-only migration (DEP-012).

-- One row per upstream authorization request. The OAuth "state" value is a
-- random bearer secret; only its digest is stored. The PKCE verifier is
-- encrypted. Each request is consumed exactly once.
CREATE TABLE federation_requests (
    id                  text PRIMARY KEY,
    realm_id            text NOT NULL REFERENCES realms(id),
    provider_id         text NOT NULL,
    purpose             text NOT NULL CHECK (purpose IN ('login', 'link')),
    transaction_id      text,
    user_id             text,
    session_id          text,
    state_digest        text NOT NULL UNIQUE,
    nonce               text NOT NULL,
    verifier_ciphertext bytea NOT NULL,
    key_version         integer NOT NULL,
    redirect_uri        text NOT NULL,
    expires_at          timestamptz NOT NULL,
    consumed_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, provider_id) REFERENCES identity_providers (realm_id, id),
    CHECK ((purpose = 'login') = (transaction_id IS NOT NULL)),
    CHECK ((purpose = 'link') = (user_id IS NOT NULL))
);
CREATE INDEX federation_requests_expiry ON federation_requests (expires_at);

ALTER TABLE external_identities ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE external_identities ADD COLUMN upstream_tenant text;
ALTER TABLE external_identities ADD COLUMN mapping_revision bigint;
CREATE INDEX external_identities_user ON external_identities (realm_id, user_id);

-- Social adapters are distinct kinds with their own identity semantics (FED-002).
ALTER TABLE identity_providers ADD COLUMN adapter text NOT NULL DEFAULT 'oidc'
    CHECK (adapter IN ('oidc', 'github'));
