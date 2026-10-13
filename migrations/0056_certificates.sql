-- Certificate authentication (TOK-019, MCH-014, PROV-016): realm trust
-- anchors for client certificates (mutual-TLS client authentication) and
-- user certificates (X.509 sign-in), optional certificate revocation lists,
-- explicit bindings of user certificates to accounts, and the sender
-- constraint of opaque access tokens. Additive only.
CREATE TABLE IF NOT EXISTS certificate_trust_anchors (
    id               text PRIMARY KEY,
    realm_id         text NOT NULL REFERENCES realms(id),
    purpose          text NOT NULL CHECK (purpose IN ('client', 'user')),
    name             text NOT NULL,
    certificate_pem  text NOT NULL,
    subject          text NOT NULL,
    fingerprint      text NOT NULL,
    not_after        timestamptz NOT NULL,
    revocation       text NOT NULL DEFAULT 'none' CHECK (revocation IN ('none', 'crl')),
    crl_der          bytea,
    crl_next_update  timestamptz,
    map_san_email    boolean NOT NULL DEFAULT false,
    multi_factor     boolean NOT NULL DEFAULT false,
    state            text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_by_id    text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, purpose, fingerprint)
);

CREATE TABLE IF NOT EXISTS user_certificate_bindings (
    id             text PRIMARY KEY,
    realm_id       text NOT NULL,
    user_id        text NOT NULL,
    anchor_id      text NOT NULL REFERENCES certificate_trust_anchors(id),
    issuer_dn      text NOT NULL,
    subject_dn     text NOT NULL,
    state          text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_by_id  text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz,
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS user_certificate_bindings_dn ON user_certificate_bindings (anchor_id, issuer_dn, subject_dn) WHERE state = 'active';

ALTER TABLE opaque_access_tokens ADD COLUMN IF NOT EXISTS cnf jsonb;

-- Mutual-TLS client authentication methods (RFC 8705). Widening only.
ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_token_endpoint_auth_method_check;
ALTER TABLE clients ADD CONSTRAINT clients_token_endpoint_auth_method_check CHECK (token_endpoint_auth_method IN ('client_secret_basic',
    'client_secret_post', 'private_key_jwt', 'none', 'tls_client_auth', 'self_signed_tls_client_auth')) NOT VALID;
ALTER TABLE clients VALIDATE CONSTRAINT clients_token_endpoint_auth_method_check;
