-- Passkeys / WebAuthn ceremonies (PASS-001..PASS-007).
--
-- Expand-only migration: new nullable columns and a new table; older binaries
-- ignore them (DEP-012).

-- Random, non-identifying WebAuthn user handle (never the user ID or an email),
-- generated on first enrollment and stable across root-key rotation.
ALTER TABLE users ADD COLUMN webauthn_user_handle bytea;
CREATE UNIQUE INDEX users_webauthn_handle ON users (realm_id, webauthn_user_handle) WHERE webauthn_user_handle IS NOT NULL;

ALTER TABLE webauthn_credentials ADD COLUMN attestation_format text NOT NULL DEFAULT 'none';
ALTER TABLE webauthn_credentials ADD COLUMN last_counter_anomaly_at timestamptz;
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (realm_id, user_id) WHERE state = 'active';

-- One row per registration or authentication ceremony. A ceremony is bound to
-- realm, ceremony kind, RP ID, user (when known) and transaction (when inside an
-- authentication transaction), expires quickly and is consumed exactly once.
CREATE TABLE webauthn_ceremonies (
    id              text PRIMARY KEY,
    realm_id        text NOT NULL REFERENCES realms(id),
    kind            text NOT NULL CHECK (kind IN ('registration', 'authentication')),
    user_id         text,
    transaction_id  text,
    rp_id           text NOT NULL,
    session_data    jsonb NOT NULL,
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_ceremonies_tx ON webauthn_ceremonies (transaction_id, kind) WHERE consumed_at IS NULL;
CREATE INDEX webauthn_ceremonies_expiry ON webauthn_ceremonies (expires_at);
