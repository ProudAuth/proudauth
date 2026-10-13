-- Passkey attestation trust (PASS-009): authenticator models a realm trusts,
-- each with the attestation root certificates its attestation must chain
-- to, and the trust result recorded per credential. Additive only.
CREATE TABLE IF NOT EXISTS webauthn_trusted_authenticators (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    aaguid             uuid NOT NULL,
    description        text NOT NULL,
    root_certificates  bytea[] NOT NULL,
    created_by_id      text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, aaguid)
);

ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS attestation_trusted boolean NOT NULL DEFAULT false;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS attestation_source text;
