-- Consent management (APP-013): the terms version a client's consent covers,
-- and administrative pre-authorization of third-party clients.
ALTER TABLE clients ADD COLUMN consent_terms_version text;

CREATE TABLE consent_preauthorizations (
    id              text PRIMARY KEY,
    realm_id        text NOT NULL,
    client_ref      text NOT NULL,
    organization_id text,
    scopes          text[] NOT NULL,
    terms_version   text,
    reason          text NOT NULL,
    granted_by_id   text NOT NULL,
    granted_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);
CREATE INDEX consent_preauthorizations_client ON consent_preauthorizations (client_ref) WHERE revoked_at IS NULL;

ALTER TABLE consents ADD COLUMN preauthorization_id text;
