-- Versioned organization onboarding templates (TEN-017).
CREATE TABLE organization_templates (
    realm_id      text NOT NULL REFERENCES realms(id),
    name          text NOT NULL,
    version       integer NOT NULL CHECK (version > 0),
    description   text,
    document      jsonb NOT NULL,
    created_by_id text NOT NULL,
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (realm_id, name, version)
);

ALTER TABLE organizations ADD COLUMN template_name text;
ALTER TABLE organizations ADD COLUMN template_version integer;
