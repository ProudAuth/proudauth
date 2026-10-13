-- Organization aliases and subdomain routing (TEN-011).
CREATE TABLE organization_aliases (
    realm_id        text NOT NULL,
    alias           text NOT NULL,
    organization_id text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, alias),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);

ALTER TABLE organization_domains ADD COLUMN include_subdomains boolean NOT NULL DEFAULT false;
