-- Organization relationships (TEN-021): explicit parent/child and partner
-- links between organizations of a realm. A relationship grants nothing by
-- itself; access across organizations still needs a project grant (TEN-020)
-- or a role assignment. Tenant-proposed relationships take effect only when
-- the other organization accepts. Additive only.
CREATE TABLE IF NOT EXISTS organization_relationships (
    id               text PRIMARY KEY,
    realm_id         text NOT NULL REFERENCES realms(id),
    kind             text NOT NULL CHECK (kind IN ('parent_child', 'partner')),
    source_org_id    text NOT NULL,
    target_org_id    text NOT NULL,
    state            text NOT NULL CHECK (state IN ('proposed', 'active', 'declined', 'ended')),
    note             text NOT NULL DEFAULT '',
    created_by_type  text NOT NULL,
    created_by_id    text NOT NULL,
    decided_by_id    text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    decided_at       timestamptz,
    ended_at         timestamptz,
    CHECK (source_org_id <> target_org_id),
    FOREIGN KEY (realm_id, source_org_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (realm_id, target_org_id) REFERENCES organizations (realm_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS organization_relationships_live ON organization_relationships
    (kind, LEAST(source_org_id, target_org_id), GREATEST(source_org_id, target_org_id)) WHERE state IN ('proposed', 'active');
CREATE UNIQUE INDEX IF NOT EXISTS organization_relationships_one_parent ON organization_relationships (target_org_id)
    WHERE kind = 'parent_child' AND state IN ('proposed', 'active');
CREATE INDEX IF NOT EXISTS organization_relationships_source ON organization_relationships (source_org_id) WHERE state IN ('proposed', 'active');
CREATE INDEX IF NOT EXISTS organization_relationships_target ON organization_relationships (target_org_id) WHERE state IN ('proposed', 'active');
