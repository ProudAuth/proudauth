-- Bounded relationship-based authorization (AZ-021, AZ-022, AZ-023, AZ-027).
-- Services register resource types with their relations and the permissions
-- each relation gives; relationship tuples link subjects to objects inside
-- one organization. The identity provider stores relationships, never the
-- application's objects. Additive only.
CREATE TABLE IF NOT EXISTS resource_types (
    id                  text PRIMARY KEY,
    realm_id            text NOT NULL REFERENCES realms(id),
    resource_id         text NOT NULL,
    name                text NOT NULL,
    relations           jsonb NOT NULL,
    permissions         jsonb NOT NULL,
    shareable_relations text[] NOT NULL DEFAULT '{}',
    share_permission    text,
    version             bigint NOT NULL DEFAULT 1,
    created_by_id       text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, name)
);

ALTER TABLE resource_relationships ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE resource_relationships ADD COLUMN IF NOT EXISTS created_by_id text;
CREATE INDEX IF NOT EXISTS resource_relationships_object ON resource_relationships (organization_id, object_type, object_id, relation);
CREATE INDEX IF NOT EXISTS resource_relationships_subject ON resource_relationships (organization_id, subject_type, subject_id);

-- User-managed sharing (AZ-027): an offer the recipient accepts or declines;
-- accepting creates the relationship tuple.
CREATE TABLE IF NOT EXISTS resource_shares (
    id                text PRIMARY KEY,
    realm_id          text NOT NULL,
    organization_id   text NOT NULL,
    object_type       text NOT NULL,
    object_id         text NOT NULL,
    relation          text NOT NULL,
    owner_user_id     text NOT NULL,
    recipient_user_id text NOT NULL,
    state             text NOT NULL CHECK (state IN ('pending', 'accepted', 'declined', 'revoked', 'expired')),
    relationship_id   text,
    message           text,
    expires_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    decided_at        timestamptz
);
CREATE INDEX IF NOT EXISTS resource_shares_recipient ON resource_shares (recipient_user_id, state);
CREATE INDEX IF NOT EXISTS resource_shares_owner ON resource_shares (owner_user_id, state);
