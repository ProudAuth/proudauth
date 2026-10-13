-- Versioned authentication-flow definitions (AUT-019). Each revision keeps
-- the complete rule list, the reachability and bypass analysis computed when
-- it was saved, and who drafted and published it. A draft records the hash
-- of the live flow it was based on so publishing refuses a draft whose base
-- changed underneath it; a rollback publishes a copy of an older revision as
-- a new revision, so history is never rewritten. Additive only.
CREATE TABLE IF NOT EXISTS auth_flow_revisions (
    realm_id           text NOT NULL REFERENCES realms(id),
    revision           integer NOT NULL CHECK (revision > 0),
    definition         jsonb NOT NULL,
    definition_hash    text NOT NULL,
    base_hash          text NOT NULL,
    state              text NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'discarded')),
    note               text NOT NULL DEFAULT '',
    analysis           jsonb NOT NULL DEFAULT '{}',
    rollback_of        integer,
    policy_revision    bigint,
    created_by_type    text NOT NULL,
    created_by_id      text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    published_by_type  text,
    published_by_id    text,
    published_at       timestamptz,
    PRIMARY KEY (realm_id, revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_flow_revisions_published ON auth_flow_revisions (realm_id) WHERE state = 'published';
CREATE INDEX IF NOT EXISTS auth_flow_revisions_drafts ON auth_flow_revisions (realm_id) WHERE state = 'draft';
