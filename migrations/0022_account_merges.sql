-- Account merge workflow (USR-011): an administrator proposes a merge, both
-- account owners confirm with fresh authentication, and an administrator
-- executes the reviewed plan. The merged-away subject is recorded as an alias
-- of the surviving account so applications can remap their data.
CREATE TABLE account_merges (
    id                  text PRIMARY KEY,
    realm_id            text NOT NULL REFERENCES realms(id),
    survivor_id         text NOT NULL,
    source_id           text NOT NULL,
    requested_by_id     text NOT NULL,
    reason              text NOT NULL,
    plan                jsonb NOT NULL,
    survivor_confirmed  timestamptz,
    source_confirmed    timestamptz,
    state               text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'completed', 'cancelled', 'expired')),
    executed_by_id      text,
    expires_at          timestamptz NOT NULL,
    completed_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX account_merges_open ON account_merges (source_id) WHERE state = 'pending';

CREATE TABLE subject_aliases (
    realm_id    text NOT NULL,
    alias_id    text NOT NULL,
    user_id     text NOT NULL,
    merge_id    text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, alias_id)
);
