-- Plugin lifecycle (EXT-014). A plugin is a signed, versioned package of
-- extension configuration (pre-action hooks, webhook subscriptions, lifecycle
-- workflows) with a manifest declaring the permissions it needs, the contract
-- versions it requires and the plugins it depends on. Nothing executes in
-- process: a plugin only configures parts that already run out of process
-- (EXT-013). Every version stays stored so an upgrade can be rolled back.
-- Additive only.

CREATE TABLE IF NOT EXISTS plugins (
    id                text PRIMARY KEY,
    realm_id          text NOT NULL REFERENCES realms(id),
    name              text NOT NULL,
    publisher         text NOT NULL,
    -- inactive: no version installed yet; enabled: its parts run;
    -- disabled: all its parts were stopped together.
    state             text NOT NULL DEFAULT 'inactive' CHECK (state IN ('inactive', 'enabled', 'disabled')),
    installed_version text,
    previous_version  text,
    installed_by_id   text,
    installed_at      timestamptz,
    version           bigint NOT NULL DEFAULT 1,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, name),
    UNIQUE (realm_id, id)
);

CREATE TABLE IF NOT EXISTS plugin_versions (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    plugin_id          text NOT NULL,
    version            text NOT NULL,
    manifest_version   integer NOT NULL,
    manifest           jsonb NOT NULL,
    -- The exact signed bytes, kept for re-verification and rollback.
    manifest_raw       bytea NOT NULL,
    payload_raw        bytea NOT NULL,
    package_digest     text NOT NULL,
    signing_key_id     text NOT NULL,
    signature          text NOT NULL,
    permissions        text[] NOT NULL DEFAULT '{}',
    status             text NOT NULL CHECK (status IN ('pending_review', 'approved', 'rejected', 'installed', 'superseded')),
    uploaded_by_id     text NOT NULL,
    reviewed_by_id     text,
    reviewed_at        timestamptz,
    review_note        text,
    installed_at       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (plugin_id, version),
    FOREIGN KEY (realm_id, plugin_id) REFERENCES plugins (realm_id, id) ON DELETE CASCADE
);

-- Parts a plugin manages carry its ID: disabling the plugin stops every part
-- in one transaction, and ordinary APIs refuse to edit them.
ALTER TABLE hooks ADD COLUMN IF NOT EXISTS plugin_id text;
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS plugin_id text;
CREATE INDEX IF NOT EXISTS hooks_plugin ON hooks (plugin_id) WHERE plugin_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS webhook_subscriptions_plugin ON webhook_subscriptions (plugin_id) WHERE plugin_id IS NOT NULL;
