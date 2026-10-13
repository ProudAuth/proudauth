-- Plugin part states (EXT-014): an emergency switch-off of a plugin's hook or
-- subscription (SEC-020) survives plugin enable, upgrade and rollback until
-- an administrator turns the part back on; a plugin workflow kept as
-- evidence after its version dropped it no longer comes back with the
-- plugin. Additive only.
ALTER TABLE hooks ADD COLUMN IF NOT EXISTS emergency_disabled boolean NOT NULL DEFAULT false;
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS emergency_disabled boolean NOT NULL DEFAULT false;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS plugin_retired boolean NOT NULL DEFAULT false;
