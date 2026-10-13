-- Independently versioned extension contracts (EXT-018). Every existing
-- subscription and hook keeps the version it was built against (1), so a
-- server upgrade changes nothing a receiver sees; new versions are opt-in.
-- Additive only: older binaries ignore the columns and keep sending v1.
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS event_version integer NOT NULL DEFAULT 1;
ALTER TABLE hooks ADD COLUMN IF NOT EXISTS contract_version integer NOT NULL DEFAULT 1;
