-- Emergency grant-class controls (SEC-020): grant types an administrator has
-- switched off realm-wide, outside ordinary policy edits.
ALTER TABLE realms ADD COLUMN disabled_grant_types text[] NOT NULL DEFAULT '{}';
