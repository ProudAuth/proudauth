-- User lifecycle jobs (USR-015): scheduled deactivation and dormant-account
-- review markers.
ALTER TABLE users ADD COLUMN deactivate_at timestamptz;
ALTER TABLE users ADD COLUMN dormant_flagged_at timestamptz;
CREATE INDEX users_deactivate_due ON users (deactivate_at) WHERE deactivate_at IS NOT NULL;
