-- Accountable owners for authorization policies and hooks (DOM-009): every
-- credential, client, provider connection, policy and integration has an
-- owner, and objects without one are reported. Additive only.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS owner_user_id text;
ALTER TABLE hooks ADD COLUMN IF NOT EXISTS owner_user_id text;
