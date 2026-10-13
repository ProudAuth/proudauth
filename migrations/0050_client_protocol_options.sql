-- Optional per-client protocol settings (SES-018 front-channel logout, and
-- later response signing/encryption profiles), kept together as one
-- document so each profile does not need its own columns. Additive only.
ALTER TABLE clients ADD COLUMN IF NOT EXISTS protocol_options jsonb NOT NULL DEFAULT '{}'::jsonb;
