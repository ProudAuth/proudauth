-- Policy lifecycle (AZ-017, AZ-018). Expand-only (DEP-012).
ALTER TABLE policies ADD COLUMN requires_approval boolean NOT NULL DEFAULT false;
ALTER TABLE policy_versions ADD COLUMN approved_at timestamptz;
ALTER TABLE policy_versions ADD COLUMN note text;
CREATE INDEX policies_active ON policies (realm_id) WHERE state = 'active';
