-- Step-up requirements for sensitive scopes (AUT-010): the assurance a
-- requesting session must reach and how recent its authentication must be.
ALTER TABLE scopes ADD COLUMN step_up_acr text;
ALTER TABLE scopes ADD COLUMN max_auth_age_seconds integer CHECK (max_auth_age_seconds IS NULL OR max_auth_age_seconds > 0);
