-- Authentication flow challenges (AUT-012, SEC-014), risk hooks and registered
-- federation adapters. Every change widens a CHECK constraint, so binaries
-- that predate this migration keep working.

-- Emailed codes that answer a flow challenge.
ALTER TABLE challenges DROP CONSTRAINT challenges_purpose_check;
ALTER TABLE challenges ADD CONSTRAINT challenges_purpose_check CHECK (purpose IN ('email_verification', 'phone_verification', 'login_otp',
    'magic_link', 'password_reset', 'identifier_change', 'account_setup', 'registration', 'flow_challenge')) NOT VALID;
ALTER TABLE challenges VALIDATE CONSTRAINT challenges_purpose_check;

-- Risk hooks supply the risk signal to authentication flow rules (AUT-014).
ALTER TABLE hooks DROP CONSTRAINT hooks_kind_check;
ALTER TABLE hooks ADD CONSTRAINT hooks_kind_check CHECK (kind IN ('registration.eligibility', 'profile.validation', 'token.claims',
    'authorization.decision', 'authentication.risk')) NOT VALID;
ALTER TABLE hooks VALIDATE CONSTRAINT hooks_kind_check;

-- Federation adapters are registered in code (FED-002); the column accepts
-- any adapter name and the API checks it against the registry.
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_adapter_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_adapter_check CHECK (adapter ~ '^[a-z][a-z0-9_-]{0,31}$') NOT VALID;
ALTER TABLE identity_providers VALIDATE CONSTRAINT identity_providers_adapter_check;
