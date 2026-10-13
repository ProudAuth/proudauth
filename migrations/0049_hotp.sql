-- Optional HOTP factor (MFA-013): one active counter-based credential per
-- user, like TOTP. The credentials table already carries the counter column.
CREATE UNIQUE INDEX IF NOT EXISTS credentials_one_hotp ON credentials (user_id) WHERE type = 'hotp' AND state = 'active';
