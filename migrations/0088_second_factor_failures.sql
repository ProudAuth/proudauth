-- Consecutive failed code-factor proofs per account (owner decision 10 of
-- 0.2.0-alpha.6; SEC-006, MFA-002, TEST-021). One row per account that has
-- made a TOTP, HOTP or recovery-code proof or failed an emailed or texted
-- sign-in code: the count grows the account's backoff across the fixed
-- proof-budget windows, records when the owner was warned and when code
-- factors were turned off, and goes back to zero after a successful second
-- factor or passkey, a completed sign-in, a password reset or an assisted
-- recovery. Its row is also the lock that orders concurrent proofs of one
-- account. Expand only: a new table that older binaries ignore.
CREATE TABLE second_factor_failures (
    user_id          text PRIMARY KEY,
    realm_id         text NOT NULL,
    consecutive      integer NOT NULL CHECK (consecutive >= 0),
    last_failure_at  timestamptz,
    notified_at      timestamptz,
    disabled_at      timestamptz,
    updated_at       timestamptz NOT NULL,
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
