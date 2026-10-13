-- Scheduled and approved assisted recovery (MFA-009): when the realm requires a
-- cooling-off period or a second operator, the request waits here and the
-- account owner is told immediately and can cancel it.
CREATE TABLE assisted_recoveries (
    id                  text PRIMARY KEY,
    realm_id            text NOT NULL,
    user_id             text NOT NULL,
    requested_by_id     text NOT NULL,
    reason              text NOT NULL,
    evidence_reference  text NOT NULL,
    reset_mfa           boolean NOT NULL DEFAULT false,
    approval_required   boolean NOT NULL DEFAULT false,
    approved_by_id      text,
    state               text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'completed', 'cancelled', 'expired')),
    effective_at        timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    completed_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX assisted_recoveries_due ON assisted_recoveries (effective_at) WHERE state IN ('pending', 'approved');
