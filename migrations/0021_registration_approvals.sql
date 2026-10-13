-- Registration approval queue (REG-008): when a realm requires approval, a
-- self-registered account cannot complete sign-in until a reviewer decides.
CREATE TABLE registration_approvals (
    id             text PRIMARY KEY,
    realm_id       text NOT NULL,
    user_id        text NOT NULL,
    state          text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    reviewer_id    text,
    reason         text,
    expires_at     timestamptz NOT NULL,
    decided_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX registration_approvals_open ON registration_approvals (user_id) WHERE state = 'pending';
