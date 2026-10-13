-- Two-party approval for roles that require it (AZ-018): a request is created by
-- one administrator and approved by a different, authenticated administrator who
-- could grant the role themselves. Expand-only.
CREATE TABLE role_assignment_requests (
    id               text PRIMARY KEY,
    realm_id         text NOT NULL REFERENCES realms(id),
    role_id          text NOT NULL,
    subject_type     text NOT NULL,
    subject_id       text NOT NULL,
    scope_type       text NOT NULL,
    scope_id         text NOT NULL,
    conditions       jsonb NOT NULL DEFAULT '{}'::jsonb,
    valid_from       timestamptz,
    assignment_expires_at timestamptz,
    reason           text,
    requested_by_type text NOT NULL,
    requested_by_id  text NOT NULL,
    state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by_id    text,
    decided_at       timestamptz,
    assignment_id    text,
    expires_at       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, role_id) REFERENCES roles (realm_id, id)
);
CREATE INDEX role_assignment_requests_pending ON role_assignment_requests (realm_id, state) WHERE state = 'pending';
