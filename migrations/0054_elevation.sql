-- Just-in-time privilege elevation (AZ-024): administrators make a person
-- eligible for a role at a scope; the person asks for it with a reason and a
-- duration, an independent approver decides (unless the eligibility waives
-- approval), and the role assignment ends on its own at the deadline.
-- Distinct from support impersonation. Additive only.
CREATE TABLE IF NOT EXISTS elevation_eligibilities (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    user_id               text NOT NULL,
    role_id               text NOT NULL,
    scope_type            text NOT NULL CHECK (scope_type IN ('realm', 'organization', 'project')),
    scope_id              text NOT NULL,
    max_duration_seconds  integer NOT NULL,
    requires_approval     boolean NOT NULL DEFAULT true,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_by_id         text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, role_id) REFERENCES roles (realm_id, id)
);
CREATE INDEX IF NOT EXISTS elevation_eligibilities_user ON elevation_eligibilities (user_id) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS elevations (
    id                text PRIMARY KEY,
    realm_id          text NOT NULL,
    eligibility_id    text NOT NULL REFERENCES elevation_eligibilities(id),
    user_id           text NOT NULL,
    reason            text NOT NULL,
    duration_seconds  integer NOT NULL,
    state             text NOT NULL CHECK (state IN ('pending', 'active', 'rejected', 'ended', 'expired', 'cancelled')),
    requested_at      timestamptz NOT NULL DEFAULT now(),
    decided_by_id     text,
    decided_at        timestamptz,
    starts_at         timestamptz,
    ends_at           timestamptz,
    assignment_id     text
);
CREATE INDEX IF NOT EXISTS elevations_pending ON elevations (realm_id) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS elevations_user ON elevations (user_id, state);
CREATE INDEX IF NOT EXISTS elevations_assignment ON elevations (assignment_id) WHERE assignment_id IS NOT NULL;
