-- Authorization, invitations, join requests, support impersonation and automation credentials.

CREATE TABLE permissions (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    name                  text NOT NULL,           -- namespaced, e.g. org.members.read, orders.refund (AZ-001)
    namespace             text NOT NULL,           -- platform | realm | organization | support | application
    description           text,
    resource_type         text,
    owner_resource_id     text,
    sensitivity           text NOT NULL DEFAULT 'normal' CHECK (sensitivity IN ('low', 'normal', 'high', 'privileged')),
    built_in              boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, id),
    UNIQUE (realm_id, name)
);

CREATE TABLE roles (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    boundary_type         text NOT NULL CHECK (boundary_type IN ('realm', 'organization', 'project')),
    organization_id       text,            -- set for organization-defined custom roles
    project_id            text,            -- set for project/application roles
    name                  text NOT NULL,
    description           text,
    protected             boolean NOT NULL DEFAULT false,   -- e.g. owner, realm-admin
    built_in              boolean NOT NULL DEFAULT false,
    is_owner_role         boolean NOT NULL DEFAULT false,
    composite_role_ids    text[] NOT NULL DEFAULT '{}',
    incompatible_role_ids text[] NOT NULL DEFAULT '{}',
    requires_approval     boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (realm_id, project_id) REFERENCES projects (realm_id, id)
);
CREATE UNIQUE INDEX roles_name ON roles (realm_id, boundary_type, coalesce(organization_id, ''), coalesce(project_id, ''), lower(name));

CREATE TABLE role_permissions (
    realm_id              text NOT NULL,
    role_id               text NOT NULL,
    permission_id         text NOT NULL,
    effect                text NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    granted_by_type       text,
    granted_by_id         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (realm_id, role_id) REFERENCES roles (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, permission_id) REFERENCES permissions (realm_id, id) ON DELETE CASCADE
);

-- Role assignments are scoped. Organization-scoped assignments reference the membership,
-- never a global user flag (AZ-003).
CREATE TABLE role_assignments (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    role_id               text NOT NULL,
    subject_type          text NOT NULL CHECK (subject_type IN ('user', 'service_principal', 'group')),
    subject_id            text NOT NULL,
    membership_id         text,
    scope_type            text NOT NULL CHECK (scope_type IN ('realm', 'organization', 'project')),
    scope_id              text NOT NULL,
    conditions            jsonb NOT NULL DEFAULT '{}'::jsonb,
    valid_from            timestamptz,
    expires_at            timestamptz,
    granted_by_type       text,
    granted_by_id         text,
    approved_by_id        text,
    source                text NOT NULL DEFAULT 'admin',
    reason                text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, role_id) REFERENCES roles (realm_id, id),
    FOREIGN KEY (realm_id, membership_id) REFERENCES memberships (realm_id, id) ON DELETE CASCADE,
    -- Users hold organization roles only through a membership (AZ-003); other subjects never reference one.
    CHECK ((subject_type = 'user' AND (scope_type = 'organization') = (membership_id IS NOT NULL))
        OR (subject_type <> 'user' AND membership_id IS NULL))
);
CREATE UNIQUE INDEX role_assignments_unique ON role_assignments (role_id, subject_type, subject_id, scope_type, scope_id);
CREATE INDEX role_assignments_subject ON role_assignments (realm_id, subject_type, subject_id);
CREATE INDEX role_assignments_scope ON role_assignments (scope_type, scope_id);

-- Versioned ABAC policies (AZ-015, AZ-017).
CREATE TABLE policies (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    name                  text NOT NULL,
    description           text,
    scope_type            text NOT NULL DEFAULT 'realm',
    scope_id              text,
    active_version        integer,
    state                 text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'active', 'disabled')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, name)
);

CREATE TABLE policy_versions (
    id                    text PRIMARY KEY,
    policy_id             text NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version_number        integer NOT NULL,
    definition            jsonb NOT NULL,
    definition_hash       text NOT NULL,
    status                text NOT NULL DEFAULT 'staged' CHECK (status IN ('staged', 'approved', 'published', 'superseded', 'rejected')),
    author_id             text NOT NULL,
    approved_by_id        text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    published_at          timestamptz,
    UNIQUE (policy_id, version_number)
);

CREATE TABLE resource_relationships (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    organization_id       text NOT NULL,
    subject_type          text NOT NULL,
    subject_id            text NOT NULL,
    relation              text NOT NULL,
    object_type           text NOT NULL,
    object_id             text NOT NULL,
    source                text NOT NULL,
    revision              bigint NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, subject_type, subject_id, relation, object_type, object_id)
);

CREATE TABLE invitations (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    organization_id       text NOT NULL,
    purpose               text NOT NULL DEFAULT 'organization_membership' CHECK (purpose IN ('organization_membership', 'project_access', 'shared_link')),
    project_id            text,
    target_email_canonical text,
    target_email_display  text,
    target_user_id        text,
    role_ids              text[] NOT NULL DEFAULT '{}',
    inviter_type          text NOT NULL,
    inviter_id            text NOT NULL,
    secret_digest         text NOT NULL,
    secret_version        integer NOT NULL DEFAULT 1,
    state                 text NOT NULL CHECK (state IN ('created', 'pending_delivery', 'pending_acceptance', 'accepted', 'declined', 'expired', 'revoked')),
    delivery_state        text NOT NULL DEFAULT 'queued' CHECK (delivery_state IN ('queued', 'attempted', 'accepted_by_provider', 'failed', 'not_applicable')),
    send_count            integer NOT NULL DEFAULT 1,
    max_uses              integer NOT NULL DEFAULT 1,
    use_count             integer NOT NULL DEFAULT 0,
    allowed_domains       text[] NOT NULL DEFAULT '{}',
    expires_at            timestamptz NOT NULL,
    accepted_by_user_id   text,
    accepted_at           timestamptz,
    membership_id         text,
    decided_at            timestamptz,
    message               text,
    idempotency_key       text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);
CREATE UNIQUE INDEX invitations_secret ON invitations (secret_digest);
CREATE INDEX invitations_org ON invitations (organization_id, state, created_at);

CREATE TABLE join_requests (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    organization_id       text NOT NULL,
    user_id               text NOT NULL,
    project_id            text,
    reason                text,
    reviewer_ids          text[] NOT NULL DEFAULT '{}',
    state                 text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'withdrawn')),
    decided_by_id         text,
    decision_reason       text,
    decided_at            timestamptz,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id)
);
CREATE UNIQUE INDEX join_requests_pending ON join_requests (organization_id, user_id) WHERE state = 'pending';

CREATE TABLE impersonation_requests (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    actor_user_id         text NOT NULL,
    actor_session_id      text NOT NULL,
    target_user_id        text NOT NULL,
    organization_id       text NOT NULL,
    client_ref            text NOT NULL,
    resource_id           text NOT NULL,
    scopes                text[] NOT NULL,
    mode                  text NOT NULL DEFAULT 'read_only' CHECK (mode IN ('read_only', 'allowlisted_write')),
    reason                text NOT NULL,
    ticket_reference      text,
    requested_ttl_seconds integer NOT NULL,
    approval_required     text NOT NULL DEFAULT 'none' CHECK (approval_required IN ('none', 'second_operator', 'organization_owner', 'customer')),
    state                 text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'issued', 'expired', 'cancelled')),
    approved_by_id        text,
    approved_at           timestamptz,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, actor_user_id) REFERENCES users (realm_id, id),
    FOREIGN KEY (realm_id, target_user_id) REFERENCES users (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id)
);

CREATE TABLE impersonation_grants (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    request_id            text NOT NULL REFERENCES impersonation_requests(id),
    actor_user_id         text NOT NULL,
    actor_session_id      text NOT NULL,
    actor_mfa_time        timestamptz NOT NULL,
    target_user_id        text NOT NULL,
    target_membership_id  text NOT NULL,
    organization_id       text NOT NULL,
    client_ref            text NOT NULL,
    resource_id           text NOT NULL,
    scope_ceiling         text[] NOT NULL,
    mode                  text NOT NULL,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz,
    revoked_by_type       text,
    revoked_by_id         text,
    revoke_reason         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, target_membership_id) REFERENCES memberships (realm_id, id)
);
CREATE INDEX impersonation_grants_actor ON impersonation_grants (actor_user_id, state);
CREATE INDEX impersonation_grants_target ON impersonation_grants (target_user_id, state);

CREATE TABLE impersonation_handoffs (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    grant_id              text NOT NULL REFERENCES impersonation_grants(id),
    code_digest           text NOT NULL UNIQUE,
    destination_client_ref text NOT NULL,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- Scoped API keys and personal access tokens (MCH-005, MCH-006).
CREATE TABLE automation_credentials (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    kind                  text NOT NULL CHECK (kind IN ('api_key', 'personal_token')),
    owner_type            text NOT NULL CHECK (owner_type IN ('user', 'service_principal')),
    owner_id              text NOT NULL,
    name                  text NOT NULL,
    display_prefix        text NOT NULL,
    secret_digest         text NOT NULL UNIQUE,
    scopes                text[] NOT NULL DEFAULT '{}',
    resource_id           text NOT NULL,
    organization_id       text,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    expires_at            timestamptz NOT NULL,
    last_used_at          timestamptz,
    created_by_type       text NOT NULL,
    created_by_id         text NOT NULL,
    revoked_at            timestamptz,
    revoke_reason         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id)
);
CREATE INDEX automation_credentials_owner ON automation_credentials (owner_type, owner_id);
