-- ProudAuth core schema.
--
-- Conventions (see docs/architecture-decisions/0004-persistence.md):
--   * Opaque, prefixed, immutable text identifiers (DOM-001).
--   * Every tenant-owned row carries realm_id; organization-owned rows also carry
--     organization_id. Composite foreign keys reference (realm_id, id) so a row can
--     never point into another realm or organization by accident (DB-001).
--   * Bearer artifacts are stored as digests only; recoverable secrets are stored
--     as authenticated ciphertext with a key version (DB-008).
--   * Schema changes follow expand -> migrate -> contract (DEP-012).

CREATE TABLE realms (
    id                 text PRIMARY KEY,
    name               text NOT NULL UNIQUE,
    display_name       text NOT NULL,
    issuer             text NOT NULL UNIQUE,
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
    settings           jsonb NOT NULL DEFAULT '{}'::jsonb,
    policy_revision    bigint NOT NULL DEFAULT 1,
    bootstrapped_at    timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    version            bigint NOT NULL DEFAULT 1
);

-- Versioned, auditable configuration history (ARC-008, AZ-017, DEP-020).
CREATE TABLE configuration_revisions (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    scope_type         text NOT NULL,
    scope_id           text NOT NULL,
    revision           bigint NOT NULL,
    document           jsonb NOT NULL,
    document_hash      text NOT NULL,
    changed_by_type    text NOT NULL,
    changed_by_id      text NOT NULL,
    reason             text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, scope_type, scope_id, revision)
);

-- Signing keys. Private keys are envelope-encrypted with the key-wrapping key
-- (DEP-008, SEC-010). Only public material is ever published (TOK-011).
CREATE TABLE signing_keys (
    kid                text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    algorithm          text NOT NULL CHECK (algorithm IN ('RS256', 'ES256', 'EdDSA', 'PS256')),
    public_jwk         jsonb NOT NULL,
    private_ciphertext bytea NOT NULL,
    enc_key_version    integer NOT NULL,
    state              text NOT NULL CHECK (state IN ('pending', 'active', 'retiring', 'retired', 'compromised')),
    purpose            text NOT NULL DEFAULT 'token' CHECK (purpose IN ('token', 'logout', 'audit')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    activated_at       timestamptz,
    retiring_at        timestamptz,
    publish_until      timestamptz,
    retired_at         timestamptz,
    compromised_at     timestamptz,
    UNIQUE (realm_id, kid)
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (realm_id, purpose) WHERE state = 'active';

CREATE TABLE organizations (
    id                 text NOT NULL,
    realm_id           text NOT NULL REFERENCES realms(id),
    slug               text NOT NULL,
    display_name       text NOT NULL,
    state              text NOT NULL DEFAULT 'active'
                       CHECK (state IN ('active', 'suspended', 'archived', 'deleting', 'deleted')),
    locale             text,
    time_zone          text,
    metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,
    contact            jsonb NOT NULL DEFAULT '{}'::jsonb,
    external_id        text,
    policy             jsonb NOT NULL DEFAULT '{}'::jsonb,
    authz_revision     bigint NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    version            bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE (realm_id, id)
);
CREATE UNIQUE INDEX organizations_slug ON organizations (realm_id, slug) WHERE state <> 'deleted';
CREATE UNIQUE INDEX organizations_external_id ON organizations (realm_id, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE organization_domains (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    organization_id    text NOT NULL,
    domain             text NOT NULL,
    state              text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'verified', 'expired', 'conflict', 'removed')),
    challenge_digest   text,
    challenge_expires_at timestamptz,
    verified_at        timestamptz,
    recheck_at         timestamptz,
    routing            jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);
CREATE UNIQUE INDEX organization_domains_verified ON organization_domains (realm_id, domain) WHERE state = 'verified';
CREATE UNIQUE INDEX organization_domains_per_org ON organization_domains (organization_id, domain) WHERE state <> 'removed';

CREATE TABLE users (
    id                    text NOT NULL,
    realm_id              text NOT NULL REFERENCES realms(id),
    state                 text NOT NULL DEFAULT 'active'
                          CHECK (state IN ('pending_verification', 'active', 'suspended', 'locked',
                                           'recovery_restricted', 'pending_deletion', 'deleted')),
    display_name          text,
    given_name            text,
    family_name           text,
    locale                text,
    zoneinfo              text,
    profile               jsonb NOT NULL DEFAULT '{}'::jsonb,   -- user-editable metadata
    admin_metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,   -- administrator-controlled metadata
    internal_metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,   -- confidential internal metadata
    protected             boolean NOT NULL DEFAULT false,       -- platform/realm admins, emergency accounts
    is_guest              boolean NOT NULL DEFAULT false,
    required_actions      text[] NOT NULL DEFAULT '{}',
    credential_revision   bigint NOT NULL DEFAULT 1,
    session_revision      bigint NOT NULL DEFAULT 1,
    authz_revision        bigint NOT NULL DEFAULT 1,
    locked_until          timestamptz,
    last_login_at         timestamptz,
    deletion_requested_at timestamptz,
    deletion_scheduled_at timestamptz,
    deleted_at            timestamptz,
    created_via           text NOT NULL DEFAULT 'registration',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE (realm_id, id)
);
CREATE INDEX users_realm_created ON users (realm_id, created_at, id);
CREATE INDEX users_pending_deletion ON users (deletion_scheduled_at) WHERE state = 'pending_deletion';

-- Login identifiers. Canonical uniqueness is enforced for verified identifiers and
-- usernames (DB-002, REG-005). Unverified contacts never block their real owner.
CREATE TABLE user_identifiers (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    type               text NOT NULL CHECK (type IN ('email', 'phone', 'username')),
    original_value     text NOT NULL,
    canonical_value    text NOT NULL,
    verified_at        timestamptz,
    verification_source text,
    is_primary         boolean NOT NULL DEFAULT false,
    source             text NOT NULL DEFAULT 'user',
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX user_identifiers_unique ON user_identifiers (realm_id, type, canonical_value)
    WHERE verified_at IS NOT NULL OR type = 'username';
CREATE UNIQUE INDEX user_identifiers_user_type_value ON user_identifiers (user_id, type, canonical_value);
CREATE UNIQUE INDEX user_identifiers_primary ON user_identifiers (user_id, type) WHERE is_primary;
CREATE INDEX user_identifiers_lookup ON user_identifiers (realm_id, type, canonical_value);

-- Terms / policy acceptance records (REG-006, PRV-007).
CREATE TABLE terms_acceptances (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    document           text NOT NULL,
    version            text NOT NULL,
    scope_type         text NOT NULL DEFAULT 'realm',
    scope_id           text,
    provenance         text NOT NULL,
    client_id          text,
    accepted_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);

-- Credentials: password verifiers (irreversible), TOTP seeds (encrypted, recoverable).
CREATE TABLE credentials (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    type               text NOT NULL CHECK (type IN ('password', 'totp', 'hotp')),
    name               text,
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('pending', 'active', 'compromised', 'revoked')),
    verifier           text,           -- PHC-format password verifier
    secret_ciphertext  bytea,          -- AEAD-encrypted TOTP seed
    key_version        integer,
    pepper_version     integer,
    algorithm          text,
    params             jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_used_step     bigint,         -- TOTP replay control (MFA-002)
    counter            bigint,         -- HOTP counter (MFA-013)
    last_used_at       timestamptz,
    expires_at         timestamptz,    -- pending enrollment expiry
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX credentials_one_password ON credentials (user_id) WHERE type = 'password' AND state = 'active';
CREATE UNIQUE INDEX credentials_one_totp ON credentials (user_id) WHERE type = 'totp' AND state = 'active';

CREATE TABLE password_history (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    verifier           text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX password_history_user ON password_history (user_id, created_at DESC);

CREATE TABLE recovery_codes (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    batch_id           text NOT NULL,
    code_digest        text NOT NULL,
    key_version        integer NOT NULL,
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'consumed', 'invalidated')),
    consumed_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id) WHERE state = 'active';

CREATE TABLE webauthn_credentials (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    credential_id      bytea NOT NULL,
    public_key         bytea NOT NULL,
    attestation_type   text,
    aaguid             bytea,
    rp_id              text NOT NULL,
    sign_count         bigint NOT NULL DEFAULT 0,
    backup_eligible    boolean NOT NULL DEFAULT false,
    backup_state       boolean NOT NULL DEFAULT false,
    user_verified      boolean NOT NULL DEFAULT false,
    transports         text[] NOT NULL DEFAULT '{}',
    discoverable       boolean NOT NULL DEFAULT false,
    name               text,
    counter_anomalies  integer NOT NULL DEFAULT 0,
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    last_used_at       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX webauthn_credentials_id ON webauthn_credentials (realm_id, credential_id);

CREATE TABLE memberships (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    organization_id    text NOT NULL,
    user_id            text NOT NULL,
    state              text NOT NULL CHECK (state IN ('invited', 'pending_approval', 'active', 'suspended', 'expired', 'removed')),
    source             text NOT NULL CHECK (source IN ('invitation', 'admin', 'directory', 'domain_policy', 'self_join', 'bootstrap', 'jit', 'creator', 'import')),
    source_reference   text,
    external_id        text,
    metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,
    joined_at          timestamptz,
    expires_at         timestamptz,
    removed_at         timestamptz,
    revision           bigint NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, id),
    UNIQUE (organization_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id)
);
-- DB-004: one live membership per user per organization.
CREATE UNIQUE INDEX memberships_single_live ON memberships (organization_id, user_id) WHERE state NOT IN ('removed', 'expired');
CREATE INDEX memberships_user ON memberships (realm_id, user_id);

CREATE TABLE groups (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    organization_id    text NOT NULL,
    parent_id          text,
    name               text NOT NULL,
    description        text,
    metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,
    external_id        text,
    source             text NOT NULL DEFAULT 'admin',
    dynamic_rule       jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    version            bigint NOT NULL DEFAULT 1,
    UNIQUE (organization_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (organization_id, parent_id) REFERENCES groups (organization_id, id)
);
CREATE UNIQUE INDEX groups_name ON groups (organization_id, lower(name));

CREATE TABLE group_memberships (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    organization_id    text NOT NULL,
    group_id           text NOT NULL,
    membership_id      text NOT NULL,
    source             text NOT NULL DEFAULT 'admin',
    valid_from         timestamptz,
    valid_until        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, group_id) REFERENCES groups (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, membership_id) REFERENCES memberships (organization_id, id),
    UNIQUE (group_id, membership_id)
);

CREATE TABLE projects (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    owner_organization_id text,
    name                  text NOT NULL,
    description           text,
    environment           text NOT NULL DEFAULT 'production' CHECK (environment IN ('development', 'staging', 'production')),
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'archived')),
    owner_user_id         text,
    config_revision       bigint NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, owner_organization_id) REFERENCES organizations (realm_id, id)
);
CREATE UNIQUE INDEX projects_name ON projects (realm_id, lower(name)) WHERE state <> 'archived';

CREATE TABLE project_grants (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    project_id         text NOT NULL,
    organization_id    text NOT NULL,
    allowed_role_ids   text[] NOT NULL DEFAULT '{}',
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'revoked')),
    valid_until        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, project_id) REFERENCES projects (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);
CREATE UNIQUE INDEX project_grants_live ON project_grants (project_id, organization_id) WHERE state <> 'revoked';

CREATE TABLE service_principals (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    name               text NOT NULL,
    description        text,
    owner_user_id      text,
    owner_organization_id text,
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled', 'deleted')),
    allowed_organization_ids text[] NOT NULL DEFAULT '{}',
    permission_revision bigint NOT NULL DEFAULT 1,
    is_agent           boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    version            bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, owner_user_id) REFERENCES users (realm_id, id),
    FOREIGN KEY (realm_id, owner_organization_id) REFERENCES organizations (realm_id, id)
);
CREATE UNIQUE INDEX service_principals_name ON service_principals (realm_id, lower(name)) WHERE state <> 'deleted';

CREATE TABLE api_resources (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    project_id            text,
    name                  text NOT NULL,
    audience              text NOT NULL,
    description           text,
    kind                  text NOT NULL DEFAULT 'business' CHECK (kind IN ('business', 'account', 'admin', 'userinfo')),
    token_format          text NOT NULL DEFAULT 'jwt' CHECK (token_format IN ('jwt', 'opaque')),
    verification_mode     text NOT NULL DEFAULT 'offline' CHECK (verification_mode IN ('offline', 'bounded_online', 'strict_online')),
    access_token_ttl_seconds integer NOT NULL DEFAULT 300 CHECK (access_token_ttl_seconds BETWEEN 30 AND 3600),
    requires_organization boolean NOT NULL DEFAULT true,
    impersonation_enabled boolean NOT NULL DEFAULT false,
    impersonation_policy  jsonb NOT NULL DEFAULT '{}'::jsonb,
    signing_algorithm     text NOT NULL DEFAULT 'RS256',
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    owner_user_id         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    UNIQUE (realm_id, audience),
    FOREIGN KEY (realm_id, project_id) REFERENCES projects (realm_id, id)
);

CREATE TABLE scopes (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    resource_id        text,
    name               text NOT NULL,
    description        text,
    consent_text       text,
    sensitivity        text NOT NULL DEFAULT 'normal' CHECK (sensitivity IN ('low', 'normal', 'high', 'privileged')),
    is_default         boolean NOT NULL DEFAULT false,
    kind               text NOT NULL DEFAULT 'resource' CHECK (kind IN ('oidc', 'resource')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, name),
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id) ON DELETE CASCADE
);

CREATE TABLE clients (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    client_id             text NOT NULL,
    project_id            text,
    name                  text NOT NULL,
    description           text,
    client_type           text NOT NULL CHECK (client_type IN ('confidential', 'public_browser', 'native', 'device', 'machine')),
    token_endpoint_auth_method text NOT NULL CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none')),
    grant_types           text[] NOT NULL,
    security_profile      text NOT NULL DEFAULT 'standard',
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'decommissioned')),
    first_party           boolean NOT NULL DEFAULT false,
    consent_mode          text NOT NULL DEFAULT 'required' CHECK (consent_mode IN ('required', 'preauthorized')),
    allow_offline_access  boolean NOT NULL DEFAULT false,
    allow_remember_me     boolean NOT NULL DEFAULT false,
    default_resource_id   text,
    service_principal_id  text,
    environment           text NOT NULL DEFAULT 'production' CHECK (environment IN ('development', 'staging', 'production')),
    subject_type          text NOT NULL DEFAULT 'public' CHECK (subject_type IN ('public', 'pairwise')),
    sector_identifier     text,
    login_ui_url          text,
    backchannel_logout_uri text,
    frontchannel_logout_uri text,
    id_token_claims       jsonb NOT NULL DEFAULT '{}'::jsonb,
    access_token_claims   jsonb NOT NULL DEFAULT '{}'::jsonb,
    token_policy          jsonb NOT NULL DEFAULT '{}'::jsonb,
    jwks                  jsonb,
    owner_user_id         text,
    contacts              text[] NOT NULL DEFAULT '{}',
    registration_access_digest text,
    dynamically_registered boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    UNIQUE (realm_id, client_id),
    FOREIGN KEY (realm_id, project_id) REFERENCES projects (realm_id, id),
    FOREIGN KEY (realm_id, default_resource_id) REFERENCES api_resources (realm_id, id),
    FOREIGN KEY (realm_id, service_principal_id) REFERENCES service_principals (realm_id, id)
);

CREATE TABLE client_redirect_uris (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    client_ref         text NOT NULL,
    uri                text NOT NULL,
    purpose            text NOT NULL CHECK (purpose IN ('redirect', 'post_logout')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id) ON DELETE CASCADE,
    UNIQUE (client_ref, purpose, uri)
);

CREATE TABLE client_origins (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    client_ref         text NOT NULL,
    origin             text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id) ON DELETE CASCADE,
    UNIQUE (client_ref, origin)
);
CREATE INDEX client_origins_origin ON client_origins (realm_id, origin);

CREATE TABLE client_credentials (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    client_ref         text NOT NULL,
    kind               text NOT NULL CHECK (kind IN ('secret', 'public_key')),
    secret_digest      text,
    display_prefix     text,
    public_jwk         jsonb,
    key_id             text,
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    expires_at         timestamptz,
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX client_credentials_client ON client_credentials (client_ref) WHERE state = 'active';

-- Which resources (audiences) a client may request and with which scope ceiling (TOK-007, TOK-008).
CREATE TABLE client_resource_grants (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    client_ref         text NOT NULL,
    resource_id        text NOT NULL,
    allowed_scopes     text[] NOT NULL DEFAULT '{}',
    subject_types      text[] NOT NULL DEFAULT '{user}',
    exchange_policy    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id) ON DELETE CASCADE,
    UNIQUE (client_ref, resource_id)
);

-- Clients that act as a resource server and may introspect tokens for an audience (TOK-009).
CREATE TABLE resource_server_clients (
    realm_id           text NOT NULL,
    resource_id        text NOT NULL,
    client_ref         text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_id, client_ref),
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id) ON DELETE CASCADE
);

-- Replay protection for signed client assertions (APP-009, MCH-010).
CREATE TABLE client_assertion_jtis (
    realm_id           text NOT NULL,
    client_ref         text NOT NULL,
    jti                text NOT NULL,
    expires_at         timestamptz NOT NULL,
    PRIMARY KEY (client_ref, jti)
);

CREATE TABLE identity_providers (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    organization_id    text,
    alias              text NOT NULL,
    display_name       text NOT NULL,
    kind               text NOT NULL CHECK (kind IN ('oidc', 'oauth2_social', 'saml')),
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    issuer             text,
    config             jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_ciphertext  bytea,
    key_version        integer,
    linking_policy     text NOT NULL DEFAULT 'verify_existing' CHECK (linking_policy IN ('verify_existing', 'trusted_verified_email', 'create_only')),
    jit_provisioning   boolean NOT NULL DEFAULT false,
    jit_default_role_id text,
    trust_upstream_mfa boolean NOT NULL DEFAULT false,
    claim_mapping      jsonb NOT NULL DEFAULT '{}'::jsonb,
    mapping_revision   bigint NOT NULL DEFAULT 1,
    owner_user_id      text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    version            bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    UNIQUE (realm_id, alias),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);

-- DB-003: a connection's validated upstream subject maps to at most one local user.
CREATE TABLE external_identities (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL,
    user_id            text NOT NULL,
    provider_id        text NOT NULL,
    upstream_issuer    text NOT NULL,
    upstream_subject   text NOT NULL,
    email_hint         text,
    linking_provenance text NOT NULL,
    upstream_token_ciphertext bytea,
    key_version        integer,
    last_used_at       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, provider_id) REFERENCES identity_providers (realm_id, id),
    UNIQUE (provider_id, upstream_issuer, upstream_subject)
);
