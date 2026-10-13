-- Authentication transactions, one-time challenges, sessions, grants and token state.

CREATE TABLE auth_transactions (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    client_ref            text NOT NULL,
    mode                  text NOT NULL CHECK (mode IN ('browser', 'headless')),
    intent                text NOT NULL DEFAULT 'login' CHECK (intent IN ('login', 'register', 'step_up', 'invitation', 'device')),
    continuation_digest   text NOT NULL,
    csrf_digest           text,
    redirect_uri          text,
    response_type         text NOT NULL DEFAULT 'code',
    response_mode         text NOT NULL DEFAULT 'query',
    requested_scopes      text[] NOT NULL DEFAULT '{}',
    requested_resource_ids text[] NOT NULL DEFAULT '{}',
    state_param           text,
    nonce                 text,
    code_challenge        text,
    code_challenge_method text,
    prompt                text[] NOT NULL DEFAULT '{}',
    max_age               integer,
    acr_values            text[] NOT NULL DEFAULT '{}',
    login_hint            text,
    ui_locales            text,
    requested_org_id      text,
    invitation_id         text,
    device_code_id        text,
    user_id               text,
    identified_via        text,
    completed_factors     jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_actions_done text[] NOT NULL DEFAULT '{}',
    auth_time             timestamptz,
    selected_org_id       text,
    granted_scopes        text[],
    consent_decided       boolean NOT NULL DEFAULT false,
    remember_me           boolean NOT NULL DEFAULT false,
    session_id            text,
    reused_session_id     text,
    status                text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'cancelled', 'expired', 'failed')),
    failure_count         integer NOT NULL DEFAULT 0,
    client_ip             text,
    user_agent            text,
    pending_state         jsonb NOT NULL DEFAULT '{}'::jsonb,
    expires_at            timestamptz NOT NULL,
    completed_at          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);
CREATE INDEX auth_transactions_expiry ON auth_transactions (expires_at) WHERE status = 'pending';

-- Purpose-bound one-time challenges (OTP codes, magic links, reset and setup secrets).
CREATE TABLE challenges (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    purpose               text NOT NULL CHECK (purpose IN ('email_verification', 'phone_verification', 'login_otp',
                               'magic_link', 'password_reset', 'identifier_change', 'account_setup', 'registration')),
    transaction_id        text,
    user_id               text,
    identifier_type       text,
    identifier_canonical  text,
    verifier              text NOT NULL,     -- keyed HMAC verifier; never the raw secret (PWDLESS-007)
    key_version           integer NOT NULL,
    secret_kind           text NOT NULL CHECK (secret_kind IN ('code', 'link')),
    attempts              integer NOT NULL DEFAULT 0,
    max_attempts          integer NOT NULL DEFAULT 5,
    send_count            integer NOT NULL DEFAULT 1,
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    superseded_at         timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, id)
);
CREATE INDEX challenges_transaction ON challenges (transaction_id) WHERE consumed_at IS NULL AND superseded_at IS NULL;
CREATE INDEX challenges_expiry ON challenges (expires_at);

CREATE TABLE sessions (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    user_id               text NOT NULL,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    auth_time             timestamptz NOT NULL,
    mfa_time              timestamptz,
    amr                   text[] NOT NULL DEFAULT '{}',
    acr                   text NOT NULL DEFAULT 'pwd',
    factors               jsonb NOT NULL DEFAULT '[]'::jsonb,
    recovery_restricted   boolean NOT NULL DEFAULT false,
    remember_me           boolean NOT NULL DEFAULT false,
    transient             boolean NOT NULL DEFAULT false,
    cookie_digest         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_activity_at      timestamptz NOT NULL DEFAULT now(),
    idle_expires_at       timestamptz NOT NULL,
    absolute_expires_at   timestamptz NOT NULL,
    revoked_at            timestamptz,
    revoke_reason         text,
    client_ip             text,
    user_agent            text,
    device_label          text,
    revision              bigint NOT NULL DEFAULT 1,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id)
);
CREATE INDEX sessions_user ON sessions (user_id) WHERE state = 'active';
CREATE UNIQUE INDEX sessions_cookie ON sessions (cookie_digest) WHERE cookie_digest IS NOT NULL;

CREATE TABLE client_sessions (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    session_id            text NOT NULL,
    client_ref            text NOT NULL,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'logged_out')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_used_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, session_id) REFERENCES sessions (realm_id, id),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id),
    UNIQUE (session_id, client_ref)
);

CREATE TABLE consents (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    user_id               text NOT NULL,
    client_ref            text NOT NULL,
    scopes                text[] NOT NULL,
    resource_ids          text[] NOT NULL DEFAULT '{}',
    terms_version         text,
    mode                  text NOT NULL DEFAULT 'user' CHECK (mode IN ('user', 'preauthorized')),
    granted_at            timestamptz NOT NULL DEFAULT now(),
    revoked_at            timestamptz,
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);
CREATE UNIQUE INDEX consents_live ON consents (user_id, client_ref) WHERE revoked_at IS NULL;

-- A persisted authorization relationship: subject + client + organization + resources/scopes.
CREATE TABLE authorization_grants (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    subject_type          text NOT NULL CHECK (subject_type IN ('user', 'service_principal')),
    subject_id            text NOT NULL,
    client_ref            text NOT NULL,
    organization_id       text,
    session_id            text,
    resource_ids          text[] NOT NULL DEFAULT '{}',
    scopes                text[] NOT NULL DEFAULT '{}',
    offline               boolean NOT NULL DEFAULT false,
    consent_id            text,
    auth_time             timestamptz,
    amr                   text[] NOT NULL DEFAULT '{}',
    acr                   text,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz,
    revoke_reason         text,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id),
    FOREIGN KEY (realm_id, session_id) REFERENCES sessions (realm_id, id)
);
CREATE INDEX authorization_grants_session ON authorization_grants (session_id) WHERE state = 'active';
CREATE INDEX authorization_grants_subject ON authorization_grants (subject_id) WHERE state = 'active';
CREATE INDEX authorization_grants_org ON authorization_grants (organization_id) WHERE state = 'active';

CREATE TABLE authorization_codes (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    code_digest           text NOT NULL UNIQUE,
    client_ref            text NOT NULL,
    transaction_id        text NOT NULL,
    grant_id              text NOT NULL,
    redirect_uri          text NOT NULL,
    code_challenge        text NOT NULL,
    code_challenge_method text NOT NULL CHECK (code_challenge_method = 'S256'),
    nonce                 text,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id),
    FOREIGN KEY (realm_id, grant_id) REFERENCES authorization_grants (realm_id, id)
);

CREATE TABLE refresh_families (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    grant_id              text NOT NULL,
    client_ref            text NOT NULL,
    current_generation    integer NOT NULL DEFAULT 1,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'compromised', 'revoked', 'expired')),
    idle_expires_at       timestamptz NOT NULL,
    absolute_expires_at   timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_rotated_at       timestamptz,
    revoked_at            timestamptz,
    revoke_reason         text,
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, grant_id) REFERENCES authorization_grants (realm_id, id),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);
CREATE INDEX refresh_families_grant ON refresh_families (grant_id);

CREATE TABLE refresh_tokens (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    family_id             text NOT NULL REFERENCES refresh_families(id),
    generation            integer NOT NULL,
    token_digest          text NOT NULL UNIQUE,
    parent_id             text REFERENCES refresh_tokens(id),
    issued_at             timestamptz NOT NULL DEFAULT now(),
    consumed_at           timestamptz,
    revoked_at            timestamptz,
    UNIQUE (family_id, generation)
);
-- DB-006: a consumed generation has at most one successor.
CREATE UNIQUE INDEX refresh_tokens_one_child ON refresh_tokens (parent_id) WHERE parent_id IS NOT NULL;

CREATE TABLE opaque_access_tokens (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    token_digest          text NOT NULL UNIQUE,
    token_kind            text NOT NULL CHECK (token_kind IN ('user_access', 'service_access', 'impersonation_access', 'exchange_access')),
    grant_id              text,
    client_ref            text NOT NULL,
    subject_type          text NOT NULL,
    subject_id            text NOT NULL,
    actor                 jsonb,
    organization_id       text,
    resource_id           text NOT NULL,
    scopes                text[] NOT NULL DEFAULT '{}',
    session_id            text,
    impersonation_grant_id text,
    jti                   text NOT NULL,
    auth_time             timestamptz,
    acr                   text,
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id),
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id)
);
CREATE INDEX opaque_access_tokens_grant ON opaque_access_tokens (grant_id);
CREATE INDEX opaque_access_tokens_imp ON opaque_access_tokens (impersonation_grant_id);

-- Revocation records for JWT access tokens and other references (TOK-010, PRV-006).
CREATE TABLE token_revocations (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    reference_type        text NOT NULL CHECK (reference_type IN ('jti', 'family', 'session', 'grant', 'key', 'user', 'client')),
    reference_id          text NOT NULL,
    reason                text NOT NULL,
    effective_at          timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz,
    revision              bigint NOT NULL DEFAULT 1
);
CREATE INDEX token_revocations_ref ON token_revocations (realm_id, reference_type, reference_id);

-- Device authorization grant (RFC 8628).
CREATE TABLE device_codes (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    client_ref            text NOT NULL,
    device_code_digest    text NOT NULL UNIQUE,
    user_code_digest      text NOT NULL,
    scopes                text[] NOT NULL DEFAULT '{}',
    resource_ids          text[] NOT NULL DEFAULT '{}',
    requested_org_id      text,
    state                 text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
    grant_id              text,
    user_id               text,
    interval_seconds      integer NOT NULL DEFAULT 5,
    last_polled_at        timestamptz,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);
CREATE UNIQUE INDEX device_codes_user_code ON device_codes (realm_id, user_code_digest) WHERE state = 'pending';

-- Pushed authorization requests (RFC 9126).
CREATE TABLE pushed_authorization_requests (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    client_ref            text NOT NULL,
    request_uri_digest    text NOT NULL UNIQUE,
    parameters            jsonb NOT NULL,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);

-- DPoP proof replay cache (RFC 9449).
CREATE TABLE dpop_proof_jtis (
    realm_id              text NOT NULL,
    jkt                   text NOT NULL,
    jti                   text NOT NULL,
    expires_at            timestamptz NOT NULL,
    PRIMARY KEY (realm_id, jkt, jti)
);
