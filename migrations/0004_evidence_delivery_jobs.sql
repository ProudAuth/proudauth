-- Audit evidence, outbox, notification and webhook delivery, jobs, idempotency,
-- rate limiting, provisioning and lifecycle tombstones.

CREATE TABLE audit_events (
    seq                   bigserial PRIMARY KEY,
    id                    text NOT NULL UNIQUE,
    schema_version        integer NOT NULL DEFAULT 1,
    type                  text NOT NULL,
    occurred_at           timestamptz NOT NULL,
    recorded_at           timestamptz NOT NULL DEFAULT now(),
    realm_id              text,
    organization_id       text,
    actor_type            text NOT NULL,
    actor_id              text NOT NULL,
    actor_session_id      text,
    subject_type          text,
    subject_id            text,
    target_type           text,
    target_id             text,
    outcome               text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    reason_code           text,
    request_id            text,
    client_id             text,
    session_id            text,
    grant_id              text,
    impersonation_grant_id text,
    source                text NOT NULL DEFAULT 'server' CHECK (source IN ('server', 'application', 'import')),
    reporting_service     text,
    ip_context            text,
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb,
    category              text NOT NULL DEFAULT 'security',
    content_hash          text NOT NULL,
    batch_id              text
);
CREATE INDEX audit_events_realm_time ON audit_events (realm_id, occurred_at DESC, seq DESC);
CREATE INDEX audit_events_org_time ON audit_events (organization_id, occurred_at DESC) WHERE organization_id IS NOT NULL;
CREATE INDEX audit_events_actor ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX audit_events_subject ON audit_events (subject_id, occurred_at DESC) WHERE subject_id IS NOT NULL;
CREATE INDEX audit_events_unsealed ON audit_events (seq) WHERE batch_id IS NULL;

-- Hash-linked batches give tamper evidence (AUD-008). Each batch commits the digest of
-- its member events and the previous batch hash.
CREATE TABLE audit_batches (
    id                    text PRIMARY KEY,
    sequence_number       bigint NOT NULL UNIQUE,
    previous_hash         text NOT NULL,
    events_digest         text NOT NULL,
    batch_hash            text NOT NULL,
    event_count           integer NOT NULL,
    first_seq             bigint NOT NULL,
    last_seq              bigint NOT NULL,
    signature             text,
    signing_kid           text,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- Audit is append-only for the application role (AUD-007). Corrections are new events.
-- Only the batch sealer may set batch_id once; nothing may delete rows except the
-- retention job, which must run with the session variable proudauth.audit_retention = 'on'.
CREATE FUNCTION audit_events_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('proudauth.audit_retention', true) = 'on' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'audit_events is append-only';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.batch_id IS NULL AND NEW.batch_id IS NOT NULL
           AND ROW(NEW.seq, NEW.id, NEW.type, NEW.occurred_at, NEW.realm_id, NEW.actor_id, NEW.content_hash, NEW.metadata, NEW.outcome)
               IS NOT DISTINCT FROM
               ROW(OLD.seq, OLD.id, OLD.type, OLD.occurred_at, OLD.realm_id, OLD.actor_id, OLD.content_hash, OLD.metadata, OLD.outcome) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'audit_events is append-only';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_guard();

CREATE FUNCTION audit_batches_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_batches is append-only';
END $$;
CREATE TRIGGER audit_batches_append_only BEFORE UPDATE OR DELETE ON audit_batches
    FOR EACH ROW EXECUTE FUNCTION audit_batches_guard();

-- Transactional outbox (ARC-003, DB-009).
CREATE TABLE outbox_events (
    seq                   bigserial PRIMARY KEY,
    id                    text NOT NULL UNIQUE,
    realm_id              text,
    organization_id       text,
    event_type            text NOT NULL,
    event_version         integer NOT NULL DEFAULT 1,
    aggregate_type        text,
    aggregate_id          text,
    payload               jsonb NOT NULL,
    occurred_at           timestamptz NOT NULL DEFAULT now(),
    state                 text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'dispatched', 'failed')),
    attempts              integer NOT NULL DEFAULT 0,
    lease_owner           text,
    lease_expires_at      timestamptz,
    dispatched_at         timestamptz,
    last_error            text
);
CREATE INDEX outbox_events_pending ON outbox_events (seq) WHERE state = 'pending';

CREATE TABLE notification_templates (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    organization_id       text,
    event_type            text NOT NULL,
    locale                text NOT NULL,
    subject               text NOT NULL,
    body_text             text NOT NULL,
    body_html             text,
    version               integer NOT NULL DEFAULT 1,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX notification_templates_key ON notification_templates (realm_id, coalesce(organization_id, ''), event_type, locale) WHERE state = 'active';

CREATE TABLE notification_settings (
    realm_id              text NOT NULL REFERENCES realms(id),
    organization_id       text NOT NULL DEFAULT '',
    sender_address        text,
    sender_name           text,
    reply_to              text,
    default_locale        text NOT NULL DEFAULT 'en',
    smtp_config           jsonb NOT NULL DEFAULT '{}'::jsonb,
    smtp_secret_ciphertext bytea,
    key_version           integer,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (realm_id, organization_id)
);

-- Durable notification jobs. Secret-bearing payloads are encrypted and purged after
-- bounded retention while non-secret delivery evidence remains (MSG-002, MSG-009).
CREATE TABLE notification_jobs (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    organization_id       text,
    channel               text NOT NULL CHECK (channel IN ('email', 'sms')),
    template              text NOT NULL,
    locale                text NOT NULL DEFAULT 'en',
    recipient_ciphertext  bytea,
    payload_ciphertext    bytea,
    key_version           integer,
    recipient_hint        text,
    mandatory             boolean NOT NULL DEFAULT true,
    reference_type        text,
    reference_id          text,
    state                 text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'attempted', 'accepted', 'failed', 'expired', 'suppressed')),
    attempts              integer NOT NULL DEFAULT 0,
    max_attempts          integer NOT NULL DEFAULT 5,
    next_attempt_at       timestamptz NOT NULL DEFAULT now(),
    lease_owner           text,
    lease_expires_at      timestamptz,
    last_error            text,
    provider_message_id   text,
    payload_purged_at     timestamptz,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notification_jobs_due ON notification_jobs (next_attempt_at) WHERE state IN ('queued', 'attempted');

-- Local development sink (MSG-011). Never enabled in production mode.
CREATE TABLE dev_mailbox (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    recipient             text NOT NULL,
    subject               text NOT NULL,
    body_text             text NOT NULL,
    template              text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_suppressions (
    realm_id              text NOT NULL,
    recipient_digest      text NOT NULL,
    reason                text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, recipient_digest)
);

CREATE TABLE webhook_subscriptions (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    organization_id       text,
    name                  text NOT NULL,
    destination_url       text NOT NULL,
    event_types           text[] NOT NULL,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'paused', 'disabled')),
    secret_ciphertext     bytea NOT NULL,
    previous_secret_ciphertext bytea,
    previous_secret_expires_at timestamptz,
    key_version           integer NOT NULL,
    allow_private_network boolean NOT NULL DEFAULT false,
    payload_form          text NOT NULL DEFAULT 'minimal' CHECK (payload_form IN ('minimal', 'standard')),
    owner_user_id         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1
);

CREATE TABLE webhook_deliveries (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    subscription_id       text NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id              text NOT NULL,
    event_type            text NOT NULL,
    payload               jsonb NOT NULL,
    state                 text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'retrying', 'dead_letter')),
    attempts              integer NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NOT NULL DEFAULT now(),
    last_status_code      integer,
    last_response_category text,
    lease_owner           text,
    lease_expires_at      timestamptz,
    delivered_at          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (subscription_id, event_id)
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at) WHERE state IN ('pending', 'retrying');

-- Back-channel logout delivery state (SES-017).
CREATE TABLE logout_deliveries (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    client_ref            text NOT NULL,
    session_id            text NOT NULL,
    user_id               text NOT NULL,
    state                 text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'retrying', 'failed')),
    attempts              integer NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NOT NULL DEFAULT now(),
    last_status_code      integer,
    delivered_at          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_ref, session_id)
);

CREATE TABLE jobs (
    id                    text PRIMARY KEY,
    realm_id              text,
    organization_id       text,
    type                  text NOT NULL,
    state                 text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'dead_letter')),
    input                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    checkpoint            jsonb NOT NULL DEFAULT '{}'::jsonb,
    result                jsonb,
    result_ciphertext     bytea,
    key_version           integer,
    progress              jsonb NOT NULL DEFAULT '{}'::jsonb,
    dry_run               boolean NOT NULL DEFAULT false,
    requested_by_type     text NOT NULL,
    requested_by_id       text NOT NULL,
    idempotency_key       text,
    attempts              integer NOT NULL DEFAULT 0,
    max_attempts          integer NOT NULL DEFAULT 5,
    run_after             timestamptz NOT NULL DEFAULT now(),
    lease_owner           text,
    lease_expires_at      timestamptz,
    last_error            text,
    cancel_requested      boolean NOT NULL DEFAULT false,
    result_expires_at     timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    finished_at           timestamptz
);
CREATE INDEX jobs_due ON jobs (run_after) WHERE state = 'queued';
CREATE UNIQUE INDEX jobs_idempotency ON jobs (requested_by_id, type, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE job_download_tokens (
    id                    text PRIMARY KEY,
    job_id                text NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    token_digest          text NOT NULL UNIQUE,
    requested_by_id       text NOT NULL,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- Idempotency records (API-005). Secret-bearing responses are never replayed (API-006).
CREATE TABLE idempotency_records (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    actor_id              text NOT NULL,
    route                 text NOT NULL,
    key_digest            text NOT NULL,
    request_hash          text NOT NULL,
    status_code           integer,
    response_body         jsonb,
    contains_secret       boolean NOT NULL DEFAULT false,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, actor_id, route, key_digest)
);

-- Concurrency-safe throttling counters shared by every node (SEC-006).
CREATE TABLE rate_limit_counters (
    bucket                text NOT NULL,
    window_start          timestamptz NOT NULL,
    count                 integer NOT NULL DEFAULT 0,
    expires_at            timestamptz NOT NULL,
    PRIMARY KEY (bucket, window_start)
);
CREATE INDEX rate_limit_counters_expiry ON rate_limit_counters (expires_at);

-- Restore reconciliation records (PRV-006, OPS-014, MIG-017).
CREATE TABLE deletion_tombstones (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    reference_type        text NOT NULL,
    reference_digest      text NOT NULL,
    reference_id          text NOT NULL,
    action                text NOT NULL CHECK (action IN ('deleted', 'revoked', 'consumed', 'suppressed')),
    revision              bigint NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX deletion_tombstones_ref ON deletion_tombstones (realm_id, reference_type, reference_digest);

CREATE TABLE provisioning_connectors (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL REFERENCES realms(id),
    organization_id       text NOT NULL,
    name                  text NOT NULL,
    kind                  text NOT NULL CHECK (kind IN ('scim_inbound', 'ldap', 'scim_outbound')),
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    token_digest          text,
    config                jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_ciphertext     bytea,
    key_version           integer,
    allowed_resource_types text[] NOT NULL DEFAULT '{User,Group}',
    role_ceiling_ids      text[] NOT NULL DEFAULT '{}',
    group_role_mappings   jsonb NOT NULL DEFAULT '{}'::jsonb,
    default_role_id       text,
    cursor                text,
    last_sync_at          timestamptz,
    last_error            text,
    stats                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint NOT NULL DEFAULT 1,
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);

-- Connector-scoped external IDs (PROV-004, USR-017). Two connectors may reuse the same
-- external ID without colliding.
CREATE TABLE connector_external_ids (
    connector_id          text NOT NULL REFERENCES provisioning_connectors(id) ON DELETE CASCADE,
    resource_type         text NOT NULL,
    external_id           text NOT NULL,
    local_id              text NOT NULL,
    resource_version      bigint NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, resource_type, external_id),
    UNIQUE (connector_id, resource_type, local_id)
);

-- Migration source mappings (MIG-004).
CREATE TABLE import_mappings (
    realm_id              text NOT NULL,
    source_system         text NOT NULL,
    source_type           text NOT NULL,
    source_id             text NOT NULL,
    local_id              text NOT NULL,
    job_id                text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, source_system, source_type, source_id)
);

CREATE TABLE remembered_devices (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    user_id               text NOT NULL,
    token_digest          text NOT NULL UNIQUE,
    label                 text,
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz,
    last_used_at          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
