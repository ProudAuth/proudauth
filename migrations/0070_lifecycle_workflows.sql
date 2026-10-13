-- Lifecycle workflows (EXT-015, EXT-016): versioned, realm-scoped definitions
-- of onboarding, access-expiry, approval and offboarding steps, triggered by
-- outbox events, by a schedule or by an administrator, and executed by the
-- worker as durable runs: one row per run and one per step attempt, each
-- attempt recording its input version, result, retry policy, idempotency key
-- and compensation. Additive only: older binaries never read these tables.

CREATE TABLE IF NOT EXISTS workflows (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    name               text NOT NULL,
    description        text,
    -- draft: no published revision yet; active: triggers fire and runs
    -- advance; disabled: nothing fires and in-flight runs pause (SEC-020).
    state              text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'active', 'disabled')),
    active_revision    integer,
    -- The administrator who published the active revision: the accountable
    -- actor of every run and the delegation ceiling of its steps.
    published_by_id    text,
    requires_approval  boolean NOT NULL DEFAULT false,
    owner_user_id      text,
    -- Set when a plugin manages the workflow (EXT-014).
    plugin_id          text,
    -- Trigger index of the active revision, so dispatch matches events and
    -- schedules without parsing definitions.
    event_types        text[] NOT NULL DEFAULT '{}',
    schedule_every_s   integer,
    next_fire_at       timestamptz,
    version            bigint NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, name),
    UNIQUE (realm_id, id)
);
CREATE INDEX IF NOT EXISTS workflows_events ON workflows USING gin (event_types) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS workflows_schedule ON workflows (next_fire_at) WHERE state = 'active' AND next_fire_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS workflows_plugin ON workflows (plugin_id) WHERE plugin_id IS NOT NULL;

-- Immutable revisions (draft -> approved -> published -> superseded).
CREATE TABLE IF NOT EXISTS workflow_revisions (
    id               text PRIMARY KEY,
    realm_id         text NOT NULL,
    workflow_id      text NOT NULL,
    number           integer NOT NULL,
    schema_version   integer NOT NULL,
    definition       jsonb NOT NULL,
    definition_hash  text NOT NULL,
    status           text NOT NULL CHECK (status IN ('draft', 'approved', 'published', 'superseded', 'rejected')),
    author_id        text NOT NULL,
    approved_by_id   text,
    approved_at      timestamptz,
    published_by_id  text,
    published_at     timestamptz,
    note             text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workflow_id, number),
    FOREIGN KEY (realm_id, workflow_id) REFERENCES workflows (realm_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    organization_id    text,
    workflow_id        text NOT NULL,
    -- The revision the run executes, pinned at start: publishing or rolling
    -- back later never changes a run in flight (EXT-016 input version).
    revision_number    integer NOT NULL,
    definition_hash    text NOT NULL,
    schema_version     integer NOT NULL,
    trigger_type       text NOT NULL CHECK (trigger_type IN ('event', 'schedule', 'manual')),
    -- Event ID, schedule slot + subject, or manual request key: unique per
    -- workflow, so redelivered events and repeated schedule claims start one
    -- run only.
    trigger_key        text NOT NULL,
    trigger_event_type text,
    subject_type       text NOT NULL DEFAULT 'user',
    subject_id         text NOT NULL,
    -- Identifiers-only snapshot of what started the run, and its contract
    -- version (the triggering event's event_version).
    input              jsonb NOT NULL DEFAULT '{}'::jsonb,
    input_version      integer NOT NULL DEFAULT 1,
    accountable_id     text NOT NULL,
    started_by_id      text,
    -- Chain depth: runs started by events another run caused.
    depth              integer NOT NULL DEFAULT 0,
    state              text NOT NULL CHECK (state IN ('pending', 'running', 'waiting', 'awaiting_approval', 'compensating',
                           'succeeded', 'failed', 'compensated', 'compensation_failed', 'cancelled')),
    step_index         integer NOT NULL DEFAULT 0,
    context            jsonb NOT NULL DEFAULT '{}'::jsonb,
    next_run_at        timestamptz NOT NULL,
    lease_owner        text,
    lease_expires_at   timestamptz,
    cancel_requested   boolean NOT NULL DEFAULT false,
    error_category     text,
    last_error         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    finished_at        timestamptz,
    UNIQUE (workflow_id, trigger_key),
    FOREIGN KEY (realm_id, workflow_id) REFERENCES workflows (realm_id, id),
    FOREIGN KEY (realm_id, organization_id) REFERENCES organizations (realm_id, id)
);
CREATE INDEX IF NOT EXISTS workflow_runs_due ON workflow_runs (next_run_at)
    WHERE state IN ('pending', 'running', 'waiting', 'awaiting_approval', 'compensating');
CREATE INDEX IF NOT EXISTS workflow_runs_workflow ON workflow_runs (realm_id, workflow_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS workflow_runs_subject ON workflow_runs (realm_id, subject_id);

-- One row per attempt of a step (EXT-016).
CREATE TABLE IF NOT EXISTS workflow_step_attempts (
    id                    text PRIMARY KEY,
    realm_id              text NOT NULL,
    run_id                text NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    step_index            integer NOT NULL,
    step_id               text NOT NULL,
    step_type             text NOT NULL,
    attempt               integer NOT NULL,
    -- Stable for every attempt of the step and sent to endpoints as
    -- Idempotency-Key, so a retry after a crash is deduplicated by the
    -- receiver; internal effects commit atomically with the attempt instead.
    idempotency_key       text NOT NULL,
    state                 text NOT NULL CHECK (state IN ('started', 'succeeded', 'failed')),
    input                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    input_version         text NOT NULL,
    result                jsonb,
    error_category        text,
    error                 text,
    max_attempts          integer NOT NULL,
    backoff_ms            bigint NOT NULL,
    compensation          text NOT NULL CHECK (compensation IN ('none', 'undo', 'notify_endpoint', 'impossible')),
    compensation_state    text CHECK (compensation_state IN ('pending', 'done', 'not_needed', 'impossible', 'failed')),
    compensation_attempts integer NOT NULL DEFAULT 0,
    compensation_result   jsonb,
    started_at            timestamptz NOT NULL,
    finished_at           timestamptz,
    compensated_at        timestamptz,
    UNIQUE (run_id, step_index, attempt)
);
CREATE INDEX IF NOT EXISTS workflow_step_attempts_run ON workflow_step_attempts (run_id, step_index, attempt);

-- Approval steps (EXT-015): named approvers decide through their own
-- account before the expiry.
CREATE TABLE IF NOT EXISTS workflow_approvals (
    id              text PRIMARY KEY,
    realm_id        text NOT NULL,
    run_id          text NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    step_index      integer NOT NULL,
    workflow_id     text NOT NULL,
    subject_id      text NOT NULL,
    approver_ids    text[] NOT NULL,
    state           text NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
    decided_by_id   text,
    decided_at      timestamptz,
    comment         text,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, step_index)
);
CREATE INDEX IF NOT EXISTS workflow_approvals_pending ON workflow_approvals (realm_id, expires_at) WHERE state = 'pending';
