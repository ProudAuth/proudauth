-- Directory integration: LDAP/Active Directory federation and synchronization
-- (PROV-011, PROV-012, PROV-014, FED-015), directory-authoritative accounts
-- and write-back modes (USR-022, PROV-013), outbound SCIM provisioning
-- (PROV-010), reconciliation (PROV-017) and operational evidence (PROV-018).
--
-- Connectors reuse provisioning_connectors (kinds 'ldap' and 'scim_outbound')
-- and their connector-scoped external IDs. Expand-only: older binaries
-- select connectors by organization and by kind 'scim_inbound', so they never
-- see the rows this release adds.

-- A workforce directory is a realm-wide identity source, not bound to one
-- customer organization (FED-015). Relaxing NOT NULL is a widening change;
-- older binaries only ever read connectors through an organization ID.
ALTER TABLE provisioning_connectors ALTER COLUMN organization_id DROP NOT NULL;
-- When the encrypted connector credential (bind password or downstream bearer
-- token) was last set; the credential itself is never readable through the API.
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS secret_set_at timestamptz;
-- Scheduling (PROV-012): the next incremental and full synchronization, or the
-- next outbound reconciliation; claimed with a conditional update so one
-- worker schedules each run.
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS next_sync_at timestamptz;
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS next_full_sync_at timestamptz;
-- Operational evidence (PROV-018): last successful run, consecutive failures,
-- endpoint health and the latest operator actions, without credentials.
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS last_success_at timestamptz;
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS consecutive_failures integer NOT NULL DEFAULT 0;
ALTER TABLE provisioning_connectors ADD COLUMN IF NOT EXISTS evidence jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS provisioning_connectors_realm_kind ON provisioning_connectors (realm_id, kind);

-- Directory links and outbound mappings are connector-scoped external IDs
-- (PROV-004, USR-017). link_kind is 'directory' for an LDAP source entry and
-- 'outbound' for a downstream resource; SCIM inbound rows leave it NULL.
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS link_kind text;
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS source_dn text;
-- The values last imported from (or pushed to) the external system, per
-- attribute: the basis for change detection and oscillation prevention
-- (PROV-017).
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS snapshot jsonb;
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS snapshot_digest text;
-- active | disabled | missing (not seen by the last full synchronization).
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS source_state text;
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS last_seen_run text;
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE connector_external_ids ADD COLUMN IF NOT EXISTS missing_since timestamptz;
CREATE INDEX IF NOT EXISTS connector_external_ids_local ON connector_external_ids (local_id);
-- An account has at most one directory source: two directories never both own
-- its password or attributes (PROV-017).
CREATE UNIQUE INDEX IF NOT EXISTS connector_external_ids_one_directory ON connector_external_ids (local_id)
    WHERE link_kind = 'directory' AND resource_type = 'User';

-- Synchronization and reconciliation runs (PROV-012, PROV-017).
CREATE TABLE IF NOT EXISTS directory_sync_runs (
    id                     text PRIMARY KEY,
    realm_id               text NOT NULL,
    organization_id        text,
    connector_id           text NOT NULL REFERENCES provisioning_connectors(id) ON DELETE CASCADE,
    job_id                 text,
    mode                   text NOT NULL CHECK (mode IN ('full', 'incremental', 'reconcile')),
    dry_run                boolean NOT NULL DEFAULT false,
    trigger                text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'schedule', 'login')),
    state                  text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'refused', 'cancelled')),
    allow_mass_deprovision boolean NOT NULL DEFAULT false,
    requested_by_type      text NOT NULL,
    requested_by_id        text NOT NULL,
    reason                 text,
    cursor_before          text,
    cursor_after           text,
    endpoint               text,
    counts                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    error                  text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    started_at             timestamptz,
    finished_at            timestamptz
);
CREATE INDEX IF NOT EXISTS directory_sync_runs_connector ON directory_sync_runs (connector_id, created_at DESC);

-- Plan items, applied changes, conflicts and divergences of a run, bounded
-- per run; counts beyond the bound are still totalled in the run.
CREATE TABLE IF NOT EXISTS directory_sync_findings (
    run_id                 text NOT NULL REFERENCES directory_sync_runs(id) ON DELETE CASCADE,
    seq                    integer NOT NULL,
    kind                   text NOT NULL,
    reason                 text,
    external_id            text,
    source_dn              text,
    local_id               text,
    attributes             text[] NOT NULL DEFAULT '{}',
    applied                boolean NOT NULL DEFAULT false,
    detail                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (run_id, seq)
);

-- Outbound provisioning deliveries (PROV-010). A delivery means "make the
-- downstream resource match the current local state", so events for the same
-- account coalesce into one open delivery; generation detects a change that
-- arrived while an attempt was in flight.
CREATE TABLE IF NOT EXISTS outbound_deliveries (
    id                     text PRIMARY KEY,
    realm_id               text NOT NULL,
    organization_id        text,
    connector_id           text NOT NULL REFERENCES provisioning_connectors(id) ON DELETE CASCADE,
    resource_type          text NOT NULL CHECK (resource_type IN ('User', 'Group')),
    local_id               text NOT NULL,
    trigger                text NOT NULL,
    event_id               text,
    state                  text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'retrying', 'delivered', 'dead_letter', 'replayed')),
    generation             bigint NOT NULL DEFAULT 1,
    attempts               integer NOT NULL DEFAULT 0,
    next_attempt_at        timestamptz NOT NULL,
    lease_owner            text,
    lease_expires_at       timestamptz,
    operation              text,
    last_status_code       integer,
    last_error_category    text,
    delivered_at           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS outbound_deliveries_open ON outbound_deliveries (connector_id, resource_type, local_id)
    WHERE state IN ('pending', 'retrying');
CREATE INDEX IF NOT EXISTS outbound_deliveries_due ON outbound_deliveries (next_attempt_at) WHERE state IN ('pending', 'retrying');
CREATE INDEX IF NOT EXISTS outbound_deliveries_connector ON outbound_deliveries (connector_id, state, created_at DESC);
