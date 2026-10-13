-- Historical audit evidence imported from a source system (MIG-016). It is
-- kept apart from audit_events: never sealed into the local hash chain, always
-- labelled as imported and unverified, with the source's own identifiers.
CREATE TABLE imported_audit_events (
    id                text PRIMARY KEY,
    realm_id          text NOT NULL REFERENCES realms(id),
    source_system     text NOT NULL,
    source_event_id   text NOT NULL,
    occurred_at       timestamptz NOT NULL,
    event_type        text NOT NULL,
    organization_id   text,
    actor             jsonb,
    subject_id        text,
    source_subject_id text,
    outcome           text NOT NULL,
    metadata          jsonb NOT NULL DEFAULT '{}',
    content_hash      text NOT NULL,
    batch_id          text NOT NULL,
    imported_at       timestamptz NOT NULL,
    imported_by_type  text NOT NULL,
    imported_by_id    text NOT NULL,
    redacted_at       timestamptz,
    UNIQUE (realm_id, source_system, source_event_id)
);
CREATE INDEX imported_audit_events_time ON imported_audit_events (realm_id, occurred_at DESC, id);
CREATE INDEX imported_audit_events_subject ON imported_audit_events (realm_id, subject_id) WHERE subject_id IS NOT NULL;
CREATE INDEX imported_audit_events_imported ON imported_audit_events (imported_at);
