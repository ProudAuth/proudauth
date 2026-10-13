-- Audit retention by category and legal holds (AUD-009).
CREATE TABLE audit_legal_holds (
    id              text PRIMARY KEY,
    realm_id        text NOT NULL REFERENCES realms(id),
    organization_id text,
    subject_id      text,
    reason          text NOT NULL,
    created_by_id   text NOT NULL,
    created_at      timestamptz NOT NULL,
    released_by_id  text,
    released_at     timestamptz
);
CREATE INDEX audit_legal_holds_active ON audit_legal_holds (realm_id) WHERE released_at IS NULL;

-- Every retention pass that removes events from an already pruned batch is
-- recorded here; the first pass stays in audit_prunes.
CREATE TABLE audit_prune_log (
    batch_id        text NOT NULL REFERENCES audit_batches(id),
    pruned_at       timestamptz NOT NULL DEFAULT now(),
    removed_events  integer NOT NULL
);
CREATE TRIGGER audit_prune_log_append_only BEFORE UPDATE OR DELETE ON audit_prune_log
    FOR EACH ROW EXECUTE FUNCTION audit_prunes_guard();
