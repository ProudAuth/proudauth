-- Retention-aware evidence chain (AUD-008, AUD-009). Retention removes events of
-- whole sealed batches and records an append-only prune entry; verification then
-- checks the batch hash chain from the stored digest and the content hash of
-- every retained event, instead of reporting pruned batches as tampered.
CREATE TABLE audit_prunes (
    batch_id         text PRIMARY KEY REFERENCES audit_batches(id),
    pruned_at        timestamptz NOT NULL DEFAULT now(),
    removed_events   integer NOT NULL,
    retained_events  integer NOT NULL
);
CREATE FUNCTION audit_prunes_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_prunes is append-only';
END $$;
CREATE TRIGGER audit_prunes_append_only BEFORE UPDATE OR DELETE ON audit_prunes
    FOR EACH ROW EXECUTE FUNCTION audit_prunes_guard();
