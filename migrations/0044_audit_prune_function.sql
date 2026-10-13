-- Audit pruning through one owner-run function (AUD-007). With separated
-- database roles (storage.runtime_role) the runtime role has no DELETE on
-- audit_events: it can only call proudauth_audit_prune, which never removes
-- unsealed, emergency, legally held or not-yet-archived events, and which
-- records every removal in audit_prunes / audit_prune_log itself. The guard
-- accepts a delete only from the table owner with the retention flag set, so
-- a runtime session setting proudauth.audit_retention cannot delete rows.
-- Older binaries keep working: they delete as the owner (single-role
-- deployments) exactly as before.
CREATE OR REPLACE FUNCTION audit_events_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('proudauth.audit_retention', true) = 'on'
           AND current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID) THEN
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

CREATE FUNCTION proudauth_audit_prune(p_batch text, p_ids text[]) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n        integer;
    retained integer;
    archived bigint;
BEGIN
    SELECT last_sequence INTO archived FROM audit_archive_state WHERE directory <> '';
    IF archived IS NOT NULL AND NOT EXISTS (SELECT 1 FROM audit_batches b WHERE b.id = p_batch AND b.sequence_number <= archived) THEN
        RAISE EXCEPTION 'audit batch % is not archived yet', p_batch;
    END IF;
    PERFORM set_config('proudauth.audit_retention', 'on', true);
    DELETE FROM audit_events e
     WHERE e.batch_id = p_batch AND e.id = ANY (p_ids) AND e.category IS DISTINCT FROM 'emergency'
       AND NOT EXISTS (SELECT 1 FROM audit_legal_holds h WHERE h.released_at IS NULL AND h.realm_id = e.realm_id
           AND (h.organization_id IS NULL OR h.organization_id = e.organization_id)
           AND (h.subject_id IS NULL OR h.subject_id = e.subject_id OR h.subject_id = e.actor_id));
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('proudauth.audit_retention', 'off', true);
    IF n > 0 THEN
        SELECT count(*) INTO retained FROM audit_events WHERE batch_id = p_batch;
        IF NOT EXISTS (SELECT 1 FROM audit_prunes WHERE batch_id = p_batch) THEN
            INSERT INTO audit_prunes (batch_id, removed_events, retained_events) VALUES (p_batch, n, retained);
        ELSE
            INSERT INTO audit_prune_log (batch_id, removed_events) VALUES (p_batch, n);
        END IF;
    END IF;
    RETURN n;
END $$;
REVOKE ALL ON FUNCTION proudauth_audit_prune(text, text[]) FROM PUBLIC;
