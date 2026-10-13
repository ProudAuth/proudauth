-- Database-enforced realm and organization boundaries (DB-001) for references
-- that previously relied on application checks only.
--
-- Foreign keys are added NOT VALID: they are enforced for every new or changed
-- row immediately, without scanning or rejecting historical rows, so this
-- migration stays expand-only. `identity-cli doctor` reports rows that would
-- fail validation; a later contract migration validates them.

ALTER TABLE webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_org_fk FOREIGN KEY (realm_id, organization_id)
    REFERENCES organizations (realm_id, id) NOT VALID;

ALTER TABLE webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_realm_fk FOREIGN KEY (realm_id) REFERENCES realms (id) NOT VALID;

ALTER TABLE jobs
    ADD CONSTRAINT jobs_org_fk FOREIGN KEY (realm_id, organization_id)
    REFERENCES organizations (realm_id, id) NOT VALID;

-- Role assignments and assignment requests reference their subject and scope
-- polymorphically, which a foreign key cannot express. The trigger enforces the
-- same rule: subject and scope must exist in the assignment's realm, and a
-- group subject must belong to the organization it is granted in.
CREATE OR REPLACE FUNCTION proudauth_check_assignment_boundary() RETURNS trigger AS $$
BEGIN
    IF NEW.subject_type = 'user' THEN
        PERFORM 1 FROM users WHERE realm_id = NEW.realm_id AND id = NEW.subject_id;
    ELSIF NEW.subject_type = 'service_principal' THEN
        PERFORM 1 FROM service_principals WHERE realm_id = NEW.realm_id AND id = NEW.subject_id;
    ELSIF NEW.subject_type = 'group' THEN
        PERFORM 1 FROM groups WHERE realm_id = NEW.realm_id AND id = NEW.subject_id
            AND NEW.scope_type = 'organization' AND organization_id = NEW.scope_id;
    ELSE
        RAISE EXCEPTION 'unknown subject type %', NEW.subject_type USING ERRCODE = 'check_violation';
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'assignment subject % is not in realm %', NEW.subject_id, NEW.realm_id USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF NEW.scope_type = 'realm' THEN
        IF NEW.scope_id <> NEW.realm_id THEN
            RAISE EXCEPTION 'realm scope must name the assignment realm' USING ERRCODE = 'foreign_key_violation';
        END IF;
    ELSIF NEW.scope_type = 'organization' THEN
        PERFORM 1 FROM organizations WHERE realm_id = NEW.realm_id AND id = NEW.scope_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'organization % is not in realm %', NEW.scope_id, NEW.realm_id USING ERRCODE = 'foreign_key_violation';
        END IF;
    ELSIF NEW.scope_type = 'project' THEN
        PERFORM 1 FROM projects WHERE realm_id = NEW.realm_id AND id = NEW.scope_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'project % is not in realm %', NEW.scope_id, NEW.realm_id USING ERRCODE = 'foreign_key_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER role_assignments_boundary BEFORE INSERT OR UPDATE OF subject_type, subject_id, scope_type, scope_id, realm_id
    ON role_assignments FOR EACH ROW EXECUTE FUNCTION proudauth_check_assignment_boundary();
CREATE TRIGGER role_assignment_requests_boundary BEFORE INSERT OR UPDATE OF subject_type, subject_id, scope_type, scope_id, realm_id
    ON role_assignment_requests FOR EACH ROW EXECUTE FUNCTION proudauth_check_assignment_boundary();
