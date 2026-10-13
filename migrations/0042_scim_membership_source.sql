-- Memberships created by an inbound SCIM connector record 'scim' as their
-- provenance (PROV-002, TEN-015). Widening the CHECK constraint keeps older
-- binaries working.
ALTER TABLE memberships DROP CONSTRAINT memberships_source_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_source_check CHECK (source IN ('invitation', 'admin', 'directory', 'domain_policy',
    'self_join', 'bootstrap', 'jit', 'creator', 'import', 'scim')) NOT VALID;
ALTER TABLE memberships VALIDATE CONSTRAINT memberships_source_check;
