-- Re-approval of changed dynamic registrations (APP-016, APP-017, ADV-003;
-- alpha.6 decision 14). reviewed_version is the client version an
-- administrator approved (POST /client-registrations/{client}/approve with
-- reviewed_version); requeued_at is when a registrant's change of its
-- reviewed metadata last returned an approved registration to pending.
-- Both stay NULL for registrations decided before this migration and for
-- those never re-queued. Nullable without defaults: older binaries neither
-- read nor write them. Additive only.
ALTER TABLE client_registrations ADD COLUMN IF NOT EXISTS reviewed_version bigint;
ALTER TABLE client_registrations ADD COLUMN IF NOT EXISTS requeued_at timestamptz;
