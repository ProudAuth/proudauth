-- Invitation identifier binding and administrator-reviewed reassignment (INV-014, USR-021).
-- bound_user_id records the account that held the invited address when the
-- invitation was created. It is never shown to inviters (DOM-008) and makes
-- acceptance fail when the address has since changed hands.
ALTER TABLE invitations ADD COLUMN bound_user_id text;
ALTER TABLE invitations ADD COLUMN superseded_by text;
ALTER TABLE invitations ADD COLUMN batch_id text;
CREATE INDEX invitations_batch ON invitations (organization_id, batch_id) WHERE batch_id IS NOT NULL;
