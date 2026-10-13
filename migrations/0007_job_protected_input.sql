-- Sensitive job input (imported password verifiers, contact data) is stored
-- encrypted, never returned by the jobs API, and erased when the job reaches a
-- terminal state (PRV-008, MIG-006). Expand-only (DEP-012).
ALTER TABLE jobs ADD COLUMN input_ciphertext bytea;
ALTER TABLE jobs ADD COLUMN input_key_version integer;
