-- The account a notification is about (PRV-005): deleting the account purges
-- its queued and delivered message payloads at once, and the deletion status
-- report can say when no payload about it remains. Additive only.
ALTER TABLE notification_jobs ADD COLUMN IF NOT EXISTS user_id text;
CREATE INDEX IF NOT EXISTS notification_jobs_user ON notification_jobs (user_id) WHERE user_id IS NOT NULL AND payload_ciphertext IS NOT NULL;
