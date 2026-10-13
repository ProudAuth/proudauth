-- Indexes for the retention and budget queries (DB-011): expiry sweeps,
-- dispatched-outbox pruning, ended-session cleanup, notification payload
-- purge and the daily SMS budget no longer scan whole tables. Additive only.
CREATE INDEX IF NOT EXISTS authorization_codes_expiry ON authorization_codes (expires_at);
CREATE INDEX IF NOT EXISTS opaque_access_tokens_expiry ON opaque_access_tokens (expires_at);
CREATE INDEX IF NOT EXISTS opaque_access_tokens_subject ON opaque_access_tokens (subject_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS dpop_proof_jtis_expiry ON dpop_proof_jtis (expires_at);
CREATE INDEX IF NOT EXISTS pushed_authorization_requests_expiry ON pushed_authorization_requests (expires_at);
CREATE INDEX IF NOT EXISTS device_codes_expiry ON device_codes (expires_at);
CREATE INDEX IF NOT EXISTS idempotency_records_expiry ON idempotency_records (expires_at);
CREATE INDEX IF NOT EXISTS outbox_events_dispatched ON outbox_events (dispatched_at) WHERE state = 'dispatched';
CREATE INDEX IF NOT EXISTS sessions_ended ON sessions ((coalesce(revoked_at, absolute_expires_at))) WHERE state <> 'active';
CREATE INDEX IF NOT EXISTS notification_jobs_sms_recent ON notification_jobs (created_at) WHERE channel = 'sms';
CREATE INDEX IF NOT EXISTS notification_jobs_payload ON notification_jobs (updated_at) WHERE payload_ciphertext IS NOT NULL;
