-- One expiry alert per credential (MCH-009, TOK-021, APP-014). The alert is
-- claimed by inserting this row in the same transaction that enqueues the
-- notifications, so concurrent workers or a retried run never notify twice.
CREATE TABLE credential_expiry_alerts (
    credential_id text PRIMARY KEY,
    realm_id      text NOT NULL,
    sent_at       timestamptz NOT NULL
);

INSERT INTO credential_expiry_alerts (credential_id, realm_id, sent_at)
SELECT reference_id, min(realm_id), min(created_at) FROM notification_jobs
WHERE reference_type = 'credential_expiry' AND reference_id IS NOT NULL
GROUP BY reference_id
ON CONFLICT DO NOTHING;
