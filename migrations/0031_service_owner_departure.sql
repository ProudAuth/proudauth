-- Service principals whose accountable owner departed (MCH-007): the time the
-- departure was detected, so it is reported once and acted on per policy.
ALTER TABLE service_principals ADD COLUMN owner_departed_at timestamptz;
