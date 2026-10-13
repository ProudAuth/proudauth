-- Certificate trust anchors (PROV-016, MCH-014): a removed anchor stays as a
-- record, and the same authority can be trusted again for the purpose (a new
-- anchor with a new ID; bindings of the removed one stay with it). Only
-- active anchors are unique per realm, purpose and fingerprint. Widening
-- only: the partial index is created before the table constraint goes, so
-- duplicates of an active anchor are refused throughout.
CREATE UNIQUE INDEX IF NOT EXISTS certificate_trust_anchors_active ON certificate_trust_anchors (realm_id, purpose, fingerprint) WHERE state = 'active';
ALTER TABLE certificate_trust_anchors DROP CONSTRAINT IF EXISTS certificate_trust_anchors_realm_id_purpose_fingerprint_key;

-- Shares with an end (AZ-027): the expiry sweep finds pending and accepted
-- shares past expires_at. Additive only.
CREATE INDEX IF NOT EXISTS resource_shares_due ON resource_shares (expires_at) WHERE state IN ('pending', 'accepted') AND expires_at IS NOT NULL;
