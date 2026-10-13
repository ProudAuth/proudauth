-- Periodic re-verification of organization domains (TEN-009): the accepted
-- DNS proof is kept (as a digest) so it can be re-checked, and consecutive
-- failures are counted before a verification lapses.
ALTER TABLE organization_domains ADD COLUMN proof_digest text;
ALTER TABLE organization_domains ADD COLUMN recheck_failures integer NOT NULL DEFAULT 0;
CREATE INDEX organization_domains_recheck ON organization_domains (recheck_at) WHERE state = 'verified';
