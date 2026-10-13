-- Dynamic group recomputation status (TEN-014).
ALTER TABLE groups ADD COLUMN rule_recomputed_at timestamptz;
ALTER TABLE groups ADD COLUMN rule_member_count integer;
ALTER TABLE groups ADD COLUMN rule_error text;
