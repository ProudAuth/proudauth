-- Time-limited, scoped debug logging windows (SEC-015), read by every node.
ALTER TABLE system_state ADD COLUMN debug_until timestamptz;
ALTER TABLE system_state ADD COLUMN debug_component text;
