-- Audit archive progress (AUD-008): the last sealed batch written to the
-- operator's append-only archive destination.
CREATE TABLE audit_archive_state (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    last_sequence bigint NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now()
);
INSERT INTO audit_archive_state (id) VALUES (true);
