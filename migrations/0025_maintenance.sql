-- Operator maintenance state (OPS-015): one row, read by every node.
CREATE TABLE system_state (
    id                  boolean PRIMARY KEY DEFAULT true CHECK (id),
    maintenance_mode    text NOT NULL DEFAULT 'off' CHECK (maintenance_mode IN ('off', 'restricted', 'unavailable')),
    maintenance_message text,
    retry_after_seconds integer NOT NULL DEFAULT 300 CHECK (retry_after_seconds BETWEEN 0 AND 86400),
    updated_at          timestamptz,
    updated_by          text
);

INSERT INTO system_state (id) VALUES (true);
