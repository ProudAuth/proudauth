-- Durable pairwise subject identifiers (OIDC-010, APP-012). A pairwise value
-- is derived once (keyed by the realm secret) and then stored, so it survives
-- root-key rotation and is removed with the user.
CREATE TABLE pairwise_subjects (
    realm_id    text NOT NULL,
    sector      text NOT NULL,
    user_id     text NOT NULL,
    subject     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, sector, user_id),
    UNIQUE (realm_id, sector, subject),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
