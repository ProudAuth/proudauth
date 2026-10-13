-- Workload federation (MCH-011..MCH-013, ADV-004): trust in an external
-- workload identity issuer, bound to one client whose service principal the
-- workload becomes. Each trust names the issuer, its keys, the exact audience,
-- a subject pattern and claim constraints; nothing else from that issuer is
-- accepted. Additive only.
CREATE TABLE IF NOT EXISTS workload_trusts (
    id                       text PRIMARY KEY,
    realm_id                 text NOT NULL,
    client_ref               text NOT NULL,
    name                     text NOT NULL,
    profile                  text NOT NULL CHECK (profile IN ('generic', 'github_actions', 'kubernetes', 'spiffe')),
    issuer                   text NOT NULL,
    jwks_uri                 text,
    jwks                     jsonb,
    audience                 text NOT NULL,
    subject                  text NOT NULL,
    claim_constraints        jsonb NOT NULL DEFAULT '{}'::jsonb,
    algorithms               text[] NOT NULL,
    max_assertion_lifetime   integer NOT NULL DEFAULT 3600,
    require_jti              boolean NOT NULL DEFAULT false,
    state                    text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    version                  bigint NOT NULL DEFAULT 1,
    created_by_id            text NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    last_used_at             timestamptz,
    FOREIGN KEY (realm_id, client_ref) REFERENCES clients (realm_id, id)
);
CREATE INDEX IF NOT EXISTS workload_trusts_client ON workload_trusts (client_ref) WHERE state = 'active';

-- Replay control for workload assertions that carry a jti, per trust.
CREATE TABLE IF NOT EXISTS workload_assertion_jtis (
    trust_id    text NOT NULL,
    jti         text NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (trust_id, jti)
);
CREATE INDEX IF NOT EXISTS workload_assertion_jtis_expiry ON workload_assertion_jtis (expires_at);
