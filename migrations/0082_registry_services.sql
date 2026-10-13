-- Container-registry token bridge (ADV-010): a registry service records the
-- registry's service name (the token audience) and the API resource its
-- credentials are minted for; ordered rules map repository name patterns to
-- the permission each action (pull, push, delete) requires. Tokens follow the Distribution token authentication
-- protocol with a dedicated audience and a short lifetime. Additive only.
CREATE TABLE IF NOT EXISTS registry_services (
    id                 text PRIMARY KEY,
    realm_id           text NOT NULL REFERENCES realms(id),
    resource_id        text NOT NULL,
    service            text NOT NULL,
    token_ttl_seconds  integer NOT NULL DEFAULT 300 CHECK (token_ttl_seconds BETWEEN 60 AND 3600),
    rules              jsonb NOT NULL DEFAULT '[]',
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    version            bigint NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (realm_id, service),
    FOREIGN KEY (realm_id, resource_id) REFERENCES api_resources (realm_id, id)
);
