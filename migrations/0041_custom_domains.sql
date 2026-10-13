-- Realm custom hostnames (DEP-014): hosts on which a realm's endpoints may be
-- served besides the public origin. A custom hostname never changes the
-- issuer or any subject; it is usable only after DNS proof of control.
CREATE TABLE realm_custom_domains (
    id                   text PRIMARY KEY,
    realm_id             text NOT NULL REFERENCES realms(id),
    host                 text NOT NULL,
    state                text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'verified', 'disabled')),
    challenge_digest     text,
    challenge_expires_at timestamptz,
    created_by_id        text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    verified_at          timestamptz,
    disabled_at          timestamptz
);
CREATE UNIQUE INDEX realm_custom_domains_host ON realm_custom_domains (host) WHERE state <> 'disabled';
CREATE INDEX realm_custom_domains_realm ON realm_custom_domains (realm_id);
