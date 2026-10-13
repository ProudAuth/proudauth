-- Custom domain claims (DEP-014): only a verified claim reserves a host
-- across realms. Pending claims are unique per realm only, so one realm can
-- no longer block a host for every other realm by registering it first, nor
-- learn that another realm registered it. Relaxing the index keeps older
-- binaries working.
DROP INDEX realm_custom_domains_host;
CREATE UNIQUE INDEX realm_custom_domains_verified_host ON realm_custom_domains (host) WHERE state = 'verified';
CREATE UNIQUE INDEX realm_custom_domains_realm_host ON realm_custom_domains (realm_id, host) WHERE state <> 'disabled';
