-- Facts behind the known-device quota (owner decision 9 of 0.2.0-alpha.6;
-- SEC-006, ABU-001): the networks (IPv4 /32, IPv6 /64), remembered devices
-- and identifiers that completed a sign-in in a realm, each only as a keyed
-- digest, with the time of the latest such sign-in. When an aggregate
-- sign-in budget (per client, organization or realm) is exhausted, a sign-in
-- that matches a fact seen within security.rate_limits.known_quota_days
-- proceeds under its own budget; everyone else gets 429. The worker deletes
-- facts older than that (PRV-004). Expand only: a new table that older
-- binaries ignore.
CREATE TABLE known_sign_ins (
    realm_id      text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('network', 'device', 'identifier')),
    digest        text NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    PRIMARY KEY (realm_id, kind, digest)
);
-- The retention sweep deletes by age.
CREATE INDEX known_sign_ins_last_seen ON known_sign_ins (last_seen_at);
