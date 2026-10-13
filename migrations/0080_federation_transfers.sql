-- Federation transfer (FED-016): moving account links from one provider
-- connection to another (a new connection, or the same provider under a new
-- upstream tenant) through a reviewed migration map. Each entry names the
-- source subject and the target subject; the plan is analysed for missing
-- sources and collisions, approved by a second administrator, and applied
-- once. Accounts are never relinked by email. Additive only.
CREATE TABLE IF NOT EXISTS federation_transfers (
    id                  text PRIMARY KEY,
    realm_id            text NOT NULL REFERENCES realms(id),
    source_provider_id  text NOT NULL,
    target_provider_id  text NOT NULL,
    mode                text NOT NULL CHECK (mode IN ('map', 'same_subject')),
    target_tenant       text,
    state               text NOT NULL CHECK (state IN ('draft', 'approved', 'applied', 'cancelled')),
    reason              text NOT NULL,
    summary             jsonb NOT NULL DEFAULT '{}',
    created_by_id       text NOT NULL,
    approved_by_id      text,
    applied_by_id       text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    approved_at         timestamptz,
    applied_at          timestamptz,
    version             bigint NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS federation_transfers_realm ON federation_transfers (realm_id, created_at DESC);

CREATE TABLE IF NOT EXISTS federation_transfer_entries (
    transfer_id      text NOT NULL REFERENCES federation_transfers(id) ON DELETE CASCADE,
    seq              integer NOT NULL,
    source_subject   text NOT NULL,
    source_issuer    text,
    target_subject   text NOT NULL,
    target_tenant    text,
    user_id          text,
    outcome          text NOT NULL,
    detail           text,
    PRIMARY KEY (transfer_id, seq)
);
CREATE INDEX IF NOT EXISTS federation_transfer_entries_outcome ON federation_transfer_entries (transfer_id, outcome);
