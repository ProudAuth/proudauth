-- Access review campaigns (AZ-025): a snapshot of role assignments in a
-- scope, decided item by item by named reviewers (never about themselves),
-- applied when the campaign closes, and kept as evidence. Additive only.
CREATE TABLE IF NOT EXISTS access_reviews (
    id               text PRIMARY KEY,
    realm_id         text NOT NULL REFERENCES realms(id),
    organization_id  text,
    name             text NOT NULL,
    description      text,
    state            text NOT NULL CHECK (state IN ('open', 'closed', 'cancelled')),
    reviewer_ids     text[] NOT NULL,
    role_ids         text[] NOT NULL DEFAULT '{}',
    privileged_only  boolean NOT NULL DEFAULT false,
    on_no_decision   text NOT NULL CHECK (on_no_decision IN ('keep', 'revoke')),
    due_at           timestamptz NOT NULL,
    items_total      integer NOT NULL DEFAULT 0,
    summary          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by_id    text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    closed_by_id     text,
    closed_at        timestamptz
);
CREATE INDEX IF NOT EXISTS access_reviews_open ON access_reviews (realm_id, due_at) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS access_review_items (
    id             text PRIMARY KEY,
    review_id      text NOT NULL REFERENCES access_reviews(id),
    assignment_id  text NOT NULL,
    role_id        text NOT NULL,
    role_name      text NOT NULL,
    subject_type   text NOT NULL,
    subject_id     text NOT NULL,
    scope_type     text NOT NULL,
    scope_id       text NOT NULL,
    source         text,
    granted_by_id  text,
    granted_at     timestamptz,
    privileged     boolean NOT NULL DEFAULT false,
    decision       text CHECK (decision IN ('keep', 'revoke')),
    decided_by_id  text,
    decided_at     timestamptz,
    comment        text,
    outcome        text CHECK (outcome IN ('kept', 'revoked', 'already_removed', 'revoke_failed')),
    applied_at     timestamptz
);
CREATE INDEX IF NOT EXISTS access_review_items_review ON access_review_items (review_id, id);
