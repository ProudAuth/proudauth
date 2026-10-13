-- Per-user preferences for optional notices (MSG-010). Mandatory security and
-- account notices ignore preferences; only optional templates can be muted.
CREATE TABLE notification_preferences (
    realm_id    text NOT NULL,
    user_id     text NOT NULL,
    template    text NOT NULL,
    enabled     boolean NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, user_id, template),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX notification_jobs_provider ON notification_jobs (realm_id, provider_message_id) WHERE provider_message_id IS NOT NULL;
