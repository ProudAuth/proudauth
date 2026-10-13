-- Each refresh family keeps the idle window it was issued with (ordinary,
-- remember-me or offline), so rotation preserves it (SES-021). Expand-only.
ALTER TABLE refresh_families ADD COLUMN idle_window_seconds integer;
