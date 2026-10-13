# 0011. Refresh model: opaque, rotated, client-bound families

**Status:** Accepted

## Context

A stolen refresh token is long-lived authority. Rotation with reuse detection
limits its value, but only if at most one successor can exist and compromise is
recorded atomically (SES-006..SES-009, DB-006, §24.3).

## Decision

- Refresh tokens are opaque (`pa_rt_` + 256 random bits), stored as SHA-256 digests
  in `refresh_tokens`, grouped into a `refresh_families` row per authorization grant
  and client.
- Rotation (`session.Service.RotateRefresh`) runs in one transaction that locks the
  session first for session-bound grants, then the family row (`FOR UPDATE`),
  checks the presented generation, re-validates the
  grant, session (for session-bound grants), user, client, organization and
  membership, consumes the generation with a conditional update, and inserts
  exactly one successor (`refresh_tokens_one_child` unique index on `parent_id`).
- **Reuse**: presenting a consumed or non-current generation marks the family
  `compromised`, revokes all its tokens and the grant, revokes the session for
  session-bound grants (the user must sign in again), records
  `token.refresh.reuse_detected` in audit and publishes
  `security.refresh_reuse_detected` to the outbox. The request fails with
  `invalid_grant`.
- **Client binding**: a token presented by another client is rejected as invalid
  and is not treated as a reuse signal.
- **Scope**: a refresh request may only narrow scope; scopes the client is no
  longer allowed are dropped.
- **Lifetimes**: a family's absolute expiry never exceeds the parent session's
  absolute expiry; offline grants (`offline_access`, allowed per client) use
  `sessions.offline_idle` / `sessions.offline_absolute` and survive single-session
  logout; remember-me sessions use `sessions.remember_me_*`.
- Client-credentials grants never receive refresh tokens. There is no retry grace
  period: a client that loses a rotation response must re-authenticate.
- The first-party OIDC client (`proudauth-sdk-go/oidcclient`) serializes refreshes per
  session so concurrent requests do not trigger reuse detection.

## Alternatives considered

- **Non-rotating refresh tokens**: no theft detection.
- **Grace window for concurrent refresh**: requires sender binding and replay
  semantics (SES-009); not implemented.

## Consequences

- Clients that refresh concurrently without serialization will log users out.
- Concurrency-32 refresh/revocation bursts across three independent pools exposed
  a lock-order inversion: refresh held the family while logout held the session.
  Session-bound refresh now locks the session first, matching logout; account-wide
  revocation visits session IDs in order. Offline grants do not require a live
  SSO session or take this session lock. [Regression evidence](../operations/consistency-tests.md)
  distinguishes in-process consistency checks from capacity measurements.
- **Former defect, fixed (Update 2026-10):** rotation used to extend every
  family's idle window (and, for session-bound grants, the session idle window) by
  `sessions.idle_timeout`, so offline and remember-me families expired after
  30 minutes of inactivity after their first refresh. Migration
  `0009_refresh_idle_window.sql` adds `refresh_families.idle_window_seconds`,
  recorded at issuance (`session.Service.IssueRefreshTx`), and
  `session.Service.RotateRefresh` now extends the family (and the session it
  touches) by that stored window, so ordinary, remember-me and offline families
  keep their own idle lifetime (SES-021). Families issued before migration 0009
  have no stored window and keep the old behavior until they expire. No automated
  test exercises an offline or remember-me family across a rotation yet.
- **Former defect, fixed (Update 2026-10):** the session touched by a refresh
  was set to the family's window from now even when that was earlier than its
  current idle expiry, so a client with a short `token_policy.refresh_idle_seconds`
  shortened the shared SSO session for every application. A refresh now only
  moves the session's idle expiry later (`session.Service.TouchFromRefreshTx`)
  and never changes its absolute expiry (`TestRefreshNeverShortensSession`).
- DPoP-bound refresh requests mint DPoP-bound access tokens, but the refresh token
  itself is not bound to the DPoP key.

## Migration implications

Refresh tokens are not portable across issuers or deployments (MIG-010); a
migration to or from ProudAuth requires users to sign in again.

## Related requirement IDs

SES-006, SES-007, SES-008, SES-009, SES-012, SES-021, DB-006, MCH-003, TOK-008, TEST-030, TEST-031, TEST-032, §24.3
