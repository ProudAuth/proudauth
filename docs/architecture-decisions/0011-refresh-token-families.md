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
- **Former limit, fixed (Update 2026-10-18, below):** DPoP-bound refresh
  requests minted DPoP-bound access tokens, but the refresh token itself was
  not bound to the DPoP key (nor to a client certificate).

## Migration implications

Refresh tokens are not portable across issuers or deployments (MIG-010); a
migration to or from ProudAuth requires users to sign in again.

## Related requirement IDs

SES-006, SES-007, SES-008, SES-009, SES-012, SES-021, DB-006, MCH-003, TOK-008, TOK-019, TEST-030, TEST-031, TEST-032, TEST-067, §24.3

## Updates

**Update — 2026-10-18.** Refresh families are sender-bound (TOK-019; RFC 9449
§5, RFC 8705 §3; owner decision 13,
`docs/releases/2026-10-alpha.6-decisions.md`). Until now only access tokens
were sender-constrained: a stolen refresh token of a DPoP-bound family could
be redeemed with the thief's own DPoP key, or, when the client lacked
`require_dpop`, with no proof at all for a bearer token. Migration
`0089_refresh_family_binding.sql` adds `refresh_families.cnf_jkt` and
`cnf_x5t_s256`. `session.Service.IssueRefreshTx` stores the sender
constraint of the family's first issuance (the DPoP proof key's thumbprint,
or the client certificate's), whatever `require_dpop` says, and nothing
changes it afterwards: rotation keeps the family row and its binding.
`session.Service.UseRefresh` (and `RotateRefresh`) take the request's proof,
its DPoP key and its TLS client certificate, and refuse a bound family whose
key or certificate it does not present (`session.ErrRefreshSender`,
`invalid_grant`), also after the client's own binding policy changed. The
check runs after the client binding and **before reuse detection**, and is
not a reuse signal: it neither consumes the generation nor compromises the
family, and records only a `token.refresh.binding_failed` audit event. This
is deliberate: a presenter that cannot prove possession cannot use the token,
of the current generation or an earlier one, so letting its attempt trigger
reuse detection would only let anyone who saw an old refresh token revoke
the holder's family, grant and session; reuse detection still applies to
every presentation that proves possession. Families issued before `0089`, or
without a sender constraint, have no binding and keep the old behaviour until
they expire; rotation never binds them later. The same change binds
authorization codes to a DPoP key named by `dpop_jkt` (RFC 9449 §10,
`authorization_codes.dpop_jkt`). DPoP nonces remain unsupported (issue #37).
Tests: `TestSenderBoundRefreshFamilies`, `TestDPoPBoundAuthorizationCodes`,
`TestSenderBindingRefusal`. The Decision section above is unchanged; this
update adds the sender binding to it.
