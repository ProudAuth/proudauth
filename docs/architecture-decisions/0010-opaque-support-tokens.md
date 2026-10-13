# 0010. High-risk and support tokens: opaque, validated online

**Status:** Accepted

## Context

Support impersonation, API keys, personal access tokens and some high-risk APIs
need revocation that takes effect on the next request. A self-contained JWT cannot
provide that (IMP-010, SES-023, §13.2 strict-online mode).

## Decision

- Support (impersonation) access tokens are always opaque: `pa_it_` + 256 random
  bits, stored as a SHA-256 digest in `opaque_access_tokens` with
  `token_kind = impersonation_access` and the grant ID. They expire with the grant
  (at most `impersonation.max_ttl`, 5 min) and are never refreshable or
  exchangeable.
- Ordinary opaque access tokens (`pa_at_`) are issued when a resource registers
  `token_format: opaque`. API keys (`pa_key_`) and personal access tokens
  (`pa_pat_`) are also opaque.
- Validation is introspection (`POST /realms/{realm}/oauth/introspect`) by a client
  registered as a resource server for the token's audience. For support tokens
  every introspection re-checks: grant active and unexpired; actor and target users
  active; target membership and organization active; actor session active; actor
  still holds `support.impersonation.start` in that organization.
- There is no positive cache on the server side. The SDK `Introspector` has none
  either and maps any transport or server failure to `ErrUnavailable` (deny).
- The IdP's account and admin APIs reject `pa_it_` tokens outright.

## Alternatives considered

- **Short-lived JWT plus revocation list**: still needs an online check to be
  immediate, while risking that a resource skips it.
- **Bounded-online caches**: acceptable for some resources but not for support
  access (§14.5: zero positive cache for impersonation).

## Consequences

- Resources that accept these tokens depend on the IdP being reachable; outages
  deny access (TEST-035).
- Each support request costs one introspection round trip and several indexed
  queries.
- `bounded_online` is accepted as a resource `verification_mode` value. The IdP
  does not enforce it, but since the 2026-10 update the SDKs provide a
  bounded-state mode fed by the session-event stream that fails closed beyond a
  staleness bound (`proudauth-sdk-go/verifier/boundedstate.go`,
  `TestBoundedStateVerification`). Support tokens still require strict-online
  validation.

## Migration implications

Token prefixes are part of the contract: resource servers and the server route on
them (`pa_it_` to the support guard, `pa_key_`/`pa_pat_` to automation-credential
introspection). Changing a prefix requires accepting both during a transition.

## Related requirement IDs

IMP-009, IMP-010, IMP-014, IMP-016, IMP-017, MCH-005, MCH-006, SES-023, TOK-009, SDK-002, TEST-035, TEST-043, TEST-044, §13.2
