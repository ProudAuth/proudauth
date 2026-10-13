# 0009. Ordinary access tokens: short-lived asymmetric JWTs with one audience

**Status:** Accepted

## Context

Most resource servers need to validate tokens without a network call on every
request, but a valid signature must not be mistaken for authorization to any
service (TOK-004..TOK-008, JWT-BCP). Local verification cannot observe revocation
(SES-023).

## Decision

- Ordinary access tokens are JWTs signed with the realm's active key
  (`keys.signing_algorithm`, default `RS256` with 3072-bit RSA; `ES256`, `PS256`,
  `EdDSA` available), header `typ: at+jwt`, and a `kid` resolvable only from that
  realm's JWKS.
- Each token has exactly one audience: a registered API resource. A token request
  naming more than one `resource` is rejected (`invalid_target`).
- Lifetime comes from the resource (`access_token_ttl_seconds`, default 300, range
  30–3600), shortened by a client cap (`token_policy.access_token_ttl_seconds`) and
  capped by `tokens.max_access_token_ttl` (60 min).
- Claims carry `token_kind` (`user_access`, `service_access`, `exchange_access`) so
  verifiers can reject the wrong class; ID tokens use `typ: JWT` and are rejected
  by access-token verifiers.
- A resource may instead choose `token_format: opaque`; such tokens must be
  verified online (introspection).
- The first-party Go verifier (`proudauth-sdk-go/verifier`) implements the §14.4 algorithm:
  configured issuer only, strict parsing with duplicate-member rejection,
  asymmetric algorithm allowlist, bounded JWKS refresh on unknown `kid`, exact
  issuer and single-audience checks, and clock skew of at most 60 s.

## Alternatives considered

- **Opaque tokens everywhere**: every API call would depend on IdP availability.
- **Multi-audience tokens**: rejected; a token accepted by one service would be
  accepted by others (TOK-007).
- **HMAC-signed tokens**: rejected; resource servers would hold minting keys
  (TOK-006).

## Consequences

- Offline verifiers accept a token until `exp` plus their clock tolerance even
  after the session, membership or user is revoked. This exposure is documented in
  [docs/operations/revocation-exposure.md](../operations/revocation-exposure.md).
- The IdP's own account and admin APIs, UserInfo, introspection and token exchange
  re-check live state (session, user, client, JTI revocations and authorization
  grant) on every call. User JWTs carry the reserved `grant_id`; exchanges retain
  the originating grant. Revoking that grant ends its linked JWT authority online
  even when an offline grant has no `sid`, without ending another grant.
- `authz_version` in tokens is a hint; it is meaningful only when compared to live
  state, which introspection returns.
- `tokens.access_token_ttl` does not set issued lifetimes (resources always have
  their own value); see [docs/operations/configuration.md](../operations/configuration.md).

## Migration implications

Changing the signing algorithm takes effect through key rotation; verifiers must
accept both algorithms during the overlap window ([0015](0015-key-hierarchy.md)).
User/exchanged JWTs from earlier development builds without `grant_id` fail
closed online after the grant-link fix. Refresh once through a new server or
reauthenticate; coordinate the rollout so old issuers no longer produce those
tokens ([upgrades.md](../operations/upgrades.md)). Offline verification still
accepts a cryptographically valid JWT until its expiry.

## Related requirement IDs

TOK-004, TOK-005, TOK-006, TOK-007, TOK-011, TOK-014, TOK-015, SES-023, SDK-001, TEST-001..TEST-006, TEST-034, §14.3, §14.4
