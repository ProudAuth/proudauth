# Tokens

Requirements: §14, TOK-001..TOK-024, JWT-AT (RFC 9068), OIDC-003. Code:
`internal/token/jwt.go`, `internal/token/keys.go`, `internal/oauth/mint.go`,
`internal/platform/secret/secret.go`.

## Artifact overview

| Artifact | Format | Consumer | Lifetime |
| --- | --- | --- | --- |
| Access token, `user_access` | JWT `typ: at+jwt` (or opaque `pa_at_` for opaque-format resources) | One API resource | Resource `access_token_ttl_seconds` (default 300 s), shortened by client and realm limits (see [Access-token lifetime](#access-token-lifetime)) |
| Access token, `service_access` | JWT `at+jwt` (or opaque) | One business resource | Same |
| Access token, `exchange_access` | JWT `at+jwt` (or opaque) | One business resource | ≤ remaining lifetime of the subject token |
| Access token, `impersonation_access` | Opaque `pa_it_` only | Resources implementing the support contract | ≤ 5 min |
| ID token | JWT `typ: JWT`; for clients with `id_token_encrypted_response_alg` a JWE wrapping it (`cty: JWT`, TOK-020) | The OIDC client | `tokens.id_token_ttl` (5 min) |
| Authorization response (JARM, ADV-002) | JWT `typ: JWT` in the `response` parameter, optionally encrypted | The client | 10 min |
| UserInfo response | JSON, or `application/jwt` (signed and/or encrypted, OIDC-013) for clients that ask for it | The OIDC client | — |
| Logout token | JWT `typ: logout+jwt` | Back-channel logout endpoint of a client | 2 min |
| Refresh token | Opaque `pa_rt_` | Token endpoint only | Family idle/absolute ([ADR 0011](../architecture-decisions/0011-refresh-token-families.md)) |
| Authorization code | Opaque `pa_ac_` | Token endpoint | 60 s |
| API key | Opaque `pa_key_` | Introspection | Set at creation |
| Personal access token | Opaque `pa_pat_` | Introspection | Set at creation |

Opaque secrets are the prefix plus 32 random bytes (base64url, 256 bits) and are
stored only as SHA-256 digests. The server routes on prefixes: a secret presented
to the wrong endpoint is rejected before any lookup. Other prefixes: `pa_hc_`
support handoff codes, `pa_inv_` invitations, `pa_tx_` transaction continuations,
`pa_csrf_` CSRF tokens, `pa_ses_` session cookies, `pa_cs_` client secrets,
`pa_dc_` device codes, `pa_dl_` download tokens, `pa_iat_` initial access
tokens and `pa_rat_` registration access tokens of dynamic client
registration ([dynamic-client-registration.md](../integrations/dynamic-client-registration.md)).
Signed and encrypted responses: [response-security.md](response-security.md).

## Access-token lifetime

`internal/oauth/mint.go` (`accessTTL`), TOK-018, `TestTokenLifetimePolicy`. The
lifetime of a `user_access`, `service_access` or `exchange_access` token is the
resource's `access_token_ttl_seconds`, lowered by each of these that is set and
shorter:

| Limit | Applies to |
| --- | --- |
| Client `token_policy.access_token_ttl_seconds` | Tokens issued to that client |
| Realm policy `tokens.access_token_ttl_seconds` | Every access token in the realm |
| Realm policy `tokens.service_access_token_ttl_seconds` | Tokens whose subject is a service principal |
| Realm policy `tokens.single_factor_access_token_ttl_seconds` | Tokens for users whose `acr` ranks below `urn:proudauth:acr:mfa` (single-factor, federated, recovery and guest sessions) |
| Remaining lifetime of the subject token | Token exchange |
| Remaining lifetime of the workload assertion | `jwt-bearer` grant ([workload-federation.md](../integrations/workload-federation.md)) |
| 10 minutes | Tokens issued to `fapi2` clients ([FAPI 2.0](oauth-oidc-profile.md#fapi-20-security-profile-adv-001)) |
| `tokens.max_access_token_ttl` (operator, 60 min) | Every access token |

The realm limits are 30–86400 seconds, or 0 (no limit); realm administrators
can only shorten lifetimes with them. `expires_in` in the token response reports
the result. Support tokens live as long as their support grant, and the grant
is bounded by the smallest of `impersonation.max_ttl` (operator), realm
`impersonation.max_ttl_seconds`, `tokens.impersonation_access_token_ttl_seconds`
and `tokens.access_token_ttl_seconds`.

## Scope reduction and consent (TOK-008)

A user token's scopes stay within the client's resource grants, the subject's
organization scope policy and, for a client with `consent_mode: required`, the
user's consent for that client (APP-013). Every path that creates a user grant
or derives a token from one applies the consent part:

| Path | Consent |
| --- | --- |
| Authorization (authentication transaction) | `CheckConsentCoverage` (`internal/authentication/consent_coverage.go`): the user's own live consent at the client's `consent_terms_version`, otherwise a live pre-authorization for the realm or the organization signed in to, must cover every scope; otherwise the transaction asks with the `consent` action ([headless-authentication.md](headless-authentication.md#consent)) |
| Organization switch (`POST /me/organization-grants`) | The same check for the target organization and the scopes of the new grant (never `offline_access`); otherwise `403 consent_required` with the obligation `{"type": "authorize", "organization_id": "...", "scope": "..."}`, which the client answers with an authorization request naming the organization (`TestOrganizationSwitchConsent`, `TestOrganizationSwitchPreauthorization`) |
| Refresh | Only narrows the grant's scopes (`invalid_scope`, "refresh cannot expand scope"), re-checked against the client's current grants |
| Token exchange | Narrowed to the user's live consent for the client the subject token was issued to ([oauth-oidc-profile.md](oauth-oidc-profile.md#token-exchange-rfc-8693), `TestExchangeLimitedToUserConsent`) |

Offline access by a third-party client always needs the user's own consent, and
a consent recorded for a pre-authorization covers a later request only while
that pre-authorization does. For a `consent_mode: required` client, a grant
issued without asking records the consent it rests on, so revoking the consent,
or the pre-authorization behind it, ends the grant and its refresh tokens; this
holds for grants created by an organization switch as for those of an
authorization.

## JWT header

```json
{ "alg": "RS256", "kid": "rs256-20261010-9f2c4e1a7b3d5c60", "typ": "at+jwt" }
```

- `alg` is the algorithm of the realm's active signing key: `RS256` (default,
  RSA 3072), `PS256`, `ES256` or `EdDSA`. An API resource may pin a
  `signing_algorithm` (from `security.allowed_algorithms`); access tokens for it
  are issued only while the realm's active key uses that algorithm (otherwise
  `503 temporarily_unavailable`). A resource created without one pins the
  realm's current algorithm. Every signing-key rotation, through
  `POST /signing-key-rotations` or scheduled by the worker, keeps the realm's
  algorithm unless the request names another, and is refused (`409`) when
  active resources pin a different algorithm or `fapi2` clients would be left
  without `PS256`, `ES256` or `EdDSA` (`TestResourceAlgorithmProfile`,
  `TestScheduledRotationKeepsRealmAlgorithm`, `TestKeyRotationGuardsAllCallers`,
  `TestKeyRotationKeepsFAPI2Algorithm`; [keys.md](../operations/keys.md#scheduled-automatic)).
- `kid` format: `<alg lowercased>-<YYYYMMDD>-<16 hex>`; opaque to verifiers.
- `typ`: `at+jwt` (access), `JWT` (ID token), `logout+jwt` (logout token).

## Access token claims (`user_access`)

```json
{
  "iss": "https://id.example.com/realms/main",
  "sub": "usr_01k7...",
  "aud": "https://orders.example.com",
  "client_id": "web-bff",
  "iat": 1791590400,
  "nbf": 1791590400,
  "exp": 1791590700,
  "jti": "tok_01k7...",
  "grant_id": "gnt_01k7...",
  "sid": "ses_01k7...",
  "scope": "orders:read orders:write",
  "org_id": "org_01k7...",
  "project_id": "prj_01k7...",
  "token_kind": "user_access",
  "authz_version": 7,
  "auth_time": 1791590390,
  "acr": "urn:proudauth:acr:mfa"
}
```

| Claim | Presence | Meaning |
| --- | --- | --- |
| `iss` | always | Realm issuer |
| `sub` | always | User ID (`usr_...`), service principal ID (`svc_...`) for `service_access`. Access tokens always use the internal ID, also for clients with pairwise subjects. |
| `aud` | always | Exactly one registered audience (serialized as a string) |
| `client_id` | always | OAuth client the token was issued to |
| `iat`, `nbf`, `exp` | always | Issue time, not-before (= `iat`), expiry |
| `jti` | always | Unique ID (`tok_...`); revocable through the revocation endpoint |
| `grant_id` | `user_access`, `exchange_access` | Durable authorization grant (`gnt_...`); exchanges retain the originating grant. Strict-online checks require it to be active, unexpired, in the token's realm and owned by its subject; ordinary user tokens must also match its client. This identifier is not a credential and makes no offline revocation guarantee. |
| `token_kind` | always | `user_access`, `service_access`, `exchange_access` |
| `scope` | when non-empty | Scopes of this resource only |
| `sid` | session-bound user grants | IdP session ID. Absent for offline grants and machine tokens. |
| `org_id` | business resources with `requires_organization` | The single organization of the grant. Never on account, admin or UserInfo tokens. |
| `project_id` | if the resource belongs to a project | |
| `authz_version` | when available | Membership revision + organization authorization revision (user tokens with an organization), user authorization revision (without), or service principal permission revision. A hint to compare with introspection's current value, not authority. |
| `auth_time`, `acr` | user tokens | Time and local assurance profile of the original authentication |
| `act` | `exchange_access` | Actor chain (RFC 8693): `{"iss": ..., "sub": "<service principal or client id>", "act": {...}}`; the actor entry adds `"agent": true` when the exchanging client's service principal is an agent (MCH-017) |
| `cnf` | sender-constrained | `{"jkt": "<JWK SHA-256 thumbprint>"}` (DPoP) or `{"x5t#S256": "<base64url SHA-256 of the client certificate>"}` (mutual TLS, RFC 8705, [mutual-tls.md](mutual-tls.md)) |
| `agent` | `service_access` of an agent | `true` when the subject is a service principal registered with `is_agent: true` (MCH-017, [machine-clients.md](../integrations/machine-clients.md#agents)); introspection returns it too. It grants nothing: treat it as information about who acts |
| custom | optional | Non-reserved claims from the client's `access_token_claims`: static values, and attribute mappings (`{"$attr": "user.locale"}`, `{"$attr": "profile.<claimable attribute>"}`, optional `transform` and `default`; APP-011, [oauth-oidc-profile.md](oauth-oidc-profile.md#clients)) that read the token's user, released only when the token's scopes (or, failing that, its grant's) include `profile` (otherwise the mapping's `default`, if any); then claims from `token.claims` pre-action hooks (which can never set reserved claims). Mappings never set OIDC standard user claims (`name`, `email`, `locale`, …; OIDC-007): registration refuses them, and issuance skips any stored by an older version. Profile attributes are released only when the realm marks them `claimable` and not `user_editable`, but `user.*` values are edited by users themselves; do not authorize on them |

`amr` is not included in access tokens. Reserved claim names that mappings can never
set: `iss sub aud exp nbf iat jti client_id scope token_kind act may_act cnf sid grant_id
org_id auth_time acr amr azp nonce at_hash c_hash authz_version events
impersonation_grant_id support_mode project_id typ agent` (TOK-015).

`service_access` tokens carry `sub` = service principal, `client_id`, `scope`,
`org_id` (when the resource requires one), `token_kind`, `authz_version`, and
`agent: true` for agents; no `sid`, `auth_time` or `acr`. The same holds for
tokens from the `jwt-bearer` grant (workload federation).

User/exchanged JWTs from development builds before the grant-link fix have no
`grant_id` and are rejected by current online consumers. Obtain a fresh access
token by a serialized refresh, or sign in again if its grant has ended. See the
[upgrade note](../operations/upgrades.md). Offline and bounded-state verifiers
still have the exposure limits in [revocation-exposure.md](../operations/revocation-exposure.md).

## Support (impersonation) tokens

Opaque. Introspection returns, when active:

```json
{
  "active": true, "iss": "https://id.example.com/realms/main",
  "sub": "usr_customer", "aud": "https://orders.example.com", "client_id": "support-bff",
  "scope": "orders:read", "exp": 1791590700, "iat": 1791590400, "jti": "tok_...",
  "token_kind": "impersonation_access", "token_type": "Bearer", "org_id": "org_...",
  "act": { "iss": "https://id.example.com/realms/main", "sub": "usr_support_agent" },
  "support_mode": "read_only", "impersonation_grant_id": "imp_..."
}
```

`support_mode` is `read_only` or `allowlisted_write`. No `auth_time` or `acr` of the
customer is asserted (IMP-018).

## ID token claims

| Claim | Notes |
| --- | --- |
| `iss`, `aud` (client ID), `azp` (client ID), `iat`, `exp` | |
| `sub` | User ID, or `pws_...` pairwise value for clients with `subject_type: pairwise` |
| `auth_time`, `acr`, `amr` | From the session (`amr` values: `pwd`, `otp`, `sms`, `magic_link`, `totp`, `hotp`, `recovery`, `hwk`, `swk`, `x509`, `fed`, `fed_mfa`, `mfa`; `totp`, `hotp`, `recovery`, `x509`, `fed`, `fed_mfa` and `magic_link` are project-specific, not RFC 8176 registered values) |
| `nonce` | Echoed when the request had one |
| `sid` | IdP session ID |
| `at_hash` | Left half of the hash of the access token issued with it |
| `org_id` | Organization of the grant, when selected |
| profile claims | Released per scope as for UserInfo and narrowed by the `id_token` member of an OIDC `claims` request ([oauth-oidc-profile.md](oauth-oidc-profile.md#claims-parameter)), plus the client's `id_token_claims` (static values and attribute mappings, APP-011), which can never set reserved claims, OIDC standard user claims (`email`, `email_verified`, `name`, …) or a claim already released by scope |

ID tokens are not access tokens: their `typ` is `JWT`, and every access-token
verifier in this repository rejects them (TEST-002). For clients that register
`id_token_encrypted_response_alg`, the signed ID token is encrypted to the
client's registered key (a nested JWT); decrypt it, then validate the inner
token as above ([response-security.md](response-security.md#encrypted-id-tokens)).

## Logout token claims

`iss`, `aud` (client ID), `iat`, `exp` (`iat` + 2 min), `jti`, `sub` (user ID),
`sid`, `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`.
No `nonce`.

## Verification rules for resource servers

Implemented by `proudauth-sdk-go/verifier` (`Verifier.Verify`) and required of any other
implementation (§14.4):

1. Configure the issuer and your audience. Never fetch keys from URLs found in a
   token; the JWKS URL defaults to `<issuer>/jwks`.
2. Reject tokens larger than 8 KiB, with duplicate JSON members in header or
   payload, or without exactly three segments.
3. Reject a mismatching `iss` **before** any key lookup, so unknown issuers never
   trigger network traffic (TEST-003).
4. Allow only asymmetric algorithms (`RS256`, `PS256`, `ES256`, `EdDSA`); `none` and
   `HS*` are refused, also in configuration (TEST-004).
5. Require `typ` `at+jwt` (or `application/at+jwt`).
6. Resolve `kid` only in the issuer's JWKS; an unknown `kid` triggers at most one
   coalesced refresh per `MinRefreshInterval` (default 30 s) (TEST-005). The key's
   `alg` must match the header.
7. Require exactly one `aud` equal to your audience (TEST-001).
8. Check `exp` and `nbf`, and reject `iat` in the future, each with at most 60 s
   tolerance (default 30 s) (TEST-006).
9. Require `sub`, `client_id`, `jti` and an accepted `token_kind` (default
   `user_access`, `service_access`, `exchange_access`).
10. Then authorize: match `org_id` against the organization of the object, from your
    own data (`Claims.RequireOrganization`), and require scopes
    (`Claims.RequireScope`).

## Signing keys and JWKS

- One active key per realm signs all JWTs of that realm. The JWKS contains
  `pending`, `active` and `retiring` keys (`use: sig`, `alg`, `kid`), never private
  material, and is cacheable for 300 s.
- Planned rotation prepublishes a new key for `keys.prepublish_period` (48 h),
  activates it, and keeps the old key published for
  `tokens.max_access_token_ttl + keys.retirement_period` (60 min + 7 d), so verifiers
  that refresh at least daily never see an unknown `kid` for a valid token.
- Emergency rotation removes the active key from JWKS immediately and activates a
  new one. Verifiers that cached the old key keep accepting it until they refresh.
- Details: [docs/operations/keys.md](../operations/keys.md).
