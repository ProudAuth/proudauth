# OAuth 2.0 and OpenID Connect profile

This is the profile the server implements. It describes behavior verified in
`internal/oauth`, `internal/application` and `internal/httpapi/protocol.go`, and
exercised by `tests/e2e/protocol_test.go`, `flows_test.go`, `tokens_test.go` and
`bff_test.go`. It is not a certification claim: no OpenID or FAPI conformance suite
has been run ([interoperability.md](../integrations/interoperability.md)).

`I` below is the issuer: `<server.public_origin>/realms/<realm>`.

## Endpoints

| Endpoint | Path | Notes |
| --- | --- | --- |
| Discovery | `GET I/.well-known/openid-configuration` | Generated from implemented features; `Cache-Control: public, max-age=300` |
| RFC 8414 metadata | `GET /.well-known/oauth-authorization-server/realms/<realm>` | Same document |
| JWKS | `GET I/jwks` | Pending, active and retiring public keys; `application/jwk-set+json`; `max-age=300` |
| Authorization | `GET` or `POST I/oauth/authorize` | `POST` requires `application/x-www-form-urlencoded` |
| Token | `POST I/oauth/token` | Form body only; parameters in the query string are rejected |
| Introspection (RFC 7662) | `POST I/oauth/introspect` | Confidential clients registered as introspectors |
| Revocation (RFC 7009) | `POST I/oauth/revoke` | |
| Device authorization (RFC 8628) | `POST I/oauth/device_authorization` | |
| Pushed authorization requests (RFC 9126) | `POST I/oauth/par` | |
| UserInfo | `GET` or `POST I/oidc/userinfo` | Bearer token in `Authorization` header only (`DPoP` scheme for DPoP-bound tokens) |
| Dynamic client registration (RFC 7591, 7592) | `POST I/oauth/register`; `GET`, `PUT`, `DELETE I/oauth/register/{client_id}` | Only when the realm enables it ([Dynamic client registration](#dynamic-client-registration-rfc-7591-7592)) |
| RP-initiated logout | `GET` or `POST I/oidc/logout` | Extension parameter `upstream_logout` ([Logout](#logout)) |
| Return from an upstream logout | `GET I/oidc/logout/upstream-return` | Redirect target registered at upstream providers ([Upstream logout](#upstream-logout-fed-013)) |
| Check-session iframe (OIDC Session Management 1.0) | `GET I/oidc/check-session` | Only when the realm turns it on ([Session management](#session-management-oidc-014)); `404` otherwise |

Every error on the `I/oauth/` and `I/oidc/` endpoints is an OAuth error
(`error`, `error_description`) with its HTTP status, also when it is decided
before the endpoint runs (load shedding and maintenance `503
temporarily_unavailable`, a body over `limits.max_body_bytes` `413
invalid_request`, the host policy `421`, an unknown realm `404`), and every
`429` and `503` carries `Retry-After`
([API conventions](api-conventions.md)).

With mutual TLS deployed ([mutual-tls.md](mutual-tls.md)), the token,
introspection, revocation, UserInfo, PAR and device authorization endpoints
are also reachable on `server.mtls_origin` and listed in discovery as
`mtls_endpoint_aliases`.

When ProudAuth acts as a client of an upstream identity provider, the upstream
redirects to `GET` or `POST /api/v1/realms/<realm>/federation/<connection alias>/callback`
(the redirect URI to register at the upstream). It is not part of the
authorization-server metadata; see
[headless-authentication.md](headless-authentication.md#upstream-identity-providers).

Issuers and endpoint URLs come only from `server.public_origin`; `Host` and
`X-Forwarded-*` headers never influence them (TOK-022; tested by
`TestDiscoveryAccuracy`). A realm's verified custom domain
([installation.md](../operations/installation.md#custom-domains)) can serve
these endpoints too, but discovery there still names the public origin's
issuer and endpoints, and tokens, DPoP proofs (`htu`) and client assertions
(`aud`) keep using public-origin URLs.

## Clients

| `client_type` | Authentication | Allowed grants |
| --- | --- | --- |
| `confidential` | `client_secret_basic` (default), `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` | authorization code, refresh, client credentials, token exchange, device code |
| `public_browser` | `none` | authorization code, refresh |
| `native` | `none` | authorization code, refresh, device code |
| `device` | `none` by default | device code, refresh |
| `machine` | `client_secret_basic` (default), `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`; `none` only when `jwt-bearer` is its only grant | client credentials, token exchange, `jwt-bearer` |

- Exactly one authentication method per request, and it must be the client's
  registered method (`client_secret_basic` and `client_secret_post` are
  interchangeable). Failures return `401 invalid_client` without detail.
- Client secrets are `pa_cs_` + 256 random bits, shown once, stored as SHA-256
  digests, at most three active per client, optionally with expiry for rotation.
- `private_key_jwt` (MCH-010, APP-009): RS256, PS256, ES256 or EdDSA (no HMAC;
  `fapi2` clients PS256, ES256 or EdDSA only); signed by one of the client's
  registered keys (`kid` and `alg` must match where the key names them);
  `iss` = `sub` = `client_id`; `aud` must be the realm's issuer as a **single
  JSON string** (`"aud": "https://id.example.com/realms/main"`) at every
  endpoint that accepts client authentication. An endpoint URL, also the
  token endpoint's, and an array, also `["<issuer>"]`, are refused (`401
  invalid_client`): this is the FAPI 2.0 Security Profile and RFC 7523bis
  rule against the audience-injection attack, where an assertion addressed to
  an endpoint URL is replayed at another server (decision 16). The realm
  policy `client_auth.allow_endpoint_audience` (default `false`) re-admits,
  for clients other than `fapi2` ones, what earlier versions accepted: the URL
  of the endpoint receiving the assertion as a string, or an array of one or
  two values each naming the issuer or that URL; an audience naming another
  party is refused either way. `exp` required, at most 5 minutes ahead (30 s
  tolerance); `jti` required and single-use (`TestPrivateKeyJWT`,
  `TestAssertionAudience`).
- `password` and `implicit` are rejected at registration and at the token endpoint.
- `client_credentials` requires a linked service principal.
- `jwt-bearer` (`urn:ietf:params:oauth:grant-type:jwt-bearer`, RFC 7523) is
  workload federation for machine clients with a service principal: an
  assertion from an issuer the client trusts yields a service token. A machine
  client whose only grant is `jwt-bearer` may use authentication method
  `none` ([Workload federation](#workload-federation-rfc-7523)).
- Mutual-TLS client authentication (`tls_client_auth`,
  `self_signed_tls_client_auth`, RFC 8705) and certificate-bound tokens:
  [Mutual TLS](#mutual-tls-rfc-8705).
- Security profiles: `standard`; `third_party` (consent required, not first-party);
  `privileged` (first-party, not `public_browser`); `high_assurance` (requires
  `private_key_jwt` and forces PAR); `fapi2` (the FAPI 2.0 rule set,
  [FAPI 2.0 security profile](#fapi-20-security-profile-adv-001)).
- Optional per-client protocol settings, stored together in
  `clients.protocol_options` (migration `0050`) and shown in the client view
  only when set: front-channel logout ([Logout](#front-channel-logout-ses-018)),
  response signing and encryption
  ([response-security.md](response-security.md)), mutual-TLS client
  authentication and certificate binding, and the display URLs of dynamically
  registered clients. Configuration documents and the configuration export
  carry them with the client (`TestConfigClientProtocolOptions`).
- Per-client `token_policy`: `access_token_ttl_seconds` (cap), `refresh_idle_seconds`,
  `refresh_absolute_seconds`, `require_dpop`, `require_par`, `require_mfa`,
  `max_session_age_seconds` (an SSO session whose authentication is older than this
  is not reused for the client; `prompt=none` then returns `login_required`, and
  an organization switch, `POST /me/organization-grants`, is refused with
  `403 step_up_required`).
- Consent (APP-013): `consent_mode` is `preauthorized` (default for first-party
  clients) or `required` (default otherwise). `consent_terms_version` (at most 64
  characters) names the client's current terms; a user's consent covers the
  client only for the version it was given for, so changing it asks users again
  at their next authorization (existing grants stay valid). Administrators can
  consent on behalf of the realm or one organization with
  `POST /clients/{client}/consent-preauthorizations` (see
  [headless-authentication.md](headless-authentication.md#consent)). An
  organization switch (`POST /me/organization-grants`) runs the same consent
  coverage as an authorization for the target organization (`403
  consent_required` otherwise).
- Pairwise subjects (`subject_type: pairwise`, OIDC-010): `sector_identifier` is
  a host name; when omitted it is the host all redirect URIs share, and it is
  required when they span several hosts. Every redirect URI must be the sector
  host or one of its subdomains (`422` otherwise), so a client cannot register
  into another application's sector. Clients in the same sector receive the same
  pairwise `sub` for a user; clients in different sectors never do
  (`TestPairwiseSectors`).
- Environments (APP-015, `TestEnvironmentSeparation`): `environment` is
  `development`, `staging` or `production` (default). Production clients cannot
  use loopback redirect URIs or `http` origins (see below). A client registered
  in a project defaults to the project's environment and must match it (`422`).
  The environment is fixed: `PUT /clients/{client}` with another value fails
  with `422` on `environment`, so a development client, its secrets and its
  redirect URIs are never promoted in place; register a new client instead.
  Token exchange refuses subject tokens issued to a client of another
  environment ([Token exchange](#token-exchange-rfc-8693)).
- Claim mappings (APP-011, `TestClaimMappings`): `id_token_claims` and
  `access_token_claims` map claim names to values, at most 20 claims per map
  and claim names of at most 64 characters. A value is either a static JSON
  value (anything but an object), released as is, or an attribute mapping:

  ```json
  {"department": {"$attr": "profile.department", "transform": "upper", "default": "none"},
   "tier": "gold"}
  ```

  `$attr` names exactly one approved attribute: `user.given_name`,
  `user.family_name`, `user.display_name`, `user.locale`, `user.zoneinfo`, or
  `profile.<name>`, a realm profile attribute (`profile.attributes`) marked
  `claimable: true`. A realm profile schema that marks an attribute both
  `claimable` and `user_editable` is refused (`422`, field
  `profile.attributes[<i>].claimable`), and an attribute stored with both
  flags by an older version is never released. Attribute values (`user.*` and
  `profile.*`) are released only when the grant includes the `profile` scope:
  for ID tokens, the scopes of the authorization request; for access tokens,
  the token's scopes or, failing that, its grant's. Static values are
  released regardless. `transform` is `lower` or `upper`; `default` is a string
  used when the attribute is absent (for `user.*`, also when it is empty), the
  profile attribute is not claimable, or the `profile` scope is missing;
  without a default no claim is emitted. Mapping objects take no
  other members, and there is no way to compute, concatenate or reach other
  data. String values are cut to 256 characters before the transform;
  numeric and boolean profile values pass unchanged. Whether a profile
  attribute is claimable is checked at issuance, not at registration.
  Mappings read the user of user tokens; service-principal tokens have no
  attributes, so only a mapping's `default` can apply, and exchanged tokens
  carry no grant, so they release attributes only when their own scopes
  include `profile`. The `user.*` attributes (names, locale, time zone) are
  edited by users themselves through `PATCH /me`: never authorize on them.
- Mappings may not name reserved claims (`422`, "reserved claim <name>
  cannot be mapped"; [tokens.md](tokens.md#access-token-claims-user_access)),
  and neither map may name an OIDC standard user claim (OIDC-007): `name`,
  `given_name`, `family_name`, `middle_name`, `nickname`,
  `preferred_username`, `profile`, `picture`, `website`, `email`,
  `email_verified`, `gender`, `birthdate`, `zoneinfo`, `locale`,
  `phone_number`, `phone_number_verified`, `address` and `updated_at`. These
  come only from the user record and are released by scope, and resource
  servers may read them as user data. Registration and update reject such a
  mapping, static value or attribute mapping alike, with `422` on
  `id_token_claims` or `access_token_claims`. Issuance skips these names, and
  reserved ones, in mappings stored by older versions, in access tokens as in
  ID tokens (ID tokens also skip any claim already released by scope).
  Attribute mappings can still release name and locale values under other
  claim names regardless of the granted scopes, so review them like a
  scope.

### Redirect URIs and origins

- Exact string match against registered URIs (APP-004). Registration rejects
  wildcards, backslashes, whitespace, fragments, userinfo, relative URIs, path
  traversal and encoded separators (`%2e`, `%2f`, `%5c`).
- `redirect_uris` and `post_logout_redirect_uris` must not point at the
  identity provider itself (APP-004): a URI whose host equals the host of
  `server.public_origin` is refused at registration and update (`422` on the
  field, "must not point at the identity provider itself"), because the
  identity provider's own endpoints redirect further (authorization, logout,
  federation) and would form open-redirect chains. The comparison is on the
  host name, whatever the scheme and port, and also covers the realm's
  verified custom domains. Loopback hosts (`localhost`, `*.localhost` and
  loopback addresses) are exempt for every client type, so native clients
  keep their loopback redirects. Other realms' custom domains are not
  checked; do not register URIs on them either.
- `https` is required, except: `http` loopback IPs for `native` and `device` clients
  (RFC 8252 §7.3, **any port** at request time when the registered URI is
  `http://127.0.0.1/...` or `http://[::1]/...`); `http://localhost` and other
  loopback hosts for non-production clients; reverse-domain private-use schemes
  (containing a dot) for `native` clients. Production clients may not redirect to
  loopback over `https` either.
- Browser origins (`allowed_origins`) are registered separately, `https` only
  (except non-production loopback), no paths or wildcards. CORS responses reflect
  only registered origins of active clients; credentials are allowed only on
  `/api/v1/realms/{realm}/auth/...`.

## Authorization endpoint

| Parameter | Rule |
| --- | --- |
| `response_type` | `code` only |
| `response_mode` | absent or `query`; `query.jwt` or `jwt` for a JWT-secured response (JARM, ADV-002, `typ: oauth-authz-resp+jwt`, [response-security.md](response-security.md#jarm-adv-002)). Others are refused with an error redirect in query mode |
| `code_challenge`, `code_challenge_method` | **Required**: `S256` and a 43-character base64url value. `plain` is rejected. |
| `redirect_uri` | Required; exact match (see above) |
| `scope` | Space-separated, at most 50; every scope must exist and be allowed for the client (see Scopes and resources) |
| `resource` | Repeatable, at most 5 per request; registered audiences only |
| `state`, `nonce` | Up to 1024 and 512 characters |
| `prompt` | `none`, `login`, `consent`, `select_account`, `create`; `none` cannot be combined |
| `max_age` | Non-negative integer |
| `acr_values` | Local values only (below) |
| `login_hint`, `ui_locales` | Hints passed to the login UI; never authority |
| `organization` | Organization ID or slug to bind; not disclosed if unknown |
| `request_uri` | A PAR reference |
| `dpop_jkt` | Optional (RFC 9449 §10): the JWK SHA-256 thumbprint of a DPoP key (43 base64url characters; anything else is `invalid_request`). The code is then redeemed only with a DPoP proof of that key ([DPoP](#dpop-rfc-9449)) |
| `intent=register` | Product extension, same as `prompt=create` |
| `claims` | OIDC `claims` request (JSON, at most 4096 bytes; members `id_token` and `userinfo` only; standard claim names plus `acr`, `auth_time`, `amr`). Unknown members or claims return `invalid_request`. See [Claims parameter](#claims-parameter). |
| `request` | Rejected (`request_not_supported`) |

- Single-valued parameters must not repeat (`invalid_request`).
- Errors detected before the client and redirect URI are validated are returned as
  JSON (`400`) and never redirected. Later errors redirect with `error`,
  `error_description`, `state` and `iss`.
- Successful responses carry `code`, `state` and `iss` (RFC 9207). With
  `response_mode=query.jwt` (or `jwt`), successful and error redirects carry
  one signed `response` parameter instead.
- Without a usable SSO session the browser is redirected to the login UI with
  `transaction_id` and `realm`; see [headless-authentication.md](headless-authentication.md).

### Sessions, prompt and assurance

- An IdP session cookie (`pa_sid`) lets the server complete a request silently when
  user, membership, client consent and assurance requirements are met (SES-014).
- `prompt=login` ignores the existing session. `max_age` reuses the session only if
  its authentication time is within the limit; the original `auth_time` is kept
  (OIDC-004, AUT-017).
- `prompt=none` returns `login_required`, `consent_required`,
  `account_selection_required` or `interaction_required` instead of showing UI.
- `prompt=consent` forces the consent step even when consent was recorded.
- `prompt=select_account` with a reusable SSO session stops the transaction with a
  required `select_account` action showing the current account (display name and
  masked email). The login UI answers with `POST .../{id}/account`:
  `{"continue": true}` keeps the signed-in account; `{"continue": false}` drops
  the session's identity and returns to `identify` (OIDC-005).
- `acr_values` accepts `urn:proudauth:acr:single_factor`, `:federated`, `:recovery`,
  `:mfa`, `:phishing_resistant`. Values containing `mfa` or `phishing_resistant`
  make MFA mandatory for the transaction. Requested scopes with a step-up policy
  add their `acr` and lower `max_age` (see [Scope step-up](#scope-step-up)).
  These are local assurance profiles, not
  external certifications (AUT-015). Guest sessions (REG-010, realm policy
  `registration.allow_guests`) carry `acr` `urn:proudauth:acr:anonymous` and
  `amr` `["anon"]`, which rank below every other profile.

### Claims parameter

The OIDC `claims` request (OIDC-008) is validated at the authorization endpoint
(and at PAR and headless start) and stored with the authorization grant. It only
**narrows** release; it never releases a claim that the granted scopes do not
already authorize, so it cannot override protected or unconsented claims.

- `id_token` member: the ID token carries only the listed user claims (plus
  `email_verified` when `email` is listed and `phone_number_verified` when
  `phone_number` is listed), still limited by the granted scopes. Without an
  `id_token` member, ID-token claims follow the scopes.
- `userinfo` member: UserInfo is narrowed the same way; `sub` is always returned.
  Without a `userinfo` member, UserInfo follows the scopes.
- `acr` requests (in either member, essential or not) add their values to the
  transaction's assurance requirement. An essential `acr` request for a value the
  server does not support fails with `unmet_authentication_requirements`; one that
  the existing session cannot meet is not satisfied silently (with `prompt=none`
  no code is issued).
- `value`, `values` and `essential` are accepted for every claim, but only `acr`
  values change behavior; other claims are released from the user record or not
  at all.

Tests: `TestClaimsRequestAndStaticClaims` (`tokens_test.go`) and
`TestBrowserFlowCSRFSSOAndLogout` subtest "OIDC-005 select_account and OIDC-008
claims" (`flows_test.go`).

## Scopes and resources

- OIDC scopes: `openid`, `profile`, `email`, `phone`, `address`, `offline_access`.
  `profile`/`email`/`phone`/`address` require `openid`; OIDC scopes require a user
  subject; `offline_access` requires the client's `allow_offline_access`.
- Resource scopes belong to one API resource; a client may request them only if it
  has a resource grant (`PUT /clients/{client}/resource-grants/{resource}`) listing
  the scope. Requesting a scope never grants it (APP-007). `PUT` replaces the
  grant (`allowed_scopes`, `subject_types`, `exchange_policy`).
  `GET /clients/{client}/resource-grants/{resource}` (`realm.clients.read`)
  returns one grant with an `ETag` derived from its content (`W/"g<hex>"`);
  `PUT` accepts it as an optional `If-Match` and answers `412
  precondition_failed` when the grant changed meanwhile, or when `If-Match` is
  sent for a grant that does not exist (API-010, DB-010).
- If no `resource` is given, the resources of the requested scopes are used, then
  the client's `default_resource_id`. `openid` adds the UserInfo resource.
- **Default grants (APP-007).** A resource scope declared with `is_default: true`
  is requested on the client's behalf when a request names its resource (with
  `resource`, or through the client's `default_resource_id`) but none of that
  resource's scopes, for example `scope=openid&resource=https://orders.example`.
  Only defaults the client's resource grant lists are added; from then on they
  are requested scopes like any other: they are shown for consent and the user
  may decline them, they raise the transaction's assurance per
  [Scope step-up](#scope-step-up), and at every issuance the organization's
  scope ceiling and the scope's `required_permissions` apply. A default scope is
  therefore never issued where requesting it would not have been; it is left out
  silently instead of failing the request. A request that names any scope of a
  resource gets exactly what it names for that resource and no defaults, and
  protocol (OIDC) scopes are never added by default (`openid` must be requested).
  Defaults are resolved at authorization (authorization endpoint, PAR, headless
  start, device authorization) and for each client-credentials and `jwt-bearer`
  request; the authorization's grant then records them, so a refresh can narrow
  them but never adds defaults declared later. Token exchange keeps its own
  default, the exchange ceiling ([Token exchange](#token-exchange-rfc-8693)).
  A resource without default scopes, or whose defaults are all left out, is
  issued a token without scopes, as before (`TestDefaultScopeGrants`).
- **Each access token has exactly one audience.** At the token endpoint, at most one
  `resource` may be named; without one, the first resource of the grant is used. A
  client obtains tokens for another resource of the same grant by refreshing with
  `resource=<audience>` (RFC 8707 style).

### Scope step-up

A resource scope can demand stronger or fresher authentication (AUT-010,
migration `0028`, `TestScopeStepUp` in `tokens_test.go`). It is declared with the
scope (`POST /resources/{resource}/scopes`, or in a resource's `scopes`):

| Member | Values |
| --- | --- |
| `step_up_acr` | `urn:proudauth:acr:mfa` or `urn:proudauth:acr:phishing_resistant`; anything else is `422` |
| `max_auth_age_seconds` | 0 (no limit) or 60–86400 seconds |

A scope with `sensitivity: privileged` and no `step_up_acr` requires
`urn:proudauth:acr:mfa`.

- **At authorization** (authorization endpoint, PAR, headless start, device
  flow): the strongest `acr` the requested scopes require is added to the
  transaction's `acr_values`, and `max_age` is lowered to the shortest
  `max_auth_age_seconds`. The usual rules then apply (see
  [Sessions, prompt and assurance](#sessions-prompt-and-assurance)): MFA becomes
  mandatory, an SSO session that is not recent enough is not reused, a remembered
  device cannot skip the MFA prompt, and with `prompt=none` the request fails
  instead of completing at lower assurance. A user without a second factor is
  asked to enroll one.
- **At issuance** (authorization code, device code and refresh): a scope is left
  out of the access token when the grant's `acr` ranks below the scope's
  requirement or its `auth_time` is older than the scope's
  `max_auth_age_seconds`; the response's `scope` lists what was issued, and other
  scopes are unaffected. A refresh after the age limit therefore keeps the
  ordinary scopes and drops the sensitive one. To regain it, the client sends a
  new authorization request; the existing session is stepped up, never
  downgraded.
- If the realm cannot produce the required assurance (for example
  `phishing_resistant` while passkeys are not enabled), the transaction completes
  with MFA and the scope is then left out of the token.
- Token exchange applies it to the subject token's own `acr` and `auth_time`:
  an explicitly requested scope that falls short is `invalid_scope`, and the
  default ceiling drops such scopes ([Token exchange](#token-exchange-rfc-8693)).
  API keys and personal access tokens never carry step-up scopes, since they
  hold no authentication event.

## Token endpoint

| Grant | Behavior |
| --- | --- |
| `authorization_code` | Requires `code`, `code_verifier` (43–128 characters), `redirect_uri` (exact). The code is single-use and bound to client, redirect, PKCE challenge, transaction and, when the request named `dpop_jkt`, a DPoP key; valid 60 s. Presenting a used code again revokes the grant and everything issued from it and fails with `invalid_grant`. A binding failure also revokes the grant. Returns access token, refresh token (if the client has the refresh grant), ID token (if `openid`). |
| `refresh_token` | Rotation with reuse detection ([ADR 0011](../architecture-decisions/0011-refresh-token-families.md)); `fapi2` clients keep the same refresh token ([FAPI 2.0](#fapi-20-security-profile-adv-001)). A family whose first issuance was bound to a DPoP key or a TLS client certificate is refreshed only with a proof of the same key or the same certificate ([sender-bound refresh tokens](#dpop-rfc-9449)). `scope` may only narrow; scopes whose step-up policy the grant no longer meets are left out ([Scope step-up](#scope-step-up)). Live re-checks of user, client, session, organization and membership. |
| `client_credentials` | Confidential client with a service principal; `resource` must resolve to exactly one business resource (account and UserInfo audiences are refused); `organization` must be allowed for the service principal; no refresh token. |
| `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628 polling: `authorization_pending`, `slow_down` (interval +5 s when polled faster than the interval, initial 5 s), `access_denied`, `expired_token`; single redemption; client-bound. Device authorization counts against the requesting network's budget (`security.rate_limits.device_per_network`, 300 per `login_window`) before the client is authenticated, and wrong user codes entered for approval against `user_code_failures_per_network` (30 per `login_window`), after which the network's lookups answer `429 rate_limited` ([headless-authentication.md](headless-authentication.md#device-flow)). |
| `urn:ietf:params:oauth:grant-type:token-exchange` | See below. |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | Workload federation (RFC 7523 §2.1): see below. |

- Budgets ([owner decision 9](../releases/2026-10-alpha.6-decisions.md),
  SEC-006): before client credentials are checked and before anything is
  audited, every request reads the requesting network's failure budget
  (`security.rate_limits.token_failures_per_network`, 300 failed requests
  per `token_window` per IPv4 address or IPv6 /64, with the wider /24 or
  /48); a network that has spent it is refused. A request that fails, a
  failed client authentication included, counts against it; successful
  requests never do. Then a confidential client's request counts against
  `security.rate_limits.token_per_client` (2000 per `token_window`). A public
  client authenticates with its `client_id` alone, so only its failed grants
  count against `token_per_client` (`invalid_request`, `invalid_grant`,
  `invalid_client`, `invalid_scope`, `invalid_target`, `unauthorized_client`,
  `unsupported_grant_type`, `invalid_dpop_proof`; not device-flow polling
  answers), and each network's failed grants through it against
  `token_per_network_client` (100), so one network cannot spend the client's
  budget for its other users. Every spent budget returns `429 slow_down` with
  `Retry-After`; a limiter that cannot be reached returns `503
  temporarily_unavailable`. Tokens bound to an
  organization also count against that organization's budget
  (`security.rate_limits.organization_per_window`, TEN-018), so one tenant
  cannot use up issuance for the others
  (`TestTokenEndpointNetworkBudgets`,
  `TestPublicClientTokenBudgetCountsFailedGrants`).
- Responses: `access_token`, `token_type`, `expires_in`, `scope`, optional
  `refresh_token`, `id_token`, `issued_token_type`. `token_type` is `DPoP`
  for a token bound to a DPoP key (`cnf.jkt`) and `Bearer` for every other
  token, certificate-bound tokens (`cnf.x5t#S256`, RFC 8705 §3) included;
  this holds for every grant, token exchange included. All responses are
  `Cache-Control: no-store`.
- Errors use RFC 6749 JSON (`error`, `error_description`); `invalid_client` adds
  `WWW-Authenticate: Basic`.
- Administrative audiences (`I/admin`) require that the session holds MFA evidence
  and is not recovery-restricted.

### Token exchange (RFC 8693)

- Confidential clients only. `subject_token_type` must be
  `urn:ietf:params:oauth:token-type:access_token`; `requested_token_type`, if given,
  the same. `actor_token` is rejected: the authenticated client is the actor.
- The subject token must be a JWT access token of this realm (`user_access` or
  `exchange_access`); support tokens, service tokens, opaque tokens and ID tokens are
  refused.
- Its signed `grant_id` must identify a live, unexpired grant of this user and
  realm. Exchanges retain that originating link, so revoking the grant stops
  further exchanges and makes its already exchanged descendants inactive online.
- Exactly one target (`resource` or `audience`), which must be an active business
  resource for which the client's resource grant lists the subject token's audience
  in `exchange_policy.accept_from_audiences` (TEST-038).
- Scope is limited to the grant's allowed scopes intersected with
  `exchange_policy.max_scopes` (a requested scope beyond that is
  `invalid_scope`: "scope X exceeds the exchange ceiling").
- The organization's scope policy applies as at every other issuance: scopes
  outside the subject token's organization `allowed_scopes`, and scopes whose
  `required_permissions` the subject does not hold there, are refused when
  requested (`invalid_scope`) and left out of the default ceiling (OIDC
  scopes are not subject to the organization ceiling). When nothing remains,
  the request fails with `invalid_scope` ("no scope is available for this
  exchange"); a token without scopes is never issued.
- When the client the subject token was issued to has `consent_mode:
  required` and is not a machine client, the exchanged token carries only
  scopes the user's live consent for that client covers: a requested scope
  outside it is `invalid_scope` ("a requested scope is outside the user's
  consent for the originating client"), and the default ceiling is narrowed to
  it (TOK-008). In practice this is the first hop, from the user's own client;
  a token from an earlier exchange names the machine client that exchanged it,
  and is bounded by the exchange policies and grants of each hop instead.
- The new token has `token_kind: exchange_access`, the subject's `sub`, `org_id` and
  `sid`, an `act` claim naming the client's service principal (or client ID) with
  nested prior actors, at most `tokens.exchange_max_chain_depth` (2) levels
  (a deeper chain is `invalid_grant`, "delegation chain too deep"), and an
  expiry no later than the subject token's. No refresh token. When the
  client's service principal is an agent (MCH-017), `act` also carries
  `agent: true`; the token itself has no top-level `agent` claim, because its
  subject is the user.
- Each exchange records the audit event `token.exchanged` (AUD-005): the actor
  is the client's service principal (`service_principal`, an agent's included),
  or the client when it has none; the subject is the user; `client_id` and
  `metadata.client_ref` name the exchanging client and
  `metadata.subject_client_id` the client the subject token was issued to.
  `metadata.actor_chain` keeps the new token's whole `act` chain, outermost
  first, including the actors of the subject token's own `act` claim (`sub`,
  `iss`, `agent: true` for agents; at most 16 entries, with
  `actor_chain_truncated` beyond), with `chain_depth`, `from_audience`,
  `to_audience` and, for an agent, `agent: true`. Decisions about an exchanged
  token record the same chain
  ([policy decisions](../integrations/machine-clients.md#acting-on-behalf-of-a-user)).
- Service and support tokens are never exchanged as subjects (`invalid_grant`,
  "this subject token cannot be exchanged"), so a service cannot turn its own
  credential into user authority. This is the on-behalf-of model for services
  and agents (MCH-015): see
  [machine-clients.md](../integrations/machine-clients.md#acting-on-behalf-of-a-user).
- The subject token must have been issued to a registered client of the same
  environment as the presenting client (APP-015); otherwise `invalid_grant`
  ("the subject token was issued to a client of another environment").
- Scopes with a step-up policy are checked against the subject token's `acr`
  and `auth_time` ([Scope step-up](#scope-step-up)). A scope named in `scope`
  that falls short fails the request with `invalid_scope`. Without `scope`, the
  default (the ceiling) leaves such scopes out and issues the rest.
- Live checks: subject session, user and membership must be active.

### Workload federation (RFC 7523)

MCH-011..MCH-013, ADV-004, `TestWorkloadFederation`. A machine client with a
service principal and the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant
sends `assertion=<JWT>`: a token from an external workload identity issuer
(GitHub Actions, Kubernetes, SPIFFE, or any issuer of signed JWTs) that matches
one of the client's workload trusts (issuer, keys, exact audience, subject,
claim constraints, lifetime, single-use `jti`). The result is the same
`service_access` token as for `client_credentials`, never longer-lived than
the assertion. A refused assertion is `400 invalid_grant` ("the assertion was
not accepted"); the reason is audited as `workload.assertion.rejected`. The
assertion is never accepted as `client_assertion` (client authentication), and
never yields a user token. Trusts, profiles and verification:
[workload-federation.md](../integrations/workload-federation.md).

### PAR (RFC 9126)

- Authenticated clients push the authorization parameters to `I/oauth/par` and
  receive `request_uri` (`urn:ietf:params:oauth:request_uri:` + random) valid 60 s,
  single use, bound to the pushing client. `request_uri` inside a pushed request is
  rejected. The same validation as the authorization endpoint applies at push time.
- The `client_id` presented with a `request_uri` (at the authorization endpoint
  or the headless API) is resolved before the reference is touched, and the
  reference is consumed only for the client that pushed it: with another
  client's `client_id`, an unknown one or none the request is `400
  invalid_request` ("invalid or expired request_uri", the same answer as for an
  unknown or expired reference; "client_id is required with request_uri"
  without one) and the reference stays usable by its own client
  (`TestDeviceFlowAndPAR`).
- Clients with `token_policy.require_par` (always for `high_assurance` and
  `fapi2`) must use it; an authorization request without it is
  `invalid_request` ("this client must use pushed authorization requests").
- Every push reads the requesting network's failure budget
  (`security.rate_limits.par_failures_per_network`, 300 failed pushes per
  `token_window`) before the client is authenticated; a push that fails
  client authentication or validation counts against it, a successful one
  never does. A public client's pushes count against `par_per_client` (2000
  per `token_window`) from every network. A spent budget returns `429
  slow_down` with `Retry-After` (`TestPARAndDeviceNetworkBudgets`).
- A pushed request may name `dpop_jkt`, or carry a `DPoP` header (RFC 9449
  §10.1): the proof is verified like one at the token endpoint, with `htu`
  the PAR endpoint, and the code is bound to its key as if the request had
  named it in `dpop_jkt`. A `dpop_jkt` that names another key than the
  proof's is `400 invalid_request` ("dpop_jkt does not match the key of the
  DPoP proof"), and more than one `DPoP` header is `400 invalid_dpop_proof`
  (`TestDPoPBoundAuthorizationCodes`).
- The headless API also accepts `request_uri`, and `dpop_jkt`.

### DPoP (RFC 9449)

- A `DPoP` header at the token endpoint is verified: `typ: dpop+jwt`, embedded public
  JWK, asymmetric algorithm, exact case-sensitive `htm` and `htu` matching the token endpoint (query and
  fragment ignored), `iat` no more than 30 s ahead or 2 minutes old, `jti` unique per
  key (replay cache 5 minutes).
  Multiple proof headers, duplicate claims and case-shadowed required claims
  are refused (`TestDPoPBoundTokens`).
- The access token gets `cnf.jkt` and `token_type: DPoP` (from every grant
  that accepts a proof, token exchange included); clients with
  `require_dpop` must send a proof.
- **Sender-bound refresh tokens**
  (RFC 9449 §5, RFC 8705 §3; TOK-019, owner decision 13 of
  [the alpha.6 decisions](../releases/2026-10-alpha.6-decisions.md)): a
  refresh token family whose first issuance (authorization code or device
  code) was sender-constrained keeps that binding for its whole life,
  whatever the client's `require_dpop` or certificate setting says, now or
  later. The family stores the proof key's JWK thumbprint
  (`refresh_families.cnf_jkt`) or the certificate's SHA-256 thumbprint
  (`cnf_x5t_s256`, see [Mutual TLS](#mutual-tls-rfc-8705)), migration `0089`.
  Every refresh must then carry a DPoP proof signed with that key, or come
  over a connection presenting that certificate; a proof from another key,
  another certificate or none is `400 invalid_grant` ("refresh token is
  sender-constrained: ..."), also for a client without `require_dpop`,
  which before got a bearer token from a DPoP-bound family. The refusal is
  checked before reuse detection and is not a reuse signal: the token is
  neither rotated nor its family compromised, so someone who holds a stolen
  refresh token without the key cannot revoke the holder's family, grant
  and session through it; it is audited as `token.refresh.binding_failed`
  (outcome `denied`, reason `REFRESH_BINDING_FAILED`, metadata `binding`
  `dpop` or `mtls` and `proof` `missing` or `mismatch`). Rotation keeps the
  family and its binding, and `fapi2` clients, which keep one refresh
  token, are bound the same way. A family issued without a sender
  constraint, or before migration `0089`, stays unbound until it expires,
  and rotation never binds it later (`TestSenderBoundRefreshFamilies`).
- **Authorization codes bound to a DPoP key** (RFC 9449 §10): an
  authorization request at the authorization endpoint, in a pushed
  request (also by a `DPoP` header, see [PAR](#par-rfc-9126)) or through the
  headless API may name `dpop_jkt`. The code is then redeemed only with a
  DPoP proof of that key; another key or no proof is `400 invalid_grant`
  ("authorization code binding failed: ..."), and, as for the other code
  binding failures, the code is spent and its grant revoked. Codes without
  `dpop_jkt` are unchanged (`TestDPoPBoundAuthorizationCodes`). Discovery
  advertises nothing new: RFC 9449 defines no metadata for `dpop_jkt`.
- The IdP's own APIs (account, organization and administration) and UserInfo
  enforce the binding (TOK-019): a DPoP-bound token is accepted only with the
  `DPoP` scheme and a fresh proof for that request whose `htu` is the
  public-origin URL (`401` otherwise), and a token that is not bound is
  refused with the `DPoP` scheme. Device-code and token-exchange grants bind
  the token they issue to the proof of their own request.
- UserInfo answers these refusals with a DPoP challenge (RFC 9449 §7.1) that
  names the accepted proof algorithms: a DPoP-bound token presented with the
  `Bearer` scheme or with a proof signed by another key gets `401` with
  `WWW-Authenticate: DPoP error="invalid_token", error_description="...",
  algs="RS256 PS256 ES256 EdDSA"`; a missing, malformed, stale, replayed or
  mismatched proof (method, URI, `ath`) gets `DPoP
  error="invalid_dpop_proof"` with the same `algs`. An invalid token
  presented with the `DPoP` scheme gets `DPoP error="invalid_token"`; every
  other refusal keeps `Bearer error="invalid_token"`, and a request without
  credentials gets both a `Bearer` and a `DPoP algs="..."` challenge
  (`TestUserInfoDPoPChallenge`). The account, organization and
  administration APIs still answer these refusals as `401` problem details
  with a `Bearer` challenge.
- **Limits:** DPoP nonces (`DPoP-Nonce`, RFC 9449 §8 and §9) are not
  supported (deferred, issue #37). The Go resource SDK checks proofs through `SenderVerifier`; token-only
  methods in all SDKs reject bound tokens. Node.js, Dart and PHP have no
  request-level proof verifier ([resource profile](../integrations/resource-servers.md#sender-constrained-tokens)).
  Introspection returns `cnf` (also for opaque tokens) and `token_type: DPoP`
  for a DPoP-bound token (`Bearer` otherwise, also for certificate-bound
  tokens), so a resource server must verify the proof itself.

### Mutual TLS (RFC 8705)

TOK-019, MCH-014, migration `0056`, `TestMutualTLS` (`tests/e2e/mtls_test.go`).
Clients can authenticate with a TLS client certificate, and access tokens can
be bound to it. Deployment (how certificates reach the server):
[mutual-tls.md](mutual-tls.md).

- `tls_client_auth` (confidential and machine clients): the certificate must
  chain to an active **client** trust anchor of the realm and match exactly one
  of the client's `tls_client_auth_subject_dn` (compared with the subject in
  Go's RFC 4514 form), `tls_client_auth_san_dns`, `_san_uri`, `_san_email`
  (exact, case-sensitive) or `_san_ip`. No secret is issued.
- `self_signed_tls_client_auth`: the certificate must equal the first `x5c`
  certificate of one of the client's registered public keys, or match its
  `x5t#S256`, and be within its validity period.
- Certificate authentication applies only when the request carries no other
  client credential, and needs `client_id` in the form. Without a fitting
  certificate: `401 invalid_client`.
- `tls_client_certificate_bound_access_tokens: true`: every access token the
  client receives carries `cnf: {"x5t#S256": "<base64url SHA-256 of the
  certificate>"}`, from any grant (code, refresh, client credentials, device,
  token exchange, `jwt-bearer`), and opaque tokens keep it too. The token
  response names it `token_type: Bearer`: it is presented with the `Bearer`
  scheme, and the TLS connection proves the binding. A token
  request without a certificate is `400 invalid_request` ("this client's
  tokens are bound to its TLS client certificate; use the mutual-TLS
  endpoint"); a request with both a DPoP proof and a certificate binding is
  `400 invalid_request` ("use one sender constraint: DPoP or a TLS client
  certificate"). A client that requires DPoP and certificate binding at once
  can therefore get no token; registration does not refuse the combination.
- A refresh token family issued with a certificate-bound access token is
  bound to that certificate (`cnf_x5t_s256`): every refresh must present the
  same certificate, also after the client's
  `tls_client_certificate_bound_access_tokens` is turned off; another
  certificate or none is `400 invalid_grant`
  ([sender-bound refresh tokens](#dpop-rfc-9449),
  `TestSenderBoundRefreshFamilies`).
- The IdP's own APIs and UserInfo accept a certificate-bound token only on a
  connection presenting the same certificate (`401`, "this token is bound to
  a TLS client certificate; present it with the same certificate").
  Introspection returns `cnf`; resource servers must compare the thumbprint
  with the certificate of their own connection; Go `SenderVerifier` performs
  this check, while ordinary SDK token-only paths reject bound tokens.
- DPoP proofs must still name the public token endpoint (`htu`), not the
  mutual-TLS alias, and `private_key_jwt` assertions the issuer (`aud`).

## FAPI 2.0 security profile (ADV-001)

`TestFAPI2Profile` (`tests/e2e/fapi_test.go`). A client registered with
`security_profile: fapi2` follows a separate rule set modelled on the FAPI 2.0
Security Profile. **This is not certified by the OpenID Foundation, and no
conformance suite has been run** ([interoperability.md](../integrations/interoperability.md#conformance-claims)).

| FAPI 2.0 requirement | ProudAuth behavior for `fapi2` clients |
| --- | --- |
| Confidential clients only | `client_type: confidential` (`422` on `security_profile` otherwise) |
| Client authentication with `private_key_jwt` or mutual TLS | `private_key_jwt`, `tls_client_auth` or `self_signed_tls_client_auth` (`422`). Client assertions must be signed with `PS256`, `ES256` or `EdDSA`; an `RS256` assertion is refused at the token endpoint (`401 invalid_client`) |
| Client assertion audience is the issuer only | `aud` must be the realm's issuer as a single JSON string at the token, PAR and every other endpoint; an endpoint URL or an array is refused (`401 invalid_client`), whatever the realm's `client_auth.allow_endpoint_audience` says |
| Authorization code flow only | Grants `authorization_code` and `refresh_token` only (`422`); default both |
| Sender-constrained access tokens | `token_policy.require_dpop` or `tls_client_certificate_bound_access_tokens` is required (`422`) |
| Pushed authorization requests | `token_policy.require_par` is forced on; requests without PAR are refused. `request_uri` lives 60 s (as for every client) |
| PKCE with `S256` | Required for every client |
| `iss` in authorization responses (RFC 9207) | Always sent |
| Exact redirect URI matching, `https` | Exact matching for every client; `fapi2` redirect URIs must be `https` (`422` on `redirect_uris`) |
| Signing algorithms `PS256`, `ES256` or `EdDSA` | The realm's signing algorithm (`keys.signing_algorithm`) must be one of them when the client is registered or updated (`422`), and a signing-key rotation to another algorithm is refused (`409`) while the realm has `fapi2` clients; the default `RS256` is not |
| Short-lived authorization codes | At most 60 seconds, whatever `tokens.authorization_code_ttl` says |
| Access token lifetime | At most 10 minutes |
| Refresh tokens | Not rotated: the same refresh token stays valid until the family's idle or absolute expiry, the session ends or it is revoked; using it again is not treated as reuse (these clients are confidential, and their tokens and refresh token families are sender-constrained: every refresh must prove the DPoP key or certificate of the first issuance) |
| TLS 1.2 or later | The mutual-TLS listener requires TLS 1.2; the public listener and any proxy in front of it are the operator's to configure (Go's defaults allow TLS 1.2 and 1.3) |
| Message signing (optional part) | JARM is available ([response-security.md](response-security.md#jarm-adv-002)); signed request objects (JAR) are not supported, the `request` parameter is refused (`request_not_supported`) |

Organization switches: `POST /me/organization-grants` issues an
authorization code outside a pushed authorization request, so it is refused
for `fapi2` clients (and for every client whose `token_policy.require_par`
is set, `high_assurance` included): `403` ("this client must use pushed
authorization requests: switch organizations with a new pushed
authorization request naming the organization"). Such a client switches by
pushing a new authorization request with the `organization` parameter,
where PAR, the 60-second code lifetime and the other rules above apply.

## Introspection

- The caller authenticates as a confidential client and must be registered as an
  introspector for the token's audience
  (`POST /resources/{resource}/introspectors`). For any other token the response is
  `{"active": false}` with no further detail (TEST-037).
- Live checks as listed in [revocation-exposure.md](../operations/revocation-exposure.md#introspection-checks).
- Active responses include `iss`, `sub`, `aud`, `client_id`, `scope`, `exp`, `iat`,
  `jti`, `token_kind`, `token_type`, and as applicable `org_id`, `sid`, `auth_time`,
  `acr`, `act`, `cnf`, current `authz_version`, and `agent: true` for JWT and
  opaque tokens of an agent service principal (MCH-017; not for its API keys); support tokens add `act`,
  `support_mode` and `impersonation_grant_id`; API keys and personal tokens return
  `token_kind` `api_key` / `personal_access` and `subject_type`.
- Every introspection of a support token is audited (`support.token.introspected`).

## Revocation

- Any authenticated client (public clients authenticate with `client_id` only).
  The response is `200` whether or not the token existed or belonged to the caller.
- When the revocation cannot be recorded (the database write or, for a JWT,
  the `token.access.revoked` audit event, which commits in the same
  transaction, fails) the response is `503 temporarily_unavailable` with
  `Retry-After` (RFC 7009 §2.2.1) and the token stays valid: the client must
  retry. An unknown token or another client's token is never an error, so the
  `503` reveals nothing about the token (`TestRevocationStorageFailure`).
- Refresh token (`pa_rt_`): revokes the grant, its refresh families and opaque
  tokens, only if it belongs to the caller. Linked user/exchanged JWTs are then
  inactive at online consumers; unrelated grants and the SSO session survive.
- JWT access token: records the JTI as revoked if the token's `client_id` is the
  caller; the IdP's APIs and introspection then reject it. Offline verifiers do not.
- Opaque access token: revoked if it belongs to the caller.
- `token_type_hint` is ignored; the token prefix or format decides.

## UserInfo

Accepts only a `user_access` JWT whose audience is `I/userinfo` and whose scope
contains `openid` (business-audience tokens are rejected even if they contain
`openid`, OIDC-006). The session (if any), user, client and linked authorization
grant must be active; the grant must be unexpired and match the realm, user and
client. Returns
`sub` (public or pairwise) and claims for the token's scopes: `profile` → `name`,
`given_name`, `family_name`, `locale`, `zoneinfo`, `preferred_username`,
`updated_at`; `email` → `email`, `email_verified`; `phone` → `phone_number`,
`phone_number_verified`; `address` → `address` from the user profile. When the
most recent active authorization of the token's session for that client carried
a `claims` request with a `userinfo` member, the response is narrowed to those
claims (see [Claims parameter](#claims-parameter)). The response is unsigned JSON,
unless the client registered `userinfo_signed_response_alg` or
`userinfo_encrypted_response_alg` (OIDC-013): then it is `application/jwt`,
signed (`typ: userinfo+jwt`, with `iss` and `aud` added) and/or encrypted
([response-security.md](response-security.md#signed-and-encrypted-userinfo)).
A sender-constrained token must come with its DPoP proof or client certificate
([DPoP](#dpop-rfc-9449), [Mutual TLS](#mutual-tls-rfc-8705)).

## Logout

- **RP-initiated** (`I/oidc/logout`): parameters `id_token_hint`, `client_id`,
  `post_logout_redirect_uri`, `state`. The hint must be an ID token of the
  realm: signature and issuer are verified (expiry is not), `typ` must be
  `JWT` (an absent `typ` is refused), and it must have `sub`, `aud`, `exp` and
  `iat` and none of `code`, `error` and `state`. Other JWTs the realm key
  signs are refused with `400 invalid_request` ("invalid id_token_hint"),
  among them JWT-secured authorization responses (`typ: oauth-authz-resp+jwt`,
  which anyone can obtain from the authorization endpoint) and signed UserInfo
  (`typ: userinfo+jwt`). A `GET` without `id_token_hint` never ends the
  browser session (prevents silent logout CSRF); use `POST` or include the
  hint. A `GET` with a hint ends the cookie session only when the hint's `sid`
  is that session or its `sub` is the session user's subject at the hint's
  client (pairwise subjects included); any other hint is refused with `400
  invalid_request` ("id_token_hint does not match the browser session") and
  the session, its cookie and the clients' sessions are left alone, so a lured
  top-level navigation cannot log a user out with someone else's token
  (decision 15, `TestLogoutHintTypes`). A relying party that cannot present a
  matching hint uses `POST`. With `POST` and a session cookie, the cookie's
  session is ended unless the hint names a different session (`200` with
  `session_ended: false` then); without a cookie, the hint's `sid` session is
  ended. `post_logout_redirect_uri` must be registered for the client (named
  by `client_id` or the hint); otherwise `400 invalid_request`
  ("post_logout_redirect_uri is not registered", or "post_logout_redirect_uri
  requires client_id or id_token_hint"). It is checked **before** anything is
  revoked, so a bad redirect leaves the session intact. Response: `302` to the
  registered URI (with `state`), or `200 {"session_ended": bool,
  "upstream_logout": {...}}` without one; when clients registered
  front-channel logout, the page or JSON described
  [below](#front-channel-logout-ses-018) instead. Clients with encrypted ID
  tokens send the decrypted, signed ID token as `id_token_hint`.
- **`upstream_logout`** in every response describes the upstream provider
  session (FED-013): `{"provider": "<connection alias>", "status": ...}` with
  `status` `not_federated` (the session was not federated; no `provider`),
  `not_requested` (only the local session ended; the provider's session may
  remain), `redirect`, `unsupported` (the connection has no end-session
  endpoint) or `unavailable` (it could not be determined). The provider is
  the connection of the session's last federated factor.
- **Back-channel logout** (OIDC Back-Channel Logout 1.0): when a session is revoked
  for any reason, clients with `backchannel_logout_uri` that have a client session
  for it receive a POST with `logout_token`: a JWT with `typ: logout+jwt`, `aud` =
  client ID, `sub`, `sid`, `jti`, `iat`, `exp` (+2 min) and the
  `http://schemas.openid.net/event/backchannel-logout` event. Delivery goes through
  the egress policy, up to 8 attempts with backoff; a 2xx response marks it
  delivered.
- **Session management** (check-session iframe and `session_state`) is
  available per realm, off by default ([below](#session-management-oidc-014)).

### Session management (OIDC-014)

OpenID Connect Session Management 1.0, opt-in per realm,
`TestCheckSessionIframe` (`tests/e2e/checksession_test.go`). The extension is
claimed only for realms that turn it on; the session APIs (`/me/sessions`,
the session-event stream, back-channel logout) do not claim it.

- **Turning it on:** realm policy `sessions.check_session_iframe: true`
  (`PUT /settings`; default `false`). Discovery then lists
  `check_session_iframe` = `I/oidc/check-session` (when the logout endpoint is
  published), and every authorization response that carries a code includes
  `session_state`: sign-in completions, silent `prompt=none` completions and
  organization switches (`POST /me/organization-grants`). With JARM the
  parameter is inside the response JWT.
- **`session_state`** is
  `hex(SHA-256(client_id + " " + RP origin + " " + opbs + " " + salt)) + "." + salt`,
  where the RP origin is the origin of the request's `redirect_uri` and the
  salt is fresh for every response.
- **OP browser state (`opbs`)** is a keyed digest of the session ID under the
  deployment's lookup key; it is never the session cookie or secret. It is
  held in the cookie `pa_opbs` on path `/realms/<realm>/`, readable by scripts
  (not `HttpOnly`), `SameSite=None; Secure` on deployments with secure cookies
  (with `sessions.cookie_insecure_dev`, not `Secure` and `SameSite` per
  `sessions.cookie_same_site`). It is set on browser sign-in completion
  (including SAML sign-ins) and silent authorization, and cleared by
  RP-initiated logout.
- **The iframe** (`GET I/oidc/check-session`) has no visible content. Its
  `Content-Security-Policy` allows only its own inline script (by hash),
  `connect-src 'self'` and `frame-ancestors *` (it must be embeddable by any
  RP); it is cacheable for an hour. It answers a `postMessage` of
  `"<client_id> <session_state>"` with `"unchanged"`, `"changed"` or
  `"error"`, posted only to the sender's origin. The sender's origin must be
  one of the client's `allowed_origins` or the origin of one of its redirect
  URIs, and the client must be active; the iframe checks this with
  `GET I/oidc/check-session/origin?client_id=&origin=` (answers
  `{"allowed": bool}`, cached per page; at most 300 checks per minute per
  client address, then `429`). Other origins get `"error"`. Because
  the state is recomputed with the message's origin, a value copied to
  another origin never reads `"unchanged"`.

**Browser and protocol limitations.** Plan for them before relying on the
iframe:

- Browsers that block or partition third-party cookies (Safari Intelligent
  Tracking Prevention, Firefox Total Cookie Protection, Chrome with
  third-party cookies restricted or in private windows) hide `pa_opbs` from the
  iframe embedded in the RP's page, so **every check reports `changed`**. The
  RP then falls back to `prompt=none` re-authentication, which in such
  browsers may itself need a top-level navigation.
- Sessions ended on the server (administrator revocation, idle or absolute
  timeout, risk or emergency actions, revocations from shared signals) are
  **not visible** to the iframe: the cookie only changes when the browser
  reaches the provider. For prompt revocation use back-channel logout,
  front-channel logout, token introspection or the session-event stream.
- Rotating the root key that the lookup key derives from changes `opbs`, so
  every RP sees `changed` once.
- The script is tested by recomputing its algorithm in Go; it has not been
  run in real browsers ([interoperability.md](../integrations/interoperability.md#untested-claims)).

### Front-channel logout (SES-018)

OpenID Connect Front-Channel Logout 1.0, `TestFrontChannelLogout`
(`tests/e2e/frontchannel_test.go`). A client registers:

| Option | Rules |
| --- | --- |
| `frontchannel_logout_uri` | Must have the scheme, host and port of one of the client's registered redirect URIs (compared as written; default ports are not normalized) and pass the redirect URI rules: `https`, or `http` only for `localhost` and loopback hosts of non-production clients |
| `frontchannel_logout_session_required` | `true` adds `iss` and `sid` to the URI's query. Requires `frontchannel_logout_uri` (`422` otherwise) |

When the logout endpoint ends a session, the active clients that took part in
it (their client session is active) and registered a URI are listed, in
`client_id` order:

- A **browser** gets `200` `text/html` instead of the `302`: a "Signed out"
  page with one hidden iframe per URI and, when there is a post-logout
  redirect, `<meta http-equiv="refresh" content="2;url=...">` and a
  "Continue" link; without one, just the "signed out" text. Its
  `Content-Security-Policy` is `default-src 'none'; frame-src <the frame
  origins>; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`: the
  page runs no script and frames only those origins. When the redirect goes to
  an upstream provider's end-session endpoint (`upstream_logout=true`), the
  page continues there.
- A caller that sends `Accept: application/json` (and not `text/html`), such
  as an external login UI, gets `200 {"session_ended", "upstream_logout",
  "frontchannel_logout_uris", "redirect_to"}` and loads the URIs in frames
  itself before continuing to `redirect_to`.

Delivery is never confirmed. Browsers that block third-party cookies often
keep the client from seeing its own session inside the frame, so the
notification may do nothing. Back-channel logout remains the reliable
mechanism; use front-channel logout only in addition. Without front-channel
clients the endpoint behaves as before (`302` or JSON). A `GET` without
`id_token_hint` ends no session and so loads no frames. Frames are produced
only by the logout endpoint, not when a session is revoked elsewhere (an
administrator, a password reset, expiry).

### Upstream logout (FED-013)

Ending the local session never ends the user's session at an upstream
identity provider. A client can ask for both with the extension parameter
`upstream_logout=true` (query on `GET`, form on `POST`; `TestFederationAdapters`):

1. ProudAuth ends the local session as usual, then redirects (`302`) the
   browser to the connection's end-session endpoint: `config.end_session_endpoint`,
   or the one in the provider's discovery document (not discovered for
   multi-tenant connections, which need it configured). The request carries
   `client_id` (ProudAuth's client at the provider),
   `post_logout_redirect_uri` = `I/oidc/logout/upstream-return` and a sealed
   `state` valid for 15 minutes; no `id_token_hint`, because upstream tokens
   are never stored. Register that return URI at the provider.
2. The provider sends the browser to `I/oidc/logout/upstream-return?state=...`,
   which redirects to the client's `post_logout_redirect_uri` with its `state`
   and `upstream_logout=returned`, or answers
   `{"session_ended": true, "upstream_logout": {"status": "returned"}}` when
   the client gave none. A forged or expired `state` is `400 invalid_request`,
   and so is a `state` used a second time ("state already used"): each
   return is accepted once. `returned` means the browser came back, not that
   the provider ended its session.
3. When no upstream redirect is possible, the client's redirect carries
   `upstream_logout=unsupported` or `unavailable` instead.

`session.logout` audit events of federated sessions record
`upstream_provider` and `upstream_logout_requested`.

## Upstream identity providers

ProudAuth is also a client of upstream providers (FED-*,
`internal/federation`); connections are realm data managed at
`/api/v1/realms/{realm}/identity-providers` and, for organization-scoped
connections, under `/organizations/{org}/identity-providers`. The sign-in
flow is in [headless-authentication.md](headless-authentication.md#upstream-identity-providers).
Each connection names an `adapter`, which fixes the protocol and what the
provider's assertions mean (FED-002, `TestFederationAdapters`):

| `adapter` | Protocol | Defaults and rules | Email |
| --- | --- | --- | --- |
| `oidc` (default) | OpenID Connect | `issuer` required; scopes `openid email profile` | `email_verified` from the provider is believed |
| `github` | OAuth 2.0 with the GitHub API | Issuer `https://github.com`, GitHub's endpoints and API; scopes `read:user user:email`; the subject is the numeric account ID | Only the primary, verified address from the API |
| `google` | OpenID Connect | Issuer fixed to `https://accounts.google.com`; with `config.allowed_tenants` (Workspace domains) the tenant claim is `hd`, so consumer accounts are refused; scopes `openid email profile` | `email_verified` is believed only where Google is authoritative for the address: a `gmail.com` or `googlemail.com` address, or an ID token whose `hd` claim equals the address's domain (case-insensitively). `hd` is read from the ID token whether or not `allowed_tenants` is set. Any other address (a consumer Google account registered with a corporate address, or a Workspace account of another domain) counts as unverified: it never links through `trusted_verified_email` and a just-in-time account keeps it unverified. A Workspace secondary domain (an alias domain that is not `hd`) is treated the same way |
| `microsoft` | OpenID Connect (Entra ID work and school accounts) | Issuer `https://login.microsoftonline.com/{tenant}/v2.0` with `multi_tenant_issuer` and tenant claim `tid` always set; `config.allowed_tenants` (tenant IDs) required; endpoints default to the `organizations` authorize and token endpoints and the `common` JWKS. Subjects are pairwise per application | **Never treated as verified** (the claim is a mutable attribute), so `trusted_verified_email` linking is refused (`422`) and just-in-time accounts keep the address unverified |

An unknown adapter is `422` on `adapter` (the message lists the registered
ones). Operators who build their own binary can add adapters with
`federation.RegisterAdapter` (name, protocol, whether email assertions are
trusted for linking, defaults and checks, identity resolution); an adapter
whose email assertions are not trusted never yields a verified email. The
generic `oidc` adapter has signed users in through a real provider, Keycloak
26.8.0 ([interoperability.md](../integrations/interoperability.md#keycloak-2680-protocol-profiles));
the `google`, `microsoft` and `github` adapters only through test doubles
([interoperability.md](../integrations/interoperability.md#untested-claims)).

The connection's `kind` (`oidc`, or `oauth2_social` for adapters that are not
OpenID Connect) follows the adapter, also when `PUT /identity-providers/{id}`
changes it (FED-016). While identities are linked to a connection, changing
its issuer or changing the adapter to one of another protocol is refused with
`409` (field `issuer` or `adapter`, "cannot change while identities are
linked; use a reviewed migration").

Just-in-time accounts (REG-009) never take over an address: an upstream
email that the provider does not mark verified and that another account has
already verified is not copied to the new account, which then gets a
generated username (`<alias>-<login or subject>`).

An organization-scoped connection (OIDC, social or SAML) speaks for its
organization only, while the accounts it creates are realm-wide. Its
upstream's verified email therefore counts only when the address's domain
is one of the organization's verified domains (or a subdomain of one
verified with `include_subdomains`; TEN-010, TEN-011), the rule SCIM
provisioning follows. Outside them a just-in-time account keeps the address
unverified with the `verify_email` required action (dropped instead when
another account has verified it), so the account proves the address before
it signs in, and the audit event `user.created` records
`email_verified: false`. An organization administrator enables
`jit_provisioning` on `/organizations/{org}/identity-providers` only with a
non-empty `config.allowed_email_domains` whose every domain is a verified
domain of the organization; otherwise `POST` and `PUT` answer `422` on
`config.allowed_email_domains` ("just-in-time provisioning requires the
organization's verified domains to be listed", or "... is limited to the
organization's verified domains"). Realm administrators may still create an
organization-scoped connection without that list; the sign-in rule above
then still applies. Connections saved by an earlier release keep working
until they are next updated; see
[incidents.md](../operations/incidents.md#federation-created-verified-addresses-outside-an-organizations-domains)
for finding accounts they created before the rule existed. A generated username
that is taken gets a random suffix instead of failing the sign-in (after
three taken suffixes the sign-in stops with `account_conflict`).

## Discovery document

Published members (values reflect configuration):
`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
`userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`,
`end_session_endpoint`, `device_authorization_endpoint`,
`pushed_authorization_request_endpoint`, `require_pushed_authorization_requests:
false`, `response_types_supported: ["code"]`, `response_modes_supported:
["query", "query.jwt", "jwt"]`, `grant_types_supported` (authorization code, refresh, client
credentials, device code, token exchange, `jwt-bearer`; a grant type the realm has disabled
with an emergency control is left out, OIDC-015, while
`device_authorization_endpoint` stays published; `jwt-bearer` has no
emergency control), `subject_types_supported: ["public",
"pairwise"]`, `id_token_signing_alg_values_supported` (algorithms of published
keys), `userinfo_signing_alg_values_supported` (`"none"` and the algorithms of
published keys), `authorization_signing_alg_values_supported`, the
`id_token_`, `userinfo_` and `authorization_` `encryption_alg_values_supported`
and `encryption_enc_values_supported` lists
([response-security.md](response-security.md#discovery)), token, introspection and
revocation endpoint auth methods (with `tls_client_auth` and
`self_signed_tls_client_auth` when client certificates can reach the server),
`token_endpoint_auth_signing_alg_values_supported`,
`code_challenge_methods_supported: ["S256"]`, `scopes_supported` (OIDC scopes only;
resource scopes are not listed), `claims_supported`, `claims_parameter_supported:
true`, `request_parameter_supported: false`, `request_uri_parameter_supported`
(`true` when PAR is enabled), `require_request_uri_registration: false`,
`prompt_values_supported`, `acr_values_supported`,
`authorization_response_iss_parameter_supported: true`,
`tls_client_certificate_bound_access_tokens` (`true` when `server.mtls_listen`
or `server.client_cert_header` is set), `mtls_endpoint_aliases` (with
`server.mtls_origin`: token, introspection, revocation, UserInfo, PAR and
device authorization endpoints on that origin; [mutual-tls.md](mutual-tls.md)),
`frontchannel_logout_supported: true`, `frontchannel_logout_session_supported:
true`, `backchannel_logout_supported: true`,
`backchannel_logout_session_supported: true`, `dpop_signing_alg_values_supported`,
and `check_session_iframe` only for realms with
`sessions.check_session_iframe` ([Session management](#session-management-oidc-014)).
No `service_documentation` member is published.

`registration_endpoint` (`I/oauth/register`) is published only while the realm
enables dynamic client registration ([Dynamic client registration](#dynamic-client-registration-rfc-7591-7592)).

## Dynamic client registration (RFC 7591, 7592)

APP-016, APP-017, ADV-003. Off by default; realm policy
`client_registration` enables it. `POST I/oauth/register` registers a
third-party client that asks for consent, authorized by an initial access
token an administrator issued (`pa_iat_`, bound to the non-privileged scopes
the client may receive) or, with `open` registration, by nothing (the client
is then held for an administrator's approval). The response carries a
registration access token (`pa_rat_`) for `GET`, `PUT` and `DELETE` on
`I/oauth/register/{client_id}`. `jwks_uri` and software statements are refused,
and no client metadata URL is ever fetched. Budgets:
`security.rate_limits.dcr_per_network` (20) registrations per network per
`dcr_window` (1 hour), counted before the request is authenticated, and 500
per realm per hour. Details:
[dynamic-client-registration.md](../integrations/dynamic-client-registration.md).

## Not supported

Implicit and hybrid flows; resource-owner password grant; `response_mode`
`fragment`, `form_post`, `fragment.jwt` and `form_post.jwt`; JAR (`request`
objects); response encryption with `RSA1_5`, `RSA-OAEP` (SHA-1) or CBC-HMAC
content encryption; client `jwks_uri`; software statements in dynamic
registration; CIBA; JWT bearer assertions that represent users (RFC 7523
`jwt-bearer` issues service tokens only); DPoP nonces. OIDC Session
Management is opt-in per realm and limited by browsers
([Session management](#session-management-oidc-014)). For the P3 items that
are deliberately not offered (push approval, CIBA, UMA, verifiable
credentials, JAR) and the reasons, see
[compatibility.md](compatibility.md#capabilities-not-offered).
