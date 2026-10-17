# API compatibility and deprecation

This page states what ProudAuth promises to API clients, SDK users and event
consumers when it changes, and how it announces changes that need client work
(API-013).

## Versioned surfaces

| Surface | Version marker | Where it is described |
| --- | --- | --- |
| Management and interaction API | Path prefix `/api/v1/` | [api/openapi/proudauth.yaml](../../api/openapi/proudauth.yaml) |
| OAuth 2.0 / OpenID Connect endpoints | Protocol standards; capabilities in discovery | [oauth-oidc-profile.md](oauth-oidc-profile.md), `/.well-known/openid-configuration` |
| Webhook and session-stream events | `event_type` plus `event_version` in every envelope; each webhook subscription chooses its `event_version` (1 or 2) | [api/events](../../api/events/README.md), [extension-contracts.md](../integrations/extension-contracts.md) |
| Pre-action hook requests and responses | The hook's `contract_version`, sent as `ProudAuth-Hook-Version` | [api/hooks](../../api/hooks/README.md) |
| Plugin packages | `manifest_version` | [api/plugins](../../api/plugins/manifest.v1.json), [plugins.md](../integrations/plugins.md) |
| Lifecycle workflow definitions and step calls | `schema_version`; the step call's `contract_version` | [api/workflows](../../api/workflows/definition.v1.json), [workflows.md](../integrations/workflows.md) |
| Problem responses | `type` URI and stable `code` | [api/openapi/proudauth.yaml](../../api/openapi/proudauth.yaml) (`Problem`) |
| Configuration documents | `format: proudauth.realm-config.v1` | [api/schemas/config-document.schema.json](../../api/schemas/config-document.schema.json) |
| Deployment configuration | YAML keys checked against the binary | [api/schemas/config.schema.json](../../api/schemas/config.schema.json), [configuration.md](../operations/configuration.md) |
| Database schema | Numbered migrations with expand/contract markers | [upgrades.md](../operations/upgrades.md) |

There is one supported management API version, `v1`. A future `v2` would be
served next to `v1` for at least the deprecation window below.

## Changes that do not need client work

Within `v1` and within an event's `event_version`, releases may:

- add endpoints, optional request members, response members and response
  headers;
- add event types and optional members of an event's `data`;
- add values to fields documented as open sets (problem `code`, audit event
  types, security signal names, `next_actions` types);
- tighten validation of input that was already documented as invalid;
- change the order of members and of unordered list items.

Clients must ignore response members and event members they do not know, must
not depend on member order, and must treat unknown enum values of open sets as
"other".

## Changes that need client work

Removing or renaming an endpoint, member or event; making an optional request
member required; changing a member's type or meaning; or changing an error a
client is expected to handle is a breaking change. ProudAuth makes one only:

1. with a new version (`/api/v2/`, a new `event_version`) served alongside the
   old one, or
2. after a deprecation period, except for security fixes (below).

### Deprecation process

- The change is announced in the CHANGELOG under **Deprecated**, naming the
  replacement and the earliest removal release.
- The operation is marked `deprecated: true` in the OpenAPI document and its
  description names the replacement. No operation is deprecated today; the
  server does not send `Deprecation` or `Sunset` headers yet.
- The minimum window between the first release that announces a deprecation
  and the release that removes it is **two minor releases and at least six
  months**.
- Removal is listed in the CHANGELOG under **Removed** with the upgrade steps
  clients need.

### Security exceptions

A change that removes insecure behavior may skip the window. When the risk
allows, it ships first behind a realm or operator setting with the secure
behavior as an opt-in, announced in the CHANGELOG under **Security fixes** with
the client upgrade needed; when the behavior is being exploited or cannot be
made safe, it changes in the next release. Examples in the current development
history: `PATCH /organizations/{org}` now requires `If-Match` when it changes
`policy` (API-010), and webhook destinations are checked against the egress
policy at registration.

## Protocol options

Newer OAuth and OpenID Connect capabilities are opt-in, per client or per
realm, so existing clients keep their behavior:

| Capability | Turned on by | Effect on clients that do not use it |
| --- | --- | --- |
| Encrypted ID tokens, signed or encrypted UserInfo (TOK-020, OIDC-013) | Client options `id_token_encrypted_response_*`, `userinfo_*_response_*` | None; UserInfo stays `application/json` |
| JARM (ADV-002) | `response_mode=query.jwt` or `jwt` per request | None; plain query responses remain the default |
| Front-channel logout (SES-018) | Client option `frontchannel_logout_uri` | The logout endpoint answers a browser with an HTML page (`200`) instead of a `302` only when a client that took part in the session registered a URI; JSON callers get two more members |
| Mutual TLS and certificate-bound tokens (TOK-019, MCH-014) | Operator `server.mtls_listen` or `server.client_cert_header`, then client options | None |
| FAPI 2.0 rule set (ADV-001) | Client `security_profile: fapi2` | None |
| Workload federation (MCH-011) | Machine client grant `jwt-bearer` and workload trusts | None |
| Dynamic client registration (APP-016) | Realm policy `client_registration.enabled` | None; no `registration_endpoint` until enabled |
| OIDC Session Management (OIDC-014) | Realm policy `sessions.check_session_iframe` | None; `check_session_iframe` and the `session_state` response parameter appear only in realms that turn it on (clients must ignore unknown response parameters) |
| Shared signals transmitter (AUD-016) | Realm policy `shared_signals.enabled` | None; metadata and stream endpoints answer `404` until enabled |

Discovery changed compatibly: `response_modes_supported` now lists
`query.jwt` and `jwt`, `userinfo_signing_alg_values_supported` lists the
realm's algorithms after `"none"`, `grant_types_supported` lists
`jwt-bearer`, `frontchannel_logout_supported` and
`frontchannel_logout_session_supported` are `true`, and encryption,
authorization-signing and mutual-TLS members were added
([oauth-oidc-profile.md](oauth-oidc-profile.md#discovery-document)). Clients
must ignore members and values they do not use.

Coordinate a change of the realm's signing algorithm (`keys.signing_algorithm`
for new realms, `POST /signing-key-rotations` with `algorithm` for an existing
one)
with clients that registered `userinfo_signed_response_alg` or
`authorization_signed_response_alg` (responses are always signed with the
active key, and such a client cannot be updated until its value matches) and
with `fapi2` clients, which need `PS256`, `ES256` or `EdDSA`
([response-security.md](response-security.md#client-options)).

Validation that was tightened as a security fix, without a deprecation
window: every `aud` value of a `private_key_jwt` client assertion must name
this server (an assertion also addressed to another party is refused), and
`post_logout_redirect_uri` is checked before the session ends.

## Events

An event type's payload changes compatibly within its `event_version`. Every
event type exists in versions 1 and 2, which differ only in the envelope
(version 2 names the organization `organization_id` and states the
`payload_form`); each webhook subscription chooses the version it receives,
and version 1 stays the default. A breaking change introduces a new
`event_version` and keeps delivering the old one to the subscriptions that
chose it for at least 12 months after the new version is published (the
support window of the extension contracts, longer than the API deprecation
window below; [extension-contracts.md](../integrations/extension-contracts.md)).
Consumers deduplicate by `event_id` and must not rely on delivery order.

Pre-action hooks, plugin manifests and lifecycle workflow definitions are
versioned the same way, each independently of the others and of server
releases: a hook pins its `contract_version`, a plugin its
`manifest_version`, a workflow definition its `schema_version`.

## SDKs

The Go, Node.js, Dart and PHP SDKs follow the API: they gain methods for new endpoints in
minor releases, keep deprecated methods working for the deprecation window and
mark them deprecated in their documentation. Their administration clients
report the `Deprecation` and `Sunset` headers of deprecated operations to a
callback (`OnDeprecated` in Go, `onDeprecated` in the others). Runtime support, SDK versioning,
breaking changes and the security-update policy are in
[sdk-compatibility.md](../integrations/sdk-compatibility.md).

## Database and configuration

Database migrations are expand-only unless marked
`-- proudauth:compat=contract`; contract migrations need the operator's backup
reference and are announced in the CHANGELOG with the release that may run
them. Deployment configuration keys are never silently ignored: an unknown key
or a malformed environment override stops the process, and
`identity-cli config-diff` shows the effect of a configuration change before
rollout.

## Declared protocol profiles

Some optional protocol extensions are offered as declared profiles: a named
specification version, opt-in per realm, with what is and is not implemented
listed. They are internal-test claims only; no conformance suite has been run
([interoperability.md](../integrations/interoperability.md#conformance-claims)).

| Profile | Version declared | Turned on by | Where it is described |
| --- | --- | --- | --- |
| OpenID Connect Session Management (OIDC-014) | 1.0 (check-session iframe and `session_state`) | Realm policy `sessions.check_session_iframe` | [oauth-oidc-profile.md](oauth-oidc-profile.md#session-management-oidc-014) |
| Shared Signals transmitter (AUD-016) | OpenID Shared Signals Framework 1.0 (`spec_version` `1_0`), CAEP 1.0 and RISC 1.0 event types listed there, RFC 8417 tokens, RFC 8935 push, RFC 8936 poll (no long polling), RFC 9493 subject identifiers | Realm policy `shared_signals.enabled` | [shared-signals.md](../integrations/shared-signals.md#transmitter-aud-016) |
| Shared Signals receiver (ADV-007) | RFC 8935 push from registered transmitters; CAEP and RISC event types with an explicit action policy | Registering a transmitter | [shared-signals.md](../integrations/shared-signals.md#receiver-adv-007) |
| Distribution token authentication (ADV-010) | Docker Registry v2 token server, `GET` with `repository` scopes only | Configuring a registry service | [container-registry.md](../integrations/container-registry.md) |
| WebAuthn Level 3 related origins (PASS-010) | §5.11 related origin requests and `/.well-known/webauthn` | Operator switch `webauthn.related_origins` and realm policy | [passkey-trust.md](../operations/passkey-trust.md#related-origins-pass-010) |

A newer version of one of these specifications would be added as a new
declared profile next to the old one, under the rules above.

## Capabilities not offered

The specification lists these capabilities as optional (the P3 extensions,
JAR and a gRPC management interface). They are **not offered**, and nothing in the product presents something else as them
(APP-020). Each entry says why and what an implementation would have to
provide before it could be offered.

| Capability | Why not | What an implementation must provide | Use instead |
| --- | --- | --- | --- |
| Push or out-of-band approval (MFA-014) | Needs a device-enrollment channel (push credentials for APNs or FCM, an authenticator app), number matching, anti-fatigue rate limits and display of the operation's context. A bare approve/deny prompt invites push-fatigue attacks | Explicit device enrollment and removal; transaction binding (number matching or code display); anti-fatigue controls (rate limits, lockout, reporting); the full context of privileged operations shown on the device; no blind approve/deny | Passkeys (phishing-resistant), TOTP and HOTP, email and SMS codes |
| CIBA (ADV-005) | Requires the same authentication-device channel as MFA-014, with user-visible binding messages. A generic webhook that asks some other system to approve is not CIBA and is not presented as such | An authenticated initiator, a user-identification policy (`login_hint` and the alternatives), transaction expiry, poll/ping/push mode rules, a user-visible `binding_message`, anti-fatigue controls, discovery entries only once complete | The device authorization grant (RFC 8628) for input-constrained devices |
| User-managed access, UMA 2.0 (ADV-006) | Resource ownership, permission tickets, requesting-party claims and resource-server responsibilities are not modelled | A version-pinned UMA profile with resource registration, ownership, consent, delegation, permission tickets, revocation and resource-server obligations defined | Relationship tuples and sharing within organizations (AZ-021..AZ-027, [relationship-authorization.md](../integrations/relationship-authorization.md)); [partner project access](../integrations/partner-access.md) |
| Verifiable credential issuance (ADV-008) | Requires credential-issuer keys isolated from token signing, credential configurations, subject eligibility, status lists and holder binding (OpenID4VCI, SD-JWT VC or another named format) | Separate issuer keys and metadata, named and versioned formats, authorized claims per credential configuration, wallet binding, a status or revocation strategy | — |
| Credential presentation and wallet federation (ADV-009) | Verifier trust, holder binding, replay protection, selective disclosure and status checks need their own design (OpenID4VP) | Trusted issuer lists, holder binding and nonce checks, a selective-disclosure policy, status checks, and an explicit identity-linking authority. Possession of an external credential must never create an account or a membership by itself | Upstream federation with explicit linking policies |
| Signed request objects, JAR (RFC 9101) | Not implemented: `request_parameter_supported` is `false` and `request` is refused with `request_not_supported` | Request-object signature verification with registered client keys, audience and replay checks, precedence rules between request-object and query parameters, and `request_uri` fetching policy | Pushed authorization requests (RFC 9126), which protect the integrity of authorization requests ([oauth-oidc-profile.md](oauth-oidc-profile.md#par-rfc-9126)) |
| gRPC management interface (API-014) | Optional in the specification; every administration operation is served by the HTTP API, and a second transport would be a second path to keep equal in authorization and audit | The same domain services, permission checks, idempotency and audit as the HTTP handlers, with no route the HTTP API lacks | The HTTP administration API (`api/openapi/proudauth.yaml`) and the SDK administration clients. Resource servers can still authenticate gRPC calls with ProudAuth tokens ([patterns.md](../integrations/patterns.md)) |
