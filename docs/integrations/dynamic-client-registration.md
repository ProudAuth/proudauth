# Dynamic client registration

Requirements: APP-016, APP-017, ADV-003 (RFC 7591, RFC 7592). Code:
`internal/application/dcr.go`, `internal/httpapi/dcr.go`, migrations `0052`
and `0090`. Tests: `TestDynamicClientRegistration` and
`TestDynamicRegistrationReapproval` (`tests/e2e/dcr_test.go`),
`TestDynamicClientRegistrationBounds` (`tests/e2e/dcr_bounds_test.go`) and
`TestReviewedChanges` (`internal/application`).

Dynamic registration lets software register its own OAuth client at
`/realms/{realm}/oauth/register` instead of asking an administrator to create
it. It is **off by default**. A realm turns it on, and an administrator then
decides who may register: holders of an initial access token, or anyone
(open registration, always held for approval). Registered clients are
third-party clients that ask users for consent; they never get privileged
scopes, first-party status, offline access or administrative audiences.

## Enabling it

Realm policy `client_registration` (`PUT /api/v1/realms/{realm}/settings`, or a
configuration import):

| Member | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Without it the registration and management endpoints answer `404` and discovery has no `registration_endpoint` |
| `open` | `false` | Registration without an initial access token is accepted; such clients are always held for approval |
| `require_approval` | `false` | Also hold registrations made with an initial access token until an administrator approves them |
| `open_scopes` | `openid`, `profile`, `email` | The OpenID Connect scopes registered clients may receive for UserInfo: only `openid`, `profile`, `email`, `phone` and `address` are accepted (`422` on `client_registration.open_scopes`) |

Discovery advertises `registration_endpoint` (`I/oauth/register`) while
`enabled` is set, whatever `open` says.

## Initial access tokens

An initial access token (`pa_iat_...`) is the registration authority an
administrator hands to a developer or a partner (ADV-003). Paths are relative
to `/api/v1/realms/{realm}`:

| Method and path | Permission | Effect |
| --- | --- | --- |
| `POST /client-registration-tokens` | `realm.clients.credentials` | Issue a token → `201 {"initial_access_token", "token", "notice"}`; the plaintext is returned once, only its SHA-256 digest is stored |
| `GET /client-registration-tokens` | `realm.clients.read` | Initial access tokens, newest first (at most 200): `id`, `description`, `allowed_scopes`, `project_id`, `max_uses`, `uses`, `expires_at`, `state` (`active`, `expired`, `exhausted` or `revoked`), `created_by_id`, `created_at`, `last_used_at` |
| `DELETE /client-registration-tokens/{id}` | `realm.clients.credentials` | Revoke an active or expired token (`204`; `404` for one that is unknown, revoked or used up). Clients already registered with it are unaffected |

```json
POST /api/v1/realms/main/client-registration-tokens
{
  "description": "Partner integrations, Q4",
  "allowed_scopes": [{"resource_id": "res_orders", "scopes": ["orders:read"]}],
  "project_id": "prj_...",
  "max_uses": 5,
  "expires_in_seconds": 604800
}
```

| Member | Rules |
| --- | --- |
| `description` | Optional, at most 200 characters |
| `allowed_scopes` | Up to 20 entries `{resource_id, scopes}`: active business API resources of the realm and scopes they declare. Privileged scopes are refused (`422`). At each use the scopes are checked again (still declared, still not privileged), so a scope made privileged later is not granted |
| `project_id` | Optional project of the realm; registered clients are created in it (and in its environment) |
| `max_uses` | 1–1000, default 1. A registration that fails does not use one up; the last use turns the token `exhausted` |
| `expires_in_seconds` | 60 seconds to 90 days, default 7 days. A token past its `expires_at` is refused and lists with `state: expired` |

## Registering a client

```sh
curl -sS https://id.example.com/realms/main/oauth/register \
  -H "Authorization: Bearer pa_iat_..." -H "Content-Type: application/json" \
  -d '{"client_name": "Example partner app",
       "redirect_uris": ["https://partner.example.net/callback"],
       "grant_types": ["authorization_code", "refresh_token"],
       "scope": "openid email orders:read"}'
```

The `Authorization` header carries an initial access token, or nothing when
the realm sets `open`. A missing token (without `open`), or a token that is
unknown, expired, revoked or used up (also with `open`), is `401`
(`error: invalid_token`, `WWW-Authenticate: Bearer error="invalid_token"`).
The body must be `application/json` of at most 64 KiB.

**Metadata.** Unknown members are ignored (RFC 7591 §2), including the
URL-valued ones ProudAuth does not support: `sector_identifier_uri`,
`request_uris`, `initiate_login_uri` and `backchannel_logout_uri` are neither
stored nor fetched, and `subject_type` is ignored (a pairwise subject and a
back-channel logout URI are set only by an administrator; a `request_uri`
is only ever a pushed authorization request reference, never fetched).
Accepted:

| Member | Rules |
| --- | --- |
| `redirect_uris` | Required, 1–20, under the ordinary registration rules (exact match; `https` except loopback IP literals and private-use schemes for native clients; never the identity provider's own host; [oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#redirect-uris-and-origins)). The client is a `production` client unless the initial access token's project says otherwise, so `http://localhost` is refused |
| `token_endpoint_auth_method` | `client_secret_basic` (default) or `client_secret_post` (a confidential client with a generated secret); `private_key_jwt` (confidential, no secret; requires inline `jwks`); `none` (a public client: `native` when every redirect URI is an `http` URI on a loopback IP literal or a private-use scheme, otherwise `public_browser`) |
| `grant_types` | Must contain `authorization_code`, optionally `refresh_token`; default `["authorization_code"]` |
| `response_types` | `["code"]` (the default) |
| `client_name` | At most 200 characters; default "Registered client" |
| `scope` | What the client asks for (see below) |
| `contacts` | At most 10 values, not validated. They are shown with the client but never mailed: credential-expiry notices for a registered client go only to an owner an administrator sets (`owner_user_id`) |
| `software_id`, `software_version` | At most 200 and 100 characters |
| `jwks` | Inline public keys, required for `private_key_jwt`; used for response encryption too |
| `client_uri`, `logo_uri`, `policy_uri`, `tos_uri` | `https` URLs with a host, at most 2048 characters, stored in the client's protocol options and returned as given. ProudAuth **never fetches** them and does not display them; a login UI that shows them shows registrant-supplied links |
| `post_logout_redirect_uris`, `frontchannel_logout_uri`, `frontchannel_logout_session_required` | As for administrator-registered clients ([front-channel logout](../protocols/oauth-oidc-profile.md#front-channel-logout-ses-018)) |
| Response signing and encryption | `id_token_encrypted_response_alg`/`enc`, `userinfo_signed_response_alg`, `userinfo_encrypted_response_alg`/`enc`, `authorization_signed_response_alg`, `authorization_encrypted_response_alg`/`enc` ([response-security.md](../protocols/response-security.md)), and `tls_client_certificate_bound_access_tokens` |

Errors are RFC 7591 JSON (`error`, `error_description`) with status `400`:

| `error` | When |
| --- | --- |
| `unapproved_software_statement` | Any `software_statement` (checked first; software statements are not supported) |
| `invalid_redirect_uri` | No or more than 20 redirect URIs, or any redirect or post-logout redirect URI that fails the registration rules |
| `invalid_client_metadata` | `jwks_uri` (ProudAuth fetches no client metadata), other grant or response types, an unsupported authentication method (including the mutual-TLS methods), `private_key_jwt` without `jwks`, a wrong body, and any other failed client validation |

Other failures are OAuth errors too, like every error under
`/realms/{realm}/oauth/` ([API conventions](../protocols/api-conventions.md)):
`404 invalid_request` when registration is disabled or the realm is not
active, `429 slow_down` and `503 temporarily_unavailable` (budgets, below),
both with `Retry-After`. Before 0.2.0-alpha.6 these were problem details.

**What the client becomes.** Every registered client is created with:

- client ID `app_...`; security profile `third_party`,
  `consent_mode: required`, not first-party, `subject_type: public`, no
  offline access (`offline_access` is refused at authorization), and
  `dynamically_registered: true` in the client view;
- UserInfo scopes: `open_scopes` ∩ the requested scopes, or all of
  `open_scopes` when `scope` is empty;
- with an initial access token, also a resource grant (subject type `user`,
  no exchange policy) for each allowed resource: its allowed scopes ∩ the
  requested ones, or all of them when `scope` is empty;
- the token's `project_id`, if it names one.

Requested scopes outside these sets are dropped without error; the
response's `scope` lists what was granted (it can be empty).

**Budgets.** 20 registration requests per hour per client address and 500
per hour per realm, in fixed hourly windows; every `POST` counts, also
refused ones. Beyond them `429 slow_down` with `Retry-After`. The budgets
fail closed: when the limiter is unavailable the answer is `503
temporarily_unavailable`, also with `Retry-After`.

**Response** `201`:

```json
{"client_id": "app_...", "client_secret": "pa_cs_...", "client_secret_expires_at": 0,
 "client_id_issued_at": 1791590400,
 "registration_access_token": "pa_rat_...",
 "registration_client_uri": "https://id.example.com/realms/main/oauth/register/app_...",
 "scope": "openid email orders:read",
 "client_name": "Example partner app",
 "redirect_uris": ["https://partner.example.net/callback"],
 "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
 "token_endpoint_auth_method": "client_secret_basic",
 "proudauth_approval_state": "approved", "proudauth_client_state": "active"}
```

The response also repeats the other registered metadata (not `jwks`).
`client_secret` is present only for `client_secret_basic` and
`client_secret_post` (`client_secret_expires_at: 0`: it does not expire).
Keep the registration access token: it is the only credential for managing
the registration.

## Approval

A registration without an initial access token, or any registration while
`require_approval` is set, is created with `proudauth_approval_state:
pending` and the client `suspended`: it can do nothing until an
administrator decides (its registrant can still read and update it). While
a registration requires approval (it was made without an initial access
token, or `require_approval` is set), its later changes of reviewed
metadata go back to review ([below](#re-approval-of-changed-registrations)).

| Method and path | Permission | Effect |
| --- | --- | --- |
| `GET /client-registrations?approval_state=pending\|approved\|rejected` | `realm.clients.read` | Dynamically registered clients (at most 500): `client_ref`, `client_id`, `name`, `client_type`, `client_state`, `version`, `approval_state`, `initial_token_id`, `software_id`, `software_version`, `redirect_uris`, `post_logout_redirect_uris`, `grant_types`, `client_uri`, `logo_uri`, `policy_uri`, `tos_uri`, `reviewed_version`, `requeued_at`, `created_at` |
| `POST /client-registrations/{client}/approve` | `realm.clients.write` | Body `{"reviewed_version": N}`, required: the client version that was reviewed. Activates the client (`204`; audited `client.registration.approved` with `reviewed_version`) and records `reviewed_version`. `409` when the client is no longer at version `N`; `422` without `reviewed_version` |
| `POST /client-registrations/{client}/reject` | `realm.clients.write` | Decommissions it (`204`; `client.registration.rejected`) |

`{client}` is the client's internal reference (`client_ref`). Each listed
item is one consistent read: `version` is the client version that the
listed metadata belongs to, and the approval takes it back as
`reviewed_version`. Every update of the client gives it a new version: a
registrant `PUT` (also one that changes nothing), an administrator's change
through the client API, and every state change. So when the registrant
changes the client after the administrator looked, even while the
registration is pending, the approval of the version reviewed is `409`
(`conflict`, "the client changed after the reviewed version ...") and
changes nothing; list it again, review what changed and approve the new
version. `reviewed_version` and `requeued_at` stay empty for approvals made
before 0.2.0-alpha.6.

Deciding a registration that is not pending is `409`, an unknown one
`404`. The address the registration came from is kept with it for review.
Only the approval activates a pending registration: `POST
/clients/{client}/reactivate` (and the emergency control's `enable` for the
client) answers `409` ("the client's dynamic registration is pending
approval ...") while the registration is pending.

### Re-approval of changed registrations

An approval covers what users see at consent and where the client may send
them. Where a registration requires approval (open registration, or
`require_approval` set now), a registrant `PUT` that changes any of these
fields of an approved registration returns it to review (0.2.0-alpha.6
[decision 14](../releases/2026-10-alpha.6-decisions.md)):

- `client_name`;
- `redirect_uris` and `post_logout_redirect_uris`;
- `grant_types`;
- `client_uri`, `logo_uri`, `policy_uri` and `tos_uri`.

The registration becomes `pending` again (`requeued_at` records when), and
the client is suspended in the same transaction, like `POST
/clients/{client}/suspend`: its refresh tokens, grants and opaque access
tokens end, its JWT access tokens are revoked by client, and token requests
fail client authentication (`401 invalid_client`) until an administrator
approves the new version. Users who signed in before sign in again
afterwards. The `PUT` response says so (`proudauth_approval_state: pending`,
`proudauth_client_state: suspended`). A client an administrator had
already suspended stays suspended; the approval activates it.

Lists compare as sets, so the same URIs or grant types in another order are
no change. A secret rotation (`rotate_secret`), a `PUT` that repeats the
current values, and changes of other metadata (`contacts`, `software_id`,
`software_version`, the authentication method, front-channel logout,
response signing and encryption) keep the approval. Where approval is not
required (registrations made with an initial access token while
`require_approval` is off), changes keep the client approved and active, as
before; their audit record still names them.

The registrant cannot get around the review by changing the client again:
each change gives it a new version, and an approval names the version
reviewed.

## Managing a registration (RFC 7592)

`registration_client_uri` (`/realms/{realm}/oauth/register/{client_id}`)
accepts only `Authorization: Bearer <registration access token>` of that
client (`pa_rat_...`, one active per client). Anything else, including
another client's token, an administrator's access token, a token already
replaced by an update, or any token of a decommissioned client, is
`401 invalid_token`.

| Method | Effect |
| --- | --- |
| `GET` | `200` with the current metadata and granted `scope`, without client secret or registration access token |
| `PUT` | Replaces the registrant's metadata with the body, checked like a registration (`client_id` must match; `400 invalid_client_metadata` otherwise). The client type cannot change, the granted scopes do not change (`scope` in the body is ignored), and settings an administrator controls are kept (below). Returns `200` with a new `registration_access_token`; the old one stops working. The update is one transaction: when any part of it fails, nothing changes and the presented token stays valid. Where the registration requires approval, a change of reviewed metadata returns it to review and suspends the client ([re-approval](#re-approval-of-changed-registrations)) |
| `DELETE` | `204`. Decommissions the client: its grants, refresh tokens and opaque tokens are revoked, its secrets end, and management stops |

`PUT` with the extension member `rotate_secret: true` also returns a new
`client_secret` (only for `client_secret_basic` and `client_secret_post`
clients; otherwise the member is ignored). The previous secrets stay valid
for at most one hour. `limits.client_secrets_max` (3 by default) bounds the
secrets that are still valid; secrets past their expiry do not count. A
rotation beyond it (for example a third rotation within the hour) is
`409 invalid_request` and changes nothing: the metadata stays as it was,
no secret is issued, and the registration access token presented stays
valid; retry once the older secrets expired, or have an administrator
revoke one (`DELETE /clients/{client}/credentials/{id}`).

A `PUT` replaces only the metadata a registrant registers: `client_name`,
`redirect_uris`, `post_logout_redirect_uris`, `grant_types`,
`token_endpoint_auth_method` (within the same client type), `contacts`,
`software_id`, `software_version`, and the protocol options (`client_uri`,
`logo_uri`, `policy_uri`, `tos_uri`, front-channel logout, response signing
and encryption, `tls_client_certificate_bound_access_tokens`). Settings an
administrator controls through the client API are **kept**, not reset:
`description`, `security_profile`, `first_party`, `consent_mode`,
`consent_terms_version`, `allow_offline_access`, `allow_remember_me`,
`default_resource_id`, environment, project and owner, `subject_type` and
`sector_identifier`, `login_ui_url`, `backchannel_logout_uri`,
`allowed_origins`, claim mappings and `token_policy`. A registrant's change
that conflicts with them is refused like any invalid metadata: for example,
with a pairwise `subject_type`, redirect URIs outside the sector are
`400 invalid_client_metadata`. Keys registered with `jwks` at registration
cannot be changed through `PUT`.

Administrators see and manage dynamically registered clients through the
ordinary client API as well (`dynamically_registered: true`): they can
change grants, issue or revoke credentials, suspend or decommission them.

## Audit

`client.registered` (actor type `registration`, ID the initial access
token's ID or `open`), `client.registration.updated`, `.approved` and
`.rejected`; `client_registration.initial_token.created` and `.revoked`; plus
the ordinary events of the changes they cause (`client.created`,
`client.resource_grant.set`, `client.updated`, `client.credential.issued`,
`client.active`, `client.suspended`, `client.decommissioned`). All
registration events are in category `configuration`.

`client.registration.updated` (actor type `registration`, ID the client ID)
records `client_id`, `secret_rotated`, `approval_state` after the update,
`requeued` (whether it returned the registration to review) and, when any
reviewed field changed, `changes`: per field `{"before": ..., "after": ...}`,
URI and grant-type lists as stored (sorted), at most 20 entries each with
`"truncated": true` beyond that. A re-queue also records `client.suspended`
with reason `registration_requeued`. `client.registration.approved` records
the `reviewed_version`.

## Limits and known issues

- No software statements, no `jwks_uri`, no fetching of client metadata URLs.
- Registered clients cannot use client credentials, device code, token
  exchange, `jwt-bearer`, mutual-TLS client authentication or the
  `privileged`, `high_assurance` and `fapi2` profiles, and cannot be
  first-party or skip consent.
- Registration access tokens do not expire; they rotate on every update and
  end with the client. The management endpoints have no rate limit.
- `contacts` are not verified, so they are never used as mail recipients;
  they still count as named contacts in the ownership report.
- Approved registered clients appear in the configuration export as ordinary
  clients (without the `dynamically_registered` marker); importing such a
  document elsewhere creates ordinary clients without a registration.
  Initial access tokens and registrations are not exported.

Threats and mitigations: [system threat model](../threat-models/system.md)
(public protocol endpoints).
