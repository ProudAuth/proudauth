# Machine clients, API keys and personal access tokens

Requirements: §17 (MCH-001..MCH-017), TEST-039, TEST-065. Reference code:
`examples/machine-client`, `internal/machine`, `internal/oauth/token.go`
(`clientCredentialsGrant`). Tests: `TestIntrospectionExchangeAndMachines` in
`tests/e2e/flows_test.go`.

## Service principals and client credentials

A machine identity is a **service principal** (`svc_...`) with an owner,
optional allowed organizations, roles and a lifecycle. A client with the
`client_credentials` grant authenticates as that principal.

```sh
# 1. Service principal (realm.service_principals.write)
identity-cli api POST /service-principals '{"name":"nightly-billing","allowed_organization_ids":["org_..."]}'
# 2. Machine client linked to it (realm.clients.write); the response shows client_secret once
identity-cli api POST /clients '{"client_id":"batch-job","name":"Nightly billing batch","client_type":"machine","service_principal_id":"svc_..."}'
# 3. Allow the client to request a resource for service-principal subjects
identity-cli api PUT /clients/cli_.../resource-grants/res_billing '{"allowed_scopes":["billing:read"],"subject_types":["service_principal"]}'
```

Token request (see `examples/machine-client/main.go`):

```sh
curl -u "batch-job:$CLIENT_SECRET" https://id.example.com/realms/main/oauth/token \
  -d grant_type=client_credentials \
  -d resource=https://billing.example.com \
  -d scope=billing:read \
  -d organization=org_...
```

- Exactly one `resource`; account and UserInfo audiences are refused (MCH-004,
  TEST-039). The admin audience can be requested when explicitly granted (used by
  resource servers that call the decision API).
- If the resource requires an organization, `organization` must be the principal's
  owner organization or one of its `allowed_organization_ids`; otherwise the owner
  organization is used when set.
- The token is a short-lived `service_access` JWT with `sub` = the service principal,
  no refresh token (MCH-003). Re-authenticate when it expires.
- `private_key_jwt` is available instead of a shared secret: register the client
  with `token_endpoint_auth_method: private_key_jwt`, add public keys with
  `POST /clients/{client}/credentials {"jwks": {...}}` (`404` for an unknown
  client), and sign assertions with `iss` = `sub` = client ID, `aud` = the token
  endpoint URL or the issuer (every `aud` value must be one of them, at most
  two), `exp` ≤ 5 minutes, a unique `jti` (MCH-010, `TestPrivateKeyJWT`).
- Mutual-TLS client authentication (`tls_client_auth`,
  `self_signed_tls_client_auth`) and certificate-bound tokens are available
  where the deployment accepts client certificates (MCH-014,
  [mutual-tls.md](../protocols/mutual-tls.md)).
- Without any stored credential: a workload that holds an identity token from
  its platform (GitHub Actions, Kubernetes, SPIFFE, ...) can use the
  `jwt-bearer` grant instead of a secret (MCH-011..MCH-013,
  [workload-federation.md](workload-federation.md)).
- DPoP-bound tokens: send a `DPoP` proof header ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#dpop-rfc-9449)).
- Budget: `security.rate_limits.token_per_client` requests per minute; excess gets
  `429 slow_down`. Tokens for a resource that requires an organization also
  count against that organization's budget
  (`security.rate_limits.organization_per_window`; TEN-018).
- Realm policy `tokens.service_access_token_ttl_seconds` (and
  `tokens.access_token_ttl_seconds`) can shorten service tokens below the
  resource's lifetime (TOK-018, [tokens.md](../protocols/tokens.md#access-token-lifetime)).

Lifecycle:

- `POST /service-principals/{id}/disable` stops new tokens immediately and makes
  existing service tokens inactive at introspection and the IdP's APIs; offline
  verifiers accept them until expiry.
- Secret rotation without downtime: `POST /clients/{client}/credentials
  {"retire_others_after_seconds": 86400}` adds a secret and bounds the old ones;
  at most three active secrets.
- Service principals hold roles like users (`POST /role-assignments` with
  `"subject": {"type": "service_principal", "id": "svc_..."}`); the built-in
  `resource-server` role allows calling the decision API. A disabled or
  deleted service principal holds no permissions anywhere (decisions included).
- Secret lifecycle is covered by `TestClientSecretLifecycle`: rotation with
  `retire_others_after_seconds`, RFC 7009 revocation, decommissioning (a
  decommissioned client cannot be reactivated) and `Cache-Control: no-store`
  on token responses.

### Agents

MCH-017, `TestAgentPrincipals` (`tests/e2e/agents_test.go`). A service
principal created with `"is_agent": true` represents software that acts with
some autonomy (an AI agent, an automation that decides what to call). It is
an ordinary service principal with three differences:

- **An accountable human owner.** `owner_user_id` is required; it defaults to
  the creating user. An agent owned only by an organization is refused
  (`422` on `owner_user_id`, "an agent needs an accountable human owner
  (MCH-017)"). `is_agent` cannot be changed after creation, and the owner
  cannot be cleared.
- **Two people for privileged roles.** Assigning an agent a privileged role
  through `POST /role-assignments` answers `202 {"status": "pending_approval",
  "request": {...}}` and creates a request under `/role-assignment-requests`
  that a second administrator must approve
  (`POST /role-assignment-requests/{id}/approve`; neither the requester nor the
  subject can approve, `403`). A role is privileged when it, or any role it
  composes at any depth, has the realm boundary or the organization `owner`
  role, a wildcard permission (`*`, `x.*`), or any permission registered as
  privileged, custom permissions included (`POST /permissions` with
  `"sensitivity": "privileged"`); a composition of more than 64 roles counts as
  privileged. Organization templates apply the same rule: a template that
  would grant an agent a privileged role (or any subject a role that
  requires approval) is not applied; its plan lists the conflict "grant
  <role> to service principal <name> needs an independent approver: assign
  it through POST /role-assignments", and applying it fails with `409`.
  Request the grant directly; once it is approved, the template sees it as
  unchanged. A dry run cannot evaluate a role the template itself creates;
  the real application refuses such a grant the same way.
- **Marked tokens.** Access tokens of an agent carry `agent: true` (a
  reserved claim, also returned by introspection of JWT and opaque tokens);
  introspection of the agent's API keys returns `agent: true` as well. When
  an agent's client exchanges a person's token, the exchanged token's `act`
  entry carries `agent: true`
  ([tokens.md](../protocols/tokens.md#access-token-claims-user_access)).

Agents get no other exemption and no extra power: ordinary authorization,
delegation ceilings, resource grants and token exchange policies apply to
them as to any service principal. Resource servers that treat agents
differently read `agent` (or `act.agent`) and decide themselves.

### Acting on behalf of a user

MCH-015. A service or agent that acts for a person uses token exchange
(TOK-016, TOK-017;
[oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#token-exchange-rfc-8693)),
never its own credentials with a user ID in the request:

- The person's token is the subject; the exchanging client's service
  principal becomes the actor in `act` (with `agent: true` for agents), and
  prior actors are nested, at most `tokens.exchange_max_chain_depth` levels
  (2 by default; a deeper chain is `invalid_grant`).
- Each hop needs a registered audience transition: the client's resource
  grant for the target lists the incoming token's audience in
  `exchange_policy.accept_from_audiences`, and the scopes are capped by
  `exchange_policy.max_scopes`, the organization's scope policy and, at the
  first hop, the person's consent for the client they used.
- The person's session, account and membership are checked live, and the
  exchanged token never outlives the token it came from.
- Service tokens (`service_access`) can never be exchanged as subjects
  (`invalid_grant`, "this subject token cannot be exchanged"), so a service
  cannot turn its own credential into user authority
  (`TestExchangeChainLimits`).
- The audit trail keeps the real actors apart from the person (AUD-005,
  `TestExchangeActorPreservation`). `token.exchanged` names the exchanging
  client's service principal (or agent) as actor, or the client when it has
  none, the person as subject, and the whole delegation chain in
  `metadata.actor_chain` (outermost actor first, earlier hops included,
  agents marked `agent: true`). `authorization.decision` events about an
  exchanged or support token keep the outermost actor in `metadata.actor` and
  the same `actor_chain`; a decision about an agent's own token carries
  `metadata.subject_agent: true`.

### Owner departure

A service principal's `owner_user_id` is the person accountable for it (MCH-007,
migration `0031`, `TestServiceOwnerDeparture` in `tests/e2e/lifecycle_test.go`).
The worker task `machine.owner_departures` runs hourly for every realm:

- An active service principal whose owner is no longer an active user (for
  example suspended, locked or deleted) is marked with the time this was
  detected, and `service_principal.owner_departed` is audited once (actor
  `system`, subject the owner, target the principal, metadata `policy`). The
  credential inventory lists its API keys with the `owner_departed` flag.
- Realm policy `machine.owner_departure` decides what follows:
  - `flag` (default): nothing else; the principal keeps working.
  - `disable`: once `machine.owner_departure_grace_days` (0–90, default 0) have
    passed since the detection, the principal is disabled exactly as by
    `POST /service-principals/{id}/disable`: its API keys and opaque tokens are
    revoked, client credentials fail, and `service_principal.disabled` (reason
    code `owner_departed`) and the `service_principal.state_changed` event are
    recorded. At most 100 principals per realm are disabled per run. The grace
    period counts from the detection, also when the policy was switched to
    `disable` later, so switching can disable principals at the next run.
- When the owner is active again, or an administrator gives the principal an
  active owner (`PATCH /service-principals/{id}` with `owner_user_id`), the next
  run clears the marker, and a later departure is reported again. A principal
  the policy disabled is not re-enabled automatically.
- Principals without an `owner_user_id` are not covered. Personal access tokens
  and a user's own API keys stop working with their owner regardless of this
  policy.
- An account that owns live service principals (or projects, clients,
  resources or connections) cannot be deleted until they are moved to
  another owner (`409 last_owner` with the extension `owned`; USR-020).
  `POST /users/{user}/ownership-transfer {"to_user_id": "usr_..."}` moves all
  of them at once, each audited as `<kind>.ownership_transferred`
  ([data-inventory.md](../operations/data-inventory.md#account-deletion)).

## API keys

Scoped, opaque keys (`pa_key_...`) owned by a service principal, for integrations
that cannot run an OAuth client:

```sh
identity-cli api POST /api-keys '{"service_principal_id":"svc_...","name":"sync",
  "audience":"https://billing.example.com","scopes":["billing:read"],"organization_id":"org_...","ttl_days":90}'
```

- The key is returned once; afterwards only ID, display prefix and metadata are
  visible (MCH-008).
- Rules (API keys and personal tokens): expiry is mandatory, `ttl_days` defaults to
  90 and may not exceed 365; the audience must be an active business resource (never
  the account or admin APIs); scopes must be declared by that resource and must not
  be `privileged`; `organization_id` is required when the resource requires an
  organization and must be allowed for the owner.
- One audience per key. Resource servers validate keys by introspection; an
  introspector of another audience receives `{"active": false}`.
- Introspection returns `token_kind: api_key`, `sub` (the owner), `subject_type`,
  `scope`, `aud`, `exp`, `org_id`.
- Each successful introspection records the key's last use: `last_used_at` in
  `GET /api-keys` (and in the credential inventory) is updated at most once a
  minute. Personal access tokens record their last use the same way.
- `DELETE /api-keys/{id}` revokes immediately (next introspection). A disabled
  owner makes its keys inactive.

## Personal access tokens

Users create their own automation tokens (`pa_pat_...`) through self-service, with
authentication within `security.recent_auth_window`:

```sh
identity-cli api --audience account POST /me/personal-tokens \
  '{"name":"cli","audience":"https://orders.example.com","scopes":["orders:read"],"organization_id":"org_...","ttl_days":30}'
```

- Requires `identity-cli login --audience account` first (the CLI stores one
  credential per audience).
- Shown once; listed without the secret (`GET /me/personal-tokens`); revoked with
  `DELETE /me/personal-tokens/{id}`.
- Scopes never exceed the owner's current authority (MCH-006): at creation, a
  scope is refused (`403`) when the organization's `allowed_scopes` excludes it,
  the owner lacks a permission listed in the scope's `required_permissions`, or
  the scope has a step-up policy (`step_up_acr`, `max_auth_age_seconds` or
  `sensitivity: privileged`; AUT-010), because a token holds no authentication
  event to be strong or recent enough; on every introspection the scopes are
  narrowed again the same way, and the token becomes inactive when none remain.
  The same rules apply to API keys. Scopes without `required_permissions` are not
  tied to the owner's roles, so resource servers must still authorize the owner.
  `ttl_days` is 1–365 (default 90). For tokens bound to an organization
  (`organization_id`), organization policy can refuse them
  (`personal_tokens: "disabled"`, `403`) or cap `ttl_days`
  (`personal_token_max_days`, `422`); tokens without an organization are not
  subject to organization policy (`TestPersonalTokenCeiling`).
- Introspection returns `token_kind: personal_access`. The token is inactive when
  the owner is no longer active or, for organization-bound tokens, loses the
  membership. Deleting the user revokes their tokens.
- Support (impersonation) tokens cannot create personal tokens (IMP-012).

## Inventory and expiry

- `GET /credential-inventory` (`realm.credentials.inventory`) lists active API keys,
  personal tokens and client secrets that carry at least one flag. Flags:
  `expiring` (14 days), `unused` (60 days), `ownerless` (the owning user or
  service principal is no longer active; for client secrets, no active owning
  user and no technical contact), `owner_departed` (a service principal's
  accountable owner user is no longer active), `over_privileged` (scopes beyond
  the owner's current authority) and `no_expiry` (client secrets) (MCH-007,
  MCH-016, APP-014). `POST /credential-inventory/revocations`
  `{"ids": [...], "reason": "..."}` revokes 1–100 API keys, personal tokens
  (`realm.api_keys.manage`) or client secrets (`realm.clients.credentials`), each
  in its own transaction with per-item results; users need recent authentication
  (`TestCredentialInventory`).
- The worker sends one notification per credential 14 days before an API key,
  personal token or client secret/key expires: to the owner (the user, or the
  service principal's owning user), and for clients to the owning user and every
  technical contact. The contacts of dynamically registered clients are
  registrant-supplied and unverified and are never mailed
  ([dynamic-client-registration.md](dynamic-client-registration.md)); such a
  client's alerts reach only an owning user an administrator sets. The alert
  is claimed in `credential_expiry_alerts` in the same transaction that
  enqueues it, so several workers or a retried run never notify twice (migration `0023`; TOK-021, MCH-009, `TestCredentialExpiryAlerts`).

### Ownership report

DOM-009, APP-014, MCH-007, migration `0047`, `TestOwnershipReport`. Every
integration object should have someone accountable for it.
`GET /api/v1/realms/{realm}/ownership-report` (`realm.settings.read`; paged
with `limit` and `cursor`, `{items, next_cursor}`) lists the live objects that
lack one:

| `kind` | Covered when |
| --- | --- |
| `client` | Active, with or without secrets (the operator CLI client excluded); its `contacts` count as accountable |
| `project` | Not archived |
| `service_principal` | Active |
| `resource` | Active business API resources |
| `identity_provider` | Active |
| `webhook` | Not disabled |
| `hook` | Active pre-action hooks |
| `authorization_policy` | Not disabled; an organization-scoped policy is owned by its organization |

Each item has `kind`, `id`, `name`, `owner_user_id`, `owner_organization_id`
and `flags`: `ownerless` (no owner user, owning organization or, for clients,
contacts) or `owner_departed` (the owner user is no longer `active` or
`recovery_restricted`). Only flagged objects are listed.

Authorization policies (`POST /policies`) and pre-action hooks (`POST /hooks`)
now take `owner_user_id` too; it defaults to the creating user and must be an
`active` account of the realm (`422`). It is not returned on the policy or
hook. To resolve a finding: transfer ownership (`POST
/users/{user}/ownership-transfer` moves projects, clients, service
principals, resources, identity providers, hooks, webhook subscriptions and
authorization policies; `POST /projects/{project}/ownership-transfer` one
project; `POST /hooks/{id}/ownership-transfer`, `POST
/webhooks/{id}/ownership-transfer` and `POST
/policies/{policy}/ownership-transfer` with `{"owner_user_id"}` one hook,
subscription or policy, also one without an owner), or disable or delete the
object. A plugin-managed hook or subscription keeps its plugin when its owner
changes (the owner is not part of the reviewed package). Each change is
audited as `<kind>.ownership_transferred` and moves the object's version
(`ETag`; the single-object routes honor `If-Match`).
