# SCIM 2.0 inbound provisioning

Requirements: §29 (PROV-001..PROV-009, PROV-018), USR-017, TEN-015. Code:
`internal/provisioning` (connectors, users, groups, filter, discovery),
`internal/httpapi/scim.go`. Tests: `TestSCIMProvisioning`
(`tests/e2e/scim_test.go`), `TestParseFilter` and `TestParseFilterRejects`
(`internal/provisioning/filter_test.go`). OpenAPI tag `Provisioning`, security
scheme `scimConnectorToken`, trust class `provisioning`.

An external directory (an HR system or another identity provider) creates,
updates and deprovisions an organization's members and groups through SCIM 2.0
(RFC 7643, RFC 7644). Each **provisioning connector** is bound to one
organization, the resource types it may manage and a role ceiling. A connector:

- sees and changes only the users and groups it provisioned itself, within its
  organization. Its `externalId` values are its own namespace: two connectors
  may use the same `externalId` for different accounts;
- never changes the realm-wide account state. `active` is the account's
  membership state in the connector's organization, and deprovisioning removes
  only that membership;
- grants roles only through the mappings and the ceiling an organization
  administrator approved.

This API manages only inbound SCIM connectors (`scim_inbound`). Outbound
provisioning (pushing accounts to another system,
[outbound-provisioning.md](outbound-provisioning.md)) and LDAP/Active
Directory connectors with directory synchronization
([directory.md](directory.md)) are separate connector kinds managed at
`/directory-connectors`; they are not listed here, and creating one here is
refused.

## Connectors

Paths are relative to `/api/v1/realms/{realm}/organizations/{org}`. Every route
needs `org.integrations.write` in the organization (the built-in organization
`owner` role and the realm `realm-admin` role have it; the built-in
organization `admin` role does not). `POST`, `PUT` and token rotation also need
an MFA session that is not recovery-restricted; the realm policy
`mfa.org_admin_mfa_optional` does not waive it.

| Method and path | Effect |
| --- | --- |
| `GET /provisioning-connectors` | List the organization's connectors |
| `POST /provisioning-connectors` | Create a connector; returns its token once |
| `GET /provisioning-connectors/{id}` | One connector with its evidence; `ETag: W/"v<N>"` |
| `PUT /provisioning-connectors/{id}` | Replace the definition and set `state`; `If-Match` required (`428` without it, `412` when stale, also when a concurrent update wins between the check and the write) |
| `POST /provisioning-connectors/{id}/token` | Issue a new token; the previous one stops working at once |

```json
POST /api/v1/realms/main/organizations/org_.../provisioning-connectors
{
  "name": "Okta",
  "allowed_resource_types": ["User", "Group"],
  "role_ceiling_ids": ["rol_member", "rol_engineering"],
  "group_role_mappings": { "Engineering": ["rol_engineering"] },
  "default_role_id": "rol_member",
  "config": {}
}
```

| Member | Rules |
| --- | --- |
| `name` | 1 to 100 characters |
| `kind` | `scim_inbound` (the default and the only accepted value). Any other kind, including `scim_outbound`, is `422` on `kind`: outbound and directory connectors are managed at `/directory-connectors` |
| `allowed_resource_types` | `User` and/or `Group` (default both). Requests for another type get `403` |
| `role_ceiling_ids` | At most 50 organization-boundary roles of this organization (or realm-wide organization roles). Each must be within the delegation ceiling of the administrator who creates or updates the connector (`403 grant_ceiling_exceeded` otherwise), so a connector never holds more authority than its creator |
| `group_role_mappings` | At most 200 entries `"<external group>": ["<role id>", ...]`; keys of 1 to 256 characters; every role must be in `role_ceiling_ids` (`422` otherwise) |
| `default_role_id` | Optional; must be in `role_ceiling_ids`. Assigned with each new membership the connector creates |
| `config` | Free-form object, stored and returned |
| `state` | `PUT` only: `active` or `disabled` (omitted keeps the current state) |

`PUT` replaces the whole definition (send every member you want to keep) and
re-validates the ceiling against the administrator making the change.

`POST` answers `201` with `Cache-Control: no-store` and:

```json
{ "connector": { "id": "con_...", "...": "..." },
  "token": "pa_scim_...",
  "scim_base_url": "https://id.example.com/api/v1/realms/main/scim/v2" }
```

The token is shown once (only its digest is stored). Configure the base URL and
the token as the bearer credential in the directory. `scim_base_url` is built
from `server.public_origin`.

A connector also reports operational evidence (PROV-018):

| Member | Meaning |
| --- | --- |
| `last_sync_at` | Time of the last successful SCIM request |
| `last_error` | The detail of the last failed request (at most 200 characters) |
| `stats` | Counters of successful requests per operation, `<method>_<resource type>` (`post_user`, `patch_group`, `delete_user`, ...; `get_discovery` for `ServiceProviderConfig`, `ResourceTypes` and `Schemas`), and `errors` for failed requests |

Requests refused before they reach the connector's logic (invalid token,
resource type not allowed, rate limit, unavailable limiter) are not counted.

A connector stops authenticating when it is `disabled`, when its organization is
not `active`, and when the organization's deletion starts (the deletion
disables all its connectors;
[data-inventory.md](../operations/data-inventory.md#organization-deletion)).

## SCIM endpoint

Base URL: `/api/v1/realms/{realm}/scim/v2`, authenticated with
`Authorization: Bearer pa_scim_...`.

| Path | Methods |
| --- | --- |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | `GET` |
| `/Users`, `/Groups` | `GET` (list), `POST` |
| `/Users/{id}`, `/Groups/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` |

- Request bodies must be `application/scim+json` or `application/json`;
  duplicate JSON members are refused (`400`, `scimType` `invalidSyntax`). The
  deployment's `limits.max_body_bytes` (256 KiB by default) applies, as on
  every route: a larger body is refused with an ordinary `413` problem
  response (the SCIM handler's own cap of 1 MiB matters only if that limit is
  raised).
  Responses are `application/scim+json` with `Cache-Control: no-store`.
- Each connector may send 1200 requests per minute; above that the answer is
  `429` with `Retry-After`. The limit fails closed: when the limiter (a
  PostgreSQL counter) cannot be read, the answer is `503` ("temporarily
  unavailable").
- Errors are SCIM error documents (RFC 7644 §3.12): `schemas`, `status`,
  `detail` and, where it applies, `scimType` (`invalidSyntax`, `invalidFilter`,
  `invalidValue`, `invalidPath`, `noTarget`, `mutability`, `uniqueness`,
  `tooMany`). A missing or invalid token gets `401` with
  `WWW-Authenticate: Bearer realm="scim"`. Validation failures that the
  administration API reports as `422` are `400 invalidValue` here, and every
  `409` (including a separation-of-duties conflict or the last-owner rule)
  carries `scimType` `uniqueness`.
- `id` is ProudAuth's ID (`usr_...`, `grp_...`). `meta.version` and the `ETag`
  header are `W/"<n>"`, derived from the resource's content (users:
  `userName`, `displayName`, `name`, `active`, `emails`, `externalId`;
  groups: `displayName`, `externalId` and members) and the connector's write
  counter, so a change made through the administration API to any of these
  makes a SCIM write with the old tag stale. Roles granted to a group do not
  change its tag. `PUT`, `PATCH` and `DELETE` honor `If-Match` (`412` when
  stale; omitted or `*` matches anything). Each of them locks the resource
  before comparing the tag: for a user the account row and its membership in
  the connector's organization, for a group the group row, which are the
  rows the administration API locks or changes. A concurrent change cannot
  slip in between (PROV-008, TEST-050).
  Group writes and local deletion lock the group before its connector
  mapping and members, so mixed deletion/update requests use the same order.
- **Conflicts with administrators.** Whichever write takes the row first
  wins the race, and the other one sees its result: an administrator's
  change that commits while a SCIM write is waiting makes that write fail
  with `412` when it sent `If-Match` from before the change, and without
  `If-Match` the SCIM change is applied on top of it (a `PATCH` changes only
  the attributes it names; a `PUT` replaces every stored attribute, by
  design). An administrator's `PATCH /users/{user}` that arrives while a SCIM
  write holds the account waits and is then applied on top of it.
  `If-Match` is optional for `PATCH /users/{user}` too: without it the
  `PATCH` changes only the fields it names on the current account, and with
  the `ETag` of `GET /users/{user}` it fails with `412` when anything,
  including a SCIM write, changed the account since. Send `If-Match` when a
  change must not be applied to an account someone else just changed.
  [Replica consistency evidence](../operations/consistency-tests.md#ownership-roles-and-connector-sync--2026-10-11)
  includes repeated concurrency-32 User races between conditional
  connector and administrator writes through three independent pools.
  [Group race evidence](../operations/consistency-tests.md#scim-group-races--2026-10-11)
  adds conditional renames, membership replacement versus administrator
  additions in both causal orders, and controlled concurrent deletion,
  preserving group-derived authority and exact transition evidence.
  This covers atomic conflicts, not full directory-sync capacity.
  `GET` of one resource honors `If-None-Match` (`304`).
- Maintenance mode `restricted` refuses writes with the ordinary `503`
  problem response ([incidents.md](../operations/incidents.md#maintenance-mode-ops-015)).

### Capabilities

`ServiceProviderConfig` advertises exactly what is implemented (PROV-009):
`patch`, `filter` (`maxResults` 200) and `etag` are supported; `bulk`, `sort`
and `changePassword` are not. `ResourceTypes` lists only the types the
connector may manage. `Schemas` lists the stored attributes; other attributes
(`phoneNumbers`, `title`, the enterprise extension, ...) are accepted and
ignored.

Lists:

- `filter` (RFC 7644 §3.4.2.2): `eq`, `ne`, `co`, `sw`, `ew`, `gt`, `ge`, `lt`,
  `le`, `pr`; `and`, `or`, `not` and parentheses; value paths such as
  `emails[type eq "work"].value`. Attribute names are case-insensitive and may
  be qualified with the core schema URN, for Users and Groups alike
  (`urn:ietf:params:scim:schemas:core:2.0:Group:displayName`); string
  comparisons are case-insensitive except for `id` and `externalId`. Ordering
  operators accept only strings and numbers, and `co`, `sw`, `ew` only strings.
  A filter has at most 1024 UTF-8 bytes and 64 nodes; anything else is
  `400 invalidFilter`.
- `attributes` and `excludedAttributes` select top-level attributes (`id`,
  `schemas` and `meta` are always returned).
- Paging with `startIndex` (from 1) and `count` (at most 200).
- A filter that is a single `eq` comparison with a string value is answered
  from indexes, whatever the number of resources: `id` and `externalId` (users
  and groups), `userName` (users; matches the username or the email address)
  and `displayName` (groups). Any other list, including an unfiltered one and
  `eq` combined with `and`, `or` or `not`, examines at most 20,000 resources
  of the connector: a connector that manages more users (or groups) gets
  `400 tooMany` on such a list, never a truncated result. Paging works on the
  examined set, so each page request examines it again.

User scans read mappings, realm-qualified users/identifiers and
organization-qualified memberships in batches, rather than four database
round trips per candidate. Every match contributes to `totalResults`,
while only the requested page is retained. Per-item content and ETags
remain identical to single-resource reads. `TestSCIMListsBoundDatabaseRoundTrips`
counts real SQL requests at two cardinalities (PROV-002, PROV-008, NFR-004,
NFR-006); `TestUserBatchReadsKeepRealmAndIdentifierOrder` checks the
internal batch's realm boundary and identifier ordering (DOM-002, DOM-007).

Group scans read connector/organization/realm-qualified metadata in one
batch, then stream member rows in the database's group/user order. They
retain one group's raw member collection at a time and only the requested
result page, including for member-dependent filters whose output excludes
members. Data and content-derived ETags match individual reads.
`TestSCIMGroupListsBoundDatabaseRoundTrips` counts three database round trips
at 8 and 64 managed Groups, checks empty/member-bearing groups, projection,
ETags and foreign/missing mappings (PROV-002, PROV-008, NFR-004, NFR-006).
`TestSCIMScanBoundaryPreservesExactAndIndexedResults` checks Users and Groups
at 20,000/20,001 resources, including concurrency-32 refusals and indexed
successes: a compound filter remains a bounded scan even when logically
equivalent to a single indexed equality. These are correctness/query-work
checks, not workload capacity measurements.

Lists fail if any database read of a candidate, its identifiers, membership
or group members fails: they return a SCIM error instead of successful
partial totals/pages. A database failure is also not a missing-user `404`.
Genuinely deleted resources or candidates removed concurrently stay
invisible. `TestSCIMReadFailuresDoNotBecomePartialLists` exercises these
boundaries with locked tables and PostgreSQL statement timeouts (PROV-002,
NFR-006, QA-008); restoring reads restores complete lists.

## Users

Stored attributes: `userName`, `name.givenName`, `name.familyName`,
`displayName`, `emails` (the primary one, or the first), `active` and
`externalId`.

**`POST /Users`** (`userName` required) looks for an existing account by email
(from `emails`, or `userName` when it is an email address):

- **No account:** a new `active` account is created (`created_via`
  `scim:<connector id>`). The email is verified only when its domain is a
  domain the organization verified; otherwise the account gets the
  `verify_email` required action. A `userName` that is not an email address
  becomes the username when it passes the
  [username rules](../protocols/identifiers.md#username); one already used by
  another account is a `409 uniqueness` conflict.
- **Existing account:** it is adopted only when all of these hold: the email
  is verified on that account, its domain is one the organization verified
  (a subdomain counts only when the domain was verified with
  `include_subdomains`), the account is not protected
  (deployment administrators, break-glass accounts), it holds no realm-scoped
  role, and this connector does not manage it yet. Otherwise the request fails
  with `409 uniqueness`; it never takes the account over. An account that a
  directory connector sources ([directory.md](directory.md)) can be adopted
  under the same rule; the connector then manages only its membership,
  because identity attributes change only on accounts the connector created.

In both cases the account gets a membership in the connector's organization
with source `scim` (`active`, or `suspended` when the document says
`"active": false`) and, for a new membership, the connector's
`default_role_id` (assignment source `scim`). An existing membership keeps its
roles. Audit: `scim.user.provisioned` (`adopted`, `active`) and, for a new
membership, `organization.membership.added` (source `scim`).

An initially inactive new membership with a default role is created,
granted that approved role and suspended in one transaction; no active
membership is visible outside it. General role assignment still requires
an active membership. Reactivation preserves that one default grant
(`TestSCIMInitiallyInactiveUserWithDefaultRole`, PROV-004, PROV-005, QA-008).

**`PUT` and `PATCH /Users/{id}`**:

- `active` sets the membership in the connector's organization to `active` or
  `suspended` (`organization.membership.suspended` / `.reactivated`);
  suspension also revokes the account's grants and support grants in that
  organization. The realm-wide account state never changes.
- Identity attributes (`userName`, `name`, `displayName`, `emails`) change only
  on accounts the connector owns: created by this connector and with no
  membership in another organization. Otherwise the request fails with
  `400 mutability`, and only `active` can change. A new email of an owned
  account replaces the old one and is verified when its domain is verified for
  the organization.
- Protected accounts and holders of realm-scoped roles cannot be changed
  (`403`).
- `PATCH` takes 1 to 100 operations (`add`, `replace`, `remove`, any case).
  Paths: `active`, `userName`, `displayName`, `externalId`, `name`,
  `name.givenName`, `name.familyName`, `emails` (including `emails[...]`
  value paths); an operation without `path` takes an object value. Both
  `{"op": "Replace", "path": "active", "value": "False"}` (Azure AD style) and
  `{"op": "replace", "value": {"active": false}}` (Okta style) are accepted.
  `active` cannot be removed.
- `PUT` without `externalId` keeps the stored one.
- Audit: `scim.user.updated` (`identity_changed`, `active`).

**`DELETE /Users/{id}`** removes the account's membership in the connector's
organization (reason `scim_deprovisioned`, `organization.membership.removed`)
and the connector's mapping, and records `scim.user.deprovisioned`. The
account, its credentials and its other memberships are not touched; afterwards
the connector no longer finds the account (`404`). The organization's last
active owner cannot be suspended or removed (`409`).

## Groups

Groups are ordinary groups of the connector's organization (source `scim`).

- `displayName` is required (at most 200 characters) and unique in the
  organization, case-insensitively (`409 uniqueness`).
- Members must be users this connector provisioned that still have a
  membership in the organization; any other member is `400 invalidValue`.
  Adding a member runs the separation-of-duties check of the group's roles
  ([ADR 0013](../architecture-decisions/0013-authorization-model.md)).
- Roles come only from the connector's `group_role_mappings`: a mapping
  whose key equals the group's `displayName` or `externalId`
  (case-insensitively) grants its roles, limited to `role_ceiling_ids`, as
  organization-scoped group assignments with source `scim`. Each `POST`,
  `PUT` and `PATCH` of the group re-applies the mapping and removes `scim`
  assignments it no longer names; roles that administrators granted to the
  group are left alone. A change to the connector's mappings takes effect for
  a group at its next write by the connector. A connector cannot add members
  to a group whose roles exceed its `role_ceiling_ids`, whoever granted them
  and including roles inherited from parent groups (`403`, "the group grants
  roles beyond this connector's ceiling"). The check runs whenever a request
  lists members to add, so a `PUT` or a `replace` of `members` on such a group
  fails as a whole even when it names only existing members; use `PATCH`
  `remove` there.
- `PATCH` supports `displayName` (`add`, `replace`), `members` (`add`,
  `replace`, `remove`; `remove` without a value removes every member),
  `members[value eq "<id>"]` removal and operations without `path` carrying
  `displayName` and/or `members`. Other paths are `400 invalidPath`.
- `DELETE /Groups/{id}` deletes the group and every role assignment granted to
  it, including those an administrator granted, in one transaction: each
  assignment is recorded as `role.unassigned` (reason `GROUP_DELETED`,
  metadata `role_id`, `subject_type: "group"`, `subject_id`), then the group
  as `group.deleted`; no `authorization.role.unassigned` webhook event is
  published. The members keep their organization memberships. A group with
  child groups cannot be deleted (`409 uniqueness`, "delete or move child
  groups first"). Deleting a group through the administration API
  (`DELETE /organizations/{org}/groups/{group}`) records the same events and
  requires that the administrator could assign every role the group grants,
  inherited ones included (`403 grant_ceiling_exceeded` otherwise); the
  connector's deletion of its own group, and its removal of members, are
  not bounded by an administrator's ceiling.
  Both paths remove inbound/directory Group links atomically, allowing the
  connector to provision that external ID again. A create also repairs a
  legacy link whose local group was already deleted; a link to a live group
  still returns `409`. Outbound links remain until downstream cleanup succeeds.
- `excludedAttributes=members` leaves members out of a list.
- Audit: `group.created`, `group.deleted`, `group.member.added` and
  `group.member.removed` (source `scim`), `role.assigned` and
  `role.unassigned`.

## Audit and evidence

| Event | Category | When |
| --- | --- | --- |
| `provisioning.connector.created`, `.updated`, `.token_rotated` | `configuration` | Connector management (actor: the administrator) |
| `scim.user.provisioned`, `scim.user.updated`, `scim.user.deprovisioned` | `account` | User requests (actor type `connector`, subject the account) |
| `organization.membership.added`, `.suspended`, `.reactivated`, `.removed` | `security` | Membership changes made by a connector |
| `group.created`, `group.deleted`, `group.member.added`, `group.member.removed`, `role.assigned`, `role.unassigned` | `security`, `authorization` | Group and role changes made by a connector (actor type `connector`) |

Find a connector's actions with
`GET /audit-events?actor_id=con_...` or `type_prefix=scim.`
([monitoring.md](../operations/monitoring.md#audit-queries)).
Stored data: `provisioning_connectors` (token digest only) and
`connector_external_ids` ([data-inventory.md](../operations/data-inventory.md)).
A compromised token is handled in
[incidents.md](../operations/incidents.md#provisioning-connector-token-compromise).

## Upgrade note

Migration `0042_scim_membership_source.sql` adds `scim` to the allowed
`memberships.source` values (expand-only). Older binaries in a mixed-version
window have no SCIM routes; create connectors after the rollout.

Since migration `0065` (directory integration), this API accepts and lists
only `scim_inbound` connectors. A `scim_outbound` connector created here
earlier (stored, never used) is no longer visible here; it now appears at
`/directory-connectors` as an outbound connector without a base URL or
credential, and while it is `active` its deliveries fail and dead-letter.
Disable such connectors before the upgrade (`PUT` here with
`"state": "disabled"`); afterwards they can only be changed through
`/directory-connectors`, where `PUT` needs a complete, valid outbound
configuration ([outbound-provisioning.md](outbound-provisioning.md)).

## Not covered

- No interoperability test against a real directory (Okta, Microsoft Entra ID,
  ...); `TestSCIMProvisioning` uses Okta- and Azure AD-style requests
  ([interoperability.md](interoperability.md#untested-claims)).
- Group capacity and real-directory load remain unmeasured. Local
  [SCIM User lifecycle and extended-mix results](../operations/benchmarks.md#extended-workload-results-nfr-003-nfr-008)
  and [User-filter results](../operations/benchmarks.md#scim-filter-results-nfr-004-nfr-006-nfr-008)
  are published with single-laptop/budget limits; the Group races above
  are correctness tests.
- Bulk operations, sorting and password changes. Outbound provisioning is a
  separate feature ([outbound-provisioning.md](outbound-provisioning.md)).
