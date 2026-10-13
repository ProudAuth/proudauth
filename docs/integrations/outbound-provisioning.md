# Outbound SCIM provisioning

Requirements: PROV-010 (outbound provisioning), PROV-017 (reconciliation),
PROV-018 (operational evidence), TEN-018 (fair share). Code:
`internal/directory/outbound.go`, `internal/httpapi/directory.go`. Tests:
`TestOutboundProvisioning` (`tests/e2e/outbound_test.go`),
`TestOutboundLegacyConnector` (`tests/e2e/directory_lifecycle_test.go`),
`TestOutboundDocument` and `TestOutboundConnectorUsability`
(`internal/directory/directory_test.go`); against ZITADEL,
`scripts/interop-zitadel.sh` (`make interop-zitadel`). OpenAPI tag `Directory`.
Migrations `0065_directory_integration.sql` and
`0085_directory_retention.sql`.

An outbound connector (kind `scim_outbound`) pushes the lifecycle of eligible
accounts, and optionally groups, from ProudAuth to a downstream SCIM 2.0
service (RFC 7643, RFC 7644): an application's user store, a SaaS product, a
directory. Local data is the authority; the downstream is made to match it.
Outbound connectors are created and managed through the shared
`/directory-connectors` API, with the same permissions, credential handling,
runs, health and audit as LDAP connectors
([directory.md](directory.md#connector-api)). Inbound SCIM (a directory
provisioning into ProudAuth) is a different feature:
[scim-provisioning.md](scim-provisioning.md).

**Status.** Tested against an in-process SCIM double in the test suite and
against one real SCIM service provider, **ZITADEL v4.16.3**
([Tested downstream services](#tested-downstream-services)). Other products
(SaaS applications, directories) are untested
([interoperability.md](interoperability.md#untested-claims)).

## Configuration

```json
POST /api/v1/realms/main/organizations/org_.../directory-connectors
{
  "name": "wiki-users",
  "kind": "scim_outbound",
  "credential": "<downstream bearer token>",
  "config": {
    "base_url": "https://wiki.example.com/scim/v2",
    "eligible_group_ids": ["grp_..."],
    "deprovision_action": "deactivate",
    "reconcile_interval_seconds": 86400
  }
}
```

| Member of `config` | Rules |
| --- | --- |
| `base_url` | Absolute URL without credentials, query or fragment; `https` in production mode. Checked against the egress policy when the connector is saved and again at every connection |
| `allow_private_network` | Reach a private address; accepted only where the operator's webhook egress policy permits private destinations (`delivery.allow_private_webhooks` in development, `delivery.egress_allowlist`), otherwise `422` |
| `timeout_seconds` | 1 to 60, default 10 |
| `max_attempts` | 1 to 20, default 8 |
| `eligible_organization_ids` | Realm connectors: push members of these organizations (at most 50); empty means every non-guest account of the realm. Refused on organization connectors |
| `eligible_group_ids` | Organization connectors: push only members of these groups (at most 50); empty means every member of the organization. Refused on realm connectors |
| `exclude_created_via` | Up to 20 `created_via` values whose accounts are never pushed, to prevent loops (for example accounts that an inbound connector created from the same system) |
| `attribute_mapping` | `"<SCIM attribute>": "<local source>"`. SCIM attributes: `userName` (required), `displayName`, `name.givenName`, `name.familyName`, `emails`, `locale`, `timezone`, `title`. Local sources: `username`, `email`, `display_name`, `given_name`, `family_name`, `locale`, `zoneinfo`, `user_id`, `profile.<name>`. Default: `userName` ← `username`, `displayName` ← `display_name`, `name.givenName` ← `given_name`, `name.familyName` ← `family_name`, `emails` ← `email`. `externalId` is always the local account ID |
| `deprovision_action` | `deactivate` (default; `PATCH` with `active: false`) or `delete` |
| `push_group_ids` | Organization connectors: groups pushed to `/Groups` (at most 50) |
| `reconcile_interval_seconds` | `0` (not scheduled) or 300 to 2592000 |

The credential is the downstream bearer token. It is encrypted, write-only,
and sent only as `Authorization: Bearer` to the configured base URL. Only
bearer tokens are supported.

### Connectors created through the old API

Earlier releases let `/organizations/{org}/provisioning-connectors` create
rows of kind `scim_outbound`, with whatever `config` was sent (usually
none) and a hashed SCIM token instead of an encrypted credential. Such a
row is listed at `/directory-connectors` but has no usable configuration:
no `base_url`, or no credential. An outbound connector without a usable
configuration gets **no deliveries** (events, the change scan and
reconciliation skip it), cannot run (`POST .../runs` and replays answer
`409`), and is never scheduled; deliveries queued for it before the
upgrade wait without using up attempts. Its health reports `status:
needs_configuration` with `configuration_error` (for example `base_url is
not configured`). To use it, set a configuration with `PUT .../{id}` and a
bearer token with `PUT .../{id}/credential`; its first reconciliation then
runs at the next scheduler pass. To retire it, delete it with `DELETE
.../{id}`: a connector without a usable configuration can be deleted
without being disabled first.

## What is sent

- `externalId` is always the local account ID, so a retry finds its own
  earlier resource and never adopts someone else's.
- The mapped attributes; for `emails`, **only a verified** primary email.
  When the `userName` source is empty, the verified email is used, then the
  account ID.
- `active`: `false` for suspended and locked accounts and, for organization
  connectors, suspended memberships; `recovery_restricted` accounts count
  as active.

Operations: create (`POST /Users`), update (`PUT /Users/{id}`; a `404`
recreates the resource), deactivate (`PATCH` with `active: false`) and
delete (`DELETE`; a `404` counts as done). Groups go to `/Groups` with their
members' downstream IDs. Requests carry `Content-Type:
application/scim+json` and `Accept: application/scim+json` (a single media
type, as RFC 7644 section 8.1 recommends; ZITADEL refuses a list); responses
are read as JSON up to 1 MiB whatever their `Content-Type`, and redirects
are not followed.

## Triggers and deliveries

- **Events.** Outbox events dispatched by the worker (`user.created`,
  `user.suspended`, `user.reactivated`, `user.locked`,
  `user.recovery_restricted`, `user.deleted`, `user.merged` for both
  accounts, `organization.membership.added`, `.removed`, `.suspended` and
  `.reactivated`) are fanned out to the connectors inside the dispatcher's
  transaction, at least once, like webhooks. Organization connectors receive
  only their own organization's members.
- **Change scan.** Each scheduler pass also catches profile edits,
  changes of the account's identifiers (an email address or username
  added, verified, made primary or removed) and membership changes that
  publish no event. An email address becoming verified therefore pushes it,
  and a create the downstream refused for want of it is delivered again.
- **Reconciliation** catches the rest, for example changes of group
  membership that affect eligibility. A new connector starts with a
  reconciliation that pushes every eligible account.

Deliveries are **level-triggered**: a delivery means "make the downstream
match this account as it is now". Events for one account coalesce into one
open delivery; a change that arrives during an attempt bumps the
delivery's generation and is delivered after it. A resource whose document
did not change since the last push (compared by digest) is not rewritten.

**Idempotency.** A `409` on create looks the resource up with
`filter=externalId eq "<account id>"` and adopts it only when its
`externalId` is exactly that account ID. A downstream account with the same
`userName` that this connector did not create is never taken over: the
delivery dead-letters with category `conflict`.

**Retries.** Network errors (including a destination the egress policy
refuses at connection time, `egress_denied`) and `408`, `425`, `429` and
`5xx` answers are retried (`retrying`) with exponential backoff: 10 seconds
after the first attempt, doubling with each attempt, plus up to 25 %
jitter, at most 1 hour; a `Retry-After` header is honored up to 6 hours.
`401` and `403` (`unauthorized`), redirects and other `4xx` answers
(`rejected`) and unresolved conflicts dead-letter at once; so does a
delivery that used up `max_attempts`. Error categories reported per
delivery: `network_error`, `egress_denied`, `throttled`, `server_error`,
`unauthorized`, `rejected`, `conflict`, `not_found`, `invalid_response`,
`local_error`, `credential_unavailable`. Dead-lettered deliveries are
audited (`directory.outbound.dead_lettered`) and counted; an operator
replays one with `POST .../{id}/deliveries/{delivery}/replay`, which marks
it `replayed` and opens a new delivery (audited, recorded as an operator
action).

**Fair share.** The worker task `directory.outbound.deliver` (every
2 seconds) claims due deliveries under 2-minute leases; each connector gets
at most a quarter of a batch, but at least 10 (25 with the default
`workers.batch_size` of 100), so one slow downstream cannot hold up the
others (TEN-018). Leases are released when the worker shuts down.

`GET .../{id}/deliveries?state=` lists the newest 200 deliveries
(`pending`, `retrying`, `delivered`, `dead_letter`, `replayed`) with their
operation, attempts, last status code and error category. Finished
deliveries (`delivered`, `dead_letter`, `replayed`) are deleted 90 days
after their last change (or after `privacy.history_retention` when that is
shorter) by the worker's retention task; replay a dead letter before then.
Open deliveries are never pruned.

## Reconciliation

PROV-017. `POST .../{id}/runs {"mode": "reconcile"}` (also as a
`"dry_run": true` plan) compares every candidate account's desired state,
derived from the mapping, with the downstream inventory (`GET /Users`, paged
and bounded by `directory.max_entries_per_run`):

| Finding | Meaning | Repair |
| --- | --- | --- |
| `missing_remote` | Eligible but not pushed, or deleted downstream | A delivery creates it |
| `drift` | Downstream attributes differ, or the local account changed since the last push | A delivery updates it |
| `deprovision` | No longer eligible | A delivery deactivates or deletes it |
| `orphan_remote` | A resource with this connector's `externalId` whose mapping was lost | Adopted again |
| `unmanaged_remote` | A resource this connector did not create | **Reported, never deleted** |

Local data is the authority, and repairs are ordinary deliveries. When the
downstream cannot list users, the run reports `remote_list_unavailable` and
the local comparison still runs.

## Evidence and monitoring

`GET .../{id}/health` reports `deliveries` by state, `oldest_due_seconds`,
`last_delivered_at`, `status: needs_configuration` with
`configuration_error` for a connector that cannot deliver, and the latest
operator actions
([directory.md](directory.md#operational-evidence)); the metrics
`proudauth_outbound_provisioning_total` and
`proudauth_outbound_provisioning_backlog` are described in
[monitoring.md](../operations/monitoring.md#directory-integration). Stored
data: `outbound_deliveries`, finished ones kept 90 days
([data-inventory.md](../operations/data-inventory.md#directory-integration)).
When an account is deleted, its mapping to the downstream resource (the
remote ID only) stays so the `user.deleted` delivery can deactivate or
delete it downstream.
The bearer token never appears in responses, errors, logs or audit
metadata.

## Tested downstream services

QA-004. A tested profile is what the script below exercised against one
release; it is not a claim about other releases or other features of the
product.

### ZITADEL v4.16.3

`scripts/interop-zitadel.sh` (`make interop-zitadel`; CI workflow
`interop.yml`, weekly and on demand) starts `ghcr.io/zitadel/zitadel:v4.16.3`
(`start-from-init`, PostgreSQL 18) and the ProudAuth binaries built from the
checkout, and reads every outcome back from ZITADEL through SCIM and its v2
user API.

| Aspect | Profile exercised |
| --- | --- |
| Endpoint | `base_url` `http://localhost:<port>/scim/v2/<ZITADEL organization ID>`: ZITADEL's SCIM endpoint is per organization. ZITADEL picks its instance from the `Host` header, so the URL must use the instance's external domain (here `localhost`; `127.0.0.1` answers `404`) |
| Authentication | Bearer: the personal access token of a ZITADEL service account (machine user, access token type Bearer) holding only `ORG_USER_MANAGER` in that organization. Its token cannot reach another organization (`404`). A revoked token answers `401`, which dead-letters as `unauthorized`; a new token set with `PUT .../credential` and a replay deliver |
| Connectors | An organization connector (`deprovision_action: deactivate`) and a realm connector with `eligible_organization_ids` (`deprovision_action: delete`), each to its own ZITADEL organization |
| Operations | `POST /Users` (initial reconciliation and membership events), `PUT /Users/{id}` (profile and email changes, account and membership suspension and reactivation), `PATCH` `active: false` (membership removal, account deletion), `DELETE /Users/{id}`, `GET /Users?filter=externalId eq "..."` and `GET /Users?startIndex=&count=` (reconciliation) |
| Attributes | Default mapping: `userName`, `displayName`, `name.givenName`, `name.familyName`, `emails` (the verified primary address), `active`, `externalId` (the account ID). ZITADEL stores `externalId` and returns it, and filters on it |
| Reconciliation | Dry run, then applied: `drift` (a `displayName` changed in ZITADEL) repaired, `missing_remote` (a managed user deleted in ZITADEL) recreated, `unmanaged_remote` (a user created in ZITADEL, and its first-instance administrator) reported and left alone |

What ZITADEL requires, and how ProudAuth meets it:

- **One media type in `Accept`.** ZITADEL v4.16.3 answers `400` (`Invalid
  accept header`) to an `Accept` header listing several media types, for
  example `application/scim+json, application/json` (RFC 9110 allows a
  list). ProudAuth now sends `Accept: application/scim+json` alone (RFC 7644
  section 8.1); earlier builds dead-lettered every request to ZITADEL as
  `rejected`.
- **Required attributes beyond RFC 7643.** ZITADEL's `/Schemas` marks
  `name` (`givenName`, `familyName`) and `emails` required; RFC 7643
  requires only `userName`. An account without a verified email address
  (ProudAuth never pushes an unverified one) or without a given or family
  name is refused with `400` and dead-lettered as `rejected` at once. When
  the address is verified or the names are set, the change scan delivers the
  account again. Make sure accounts pushed to ZITADEL have both names and a
  verified email address, for example by limiting eligibility with
  `eligible_group_ids`, or map the names from other sources with
  `attribute_mapping`.
- **No groups.** ZITADEL's SCIM serves only the `User` resource type;
  `/Groups` answers `404`. Do not set `push_group_ids` on a connector to
  ZITADEL: its group deliveries would dead-letter.
- `etag.supported` is `false` (ProudAuth sends no `If-Match` downstream);
  `PATCH` answers `204` and `DELETE` `204`, then `404`.

Not covered with ZITADEL: TLS (the test runs over loopback HTTP with the
development egress allowances `delivery.allow_private_webhooks` and the
connector's `allow_private_network`; production needs `https`, verified
against the system trust store only, so a ZITADEL behind a private CA needs
that CA in the host's or image's store:
[configuration.md](../operations/configuration.md#delivery)),
`eligible_group_ids`, `exclude_created_via`, custom `attribute_mapping`
(`locale`, `timezone`, `title`, `profile.*`), retries on `429` and `5xx`,
adoption after a `409` (ZITADEL answers `409` with `scimType: uniqueness`
for a taken `userName`, which the in-process double covers), `userName`
changes, accounts merged, scheduled reconciliation
(`reconcile_interval_seconds`), and bulk or very large inventories.

## Not supported

- SCIM bulk operations; extension schemas such as the enterprise User
  extension; `PATCH` other than for `active`.
- Authentication to the downstream other than a static bearer token (no
  OAuth client credentials, no mutual TLS).
- Reading data back from the downstream into local accounts: outbound
  provisioning never changes local data.
- Deleting downstream resources this connector did not create.

## Testing and interoperability status

`TestOutboundProvisioning` runs one organization connector against an
in-process SCIM double: the initial reconciliation, an update found by the
change scan (and no rewrite of an unchanged account), deactivation after a
membership removal, a group push, retries with backoff, dead-lettering and
replay, adoption of its own earlier resource through `externalId`, refusal
to take over a resource with the same `userName`, reconciliation of drift
and lost resources without deleting foreign ones, the egress opt-in,
tenant isolation (an organization connector cannot name another
organization, and another organization's accounts are not pushed),
evidence without the token, and credential rotation.
`TestOutboundLegacyConnector` checks that a row created through the old
API gets no deliveries or runs, reports `needs_configuration`, and delivers
once configured. The same test checks that an email change (a new address,
verified and made primary) reaches the downstream through the change scan
and that `Accept` names one media type. `deprovision_action: delete` and
realm connectors are tested only against ZITADEL
([above](#zitadel-v4163)); `eligible_group_ids` has no end-to-end test.
Other SCIM service providers are untested (QA-004). Test a new downstream
with a reconciliation dry run first.

Threat analysis: [threat-models/directory.md](../threat-models/directory.md).
