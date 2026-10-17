# Directory integration: LDAP and Active Directory

Requirements: PROV-011 (LDAP/AD federation), PROV-012 (synchronization),
PROV-013 (write-back modes), PROV-014 (failover), PROV-017
(reconciliation), PROV-018 (operational evidence), FED-015 (inbound
workforce federation), USR-022 (directory-authoritative accounts); PROV-015
(Kerberos/SPNEGO) is [not offered](#kerberos-and-spnego-are-not-offered).
Code: `internal/directory` (module), `internal/directory/ldaptest`
(in-process LDAP test server), `internal/identity/authority.go` (the
attribute-authority check), `internal/httpapi/directory.go` (routes).
Tests: `TestLDAPDirectorySignIn`, `TestDirectorySynchronization`,
`TestDirectoryAuthority`, `TestDirectoryTenantIsolation`
(`tests/e2e/directory_test.go`), `TestDirectoryQueuedRunWhileDisabled`,
`TestDirectoryErasureAndRetention`, `TestDirectoryMembershipReactivation`
(`tests/e2e/directory_lifecycle_test.go`), `TestOutboundProvisioning`
(`tests/e2e/outbound_test.go`) and the unit tests in
`internal/directory/directory_test.go`. OpenAPI tag `Directory`. Migrations
`0065_directory_integration.sql` and `0085_directory_retention.sql`.

A **directory connector** connects a realm or an organization to an LDAP
directory or Active Directory domain (kind `ldap`), or pushes accounts to a
downstream SCIM 2.0 service (kind `scim_outbound`,
[outbound-provisioning.md](outbound-provisioning.md)). Both kinds share the
`/directory-connectors` API described here. Inbound SCIM connectors
(`scim_inbound`, a directory pushing to ProudAuth) are separate and stay at
`/organizations/{org}/provisioning-connectors`
([scim-provisioning.md](scim-provisioning.md)).

**Status.** LDAP support is tested only against the in-process `ldaptest`
server (OpenLDAP- and Active Directory-style data, LDAPS, StartTLS, paged
results, USN change tracking). **No test has been run against a real
Active Directory domain controller, OpenLDAP, 389 Directory Server or any
other third-party directory**
([interoperability.md](interoperability.md#untested-claims)). Kerberos and
SPNEGO, password write-back and the other features listed under
[Not supported](#not-supported) are not implemented.

## Concepts

- **Realm (workforce) connector:** `organization_id` absent. It sources
  realm accounts and grants **no** organization memberships or roles: a
  workforce user is never assumed to belong to a customer organization
  (FED-015). Only realm administrators manage it.
- **Organization connector:** bound to one organization. It creates
  memberships only in that organization (with an optional default role),
  maps approved directory groups to that organization's groups and roles
  within a role ceiling, and deprovisions only that organization's access
  (PROV-005). Its ceiling and group mappings must lie within the creating
  administrator's own delegation ceiling (PROV-003, TEST-049). It is
  managed by holders of `org.integrations.write` in the organization (the
  built-in organization `owner` role and the realm `realm-admin` role have
  it; the built-in organization `admin` role does not) and by realm
  administrators.
- **Link:** a connector-scoped external ID (`connector_external_ids` with
  `link_kind = 'directory'`): the entry's immutable ID (`entryUUID`, or
  `objectGUID` as hex for Active Directory), its current DN, a snapshot of
  the values last imported, and a source state (`active`, `disabled`,
  `missing`, or `deleted` once the account was erased). A unique index
  allows **at most one directory link per account**, so two directories
  never both own an account's password or attributes. An account with a directory link is a
  **directory-sourced account**.
- **Credential:** the service account's bind password (`ldap`) or the
  downstream bearer token (`scim_outbound`). It is stored encrypted under
  the key hierarchy (data purpose key, associated data
  `directory-connector-credential:<connector id>`, so a ciphertext copied to
  another row does not decrypt), is write-only, and never appears in
  responses, run errors, findings, logs or audit metadata. Replace it with
  `PUT .../credential`.

## Enabling

The `directory` configuration section
([configuration.md](../operations/configuration.md#directory)):

| Key | Default | Effect |
| --- | --- | --- |
| `directory.enabled` | `true` | `false`: the connector APIs answer `404 feature_disabled`, nothing runs or is delivered, and directory-sourced accounts **fail closed** (password sign-in `503`, password changes and edits of managed attributes refused). A run that was queued when the module was switched off ends `cancelled` (with the reason in `error`) when the worker picks up its job, so it never blocks the connector once the module is enabled again |
| `directory.allow_private_network` | `false` | Lets directory connections reach private and loopback addresses. Development only; rejected in production. `PROUDAUTH_ALLOW_PRIVATE_EGRESS` sets it, together with `federation.allow_private_network` and `delivery.allow_private_webhooks` |
| `directory.egress_allowlist` | `[]` | CIDRs that directory connections may reach even if private: in production, list your directory servers' networks here |
| `directory.ca_file` | `""` | PEM bundle of additional trusted roots for LDAPS and StartTLS (added to the system roots); startup fails if the file is unreadable or holds no certificate |
| `directory.connect_timeout` | `5s` | Connection timeout (at most `1m`); a connector can set its own |
| `directory.operation_timeout` | `10s` | Timeout of one LDAP operation (at most `2m`); a connector can set its own |
| `directory.sign_in_timeout` | `8s` | Overall deadline of one sign-in attempt's directory work, across every endpoint and JIT connector (at most `25s`) |
| `directory.max_concurrent_binds` | half the transaction slots | Most sign-in directory operations per process; a full bound answers `503 unavailable` with `Retry-After: 5` |
| `directory.max_entries_per_run` | `100000` | Most entries one synchronization or reconciliation run processes (at most `1000000`); an LDAP connector's own `max_entries` can only lower it |

`directory.enabled`, `directory.allow_private_network`,
`directory.egress_allowlist` and `directory.ca_file` are security
boundaries in `config-diff` (a change needs a second reviewer).

Outbound SCIM destinations use the webhook egress policy instead
([outbound-provisioning.md](outbound-provisioning.md#configuration)).

## Connector API

Two route families with the same shape:

- **Realm:** `/api/v1/realms/{realm}/directory-connectors`. Administration
  token from an MFA session. Reads need `realm.provisioning.read` (new; also
  held by the built-in `realm-auditor` role) or `realm.provisioning.manage`;
  changes, tests, runs and replays need `realm.provisioning.manage`. Lists
  every connector of the realm, realm and organization connectors alike.
- **Organization:**
  `/api/v1/realms/{realm}/organizations/{org}/directory-connectors`.
  Account or administration token with `org.integrations.write` in that
  organization (built-in `owner`, not `admin`); changes, tests, runs and
  replays need an MFA session. Sees only that organization's
  connectors (others answer `404`).

| Method and path (relative to the family) | Effect |
| --- | --- |
| `GET` | List connectors (cursor pagination) |
| `POST` | Create a connector: `name` (1 to 100 characters), `kind` (`ldap` or `scim_outbound`), `config`, `credential` (required, 1 to 4096 bytes); for organization LDAP connectors `role_ceiling_ids` (at most 50), `group_role_mappings` (at most 200) and `default_role_id` (roles on realm or outbound connectors are refused with `422`); on the realm route an optional `organization_id`. `201` with `ETag` |
| `GET /{id}` | One connector with `last_sync_at`, `last_success_at`, `last_error`, `consecutive_failures`, `credential_set`, `credential_set_at` |
| `PUT /{id}` | Replace the definition and set `state` (`active`, `disabled`); `If-Match` required (`428` without it, `412` when stale); `kind` and `organization_id` are fixed; `credential` is refused here. A change makes the connector due at the next scheduler pass |
| `DELETE /{id}` | Delete a connector (`204`); only a `disabled` one (`409` otherwise), except an outbound connector without a usable configuration, which can be deleted at once. Its links, runs and deliveries are deleted; accounts stay |
| `PUT /{id}/credential` | Replace the credential (write-only) |
| `POST /{id}/test` | Connectivity test: for `ldap`, connect, TLS, service-account bind and root DSE; for `scim_outbound`, `GET /ServiceProviderConfig`. Answers `200` with `ok`, the endpoint and details (TLS version and server, or the status code), and `ok: false` with a client-safe `error` on failure. Recorded as an operator action |
| `POST /{id}/runs` | Request a run: `mode` (`full` or `incremental`, default `incremental`, for `ldap`; `reconcile` for `scim_outbound`), `dry_run`, and `allow_mass_deprovision` with a `reason` (10 to 500 characters; only for an applied full LDAP run, `422` otherwise). `202` with the run. One queued or running run per connector (`409` with `run_id` otherwise); a disabled connector, or an outbound connector without a usable configuration, is `409`. A queued or running run whose job already ended (cancelled, dead-lettered, or stopped while the module was disabled) does not count: it is closed first, `cancelled` if it never started and `failed` otherwise, with the reason in `error` |
| `GET /{id}/runs` | The newest 200 runs, newest first. Run states: `queued`, `running`, `succeeded`, `failed`, `refused`, `cancelled` |
| `GET /{id}/runs/{run}` | One run: state, counts, cursors, endpoint host, error |
| `GET /{id}/runs/{run}/findings` | The run's findings: `?kind=`, `?limit=` (default 50, at most 200), `?after=` with the returned `next_after` |
| `GET /{id}/health` | [Operational evidence](#operational-evidence) |
| `GET /{id}/deliveries` | The newest 200 outbound deliveries (`?state=`) |
| `POST /{id}/deliveries/{delivery}/replay` | Replay a dead-lettered delivery: `202`; `409` in any other state |

The `/provisioning-connectors` API now manages only `scim_inbound`
connectors: creating a `scim_outbound` connector there answers `422`
pointing to `/directory-connectors`, and directory connectors are not
listed there. `scim_outbound` rows that earlier releases created through
that API have no `base_url` and no encrypted credential: they are listed
here but stay inert (no deliveries, no runs; health `needs_configuration`)
until they are configured with `PUT /{id}` and `PUT /{id}/credential`
([outbound-provisioning.md](outbound-provisioning.md#connectors-created-through-the-old-api)).

## LDAP connector configuration

Example: a realm connector for an Active Directory domain.

```json
POST /api/v1/realms/main/directory-connectors
{
  "name": "corp-ad",
  "kind": "ldap",
  "credential": "<service account password>",
  "config": {
    "dialect": "active_directory",
    "endpoints": ["ldaps://dc1.corp.example:636", "ldaps://dc2.corp.example:636"],
    "bind_dn": "CN=svc-proudauth,OU=Service Accounts,DC=corp,DC=example",
    "user_base_dn": "OU=Staff,DC=corp,DC=example",
    "jit_provisioning": true,
    "incremental_interval_seconds": 900,
    "full_interval_seconds": 86400
  }
}
```

| Member of `config` | Rules |
| --- | --- |
| `endpoints` | 1 to 8 `ldaps://host[:port]` or `ldap://host[:port]` URLs, tried in order; no credentials, path or query |
| `start_tls` | Default `true`: `ldap://` endpoints upgrade with StartTLS before any credential is sent. `false` (cleartext) is refused outside `development` mode |
| `ca_certificates_pem` | Additional trusted roots for this connector (at most 64 KiB). Certificates and host names are always verified, TLS 1.2 or later; there is no option to skip verification |
| `connect_timeout_seconds`, `operation_timeout_seconds` | 0 to 60 and 0 to 120; `0` uses the deployment default |
| `bind_dn` | The service account's DN (at most 1024 characters; so is `user_base_dn`) |
| `dialect` | `openldap` (default) or `active_directory`; selects the defaults below |
| `user_base_dn`, `user_scope` | Where users are searched; scope `sub` (default) or `one` |
| `user_filter` | RFC 4515 filter (at most 2048 characters), compiled when the connector is saved |
| `id_attribute` | The entry's immutable ID |
| `login_attributes` | Up to 4 attributes a sign-in identifier is matched against |
| `attribute_mapping` | Up to 32 entries `"<local attribute>": "<directory attribute>"`. Local attributes: `username`, `email`, `display_name`, `given_name`, `family_name`, `locale`, `zoneinfo`, `profile.<name>` (`<name>` matching `[a-z][a-z0-9_]{0,63}`). Phone numbers cannot be mapped (they would need proof of control, USR-004). The dialect's default mapping applies only when the member is empty; it is not merged with a mapping you give |
| `mode`, `attribute_authority`, `write_back_attributes` | [Directory-authoritative accounts](#directory-authoritative-accounts-and-write-back) |
| `disabled_attribute`, `disabled_values` | An attribute whose listed values mark an entry disabled; without `disabled_values`, the attribute's presence alone does (Active Directory also uses `userAccountControl`) |
| `change_tracking` | `usn`, `modify_timestamp` or `none` |
| `page_size` | Simple paged results (RFC 2696), 1 to 5000, default 500 |
| `max_entries` | 0 (use `directory.max_entries_per_run`) or a lower bound for this connector; a value above `directory.max_entries_per_run` is refused (`422`). If the operator lowers the deployment bound later, runs are clamped to it and an update that keeps the stored value is still accepted |
| `group_base_dn`, `group_filter`, `group_name_attribute`, `group_member_attribute` | Group settings; the base DN defaults to `user_base_dn`, the name attribute to `cn`, the member attribute is `member`, `uniqueMember` or `memberUid` |
| `jit_provisioning` | [First sign-in provisioning](#first-sign-in-provisioning); realm connectors only |
| `incremental_interval_seconds` | `0` (not scheduled) or 60 to 604800 |
| `full_interval_seconds` | `0` (not scheduled) or 300 to 2592000 |
| `deletion_threshold_percent`, `deletion_threshold_count` | [Deletion detection](#deletion-detection-and-deprovisioning); percent 1 to 100, default 20; the count is an optional cap |
| `deprovision_action` | Realm connectors: `suspend_account` (default) or `report_only`. Organization connectors: `remove_membership` (default), `suspend_membership` or `report_only` |

Dialect defaults:

| | `openldap` | `active_directory` |
| --- | --- | --- |
| `user_filter` | `(objectClass=inetOrgPerson)` | `(&(objectCategory=person)(objectClass=user))` |
| `id_attribute` | `entryUUID` | `objectGUID` (binary; stored as hex and escaped byte by byte in filters) |
| `username` from | `uid` | `sAMAccountName` |
| `email`, `display_name`, `given_name`, `family_name` from | `mail`, `displayName`, `givenName`, `sn` | the same |
| `login_attributes` | `uid`, `mail` | `sAMAccountName`, `userPrincipalName`, `mail` |
| `change_tracking` | `modify_timestamp` | `usn` (`uSNChanged` and `highestCommittedUSN`) |
| Disabled entries | `disabled_attribute` and `disabled_values` | `userAccountControl` bit `0x2`, plus the optional attribute |
| Groups | `(objectClass=groupOfNames)`, `member` | `(objectClass=group)`, `member` |

Configuration errors are `422 validation_failed` with
`errors["config.<field>"]` (for example an endpoint without TLS in
production, a malformed filter, write-back of an identifier, JIT on an
organization connector); a group mapping or default role outside the
connector's `role_ceiling_ids` is also `422`, and a ceiling role beyond the
administrator's own delegation ceiling is `403 grant_ceiling_exceeded`.
Endpoints without a port use 389 (`ldap://`) or 636 (`ldaps://`).

## Connections, TLS and failover

PROV-014.

- Each operation connects to the first endpoint that works, in the
  configured order. The egress policy is checked against **every address
  the host name resolves to, at connection time**: private and loopback
  ranges only with `directory.allow_private_network` (development) or
  CIDRs in `directory.egress_allowlist`; the residency policy
  (`privacy.residency.allowed_destinations`) applies too.
- `ldaps://` performs the TLS handshake directly; `ldap://` performs
  StartTLS before any bind. Certificates are verified against the system
  roots, `directory.ca_file` and the connector's `ca_certificates_pem`, with
  the host name checked and TLS 1.2 or later.
- **Failover happens only on transport failures:** connection refused, DNS
  errors, TLS handshake or verification failures, timeouts, broken
  connections, malformed responses, and the server result codes `busy` and
  `unavailable`. An answer about the request itself (invalid credentials,
  insufficient access, no such object, a refused service bind) is final and
  is never retried on another endpoint.
- Referrals and continuation references are never followed, so an operation
  never reaches a server that is not configured.
- When every endpoint fails, the operation reports the directory as
  unavailable.
- Health per endpoint (last success, last failure category, consecutive
  failures), keyed by `host[:port]` as written in the endpoint URL, is kept
  per node and saved in the connector's evidence when it changes.

## Sign-in with directory passwords

- The password of a directory-sourced account is verified **by a bind as
  that account**: the service account binds and finds the entry by its
  stored DN (and, if the entry moved, by its immutable ID); the entry must
  still match `user_filter`, carry the same ID and not be disabled; then a
  simple bind with the user's DN and password decides. Password hashes are
  never read or stored. A moved entry's new DN is recorded.
- Empty passwords are never sent (they would be unauthenticated binds, RFC
  4513 §5.1.2); passwords longer than 1024 bytes are rejected.
- The local password credential of a directory-sourced account is never
  consulted; adopting an account revokes it. Local accounts keep their
  local passwords, including during a directory outage.
- A directory outage, a disabled connector or a disabled module answers
  **`503 upstream_unavailable`** with `Retry-After: 30` and never falls
  back to a local password or another source (TEST-027, FED-012). An
  outage is audited as `directory.authentication.unavailable`; every case
  is counted in `proudauth_directory_binds_total` (`outcome` `unavailable`
  or `disabled`).
- One sign-in attempt's directory work (service bind, search and user
  bind, across every endpoint, and across every connector first sign-in
  provisioning tries) ends at `directory.sign_in_timeout` (8 s) in total,
  as `503 upstream_unavailable`; an endpoint that accepts connections and
  never answers cannot hold the attempt for each endpoint's timeouts in
  turn. At most `directory.max_concurrent_binds` such attempts run at once
  per process; beyond that a sign-in that needs the directory answers
  `503 unavailable` with `Retry-After: 5` at once and is counted
  as `outcome` `busy`. A password step that may ask a directory is never
  retried after a database deadlock, so the directory never sees the same
  bind twice (DB-014).
- A wrong password, or a disabled or missing entry, is
  `401 invalid_credentials`, as for local accounts. MFA, the temporary
  password lock and the realm's rate limits apply as for local passwords;
  the local lock also shields the directory's own lockout counter from
  online guessing.
- Other sign-in methods of a directory-sourced account (passkeys, email
  codes, federation) follow realm policy. A disable in the directory
  reaches them at the next synchronization; the bind itself refuses a
  disabled entry at once.

### First sign-in provisioning

FED-015. A realm connector with `jit_provisioning: true` creates the
account the first time its user signs in. When a sign-in identifier matches
no local account, the realm's JIT directories are searched in name order
with the identifier escaped into
`(&<user_filter>(|(<login attribute>=<value>)...))` (RFC 4515):

- the first directory with a match decides: exactly one enabled entry and a
  successful bind create and link the account, with the same rules as
  synchronization, including conflict refusal (an entry that collides with
  an existing account is refused and audited as
  `directory.user.jit_refused`, never merged);
- a wrong password there is final; other directories are not tried with the
  same credentials;
- any unreachable JIT directory fails the attempt closed (`503`, not
  audited as `directory.authentication.unavailable`);
- the extra directory round trips for identifiers unknown locally are
  masked only up to the password step's minimum response time
  (`security.min_auth_response`), and not at all when the attempt ends in
  `503`.

Organization connectors cannot enable it: a server that a tenant
administrator configured must never receive sign-in attempts, and
passwords, for identifiers it does not own.

### User-storage modes

PROV-011 asks for documented user-storage modes:

- **Import (synchronized):** scheduled or manual runs import entries as
  local accounts linked to the directory; passwords stay in the directory.
- **Import at first sign-in:** `jit_provisioning` on a realm connector.
- **Not offered: no import** (looking users up live without a local
  account). Every account needs a stable local subject for sessions,
  refresh-token families, memberships, MFA factors, consents and audit
  evidence; a lookup-only mode would give none of them a durable anchor.

In both modes the directory remains authoritative as the connector's write
mode declares.

### Accounts a directory creates

- `created_via` is `directory:<connector id>`. The username comes from the
  mapped attribute when it is a valid local username. The email is
  verified **only** for organization connectors and only when its domain is
  verified by that organization; realm connectors import emails unverified
  (users sign in with their directory username). Names, locale, time zone
  (validated) and profile values are imported.
- Organization connectors create an active membership (source `directory`,
  outbox event `organization.membership.added`) with `default_role_id` when
  set.
- Disabled directory entries are not imported.

## Synchronization

PROV-012, PROV-017.

- **Runs** are jobs of type `directory.sync`, one queued or running per
  connector. The job input names the run (and its connector); the handler
  loads both from the database and re-checks that the requester still holds
  `realm.provisioning.manage` (or `org.integrations.write` for an
  organization connector); scheduled runs are requested by `system`. A
  disabled connector or organization cancels the run (TEST-063), and so
  does `directory.enabled: false`. A run whose job ended without it (for
  example a job cancelled through the jobs API) is closed by the next
  scheduler pass or run request, so it never blocks the connector.
- **Scheduling:** the worker task `directory.schedule` (every 15 seconds)
  claims due slots (`next_sync_at`, `next_full_sync_at`) with a conditional
  update and queues the run in the same transaction; a full run also
  satisfies the incremental slot.
- **Full run:** a paged search of `user_filter` under `user_base_dn`, each
  entry applied in its own transaction (idempotently), then deletion
  detection, then group mapping.
- **Incremental run:** Active Directory searches
  `(uSNChanged>=<cursor + 1>)`, where the cursor is the
  `highestCommittedUSN` read **before** the search and stored with the
  domain controller's identity (`dsServiceName`); a cursor from another
  controller (for example after failover) turns the run into a full run.
  OpenLDAP searches `(modifyTimestamp>=<newest seen − 5 minutes>)`. Without
  a cursor, with `change_tracking: none` or with an unusable cursor, the
  run becomes a full run (`counts.incremental_promoted_to_full`).
  Incremental runs cannot detect deletions; full runs do.
- **Cursors** advance when a run ends `succeeded` or `refused`, never for
  a failed run or a dry run.
- **Dry run:** the same logic inside transactions that are rolled back, so
  the findings (`applied: false`) are what an applied run would do at that
  moment. A dry run records no `directory.sync.completed` event and does not
  change `last_sync_at`.
- **Resumability:** entries are applied one transaction at a time and
  idempotently. A crash or failover during a run starts over from the
  beginning and never deprovisions on partial data (deletion detection runs
  only after a complete scan); a failed run leaves the cursor unchanged.
  Each applied transaction locks the owning job claim before domain rows.
  An expired or replaced worker cannot change users, Groups, delivery state,
  findings or the recovered run/cursor when it resumes. Job ownership includes
  the attempt number even when a worker ID is reused. A takeover repeats the
  scan; already committed entries retain their original account IDs and do
  not repeat provisioning audits. [Replica scheduling and expiry evidence](../operations/consistency-tests.md#directory-schedules-and-expired-worker-leases--2026-10-12)
  describes the tested profile and its limits.
  [Native worker-task death](../operations/consistency-tests.md#native-directory-worker-process-death--2026-10-12)
  also verifies full/incremental recovery after an OS kill following the first
  committed page, retaining account IDs and exact mutation audits. The
  database/directory remain alive and lease expiry uses the controlled clock.
- **Limits:** `directory.max_entries_per_run` (default 100,000), or the
  connector's lower `max_entries`; a run that exceeds it fails without
  deprovisioning. At most
  5,000 findings are stored per run (counts stay complete;
  `findings_truncated`).

### Conflicts

Conflicts are reported, never merged. An entry whose username or verified
email belongs to an existing account without a directory link is adopted
only by an **organization** connector, and only when the account's
verified email equals the entry's, the domain is verified by the
organization, the account is neither protected nor holds a privileged realm
role, no other connector manages it (accounts created by inbound SCIM or
another directory are never adopted), and the username (if any) belongs to
the same account: the same rule as inbound SCIM. Adoption revokes the
account's local password. Otherwise the run records a `conflict` finding
with reason `identifier_in_use`, `domain_not_verified`,
`protected_account`, `managed_by_another_connector` or
`identifiers_belong_to_different_accounts`. An entry without a usable
username or email, or without the ID attribute, is an `error` finding
(`no_usable_identifier`, `missing_id_attribute`).
Findings never contain attribute values or the conflicting account's ID,
so an organization administrator does not learn which realm accounts exist.
Realm connectors never adopt existing accounts.

### Deletion detection and deprovisioning

- Linked accounts that a complete full run did not see count as deleted
  in the directory. After transport failover, only the endpoint that
  completes its full scan supplies this presence set; users seen solely
  on a failed partial endpoint do not suppress deletion. Applied entry
  changes remain committed/idempotent across retry. When every endpoint
  fails, deletion detection does not run and the cursor remains unchanged.
  [Interruption and complete-source evidence](../operations/consistency-tests.md#directory-transport-interruption-and-complete-source-deletion--2026-10-12)
  covers full and promoted incremental scans plus outage/recovery.
  If missing accounts exceed `deletion_threshold_percent` of the
  linked accounts (or `deletion_threshold_count` when set), the run
  deprovisions nothing, records `deprovision` findings with reason
  `deletion_threshold_exceeded` and ends in state `refused`; its other
  changes are applied (audit reason `DELETION_THRESHOLD_EXCEEDED`). After
  checking the directory, an operator can request one full run with
  `"allow_mass_deprovision": true` and a `reason` of at least 10
  characters, audited with reason `MASS_DEPROVISION_OVERRIDE` and recorded
  as an operator action.
- `deprovision_action`: realm connectors `suspend_account` (default; a
  directory never deletes accounts) or `report_only`; organization
  connectors `remove_membership` (default), `suspend_membership` or
  `report_only`, never the realm account or other memberships (PROV-005,
  TEST-048). Protected accounts and holders of privileged realm roles are
  never deprovisioned. When the account or membership is deprovisioned, the
  link stays with state `missing`, so a returning entry with the same
  immutable ID is linked and reactivated again (with `report_only`, and for
  protected or privileged accounts, the link is left unchanged).
- **Disable and enable:** a disabled entry suspends the realm account
  (realm connectors, reason `DIRECTORY_DISABLED`) or the organization
  membership (organization connectors). Re-enabling the entry, or an entry
  that returns after deprovisioning, undoes only what the directory did:
  - realm connectors reactivate the account only when its latest
    suspension was the directory's (`DIRECTORY_DISABLED`,
    `DIRECTORY_DEPROVISIONED`); otherwise it stays suspended (divergence
    `suspended_locally`);
  - organization connectors reactivate a suspended membership only when
    its latest suspension was made by this connector, and give a returning
    entry a new membership only when the latest removal of its membership
    in the organization was this connector's (or there is none). A
    membership an administrator (or anyone else) suspended or removed last
    stays so, reported as divergence `suspended_locally` or
    `removed_locally`. Who made the change is read from the audit event
    recorded with every membership state change; a suspension whose event
    audit retention has already removed stays in place;
  - linking or adopting an account never changes the state of a
    membership it already has.

### Attribute authority and oscillation

PROV-017. Each mapped attribute has exactly one authority:

| Authority | Synchronization | Local edits |
| --- | --- | --- |
| `directory` | Overwrites the local value | Refused |
| `write_back` | Applies directory changes | Written to the directory first |
| `local` | Imported when the account is created, never overwritten; full runs report differences as `divergence` findings | Allowed |

Synchronization compares the directory's value with the current local
value, so after a write-back the next run sees the same value and changes
nothing (no oscillation). Organization connectors
own identity attributes only of accounts they created that belong to no
other organization; for shared accounts they manage only the membership
state and report differences (`divergence`, reason `shared_account`). One
directory per account (unique index), and a directory never adopts accounts
that inbound SCIM created. The reverse is not prevented: an inbound SCIM
connector can adopt a directory-sourced account into its organization under
its own adoption rule; it manages only that membership, because it never
owns the identity attributes of an account it did not create.

### Groups

Organization connectors only (PROV-007). Only directory groups named in
`group_role_mappings` (by name under `group_base_dn`, or by DN) are
mirrored. The connector creates and owns one local group per mapped group
(source `directory`; it never takes over an existing group with the same
name), keeps its members equal to the directory members it manages, and
grants the mapped roles (source `directory`). Every role the group carries,
including roles others granted to it and roles inherited from parent
groups, must stay within the connector's ceiling
(`group_roles_beyond_ceiling` otherwise). Only direct members count: nested
groups are not expanded, and Active Directory ranged retrieval
(`member;range=`) for groups larger than the server's `MaxValRange` (1500
by default) is not implemented.

Group application locks the local group before its source mapping and
members, matching administrator/SCIM deletion (PROV-008, DB-014). Local
deletion removes the directory Group link; the next sync can recreate the
group if it still exists in the authoritative source. An older orphan link
is repaired on apply only when its local group is absent. Dry runs roll
back this repair. Disable or change the source/mapping if deletion should
persist across future syncs. [Deletion and repair regressions](../operations/consistency-tests.md#mixed-group-deletion-and-link-repair--2026-10-11)
include repeated full LDAP sync and preserve outbound cleanup references.

### Findings

Finding kinds: `create`, `update`, `link`, `suspend`, `reactivate`,
`deprovision`, `conflict`, `divergence` (`local_authority`,
`shared_account`, `suspended_locally`, `removed_locally`), `skip`
(`disabled_in_directory`, `protected_account`), `error` (for example
`linked_account_deleted` for an entry whose account was deleted; it carries
no DN) and `group`; outbound reconciliation adds
`missing_remote`, `drift`, `orphan_remote` and `unmanaged_remote`
([outbound-provisioning.md](outbound-provisioning.md#reconciliation)).

## Directory-authoritative accounts and write-back

USR-022, PROV-013.

| `mode` | Mapped attributes | Directory writes |
| --- | --- | --- |
| `read_only` (default) | Externally managed | None |
| `import_only` | Owned locally after import; differences are reported, never overwritten | None |
| `write_back` | Those in `write_back_attributes` are editable and written to the directory first by an LDAP modify as the service account (which needs write access to them); the others stay externally managed | The listed attributes |

`attribute_authority` can declare individual mapped attributes `local` (or
`directory`). In every mode the directory owns the **password** and the
account lifecycle (disable, deprovision).

Enforcement is one check (`identity.AttributeAuthority`) called inside the
editing transaction of every path: self-service profile and identifiers
(`PATCH /me`, `/me/identifiers`), administrator profile edits
(`PATCH /users/{user}`), every way of setting a password (`POST
/me/password`, password reset completion, account setup tokens, the
`update_password` required action), and reactivation of an account the
directory disabled.
Administrator metadata is always local. A local edit of an externally
managed attribute is `409 conflict`: `detail` names the attributes and the
connector, `errors.<attribute>` is `externally managed`, and the extension
members are `externally_managed` (a list) and `connector_id`. Sending an
attribute's current value is not a change.

A write-back the directory refuses (for example for missing rights) is
`409 conflict`, and a directory that cannot be reached `503
upstream_unavailable`; the local edit is not made either. If the directory
accepted the write but the local transaction then failed, the next
synchronization applies the directory's value.

Not offered: write-back of `username` or `email` (a changed identifier
needs proof of control) and **password write-back**. Password write-back
needs a service account with reset-password rights over every user object
(equivalent to domain-wide account takeover authority held by the identity
provider), Active Directory's `unicodePwd` modify semantics over LDAPS with
policy errors (history, complexity, minimum age) that surface opaquely, and
change-versus-reset semantics; PROV-013 requires a reviewed connector and
transport policy for it, which this release does not claim. Users change
their passwords in the directory.

### Attribute-authority declaration

Applications and login interfaces can ask which attributes and operations
are editable:

- `GET /api/v1/realms/{realm}/me/attribute-authority` (account token);
- `GET /api/v1/realms/{realm}/users/{user}/attribute-authority`
  (administration token from an MFA session, `realm.users.read`).

```json
{
  "source": {"type": "directory", "connector_id": "con_...", "name": "corp-ad",
             "mode": "write_back", "state": "active"},
  "attributes": {"username": "externally_managed", "email": "externally_managed",
                 "display_name": "write_back", "locale": "local"},
  "operations": {"password_change": "externally_managed",
                 "password_reset": "externally_managed",
                 "reactivation": "local"}
}
```

`source` is `null` for local accounts; otherwise it names the connector
(`organization_id` for organization connectors), its `mode`, and in `state`
the link's source state (`active`, `disabled`, `missing` or `deleted`). `attributes`
covers `username`, `email`, `phone`, `display_name`, `given_name`,
`family_name`, `locale`, `zoneinfo` and mapped `profile.<name>` attributes,
each `local`, `externally_managed` or `write_back`; for an account an
organization connector does not own (one shared with another organization)
they all stay `local`. In `operations`, the password operations are
`externally_managed` for every directory-sourced account, and
`reactivation` is `externally_managed` while a realm connector's entry is
disabled or missing.

## Operational evidence

PROV-018. `GET .../{id}/health`:

| Member | Meaning |
| --- | --- |
| `status` | `healthy`, `degraded`, `disabled`, `needs_configuration` (an outbound connector without a usable configuration; `configuration_error` says why) or `needs_credential` |
| `credential_set_at`, `last_sync_at`, `last_success_at`, `lag_seconds`, `consecutive_failures` | Synchronization freshness |
| `last_error` | A client-safe summary: categories and host names only |
| `endpoints` | Health per endpoint, keyed by `host:port`: `last_ok_at`, `last_failure_at`, `last_failure_category`, `consecutive_failures` |
| `last_run` | The latest run |
| `managed_accounts`, `managed_groups` | Linked accounts by source state (`deleted` for links of erased accounts), and groups the connector owns |
| `deliveries`, `oldest_due_seconds`, `last_delivered_at` | Outbound connectors: deliveries by state |
| `operator_actions` | The latest 20 operator actions with actor and time: `created`, `updated`, `state_disabled`, `state_active`, `credential_set`, `tested`, `run_*`, `mass_deprovision_authorized`, `delivery_replayed` |

Credentials never appear in responses, run errors, findings, logs or audit
metadata (the end-to-end tests check the connector, health, run and
delivery responses and audit metadata). Metrics and alert suggestions are
in
[monitoring.md](../operations/monitoring.md#directory-integration).

## Errors

All errors are problem details; no new problem codes were added.

| Situation | Status and `code` |
| --- | --- |
| Local edit of an externally managed attribute or operation | `409 conflict` with `externally_managed` and `connector_id` |
| Directory unreachable during sign-in or write-back; connector or module disabled | `503 upstream_unavailable` with `Retry-After: 30`; never a fallback |
| Wrong directory password; disabled or missing entry | `401 invalid_credentials` |
| Write-back refused by the directory | `409 conflict`; the local change is not made |
| Invalid configuration | `422 validation_failed` (`errors["config.<field>"]`) |
| Ceiling or mapping beyond the administrator's own | `403 grant_ceiling_exceeded` |
| A second run while one is queued or running | `409 conflict` with `run_id` |
| A run or replay of an outbound connector without a usable configuration | `409 conflict` |
| Deleting a connector that is not disabled | `409 conflict` |
| `directory.enabled: false` | `404 feature_disabled` on the connector APIs |

## Audit events

All carry the connector as target or actor and never contain secrets.

| Event | Category |
| --- | --- |
| `directory.connector.created`, `.updated`, `.deleted`, `.credential_set`, `.tested` | `configuration`, `operations` |
| `directory.sync.requested` (reason `MASS_DEPROVISION_OVERRIDE` for an override) | `operations` |
| `directory.sync.completed` (outcome `failure` and reason `DELETION_THRESHOLD_EXCEEDED` for a refused run) | `operations` |
| `directory.user.provisioned`, `.linked`, `.updated`, `.deprovisioned`, `.written_back`, `.jit_refused` | `account` |
| `directory.authentication.unavailable` | `operations` |
| `directory.outbound.dead_lettered`, `.replayed` | `operations` |

The standard membership, group, role and account-state events are recorded
with the connector as actor. Find them with
`GET /audit-events?type_prefix=directory.` or `?actor_id=con_...`
([monitoring.md](../operations/monitoring.md#audit-queries)).

## Stored data and upgrade note

Migration `0065_directory_integration.sql` is expand-only:

- `provisioning_connectors.organization_id` becomes nullable (realm
  connectors), and the table gains `secret_set_at`, `next_sync_at`,
  `next_full_sync_at`, `last_success_at`, `consecutive_failures` and
  `evidence`. Older binaries select connectors only by organization and
  authenticate only `scim_inbound` connectors, so they never act on these
  rows.
- `connector_external_ids` gains `link_kind`, `source_dn`, `snapshot`,
  `snapshot_digest`, `source_state`, `last_seen_run`, `last_seen_at`,
  `missing_since`, an index on `local_id` and the unique partial index "one
  directory per account".
- New tables `directory_sync_runs`, `directory_sync_findings` and
  `outbound_deliveries`.

Migration `0085_directory_retention.sql` adds indexes only (findings by
account, finished runs and deliveries by age, queued and running runs by
connector); it is expand-only.

Links hold DNs and imported attribute values (the snapshot), findings hold
DNs, external IDs and attribute names (not values), and runs hold cursors
(USN or timestamps, the domain controller's name)
([data-inventory.md](../operations/data-inventory.md#directory-integration)).

- **Retention.** The worker's retention task (step `directory_history`)
  deletes, once they are older than **90 days** (or
  `privacy.history_retention` when that is shorter): the findings of
  finished runs, finished runs themselves except each connector's latest
  (kept as evidence of its last outcome, without its findings once they
  are that old), and finished outbound deliveries (`delivered`,
  `dead_letter`, `replayed`). Queued and running runs and open deliveries
  are never pruned. Audit events about runs follow audit retention.
- **Account deletion (PRV-005).** Erasing an account clears its directory
  link's DN and attribute snapshot; the link keeps only the entry's
  immutable ID and the account ID, with source state `deleted`, so the
  next synchronization reports the entry (`linked_account_deleted`, without
  its DN) instead of importing it as a new account, and deletion detection
  ignores it. The DN is also removed from every finding that names the
  account (by account ID, or by the entry's ID under the link's connector).
  Outbound mappings keep only the downstream resource ID, which
  deprovisioning the account downstream needs.
Deleting an organization disables its directory connectors, as for other
connector kinds. Older binaries in a mixed-version window have no
`/directory-connectors` routes and no directory sign-in: create connectors
after the rollout.

## Not supported

Supported: LDAPv3 simple bind over LDAPS or StartTLS; OpenLDAP-style and
Active Directory directories; simple paged results; Active Directory USN and
`modifyTimestamp` change tracking; the Active Directory
`userAccountControl` disable bit and a configurable disable attribute;
direct group membership through `member`, `uniqueMember` or `memberUid`.

Not supported, and not advertised:

- SASL binds (GSSAPI/Kerberos, DIGEST-MD5, EXTERNAL with client
  certificates), NTLM, anonymous binds;
- password write-back and identifier write-back;
- Active Directory DirSync and LDAP Content Synchronization (RFC 4533)
  controls; reading Active Directory tombstones (`isDeleted`); deletions are
  detected by full runs;
- nested group expansion and ranged attribute retrieval;
- referral chasing;
- a lookup-only user-storage mode without local accounts;
- Kerberos and SPNEGO sign-in (below).

### Kerberos and SPNEGO are not offered

PROV-015 allows a Kerberos/SPNEGO adapter only as an optional module with
explicit keytab custody, service-principal configuration, trust boundaries
and negative tests. None is shipped or advertised
([ADR 0018](../architecture-decisions/0018-enterprise-protocols-when-complete.md)):

1. **Keytab custody.** An SPNEGO acceptor needs the service principal's
   long-term key (keytab), which lets its holder impersonate the service
   and decrypt every service ticket issued for it. ProudAuth's key
   hierarchy has no keytab custody, no rollover tied to the KDC's key
   version number (kvno), and no way to distribute it to every node.
2. **Trust boundaries.** Accepting tickets makes the Active Directory
   domain, and any trusted realm or forest, an authentication authority
   for realm accounts, with identity and group claims in the PAC that need
   signature validation; cross-realm trust, mapping principals to accounts
   and organization boundaries (FED-015) need their own design.
3. **Protocol hardening.** A replay cache shared across nodes, a clock-skew
   policy, channel binding (Extended Protection), encryption-type allow
   lists (no RC4 or DES), and safe `Negotiate` handling through the external
   login interface ([ADR 0017](../architecture-decisions/0017-external-login-ui.md))
   and proxies that strip or cache `WWW-Authenticate`.
4. **Negative tests.** They need a KDC test harness (forged, expired and
   replayed tickets, wrong SPN, wrong realm) that does not exist yet.

Alternatives today: LDAP bind against Active Directory over LDAPS (this
page), and enterprise SSO through OpenID Connect (the `microsoft` adapter
for Entra ID) or SAML ([saml.md](saml.md), for example with ADFS or Entra
ID; not yet tested against them).

## Testing and interoperability status

- `TestLDAPDirectorySignIn`, `TestDirectorySynchronization`,
  `TestDirectoryAuthority` and `TestDirectoryTenantIsolation` run against
  `internal/directory/ldaptest`, an in-process LDAP server written for these
  tests (OpenLDAP- and Active Directory-style data, LDAPS, StartTLS, paged
  results, USN).
- `TestDirectoryQueuedRunWhileDisabled`, `TestDirectoryErasureAndRetention`
  and `TestDirectoryMembershipReactivation` cover runs queued while the
  module is disabled and runs whose job ended, the `max_entries` bound,
  account erasure and retention, and reactivation of only the memberships
  the directory itself suspended or removed.
- Unit tests cover filter escaping (`*@corp.test` becomes
  `\2a@corp.test`), configuration rules, failover on transport errors only,
  TLS verification, operation timeouts, paged search, the `max_entries`
  bound and outbound connector usability.
- **Pending (QA-004):** no run against a real Active Directory, OpenLDAP,
  389 Directory Server or other directory. Treat compatibility with your
  directory as unverified until you have tested it, starting with a dry
  run.

Threat analysis: [threat-models/directory.md](../threat-models/directory.md).
