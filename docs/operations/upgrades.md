# Upgrades

Requirements: DEP-012, DEP-020, OPS-008, OPS-012, OPS-013, TEST-061, API-013.

ProudAuth publishes 0.2.0 prereleases (`v0.2.0-alpha.N`). Until 1.0 there is no
compatibility promise between versions; read [CHANGELOG.md](../../CHANGELOG.md)
before every upgrade.

Audit pagination from earlier development builds uses a different cursor
MAC scope. After upgrading, restart `GET /audit-events` and organization
audit listings from the first page; existing cursors return `400 invalid
cursor`. Preserve filters while paging; page size may change. Event-type
prefixes are literal, so `%`, `_` and backslash no longer act as SQL search
wildcards. No audit records or schema migrations change.

Metadata/JWKS retry budgets now cover concurrent and failed fetches in
OIDC brokering, workload federation and Shared Signals. After an upstream
failure, retry after one minute; repeated calls retain the failure during
that cooldown. An administrator's fresh connection test or configuration
change explicitly invalidates its provider cache. Complete the server
rollout before relying on these per-process bounds; no schema migration
or persisted counter changes are required. Workload's existing last-good
transport/status fallback remains as documented.

## How migrations work

- SQL migrations (`migrations/NNNN_*.sql`) are embedded in every binary and applied
  in lexical order by `identity-cli migrate`, `identity-server -migrate`, or the
  server and the worker at startup when `storage.migrate_on_start: true`. Other
  operator commands never apply migrations.
- The runner holds a PostgreSQL advisory lock, so concurrent migrators serialize.
- Each migration runs in its own transaction and is recorded with a SHA-256 checksum
  in `schema_migrations`. If an applied migration's checksum differs from the
  binary's copy, `migrate` stops with an error.
- If the database contains a migration the binary does not know (the database is
  newer), `migrate` refuses to run.
- There are **no down migrations**.
- **Safety gates (OPS-008).** A migration marked `-- proudauth:compat=contract`
  (it removes or rewrites schema older binaries need) runs only when the operator
  passes the identifier of a verified backup:
  `identity-cli migrate -backup-reference <snapshot-or-dump-id>`. The reference is
  recorded in `schema_migrations.backup_reference`; automatic migration
  (`migrate_on_start`, `identity-server -migrate`) never runs a contract migration.
  A migration may declare `-- proudauth:precondition <SQL>` lines (single-row boolean
  queries, for example "no rows still use the old column"); every precondition must
  hold or the run stops before changing anything.
- `identity-cli migrate -plan` lists pending migrations with their compatibility
  class and precondition results without applying them; it is read-only and
  runs with the runtime role. Preconditions of later pending migrations are
  evaluated against the current schema. Every run that applies migrations is
  recorded in the audit log as the operator event
  `operations.migrations.applied` (no realm; metadata `migrations`):
  `identity-cli migrate` with the backup reference, startup migrations with
  actor `startup:<hostname>` and `trigger` (`migrate_flag` or
  `migrate_on_start`) ([installation.md](installation.md#4-check-and-migrate)).
- With `storage.migration_database_url` set, migrations run as that
  (schema-owner) role and `storage.runtime_role` is granted data privileges
  after each run ([installation.md](installation.md#database-roles)).

Readiness and startup checks:

| Situation | `identity-server` | `identity-worker` | `identity-cli doctor` |
| --- | --- | --- | --- |
| Schema behind the binary | Starts; `/health/ready` returns 503 | Refuses to start | Fails ("schema is behind this binary") |
| Schema ahead of the binary, expand-only (newer migrations applied) | Starts and reports ready | Starts | Passes |
| Schema ahead of the binary with a newer contract migration | Refuses (`schema is incompatible with this binary`) | Refuses | Fails |
| Applied migration modified | `migrate` fails; serving is unaffected | — | Passes |

## Expand → migrate → contract

Every schema change is split so that the previous release keeps working against
the new schema:

1. **Expand** (release N+1): additive changes only — new tables, new nullable
   columns, new indexes, relaxed constraints. Release N ignores them.
2. **Migrate** (release N+1 code): write both old and new shapes; backfill in
   bounded batches outside the migration transaction.
3. **Contract** (release N+2 or later): remove what release N+1 no longer reads.

## Rolling upgrade procedure

1. Back up the database and verify you hold the matching keys ([backup-restore.md](backup-restore.md)).
2. Read the changelog for configuration changes. Unknown configuration keys are
   startup errors, so remove keys that a new version dropped and add required ones
   before restarting. Check the edited file with the **new** CLI:
   `identity-cli config-diff -from <current> -to <new>` validates it and marks
   changes that move a security boundary (`!`); every change takes effect only
   when a process restarts ([configuration.md](configuration.md#reviewing-a-change)).
3. Review `identity-cli migrate -plan` (new CLI), then run the **new** binary's
   migrations once: `identity-cli migrate -backup-reference <id from step 1>`.
4. Replace `identity-server` instances one at a time, waiting for `/health/ready`.
   A stopping instance reports `draining` on `/health/ready` for
   `server.drain_delay` before it closes its listeners, so the load balancer stops
   sending it requests first ([installation.md](installation.md#5-start-the-processes)).
5. Replace `identity-worker` instances. A stopping worker finishes its current
   task within `workers.drain_timeout` and hands back the work it still holds.
6. Run `identity-cli doctor` and the smoke checks (`scripts/smoke-test.sh` shows the
   minimal set: liveness, readiness, discovery, JWKS).

## Mixed-version window

During steps 3–5, old and new binaries run against the new schema. This is safe only
when the new release's migrations are expand-only, which is the project rule for
every release. The window should last only for the rollout itself; do not run two
versions side by side as a steady state. Older binaries do not know controls that
newer migrations add: for example, binaries without migrations `0024`–`0027`
ignore emergency grant controls, maintenance mode, debug windows and account
lifecycle rules, and binaries without `0028`–`0031` ignore scope step-up
requirements (they issue such scopes without stepping up), consent terms
versions and pre-authorizations, domain re-verification and service-principal
owner departure. Do not rely on these controls until every instance runs the
new version.

Migrations `0032`–`0037` are expand-only, but older binaries running against
them behave differently from new ones:

- An older worker's `retention.cleanup` ignores legal holds and
  `privacy.audit_retention_by_category`: it prunes by `privacy.audit_retention`
  alone and can delete held evidence. Place legal holds only after every worker
  runs the new version, and export evidence that must not be lost before the
  rollout.
- Older binaries reject the new keys `privacy.audit_retention_by_category` and
  `privacy.audit_archive_dir` (unknown keys are startup errors), so add them to
  the configuration only for new processes.
- Older workers do not archive audit batches, do not recompute dynamic groups
  and send an organization's mail through the deployment relay even when it has
  its own SMTP server (TEN-022). Older servers do not resolve organization
  aliases or route subdomains of verified domains; they let a new organization
  take a former slug, allow a client's `environment` to change and accept token
  exchanges across environments.
- Configure organization mail servers, dynamic groups and aliases once the
  rollout is complete.

Migrations `0038` (the `imported_audit_events` table and its indexes) and
`0039` (`audit_archive_state.directory`, default `''`) are expand-only as well.
With older binaries in the window:

- Older servers do not serve `POST /audit-imports`,
  `GET /imported-audit-events`, `GET /user-import-formats` or
  `GET /user-imports/reconciliation`, and do not clear imported audit records
  when they delete an account; older workers do not prune imported records.
  Import audit history only after the rollout.
- An older worker's `audit.archive` ignores `audit_archive_state.directory`:
  once an archive has forked after a restore, it would write into the main
  directory again, find the file taken and stop. Older workers also prune
  audit events without waiting for the archive, and older
  `identity-cli verify-audit-archive` does not know `archived_events` or fork
  directories. Run archiving workers and the verifier from the new version
  only.

Migrations `0040` and `0041` are expand-only too. `0040_flow_challenges.sql`
replaces three check constraints with wider ones (challenge purpose
`flow_challenge`, hook kind `authentication.risk`, and any adapter name
matching `^[a-z][a-z0-9_-]{0,31}$` instead of `oidc` and `github`), validating
them while it holds the tables' locks; `0041_custom_domains.sql` adds the
table `realm_custom_domains`. With older binaries in the window:

- Older servers do not evaluate realm `authentication_flow` rules, offer
  challenges or call `authentication.risk` hooks. Add rules only after every
  server runs the new version.
- Older binaries do not know the `google` and `microsoft` federation adapters
  and their rules (for example that Microsoft email addresses are never
  treated as verified). Create such connections only after the rollout.
- Older servers do not serve `/custom-domains` and do not check `Host`;
  register custom domains and turn on `server.host_policy: strict` after the
  rollout ([installation.md](installation.md#custom-domains)).
- Older binaries reject the new configuration keys `server.host_policy`,
  `storage.migration_database_url`, `storage.runtime_role`, `keys.kms`,
  `security.challenge_providers`, `observability.otlp_endpoint`,
  `privacy.residency` and `privacy.backup_retention`, and cannot resolve
  `kms:` references: give them to new processes only.

Migration `0042_scim_membership_source.sql` is expand-only: it replaces the
`memberships.source` check constraint with one that also allows `scim`. Older
servers have no SCIM routes and no `/provisioning-connectors` routes; create
connectors after every server runs the new version
([scim-provisioning.md](../integrations/scim-provisioning.md)).

Migrations `0060_saml.sql` and `0065_directory_integration.sql` are
expand-only. `0060` adds `clients.protocol` (default `oidc`) and the `saml_*`
tables; `0065` makes `provisioning_connectors.organization_id` nullable, adds
columns to `provisioning_connectors` and `connector_external_ids`, and adds
`directory_sync_runs`, `directory_sync_findings` and `outbound_deliveries`.
Older binaries have no SAML or `/directory-connectors` routes and no
directory sign-in; they select connectors only by organization and
authenticate only `scim_inbound` connectors, so they ignore the new rows.
Older servers apply neither the guards that keep a SAML application's
backing client from acting as an OAuth client nor the attribute-authority
check of directory-sourced accounts (local edits of managed attributes would
succeed there and be overwritten by the next synchronization): create SAML
applications and directory connectors only after every server runs the new
version. Older binaries reject the
`saml` and `directory` configuration sections; add them only for new
processes. `scim_outbound` connectors created earlier through
`/provisioning-connectors` become outbound connectors with no configuration:
disable them before the upgrade
([scim-provisioning.md](../integrations/scim-provisioning.md#upgrade-note)).

Migrations `0043`–`0046` are expand-only:

- `0043_custom_domain_claims.sql` replaces the unique index on custom-domain
  hosts with one over verified domains and one per realm. Older servers keep
  working, but they still treat a pending domain of another realm as taken.
- `0044_audit_prune_function.sql` replaces the audit guard trigger and adds
  `proudauth_audit_prune`. Older workers delete audit events directly, which
  the new guard allows only to the table owner: in a single-role deployment
  they keep pruning as before; with `storage.runtime_role`, an older worker's
  `retention.cleanup` fails (`audit_events is append-only`) from the moment
  `0044` is applied until the worker is replaced, so nothing is pruned in
  the window.
- `0045_cleanup_indexes.sql` creates eleven indexes for expiry and cleanup
  queries (DB-011) with plain `CREATE INDEX`, in the migration's single
  transaction: each table (`authorization_codes`, `opaque_access_tokens`,
  `dpop_proof_jtis`, `pushed_authorization_requests`, `device_codes`,
  `idempotency_records`, `outbox_events`, `sessions`, `notification_jobs`)
  is locked against writes (`SHARE`) until the whole migration commits.
  Brief on small tables; on large deployments run it in a quiet period
  ([capacity.md](capacity.md#storage-growth)).
- `0046_event_stream_horizon.sql` adds `event_stream_horizon`. Older workers
  do not record it, so cursors of realms they prune keep the old expiry rule
  (a cursor older than the oldest retained event expires); older servers
  ignore it.

Migrations `0070`–`0072` (extensibility) are expand-only:
`0070_lifecycle_workflows.sql` adds the workflow tables,
`0071_plugins.sql` adds `plugins`, `plugin_versions` and `plugin_id` on
`hooks` and `webhook_subscriptions`, and `0072_contract_versions.sql` adds
`webhook_subscriptions.event_version` and `hooks.contract_version`, both
`NOT NULL DEFAULT 1`, so every existing subscription and hook keeps exactly
what it sent and received before. With older binaries in the window:

- Older servers have no `/workflows`, `/plugins` or `/extension-contracts`
  routes, and older workers neither start nor advance workflow runs (an
  event dispatched by an older worker starts no run). Publish workflows and
  install plugins only after every server and worker runs the new version.
- Older binaries ignore `event_version`, `contract_version` and `plugin_id`:
  they deliver version 1 to every subscription, send hook requests without
  `ProudAuth-Hook-Version`, and let ordinary API calls change plugin parts.
  Move subscriptions to `event_version` 2 after the rollout.
- Older binaries reject the configuration key `extensions.plugin_publishers`:
  give it to new processes only.

Migrations `0084_extension_part_states.sql` and
`0085_directory_retention.sql` are expand-only. `0084` adds
`emergency_disabled` to `hooks` and `webhook_subscriptions` and
`plugin_retired` to `workflows`, all `NOT NULL DEFAULT false`; older binaries
ignore them, so a part an administrator disabled in an emergency can be
re-enabled there by enabling its plugin again, and a workflow a plugin
upgrade removed stays visible to them. `0085` only adds indexes for directory
retention and erasure; older binaries ignore them.

Migration `0086_anchor_readd_share_expiry.sql` is expand-only: certificate
trust anchors become unique per realm, purpose and fingerprint only while
active (a partial unique index replaces the table constraint, created
first), so a removed anchor's authority can be trusted again; and an index
on due shares serves the share expiry sweep. Older binaries keep working:
they too can then add an authority whose earlier anchor was removed.

Migration `0087_restore_marker.sql` is expand-only: it adds
`system_state.restore_pending_since` and `restore_pending_by`, `NULL` on
every database. New binaries report `/health/ready` as `503
restore_pending` and the worker refuses to start while the marker is set,
which only `identity-cli restore-begin` does on a restored database
([backup-restore.md](backup-restore.md)); older binaries ignore it, so run
only new binaries against a database you are restoring.

New binaries also change the user ownership transfer: `POST
/users/{user}/ownership-transfer` moves hooks, webhook subscriptions and
authorization policies too and so also needs `realm.hooks.write`,
`realm.webhooks.write` and `realm.policies.write`; give custom offboarding
roles those permissions.

New binaries also behave differently from older ones in ways that need
action:

- **Retention:** the worker now deletes ended grants (with their refresh
  tokens, codes and opaque tokens), ended sessions and, after the new
  `privacy.history_retention` (default 180 days), revoked consents, ended
  invitations, finished notification jobs and delivered or dead-lettered
  webhook and back-channel logout deliveries. Directory run history (runs,
  their findings) and finished outbound deliveries go after 90 days, or
  `privacy.history_retention` when that is shorter; each connector keeps its
  latest run ([data-inventory.md](data-inventory.md)). Export what you must keep longer
  before the first new worker runs.
- **Configuration import** needs, besides `realm.configuration.import`, the
  write permission of every change, and `expected_policy_revision` in any
  document that changes the realm policy; update automation and service
  principals that import
  ([exit-and-export.md](exit-and-export.md#configuration-import)).
- **Production configuration** now requires an `https`
  `observability.otlp_endpoint` (loopback excepted) and a lowercase
  `storage.runtime_role`; a configuration that violates the
  `security.mfa_floor` you add makes every later realm policy update fail
  until the realm's MFA settings are raised.
- **Legacy password verifiers** stop verifying after
  `security.password.legacy_hashes_until`; check `identity-cli doctor` for
  the number of accounts still on them before setting it.
- Older binaries reject the new keys `privacy.history_retention`,
  `security.password.legacy_hashes_until`, `security.mfa_floor`,
  `security.rate_limits.login_per_client` and the new `limits.*` keys; add
  them only for new processes.

New binaries also refuse configurations that older ones accepted: request
limits outside their safe ranges (`limits.max_body_bytes` below 256 KiB,
`max_json_depth` below 32 and the other ranges in
[configuration.md](configuration.md#limits));
`security.decision_cache_ttl` above `10m` or negative,
`security.dynamic_group_max_staleness` other than `0` or `10m`–`168h`,
`security.totp_skew_steps` outside `0`–`2` and `security.recovery_code_count`
outside `5`–`20`, and negative `security.rate_limits` values or a positive
limit whose window is `0` (for example `temporary_lock: 0` with the default
`failures_before_lock`; set the limit to `0` to disable a budget, as
[configuration.md](configuration.md#security) describes). Check the file with
the new `identity-cli config-diff` before step 2.

### Separating database roles

To move an existing installation to separate owner and runtime roles
(OPS-013):

1. Create the runtime role (`CREATE ROLE proudauth_app LOGIN PASSWORD '...'`)
   and keep the current role, which owns the tables, as the migration role.
2. Set `storage.migration_database_url` to the current connection,
   `storage.database_url` to the new role's connection and
   `storage.runtime_role: proudauth_app`, on the hosts that run migrations
   first.
3. Run `identity-cli migrate` once with the new configuration: it grants the
   runtime role its data privileges even when no migration is pending.
4. Roll the configuration out to servers and workers, then run
   `identity-cli doctor`: it should print
   `database role proudauth_app: data privileges only`.
5. `identity-cli migrate -plan` keeps working with the runtime connection: it
   is read-only. Once migration `0044` has run with `storage.runtime_role`
   set, the runtime role can no longer delete audit rows directly; it prunes
   through `proudauth_audit_prune`.

The removed key `security.rate_limits.token_per_organization` makes new
binaries refuse a configuration that still sets it; delete it before step 2.
New binaries also refuse unknown category names under
`privacy.audit_retention_by_category` (older ones ignored them); keep only the
names listed in [configuration.md](configuration.md#privacy).

These API changes need action from administrators or their tooling when they
upgrade to this version:

- **Shared passwordless proof budget (TEST-021, NFR-006):** email/SMS login
  codes now share their bound account's verification budget with HOTP/TOTP
  and recovery proofs. No schema migration is needed. Complete the server
  rollout before relying on this combined limit: older instances still use
  identifier buckets for passwordless codes. Existing identifier counters
  are not migrated into account counters; a clean comparison starts after
  the configured verification window expires. The default remains ten
  proofs per 15 minutes, not a permanent account lockout. See the
  [cross-method regression](consistency-tests.md#shared-otp-guessing-budgets--2026-10-12).
- **Directory failover deletion (PROV-012, PROV-014):** a completed
  replacement endpoint's full view now determines missing memberships,
  without retaining presence from a failed partial endpoint. No schema
  migration is needed. After upgrading, request a full sync against the
  intended trusted source to reconcile memberships earlier failovers left
  active; review its deletion threshold/report before authorizing any mass
  override. No override or direct SQL repair is applied automatically.
  [Failure and correction](consistency-tests.md#directory-transport-interruption-and-complete-source-deletion--2026-10-12).
- **Expired directory workers (DEP-011, PROV-012):** workers now fence job
  progress/final results and directory mutations with the current lease and
  attempt. Drain/stop all old workers before starting replacement workers;
  an older worker in a mixed-version window still has unfenced writes.
  No schema migration is needed. If an earlier worker overwrote a recovered
  sync's status or counts, inspect the connector and request a full run after
  the upgrade to refresh its evidence from authoritative source data; do not
  repair it with manual SQL. [Failure and correction](consistency-tests.md#directory-schedules-and-expired-worker-leases--2026-10-12).
- **Profile attributes that are both `claimable` and `user_editable`** are
  refused by the realm profile schema (`422` on
  `profile.attributes[<i>].claimable`) and are no longer released in token
  claims. A realm that has one keeps working, but its next policy update
  (`PUT /settings` or a configuration import) is refused until one of the two
  flags is cleared; clear it as part of the upgrade.
- **`PATCH /organizations/{org}` with `policy`** needs `If-Match` (the `ETag`
  of `GET /organizations/{org}`); without it the server answers `428`
  (API-010). Update scripts and integrations that patch organization policy.
- **`If-Match` with version `0`** (`v0`, `"v0"`, `W/"v0"`, `0`) or a negative
  or unparsable value is refused with `412 precondition_failed` on every
  route; it no longer skips a required precondition. Send the `ETag` you read.
- **`PATCH /organizations/{org}`** keeps `locale`, `time_zone` and
  `external_id` when the body omits them; send `""` to clear one.
- **Deleted connector Groups (PROV-004, PROV-007):** local deletion now
  removes inbound/directory Group links in the same transaction. A SCIM
  create using the same external ID or directory Group apply repairs older orphan links whose local
  group is absent, without adopting live groups. No schema migration or
  manual database cleanup is required. Directory sync may recreate a
  deleted group still present in its authoritative source. Outbound
  links remain available until downstream deletion is acknowledged;
  [regressions and limits](consistency-tests.md#mixed-group-deletion-and-link-repair--2026-10-11).
- **JWT grant authority (SES-023):** user and exchanged JWTs now carry the
  reserved `grant_id`, checked live by introspection, UserInfo, IdP user APIs
  and token exchange. Earlier development JWTs without it fail closed online.
  Clients must obtain fresh access tokens through serialized refresh or sign
  in again if the grant has ended. Coordinate the server upgrade so old issuers
  cannot keep minting unlinked tokens. Rename/remove any older claim mapping
  called `grant_id`: issuance skips it and the next client update refuses it.
  Offline verifiers retain their expiry-based revocation exposure.
- **Token exchange** applies the organization's `allowed_scopes` and the
  scopes' `required_permissions`: a requested scope beyond them fails with
  `invalid_scope`, and an exchange with no scope left fails instead of
  issuing a token without scopes
  ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#token-exchange-rfc-8693)).
- **Claim mappings:** neither `id_token_claims` nor `access_token_claims`
  may name an OIDC standard user claim (`name`, `email`, `locale`, …; `422`
  on the field). Clients registered earlier with such mappings stop
  releasing them at once (issuance skips them in access tokens as in ID
  tokens), and their next update is refused until the mapping is renamed or
  removed. Review the claim mappings of existing clients, and move resource
  servers that read such a claim to another name
  ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#clients)).
- **MFA sessions** are now required to apply an organization template (not a
  dry run) and to remove an organization's mail server.
- **Administration SDKs 0.2.0** return one-time secrets wrapped in
  `admin.Secret` (Go) or `Secret` (Node.js); code that reads them as strings
  must call `Reveal()` / `reveal()`
  ([sdk-compatibility.md](../integrations/sdk-compatibility.md#breaking-changes-in-020)).
- **Federation logout:** RP-initiated logout responses now carry
  `upstream_logout`; clients that parse the JSON body must ignore unknown
  members (they already should).
- **Webhooks of a deleted organization:** an organization's own subscriptions
  are disabled when its deletion starts and deleted when it finishes, so
  they no longer receive `organization.deleted`; subscribe realm-wide to see
  it.
- **Account deletion** (`DELETE /users/{user}`, `POST /me/deletion-request`)
  answers `409 last_owner` with the extension `owned` while the account owns
  live projects, clients, service principals, resources or connections;
  offboarding scripts must call `POST /users/{user}/ownership-transfer` first
  ([data-inventory.md](data-inventory.md#account-deletion)).
- **Account state `recovery_restricted`:** a sign-in with a recovery code now
  also sets the account's state, and a restricted session gets `403
  recovery_restricted` for most writes; tooling that reads account states or
  problem codes must accept the new values
  ([account-recovery.md](account-recovery.md#recovery-restricted-sessions-mfa-010-usr-003)).
- **Redirect URIs on the identity provider's own host** are refused when a
  client is created or updated; move such URIs before the next client update
  ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#redirect-uris-and-origins)).
- **Support writes through the decision API** need
  `impersonation_policy.write_actions` on the resource; without it every
  support write is denied (`SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED`)
  ([resource-servers.md](../integrations/resource-servers.md#6-support-access-contract)).
- **Factor enrollment** through `/me/totp/*` and `/me/webauthn/registration-*`
  needs an MFA session when the account already has a factor; login UIs that
  offer "add another authenticator" after a password-only sign-in must
  handle `403 step_up_required`.

`TestMixedVersionWindow` (`internal/storage`, TEST-061) checks that an older
binary keeps working after newer expand-only migrations, refuses to migrate a
newer schema and fails clearly after a newer contract migration. No test runs two
complete server versions against one schema; validate each upgrade in a staging
environment with production-like data.

## Rollback limits

- **Binary rollback** to release N is possible while the database contains only
  expand migrations from N+1. Data written into new columns or tables by N+1 is
  ignored by N; behavior that depends on it is lost.
- A release N binary cannot run `migrate` against the N+1 schema (it refuses), so
  roll back with `migrate_on_start: false`.
- **After a contract migration**, rolling back the binary is unsupported; the only
  path back is restoring a backup taken before the upgrade, which loses every change
  made since and requires restore reconciliation.
- Signing keys, sessions and grants created by the newer version stay valid after a
  binary rollback; nothing in the token formats is version-specific today.

## Token and API compatibility

- Token formats (`at+jwt`, claims, `token_kind`, opaque prefixes such as `pa_it_`,
  `pa_key_`, `pa_pat_`) are relied on by resource servers. Changes must be announced
  in the changelog with a transition period in which both forms are accepted.
- Custom APIs are versioned under `/api/v1`. Breaking changes require a new version
  path or a deprecation window; security fixes may tighten behavior without one.
  The rules are in [compatibility.md](../protocols/compatibility.md) (API-013).
