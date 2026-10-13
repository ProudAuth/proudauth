# Exit and export

Requirements: OSS-008 (portable exit), MIG-002..MIG-007, MIG-009, MIG-011,
MIG-012, MIG-014..MIG-017, USR-013, USR-016, USR-017, AUD-010, APP-019,
ARC-008. This page lists what can leave a ProudAuth deployment through
supported interfaces and what cannot, and how users, audit history and
configuration are imported. The step-by-step migration runbook is
[migration.md](migration.md).

All export jobs run in `identity-worker`. The flow is the same for each:

1. `POST` the export request → `202 {"job_id": "job_..."}` (an `Idempotency-Key`
   header returns the same job on retry).
2. Poll `GET /api/v1/realms/{realm}/jobs/{id}` until `state` is `succeeded`. The
   job's non-secret `result` contains counts and a SHA-256 checksum.
3. `POST /jobs/{id}/downloads` → `201 {"download_token", "expires_in": 300}`:
   a single-use token valid for 5 minutes (requires authentication within
   `security.recent_auth_window` for users; only the requester can obtain it,
   and for audit, configuration and realm data exports only while still
   holding `realm.audit.export`, `realm.configuration.export` or
   `realm.data.export`, `403` otherwise). The worker also re-checks
   the requester's permission when the job runs (INT-006, TEST-063): see
   [Job authority](#job-authority-test-063).
4. `POST /job-downloads {"download_token": "..."}` → the file. Audit exports
   and realm data exports are served as `Content-Type: application/x-ndjson`
   with `Content-Disposition: attachment; filename="export.ndjson"`, every
   other job's file as `application/json`, `export.json`. The permission is
   checked again when the token is redeemed; a refusal (`403`) does not use up
   the token. The download is audited (`job.result.downloaded`, category
   `privacy`, with the actual actor type: `user` or `service_principal`). The
   encrypted result is purged after `privacy.export_retention` (24 h).

### Job authority (TEST-063)

A job row names its requester, realm and organization. The worker never trusts
that as authority: before it runs a job it checks again that the requester
holds the permission the job type needs, so a row written or changed by
anything other than the API (a forged or replayed queue entry) cannot act for
someone else. A requester who lost the permission makes the job dead-letter
without running, with `last_error`
`permanent job failure: the requester no longer holds <permission>`:

| Job type | Re-checked at run time |
| --- | --- |
| `audit.export` | `realm.audit.export` (realm-wide, also for an export limited to one organization) |
| `config.export` | `realm.configuration.export` |
| `realm.export` | `realm.data.export` |
| `user.import` | `realm.users.import`, plus `realm.users.verification.override` for `trust_email_verification` and `realm.users.credentials.manage` for `import_totp`; the permission of every required action the records carry (`realm.users.credentials.manage` for `update_password` and `configure_totp`, `realm.users.write` for `verify_email` and `verify_contact`); each mapped role against the requester's delegation ceiling |
| `user.bulk` | The permission of the bulk action (`realm.users.suspend`, `realm.users.sessions.revoke` or `realm.users.required_actions` plus the required action's own permission), checked per action; there is no blanket mapping to `realm.users.write` |
| `user.export` | No permission: the job exports only its requester's own data, and a job naming another user dead-letters ("exports are limited to the requesting user") |
| `organization.delete` | `org.delete` in the organization, evaluated as if the organization were still active; it runs only for an organization in state `deleting` ([data-inventory.md](data-inventory.md#organization-deletion)) |

The check runs without the requester's request context, so a permission held
only through a conditional role assignment (client, resource, assurance or
authentication-age conditions) does not count. A requester whose account is
no longer active (suspended, locked, pending verification or deletion,
deleted), or a disabled or deleted service principal, holds no permissions,
so their jobs dead-letter.

## Supported exports

| Export | Request | Who | Contents | Format |
| --- | --- | --- | --- | --- |
| Personal data export (USR-013) | `POST /me/exports` | The user, with recent authentication | Profile (ID, names, locale, zoneinfo, user-editable profile, created time); identifiers (type, value, verified, primary); memberships; credential metadata (type, name, state, created, last used); passkey names and dates; active sessions (ID, created, last activity, AMR, user agent); active consents (client, scopes, time); terms acceptances; linked identities (provider alias, dates); last 500 security events about the user (type, time, outcome); `imported_history`: up to 500 historical audit records imported about the user (`source_system`, `event_type`, `occurred_at`, `outcome`), newest first | JSON, `"format": "proudauth.user-export.v1"` |
| Configuration export (APP-019) | `POST /configuration/exports` | `realm.configuration.export` | Realm name, display name, `policy_revision` and policy (including its `audit` and `authentication_flow` members); every active client except `proudauth-cli` and the clients backing SAML applications (including `consent_terms_version` and its protocol options: front-channel logout, ID-token, UserInfo and authorization-response signing and encryption, `tls_client_auth_*` and certificate-bound tokens, `client_uri`, `logo_uri`, `policy_uri`, `tos_uri`) with its resource grants (scopes, subject types and, when set, `exchange_policy`); every business API resource (built-in ones are left out) with `signing_algorithm`, `impersonation_enabled`, `impersonation_policy` and its scopes (including `required_permissions`, `step_up_acr` and `max_auth_age_seconds`); realm-level custom roles; application permissions. Clients and resources are read page by page, without a cap. Lists what is excluded: client secrets, signing keys, encryption keys, connector and identity-provider credentials, user credentials, environment-bound identifiers (projects, owners, service principals, composite role links). The document validates against `api/schemas/config-document.schema.json` | JSON, `"format": "proudauth.realm-config.v1"` |
| Realm data export (OSS-008, MIG-014) | `POST /data-exports` | `realm.data.export`, recent authentication | The realm's accounts, organizations, memberships, groups, role assignments, authorization policies, projects, service principals, identity providers, webhook subscriptions and hooks, plus the configuration export document; credentials and live bearer state excluded ([below](#realm-data-export)) | NDJSON, `"format": "proudauth.realm-export.v1"`; job result has counts per kind and SHA-256 of the file |
| Audit export (AUD-010) | `POST /audit-exports {"organization_id": "...", "from": "RFC3339", "to": "RFC3339"}` | `realm.audit.export`, recent authentication | Audit events of the realm (optionally one organization) in the range, newest first, up to 2000 × 500 events per job, each with its `content_hash`; imported history (`GET /imported-audit-events`) is not included | NDJSON (`application/x-ndjson`); job result has the event count and SHA-256 of the file |
| Audit archive (AUD-008) | Configuration `privacy.audit_archive_dir`; worker task `audit.archive` | Operator (file system access) | Every sealed audit batch of the deployment (all realms and operator events), with its batch hash, chain link and signature, as written; verifiable with `identity-cli verify-audit-archive` ([incidents.md](incidents.md#audit-archive-aud-008)) | One write-once NDJSON file per batch |

The personal data, realm data and audit exports and the audit archive are the
bulk exports of personal data. For incremental reads, or for objects the realm
data export leaves out, page through the administration APIs:

| Data | API |
| --- | --- |
| Users (admin view including identifiers and metadata) | `GET /users?limit=200&cursor=...` (`realm.users.read`) |
| Organizations | `GET /organizations` |
| Members and their roles | `GET /organizations/{org}/members` |
| Groups and group members | `GET /organizations/{org}/groups`, `/groups/{group}/members` |
| Role assignments | `GET /role-assignments` |
| Service principals, API key metadata | `GET /service-principals`, `GET /api-keys` |
| Webhook subscriptions | `GET /webhooks` |

## Realm data export

OSS-008, MIG-014, `internal/worker/realmexport.go`. One job writes the realm's
identities, tenancy, authorization and integration settings as NDJSON with
stable IDs, for leaving ProudAuth or keeping a portable copy:

```sh
identity-cli api POST /data-exports            # → 202 {"job_id": "job_..."}
identity-cli api GET /jobs/job_...             # until state is succeeded
identity-cli api POST /jobs/job_.../downloads  # → 201 {"download_token", "expires_in": 300}
curl -sS -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"download_token":"pa_dl_..."}' \
  https://id.example.com/api/v1/realms/main/job-downloads > realm-export.ndjson
```

- **Permission:** `realm.data.export`, a privileged permission that only the
  built-in `realm-admin` role holds (through `realm.*`); users also need an MFA
  session and recent authentication. The request has no body; an
  `Idempotency-Key` returns the same job. The request is audited as
  `job.created` (`job_type: "realm.export"`), each download as
  `job.result.downloaded`.
- **Authority is checked four times:** at the request, when the worker runs
  the job (a requester who lost `realm.data.export` makes it dead-letter
  without reading anything), when a download token is issued and when it is
  redeemed.
- **Download:** follow the [common flow](#exit-and-export). Download it with
  a plain HTTP client: `identity-cli api` parses responses as one JSON value
  and cannot save NDJSON. The file is served as `application/x-ndjson` with
  the name `export.ndjson`. Each `POST /jobs/{id}/downloads` issues a new
  single-use token, so the file can be downloaded again until it is purged
  after `privacy.export_retention` (24 h). There is no `identity-cli`
  command for this export.
- **Result:** `GET /jobs/{id}` shows `result` with `format`, `content_type`
  (`application/x-ndjson`), `counts` (records per kind, from `user` to
  `hook`) and `sha256` (hex SHA-256 of the file); compare the checksum after
  the download. `progress` names the last section written and its record
  count.
- **Consistency and size:** each section is read separately, not from one
  snapshot, so changes made while the job runs can appear in one section and
  not another; export in a quiet period (or under maintenance mode
  `restricted`) when you need a consistent copy. The file is built in the
  worker's memory and stored encrypted in the job row; there is no size cap.

### Format

Each line is one JSON object `{"kind": "<kind>", "data": {...}}` (members in
any order). The first line is the header and the second the configuration;
the other kinds follow in this order, each sorted by `id`:

| `kind` | Records | `data` |
| --- | --- | --- |
| `header` | One | `format` (`proudauth.realm-export.v1`), `generated_at`, `realm` (`id`, `name`, `display_name`, `issuer`) and `excluded`: the list of what the file leaves out (below) |
| `configuration` | One | The configuration export document (`proudauth.realm-config.v1`, [above](#supported-exports)): realm policy, active clients with their resource grants, business API resources with scopes, application permissions and realm-level roles. Clients, resources and scopes are only here |
| `user` | Every account that is not `deleted` (suspended, locked, pending verification, recovery-restricted, pending deletion and guest accounts included) | `id`, `state`, `display_name`, `given_name`, `family_name`, `locale`, `zoneinfo`, `profile` (every attribute, whatever its visibility), `admin_metadata`, `protected`, `is_guest`, `required_actions`, `created_via`, `last_login_at`, `created_at`, `updated_at`; `identifiers` (`type`, `value` as entered, `verified`, `verified_at`, `primary`; unverified ones included); `external_ids` (`source_system`, `source_id`); `federated_identities` (`provider_id`, `upstream_issuer`, `upstream_subject`); `credentials`, a summary only: `password`, `totp` and `hotp` (whether an active one exists) and `passkeys` (count). `internal_metadata` is not exported |
| `organization` | Every organization that is not `deleted` | `id`, `slug`, `display_name`, `state`, `locale`, `time_zone`, `metadata`, `contact`, `external_id`, `policy`, `template_name`, `template_version`, `created_at`, `updated_at`, `domains` (`domain`, `state`, `include_subdomains`, `verified_at`; removed ones left out) |
| `membership` | Memberships not `removed` or `expired` | `id`, `organization_id`, `user_id`, `state`, `source`, `external_id`, `metadata` (the organization's membership metadata, USR-009; not in the member's personal data export), `joined_at`, `expires_at`, `created_at`, `roles` (`role_id`, `role`) |
| `group` | Every group | `id`, `organization_id`, `parent_id`, `name`, `description`, `metadata`, `external_id`, `source`, `dynamic_rule`, `created_at`, `members` (membership IDs; a removed membership can be listed although its record is not in the file) |
| `role_assignment` | Assignments not held through a membership (realm-scoped, group and service-principal assignments), expired ones included | `id`, `role_id`, `role`, `subject_type`, `subject_id`, `scope_type`, `scope_id`, `conditions`, `valid_from`, `expires_at`, `source`, `reason`, `created_at` |
| `authorization_policy` | Every policy, in any state | `id`, `name`, `description`, `scope_type`, `scope_id`, `state`, `requires_approval`, `owner_user_id`, `created_at`, `definition` (the active version; `null` when there is none) |
| `project` | Every project | `id`, `name`, `description`, `environment`, `state`, `owner_user_id`, `owner_organization_id`, `created_at` |
| `service_principal` | Service principals not `deleted` | `id`, `name`, `description`, `owner_user_id`, `owner_organization_id`, `state`, `allowed_organization_ids`, `is_agent`, `created_at` |
| `identity_provider` | Every connection | `id`, `organization_id`, `alias`, `display_name`, `kind`, `adapter`, `state`, `issuer`, `config`, `linking_policy`, `jit_provisioning`, `jit_default_role_id`, `trust_upstream_mfa`, `claim_mapping`, `owner_user_id`, `created_at`; no client secret |
| `webhook` | Every subscription | `id`, `organization_id`, `name`, `destination_url`, `event_types`, `state`, `allow_private_network`, `payload_form`, `owner_user_id`, `created_at`; no signing secret |
| `hook` | Every pre-action hook | `id`, `name`, `kind`, `url`, `timeout_ms`, `failure_mode`, `client_ids`, `allow_private_network`, `state`, `owner_user_id`, `created_at`; no signing secret |

The header's `excluded` list names, in words, what the file never carries:
password verifiers and imported password hashes; TOTP seeds and recovery
codes; passkey credentials; client, webhook, hook and identity-provider
secrets; signing and encryption keys; active tokens, sessions, grants and
consents; audit evidence (use `POST /audit-exports` and the audit archive);
deleted accounts (only their tombstones remain). The columns of every kind
are listed explicitly in the code, so a secret column added to a table later
cannot appear in the file. Also not in the file: organization- and
project-scoped roles, built-in roles, inactive clients and the
`proudauth-cli` client (role IDs in memberships and assignments can name
roles defined nowhere in the file), invitations, join requests, organization
aliases and templates, custom domains, notification settings,
provisioning connectors, API keys and personal tokens, consents and legal
holds; read those through the administration APIs above.

Extensions are only partly in the file: `webhook` and `hook` records omit the
subscription's `event_version`, the hook's `contract_version` and the
`plugin_id` of plugin-managed parts, and lifecycle workflows (with their
revisions and runs) and plugins (with their signed versions) are not
exported at all. Read them with `GET /webhooks`, `GET /hooks`,
`GET /workflows` (and `/revisions`) and `GET /plugins` (and `/versions`), and
keep the original plugin packages: a plugin is moved by uploading its signed
package again ([plugins.md](../integrations/plugins.md)).

The file holds personal data of every account in the realm (contact
identifiers, profiles, metadata): treat it like a database dump, transfer it
encrypted and delete it when it is no longer needed. ProudAuth has no import
for this format; to move into another ProudAuth realm, use the configuration
import and the user import ([migration.md](migration.md)).

## What cannot be exported

| Item | Why | Exit path |
| --- | --- | --- |
| Password verifiers | No API returns them (CRED-005); they are Argon2id PHC strings, optionally peppered | An operator with database access can read `credentials.verifier` and import it into a system that verifies Argon2id PHC strings. Peppered verifiers (`,k=N` in the parameters) are useless without the pepper key and ProudAuth's HMAC construction; plan password resets instead (MIG-006). |
| TOTP seeds | Encrypted under the root key; no export API | Users re-enroll in the target system (MIG-007). |
| Passkeys | Bound to the relying-party ID; private keys never leave authenticators | Re-registration unless the target keeps the same RP ID (MIG-008). |
| Recovery codes, one-time codes | Stored only as keyed verifiers | Regenerate in the target system. |
| Sessions, refresh tokens, access tokens | Not portable across issuers (MIG-010) | Users sign in again; plan the cutover. |
| Signing keys | Encrypted, never exported | Target issues its own keys; relying parties switch trust. |
| Client secrets, webhook secrets | Stored as digests or encrypted | Issue new secrets in the target. |
| Pairwise subject values | Stored in `pairwise_subjects` (once issued), but no API exports them | An operator with database access can read `pairwise_subjects` (sector, user ID, subject); otherwise export the client's mapping by requesting tokens before exit, or switch clients to public subjects first. |

## Import into ProudAuth

MIG-002..MIG-007, MIG-009, MIG-011, MIG-012, MIG-016..MIG-018. Code:
`internal/httpapi/ops.go` (request), `internal/worker/exports.go`
(`importUsers`), `internal/worker/importprofile.go` (profile, state, required
actions and metadata of a record), `internal/credential/imported.go` (bcrypt
and PBKDF2 verifiers), `internal/httpapi/migration.go` (formats,
reconciliation), `internal/httpapi/migration_adapters.go` (adapters and
plans), `internal/audit/imported.go` (historical audit records). Tests:
`TestImportAuthorityAndHashBounds`, `TestImportFactorsAndDeletionContinuity`,
`TestMigrationPlanningAndReconciliation` (`tests/e2e/imports_test.go`),
`TestMigrateFromImportRecordRules` (`tests/e2e/migrate_from_test.go`). For the
order of steps, inventory and cutover, follow the runbook in
[migration.md](migration.md); for Keycloak, ZITADEL and SuperTokens exports,
[migration-adapters.md](migration-adapters.md).

### User import request

`POST /user-imports` (`realm.users.import`) creates users in bounded jobs of
1–1000 records with per-record results, `dry_run`, and source-qualified
idempotency (`import_mappings`). The response is `202 {"job_id", "dry_run"}`;
an `Idempotency-Key` header returns the same job on retry. The body:

| Member | Meaning |
| --- | --- |
| `format` | The declared record format (MIG-002), default `proudauth.user-import.v1`. Any other value is refused with `422` on `format`. Compatibility is never inferred from `source_system`. |
| `source_system` | Required, `^[a-z0-9][a-z0-9._-]{0,62}$` (`422` otherwise): the same rule as for audit imports, external IDs and the reconciliation report. With each record's `source_id` it forms the idempotency key; `import:<source_system>` is recorded as the account's creation and email-verification source. |
| `users` | 1–1000 records (below). The whole body must fit `limits.max_body_bytes` (256 KiB by default). |
| `dry_run` | Validate and plan without writing ([Dry run](#dry-run-plan-and-conflicts)). |
| `trust_email_verification`, `verification_reason` | Keep the records' `email_verified` (MIG-009). Requires `realm.users.verification.override` and a reason of at least 10 characters; otherwise every imported email is unverified. |
| `allow_owner_roles` | Allow memberships that map to an owner role. |
| `import_totp` | Allow records to carry `totp_secret` (MIG-007). Requires `realm.users.credentials.manage` and an MFA session ([TOTP seeds](#totp-seeds-mig-007)). |

Records are decoded strictly when the request arrives: an unknown member or a
wrong type in any record fails the request with `400` before a job is queued.
Each record carries:

- `source_id` (required), `email`, `email_verified`, `username`,
  `display_name`; a record needs an email or a username;
- `given_name`, `family_name` (each at most 100 bytes) and `locale` (a BCP 47
  tag), optional;
- `state`: `active` (the default) or `suspended`, for accounts the source had
  disabled; an import never creates a state more permissive than `active`;
- `required_actions`: obligations the account starts with, each one of
  `update_password`, `verify_email`, `configure_totp`, `accept_terms`,
  `complete_profile` and `verify_contact`, without repeats. They need the
  same authority as on an existing account (AUT-018): `update_password` and
  `configure_totp` need `realm.users.credentials.manage`, `verify_email` and
  `verify_contact` need `realm.users.write`; the request is refused (`403`)
  without them, and the worker checks again;
- `admin_metadata`: administrator-only metadata (users cannot edit it), at
  most `limits.metadata_bytes` as JSON (checked when the job runs);
- `password_hash` as one of these verifiers, rehashed to the deployment's
  Argon2id at the first successful sign-in (CRED-004, MIG-006):

  | Format | Accepted |
  | --- | --- |
  | Argon2id PHC string (`$argon2id$...`) | Memory at most 1 GiB, at most 16 iterations and 16 lanes, salt 8–64 bytes, hash 16–64 bytes; hashes carrying a pepper version are refused |
  | bcrypt (`$2a$`, `$2b$`, `$2y$`, 60 characters) | Cost 10–15 |
  | PBKDF2 (`$pbkdf2-sha1$`, `$pbkdf2-sha256$`, `$pbkdf2-sha512$` followed by `i=<iterations>$<salt>$<derived key>`, unpadded standard base64) | 10,000–2,000,000 iterations, salt 8–64 bytes, derived key 16–64 bytes |
  | `$legacy-sha256$<b64 salt>$<b64 sha256(salt\|\|password)>` | Transitional salted SHA-256 |

  Other formats (scrypt, MD5-crypt, SHA-crypt, …) and verifiers outside these
  bounds are rejected per record, so an imported verifier cannot turn a login
  into a resource-exhaustion attack. bcrypt, PBKDF2 and salted SHA-256 are
  legacy verifiers: after `security.password.legacy_hashes_until` they no
  longer verify, and records carrying one are refused per record ("legacy
  password verifiers are no longer accepted"; checked when the job runs, not
  at the request). bcrypt and PBKDF2 verifiers are checked against the
  password as typed and against its NFKC form, because the source hashed
  what the user typed. For users whose verifier cannot come over, leave
  `password_hash` out and set `update_password`;
- `totp_secret` (only with `import_totp`);
- `memberships` mapped to existing organizations (ID or slug) and existing
  organization roles by name; unknown roles are errors, owner roles require
  `allow_owner_roles: true`, and every mapped role must be within the requester's
  own delegation ceiling in that organization (MIG-005).

`GET /user-import-formats` (`realm.users.import`) lists the accepted formats as
`items`, each with `format`, `source_products`, `schema` (the JSON Schema
describing the records, `api/schemas/user-import.schema.json`), `supports` and
`unsupported`. This release has one format, `proudauth.user-import.v1`:
normalized records, produced by you from any source or by the
[migration adapters](migration-adapters.md). Its `supports` list includes
bcrypt and PBKDF2 within the bounds above, given and family names and locale,
the suspended state, required actions and administrator-only metadata; its
`unsupported` list names what it cannot carry: scrypt, MD5-crypt, SHA-crypt
and other verifier formats (and bcrypt or PBKDF2 outside the bounds),
passkeys, recovery codes, sessions and refresh tokens, consents, federated
links and phone identifiers.

Imported accounts are created in the record's `state` (`active` by default),
with memberships `active`, `source: "import"` and `source_reference` set to
`source_system`, and roles assigned with source `import`. Each account is
audited as `user.imported` (with `source_system`, `job_id`, `state` and
`required_actions`), each role as `role.assigned`; memberships created by an
import emit no webhook event.

The worker re-checks the requester's authority when the job runs: a requester who
no longer holds `realm.users.import` (or the verification override, or
`realm.users.credentials.manage` for `import_totp`, or the permission of a
record's required actions) fails the job (`TestImportAuthorityAndHashBounds`,
`TestMigrateFromImportRecordRules`).

### Migration adapters and plans (MIG-018)

Two read-only endpoints (`realm.users.import`) serve the first-party adapters
for Keycloak 26, ZITADEL v4 and SuperTokens core 12; they write and store
nothing:

- `GET /migration-adapters` lists the adapters with their supported and
  tested source versions, export instructions, and what converts, converts
  with loss and is unsupported.
- `POST /migration-plans` (`{"source", "exports", "source_version"?,
  "source_system"?, "mapping"?, "keep_attributes"?, "import_totp"?}`)
  converts up to 20 export documents in memory and returns the capability
  report, the checks against the realm (organizations that exist, conflict or
  would be created; mapped roles that exist; source IDs already imported or
  deleted; identifiers that belong to other accounts) and a mapping template.
  The export travels in the request, so it is bounded by
  `limits.max_body_bytes`.

The import itself goes through `POST /organizations` and `POST /user-imports`
(`identity-cli migrate-from --apply`), and ends with
`GET /user-imports/reconciliation` with the `expected_*` counts of the
converted export ([reconciliation](#reconciliation-mig-012)); the command
fails when it does not reconcile. Request members, responses and limits are in
[migration-adapters.md](migration-adapters.md#admin-api).

The submitted records (including password hashes and TOTP seeds) are stored
encrypted in the job (`jobs.input_ciphertext`, data key bound to the job ID), are
not returned by `GET /jobs/{id}` (whose `input` shows `format`, `source_system`,
`user_count`, `trust_email_verification`, `verification_reason`,
`allow_owner_roles` and `import_totp`), and are erased when the job succeeds,
fails, dead-letters or is cancelled (migration `0007_job_protected_input.sql`). A
job that is retrying keeps them until it reaches a terminal state.

### Job result

`GET /jobs/{id}` returns, once the job has `succeeded`, a `result` of
`{"dry_run", "counts", "totals", "results"}`. `counts` holds the number of
records per status; each `results` item has `index` (0-based position in
`users`), `source_id`, `status`, and `user_id`, `error` or `plan` where they
apply:

| `status` | Meaning |
| --- | --- |
| `imported` | The account was created (`user_id`). |
| `valid` | Dry run only: the record would be imported; `plan` shows what it would change. |
| `already_imported` | The `source_id` is already mapped for this `source_system` to an existing account (`user_id`). The account is **not** updated: imports only create. |
| `skipped_deleted` | Deletion continuity (MIG-017): the `source_id` is mapped to an account deleted since, or the email or username was released by an earlier account deletion. Nothing is created. |
| `conflict` | The record repeats an identifier of an earlier record of the same batch (`"<source\|email\|username> repeats record N of this batch"`, where `N` is that record's `index`), or its email or username already belongs to an account (`"<email\|username> already belongs to another account; imports never merge accounts by matching identifiers"`, MIG-004). Nothing is created. |
| `error` | The record failed validation or creation; `error` names the reason (for example `unmapped role ...`, `unknown organization ...`, `owner role requires explicit approval`, `role ... exceeds the requester's delegation ceiling`, an unsupported password hash, or a TOTP seed problem). |

`totals` sums what the `valid` (dry run) or `imported` records grant, so the
two runs can be compared:

| Total | Counts |
| --- | --- |
| `memberships` | Memberships created |
| `role_assignments` | Role assignments created |
| `privileged_memberships` | Memberships with at least one privileged role: an owner role, a realm role, or a role holding a wildcard grant (`*`, `x.*`) or a permission marked `privileged` (built-in or a custom permission registered as privileged), directly or through roles it composes at any depth. The built-in organization `member` and `admin` roles are not privileged. |
| `trusted_verified_emails` | Emails imported as verified (`email_verified` with `trust_email_verification`) |
| `password_verifiers` | Password verifiers imported |
| `totp_factors` | TOTP factors imported |
| `suspended_accounts` | Accounts created `suspended` |
| `password_updates_required` | Accounts created with the required action `update_password` |

### Dry run, plan and conflicts

With `dry_run: true` nothing is written (MIG-003). Each record goes through the
same checks as a real run, in this order: `source_id` present, repeats within
the batch (`conflict`), existing mapping (`already_imported` or
`skipped_deleted`), username and email tombstones (`skipped_deleted`), TOTP
seed, email syntax, password hash format, identifiers owned by existing
accounts (`conflict`), organizations and role mappings. A record that passes is
`valid` and carries `plan`:

| `plan` member | Meaning |
| --- | --- |
| `mapping` | The source-qualified mapping that would be stored, `<source_system>/<source_id>` |
| `email_verified` | Whether the email would be marked verified (trusted import only) |
| `password_verifier`, `totp_factor` | Whether a password verifier or TOTP factor would be imported |
| `state` | `suspended` when the account would be created suspended (absent otherwise) |
| `required_actions` | The required actions the account would start with |
| `memberships` | Per membership: `organization_id`, `roles` (role names) and `privileged` (present when a mapped role is privileged, as in `totals`) |

A dry run does not check that a record has an email or a username, username
syntax, or `display_name` length; those fail only when the account is
created. Real runs report conflicts the same way, so a conflict found in a dry
run is never resolved by merging: fix the source data (or the existing account)
and import the record again.

### Resumption and cancellation (MIG-011)

Each record is imported in its own transaction, so a failure never leaves a
record half-created and never undoes earlier records. Every 50 records the job
saves a checkpoint (the next index, `counts`, `totals` and the `results` so
far), which is also its `progress`. A job that is retried, or picked up again
after a worker stopped, continues after its last checkpoint and keeps the
earlier results; records handled after that checkpoint run again and report
`already_imported`. A checkpoint whose results do not match its position is
ignored and the job starts from the first record; records it already created
then report `already_imported`.

`POST /jobs/{id}/cancel` (the requester, or `realm.jobs.cancel`) stops a queued
job at once and a running job at its next checkpoint: the job ends
`cancelled`, its `progress` lists every record handled so far, the records
already imported stay, and the protected input is erased. To finish later,
submit the same records again; imported ones report `already_imported`.

### TOTP seeds (MIG-007)

A record's `totp_secret` is a base32 seed (RFC 4648; case, spaces and padding
are ignored) of 80 to 512 bits. It is imported as an active TOTP factor named
"Authenticator app (imported)" for SHA-1, 6 digits and 30-second steps: seeds
generated for other algorithms, lengths or periods produce codes that never
match, so convert or exclude them. Without `import_totp: true` a record that
carries a seed fails (`error`); `import_totp` requires
`realm.users.credentials.manage` and an MFA session, and the worker re-checks
the permission. The seed is re-encrypted under this deployment's data key
(AES-256-GCM, bound to the credential ID) and audited as `mfa.totp.imported`
(source `import`, with `credential_id` and `source_system`, never the seed). No
recovery codes are created: users generate them after their first sign-in.

The export file that carries seeds is as sensitive as the users' second factor:
anyone holding it can produce valid codes. Transfer it over an encrypted
channel, keep it out of tickets and chat, and delete it once the import is
reconciled. Factors without transferable secrets (passkeys, SMS, recovery
codes) need re-enrollment ([migration.md](migration.md#credentials-and-factors)).

### Deletion continuity (MIG-017)

An import never recreates an account deleted in ProudAuth: a `source_id` mapped
to a deleted account, or an email or username matching a deletion tombstone, is
reported `skipped_deleted`, in dry runs as well
(`TestImportFactorsAndDeletionContinuity`). Tombstones cover the identifiers an
account held when it was deleted, and restore reconciliation re-inserts them
after a database restore ([backup-restore.md](backup-restore.md)). ProudAuth
cannot know about deletions in the source system: remove deleted or
deletion-pending accounts from the export, and delete accounts removed in the
source after the export in ProudAuth (find them with
`GET /external-ids/{source}/{id}`).

### Reconciliation (MIG-012)

`GET /user-imports/reconciliation?source_system=<name>` (`realm.users.import`)
summarizes what the realm holds now for the users imported from one source
system; `404` when nothing was imported from it. Optional query parameters
`expected_users`, `expected_memberships`, `expected_privileged_assignments`,
`expected_password_verifiers` and `expected_totp_factors` (non-negative
integers, counted in the source export) are compared with the matching measure.

| Member | Meaning |
| --- | --- |
| `mappings` | `total` mappings of the source and `by_state`: accounts per state (`active`, `suspended`, ..., `deleted`, or `missing`) |
| `users` | Imported accounts that are not deleted (measure `users`) |
| `memberships` | `active` memberships of those accounts in any organization (measure `memberships`), `from_import` (created by this source's imports) and the number of `organizations` |
| `privileged_assignments` | Role assignments of those accounts with a privileged role (decided as everywhere else: the role or a role it composes is privileged, or the composition has more than 64 roles), whatever created them: `total` (measure `privileged_assignments`), up to 200 `items` (`user_id`, `source_id`, `role`, `scope_type`, `scope_id`, `assignment_source`) and `truncated` |
| `credentials` | Accounts with an active `password` (measure `password_verifiers`), `password_not_yet_rehashed` (the active password is still the imported verifier: no password sign-in yet, or an Argon2id verifier that already used the deployment's parameters), `totp` (measure `totp_factors`), `passkey`, `federated` (linked upstream identities) and `without_sign_in_method` (no password, passkey or linked identity) |
| `verified_emails` | Accounts with a verified email |
| `signed_in_since` | Accounts that have signed in at least once |
| `subject_continuity` | `resolvable_source_ids` (source IDs that resolve to a live account) and `deleted_since_import` |
| `mismatches`, `reconciled` | One `{"measure", "expected", "actual"}` per expected count that differs; `reconciled` is `true` when there is none |

The report holds counts and identifiers only, never credentials or contact
data. What to compare before cutover is in
[migration.md](migration.md#7-reconcile-mig-012).

### Historical audit records (MIG-016)

`POST /audit-imports` (`realm.audit.import`, a privileged permission that no
built-in role except `realm-admin` holds; an MFA session) files audit history
from the source system **apart from** ProudAuth's own evidence:

```json
POST /api/v1/realms/main/audit-imports
{
  "source_system": "legacy-idp",
  "events": [
    {"source_event_id": "ev-1", "occurred_at": "2019-03-01T12:00:00Z", "type": "LOGIN",
     "organization": "acme", "actor": {"type": "user", "id": "u-17", "display": "Ada"},
     "subject_source_id": "u-17", "outcome": "success", "metadata": {"ip": "198.51.100.7"}}
  ]
}
```

| Member | Rules |
| --- | --- |
| `source_system` | Lowercase letters, digits, `.`, `_`, `-`; at most 63 characters. Use the name of the user import so subjects resolve. |
| `events` | 1–500 records |
| `source_event_id` | Required, 1–256 characters without line breaks; unique per source system |
| `occurred_at` | Required RFC 3339 time, not later than 5 minutes from now |
| `type` | Required, the source's own type name: 1–128 letters, digits and `_ . : / -` |
| `organization` | Optional organization ID or slug of this realm |
| `actor` | Optional `type` (at most 64 characters), `id` and `display` (at most 256 each), as the source stated them |
| `subject_source_id` | Optional source user ID; resolved through the user import mappings of the same `source_system` to a local `subject_id` when that account exists and is not deleted |
| `outcome` | `success`, `failure`, `denied` or `unknown` (default) |
| `metadata` | Optional object of at most 4 KiB as JSON. It passes through audit redaction before it is stored: members whose names look secret (for example `password`, `token`, `secret`, `api_key`, `access_key`) and values shaped like bearer tokens or JWTs become `[REDACTED]`. Other personal data is stored as given |

The response is `200 {"batch_id", "counts", "batch_digest", "results"}`:
`counts` per status `imported`, `duplicate` (the `source_event_id` was imported
before; the stored record is not changed) or `error`, and one result per event
(`index`, `source_event_id`, `status`, `id`, `subject_id`, `error`). The batch
is written in one transaction together with one local audit event,
`audit.history.imported` (category `audit`, target `audit_import_batch`), whose
metadata holds `batch_id`, `source_system`, the counts, `batch_digest` (SHA-256
over the `content_hash` values of the records imported in this batch, in
order) and `earliest_occurred_at` / `latest_occurred_at`. That event is the
only thing ProudAuth witnessed, and it is sealed into the hash chain like any
other; every request records one, even when every record is a duplicate.

Imported records are stored in `imported_audit_events` (migration `0038`),
never in `audit_events`: they are not sealed into the chain, not returned by
`GET /audit-events` or audit exports, and raise no security signal.
`GET /imported-audit-events` (`realm.audit.read`) lists them, newest
`occurred_at` first, at most 1000 per query (paginated with `cursor`; narrow
with the filters to reach older records), filtered by `source_system`,
`subject_id` (local user ID), `organization_id`, `type`, `batch_id`, `from`
and `to` (RFC 3339 on `occurred_at`). Each item has `source: "import"` and
`verified: false`, the source's identifiers (`source_system`,
`source_event_id`, `source_subject_id`, `actor`), the mapped `subject_id` and
`organization_id`, `content_hash` (SHA-256 of the record as submitted,
re-encoded as JSON by the server), `batch_id`, `imported_at`, `imported_by`
and `redacted_at`.

Retention counts from `imported_at`, not `occurred_at`: `retention.cleanup`
deletes imported records older than `privacy.audit_retention`, or the
`imported` entry of `privacy.audit_retention_by_category`, unless an active
legal hold matches the realm, organization or local subject, or the realm's
`audit.retention_days` or the organization's `audit_retention_days` keeps
them longer ([configuration.md](configuration.md#privacy)). Deleting an account removes the
source-supplied details of the imported records about it (`metadata`,
`source_subject_id` and the actor's `display`; the record keeps its type, time,
outcome and `content_hash`) unless a legal hold covers them
([data-inventory.md](data-inventory.md#account-deletion)). A record whose
`subject_source_id` maps to an account that is already deleted is stored
that way from the start (`subject_id` set, `metadata` empty, no
`source_subject_id` or actor `display`, `redacted_at` set), unless an active
legal hold covers it (a hold on its organization, a realm-wide hold or a hold
on that account): then it keeps its details like any held record; its
`content_hash` always covers the record as submitted. Restore reconciliation
clears them again in a restored database. The account's owner sees the
records about them in the personal data export (`imported_history`).

### External IDs

The `import_mappings` rows double as external IDs (USR-017): an imported account
can be found by its source ID with `GET /external-ids/{source}/{id}`
(`realm.users.read`), and administrators can list, set or remove an account's ID
in a source system with `GET /users/{user}/external-ids` and
`PUT`/`DELETE /users/{user}/external-ids/{source}` (`realm.users.write`; body
`{"external_id": "..."}`). Source names match `^[a-z0-9][a-z0-9._-]{0,62}$`,
values are 1–256 printable characters, an account has one ID per source (an
account merge is the exception, below),
and an ID is unique only within its source: a value already mapped to another
account in that source is refused with `409`, unless that account was deleted,
in which case the old mapping is removed and the value assigned. Changes are
audited as `user.external_id.set` and `user.external_id.removed` (with the
source name, not the value); lookups ignore deleted accounts
(`TestExternalIDs`). An executed account merge moves the merged-away account's
external IDs to the surviving account. If both accounts had an ID in the same
source system, the survivor keeps both (the source system held two records for
one person) and either resolves to it; `GET /users/{user}/external-ids` then
lists both, and a `PUT` or `DELETE` for that source replaces or removes both.

### Configuration import

Configuration can be imported with `POST /configuration/validate` (dry plan) and
`POST /configuration/imports` (`?dry_run=true` for a plan only). The document
is `proudauth.realm-config.v1` (`api/schemas/config-document.schema.json`), as
produced by the configuration export. Imports create missing permissions,
resources, clients, client resource grants and roles, update client resource
grants (below), and update the realm policy when one is given. The import is
applied in one transaction, with the same validation, delegation ceilings (for
created roles) and audit as the API (ARC-008); a realm policy change is
audited as `realm.policy.updated` like `PUT /settings`.

**Authority (ARC-008).** Both routes need `realm.configuration.import`, and
`/imports` also recent authentication (users). Applying a document needs, in
addition, the permission each change needs through the API, checked for every
item the plan creates or updates: the realm policy `realm.settings.write`,
clients and grants `realm.clients.write`, resources `realm.resources.write`,
roles and permissions `realm.roles.write`. A missing one fails the import
with `403` (and an `authorization.denied` audit event) before anything is
written. Items that are only unchanged or drift need nothing more.
`/validate` and `?dry_run=true` run the same checks and report each missing
permission as a plan error (`<item>: requires <permission>`), so a clean plan
does not fail at apply for lack of authority.

**Realm policy and `expected_policy_revision`.** The document's `policy` is
merged over a copy of the current policy: objects member by member, while a
list or a scalar in the document replaces the current value whole, so list
elements (for example `profile.attributes` entries) never keep members of the
elements they replace. The merged policy goes through the same checks as
`PUT /settings`, including the operator's MFA floor
([configuration.md](configuration.md#security)). The plan reports the realm
policy as `update` whenever the merged result differs from the current
policy, including changes that only touch a list, and as `unchanged`
otherwise (an empty list and an omitted one count as equal).

A document that changes the realm policy must carry `expected_policy_revision`,
the realm's `policy_revision` the document was reviewed against, like
`If-Match` on `PUT /settings`: without it `/imports` (also with
`?dry_run=true`) answers `422` with the plan error
`policy: set expected_policy_revision (the realm is at N) after reviewing the change`.
The revision is the `policy_revision` member of `GET /settings`, of the
`PUT /settings` response and of the exported document's `realm`; it counts
policy updates only and is not the number in the settings `ETag`. A stale
value is a plan error (`policy: expected revision X but the realm is at N`)
whenever the document has a `policy`, even an unchanged one, and a policy
change that lands between plan and apply makes the import fail with
`412 precondition_failed` ("the realm policy changed since the document was
reviewed"). `/validate` reports a missing or stale revision as a plan error
too, so `identity-cli config-plan` shows it before `config-apply`.

**Client resource grants.** An entry of `client_resource_grants` is either a
list of scopes or an object `{"scopes", "subject_types", "exchange_policy"}`,
where `exchange_policy` is `{"accept_from_audiences", "max_scopes"}`
(token exchange, TOK-016). A grant is `unchanged` when its scopes match, its
subject types match if the document gives them, and its exchange policy
matches if the document gives one (lists are compared as sets, so order does
not matter); otherwise it is `update` and is set to the document's scopes. An
existing grant keeps the `subject_types` and the `exchange_policy` the
document omits; a new grant without subject types gets `["user"]`. An
explicit `"exchange_policy": {}` removes the policy. The exchange policy is
validated as by `PUT /clients/{client}/resource-grants/{resource}`:
`max_scopes` must be scopes the resource declares and
`accept_from_audiences` audiences registered in the realm (a plan error
`grant <client> -> <audience>: ...`; `422` on `exchange_policy` through the
API). The `client.resource_grant.set` audit event records the exchange
policy.

**Existing objects.** Existing permissions are never changed. Existing
resources, clients and roles whose settings differ from the document are
listed under `drift` in the plan (`<kind> <id>: <fields> differ`), for
review: resources (`name`, `verification_mode`, `access_token_ttl`,
`requires_organization`, `signing_algorithm`, `impersonation_enabled`,
`impersonation_policy`, `scopes`), clients (`name`, `grant_types`,
`redirect_uris`, `post_logout_redirect_uris`, `first_party`,
`consent_mode`, `allowed_origins`, `backchannel_logout_uri`,
`allow_offline_access`, `allow_remember_me`, `token_endpoint_auth_method`,
`security_profile`, `protocol_options` compared as a whole, and
`client_type`; `consent_mode`, `token_endpoint_auth_method` and
`security_profile` only when the document sets them) and roles (`permissions`,
`denied_permissions`, `requires_approval`). `impersonation_enabled` is
compared even when the document omits it (as `false`), so a resource with
support access on always shows drift against a document without the member.
With `?mode=reconcile` (on both routes; SDK-012, `TestConfigReconcile`),
resources, clients and roles that differ in the fields a reconcile can set
are planned as `update` and applied in the same atomic import through the
ordinary update path:

- a **client**'s whole registration is replaced from the document (fields the
  document omits take their defaults; `contacts` come from the document),
  keeping only its project, owner, default resource and service principal
  links;
- a **resource** takes the members the document gives (`name`,
  `verification_mode`, `access_token_ttl`, `requires_organization`,
  `signing_algorithm`, `impersonation_enabled`/`impersonation_policy`, ...);
  members the document omits keep their current values;
- a **role** gets exactly the document's permissions: missing ones are added
  and extra ones removed, within the importer's delegation ceiling
  (`403`, "permission X exceeds your delegable set").

Each update needs the matching write permission and is audited like the API
call (`client.updated`, `resource.updated`, `role.permissions.changed`). A
resource's `scopes`, a client's type and a role's denied permissions and
approval flag are never reconciled and remain drift. Nothing is ever deleted.
A client whose type differs **and** that differs in a reconcilable field
would need an update that cannot change its type: under `mode=reconcile` it
is a plan error ("client X: client_type is A and cannot change to B; register
a new client (another client_id) or keep A in the document"), so validation
and dry runs report it and the import is refused up front with `422` and the
plan, before anything is applied (`TestConfigReconcileClientType`). A client
that differs only in its type stays drift.

The response is `{"plan", "applied", "client_secrets"}`; a plan with errors
is answered `422` with the plan itself as the body. `client_secrets` maps the
`client_id` of each newly created confidential client to its generated secret
(`Cache-Control: no-store`); store it immediately, or issue a new one later
with `POST /clients/{client}/credentials`. Like other secret-bearing
responses (API-006), an import response is never stored by the idempotency
layer, because it always carries the `client_secrets` member: a retry with the
same `Idempotency-Key` returns `409` (with `original_status`) instead of the
original response. If the response was lost, check the realm's state (or `GET`
the created clients and issue new secrets) before importing again. A document
must fit `limits.max_body_bytes` (256 KiB by default), so the export of a
large realm may need to be split or the limit raised.

`identity-cli config-export`, `config-plan` and `config-apply` wrap these
endpoints for configuration-as-code workflows, with a confirmation step and a
`0600` file for new client secrets
([sdk-compatibility.md](../integrations/sdk-compatibility.md#administrative-automation-sdk-012)).

**Secrets never enter documents (APP-019).** Client secrets are generated
when an import creates a client and returned once in `client_secrets`;
keep them in a secret store and reference them from your deployment
tooling, never in the document or version control. Existing clients keep
their secrets; rotate them through `/clients/{client}/credentials`.

**Not part of configuration documents.** These are managed only through
their own APIs, so a configuration-as-code workflow must cover them
separately: SAML applications (including the clients that back them) and
SAML connections, upstream identity-provider connections, workload trusts
(MCH-011), shared-signals streams and transmitters, registry services,
lifecycle workflows, plugins, organization relationships and project
grants, webhooks and hooks, and authentication flow drafts (the published
flow is part of the realm policy; its revision history is not). Dynamically
registered clients (APP-016) are managed through the registration endpoint,
but the export does not skip them: active ones appear in the document as
ordinary clients (the document cannot mark a client as dynamically
registered, and registration access tokens are never exported), so an
import into another realm creates them as administrator-managed clients.
Remove them from the document if that is not intended.

## Bulk user operations

`POST /user-bulk-operations` (USR-016, `internal/worker/bulk.go`,
`TestBulkUserOperations`) applies one action to up to 1000 existing accounts as a
`user.bulk` job:

```json
POST /api/v1/realms/main/user-bulk-operations
{
  "action": "suspend",
  "user_ids": ["usr_...", "usr_..."],
  "reason": "INC-42 contractor offboarding",
  "dry_run": true
}
```

| `action` | Effect per account | Permission |
| --- | --- | --- |
| `suspend`, `lock`, `reactivate` | The same state change as the single-account routes (suspension and locking revoke sessions and grants); accounts already in that state are `skipped` (`already_in_state`) | `realm.users.suspend` |
| `revoke_sessions` | Revokes every session and grant (`user.sessions.revoked`) | `realm.users.sessions.revoke` |
| `add_required_action` | Adds `required_action` (one of the supported required actions) (`user.required_actions.set`) | `realm.users.required_actions` |

- The request needs an MFA session and the action's permission; `user_ids` must
  be 1–1000 unique, non-empty IDs and `reason` 5–500 characters. The response is
  `202 {"job_id", "dry_run"}`, and an `Idempotency-Key` header returns the same
  job on retry. The worker re-checks the requester's permission when the job runs
  and fails the job if it is gone.
- Each account is handled in its own transaction, and progress is checkpointed
  every 50 accounts, so a retried job continues where it stopped. Every change is
  audited with the requester as actor and the `reason`.
- Accounts are `skipped` when deleted or being deleted (`account_deleted`), when
  protected (`protected_account`; except for `revoke_sessions`), and the
  requester's own account for `suspend` and `lock` (`requester_account`).
- With `dry_run`, nothing changes and every account that passes these checks is
  reported `valid` (whether it is already in the target state is not checked).
- The job's `result` (`GET /jobs/{id}`) holds `action`, `dry_run`, `counts` per
  outcome and `results`: one `{"user_id", "outcome", "code"}` per account, with
  `outcome` `applied`, `valid`, `skipped` or `failed` and, for failures, the
  problem code (for example `not_found`); never profile data. The job input
  keeps the submitted user IDs and reason.
