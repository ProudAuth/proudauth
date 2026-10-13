# Migration adapters: Keycloak, ZITADEL, SuperTokens

Requirements: MIG-018 (with MIG-002..MIG-007, MIG-009, MIG-012, MIG-015,
MIG-017). Code: `internal/migrate` (converter, capability report, applier),
`cmd/identity-cli/migrate_from.go`, `internal/httpapi/migration_adapters.go`.
Tests: `internal/migrate` (fixtures in `internal/migrate/testdata`, real
exports of the tested versions), `internal/credential` (`TestImportedForeignVerifiers`,
`TestImportedVerifierRawPassword`), `TestMigrateFromOffline` and
`TestMigrateFromApplyReconciles` (`cmd/identity-cli`), and `TestMigrateFromKeycloak`, `TestMigrateFromZitadel`,
`TestMigrateFromSuperTokens` and `TestMigrateFromImportRecordRules`
(`tests/e2e/migrate_from_test.go`).

`identity-cli migrate-from keycloak|zitadel|supertokens` reads a source
export, converts it into `proudauth.user-import.v1` records and the
organizations they need, and writes a **capability report**
(`proudauth.migration-report.v1`) that counts, per kind of thing in the
export, what converts, what converts with loss and what is not carried over.
By default it then validates the result against the realm with dry-run
imports; with `--apply` it imports. Both go through the ordinary
authenticated APIs (`GET`/`POST /organizations`, `GET /roles`,
`POST /user-imports`, `GET /jobs/{id}`, `GET /user-imports/reconciliation`)
with the administrator session of `identity-cli login`. There is no
privileged side channel: the importing administrator's permissions,
delegation ceiling, owner-role approval and MFA session apply exactly as for
a hand-written import (MIG-005).

This page is the reference for the adapters. The order of work (inventory,
realm preparation, dry run, import, reconciliation, cutover) is the same as
for any import: follow [migration.md](migration.md) and use the adapter for
steps 2, 4 and 5. Everything the adapters produce is an ordinary user-import
request ([exit-and-export.md](exit-and-export.md#user-import-request)).

## Supported and tested versions (MIG-002)

| Source | Accepted | Tested with | Export |
| --- | --- | --- | --- |
| Keycloak | 26.x: the export's `keycloakVersion` must have major version 26 | 26.8.0 (`quay.io/keycloak/keycloak:26.8.0`, dev-file H2) | Realm export JSON with users ([below](#keycloak-26)) |
| ZITADEL | v4.x; the export does not state its version, so `--source-version` is required | v4.16.3 (`ghcr.io/zitadel/zitadel:v4.16.3`, PostgreSQL 18) | Admin API v1 data export ([below](#zitadel-v4)) |
| SuperTokens | core 12.x with the PostgreSQL plugin | core 12.0.7, plugin postgresql 9.5.5, CDI 5.4 (`supertokens/supertokens-postgresql`) | `proudauth.supertokens-export.v1`, produced read-only from the core database ([below](#supertokens-core-12)); the core API user list (`GET /users`, no password hashes) is accepted too, with `--source-version` |

The version check accepts any minor and patch release of the listed major
version, but only the tested version has been exercised; test a dry run on
a copy when your source runs another release. An export of another major
version is refused with `unsupported source version` (`422` on
`source_version` from the plan endpoint). When the export states its version
(Keycloak, the SuperTokens export) and `--source-version` is given too, the
option must name that version: the version itself or a leading part of it,
such as its major version (`26` or `26.8` for an export of `26.8.0`, `12` for
SuperTokens core `12.0.7`; a leading `v` or `core ` and a trailing `.x` are
ignored). Anything else (`25`, `26.9`) is refused with a message naming the
export's version and its major version; the report always records the
export's own version. For ZITADEL and the SuperTokens core API list, whose
exports do not state a version, the given version is the one checked and
recorded (`v4` is enough). An export of an unsupported major version is
refused whatever `--source-version` says. Compatibility is never inferred
from the product name. Other major versions are not supported until fixtures
exported from them are added to `internal/migrate/testdata` and the
adapter's version rule is widened.

The fixtures are real exports of the tested versions, trimmed (Keycloak:
built-in flows and client scopes, localization texts and key-provider private
keys removed). Every user of the SuperTokens fixture was also accepted by
SuperTokens 12.0.7's own bulk-import validation (`POST /bulk-import/users`),
and Keycloak's OTP key handling was checked against a running Keycloak 26.8.0.

`identity-cli migrate-from --list` and `GET /migration-adapters` print the
same table with the export command, and what converts, converts with loss and
is unsupported for each adapter.

## Producing the export

Every export holds password hashes and, when requested, TOTP secrets, and the
Keycloak export also holds client secrets in clear. Treat each file like a
database dump: produce it on a trusted host, keep it encrypted at rest and in
transit, and delete it after the rollback horizon (MIG-015,
[migration.md](migration.md#9-after-cutover)). Stop writes to the source (or
export from a snapshot) so the export matches the inventory.

### Keycloak 26

```sh
kc.sh export --file demo-realm.json --realm demo --users same_file
```

With `--dir <dir> --users different_files`, pass the realm file and every
users file as repeated `--input` options. In containers, run the export with
the server's data volume and the same `--db` options (for example
`--db dev-file` in development mode).

### ZITADEL v4

```sh
curl -X POST "$ZITADEL/admin/v1/export" -H "Authorization: Bearer $IAM_OWNER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"withPasswords": true, "withOtp": true, "responseOutput": true, "timeout": "60s"}' > zitadel-export.json
identity-cli migrate-from zitadel --input zitadel-export.json --source-version v4.16.3 --offline
```

This is the request `GET /migration-adapters` and `migrate-from --list`
show. The token needs `IAM_OWNER`. Password hashes are exported only with
`withPasswords`, TOTP secrets only with `withOtp`; `orgIds` and
`excludedOrgIds` limit the export. `timeout` belongs to ZITADEL's documented
export request (`ExportDataRequest`, a duration string such as `60s`); the
export comes back as one response, so for a large instance also allow a
long request in any proxy in front of ZITADEL. The response (`{"orgs": [...]}`) is the
input; the import-request shape `{"dataOrgs": {"orgs": [...]}}` is accepted
too. The v4 export carries no passkeys, U2F, OTP over SMS or email, instance
members (IAM roles) or instance settings, and does not fill in
`passwordChangeRequired` (when an export does carry `true`, the adapter adds
`update_password`).

### SuperTokens core 12

SuperTokens has no export API that returns password hashes, so the adapter
ships a read-only query (one `REPEATABLE READ, READ ONLY` transaction) to run
against the core's PostgreSQL database, once per app:

```sh
identity-cli migrate-from supertokens --print-export-sql > supertokens-export.sql
psql "$SUPERTOKENS_DB" -X -A -t -q -v app_id=public -v core_version=12.0.7 \
  -f supertokens-export.sql > supertokens-export.json
```

`core_version` is the `core_version` of the core's `version.yaml`. The output
is `{"format": "proudauth.supertokens-export.v1", "supertokens":
{"core_version", "plugin", "app_id", "exported_at"}, "tenants": [...],
"roles": [{"role", "permissions"}], "users": [...]}`; each user has the shape
of SuperTokens' documented bulk-import user (`externalUserId`,
`userMetadata`, `userRoles`, `totpDevices` with `deviceName`, `secretKey`,
`period` and `skew` (verified devices only), `loginMethods` with `recipeId`,
`email`, `passwordHash`, `hashingAlgorithm`, `thirdPartyId`,
`thirdPartyUserId`, `phoneNumber`, `isVerified`, `isPrimary` (true only for
linked primary users), `tenantIds` (default `["public"]`), `rpId` and
`timeJoinedInMSSinceEpoch`) plus `supertokensUserId`. WebAuthn login methods
are emitted with `recipeId: "webauthn"` so that the report counts them. When
several export documents are given in one run, they must share one core
version.

## The command

```text
identity-cli migrate-from <keycloak|zitadel|supertokens> --input FILE [--input FILE ...]
    [--realm main] [--source-system NAME] [--source-version V]
    [--mapping mapping.json] [--write-mapping-template mapping.json]
    [--plan (default) | --apply] [--offline]
    [--report FILE] [--write-documents DIR]
    [--trust-email-verification --verification-reason "..."]
    [--import-totp] [--allow-owner-roles] [--keep-attributes] [--batch-size 500]
identity-cli migrate-from --list
identity-cli migrate-from supertokens --print-export-sql
```

| Option | Meaning |
| --- | --- |
| `--input` | Export file; repeatable (Keycloak directory exports: the realm file and every users file; one Keycloak realm per run) |
| `--realm` | Target realm (default `main`); the command uses the session `identity-cli login` stored for it |
| `--source-system` | Qualifies every source ID in `import_mappings` and every organization external ID. Default `keycloak-<Keycloak realm name>` (lower-cased, other characters replaced by `-`, at most 63 characters), `zitadel`, `supertokens-<app ID>` (`public` when the export names none). Keep it for the whole migration: reconciliation, external IDs and re-runs depend on it ([migration.md](migration.md#2-choose-the-format-mig-002)) |
| `--source-version` | Required for ZITADEL and for the SuperTokens core API list; when the export states a version too, give that version or a leading part of it such as its major version (`26` for `26.8.0`; [above](#supported-and-tested-versions-mig-002)) |
| `--mapping` | The reviewed translation ([Mapping file](#mapping-file)) |
| `--write-mapping-template` | Writes a mapping template for review (mode 0600; [what it contains](#mapping-file)) |
| `--plan` (default) | Converts, resolves organizations and roles, submits every batch to `POST /user-imports` with `dry_run: true`, and puts the server's per-record outcome into the report. Nothing is written to the realm |
| `--offline` | With `--plan`: conversion and report only, no server calls and no login needed. Refused with `--apply` |
| `--apply` | Creates the missing organizations (with their external ID), imports the batches, and always finishes with a reconciliation against the converted export's counts ([step 7 below](#apply-idempotency-and-blocking)); the command exits non-zero when the reconciliation does not match or cannot be requested. Still run [step 7](migration.md#7-reconcile-mig-012) with the inventory's counts |
| `--report` | Report file (default `migration-report-<source system>.json`, mode 0600). Written also when the run is blocked, stops with an error or does not reconcile; the command then exits non-zero |
| `--write-documents` | Also writes the converted documents to this directory (created with mode 0700, files 0600): `organizations.json` (the target organizations with `source_key`, `slug`, `display_name`, `external_id`, `from_mapping` and `members`; not request bodies) and `user-import-NNN.json` (`format`, `source_system` and `users`, split by record count only; memberships name organizations by slug, and the `dry_run`, `import_totp` and `trust_*` flags are not included). They contain password verifiers and TOTP seeds |
| `--trust-email-verification`, `--verification-reason` | Keep the source's verified flags (MIG-009); needs `realm.users.verification.override` and a reason of at least 10 characters (checked before anything else) |
| `--import-totp` | Carry compatible TOTP seeds over (MIG-007); needs `realm.users.credentials.manage`. Without it, no seed is sent to the server, and users who had TOTP get the required action `configure_totp` |
| `--allow-owner-roles` | Allow memberships that the mapping translates to an owner role |
| `--keep-attributes` | Keep source attributes and metadata as administrator-only metadata: `admin_metadata` becomes `{"migration": {"source_system", "source_attributes"}}`, with `source_attributes` capped at 16 KiB by the converter; the server also applies `limits.metadata_bytes` (16 KiB by default) to the whole `admin_metadata` when the job runs |
| `--batch-size` | Records per import job (and per `user-import-NNN.json` document): 1–1000, default 500; any other value is refused before anything is read or sent (`--batch-size N is out of range: it must be between 1 and 1000 records per import job`). A batch also stays below 192 KiB of JSON, under `limits.max_body_bytes` |

The importing administrator needs an MFA session (every administration
endpoint requires one, dry runs included) and:

- `realm.users.import`;
- `realm.organizations.read`, and, for `--apply` when organizations are
  created, `realm.organizations.create`. Do not run the command without
  `realm.organizations.read`: `GET /organizations` then lists only the
  organizations the administrator is a member of, without an error, and the
  existing organizations would be resolved wrongly;
- `realm.roles.read`;
- `realm.jobs.read`, or being the job's requester (always the case here);
- `realm.users.credentials.manage` whenever records carry `update_password`
  or `configure_totp` (almost every real migration: unsupported verifiers and
  TOTP that is not imported produce them) and for `--import-totp`;
- `realm.users.write` for records with `verify_email`;
- `realm.users.verification.override` for `--trust-email-verification`;
- a delegation ceiling that covers every mapped role.

A typical session:

```sh
identity-cli login --url https://id.example.com --realm main
identity-cli migrate-from keycloak --input demo-realm.json --offline --write-mapping-template mapping.json
# review mapping.json: organizations -> slugs, roles -> organization roles
identity-cli migrate-from keycloak --input demo-realm.json --mapping mapping.json --import-totp \
  --trust-email-verification --verification-reason "Keycloak verified addresses by emailed link (CHG-1234)"
# read the report; fix conflicts, create missing roles, adjust the mapping; repeat
identity-cli migrate-from keycloak --input demo-realm.json --mapping mapping.json --import-totp \
  --trust-email-verification --verification-reason "Keycloak verified addresses by emailed link (CHG-1234)" --apply
```

### Apply, idempotency and blocking

1. **Organizations are resolved first, without writes.** An organization
   whose `external_id` is `<source system>:<kind>:<immutable source ID>` (for
   example `keycloak-demo:org:759f3c59-…`, `zitadel:org:3945…`,
   `supertokens-public:tenant:public`) was created by an earlier run and is
   reused. An organization the reviewed mapping names is used by its slug.
   An existing organization that only shares an *automatically proposed* slug
   is a **conflict**: imports never merge by name (MIG-004); map the source
   key to it explicitly, or to another slug. An organization the mapping
   names only to scope roles (`"organization": "<slug>"`) must already exist.
2. **Every mapped role must exist** as a realm-wide organization role
   (`GET /roles?boundary_type=organization`, roles without an organization or
   project), including the `membership_roles`; names are compared without
   regard to case.
3. **Any conflict or missing role blocks `--apply` before anything is
   written** (`migration blocked: …`). A dry run lists them as report notes
   (`blocks the import: …`).
4. Missing organizations are created (`POST /organizations` with slug,
   display name and external ID, one idempotency key per request).
5. Records are submitted in batches to `POST /user-imports`, naming
   organizations by ID, each with its own `Idempotency-Key`; each job is
   polled every second until it ends, and a job that ends `dead_letter`,
   `cancelled` or `failed` stops the run (`job ended <state>: <error>`).
   Requests that fail with a network error or `5xx` are tried up to three
   times, a second apart, with the same key; `4xx` answers are not retried.
6. **Re-running is safe.** Organizations are found again by external ID;
   every record already imported reports `already_imported` (import mappings
   are keyed by source system and source ID); accounts deleted in ProudAuth
   are `skipped_deleted` (MIG-017). A run that stopped part-way is completed
   by running it again.
7. **Every `--apply` ends with a reconciliation** (MIG-012), also one that
   stopped part-way: `GET /user-imports/reconciliation` for the source system
   with `expected_users`, `expected_memberships`,
   `expected_password_verifiers` and `expected_totp_factors` counted from the
   converted export: every record except those the server reported
   `skipped_deleted`, their memberships, the records with a password
   verifier and, with `--import-totp`, those with a TOTP seed (`0` without
   it). `expected_privileged_assignments` is not sent, because only the
   server knows which roles are privileged: review
   `privileged_assignments.items` in the answer. The counts are kept in the
   report's `import.expected` and the answer in `import.reconciliation`.
   A record that was not imported (`conflict`, `error`), a job that stopped,
   or a change made in ProudAuth since an earlier run (a password set
   through a reset, a factor enrolled, a membership added or removed) is a
   mismatch: the command prints each one (`reconciliation mismatch users:
   expected 12, actual 11`) and exits non-zero (`import not reconciled with
   the converted export: …`). A reconciliation request that fails is an
   error too. When nothing was ever imported under the source system the
   endpoint answers `404`, which matches an export without users and is a
   mismatch for any other. The reconciliation covers every account imported
   under the source system, so an export that covers only part of them (a
   ZITADEL export limited with `orgIds`, for example) does not reconcile;
   compare such runs by hand.

In a dry run, organizations that do not exist yet have no ID, so memberships
in them are left out of the dry-run batches and checked only by the real
import; the report says so in a note. Create the organizations first (or map
the keys to existing ones) when you need the dry run to cover every
membership.

Imports never update accounts: a re-run after the source changed reports
`already_imported` for changed users, and the change has to be applied in
ProudAuth by hand ([migration.md](migration.md#5-import-mig-011)).

## What converts

Outcomes in the report: **converted** (complete), **converted with loss**
(carried over; the reasons say what was lost), **unsupported** (not carried
over: outside the accepted bounds, no equivalent, secrets that cannot move,
or no reviewed translation), **ignored** (deliberately not carried: excluded
by the mapping, not requested, or without meaning in ProudAuth, such as
Keycloak's default roles or built-in clients).

"Requires a password reset" means: no verifier is imported, the account gets
the required action `update_password`, and the user sets a password through
`POST /password-resets`, which needs a verified email address (trust the
source's verification, or the user verifies first; otherwise use
[administrator-assisted recovery](account-recovery.md)). Completing the reset
clears `update_password`.

Rules that apply to every adapter:

- A user without a source ID, or with one longer than 256 characters, is
  unsupported. A user left with neither an email nor a username (for example
  phone-only users) is not imported.
- An email address that is not valid is dropped with a loss; the user is kept
  when a username remains.
- `display_name` is cut to 200 bytes, `given_name` and `family_name` to 100
  bytes, each with a loss.
- A proposed slug that collides with another organization of the same export
  gets `-2`, `-3`, … (with a loss note); a name that yields no slug becomes
  `org-<n>`; two keys mapped to one slug produce a note that they share one
  organization.
- Argon2id verifiers are imported only within the import bounds (memory at
  most 1 GiB, at most 16 iterations and 16 lanes, salt 8–64 bytes, hash
  16–64 bytes, no pepper), and bcrypt and PBKDF2 only within
  [theirs](#imported-password-verifiers); a verifier outside them means a
  password reset.

### Keycloak 26 to ProudAuth

| Keycloak | ProudAuth | Notes |
| --- | --- | --- |
| user `id` | `source_id` | The subject relying parties stored |
| `username` | `username` | Dropped (with loss) when it is not a valid, allowed ProudAuth username (reserved names such as `support`, characters outside `[a-z0-9._-]`); not repeated when equal to the email |
| `email`, `emailVerified` | `email`, `email_verified` | The verified flag is kept only with trusted verification |
| `firstName`, `lastName` | `given_name`, `family_name`, `display_name` ("First Last") | |
| attribute `locale` | `locale` | |
| other `attributes` | `admin_metadata.migration.source_attributes` with `--keep-attributes` | Otherwise reported as dropped |
| `enabled: false` | `state: suspended` | |
| `requiredActions` `UPDATE_PASSWORD`, `VERIFY_EMAIL`, `CONFIGURE_TOTP`, `TERMS_AND_CONDITIONS`, `UPDATE_PROFILE`, `VERIFY_PROFILE` | `update_password`, `verify_email`, `configure_totp`, `accept_terms`, `complete_profile`, `complete_profile` | Other required actions (`webauthn-register`, `delete_account`, `update_user_locale`, `CONFIGURE_RECOVERY_AUTHN_CODES`, `UPDATE_EMAIL`, …) are unsupported |
| password credential, algorithm `argon2` (type `id`, version 1.3) | `$argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>` | Lossless; Keycloak 26's default is m=7168, t=5, p=1 |
| `pbkdf2`, `pbkdf2-sha256`, `pbkdf2-sha512` | `$pbkdf2-sha1\|sha256\|sha512$i=<iterations>$<salt>$<value>` | Lossless re-encoding when within the [bounds](#imported-password-verifiers) (10,000–2,000,000 iterations); outside them a password reset is required |
| argon2 types `i` and `d`, version 1.0, parameters above the ceiling, unknown providers | Not imported: password reset required | Community bcrypt providers that store a `$2…` string are passed through |
| FIPS-mode PBKDF2 verifiers padded to `maxPaddingLength` | Not detectable | The padding length is server configuration, not part of the export: such users fail to verify and must reset their password |
| OTP credential (TOTP, HmacSHA1, 6 digits, 30 s) | `totp_secret` = base32 of the UTF-8 bytes of the stored secret (or the secret itself when `secretEncoding` is `BASE32`) | Only with `--import-totp`. HOTP, SHA-256/512, 8 digits or 60 s: unsupported, `configure_totp` |
| `webauthn`, `webauthn-passwordless` | — | Unsupported: users register passkeys again (MIG-008) |
| `recovery-authn-codes` | — | Unsupported |
| `federatedIdentities` | — | Unsupported: users link their upstream accounts again |
| `federationLink` (LDAP or Kerberos user) without a local password | — | Password unsupported: password reset required |
| service-account users (`serviceAccountClientId`) | — | `service_accounts`: unsupported |
| `federatedUsers` | — | Unsupported users |
| organizations (`alias`, `name`, `members`) | Organization (slug from the alias, external ID from the organization's ID) and memberships | Members are matched by user name (lower-cased), then by user ID. Domains and organization identity providers are reported lost; disabled organizations are created active (loss) |
| groups | Role-grant key `group:<path>` for the groups a user is directly in; an organization only when the mapping lists `group:<path>` | Membership in a subgroup counts for its ancestors' organization membership, and the realm and client roles of ancestor groups are inherited into the member's grants, but a `group:<path>` grant key exists only for direct groups. Group attributes and hierarchy are not migrated |
| realm roles, client roles | Role-grant keys `realm-role:<name>`, `client-role:<client>:<role>` | Translated only through the mapping; `default-roles-<realm>`, `offline_access` and `uma_authorization` are ignored |
| clients (other than built-in ones), identity providers, authentication flows, user federation components, password policy, a non-default OTP policy, WebAuthn policy, brute-force settings, client scopes, SMTP | — | Reported unsupported; recreate them through the configuration import or the API, with new secrets |

### ZITADEL v4 to ProudAuth

| ZITADEL | ProudAuth | Notes |
| --- | --- | --- |
| org (`orgId`, `org.name`) | Organization (slug from the name), external ID `<source system>:org:<orgId>` | Domains reported lost; organizations that are not active are created active (loss) |
| human user `userId` | `source_id`, with a membership in its own org | |
| `userName` | `username` | Dropped with loss when invalid; not repeated when equal to the email |
| `email.email`, `isEmailVerified` | `email`, `email_verified` | |
| `profile.firstName`, `lastName`, `displayName`, `preferredLanguage` | `given_name`, `family_name`, `display_name`, `locale` (`und` ignored) | `nickName` and `gender` reported lost |
| `state` | `ACTIVE`, `INITIAL`, unspecified: active; `INACTIVE`, `SUSPEND`: suspended; `LOCKED` and unknown states: suspended (with loss); `DELETED`: not imported | |
| `passwordChangeRequired: true` | `update_password` | The v4 export does not fill it in |
| `hashedPassword.value`: bcrypt (`$2a$`, ZITADEL's default cost 14) or argon2id PHC | Passed through | Within the [bounds](#imported-password-verifiers) |
| PBKDF2 in passlib form (`$pbkdf2-sha256$<iterations>$<ab64 salt>$<ab64 hash>`) | Re-encoded as `$pbkdf2-sha256$i=…` | |
| md5crypt, sha-crypt, scrypt, argon2i, phpass, plaintext `password` | Not imported: password reset required | |
| `otpCode` | `totp_secret` (SHA-1, 6 digits, 30 s) | Only with `--import-totp` |
| `phone` | — | Unsupported |
| `userMetadata` (base64) | Decoded into kept attributes with `--keep-attributes` | |
| `userLinks`, `user.idps` | — | Unsupported: users link again |
| `orgMembers` roles (`ORG_OWNER`, …) | Role-grant key `org-member:<ROLE>`, scoped to the org that lists the member | A user can be a member of other orgs than its own |
| `projectMembers` | `project-member:<projectId>:<ROLE>` | |
| `userGrants` | `project-role:<projectId>:<roleKey>`, scoped to the user's own org | |
| machine users | `service_accounts`: unsupported | Keys and personal access tokens cannot move |
| projects, applications (OIDC, API, SAML), policies, actions, keys, identity providers, project grants | — | Reported unsupported (the built-in ZITADEL project and its applications are ignored) |

### SuperTokens core 12 to ProudAuth

| SuperTokens | ProudAuth | Notes |
| --- | --- | --- |
| primary user: `externalUserId` (user ID mapping) or `supertokensUserId` | `source_id` (the ID applications see) | Linked login methods become one account |
| emailpassword `email` (preferred), otherwise the first email of a login method | `email`; `isVerified` → `email_verified` | Further distinct emails reported lost |
| `passwordHash` BCRYPT (`$2a$`, default log rounds 11) | Passed through | Cost 10–15 |
| ARGON2 (`$argon2id$`, default m=87795, t=1, p=2) | Passed through | argon2i and argon2d are unsupported |
| FIREBASE_SCRYPT | Not imported: password reset required | Depends on the Firebase signer key |
| thirdparty (`thirdPartyId`, `thirdPartyUserId`) | — | Unsupported link: users link again |
| passwordless email | Account by email, without a password | |
| passwordless phone | — | Phone numbers are unsupported; phone-only users (no email or username) are not imported |
| webauthn | — | Unsupported |
| `totpDevices` (period 30) | The first compatible device → `totp_secret` | Other periods unsupported; further devices ignored (one TOTP factor per account) |
| `userMetadata` | Kept attributes with `--keep-attributes` | |
| tenants | Organizations (`tenant:<id>`) | The `public` tenant is an organization only when the mapping makes it one |
| `userRoles` (`role`, `tenantIds`) | `role:<name>`, scoped to the organizations of those tenants | Role permissions are not migrated (the review note says so) |

### Never carried over by any adapter

Passkeys and WebAuthn credentials, recovery codes, HOTP, OTP over SMS or
email (users enroll again, MIG-008); identity-provider links (there is no
administration API to pre-link an account, TEST-026: users link again
through the configured upstream connection); phone numbers; service
accounts, machine users and their keys; clients, client secrets,
identity-provider secrets, flows, policies, scopes and mappers, ZITADEL
projects, actions and keys (recreate them, [configuration
import](exit-and-export.md#configuration-import)); scripted extensions such as
Keycloak script authenticators or ZITADEL actions (re-implement them as
[hooks or workflows](../architecture-decisions/0021-no-embedded-code-execution.md));
sessions, refresh and offline tokens and consents (users sign in again,
MIG-010); creation and last-login timestamps; the source's audit history
(not part of these exports; import it separately with `POST /audit-imports`,
MIG-016).

## Mapping file

The mapping (`proudauth.migration-mapping.v1`) is the reviewed translation of
source organizations and role grants. Without it, every role grant is
unsupported (`no reviewed translation for <key>`) and grants nothing
(MIG-005: an unknown source permission never becomes access).

```json
{
  "format": "proudauth.migration-mapping.v1",
  "organizations": {
    "org:acme": {"slug": "acme", "display_name": "Acme Corp"},
    "org:globex": null,
    "group:/tenants/initech": {"slug": "initech"},
    "tenant:public": {"slug": "northwind"}
  },
  "membership_roles": ["member"],
  "roles": {
    "realm-role:app-admin": {"roles": ["admin"]},
    "client-role:billing-app:editor": {"organization": "acme", "roles": ["billing-editor"]},
    "realm-role:app-user": {"roles": []},
    "group:/acme/admins": {"roles": ["admin"]},
    "org-member:ORG_OWNER": {"roles": ["owner"]},
    "project-role:394589305978224645:portal.editor": {"roles": ["member"]},
    "role:viewer": null
  }
}
```

- **Organization keys:** Keycloak `org:<alias>` and `group:<path>`; ZITADEL
  `org:<orgId>`; SuperTokens `tenant:<tenantId>`. A key that is absent: Keycloak
  organizations, ZITADEL orgs and SuperTokens tenants other than `public`
  become organizations with a derived slug; Keycloak groups and the `public`
  tenant do not. `null` excludes the organization (memberships through it are
  reported `ignored`). A mapped slug may name an existing organization, which
  is then used: this is the reviewed way to merge into an existing tenant.
- **Role keys:** Keycloak `realm-role:<name>`, `client-role:<clientId>:<role>`,
  `group:<path>`; ZITADEL `org-member:<ROLE>`,
  `project-member:<projectId>:<ROLE>`, `project-role:<projectId>:<roleKey>`;
  SuperTokens `role:<name>`. Targets are names of realm-wide
  **organization** roles. Without `organization`, the roles apply in the
  grant's natural scope: every membership of the user (Keycloak), the org that
  lists the member (ZITADEL organization and project members), the user's own
  org (ZITADEL project roles), the role's tenants (SuperTokens). With
  `organization`, they apply in that organization, creating the membership.
  `[]` and `null` translate to nothing (`ignored`); an **absent** key is
  unsupported and counted in `summary.untranslated_role_grants`. A translated
  grant that has no organization to apply in (for example a SuperTokens role
  held only in the `public` tenant when `public` is not mapped, or a Keycloak
  user without memberships) is unsupported too and counted the same way;
  give the entry an `organization` to place it.
- `membership_roles` are given to every membership the conversion creates.
- `note` members are free text; the template fills them in for role entries
  with descriptions and grant counts.
- `--write-mapping-template` (and `mapping_template` in the plan response)
  writes a starting point, not a complete list: every organization key that
  becomes an organization by default, with its proposed `slug` and
  `display_name` (excluded keys as `null`), and every role key with
  `"roles": []` and a note, except the default roles the adapter ignores.
  **Keys that are not organizations by default (Keycloak `group:<path>` keys
  and the SuperTokens `tenant:public`) are not listed: add them by hand** to
  make a group or the public tenant an organization. Entries of a mapping
  given with `--mapping` are copied into the template. The reviewer fills in
  the roles. Unknown members are rejected, and slugs must be canonical.

Review every translation to an owner role or a role holding privileged
permissions by name; the dry run's `plan` and `totals` mark them
([migration.md](migration.md#4-dry-run-mig-003-mig-004)).

## Capability report

The report (`proudauth.migration-report.v1`) is written to the `--report`
file and returned by `POST /migration-plans`. It never contains password
verifiers, TOTP seeds or email addresses (the tests assert this), and user
records are identified by source ID. It still describes the source: its
structure (organization and role names, counts), and in loss reasons some
names, such as the names of ZITADEL machine users, Keycloak organization
domains and attribute keys. Keep it with the migration record, not in public
tickets.

| Member | Content |
| --- | --- |
| `format`, `generated_at` | `proudauth.migration-report.v1` and the time of the conversion |
| `source` | `product`, `source`, `version`, `tested_versions`, `realm` (the Keycloak realm or the SuperTokens app ID; absent for ZITADEL) |
| `source_system` | The source-system name every source ID is qualified with |
| `options` | `import_totp`, `keep_attributes`, `mapping_given` |
| `summary` | `users`, `users_to_import`, `passwords_migrated`, `password_resets_required`, `totp_migrated`, `mfa_reenrollments_required`, `suspended_accounts`, `organizations`, `memberships`, `role_assignments`, `untranslated_role_grants` |
| `entities.<name>` | `total`, `converted`, `converted_with_loss`, `unsupported`, `ignored`, and `reasons` (`outcome`, `reason`, `count`) aggregated per entity |
| `items` | Every item that was not simply converted: `entity`, `source_id`, `outcome`, `reasons`. A user with any loss is `converted_with_loss` with all its losses listed (password not migrated and why, reset required, TOTP not migrated, passkeys, links, dropped username or attributes, untranslated role grants, …) |
| `mapping` | `organizations` (`key`, `name`, `status` `auto`, `mapped`, `excluded` or `not_an_organization`, `slug`, `members`), `roles` (`key`, `note`, `grants`, `status` `mapped`, `no_roles`, `untranslated` or `ignored`, `organization`, `roles`) and `unknown_keys` (mapping entries that match nothing) |
| `notes` | Blocking conflicts, missing roles and other remarks |
| `import` | After a dry run or an import: `dry_run`, `jobs`, `counts` (server statuses summed over the batches: `imported`, `valid`, `already_imported`, `conflict`, `skipped_deleted`, `error`), `totals` (`password_verifiers`, `totp_factors`, `memberships`, `role_assignments`, `privileged_memberships`, `trusted_verified_emails`, `suspended_accounts`, `password_updates_required`), `organizations` (`slug`, `id`, `status` `exists`, `created`, `will_create` or `conflict`, `detail`), `records` (every record that was not `imported` or `valid`, with its status, user ID and error), and after a real import `expected` (`users`, `memberships`, `password_verifiers`, `totp_factors`: the converted export's counts sent as `expected_*`) and `reconciliation` (the `GET /user-imports/reconciliation` body, with `mismatches` and `reconciled`; absent when the request failed) |

Entity names: `users`, `service_accounts`, `organizations`, `groups`,
`tenants`, `memberships`, `role_assignments`, `role_definitions`,
`password_credentials`, `totp_factors`, `webauthn_credentials`,
`recovery_codes`, `other_credentials`, `federated_identities`,
`phone_numbers`, `attributes`, `required_actions`, `clients`,
`identity_providers`, `authentication_flows`, `realm_policies`,
`user_federation`, `client_scopes`, `projects`, `project_grants`, `actions`,
`keys`, `other_configuration`, `sessions`.

Compare the summary with the inventory (MIG-001) before importing. The
reconciliation that ends `--apply` checks the realm against the converted
export, so it shows whether the import carried over what the converter
produced. For the reconciliation in
[migration.md](migration.md#7-reconcile-mig-012), take the `expected_*`
counts from the inventory, not from the report: the report describes what the
converter produced, not what the source holds. A difference between the two
(for example `passwords_migrated` below the inventory's password users) is
exactly what the review has to explain.

## Imported password verifiers

The adapters pass verifiers through, or re-encode them losslessly, only into
formats the user-import API accepts (CRED-004, MIG-006):

| Format | Bounds | Verification |
| --- | --- | --- |
| Argon2id PHC (`$argon2id$`) | Memory at most 1 GiB, at most 16 iterations and 16 lanes, salt 8–64 bytes, hash 16–64 bytes; no pepper (`k=`) | Native verifier |
| bcrypt `$2a$`, `$2b$`, `$2y$` (60 characters) | Cost 10–15 | `golang.org/x/crypto/bcrypt`, with the source's 72-byte semantics |
| PBKDF2 `$pbkdf2-sha1\|sha256\|sha512$i=<n>$<salt>$<dk>` (unpadded standard base64) | 10,000–2,000,000 iterations; salt 8–64 bytes; derived key 16–64 bytes | `crypto/pbkdf2` |

bcrypt and PBKDF2 are **legacy** verifiers, like salted SHA-256: they verify
only until `security.password.legacy_hashes_until`, and user imports refuse
them after that date ([configuration.md](configuration.md#security)). Every
imported verifier is rehashed to the deployment's Argon2id at the next
successful sign-in. Imported verifiers are checked against the password as
typed (what the source hashed) and its NFKC form; a match of the typed form is
rehashed to the NFKC-based local verifier. A stored verifier outside the
bounds never verifies. The floors follow OWASP (bcrypt cost 10) and NIST
SP 800-63B (PBKDF2 10,000 iterations); the ceilings keep a stored verifier
from turning a sign-in into a CPU sink.

## Admin API

Two read-only endpoints expose the same converter (`realm.users.import`,
admin-audience token from an MFA session). They never write or store
anything.

- `GET /api/v1/realms/{realm}/migration-adapters` returns `items`, one per
  adapter: `source`, `product`, `supported_versions`, `tested_versions`,
  `export_format`, `export_command`, `converts`, `converts_with_loss` and
  `unsupported`.
- `POST /api/v1/realms/{realm}/migration-plans` converts an export in memory
  and checks it against the realm. Body:

  | Member | Meaning |
  | --- | --- |
  | `source` | `keycloak`, `zitadel` or `supertokens` (`422` otherwise) |
  | `exports` | 1–20 export documents, as JSON values (the files' contents) |
  | `source_version` | As `--source-version` (`26` names an export of `26.8.0`); an unsupported version, or one that does not name the export's own, is `422` on `source_version` |
  | `source_system` | As `--source-system` (same syntax rule as user imports) |
  | `mapping` | A mapping document, or `null` |
  | `keep_attributes`, `import_totp` | As the CLI options |

  The response is `200 {"report", "target", "mapping_template"}`: the
  capability report (without `import`), the checks against the realm, and a
  mapping template (merged with the given mapping). `target` holds `users`
  (count), `organizations` (each target organization with `source_key`,
  `slug`, `display_name`, `external_id`, `from_mapping`, `members`, `status`
  `exists`, `will_create` or `conflict`, and `id` when it exists), `roles` (each
  mapped role name with `exists` and, when it exists, `privileged` and
  `owner`), `already_imported` and `skipped_deleted` (source IDs mapped
  earlier for this source system, to a live or a deleted account), and
  `identifier_conflicts` (source IDs whose email or username already belongs
  to an account). Records are named by source ID only.

  Errors: `422` on `source`, `exports`, `source_system`, `mapping` or
  `source_version` (other conversion errors are `422` on `exports`); `400`
  for unknown members or malformed JSON; `413` above the body limit. The
  endpoint checks only `realm.users.import`, also with `import_totp: true`,
  because it imports nothing; the import itself checks the credential
  permission.

  The request carries the export, including password hashes, so it is
  bounded by `limits.max_body_bytes` (256 KiB by default): it suits small
  realms and previews in an administration UI. Plan large exports with the
  CLI, which sends the records in batches. Unlike the CLI's dry run, the plan
  does not run the server's record validation (`POST /user-imports` with
  `dry_run`).

## Limitations

- Only the listed major versions are accepted, and only one release of each
  has been tested; other major versions must be tested and added first.
- The reconciliation that ends `--apply` does not count privileged
  assignments (`expected_privileged_assignments`): review
  `privileged_assignments.items` in the report, and pass the inventory's
  count in [step 7](migration.md#7-reconcile-mig-012).
- Keycloak FIPS-mode PBKDF2 verifiers padded to `maxPaddingLength` cannot be
  recognized from the export; those users fail to verify and must reset their
  password. Leave them with a reset.
- Keycloak organization domains, organization identity providers, group
  attributes and group hierarchy are not migrated; groups become
  organizations only when mapped.
- One TOTP factor per account; further SuperTokens devices are ignored.
- Organizations deleted in ProudAuth lose their external ID, so a later run
  would create them again (users deleted in ProudAuth are not recreated).
- The plan endpoint is bounded by `limits.max_body_bytes`.
- Dry runs cannot validate memberships in organizations that do not exist yet.
