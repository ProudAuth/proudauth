# Migrating into ProudAuth

Requirements: MIG-001..MIG-018 (docs/plan.md). This runbook moves users,
memberships and audit history from another identity system into one ProudAuth
realm and switches relying parties over. The endpoint reference (request
members, result fields, limits) is
[exit-and-export.md](exit-and-export.md#import-into-proudauth); this page gives
the order of work, the decisions and the checks. From Keycloak 26, ZITADEL v4
and SuperTokens core 12, `identity-cli migrate-from` converts the export and
drives steps 2, 4 and 5 for you
([migration-adapters.md](migration-adapters.md)); from any other source you
convert the export yourself.

API paths are relative to `/api/v1/realms/{realm}` and need an admin-audience
token from an MFA session (`identity-cli login`, then
`identity-cli api METHOD /path [json]`). Asynchronous jobs are read with
`GET /jobs/{id}`.

What carries over and what does not:

| Carried over | Not carried over |
| --- | --- |
| Accounts (email, username, display name, given and family name, locale) keyed by a source ID; account state `active` or `suspended`; required actions (`update_password`, `configure_totp`, `verify_email`, …); administrator-only metadata; verified-email flags when explicitly trusted; password verifiers in Argon2id, bcrypt (cost 10–15), PBKDF2 (SHA-1, SHA-256 or SHA-512, 10,000–2,000,000 iterations) and salted SHA-256, the last three only until `security.password.legacy_hashes_until`; TOTP seeds (SHA-1, 6 digits, 30 s) when explicitly authorized; organization memberships through an explicit role translation; historical audit records, labelled as imported | Other password formats (scrypt, Firebase scrypt, md5crypt, sha-crypt, argon2i/argon2d, verifiers that need a source pepper, ...), passkeys, recovery codes, HOTP, SMS and email factors, phone identifiers, federated links, sessions, refresh and access tokens, consents, user-editable profile attributes, groups, locked or other account states, creation and last-login times |

## 1. Inventory the source (MIG-001)

Write the inventory down and get it reviewed **before** any data is written to
ProudAuth. Keep it with the change record; the reconciliation in step 7 compares
against its counts.

| Item | Record in the inventory | Where it goes |
| --- | --- | --- |
| Users | Count by state (active, disabled or locked, pending deletion, deleted); which identifiers they use (email, username, phone) and whether emails are verified | One import record per user. Leave deleted and deletion-pending users out; import disabled and locked users with `state: "suspended"` (step 5) |
| Subject IDs | The source's stable, immutable user ID; the subject value each relying party stores (public `sub`, pairwise `sub`, email, other) | `source_id`; relying-party remapping in step 8 |
| Organizations | Tenants or organizations with their IDs and names | Created in ProudAuth before the import (`POST /organizations`); records name them by ID or slug |
| Memberships | Per user: organization and roles | `memberships[]` with translated role names |
| Roles, groups, permissions | Every source role or group that grants access, with what it allows | A reviewed translation table to ProudAuth organization roles (step 3). Groups are not imported |
| Clients | Applications, client IDs, redirect URIs, grant types, audiences | Recreated through configuration import or `POST /clients`; new client secrets |
| Credentials | Password hash algorithm, parameters, salt layout, pepper or secret key in use | Import Argon2id (re-encoded as PHC strings if needed), bcrypt, PBKDF2 (re-encoded as `$pbkdf2-<hash>$i=…`) and `sha256(salt \|\| password)` verifiers within the accepted bounds; everything else, including verifiers that depend on a source pepper, means a password reset (`required_actions: ["update_password"]`) or recovery ([step 5](#credentials-and-factors)) |
| Factors | TOTP (algorithm, digits, period), passkeys and their RP ID, SMS, recovery codes | TOTP seeds when compatible; others re-enroll |
| Grants and consents | Refresh tokens, offline grants, consents per client | Not carried over: users sign in and consent again (MIG-010) |
| Federated links | Upstream identity providers and linked accounts | Not carried over: configure the connection, users link again |
| Data ownership | For each data set: the system of record, who approves its move and the legal basis, and which other systems key data by the source subject | Who signs off each step; which relying parties must remap subjects |

## 2. Choose the format (MIG-002)

`GET /user-import-formats` (`realm.users.import`) lists what this release
accepts. There is one import format, `proudauth.user-import.v1`: normalized
records produced from your source export. Read the format's `supports` and
`unsupported` lists against your inventory, and name the format in every
request (`"format": "proudauth.user-import.v1"`); any other value is refused
with `422`.

There are first-party adapters for three source products (MIG-018), each for
exact versions only:

| Source | Accepted versions | Tested with |
| --- | --- | --- |
| Keycloak | 26.x | 26.8.0 |
| ZITADEL | v4.x | v4.16.3 |
| SuperTokens core (PostgreSQL plugin) | 12.x | 12.0.7 |

`identity-cli migrate-from <source>` converts such an export into import
records, writes a capability report of what converts, converts with loss and
is unsupported, and runs the dry run and the import through the same APIs
([migration-adapters.md](migration-adapters.md)). Run it with `--offline`
first and read the report against the inventory before anything touches the
realm. For any other product or version, write the conversion yourself: do
not assume an export is compatible because the product is familiar, and an
export of another major version is refused by the adapters.

Pick the `source_system` name now and keep it for the whole migration: it
qualifies every source ID, links audit history to users and is what the
reconciliation report is asked for. It must match `^[a-z0-9][a-z0-9._-]{0,62}$`
(lowercase letters, digits, `.`, `_` and `-`, at most 63 characters), for
example `legacy-idp`; user imports, audit imports, external IDs and the
reconciliation report all refuse other names.

## 3. Prepare the realm

1. Configure the realm (policy, passkey relying party, upstream connections)
   and create the organizations. With `identity-cli migrate-from --apply`,
   the organizations of the export are created for you, with an external ID
   that later runs find them by; an existing organization is used only when
   the reviewed mapping names it
   ([migration-adapters.md](migration-adapters.md#apply-idempotency-and-blocking)).
2. Create the organization roles your translation table maps to, as realm-wide
   organization roles (`POST /roles` with `boundary_type: "organization"`, no
   organization or project). Write the translation as an explicit, reviewed
   table: an unknown role name fails the record (`unmapped role ...`), owner
   roles need `allow_owner_roles: true`, and every role must be within the
   importing administrator's own delegation ceiling (MIG-005). Never map an
   unknown source permission to an administrator role.
3. Recreate clients and resources, for example with a reviewed configuration
   document (`POST /configuration/imports`,
   [exit-and-export.md](exit-and-export.md#configuration-import)).
4. Grant the importing administrator only what the import needs:
   `realm.users.import`; `realm.users.verification.override` to keep verified
   emails; `realm.users.credentials.manage` to import TOTP seeds and for
   records that carry the required actions `update_password` or
   `configure_totp`; `realm.users.write` for records that carry
   `verify_email` or `verify_contact`; `realm.audit.import` for audit history.
   All of them except `realm.users.write` (high) are privileged permissions.
   The adapters also need `realm.organizations.read`, `realm.organizations.create`
   (when they create organizations) and `realm.roles.read`.

## 4. Dry run (MIG-003, MIG-004)

With an adapter, `identity-cli migrate-from <source> --input … --mapping …`
(without `--apply`) does this step: it submits every batch with `dry_run: true`
and adds the server's per-record outcome to the capability report
([migration-adapters.md](migration-adapters.md#the-command)). Otherwise,
convert the export into batches of at most 1000 records whose body fits
`limits.max_body_bytes` (256 KiB by default), then submit each batch with
`dry_run: true`:

```json
POST /api/v1/realms/main/user-imports
{
  "format": "proudauth.user-import.v1",
  "source_system": "legacy-idp",
  "dry_run": true,
  "trust_email_verification": true,
  "verification_reason": "legacy-idp verified addresses by emailed link (CHG-1234)",
  "users": [
    {"source_id": "u-17", "email": "ada@example.com", "email_verified": true,
     "password_hash": "$argon2id$v=19$m=65536,t=3,p=2$...$...",
     "memberships": [{"organization": "acme", "roles": ["member"]}]}
  ]
}
```

Review the job result ([fields](exit-and-export.md#job-result)):

- `counts`: every record should be `valid`. Fix the data behind each `error`
  and `conflict` and run the dry run again.
- `conflict` means a repeated `source_id`, email or username within the batch,
  or an email or username that already belongs to an account. Imports never
  merge accounts by matching identifiers: decide per case whether the source
  holds a duplicate person, whether the existing ProudAuth account is the same
  person (then record the source ID on it with
  `PUT /users/{user}/external-ids/{source}` instead of importing), or whether
  the identifier is stale.
- `already_imported` and `skipped_deleted` are expected only for records
  imported or deleted earlier.
- Each `plan` shows the mapping (`<source_system>/<source_id>`), whether the
  email will be verified, whether a password verifier or TOTP factor comes
  over, the account `state` when it is `suspended`, its `required_actions`,
  and the memberships with role names and a `privileged` flag. Review every
  privileged membership by name.
- `totals` gives the memberships, role assignments, privileged memberships,
  verified emails, password verifiers, TOTP factors, suspended accounts and
  accounts that must set a password (`password_updates_required`) the batch
  would create. Compare them with the inventory.

A dry run does not check that a record has an email or username, username
syntax or display-name length; those fail in the real run.

## 5. Import (MIG-011)

Submit the same batches without `dry_run`, with an `Idempotency-Key` header per
batch so a retried request returns the same job. Each record is created in its
own transaction, the job checkpoints every 50 records and resumes after its last
checkpoint when retried or picked up by another worker, and
`POST /jobs/{id}/cancel` stops it at the next checkpoint without undoing the
records already created ([details](exit-and-export.md#resumption-and-cancellation-mig-011)).
Re-submitting a batch is safe: records already imported report
`already_imported`. With an adapter, `--apply` creates the organizations,
submits the batches with their own idempotency keys, waits for each job and
ends with the reconciliation report, requested with the converted export's
expected counts: the command exits non-zero when the realm does not match
the export (a record that was not imported, for example) or the
reconciliation cannot be requested. Running the same command again is safe
([migration-adapters.md](migration-adapters.md#apply-idempotency-and-blocking)).

Imports only create accounts. A record whose `source_id` is already imported is
not updated, so changes made in the source after a record was imported (new
email, new password, removed membership) do not come over: freeze the source
(step 8) or apply those changes in ProudAuth yourself.

After each batch:

- Accounts that were disabled in the source should arrive `suspended`: give
  their records `"state": "suspended"` (the adapters do). A record never makes
  an account more permissive than `active`; for accounts imported `active` by
  mistake, use
  `POST /user-bulk-operations {"action": "suspend", "user_ids": [...], "reason": "..."}`
  ([bulk operations](exit-and-export.md#bulk-user-operations)). Locked
  accounts have no import equivalent and arrive `suspended`.
- Keep each job's `results`: they map every `source_id` to the new `user_id`.

### Credentials and factors

| Item | What happens | Reference |
| --- | --- | --- |
| Role translation (MIG-005) | Explicit role names per membership; ceilings and owner-role approval enforced, re-checked by the worker | [User import request](exit-and-export.md#user-import-request) |
| Password verifiers (MIG-006, CRED-004) | Argon2id PHC strings (bounded parameters, no pepper), bcrypt (`$2a$`, `$2b$`, `$2y$`, cost 10–15), PBKDF2 (`$pbkdf2-sha1\|sha256\|sha512$i=<n>$<salt>$<dk>`, 10,000–2,000,000 iterations, salt 8–64 bytes, key 16–64 bytes) and salted SHA-256 are imported and rehashed to the deployment's Argon2id at the next successful sign-in; other formats fail the record. For users whose verifier cannot come over, leave `password_hash` out and set `required_actions: ["update_password"]`: they set a password through `POST /password-resets` (which needs a verified email) or administrator-assisted recovery. Never collect plaintext passwords. bcrypt, PBKDF2 and salted SHA-256 are legacy verifiers: end their window with `security.password.legacy_hashes_until` (a UTC date, inclusive): from the next day they no longer verify (the sign-in fails like a wrong password and records `credential.password.legacy_retired`) and imports refuse them, so the remaining users recover their password. `identity-cli doctor` prints how many accounts still have one; set the date once that number is low enough | [User import request](exit-and-export.md#user-import-request), [configuration.md](configuration.md#security), [imported verifiers](migration-adapters.md#imported-password-verifiers) |
| TOTP seeds (MIG-007) | Imported only with `import_totp: true` (credential authority and an MFA session), re-encrypted under the deployment's key, audited as `mfa.totp.imported`; SHA-1, 6 digits, 30 s only; one factor per account; no recovery codes. Users whose factor does not come over can be given `required_actions: ["configure_totp"]` | [TOTP seeds](exit-and-export.md#totp-seeds-mig-007) |
| Verified emails (MIG-009) | Kept only with `trust_email_verification`, the verification override and a written reason; the account records `import:<source_system>` as the verification source | [User import request](exit-and-export.md#user-import-request) |
| Passkeys (MIG-008) | Not imported. A passkey is bound to the relying-party ID it was registered for, and its private key never leaves the authenticator, so copying a database does not move it. Users register new passkeys in ProudAuth | Below |
| Sessions and tokens (MIG-010) | Not imported. Every user signs in again at cutover | [Step 8](#8-cut-over-mig-013) |

**Passkeys (MIG-008).** ProudAuth's RP ID is the realm policy
`webauthn.rp_id`, or, when it is unset, the host of
`interaction.login_ui_url` or of the issuer. Set `webauthn.rp_id` (and
`webauthn.origins`) explicitly before users enroll, to a host name you will
keep: passkeys keep working after a host name change only if the RP ID stays
the same (the new origin must be that RP ID or a subdomain of it). Changing
the RP ID, or moving the deployment to a domain outside it, means every user
enrolls again. The same holds in the other direction: the source's passkeys
only work for its own RP ID, so plan re-enrollment and keep another sign-in
method (password or emailed code) available for users who had only passkeys.

## 6. Import audit history (MIG-016)

If the source's audit records must stay available, import them after the users,
with the same `source_system`, so their subjects resolve to the new accounts:
`POST /audit-imports` (`realm.audit.import`, MFA session), at most 500 records
per request, each with its own `source_event_id`, so a repeated request reports
`duplicate` instead of storing twice
([reference](exit-and-export.md#historical-audit-records-mig-016)).

Imported records stay apart from ProudAuth's evidence: they are listed only by
`GET /imported-audit-events`, always with `source: "import"` and
`verified: false`, and never enter the hash-linked audit chain. ProudAuth
records one `audit.history.imported` event per request whose `batch_digest`
commits to the imported records' content hashes; keep the source export and
the digests together if the history may be needed as evidence. Retention of
imported records counts from the import, so set
`privacy.audit_retention_by_category.imported` if the source's records must be
kept longer or shorter than local events.

Imported metadata passes through audit redaction (secret-looking member names
and token-shaped values become `[REDACTED]`), but other personal data in it is
kept: drop what you do not need from the export first. Records about accounts
that were already deleted in ProudAuth are stored without their
source-supplied details, and users see the imported records about them in
their personal data export.

## 7. Reconcile (MIG-012)

Before cutover, compare the realm with the inventory:

```
GET /user-imports/reconciliation?source_system=legacy-idp&expected_users=4180
    &expected_memberships=5012&expected_privileged_assignments=37
    &expected_password_verifiers=3990&expected_totp_factors=820
```

The report ([fields](exit-and-export.md#reconciliation-mig-012)) lists every
expected count that differs in `mismatches`, and `reconciled` is `true` only
when none does. `identity-cli migrate-from --apply` already asks for it with
the counts of the converted export, which shows whether the import carried
over what the converter produced; this step compares with the source's
inventory instead, so run it in any case. Check:

| Check | Using | Expect |
| --- | --- | --- |
| Account counts | `users`, `mappings.by_state` | Inventory's active and disabled users; `deleted` only for accounts you deleted on purpose; no `missing` |
| Scoped memberships | `memberships.active`, `.from_import`, `.organizations` | Inventory's memberships and organizations; `active` above `from_import` means memberships added in ProudAuth since |
| Privileged assignments | `privileged_assignments.items` (and `truncated`) | Each owner, realm or privileged-permission role is one the source granted to that person; review all of them, not only the count |
| Credential usability | `credentials.password`, `.totp`, `.without_sign_in_method` | Accounts without any sign-in method need a setup or recovery path before cutover |
| Verified identifiers | `verified_emails` | The inventory's verified count when verification was trusted, otherwise 0 |
| Subject continuity | `subject_continuity.resolvable_source_ids`, `GET /external-ids/{source}/{id}` for a sample | Every inventoried source ID resolves; spot-check a sample per relying party |
| Application subject mapping | Job `results` (`source_id` → `user_id`) | Every relying party that keys data by the source subject has a mapping for its users |

Also run synthetic sign-ins with a migrated password account and a migrated
TOTP account, and request a token for each relying party.

## 8. Cut over (MIG-013)

1. **Announce** the impact (MIG-010): every user signs in again; refresh tokens
   and remembered sessions of the source stop working; users with only
   passkeys or federated sign-in use the recovery or linking path you prepared;
   third-party applications ask for consent again.
2. **Freeze or reconcile source writes.** Put the source in read-only mode for
   account, credential and membership changes. If you cannot freeze it, list
   the changes made since each batch was exported (new users, changed
   identifiers or passwords, removed memberships, deletions) and apply them:
   new users through a final import batch, everything else through the
   administration API, since imports never update accounts.
3. **Final batch and reconciliation.** Import the users created since the last
   batch and run step 7 again with counts taken from the frozen source.
4. **Switch relying-party trust deliberately**, one relying party at a time,
   and verify each before the next:
   - issuer `<server.public_origin>/realms/<realm>`, discovery
     (`/.well-known/openid-configuration` under the issuer) and JWKS
     (`<issuer>/jwks`); remove the source's issuer and keys from the relying
     party's trust only when its rollback window ends;
   - audiences: each resource server accepts the `aud` of its ProudAuth
     resource, and each client requests it with `resource` or `audience`;
   - client IDs, new client secrets and redirect URIs registered in ProudAuth;
   - subjects: ProudAuth tokens carry its own `sub` (`usr_...`, or a `pws_...`
     value in ID tokens for pairwise clients), never the source's. Remap
     stored subjects before the switch using the import results or
     `GET /external-ids/{source}/{id}`; keep the import mappings (do not delete
     the external IDs), they are the lasting issuer/subject link between the
     two systems.
5. **Revoke the source's sessions and refresh tokens** once its relying parties
   have moved, so old grants cannot be used against it.
6. **Define and announce the rollback horizon.** Rolling back means pointing
   relying parties back at the source issuer and revoking ProudAuth sessions
   (`POST /user-bulk-operations` with `revoke_sessions`). It is safe only until
   ProudAuth holds writes the source does not have. From the first of these,
   rollback loses data unless you replay it to the source by hand: accounts
   registered in ProudAuth, password changes and resets, enrolled factors and
   passkeys, identifier changes, membership and role changes, consents, and
   account deletions (a deletion not replayed to the source brings the account
   back). Find them with `GET /audit-events?from=<cutover time>` (for example
   `type_prefix=user.`, `credential.`, `mfa.`, `role.`,
   `organization.membership.`, `consent.`). ProudAuth has no export
   of changes in the source's format, so decide in advance at which point, or
   after how much independent write activity, rollback is no longer an option,
   and decommission the source only after that point.

## 9. After cutover

- **Deletion continuity (MIG-017).** ProudAuth never recreates an account
  deleted in ProudAuth, by a later import or a restore
  ([details](exit-and-export.md#deletion-continuity-mig-017)). It cannot know
  about accounts deleted in the source after its export: delete them in
  ProudAuth (`DELETE /users/{user}`, found with
  `GET /external-ids/{source}/{id}`), and keep the source's deletion list with
  the migration record. Deleting an account also removes the source-supplied
  details of its imported audit records.
- **Artifacts.** Delete the converted export files, especially those holding
  password verifiers or TOTP seeds, once reconciliation and the rollback
  horizon are behind you. Job inputs are erased by ProudAuth when the jobs
  finish; job results (source and user IDs, plans) are kept.
- **Exit.** What can leave ProudAuth again, including the realm data export
  (`POST /data-exports`), and how export artifacts are protected (MIG-014,
  MIG-015), is in [exit-and-export.md](exit-and-export.md#realm-data-export).
