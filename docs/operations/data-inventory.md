# Data inventory

Requirement: PRV-001 (with PRV-002, PRV-004, PRV-005, DB-008). Derived from
`migrations/*.sql` and the code that reads and cleans each table. It covers
personal data, secrets and identifiers; purely technical tables are omitted.

**Protection column legend**

- **plain** — stored as plaintext in PostgreSQL. ProudAuth does not encrypt the
  database as a whole; use storage/disk encryption and access control.
- **AEAD** — AES-256-GCM under a key derived from the root keys
  ([keys.md](keys.md)), bound to the row by associated data.
- **SHA-256** — unkeyed digest of a high-entropy secret (not reversible in practice).
- **HMAC** — keyed verifier of a low-entropy code; useless without the root key.
- **Argon2id** — password verifier, optionally peppered.
- **digest (guessable)** — unkeyed SHA-256 of a low-entropy value such as an email
  address; anyone with database access can confirm a guessed value.

**Retention column** describes what the code does today. "Kept" means no automatic
deletion exists.

**Ownership and export.** The operator running the deployment is responsible
for all of it; within a realm, these roles decide over each section's data
and these paths export it ([exit-and-export.md](exit-and-export.md)). Fields
that are secrets (verifiers, seeds, keys, token digests) are never exported,
whichever section they are in
([What cannot be exported](exit-and-export.md#what-cannot-be-exported)).

| Section | Owned and changed by | Exported through |
| --- | --- | --- |
| [Accounts and credentials](#accounts-and-credentials) | The user for their profile, identifiers and factors; realm administrators (`realm.users.*`) for accounts; a directory or SCIM connector for the attributes it manages | Personal data export (the user), realm data export, `GET /users`; credential metadata only |
| [Sessions, tokens and authentication](#sessions-tokens-and-authentication) | The user (sign out, revoke consents), realm administrators (revocation) | Personal data export (sessions, consents); no export of token material |
| [Organizations, authorization, support](#organizations-authorization-support) | Organization owners and administrators within their organization; realm administrators | Realm data export, organization and role-assignment APIs, personal data export (memberships) |
| [Evidence, delivery and jobs](#evidence-delivery-and-jobs) | The system (append-only audit); auditors read it (`realm.audit.*`) | Audit export, audit archive, personal data export (last 500 security events) |
| [SAML](#saml) | Realm administrators (`realm.clients.*` for SAML applications, `realm.identity_providers.*` for SAML connections) | Configuration APIs; SAML session records are not exported |
| [Directory integration](#directory-integration) | Realm or organization administrators who own the connector; the directory itself for imported values | Connector, run and finding APIs; imported values through the user APIs |
| [Security events, cross-organization access and other evidence](#security-events-cross-organization-access-and-other-evidence) | Realm administrators; organization owners for relationships and partner grants | The feature's API (stream, relationship, transfer and revision listings); audit export |
| [Protocol, machine-identity and authorization extensions](#protocol-machine-identity-and-authorization-extensions) | Realm administrators; object owners for relationship tuples and shares | The feature's API; realm data export for service principals and policies |

## Accounts and credentials

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `users`: `display_name`, `given_name`, `family_name`, `locale`, `zoneinfo`, `profile` (JSON, e.g. `address`; at most `limits.metadata_bytes`, 16 KiB by default), `admin_metadata` (the same limit), `internal_metadata` | Profile. Who sees a `profile` attribute follows its `visibility` in the realm schema (`profile.attributes[].visibility`, USR-002, USR-007): `GET /me`, `PATCH /me` and the self-service data export show only `self` attributes; administrator views (`GET`, `PATCH /users/{user}` and user lists) show `self` and `admin` attributes and attributes the schema does not define, never `internal` ones. Without a schema every attribute is shown. Only `self` attributes can be `user_editable` | Identity, claims release, administration | Cleared when the account is deleted; the row (ID, state `deleted`, timestamps) is kept | plain |
| `users`: `last_login_at`, `created_via`, deletion timestamps, `webauthn_user_handle`, `deactivate_at`, `dormant_flagged_at` | Activity metadata; random WebAuthn handle; scheduled deactivation and the last time the account was flagged dormant (USR-015) | Lifecycle, passkeys | Kept with the row; `deactivate_at` is cleared when the scheduled suspension runs or is cancelled | plain |
| `user_identifiers`: `original_value`, `canonical_value`, `verified_at`, `verification_source` | Email addresses, phone numbers, usernames | Login, contact, uniqueness | Deleted with the account | plain |
| `credentials`: `verifier` | Password verifier (PHC string) | Password check | Deleted with the account; replaced on change; an imported legacy verifier (salted SHA-256, bcrypt or PBKDF2) is replaced by Argon2id at the next successful sign-in | Argon2id; imported legacy verifiers keep their source algorithm until then ([migration-adapters.md](migration-adapters.md#imported-password-verifiers)) |
| `credentials`: `secret_ciphertext` | TOTP seed, enrolled by the user or imported with `import_totp` (MIG-007) | TOTP check | Removal sets `state = revoked` and keeps the ciphertext; deleted with the account | AEAD |
| `password_history.verifier` | Previous verifiers (only if realm `password.history_count > 0`) | Reuse prevention | Deleted with the account | Argon2id |
| `recovery_codes.code_digest` | Recovery codes | Second factor / recovery | Deleted with the account; invalidated on regeneration | HMAC |
| `webauthn_credentials`: `credential_id`, `public_key`, `aaguid`, `transports`, `name`, counters, backup flags, `attestation_trusted`, `attestation_source` | Passkey public data; whether the attestation chained to trusted metadata and from which source (PASS-009, migration `0059`). The AAGUID names the authenticator model only when the realm requests attestation or the authenticator volunteers it | Passkey authentication, authenticator policy | Deleted with the account | plain (no secrets) |
| `webauthn_ceremonies.session_data` | Challenge and ceremony state | Passkey ceremony binding | Short-lived (5 min); cleaned by the worker when the passkey module is enabled | plain |
| `terms_acceptances` | Document, version, time, client | Evidence of acceptance (REG-006) | **Kept**, also after account deletion | plain |
| `consents` | Client, scopes, resources, terms version, basis (`mode` `user` or `preauthorized`, `preauthorization_id`), times | Consent records (APP-013) | Active consents **kept**, also after account deletion; revoked consents remain (`?history=true`) until `privacy.history_retention` (180 days) after revocation | plain |
| `external_identities`: `upstream_issuer`, `upstream_subject`, `email_hint`, `email_verified`, `upstream_tenant` | Federated identity binding | Federated login | Deleted with the account | plain |
| `external_identities.upstream_token_ciphertext` | Upstream tokens (only if retained) | Upstream API access | Deleted with the account | AEAD |
| `federation_requests`: `nonce`, `state_digest`, `verifier_ciphertext`, `redirect_uri` | Upstream request state | Federation callback validation | Single use, short expiry | SHA-256 / AEAD |
| `deletion_tombstones`: `reference_digest`, `reference_id` | Digest of each deleted identifier; deleted user ID | Prevent resurrection by import or restore | **Kept** | digest (guessable) |
| `import_mappings` | Source-system IDs ↔ local IDs: written by user imports and by administrators as external IDs (`PUT /users/{user}/external-ids/{source}`, USR-017) | Idempotent imports; lookup by another system's ID | Kept, also after account deletion; an external ID is removed with `DELETE /users/{user}/external-ids/{source}`, a deleted account's mapping when its ID is assigned to another account, and an account merge moves the merged-away account's mappings to the survivor (which can then hold two IDs in one source system) | plain |
| `notification_preferences`: template, enabled | Which optional notices the user muted (MSG-010) | Notification preferences | Deleted with the account | plain |
| `registration_approvals`: user, state, `reviewer_id`, `reason` | Review of a self-registration (REG-008) | Approval queue | **Kept**, also after account deletion | plain |
| `assisted_recoveries`: user, requester, approver, `reason`, `evidence_reference` | Free-text justification and evidence reference of a scheduled recovery (MFA-009) | Cooling-off and approval of assisted recovery | **Kept** (expired, cancelled and completed rows remain), also after account deletion | plain |
| `account_merges`: both user IDs, requester, executor, `reason`, `plan` (identifier, upstream-link and organization IDs, role names, credential types) | Merge request and the executed plan (USR-011) | Account merge workflow | **Kept** | plain |
| `subject_aliases`: merged-away user ID → surviving user ID | Alias of a merged account | Remapping application data after a merge | **Kept** | plain |

## Sessions, tokens and authentication

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `sessions`: `client_ip`, `user_agent`, `device_label` | Client network (/24 for IPv4, /48 for IPv6; the full address when `privacy.store_full_ip` is set), user agent (≤ 256 characters), a device label derived from the user agent | Session listing, security review | Ended rows (revoked, or past their absolute expiry) are deleted `privacy.session_retention` (30 days) after they ended, once no grant references them; an offline grant keeps its session row until the grant itself is removed. A session that ended by idle timeout counts from its absolute expiry | plain |
| `sessions`: `auth_time`, `mfa_time`, `amr`, `acr`, `factors` | Authentication evidence | Assurance decisions | As above | plain |
| `sessions.cookie_digest` | Browser session cookie | Session lookup | Cleared on revocation/expiry | SHA-256 |
| `auth_transactions`: `client_ip` (full), `user_agent`, `login_hint`, `user_id`, `pending_state` (identifier, registration email, encrypted invitation secret, the authentication flow decision with the signals it used, such as risk level and reasons from risk hooks and recent failed attempts) | In-flight login data | Transaction binding, per-network budgets | `client_ip` and `user_agent` cleared at the next cleanup run (every 5 minutes) once the transaction is no longer pending, unless `privacy.store_full_ip` is set (PRV-002); rows deleted 24 h after completion or expiry | plain; invitation secret AEAD |
| `challenges`: `identifier_canonical`, `verifier` | Email address or phone number; one-time code or magic-link secret | Verification, login OTP (email or SMS), magic links, authentication flow challenge codes, reset, setup | Deleted 1 h after expiry | plain / HMAC |
| `authorization_grants`: subject, client, organization, scopes, `amr`, `acr`, `auth_time` | Authorization history | Token issuance and refresh | Deleted `privacy.session_retention` after the grant ended (revoked, or past its expiry), with its refresh families and tokens, codes and opaque tokens (PRV-004) | plain |
| `client_sessions` | Which clients took part in a session | Back-channel and front-channel logout | Deleted `privacy.session_retention` after the session ended | plain |
| `authorization_codes.code_digest` | Authorization codes | Code redemption | Deleted after expiry, or with their grant | SHA-256 |
| `refresh_families`, `refresh_tokens.token_digest` | Refresh token lineage | Rotation, reuse detection | Deleted with their grant | SHA-256 |
| `opaque_access_tokens`: `token_digest`, subject, `actor`, organization | Opaque/support tokens | Introspection | Deleted after expiry, or with their grant | SHA-256 |
| `token_revocations` | Revoked references (session, user, family, client, key, JTI) | Revocation checks, restore reconciliation | JTI rows deleted after the token's expiry; others kept | plain |
| `device_codes`: digests, `user_id` | Device flow | Device authorization | Deleted after expiry | SHA-256 |
| `pushed_authorization_requests.parameters` | Authorization request incl. `login_hint`, `state`, `nonce` | PAR | 60 s; deleted after expiry | plain |
| `dpop_proof_jtis.jkt` | Public-key thumbprints | DPoP replay protection | Deleted after expiry | plain |
| `remembered_devices` | Device token digest, label (truncated user agent), last use, expiry | Remembered devices: skipping the MFA prompt where policy allows (AUT-013) | Revoked by the user, on account-wide session revocation, or at expiry (`login.remember_device_days`, at most 90 days); revoked and expired rows are kept until the account is deleted | SHA-256 |
| `pairwise_subjects`: sector, user ID, subject | Per-sector pairwise identifiers | Stable pairwise `sub` values across root-key rotation (OIDC-010) | Deleted with the account (explicitly: the `users` row is kept, so nothing cascades) | plain |
| `rate_limit_counters.bucket` | Truncated digest of keys such as `login-id:<realm>:<email>` and `login-ip:<realm>:<network>` (an IPv4 /32 or /24, an IPv6 /64 or /48) | Abuse budgets | Deleted after the window | digest (guessable) |
| `known_sign_ins`: realm, `kind`, `digest`, `last_seen_at` | Keyed digests of the networks (IPv4 /32, IPv6 /64), remembered-device secrets, and canonical identifiers together with their wider network (IPv4 /24, IPv6 /48), that completed a sign-in, with the time of the latest one; not linked to an account | Known-device quota: who still signs in while an aggregate sign-in budget is exhausted (owner decision 9 of 0.2.0-alpha.6, SEC-006) | Deleted by the worker once older than `rate_limits.known_quota_days` (default 30, at most 365; all of them when it is `0`); not removed by account deletion, so an erased account's identifier digest expires with the rest | HMAC (lookup key) |
| `second_factor_failures`: user, `consecutive`, `last_failure_at`, `notified_at`, `disabled_at` | How many TOTP, HOTP, recovery-code and emailed or texted sign-in code proofs of the account failed in a row, when the last one failed, when the owner was warned and when code factors were turned off (owner decision 10 of 0.2.0-alpha.6, SEC-006) | Code-factor backoff, owner notice and ceiling; shown to administrators in `GET /users/{user}` | One row per account that made a TOTP, HOTP or recovery-code proof or failed a sign-in code; the count is set back to zero (the row and `last_failure_at` stay) after a successful second factor or passkey, a completed sign-in, a password reset or an assisted recovery; deleted with the account | plain |
| `signing_keys`: `private_ciphertext`, `public_jwk` | Realm token-signing private keys (and their public halves) | Signing tokens; JWKS publication | Kept with their state (`retired`, `compromised`) for evidence; the public key is published until `publish_until` ([keys.md](keys.md)) | AEAD under the signing-wrap key, bound to the key ID (`signing-key:<kid>`) |

## Organizations, authorization, support

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `organizations`: `display_name`, `slug`, `contact`, `metadata`, `external_id` | Organization data; `contact` may hold personal contact details | Tenancy | Organization deletion ([below](#organization-deletion)) clears display name, contact, metadata and external ID, deletes role assignments and group memberships and marks memberships removed; the row is kept as `deleted` | plain |
| `memberships`: user, state, source, `external_id`, `metadata` | Membership history. `metadata` is the organization's own data about the member (USR-009, at most `limits.metadata_bytes`), set with `PATCH /organizations/{org}/members/{membership}` and shown only to callers holding `org.members.write` there: never to the member (not in `GET /me`, the member's organization list or the personal data export) and never in tokens; included in the realm data export | Tenancy | Set to `removed` on removal or account deletion; kept. `metadata` is cleared when the membership is removed or expires, when its organization is deleted, and on account deletion | plain |
| `invitations`: `target_email_canonical`, `target_email_display`, `inviter_id`, `message`, `accepted_by_user_id` | Invitee address, inviter, free-text message | Invitations | Pending ones kept; accepted, declined, expired and revoked ones deleted `privacy.history_retention` (180 days) after their last change | plain; secret SHA-256 |
| `join_requests`: `reason`, `decision_reason`, reviewers | Free text | Join approval | Kept | plain |
| `consent_preauthorizations`: `reason`, `granted_by_id`, organization, scopes | Administrator who consented for a client on behalf of the realm or an organization, and why (APP-013) | Consent pre-authorization | **Kept** (revoked rows remain) | plain |
| `role_assignments`: subject, `granted_by_id`, `approved_by_id`, `reason` | Who granted what | Authorization, evidence | Deleted on unassignment | plain |
| `role_assignment_requests`: subject, `requested_by_id`, `decided_by_id`, `reason` | Pending and decided two-party role requests | Separation of duties (AZ-018) | Kept (pending requests expire after 7 days) | plain |
| `impersonation_requests`: actor, target, `reason`, `ticket_reference` | Support justification (free text) | Support access evidence | Kept | plain |
| `impersonation_grants`, `impersonation_handoffs` | Actor/target, times, revocation reason; handoff code digest | Support access | Kept | plain / SHA-256 |
| `automation_credentials`: owner, `name`, `display_prefix`, `last_used_at` | API keys and personal tokens | Machine access | Kept (a user's are revoked when the user is deleted, and by a password reset, password-compromise marking or assisted recovery) | secret SHA-256 |
| `client_credentials`: `display_prefix`, `last_used_at` | Client secrets / public keys | Client authentication | Kept | secret SHA-256 |
| `clients`: `contacts`, `owner_user_id` | Technical contact emails | Ownership | Kept | plain |
| `hooks`: `url`, `secret_ciphertext`, `last_error` | Hook endpoint and signing secret; last failure text | Pre-action hooks | Kept until the hook is deleted | plain; secret AEAD |
| Identity-provider connections: client secret | Upstream OAuth client secret | Federation | Kept until the connection is deleted | AEAD, bound to the connection's ID (`idp-client-secret:<id>`, TEN-022) |
| `provisioning_connectors`: `token_digest`, `name`, `config`, `last_error`, `stats` | SCIM connector token (digest only), connector settings, the last error detail (at most 200 characters; may name a value the directory sent) and request counters (PROV-003, PROV-018). Directory and outbound connectors ([below](#directory-integration)) use the same table | SCIM provisioning ([scim-provisioning.md](../integrations/scim-provisioning.md)) | Kept; disabled when the organization's deletion starts | token SHA-256 |
| `connector_external_ids`: `external_id`, `local_id` | The directory's identifier for each user and group a connector provisioned (one namespace per connector); for directory links also the entry's DN and the imported values ([below](#directory-integration)) | Connector-scoped mapping (PROV-004) | Deleted when the connector deprovisions the user or group, or with the connector; for a deleted account a directory link keeps only the entry's ID ([below](#directory-integration)) | plain |
| Webhook subscriptions: signing secret (and the previous one during rotation) | `whsec_` secret of realm and organization subscriptions | Signing deliveries | Kept until the subscription is deleted | AEAD, bound to the subscription's ID (`webhook:<id>`) |
| `configuration_revisions`: `changed_by_id`, `reason` | Administrator attribution | Configuration history | Kept | plain |
| `organization_templates`: `created_by_id`, `description`, `document` | Administrator attribution; template content (organization policy, role and group names) | Organization onboarding templates (TEN-017) | **Kept**: versions are never changed or deleted | plain |
| `workflows` (migration `0070`): `name`, `description`, `owner_user_id`, `published_by_id` | Administrator free text (the name also appears in `workflow_notice` messages) and attribution | Lifecycle workflows (EXT-015, [workflows.md](../integrations/workflows.md)) | Kept until the workflow is deleted (possible only once it has no runs) | plain |
| `workflow_revisions`: `definition`, `author_id`, `approved_by_id`, `published_by_id`, `note` | Definitions (approver user IDs, role, group, organization and subscription IDs), attribution, review notes (free text) | Workflow versions and their review | Kept with the workflow; deleted with it | plain, SHA-256 of the definition |
| `plugins` (migration `0071`): `installed_by_id`; `plugin_versions`: `manifest_raw`, `payload_raw`, `signature`, `signing_key_id`, `package_digest`, `manifest`, `uploaded_by_id`, `reviewed_by_id`, `review_note` | The exact signed package bytes (the payload can name approver user IDs and hook and webhook URLs, query strings included), attribution, review notes (free text, at most 500 characters); no secrets (part secrets stay in `hooks` and the webhook subscriptions) | Plugins (EXT-014, [plugins.md](../integrations/plugins.md)) | **Kept**: no API or retention job deletes plugins or their versions | plain; Ed25519 signature and SHA-256 digests |
| `hooks.contract_version`, `hooks.plugin_id`, `webhook_subscriptions.event_version`, `webhook_subscriptions.plugin_id` (migrations `0071`, `0072`) | Contract versions and the managing plugin | Extension contracts (EXT-018) | With the hook or subscription | plain |
| `group_memberships`: `membership_id`, `group_id`, `source`, `valid_from`, `valid_until` | Which member belongs to which group, and why (manual, dynamic, SCIM, directory) | Group-derived roles | Deleted with the group or membership; organization deletion deletes them | plain |

## Evidence, delivery and jobs

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `audit_events`: actor/subject/target IDs, `ip_context`, `metadata`, `request_id` | Activity evidence. Actor, subject and target IDs are at most 128 printable bytes: identifiers ProudAuth issues are stored as they are, while a longer value or one with control characters, which only a request can supply (an unknown `client_id` or Basic user name in `client.authentication.failed`), keeps its printable characters up to 128 bytes followed by `~` and the first 16 hexadecimal digits of the SHA-256 of the whole value, so the same value always gives the same ID and searches by the original value find it (`audit.BoundID`; AUD-001, SEC-006). `request_id` is at most 64 printable ASCII characters. `ip_context` is /24 (IPv4) or /48 (IPv6) unless `privacy.store_full_ip`. Metadata is redacted of secrets but can contain free text such as support ticket references, assisted-recovery reasons and legal-hold reasons, masked email addresses, and, in the audit event `invitation.created`, `recipient_digest`: an HMAC-SHA256 of the canonical invited address under the deployment's lookup key (derived from the active root key, version in `recipient_digest_key_version`; INV-016), so reading the event alone does not confirm a guessed address; recomputing it needs that root-key version. With realm policy `data_access.log_identity_reads`, administrative reads and searches of accounts are recorded too (see below), and with `data_access.sample_allowed_decisions_percent` a share of ordinary allowed authorization decisions (subject, action, resource type and ID; AZ-020). Services holding `realm.activity.report` add application activity (`source: application`, category `application`) with up to 4 KiB of redacted metadata of their choosing (AUD-013) | Security evidence | Sealed events past every retention that applies to them (category or deployment, realm, organization) deleted, except category `emergency` and events under an active legal hold ([below](#audit-retention-and-legal-holds)); never changed (corrections are new events) | plain, hash-linked |
| Audit archive files (`privacy.audit_archive_dir`, outside the database) | A copy of every sealed batch with all its events as recorded, including the personal data listed for `audit_events`; after a database restore also `fork-*` directories | Independent tamper evidence (AUD-008) | **Never deleted by ProudAuth**, including after database retention or account deletion; the operator's storage policy applies | plain, hash-linked, signed batch headers |
| `imported_audit_events` (migration `0038`): `source_event_id`, `occurred_at`, `event_type`, `organization_id`, `actor` (source `type`, `id`, `display`), `subject_id`, `source_subject_id`, `outcome`, `metadata`, `imported_by_*` | Historical audit records imported from a source system with `POST /audit-imports` (MIG-016): the source's own identifiers and display names, the mapped local user, and up to 4 KiB of metadata as the source supplied it after audit redaction (members with secret-looking names such as `password`, `token`, `api_key` or `access_key` become `[REDACTED]`; other personal data such as IP addresses stays) | Keeping the source's history available after migration, apart from local evidence | Deleted by `retention.cleanup` when older than `privacy.audit_retention` (or the `imported` category of `privacy.audit_retention_by_category`), **counted from `imported_at`**, or later when the realm's or organization's audit retention is longer, unless an active legal hold matches; account deletion clears `metadata`, `source_subject_id` and the actor's `display` of records whose `subject_id` is the account (not of records where the person is only the actor); records imported for an account already deleted are stored without them, unless a legal hold covers them | plain, per-record `content_hash`; not hash-linked |
| `audit_legal_holds`: `organization_id`, `subject_id`, `reason`, `created_by_id`, `released_by_id` | Which organization's or person's evidence is held, why, and by whom | Keeping evidence from retention (AUD-009) | **Kept**, also after release | plain |
| `outbox_events.payload` | Event data (user IDs, organization IDs, states) | Webhook fan-out | Deleted 7 days after dispatch | plain |
| `webhook_deliveries.payload` | Event envelope per subscription, with `correlation_id` (the causing request's ID) when there is one (`minimal` form keeps only `*_id` members and the non-personal `state`, `reason`, `mode`, `authorization_revision`, `signal`, `event_type`, `actor_type`, `subject_type`, `client_ref`, `new_kid`, `previous_kid`, `previous_key_compromised`; `standard` keeps all data fields) | Delivery and replay | Delivered and dead-lettered deliveries deleted `privacy.history_retention` (180 days) after they were created; deliveries of an organization's subscriptions deleted with them when the organization's deletion finishes | plain |
| `logout_deliveries` | User and session IDs | Back-channel logout | Delivered and failed deliveries deleted `privacy.history_retention` after they were created | plain |
| `notification_jobs.payload_ciphertext` | Recipient email address or phone number and template data, including one-time codes, magic links, setup and invitation secrets | Email and SMS delivery | Purged after `delivery.payload_retention` (24 h) once finished/expired | AEAD |
| `notification_jobs.recipient_hint`, `last_error` | Masked address (e.g. `a***@example.com`); provider error text | Diagnostics | Finished jobs (`accepted`, `failed`, `expired`, `suppressed`) deleted `privacy.history_retention` (180 days) after their last change | plain |
| `notification_settings`: sender address and name; `smtp_config`, `smtp_secret_ciphertext` | Sender settings; an organization's own SMTP server (host, port, TLS mode, username) and its password (TEN-022) | Delivery | Kept; the SMTP server and password are cleared by `DELETE /organizations/{org}/notification-settings/smtp`, and an organization's whole row is deleted when its deletion finishes | plain; password AEAD, bound to the realm and organization |
| `notification_suppressions`: `recipient_digest`, `reason` | Addresses that hard-bounced or complained, reported through `POST /delivery-events` (MSG-007) | Stop optional notices to those addresses | **Kept**, also after account deletion | digest (guessable) |
| `dev_mailbox`: `recipient`, `subject`, `body_text` | **Plaintext email and SMS messages including codes and magic links** | Development sinks only (never in production mode) | Deleted after 24 h | plain |
| `jobs.input` | Non-secret job parameters (for `user.import`: `format`, source system, user count, the `trust_email_verification`, `allow_owner_roles` and `import_totp` flags, and the free-text `verification_reason`) | Job status | Kept | plain |
| `jobs.input_ciphertext` | Protected job input. For `user.import`: the submitted users (emails, usernames, display, given and family names, locales, states, required actions, administrator metadata such as source attributes kept by the migration adapters, password hashes, TOTP seeds, memberships); never returned by the API | Job execution | Erased when the job reaches a terminal state (and by the worker's purge pass) | AEAD |
| `jobs.result`, `jobs.progress`, `jobs.checkpoint` | Non-secret summaries (counts, checksums; import results and checkpoints list source IDs, user IDs, error texts and, for dry runs, the plan with organization IDs and role names) | Job status, resumption | Kept | plain |
| `jobs.result_ciphertext` | Export payloads (user export, audit export, configuration export, realm data export: every account's profile, identifiers and metadata, [exit-and-export.md](exit-and-export.md#realm-data-export)) | Downloads | Purged after `privacy.export_retention` (24 h), and at once for every job of an organization whose deletion starts | AEAD |
| `idempotency_records.response_body` | Replayable responses (can include created user or organization views; responses with a member named like a secret, including `token`, `access_token`, `refresh_token` and `id_token`, are never stored: a retry gets `409` with `original_status`, API-006) | Idempotent retries | Deleted after 24 h | plain |
| `workflow_runs` (migration `0070`): `subject_id`, `accountable_id`, `started_by_id`, `input`, `context`, `last_error`, `trigger_key`, `lease_owner` | Who a run is about and who is accountable; the triggering event's identifiers and states; IDs of the assignments and memberships it created and of the approval's decider; an error text (at most 300 characters); for manual runs a digest of the caller's `Idempotency-Key` | Lifecycle workflow runs (EXT-015, EXT-016) | Finished runs deleted by `retention.cleanup` `privacy.history_retention` (180 days) after they ended; **account deletion does not touch them** | plain |
| `workflow_step_attempts`: `input`, `result`, `error`, `compensation_result` | Resolved step input (subject, organization, step parameters including approver IDs), results and error texts | Step idempotency and compensation evidence (EXT-016) | Deleted with their run | plain |
| `workflow_approvals`: `subject_id`, `approver_ids`, `decided_by_id`, `comment` | Approvers and the decision, with the approver's free-text comment (at most 500 characters) | Workflow approval steps | Deleted with their run | plain |
| `job_download_tokens`: `token_digest`, `requested_by_id` | One-time download credential of a job result and who may redeem it | Export downloads (5 minutes, single use) | Deleted with the job | SHA-256 |

## SAML

Migration `0060` ([saml.md](../integrations/saml.md)). Persistent NameIDs
are rows of `pairwise_subjects` (sector `saml:<application id>`), deleted
with the account like other pairwise subjects.

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `saml_signing_keys`: `private_ciphertext`, `certificate` | The realm's SAML signing keys and their self-signed certificates | Signing responses, assertions, logout messages and `AuthnRequest`s | Kept; retired keys stay with state `retired` | AEAD under the signing-wrap key, bound to the key ID (`saml-signing-key:<id>`) |
| `saml_service_providers`: `entity_id`, `config` | SAML application settings: ACS and logout URLs, SP certificates, attribute mappings, organization | Identity provider (APP-018) | Until the application is deleted | plain |
| `saml_idp_requests`: `acs_url`, `relay_state`, `transaction_id`, `state_digest`, `binding_digest`, `verifier_ciphertext`, `options` | One accepted `AuthnRequest` (or IdP-initiated sign-in): where to deliver, the SP's opaque `RelayState`, the browser binding and the internal PKCE verifier | Correlation and single use | Deleted 1 hour after expiry (`tokens.transaction_ttl`), and with the application | digests SHA-256; verifier AEAD; `relay_state` plain |
| `saml_idp_sessions`: `session_id`, `user_id`, `session_index`, `name_id_digest` | Which sessions an application received assertions for; a digest of the NameID, not the NameID | Single logout | Deleted 1 hour after the session participation ended or expired, and with the application | plain; NameID SHA-256 |
| `saml_connections.config` | SAML connection settings: IdP entity ID, SSO URL, trusted certificates, attribute names | Broker (FED-014) | Deleted with the identity provider row | plain |
| `saml_broker_requests`: `transaction_id`, `user_id`, `session_id`, `relay_digest` | One outstanding `AuthnRequest` to an IdP (sign-in or linking) | Correlation and single use | Deleted 1 hour after expiry (10 minutes) | `RelayState` SHA-256 |
| `saml_assertion_ids` | Assertion IDs received per connection | Replay prevention | Deleted at the assertion's expiry | plain |

Assertions themselves are not stored. The identity a SAML connection
asserts is stored like any federated identity (`external_identities`).

## Directory integration

Migration `0065` ([directory.md](../integrations/directory.md),
[outbound-provisioning.md](../integrations/outbound-provisioning.md)).

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `provisioning_connectors` (kinds `ldap`, `scim_outbound`): `secret_ciphertext`, `secret_set_at` | Service-account bind password or downstream bearer token | Directory binds, downstream calls | Replaced on rotation; deleted with the connector | AEAD, bound to the connector's ID (`directory-connector-credential:<id>`) |
| `provisioning_connectors`: `config`, `cursor`, `evidence`, `last_error` | Endpoints, bind DN, base DNs and filters, mappings, downstream URL; change cursor (USN or timestamp and the domain controller's name); endpoint health (host names, failure categories) and the latest 20 operator actions (actor IDs); client-safe error summaries | Connector operation and evidence (PROV-018) | Kept until the connector is deleted (only a disabled one can be) | plain |
| `connector_external_ids` (`link_kind = 'directory'`): `external_id`, `source_dn`, `snapshot`, `snapshot_digest`, `source_state`, `missing_since` | The entry's immutable ID and DN (a DN usually contains the person's name), the values last imported (names, email, username, locale, profile values), and whether the entry is active, disabled or missing | Linking, the attribute-authority declaration, group membership matching | Deleted with the connector. When the account is erased, the DN and snapshot are removed and the link keeps only the entry's ID with source state `deleted`, so the next run reports the entry instead of recreating the account | plain |
| `directory_sync_runs`: `requested_by_*`, `reason`, `cursor_before`, `cursor_after`, `endpoint`, `counts`, `error` | Who requested a run and why (free text, for mass-deprovision overrides), cursors, the endpoint host, counts | Run history and evidence | Finished runs are deleted 90 days after they finish (or after `privacy.history_retention` when shorter); each connector keeps its latest run | plain |
| `directory_sync_findings`: `external_id`, `source_dn`, `local_id`, `attributes`, `detail` | Per entry: what a run did or would do; DNs, external IDs, local account IDs and attribute **names** (never values) | Dry-run plans, conflict reports | Deleted with their run's age, also for a connector's latest run (at most 5000 per run); erasing an account removes the DNs of findings about it | plain |
| `connector_external_ids` (`link_kind = 'outbound'`): `external_id`, `local_id`, `snapshot_digest` | The downstream resource ID of each pushed account or group and a digest of the last pushed document | Idempotent updates; skipping unchanged resources | Deleted when the downstream resource is deleted, or with the connector | plain; document SHA-256 |
| `outbound_deliveries`: `local_id`, `operation`, `last_status_code`, `last_error_category` | Which account or group is due for which downstream operation; no payload is stored | Outbound provisioning | Delivered, dead-lettered and replayed deliveries are deleted 90 days after their last update (or after `privacy.history_retention` when shorter); open ones are kept | plain |

## Security events, cross-organization access and other evidence

Migrations `0057`–`0059` and `0080`–`0083`
([shared-signals.md](../integrations/shared-signals.md),
[federation-transfer.md](federation-transfer.md),
[partner-access.md](../integrations/partner-access.md),
[container-registry.md](../integrations/container-registry.md),
[authentication-flows.md](../protocols/authentication-flows.md)).

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `ssf_streams`: `audience`, `endpoint_url`, `description`, `status_reason` | Receiver client, push endpoint, free-text description and status reason | Shared-signals streams (AUD-016) | Until the receiver or an administrator deletes the stream | plain |
| `ssf_streams.authorization_ciphertext` | The `Authorization` value sent with each push | Authenticating pushes to the receiver | Replaced or cleared on update; deleted with the stream | AEAD, bound to the stream's ID (`ssf:<id>`) |
| `ssf_stream_subjects`: `user_id` | Users a receiver added to a `listed` stream | Narrowing a stream | Deleted with the stream, and when the account is erased | plain |
| `ssf_events`: `user_id`, `subject`, `session_id`, `payload`, `set_jwt`, delivery state | Which user an event is about, the subject as the receiver knows it (public or pairwise `sub`), session ID, event members (credential type, initiating entity, timestamps) and the signed token | Delivery and re-delivery of the same token | Events not acknowledged or failed are marked expired 7 days after they occurred; finished events are deleted 14 days after they occurred (`retention.cleanup` step `ssf_events`), and with the stream. Erasing the account expires the events queued about it and drops their subject and token | plain |
| `ssf_transmitters`: `name`, `issuer`, `jwks_uri`, `jwks`, `provider_id`, `actions`, `push_secret_digest` | Trusted transmitters, their public keys and action policy | Receiving security events (ADV-007) | Until deleted | push secret SHA-256 |
| `ssf_received_events`: `jti`, `event_type`, `subject_format`, `user_id`, `action`, `outcome` | Minimal record of each accepted event; never the token or the subject identifiers | Replay defense, evidence | Deleted after 30 days (`retention.cleanup` step `ssf_received_events`) and with the transmitter | plain |
| `federation_transfers`: `reason`, `created_by_id`, `approved_by_id`, `applied_by_id`, `summary` | Transfer plan, free-text reason, administrators | Federation transfer (FED-016) | **Kept** | plain |
| `federation_transfer_entries`: `source_subject`, `source_issuer`, `target_subject`, `target_tenant`, `user_id`, `outcome` | Upstream subjects at both connections and the matched account | Reviewing and applying the map | Deleted 180 days after the transfer was applied or cancelled (`retention.cleanup` step `federation_transfer_entries`; the transfer and its summary are kept); erasing an account replaces its entries' subjects with `[erased]` | plain |
| `organization_relationships`: `note`, `created_by_*`, `decided_by_id` | Relationship between two organizations, free-text note, who proposed and decided | TEN-021 | **Kept** (ended and declined rows remain) | plain |
| `webauthn_trusted_authenticators`: `aaguid`, `description`, `root_certificates`, `created_by_id` | Trusted authenticator models and their root certificates | Trusted attestation (PASS-009) | Until removed | plain (public certificates) |
| `auth_flow_revisions`: `definition`, `note`, `created_by_*`, `published_by_*` | Flow rules (client IDs, organization IDs, network ranges), free-text note, administrators | Flow history (AUT-019) | **Kept** (discarded drafts remain) | plain |
| `registry_services`: `service`, `rules` | Registry service name, repository patterns and permission names | Registry token bridge (ADV-010) | Until deleted | plain |

Registry tokens and reconstructed entitlement histories (ADV-011) are not
stored; issuances, denials and reconstructions are audit events.

## Protocol, machine-identity and authorization extensions

Migrations `0047`–`0056`
([workload-federation.md](../integrations/workload-federation.md),
[dynamic-client-registration.md](../integrations/dynamic-client-registration.md),
[relationship-authorization.md](../integrations/relationship-authorization.md),
[elevation-and-access-reviews.md](../integrations/elevation-and-access-reviews.md),
[mutual-tls.md](../protocols/mutual-tls.md)).

| Table / columns | Data | Purpose | Retention | Protection |
| --- | --- | --- | --- | --- |
| `credentials` (type `hotp`): `secret_ciphertext`, `counter` | HOTP seed and counter (MFA-013) | HOTP check | As TOTP: removal revokes the row; deleted with the account | seed AEAD, bound to the credential ID |
| `user_certificate_bindings`: `issuer_dn`, `subject_dn`, `last_used_at`, `created_by_id` | Certificate names bound to an account (PROV-016) | X.509 sign-in | Removal marks the row revoked; deleted with the account | plain |
| `certificate_trust_anchors`: `certificate_pem`, `subject`, `crl_der` | CA certificates and their CRLs (CRLs list revoked serial numbers) | Mutual TLS and X.509 sign-in | Removal marks the row removed; **kept** | plain (public data) |
| `opaque_access_tokens.cnf` | Thumbprint of the DPoP key or client certificate an opaque token is bound to | Sender-constrained tokens (TOK-019) | With the token | plain |
| `clients.protocol_options` | Front-channel logout URI, response signing and encryption settings, mutual-TLS settings, and for dynamically registered clients `client_uri`, `logo_uri`, `policy_uri`, `tos_uri` | Per-client protocol settings (migration `0050`) | With the client | plain |
| `workload_trusts`: `issuer`, `subject`, `audience`, `jwks`, `claim_constraints`, `created_by_id`, `last_used_at` | External workload identities trusted for a client (repository names, service-account names, SPIFFE IDs) | Workload federation (MCH-011) | Until deleted | plain (public keys) |
| `workload_assertion_jtis` | `jti` values of used workload assertions, per trust | Replay protection | Deleted by the worker's retention task once past the assertion's expiry plus the clock skew, and when the trust is deleted | plain |
| `client_registration_tokens`: `token_digest`, `description`, `allowed_scopes`, `created_by_id` | Initial and registration access tokens (digests only) | Dynamic client registration (APP-016) | **Kept** (revoked and used-up tokens remain) | SHA-256 |
| `client_registrations`: `software_id`, `software_version`, `registered_from`, `decided_by_id` | How a client registered itself, **the registrant's IP address**, and who approved it | Approval and review | **Kept** | plain |
| `resource_types`: `relations`, `permissions`, `created_by_id` | Relationship schemas of applications | Relationship-based authorization (AZ-022) | Until deleted | plain |
| `resource_relationships`: `object_id`, `subject_id`, `relation`, `expires_at`, `created_by_id` | Who holds which relation to which application object (object IDs are the application's own) | Object-level decisions (AZ-021) | Until removed through the API; expired tuples stay stored but never match (the tuple of an expired share is removed with it); tuples with an account as subject, and the tuples of accepted shares the account made, are deleted with the account; **not removed by organization deletion** (inert, because subjects must be active members) | plain |
| `resource_shares`: `owner_user_id`, `recipient_user_id`, `object_id`, `message` | Sharing offers between members, with a free-text message (at most 500 characters) | User-managed sharing (AZ-027) | **Kept** in every state (past `expires_at` they are stored as `expired`); account deletion revokes the pending and accepted shares to or from the account and clears the message of every share naming it | plain |
| `elevation_eligibilities`, `elevations`: `user_id`, `reason`, `decided_by_id`, times | Who may elevate to which role, each request with its free-text reason, approver and times | Just-in-time elevation (AZ-024) | **Kept**; account deletion revokes the account's eligibilities, cancels its pending requests and ends an active elevation | plain |
| `access_reviews`, `access_review_items`: `reviewer_ids`, subjects, `decided_by_id`, `comment`, `outcome` | Review campaigns, reviewers' decisions with free-text comments | Access review evidence (AZ-025) | **Kept** | plain |
| `policies.owner_user_id`, `hooks.owner_user_id` | Accountable owner of an authorization policy or hook (DOM-009, migration `0047`) | Ownership report; moved by the ownership transfers | With the object | plain |
| `notification_jobs.user_id` | The account a message is about (migration `0048`): recorded for every message, from the sender, a user reference, or a recipient address that is one of the account's identifiers | Purging messages at account deletion (PRV-005) | With the job | plain |

None of these tables is in the realm data export, except the `is_agent` flag
of service principals, the owners of policies and hooks, the `hotp` flag of
the credential summary and the protocol options of clients (in the
configuration document).

## Tables without personal data

These tables hold configuration, protocol state or bookkeeping and no personal
data: `realms`, `realm_custom_domains`, `api_resources`, `scopes`, `roles`,
`role_permissions`, `policies`, `policy_versions`, `project_grants`,
`client_origins`, `client_redirect_uris`, `client_resource_grants`,
`resource_server_clients`, `organization_domains`, `organization_aliases`,
`notification_templates`, `client_assertion_jtis` (client assertion IDs until
they expire), `credential_expiry_alerts` (which machine credential was
reported), `hook_invocations` (outcome, latency and error category per hook
call; deleted after 7 days), `event_stream_horizon`, `audit_archive_state`
and `system_state`. `TestDataInventoryCoversTables` fails when a migration
adds a table that is neither in a section above nor in this list.

## Data sent outside the deployment

Only to destinations the operator or an administrator configures:

| Destination | Data |
| --- | --- |
| SMTP relay | Recipient address, rendered message (codes, magic links, invitation and setup links) |
| An organization's own SMTP server (TEN-022) | The same, for every message of that organization (invitations, join-request notices and other mail sent in the organization's context) |
| SMS gateway (`delivery.sms.webhook_url`) | Phone number, message text including the code |
| Webhook receivers | Event envelope; `minimal` payloads keep only identifiers, states and the non-personal members listed in [api/events](../../api/events/README.md#payload-forms). Organization templates can create organization-scoped subscriptions to public HTTPS destinations, and [plugins](../integrations/plugins.md) realm-wide ones |
| Lifecycle workflow endpoints (`call_webhook` steps, sent to a realm-wide subscription's destination) | The step call: realm, organization, workflow, revision, run, step and subject (user) IDs, the trigger's event type and ID ([workflows.md](../integrations/workflows.md#step-call-contract)) |
| Back-channel logout URIs | Logout token (`sub` as seen by that client, `sid`) |
| Shared-signals receivers (push streams; poll streams fetch the same) | Security Event Tokens about users who authorized the receiver (or every user, for streams an administrator scoped to `all`): `sub` as that client sees it, session ID for session revocations, event type and members (credential type, initiating entity, time), and the stream's `Authorization` value |
| Shared-signals transmitters (`jwks_uri`) | A `GET` for the transmitter's key set; no user data |
| Upstream identity providers | Authorization request (`state`, `nonce`, PKCE challenge; for OIDC connections also `login_hint` when the transaction has one); the upstream returns the user's claims |
| SAML identity providers (SAML connections), through the browser | A signed `AuthnRequest` (request ID, SP entity ID, ACS URL, requested NameID format and authentication context) and a random `RelayState`; the IdP returns an assertion with the user's NameID and attributes |
| SAML service providers (SAML applications), through the browser | Signed assertions: the NameID (per-application persistent value, verified email, account ID or transient value), the mapped attributes (for example verified email, names, username, verified phone number, organization ID), authentication time and context, session index; signed logout responses |
| LDAP and Active Directory servers (directory connectors) | The service account's bind password; search filters containing sign-in identifiers (also identifiers unknown locally, with first sign-in provisioning); **the user's password in a bind** for directory-sourced accounts; for write-back, the attribute values a user or administrator edited |
| Downstream SCIM services (outbound connectors) | The bearer token; for each eligible account its ID (`externalId`), the mapped attributes (by default username, display name, given and family name, verified email) and `active`; group names and members' downstream IDs |
| Pre-action hook endpoints | Signed request with the data of the hook's kind: the registering email address, its domain, username and flags (registration eligibility); user ID and submitted profile (profile validation); subject, client, audience, scopes and organization of the token (claims enrichment); subject attributes, action, resource and caller-supplied context (authorization decisions); user, client and organization IDs, sign-in method, client network (/24 or /48), whether the device is remembered and recent failed attempts (authentication risk) |
| Challenge providers (`security.challenge_providers`) | The provider's response token from the login UI and the configured secret; the client's full IP address only with `send_remote_ip`. The provider's own widget in the login UI sees whatever the provider collects in the browser |
| External policy engines (`security.policy_engines`, AZ-026) | For each decision in a realm that names one: realm name, organization, subject type and ID, actor, client, audience, token kind, `acr`, `auth_time`, support mode, action, resource type and ID, the caller-supplied `context`, the local result and the configured bearer token ([policy-engines.md](../integrations/policy-engines.md)) |
| Workload key-set URLs (`jwks_uri` of workload trusts) | A `GET` for the issuer's public keys; no user data |
| Front-channel logout URIs (in the user's browser) | The browser loads each URI in a frame, with `iss` and the session ID when the client asked for them |
| OTLP collector (`observability.otlp_endpoint`) | Spans of sampled requests and worker task runs: method, route label, status, timings, task name and item count, trace and span IDs, and for outbound calls the destination host ([monitoring.md](monitoring.md#tracing)) |

HTTP calls made while serving a request (hooks, upstream identity providers,
challenge providers) also carry a `traceparent` header: the request's trace ID
(random, or continued from the caller's own `traceparent`) and span ID, no
request data (API-012).

## Data residency

PRV-003. ProudAuth does not choose where data is stored; it lets the operator
keep connectors within chosen destinations and reports the deployment's
label:

| Data | Where it lives | Controlled by |
| --- | --- | --- |
| Everything in the tables above | The PostgreSQL database | Where you run it (`storage.database_url`) |
| Backups | Your backup storage | You; ProudAuth does not manage backups (`privacy.backup_retention` only informs the deletion report) |
| Audit archive | `privacy.audit_archive_dir` | The volume you mount |
| Logs, metrics, spans | Standard error, `/metrics`, the OTLP collector | Your log and monitoring pipeline; `observability.otlp_endpoint` |
| Outbound connector data (webhooks, pre-action hooks, back-channel logout, SMS gateway, organization mail servers, upstream identity providers, challenge providers, policy engines, workload key sets, LDAP directories, downstream SCIM services) | The destinations administrators register | `privacy.residency.allowed_destinations` |
| SAML messages (assertions to service providers, `AuthnRequest`s to identity providers) | The counterparties, through the user's browser | Not checked at connection time (ProudAuth makes no connection to them); a SAML connection's `sso_url` is checked against the residency policy when it is saved |
| The deployment's SMTP relay, SMS gateway URL, OTLP endpoint | Operator configuration | Checked against `allowed_destinations` at startup |
| Secret stores and KMS (`vault:`, `kms:`) | Your Vault or KMS | Not checked |

With `privacy.residency.allowed_destinations` set (host names or `.domain`
suffixes), a destination outside the list is refused when a webhook, hook,
organization mail server, upstream identity provider or workload trust key
set is saved (`422 validation_failed` on the field, like other egress-policy
violations; PRV-003, `TestResidencyAtSave`) and at every connection,
including DNS changes later ([configuration.md](configuration.md#privacy),
`internal/egress/residency_test.go`). `privacy.residency.region` is a label
shown by `/status` with `destinations_restricted`
([monitoring.md](monitoring.md#operator-status)); ProudAuth cannot observe or
enforce where the database, backups or logs are located.

## Account deletion

`DELETE /users/{user}` (administrator), the scheduled completion of a
self-service deletion request (`POST /me/deletion-request`, after
`privacy.deletion_grace_period`, default 14 days; the request sends the
`deletion_scheduled` notice, and until the deletion is due the owner can
cancel it by signing in, which offers nothing but the `cancel_deletion` step:
[headless-authentication.md](../protocols/headless-authentication.md#pending-deletion-usr-012),
USR-012), the merged-away account of
an executed account merge (`POST /account-merges/{id}/execute`), and the
lifecycle rules for expired unverified registrations and unused guest accounts
(below):

- revokes sessions, grants, refresh families, opaque tokens and support grants;
- deletes identifiers, credentials, recovery codes, passkeys, external identities,
  password history, remembered devices, pairwise subject mappings and notification
  preferences;
- marks memberships `removed`, clears the metadata of every membership the
  account had (USR-009), and revokes the user's automation credentials;
- suppresses the account's queued notifications and erases the payload and
  recipient of every notification job about it, at once rather than at
  `delivery.payload_retention` (migration `0048`). Every message about an
  account records it (`notification_jobs.user_id`): login codes,
  password-reset, verification and magic-link messages, security and
  support-access notices, group notices, and any message sent to one of the
  account's addresses. Messages queued before this was recorded are found
  through their user or challenge reference;
- deletes its certificate bindings (PROV-016) and the relationship tuples
  that name it as subject (AZ-021); revokes the pending and accepted shares
  it made or received (removing the tuple of an accepted share it made, as a
  revocation does) and clears the message of every share naming it
  (AZ-027); revokes its elevation eligibilities, cancels its pending
  elevation requests and ends an active elevation, whose role assignment
  then expires at once and is removed by `lifecycle.expiry` (AZ-024;
  `TestAccountDeletionCoverage`);
- ends pending work about the account: scheduled assisted recoveries
  (`pending` or `approved`) and pending account merges in which it is either
  account become `cancelled`, and a pending registration approval becomes
  `expired`;
- clears profile, metadata and required actions and sets the state `deleted`;
- writes digest-only tombstones for each identifier and for the user ID;
- clears the source-supplied details (`metadata`, `source_subject_id`, the
  actor's `display`) of imported historical audit records whose subject is the
  account, unless an active legal hold covers them (MIG-016); records imported
  later for the deleted account are stored without those details unless a
  legal hold covers them (a hold on their organization, a realm-wide hold or a
  hold on the account), in which case they keep them (PRV-004);
- records audit `user.deleted` and outbox `user.deleted`.

**Owned objects come first** (USR-020, APP-001, APP-014,
`TestDeletionNeedsOwnershipTransfer`). `DELETE /users/{user}` and
`POST /me/deletion-request` are refused with `409 last_owner` while the account
is the only active owner of an organization (extension `organizations` on the
administrator route) or is the recorded owner of live objects, listed in the
extension `owned`: `projects` (not archived), `clients` (not decommissioned),
`service_principals` (not deleted), `resources` and `identity_providers`
(active). Move them first: one project with
`POST /projects/{project}/ownership-transfer` (`owner_user_id` of an `active`
account and/or `owner_organization_id`, and a `reason`; optional `If-Match`;
audited `project.ownership_transferred`), or everything at once with
`POST /users/{user}/ownership-transfer {"to_user_id": "usr_..."}`, which moves
every object the account owns, in any state, to another account and answers
`{"transferred": {"project": 2, "client": 1}}` (kinds with nothing to move are
left out). The transfer needs `realm.projects.write`,
`realm.clients.write`, `realm.service_principals.write`,
`realm.resources.write`, `realm.identity_providers.write`,
`realm.policies.write`, `realm.hooks.write` and `realm.webhooks.write`
together, and the new owner must be an account of the realm in state `active` or
`recovery_restricted` (`422` on `owner_user_id` otherwise); each move is
audited as `<kind>.ownership_transferred` (category `configuration`, metadata
`previous_owner_user_id` and `owner_user_id`) and increments the object's
version, so an `ETag` read before the transfer no longer matches `If-Match`.
The transfer also moves the authorization policies, pre-action hooks and
webhook subscriptions the account owns (`authorization_policy`, `hook` and
`webhook` in `transferred`; a plugin-managed hook or subscription keeps its
plugin, only its accountable owner changes;
`TestOwnershipTransferCoversExtensions`). Such objects do not block the
deletion; one left behind is listed as
`owner_departed` by the ownership report
([machine-clients.md](../integrations/machine-clients.md#ownership-report)),
and `POST /hooks/{id}/ownership-transfer`, `POST
/webhooks/{id}/ownership-transfer` or `POST
/policies/{policy}/ownership-transfer` (`{"owner_user_id"}`, optional
`If-Match`; `realm.hooks.write`, `realm.webhooks.write` or
`realm.policies.write`) gives it a new owner, also when it has none.
The check runs when the deletion is
requested, and again when a scheduled self-service deletion falls due: while
the account is then the only active owner of an organization that is not
being deleted, or owns live objects, the deletion is postponed by 24 hours
and recorded as `user.deletion.postponed` (reason
`OWNERSHIP_NOT_TRANSFERRED`, metadata `organizations` and `owned` with the
IDs per kind), every day until the ownership is moved. A lifecycle deletion
and the merged-away account of a merge are not checked again.

It does **not** delete: the `users` row and ID, session rows (with IP and user
agent) and grants (until `privacy.session_retention` after they were
revoked), consents and invitations addressed to the user (until
`privacy.history_retention` once revoked or ended), terms acceptances,
registration approvals, assisted-recovery requests, merge records and subject
aliases, suppression entries for the user's addresses,
audit events (until audit retention, or longer under a legal hold) and their
archived copies, the rest of imported historical audit records (type, time,
outcome, content hash, until retention), webhook delivery payloads (until
`privacy.history_retention`), job records (export payloads until
`privacy.export_retention`), or data in backups (PRV-005). Restore reconciliation re-applies deletions to restored
backups, including the clearing of imported audit records
([backup-restore.md](backup-restore.md#what-reconciliation-re-applies)).

### Deletion propagation report

PRV-005, `internal/httpapi/privacy.go`, `TestDeletionPropagationStatus`.
`GET /api/v1/realms/{realm}/users/{user}/deletion-status` (`realm.users.read`)
reports, for a deleted account, where its data still exists. It is derived
from what is stored at the time of the request, not from a separate log;
an account that is not deleted gets `409 conflict` (with its `state`), an
unknown one `404`.

```json
{"user_id": "usr_...", "deleted_at": "2026-10-11T08:00:00Z",
 "stages": [{"stage": "connectors", "state": "pending", "count": 2,
             "details": "user.deleted event published to webhook subscribers; ..."}, ...]}
```

Each stage has `stage`, `state` (`done`, `pending`, `retained` or
`unknown`), optional `count` and `until`, and `details`:

| `stage` | Reports |
| --- | --- |
| `primary_storage` | Always `done`: identifiers, credentials, factors, linked identities and profile were erased in the deletion; the ID remains |
| `sessions_and_grants` | `pending` while sessions or grants of the account are still active (`count`) |
| `exports` | `pending` while export results the account requested are stored (`count`); `until` deletion + `privacy.export_retention` |
| `notifications` | `done`, or `pending` with a `count` of notification jobs about the account that still hold a payload or recipient (normally none, since deletion erases them; every message about an account records it) |
| `connectors` | `pending` while the `user.deleted` event is not dispatched or any of its webhook deliveries is pending or retrying; `count` is the number of deliveries |
| `imported_audit_history` | `pending` while imported records about the account still carry source-supplied details (`count`); those left are under a legal hold |
| `caches` | `pending` until deletion + `security.decision_cache_ttl` (at least one minute): decisions callers may have cached, and in-process caches |
| `audit_evidence` | `retained`: audit events naming the account by ID (`count`), `until` deletion + the longest retention that can apply (`privacy.audit_retention`, any `privacy.audit_retention_by_category` value, the realm's `audit.retention_days`); the details mention that organization retention can keep events longer. No `until` while an active legal hold covers the account (a hold on it as subject, or a realm-wide hold); organization holds of the realm are mentioned in the details when no such hold exists |
| `backups` | `unknown` without `privacy.backup_retention`; otherwise `retained` until deletion + that period, then `done`. ProudAuth never reports a backup erased early; the details note when restore reconciliation would re-apply the deletion (a tombstone exists) |

## Organization deletion

TEN-011, TEN-024, `TestOrganizationDeletionWorkflow`.
`GET /organizations/{org}/deletion-preview` (`org.delete`) counts what a
deletion affects: `active_members`, `pending_invitations`, `active_grants`,
`owned_projects`, `owned_clients` (active clients of the organization's
projects and service principals), `provisioning_connectors`,
`active_support_grants`,
`role_assignments`, `groups`, `verified_domains`, `owned_service_principals`,
`active_automation_credentials`, `webhook_subscriptions`,
`identity_providers`, `mail_server_configured`, `consent_preauthorizations`,
`export_results`, `pending_jobs`, `retained_audit_events` and
`active_legal_holds` (the holds that cover the organization's evidence: holds
on the organization, realm-wide holds, and subject holds on anyone with a
membership in it), and lists in `retained` what is kept: audit events
(until audit retention, longer under a legal hold), the organization record
as a deleted tombstone, memberships and invitations as removed or revoked
records, and members' federated identity links (with the provider disabled).

`DELETE /organizations/{org}` (`org.delete`, recent authentication) answers
`202 {"state": "deleting", "job_id"}` and, in that transaction, revokes the
organization's sessions, grants, pending invitations and automation
credentials; disables its provisioning connectors, service principals,
webhook subscriptions and identity providers; suspends its active owned
projects and the active clients of those projects and of its service
principals, and revokes those clients' refresh tokens; revokes its consent
pre-authorizations; erases the results of all its jobs and cancels its
other queued jobs (running ones are asked to stop); and publishes
`organization.deleted`. A job of the organization that is still running
when the deletion starts stores no result: it ends `cancelled` with
`last_error` "organization deleted while the job ran" (the deletion job
itself excepted). The worker then finishes at its next run (there is no
grace period, and it cannot be cancelled): it deletes role assignments, group
memberships, aliases, the organization's notification settings (sender and
mail server with its password) and webhook subscriptions (with their
deliveries), erases identity providers' client secrets, revokes the owned
clients' credentials and erases their secret digests and public keys (key
IDs and display prefixes stay), marks memberships removed, domains removed
and join requests withdrawn, and turns the organization into a tombstone
(`organization.deletion.completed`). Audit events are not changed.

The deletion job runs only while its requester still holds `org.delete`
(evaluated as if the organization were still active). Otherwise it
dead-letters ("permanent job failure: the requester no longer holds
org.delete") and the organization stays `deleting` until someone authorized
sends `DELETE /organizations/{org}` again, which queues a new job (`202`);
while a deletion job is queued or running, another `DELETE` is `409`
(`TestOrganizationDeletionRequesterRechecked`). Relationship tuples and
sharing records of the organization are not removed
([relationship-authorization.md](../integrations/relationship-authorization.md#data-and-limits)).


## Account lifecycle jobs

USR-015, `internal/identity/lifecycle.go`, `TestUserLifecycleJobs`. The worker
task `lifecycle.users` runs every 10 minutes and applies these rules to each realm
(including suspended realms):

| Rule | Selects | Action | Realm policy |
| --- | --- | --- | --- |
| `unverified_expired` | Accounts still `pending_verification` that were created before the cut-off | Account deletion (above), audit reason `unverified_registration_expired` | `lifecycle.unverified_account_ttl_hours` (default 72) |
| `dormant` | `active` accounts that are neither protected nor guests, with no sign-in (or, without one, created) before the cut-off, and not flagged since their last sign-in | `report` (default): sets `dormant_flagged_at` and records `user.dormant_detected` (category `account`), once per dormancy; `suspend`: also suspends the account (`user.suspended`, reason `dormant`), which revokes its sessions and grants | `lifecycle.dormant_days` (0 or omitted disables, at most 3650) and `lifecycle.dormant_action` (`report` or `suspend`) |
| `guest_expired` | Guest accounts with no sign-in (or, without one, created) before the cut-off | Account deletion, audit reason `guest_expired` | `lifecycle.guest_ttl_days` (default 30, at most 3650; 0 or omitted means the default) |
| `scheduled_deactivation` | `active` accounts whose `deactivate_at` has passed | Suspension (`user.suspended`, reason `scheduled_deactivation`); `deactivate_at` is cleared | — |

- Each run handles at most 100 accounts per rule and realm, oldest first. Every
  account is re-checked against the rule and changed in its own transaction, so
  a sign-in or an administrator change that happened meanwhile wins. Changes are
  recorded with the actor `system`. A realm whose run fails does not stop the
  others; the task reports the first error after every realm ran.
- `GET /api/v1/realms/{realm}/lifecycle/preview` (`realm.users.read`) is the dry
  run: `{"dry_run": true, "batch_size": 100, "rules": [{"name", "action", "due",
  "sample_user_ids"}]}` with the number of accounts each rule would select now and
  up to 20 of their IDs. Nothing is changed.
- Administrators schedule a suspension with
  `PUT /api/v1/realms/{realm}/users/{user}/scheduled-deactivation
  {"at": "RFC 3339", "reason": "..."}` (`realm.users.suspend`; `at` must be in
  the future; refused for accounts being deleted) and cancel it with `DELETE` on
  the same path. Both are audited (`user.deactivation_scheduled` with
  `deactivate_at`, `user.deactivation_cancelled`), and administrator user views
  show `deactivate_at`.
- Protected accounts are never treated as dormant, but a scheduled deactivation
  applies to any `active` account.

## Identity read evidence

USR-018, AUD-015, `TestIdentityReadEvidence`. Reads of account records are not
logged by default. With realm policy `data_access.log_identity_reads: true`:

- `GET /users/{user}` records `user.read` with the account as subject;
- `GET /users` records `user.search` with `result_count` and `filtered` (whether
  a `q` search term was given);

both in the audit category `data_access`, with the calling administrator or
support operator as actor and `masked` telling whether the caller received the
masked view (callers with `support.users.read` but not `realm.users.read`). The
event holds no profile or contact data, and it is written before the data is
returned: if it cannot be written, the request fails. Query the evidence with
`GET /audit-events?category=data_access`.

## Audit retention and legal holds

AUD-007, AUD-009, `internal/audit/query.go` (`PruneExpired`),
`internal/audit/holds.go`, migration `0044`,
`TestAuditRetentionCategoriesAndHolds`. The worker task `retention.cleanup`
(every 5 minutes, up to 100 batches per run) deletes **sealed** audit events
whose retention has passed:

- the deployment's retention of an event is
  `privacy.audit_retention_by_category[<category>]` when its category is
  listed, otherwise `privacy.audit_retention` (400 days);
- a realm can keep its evidence longer with the realm policy
  `audit.retention_days`, and an organization with its policy
  `audit_retention_days` (`PATCH /organizations/{org}`); both are `0` (not
  set) or 30–3650 days (`422` otherwise). An event is pruned only when every
  retention that applies to it (deployment or category, realm, organization)
  has passed, so a scope can only extend retention, never shorten it. All
  are measured from `occurred_at`;
- category `emergency` is never pruned, and neither is an event matched by an
  active legal hold;
- events are removed one by one, so a batch can lose its events over several
  passes as different retentions expire. The first pass over a batch is
  recorded in `audit_prunes` and later ones in `audit_prune_log`, both
  append-only, and the chain still verifies
  ([incidents.md](incidents.md#audit-chain-verification-failure));
- with `privacy.audit_archive_dir` set, only batches the archive already holds
  are pruned, so nothing is pruned before the first archive run and a stopped
  archive also stops retention.

Every removal goes through the database function `proudauth_audit_prune`
(owner-run, `SECURITY DEFINER`). It never removes unsealed events, category
`emergency` or events under an active legal hold, refuses batches not yet
archived once the archive has forked after a restore, and writes the
`audit_prunes` / `audit_prune_log` rows itself. The guard trigger accepts a
delete only from the table owner with the retention flag set, which only
the function does. With separate database roles (`storage.runtime_role`)
the runtime role has no `DELETE` on `audit_events`, `audit_batches`,
`audit_prunes` or `audit_prune_log`, only `EXECUTE` on the function, so the
service's credentials cannot delete held, emergency or unsealed evidence.
The function does not check age, though: the retention periods and the
archive progress are applied by the worker, so a stolen runtime credential
can still prune other sealed events early, recorded like retention (the
archive keeps the copies). In a single-role deployment the runtime role is
the owner and can delete audit rows directly; separate the roles where that
matters ([installation.md](installation.md#database-roles)).

The same task deletes imported historical audit records (`imported_audit_events`,
MIG-016, up to 1000 per run) once `privacy.audit_retention_by_category.imported`,
or else `privacy.audit_retention`, has passed since they were **imported**
(their `occurred_at` can be years older). A longer realm (`audit.retention_days`)
or organization (`audit_retention_days`) retention keeps them longer too,
also counted from the import. Legal holds apply to them by realm, organization and
local `subject_id`; a hold on a person does not match records where that
person is only the source-stated actor.

A **legal hold** keeps evidence regardless of retention. `POST
/api/v1/realms/{realm}/audit-legal-holds` (`realm.audit.legal_hold`, held by
the built-in `realm-admin` role; an MFA session) takes a `reason` of 5–500
characters and optionally `organization_id` and `subject_id`:

| Body | Keeps |
| --- | --- |
| neither | every event of the realm |
| `organization_id` | the realm's events of that organization |
| `subject_id` | the realm's events whose subject or actor is that ID |
| both | events of that organization whose subject or actor is that ID |

Neither ID is checked against existing organizations or accounts, and events
without a realm (operator events written by `identity-cli`) cannot be held.
`GET .../audit-legal-holds` lists the realm's holds (`id`, `organization_id`,
`subject_id`, `reason`, `created_by_id`, `created_at`, `released_by_id`,
`released_at`), active ones first, at most 500. `POST
.../audit-legal-holds/{id}/release` ends a hold (`404` if it is unknown or
already released); retention applies to its events again at the next run.
Placing and releasing are audited as `audit.legal_hold.placed` (with the
reason) and `audit.legal_hold.released`, in category `audit`; a release also
raises the `configuration_change` security signal and a `security.alert`
event. Held evidence is kept in the database only as long as the hold, so
also export it (`POST /audit-exports`) if it must outlive a database restore.

### Audit corrections

AUD-007. Audit events are never edited, also not by administrators. A
mistaken or incomplete record is corrected by a new event linked to it:

```json
POST /api/v1/realms/{realm}/audit-events/evt_.../corrections
{"reason": "INC-77: the ticket reference was wrong", "correction": {"ticket": "INC-77"}}
```

- Needs `realm.audit.correct` (privileged; held by the built-in `realm-admin`
  role through `realm.*`) and, for users, an MFA session. `reason` is 5–1000
  characters; `correction` is an optional object of at most 8 KiB as JSON,
  redacted like other audit metadata. Only events of the caller's realm can be
  corrected (`404` otherwise, also for operator events without a realm); a
  correction can itself be corrected.
- The answer is `201 {"event_id", "corrects_event_id"}`. The correction is the
  audit event `audit.correction` (category `configuration`, the caller as
  actor, the original's organization, target `audit_event` with the
  original's ID; metadata `corrects_event_id`, `corrects_type`, `reason`,
  `correction`), sealed into the chain like any other. The original never
  changes.
- Find the corrections of an event with
  `GET /audit-events?type=audit.correction&target_id=<event id>`. A retried
  request without an `Idempotency-Key` records a second correction.
- A correction follows its own retention, not the original's.

## Known data-minimization gaps

- `auth_transactions` holds the full client IP address and the user agent
  while a transaction is pending (the per-network budgets of a step without
  a request address of its own, the authentication flow's network signals
  and challenge providers use it), and `sessions` keeps user agents until
  the session row is deleted (PRV-002).
- Imported audit metadata is redacted only by member name (secret-looking
  keys and bearer-token or JWT-shaped values); other personal data the source
  supplied, such as IP addresses, is stored as given.
- Active consents, pending invitations, consent pre-authorizations,
  registration approvals, assisted-recovery requests, account-merge records,
  notification suppressions, terms acceptances, legal holds and audit archive
  files have no retention job.
- A failing step of `retention.cleanup` no longer stops the others: every
  step runs, and the run reports the failed ones together
  (`<step>: <error>`); the failed step's data stays until the cause is fixed.
  Watch `proudauth_worker_runs_total{task="retention.cleanup",outcome="error"}`
  and the `worker task failed` log line.
- Account deletion does not touch access review items about the account;
  the client registration records keep the registrant's IP address, and
  none of these tables has a retention job
  ([Protocol, machine-identity and authorization extensions](#protocol-machine-identity-and-authorization-extensions)).
- Account deletion does not touch lifecycle workflow tables: runs, attempts
  and approvals about a deleted account (or decided by it) keep its user ID
  until `privacy.history_retention` purges the finished runs; a run still in
  progress keeps it longer. Workflows and revisions (with approver IDs in
  their definitions) are kept until the workflow is deleted.
- Plugins and their versions (signed packages, uploader and reviewer IDs,
  review notes) have no retention job and no deletion API.
- Migration adapters write the capability report, mapping template and, with
  `--write-documents`, the converted import documents (with password
  verifiers and TOTP seeds) to files on the operator's machine (mode 0600);
  ProudAuth does not track or delete them
  ([migration-adapters.md](migration-adapters.md)).
- A deleted account's directory link keeps the entry's immutable ID (with
  source state `deleted`) until the connector is deleted, so the directory
  entry is not imported again
  ([Directory integration](#directory-integration)).
- Organization relationships, flow revisions and federation transfer
  summaries are kept indefinitely
  ([Security events, cross-organization access and other evidence](#security-events-cross-organization-access-and-other-evidence)).
