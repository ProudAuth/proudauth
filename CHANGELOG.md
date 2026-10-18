# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html); 0.2.0 is
published as prereleases (`v0.2.0-alpha.N`). During 0.x, any minor version can
contain breaking changes; they are listed under **Changed** or **Removed** with
migration notes.

Security fixes name the affected versions and link the advisory (QA-008,
GOV-003). Requirement IDs refer to [docs/plan.md](docs/plan.md).

## [Unreleased]

### Added

- [0.2.0-alpha.6 owner decisions](docs/releases/2026-10-alpha.6-decisions.md):
  the known-device quota and budget defaults, the second-factor failure
  ceiling, personal-access-token revocation, organization-switch consent,
  sender-bound refresh families, re-approval of changed dynamic registrations,
  logout-hint handling, the issuer-only client-assertion audience, the merge
  model and the benchmark method for the alpha.6 phase.
- Mandatory notification template `credentials_revoked` (variables `realm`,
  `change`, `credentials`, `time`), which names the personal access tokens and
  API keys an account recovery revoked.
- A migration lint in CI: `TestMigrationLint` (`tests/contract`) reads every
  migration with the runner's statement splitter and fails on DDL that
  blocks a hot table or breaks older binaries in the mixed-version window,
  which until now only review caught (OPS-008, DEP-012, TEST-061). Lock
  findings: a plain `CREATE INDEX` on a table the file does not create (and
  `ADD UNIQUE`, `ADD PRIMARY KEY` or a `UNIQUE` column, which build an index
  under `ACCESS EXCLUSIVE`), `ALTER COLUMN ... TYPE` and stored generated
  columns (table rewrite), and `ADD COLUMN` with a default that is not a
  constant (`now()`, `gen_random_uuid()`, `nextval()`, a `serial` type or an
  identity); `CONCURRENTLY` in a file without `-- proudauth:no-transaction`
  is reported before the runner refuses it. A file allows a lock finding
  with `-- proudauth:allow-<rule>: <reason>`. Destructive or contracting DDL
  (`DROP TABLE`, `DROP COLUMN`, `DROP INDEX`, `DROP CONSTRAINT` and other
  drops, `DROP NOT NULL`, `SET NOT NULL`, `DROP DEFAULT`, column type
  changes, renames, `ALTER TYPE`, `ALTER DOMAIN`, `TRUNCATE`) passes only in
  a file marked `-- proudauth:compat=contract` or carrying the new
  `-- proudauth:reviewed-expand: <why older binaries keep working>`. The
  lint understands schema-qualified and quoted names, `IF [NOT] EXISTS`,
  `ONLY`, several actions in one `ALTER TABLE`, comments and DO blocks, and
  never reports DDL on a table the same file creates. The 46 findings of
  migrations `0001`–`0087`, which shipped before the lint and cannot change
  (their checksums are verified), are listed with their reasons in
  `migrations/lint-baseline.txt` (37 plain index builds, 6 replaced check or
  unique constraints, one replaced index, `0065`'s `DROP NOT NULL` and
  `0012`'s `pg_current_xact_id()` default); the baseline is exact and
  history only. Migration files are unchanged. The real N-1 upgrade job of
  TEST-061 is still planned for 0.2.0-alpha.7
  ([CONTRIBUTING.md](CONTRIBUTING.md#database-migrations)). Regression tests
  `TestMigrationLint`, `TestLintMigrationRules`, `TestLintFindingText`,
  `TestLintBaseline`.
- `migrate` warns about a migration that sorts before the newest one the
  database has applied (a backported fix, or a file merged late): it still
  runs, but `identity-cli migrate -plan` marks it `out-of-order` with that
  newest migration, `identity-cli migrate` prints a warning when it applies
  it, and `identity-server -migrate` and `storage.migrate_on_start` log
  `migration applied out of order`. A file reviewed for this carries
  `-- proudauth:allow-out-of-order: <reason>` (OPS-008,
  [upgrades.md](docs/operations/upgrades.md#how-migrations-work)).
  `storage.DB.MigrateWith` now returns the migrations a run applied with
  their plan items, and `server.MigrateAsOwner` passes them on. Regression
  tests `TestOutOfOrderMigrations`, `TestMigratePlanLine`,
  `TestWarnOutOfOrder`.
- `DELETE /organizations/{org}/groups/{group}/roles/{assignment}` removes a
  role assignment from a group within its organization (`org.roles.assign`,
  from an MFA session). Before, only the realm route
  `DELETE /role-assignments/{assignment}` could. The assignment must be that
  group's in that organization (`404` otherwise, also for a user's
  assignment), and the caller must be able to assign the role
  (`403 grant_ceiling_exceeded`); the members of the group and of its
  descendant groups lose the role, recorded as `role.unassigned`
  (TEN-007, TEN-008, TEN-013, `TestGroupRoleUnassignRoute`).

### Changed

- The service depends on `github.com/proudauth/proudauth-sdk-go` `v0.2.0`, the
  SDK's first release tag, instead of a pseudo-version of its `main` branch
  (SDK-009); `docs/integrations/sdk-repositories.json` pins that revision.
- The rate limiter counts all the budgets of a check in one database
  statement (a multi-row `INSERT ... ON CONFLICT` over arrays) instead of one
  round trip per budget, so the password step's four or five budgets cost one
  round trip (SEC-006, ARC-006). Every budget of the check is now consumed even
  when one of them is exhausted: a refused attempt still counts toward the
  client, organization and realm budgets it would have used (REG-012).
  Before, the budgets after the first exhausted one were not counted. The
  send cooldown (`security.rate_limits.send_cooldown`) is checked on its own
  first, so a resend it refuses consumes nothing but the cooldown: no unit
  of `send_per_identifier`, `send_per_ip` or the client, organization and
  realm send budgets (PWDLESS-004). A send costs two round trips instead of
  four to six. The refusal still names the first exhausted budget in the order
  the caller lists them, with `Retry-After` the time left in its window.
  Lock checks treat a disabled budget as not exhausted, as counting does
  (latent: every caller already skipped disabled locks). Regression tests
  `TestHitConsumesEveryBudgetInOneStatement`,
  `TestHitDeniesAndStillConsumesEveryBudget`, `TestDisabledBudgetsPeekLikeHit`,
  `TestHitSharedCountersConcurrently` and `TestSendCooldownConsumesNothingElse`.
- Configuration validation covers `security.rate_limits`: a negative value,
  which disabled its budget silently, and a positive limit whose window is
  `0`, which the limiter skipped, now stop startup; `0` still disables a
  budget (SEC-006). A configuration that set `temporary_lock: 0` to turn the
  password lock off sets `failures_before_lock: 0` instead.
  `api/schemas/config.schema.json` marks the limits and windows
  non-negative. Regression test `TestValidateRateLimits`.
- The invitation resend cap (`limits.invitation_resends`) answers `409
  conflict` ("resend limit reached for this invitation; create a new
  invitation") instead of `429 rate_limited`: the cap never resets, so a
  `429` told clients to wait for a retry that could never succeed (INV-009,
  API-009, `TestInvitationLimitsAndExpiry`). **Migration:** a client that
  read a `429` from `POST .../invitations/{id}/resend` as the cap should
  handle `409` by creating a new invitation; a `429` from that route now only
  means the organization's invitation budget and carries `Retry-After`.
- The Kubernetes server Deployment probes the internal listener (port
  `internal`, `:9090`) instead of the public one: liveness and startup
  `GET /health/live`, readiness `GET /health/ready`, which the internal
  listener now serves with the public check's statuses and bodies (DEP-009,
  DEP-013). On `:8080` the probes shared the administration reserve
  (NFR-002), so a full reserve answered liveness with `503` and Kubernetes
  restarted pods mid-incident. The public `/health/*` routes stay for
  Compose, load balancers and operators, and `workers.metrics_listen` serves
  `/health/ready` too ([monitoring.md](docs/operations/monitoring.md#probes-and-load-shedding)).
  Regression tests `TestDeployKubernetesManifests`, `TestHealthContracts`,
  `TestLoadShedding`. **Operators:** custom overlays should point their
  probes at port `internal` and bind `server.internal_listen` to the pod's
  addresses (`":9090"`, as `overlays/example` does), not the default
  `127.0.0.1:9090`.

### Fixed

- Errors on the OAuth and OIDC endpoints (`/realms/{realm}/oauth/*` and
  `/realms/{realm}/oidc/*`) are always OAuth errors (`error` and
  `error_description` only), as the API conventions promise, also when the
  refusal is decided before the endpoint runs: load shedding and maintenance
  answer `503 temporarily_unavailable`, a body over `limits.max_body_bytes`
  `413 invalid_request`, the host policy `421 invalid_request` and an unknown
  realm `404 invalid_request`. These, and other problems an endpoint raised
  (for example dynamic client registration's `404` and `429`), came back as
  `application/problem+json` without an `error` member, which OAuth client
  libraries cannot read. HTTP statuses are unchanged; the custom APIs and the
  discovery and JWKS documents keep problem details (API-001, API-007,
  `TestProtocolErrorFormat`, `TestLoadShedding`,
  `TestProtocolRouteErrorFormat`). Clients that parsed problem details from
  these routes should read `error` instead.
- Every `429` and `503` carries `Retry-After`, as the API conventions state:
  a refusal that names no delay gets 2 seconds (`problem.DefaultRetryAfter`)
  in problem details, OAuth errors, SCIM and the registry token endpoint, and
  maintenance with `retry_after_seconds` `0` sends that default instead of no
  header. The `503`s of JWKS, dynamic client registration, the session check
  and an inactive identity domain, the Shared Signals verification `429` (now
  the rest of its interval) and maintenance with `0` had none (API-009,
  OPS-015, `TestRetryAfterOnThrottlingAndUnavailable`,
  `TestRetryAfterClampsZero`, `TestProtocolErrorFormat`).
- Token revocation answers `503 temporarily_unavailable` with `Retry-After`
  when the revocation cannot be recorded, as RFC 7009 §2.2.1 recommends; the
  errors of the refresh-token, opaque-token and JWT revocation writes and of
  the JWT path's audit event were dropped, so the endpoint answered `200`
  while the token stayed valid. A JWT's revocation record and its
  `token.access.revoked` audit event now commit in one transaction. Unknown
  tokens and other clients' tokens still answer `200`, so the `503` reveals
  nothing about a token (TOK-010, `TestRevocationStorageFailure`). Affects
  0.2.0-alpha.5 and earlier.
- A pushed authorization request is consumed only by the client that pushed
  it. The `request_uri` was marked used before the presented `client_id` was
  compared with the pushing client, so a request with another client's or an
  unknown `client_id` failed and also spent the reference for its own client.
  The client is now resolved first and the consuming update matches it; the
  refusal is `400 invalid_request` ("invalid or expired request_uri") either
  way (RFC 9126 §4, OIDC-001, `TestDeviceFlowAndPAR`). Affects 0.2.0-alpha.5
  and earlier.
- UserInfo answers a refused DPoP binding with a `DPoP` challenge naming the
  accepted proof algorithms (RFC 9449 §7.1) instead of `Bearer
  error="invalid_token"`: `invalid_token` for a DPoP-bound token sent with
  the `Bearer` scheme or with another key's proof, `invalid_dpop_proof` for a
  missing or invalid proof. A request without credentials gets a `Bearer` and
  a `DPoP` challenge (TOK-019, `TestUserInfoDPoPChallenge`,
  `TestSenderConstraintChallenges`).

- Accepting a resource share no longer rewrites a relationship tuple the
  share did not create, and revoking a share no longer deletes one (AZ-021,
  AZ-027). When the recipient already held the relation on the object
  through a tuple written by the relationships API or by another share,
  acceptance kept that tuple's `source` but gave it the share's `expires_at`,
  so a permanent grant became time-boxed and a time-boxed one permanent, and
  recorded the tuple as the share's, so revoking the share removed access the
  application had granted. Acceptance now writes a tuple of its own or is
  refused with `409 conflict` ("you already hold this relation on the object
  outside this share"), leaving the existing tuple unchanged and the offer
  pending, also when that tuple has expired but was not removed. Revoking a
  share removes only a tuple whose `source` is that share's `share:<id>`,
  which also protects tuples that shares accepted by earlier versions
  recorded as their own
  ([relationship-authorization.md](docs/integrations/relationship-authorization.md#sharing)).
  Affected: every earlier 0.2.0 prerelease; regression test
  `TestResourceSharesKeepForeignTuples`.
- Migrations bound their lock waits: each migration runs with `lock_timeout`
  set to the new `storage.migration_lock_timeout` (default `5s`), so DDL that
  queues behind a long query no longer holds up every later query on a hot
  table (`authorization_codes`, `opaque_access_tokens`, `sessions`) until it
  commits. A migration that gives up waiting (SQLSTATE `55P03`) is rolled
  back and retried up to 5 times with pauses growing from 0.5 s to 8 s, then
  `migrate` fails and nothing of it is applied. Migration statements run with
  the new `storage.migration_statement_timeout` (default `10m`) instead of
  the runtime `storage.statement_timeout`: over the runtime connection they
  were cut off after 10 seconds, over `storage.migration_database_url` they
  had no limit. Both are set for the migration's own statements only;
  `identity-cli migrate -lock-timeout`, `-lock-retries` and
  `-statement-timeout` override them for one run (OPS-008, DEP-012). A
  migration file with a `-- proudauth:no-transaction` line runs statement by
  statement outside a transaction, so it can use `CREATE INDEX CONCURRENTLY`;
  its `CREATE INDEX` and `DROP INDEX` statements must be repeatable
  (`IF NOT EXISTS`, `IF EXISTS`), an invalid index left by an interrupted
  concurrent build is dropped and rebuilt, and the migration is recorded only
  when every index it creates is valid (`pg_index.indisvalid`). Its
  `CREATE INDEX CONCURRENTLY` and `DROP INDEX CONCURRENTLY` statements wait
  for older transactions without blocking the service's queries, so they run
  without `lock_timeout` and are bounded by
  `storage.migration_statement_timeout` only; its other statements keep the
  lock bound. `migrate -plan` marks such migrations `no-transaction`
  ([upgrades.md](docs/operations/upgrades.md#no-transaction-migrations),
  [CONTRIBUTING.md](CONTRIBUTING.md#database-migrations)). Regression tests
  `TestMigrationLockTimeout`, `TestMigrationStatementTimeout`,
  `TestNoTransactionMigrationRebuildsInvalidIndex`,
  `TestNoTransactionMigrationLockBounds`,
  `TestNoTransactionMigrationFailures`, `TestSplitSQL`,
  `TestParseNoTransaction`, `TestMigrationBounds`.
- The reserved request pool for administration and health admits an
  administrative request only when its `Bearer` or `DPoP` credential is a JWT
  whose header names a signing key of the path's realm with that key's
  algorithm, checked against the process's realm and key caches without a
  database query or signature check (NFR-002). Any non-empty `Authorization`
  header was enough before, so anonymous clients sending a junk header to
  `/api/v1/realms/{realm}/users` and the other administrative paths competed
  with operators for the reserve. Requests without credentials or with any
  other value (opaque, `Basic`, malformed, another realm's key or an unknown
  key) now use the ordinary pool; the reserve size and
  `limits.max_inflight_requests` are unchanged
  ([monitoring.md](docs/operations/monitoring.md#probes-and-load-shedding)).
  Key IDs are published in JWKS, so a forged token that copies one still
  reaches the reserve, where authentication refuses it. Regression tests
  `TestReservedPoolAdmission`, `TestLoadShedding`. Affects 0.2.0-alpha.5 and
  earlier.
- Removing a member from a group
  (`DELETE /organizations/{org}/groups/{group}/members/{member}`) and
  deleting a group (`DELETE /organizations/{org}/groups/{group}`) require
  that the administrator could assign every role the group grants, including
  roles inherited from its ancestor groups, as adding a member and
  unassigning a role already did: `403 forbidden` without
  `org.roles.assign`, `403 grant_ceiling_exceeded` for a role beyond the
  administrator's delegable set. Both needed only `org.groups.write`, and
  deleting a group removed its role assignments without the ceiling check,
  so an organization administrator who could not add members to a group
  could still take its roles from every member, one removal at a time or by
  deleting a leaf group (TEN-007, TEN-008, AZ-006, TEN-013). SCIM connectors
  still remove members from and delete the groups they own, and lifecycle
  workflows still check their publisher's authority themselves
  ([ADR 0006](docs/architecture-decisions/0006-realm-and-organization-boundaries.md#update-2026-10)).
  Affects 0.2.0-alpha.5 and earlier; regression tests
  `TestGroupRemovalNeedsTheGroupCeiling`, `TestTenantCrossingMatrix`.
- ABAC conditions with `in` and `contains` are unknown over a mistyped
  attribute, as the policy language promises and as `eq`, `ne` and the
  numeric operators already were, so the rule applies: a deny rule is
  answered `POLICY_ATTRIBUTE_MISSING`. `in` returned false when the attribute
  could not be compared with any list element (a number, list or object
  checked against a list of strings), and `contains` when the attribute was
  a list none of whose elements could be compared with the value, so a
  positive deny rule such as `context.classification in ["secret"]` did not
  apply to a wrongly typed value while `eq "secret"` did. `in` is now false
  only when at least one list element was comparable with the attribute, and
  `contains` only when the attribute is a list with at least one element
  comparable with the value, or an empty list. A rule with the comparison
  under `not` already applied; its denial now carries
  `POLICY_ATTRIBUTE_MISSING` instead of the rule's own reason code (AZ-007,
  AZ-015). Only the authenticated calling service's context and resource
  attributes, or the IdP's own records, reach a condition. Affects
  0.2.0-alpha.5 and earlier; regression tests
  `TestPolicyInContainsUnknownOnMistypedAttributes`,
  `TestPolicyInOverMistypedAttributeFailsClosed`.

### Security

- A password reset, marking the password compromised (by an administrator or
  a received shared signal) and assisted recovery revoke the user's personal
  access tokens and the API keys the user owns, in the transaction that
  revokes the sessions, with `revoke_reason` `password_reset`,
  `credential_compromised` or `assisted_recovery` and one
  `automation_credential.revoked` audit record each; the owner receives a
  `credentials_revoked` notice naming them by name and display prefix. These
  flows ended only sessions and grants, so someone who briefly controlled an
  account and minted a token kept up to 365 days of access after the owner
  reset the password or an operator recovered the account. Introspection also
  treats a user-owned credential created before the owner's latest such
  revocation as inactive. "Log out everywhere", an administrator's session
  revocation and a password change still leave personal access tokens alone
  (CRED-008, MCH-007, SES-005). Affected: every earlier 0.2.0 prerelease;
  regression tests `TestPersonalAccessTokensEndWithAccountRecovery`,
  `TestPersonalAccessTokenIntrospectionHonoursUserRevocation`.
- `POST /me/personal-tokens` on an account with an active TOTP, HOTP or
  passkey needs a session that completed MFA: a password-only or
  remembered-device session gets `403 step_up_required` with a
  `reauthenticate` obligation for the `mfa` profile, so a stolen password no
  longer turns into a year-long token. Accounts without a second factor are
  unchanged (MCH-006, MFA-006). Affected: every earlier 0.2.0 prerelease;
  regression test `TestPersonalAccessTokenMintingNeedsFactorProof`.
- `POST /me/organization-grants`, the organization switch, runs the consent
  coverage of an authorization before it creates a grant
  ([decision 12](docs/releases/2026-10-alpha.6-decisions.md)): for a client
  with `consent_mode: required`, the user's own live consent at the client's
  terms version, otherwise a live pre-authorization for the realm or the
  target organization, must cover every scope of the new grant, otherwise
  `403 consent_required` (a new problem code) with an `authorize` obligation
  naming `organization_id` and `scope`. The grant records the consent it rests
  on, so revoking the consent or the pre-authorization ends it, and the
  client's `token_policy.max_session_age_seconds` refuses an older session
  with `403 step_up_required`. The switch checked only the client's resource
  grants, so a third-party client holding a user's account-API token could
  mint a code for scopes the user never approved or for an organization
  without a pre-authorization, and such a grant outlived the revoked
  pre-authorization (TOK-008, APP-013, TEN-005, SES-002). The authentication
  transaction uses the same coverage check (`CheckConsentCoverage`): a consent
  recorded for an organization's pre-authorization now covers a later sign-in
  only while that pre-authorization does, so it no longer stands in for the
  user's consent in another organization, where the user is now asked, and a
  grant issued without asking records the consent it rests on. Affected:
  every earlier 0.2.0 prerelease; regression tests
  `TestOrganizationSwitchConsent`, `TestOrganizationSwitchPreauthorization`.

## [0.2.0-alpha.5] - 2026-10-18

### Added

- `internal/testutil` fault-injection helpers for reliability tests: a TCP
  black hole, silent and stalling SMTP relays, a refused port and a slow HTTP
  server.
- `docs/releases/` records the owner decisions taken at the start of each
  release phase, beginning with
  [0.2.0-alpha.5](docs/releases/2026-10-alpha.5-decisions.md).
- Reference measurements of the four core token flows on the alpha.5 tree,
  within three percent of the 2026-10-11 results
  ([benchmarks.md](docs/operations/benchmarks.md#alpha5-core-flow-baselines-nfr-003-nfr-008),
  `docs/operations/bench-results/2026-10-18-laptop-alpha5-baselines/`).
- The release workflow can be dry-run from `main` (`workflow_dispatch`): it
  builds, pushes by digest to `ghcr.io/proudauth/proudauth-staging`, attests,
  signs, tags, verifies its outputs with the operator commands from
  [installation.md](docs/operations/installation.md#verifying-a-release) and
  renders the release notes, and publishes nothing (DEP-003, GOV-005).
- Configuration: `directory.sign_in_timeout`, `directory.max_concurrent_binds`,
  `security.password.max_concurrent_hashes`; Compose variable `NETWORK_SUBNET`.
- Metrics: `proudauth_key_rotations_refused_total{reason}` on the worker,
  `busy` outcome of `proudauth_directory_binds_total`.
- Audit event `mfa.upgrade_proof.recorded`; `mfa.totp.used`, `mfa.hotp.used`
  and `mfa.recovery_code.used` carry `upgrade_proof`.

### Changed

- Database-backed tests clone a template database that is migrated once per
  migration set (its name carries a digest of `migrations/*.sql`), instead of
  replaying every migration for each test. `PROUDAUTH_TEST_NO_TEMPLATE=1`
  restores direct migration (QA-001).
- CI runs `tests/e2e` as four parallel shards (`scripts/e2e-shard.sh`, job
  `e2e`) and pipes every `go test` run through `internal/tools/testreport`,
  which fails the job when a test skips outside `tests/skip-allowlist.txt`,
  when a package fails to build, or when no test ran. Under CI, or with
  `PROUDAUTH_TEST_REQUIRE_DB=1`, a missing `PROUDAUTH_TEST_DATABASE_URL`
  fails database tests instead of skipping them. The `image` check now also
  waits for every e2e shard.
- The release image is pushed by digest and receives its version tags only
  after its provenance, SBOM attestations and signature exist, so a tag never
  names an unsigned image; every release verifies its own checksums,
  attestations, signature and tag before it is published. The source SBOM
  lists the Go module graph only, no longer the GitHub Actions and the SBOM
  evidence files found in the tree.
- A release whose CHANGELOG section has no `### Known limitations` heading is
  refused by the release workflow (GOV-005).
- GHCR is the only registry the project publishes to; the Docker Hub mirror
  is not updated and is no longer documented.

### Security

- Phishing-resistant administrator profile: an account that holds TOTP, HOTP,
  recovery codes or a passkey never used with user verification must prove
  that factor in the sign-in before a passkey can be registered. The proof is
  an upgrade proof: it unlocks `enroll_webauthn`, is audited as
  `mfa.upgrade_proof.recorded`, and never satisfies MFA. `totp/enroll` and
  `totp/activate` are refused under the profile, so the password alone can no
  longer register a passkey or replace the account's TOTP and recovery codes
  (MFA-006, SEC-012). Sign-in factor and enrollment steps are accepted only
  while their action is in `next_actions`; otherwise `409 unexpected_step`
  (AUT-002, AUT-004). `security.mfa_floor.admin_phishing_resistant` and the
  realm's `mfa.admin_phishing_resistant` fail closed: realm policies that
  leave passkeys disabled are refused (`422`), a production server does not
  start with the floor when it provides no passkeys, and `identity-cli doctor`
  warns about realms already in that state (MFA-005). Affected: every
  earlier 0.2.0 prerelease; regression tests `TestPasskeys`,
  `TestPhishingResistantUpgradeFromUnverifiedPasskey`,
  `TestFactorPolicyLeavesNoDeadEnd`.
- Organization role grants made outside the role routes need an MFA session
  (MFA-003, TEN-008, TEN-013) unless the realm waives it with
  `mfa.org_admin_mfa_optional`: adding a member with any role besides
  `member`; creating or reassigning an invitation, or a batch, that offers such
  a role or any project role; adding a member to a group that grants roles
  directly or through its ancestors; moving a group under such a parent; and
  setting a dynamic rule on such a group. A password-only organization
  administrator could grant the admin role this way; single-factor sessions
  now get `403 mfa_required`. Affected: every earlier 0.2.0 prerelease;
  regression test `TestOrgAuthorityGrantsNeedMFA`.
- Relationship (ReBAC) decisions and `list-objects` apply the same tenant
  eligibility as RBAC (AZ-007, AZ-010, AZ-021): nothing matches when the
  organization is not `active`, a membership stops counting once `expires_at`
  passes (before the expiry sweep), a rule-derived group membership counts
  only while its dynamic group is fresh and without rule error, and a service
  principal only while active and allowed in the organization. Affected:
  every earlier 0.2.0 prerelease; regression test
  `TestRelationshipTenantEligibility`.
- An organization-scoped connection's just-in-time accounts get their
  upstream email verified only inside the organization's verified domains;
  elsewhere the address stays unverified behind `verify_email`, or is dropped
  when another account has verified it. Organization administrators can
  enable `jit_provisioning` only with a non-empty `config.allowed_email_domains`
  made of the organization's verified domains (`422` otherwise). The `google`
  adapter believes `email_verified` only for `gmail.com` and `googlemail.com`
  addresses or when the `hd` claim equals the address's domain (REG-009,
  TEN-007, TEN-010, TEN-011, FED-002, FED-004). After upgrading, run the query
  in [incidents.md](docs/operations/incidents.md) to review accounts created
  by earlier alphas. Affected: every earlier 0.2.0 prerelease; regression
  tests `TestOrganizationJITEmailVerification`,
  `TestOrganizationJITConnectionDomains`, `TestGoogleAdapterEmailAuthority`.
- The egress policy refuses zoned IPv6 literals (`fc00::%0`, `fe80::1%eth0`)
  under the public-only rule and compares every blocked range without the
  zone: `netip` prefixes never contain a zoned address, so such a literal
  passed every blocked range and counted as global unicast, which let an
  administrator-supplied webhook, hook, federation or provisioning URL name a
  private or loopback destination (SEC-007; found by `FuzzAllowed` in CI).
  Zoned addresses stay reachable only with `allow_private_network` or an
  explicit allowed CIDR. Affected: every earlier 0.2.0 prerelease; regression
  test `TestAllowedRefusesZonedAddresses`.
- `deploy/prod` trusts the stack's own Docker network as the reverse proxy by
  default (`NETWORK_SUBNET`, `172.30.0.0/24`), so client addresses behind the
  required HTTPS proxy reach the per-address sign-in budgets and the audit
  records instead of every user sharing the gateway's address; the install
  guide gains a reverse-proxy section. In production, `X-Forwarded-For` from
  a peer outside `server.trusted_proxies` logs a warning once a minute, and
  `identity-cli doctor` warns when the list is empty (ABU-001, SEC-001,
  DEP-002). Affected: `deploy/prod` of every earlier 0.2.0 prerelease;
  regression test `TestUntrustedForwardedForWarnsOnceAMinute`.

### Fixed

- Scheduled signing-key rotation keeps each realm's algorithm, taken from its
  active key; it reverted every realm to `keys.signing_algorithm`, which broke
  resources pinned to ES256, PS256 or EdDSA and fapi2 clients after
  `keys.rotation_interval`. `KeyManager.Rotate` runs the rotation guards for
  every caller and refuses with `409` an algorithm that pinned business
  resources reject (`resources`) or that leaves fapi2 clients with a
  non-FAPI 2.0 algorithm (`clients`); a refused scheduled rotation is logged,
  counted and skipped while the other realms rotate. `POST
  /signing-key-rotations` without `algorithm` keeps the realm's algorithm,
  and a resource created without `signing_algorithm` pins it (TOK-005,
  TOK-012, ADV-001).
- SMTP delivery and the relay check run each session under a 30 s connection
  deadline, or the task's deadline if sooner, and close the connection when
  the worker task's context ends, so a relay or organization mail server that
  accepts connections and never answers cannot freeze the worker (TEN-022,
  MSG-012). Non-ASCII `Subject` and sender names are sent as RFC 2047 encoded
  words and non-ASCII body parts as quoted-printable (MSG-006).
- Password sign-in no longer lets a slow or unreachable LDAP/AD directory hold
  every database transaction slot (NFR-002, DB-014): `directory.sign_in_timeout`
  (8 s) bounds one attempt's directory work across every endpoint and JIT
  connector, `directory.max_concurrent_binds` (half the transaction slots)
  fails fast with `503 unavailable` and `Retry-After`, and password steps
  that may ask a directory are not retried after a deadlock, so a bind is
  never repeated. `security.password.max_concurrent_hashes` can bound Argon2id
  work the same way and is off by default. The two-phase password step that
  moves this work out of the transaction follows in 0.2.0-alpha.8.
- Factor-policy narrowing is applied before the MFA requirement: a TOTP the
  realm no longer allows does not force MFA, a passkey does not count while
  passkeys are disabled, `mfa.allowed_factors` lists without an enrollable
  second factor are refused, and a policy stored earlier in that state reports
  `mfa_enrollment_unavailable` instead of an empty `next_actions` (MFA-003,
  MFA-005).

### Known limitations

- Not independently reviewed or certified (SEC-018, QA-005); no OpenID
  Foundation conformance suite has been run.
- The Go and Node SDKs keep a retired or compromised signing key trusted until
  the verifying process restarts; after an emergency rotation, restart
  resource servers. SDK 0.3.0 adds key refresh and rejection.
- Administrators of different organizations inside one realm are not yet
  separated from each other everywhere: an organization's mail server, egress
  allowances, membership expiry and the approval rule on every grant path are
  tightened in 0.2.0-alpha.7 and alpha.8. Until then, treat organization
  administrator as a trusted role.
- Per-network abuse budgets key on the full IPv6 address and the token
  endpoint has one budget per client (0.2.0-alpha.6 changes both); the worker
  runs its tasks in one sequential loop (0.2.0-alpha.7 isolates them).

## [0.2.0-alpha.4] - 2026-10-15

### Changed

- The Docker quickstart offers two setups, development first: ProudAuth with
  PostgreSQL, Mailpit and Swagger UI on one machine, ready as is, then the
  production files. A test keeps both identical to `deploy/dev` and
  `deploy/prod` (DEP-002).
- `deploy/dev` runs the released image named in its `.env`, so its two files
  work without a checkout; Swagger UI reads the API contract from
  proudauth.com. `make dev` builds the checkout as `proudauth:dev` and runs the
  same stack on it.
- The README opens with the ProudAuth banner and badges.

### Fixed

- The administrator example used the reserved username `admin`, which
  `identity-cli bootstrap` refuses; it is now `owner`.
- `identity-bench` no longer sends a token in the last tenth of its lifetime
  (it waits for the renewal instead) and counts the lifetime from the token
  request, so a slow network does not turn renewals into `401`s. A refresh
  still running when the command ends is awaited before the credentials file
  is reported saved, so the file never keeps a spent refresh token.

## [0.2.0-alpha.3] - 2026-10-15

### Changed

- The project moved to the ProudAuth GitHub organization: the Go module is
  `github.com/proudauth/proudauth` (Go SDK `github.com/proudauth/proudauth-sdk-go`),
  release images are `ghcr.io/proudauth/proudauth`, and JSON Schema `$id`s and
  RFC 9457 problem types use `https://proudauth.com/`. Earlier images stay at
  `ghcr.io/proudbase/proudauth`; GitHub redirects the old repository links.

### Added

- `scripts/prepare-release.sh vX.Y.Z` prepares a release in one step: it moves
  every published version reference (the `deploy/prod/.env` image, install
  commands, guides) to the new version and turns the Unreleased notes into
  the version's CHANGELOG section (GOV-005).
- After publishing, the release workflow asks proudauth.com to redeploy when a
  `WEBSITES_DISPATCH_TOKEN` secret exists; without it, the site picks up the
  release within the hour.

### Changed

- The release workflow also refuses a tag that `docs/operations/docker-compose.md`
  does not name: the website publishes that guide as its quickstart.
- The install guide (the website's Docker quickstart) shows `docker-compose.yaml`
  and `.env` in full to copy, then `docker compose pull` and `up -d`; a test
  keeps them identical to `deploy/prod`. The production files carry short
  comments, and the README is a short overview with a three-step install.
- Release images carry `org.opencontainers.image.*` annotations on the
  multi-architecture index, so GitHub links the container package to this
  repository, and release notes end with the `docker pull` command and digest.

## [0.2.0-alpha.2] - 2026-10-15

### Added

- `deploy/dev/` and `deploy/prod/` run the same image from a `.env` file
  alone: `dev/` with PostgreSQL, a Mailpit mail catcher and Swagger UI, `prod/` with only the
  ProudAuth image for an existing PostgreSQL, HTTPS proxy and SMTP relay. Both
  apply migrations and create the default realm on every start (DEP-002).
- `PROUDAUTH_SMTP_USERNAME`, `PROUDAUTH_SMTP_PASSWORD` and
  `PROUDAUTH_HOST_POLICY` environment overrides.
- `identity-cli realm-create -if-missing` succeeds without changes when the
  realm exists, for unattended setup.

### Changed

- The release's Compose installer (`proudauth-<version>-compose.tar.gz`) is now
  `deploy/prod`: `docker-compose.yaml` and `.env` with the image pinned to the
  release, for your own PostgreSQL, HTTPS proxy and SMTP. Fill `.env`, then
  `docker compose up -d --wait`; no Python initializer or generated secret
  files. Separate schema-owner and runtime database roles (OPS-013) now need
  the YAML configuration (DEP-002, DEP-006).
- `make dev`, CI and `scripts/smoke-test.sh` use `deploy/dev`; CI runs the
  stack on the image it just built and scanned.
- The OpenAPI document opens with a one-line description; the shared API
  conventions moved to `docs/protocols/api-conventions.md`, the license is
  `Apache-2.0`, the server variable defaults to `http://localhost:8080` and tag
  descriptions no longer carry requirement IDs. Swagger UI in `deploy/dev`
  shows one page without the URL bar or schema list.
- A secret given directly in `PROUDAUTH_DATABASE_URL`, `PROUDAUTH_ROOT_KEY`
  or `PROUDAUTH_SMTP_PASSWORD` becomes the reference `env:<variable>`, so
  production accepts environment-only configuration while literal secrets in
  YAML files are still refused, and redacted exports show the variable name
  instead of the value (DEP-006).

### Removed

- `deploy/release/` (`init.sh`, `configure.py`, `init-database.sh`, the demo
  profile and its bundled PostgreSQL) and `deploy/compose/` (`init-secrets.sh`,
  `config.dev.yaml`), replaced by `deploy/prod/` and `deploy/dev/`.
- `deploy/config/production.example.yaml`. Environment variables configure
  the image; for settings that need YAML, the installation runbook points to
  `deploy/kubernetes/overlays/example/config.yaml` and the configuration
  reference.
- `PHASE1_VALIDATION.md`, an internal note from the repository migration.
- The `docker-deploy/` folder and its offline local-image profile
  (`init-env.sh`, `prepare-secrets.sh`, `start.sh`, `load-images.sh`,
  `config.yaml`, `config.tunnel.yaml`, its Compose file and the copied OpenAPI
  file). Use `deploy/dev/` instead; Swagger UI there reads `api/openapi/`
  directly.

## [0.2.0-alpha.1] - 2026-10-13

### Added

- First public pre-release under `proudbase/proudauth`: versioned Linux/macOS
  binaries, a multi-architecture Linux amd64/arm64 container image, source and
  per-platform image SBOMs, release checksums, keyless image signatures and
  GitHub build-provenance attestations (DEP-003, SEC-016, GOV-005).
- Source-free Docker Compose installer with complete adjacent `.env`
  documentation, production HTTPS/SMTP and loopback-only demo profiles,
  stable file-backed keys, PostgreSQL 18.6, separated migration/runtime roles
  and one-time administrator bootstrap (DEP-002, DEP-004, DEP-006, OPS-013).
- Independent public Go, Node/TypeScript, Dart, PHP and .NET SDK repositories,
  with standalone CI and a pinned Go SDK dependency. Project information and
  documentation are maintained separately in `proudauth-website`.
- Measured laptop capacity/adversarial/soak and restore evidence carried into
  the public service repository with explicit build provenance and sizing
  caveats (NFR-003..NFR-008, DEP-019, OPS-007).

### Changed

- Go module path is now `github.com/proudbase/proudauth`; applications import
  Go SDK packages from `github.com/proudbase/proudauth-sdk-go`. SDK source no
  longer ships inside the service tree; package/registry publication remains
  distinct from repository publication.
- Release publication reuses successful main CI only for the exact tagged
  commit, otherwise running the full reusable CI before publishing.
- GitHub Container Registry is the automated organization-owned registry;
  the Docker Hub mirror is published separately by the maintainer.

### Fixed

- Deployment initialization rejects accidental public demo bindings, mismatched
  demo issuer ports, globally trusted proxy ranges and invalid pool capacity.
  Repeated initialization preserves credentials and mounted secret inodes.
- Offline and Compose release archives exclude generated environment files,
  secret directories, installed configuration and initializer locks.

This is a pre-release, with no completed external security review or conformance
certification. Existing benchmark numbers describe their recorded development
builds and are not guarantees for this release.

## Earlier development history

Changes made before the first prerelease, 0.2.0-alpha.1, are kept in
[docs/history/CHANGELOG-pre-0.2.0.md](docs/history/CHANGELOG-pre-0.2.0.md).

[Unreleased]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.5...main
[0.2.0-alpha.5]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.4...v0.2.0-alpha.5
[0.2.0-alpha.4]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.3...v0.2.0-alpha.4
[0.2.0-alpha.3]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.2...v0.2.0-alpha.3
[0.2.0-alpha.2]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.1...v0.2.0-alpha.2
[0.2.0-alpha.1]: https://github.com/proudauth/proudauth/releases/tag/v0.2.0-alpha.1
