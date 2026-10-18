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

- Reference measurements of the four core token flows on the alpha.6 budget
  chain, against the alpha.5 baselines of the same day: throughput between
  2.5 and 7.8 percent lower, inside the phase's ten-percent gate, with the
  cost of the new pre-authentication budget statement visible in p99
  ([benchmarks.md](docs/operations/benchmarks.md#alpha6-budget-chain-comparison-nfr-003-nfr-008),
  `docs/operations/bench-results/2026-10-18-laptop-alpha6-budgets/`).
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
- Migration `0090_dcr_reviewed_version.sql` adds the nullable
  `client_registrations.reviewed_version` (the client version an approval
  reviewed) and `requeued_at` (when a change returned the registration to
  review); an expand migration that older binaries ignore. `POST
  /client-registrations/{client}/approve` takes `{"reviewed_version": N}`
  and `GET /client-registrations` lists, per registration, the client
  `version` and `client_state`, `post_logout_redirect_uris`, `grant_types`,
  `client_uri`, `logo_uri`, `policy_uri`, `tos_uri`, `reviewed_version` and
  `requeued_at` (APP-016, APP-017, API-010;
  [dynamic-client-registration.md](docs/integrations/dynamic-client-registration.md#approval)).
- Authorization codes bound to a DPoP key (RFC 9449 §10): the authorization
  endpoint, pushed authorization requests and the headless transaction API
  accept `dpop_jkt`, the JWK SHA-256 thumbprint of a DPoP key (43 base64url
  characters; anything else is `invalid_request`), and the PAR endpoint
  verifies a `DPoP` header and binds the code to its key as if it were named
  in `dpop_jkt` (RFC 9449 §10.1; a `dpop_jkt` naming another key is `400
  invalid_request`). Such a code is redeemed only with a DPoP proof of that
  key: another key or none is `400 invalid_grant`, and, as for the other
  code binding failures, the code is spent and its grant revoked. Codes
  without `dpop_jkt` are unchanged and discovery advertises nothing new.
  Migration `0089_refresh_family_binding.sql` (expand only, nullable columns
  without a default) adds `authorization_codes.dpop_jkt` and the
  `refresh_families.cnf_jkt` and `cnf_x5t_s256` columns of the refresh
  binding under Security; older binaries in the mixed-version window neither
  store nor check either binding
  ([upgrades.md](docs/operations/upgrades.md#mixed-version-window)). The
  OpenAPI document lists `dpop_jkt` and the PAR `DPoP` header (TOK-019, owner
  decision 13 of the [alpha.6 decisions](docs/releases/2026-10-alpha.6-decisions.md)).
  Regression tests `TestDPoPBoundAuthorizationCodes`, `TestValidJKT`,
  `TestParseAuthorize`.
- The consecutive second-factor failure ceiling of
  [owner decision 10](docs/releases/2026-10-alpha.6-decisions.md) (see
  Security): migration `0088_second_factor_failures.sql` (expand only, a new
  table), the configuration keys `security.second_factor.failure_backoff_after`
  (default `10`), `failure_backoff_max` (`1h`), `failure_notice_at` (`20`) and
  `failure_disable_at` (`100`), the mandatory notification template
  `second_factor_failures` (variables `realm`, `count`, `time`), the problem
  code `code_factors_disabled` (`403`), the audit events
  `mfa.code_factors.failure_notice`, `.disabled` and `.restored`, and
  `second_factor_failures` in `GET /users/{user}`
  ([configuration.md](docs/operations/configuration.md#security)).
- Configuration keys `security.rate_limits.join_requests_per_user` (default
  `10`), `join_requests_per_organization` (default `100`) and
  `join_request_window` (default `24h`) for the join-request budgets
  (INV-013, REG-012, TEN-018); `0` disables a budget, and a zero window also
  turns the reviewer-notice de-duplication off. Validation refuses negative
  values and a positive limit with a zero window, as for the other
  `rate_limits` keys ([configuration.md](docs/operations/configuration.md)).
  Regression test `TestValidateRateLimits`.
- The network-normalized abuse budgets and the known-device quota of
  [owner decision 9](docs/releases/2026-10-alpha.6-decisions.md) (see
  Security): migration `0091_known_device_quota.sql` (expand only, a new
  table `known_sign_ins` of keyed digests that the worker's retention task
  sweeps), the configuration keys `security.rate_limits.start_per_network`
  (default `300` per `login_window`), `network_coarse_factor` (`10`, at most
  `1000`), `known_quota_days` (`30`, at most `365`),
  `known_login_per_network` (`50`), `known_login_per_device` (`20`) and
  `known_login_per_identifier` (`10`), each `0` to disable, and the gauge
  `proudauth_rate_budget_utilization{budget}` over the fixed aggregate
  budget families, for an alert near the cap
  ([monitoring.md](docs/operations/monitoring.md#metrics)). Load generators
  raise `start_per_network` along with `login_per_ip`
  ([benchmarks.md](docs/operations/benchmarks.md)). Regression tests
  `TestNetworkBudgetConfig`, `TestGaugeVecFixedLabels`.
- The protocol-endpoint budgets of
  [owner decision 9](docs/releases/2026-10-alpha.6-decisions.md) (see
  Security): the configuration keys
  `security.rate_limits.token_failures_per_network` (default `300` failed
  token requests per network per `token_window`),
  `token_per_network_client` (`100` failed grants per network per public
  client per `token_window`), `par_failures_per_network` (`300` failed
  pushed requests per network per `token_window`), `par_per_client` (`2000`
  per public client per `token_window`), `device_per_network` (`300` per
  `login_window`), `user_code_failures_per_network` (`30` per
  `login_window`), `dcr_per_network` (`20`) and `dcr_window` (`1h`), each
  `0` to disable, validated like the other `rate_limits` keys (a positive
  limit needs a positive window); every per-network one also counts the wider
  /24 or /48 at `network_coarse_factor` times its limit. The aggregate family
  `par-client` joins `proudauth_rate_budget_utilization{budget}`
  ([monitoring.md](docs/operations/monitoring.md#metrics)).
  `scripts/bench-local.sh` raises every budget a benchmark workload can trip
  to 1000000: the four it raised before, `start_per_network` and these
  (`BENCH_*` variables override each), and records them in
  `environment.json` ([benchmarks.md](docs/operations/benchmarks.md)).
  Regression tests `TestProtocolEndpointBudgetConfig`,
  `TestValidateRateLimits`, `TestUtilizationOfAggregateBudgets`,
  `TestCheckConsumesNothing`, `TestFailedRequestClassification`.
- The configuration key `security.rate_limits.api_token_failures_per_network`
  (default `300` support tokens presented to the identity and administration
  APIs per network per `token_window`, with the wider /24 or /48 at
  `network_coarse_factor` times; `0` disables it), validated like the other
  `rate_limits` keys (see Security). The counter
  `proudauth_metrics_series_dropped_total{metric}`, one series per counter
  and histogram, `0` until it drops an update at its series cap, with a
  suggested alert ([monitoring.md](docs/operations/monitoring.md)); see
  Fixed. Regression tests `TestProtocolEndpointBudgetConfig`,
  `TestValidateRateLimits`, `TestDroppedSeriesCounted`.

### Changed

- `security.rate_limits.token_per_client` defaults to `2000` token requests
  per client per minute instead of `600`, consistent with `login_per_client`
  (20000 sign-ins per 15 minutes, about 1333 a minute, so a busy client no
  longer signs users in faster than it can exchange their codes), and for a
  public client it counts only failed grants: `invalid_client`,
  `invalid_request`, `invalid_grant`, `invalid_scope`, `invalid_target`,
  `unauthorized_client`, `unsupported_grant_type` and `invalid_dpop_proof`
  from a request whose client is identified, not its successful grants,
  device-flow polling answers, budget refusals or server errors
  ([decision 9](docs/releases/2026-10-alpha.6-decisions.md); REG-012,
  SEC-006). A confidential client's budget counts every request, as before.
  Once a public client's failed grants spend it, every token request of the
  client answers `429 slow_down` until the window ends. Migration: a
  configuration that sets `token_per_client` keeps its value, which now caps
  only the failed grants of public clients. The new per-network budgets of
  the token endpoint and PAR count failures only, so a confidential
  client's backend sending many successful requests from one address is not
  refused by them; a network whose requests fail more than
  `token_failures_per_network` times a minute is refused for every client
  until the window ends ([configuration.md](docs/operations/configuration.md),
  [upgrades.md](docs/operations/upgrades.md)). Regression tests
  `TestPublicClientTokenBudgetCountsFailedGrants`,
  `TestProtocolEndpointBudgetConfig`.
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
- JWT-secured authorization responses (JARM) carry `typ`
  `oauth-authz-resp+jwt` and signed UserInfo responses `typ` `userinfo+jwt`
  instead of `JWT`; ID tokens keep `JWT`, and a nested JWE keeps `cty` `JWT`
  (ADV-002, OIDC-013,
  [response-security.md](docs/protocols/response-security.md)). A
  `private_key_jwt` client assertion's `aud` must be the realm's issuer as a
  single JSON string in every realm; the token endpoint URL (or the URL of
  whichever endpoint receives the assertion) and arrays, also
  `["<issuer>"]`, are refused with `401 invalid_client` (APP-009, MCH-010,
  [decision 16](docs/releases/2026-10-alpha.6-decisions.md)). A `GET
  /oidc/logout` from a browser with a session whose `id_token_hint` names
  another session or user answers `400 invalid_request` instead of `200`
  with `session_ended: false` (SES-016, decision 15). All three follow from
  the security fixes below.
  **Migration:** a relying party that checks the `typ` of a JARM or signed
  UserInfo response accepts the new values; none of the five ProudAuth SDKs
  verifies JARM or signed UserInfo responses, so no first-party verifier
  changes. A `private_key_jwt` client that sends the token endpoint URL or an
  array as `aud` switches to `"aud": "<issuer>"` (the `issuer` of the realm's
  discovery document); until it can, set the realm policy
  `client_auth.allow_endpoint_audience: true` (`PUT /settings` or a
  configuration document), which re-admits what earlier versions accepted for
  every client but `fapi2` ones, and turn it off once the clients are
  updated. No ProudAuth SDK creates client assertions. A relying party that
  logs users out with a `GET` and a hint from another session uses that
  session's ID token or `POST`.
- `POST /client-registrations/{client}/approve` requires `reviewed_version`,
  the client version that was reviewed: `422` without it, `409` when the
  client is at another version (APP-017, decision 14). **Migration:** read
  `version` from `GET /client-registrations` with the metadata being
  reviewed and send it; after a `409`, list and review again.

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
- Imported salted SHA-256 verifiers (`$legacy-sha256$`) are checked against
  the password as typed first and then against its NFKC form, as imported
  Argon2id, bcrypt and PBKDF2 verifiers are. They were checked only as
  `sha256(salt || NFKC(password))`, while the import schema's example, the
  migration guides and the benchmark seeder describe
  `sha256(salt || password)` over the typed input, so a migrated user whose
  password NFKC normalization changes (full-width or compatibility
  characters, ligatures, decomposed accents) could never sign in with it. A
  match is still rehashed to Argon2id. The `password_hash` description in
  `api/schemas/user-import.schema.json` now gives the format as
  `sha256(salt || password)` (MIG-006, CRED-003, CRED-004,
  [exit-and-export.md](docs/operations/exit-and-export.md#user-import-request)).
  Affected: every earlier 0.2.0 prerelease; regression test
  `TestLegacySHA256TypedPassword`.
- `proudauth_tokens_total` no longer takes label values from the request
  (finding `httpapi-surface/metrics-silent-drops`, parts 1 and 2). Its
  `grant_type` label was the request's raw `grant_type` (up to 64
  characters), counted even when client authentication failed, so an
  unauthenticated caller could fill the counter's 1000-series cap with junk,
  after which every new legitimate series was dropped, silently, until a
  restart. `grant_type` is now one of the six grants the endpoint implements
  or `other`, and `outcome` is `success`, one of the known OAuth error codes
  or `other`, at most 7 × 19 series. Updates that a counter (1000 series) or
  histogram (500) drops at its cap are now counted in the new
  `proudauth_metrics_series_dropped_total{metric}`, and the first one of each
  metric logs a warning ([monitoring.md](docs/operations/monitoring.md#metrics))
  (OPS-002, SEC-006). Affected: every earlier 0.2.0 prerelease; regression
  tests `TestTokenMetricFixedLabels`, `TestDroppedSeriesCounted`.

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
- A JARM response or a signed UserInfo response no longer passes as
  `id_token_hint` at the logout endpoint. Both were signed with the realm key
  and typed `JWT` like ID tokens, and the hint check verified only the
  signature, `typ` (an absent one too) and `iss`. Anyone could obtain a
  signed JARM error response without credentials, from a valid `client_id`
  and registered `redirect_uri` with `response_mode=jwt` and no PKCE, and by
  luring a browser to `GET /oidc/logout?id_token_hint=<it>` end its SSO
  session, with front- and back-channel logout to the clients: the response
  has no `sid`, so the cookie session was the one revoked. JARM responses
  are now typed `oauth-authz-resp+jwt` and signed UserInfo `userinfo+jwt`;
  a hint must be typed `JWT` and have the shape of an ID token (`sub`, `aud`,
  `exp` and `iat`, none of `code`, `error` and `state`), which also refuses
  responses signed by earlier versions; and a `GET` ends the cookie session
  only when the hint's `sid` is that session or its `sub` is the session
  user's subject at the hint's client, otherwise it answers `400
  invalid_request` and leaves the session alone
  ([decision 15](docs/releases/2026-10-alpha.6-decisions.md)); `POST` keeps
  its rules. A client `id_token_claims` mapping named `code`, `error` or
  `state` is left out of ID tokens, so ID tokens always pass the shape check
  (SES-016, ADV-002, OIDC-013, TOK-015,
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#logout)).
  Affected: every earlier 0.2.0 prerelease; regression tests
  `TestLogoutHintTypes`, `TestIDTokenHintTypes`,
  `TestIDTokenLeavesOutAuthorizationResponseMembers`, and `typ` assertions
  in `TestJARM` and `TestEncryptedResponses`.
- `private_key_jwt` client assertions must name the realm's issuer as their
  only audience, as a single JSON string, for every client including `fapi2`
  ones. `aud` could be an array of one or two values, each the issuer or the
  URL of the endpoint receiving the assertion; the FAPI 2.0 Security Profile
  and RFC 7523bis accept only the issuer, because endpoint-URL audiences
  allow the audience-injection attack published in 2025: an authorization
  server that advertises another server's endpoint URL as its own gets
  assertions from a shared client that the other server accepts. The check
  reads the raw `aud` claim, since a JWT library decodes `"aud": "x"` and
  `"aud": ["x"]` alike. The new realm policy
  `client_auth.allow_endpoint_audience` (default `false`) re-admits the old
  forms for clients other than `fapi2` ones
  ([decision 16](docs/releases/2026-10-alpha.6-decisions.md); APP-009,
  MCH-010, ADV-001,
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#clients)).
  Affected: every earlier 0.2.0 prerelease; regression tests
  `TestPrivateKeyJWT`, `TestFAPI2Profile`, `TestAssertionAudience`.
- Dynamic client registration: where a registration requires approval (open
  registration, or `client_registration.require_approval`), the registrant's
  RFC 7592 `PUT` changing `client_name`, `redirect_uris`,
  `post_logout_redirect_uris`, `grant_types`, `client_uri`, `logo_uri`,
  `policy_uri` or `tos_uri` now returns an approved registration to
  `pending` and suspends the client in the same transaction (refresh tokens,
  grants and opaque access tokens end; token requests fail with `401
  invalid_client` until approved). Before, the client stayed approved and
  active, so a registrant could pass review with harmless branding and
  redirects and then present another name, logo or redirect at consent
  (consent phishing), and administrators could not see the change:
  `client.registration.updated` now records each changed field's values
  before and after (lists bounded at 20 entries), whether it re-queued, and
  `secret_rotated`, which the audit redaction used to hide. An approval
  names the client version reviewed and is refused with `409` when the
  client changed since, including changes made while under review; the
  approved version is kept as `reviewed_version`. Lists compare as sets; a
  secret rotation or an update of other metadata does not re-queue, and
  realms without approval are unchanged (APP-016, APP-017, ADV-003, APP-008,
  API-010; [decision 14](docs/releases/2026-10-alpha.6-decisions.md)).
  Affected: every earlier 0.2.0 prerelease; regression tests
  `TestDynamicRegistrationReapproval`, `TestReviewedChanges`.
- Refresh tokens are bound to the sender of their first issuance (owner
  decision 13 of the [alpha.6 decisions](docs/releases/2026-10-alpha.6-decisions.md)).
  A refresh token family issued with a DPoP proof or with a
  certificate-bound access token (RFC 8705) stores the proof key's JWK
  thumbprint or the certificate's SHA-256 thumbprint
  (`refresh_families.cnf_jkt`, `cnf_x5t_s256`, migration `0089`), and every
  refresh must prove the same key or certificate, whatever the client's
  `require_dpop` or certificate setting says, now or later: a proof from
  another key, another certificate or none is `400 invalid_grant`. Until
  now only access tokens were sender-constrained, against RFC 9449 §5, so
  anyone holding a stolen refresh token of a DPoP-bound single-page or
  native application could redeem it with a DPoP key of their own and, when
  the client lacked `require_dpop`, with no proof at all, for a bearer
  token. The refusal is checked before reuse detection and is not a reuse
  signal: it neither rotates the token nor compromises the family, so a
  stolen token without its key cannot be used to revoke the holder's
  family, grant and session; it is audited as `token.refresh.binding_failed`
  (reason `REFRESH_BINDING_FAILED`). Rotation keeps the family's binding,
  `fapi2` refresh tokens included. Families issued before the upgrade, and
  bearer families, keep refreshing as before until they expire. DPoP nonces
  remain unsupported (issue #37) (TOK-019, SES-006, TEST-067,
  [ADR 0011](docs/architecture-decisions/0011-refresh-token-families.md)).
  Affected: every earlier 0.2.0 prerelease; regression tests
  `TestSenderBoundRefreshFamilies`, `TestSenderBindingRefusal`.
- Support impersonation re-checks the target exclusions (IMP-015) when a
  request is approved, when the grant is issued and on every introspection
  of a support token, not only when the request is made: the target must
  still be active and not `protected`, hold no privileged realm role and not
  hold `org.roles.assign`, `org.ownership.transfer` or `org.members.write`
  in the organization. A target promoted to realm or organization
  administrator after the request could be issued a grant (requests live up
  to 15 minutes) and impersonated until it expired (up to 5 minutes);
  issuance and approval now answer `403 impersonation_denied` and the
  token's introspection `active: false` (IMP-010). Assigning a role still
  revokes no request or grant; the grant stays `active` in the inventory
  until it expires ([impersonation.md](docs/threat-models/impersonation.md#flow-and-checks),
  steps 3 to 5). Affected: every earlier 0.2.0 prerelease; regression tests
  `TestImpersonationDenials` ("TEST-041 targets promoted after the
  request", TEST-041) and `TestCustomerApprovedSupportAccess`.
- Identified sign-ins no longer reveal through passkey options or response
  times whether an account or its passkeys exist (SEC-005, PASS-003).
  `webauthn/options` after `identify` lists the account's passkeys without
  their stored transports, and the decoy for an unknown identifier or an
  account without passkeys has one to three credential IDs of common lengths
  (16 to 64 bytes), all derived from a keyed hash of the identifier; it was
  always one 32-byte ID with the transports `internal` and `hybrid`, so the
  number of entries, the transports or the ID length told a real list apart.
  An account with more than three passkeys is still recognizable by the
  count. `otp/send` with purpose `login` (email or SMS) or `magic_link` is
  padded to `security.min_auth_response` like the password step and reset
  requests; only known accounts had the message rendered, encrypted and
  queued, unpadded
  ([headless-authentication.md](docs/protocols/headless-authentication.md#enumeration-resistance)).
  Affected: every earlier 0.2.0 prerelease; regression tests `TestPasskeys`
  ("identified allow lists reveal no passkeys") and
  `TestIdentifierProbeResponses` ("sign-in code and magic-link sends are
  padded").
- Second factors that are codes now have a ceiling across budget windows.
  TOTP, HOTP and recovery codes, and emailed or texted sign-in codes, shared
  only fixed-window budgets (10 proofs per account per 15 minutes, 5 per
  transaction), so someone who knew the password could make about 960 TOTP
  guesses a day, about 8.6% success within a month with the default
  ±1 step, and failed proofs were only audited. A persistent
  per-account count of consecutive failures (`second_factor_failures`,
  migration `0088`) now grows across windows: from 10 failures every TOTP,
  HOTP or recovery-code step waits 2 s after the last failure, doubling up
  to 1 hour (`429 rate_limited` with `Retry-After`); at 20 the owner
  receives one mandatory `second_factor_failures` notice
  (`mfa.code_factors.failure_notice`); at 100 the account's code factors are
  turned off (`403 code_factors_disabled`, `mfa.code_factors.disabled`; no
  sign-in code is sent, and a code is refused exactly as for an unknown
  address). Passkeys never count and are never blocked; a passkey sign-in,
  a completed password reset from the account's email address and an
  assisted recovery turn code factors back on, and any successful TOTP, HOTP,
  recovery-code or passkey proof or completed sign-in resets the count, never
  a correct password alone, so an attacker cannot cause a permanent lockout.
  Administrators see the state in `GET /users/{user}`
  ([owner decision 10](docs/releases/2026-10-alpha.6-decisions.md);
  SEC-006, MFA-002, MFA-012, TEST-021,
  [headless-authentication.md](docs/protocols/headless-authentication.md#consecutive-code-factor-failures),
  [account-recovery.md](docs/operations/account-recovery.md#code-factors-turned-off-after-repeated-failures)).
  Affected: every earlier 0.2.0 prerelease; regression tests
  `TestSecondFactorFailureNotice`, `TestSecondFactorBackoff`,
  `TestSecondFactorCeiling`.
- The current password of a self-service password change
  (`POST /me/password`) is checked under the account's sign-in password lock
  (`security.rate_limits.failures_before_lock`, `temporary_lock`): a wrong one
  counts against the same budget as a wrong sign-in password, and once it is
  spent the change answers `429 rate_limited` without checking the password
  and password sign-in to the account is locked as well, until the window
  ends. A recently authenticated session could guess the current password
  without any bound. The refusals' `credential.password.change_failed`
  evidence, which the rolled-back transaction used to discard, is now kept
  (owner decision 10; CRED-006, SEC-006). Affected: every earlier 0.2.0
  prerelease; regression test `TestChangePasswordUnderSignInLock`.
- Join requests have abuse budgets. `POST /organizations/{org}/join-requests`
  spends the requester's budget across the realm
  (`security.rate_limits.join_requests_per_user`, 10 by default) and then the
  organization's (`join_requests_per_organization`, 100) per
  `join_request_window` (`24h`); an exhausted budget answers `429
  rate_limited` with `Retry-After` and writes no audit event, and withdrawing
  a request refunds neither. A request the requester's budget refuses does not
  count toward the organization's, so one account cannot use up an
  organization's budget for everyone else. A user's repeat request to the same
  organization within the window is still recorded and audited
  (`organization.join_request.created`, with `reviewer_notice:
  suppressed_repeat`) but no longer notifies the reviewers again. Join
  requests had no budget: any signed-in user of the realm could request to
  join an organization that accepts join requests, withdraw at once and
  request again without limit, and every request emailed up to 20 reviewers
  and wrote membership, audit and outbox rows, where invitations were already
  capped (REG-012, TEN-018, INV-013). Affected: every earlier 0.2.0
  prerelease; regression tests `TestJoinRequestBudgets`,
  `TestJoinRequestReviewerNotices`.
- Abuse budgets count networks instead of addresses, and an exhausted
  aggregate sign-in budget no longer refuses everyone
  ([decision 9](docs/releases/2026-10-alpha.6-decisions.md)). The per-IP
  budgets (`login-ip`, `pwd-ip`, `verify-ip`, `send-ip`, `signup-ip`,
  `guest-ip`, `wan-ip`, `setup-ip`, and the fixed `dcr-ip`, registry,
  shared-signals and check-session budgets) were keyed by the full client
  address, each step was charged to the address its transaction started
  from, and starting a transaction had no budget. With one IPv6 /64, an
  attacker started every attempt from a new address with random identifiers
  and passed every per-IP and per-identifier limit, leaving only the
  aggregate caps, which then failed for everyone: about 22 requests per
  second through one public client used up `pwd-client` (20000 per 15
  minutes) and refused every password sign-in through that client, and
  about 55 per second through three clients did the same for `pwd-realm`
  across the realm, window after window. A network is now an IPv4 /32 or an
  IPv6 /64; every configurable per-network budget also counts the wider /24
  or /48 at `network_coarse_factor` times its limit; each step is charged to
  the network of the request that makes it; and starting a transaction is
  budgeted per network (`start_per_network`; a start that reuses an SSO
  session is not counted, and the browser authorization endpoint redirects
  with `error=temporarily_unavailable`). When an aggregate password or proof
  budget (per client, organization or realm) is exhausted, networks,
  remembered devices and identifiers with a successful sign-in in the last
  `known_quota_days` keep a quota of their own; everyone else gets
  `429 rate_limited` with `Retry-After`, with no CAPTCHA and no
  proof-of-work. An identifier counts only from the /24 or /48 it signed in
  from, so outside it the `429` still does not tell recently active accounts
  from others (SEC-005, API-009). Aggregate send and registration budgets
  have no such quota (SEC-006, ABU-001, REG-012, TEN-018, SEC-001).
  Affected: every earlier 0.2.0 prerelease; regression tests
  `TestNetworkNormalizedBudgets`, `TestTransactionStartBudget`,
  `TestKnownDeviceQuota`, `TestPerNetworkBudgets`,
  `TestUtilizationOfAggregateBudgets`, `TestNetworkPrefix`.
- The token endpoint and PAR bound the failed requests of each network,
  checked before the client is authenticated, device authorization counts
  every request per network, and one network can no longer put every user of
  a public client into `429`
  ([decision 9](docs/releases/2026-10-alpha.6-decisions.md); finding
  `core-oauth-oidc/token-endpoint-rate-limit`). The token endpoint had one
  budget, `token_per_client` (600 per minute), checked after client
  authentication and counting every request, failed ones included. A public
  client authenticates with its `client_id` alone, so one unauthenticated
  sender at about 10 requests per second (bad `code` or `refresh_token`
  values) put every user of an SPA or native app into `429 slow_down`,
  window after window: cheap denial of service for code exchange and
  refresh. Each failing client authentication also wrote an audit record
  without any per-network bound. PAR, device authorization, the device
  approval's user-code entry and the per-network budget of dynamic client
  registration (fixed in code) had no configurable per-network budget. Now
  every token request first reads its network's failure budget
  (`token_failures_per_network`: decision 9's 300 per minute per IPv4
  address or IPv6 /64, which bounds failures, with the wider /24 or /48 at
  `network_coarse_factor` times), before client credentials are read or
  checked and before anything is audited, and a network that has spent it
  is refused; a failed client authentication or failed grant counts against
  it, a successful request never does, so a confidential client's backend
  or a busy NAT is not throttled for its volume while a flood of junk
  client IDs, wrong secrets, bad codes or stolen tokens from one network is
  cut off before client authentication. A public client's budget counts only
  failed grants, and each network's failed grants through it are bounded by
  `token_per_network_client` (100 per minute), past which that network is
  refused before its grant runs and stops counting against the client, so
  spending a public client's budget takes many networks. PAR keeps the same
  failure budget per network (`par_failures_per_network`) and counts a
  public client's pushes against `par_per_client`; device authorization,
  which stores a row per request, counts every request against
  `device_per_network`; user-code lookups that
  find no pending code against `user_code_failures_per_network` (30 per 15
  minutes), after which the network's lookups answer `429 rate_limited`
  before any code is looked up; dynamic client registration against
  `dcr_per_network` per `dcr_window`. The browser authorization endpoint and
  the headless start write a row only by starting a transaction, which
  `start_per_network` already counts, so they gain no second budget. Spent
  protocol budgets answer `429 slow_down` with `Retry-After` in the OAuth
  error format, and every new budget fails closed (`503
  temporarily_unavailable`) when the limiter is unreachable. No CAPTCHA and
  no proof-of-work: someone holding many networks can still spend a public
  client's failure budget, and the aggregate caps then refuse everyone until
  the window ends (SEC-006, REG-012, TEN-018, ABU-001, TOK-001, APP-016,
  SEC-001). Affected: every earlier 0.2.0 prerelease; regression tests
  `TestTokenEndpointNetworkBudgets`,
  `TestPublicClientTokenBudgetCountsFailedGrants`,
  `TestPARAndDeviceNetworkBudgets`,
  `TestDynamicClientRegistrationNetworkBudget`,
  `TestTokenEndpointLimiterFailsClosed`, `TestCheckConsumesNothing`,
  `TestFailedRequestClassification`.
- Unauthenticated requests can no longer write unbounded audit records
  (finding `httpapi-surface/unauth-audit-amplification`). Every failed client
  authentication at the token endpoint recorded `client.authentication.failed`
  with the presented `client_id` or Basic user name as `actor_id`, stored
  unbounded (up to the 256 KiB body or the 16 KiB header) in an indexed column
  for 400 days; an incompressible one past the index row limit (about 2.7 KB)
  made the insert fail and raised a false `audit_write_failed` signal. Every
  bearer starting with `pa_it_` on the identity and administration APIs cost a
  token lookup and a `support.token.rejected` record, with no budget, and
  introspection and revocation had no budget at all. Now audit records store
  actor, subject and target IDs as at most 128 printable bytes, followed by
  `~` and 16 hexadecimal digits of the SHA-256 of the whole value when
  anything was cut or dropped, so the same junk still correlates and control
  characters are never stored (identifiers ProudAuth issues are unchanged;
  audit searches by `actor_id`, `subject_id` and `target_id` bound their value
  the same way); a `client_id` longer than 255 bytes is `invalid_client`
  before it is looked up or audited and counts as a failed request;
  introspection and revocation read the token endpoint's failure budget per
  network (`token_failures_per_network`) before client authentication and
  count their failed client authentications against it, so once a network
  has spent it, its token, introspection and revocation requests get `429
  slow_down` and write no audit record; support tokens on the APIs count
  against the new `api_token_failures_per_network` (300 per `token_window`
  per network) before they are looked up, after which the network's get `429
  rate_limited` and write nothing, while its other bearer tokens are
  unaffected. Each budget fails closed. Within its budgets one network still
  writes up to about 300 records of each kind per minute
  ([threat model](docs/threat-models/system.md)) (SEC-006, AUD-001, AUD-014,
  IMP-012, ABU-001). Affected: every earlier 0.2.0 prerelease; regression
  tests `TestFailureBudgetsStopAuditAmplification`,
  `TestRecordBoundsIdentifiers`, `TestQueryFilterUsesBoundIdentifiers`,
  `TestOversizedClientIDRefusedBeforeAuthentication`,
  `TestAuthenticateRefusesOversizedClientID`,
  `TestTokenEndpointLimiterFailsClosed`.

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
