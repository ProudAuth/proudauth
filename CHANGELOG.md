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

### Added

- `internal/testutil` fault-injection helpers for reliability tests: a TCP
  black hole, silent and stalling SMTP relays, a refused port and a slow HTTP
  server.
- `docs/releases/` records the owner decisions taken at the start of each
  release phase, beginning with
  [0.2.0-alpha.5](docs/releases/2026-10-alpha.5-decisions.md).

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

## Historical development before 0.2.0-alpha.1

The entries below preserve evidence from development before repository
separation and the first public release. References to the private monorepo,
unpublished artifacts, local tunnels and embedded SDK paths describe that
historical setup; they are not current deployment instructions or release
claims. **Changed**, **Fixed** and **Security fixes** describe earlier development
behavior. No external security review (SEC-018) or certification (QA-006) was
completed for that work.

### Added

- **Public documentation website** (`docs-site`): complete source-derived guides,
  all OpenAPI operations, five SDK guides, full-text search, downloadable contracts
  and a read-only API explorer. `make docs-site` builds/checks offline with loaded
  images; `make docs-serve` retains the documentation, service overview and a
  sanitized live status page behind the existing Cloudflare tunnel. Deployment
  credentials and private source/seed files are excluded from publication.
- **Cloudflare Tunnel test profile** (`docker-deploy/config.tunnel.yaml`;
  DEP-002, DEP-004): `auth.proudauth.com` serves the public identity API
  through the existing host connector, with a canonical HTTPS issuer,
  strict hostname checking, Secure cookies and an explicit local proxy.
  Operator endpoints remain on loopback; development email
  remains private. The deployment README records activation and restart settings.
- **Standalone local image deployment** (`docker-deploy`; DEP-002,
  DEP-004): a PostgreSQL 18, server, worker and Swagger Compose stack using
  already loaded ARM64 images. Initialization generates a private `.env`,
  preserves existing credentials and provisions realm `main` once.
  [Local validation](docker-deploy/validation.md) covers the stack and .NET
  SDK interoperability with the running server.
- **.NET SDK** (`sdk/dotnet`, unpublished 0.2.0, .NET 8+; SDK-001..SDK-011):
  `ProudAuth.Sdk` implements offline verification (RS256, PS256, ES256,
  Ed25519), multi-issuer routing, introspection and audited support access,
  bounded revocation state, OIDC code + PKCE with ID-token validation,
  single-flight refresh and logout, and an administration client with
  cursor pagination, problem details and redacted one-time secrets.
  `ProudAuth.Sdk.AspNetCore` adds the authentication scheme and middleware.
  Shared token/support fixtures and Go signature vectors run in its test
  executable; CI is configured for .NET 8 on Linux, macOS and Windows.
  BouncyCastle.Cryptography 2.7.0 supplies Ed25519 and RSA-PSS verification.
  Fifteen manual live-server checks pass alongside the 342 SDK tests;
  the live checks are separate from CI. No NuGet publication is claimed.
- **Private source handoff** (GOV-005, SEC-016): the owner authorized
  committing/pushing the implementation and evidence while keeping the
  repository private. Public releases, tags and hosted signing/attestation
  are explicitly deferred. Host-built executables stay outside Git and the
  Docker build context; traceability evidence uses versioned source rather
  than generated TypeScript declarations. Frozen benchmark/tool outputs
  retain their original whitespace and checksums.
- **Local production-image and release preparation** (SEC-016, DEP-003,
  DEP-004, DEP-017, GOV-005):
  [Image/SBOM/package evidence](docs/operations/security-checks.md#local-image-and-release-preparation--2026-10-13)
  records passing TLS/read-only/non-root image checks, zero image OS-package
  vulnerability matches, all 12 stripped target builds, image/host binary
  equality and 582 verified offline-bundle files. Source/image SPDX SBOMs
  and exact hashes are retained; temporary resources are removed. Module-only
  OpenPGP findings are explicitly triaged. No official tag, upload,
  signature or trusted provenance attestation is claimed.
- **Current dependency and artifact checks** (QA-002, SEC-016, DEP-003):
  [Published results](docs/operations/security-checks.md#current-dependency-and-supply-chain-checks--2026-10-13)
  record zero reachable findings in Go source and all 12 release binary
  targets, zero npm advisories and zero final Staticcheck findings. The
  frozen official database and an unimported OpenPGP module-level finding
  have explicit provenance/triage. Eight workflow Actions and the Dockerfile
  frontend now use immutable references, guarded by contract checks.
- **Local SDK runtime evidence** (SDK-009, SDK-010, QA-002, QA-004):
  [Offline check results](docs/integrations/sdk-compatibility.md#local-sdk-checks--2026-10-13)
  publish passing Node.js 25.9.0 (116 tests), Dart 3.13.3 (216 tests) and
  PHP 8.5.8 (157 tests, 3078 assertions) profiles with source hashes,
  type/analyzer/format/lint checks and unchanged locks. Current Go 1.27.2
  SDK results come from the separate complete module check. Declared
  minimums, configured CI versions and measured local runtimes remain
  distinct; dependency vulnerability review and external assurance are open.
- **Offline two-OS binary reproduction** (M0, DEP-003, SEC-016):
  `make repro-local` freezes the Go build inputs and compares all 12 release
  targets between a host compiler and the pinned cached Linux image, using
  Go 1.27.2, separate caches, no downloads and no Linux network. A temporary
  host SDK is bootstrapped from cached source when needed. All 12 real binary
  pairs match byte-for-byte across two invocations; source/target hashes and
  scope limits are [published](docs/operations/security-checks.md#two-os-binary-reproduction--2026-10-13).
  Controlled regressions reject one changed output, incorrect SDK/version
  and unexpected caller flags while checking cleanup. This is one physical
  host; official release, image/archive and independent-machine reproduction
  remain unverified.
- **Controlled HTTPS metadata benchmark** (MCH-011, NFR-006, NFR-008):
  `metadata-fetch` alternates a valid workload grant with unknown-key,
  malformed/oversized JWKS, HTTP failure, redirect, timeout and live denied
  IPv6 profiles. The counts-only TLS source proves actual upstream contacts
  and unchanged cooldowns; assertions and private keys stay private. Included
  in `bench-local` and all 26 benchmark smoke scenarios, with strict refusal,
  TLS, response-size, cancellation and result-privacy regressions.
  [Published reference results](docs/operations/benchmarks.md#controlled-metadata-fetch-results-nfr-006-nfr-008)
  pass the full-seed cohosted 60-second/concurrency-32 profile with actual
  upstream spacing/counts, build/configuration hashes and latency caveats.
- **Metadata fetch regressions** (FED-017, MCH-011, ADV-004, ADV-007,
  NFR-006): concurrency-32 TLS bursts prove shared cold/expired/unknown-key
  fetches, negative-response cooldowns and recovery. Additional cases cover
  issuer mismatch, redirect, response size, timeout, DNS deadline, caller
  cancellation, cache invalidation and last-good workload fallback.
- **Compound audit filter benchmark** (NFR-004, NFR-006, NFR-008):
  `complex-audit-filter` owns public application reports in two seeded
  organizations and verifies eleven simultaneous search parameters, exact
  sequence pages and provenance, literal prefixes, typed network/time
  refusals and changed-filter cursor rejection. Included in `bench-local`
  and the complete benchmark smoke test; setup and reporter-token renewal
  are unmeasured. [Published reference results](docs/operations/benchmarks.md#compound-audit-filter-results-nfr-004-nfr-006-nfr-008)
  pass the cohosted 60-second/concurrency-32 profile on 10000 reports,
  with environment, hashes, redacted configuration and aggregate-latency caveats.
- **SCIM Group filter benchmark** (NFR-003, NFR-004, NFR-006, NFR-008):
  `complex-group-filter` creates owned Groups matching the seed organization
  count and owned member Users matching its large-group size. One Group has
  every member; others have one. It verifies 64-node member/name predicates,
  65-node/1025-byte refusals, exact bounded pages, schemas, references and
  ETags, including member projection, under unchanged connector budgets.
  It is included in `bench-local` and the complete benchmark smoke test.
  [Published results](docs/operations/benchmarks.md#scim-group-filter-results-nfr-004-nfr-006-nfr-008)
  record the cohosted 60-second/concurrency-32 baseline and its budget caveats.
- **SCIM scan-boundary regressions** (PROV-002, PROV-004, NFR-004,
  NFR-006): Users and Groups at 20,000 resources retain exact totals and
  bounded pages; 20,001 broad/compound scans refuse without partial data,
  while indexed equality returns its exact owned resource at concurrency 32.
- **Shared OTP guessing regressions** (TEST-021, NFR-006, NFR-007,
  MFA-013): email, SMS, HOTP, mixed-method and phantom-account bursts use
  eight source IPs and three independent runtimes/pools. The unchanged
  ten-proof account budget, exact challenge/transaction failures and
  audits, exhausted-budget refusals and next-window authority are checked.
  [Evidence](docs/operations/consistency-tests.md#shared-otp-guessing-budgets--2026-10-12)
  and [structured results](docs/operations/consistency-results/2026-10-12-otp-budgets.json)
  record the cross-method failure, correction and passing full offline check.
- **Directory transport consistency regressions** (PROV-012, PROV-014,
  NFR-007): actual LDAPS sockets are dropped after a committed user page
  across three independent pools. Full and promoted incremental failover
  enforce complete-source deletion, while exhausted transport preserves
  memberships/cursor until a full retry succeeds. [Pre/post evidence](docs/operations/consistency-tests.md#directory-transport-interruption-and-complete-source-deletion--2026-10-12)
  and [frozen-build results](docs/operations/consistency-results/2026-10-12-directory-transport.json)
  include three race-detector repetitions with existing crash/sync support
  and the passing full offline race-detector check.
- **Native directory worker crash regressions** (PROV-007, PROV-012,
  NFR-007, TEST-058): a separately exec'd worker task is killed after one
  committed/checkpointed LDAPS page. Three replicas refuse early takeover
  and recover full/incremental scans at lease expiry with original account
  IDs, exact Group authority, cursor and audit counts. Six OS kills pass
  across three race-detector repetitions; [evidence and scope](docs/operations/consistency-tests.md#native-directory-worker-process-death--2026-10-12)
  and [structured results](docs/operations/consistency-results/2026-10-12-directory-native-crash.json)
  distinguish worker-task death from production-entrypoint and host/DB/network failures.
- **Directory scheduler and lease-recovery regressions** (PROV-012,
  NFR-007, TEST-058): concurrency-32 schedule claims across independent
  pools verify rollback while blocked, exact full/incremental slots and
  one leased handler per run. A partial scan is reclaimed at lease expiry;
  the returning worker cannot modify the recovered state. Six generic job
  outcomes cover stale finalization/progress, attempt fencing and protected
  results. [Evidence](docs/operations/consistency-tests.md#directory-schedules-and-expired-worker-leases--2026-10-12)
  and the [full offline verification result](docs/operations/consistency-results/2026-10-12-directory-lease.json)
  preserve source hashes, environment and test/package outcomes.
- **Directory replica synchronization stress** (PROV-007, PROV-012,
  NFR-007): concurrency-32 public requests and three competing workers
  execute paged full, incremental dry-run, applied incremental and repeat
  full sync against a loopback LDAPS test directory. All independent pools
  check sole run/job leases, exact account/link/membership/audit effects,
  durable cursors, Group-derived authority and preserved administrator
  state. Three race-detector repetitions pass; [evidence and limits](docs/operations/consistency-tests.md#directory-synchronization-across-replicas--2026-10-12)
  distinguish this profile from real AD interoperability and fault testing.
- **Mixed group deletion regressions** (NFR-007, QA-008): a controlled
  lock-order check, connector external-ID reuse, legacy LDAP Group repair
  and actual outbound SCIM cleanup complement concurrency-32
  administrator/connector deletion races across three independent pools.
  [Before/after evidence](docs/operations/consistency-tests.md#mixed-group-deletion-and-link-repair--2026-10-11)
  records three race-detector repetitions and exact durable effects.
- **SCIM Group replica stress** (PROV-007, PROV-008, NFR-007):
  concurrency-32 conditional connector/admin renames require exactly one
  winner across three independent runtimes/pools. Membership replacement
  versus administrator addition covers concurrent writes and both causal
  orders; controlled deletion removes both role sources once while
  keeping organization memberships active. Exact versions, member revisions,
  audit counts and effective permissions pass three race-detector repetitions.
  [Evidence and scope](docs/operations/consistency-tests.md#scim-group-races--2026-10-11).
- **Shared-SSO replica revocation stress** (NFR-007, SES-014, SES-015,
  SES-021): three grants from two clients share one real browser SSO
  session across three independent runtimes/pools. Concurrency-32 races
  cover client-local revocation, offline/bound refresh reuse, one-session
  and account-wide revocation; post-commit checks preserve each logout
  scope, independent same-user sessions and unrelated users. Exact lineage,
  reuse/session audit/outbox counts and silent SSO checks pass three times
  with the race detector. [Evidence and limits](docs/operations/consistency-tests.md#shared-sso-revocation-races--2026-10-11).
- **Native-process refresh benchmark results** (NFR-003, NFR-007, NFR-008):
  `make bench-replicas` runs three independent server processes behind the
  loopback, per-request `identity-bench replica-proxy`, with no cross-backend
  failover or one-use POST replay. The local runner records per-node CPU,
  counts-only routing and independent SQL lineage/reuse evidence. Both
  full-cardinality 60-second refresh profiles pass; redacted configuration,
  raw results and their single-laptop limits are
  [published](docs/operations/benchmarks.md#independent-server-process-results-nfr-003-nfr-007-nfr-008).
- **Replica refresh and revocation stress** (NFR-007): concurrency-32
  bursts across three independent pools check foreign-client refusals,
  exact successor/reuse counts for session JWT, opaque and offline JWT
  grants, and post-commit rejection after concurrent session/account-wide
  revocations. Grant-level regressions cover UserInfo, account APIs and
  exchanged descendants while unrelated grants remain active.
  [Evidence and topology limits](docs/operations/consistency-tests.md).
- **Replica ownership, role and connector stress** (NFR-007):
  concurrency-32 bursts across three independent pools prove one
  self-releasing ownership transfer, one role grant/edit/revoke transition
  and one conditional SCIM/admin writer. Each pool checks exact versions,
  permissions and audit/outbox counts. Additional regressions prove
  idempotent template setup and competing expiry-worker cleanup.
  [Results and topology limits](docs/operations/consistency-tests.md#ownership-roles-and-connector-sync--2026-10-11)
  record three race-detector repetitions without treating them as capacity.
- **Independent-replica recovery and invitation stress** (NFR-007):
  three HTTP replicas have separate pools, transaction limits, keyrings and
  caches. Barrier-started concurrency-32 bursts require exact refusals and
  committed one-use/membership/role/audit/outbox counts from every pool.
  Three race-detector repetitions pass without raising account budgets.
  [Recorded evidence and remaining scope](docs/operations/consistency-tests.md)
  distinguish these local consistency tests from multi-machine capacity.
- **Complex SCIM filter benchmark** (NFR-006, NFR-008): `complex-filter`
  creates an isolated connector with the seed's user cardinality through
  public APIs, preserving its 1200/minute budget. It measures 64-node scans,
  65-node/1025-byte rejection, exact active/inactive totals, clamped pages
  and owned IDs, with strict SCIM errors/retry guidance. Fixture creation
  is unmeasured and paced; measured operations are unpaced. Unit and smoke
  checks cover the profile. Passing full-cardinality laptop results, with
  the initial failure preserved and budget-refusal limits explained, are
  [published](docs/operations/benchmarks.md#scim-filter-results-nfr-004-nfr-006-nfr-008).
- **TOTP guessing benchmark** (NFR-006, NFR-008): `otp-guess` enrolls
  an isolated owned factor and attacks eight MFA transactions without
  raising proof or identifier budgets. It excludes legitimate codes,
  requires retry guidance and proves transaction closure before retirement;
  private factor/continuation authority is cleared on close. The local
  runner checks ten evaluated proofs against stored failure/audit counts.
  Concurrent and sequential database-backed regressions cover the shared
  account budget and five-failure transaction retirement. Passing laptop
  results and the limits of this TOTP-only profile are
  [published](docs/operations/benchmarks.md#totp-guessing-results-nfr-006-nfr-008).
- **Webhook worker benchmarks** (NFR-003, NFR-005, NFR-008): isolated
  membership add/remove cycles prove signed, request-correlated callbacks
  and exact delivered records. `webhook-retry` injects one `503` per event
  and checks identical ID/body, fresh timestamp and two attempts under the
  default backoff; `mixed-delivery` covers all 12 workload components.
  Portable receiver snapshots record retry/recovery times without secrets
  or message contents. The local runner selects the soak scenario and
  permits only the loopback `/32` egress needed by its own receiver.
  Passing local delivery/retry, twelve-component mix and every window of a
  ten-minute delivery soak with actual retries and key activation, along
  with the initial seed-backlog failures and their limits, are
  [published](docs/operations/benchmarks.md#webhook-worker-results-nfr-003-nfr-005-nfr-008).
- **SMTP worker benchmarks** (NFR-003, NFR-008): `email-delivery` measures
  enqueue through confirmed worker/provider acceptance; `mixed-email`
  combines it with all nine extended workloads. A loopback-only SMTP sink
  exercises the actual transport and retains counters, never message bodies.
  The local runner switches after bootstrap, records the SMTP configuration,
  checks receiver counts and cleans up its own listener. Latency includes
  job polling; acceptance does not prove inbox delivery. Passing laptop
  results for the independent workload, the ten-component mix and a flood
  limited to three actual SMTP messages are [published with their limits](docs/operations/benchmarks.md#smtp-worker-results-nfr-003-nfr-008).
- **Extended workload benchmarks** (NFR-003, NFR-008):
  `passkey-assertion` exercises discoverable ES256 software credentials through
  complete sign-in and PKCE exchange; `scim` checks a completed five-request
  user lifecycle under unchanged connector budgets. `mixed-extended` combines
  them and imports with the original workloads. Private fixtures are prepared
  through public APIs before timing; the original `mixed` profile is preserved.
  `make bench-local` enables passkeys only in its dedicated realm and records
  explicit localhost RP/origin settings. Measured results for all three new
  scenarios, including the initial configuration failure, are published with
  software-authenticator and SCIM pacing limits in
  [benchmarks.md](docs/operations/benchmarks.md#extended-workload-results-nfr-003-nfr-008).
- **Go resource-server sender verification** (TOK-019, MCH-014, TEST-067):
  `verifier.SenderVerifier` verifies request-bound DPoP proofs or TLS client
  certificates with offline JWT verification or strict-online introspection.
  It checks the method, configured public URL, access-token hash, key or
  certificate binding and atomic single-use proof state. Concurrent replay,
  state-store outages, ambiguous headers/JSON and forged proxy headers deny
  access. A separate TLS API exercises actual ProudAuth JWT/opaque DPoP
  tokens and certificate-bound JWTs in `TestResourceSenderVerifier`.
  The exact profile, shared-store requirement and TLS proxy boundary are in
  [resource-servers.md](docs/integrations/resource-servers.md#sender-constrained-tokens).
- **Published laptop benchmark results and an offline local runner**
  (NFR-003..NFR-008, M4): `make bench-local` starts dedicated PostgreSQL 18,
  builds host server/worker/tool binaries from cached modules, bootstraps an
  MFA administrator, seeds the `make bench` cardinalities, and checks every
  workload, adversarial and refresh-race scenario plus a 10-minute mixed
  soak crossing token expiry, signing-key activation, retention, vacuum and
  backup. Results, redacted configuration, exact environment and commands,
  pass criteria and caveats are in
  [benchmarks.md](docs/operations/benchmarks.md#reference-results) and
  `docs/operations/bench-results/2026-10-11-laptop/`. The runner refuses
  existing resources and cleans up only its own processes and data; the
  seed file and administrator credentials are never published.
- **Interoperability with Keycloak 26.8.0** (QA-004, M4;
  SAML-010): `scripts/interop-keycloak.sh` (`make interop-keycloak`, job
  `keycloak` of the weekly `interop.yml` workflow) starts Keycloak
  (`start-dev`, HTTPS), PostgreSQL 18 and ProudAuth built from the checkout
  in throwaway containers and plays the browser and the login UI: Keycloak
  as OpenID Connect relying party of ProudAuth (code + PKCE S256,
  `client_secret_basic`, ID token through the JWKS, UserInfo, RP-initiated
  and back-channel logout), Keycloak as upstream OpenID Provider of a
  ProudAuth OIDC connection (just-in-time account and link, upstream
  logout), Keycloak as SAML service provider of a ProudAuth SAML application
  (signed requests and responses, persistent NameID, encrypted assertions,
  single logout) and as SAML identity provider of a ProudAuth SAML
  connection, each side configured from the other's discovery document or
  metadata; replayed codes, callbacks, `AuthnRequest`s and SAML responses,
  tampered SAML messages and wrong client secrets are refused. Profiles,
  the Keycloak settings that matter and what is not covered:
  [interoperability.md](docs/integrations/interoperability.md#keycloak-2680-protocol-profiles).
- **Interoperability with ZITADEL v4.16.3 as a SCIM service provider**
  (QA-004, PROV-010, PROV-017): `scripts/interop-zitadel.sh` (`make
  interop-zitadel`, job `zitadel` of the weekly `interop.yml` workflow)
  starts ZITADEL and PostgreSQL 18 in throwaway containers and pushes
  ProudAuth accounts to ZITADEL's `/scim/v2/{orgId}/Users` with a
  least-privilege service account's token: creates, profile and email
  changes, suspension, deactivation and deletion by an organization and a
  realm connector, a token revoked in ZITADEL and rotated, and
  reconciliation (dry run, drift, a deleted and an unmanaged user), all read
  back from ZITADEL. The tested profile, what ZITADEL requires (one media
  type in `Accept`; `name` and `emails`; no groups) and what is not covered
  are in [outbound-provisioning.md](docs/integrations/outbound-provisioning.md#zitadel-v4163)
  and [interoperability.md](docs/integrations/interoperability.md#third-party-products).
- **Independent OpenID Connect relying-party test** (QA-004, OIDC-001,
  OIDC-003, TOK-011): `TestOIDCRelyingPartyLibrary` signs in through
  `github.com/coreos/go-oidc/v3` v3.18.0 and `golang.org/x/oauth2` v0.37.0
  (new test-only dependencies): discovery, code flow with S256 PKCE, the
  library's ID-token verification through the JWKS (including a planned
  rotation and a withdrawn key), UserInfo and refresh, and refusal of
  another client's or a tampered ID token.
- **Provisioning and federation attack suites** (M4 exit gate):
  [attack-suites.md](docs/threat-models/attack-suites.md) maps each attack on
  provisioning and federation to the tests that mount it; `make
  attack-suites` runs them and CI runs them as their own step
  (`TestAttackSuitesExist` keeps the document and the Makefile in step).
#### Protocols

- OAuth 2.0 authorization code flow with mandatory PKCE `S256`, exact redirect
  matching and single-use, client-bound codes (TOK-001, TOK-002, OIDC-001,
  TEST-028, TEST-029).
- Refresh-token families with rotation, reuse detection and family/session
  revocation (SES-006, SES-009, DB-006, TEST-030..TEST-032).
- Client credentials; device authorization grant (RFC 8628); token exchange
  (RFC 8693, TOK-016, TOK-017) for access-token subjects with explicit audience
  transitions and a bounded `act` chain; pushed authorization requests (RFC 9126); DPoP proofs and
  `cnf.jkt`-bound access tokens at the token endpoint (RFC 9449).
- Introspection (RFC 7662) limited to clients registered as introspectors of the
  token's audience (TEST-037); revocation (RFC 7009).
- OpenID Connect: discovery and RFC 8414 metadata generated from implemented
  features, JWKS, ID tokens, UserInfo, RP-initiated logout, back-channel logout,
  RFC 9207 `iss` parameter.
- JWT access tokens (`at+jwt`, one audience per token, `token_kind`) and opaque
  access tokens per resource; opaque support tokens (`pa_it_`).
- OIDC `claims` parameter (OIDC-008): validated, stored with the grant and used
  only to narrow release per target. An `id_token` member limits the ID token to
  the listed user claims (plus `email_verified`/`phone_number_verified` when
  `email`/`phone_number` is listed) and a `userinfo` member limits UserInfo the
  same way, always within the granted scopes; a missing member means scope-based
  release for that target. `acr` requests raise the assurance requirement.
  Discovery now advertises `claims_parameter_supported: true` (migration `0017`,
  `TestClaimsRequestAndStaticClaims`).
- `prompt=select_account` stops for the user to keep or switch the signed-in
  account (`POST .../auth/transactions/{id}/account`, OIDC-005).
- Per-resource `signing_algorithm` for access tokens, limited to
  `security.allowed_algorithms`; key rotation refuses to strand pinned resources
  (TOK-005, `TestResourceAlgorithmProfile`).
- Organization scope ceilings (`allowed_scopes` in organization policy) and scope
  `required_permissions` (migration `0015`), applied at every issuance including
  refresh (TOK-008, `TestScopeSubjectAndOrganizationPolicy`).
- Client `token_policy.max_session_age_seconds`: older SSO sessions are not reused
  for that client (SES-002).
- Durable pairwise subject identifiers: derived once and stored in
  `pairwise_subjects` (migration `0018`), so they no longer change when the active
  root-key version changes (OIDC-010, APP-012, `TestPairwiseSubjects`).
- Reviewed pairwise sectors (OIDC-010): a pairwise client's `sector_identifier`
  defaults to the host its redirect URIs share and is required (`422`) when they
  span several hosts; every redirect URI must be the sector host or one of its
  subdomains, so a client cannot claim another application's sector. Clients
  registered in the same sector receive the same pairwise `sub`
  (`TestPairwiseSectors`).
- **Scope step-up** (AUT-010, migration `0028`): scopes accept `step_up_acr`
  (`urn:proudauth:acr:mfa` or `urn:proudauth:acr:phishing_resistant`) and
  `max_auth_age_seconds` (60–86400); a scope with `sensitivity: privileged`
  and no `step_up_acr` requires MFA. Requesting such scopes adds the strongest
  required `acr` to the transaction's `acr_values` and lowers `max_age` to the
  shortest age, so an SSO session is stepped up (never downgraded) and a remembered device
  cannot skip the MFA prompt. At code, device-code and refresh issuance a scope is
  left out of the access token when the grant's `acr` ranks below the scope's or
  its `auth_time` is older than the scope allows; the client regains it with a
  new authorization request (`TestScopeStepUp`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#scope-step-up)).
- **Realm access-token lifetime limits** (TOK-018): realm policy
  `tokens.access_token_ttl_seconds` (every access token),
  `tokens.service_access_token_ttl_seconds` (service principals) and
  `tokens.single_factor_access_token_ttl_seconds` (user tokens whose `acr` is
  below `urn:proudauth:acr:mfa`), each 30–86400 seconds or 0 for no limit, can
  only shorten the lifetime set by the resource and the client, and
  `tokens.max_access_token_ttl` still applies (`TestTokenLifetimePolicy`;
  [tokens.md](docs/protocols/tokens.md#access-token-lifetime)).
  `tokens.impersonation_access_token_ttl_seconds` (and the realm-wide
  `tokens.access_token_ttl_seconds`) also bound support grants, whose tokens
  live as long as the grant.
- **Environment separation** (APP-015): a client's `environment`
  (`development`, `staging` or `production`; default `production`) is fixed at
  registration, so a development client and its credentials are never promoted
  in place: `PUT /clients/{client}` with another value is refused (`422` on
  `environment`). A client registered in a project defaults to the project's
  environment and must match it (`422`). Token exchange refuses
  (`invalid_grant`) a subject token issued to a client of another environment
  than the presenting client's, so production clients never accept development
  tokens (`TestEnvironmentSeparation`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#clients)).
- **Claim mappings** (APP-011): besides static values, a client's
  `id_token_claims` and `access_token_claims` accept attribute mappings
  `{"$attr": "...", "transform": "lower" | "upper", "default": "..."}`. `$attr`
  names one approved attribute: `user.given_name`, `user.family_name`,
  `user.display_name`, `user.locale`, `user.zoneinfo`, or `profile.<name>` for a
  realm profile attribute marked `claimable: true` in `profile.attributes`;
  there are no expressions. Each map holds at most 20 claims with names of at
  most 64 characters; string values are cut to 256 characters before the
  transform, and an absent (or not claimable) attribute yields `default` or no
  claim. Attribute values are released only when the grant includes the
  `profile` scope (see **Security fixes**), and a profile attribute cannot be
  both `claimable` and `user_editable`. Mappings never set reserved claims, and in ID tokens never set OIDC
  standard user claims or claims already released by scope. Service-principal
  tokens have no attributes, so only a mapping's `default` can apply to them
  (`TestClaimMappings` in `tests/e2e/tokens_test.go` and
  `internal/application/claimmap_test.go`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#clients); the
  configuration document schema describes them as `ClaimAttributeMapping`).
- **SAML 2.0 identity provider and broker** (SAML-001..SAML-010, APP-018,
  FED-014, TEST-051; migration `0060`; `internal/saml`, `internal/saml/idp`,
  `internal/federation/saml.go`; `TestSAMLIdentityProvider`,
  `TestSAMLKeyRollover`, `TestSAMLBroker`), off unless `saml.enabled` is set
  (new `saml.*` keys). *SAML applications*
  (`/api/v1/realms/{realm}/saml/applications`, `realm.clients.read` /
  `.write`) are service providers backed by a client record with
  `protocol: "saml"` that is not an OAuth client: SP-initiated SSO over
  HTTP-Redirect and HTTP-POST (`/realms/{realm}/saml/sso`), responses over
  HTTP-POST only to exactly registered ACS URLs, a browser-bound
  continuation (`pa_saml` cookie), signed error responses, persistent
  (per-application `sps_...`), `emailAddress` (verified only), `unspecified`
  and transient NameIDs (full URNs), attribute mappings with protected
  names, `RequestedAuthnContext` mapped to step-up, organization binding and
  consent, optional encrypted assertions (AES-GCM with RSA-OAEP only),
  IdP-initiated SSO off by default and per application, and SP-initiated
  single logout from signed requests only that reports `PartialLogout`.
  *SAML connections* (`/api/v1/realms/{realm}/saml/connections`,
  `realm.identity_providers.read` / `.write`) are federation connections of
  kind `saml` with uploaded IdP metadata, signed HTTP-Redirect
  `AuthnRequest`s, single-use correlation (`InResponseTo` plus a 256-bit
  `RelayState`), assertion-ID replay records, pinned certificates with
  overlap for rollover, strict audience, destination, recipient and time
  checks, and email trusted only with `trust_email_verified`; unsolicited
  and encrypted responses are refused. Both roles use a per-realm RSA 3072
  SAML key set with pre-published rollover
  (`/api/v1/realms/{realm}/saml/signing-keys`, `realm.keys.read` /
  `realm.keys.rotate`; forced activation is audited as `emergency`), a
  parser that refuses DTDs, comments, duplicate IDs and oversized or deep
  documents before building a tree, and `goxmldsig` v1.6.1 with SHA-1
  refused and no algorithm exception. Audit `saml.*`. **Tested only against
  the repository's own test SP and IdP; no interoperability test against a
  third-party SAML product has been run**
  ([saml.md](docs/integrations/saml.md),
  [SAML threat model](docs/threat-models/saml.md),
  [ADR 0018](docs/architecture-decisions/0018-enterprise-protocols-deferred.md#update-2026-10-11-saml-and-directory-integration)).
- **OpenID Connect Session Management 1.0** (OIDC-014), opt-in per realm
  (`sessions.check_session_iframe`, default off): discovery lists
  `check_session_iframe` (`I/oidc/check-session`), authorization responses
  with a code carry `session_state` (salted, bound to the client and the
  redirect URI's origin; inside the JWT with JARM), and the script-readable
  `pa_opbs` cookie holds a keyed digest of the session ID, never the session
  secret. The iframe answers only origins registered for the client.
  Third-party cookie blocking makes every check report `changed`, and
  server-side revocations are not visible to it; use back-channel logout for
  those (`TestCheckSessionIframe`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#session-management-oidc-014)).
- **Front-channel logout** (SES-018, migration `0050`): clients register
  `frontchannel_logout_uri` (same scheme, host and port as a registered
  redirect URI) and optionally `frontchannel_logout_session_required` (adds
  `iss` and `sid`). When the logout endpoint ends a session, browsers get a
  `200` page that loads the URIs of the active participating clients in
  hidden frames (its CSP frames only those origins and allows no script) and
  continues to the post-logout redirect after two seconds; callers sending
  `Accept: application/json` get `frontchannel_logout_uris` and `redirect_to`
  to render the frames themselves. Delivery is never confirmed; back-channel
  logout remains the reliable mechanism. Discovery sets
  `frontchannel_logout_supported` and `frontchannel_logout_session_supported`
  (`TestFrontChannelLogout`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#front-channel-logout-ses-018)).
- **Encrypted ID tokens and signed or encrypted UserInfo** (TOK-020, OIDC-013):
  per-client `id_token_encrypted_response_alg`/`enc`,
  `userinfo_signed_response_alg` and `userinfo_encrypted_response_alg`/`enc`
  (stored in the new `clients.protocol_options`). Key management
  `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW`; content
  encryption `A128GCM` or `A256GCM`, always explicit (`RSA1_5`, SHA-1
  `RSA-OAEP` and CBC-HMAC are refused, `422`). ID tokens become nested JWTs
  encrypted to the client's newest fitting registered key; UserInfo answers
  `application/jwt`. A client without a fitting key gets `400
  unauthorized_client` at the token endpoint and `400 invalid_request` at
  UserInfo (`TestEncryptedResponses`;
  [response-security.md](docs/protocols/response-security.md)).
- **JARM** (ADV-002): `response_mode=query.jwt` (or `jwt`) at the
  authorization endpoint, in PAR and in the headless start returns one
  signed `response` parameter (`iss`, `aud`, 10-minute `exp`, and `code` and
  `state` or the error), optionally encrypted
  (`authorization_encrypted_response_alg`/`enc`); errors returned to the
  redirect URI use the same mode. `fragment.jwt`, `form_post` and
  `form_post.jwt` are not offered. Discovery lists the response modes and
  algorithms (`TestJARM`;
  [response-security.md](docs/protocols/response-security.md#jarm-adv-002)).
- **Dynamic client registration** (APP-016, APP-017, ADV-003, RFC 7591/7592,
  migration `0052`): off by default (realm policy `client_registration`);
  `POST I/oauth/register` with an administrator-issued initial access token
  (`pa_iat_`, bound to non-privileged scopes, limited uses, default expiry
  7 days) or, with `open`, without one (then always held for approval);
  registered clients are third-party clients that ask for consent; metadata
  URLs are never fetched, `jwks_uri` and software statements are refused;
  registration access tokens (`pa_rat_`) for `GET`, `PUT` (rotating, with an
  optional `rotate_secret`) and `DELETE`; 20 registrations per hour per network
  and 500 per realm, failing closed; approval queue at `/client-registrations`.
  Discovery publishes `registration_endpoint` only while enabled
  (`TestDynamicClientRegistration`;
  [dynamic-client-registration.md](docs/integrations/dynamic-client-registration.md)).
- **Mutual TLS** (TOK-019, MCH-014, RFC 8705, migration `0056`): a second TLS
  listener (`server.mtls_listen`, advertised through `server.mtls_origin` as
  `mtls_endpoint_aliases`) or a trusted proxy header
  (`server.client_cert_header`); realm trust anchors with optional uploaded
  CRLs (`/certificate-trust-anchors`); client authentication
  `tls_client_auth` and `self_signed_tls_client_auth`; certificate-bound
  access tokens (`tls_client_certificate_bound_access_tokens`, `cnf.x5t#S256`)
  enforced by the IdP's own APIs and UserInfo; opaque tokens keep `cnf` and
  introspection returns it (`TestMutualTLS`;
  [mutual-tls.md](docs/protocols/mutual-tls.md)).
- **Workload identity federation** (MCH-011..MCH-013, ADV-004, RFC 7523,
  migration `0051`): machine clients with a service principal accept the
  `urn:ietf:params:oauth:grant-type:jwt-bearer` grant and, when it is their
  only grant, `token_endpoint_auth_method: none`. Per-client workload trusts
  (`/clients/{client}/workload-trusts`; profiles `github_actions`,
  `kubernetes`, `spiffe`, `generic`) fix issuer, keys, exact audience, subject,
  claim constraints, algorithms, maximum lifetime and `jti` replay control.
  Key sets are fetched under the federation egress rules and cached
  5 minutes. The token is the client's service token and never outlives the
  assertion; refusals are `invalid_grant` with the reason audited as
  `workload.assertion.rejected`. Assertions never become user identities
  (`TestWorkloadFederation`;
  [workload-federation.md](docs/integrations/workload-federation.md)).
- **FAPI 2.0 security profile** (ADV-001): client `security_profile: fapi2`
  requires a confidential client authenticating with `private_key_jwt` (PS256,
  ES256 or EdDSA assertions) or mutual TLS, the code flow only,
  sender-constrained tokens, `https` redirect URIs and a realm signing
  algorithm of PS256, ES256 or EdDSA; it forces PAR, caps codes at 60 s and
  access tokens at 10 minutes, and does not rotate refresh tokens. **Not
  certified by the OpenID Foundation; no conformance-suite run**
  (`TestFAPI2Profile`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#fapi-20-security-profile-adv-001)).

#### Authentication

- Headless authentication transactions with continuation tokens, and a browser mode
  for application-provided login UIs with cookie, CSRF token and `Origin` checks
  (AUT-001..AUT-020, TEST-056).
- Passwords (Argon2id, optional pepper, embedded and operator blocklists), email
  one-time codes, **SMS one-time codes**, **magic links** (fragment-carried,
  transaction-bound), TOTP, recovery codes with recovery-restricted sessions.
- **Passkeys (WebAuthn)**: registration and assertion, discoverable and
  identified sign-in, synced-passkey counter handling, phishing-resistant profile
  for administrators, self-service management (PASS-001..PASS-007, TEST-025).
- **Upstream federation**: OpenID Connect and GitHub-style OAuth connections with
  PKCE, state, nonce and issuer validation; JIT provisioning; linking policies with
  local proof of control; tenant and email-domain restrictions; trusted upstream
  MFA; SSO-mandatory organizations; self-service and administrator management of
  linked identities (FED-*).
- Registration modes, email verification, enumeration-resistant responses,
  password reset that keeps MFA (TEST-020, TEST-070), administrator-created
  accounts with setup tokens, step-up and `max_age`/`prompt` handling.
- Temporary password lock and per-identifier, per-IP, per-client, per-subject and
  per-organization budgets stored in PostgreSQL.
- Aggregate abuse budgets per client, organization and realm for sign-up,
  code/link sends and password attempts, and per-organization and per-recipient
  invitation budgets (`security.rate_limits.signup_per_client`,
  `signup_per_realm`, `send_per_client`, `send_per_organization`,
  `send_per_realm`, `login_per_realm`, `invitations_per_organization`,
  `invitations_per_recipient`, `invitation_window`; SEC-006, INV-009).
- **Remembered devices** (AUT-013): an opt-in, random device secret (HttpOnly
  `pa_rd` cookie or `X-Remembered-Device` header) that can skip the MFA prompt
  where policy allows, without adding assurance; listed and revoked under
  `/me/remembered-devices` (`TestRememberedDevices`).
- Concurrent browser transactions: the `pa_tx` cookie is scoped to each
  transaction's own path (AUT-016, `TestConcurrentBrowserTransactions`).
- Profile attribute schema in realm policy (`profile.attributes`: typed,
  validated, user-editable or admin-only) with the `complete_profile` required
  action (USR-007, AUT-018, `TestProfileSchemaAndCompletion`).
- Transient sessions (`POST .../auth/transactions/{id}/transient`, SES-020).
- **Pre-action hooks** (EXT-009..EXT-012, EXT-017): operator HTTPS endpoints for
  registration eligibility, profile validation, access-token claims enrichment and
  authorization decisions, called through the egress policy with signed
  requests. Hooks can only restrict; security hooks fail closed, and claims
  enrichment cannot override reserved or standard user claims. Managed under
  `/api/v1/realms/{realm}/hooks`; `TestPreActionHooks` (TEST-053).
- **Guest identities** (REG-010): with realm policy `registration.allow_guests`,
  `POST .../auth/transactions/{id}/guest` (a login transaction, before any
  identifier) creates a guest account under the sign-up budgets and signs it in
  with `amr` `anon` and `acr` `urn:proudauth:acr:anonymous`. Guests cannot join
  organizations or hold roles, and transactions that need MFA or an organization
  stop with `guest_not_permitted`. `POST /me/upgrade` (`email`, `password`) sets a
  password and adds the address unverified; the same account stops being a guest
  once the address is verified through `POST /verification-challenges`. An address
  another account has verified cannot be verified, so nothing is linked or merged
  (`TestGuestIdentities`).
- **Registration approval queue** (REG-008, migration `0021`): with realm policy
  `registration.require_approval`, self-registrations without an invitation are
  queued, and after email verification and required actions the transaction stops
  with `error: registration_pending_approval`. Holders of
  `realm.registrations.review` list the queue (`GET /registration-approvals`,
  optional `state`) and decide with `POST /registration-approvals/{id}/decision`
  (`approve`, `reason`); applicants cannot review themselves. The applicant is
  emailed the decision and denied accounts are suspended; requests undecided after
  14 days expire and the account is suspended, never approved
  (`TestRegistrationApprovalQueue`).
- **Scheduled assisted recovery** (MFA-009, migration `0020`): when realm policy
  sets `recovery.cooling_off_hours` (0–168) or `recovery.require_approval`,
  `POST /users/{user}/recovery-requests` returns `202 recovery_scheduled`
  (`recovery_id`, `effective_at`, `approval_required`) instead of acting at once.
  The owner is notified immediately and can list and cancel the request
  (`GET /me/assisted-recoveries`, `POST /me/assisted-recoveries/{id}/cancel`); an
  operator other than the requester and the owner approves it
  (`POST /assisted-recoveries/{id}/approve`; `support.recovery.assist`, plus
  `realm.users.credentials.manage` for `reset_mfa`); the worker task
  `recovery.assisted_due` runs due requests, which expire seven days after
  `effective_at`. Scheduling is refused for accounts without a verified email
  address (`TestScheduledAssistedRecovery`,
  [account-recovery.md](docs/operations/account-recovery.md)).
- **Authentication flow policy** (AUT-012, AUT-014, SEC-014, migration
  `0040`): realm policy `authentication_flow` holds up to 50 ordered rules
  whose conditions (`clients`, `organizations`, `methods`, `resources`,
  `networks`/`outside_networks`, `new_device`, `failed_attempts_at_least`,
  `risk_at_least`, `privileged`, `assurance_below`) select an outcome:
  `allow`, `require_mfa`, `require_phishing_resistant`, `challenge`, `review`
  or `deny`. The decision is made once the account is known, kept in the
  transaction, re-made when the organization or the policy revision changes,
  and audited as `authentication.flow.evaluated` with the rule and the
  signals used. A missing signal applies a restrictive rule unless it says
  `on_missing_signal: skip` and never satisfies `allow`. `deny` stops the
  transaction with `error: "authentication_policy_denied"`; `review` raises
  the new security signal `authentication_review` (and a `security.alert`).
  `challenge` adds the next action `challenge`, answered with
  `POST .../auth/transactions/{id}/challenge` (`provider_response` or `code`)
  after `POST .../challenge/send` for an emailed code, or with a second
  factor already enrolled; wrong answers are `400 invalid_proof`, an
  unavailable provider `503 unavailable`. Challenge providers are operator
  configuration (`security.challenge_providers`: a siteverify-style
  `verify_url`, `site_key`, `secret`, opt-in `send_remote_ip`, `timeout`); none
  is built in or contacted unless configured and named by a realm. New hook
  kind `authentication.risk` reports `low`, `medium` or `high` with reasons;
  a failing hook makes the signal missing, never blocks by itself
  (`TestAuthenticationFlowPolicy`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#authentication-flow-policy)).
- Completing a sign-in records `user.required_actions.completed` (category
  `account`) with the required actions done in that transaction (AUT-018,
  `TestRequiredActionPermissions`).
- **Federation adapters** (FED-002, migration `0040`): connections name an
  adapter that fixes the provider's semantics. New built-in adapters
  `google` (issuer `https://accounts.google.com`; `allowed_tenants` restricts
  to Workspace domains through `hd`) and `microsoft` (Entra ID issuer
  `https://login.microsoftonline.com/{tenant}/v2.0` selected by `tid`,
  `allowed_tenants` required, email never treated as verified, so
  `trusted_verified_email` linking is refused). Operator-built binaries can
  register more with `federation.RegisterAdapter`; an adapter whose email
  assertions are not trusted never yields a verified email
  (`TestFederationAdapters`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#upstream-identity-providers)).
- **Upstream logout** (FED-013): `/oidc/logout` responses report
  `upstream_logout` (`not_federated`, `not_requested`, `redirect`,
  `unsupported`, `unavailable`), and the extension parameter
  `upstream_logout=true` sends the browser on to the provider's end-session
  endpoint, returning through `/oidc/logout/upstream-return` with
  `upstream_logout=returned`. `session.logout` audit events record
  `upstream_provider` and `upstream_logout_requested`
  (`TestFederationAdapters`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#upstream-logout-fed-013)).
- **Verified-contact update** (AUT-018): the required action `verify_contact`
  (setting or removing it needs `realm.users.write` besides
  `realm.users.required_actions`) makes the next sign-in offer
  `verify_contact`; `otp/send {"purpose": "verify_contact"}` emails a code to
  the primary address even when it is verified, and `otp/verify` clears the
  action and lists it in `user.required_actions.completed`
  ([headless-authentication.md](docs/protocols/headless-authentication.md#verified-contact-aut-018)).
- **Operator MFA floor** (MFA-005): `security.mfa_floor` (`require: none|all`,
  `admin_phishing_resistant`, `forbid_org_admin_waiver`). Realm policy updates
  and configuration imports below it are refused (`422` on the realm field),
  and sign-in and organization administration apply it even to policies saved
  before it was raised (`TestOperatorMFAFloor`;
  [configuration.md](docs/operations/configuration.md#security)).
- **Versioned authentication flows** (AUT-019, migration `0057`):
  `/api/v1/realms/{realm}/authentication-flow/revisions` saves drafts with a
  reachability and bypass analysis (`bypass` errors; `unreachable`,
  `partial_bypass`, `skip_on_missing` and `deny_all` warnings), simulates up
  to 200 sign-in cases against the live flow with the sign-in evaluator,
  publishes only drafts whose base is still the live flow (`409` otherwise)
  and only with acknowledged warnings, and rolls back by publishing an
  earlier revision as a new one. Every flow change through `PUT /settings`
  or configuration import is recorded as a published revision, and a bypass
  is refused there too (`422` on `authentication_flow.rules[<i>]`). Audit
  `realm.auth_flow.*` (`TestAuthenticationFlowRevisions`;
  [authentication-flows.md](docs/protocols/authentication-flows.md)).
- **Passkey attestation policy** (PASS-009, migration `0059`): realm
  `webauthn.attestation` (default none: no authenticator model disclosed),
  `webauthn.require_trusted_attestation` against an operator FIDO MDS3 BLOB
  (`webauthn.metadata_file`, verified at startup, never fetched by the
  server) or realm trusted authenticators
  (`/webauthn/trusted-authenticators`), and AAGUID allow or block lists
  applied at registration and every sign-in. Passkeys record
  `attestation_trusted` and `attestation_source`.
- **Advanced WebAuthn options** (PASS-010): WebAuthn Level 3 related origins
  behind the operator switch `webauthn.related_origins`, published at
  `/.well-known/webauthn`; `credProtect` requested and optionally enforced;
  other extensions are not requested and unrequested outputs fail the
  ceremony (`TestPasskeyAttestationTrust`, `TestPasskeyAdvancedCapabilities`;
  [passkey-trust.md](docs/operations/passkey-trust.md)).
- **Federation transfer** (FED-016, migration `0080`):
  `/federation-transfers` moves account links to another connection or a new
  upstream tenant through a reviewed map (or `same_subject` mode) with
  per-entry analysis and collision reporting, approval by a second
  administrator, and an apply that re-analyses under lock, keeps link IDs and
  drops stored upstream tokens; never by email (`TestFederationTransfer`;
  [federation-transfer.md](docs/operations/federation-transfer.md)).
- Risk integrations (ADV-012) are documented as the `authentication.risk`
  hook contract with its deterministic fallback; a risk verdict cannot
  override an explicit `deny` rule (`TestRiskNeverOverridesDeny`;
  [authentication-flows.md](docs/protocols/authentication-flows.md#risk-integrations-adv-012)).
- **HOTP** (MFA-013, migration `0049`): counter-based codes (RFC 4226, SHA-1,
  6 digits), opt-in per realm (`hotp` in `mfa.allowed_factors`; realm policy
  `mfa.hotp.look_ahead` 0 = 10, at most 50, and `resync_window` 0 = 100, at
  most 1000). Self-service `/me/hotp/enroll`, `/activate`, `/resync` (two
  consecutive codes, 5 attempts per 15 minutes) and `DELETE /me/hotp`; one
  active token per account. Sign-in action `hotp`, offered where `totp` is
  (not under the phishing-resistant profile); a code is accepted once, with
  the counter advanced under a row lock and a conditional update. The factor
  counts as MFA (`amr` `hotp`), restores recovery-restricted accounts at
  sign-in and allows remembered devices; an administrator's factor reset
  revokes it; a realm that stops allowing it stops offering and accepting it
  (MFA-005). `identity-cli login` prompts for it (`TestHOTP`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#hotp-counter-based-codes)).
- **X.509 certificate sign-in** (PROV-016, migration `0056`): realm policy
  `login.certificates` offers the `certificate` action; the certificate comes
  from the mutual-TLS listener or a trusted proxy and must chain to a realm
  `user` trust anchor; accounts are resolved by administrator bindings
  (`/users/{user}/certificate-bindings`) or a single verified SAN e-mail
  address; failures are proof failures audited with a reason. A
  `multi_factor` anchor makes the sign-in phishing-resistant MFA. Organization
  `allowed_login_methods` and flow rule `methods` accept `certificate`
  (`TestCertificateSignIn`;
  [mutual-tls.md](docs/protocols/mutual-tls.md#x509-sign-in-prov-016)).

#### Accounts, organizations and authorization

- Organization membership metadata (USR-009): `PATCH
  /organizations/{org}/members/{membership}` accepts `metadata` (merged; a
  `null` value removes a key; at most `limits.metadata_bytes` as JSON; together
  with or without `state`), for callers holding `org.members.write` within the
  member-management ceiling. The member `GET`, list and `PATCH` return it only to
  such callers; it is not the user's profile, `admin_metadata` or internal
  metadata, never appears in the member's own views, personal data export or
  tokens, and cannot be read or written through another organization. Changes
  are audited as `organization.membership.metadata_updated` with the key names
  only; the realm data export carries it; it is cleared when the membership is
  removed or expires, when the organization is deleted and when the account is
  deleted (`TestMembershipMetadata`; [data-inventory.md](docs/operations/data-inventory.md)).
- Self-service profile, identifiers with verification challenges, sessions,
  consents, personal access tokens, data export and deletion request.
- Organizations with memberships, invitations (rotated secrets, non-consuming
  inspect, inviter re-validation), join requests, groups, DNS domain verification,
  ownership transfer, last-owner protection and asynchronous deletion
  (TEST-011, TEST-015..TEST-019, TEST-064).
- Scoped RBAC with built-in roles, delegation ceilings, composite roles and
  membership-scoped assignments; policy decision API (single and batch) with
  obligations (TEST-010, TEST-014).
- Support impersonation with three-level enablement, approvals, opaque short-lived
  tokens validated on every introspection, handoff codes, customer visibility and
  opt-out (IMP-001..IMP-024, TEST-040..TEST-047, TEST-071).
- Service principals, API keys, personal access tokens, credential inventory and
  expiry notifications (TEST-065).
- Account activity API `GET /me/activity`: recent sign-ins, sessions,
  authenticators, security changes and support access, without other principals'
  identifiers (USR-019, `TestAccountActivity`).
- Device labels derived from the User-Agent for sessions (`device_label`), and
  administrator revocation of a single session
  (`DELETE /users/{user}/sessions/{id}`); realm policy `sessions.max_concurrent`
  can lower the deployment limit (`TestSessionLimitsAndAdminRevocation`).
- Invitations: bulk creation with per-item results
  (`POST /organizations/{org}/invitations/batch`, up to
  `limits.max_batch_size`, 100 by default), administrator
  reassignment (`.../invitations/{id}/reassign`), binding to the account that held
  the invited address so a recycled address does not inherit it (migration
  `0014`), and project-access invitations backed by project grants
  (`/projects/{project}/grants`) (INV-011, INV-012, INV-014, USR-021,
  `TestBulkAndProjectInvitations`).
- Membership states `invited` and `pending_approval`, and expiry of join requests
  after 14 days (TEN-003, `TestMembershipLifecycle`).
- **Join request review** (INV-013): a new join request emails up to 20 users
  who hold `org.join_requests.review` in the organization (template
  `join_request`), without naming the requester.
  `POST /organizations/{org}/join-requests/{id}/reviewers` (`org.members.write`;
  `reviewer_ids`: 1–10 users who hold `org.join_requests.review`, never the
  requester) assigns a pending request: the assignees are notified, and only they
  or a reviewer who also holds `org.members.write` can decide it. The requester
  is emailed the decision (template `join_request_decision`), lists their own
  requests at `GET /me/join-requests` (reviewers are never shown) and withdraws a
  pending one with `POST /organizations/{org}/join-requests/{id}/withdraw`, which
  releases the `pending_approval` membership. Audited
  `organization.join_request.reviewers_assigned` and `.withdrawn`
  (`TestMembershipLifecycle`;
  [ADR 0006](docs/architecture-decisions/0006-realm-and-organization-boundaries.md#update-2026-10)).
- **Domain re-verification** (TEN-009, migration `0030`): verifying a domain now
  keeps a digest of the accepted DNS TXT proof, and the hourly worker task
  `domains.recheck` (up to 100 due domains per run) looks the record up again
  every realm policy `domains.recheck_days` (1–365; 0 or omitted means 30). A
  missing proof is retried every 24 hours; after
  `domains.lapse_after_failures` consecutive failures (1–30; 0 or omitted means
  3) the domain becomes `expired` and stops counting as verified. Audited
  `organization.domain.rechecked` (category `configuration`) and
  `organization.domain.verification_lapsed`. A lapsed domain is verified again by
  removing and re-adding it. Domains verified before migration `0030` have no
  stored proof and are not re-checked (`TestDomainReverification`;
  [identifiers.md](docs/protocols/identifiers.md#organization-slugs-and-domains)).
- **Organization aliases and subdomain routing** (TEN-011, migration `0034`):
  renaming an organization keeps its former slug as an alias, and
  `POST /organizations/{org}/aliases {"alias": "..."}` (`org.update`; slug
  syntax) adds one; `GET .../aliases` (`org.read`) lists them and
  `DELETE .../aliases/{alias}` releases one. Aliases resolve wherever an
  organization is named by slug (the `organization` parameter of authorization
  and device requests, organization references in user imports), and no other
  organization can take an alias as its slug or alias (`409`). Audited
  `organization.alias.added` / `.removed` (category `configuration`).
  `PATCH /organizations/{org}/domains/{id} {"include_subdomains": true}`
  (`org.domains.write`; audited `organization.domain.updated`) lets a verified
  domain also route addresses of its subdomains. Email-domain routing (at the
  `identify` step and for organization registration rules) is deterministic: an
  exact verified domain wins, otherwise the longest verified parent domain with
  `include_subdomains`, and only active organizations route
  (`TestOrganizationAliasesAndDomainRouting`;
  [identifiers.md](docs/protocols/identifiers.md#organization-slugs-and-domains)).
- **Organization templates** (TEN-017, migration `0032`):
  `POST /organization-templates` (`realm.organizations.write`) stores a new
  version (numbered from 1, never changed) of a named template (`name`: 1–63
  lowercase letters, digits and dashes; `description`; `document` with an
  organization `policy`, up to 50 custom `roles` with 1–100 `permissions` and
  no `realm.` or `support.` permissions, up to 50 `groups` with up to 20
  `role_names`, up to 20 `service_principals` (`name` matching
  `^[a-z0-9][a-z0-9-]{0,62}$`, `description`, `role_names`) and up to 20
  `webhooks` (`name`, an `https://` `destination_url`, `event_types`,
  `payload_form`)).
  `GET /organization-templates` (`realm.organizations.read`; `?name=` for one
  template) lists versions, newest first. `POST
  /organizations/{org}/template-applications` (`org.update`; `template`,
  optional `version` (default: the latest) and `dry_run`) returns the plan
  (`create`, `update`, `unchanged`, `conflicts`, `applied`) and, without
  `dry_run`, applies it in one transaction: a differing policy replaces the
  organization's policy, missing roles and groups are created and missing group
  role grants assigned with the caller's authority (delegation ceilings apply),
  and existing items are left alone, so re-applying is idempotent. A role that
  exists with other permissions is a conflict and is never rewritten; any
  conflict fails the application with `409` and `conflicts`. Service
  principals are created as `<organization slug>-<name>`, owned by the
  organization, allowed only for it, with their roles assigned in its scope
  and no credentials; webhook subscriptions are created for the organization,
  limited to public addresses, and the response's `webhook_secrets` maps each
  new subscription's name to its signing secret, shown once and never
  replayed for an `Idempotency-Key`. A template with service principals or
  webhooks needs `org.service_principals.write` or `org.integrations.write`
  in the organization; without it the plan lists a conflict. Event types,
  payload form and destination are validated only when applying, and an
  existing service principal or subscription of the same name is reported
  unchanged without comparing its settings. Audited
  `organization.template.saved` and `organization.template.applied` (category
  `configuration`) (`TestOrganizationTemplates`;
  [ADR 0006](docs/architecture-decisions/0006-realm-and-organization-boundaries.md#update-2026-10)).
- **Dynamic groups** (TEN-014, migration `0033`):
  `PUT /organizations/{org}/groups/{group}/dynamic-rule` (`org.groups.write`)
  with `{"all": [{"attribute": "...", "equals": "..."}]}` (1–5 conditions, each
  with exactly one of `equals` or `in` (at most 20 values)) derives the group's
  members from realm profile attributes: active members of the organization
  whose active account matches every condition, at most 10,000. Only attributes
  of the realm's `profile.attributes` that are not `user_editable` are accepted
  (`422`), so nobody joins a group, or gains its roles, by editing their own
  profile; the caller must be able to grant the group's roles. Setting a rule
  removes manually added members and recomputes at once; `GET` (`org.groups.read`)
  returns `rule`, `recomputed_at`, `member_count` and `error`, and `DELETE` makes
  the group static again (its rule-derived members stay listed but no longer
  grant the group's roles; see **Known limitations**). Members of a dynamic group
  cannot be added or removed by hand (`409`). The worker task `groups.dynamic`
  (every 10 minutes, up to 100 groups per run, least recently recomputed first)
  applies attribute changes; a rule that no longer validates (an attribute was
  removed or became user-editable) removes every rule-derived member and
  records `error`. Changes bump the membership's authorization revision. Setting
  or removing a rule is audited (`group.dynamic_rule.set`), and so is every
  member a rule adds or removes (`group.member.added` / `.removed` with
  `source: "dynamic"`, actor the administrator who set the rule or `system`
  for scheduled runs) and every manual member removed when a rule is set
  (`source: "dynamic_rule_set"`). Rule-derived memberships grant roles only
  while the group was recomputed within `security.dynamic_group_max_staleness`
  (default `1h`) and its rule has no error (AZ-010) (`TestDynamicGroups`;
  [ADR 0006](docs/architecture-decisions/0006-realm-and-organization-boundaries.md#update-2026-10)).
- Organization `registration_mode` (`inherit`, `closed`, `invitation_only`,
  `domain_restricted`) that can only tighten the realm mode (REG-001,
  `TestOrganizationRegistrationMode`).
- Organization-scoped identity providers that organization administrators manage
  under `/organizations/{org}/identity-providers` (TEN-007).
- **ABAC policies** that restrict RBAC (deny or obligations only): versioned,
  approved, published, diffed and rolled back under `/policies`, evaluated with
  missing attributes failing closed; **policy simulation** at
  `POST /authorization/simulate`; conditional role assignments; two-party
  approval for roles marked `requires_approval` (`/role-assignment-requests`)
  (AZ-012..AZ-019, `TestPoliciesAndConditionalGrants`).
- **Decision audit sampling** (AZ-020): `/authorization/check` and
  `/check-batch` record `authorization.decision` (category `authorization`) for
  denials, privileged actions and support tokens; realm policy
  `data_access.sample_allowed_decisions_percent` (0–100, default 0) also records
  that share of the other allowed decisions, marked `metadata.sampled: true`.
  Every refused authenticated API request is recorded once as
  `authorization.denied` (reason `PERMISSION_REQUIRED`; metadata `method` and
  `route`, the path with IDs replaced by `{id}`, plus `permission` when one
  permission was missing and `concealed` when the organization's existence was
  hidden with 404; never the body or query) (`TestDecisionAuditSampling`;
  [ADR 0013](docs/architecture-decisions/0013-authorization-model.md#update-2026-10)).
- **Decision cache contract** (AZ-019): decisions of `/authorization/check`
  and `/check-batch` made by RBAC alone (a `NOT_PERMITTED` denial, or an allow
  of a non-privileged action with no applicable ABAC policy, active pre-action
  hook or obligation; never for support tokens) carry `cache_key` (SHA-256
  over realm, subject, actor, client, organization, resource, action, the
  subject's authorization revision, the policy version and the asserted
  context) and `cache_ttl_seconds` from the new `security.decision_cache_ttl`
  (default `30s`, `0` disables); every other decision has
  `cache_ttl_seconds: 0` (`TestDecisionCacheContract`;
  [ADR 0013](docs/architecture-decisions/0013-authorization-model.md#update-2026-10)).
  The SDKs do not cache decisions yet; see **Known limitations** for what the
  key does not cover.
- Support capability conditions on operator role assignments (organizations,
  target categories, support modes and scopes), re-checked on every use of a live
  grant (IMP-002, IMP-007, `TestSupportCapabilityProfile`).
- Authorization inspection with provenance: `GET /subjects/{subject}/permissions`,
  `GET /me/permissions` and organization-scoped
  `GET /organizations/{org}/members/{membership}/permissions`, with realm sources
  and policies redacted where the caller may not see them (AZ-009,
  `TestAuthorizationInspection`).
- **Account merges** (USR-011, migration `0022`): an administrator with
  `realm.users.write` proposes `POST /users/{user}/merges` (`source_user_id`,
  `reason` of 10+ characters; both accounts active, registered (not guests) and
  not protected). The stored
  plan lists identifiers and upstream links to move, duplicate identifiers to drop,
  memberships to move with the plain member role, the source's roles for review
  (never copied) and credentials that are not transferred. Both owners are
  notified and each confirms with recent authentication
  (`GET /me/account-merges`, `POST /me/account-merges/{id}/confirm`); then an
  administrator runs `POST /account-merges/{id}/execute`, which re-plans against
  current state and, in one transaction, moves the data, revokes the survivor's
  sessions, deletes the source account, records its ID as a subject alias
  (`GET /subject-aliases/{id}`, `realm.users.read`) and emits the `user.merged`
  event. Requests can be confirmed or executed for 7 days (`TestAccountMerge`).
- **Customer-approved support access** (IMP-022): when the realm's
  `impersonation.approval` or the organization's `impersonation_approval` is
  `customer`, the target user is emailed at request time, sees pending requests
  (reason and ticket, not the operator) at `GET /me/impersonation-requests`, and
  approves with `POST /impersonation-requests/{id}/approve` or refuses with
  `POST /impersonation-requests/{id}/deny` using an account-audience token. The
  deny route also lets the requester withdraw and lets policy approvers refuse
  (`TestCustomerApprovedSupportAccess`).
- Personal access token ceilings (MCH-006): scopes are limited at creation to the
  owner's current authority and narrowed again on every introspection, and
  organization policy `personal_tokens: "disabled"` refuses organization-bound
  tokens while `personal_token_max_days` caps their lifetime
  (`TestPersonalTokenCeiling`). Credential inventory flags `owner_departed`,
  `over_privileged` and `no_expiry` (client secrets) besides `expiring`, `unused`
  and `ownerless`, and `POST /credential-inventory/revocations` revokes up to 100
  API keys, personal tokens or client secrets with per-item results (MCH-007,
  MCH-016, APP-014, `TestCredentialInventory`;
  [machine-clients.md](docs/integrations/machine-clients.md)).
- **Service-principal owner departure** (MCH-007, migration `0031`): the hourly
  worker task `machine.owner_departures` finds active service principals whose
  `owner_user_id` is no longer an active user (for example suspended, locked or
  deleted), records when that was detected and audits `service_principal.owner_departed`
  once (subject: the owner). Realm policy `machine.owner_departure` `flag`
  (default) only reports; `disable` disables the principal
  `machine.owner_departure_grace_days` (0–90, default 0) after the detection,
  with the effects of `POST /service-principals/{id}/disable` (API keys and
  opaque tokens revoked, `service_principal.disabled` with reason code
  `owner_departed`, `service_principal.state_changed` event), at most 100 per
  realm and run. An owner who is active again clears the marker
  (`TestServiceOwnerDeparture`;
  [machine-clients.md](docs/integrations/machine-clients.md#owner-departure)).
- **Account lifecycle jobs** (USR-015, migration `0027`): realm policy
  `lifecycle.dormant_days` (0 disables, at most 3650) with
  `lifecycle.dormant_action` `report` (default; audit `user.dormant_detected`
  once per dormancy) or `suspend`, and `lifecycle.guest_ttl_days` (default 30)
  for deleting guest accounts unused that long. Administrators schedule a
  suspension with `PUT /users/{user}/scheduled-deactivation {"at", "reason"}` and
  cancel it with `DELETE` (`realm.users.suspend`; audited
  `user.deactivation_scheduled` / `user.deactivation_cancelled`); administrator
  user views show `deactivate_at`. The worker task `lifecycle.users` (every
  10 minutes) applies these rules and the expiry of unverified registrations
  (`lifecycle.unverified_account_ttl_hours`) to at most 100 accounts per rule and
  realm per run, re-checking each account in its own transaction;
  `GET /lifecycle/preview` (`realm.users.read`) is the dry run. Protected accounts
  are never treated as dormant (`TestUserLifecycleJobs`;
  [data-inventory.md](docs/operations/data-inventory.md#account-lifecycle-jobs)).
- **Bulk user operations** (USR-016): `POST /user-bulk-operations` with `action`
  (`suspend`, `reactivate`, `lock`, `revoke_sessions` or `add_required_action`
  with `required_action`), 1–1000 unique `user_ids`, a `reason` of 5–500
  characters and optional `dry_run` queues a `user.bulk` job. It needs an MFA
  session and the action's permission (`realm.users.suspend`,
  `realm.users.sessions.revoke` or `realm.users.required_actions`), re-checked
  when the job runs; an `Idempotency-Key` returns the same job. Each account is
  handled in its own transaction with a checkpoint every 50 records; protected
  accounts are skipped (except for `revoke_sessions`), and so is the requester's
  own account for `suspend` and `lock`. The job result lists only `user_id`,
  `outcome` (`applied`, `valid`, `skipped`, `failed`) and `code` per account
  (`TestBulkUserOperations`; [exit-and-export.md](docs/operations/exit-and-export.md#bulk-user-operations)).
- **External IDs** (USR-017): `GET /users/{user}/external-ids`
  (`realm.users.read`), `PUT /users/{user}/external-ids/{source}
  {"external_id": "..."}` and `DELETE` (`realm.users.write`; audited
  `user.external_id.set` / `.removed` with the source system only), and the
  lookup `GET /external-ids/{source}/{id}` (`realm.users.read`). An account holds
  one ID per source system (names matching `^[a-z0-9][a-z0-9._-]{0,62}$`, values
  of 1–256 printable characters); IDs are unique within a source system only and
  share the `import_mappings` table with user imports (`TestExternalIDs`;
  [data-inventory.md](docs/operations/data-inventory.md#accounts-and-credentials)).
- **Identity read evidence** (USR-018, AUD-015): with realm policy
  `data_access.log_identity_reads`, `GET /users/{user}` records `user.read` and
  `GET /users` records `user.search` (with `result_count` and `filtered`) in the
  audit category `data_access`, with the actor, the account (for reads) and
  whether the view was `masked`; the event is written before the data is
  returned, and the request fails if it cannot be written. Support operators with
  only `support.users.read` keep receiving masked views. This replaces the
  earlier `user.search` evidence, which was recorded only for holders of
  `realm.users.sensitive.read` (`TestIdentityReadEvidence`).
- **Consent management** (APP-013, migration `0029`): clients take
  `consent_terms_version` (at most 64 characters). A consent records the terms
  version it was given for and covers the client only while that version is
  current, so changing the version asks users again at their next authorization
  (existing grants are not revoked); the `consent` action's `options` carry
  `terms_version`. Administrators see a user's consents with
  `GET /users/{user}/consents` (`realm.users.read`; `?history=true` adds revoked
  ones) and revoke one with `DELETE /users/{user}/consents/{id}`
  (`realm.users.write`), which also revokes the client's grants for that user.
  **Pre-authorization:** `POST /clients/{client}/consent-preauthorizations`
  (`realm.clients.write`; `scopes`: 1–50 existing scopes, never
  `offline_access`; `reason` of at least 5 characters; optional
  `organization_id`) consents on behalf of the realm or one organization for the
  client's current terms version. Users signing in through that organization (or
  any, for realm-wide ones) are not asked when a pre-authorization covers every
  requested scope, and a consent with `mode: preauthorized` is recorded.
  `GET` lists a client's pre-authorizations (`realm.clients.read`), and
  `DELETE .../consent-preauthorizations/{id}` revokes one together with every
  consent and grant that relied on it. Audited `consent.preauthorized` and
  `consent.preauthorization_revoked` (category `configuration`) and
  `consent.revoked` (`TestConsentManagement`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#consent)).
- **Organization deletion workflow** (TEN-024): the deletion preview also
  counts role assignments, groups, verified domains, owned service
  principals, active automation credentials, webhook subscriptions, identity
  providers, the mail server, consent pre-authorizations, export results,
  pending jobs, retained audit events and active legal holds, and lists what
  is retained. Starting a deletion now also disables the organization's
  service principals, webhook subscriptions and identity providers, revokes
  its consent pre-authorizations, erases its job results and cancels its
  other jobs; finishing it deletes its notification settings (mail server and
  password) and webhook subscriptions and erases identity-provider client
  secrets (`TestOrganizationDeletionWorkflow`;
  [data-inventory.md](docs/operations/data-inventory.md#organization-deletion)).
- **Deletion propagation report** (PRV-005):
  `GET /users/{user}/deletion-status` (`realm.users.read`) shows, for a
  deleted account, the state of each place its data lived (primary storage,
  sessions and grants, exports, notifications, connectors, imported audit
  history, caches, audit evidence, backups), derived from current data
  (`TestDeletionPropagationStatus`;
  [data-inventory.md](docs/operations/data-inventory.md#deletion-propagation-report)).

- **SCIM 2.0 inbound provisioning** (PROV-001..PROV-009, PROV-018, TEN-015,
  migration `0042`; `internal/provisioning`, `TestSCIMProvisioning`):
  organization administrators holding `org.integrations.write` (built-in
  `owner`, not `admin`) manage connectors at
  `/organizations/{org}/provisioning-connectors` (writes from an MFA session;
  `PUT` with `If-Match`; `POST .../{id}/token` rotates the bearer token, which
  is shown once and stored as a digest). A connector's `role_ceiling_ids` must
  be within its creator's delegation ceiling, and its `group_role_mappings`
  and `default_role_id` within that ceiling. The SCIM endpoint
  `/api/v1/realms/{realm}/scim/v2` serves `ServiceProviderConfig`,
  `ResourceTypes`, `Schemas`, `Users` and `Groups` (list with filters,
  `attributes`/`excludedAttributes` and paging, create, read, `PUT`, `PATCH`,
  `DELETE`) with ETags, 1200 requests per minute per connector, and SCIM error
  documents; bulk, sort and password change are not advertised. A connector
  sees only what it provisioned (its own `externalId` namespace), adopts an
  existing account only when its verified email is in a domain the
  organization verified (never protected accounts or holders of realm-scoped
  roles), changes identity attributes only of accounts it created that belong
  to no other organization (`400 mutability` otherwise), and treats `active`
  and `DELETE` as the organization membership's state, never the account's.
  Group roles come only from approved mappings. Each connector reports
  `last_sync_at`, `last_error` and per-operation `stats`. Audit:
  `provisioning.connector.*`, `scim.user.provisioned` / `.updated` /
  `.deprovisioned` ([scim-provisioning.md](docs/integrations/scim-provisioning.md),
  [incidents.md](docs/operations/incidents.md#provisioning-connector-token-compromise)).
- **Ownership transfer** (USR-020, APP-001, APP-014,
  `TestDeletionNeedsOwnershipTransfer`): `POST /users/{user}/ownership-transfer
  {"to_user_id"}` moves every project, client, service principal, resource and
  identity provider an account owns to another account of the realm in state
  `active` or `recovery_restricted` (it needs the write permission of each
  kind) and answers `{"transferred": {"<kind>": <count>}}`. Each move is
  audited as `<kind>.ownership_transferred` (category `configuration`,
  `previous_owner_user_id`, `owner_user_id`). A single project still moves
  with `POST /projects/{project}/ownership-transfer` (`owner_user_id` and/or
  `owner_organization_id`, `reason`; `project.ownership_transferred`). See
  **Changed** for the deletion rule
  ([data-inventory.md](docs/operations/data-inventory.md#account-deletion)).
- **Conditional updates of settings and grants** (API-010, DB-010,
  `TestConditionalSettingsUpdates`): `GET /clients/{client}/resource-grants/{resource}`
  (new, `realm.clients.read`) returns the grant with a content `ETag`
  (`W/"g..."`) that `PUT` accepts as `If-Match`; `GET /notification-settings`
  returns `W/"c..."` for `PATCH`; `GET` and `PUT
  /organizations/{org}/notification-settings/smtp` return an `ETag` that `PUT`
  accepts; `POST /roles/{role}/permissions` and
  `POST /organizations/{org}/roles/{role}/permissions` accept the role version
  (`W/"vN"`; the realm route returns the new `ETag`). `If-Match` is optional on
  all of them; a stale value is `412 precondition_failed`
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#scopes-and-resources),
  [ADR 0016](docs/architecture-decisions/0016-delivery-adapters.md#decision)).
- **Support write allowlist on the decision API** (IMP-011): resources take
  `impersonation_policy.write_actions` (OpenAPI and configuration document);
  see **Security fixes**
  ([resource-servers.md](docs/integrations/resource-servers.md#6-support-access-contract)).
- `GET /organizations/{org}/invitations/{id}` (`org.invites.read`) returns one
  invitation with its `ETag`; invited users decline with
  `POST /invitations/decline {"invitation": "<secret>"}` (`204`, audited
  `invitation.declined`).
- **Organization relationships** (TEN-021, migration `0081`):
  `parent_child` and `partner` relationships between organizations of a
  realm, proposed by organization administrators and accepted by the other
  side, or recorded directly by realm administrators; one parent per child,
  no cycles, at most 10 levels. A relationship grants no membership, role or
  permission. New permissions `org.relationships.read`,
  `org.relationships.write` and `org.projects.share`.
- **Partner project access** (TEN-020): an owner organization shares a
  subset of a project's roles with a related organization
  (`/organizations/{org}/projects/{project}/grants`), which assigns only that
  subset to its active members (`/organizations/{org}/project-role-assignments`,
  `403 grant_ceiling_exceeded` beyond it). Revoking the grant or removing the
  member removes those assignments
  (`TestOrganizationRelationshipsAndPartnerProjects`;
  [partner-access.md](docs/integrations/partner-access.md)).
- **Relationship-based authorization** (AZ-021, AZ-022, AZ-023, AZ-027,
  migration `0053`): resource types (`/resource-types/{name}`) with
  relations, `implied_by`, one-hop links and the application permissions
  each relation gives; relationship tuples per organization
  (`/organizations/{org}/relationships`, up to 100 atomic writes, subjects
  confined to the organization); object-level decisions in
  `/authorization/check` when RBAC does not grant, bounded at depth 6,
  64 object reads and 1000 tuples per object, never cacheable;
  `POST /authorization/list-objects` returning only verified objects (or
  `all: true`); user-managed sharing (`/me/shares`). New permissions
  `realm.resource_types.read`/`write` and `realm.relationships.read`/`write`
  for the built-in `resource-server` role (the read ones also for
  `realm-auditor`) (`TestRelationshipAuthorization`;
  [relationship-authorization.md](docs/integrations/relationship-authorization.md)).
- **External policy engines** (AZ-026): operator-configured
  `security.policy_engines` (HTTPS, bearer token, timeout at most 5 s) that a
  realm names in its policy `policy_engine` (`restrict`, the default, or
  `decide`; `on_error` `deny` or `local`). The decision API sends the subject,
  action, resource, context and local result; accepts native or OPA data API
  answers; denies with `EXTERNAL_POLICY_DENIED` or
  `EXTERNAL_POLICY_UNAVAILABLE`; and never marks such decisions cacheable
  (`TestExternalPolicyEngine`;
  [policy-engines.md](docs/integrations/policy-engines.md)).
- **Just-in-time elevation** (AZ-024, migration `0054`): eligibilities
  (`/elevation-eligibilities`, 5 minutes to 7 days, approval required for
  privileged roles), requests from a recent MFA session with a reason
  (`/me/elevations`), approval by someone else who could assign the role, and
  an ordinary expiring role assignment (`source: elevation`) removed by the
  expiry sweep (`TestJustInTimeElevation`;
  [elevation-and-access-reviews.md](docs/integrations/elevation-and-access-reviews.md)).
- **Access reviews** (AZ-025, migration `0055`): campaigns that snapshot up
  to 10000 role assignments of the realm or one organization, named reviewers
  who keep or revoke items (never their own), closing by an administrator or
  at the due date that applies revocations and records each outcome, and an
  evidence export that "documents an access review; it is not a regulatory
  certification". New privileged permission `realm.access_reviews.manage`
  (`TestAccessReviews`;
  [elevation-and-access-reviews.md](docs/integrations/elevation-and-access-reviews.md#access-reviews)).
- **Agents** (MCH-017): service principals with `is_agent: true` need an
  accountable human owner; assigning them a privileged role (including
  through composition and custom permissions registered as privileged)
  answers `202 pending_approval` and needs a second administrator; their
  tokens carry the reserved claim `agent: true` (also in introspection), and
  `act.agent` marks exchanges they perform (`TestAgentPrincipals`;
  [machine-clients.md](docs/integrations/machine-clients.md#agents)).
- **Ownership report** (DOM-009, APP-014, MCH-007, migration `0047`):
  `GET /ownership-report` lists live clients, projects, service principals,
  resources, identity providers, webhooks, hooks and authorization policies
  that are `ownerless` or `owner_departed`; `POST /policies` and
  `POST /hooks` accept `owner_user_id` (default the creating user)
  (`TestOwnershipReport`;
  [machine-clients.md](docs/integrations/machine-clients.md#ownership-report)).

#### Evidence, delivery and integrations

- Audit events written in the same transaction as each change, append-only
  trigger, redaction, hash-linked batches, verification (`identity-cli
  verify-audit`, API), scoped query and NDJSON export.
- Transactional outbox; signed webhooks with retries, dead-lettering, replay and
  secret rotation with 24 h dual signing (TEST-054, TEST-058); SSRF-restricted
  egress for webhooks, back-channel logout, SMS gateway and federation (TEST-052).
- Email over SMTP; SMS through an operator-run HTTPS gateway with signed requests,
  a country allowlist and a daily budget; development sinks; per-realm and
  per-organization templates and sender settings.
- Asynchronous jobs: user, audit and configuration exports with single-use
  download tokens (TEST-069); bounded user import with dry run (submitted records
  encrypted and erased after the job, migration `0007`); configuration-as-code
  validate, import and export.
- **Signed audit batches** (Ed25519 key derived from the root key) and
  retention-aware verification: pruned batches are recorded in the append-only
  `audit_prunes` ledger (migration `0011`) and still verify;
  `identity-cli verify-audit -require-signatures` (AUD-008, AUD-009,
  `TestAuditSignaturesAndRetention`).
- **Audit search dimensions** (AUD-011): `GET /audit-events` and
  `GET /organizations/{org}/audit-events` also filter by `grant_id`,
  `session_id` (the event's session or the actor's session), `target_id`,
  `category` and `network`: an IP address or CIDR prefix, matched by overlap with
  the truncated network context stored with each event, so an address finds the
  events of its /24 or /48 (or exact matches when `privacy.store_full_ip` is set)
  (`TestAuditSearchDimensions`; [monitoring.md](docs/operations/monitoring.md#audit-queries)).
- **Session-event stream** `GET /session-events` (SES-019): gap-free, ordered by
  commit horizon (migration `0012`), long-poll with a resumable cursor, 7-day
  history (`TestSessionEventStream`).
- **Delivery feedback, sender control and notification preferences**
  (migration `0019`, `TestMessagingControls`):
  - `POST /delivery-events` accepts up to 500 `delivered`, `bounce` and
    `complaint` events from the email provider, signed with Standard Webhooks
    headers under `delivery.email.events_secret` (the route answers
    `404 feature_disabled` without a secret). Permanent bounces and complaints
    suppress the address for optional notices; a bounce marks the job with that
    `provider_message_id` `failed`. Feedback never verifies or changes an
    identity (MSG-007).
  - `GET`/`PUT /me/notification-preferences`: users can mute optional notices
    (currently the new-login alert); security and account notices cannot be
    muted (`422`) and are delivered even to suppressed addresses (MSG-010).
  - A realm sender address must use a domain listed in
    `delivery.email.allowed_sender_domains` or the domain of
    `delivery.email.from`; an organization sender must use one of the
    organization's verified domains (MSG-005).
  - `POST /notification-settings/check` (`realm.notifications.write`) tests the
    SMTP connection, TLS and authentication without sending a message and
    reports only the failing stage (MSG-012).
- **Localized notices** (MSG-006): a notice addressed to an account is written
  in the account's `locale` when the message sets none (without either, the
  realm's or organization's default locale; templates then fall back to the base
  language and to English), and its `time`, `expires` and `scheduled` values
  are rendered in the account's
  `zoneinfo` time zone (for example `2 Jan 2026 21:04 JST`). Messages without an
  account, and accounts without a valid time zone, use UTC
  (`TestNoticeTimeZones`;
  [ADR 0016](docs/architecture-decisions/0016-delivery-adapters.md#decision)).
- **Organization mail servers** (TEN-022):
  `PUT /organizations/{org}/notification-settings/smtp` with `host`, `port`
  (25, 465, 587 or 2525), `tls_mode` (`starttls` or `implicit`; plain text is
  refused) and optional `username` and `password` sends the organization's
  email through its own SMTP server. It needs the new privileged permission
  `org.integrations.write` (held by the organization `owner` role, not by
  `admin`) and, for users, an MFA session. The password is encrypted
  (AES-256-GCM, bound to the realm and organization, so it decrypts only for
  that organization's mail), is never returned (`GET`, which also needs
  `org.integrations.write`, shows `has_password`) and is kept when a later `PUT`
  omits it. Every resolved address of the server must pass the delivery egress
  policy (`delivery.egress_allowlist` for private addresses) at connection
  time. `DELETE` returns the organization to the deployment relay. Audited
  `notification.smtp.updated` (host, port, TLS mode and whether the password
  changed) and `notification.smtp.cleared` (category `configuration`). The
  development sink still takes precedence, and
  `POST /notification-settings/check` tests only the deployment relay.
  Upstream identity-provider client secrets (including organization-scoped
  connections) and webhook signing secrets are likewise encrypted with their
  connection's or subscription's ID as associated data, so each decrypts only
  for its own integration. SCIM connector tokens are stored only as SHA-256
  digests (`TestTenantSMTPCredentials`;
  [ADR 0016](docs/architecture-decisions/0016-delivery-adapters.md#decision)).
- **Audit retention by category and legal holds** (AUD-009, migration `0035`):
  `privacy.audit_retention_by_category` maps audit categories to their own
  retention (each at least `24h`), overriding `privacy.audit_retention` for those
  categories; `emergency` is refused because emergency events are never pruned,
  and so is any name that is not an audit category (see **Changed**).
  **Legal holds:** `POST /audit-legal-holds` (`realm.audit.legal_hold`, held by
  `realm-admin`) with a `reason` of 5–500 characters and optional
  `organization_id` and `subject_id` keeps every matching event of the realm
  (all events, the organization's events, and/or events whose subject or actor
  is `subject_id`) from being pruned until
  `POST /audit-legal-holds/{id}/release`; `GET /audit-legal-holds` lists the
  realm's holds, active first. Audited `audit.legal_hold.placed` and
  `audit.legal_hold.released` (category `audit`; a release raises the
  `configuration_change` security signal)
  (`TestAuditRetentionCategoriesAndHolds`;
  [configuration.md](docs/operations/configuration.md#privacy)).
- **Audit archive** (AUD-008, migration `0037`): with `privacy.audit_archive_dir`
  set, the worker task `audit.archive` (every minute, up to 500 batches per run)
  writes every sealed batch after the last archived one to that directory as a
  write-once, read-only file `batch-<12-digit sequence>.ndjson`: a header line
  with the batch hash, chain link, signature, event count and, for batches
  pruned before the archive existed, `archived_events`, then the batch's events
  as recorded. An existing file is accepted only if it is byte-identical. While
  an archive is configured, retention prunes only batches already archived.
  After a database restore, a batch that reuses an archived sequence number
  with other content starts a fork directory `fork-<sequence>-<batch id>/`
  where archiving continues (migration `0039`, operator event
  `audit.archive.forked`). Mount storage you control independently there,
  ideally with retention locks. `identity-cli verify-audit-archive [-dir
  <path>]` checks the directory and its forks without the database (it reads
  the configuration only for the keys): event content hashes, batch digests,
  batch hashes, the hash links between files, missing sequence numbers, the
  first batch's link, event counts against `event_count` and
  `archived_events`, each fork's link to the main archive, and batch
  signatures (always required); it reports `first_sequence`, `last_sequence`
  and `forks`, and exits non-zero on problems (`TestAuditArchive`;
  [incidents.md](docs/operations/incidents.md#audit-chain-verification-failure)).
- **Reported application activity** (AUD-013): a service principal holding
  `realm.activity.report` records application activity in the realm's audit
  log with `POST /activity-events`: `type` (`app.` followed by up to 96
  lowercase letters, digits, dots and underscores), optional `occurred_at`
  (within the last 24 hours and at most 5 minutes ahead), `organization_id` (an
  existing organization), `subject` (`user` or `service_principal`), `outcome`
  (`success` by default, `failure` or `denied`) and `metadata` (at most 4 KiB,
  redacted like server metadata). Reported events carry `source: application`,
  category `application` and `reporting_service` (the caller's client ID), so
  they are told apart from server-generated evidence, and are sealed into the
  chain like any event. The response is `202` with `id`, `source` and
  `reporting_service`; user tokens are refused (`403`)
  (`TestReportedApplicationActivity`;
  [monitoring.md](docs/operations/monitoring.md#audit-queries)).
- **Security alerts** (AUD-012): every audit event of a realm that carries a
  security signal is also published, in the same transaction, as the webhook
  event `security.alert` with identifiers only (`signal`, `audit_event_id`,
  `event_type`, `actor_type`, `actor_id`, optional `subject_type` and
  `subject_id`). New signals: `protected_account_signin` (a protected account
  signed in), `privileged_grant` (an assignment of an owner role, a realm
  role, or a role holding a permission the catalog marks `privileged`,
  directly or through a role it composes; not the built-in organization
  `member` and `admin` roles) and
  `configuration_change` (`realm.policy.updated`, `federation.provider.*`,
  `hook.created`, `hook.updated`, `webhook.created`,
  `audit.legal_hold.released`); they are counted in
  `proudauth_security_signals_total` too. Both payload forms carry every
  member of the alert, and `GET /audit-events?id=<audit_event_id>` (also on
  the organization route) returns the audit event it refers to
  (`TestSecurityAlerts`;
  [api/events/README.md](api/events/README.md)).
- **Webhook backlog** (EXT-005): `GET /webhooks/{id}/backlog`
  (`realm.webhooks.read`) returns the subscription's delivery counts
  (`pending`, `retrying`, `dead_letter`, `delivered`), `oldest_due_seconds` (how
  long the oldest due pending or retrying delivery has waited),
  `last_delivered_at` and `last_failure_category` (of the newest retrying or
  dead-lettered delivery) (`TestWebhooksAndBackchannelLogout`;
  [webhooks.md](docs/integrations/webhooks.md#delivery-semantics)).
- **Hook diagnostics** (EXT-017, migration `0036`): every pre-action hook call is
  recorded in `hook_invocations` with its outcome, latency and a coarse
  `error_category` (`status` with `status_code`, `timeout`, `egress_denied`,
  `malformed_response`, `unreachable` or `error`), never the payload or
  response; `retention.cleanup` removes records older than 7 days.
  `GET /hooks/{id}/diagnostics` (`realm.hooks.read`) returns the last 100
  invocations with `recent_invocations`, `recent_failures`, `latency_p50_ms`,
  `latency_p95_ms` and `health` (`unknown` without calls, `degraded` when more
  than 10 % of them failed, otherwise `healthy`) (`TestPreActionHooks`;
  [monitoring.md](docs/operations/monitoring.md#suggested-alerts)).
- **Audit corrections** (AUD-007): `POST /audit-events/{id}/corrections`
  (`realm.audit.correct`, privileged; `reason` 5–1000 characters, optional
  `correction` object of at most 8 KiB) records `audit.correction` linked to
  the original (target `audit_event`, metadata `corrects_event_id`,
  `corrects_type`, `reason`, `correction`) and answers
  `201 {"event_id", "corrects_event_id"}`; the original never changes. Find
  them with `GET /audit-events?type=audit.correction&target_id=<id>`
  (`TestAuditCorrections`;
  [data-inventory.md](docs/operations/data-inventory.md#audit-corrections)).
- **Scoped audit retention** (AUD-009): realm policy `audit.retention_days` and
  organization policy `audit_retention_days` (30–3650) keep that scope's
  evidence longer; an event is pruned only when every retention that applies
  (category or deployment, realm, organization) has passed and no legal hold
  covers it
  ([data-inventory.md](docs/operations/data-inventory.md#audit-retention-and-legal-holds)).
- **Lifecycle workflows** (EXT-015, EXT-016, migration `0070`): realm-scoped,
  versioned definitions (`schema_version` 1,
  `api/workflows/definition.v1.json`) with event triggers (eight user and
  membership event types), schedule triggers (fixed selectors of role
  holders or organization members, at most 500 runs per firing) and manual
  starts, and a bounded step vocabulary (`wait`, `approval`, `assign_role`,
  `add_to_group`, `remove_access`, `notify` with fixed notice codes and the
  new mandatory `workflow_notice` template, `call_webhook`, `suspend_user`,
  `end`); no expressions, conditions or loops. Revisions are immutable and
  are approved, published and rolled back; the publisher is the accountable
  actor, checked against the delegation ceiling at publication and again
  inside every effect's transaction. Runs are durable and leased by the new
  worker tasks `workflows.run` and `workflows.schedule`; every step attempt
  is recorded with its idempotency key, input version, result, retry policy
  and compensation strategy, internal effects commit atomically with the
  attempt, endpoint calls carry a stable `Idempotency-Key`, and failed runs
  compensate (undo their own grants, notify endpoints). Approvals by named
  approvers through `/me/workflow-approvals`. New permissions
  `realm.workflows.read`, `.write`, `.publish` and `.run`; realm policy
  `extensions.workflow_publish_approval`; `GET /workflows/{id}/diagnostics`;
  disabling a workflow is audited in category `emergency`; events a run
  causes carry the run ID as `correlation_id` (`TestWorkflowDelegationCeiling`,
  `TestWorkflowIdempotency`, `TestWorkflowScheduleAndOffboarding` and others;
  [workflows.md](docs/integrations/workflows.md)).
- **Plugins** (EXT-014, migration `0071`): signed configuration bundles of
  pre-action hooks, webhook subscriptions and workflows. Packages carry an
  Ed25519 signature over the manifest (domain `proudauth-plugin-v1\n`), which
  binds the payload by SHA-256, by a publisher key the operator lists in the
  new configuration `extensions.plugin_publishers` (no unsigned mode).
  Upload, second-administrator review (realm policy
  `extensions.plugin_review`, `second_admin` by default), install, upgrade,
  downgrade, rollback, enable, disable (an emergency control) and uninstall,
  with declared permissions checked for uploader, reviewer and installer,
  dependency checks, compatibility checks against the extension contracts,
  and parts reconciled by name so endpoints keep their signing secrets;
  ordinary edits of plugin parts answer `409`. New permissions
  `realm.plugins.read`, `.manage` and `.approve` (`TestPluginLifecycle`,
  `TestPluginSingleAdminReview`;
  [plugins.md](docs/integrations/plugins.md)).
- **Extension contract versions** (EXT-018, migration `0072`): webhook
  events, the pre-action hook contract, plugin manifests and workflow
  definitions are versioned independently of each other and of releases;
  `GET /extension-contracts` lists the versions. Webhook subscriptions choose
  `event_version` 1 (default; byte-for-byte the previous envelope) or 2
  (envelope with `organization_id` instead of `org_id` and a `payload_form`
  member; `api/events/envelope.v2.json` and `<type>.v2.json`); hooks pin
  `contract_version` (1), sent as the `ProudAuth-Hook-Version` header, and a
  response echoing another version fails as the hook kind fails; JSON
  Schemas for hook requests and responses in `api/hooks`. A version stays
  supported at least 12 months after its successor (`TestContractVersions`;
  [extension-contracts.md](docs/integrations/extension-contracts.md)).
- **No embedded code execution** (EXT-013): ProudAuth ships no interpreter,
  expression language or WASM runtime; custom logic stays in hooks, webhook
  receivers and workflow endpoints, and workflow definitions and plugin
  packages refuse unknown members such as `script`
  ([ADR 0021](docs/architecture-decisions/0021-no-embedded-code-execution.md)).
- **LDAP and Active Directory federation and synchronization**
  (PROV-011..PROV-014, PROV-017, PROV-018, FED-015, USR-022; migration
  `0065`; `internal/directory`; `TestLDAPDirectorySignIn`,
  `TestDirectorySynchronization`, `TestDirectoryAuthority`,
  `TestDirectoryTenantIsolation`): directory connectors at
  `/api/v1/realms/{realm}/directory-connectors` (realm workforce
  connectors, which grant no organization access) and
  `/organizations/{org}/directory-connectors` (`org.integrations.write`;
  memberships, groups and roles only in that organization, within a ceiling
  bounded by the creator's). Ordered `ldaps://` or StartTLS endpoints with
  verified TLS, failover only on transport errors, referrals never
  followed, egress checks at connection time (new `directory.*` keys); an
  encrypted, write-only service-account credential. Passwords of
  directory-sourced accounts are verified by a bind as the user and fail
  closed (`503 upstream_unavailable`, never a local password); realm
  connectors can provision accounts at first sign-in. Full and incremental
  runs (Active Directory USN bound to the domain controller, OpenLDAP
  `modifyTimestamp`) as `directory.sync` jobs scheduled by the worker task
  `directory.schedule`, with dry runs, conflict findings that never merge
  accounts, adoption only through an organization's verified domain, a
  deletion threshold with an audited override, and deprovisioning that
  suspends the account (realm) or removes or suspends only the membership
  (organization). Read-only, import-only and write-back modes; local edits of
  externally managed attributes, password changes and reactivation of
  directory-disabled accounts are refused on every path with
  `409 conflict` (`externally_managed`), and
  `GET /me/attribute-authority` and `/users/{user}/attribute-authority`
  declare what is editable. Connector health (`.../health`), runs and
  findings; metrics `proudauth_directory_*`; audit `directory.*`.
  Kerberos/SPNEGO and password write-back are not offered. **Tested only against an
  in-process LDAP server, not against real directories**
  ([directory.md](docs/integrations/directory.md),
  [directory threat model](docs/threat-models/directory.md)).
- **Outbound SCIM provisioning** (PROV-010, PROV-017; `TestOutboundProvisioning`):
  `scim_outbound` directory connectors push eligible accounts (and,
  for organization connectors, chosen groups) to a downstream SCIM 2.0
  service with a write-only bearer token: outbox events, a change scan and
  reconciliation runs feed coalesced, level-triggered deliveries (worker
  task `directory.outbound.deliver`) with `externalId` = the account ID,
  only verified emails, exponential backoff, dead-lettering and replay, a
  fair share per connector, and reconciliation findings that never delete
  resources the connector did not create. **Tested only against an
  in-process SCIM double**
  ([outbound-provisioning.md](docs/integrations/outbound-provisioning.md)).
- New permission `realm.provisioning.read` (held by the built-in
  `realm-auditor` role): read directory and outbound connectors, their runs,
  findings, health and deliveries, never credentials;
  `realm.provisioning.manage` manages them.
- **Shared Signals transmitter** (AUD-016, migration `0058`), a declared
  profile of OpenID Shared Signals Framework 1.0 with CAEP
  `session-revoked`/`credential-change` and RISC account and credential
  events, opt-in per realm (`shared_signals.enabled`). Receivers are machine
  clients holding `realm.ssf_streams.manage`; events are queued with their
  audit evidence, only about users who authorized the receiver unless an
  administrator widens a stream, and delivered as signed Security Event
  Tokens by RFC 8935 push (worker task `ssf.deliver`) or RFC 8936 poll (no
  long polling). Administrators see every stream and its delivery state
  (`/ssf-streams`) (`TestSharedSignalsTransmitter`).
- **Shared Signals receiver** (ADV-007, migration `0083`): transmitters an
  administrator registers (`/ssf-transmitters`) push SETs to
  `I/ssf/receivers/{id}/events` with a push secret; signature, issuer,
  audience, age and replay are checked, subjects map through a federation
  connection or verified email, and each event type maps to an explicit
  action (record only by default; never re-enabling an account or
  suspending a protected one). Records keep no token or subject identifiers
  and are deleted after 30 days (`TestSharedSignalsReceiver`;
  [shared-signals.md](docs/integrations/shared-signals.md),
  [ADR 0022](docs/architecture-decisions/0022-shared-signals-adapter.md)).
- **Container-registry token bridge** (ADV-010, migration `0082`):
  `/registry-services` maps repository patterns to permissions, and
  `I/registry/token` implements the Distribution token protocol, issuing
  short-lived tokens for the registry's audience with only the repository
  actions the principal's permissions and credential scopes allow
  (`TestRegistryTokenBridge`;
  [container-registry.md](docs/integrations/container-registry.md)).
- **Historical entitlement evidence** (ADV-011):
  `POST /investigations/entitlements` (`realm.audit.read`, required reason,
  audited) reconstructs a subject's account state, memberships, groups, role
  assignments and permissions, live OAuth grants, ABAC policy versions and
  realm policy revision at a past instant from retained evidence, with
  completeness and caveats (`TestHistoricalEntitlements`;
  [investigations.md](docs/operations/investigations.md)).

#### Migration

The runbook is [docs/operations/migration.md](docs/operations/migration.md)
(MIG-001..MIG-017); the endpoint reference is
[exit-and-export.md](docs/operations/exit-and-export.md#import-into-proudauth)
(`TestImportFactorsAndDeletionContinuity`,
`TestMigrationPlanningAndReconciliation`).

- **Declared import formats** (MIG-002): `POST /user-imports` takes `format`
  (default `proudauth.user-import.v1`; any other value is refused with `422`),
  and `GET /user-import-formats` (`realm.users.import`) lists each accepted
  format with its source products, schema and `supports` / `unsupported`
  lists.
- **Dry-run plans, conflicts and totals** (MIG-003, MIG-004): a record that
  repeats a `source_id`, email or username of an earlier record of the batch,
  or whose email or username belongs to an existing account, is reported
  `conflict` (imports never merge accounts by matching identifiers), in dry
  runs and real runs. Dry-run results carry a `plan` per record (`mapping`,
  `email_verified`, `password_verifier`, `totp_factor`, and `memberships` with
  `organization_id`, role names and `privileged`), and every result has
  `totals` (`memberships`, `role_assignments`, `privileged_memberships`,
  `trusted_verified_emails`, `password_verifiers`, `totp_factors`).
- **Resumable imports** (MIG-011): the checkpoint saved every 50 records now
  holds the counts, totals and results, so a retried or resumed job keeps the
  results recorded before it; a checkpoint that does not match its position
  restarts the job from the first record (records already created then report
  `already_imported`).
- **Reconciliation report** (MIG-012):
  `GET /user-imports/reconciliation?source_system=...` (`realm.users.import`)
  reports, for the accounts imported from one source system, mappings by
  account state, accounts, memberships, privileged role assignments (up to
  200 listed), credential usability (password, not yet rehashed, TOTP,
  passkey, federated, no sign-in method), verified emails, accounts that have
  signed in and subject continuity, and compares optional `expected_*` counts
  in `mismatches` and `reconciled`; `404` when nothing was imported from that
  source.
- **TOTP seed import** (MIG-007): with `import_totp: true` (requires
  `realm.users.credentials.manage` and an MFA session, re-checked by the
  worker), records may carry `totp_secret` (base32, 80–512 bits; SHA-1, 6
  digits and 30 s assumed). Seeds are re-encrypted under the deployment's data
  key and audited as `mfa.totp.imported`; a record with a seed fails without
  `import_totp`.
- **Deletion continuity** (MIG-017): a `source_id` mapped to an account that
  was deleted since is reported `skipped_deleted`, like an email or username
  released by an account deletion, so an import never recreates a deleted
  account.
- **Historical audit import** (MIG-016, migration `0038`): `POST /audit-imports`
  (new privileged permission `realm.audit.import`, MFA session) files up to
  500 records of a source system's audit history per request in the new table
  `imported_audit_events`, apart from local evidence: never sealed into the
  hash chain, always reported with `source: "import"` and `verified: false`,
  subjects mapped through the user import mappings of the same source system,
  duplicates by `source_event_id` left unchanged. Each request records one
  local `audit.history.imported` event (category `audit`) with a
  `batch_digest` over the records' content hashes. `GET /imported-audit-events`
  (`realm.audit.read`) lists them by source system, subject, organization,
  type, batch and time. Retention is counted from the import
  (`privacy.audit_retention`, or the new category `imported` of
  `privacy.audit_retention_by_category`; legal holds apply), and account
  deletion clears the source-supplied details of records about the account.
- **Realm data export** (OSS-008, MIG-014): `POST /data-exports`
  (`realm.data.export`, privileged; recent authentication) queues a
  `realm.export` job whose NDJSON file (`proudauth.realm-export.v1`) holds a
  header listing what is excluded, the configuration document, and the
  realm's accounts (identifiers, external IDs, linked identities and a
  credential summary), organizations, memberships, groups, role assignments,
  authorization policies, projects, service principals, identity providers,
  webhook subscriptions and hooks, with stable IDs and without credentials,
  secrets or live tokens. The job result has counts per kind and the file's
  SHA-256; the permission is re-checked when the job runs and when a download
  token is issued (`TestRealmDataExport`;
  [exit-and-export.md](docs/operations/exit-and-export.md#realm-data-export)).
- **Legacy hash deadline** (CRED-004): `security.password.legacy_hashes_until`
  (UTC date, inclusive) ends the migration window for imported salted SHA-256
  verifiers: afterwards they no longer verify (the sign-in fails like a wrong
  password; audit `credential.password.legacy_retired`, reason
  `LEGACY_HASH_RETIRED`) and user imports refuse them. `identity-cli doctor`
  prints how many accounts still use one (`TestLegacyHashDeadline`;
  [migration.md](docs/operations/migration.md#credentials-and-factors)).
- **First-party migration adapters** (MIG-018): `identity-cli migrate-from
  keycloak|zitadel|supertokens` converts a Keycloak 26.x realm export, a
  ZITADEL v4.x admin API data export or a SuperTokens core 12.x export
  (produced read-only from the core database with the query
  `--print-export-sql` prints) into `proudauth.user-import.v1` records and
  the organizations they need, translates source roles and groups only
  through a reviewed mapping (`proudauth.migration-mapping.v1`; an absent key
  grants nothing), writes a capability report
  (`proudauth.migration-report.v1`: per entity what converts, converts with
  loss, is unsupported or ignored, without verifiers, seeds or emails) and
  runs dry-run imports (default) or, with `--apply`, creates the
  organizations (with source-qualified external IDs, so re-runs reuse them)
  and imports through the ordinary authenticated APIs. Tested versions:
  Keycloak 26.8.0, ZITADEL v4.16.3, SuperTokens core 12.0.7; other major
  versions are refused. Two read-only endpoints (`realm.users.import`):
  `GET /migration-adapters` and `POST /migration-plans` (converts up to 20
  export documents in memory and checks them against the realm)
  (`TestMigrateFromKeycloak`, `TestMigrateFromZitadel`,
  `TestMigrateFromSuperTokens`, `internal/migrate`;
  [migration-adapters.md](docs/operations/migration-adapters.md)).
- **Imported bcrypt and PBKDF2 verifiers** (MIG-006, CRED-004): user imports
  accept bcrypt (`$2a$`, `$2b$`, `$2y$`, cost 10–15) and PBKDF2
  (`$pbkdf2-sha1|sha256|sha512$i=<n>$<salt>$<dk>`, 10,000–2,000,000
  iterations, salt 8–64 bytes, key 16–64 bytes), checked against the
  password as typed and its NFKC form and rehashed to Argon2id at the next
  successful sign-in. Both are legacy verifiers covered by
  `security.password.legacy_hashes_until`, and `identity-cli doctor` counts
  them (`TestImportedForeignVerifiers`, `TestImportedVerifierRawPassword`;
  [exit-and-export.md](docs/operations/exit-and-export.md#user-import-request)).
- **Import record members** (MIG-006, AUT-018): `proudauth.user-import.v1`
  records accept `given_name`, `family_name`, `locale`, `state` (`active` or
  `suspended`), `required_actions` (each needing the same permission as on
  an existing account, checked at the request and in the job) and
  `admin_metadata` (at most `limits.metadata_bytes`). Dry-run plans show the
  state and required actions; job totals add `suspended_accounts` and
  `password_updates_required`; `user.imported` audit metadata adds `state`
  and `required_actions` (`TestMigrateFromImportRecordRules`).

#### Operations

- `identity-server`, `identity-worker`, `identity-cli` (migrate, doctor,
  realm-create, bootstrap with break-glass option, verify-audit, support-bundle,
  revocation-log, restore-reconcile, and OAuth-authenticated API commands).
- Versioned root keys with HKDF purpose keys; signing-key lifecycle with planned
  and emergency rotation (TEST-036).
- Embedded migrations with advisory lock, checksums and refusal of unknown
  migrations; readiness checks for database, schema, signing keys and clock skew.
- Prometheus-format metrics and `/status` on an internal listener; trace IDs in
  logs and optional sampled `span` log records; support bundle.
- Revocation log and restore reconciliation (TEST-060).
- Restore marker (TEST-060, OPS-014, migration `0087`, expand-only):
  `identity-cli restore-begin` marks a restored database (audited
  `operations.restore.begun`; `-status` shows it); while marked,
  `GET /health/ready` answers `503 {"status":"unavailable","reason":"restore_pending"}`
  and `identity-worker` refuses to start, until `identity-cli restore-reconcile`
  clears the marker in its transaction (report `restore_marker_cleared`).
  Databases never marked are unaffected
  (`TestRestoreProofConsumption`, `TestRestoreBeginAndReconcileCommands`;
  [backup-restore.md](docs/operations/backup-restore.md#the-restore-marker)).
- Disaster-recovery drill (DEP-019, OPS-007): `make dr-drill`
  (`scripts/dr-drill.sh`) runs the promotion runbook and a point-in-time
  recovery against real PostgreSQL 18 replication with throwaway containers
  and the binaries of the checkout: a primary with WAL archiving and a
  synchronous (or, with `DRILL_SYNC=off`, asynchronous) streaming standby,
  ProudAuth state created through the API, the primary fenced under write
  load, the standby promoted, `restore-begin`, `doctor` fingerprint
  comparison, `restore-reconcile` with the exported revocation log, and
  sign-in, token, introspection and revoked, deleted and suspended state
  verified; then a base backup plus archived WAL restored to a target time
  between two changes, with the later changes absent and the revocations
  exported after the target re-applied. It prints the measured RPO
  (acknowledged transactions lost) and RTO (fencing to the first token). A
  weekly and on-demand workflow (`.github/workflows/dr-drill.yml`) runs it
  ([backup-restore.md](docs/operations/backup-restore.md#what-is-tested)).
  Runbook corrections from the drill: clear `synchronous_standby_names` on a
  promoted standby or a point-in-time restore (it comes with
  `postgresql.auto.conf`, and every commit otherwise waits for a standby that
  is gone), and verify under maintenance mode `restricted`, because
  `unavailable` refuses sign-in and token requests.
- Failure-mode tests (TEST-059, docs/plan.md §31.2) with test-only
  fault-injection seams in the style of `impersonation.FailAudit`:
  `storage.DB.SetFault` fails a chosen transaction at its start or just
  before its commit, `keys.Keyring.SetFault` makes the key provider
  unreachable for a purpose. `TestTransactionFaultsLeaveNoPartialState`
  (refresh rotation, code exchange, password-reset completion, invitation
  acceptance: every transaction failed in turn, nothing half-applied, the
  proof stays usable), `TestSigningKeyOutageDuringIssuance` and
  `TestDeliveryOutageDuringSensitiveFlows` (mail down during password reset,
  email verification and invitation).
- Dockerfile, Compose development stack, Kustomize manifests, offline bundle
  script (`make bundle`), CI (tests with PostgreSQL 17, fuzz smoke, secret scan,
  license policy, govulncheck, staticcheck, image smoke test) and a release
  workflow with SBOM and build provenance.
- Migrations `0019`–`0023` are expand-only (new tables, one new index on
  `notification_jobs`, and in `0023` a backfill of alert claims for expiry
  notices already sent); none is marked `-- proudauth:compat=contract`, so
  binaries without them keep running during a rolling upgrade
  ([upgrades.md](docs/operations/upgrades.md)).
- Migrations `0024`–`0027` are expand-only as well (a `realms` column with a
  default, the one-row `system_state` table and its debug-window columns, and two
  nullable `users` columns with a partial index); none is marked
  `-- proudauth:compat=contract`. Binaries without them ignore emergency grant
  controls, maintenance mode, debug windows and lifecycle rules, so finish the
  rollout before relying on these controls.
- Migrations `0028`–`0031` are expand-only too: nullable columns on `scopes`
  (`step_up_acr`, `max_auth_age_seconds`), `clients` (`consent_terms_version`),
  `consents` (`preauthorization_id`), `organization_domains` (`proof_digest`)
  and `service_principals` (`owner_departed_at`), the counter
  `organization_domains.recheck_failures` with default `0`, the new
  `consent_preauthorizations` table and two indexes; none is marked
  `-- proudauth:compat=contract`. Binaries without them ignore scope step-up
  requirements (they grant such scopes without stepping up), consent terms
  versions and pre-authorizations, domain re-verification and owner-departure
  handling, so finish the rollout before configuring these.
- Migrations `0032`–`0037` are expand-only as well: new tables
  `organization_templates`, `organization_aliases`, `audit_legal_holds`,
  `audit_prune_log` (append-only, guarded by the `audit_prunes` trigger
  function), `hook_invocations` and the one-row `audit_archive_state`; nullable
  columns on `organizations` (`template_name`, `template_version`) and `groups`
  (`rule_recomputed_at`, `rule_member_count`, `rule_error`);
  `organization_domains.include_subdomains` with default `false`; and two
  indexes. None is marked `-- proudauth:compat=contract`. Older binaries
  ignore legal holds and per-category retention when they prune audit events,
  do not resolve aliases or route subdomains, do not recompute dynamic groups,
  do not archive audit batches, and send an organization's mail through the
  deployment relay; they also reject the new keys
  `privacy.audit_retention_by_category` and `privacy.audit_archive_dir` as
  unknown. Finish the rollout before placing legal holds or configuring these
  features ([upgrades.md](docs/operations/upgrades.md#mixed-version-window)).
- **Trace propagation and event correlation** (API-012): outbound HTTP calls
  made while serving a request (pre-action hooks, upstream identity
  providers, challenge providers) carry the request's W3C `traceparent` (no
  `tracestate` or baggage), and webhook events carry `correlation_id`, the
  `X-Request-Id` of the causing request and the `request_id` of its audit
  events; events from background work have none (`TestCorrelationPropagation`;
  [monitoring.md](docs/operations/monitoring.md#logs)).
- Migrations `0038` (the `imported_audit_events` table) and `0039`
  (`audit_archive_state.directory`) are expand-only; neither is marked
  `-- proudauth:compat=contract`. Older binaries do not serve the import,
  reconciliation and imported-audit routes, do not clear imported records on
  account deletion, and archive and prune audit batches the old way, so run
  the archive and retention on new workers only and import audit history after
  the rollout ([upgrades.md](docs/operations/upgrades.md#mixed-version-window)).
- **Audit failure observability** (AUD-014): gauges
  `proudauth_audit_unsealed_events` and `proudauth_audit_unsealed_oldest_seconds`
  (refreshed on every scrape), `proudauth_audit_integrity_problems` (set by the
  worker task `audit.verify_recent`) and the counter
  `proudauth_jobs_failed_total{type}` (asynchronous jobs that reached
  `dead_letter`, counted by the worker). `audit.verify_recent` runs hourly and
  verifies the newest 200 sealed batches (content hashes, digests, links, and
  signatures where present); problems also raise
  `proudauth_security_signals_total{signal="audit_failure"}` on the worker and
  log `audit integrity problems` (`event_code` `audit.integrity_failed`).
  `GET /status` adds the `audit_sealing` capability and backlog
  (`TestAuditRetentionCategoriesAndHolds`;
  [monitoring.md](docs/operations/monitoring.md#metrics)).
- **Tenant fairness** (TEN-018): per-organization budgets
  `security.rate_limits.login_per_organization` (password attempts in
  transactions that name an organization, per `login_window`, default 10000) and
  the existing `security.rate_limits.organization_per_window` (access tokens
  minted in an organization's context, per `token_window`, default 2000; fails
  closed),
  and worker shares `workers.tenant_batch_share` (at most 25 due notifications
  of one organization, or of a realm for messages without one, and 25 webhook
  deliveries of one subscription per batch) and
  `workers.max_jobs_per_organization` (at most 2 running jobs per
  organization); `0` disables each (`TestTenantFairness`;
  [configuration.md](docs/operations/configuration.md#workers)).
- **Emergency controls** (SEC-020, migration `0024`):
  `POST /api/v1/realms/{realm}/emergency/controls` (`realm.emergency`) with
  `target_type` (`grant_type`, `client`, `identity_provider`, `organization`,
  `service_principal`, `hook` or `webhook`), `target_id`, `action` (`disable` or
  `enable`) and a required `reason` (at most 500 characters).
  Grant classes (`authorization_code`, `refresh_token`, `client_credentials`, and
  the device-code and token-exchange grant URNs) are stored in
  `realms.disabled_grant_types` and refused realm-wide by the authorization,
  device-authorization and token endpoints (`unauthorized_client`); while
  `refresh_token` is disabled no refresh tokens are issued. The operator CLI
  client `proudauth-cli` is exempt so the control can always be reversed.
  Identity providers, hooks and webhooks are switched without revalidating their
  configuration or destination. `GET .../emergency/controls` shows the realm
  state, the disabled grant types and up to 200 suspended or disabled targets of
  each kind. Every audit event a control causes is filed in the `emergency`
  category, with the operator's reason when the event carries none, and raises
  the `emergency_action` security signal (`TestEmergencyControls`;
  [incidents.md](docs/operations/incidents.md#emergency-controls-sec-020)).
- **Maintenance mode** (OPS-015, migration `0025`):
  `identity-cli maintenance -mode off|restricted|unavailable -message "..."
  -retry-after N` (audited `operations.maintenance.changed`), observed by every
  server within 2 seconds. `restricted` keeps sign-in, token issuance,
  introspection, revocation, logout and emergency controls available, as well as
  `POST` requests whose path ends in `/revoke-sessions`, `/suspend` or `/lock`,
  and refuses other changes; `unavailable` serves only health, discovery, JWKS,
  introspection, revocation and logout. Refusals are `503` with problem code
  `maintenance`, `Retry-After` and the operator's plain-text message
  (`TestMaintenanceAndStatus`; [incidents.md](docs/operations/incidents.md#maintenance-mode-ops-015)).
- **Debug logging windows** (SEC-015, migration `0026`):
  `identity-cli debug-window -for 15m -component worker -reason "..."` emits
  records below `observability.log_level` for a bounded time (at most 1 hour in
  production, 24 hours otherwise), optionally for one log `component`, with
  redaction unchanged; `-close` ends the window. Opening and closing are audited
  (`operations.debug_window.opened`, `.closed`) (`TestDebugWindow`;
  [support-bundle.md](docs/operations/support-bundle.md#debug-logging-windows)).
- **Configuration diff** (DEP-020): `identity-cli config-diff -from <current>
  -to <proposed> [-json]` validates the proposed file and lists every changed key
  with redacted old and new values, its effect (always `restart`: there is no
  file watcher) and whether it moves a security boundary (`TestDiffClassifiesAndRedacts`;
  [configuration.md](docs/operations/configuration.md#reviewing-a-change)).
- **Graceful shutdown** (OPS-012): on `SIGINT`/`SIGTERM` the server first
  answers `/health/ready` with `503 {"status":"draining"}` for
  `server.drain_delay` (default 5 s), then stops accepting connections and
  drains for up to `server.shutdown_deadline`. The worker stops claiming work,
  lets the task in progress finish for up to `workers.drain_timeout` (default
  20 s) and then returns the jobs, notifications and webhook deliveries it still
  holds to the queue. The Kubernetes manifests' termination grace periods (30 s
  for the server, 60 s for the worker) cover the defaults
  (`TestWorkerShutdownReleasesLeases`; [installation.md](docs/operations/installation.md#5-start-the-processes)).
- Migration safety gates (OPS-008): `identity-cli migrate -plan`, contract
  (destructive) migrations only with `-backup-reference`, and
  `-- proudauth:precondition` checks; a mixed-version window in which older
  binaries keep running against newer expand-only migrations (TEST-061,
  `TestMixedVersionWindow`, `TestMigrationSafetyGates`).
- Database-enforced realm boundaries: a trigger rejects role assignments and
  assignment requests whose subject or scope lives in another realm, and
  realm/organization foreign keys on webhook subscriptions, webhook deliveries
  and jobs apply to new and changed rows (added `NOT VALID`; `identity-cli
  doctor` reports older orphan rows) (migration `0016`, DB-001,
  `TestAssignmentRealmBoundary`).
- Secret references `cred:NAME` (systemd credentials) and
  `vault:<mount>/data/<path>#<field>` (HashiCorp Vault KV v2), and a registry
  for operator-built resolvers (DEP-006).
- `identity-cli` commands `clients`, `roles`, `assign-role`, `grant-scopes`,
  `sessions`, `invitations`, `support-grants`, `permissions` and
  `password-calibrate`.
- Generic cursor pagination for list endpoints: opaque cursors MAC-bound to the
  realm, route and filters (API-004, `TestListPagination`).
- Security-signal metrics `proudauth_security_signals_total{signal}` derived from
  audit evidence (OPS-004, `TestSecuritySignalsMetrics`), plus
  `proudauth_signing_failures_total{reason}`,
  `proudauth_worker_active_leases` and `proudauth_hook_calls_total`; gauges are
  refreshed at scrape time; the worker can expose its metrics on
  `workers.metrics_listen`; every log record carries `component` and
  `event_code`.
- Release workflow publishes the container image by digest with SBOMs,
  build-provenance and SBOM attestations and a keyless cosign signature;
  Dependabot for Go modules, npm, GitHub Actions and Docker; CI runs the Node.js
  SDK tests.
- **KMS envelope** (DEP-016, implemented as unwrap-at-start): root, pepper and
  signing-wrap keys can be stored wrapped by any KMS or HSM with a
  command-line client and referenced as `kms:<file>`; `keys.kms.command` runs
  without a shell at each process start, receives the wrapped key on standard
  input and prints the key. The keys are then held in process memory; signing
  inside an HSM is not supported. `/status` reports `key_provider`
  (`software` or `kms_unwrapped`) (`TestKMSUnwrap`;
  [keys.md](docs/operations/keys.md#kms-envelope-dep-016)).
- **Trace export** (OPS-003): `observability.otlp_endpoint` exports sampled
  server spans (method and route, status) and client spans of outbound calls
  (method, host, status) as OTLP/HTTP JSON, batched and dropped rather than
  delayed; the `tracing.Tracer` interface accepts other exporters
  (`TestTraceExport`, `TestOTLPExporter`;
  [monitoring.md](docs/operations/monitoring.md#tracing)).
- **Custom domains** (DEP-014, migration `0041`): `/custom-domains` registers
  realm host names proven by a DNS TXT record (`realm.settings.write`, MFA
  session), and `server.host_policy: strict` serves only the public origin
  and verified custom domains (each for its own realm's paths), answering
  `421 misdirected_request` otherwise. Issuers and subjects never change;
  cookies are per host (`TestCustomDomains`;
  [installation.md](docs/operations/installation.md#custom-domains)).
- **Database role separation** (OPS-013): `storage.migration_database_url`
  runs migrations as the schema owner and `storage.runtime_role` receives
  data privileges only after each run (no `DELETE` on the audit tables);
  `identity-cli doctor` warns when the runtime role is a superuser, owns the
  schema, inherits the owner's privileges, can create roles or can create
  objects in `public` (`TestRuntimeRoleSeparation`;
  [installation.md](docs/operations/installation.md#database-roles)).
  `identity-cli revocation-log` now records the operator audit event
  `operations.revocation_log.exported` (`since`, `records`).
- **Data residency** (PRV-003): `privacy.residency.allowed_destinations`
  keeps outbound connectors (webhooks, hooks, back-channel logout, SMS
  gateway, organization mail servers, upstream providers, challenge
  providers) on listed hosts or domains, checked by the egress policy;
  `privacy.residency.region` and `destinations_restricted` appear in
  `/status`. `privacy.backup_retention` dates the backup stage of the
  deletion report (`TestResidency`;
  [data-inventory.md](docs/operations/data-inventory.md#data-residency)).
- **Benchmark suite** (NFR-003..NFR-008): `cmd/identity-bench` seeds a
  dedicated realm through the public API and runs workload, adversarial,
  consistency-stress and soak scenarios with JSON results (latency
  percentiles and histogram, outcomes, environment); `make bench` reproduces
  the default run. Laptop reference numbers, software passkey/SCIM workloads
  and SMTP worker scenarios are documented; physical authenticator latency,
  webhook capacity and multi-node consistency beyond refresh races remain
  outside the measured baseline (`TestBenchSuiteSmoke`;
  [benchmarks.md](docs/operations/benchmarks.md)).
- `TestTimeAndUnicodeInvariants` (NFR-010) checks that token lifetimes are
  absolute (`iat`/`exp` in Unix seconds) with the host time zone set to New
  York shortly before a daylight-saving change, that case variants of an
  email address and case and full-width variants of a username resolve to
  one account, and that `İ` lower-cases to `i` in usernames without locale
  rules.

- **Supply chain** (GOV-004): the release workflow runs the whole CI
  workflow (`workflow_call`) before it publishes; pull requests get a `dco`
  job that fails when a commit lacks `Signed-off-by`; the Node.js job runs
  `npm audit --audit-level=high`; `govulncheck` (pinned `v1.8.0`, also in
  `make vuln`) additionally scans unstripped rebuilds of the shipped binaries
  in `-mode=binary`; CI and release use the latest Go 1.27 patch release
  (`go-version: "1.27.x"`, `check-latest: true`) and the image builds with
  `golang:1.27.2-trixie`, so standard-library security fixes no longer wait
  for a `go.mod` change; `.github/CODEOWNERS` now also requires security
  reviewers for `internal/machine`, `internal/platform/secret`,
  `internal/provisioning`, `internal/provision`, `internal/audit`,
  `internal/configuration`, `internal/restore`, `api/`, all of `sdk/`,
  `.github/`, `go.mod`/`go.sum`, the secret and license scripts and the
  security documents ([CONTRIBUTING.md](CONTRIBUTING.md#security-sensitive-areas));
  `.gitignore` covers the secret-bearing files the CLI and benchmark tool
  write (seed files, configuration exports, `--secrets-out` files, support
  bundles, revocation logs).
- **Operational retention** (PRV-004, OPS-009): ended grants are deleted
  `privacy.session_retention` after they ended, with their refresh families
  and tokens, codes and opaque tokens, and then ended client sessions and
  sessions; the new `privacy.history_retention` (default `4320h`, at least
  `168h`) deletes revoked consents, ended invitations, finished notification
  jobs and delivered or dead-lettered webhook and back-channel logout
  deliveries (`TestOperationalRetention`;
  [data-inventory.md](docs/operations/data-inventory.md)).
- **Configurable safety limits** (OSS-007): `limits.invitation_resends`,
  `limits.shared_invitation_max_uses`, `limits.shared_invitation_max_ttl`,
  `limits.client_secrets_max` and `limits.metadata_bytes` (organization
  metadata, user profile and admin metadata); `limits.max_batch_size` also
  bounds bulk invitations (`TestConfigurableLimits`;
  [configuration.md](docs/operations/configuration.md#limits)).
- **Queue age metrics** (OPS-002): `proudauth_notification_oldest_due_seconds`,
  `proudauth_webhook_oldest_due_seconds` and
  `proudauth_jobs_oldest_queued_seconds`, refreshed at every scrape of the
  server's or the worker's metrics listener
  ([monitoring.md](docs/operations/monitoring.md#metrics)).
- **Worker spans** (OPS-003): `identity-worker` exports sampled task runs
  (`service.name` `proudauth-worker`, span `worker <task>`, attributes
  `proudauth.worker.task` and `proudauth.worker.items`) with their outbound
  calls as child spans ([monitoring.md](docs/operations/monitoring.md#tracing)).
- **Cleanup indexes** (DB-011, migration `0045`): expiry and cleanup queries
  (codes, opaque tokens, DPoP JTIs, PAR, device codes, idempotency records,
  dispatched outbox events, ended sessions, the SMS budget, the notification
  payload purge) use indexes instead of scanning tables
  ([capacity.md](docs/operations/capacity.md#storage-growth)).
- Startup migrations (`identity-server -migrate`, `migrate_on_start`) are
  audited as `operations.migrations.applied` (actor `startup:<hostname>`,
  metadata `migrations` and `trigger`) (OPS-013;
  [installation.md](docs/operations/installation.md#4-check-and-migrate)).
- **Client configuration as code** (APP-019): configuration exports now
  include each client's protocol options (front-channel logout, response
  signing and encryption, `tls_client_auth_*` and certificate-bound tokens,
  display URIs), and the configuration document schema lists them with
  `tls_client_auth`, `self_signed_tls_client_auth` and `security_profile:
  fapi2`. Drift detection also compares `allowed_origins`,
  `backchannel_logout_uri`, `allow_offline_access`, `allow_remember_me`,
  `token_endpoint_auth_method`, `security_profile` and the protocol options.
  Clients backing SAML applications are left out of documents
  ([exit-and-export.md](docs/operations/exit-and-export.md#configuration-import)).

#### SDKs, contracts and examples

- Go SDKs: `sdk/go/verifier` (offline verification, strict-online introspection,
  `SupportGuard`), `sdk/go/oidcclient` (BFF client), `sdk/go/admin`.
- Node.js/TypeScript SDK `sdk/node` (unpublished; now 0.2.0) with the same four areas.
- **Dart SDK** `sdk/dart` (`proudauth_sdk` 0.2.0, unpublished, Dart 3.4+, no
  Flutter dependency): offline verification (`Verifier`,
  `MultiIssuerVerifier`), strict-online introspection with `SupportGuard`,
  bounded-state verification, the OIDC/BFF client with single-flight refresh,
  and the administration client (`Secret`, `onDeprecated`, idempotency keys,
  `If-Match`). RS256, PS256, ES256 and EdDSA verification is implemented in
  the package on `BigInt` (no native crypto dependency) and checked against
  vectors and tokens signed by Go. Adapters: the framework-neutral
  `authorizeBearer` and `package:proudauth_sdk/io.dart` for `dart:io`
  servers. `make test-dart`, CI job `dart-sdk`.
- **PHP SDK** `sdk/php` (`proudauth/sdk` 0.2.0, unpublished, PHP 8.2+ with
  `curl`, `json`, `openssl` and `sodium`; no Composer dependencies): the same
  areas, with a key-set `Store` (`MemoryStore`, `FileStore`) so PHP-FPM
  workers share the JWKS, refresh serialization across workers
  (`FileRefreshLock`), `RequestAuthenticator` for plain PHP (a PSR-15 example
  in its README) and a cURL transport that never follows redirects. Checked
  against signature vectors signed by Go. `make test-php`, CI job `php-sdk`
  (PHP 8.2 and 8.5).
- Both new SDKs run the shared access-token and support-operation fixtures
  and send `ProudAuth-SDK: dart/0.2.0` / `php/0.2.0`
  ([sdk-compatibility.md](docs/integrations/sdk-compatibility.md)).
- Bounded-state verification mode in both SDKs (`sdk/go/verifier`
  `BoundedState`/`BoundedVerifier`, `sdk/node` `bounded-state`): local JWT checks
  plus revocations replayed from the session-event stream, failing closed when
  the state is older than the configured bound (SDK-002,
  `TestBoundedStateVerification`).
- OpenAPI document, configuration/import JSON Schemas and event schemas under
  `api/`, with contract tests (`tests/contract`).
- **Shared verification fixtures** (SDK-009):
  `sdk/fixtures/access-tokens/cases.json` holds 18 accepted and rejected access
  tokens with a test-only public JWKS; both SDKs run every case
  (`sdk/go/verifier/fixtures_test.go`, `sdk/node/test/fixtures.test.ts`), and
  independent verifiers can use them ([sdk/fixtures/README.md](sdk/fixtures/README.md)).
- **Fuzz targets** (QA-003): `FuzzPolicyDefinition` (`internal/authorization`),
  `FuzzParseTraceparent` (`internal/platform/reqctx`), `FuzzAllowed`
  (`internal/egress`: the public-only policy never allows private, loopback,
  link-local, unspecified or multicast addresses) and `FuzzClaimMappings`
  (`internal/application`), run by the CI fuzz smoke and `make fuzz`.
- `correlation_id` in the event envelope (`api/events/envelope.v1.json`,
  optional, API-012).
- Examples: backend-for-frontend, protected orders API (strict-online),
  protected billing API (offline), machine client.
- **SDKs 0.2.0** (SDK-007, SDK-008, SDK-010..SDK-012; see **Changed** for the
  breaking part): the administration clients send `ProudAuth-SDK` and a
  versioned `User-Agent`, report `Deprecation`/`Sunset` headers
  (`Response.Deprecation`/`Sunset` and `Client.OnDeprecated` in Go,
  `deprecation`/`sunset` and `onDeprecated` in Node.js) and wrap one-time
  secrets (`admin.Secret`, `Secret`). New adapters: Node.js `fastifyHook`
  and Go `verifier.AuthenticateMetadata` for gRPC metadata, WebSocket upgrade
  and message headers. Multi-issuer verification (INT-009):
  `verifier.NewMultiIssuer` / `MultiIssuerVerifier` map explicitly registered
  issuers to tenants and refuse all others. `identity-cli config-export`,
  `config-plan` (with a `drift` list of existing objects that differ from the
  document) and `config-apply` (confirmation, `--secrets-out`)
  ([sdk-compatibility.md](docs/integrations/sdk-compatibility.md)).

- **Shared support-operation rule** (IMP-011, IMP-013): both SDKs export the
  write-verb list and a classifier (Go `verifier.WriteSegmentList()` and
  `IsWriteOperation`, Node.js `WRITE_SEGMENTS` and `isWriteOperation`, next to
  `verifier.ProtectedOperationList()` / `PROTECTED_OPERATIONS`), and both SDKs and the
  server's decision API run the cases in
  `sdk/fixtures/support-operations/cases.json`
  (`TestSupportClassificationMatchesSDKTable`).
- Go `verifier.ErrNotStarted`: `BoundedState.Sync` before a successful
  `Start` returns it instead of replaying from an empty position; `Run` starts
  the stream itself
  ([resource-servers.md](docs/integrations/resource-servers.md#1-register-the-api)).
- Configuration import reconcile (SDK-012): `?mode=reconcile` on
  `POST /configuration/validate` and `/imports` (`identity-cli config-plan`
  and `config-apply -reconcile`) updates existing clients, resources and role
  permissions that differ from the document; nothing is deleted
  (`TestConfigReconcile`;
  [exit-and-export.md](docs/operations/exit-and-export.md#configuration-import)).

#### Documentation and governance

- README, SECURITY, CONTRIBUTING (DCO, review rules), CODE_OF_CONDUCT, CODEOWNERS,
  issue and pull-request templates.
- Architecture decision records 0001–0020, operations runbooks, protocol profiles,
  integration guides and threat models.
- API compatibility policy: versioned surfaces, additive changes, deprecation
  window and security exceptions
  ([docs/protocols/compatibility.md](docs/protocols/compatibility.md), API-013).
- Migration runbook ([docs/operations/migration.md](docs/operations/migration.md),
  MIG-001..MIG-017).
- Integration patterns for HTTP, GraphQL, gRPC, WebSockets, long-lived
  streams, background jobs, message consumers, download grants, multi-issuer
  applications and contract validation
  ([docs/integrations/patterns.md](docs/integrations/patterns.md),
  INT-001..INT-010); SDK compatibility policy
  ([sdk-compatibility.md](docs/integrations/sdk-compatibility.md), SDK-010);
  benchmark guide ([benchmarks.md](docs/operations/benchmarks.md)); runbooks
  for root-key and KMS compromise, connector compromise, abuse spikes,
  database loss, organization owner recovery and privacy deletion errors
  ([incidents.md](docs/operations/incidents.md#runbook-coverage-ops-016),
  OPS-016); conformance claims and tested versions
  ([interoperability.md](docs/integrations/interoperability.md), QA-004,
  QA-006); security regression policy
  ([SECURITY.md](SECURITY.md#security-regressions-qa-008), QA-008);
  partitioning policy ([capacity.md](docs/operations/capacity.md#partitioning-policy-db-012),
  DB-012); accessibility metadata of the transaction API
  ([headless-authentication.md](docs/protocols/headless-authentication.md#accessibility-metadata),
  NFR-009).
- SAML, directory and outbound provisioning guides
  ([saml.md](docs/integrations/saml.md),
  [directory.md](docs/integrations/directory.md),
  [outbound-provisioning.md](docs/integrations/outbound-provisioning.md)),
  their threat models ([saml](docs/threat-models/saml.md),
  [directory](docs/threat-models/directory.md)), incident runbooks for SAML
  key or counterparty compromise and directory connector compromise, and a
  dated update of ADR 0018 recording what is now implemented and what stays
  unsupported (including why Kerberos/SPNEGO is not offered).
- Isolation tiers: organization-, realm- and deployment-per-customer
  patterns with issuer, key, migration, backup, residency and cost
  tradeoffs ([isolation-tiers.md](docs/operations/isolation-tiers.md),
  TEN-019).
- Disaster-region recovery profile: one writing region with a warm standby,
  a promotion runbook with restore reconciliation, and what is not offered
  (active-active writes, globally immediate revocation)
  ([backup-restore.md](docs/operations/backup-restore.md#disaster-region-recovery-dep-019),
  [ADR 0019](docs/architecture-decisions/0019-single-write-region.md),
  DEP-019).
- Capabilities deliberately not offered, with the reasons and what an
  implementation would need: push approval (MFA-014), CIBA (ADV-005), UMA
  (ADV-006), verifiable credential issuance and presentation (ADV-008,
  ADV-009) and JAR; declared protocol profiles
  ([compatibility.md](docs/protocols/compatibility.md#capabilities-not-offered)).
- Threat model for cross-system trust surfaces (session iframe, shared
  signals, registry tokens, passkey trust, federation transfer, partner
  access, flow revisions, investigations)
  ([cross-system-trust.md](docs/threat-models/cross-system-trust.md)); ADR
  0022 on security-event exchange.

### Changed

- The owner excludes independent security review from the 2026-10-13
  delivery's completion gate ([scope exception](docs/plan.md#354-delivery-checkpoint--2026-10-13)).
  The project remains unreviewed; all other implementation, verification
  and release requirements remain in scope.
- **User/exchanged JWTs require a live grant link online** (SES-023):
  newly issued JWTs carry the reserved `grant_id`; exchanges preserve the
  originating link. Earlier development JWTs without it are refused by
  online consumers. Obtain fresh access tokens through serialized refresh
  or reauthentication, coordinate issuer upgrades and rename older mappings
  with this claim name; see [upgrades.md](docs/operations/upgrades.md).
  Offline verifiers retain their documented expiry-based exposure.
- **`identity-cli restore-reconcile` ends every outstanding one-time proof**
  (TEST-060): reset, verification, sign-in and account-setup codes and links,
  authorization and device codes, pushed requests, pending sign-in
  transactions, passkey ceremonies, federation and SAML request states,
  support handoff codes and job download tokens, reported as
  `proofs_invalidated`. This also applies when it is used on a live
  deployment for `-invalidate-all-sessions`
  ([incidents.md](docs/operations/incidents.md)): users mid-sign-in start
  again and account-setup links must be resent.
- **Request limits have safe ranges** (NFR-001): `limits.max_body_bytes`
  `262144`–`67108864`, `max_header_bytes` `8192`–`1048576`,
  `max_token_bytes` `4096`–`65536`, `max_json_depth` `32`–`256`,
  `max_page_size` `1`–`1000`, `max_group_depth` `1`–`32`,
  `max_role_expansion` `8`–`1024` and `max_inflight_requests` `1`–`100000`
  (`0` still means 2000). A configuration outside them no longer starts;
  before, `max_body_bytes: 0` refused every request body and other zero values
  fell back silently (`TestLimitRanges`;
  [configuration.md](docs/operations/configuration.md#limits)).
- `identity-cli support-bundle` requires `-out`: diagnostic files are
  written only where the operator says, never by default into the working
  directory (DEP-004, `TestSupportBundleNeedsOut`). Scripts that relied on the
  default `support-bundle.json` must pass `-out support-bundle.json`.
- The release workflow builds binaries with the Dockerfile's exact Go
  toolchain and `-buildid=`, scans every shipped platform with govulncheck,
  and puts the container image into the offline bundle
  (`TestReleaseToolchainPinned`); the license check covers every module the
  build and tests use and fails when one is missing instead of skipping it;
  CI renders the Kubernetes manifests; the worker has liveness and startup
  probes on `workers.metrics_listen`
  ([security-checks.md](docs/operations/security-checks.md)).
- **Go module path** is now `github.com/proudauth` (was
  `github.com/proudauth/proudauth`): update imports of `sdk/go/verifier`,
  `sdk/go/oidcclient` and `sdk/go/admin` (for example
  `github.com/proudauth/sdk/go/verifier`).
- **Base URL of ProudAuth identifiers** is now `https://auth.proudbase.com/`
  (was `https://proudauth.dev/`): the `type` of every problem response is
  `https://auth.proudbase.com/problems/<code>`, and the `$id` of every JSON
  Schema under `api/` starts with `https://auth.proudbase.com/schemas/`.
  Clients that compare problem `type` URIs instead of `code` must accept the
  new prefix.
- Configuration keys that previously had no effect now do:
  `security.password.history_count` is a deployment floor under the realm's
  password history, `workers.concurrency` bounds parallel asynchronous jobs per
  worker, `workers.max_attempts` sets the job attempt limit, and realm policy
  `login.remember_devices` enables remembered devices
  ([configuration.md](docs/operations/configuration.md)).
- Production configuration now also rejects literal `keys.pepper_keys` and
  `keys.signing_wrap_keys`, and `delivery.allow_private_webhooks` (use
  `delivery.egress_allowlist`); upstream identity providers on private networks
  use the new `federation.egress_allowlist`.
- Enabling SMS sign-in requires the realm policy acknowledgement
  `login.sms_risk_accepted` (PWDLESS-005).
- `sessions.client_ip` stores a /24 or /48 network unless
  `privacy.store_full_ip` is set.
- Environment overrides fail closed (DEP-020): a malformed boolean or an integer
  outside its range in a `PROUDAUTH_*` variable is now a startup error
  (`environment: ...`) instead of being read as `false` or `0`
  (`TestEnvParseErrorsFailClosed`; [configuration.md](docs/operations/configuration.md#environment-overrides)).
- Production configuration rejects `observability.log_level: debug` (SEC-015);
  use a time-limited debug window instead.
- `GET /status` on the internal listener (and on `workers.metrics_listen`)
  requires `Authorization: Bearer <server.metrics_token>` when a metrics token is
  configured, and its JSON changed (OPS-015): `database` and
  `outbox_oldest_pending_seconds` moved to `capabilities.database` and
  `backlog_oldest_seconds.outbox`, and the response adds `capabilities`
  (`database`, `schema`, `signing`, `outbox`, `email_delivery`, `webhooks`,
  `jobs`), `backlog_oldest_seconds`, `maintenance` and an overall `status`
  (`ok`, `degraded`, `maintenance`, `unavailable`). Update monitors that read the
  old members ([monitoring.md](docs/operations/monitoring.md#operator-status)).
- Expired unverified registrations are removed by the new `lifecycle.users`
  worker task instead of `retention.cleanup`.
- `GET /me/consents` items now carry `id`, `client` (internal reference),
  `client_id`, `client_name`, `scopes`, `resource_ids`, `terms_version`, `mode`
  (`user` or `preauthorized`), `preauthorization_id`, `granted_at` and
  `revoked_at`, newest first (at most 500); revoked consents are listed only with
  `?history=true` (APP-013, `TestConsentManagement`).
- Configuration as code (APP-019, DEP-020, OSS-008): the `config.export` job now
  writes the importable `proudauth.realm-config.v1` document; an import merges
  `policy` over the current realm policy instead of replacing it, accepts
  `expected_policy_revision` to refuse a stale reviewed document, names service
  principals by name, accepts grants with `subject_types`, rejects
  environment-bound identifiers in the plan, and is applied in one transaction
  (all or nothing). `POST /configuration/validate` now needs
  `realm.configuration.import` (`TestExportsImportsAndJobs`;
  [exit-and-export.md](docs/operations/exit-and-export.md#import-into-proudauth),
  `api/schemas/config-document.schema.json`).
- **Removed** `security.rate_limits.token_per_organization`. It duplicated
  `security.rate_limits.organization_per_window`, which already bounds the
  access tokens minted in an organization's context (every grant type,
  including token exchange; TEN-018). Unknown keys are startup errors, so delete
  it from configuration files before upgrading
  ([configuration.md](docs/operations/configuration.md#security)).
- Audit retention (AUD-009) now removes individual expired events from sealed
  batches instead of whole batches, so events kept longer (a longer category
  retention, category `emergency`, or a legal hold) stay in their batch. The
  first pass over a batch is recorded in `audit_prunes`, as before, and every
  later pass in the new append-only `audit_prune_log`; the chain still verifies
  (`TestAuditRetentionCategoriesAndHolds`;
  [incidents.md](docs/operations/incidents.md#audit-chain-verification-failure)).
- `GET /status` reports a new capability and backlog, `audit_sealing` (age of
  the oldest unsealed audit event; `degraded` after 300 s), which also turns the
  overall `status` to `degraded` (AUD-014;
  [monitoring.md](docs/operations/monitoring.md#operator-status)).
- A client's `environment` can no longer change (APP-015): `PUT
  /clients/{client}` with a different value is refused with `422`, and clients
  in a project take the project's environment by default and must match it.
  Register a new client for another environment (`TestEnvironmentSeparation`).
- Webhook subscriptions to `"*"` now also receive `security.alert` events
  (AUD-012), and the worker counts them in
  `proudauth_security_events_total{type="security.alert"}` and logs each as a
  `security event` warning, like the other `security.*` events.
- **`PATCH /organizations/{org}` requires `If-Match` when the body contains
  `policy`** (API-010): without the header the request fails with `428
  precondition_required`, and with a stale version with `412
  precondition_failed`. Read the organization first (`GET` returns its `ETag`,
  the organization's version, which every change to the organization bumps)
  and send it back. Clients that patch organization policy without `If-Match`
  must be updated; other members can still be patched without it, like the
  routes that already required it (`PUT` of clients, resources, `/settings`,
  identity providers and hooks)
  ([compatibility.md](docs/protocols/compatibility.md)).
- **Claim mappings release attribute values only with the `profile` scope**
  (APP-011): `user.*` and `profile.*` mappings in `id_token_claims` and
  `access_token_claims` now yield their value only when the grant includes
  `profile` (ID tokens: the requested scopes; access tokens: the token's or
  its grant's scopes), and otherwise their `default` or no claim; static
  values are unchanged. A realm profile schema with an attribute that is both
  `claimable` and `user_editable` is refused with `422` (field
  `profile.attributes[<i>].claimable`), and such attributes stored earlier
  are no longer released. **Upgrade note:** a realm whose policy has such an
  attribute must clear one of the two flags before its next policy update
  (`PUT /settings` or configuration import), or the update is refused
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#clients)).
- **Token exchange without `scope`** (AUT-010): the default ceiling now leaves
  out scopes whose step-up policy the subject token's `acr` or `auth_time`
  cannot meet and issues the rest; the request fails with `invalid_scope` only
  when no scope remains. A step-up scope named in `scope` still fails with
  `invalid_scope` (`TestScopeStepUp`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#token-exchange-rfc-8693)).
- **Privileged role assignments** (AUD-012, MIG-003, MIG-012): `role.assigned`
  `metadata.privileged`, the `privileged_grant` signal and `security.alert`,
  the import plan's `privileged` flag and the reconciliation report now count
  a role as privileged when it is an owner role, a realm role, or holds a
  permission the catalog marks `privileged` (directly or through a role it
  composes). The built-in organization `member` and `admin` roles no longer
  raise `privileged_grant`, which removes an alert for every new member
  ([monitoring.md](docs/operations/monitoring.md#security-alerts)).
- **Minimal webhook payloads** keep the non-personal members `signal`,
  `event_type`, `actor_type`, `subject_type`, `client_ref`, `new_kid`,
  `previous_kid` and `previous_key_compromised` besides `*_id`, `state`,
  `reason`, `authorization_revision` and `mode`, so `security.alert`,
  `client.state_changed` and `signing_key.rotated` are complete in the default
  form; `user.created`'s `created_via` is still standard-only
  ([api/events/README.md](api/events/README.md#payload-forms)).
- `privacy.audit_retention_by_category` accepts only known category names
  (`account`, `application`, `audit`, `authorization`, `configuration`,
  `data_access`, `imported`, `operations`, `privacy`, `security`, `support`,
  `token`); any other name now stops startup instead of being ignored
  (`TestAuditCategoriesKnown`;
  [configuration.md](docs/operations/configuration.md#privacy)).
- With `privacy.audit_archive_dir` set, audit retention prunes only batches
  the archive already holds, so nothing is pruned before the first archive run
  and a stopped archive holds retention back
  ([incidents.md](docs/operations/incidents.md#audit-archive-aud-008)).
- Organization template roles can no longer carry `support.*` permissions
  (only `realm.*` was refused before).
- User imports report an email or username that already belongs to an
  account as `conflict` (in dry runs too) instead of an `error` at creation,
  and `GET /jobs/{id}` shows `format` and `import_totp` in a `user.import`
  job's `input`.
- Migrations `0040_flow_challenges.sql` (wider check constraints for the
  challenge purpose `flow_challenge`, the hook kind `authentication.risk` and
  adapter names) and `0041_custom_domains.sql` (new table
  `realm_custom_domains`) are expand-only. Older binaries in a mixed-version
  window ignore the features they back and reject the new configuration keys;
  add rules, adapters, custom domains and keys only after the rollout
  ([upgrades.md](docs/operations/upgrades.md#mixed-version-window)).
- **SDK 0.2.0 (breaking): one-time secrets are wrapped.** The Go
  administration client returns `admin.Secret` instead of `string` for
  secret members (`client_secret`, `api_key`, `setup_token`,
  `invitation_secret`, `access_token`, `handoff_code`, `download_token`, …) in
  results decoded into `map[string]any` or `any`; the Node.js client wraps
  them in `Secret` in all response data. Code that reads them as strings must
  call `Reveal()` / `reveal()`; printing, logging and JSON-encoding show
  `[REDACTED]`
  ([sdk-compatibility.md](docs/integrations/sdk-compatibility.md#breaking-changes-in-020)).
- **Required actions need the authority of each action** (AUT-018): adding
  or removing `update_password` or `configure_totp` needs
  `realm.users.credentials.manage`, and `verify_email` needs
  `realm.users.write`, in `POST /users/{user}/required-actions` and bulk
  operations (besides `realm.users.required_actions`; checked at the request
  and again by the worker) and in the `required_actions` of `POST /users`
  (besides `realm.users.write`); others get `403`
  (`TestRequiredActionPermissions` covers the first two).
- `security.decision_cache_ttl` accepts `0` to `10m` and
  `security.dynamic_group_max_staleness` `0` or `10m` to `168h`; other values,
  including negative ones, now stop startup. The worker task `groups.dynamic`
  runs every 5 minutes, recomputes the 100 least recently computed groups
  and then catches up in batches of up to 200 while groups are older than half
  of the staleness bound (at most 4900 groups per run).
- Removing a dynamic group's rule keeps its members as ordinary members
  (source `admin`) instead of leaving rule-derived memberships that grant
  nothing, bumps their membership revisions and records
  `group.dynamic_rule.removed` (`members_kept`); re-adding an existing member
  is a no-op without an audit event.
- User imports refuse a `source_system` that does not match
  `^[a-z0-9][a-z0-9._-]{0,62}$`, like audit imports, external IDs and the
  reconciliation report already did.
- `proudauth_delivery_total` also counts final webhook (`delivered`,
  `dead_letter`) and notification (`accepted`, `failed`, `expired`) outcomes,
  besides back-channel logout
  ([monitoring.md](docs/operations/monitoring.md#metrics)).
- RP-initiated logout responses carry `upstream_logout`; organization-scoped
  webhook subscriptions are disabled when their organization's deletion
  starts and no longer receive its `organization.deleted` event.
- `PATCH /organizations/{org}` keeps `locale`, `time_zone` and `external_id`
  when the body omits them (`""` clears) instead of clearing them
  (`TestOrganizationPartialUpdate`).

- **Recovery-restricted accounts and sessions** (MFA-010, USR-003): a sign-in
  whose second factor is a recovery code (and no TOTP or passkey) now also
  moves an `active` account to the state `recovery_restricted`
  (`user.recovery_restricted`, reason `RECOVERY_CODE_USED`); a later TOTP or
  passkey sign-in, or enrolling a new TOTP or passkey from the restricted
  session, returns it to `active` (`user.reactivated`, reason
  `FACTOR_ASSURANCE_RESTORED`) and lifts the session's restriction. The
  restricted session may only read and call `POST /me/totp/enroll`,
  `/me/totp/activate`, `/me/webauthn/registration-options`,
  `/me/webauthn/registration-complete`, `DELETE /me/sessions/{id}`,
  `POST /me/sessions/revoke-all` and `DELETE /me/remembered-devices[/{id}]`;
  every other write is `403` with the new problem code `recovery_restricted`
  (`TestMultiFactorAndProofs`;
  [account-recovery.md](docs/operations/account-recovery.md#recovery-restricted-sessions-mfa-010-usr-003)).
  Clients that react to account states must accept `recovery_restricted`.
- **Adding a factor needs an existing one** (MFA-006): when the account
  already has an active TOTP or passkey, the four self-service enrollment
  routes need a session that completed MFA (a recovery-code session counts);
  otherwise `403 step_up_required` with the obligation
  `{"type": "reauthenticate", "required_profile": "mfa"}`
  (`TestFactorEnrollmentNeedsExistingFactor`, `TestPasskeys`).
- **Profile attribute visibility** (USR-002, USR-007): `GET /me`,
  `PATCH /me` and the self-service data export include only attributes the
  realm schema defines with `visibility: self`; administrator views include
  `self` and `admin` attributes and undefined ones, never `internal`. Admin
  `PATCH /users/{user}` type-checks `profile` values against the schema
  (unknown attribute `422`), limits `profile` and `admin_metadata` to 16 KiB
  each and bounds name fields like self-service; administrators may set
  attributes of any `source`
  ([data-inventory.md](docs/operations/data-inventory.md#accounts-and-credentials))
  (`TestProfileAttributeVisibility`).
- **Account deletion needs ownership transfer** (USR-020): `DELETE
  /users/{user}` and `POST /me/deletion-request` answer `409 last_owner` with
  the extension `owned` (`projects`, `clients`, `service_principals`,
  `resources`, `identity_providers`: IDs) while the account owns live objects;
  move them first (see **Added**). Offboarding scripts must transfer
  ownership before deleting.
- **Organization switch follows the organization's sign-in rules** (TEN-005,
  TEN-012, `TestOrganizationSwitch`): `POST /me/organization-grants` refuses
  a session without a federated factor from `policy.sso_provider_id` when
  `sso_required` (`403 sso_required`), a session without an allowed method
  (`403 step_up_required`, obligation with `allowed_login_methods`), and a
  session past the organization's `session_absolute_seconds`
  (`403 step_up_required`); the new grant expires no later than `auth_time`
  plus that lifetime
  ([ADR 0012](docs/architecture-decisions/0012-one-organization-per-token.md#decision)).
- **Groups** (TEN-008, TEN-013): adding a group member, or moving a group
  under another parent (`PATCH` with `parent_id`), needs the authority to
  assign every role of the group (or new parent) and its ancestors (`403`),
  and a move counts the moved subtree's height against
  `limits.max_group_depth` (`422`). `group.updated` records `parent_id` and
  `previous_parent_id`, and every group update bumps the membership revision
  of all members of the subtree (`TestDelegationCeilings`;
  [ADR 0006](docs/architecture-decisions/0006-realm-and-organization-boundaries.md#update-2026-10)).
- **Domain conflicts** (TEN-009, `TestDomainReverification`): verifying a
  domain another organization of the realm holds verified sets the claim to
  `conflict`, records `organization.domain.conflict` (category `security`,
  outcome `denied`) and answers `409`.
- **Required actions** (AUT-018): `POST /users` with `required_actions` needs
  the permission of each action (`realm.users.credentials.manage` for
  `update_password` and `configure_totp`, `realm.users.write` for
  `verify_email`), like `POST /users/{user}/required-actions`; it does not
  need `realm.users.required_actions`. `POST /users/{user}/required-actions`
  is now a compare-and-set: a concurrent change makes it fail with
  `409 conflict` ("the required actions changed concurrently; retry")
  (`TestRequiredActionEditRace`). The `POST /users` check has no regression
  test yet.
- **Conditional required-action edits** (AUT-018, API-010, SEC-008,
  `TestRequiredActionEditRace`): the compare-and-set above only covered the
  request's own read, so two administrators who each read the list, changed
  a different action and wrote it back could both succeed, the later one
  silently undoing the earlier. `POST /users/{user}/required-actions` now
  accepts `If-Match` with the ETag of `GET /users/{user}` and answers `412`
  when the account changed since that read; a successful edit returns the new
  `ETag`. Adding or removing an action through bulk `add_required_action`,
  the assisted-recovery factor reset or passkey enrollment now moves the
  account version (and so the ETag of `GET /users/{user}` and `GET /me`), so
  such a change also makes an earlier `If-Match` stale. Actions that sign-in
  completes inline still do not move it
  ([threat model](docs/threat-models/system.md)).
- **Redirect targets on the identity provider's own origin** (APP-004,
  `TestRedirectRegistrationRules`): `redirect_uris` and
  `post_logout_redirect_uris` whose host is that of `server.public_origin` are
  refused at registration and update (`422`, "must not point at the identity
  provider itself"). Existing clients with such URIs keep working until their
  next update
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#redirect-uris-and-origins)).
- **Support writes through the decision API** (IMP-011, IMP-013): an action is
  a write when any segment is a write verb, whatever its suffix, and an
  `allowlisted_write` support token may perform a write only when the
  resource lists the action in `impersonation_policy.write_actions`
  (`SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED` otherwise). Resources that relied on
  support writes through `/authorization/check` must list them
  ([resource-servers.md](docs/integrations/resource-servers.md#6-support-access-contract)).
- `security.totp_skew_steps` accepts `0`–`2` and `security.recovery_code_count`
  `5`–`20` (MFA-002); other values stop startup
  ([configuration.md](docs/operations/configuration.md#security)).
- Discovery's `grant_types_supported` leaves out grant types the realm
  disabled with an emergency control (OIDC-015, `TestEmergencyControls`).
- Transient sessions never yield an offline grant or a refresh token, even
  when `offline_access` was requested and consented, also when a later
  sign-in reuses the session through SSO; the token endpoint mints no refresh
  token for a transient session's grants (SES-020,
  `TestOfflineConsentAndTransientSessions`; see **Security fixes**).
- `make bench` refuses to start without `BENCH_URL` and
  `PROUDAUTH_BENCH_ADMIN_TOKEN`, seeds with the current time unless
  `BENCH_SEED` is set, and the `refresh-race` scenario reports
  `inconclusive_rate_limited`, `inconclusive_http_5xx` and
  `inconclusive_transport_error` instead of a violation when no attempt
  reached a decision ([benchmarks.md](docs/operations/benchmarks.md)).
- `identity-cli` writes stored credentials, `config-export` and
  `config-apply --secrets-out` files and support bundles with mode `0600`
  through a temporary file and a rename (`revocation-log --out` appends to a
  `0600` file instead).
- SDK middleware: Go `Middleware` failures carry `Cache-Control: no-store`
  and scope or organization errors answer `403` with
  `Bearer error="insufficient_scope"`; the Node.js adapters send that header
  for organization mismatches too. The Go `Introspector` refuses support
  tokens (`ErrTokenKind`) and a configuration that accepts them
  (`ErrSupportKind`); support tokens go through `SupportGuard`.
  `OnDeprecated` / `onDeprecated` receive the path without its query
  ([sdk-compatibility.md](docs/integrations/sdk-compatibility.md)).
- Go SDK: `verifier.ProtectedOperations`, `verifier.WriteSegments` and
  `verifier.DefaultOnlineKinds` are no longer exported variables, so code
  importing the package cannot weaken the support-access protections or the
  introspector's accepted token kinds at run time. Read them with
  `verifier.ProtectedOperationList()`, `verifier.WriteSegmentList()` and
  `verifier.DefaultOnlineKindList()`, which return copies; add protected
  operations of your own with `SupportGuard.ProtectedOperations` as before.
  **Migration:** replace reads of the variables with the functions; code that
  modified them no longer compiles (by design).
- Bounded-state verification (Go `BoundedState`, Node.js `BoundedState`):
  `Start` / `start()` no longer clears the revocations already replayed (the
  stream has no snapshot that could supersede them), the state counts as fresh
  for `MaxStaleness` only once a sync has reached the end of the stream, and a
  `410` (cursor older than the retained history) rewinds to the beginning of
  the retained history and reports Go `ErrCursorExpired` / Node.js
  `CursorExpiredError` (code `unavailable`); `Run` / `run()` then replays that
  history at once (once in a row) and keeps following the stream. A
  revocation time only moves forward, so a replay never weakens the state.
  `user.recovery_restricted` is no longer treated as a subject revocation
  (the server keeps those sessions valid), and Node.js `run(signal)` aborts an
  in-flight long poll and a backoff wait at once (`sync(waitSeconds, signal)`
  passes the signal to `fetch`)
  ([resource-servers.md](docs/integrations/resource-servers.md#1-register-the-api)).
- **Configuration import authority** (ARC-008, `TestConfigImportAuthority`):
  applying a document needs, besides `realm.configuration.import`, the write
  permission of every change in the plan (realm policy
  `realm.settings.write`; clients and grants `realm.clients.write`; resources
  `realm.resources.write`; roles and permissions `realm.roles.write`;
  `403` otherwise). A document that changes the realm policy must carry
  `expected_policy_revision`, like `If-Match` on `PUT /settings` (`422`,
  "set expected_policy_revision (the realm is at N)"). `/validate` and dry
  runs check neither. **Migration:** give importing service principals the
  write permissions and add `expected_policy_revision` (the `policy_revision`
  of `GET /settings`) to documents that change the policy
  ([exit-and-export.md](docs/operations/exit-and-export.md#configuration-import)).
- Configuration import and export of client resource grants (SDK-012,
  TOK-016): entries accept `exchange_policy` (`accept_from_audiences`,
  `max_scopes`), and the export includes it when set. An existing grant keeps
  the `subject_types` and `exchange_policy` the document omits instead of
  being reset to `["user"]` and no policy; a grant is unchanged when its
  scopes, and its subject types and exchange policy where given, match.
- The configuration export includes every active client and resource (paged,
  no 1000 cap), and the configuration document schema describes the policy
  members `audit` and `authentication_flow`. The plan reports drift of a
  resource's `impersonation_enabled` and `impersonation_policy`.
- Operator commands (`migrate -status`, `migrate -plan`, `doctor`,
  `realm-create`, ...) never apply migrations, whatever
  `storage.migrate_on_start` says; only `identity-cli migrate` and server or
  worker startup do. `identity-cli migrate -plan` is read-only and works with
  the runtime role (OPS-013;
  [upgrades.md](docs/operations/upgrades.md#how-migrations-work)).
- Database roles (OPS-013): `storage.runtime_role` is validated at startup;
  the grants after each migration run also set default privileges for later
  tables and sequences, revoke `CREATE` on schema `public` and `DELETE` on the
  audit tables from the runtime role (it prunes through
  `proudauth_audit_prune`, migration `0044`), and `identity-cli doctor` also
  warns when the role inherits the owner's privileges or can create objects
  in `public`
  ([installation.md](docs/operations/installation.md#database-roles)).
- Custom domains (DEP-014, migration `0043`): only a verified domain reserves
  its host across realms; a pending one is unique within its realm (`409`,
  "already registered in this realm"), and verifying a host another realm
  verified first answers `409` ("the host is already in use").
  `passkeys_usable` uses the realm's effective RP ID (`webauthn.rp_id`, else
  the login UI host, else the issuer host), and without configured
  `webauthn.origins` the verified custom hosts under the RP ID are accepted
  origins. The host cache keeps its previous list when the database cannot
  be read ([installation.md](docs/operations/installation.md#custom-domains)).
- `keys.kms.timeout` (at most `1m`, default `10s`) now limits each unwrap;
  secret references are bounded at 5 minutes overall. The KMS command no
  longer receives `PROUDAUTH_*` variables (DEP-016;
  [keys.md](docs/operations/keys.md#kms-envelope-dep-016)).
- Tracing (OPS-003): an incoming `traceparent`'s sampled flag is honored only
  from `server.trusted_proxies`; from other clients the trace ID is continued
  and `observability.trace_sampling` decides. In production
  `observability.otlp_endpoint` must be `https` (loopback excepted); the
  exporter ignores proxy variables, never follows redirects and drops spans
  exported after shutdown.
- Finished sign-in transactions lose their client IP address and user agent
  at the next cleanup run unless `privacy.store_full_ip` is set; the rows go
  24 h after finishing (PRV-002).
- Paged lists (API-004, `TestDatabasePagedLists`):
  `GET /webhooks/{id}/deliveries`, `GET /notification-jobs` and
  `GET /me/security-events` are paged in the database with cursors (newest
  first, `limit` up to `limits.max_page_size`, `next_cursor` until the end)
  instead of returning one capped page (200 or 100 items).
- Verification budgets (REG-012, SEC-006, `TestVerificationBudgetPerClient`):
  proof attempts (codes, magic links, TOTP, recovery codes, passkeys,
  challenge answers) also count against `security.rate_limits.login_per_realm`,
  the new `login_per_client` (default 20000 per `login_window`) and
  `login_per_organization`, besides the per-account and per-network budgets.
- Claim mappings (APP-011, OIDC-007): neither `id_token_claims` nor
  `access_token_claims` may name an OIDC standard user claim (`name`, `email`,
  `locale`, ...; `422`), and issuance skips such names stored by older
  versions in access tokens as it already did in ID tokens. **Migration:**
  rename such mappings
  ([upgrades.md](docs/operations/upgrades.md#mixed-version-window)).
- Organization deletion (TEN-024, PRV-005): the preview adds `owned_clients`;
  starting the deletion suspends the organization's owned projects and the
  active clients of those projects and of its service principals and revokes
  their refresh tokens, and finishing it revokes the clients' credentials and
  erases their secret digests and public keys. A job of the organization
  still running when the deletion starts stores no result and ends
  `cancelled` ("organization deleted while the job ran"), except the deletion
  job itself
  ([data-inventory.md](docs/operations/data-inventory.md#organization-deletion)).
- A scheduled self-service deletion that falls due while the account is the
  only owner of an organization or owns projects, clients, service
  principals, resources or connections is postponed by 24 hours and recorded
  as `user.deletion.postponed` (reason `OWNERSHIP_NOT_TRANSFERRED`, metadata
  `organizations` and `owned`) (USR-020;
  [data-inventory.md](docs/operations/data-inventory.md#account-deletion)).
- `POST /organizations` validates a given policy like `PATCH` does; at
  creation `policy.sso_provider_id` can name only a realm-wide connection
  (`422`). Ownership transfers increment the transferred object's version, so
  an earlier `ETag` no longer matches.
- Groups (AZ-018, AZ-019): a dynamic group's recomputation leaves out a
  member whose roles would conflict and records `group.member.skipped`;
  granting or removing a role on a group raises the membership revision of
  the members of the group and its descendants, which changes their decision
  cache keys in an organization's context
  ([ADR 0013](docs/architecture-decisions/0013-authorization-model.md)).
- Authentication: polling a transaction locks it like a step; self-service
  passkey enrollment also clears the `configure_totp` required action; stored
  texts (remembered-device labels, passkey names, user agents, hook and
  federation error messages, JIT usernames, claim values) are cut on UTF-8
  boundaries; audit metadata `recovery_restricted` and `recovery_id` are no
  longer redacted.
- Organization domains: a removed or expired claim can no longer be verified
  (`409`, "add the domain again"), and a verification racing a removal fails
  ([ADR 0006](docs/architecture-decisions/0006-realm-and-organization-boundaries.md#update-2026-10)).
- `GET /notification-settings?organization_id=<org>` returns that
  organization's settings and `ETag` (for `PATCH` with `organization_id`), and
  `POST /organizations/{org}/roles/{role}/permissions` returns the role's
  `ETag`.
- The redirect-URI own-origin check (APP-004) compares host names whatever the
  port and also covers the realm's verified custom domains; loopback hosts are
  exempt
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#redirect-uris-and-origins)).
- Registering client public keys (`POST /clients/{client}/credentials` with
  `jwks`) records `client.credential.public_key_added` (metadata `key_ids`).
- Session-event stream (SES-019, migration `0046`): pruning records the
  newest pruned stream position per realm, and a cursor expires
  (`410 cursor_expired`) only when stream events after it were pruned, so a
  caught-up consumer on a quiet realm keeps its cursor
  (`TestStreamCursorAfterPruning`).
- Restore reconciliation (OPS-006) erases a user deleted after the backup
  with the same code as account deletion (also password history, remembered
  devices, pairwise subjects, notification preferences, grants, automation
  credentials, pending recoveries, merges and approvals)
  ([backup-restore.md](docs/operations/backup-restore.md#what-reconciliation-re-applies)).
- Organization templates (TEN-017) match an existing service principal only
  by the exact name `<slug>-<entry>` for the organization's current or a
  former slug, never by a name suffix.
- SCIM (PROV-003, PROV-009, `TestSCIMProvisioning`): `eq` filters on `id`,
  `externalId`, `userName` or `displayName` are answered from indexes; other
  lists over more than 20,000 resources answer `400 tooMany` for groups too
  (no truncation); `ETag`s are derived from the resource's content, so
  administration-API changes make them stale (`412`); discovery requests are
  counted as `get_discovery`; deleting a group (also through the
  administration API) is one transaction that records each removed role
  assignment as `role.unassigned` (reason `GROUP_DELETED`)
  ([scim-provisioning.md](docs/integrations/scim-provisioning.md)).
- User imports (MIG-002, MIG-006): `GET /user-import-formats` now lists bcrypt
  and PBKDF2 verifiers, names, locale, the suspended state, required actions
  and administrator metadata under `supports`, and bcrypt and PBKDF2 are no
  longer in `unsupported` (only outside their bounds); records carrying
  required actions now need the matching permission besides
  `realm.users.import`, also when the worker runs the job.
- `security.password.legacy_hashes_until` (CRED-004) now also ends imported
  bcrypt and PBKDF2 verifiers, not only salted SHA-256, and `identity-cli
  doctor` counts them.
- Webhook subscriptions and pre-action hooks (EXT-014, EXT-018) gain `event_version` and
  `contract_version` (both `1` for existing ones, so their deliveries and
  requests are unchanged) and `plugin_id`; `PATCH`/`DELETE /webhooks/{id}` and
  `PUT`/`DELETE /hooks/{id}` answer `409` for parts a plugin manages. Every
  hook request now carries the `ProudAuth-Hook-Version` header. Events caused
  by a lifecycle workflow run carry the run ID as `correlation_id`, where
  background work had none before.
- `/organizations/{org}/provisioning-connectors` now accepts and lists only
  `scim_inbound` connectors: `"kind": "scim_outbound"` (previously stored
  without behavior) is `422` on `kind`, and `ldap` and `scim_outbound`
  connectors are managed at `/directory-connectors` (PROV-010, PROV-011).
  `scim_outbound` connectors created earlier appear there without a
  configuration; disable them before upgrading
  ([scim-provisioning.md](docs/integrations/scim-provisioning.md#upgrade-note)).
- `clients` gain `protocol` (`oidc`, or `saml` for the backing client of a
  SAML application); `GET /clients` shows it, and `PUT /clients/{id}` answers
  `409` for SAML-backed clients (change them through `/saml/applications`).
  Password changes, password reset completion, account setup, profile and
  identifier edits and reactivation now pass an attribute-authority check
  that refuses changes a directory owns (`409 conflict`, USR-022); accounts
  without a directory link are unaffected.
- Configuration reconcile (SDK-012): `?mode=reconcile` on
  `/configuration/validate` and `/configuration/imports` (CLI
  `config-plan -reconcile`, `config-apply -reconcile`) applies updates of
  differing clients (the whole registration from the document, keeping
  project, owner, default resource and service principal links), resources
  (members the document omits keep their values; they used to be cleared) and
  role permissions (added and removed within the delegation ceiling) in the
  same atomic import, each needing its write permission and audited as
  `client.updated`, `resource.updated` or `role.permissions.changed`.
  `/validate` needs `realm.configuration.import` and, like dry runs, reports
  missing per-change permissions (`<item>: requires <permission>`) and a
  missing `expected_policy_revision` as plan errors. Exchange policies are
  validated in imports and in `PUT /clients/{client}/resource-grants/{resource}`
  (`max_scopes` declared by the resource, `accept_from_audiences` registered
  audiences; `422`), lists are compared as sets, and the grant audit event
  records `exchange_policy`
  ([exit-and-export.md](docs/operations/exit-and-export.md#configuration-import)).
- `private_key_jwt` (MCH-010, APP-009): every `aud` value of a client
  assertion must be this server's token endpoint or issuer (at most two
  values); an assertion also addressed to another party is refused.
- RP-initiated logout validates `post_logout_redirect_uri` before anything is
  revoked, so a bad redirect leaves the session intact; the upstream-logout
  return `state` (FED-013) is single-use (a replay is `400`).
- The token-exchange consent ceiling (TOK-008) applies to subject tokens of
  consent-governed, non-machine clients, that is at the first hop; later hops
  are bounded by the exchange policies and grants of each hop.
- Account deletion (PRV-005, migration `0048`) suppresses the account's queued
  notifications and erases their payloads and recipients at once, for
  messages whose sender records the account; `GET
  /users/{user}/deletion-status` reports `notifications` as `done` or
  `pending` with a count, dates `audit_evidence` by the longest applicable
  retention (deployment, categories, realm) and counts only legal holds that
  cover the account (organization holds are mentioned separately)
  ([data-inventory.md](docs/operations/data-inventory.md#deletion-propagation-report)).
- Organization deletion preview (TEN-024): `active_legal_holds` counts holds
  on the organization, realm-wide holds and subject holds on its members.
- Imported audit history (AUD-013, PRV-004): records about an account already
  deleted keep their details when a legal hold covers them; realm and
  organization audit retention now also keep imported records longer.
- Federation (FED-016): a connection's `kind` follows its adapter on update;
  changing the adapter to another protocol while identities are linked is
  refused with `409` (field `adapter`), like changing the issuer.
- Just-in-time provisioning (REG-009): an unverified upstream email that
  another account has verified is not copied to the new account, and a taken
  generated username gets a random suffix instead of failing the sign-in.
- `identity-cli config-diff` (DEP-020) also marks `server.host_policy`,
  `server.public_listen`, `server.tls_cert_file`, `server.tls_key_file`,
  `storage.migration_database_url`, `storage.runtime_role`,
  `observability.otlp_endpoint` and `workers.metrics_listen` as security
  boundary changes.
- Cookie-authenticated calls (SEC-002, DEP-014) accept a verified custom
  domain as `Origin` only on the default port or the public origin's port.
- Operator commands (OPS-013): `restore-reconcile` records the OS user as
  actor (`local:<user>`); `migrate`, `revocation-log` and `support-bundle`
  exit with an error when their audit record cannot be written (the action
  has already happened, and the message says so).
- Privileged-role detection (access reviews, migration reconciliation,
  exports, approvals) follows role composition at any depth, counts wildcard
  grants (`*`, `x.*`) and custom permissions registered as privileged, and
  treats a composition of more than 64 roles as privileged.
- Dynamic groups (TEN-014, AZ-010): a rule matching more than 10000 members
  records a rule error and leaves memberships unchanged (they grant nothing
  meanwhile); `group.member.skipped` is recorded once per new skip;
  `member_count` excludes skipped members. Groups refuse removed or expired
  memberships as members (`422`).
- Flow challenges (SEC-014): the challenge provider is called outside the
  database transaction, after the continuation proof and the pending
  challenge are checked; its answer is applied in the step's transaction.
- `proudauth_security_signals_total` (OPS-004) counts an audit event when its
  transaction commits; rolled-back or retried attempts are not counted (audit
  write failures still are, immediately).
- `identity-cli bootstrap -ttl` outside 1 minute to 24 hours is refused (it
  used to become 1 hour silently; DEP-005).
- Custom domain verification succeeds only for the pending challenge that
  was checked; a removal during the DNS lookup wins (`409`).
- Route labels of metrics, spans and request logs (OPS-002) are the
  registered route patterns (for example `/api/v1/realms/{realm}/users/{user}`),
  or `unmatched`. Idempotency records (API-008) hash method and path with the
  body, so a key reused for another resource is a mismatch (`422`), never a
  replay.
- Residency (PRV-003): organization mail servers and upstream identity
  provider URLs outside `privacy.residency.allowed_destinations` are refused
  when saved (`422`), not only when contacted.
- Decision cache key (AZ-019): the fingerprint covers the roles of ancestor
  groups and the versions of composed roles; group memberships with a
  validity window make decisions uncacheable; a role's permission change
  invalidates holders of roles composing it (any depth) and members of groups
  holding them.
- Rate limits: password attempts per client use
  `security.rate_limits.login_per_client` (default 20000 per login window; it
  was `token_per_client` × 10, about 6000); identifier-verification sends
  count against the per-client and per-organization send budgets.
- Inactive accounts (suspended, locked, pending verification or deletion,
  deleted) and disabled or deleted service principals hold no permissions
  anywhere, in decisions and in job re-checks.
- `user.bulk` jobs check the permission of each action (no longer a blanket
  `realm.users.write`), at the request and in the worker; organization
  deletion jobs run only while the requester still holds `org.delete` (else
  they dead-letter and the organization stays `deleting` until an authorized
  `DELETE` queues the job again).
- Job downloads: audit and realm data exports are served as
  `application/x-ndjson` (`export.ndjson`), other results as
  `application/json` (`export.json`); the download permission is checked again
  when the token is redeemed (a `403` does not spend the token), and
  `job.result.downloaded` records the actual actor type.
- Invitations: `limits.invitation_resends` counts resends only (one more send
  than before); a negative `ttl_hours` is `422`; declining an expired
  invitation is `400 invitation_invalid` and marks it expired; list cursors
  are bound to their filters (`400` when reused with others); the bulk
  limit error names the configured maximum.
- Passkey self-service enrollment requires user verification while
  `security.mfa_floor.admin_phishing_resistant` (or the realm's
  `mfa.admin_phishing_resistant`) is set.
- Runtime role setup also revokes `CREATE` on schema `public` from `PUBLIC`
  (effective when the migration role owns the schema or is a superuser).
- The realm data export includes `owner_user_id` for authorization policies
  and hooks, and `hotp` in each account's credential summary.
- SCIM: Group filters accept URN-qualified attribute names; deletes check
  `If-Match` under a row lock; a connector `PUT` that loses to a concurrent
  update answers `412`.
- `retention.cleanup` runs every step even when one fails and reports the
  failed steps together; KMS commands that leave a child process holding
  their output are waited for at most 1 more second.

### Fixed

- **Local image secret reinitialization** (DEP-002, DEP-004): unchanged
  credentials now recover the container-readable file mode while preserving
  their bind-mounted inode. PostgreSQL startup also refuses automatic image
  pulls. Deployment regressions cover private generation, idempotence,
  permission repair, the PostgreSQL 18 volume root and Swagger contract drift.
- **Hosted CI E2E deadline** (QA-002, QA-008): a full race-detector run
  reached test 378 of 403 when the 20-minute package deadline expired; the
  active test had run for only two seconds and no assertion failure preceded
  the alarm. The package deadline is now 30 minutes, with a 45-minute test-job
  cap and verbose progress for diagnosis. The complete suite, race detector,
  password costs and test assertions remain required.
- **Development Compose startup on PostgreSQL 18 and native Linux**
  (DEP-002, DEP-004): the data volume now mounts `/var/lib/postgresql`, as
  required by PostgreSQL 18's versioned data layout. Generated secret files
  are readable through the non-root containers' read-only mounts while their
  host directory remains owner-only; repeated initialization preserves keys
  and passwords. Deployment regressions cover the mount, permissions and
  idempotence. Existing database volumes require an explicit migration.
- **CI static analysis failed on Go 1.27** (QA-002, QA-008): the old
  Staticcheck 2025.1.1 exporter supports data version 2 and cannot read the
  compiler's version 5. CI now pins the tested stable 2026.2.2 release.
  Twenty real findings are resolved: unused helpers/fields and assignments,
  redundant formatting/loops, and deprecated coordinate access in the
  software passkey fixture. Exchange expiry continues to use the injected
  clock. The old failure and passing replacement are recorded with source
  hashes; no tagged release is affected.
- **Session-lifetime test clock calculation** (TEST-032): the regression
  now measures elapsed time from its injected clock's starting value,
  removing a sign error introduced during the Staticcheck cleanup and
  avoiding dependence on wall time. Three race-detector repetitions and the
  [final full check](docs/operations/consistency-tests.md#complete-current-go-module-check--2026-10-13)
  pass (716 top-level tests, 562 subtests); production session and refresh
  limits are unchanged. All 11 CI fuzz targets also pass.
- **Offline bundle failures could destroy prior assets or hide export errors**
  (DEP-017, QA-008): builds now validate version labels, stage privately,
  preserve/restore the previous archive and checksum on failure, refuse
  concurrent writers and clean up on interruption. Explicit image export and
  per-file hashing propagate failures instead of hiding them in POSIX shell
  pipelines. Filenames containing spaces keep their checksums, and macOS
  AppleDouble metadata is excluded from the distributed archive. Executable
  fault, signal, concurrency and archive-integrity regressions cover these
  boundaries. Affected: earlier untagged development tooling; no schema change.
- **Floating container base references** (DEP-003, SEC-016): the builder
  and non-root runtime now use verified, locally cached OCI index digests
  while retaining exact version tags. The release toolchain contract requires
  immutable references; frontend/Action pins, vulnerability review and
  off-host release/image reproduction remain open.
- **Offline federation guidance omitted production CIDR allowances**
  (OSS-005, FED-017): internal upstream providers may use explicit
  `federation.egress_allowlist` and a private CA in production; the broad
  private-network bypass remains rejected.
- **Concurrent and failed metadata/JWKS fetching bypassed retry bounds**
  (FED-017, NFR-006): OIDC discovery/key fetches, workload keys and Shared
  Signals keys share a bounded fetch and a one-minute retry cooldown per
  process/cache identity. Previously a concurrency-32 burst made 32 fetches;
  three invalid-response bursts made 96 instead of two. Caller cancellation
  leaves other waiters' fetch alive, invalidated old responses cannot overwrite
  new caches, DNS shares the fetch deadline and temporary metadata clients
  close idle traced connections. TLS, egress, signature checks and workload
  transport/status fallback remain enforced. Affected: earlier untagged
  development builds; no schema migration. See [upgrades](docs/operations/upgrades.md).
- **Literal audit prefixes and filter-bound cursors** (AUD-006, AUD-011,
  API-004): earlier development builds interpreted `_`/`%`/backslash as
  SQL LIKE instructions and accepted audit cursors after filter/route
  changes. Prefixes now match literally; cursors bind canonical filters,
  route, realm and authorized organization. Regression fixtures prove
  exact compound pages with newer evidence inserted between pages, foreign
  scope and changed-filter refusals. Restart existing audit pagination after upgrading;
  records and schema are unchanged ([upgrades](docs/operations/upgrades.md)).
- **SCIM Group filters issued per-group database reads** (PROV-002,
  PROV-008, NFR-004, NFR-006): list queries now batch scoped metadata and
  stream ordered members, retaining one raw group collection and the
  requested page. The regression observed 17 queries for 8 Groups and
  129 for 64; both now use three. Member-dependent projection, full counts,
  individual-read ETags, missing/foreign mappings and database-error
  propagation retain regression coverage. Single Group reads also qualify
  organization/realm membership scope. Affected: untagged development builds
  before this fix; no schema migration.
- **Passwordless OTP aliases bypassed the shared account budget**
  (TEST-021, NFR-006): an email/SMS login challenge now supplies its bound
  account solely for budget selection, without authenticating the transaction.
  Previously rotating email, phone and HOTP for one account allowed 28
  evaluated wrong proofs in a concurrency-32 burst instead of ten. Phantom
  challenges retain identifier budgets; database lookup errors fail closed.
  Affected: untagged development builds before this fix. No schema change.
- **Partial directory failover suppressed deprovisioning** (PROV-012,
  PROV-014, PROV-017, NFR-007): each endpoint scan resets its deletion
  presence set, so only a complete successful source view determines
  missing memberships. Previously users seen before a broken connection
  stayed active even when absent from the fully scanned replacement.
  Regression tests reproduce this on full and incremental-to-full scans;
  complete transport exhaustion still cannot delete from partial data.
  Affected: untagged development builds before this fix.
- **Expired job workers could overwrite replacement results** (DEP-011,
  PROV-012, NFR-007): progress and terminal writes now require the unexpired
  worker/attempt claim. Directory mutation transactions lock that claim
  before changing accounts, links, Groups, delivery state or final evidence.
  Previously a stalled worker changed a successfully recovered sync to
  failed and emitted a second completion audit. Regressions retain the
  replacement's state, cursor, protected job results and exact audit counts.
  Final-write errors propagate instead of reporting completion.
  Affected: untagged development builds before this fix. Drain old workers
  before replacement; [upgrade notes](docs/operations/upgrades.md).
- **Group deletion could stall connector updates and strand external IDs**
  (TEN-013, PROV-004, PROV-007, PROV-008, DB-014): local deletion, SCIM
  writes and directory Group application now lock the group before its
  mapping and members. Inbound/directory links end atomically with local
  deletion, and reprovisioning repairs legacy orphan links. Live groups
  are not adopted; outbound links remain until remote deletion is delivered.
  Pre-fix regressions reproduce a membership lock timeout and `409`
  recreation failure; replica, LDAP and actual SCIM transport regressions
  prove the correction. Affected: untagged development builds before this fix.
- **Benchmark SQL commands could consume a streaming caller's input**
  (NFR-008): `bench-local.sh` uses interactive Docker stdin only for
  explicit stdin SQL, keeping later caller validation/cleanup commands
  intact after `psql -c`. `TestBenchRunnerSQLKeepsCallerInput` exercises
  command and heredoc forms with a consuming Docker stub.
  Affected: the untagged local runner before this fix.
- **Refresh and session revocation held locks in opposite orders**
  (SES-007, NFR-007): session-bound refresh now locks its session before
  the family; account-wide revocation visits session IDs in order.
  Initial concurrency-32 requests reached the 30-second deadline.
  Database-backed replica regressions require completed revocations and
  no post-commit successor or active access token.
  Affected: untagged development builds before this fix.
- **Grant revocation left JWT authority active online** (SES-008,
  SES-021, SES-023, TOK-010): JWT introspection, UserInfo and IdP user APIs
  now check their realm/subject/client-bound active, unexpired grant.
  Token exchange checks and retains the originating grant. Previously an
  offline JWT remained active after confirmed refresh reuse; unrelated
  grants and SSO sessions still survive client-local grant revocation.
  Regression tests cover all three replicas, missing/foreign-client grant
  links, exchanged descendants and fail-closed grant-store errors.
  Affected: untagged development builds before this fix.
- **Concurrent ownership transfers upgraded incompatible shared locks**
  (TEN-006, NFR-007): transfers now acquire the exclusive organization
  lock directly, then check active state and current authority. Non-dry
  template application uses the same mode for policy writes. The
  concurrency-32 regression failed at the 30-second deadline before the
  fix; it now leaves one active owner and rejects the former owner's
  competing transfers. Ordinary grant issuance retains shared locking.
  Affected: the untagged development build before this fix.
- **Concurrent role deletion reported repeated transitions** (NFR-007):
  a delete affecting no row now returns `404` before changing revisions
  or recording audit/outbox evidence. Competing expiry workers skip an
  already removed assignment and count only real expirations. The
  regression previously observed 27 successful deletes of one grant;
  repeated replica tests now require one transition and exact live
  permissions, holder revisions and evidence counts.
  Affected: the untagged development build before this fix.
- **SCIM User scans performed four database round trips per candidate**
  (PROV-002, PROV-008, NFR-004, NFR-006): 32 concurrent 10000-user
  boundary-filter scans timed out without a successful result. Scoped
  mappings, user/identifier data and memberships now load in bounded
  batches; only the requested page is retained while every match is counted.
  A real-query tracer regression fails for the old 33/257-query reads and
  now observes five queries at both cardinalities, with identical individual
  resource data/ETags. Batch reads preserve realm scope, identifier order,
  deletion and failure semantics. The initial failed reference run remains
  published alongside the [passing corrected measurement](docs/operations/benchmarks.md#scim-filter-results-nfr-004-nfr-006-nfr-008):
  677 exact bounded searches complete without transport errors, with
  parser-overflow and unchanged connector-budget refusals also verified.
  Affected: the untagged development build before this fix.
- **Initially inactive SCIM users failed with a default role**
  (PROV-004, PROV-005, QA-008): the connector now creates the membership,
  assigns its approved default role and suspends it in the same transaction.
  An active membership is never exposed outside that transaction. The
  regression checks the suspended membership and retained default role,
  then ETag-bound reactivation without a duplicate grant. General role
  assignment's active-membership requirement remains enforced.
  Affected: the untagged development build before this fix.
- **SCIM read failures appeared as complete empty/partial lists**
  (PROV-002, NFR-006, QA-008): user and group lists now propagate database
  read errors instead of silently dropping candidates. User/identifier
  failures also return an error instead of falsely reporting `404`.
  Deleted or concurrently removed resources remain invisible. A real
  PostgreSQL regression locks each relevant table and forces read timeouts,
  then checks error documents, recovery and deleted-account behavior.
  Affected: the untagged development build before this fix.
- **Benchmark interruptions and cleanup failures could report success**
  (NFR-005, NFR-008): the CLI now keeps usable partial JSON while returning
  a failure, and results/envelopes record `complete`. Encoding/write errors
  are propagated with the original failure. The local runner requires
  completed runs/windows and preserves the configured host label on partial
  evidence. Soaks exclude preparation/warm-up from the measured budget and
  shorten their last window instead of overrunning a nonmultiple duration.
  Unit and real-process signal regressions cover these lifecycle failures;
  historical reference JSON remains unchanged. Details:
  [benchmarks.md](docs/operations/benchmarks.md#run-completeness-nfr-005-nfr-008).
- **Webhook benchmark preparation crossed unfinished seed work** (NFR-004,
  NFR-008): full-cardinality imports and assignments can leave an outbox
  backlog behind a default worker. An unmeasured public-API readiness cycle
  now proves callbacks and delivered records before timing, with its wait
  recorded. Measured timeouts and worker budgets remain unchanged.
  `TestBenchWebhookReadinessCrossesSetupBacklog` checks that delayed setup
  callbacks cannot satisfy a later operation.
- **Empty membership pages violated the API contract** (API-004): a
  newly created organization or the last live member's removal could yield
  `{"items":null}`. Member listings now return an empty array and an empty
  cursor as specified. `TestEmptyMembershipPagesAreArrays` reproduces the
  earlier failure and checks both default and active-state listings.
- **Benchmark boundaries lost completed mixed operations** (NFR-008):
  a component's `:ok` response completed at cancellation is now counted,
  consistently with standalone `ok`; interrupted operations remain excluded.
  `TestBenchCountsCompletedMixedOperationAtBoundary` covers both cases.
- **Soak fixture preparation** (NFR-005): the configured concurrency is now
  available before preparation, so passkey, SCIM and mixed scenarios can
  reserve their per-worker fixtures and reuse them across windows.
  `TestSoakPreparesAllWorkerFixturesOnce` covers this tool defect.
- **Local SMTP benchmark configuration:** the runner supplies the required
  sender address when switching from the bootstrap mailbox to SMTP;
  `TestBenchSuiteSmoke` validates that complete configuration before loading
  the actual transport.
- **Benchmark import polling:** missing job IDs and HTTP errors now fail
  preparation immediately instead of polling an invalid resource for up to
  five minutes. Controlled missing-ID and 401/404/503 fixtures cover this
  behavior in `internal/bench`.
- **SDK bearer paths ignored sender bindings:** the unpublished 0.2.0
  Go, Node.js, Dart and PHP SDKs could accept a valid JWT or active opaque
  token containing `cnf` without checking possession. Their token-only
  verifier, introspection, bounded-state and metadata paths now reject it
  with `sender_constraint`; unknown/malformed bindings are also refused.
  Four new shared signed fixtures and opaque-token tests cover every SDK.
  Go applications using bound tokens must migrate to `SenderVerifier`;
  request-level sender verification is not yet offered by the other three
  SDKs. Ordinary unbound bearer tokens keep their previous behavior.
- **Go introspection accepted ambiguous or oversized JSON:** response
  parsing now rejects duplicate members, trailing values and responses
  above 64 KiB, with `ErrUnavailable`. Controlled regression responses
  cover each case; this affects the unpublished development SDK.
- **Go SDK requests followed HTTP redirects:** issuer metadata/JWKS,
  OIDC token/revocation requests, introspection, revocation-state replay and
  administration calls now return redirect responses without forwarding
  credentials or sensitive bodies. A shared transport wrapper preserves
  the caller's client settings and a real HTTP regression proves that
  301/302/303/307/308 destinations receive no requests. This affects the
  unpublished 0.2.0 SDK (SDK-008).
- **Timezone regression test raced with HTTP cleanup:**
  `TestTimeAndUnicodeInvariants` now starts an isolated subprocess with
  `TZ=America/New_York` instead of mutating `time.Local` while HTTP and
  database goroutines read it. Its DST/Unicode checks still run against
  a real isolated PostgreSQL database under the race detector.
- **Identifier uniqueness stress test counted successful no-op updates:**
  contenders now choose a stable identifier before racing, require one
  affected row on success and verify the persisted count. An `OFFSET` into
  the shrinking set of unverified identifiers previously let a late
  transaction update zero rows and falsely report two winners. The verified
  identifier unique constraint remains unchanged.
- **DPoP request binding accepted ambiguous headers and method casing:**
  the token endpoint and protected APIs now refuse multiple DPoP headers,
  and the proof's HTTP method must match exactly, as required by RFC 9449.
  `TestDPoPBoundTokens` reproduced both earlier acceptances with controlled
  proofs and retains duplicate/case-shadowed claim refusals. This affects
  the untagged development server; proofs with lowercase `post` for a
  `POST` request must be corrected by clients (TOK-019, TEST-067).
- **The oversized-input benchmark could upload bodies despite `Expect:
  100-continue` (NFR-006):** Go's one-second continue timeout fell back to
  sending the body while waiting for a delayed 413. The probe now offers
  headers with the declared length, waits through the request deadline,
  and uses a reader that cannot transmit body bytes; asking for the body
  reports `invariant_violation_body_requested`. Regression tests cover a
  delayed refusal and a server sending `100 Continue`
  (`TestOversizedWaitsForHeaderRefusal`, `TestOversizedDetectsContinue`).
- **Benchmark seeding exceeded the default request limit (NFR-004):**
  `make bench`'s 10000-user dataset failed with HTTP 413 because a batch of
  1000 users with password verifiers and organization memberships exceeded
  256 KiB. `identity-bench seed` now bounds each import by both 1000 records
  and 192 KiB; the server's request limit stays unchanged
  (`TestSeedImportsFitDefaultBodyLimit` in `internal/bench`).
- **SAML connections refused responses that repeat an attribute name
  (FED-014, SAML-006):** the broker refused a whole response
  (`upstream_invalid_response`, audit reason `duplicate_attribute`) when two
  `Attribute` elements had the same `Name`. Keycloak's default SAML client
  scope `role_list` sends one `Role` element per role, so no Keycloak user
  holding roles (every user has the realm's default roles) could sign in
  through a SAML connection to Keycloak. Repeated names are now one
  multi-valued attribute, which never fills a single-valued field; the
  connection's `subject_attribute` and `email_attribute` must still appear
  once, and a repeated one is still refused as ambiguous
  (`TestSAMLBroker` subtest "repeated attribute elements (Keycloak role
  list)", `scripts/interop-keycloak.sh`;
  [saml.md](docs/integrations/saml.md#response-validation)).
- **Outbound SCIM requests were refused by ZITADEL (PROV-010):** every
  request carried `Accept: application/scim+json, application/json`, which
  ZITADEL v4 answers with `400 Invalid accept header`, so every delivery to
  it dead-lettered as `rejected`. Requests now name one media type, `Accept:
  application/scim+json` (RFC 7644 section 8.1); responses are still read as
  JSON whatever their `Content-Type` (`TestOutboundProvisioning`, whose SCIM
  double now refuses an `Accept` list as ZITADEL does;
  `scripts/interop-zitadel.sh`).
- **Email changes did not reach outbound SCIM services until a
  reconciliation (PROV-010):** adding, verifying, making primary or removing
  an email address or username did not change the account's `updated_at`
  and published no outbox event, so the change scan never saw it; a
  downstream kept the old address (and an account refused for want of a
  verified address was never retried) until a reconciliation, which is not
  scheduled by default. Identifier changes now mark the account changed, and
  the next scheduler pass delivers it (`TestOutboundProvisioning`;
  [outbound-provisioning.md](docs/integrations/outbound-provisioning.md#triggers-and-deliveries)).
- **A self-service deletion request could not be cancelled by its owner
  (USR-012):** the request revoked every session and a `pending_deletion`
  account could not sign in, so `DELETE /me/deletion-request` could never be
  called, and the `deletion_scheduled` notice ("sign in and cancel") was never
  sent. The request now queues that notice in its own transaction, and a
  pending-deletion account can sign in with its usual factors (MFA included)
  into a transaction whose only action is `cancel_deletion`
  (`POST /auth/transactions/{id}/cancel-deletion`, options
  `deletion_scheduled_at`, `deletion_requested_at`); no session, code or token
  is issued while the deletion is pending. Cancelling makes the account active
  (audit `user.deletion.cancelled`, `via: sign_in`) and the sign-in completes;
  otherwise the deletion completes when due (`TestDeletionCancelAtSignIn`,
  `TestDeletionCompletesWithoutCancel`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#pending-deletion-usr-012)).
- **A refresh could shorten the shared SSO session (SES-002, SES-006):** a
  refresh set the session's idle expiry to the refresh family's window from
  now, so a client with a short `token_policy.refresh_idle_seconds` cut the
  session's idle period for every application. A refresh now only moves the
  session's idle expiry later and never touches its absolute expiry
  (`TestRefreshNeverShortensSession`).
- **A missing pepper version was hashed as an empty password (CRED-009):**
  a verifier naming a pepper version the keyring lacked was checked against
  Argon2id of the empty input instead of failing. It now fails closed with
  `credential.ErrPepperUnavailable`, logged and audited as
  `credential.password.pepper_unavailable` (`TestMissingPepperVersionFailsClosed`;
  [keys.md](docs/operations/keys.md#password-pepper)).
- A sign-in for a resource that requires an organization, by a user with no
  active membership, offered `select_organization` with an empty list that
  could never be answered; the transaction now stops with the blocking reason
  `no_organization` (TEN-005, `TestSignInWithoutAnyOrganization`;
  [headless-authentication.md](docs/protocols/headless-authentication.md)).
- **Lost contact address recovery could not reach the new address
  (MFA-008, USR-004, USR-005):** the runbook told administrators to add the
  owner's new address, override its verification and run assisted recovery,
  but there was no administrator API to add an identifier or make one
  primary, and assisted recovery always mails the primary address, so the
  setup link went to the lost one unless the owner, who could not sign in,
  changed it themselves. Administrators holding both
  `realm.users.verification.override` and `realm.users.credentials.manage`,
  from an MFA session with recent authentication and never for their own
  account, now add an email address with a reason
  (`POST /users/{user}/identifiers`: unverified, not primary, `409` when
  another account verified it, audited as `user.identifier.added`) and make a
  verified one primary (`POST /users/{user}/identifiers/{id}/primary`: `422`
  for an unverified address, audited as `user.identifier.primary_changed`);
  the previous verified primary address receives an `identifier_changed`
  notice for each change. Assisted recovery no longer mails its setup link to
  an unverified primary address: an immediate request answers `409`,
  scheduling one is refused the same way, and a due request whose primary
  address is unverified is cancelled with `contact_unverified`. Before,
  recovery mailed the link to the primary or any other listed email address,
  verified or not, and completing that setup marked the address verified
  ([account-recovery.md](docs/operations/account-recovery.md),
  `TestLostContactAndFactorRecovery`, `TestAdminIdentifierChangeGuards`).
- A request to the API without any credentials was answered with
  `WWW-Authenticate: Bearer error="invalid_token"`; it now gets a bare
  `Bearer` challenge (RFC 6750 section 3.1), and CORS responses expose
  `WWW-Authenticate` to registered origins (INT-001, `TestIdPCORSAndChallenges`).
- **Incident runbooks that did not match the server (OPS-016):** found by the
  new runbook tests (`TestRunbookConnectorCompromise`,
  `TestRunbookWebhookOutage`, `TestRunbookRootKeyCompromise`,
  `TestSharedRevocationAcrossNodes`). A disabled connection refuses sign-in
  and linking with `422 validation_failed`, not `feature_disabled`; webhook
  failure categories are status classes such as `http_500`, not `http_5xx`
  ([incidents.md](docs/operations/incidents.md),
  [monitoring.md](docs/operations/monitoring.md),
  [webhooks.md](docs/integrations/webhooks.md)); the root-key drain checks in
  [keys.md](docs/operations/keys.md#root-key-rotation) never reached zero after
  an emergency rotation or a webhook secret rotation (they counted
  `compromised` signing keys and expired previous webhook secrets) and missed
  HOTP seeds, SAML signing keys, organization mail-server passwords,
  connector credentials, shared-signals stream headers and protected job
  input; TOTP re-enrollment now uses enroll and activate (`DELETE /me/totp`
  is refused for accounts that must keep a second factor); an emergency
  signing-key rotation is documented as taking up to the 5-second key cache
  on other server nodes, which until then also sign new tokens with the
  compromised key; and an account created just in time through a compromised
  connection is suspended, because its only link cannot be removed
  (`409 last_sign_in_method`).

- Role assignments to a group at realm or project scope were stored but
  never evaluated; they are now refused with `422` on `scope` ("groups hold
  organization roles only"), since a group belongs to one organization
  (AZ-010, `TestGroupsHoldOrganizationRolesOnly`).
- **Emailed codes ignored a `ui_locales` preference list (NFR-009):** the
  locale of a message sent during an authentication transaction is the
  request's `ui_locales`, a space-separated list, but template lookup treated
  the whole list as one tag, so `ui_locales=fr-CA es` fell back to English
  although a Spanish template exists. Each listed tag (then its base
  language, at most five tags) is now tried in order before English
  (`TestAuthorizationLocale`, `TestLocaleFallbacks`).
- **Headless error table (NFR-009):** `403 account_unavailable`, returned when
  the step that would complete sign-in finds the account suspended, locked or
  deactivated meanwhile, was missing from the Errors table of
  [headless-authentication.md](docs/protocols/headless-authentication.md#errors);
  `TestHeadlessErrorCodesDocumented` now keeps the table and the transaction
  API's problem codes in step.
- **Key provider outage answered `500 server_error` (TEST-059, SEC-009):**
  when the active signing key existed but could not be unwrapped (keyring,
  KMS or HSM unavailable), token requests failed with `500 server_error`;
  they now answer `503 temporarily_unavailable` like a missing active key
  (`token.ErrKeyUnavailable` is an `ErrNoActiveKey`), still without consuming
  the code or refresh token presented, and an ID token that cannot be signed
  answers the same. The signing-failure metric keeps the reason
  `key_unavailable` (`TestSigningKeyOutageDuringIssuance`).
- **Restore reconciliation could apply nothing on a retried transaction
  (TEST-060):** the revocation log was read inside the database transaction,
  so a retry after a deadlock found the reader drained and committed without
  the records. The log is now read (and validated: a malformed line aborts
  without effect) before the transaction. A `password_changed` record whose
  restore already holds the current password (an overlapping log) no longer
  revokes the user's sessions.
- **Project-scoped role assignments were never evaluated (AZ-002):** roles
  assigned with `scope.type: project` were stored but ignored: token scope
  policy and the decision API evaluated only realm and organization
  assignments, the decision request could not name a project, and the
  permission views were realm or organization only. Project assignments now
  count, for their own project only, wherever a resource belongs to a
  project: scopes with `required_permissions` of a resource with a
  `project_id` (every grant type, personal tokens and API keys), the
  decision API with the new optional `resource.project_id` (on `/check`,
  `/check-batch` and simulation; validated: an unknown project denies with
  `UNKNOWN_PROJECT`, one that does not belong to the decision's organization,
  owned or shared through an active project grant, with
  `PROJECT_ORGANIZATION_MISMATCH`), and `GET /me/permissions` and
  `GET /subjects/{subject}/permissions` with `?project_id=`. They apply only
  while the project is active and never at organization or realm level, for
  another project, or in an organization the project does not belong to;
  explicit denies still override them, and decision cache keys include the
  project (`TestProjectScopedRoles`).
- **Composite roles across projects and beyond the evaluation bound
  (AZ-011):** a project role could compose another project's role, carrying
  that project's grants; this is now refused with `422`. A composite role
  whose composites exceed `limits.max_role_expansion` failed with `500`, and
  the creation check bounded only path depth while enumerating every path,
  so a diamond-shaped composition was expensive to check; creation now
  checks cycles and the bound (the role and every role it reaches) in one
  linear walk and refuses with `422`. Roles that together exceed the bound
  for a subject still fail closed at evaluation (`EVALUATION_ERROR`)
  (`TestCompositeRoleBounds`, `TestCompositeRoleGraphChecks`).
- **Backend enforcement of new routes (AZ-008):** nothing guaranteed that a
  route registered through the authenticating wrappers (`a.admin`,
  `a.tenant`, `a.self`, `a.protected`) checked a permission. A contract test
  now requires every such route to reach a permission check or a service
  operation that authorizes the caller, with an explicit, reasoned list of
  self-service and addressee-only routes
  (`TestAuthenticatedRoutesCheckPermissions`).
- **API key and personal token last use (MCH-005, MCH-007):** introspection
  never recorded `last_used_at` for API keys and personal access tokens: the
  update compared the column with an untyped `$2 - interval '1 minute'`, which
  PostgreSQL resolves as interval arithmetic, so the statement failed and its
  error was ignored. Every credential therefore looked never used in
  `GET /api-keys`, `GET /me/personal-tokens` and the credential inventory,
  whose `unused` flag fired for keys in daily use. The parameter is now typed
  and the last use is recorded at most once a minute (`TestScopedAPIKeys`).
- **`identity-cli assign-role` for realm roles (SDK-003):** without `--org`
  the command sent a realm scope naming the realm by its name (`main`), which
  the API refuses because a realm scope carries the realm's ID; realm roles
  could not be assigned with the CLI. It now sends no scope, and the server
  applies the realm of the request (`TestAdminCommandsCallAdministrationAPI`,
  `TestAdminSDKTypedOperations`).
- **ZITADEL adapter capabilities (SES-022, MIG-010):** the ZITADEL entry of
  `GET /migration-adapters` and `identity-cli migrate-from --list` did not
  list sessions among what is unsupported, although no adapter migrates
  sessions and the conversion report already counted them as unsupported;
  it now lists "sessions and tokens (users sign in again)", and every
  registered adapter is checked for it
  (`TestEveryAdapterReportsSessionsUnsupported`).
- **Hook diagnostics for answers outside the contract (EXT-011, EXT-017,
  TEST-053):** an `authorization.decision` hook answering with more than
  five obligations was denied (`HOOK_INVALID_RESPONSE`) but recorded as a
  successful call, so its diagnostics stayed `healthy`; it is now a failure
  with category `malformed_response`, and a denial carrying more than five
  obligations is `HOOK_INVALID_RESPONSE` as well. A `token.claims` answer
  setting a protected claim or exceeding 20 claims or 4 KiB is now
  categorized `malformed_response` instead of `error`, and a transport
  timeout that is not a context deadline is categorized `timeout`
  (`TestHookBounds`, `TestClaimsAnswerBounds`, `TestErrorCategories`).
- **Per-organization job cap under concurrency (DEP-015, TEN-018):**
  `workers.max_jobs_per_organization` was checked inside each claim, so two
  workers (or runners of one worker) claiming at the same moment each counted
  the other's job as not yet running and together exceeded the cap. Claims
  are now serialized by a database advisory lock while the cap is on
  (`TestWorkerPoolBoundsAndTenantShares`).
- **Duplicate notification delivery under concurrent workers (DEP-011):**
  the notification claim checked state and lease only in the snapshot it
  started with, so a worker could lock a message another worker had just
  claimed (or already delivered) and send it again. The claim now re-checks
  state, due time and lease on the row version it locks
  (`TestReplicasShareOneTimeState`, `TestNotificationLeases`).
- **Duplicate webhook and outbound provisioning deliveries, early workflow
  steps under concurrent workers (DEP-011):** the webhook and outbound SCIM
  delivery claims had the same flaw as the notification claim: state, due
  time and lease were checked only in the claim's starting snapshot, so two
  workers could claim the same delivery and send it twice (8 of 90 webhook
  events and 2 of 42 SCIM creations went out twice in a two-process burst).
  The workflow-run claim re-checked only the lease, so a run another worker
  had advanced and parked for later (a retry backoff, a wait) or finished
  in the meantime was claimed again and its next step (an endpoint call)
  ran early. All three claims now re-check state, due time and lease on the
  row version they lock or update. The other claim loops (outbox dispatch,
  back-channel logout and SSF push deliveries, jobs, workflow schedules and
  the expiry sweeps) already checked their conditions at the lock and are
  unchanged (`TestWebhookDeliveryClaimedOnce`,
  `TestOutboundDeliveryClaimedOnce`, `TestWorkflowRunClaimRechecksState`).
- **Default scopes were only a declaration (APP-007):** a scope's
  `is_default` was stored and returned but never used, so a request naming a
  resource without any of its scopes (`scope=openid&resource=...`, or a
  client-credentials request without `scope`) got an access token with no
  scopes. Such a request is now made with the resource's default scopes, as
  far as the client's resource grant lists them, and they pass every check a
  requested scope passes (consent, step-up, the organization's scope ceiling,
  `required_permissions`); a default the client, user or organization does not
  qualify for is left out without failing the request. Requests that name a
  scope of the resource are unchanged, OIDC scopes are never defaulted, a
  refresh never adds defaults declared after the authorization, and token
  exchange keeps the exchange ceiling as its default
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#scopes-and-resources),
  `TestDefaultScopeGrants`).
- **Support bundle (OPS-010):** `storage.migration_database_url` was copied
  into the bundle's configuration (and into `identity-cli config-diff`
  output) unredacted, including a literal password; it is now redacted like
  `storage.database_url`. The bundle also reports the release it was built
  from (`version`): `-X main.version` in the image, release and bundle builds
  had no variable to set (`TestSupportBundleIsSanitized`,
  `TestRedactedHidesSecretValues`).
- **Custom HTML notification templates (MSG-004):** `POST /templates`
  checked only which variables a template names, so an HTML body could put
  a client-controlled value (the sign-in device, an inviter's display name)
  in a link (`<a href="{{.device}}">`), build a URL around a code, place
  values in scripts, styles or event handlers, or be HTML that
  `html/template` cannot render, which made every delivery of that event
  fail. The HTML body must now render, a URL attribute may hold only exactly
  `{{.link}}` (built by the server), and values in scripts, styles, `on*`
  attributes, `<meta>` elements and tag or attribute names are refused
  (`422`). Templates saved earlier are not re-validated
  (`TestValidateTemplate`, `TestCustomTemplateSafety`).
- **Certificate sign-in attempt budget (PROV-016):** before `identify` the
  step's per-subject budget was keyed by an empty account, so every
  certificate attempt of a realm shared one budget (one client could lock
  everyone out of certificate sign-in). It is now keyed by the certificate's
  thumbprint and the client's /24 or /48 network until the account is known,
  and by the account after `identify` (`TestCertificateSignIn`,
  `TestCertificateBudgetSubject`).
- **mTLS trust anchors and certificate checks (MCH-014, PROV-016):** with
  `revocation: crl`, every certificate of the chain below the anchor is
  checked against its issuer's CRL (a revoked intermediate now refuses its
  leaves; a leaf issued by an intermediate is no longer looked up by serial
  in the anchor's list, and is refused as `REVOCATION_UNAVAILABLE` because
  the anchor holds no CRL for it). A CRL without `nextUpdate`, which made
  every certificate of the anchor fail, is refused at upload (`422`). A CRL
  update needs a greater CRL number (or, without numbers, a later
  `thisUpdate`) or the identical list: an equal number with other content is
  `422`, and the comparison runs on the locked anchor. A removed anchor can
  be trusted again (a new anchor; migration `0086` makes only active anchors
  unique). A binding created from `certificate_pem` is verified against the
  anchor named in `anchor_id`, not any user anchor (`TestCertificateSignIn`,
  `internal/certauth/certauth_test.go`).
- **HOTP (MFA-013):** a recovery-restricted session may enroll and activate
  HOTP (`/me/hotp/enroll`, `/me/hotp/activate` are among its permitted
  writes), and activation restores the session and the account as TOTP's
  does. `POST /me/hotp/resync` needs a session that completed MFA
  (`403 mfa_required`), as regenerating recovery codes does. A TOTP or HOTP
  the realm's `mfa.allowed_factors` does not allow satisfies nothing, and no
  longer counts as an enrolled factor for adding a factor (MFA-006),
  changing the password (CRED-006) or the last-factor guard (`TestHOTP`,
  `TestCodeFactorsFollowAllowedFactors`).
- **Relationship sharing and listing (AZ-023, AZ-027):** an expired share was
  never stored as `expired` (the update was rolled back with the refused
  acceptance) and kept blocking a new offer. The refused acceptance now
  stores it in its own transaction, `lifecycle.expiry` stores every pending
  or accepted share past `expires_at` as `expired` (removing an accepted
  share's tuple; audit `authorization.share.expired`), listings show and
  filter such shares as `expired` at once, and an expired share no longer
  counts as a duplicate. `list-objects` clamps a `limit` above 500 to 500
  (it was reset to 100) and sets `truncated` when an object's own evaluation
  reaches a bound and it is left out (`TestRelationshipAuthorization`).
- **Elevation expiry evidence (AZ-024):** the expiry sweep now records the
  documented `authorization.elevation.expired` event (actor `system`) when
  an active elevation ends at its deadline (`TestJustInTimeElevation`).
- **Ownership transfer of extensions (DOM-009, APP-014, MCH-007):**
  `POST /users/{user}/ownership-transfer` also moves the pre-action hooks,
  webhook subscriptions and authorization policies the account owns
  (plugin-managed ones keep their plugin), and needs their write permissions
  too. New `POST /hooks/{id}/ownership-transfer`,
  `POST /webhooks/{id}/ownership-transfer` and
  `POST /policies/{policy}/ownership-transfer` (`{"owner_user_id"}`,
  optional `If-Match`) change one object's owner, also for objects without
  one (`TestOwnershipTransferCoversExtensions`).
- **Account deletion coverage (PRV-005):** every message about an account
  now records it (`notification_jobs.user_id`: password-reset, verification
  and magic-link messages, security notices and any message to one of the
  account's addresses), so deletion purges them; messages queued earlier are
  found through their user or challenge reference. Deletion also deletes the
  account's certificate bindings and the relationship tuples naming it,
  revokes the shares to or from it (removing the tuple of an accepted share
  it made) and clears their messages, and revokes its elevation
  eligibilities, cancels pending requests and ends an active elevation
  (`TestAccountDeletionCoverage`).
- **Privileged-role checks agree (MIG-005):** the migration reconciliation's
  SQL now counts a composition of more than 64 roles as privileged, as
  `IsPrivilegedRole` does (which now counts only roles that exist)
  (`TestPrivilegedRoleCapConsistent`).
- **Configuration reconcile of a client whose type differs (SDK-012):**
  under `mode=reconcile` such a client, when it also differs in a
  reconcilable field, is a plan error ("client_type is A and cannot change
  to B") reported by validation and refused up front, instead of being
  planned as an update that failed with `422` and rolled the import back
  (`TestConfigReconcileClientType`).
- Introspection reported every token as `token_type: Bearer`; a DPoP-bound
  token is now `DPoP` (RFC 9449 section 6.2), as in the token response
  (`TestDPoPBoundTokens`).
- **Token type of sender-constrained tokens (TOK-019, RFC 8705, RFC 9449):**
  certificate-bound access tokens (`cnf.x5t#S256`) are reported as
  `token_type: Bearer`, no longer `DPoP`; only DPoP-bound tokens are `DPoP`.
  Token exchange now reports `DPoP` for a DPoP-bound result instead of always
  `Bearer` (`TestMutualTLS`, `TestDPoPBoundTokens`).
- **Encrypted responses (TOK-020, OIDC-013):** when a client registered
  response encryption but has no key that can receive it (or the realm has
  no active signing key), the token request is rolled back: the
  authorization code, device code or refresh token is no longer consumed,
  so a retry gets the same `unauthorized_client` (or
  `temporarily_unavailable`) answer instead of being treated as code replay
  that revoked the grant, and the code can be redeemed once a key is
  registered. Encrypt-only UserInfo responses no longer carry an empty `cty`
  header; only nested JWTs name `cty: JWT` (`TestEncryptedResponses`).
- **Workload federation (MCH-011, ADV-004):** an assertion's `jti` is spent
  only by a request that is otherwise accepted, inside the issuing
  transaction (still exclusive: of two concurrent uses one gets a token), so
  a request refused for its resource, organization or scope no longer burns
  the assertion. The worker's retention task deletes expired
  `workload_assertion_jtis` records (step `workload_assertion_jtis`). The
  configuration-document schema now accepts `token_endpoint_auth_method:
  none` for machine clients whose only grant is `jwt-bearer`, as the server
  and the configuration export do (`TestWorkloadFederation`,
  `TestConfigDocumentClientAuthMethods`).
- **Agents (MCH-017):** introspection of an agent's API keys returns
  `agent: true`, as for its access tokens. Organization templates no longer
  grant an agent a privileged role (or any subject a role that requires
  approval) without the second administrator direct assignment needs: such
  a grant is a plan conflict and the application fails with `409` until the
  grant is approved through `/role-assignments` (`TestAgentPrincipals`).
- **Dynamic client registration (APP-016, APP-017):** a registrant's `PUT` is
  one transaction, so a refused `rotate_secret` (`409`) no longer replaces
  the registration access token and leaves the registrant without management
  access; `limits.client_secrets_max` counts only secrets that have not
  expired (for administrator rotations too). A registrant's `PUT` keeps the
  settings an administrator controls (token policy, claim mappings,
  back-channel logout URI, pairwise subject type and sector, consent and
  offline-access settings, origins and the like) instead of resetting them.
  Registrant-supplied `contacts` no longer receive credential-expiry mail.
  `POST /clients/{client}/reactivate` (and the emergency control's `enable`)
  refuses a client whose registration is pending approval (`409`); approval
  and the client's activation are one transaction. Expired initial access
  tokens are listed with `state: expired` (`TestDynamicClientRegistration`).
- **FAPI 2.0 (ADV-001):** an organization switch (`POST
  /me/organization-grants`) no longer issues authorization codes outside PAR
  (and without the 60-second lifetime) to `fapi2` clients: clients that must
  use pushed authorization requests (`fapi2`, `high_assurance`,
  `token_policy.require_par`) get `403` and switch with a new pushed request
  naming the organization (`TestFAPI2Profile`).
- **Configuration and API contract:** `identity-cli config-diff` marks
  `server.mtls_listen`, `server.mtls_origin` and `server.client_cert_header`
  as security boundaries (`TestDiffMutualTLSBoundaries`). The OpenAPI
  `OpenIDConfiguration` schema lists every member discovery emits
  (`mtls_endpoint_aliases`, `frontchannel_logout_session_supported`, the
  JARM, ID-token and UserInfo signing and encryption algorithm lists;
  `TestDiscoveryDocumented`); the authentication flow rule `methods` accept
  `certificate`; HOTP removal documents `409 last_sign_in_method`; the
  descriptions of deletion status, the organization deletion preview (legal
  holds on members, `owned_clients`), identity-provider replacement,
  `Idempotency-Key`, custom-domain verification conflicts, the single-use
  upstream-logout return state, dynamic registration updates, client
  reactivation, organization template conflicts, the organization switch,
  the token response's `token_type` and the introspection `agent` member
  match the server.
- **Migration adapters (MIG-018, MIG-012):** `identity-cli migrate-from
  --apply` always ends with `GET /user-imports/reconciliation` carrying the
  converted export's `expected_users`, `expected_memberships`,
  `expected_password_verifiers` and `expected_totp_factors` (records the
  server skips as deleted left out), also after a run that stopped part-way
  or had no records; a mismatch (`import not reconciled with the converted
  export: …`) or a failed reconciliation request makes the command exit
  non-zero after writing the report (`import.expected`,
  `import.reconciliation`). Before, it reconciled only when records were
  submitted, without expected counts (always `reconciled: true`), and
  ignored failures. `--batch-size` outside 1–1000 is refused instead of
  silently becoming 500. The ZITADEL export command reported by
  `GET /migration-adapters` and `--list` includes the `"timeout"` member of
  ZITADEL's export request. `--source-version` (and `source_version` of
  `POST /migration-plans`) accepts a leading part of the version the export
  states, such as the major version (`26` for `26.8.0`), and the refusal
  names what is expected; unsupported majors are still refused
  (`TestApplyReconciles`, `TestSourceVersionForms`,
  `TestMigrateFromApplyReconciles`, `TestMigrateFromSuperTokens`;
  [migration-adapters.md](docs/operations/migration-adapters.md#apply-idempotency-and-blocking)).
- **Plugins (EXT-014):** a workflow a new plugin version drops (or an
  uninstall keeps as evidence) is retired and no longer re-activated by the
  next installation or enable; hooks and subscriptions switched off by an
  emergency control stay off through plugin installs, rollbacks and enables
  (migration 0084); a hook the package declares `disabled` stays disabled;
  enabling a plugin re-checks its signature, publisher key, contracts and the
  administrator's permissions; installing a version below an enabled
  dependent's `min_version` is refused (`409`); `webhook.created` and
  `workflow.revision.staged` carry `plugin_id` for plugin parts.
- **Workflows (EXT-015/016):** retry backoff never exceeds six hours
  (jitter included); an `assign_role` step's `reason` is recorded on the
  assignment; a manual run's `Idempotency-Key` is stored only as a digest;
  the `call_webhook` body is registered as its own contract
  (`workflow_step_call` v1); worker processes use a unique lease owner per
  process (host name, process ID and a random suffix), so two workers on one
  host never share leases.
- **Partner project access (TEN-020):** project grants end at
  `valid_until` with every role assigned through them
  (`project.grant.expired`); revoking or expiring a grant moves the holders'
  authorization revision.
- **Shared signals (AUD-016, ADV-007):** a receiver echoing an
  administrator-set `subject_scope: all` on `PUT`/`PATCH` is accepted;
  delivered pushes are no longer relabelled `expired` by retention (and are
  deleted with other finished events); while the realm's transmitter is off,
  queued pushes wait without using up attempts; the push endpoint, the
  check-session origin check and the registry token endpoint are rate
  limited (the registry also throttles repeated failed sign-ins per address);
  account erasure removes stream subjects and queued events about the account
  and redacts the account's federation transfer entries, whose detail is
  pruned 180 days after a transfer finishes.

- Refresh rotation keeps each family's own idle window, so offline and
  remember-me families no longer expire after `sessions.idle_timeout` of
  inactivity (migration `0009`;
  [ADR 0011](docs/architecture-decisions/0011-refresh-token-families.md)).
- Audit retention prunes only sealed batches and records them in
  `audit_prunes`, so verification no longer reports pruned batches as digest
  mismatches (migration `0011`, `TestAuditSignaturesAndRetention`; retention
  now removes individual expired events, see **Changed**).
- Restore reconciliation now also re-applies password changes, client-secret
  and API-key/personal-token revocations, and membership removal, suspension and
  expiry ([backup-restore.md](docs/operations/backup-restore.md)).
- `proudauth_outbox_oldest_pending_seconds`, `proudauth_clock_skew_milliseconds`
  and `proudauth_database_up` are refreshed on every scrape.
- Support impersonation: disabling support access (deployment, realm, resource,
  organization or customer opt-out) ends live grants on their next
  introspection; denied requests and rejected handoffs are audited after the
  failed transaction rolls back; the decision API denies the same protected
  actions as `SupportGuard` (payments, refunds, ownership transfer, secret
  reads, deletes) in every support mode
  ([impersonation threat model](docs/threat-models/impersonation.md)).
- Two-party approval for roles marked `requires_approval` uses the
  authenticated approver instead of a caller-asserted `approver_id` (AZ-018).
- Credential expiry alerts are sent exactly once per credential. The hourly
  `alerts.credentials_expiring` task used to repeat them; each alert is now
  claimed by inserting a `credential_expiry_alerts` row in the same transaction
  that enqueues its notifications, so concurrent workers and retried runs cannot
  notify twice, and a failed enqueue releases the claim. The migration backfills
  claims for alerts already sent (migration `0023`, MCH-009, TOK-021, APP-014,
  `TestCredentialExpiryAlerts`).
- Browser login UIs can register: the `pa_tx` cookie is scoped to the
  transaction's own path (AUT-016), so it never reached
  `POST /registrations`. Registration now also has the transaction-scoped route
  `POST /api/v1/realms/{realm}/auth/transactions/{id}/registration` (same body
  without `transaction_id`) (`TestBrowserRegistration`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#registration),
  [ADR 0017](docs/architecture-decisions/0017-external-login-ui.md)).
- Account deletion also deletes the user's pairwise subject mappings
  (`pairwise_subjects`) and notification preferences. The `users` row is kept as
  a tombstone, so these rows never cascaded (PRV-005, `TestPairwiseSubjects`;
  [data-inventory.md](docs/operations/data-inventory.md#account-deletion)).
- Webhook subscriptions created or updated without
  `allow_private_network: true` are refused private destinations at registration
  (`422` on `destination_url`) instead of being accepted and then failing every
  delivery with `egress_denied` (EXT-007, `TestWebhooksAndBackchannelLogout`).
- `PATCH /webhooks/{id}` is a partial update (EXT-001): members the body omits
  keep their values (an update no longer resets `allow_private_network` to
  `false` or `payload_form` to `minimal`), a change of `state` alone does not
  re-resolve the destination, so pausing works while the receiver's DNS fails,
  and `organization_id` is no longer accepted in the body (`400`)
  ([webhooks.md](docs/integrations/webhooks.md#subscribing)).
- Scheduled assisted recovery (MFA-009): when a recovery is due, the worker
  re-checks that the account still exists and that the requester still has the
  authority the request route requires (`support.recovery.assist` or
  `realm.users.credentials.manage`, and the latter for `reset_mfa`); otherwise
  the request is cancelled with reason code `account_unavailable` or
  `requester_no_longer_authorized`. Requests cancelled this way are not counted
  as executed. Each due recovery runs in its own transaction, so one failure no
  longer holds up the rest of the batch ([account-recovery.md](docs/operations/account-recovery.md#cooling-off-and-second-operator-approval-mfa-009)).
- Account deletion ends pending work about the account: scheduled assisted
  recoveries and pending account merges are cancelled, and a pending
  registration approval is closed as `expired` (PRV-005,
  [data-inventory.md](docs/operations/data-inventory.md#account-deletion)).
- Account merges (USR-011): proposals past their 7 days are marked `expired` by
  the hourly worker task `account_merges.expiry` and when a new proposal for the
  same source account is made, so a lapsed proposal no longer blocks a new one.
  An administrator can withdraw a pending merge with
  `POST /account-merges/{id}/cancel` (`realm.users.write`; audit
  `user.merge.cancelled`) and either owner can refuse it with
  `POST /me/account-merges/{id}/decline` (audit `user.merge.declined`). Guest
  accounts cannot be merged, and execution re-checks that both accounts are still
  active, registered (not guests) and not protected (`TestAccountMerge`).
- `delivery.email.allowed_sender_domains` entries are trimmed, lowercased and
  stripped of a trailing dot before they are compared with a realm sender
  address's domain, so `Example.COM` in the configuration matches (MSG-005).
- Credential-expiry notices name the realm by its display name (or its name)
  instead of its internal ID, and the `alerts.credentials_expiring` task counts
  only notices whose transaction committed (TOK-021, MCH-009).
- Configuration import (APP-019): merging a document's `policy` no longer
  modifies the server's cached copy of the realm policy; the merge works on
  copies. Lists in the document replace the current list whole, so list elements
  (for example `profile.attributes`) no longer inherit members from the elements
  they replace, and a change that only touches a list is reported as an
  `update` of the realm policy instead of `unchanged`
  ([exit-and-export.md](docs/operations/exit-and-export.md#import-into-proudauth)).
- Configuration export (APP-019) now writes each scope's
  `required_permissions`, `step_up_acr` and `max_auth_age_seconds` and each
  resource's `signing_algorithm`, so importing an export no longer drops them;
  clients' new `consent_terms_version` is exported as well.
- Emergency controls (SEC-020): every audit event recorded while a control runs,
  including the `client.*`, `organization.*` and `service_principal.*` state
  changes, is filed in the `emergency` category with the operator's reason (when
  the event has no reason of its own), so it is kept past
  `privacy.audit_retention` and raises `emergency_action`. Previously only the
  grant-type, identity-provider, hook and webhook controls were, and the
  service-principal control recorded no reason (`TestEmergencyControls`;
  [incidents.md](docs/operations/incidents.md#emergency-controls-sec-020)).
- Maintenance mode `restricted` (OPS-015) now lets `POST` requests whose path
  ends in `/revoke-sessions`, `/suspend` or `/lock` through (for example
  `POST /users/{user}/revoke-sessions`, user, client and organization
  suspension, and user locking), so access can still be taken away while
  configuration is frozen
  ([incidents.md](docs/operations/incidents.md#maintenance-mode-ops-015)).
- `identity-cli maintenance` and `identity-cli debug-window` write the change and
  its audit event (`operations.maintenance.changed`,
  `operations.debug_window.opened` / `.closed`) in one transaction, so neither
  can be recorded without the other; `operations.maintenance.changed` also
  records the public message (`public_message`).
- `identity-cli config-diff` (DEP-020) now also marks `federation.ca_file`,
  `federation.egress_allowlist`, `delivery.egress_allowlist`,
  `delivery.sms.webhook_secret` and `observability.metrics_enabled` as moving a
  security boundary ([configuration.md](docs/operations/configuration.md#reviewing-a-change)).
- `PATCH /webhooks/{id}` (EXT-001, API-010): the version check is part of the
  `UPDATE`, so of two concurrent updates of one subscription the second fails
  with `412 precondition_failed` instead of overwriting the first, with or
  without `If-Match` ([webhooks.md](docs/integrations/webhooks.md#subscribing)).
- External IDs (USR-017): an ID still mapped to a deleted account can be
  assigned to another account (the old mapping is removed), and an executed
  account merge moves the merged-away account's external IDs to the surviving
  account. When both accounts had an ID in the same source system, the
  survivor keeps both (the source system held two records for one person) and
  either resolves to it; setting a new ID in that source replaces both. No
  regression test covers these cases yet
  ([exit-and-export.md](docs/operations/exit-and-export.md#import-into-proudauth)).
- The `lifecycle.users` worker task (USR-015) continues with the other realms
  when one realm's run fails and reports the first error afterwards.
- `api/schemas/config.schema.json` now documents every deployment configuration
  key, and the contract test `TestConfigSchemaMatchesStructs`
  (`tests/contract/config_schema_test.go`) fails when a key the server accepts is
  missing from it or a documented key is rejected (DEP-020).
- Realm policy `tokens.impersonation_access_token_ttl_seconds` was accepted but
  not applied. It now bounds support grants, together with
  `tokens.access_token_ttl_seconds`, `impersonation.max_ttl` and the realm's
  `impersonation.max_ttl_seconds` (the smallest wins); support tokens live as
  long as their grant (TOK-018; [tokens.md](docs/protocols/tokens.md#access-token-lifetime)).
  No regression test covers it yet.
- Consent pre-authorization (APP-013): when a pre-authorization covers a request
  but the user's own live consent no longer does (other terms version or fewer
  scopes), the stale consent is revoked and replaced by a `preauthorized`
  consent, so revoking the pre-authorization also ends the new grant. A live
  consent that still covers the request stays the basis. No regression test
  covers the stale-consent case yet.
- Decision audit (AZ-020): refusals on organization routes, including those
  concealed as `404` (marked `metadata.concealed: true`), and refusals decided
  inside handlers are recorded as `authorization.denied`, once per request,
  like refusals of realm administration routes. `TestDecisionAuditSampling`
  covers the realm administration case only
  ([ADR 0013](docs/architecture-decisions/0013-authorization-model.md#update-2026-10)).
- Localized notices (MSG-006): join-request notices to reviewers and assignees
  and the decision notice to the requester are written in each recipient's
  locale and time zone, and the time in the scheduled assisted-recovery notice
  is rendered in the account owner's time zone (UTC when unknown).
- `audit_events.recorded_at` is now the database's time (`now()` in the
  recording transaction) instead of the writing process's clock, so a server
  whose clock is skewed no longer shifts when its events are sealed (sealing
  takes events recorded more than 2 seconds ago, by the database clock) or the
  reported `audit_sealing` backlog (AUD-014).
- Audit archive after a database restore (AUD-008): `audit.archive` no longer
  stops at the first new batch whose sequence number the archive already holds
  with other content; it continues in a fork directory and records
  `audit.archive.forked` (migration `0039`). The manual step of moving archived
  files aside after a restore is gone
  ([backup-restore.md](docs/operations/backup-restore.md#restore-procedure)).
- `identity-cli verify-audit-archive` (AUD-008) now reports missing sequence
  numbers between files, a first batch that does not start the chain, a file
  with fewer events than its header records unless it is one of the leading
  batches pruned before the archive existed (marked with `archived_events`),
  and a fork that does not link to the main archive; it also reports
  `first_sequence`, `last_sequence` and `forks`. Previously every short file
  counted as pruned and the first file's link was not checked (`TestAuditArchive`;
  [incidents.md](docs/operations/incidents.md#audit-archive-aud-008)).
- Dynamic groups (TEN-014): each member a rule adds or removes is now audited
  (`group.member.added` / `.removed`, `source: "dynamic"`), and so is each
  manual member removed when a rule is set (`source: "dynamic_rule_set"`).
- Organization deletion (TEN-011) releases the organization's aliases when it
  completes, like its slug, so other organizations can take those names
  ([identifiers.md](docs/protocols/identifiers.md#organization-slugs-and-domains)).
- An organization's own SMTP server (TEN-022) is reached through each resolved
  address in turn, not only the first one.
- The help text of `proudauth_jobs_failed_total` now says that it counts
  dead-lettered jobs and is updated by `identity-worker`.
- Transaction retries no longer repeat pre-action hook calls (DB-014): the
  token endpoint and authentication steps run their transaction once
  (`storage.NoRetry`) when the realm has an active hook, instead of retrying
  it on a deadlock or serialization failure, so claims, registration-eligibility
  and profile hooks are never called twice for one request; other transactions
  are still retried up to 4 attempts, and tokens are returned only after their
  transaction commits (`TestTransactionRetries`;
  [ADR 0004](docs/architecture-decisions/0004-persistence.md)).
- Imported audit history (MIG-016, PRV-004): records imported for an account
  that is already deleted are stored without their source-supplied details;
  restore reconciliation clears those details again for accounts deleted
  after the backup; the personal data export includes the imported records
  about the user (`imported_history`, at most 500); and imported metadata
  passes through audit redaction (`TestMigrationPlanningAndReconciliation`
  covers the import-time redaction; the restore and export paths have no
  regression test yet).
- Transaction retries (DB-014): answering a flow challenge with a provider
  response runs once (no retry), and device-code and token-exchange
  transactions reset their result on each attempt. No regression test covers
  the reset yet.
- Privileged-role detection for `role.assigned` metadata and the
  `privileged_grant` alert follows composed roles at any depth; the
  reconciliation report still checks one level.
- Organization templates (TEN-017): a service principal is found by its
  owning organization after a slug rename instead of being created again; an
  existing webhook subscription with another destination or event types is
  reported as a conflict instead of unchanged; `service_principal.created`
  carries the owning organization. No regression test covers these yet.
- The error for an unknown `privacy.audit_retention_by_category` name no
  longer lists `emergency` as allowed.
- `api/schemas/user-import.schema.json` documents `format`,
  `verification_reason` and `import_totp`, and the `source_system` pattern;
  the OpenAPI document marks `If-Match` required on `PUT /hooks/{id}` and
  `PUT /organizations/{org}/identity-providers/{id}`; the SDK fixture test
  rejects unknown expected categories.

- Failing and dead-lettered jobs are recorded again: the update that stores
  the failure used inconsistent parameter types and failed in SQL, so such
  jobs could not reach `failed` or `dead_letter`.
- Polling `GET /auth/transactions/{id}` stores a re-evaluated flow decision,
  so risk hooks are no longer called on every poll; a challenge answered in
  the transaction stays answered when the organization changes (AUT-012).
- The `503` for an unreachable challenge provider suggests the emailed code
  only when that option is offered to the account (SEC-014).
- Registering a passkey during sign-in also completes the `configure_totp`
  required action (MFA-003).
- `login_hint`, `ui_locales` and the user agent are shortened on UTF-8
  boundaries (invalid sequences removed) before they are stored, so such
  input no longer makes a transaction start fail with `500`.
- Audit evidence (MFA-012, AZ-020, IMP-006, IMP-024, INV-016): a failed
  self-service TOTP activation proof is committed as `mfa.totp.proof_failed`;
  passkey enrollment start is audited as `mfa.webauthn.enrollment_started`
  (`ceremony_id`, `transaction_id`); `authorization.decision` denials carry
  the subject, the support operator (`metadata.actor`) and
  `impersonation_grant_id` once the subject token is resolved;
  `support.token.rejected` names the operator as actor and the customer as
  subject, with the support grant, organization and route
  (`TestSupportImpersonation`); the audit filter `impersonation_grant_id`
  also returns the request-phase events, and `support.impersonation.started`
  carries `request_id` (`TestCustomerApprovedSupportAccess`);
  `invitation.created` names the invited account as subject (for `user_id`
  invitations, or the account holding the verified address) and carries
  `recipient_digest` beside the masked address: an HMAC of the canonical
  address under the deployment's lookup key, with
  `recipient_digest_key_version` (INV-016; see **Security fixes**;
  [data-inventory.md](docs/operations/data-inventory.md#evidence-delivery-and-jobs)).
- The Node.js administration client's `inviteBatch` keeps its generated
  `Idempotency-Key` when the caller passes `idempotencyKey: undefined`.
- `identity-cli` warns on standard error when credentials refreshed during a
  command cannot be saved, instead of ignoring the error; the next command
  may need `identity-cli login` because the stored refresh token can already
  be spent.
- The release workflow writes `SHA256SUMS` once, after the image digest and
  image SBOM exist, and attests the release files only then; it used to
  attest `SHA256SUMS` and append the image entries afterwards, so the
  published file did not match its attestation.
- `.dockerignore` now excludes the secret-bearing files `.gitignore` lists
  (benchmark seeds, `realm-config.json`, `secrets-out*`, `*.secrets.json`,
  `client-secrets.json`, `support-bundle.json`, `revocation-log*`,
  `deploy/compose/secrets`) in every directory, plus private keys (`*.pem`,
  `*.key`, `*.p12`, `*.pfx`), `.env*`, credentials files and build output,
  so `COPY . .` cannot place them in the build stage or its cache.
- UserInfo now enforces DPoP-bound tokens (the `DPoP` scheme and a matching
  proof), and device-code and token-exchange grants bind their tokens to the
  request's DPoP proof or client certificate (TOK-019).
- Support bundles and `config-diff` redact literal challenge-provider secrets
  (and policy engine tokens) (`TestRedactedHidesProviderSecrets`).
- Registering keys (`POST /clients/{client}/credentials` with `jwks`) for an
  unknown client answers `404`.
- Session-event stream: the `410 cursor_expired` problem explains how to
  resynchronize (read the retained history from the beginning, without a
  cursor); the Go and Node.js bounded-state helpers read the user from
  `data.subject_id` (user subjects only) for `security.refresh_reuse_detected`
  (revoking the user) and `authorization.role.unassigned` (revoking the user's
  membership in that organization), and Go `Sync` clamps `wait` to 25 s.
- **Review boundaries (GOV-004):** `.github/CODEOWNERS` did not require a
  security reviewer for client authentication and redirect URI validation
  (`internal/application/`), API bearer authentication
  (`internal/httpapi/auth.go`), client certificates behind a proxy
  (`internal/httpapi/clientcert.go`), or the release inputs the release
  workflow runs or builds from (`Makefile` and `scripts/offline-bundle.sh`
  through `make bundle`, and `.dockerignore`); CONTRIBUTING.md only asked
  for one. They are now security-reviewer paths
  (`TestCodeOwnersReviewBoundaries`).

### Security fixes

These were found and fixed before any version was tagged; no released version is
affected (only untagged development commits).

- **Offline-grant access tokens stayed active after "log out everywhere"
  (SES-005):** the revocation revoked every grant and wrote a user-level
  `token_revocations` record that nothing read, so an offline grant's JWT
  access tokens (which carry no `sid`) and its UserInfo tokens stayed active
  at introspection and UserInfo until they expired (about 5 minutes).
  Introspection (JWT and opaque) and UserInfo now treat a user token without a
  session as inactive when an account-wide revocation took effect at or after
  its issuance (one indexed lookup); session-bound tokens, the only user tokens
  the IdP's own APIs accept, are covered exactly by the session check.
  Revocations that keep offline grants (account merge survivor, shared signals
  without offline scope) no longer write the user-level record
  (`TestLogoutEverywhereEndsOfflineTokens`;
  [revocation-exposure.md](docs/operations/revocation-exposure.md)).

- **A sign-in already at the upstream finished through a disabled
  connection (SEC-020, FED-001, OPS-016):** disabling an identity provider
  (the emergency control, or `"state": "disabled"`) refused new sign-ins and
  links, but a round trip started before it could still come back through
  the callback (OIDC) or the ACS (SAML) within the 10-minute request
  lifetime, sign the user in or create a just-in-time account or link. Such a
  round trip now ends with `connection_disabled` without contacting the
  upstream again (`TestRunbookConnectorCompromise`;
  [incidents.md](docs/operations/incidents.md#emergency-controls-sec-020),
  [headless-authentication.md](docs/protocols/headless-authentication.md)).
- **SCIM write overwrote a concurrent administrator change (TEST-050,
  PROV-008).** A SCIM `PUT` or `PATCH` locked only the connector's mapping row
  and read the account (or group) without a lock; after the `If-Match`
  comparison it wrote every managed attribute unconditionally, so an
  administrator's `PATCH` that committed in between was silently reverted
  although `If-Match` had passed, and a SCIM write without `If-Match`
  reverted it too. SCIM `PUT`, `PATCH` and `DELETE` now lock the account and
  its membership (users) or the group row before computing the entity tag,
  and removing a group member takes a share lock on the group, so the
  competing change either makes the SCIM write fail with `412` or is applied
  on top of it. The conflict policy, including the optional `If-Match` of
  `PATCH /users/{user}`, is documented
  (`TestSCIMAdminRaceNeverLosesChanges`;
  [scim-provisioning.md](docs/integrations/scim-provisioning.md#scim-endpoint)).
- **Identifier probes through the SMS budget and the password lock
  (API-009).** Once `delivery.sms.daily_budget` was spent, a sign-in code for
  a number with an account got `429` while one without an account got `200`;
  and the temporary password lock, keyed by account for known identifiers and
  by identifier otherwise, answered `429` through every identifier of an
  account locked through one of them, revealing that they share it. The SMS
  ceilings are now checked before the number is looked up, and password
  failures count per identifier and per account: the account's budget still
  stops all password checks for the account, but only an identifier's own
  budget answers `429`, so another identifier of a locked account answers like
  one without an account. The existing test now asserts that an unknown
  identifier's lock is identical to a known one's (status, problem code,
  `Retry-After`) (`TestIdentifierProbeResponses`,
  `TestPasswordlessAndAbuseBudgets`;
  [configuration.md](docs/operations/configuration.md#security)).
- **Delegation chain dropped from audit (AUD-005).** `token.exchanged`
  recorded the client as actor even when it acts as a service principal or
  agent and kept only the chain depth, and `authorization.decision` kept only
  the outermost `act.sub` (none at all for JWT access tokens, whose `act` claim
  was not read). `token.exchanged` now names the service principal as actor
  and both events keep the whole `act` chain (`metadata.actor_chain`, bounded,
  agents marked); decisions about an agent's own token carry `subject_agent`
  (`TestExchangeActorPreservation`, `TestActorAuditChain`;
  [oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#token-exchange-rfc-8693)).
- **Passwordless codes accepted as proof for account linking without saying
  so (PWDLESS-008).** Linking an external identity to an existing account
  accepted any email code, magic link or SMS code completed in the
  transaction, including one requested for a plain sign-in before the link
  was pending, and the message called it a sign-in code. While a link is
  pending, emailed codes and magic links are now sent with the templates
  `account_link_code` and `account_link_magic_link`, which name the
  connection and the linking purpose, and are bound to that link; earlier
  sign-in codes and links are refused, a linking code is no plain sign-in, and
  SMS never proves control for linking (`TestPasswordlessLinkPurpose`,
  `TestLinkProofRequiresLinkBoundEmailProof`,
  `TestAccountLinkTemplatesStatePurpose`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#upstream-identity-providers)).

- **Restore resurrected consumed proofs (TEST-060).** Restoring a backup
  brought back, as unused, refresh tokens rotated or revoked after it, revoked
  grants, consumed or replaced recovery codes, used HOTP codes (lower counter),
  used-up or revoked initial access tokens, rotated registration access tokens
  and consumed reset, verification and setup codes, and nothing kept the
  restored database out of traffic before reconciliation. The revocation log
  now carries `refresh_rotated`, `refresh_family_revoked`, `grant_revoked`,
  `recovery_code_consumed`, `recovery_codes_replaced`, `hotp_counter`,
  `initial_access_token` (revocations reconstructed from the audit evidence)
  and `registration_token_rotated` records, reconciliation re-applies them
  and ends every outstanding one-time proof of the restore, and the restore
  marker keeps the database unready until then
  (`TestRestoreProofConsumption`;
  [backup-restore.md](docs/operations/backup-restore.md#what-reconciliation-re-applies)).

- **Import role-ceiling bypass (MIG-005).** User imports could map members to
  organization roles above the requester's own authority. Each mapped role must
  now pass the requester's delegation ceiling in that organization, the worker
  re-checks at run time that the requester still holds `realm.users.import` (and
  the verification override when email verification is trusted), and roles
  created by configuration import go through the same ceiling check as the API
  (`TestImportAuthorityAndHashBounds`).
- **Unbounded imported Argon2id parameters (MIG-006).** An imported verifier
  could demand arbitrary memory and time at the next login. Verifiers are now
  capped (memory 1 GiB, 16 iterations, 16 lanes, bounded salt and hash) and
  hashes with a pepper version are refused (`TestValidateImportedHash`,
  `TestImportAuthorityAndHashBounds`).
- **Webhook private-network enforcement (EXT-007).** The operator's private
  egress allowance applied to every webhook subscription. Only subscriptions
  created with `allow_private_network: true` (refused unless the operator policy
  permits private destinations) may now reach private addresses; all others are
  held to public addresses at delivery (`TestWebhooksAndBackchannelLogout`).
- **Token-endpoint rate limit failed open (SEC-006).** When the rate limiter
  could not be reached, token requests proceeded unbudgeted; they are now refused
  with `503 temporarily_unavailable` (`TestTokenEndpointLimiterFailsClosed`).
- **Caller-asserted assurance in `/authorization/check` (AZ-016).**
  `subject_attributes` (assumed `acr`, authentication age, client, organization)
  could satisfy MFA or freshness conditions in a real decision about a named
  subject. They are now accepted only by `/authorization/simulate`; a real check
  that supplies them is denied (`SUBJECT_ATTRIBUTES_SIMULATION_ONLY`,
  `TestPoliciesAndConditionalGrants`).
- **Static claim mappings could replace verified user claims (OIDC-007).** A
  client's `id_token_claims` could set OIDC standard user claims such as
  `email_verified`. Such mappings are now rejected at registration (`422`) and
  ignored at issuance for clients registered earlier
  (`TestClaimsRequestAndStaticClaims`).
- **Generated client secrets stored for idempotent replay (API-006).** A
  configuration import sent with an `Idempotency-Key` header had its response,
  including generated `client_secrets`, stored in `idempotency_records` and
  replayed for 24 hours. `client_secrets` is now one of the secret markers in
  `internal/httpapi/idempotency.go`, so import responses (which always carry that
  member) are not stored, and a retry with the same key returns `409` with
  `original_status` instead of the secrets
  (`TestConfigImportSecretsNotReplayed`).
- **Guest upgrades bypassed registration controls (REG-010, REG-001, REG-008).**
  `POST /me/upgrade` turned a guest into a registered account in realms whose
  registration was closed, invitation-only or limited to other domains. An
  upgrade is now a registration: the realm and organization registration modes
  and the registration-eligibility hooks apply (a refused upgrade leaves the
  account a guest), and in realms
  with `registration.require_approval` the upgraded account is queued for review
  and its sessions end once the address is verified (`TestGuestIdentities`;
  [headless-authentication.md](docs/protocols/headless-authentication.md#guest-identities)).
- **Federated just-in-time accounts skipped the approval queue (REG-008,
  REG-009).** Accounts created by a trusted connection are now queued in
  realms with `registration.require_approval` and cannot sign in until approved
  (`TestFederation`).
- **Factor-reset approval without credential authority (MFA-009).** Approving a
  scheduled recovery with `reset_mfa` needed only `support.recovery.assist`; it
  now also needs `realm.users.credentials.manage`, the permission required to
  request such a reset (`TestScheduledAssistedRecovery`).
- **Literal email-provider callback secret (DEP-006, OPS-010).** A literal
  `delivery.email.events_secret` was accepted in production and copied unredacted
  into support bundles. Production now requires a secret reference for it and
  for `delivery.sms.webhook_secret` whenever they are set, and
  `Config.Redacted` replaces a literal `events_secret` with `[REDACTED]`
  (`TestCallbackSecretsNeedReferences`).
- **Scope step-up bypass (AUT-010).** Token exchange could mint a scope with a
  step-up policy from a subject token whose authentication was weaker or older
  than the scope requires, and API keys and personal access tokens could carry
  such scopes although they hold no authentication event. Token exchange now
  applies the step-up policy to the subject token's own `acr` and `auth_time`
  and refuses the request with `invalid_scope` when they fall short; API keys
  and personal access tokens are refused step-up scopes at creation
  (`403 grant_ceiling_exceeded`), and introspection leaves such scopes out of
  existing ones (a credential left without scopes is inactive)
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#scope-step-up)).
  `TestScopeStepUp` covers the token-exchange path and
  `TestAutomationCredentialStepUpScopes` the API-key and
  personal-access-token paths.
- **Consent revocation across realms (APP-013).**
  `DELETE /users/{user}/consents/{id}` did not check that the consent belonged
  to the administrator's realm, so an administrator with `realm.users.write`
  who knew another realm's user and consent IDs could revoke that consent and
  end the client's grants for that user. Revocation is now limited to the
  realm in the path (`TestConsentRevocationStaysInRealm`).
- **Lost updates of organization policy (API-010).** Two administrators editing
  an organization's policy at the same time could silently overwrite each
  other's change, for example re-enabling a sign-in method the other had just
  restricted. `PATCH /organizations/{org}` now requires `If-Match` when it
  changes `policy` (see **Changed**).
- **Claim mappings released profile data without consent (APP-011).** A
  client's attribute mappings released names, locale, time zone and claimable
  profile attributes in ID and access tokens whatever scopes the user had
  granted, and a claimable attribute that users could edit produced
  user-controlled claim values. Attribute values now require the `profile`
  scope, and attributes that are both `claimable` and `user_editable` are
  refused and never released (`TestClaimMappings`; see **Changed**).
- **`If-Match` with version 0 skipped required preconditions (API-010).** A
  header such as `W/"v0"` was accepted as "no precondition" on routes that
  require one, so concurrent updates (for example of organization policy)
  could still overwrite each other. Version `0`, negative and unparsable
  values are now refused with `412 precondition_failed` on every route
  (`TestAdminSDKInterop`).
- **Decision cache keys ignored token evidence and group grants (AZ-019).**
  A caller caching `/authorization/check` results by `cache_key` could reuse
  an allow for a token with another audience or lower assurance, or after a
  group's roles or a service principal's roles changed. The key now covers
  the token's kind, audience and `acr`, the applicable direct and group
  assignments with role versions, and organization and membership state;
  decisions are not cacheable for conditional, scheduled or soon-expiring
  assignments or rule-derived memberships; and the TTL is at most 10 minutes
  (`TestDecisionCacheContract`).
- **Token exchange ignored the organization's scope policy (TOK-008).**
  Exchanged tokens could carry scopes outside the organization's
  `allowed_scopes` or whose `required_permissions` the subject lacked, and an
  exchange whose ceiling was empty issued a token without scopes. Both are now
  refused with `invalid_scope` (`TestScopeStepUp` covers the organization
  ceiling, `TestExchangeScopeRequiredPermissions` the
  `required_permissions`).
- **Claim mappings could put static or contact values into standard claim
  names of access tokens (OIDC-007).** `access_token_claims` now refuses
  every OIDC standard user claim name, static value and attribute mapping
  alike, including `email*`, `phone_number*` and `address` (`422`; see
  **Changed**) (`TestAccessTokenClaimsRefuseStandardClaims`). Issuance skips
  such names in mappings registered earlier (see **Standard claims in access
  tokens** below).
- **Organization templates and mail-server removal without MFA (MFA-003).**
  Applying an organization template (which can create webhook subscriptions
  and return their secrets) and removing an organization's mail server were
  possible from single-factor sessions where the realm waives MFA for
  organization administration. Both now need an MFA session
  (`TestOrgTemplateAndMailServerRemovalNeedMFA`).
- **IPv6 transition addresses bypassed the egress block list (EXT-007).**
  6to4 (`2002::/16`), Teredo (`2001::/32`) and local-use NAT64
  (`64:ff9b:1::/48`) addresses, which embed IPv4 addresses, were not blocked
  for webhooks, hooks and other outbound calls; they are now
  (`TestTransitionAddressesBlocked`).
- **Secrets in audit metadata (AUD-003).** Audit redaction now also covers
  members named like `api_key`, `apikey` and `access_key`, in local evidence
  and in imported audit records (`TestMigrationPlanningAndReconciliation`
  covers `api_key` in imported records).

- **Authentication flow rules could be weakened or answered by the attacker
  (AUT-012, AUT-014).** A `require_mfa` rule replaced an active
  phishing-resistant requirement with plain MFA; it now keeps it, so only a
  user-verified passkey satisfies the transaction
  (`TestApplyFlowKeepsStrongerRequirement`). A `challenge` could be answered
  by a factor enrolled in the same transaction, so whoever held only the
  password could enroll their own TOTP and pass; the challenge is now
  answered before any in-transaction enrollment, by the provider, an emailed
  code sent only to the verified primary address, or an already enrolled
  passkey or TOTP, never a remembered device, and with none available the
  transaction stops with `authentication_policy_denied`
  (`TestFlowChallengeNotAnsweredByEnrollment`). When one
  `authentication.risk` hook failed, the levels of the others were
  discarded; every hook is now called and their highest level counts as a
  lower bound (`risk: at_least_<level>`)
  (`TestRiskHookFailureKeepsOtherLevels`).
- **Recovery-restricted sessions could change the account (MFA-010).** A
  session that signed in with a recovery code could change the password and
  identifiers, request deletion, export data and create personal tokens; it
  is now limited as described under **Changed** (`TestMultiFactorAndProofs`).
- **A second factor could be added without proving the first (MFA-006).** A
  password-only session (or one skipping MFA through a remembered device)
  could enroll TOTP or a passkey on an account that already had one
  (`TestFactorEnrollmentNeedsExistingFactor`, `TestPasskeys`).
- **Transient sessions minted offline refresh tokens (SES-020).** With
  `offline_access` requested and consented, a transient session produced an
  offline grant and a refresh token that outlived it
  (`TestOfflineConsentAndTransientSessions`).
- **Group membership and moves bypassed delegation ceilings (TEN-008,
  TEN-013).** Roles inherited from ancestor groups were not checked when a
  member was added, and moving a group under a parent with more powerful
  roles was not checked at all (`TestDelegationCeilings`).
- **Incompatible roles combined through groups and composites (AZ-018).**
  Separation of duties compared direct assignments only; it now covers group
  and ancestor-group roles and composites, on assignment, group grants,
  group membership and group moves (`TestSeparationOfDuties`).
- **A domain verified by two organizations (TEN-009).** Verifying a domain
  another organization already held verified was accepted; it now ends in
  `conflict` (`TestDomainReverification`).
- **Another organization's SSO connection (TEN-007, FED-006).** An
  organization could name another organization's connection as its
  `sso_provider_id`; `PATCH /organizations/{org}` now refuses it (`422`)
  (`TestFederation`), and `POST /organizations` refuses it too
  (`TestOrganizationCreationRefusesForeignConnection`).
- **Organization switch ignored the target's sign-in rules (TEN-005,
  TEN-012).** A session could switch into an organization that requires SSO,
  restricts sign-in methods or limits session age without meeting those
  rules (`TestOrganizationSwitch`).
- **Token exchange beyond the user's consent (TOK-008).** For a subject token
  issued to a client with `consent_mode: required`, exchanged scopes are now
  limited to the user's live consent for that client (`invalid_scope` when a
  requested scope is outside it; the default ceiling is narrowed)
  (`TestExchangeLimitedToUserConsent`; `TestConsentManagement` covers an
  explicit scope outside the consent).
- **Profile attribute visibility was not enforced (USR-002, USR-007).**
  Self-service responses and exports are now limited to `self` attributes and
  administrator views never show `internal` ones; see **Changed**
  (`TestProfileAttributeVisibility`).
- **Jobs ran after their requester lost the permission (INT-006).** Audit and
  configuration exports, user imports and bulk user operations now re-check
  the requester's permission when they run (dead-letter: "the requester no
  longer holds <permission>"), and `POST /jobs/{id}/downloads` re-checks it
  (`403`) (`TestJobAuthorityRechecked`).
- **Support writes through the decision API (IMP-011, IMP-013).** The
  server's classification of support actions differed from the SDKs', and an
  `allowlisted_write` support token could perform any write through
  `/authorization/check`; the server now uses the SDK rule (an action with a
  write-verb segment is a write whatever its suffix) and the resource's
  `write_actions` allowlist
  (`TestSupportClassificationMatchesSDKTable` covers the classification,
  `TestSupportWritesNeedAllowlist` the allowlist).
- **Refresh and ID tokens stored for idempotent replay (API-006).** Responses
  containing `refresh_token` or `id_token` are no longer stored in
  `idempotency_records`; a retry with the same key gets `409` with
  `original_status`. No route returns them through the idempotency layer
  today, so `TestIdempotencyNeverStoresIssuedTokens` drives the middleware
  directly.
- **Redirect chains through the identity provider (APP-004).** Clients could
  register redirect or post-logout URIs on the identity provider's own origin,
  whose endpoints redirect onwards (`TestRedirectRegistrationRules`).
- **Required actions at account creation (AUT-018).** `POST /users` accepted
  `update_password` and `configure_totp` without
  `realm.users.credentials.manage`, and concurrent required-action edits
  could overwrite each other; see **Changed**.
- **Configuration import bypassed write permissions (ARC-008).**
  `realm.configuration.import` alone could change the realm policy, clients,
  grants, resources and roles. Applying a document now needs the write
  permission of each change, and a policy change needs the reviewed
  `expected_policy_revision` (`TestConfigImportAuthority`).
- **Runtime credentials could delete audit evidence (AUD-007).** Any role
  could set the session variable the audit guard checked and delete events
  the way retention does. The guard now accepts deletes only from the table
  owner inside `proudauth_audit_prune` (migration `0044`), which never removes
  unsealed, `emergency` or held events, and with `storage.runtime_role` the
  runtime role has no `DELETE` on the audit tables.
- **Organization connections crossed tenants (FED-006).** A session from an
  organization's own connection could select or switch into another
  organization. Selecting (`403`), switching (`POST /me/organization-grants`,
  `403`) and transactions whose organization context differs
  (`connection_not_allowed`) are now refused.
- **Transient sessions reused through SSO got refresh tokens (SES-020).** A
  sign-in reusing a transient session could still obtain an offline grant.
  Neither the sign-in nor the token endpoint now issues refresh tokens for a
  transient session's grants.
- **Pending custom domains blocked other realms (DEP-014).** Registering a
  host reserved it for every realm and told the administrator that another
  realm had it. Only verified domains reserve hosts now (migration `0043`).
- **Clients could force trace export (OPS-003).** A sampled `traceparent`
  from any client forced span export; the flag is now honored only from
  trusted proxies.
- **SCIM fail-open and ceiling bypass (PROV-003, TEST-049).** The connector
  rate limit let requests through when the limiter was unavailable (now
  `503`); a connector could add members to a group whose roles, granted by an
  administrator or inherited from parent groups, exceeded its ceiling (now
  `403`); adoption and domain-restricted registration treated subdomains of a
  verified domain as verified without `include_subdomains`.
- **Standard claims in access tokens (OIDC-007).** Older client registrations
  could still release standard user claim names from static or mapped values
  in access tokens; issuance now skips them.
- **Own-origin redirect check bypassed by port or custom domain (APP-004).**
  A redirect URI on the identity provider's host with another port, or on one
  of the realm's verified custom domains, was accepted.
- **Forged job rows (TEST-063).** Job types are re-checked against their
  requester's current authority when they run, and a personal export only for
  the requester's own account, so a queue row naming another requester,
  subject or tenant dead-letters (`TestForgedJobMetadata`).
- **Session-event consumers outlived their authorization (TEST-062).** A long
  poll now re-checks the session and `realm.session_events.read` about every
  2 seconds and before releasing events (`TestStreamOutlivingAuthorization`).
- **Guessable invitation recipient digest (INV-016).** `recipient_digest` in
  `invitation.created` is now an HMAC under the deployment's lookup key, with
  `recipient_digest_key_version`.

### Known limitations

Details and workarounds are in the linked documents.

- **Support impersonation:** no intersection with the target's current
  permissions at issuance; realm state is not re-checked for live grants; there
  is no bulk revocation
  ([impersonation threat model](docs/threat-models/impersonation.md)).
- **Restore reconciliation** does not cover every change (for example a password
  marked compromised without a new one, MFA changes, role unassignment or
  organization suspension)
  ([backup-restore.md](docs/operations/backup-restore.md#what-reconciliation-does-not-cover)).
- **Sender-constrained tokens:** DPoP and certificate bindings are enforced
  at the token endpoint, by the IdP's own APIs and UserInfo, and by the Go
  resource SDK's request-level `SenderVerifier`. All SDK token-only methods
  reject bound tokens; Node.js, Dart and PHP have no request-level proof
  verifier. Refresh tokens are not sender-bound
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#mutual-tls-rfc-8705)).
- **Privacy:** authentication transactions hold the full client IP address and
  the user agent while they are pending, sessions keep user agents, and active
  consents, pending invitations, registration approvals, assisted-recovery and
  merge records, suppressions, terms acceptances and legal holds have no
  retention job ([data-inventory.md](docs/operations/data-inventory.md#known-data-minimization-gaps)).
- **Metrics and tracing:** worker metrics (including
  `proudauth_delivery_total`, `proudauth_audit_integrity_problems`,
  `proudauth_jobs_failed_total` and the `audit_failure` signal) are visible only
  when `workers.metrics_listen` is set; dropped spans are not counted; the
  OTLP exporter does not use the egress policy
  ([monitoring.md](docs/operations/monitoring.md#tracing)).
- **Audit archive:** files are written to a directory only (mount object
  storage or a WORM volume there yourself). `identity-cli verify-audit-archive`
  cannot tell that the newest files, or leading files before the first one, are
  missing, and checks a fork's first link against the main directory only;
  compare `first_sequence` and `last_sequence` with the database
  ([incidents.md](docs/operations/incidents.md#audit-archive-aud-008)).
- **Organization templates** cover the organization policy, custom roles,
  groups, service principals (without credentials) and webhook subscriptions,
  not clients or identity providers. A dry run does not validate webhook event
  types, payload form or destinations.
- **Dynamic groups:** more dynamic groups than the worker recomputes within
  `security.dynamic_group_max_staleness` (up to 4900 per 5-minute run) lose
  their roles between recomputations; a rule matching more than 10000
  members grants nothing until it is narrowed.
- **Decision cache:** callers may reuse a decision for its TTL (at most
  10 minutes) after a change the key does not see; decisions that consulted
  relationships or an external policy engine are never cacheable. The SDKs
  do not cache decisions.
- **Migration:** user imports only create accounts (a record already imported
  is never updated) and create them `active` or `suspended` (locked source
  accounts have no equivalent). First-party adapters exist only for
  Keycloak 26.x, ZITADEL v4.x and SuperTokens core 12.x, each tested with one
  release; they carry over no passkeys, recovery codes, HOTP, SMS or email
  factors, identity-provider links, phone numbers, service accounts, clients
  or secrets, flows, policies or sessions, and Keycloak FIPS-padded PBKDF2
  verifiers fail to verify. The mapping template leaves out keys that are not
  organizations by default (Keycloak groups, the SuperTokens `public`
  tenant); dry runs cannot validate memberships in organizations not yet
  created; the reconciliation `--apply` requests has no expected counts
  ([migration-adapters.md](docs/operations/migration-adapters.md)). Imported
  audit metadata is redacted only by member name and token shape, and
  imported records held by a legal hold at deletion time are not cleared when
  the hold is released ([migration.md](docs/operations/migration.md)).
- **Lifecycle workflows:** no conditions, loops or expressions; subjects are
  users only; missed schedule slots are not replayed; endpoint calls are at
  least once (endpoints must deduplicate by `Idempotency-Key`);
  `extensions.workflow_publish_approval` applies only to workflows created
  while it is on; runs keep their accountable publisher after a
  re-publication; indirect trigger cycles stop only at depth 3; no
  workflow-specific metrics; account deletion does not clear workflow runs
  before retention; two workers with the same host name share lease
  ownership; the depth limit, the 500-run cap, the per-realm share and the
  transition cap have no tests; workflows are not in the configuration or
  realm data export ([workflows.md](docs/integrations/workflows.md)).
- **Plugins:** parts can only be hooks, webhook subscriptions and workflows;
  plugins and their versions are never deleted and are not exported
  ([plugins.md](docs/integrations/plugins.md#data)).
- **Extension contracts:** only webhook events have a second version; hook
  request schemas are closed (`additionalProperties: false`), so new request
  members arrive only with a new hook contract version; the realm data
  export omits `event_version`, `contract_version` and `plugin_id`
  ([extension-contracts.md](docs/integrations/extension-contracts.md)).
- **Configuration import:** a reconcile replaces a client's whole
  registration from the document (client fields it omits take their
  defaults); a client whose type differs makes the reconciling import fail as
  a whole; resource scopes, client types, denied permissions and approval
  flags are never reconciled; nothing is deleted; a document must fit
  `limits.max_body_bytes`
  ([exit-and-export.md](docs/operations/exit-and-export.md#configuration-import)).
- **Configuration import with `Idempotency-Key`:** the response is never
  replayed; a retry with the same key returns `409`, so check the realm's state
  before re-sending an import whose response was lost
  ([exit-and-export.md](docs/operations/exit-and-export.md#import-into-proudauth)).
- **Realm data export:** sections are read one after another, not from one
  snapshot; the whole file is built in the worker's memory; `identity-cli api`
  cannot save the NDJSON download, and there is no import for the format
  ([exit-and-export.md](docs/operations/exit-and-export.md#realm-data-export)).
- **Untested paths:** the role-assignment approval workflow (except for
  agents) and refresh families with remember-me or offline idle windows
  across rotations have no automated tests.
- **Federation:** the published OIDC profiles cover Keycloak 26.8.0 alongside
  repository test doubles; the `google` and `microsoft` adapters are tested
  only for their configuration rules. Other upstream products are untested
  ([interoperability.md](docs/integrations/interoperability.md)).
- **Authentication flow policy:** network, failed-attempt, privilege and
  assurance conditions, `require_phishing_resistant` and an unavailable
  challenge provider have no end-to-end test; a `deny` leaves the transaction
  pending without an error redirect to the client
  ([headless-authentication.md](docs/protocols/headless-authentication.md#authentication-flow-policy)).
- **Residency:** the deployment's SMTP relay and the OTLP endpoint are checked
  only at startup, and Vault, KMS commands, the database, backups and logs are
  outside the policy ([data-inventory.md](docs/operations/data-inventory.md#data-residency)).
- **KMS envelope:** keys are unwrapped into process memory, and the KMS
  command receives the process environment except `PROUDAUTH_*` variables
  ([keys.md](docs/operations/keys.md#kms-envelope-dep-016)).
- **Database roles:** `proudauth_audit_prune` does not check an event's age,
  so a stolen runtime credential can still prune sealed, unheld,
  non-`emergency` events early (recorded like retention); without separate
  roles the runtime credential can delete audit rows directly; the
  migration's revoke of `CREATE` on `public` from `PUBLIC` takes effect only
  when the migration role owns the schema
  ([installation.md](docs/operations/installation.md#database-roles)).
- **MFA floor:** `admin_phishing_resistant` is enforced at sign-in only in
  realms with passkeys enabled, and realm creation does not check the floor
  ([configuration.md](docs/operations/configuration.md#security)).
- **Verified-contact update:** an account without a primary email address
  cannot complete `verify_contact`, and a re-confirmed address keeps its
  earlier `verified_at`
  ([headless-authentication.md](docs/protocols/headless-authentication.md#verified-contact-aut-018)).
- **Benchmarks:** one laptop's reference numbers are published; they do not
  validate the proposed targets or provide sizing guarantees. Extended
  scenarios cover software-passkey flows and paced SCIM user lifecycles;
  physical authenticator latency, delivery workers and multi-node
  consistency beyond refresh races are not covered
  ([benchmarks.md](docs/operations/benchmarks.md#reference-results)).
- **SCIM:** tested only with requests shaped like Okta's and Azure AD's, not
  against real directories; no bulk operations or sorting; a connector that
  manages more than 20,000 users or groups can list them only with a single
  `eq` filter on `id`, `externalId`, `userName` or `displayName` (other lists
  answer `400 tooMany`); a change to a connector's mappings reaches a group
  only at its next write by the connector; a `PUT` or `replace` of a group's
  members fails as a whole when the group's roles exceed the connector's
  ceiling ([scim-provisioning.md](docs/integrations/scim-provisioning.md)).
- **SAML:** tested against the repository's own test SP and IdP and the
  published Keycloak 26.8.0 profiles (SAML-010); other products and external
  conformance suites are untested. Not supported:
  Artifact binding, SOAP, attribute queries, ECP, proxying, metadata signing
  and metadata URLs, IdP-initiated logout and logout propagation (logout
  reports `PartialLogout` instead), HTTP-Redirect ACS endpoints, encrypted
  assertions and upstream logout at the broker, any SHA-1 or algorithm
  exception. One SAML key set per realm serves both roles; recreating a SAML
  application changes its persistent NameIDs; SAML applications,
  connections and keys are not part of the configuration document
  ([saml.md](docs/integrations/saml.md#not-supported)).
- **Directories and outbound provisioning:** LDAP is tested only against an
  in-process server; outbound SCIM also has a published ZITADEL v4.16.3
  profile alongside the in-process double. Other counterparties are untested
  ([interoperability.md](docs/integrations/interoperability.md)). Not supported:
  Kerberos/SPNEGO (PROV-015), password and identifier write-back, SASL and
  anonymous binds, nested groups and ranged retrieval, AD DirSync and RFC 4533
  synchronization, referral chasing, a lookup-only storage mode, outbound
  SCIM bulk, extension schemas and authentication other than a bearer
  token. A directory outage blocks password sign-in for its users (by
  design); organization connectors reactivate a membership on re-enable
  whoever suspended it; account deletion keeps the directory link's DN and
  imported values, and runs, findings and deliveries have no retention job;
  disabling `directory.enabled` while a run is queued leaves the run
  `queued` and blocks new runs of that connector
  ([directory.md](docs/integrations/directory.md#not-supported),
  [data-inventory.md](docs/operations/data-inventory.md#known-data-minimization-gaps)).
- **Not implemented:** SCIM bulk operations, JAR (signed request objects),
  CIBA, OCSP and CRL fetching, user assertions in `jwt-bearer`, signing or
  decryption inside an HSM, Helm chart; embedded or sandboxed code execution is excluded by
  design (EXT-013, [ADR 0021](docs/architecture-decisions/0021-no-embedded-code-execution.md)).
- The Node.js SDK is tested (in CI) only against local mock HTTP servers.
- **OIDC Session Management:** browsers that block or partition
  third-party cookies report every session as `changed`, server-side
  revocations are invisible to the iframe, and the iframe script has not been
  run in real browsers
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#session-management-oidc-014)).
- **Shared signals:** no long polling, no polling of remote transmitters, no
  CAEP `assurance-level-change`, `token-claims-change` or
  `device-compliance-change` events out; tested only against the
  repository's test servers. Revoked grants keep a user in a
  `client_users` stream until their rows are purged, and account deletion
  leaves the user ID in `ssf_stream_subjects`
  ([shared-signals.md](docs/integrations/shared-signals.md)).
- **Partner project access:** a grant's `valid_until` stops new assignments
  but does not remove or disable existing ones; ending a relationship leaves
  existing grants in place
  ([partner-access.md](docs/integrations/partner-access.md#what-ends-partner-access)).
- **Passkey trust:** the FIDO metadata BLOB is read at startup only and has
  not been tested with real metadata; with `server.host_policy: strict`,
  related origins work only when the RP ID is the public origin's host
  ([passkey-trust.md](docs/operations/passkey-trust.md)).
- **Registry token bridge:** no registry implementation has been run
  against it; machine-client and API-key credentials are untested there
  ([container-registry.md](docs/integrations/container-registry.md)).
- **Historical entitlements:** service principals are always reported
  `active`, OAuth grants older than `privacy.session_retention` after they
  ended are gone, and reconstruction cannot go past audit retention
  ([investigations.md](docs/operations/investigations.md)).
- **Realms** cannot be deleted (only suspended), and share the database,
  root keys and upgrade timing of their deployment
  ([isolation-tiers.md](docs/operations/isolation-tiers.md)).
- **FAPI 2.0:** the `fapi2` profile is not certified by the OpenID Foundation
  and no conformance suite has been run
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#fapi-20-security-profile-adv-001)).
- **Mutual TLS and X.509 sign-in:** no OCSP or CRL fetching; an anchor holds
  only its own CRL, so under `revocation: crl` certificates issued by an
  intermediate are refused unless the issuing CA is the anchor; tested only
  with in-process TLS and generated certificates
  ([mutual-tls.md](docs/protocols/mutual-tls.md#known-issues)).
- **Workload federation:** tested only with locally signed tokens in the
  shape of GitHub Actions, Kubernetes and SPIFFE tokens; `jti` replay control
  is per trust; there is no emergency control for the grant; trusts are not
  in configuration documents or the realm data export
  ([workload-federation.md](docs/integrations/workload-federation.md#limits)).
- **Dynamic client registration:** no software statements or `jwks_uri`;
  registration access tokens do not expire and the management endpoints have
  no rate limit; registrant-supplied contacts are not verified (they are
  never mailed, but count as contacts in the ownership report)
  ([dynamic-client-registration.md](docs/integrations/dynamic-client-registration.md#limits-and-known-issues)).
- **Relationship-based authorization:** links follow one hop; tuples and
  shares are not removed with organizations and are not exported;
  `list-objects` applies no step-up, policies, engines or hooks
  ([relationship-authorization.md](docs/integrations/relationship-authorization.md#data-and-limits)).
- **Elevation and access reviews:** the `state` filter shows an elapsed
  elevation as `active` until the sweep runs; campaigns cannot be wider than 10000
  assignments and are closed item by item
  ([elevation-and-access-reviews.md](docs/integrations/elevation-and-access-reviews.md#limits)).
- **Front-channel logout:** delivery is not confirmed and third-party cookie
  restrictions often defeat it; frames are produced only by the logout
  endpoint, not when a session is revoked elsewhere
  ([oauth-oidc-profile.md](docs/protocols/oauth-oidc-profile.md#front-channel-logout-ses-018)).

[Unreleased]: https://github.com/proudauth/commits/main
