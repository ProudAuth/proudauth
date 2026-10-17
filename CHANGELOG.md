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

- `internal/testutil` fault-injection helpers for reliability tests: a TCP
  black hole, silent and stalling SMTP relays, a refused port and a slow HTTP
  server.
- `docs/releases/` records the owner decisions taken at the start of each
  release phase, beginning with
  [0.2.0-alpha.5](docs/releases/2026-10-alpha.5-decisions.md).
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

[Unreleased]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.4...main
[0.2.0-alpha.4]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.3...v0.2.0-alpha.4
[0.2.0-alpha.3]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.2...v0.2.0-alpha.3
[0.2.0-alpha.2]: https://github.com/proudauth/proudauth/compare/v0.2.0-alpha.1...v0.2.0-alpha.2
[0.2.0-alpha.1]: https://github.com/proudauth/proudauth/releases/tag/v0.2.0-alpha.1
