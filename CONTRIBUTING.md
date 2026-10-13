# Contributing to ProudAuth

Thank you for helping. ProudAuth is an identity provider: a small mistake can let
one tenant read another's data or let a token outlive its revocation. The rules
below exist for that reason (GOV-002, GOV-004, QA-001, QA-008).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
**Security vulnerabilities go through [SECURITY.md](SECURITY.md), never a public
issue or pull request.**

## Before you start

- Read the relevant chapter of [docs/plan.md](docs/plan.md) and find the
  requirement IDs (for example `TOK-008`, `IMP-012`) and acceptance tests
  (`TEST-0xx`) your change touches.
- For new features, open a feature request first. A later priority (P1–P3) never
  permits a partial implementation that is unsafe when enabled (docs/plan.md §1.3);
  a feature that cannot ship with its negative tests should stay disabled and
  unadvertised (APP-020).
- Architecture changes that replace a decision in
  [docs/architecture-decisions/](docs/architecture-decisions/README.md) need a new
  ADR in the same pull request (GOV-001).

## Developer Certificate of Origin

Every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```sh
git commit -s -m "oauth: reject repeated resource parameters at PAR"
```

This adds `Signed-off-by: Your Name <you@example.com>`, certifying that you have the
right to submit the work under the project license (Apache-2.0). Sign-off applies
to code, tests, fixtures, documentation and bundled data. Do not submit code
copied from projects whose license is incompatible with Apache-2.0 (docs/plan.md
§2.3 lists caveats for reference products). Commits without a sign-off cannot be
merged: the CI job `dco` fails a pull request when any of its commits lacks a
`Signed-off-by:` line (fix with `git rebase --signoff <base>`).

## Development setup

- Go: the version in `go.mod`.
- PostgreSQL: any role that can `CREATE DATABASE`. CI uses PostgreSQL 18.6.
- Docker with Compose v2 for `make dev` and `make smoke`; Docker, curl, jq
  and python3 for `make dr-drill`, the disaster-recovery drill
  ([backup-restore.md](docs/operations/backup-restore.md#what-is-tested)),
  and for `make interop-zitadel`, outbound SCIM provisioning against ZITADEL
  ([outbound-provisioning.md](docs/integrations/outbound-provisioning.md#zitadel-v4163)).

```sh
docker run -d --name proudauth-dev-pg -e POSTGRES_USER=proudauth -e POSTGRES_PASSWORD=devpassword \
  -e POSTGRES_DB=proudauth -p 127.0.0.1:55432:5432 postgres:18.6
export PROUDAUTH_TEST_DATABASE_URL='postgres://proudauth:devpassword@127.0.0.1:55432/proudauth?sslmode=disable'
```

## Running tests

```sh
make test                       # go vet ./... && go test -count=1 ./...
go test ./... -count=1 -race    # what CI runs (with -timeout 30m; CI job deadline 45m)
go test ./tests/e2e -run TestSupportImpersonation -v
```

Database-backed tests (`internal/storage`, `tests/e2e`) **skip** when
`PROUDAUTH_TEST_DATABASE_URL` is unset, and `go test` still prints `ok`. A run that
finishes in a few seconds almost certainly skipped them; use `-v` and check for
`=== RUN` and `SKIP` lines. Useful variables:

| Variable | Effect |
| --- | --- |
| `PROUDAUTH_TEST_DATABASE_URL` | Admin connection; each test creates and drops its own database |
| `PROUDAUTH_TEST_LOG=1` | Prints server warnings from the in-process harness |
| `PROUDAUTH_TEST_KEEP_DB=1` | Keeps test databases after the run |

The end-to-end suite (`tests/e2e`) starts the server in-process and builds the
§37.3 fixture (one realm, two organizations, two resource audiences, several users,
an organization administrator, a support operator and machine principals) through
public APIs. Prefer adding scenarios there over mocking.

`tests/contract` needs no database: it checks that every route in
`api/openapi/proudauth.yaml` is registered by the server and vice versa, that
operations are well formed, that the JSON Schemas under `api/` parse, and that
every event type has a schema. **A new or changed route or event must update
`api/` in the same pull request.**

Language SDK changes belong in their standalone repositories under `proudbase`.
The CLI and protocol compatibility tests import a version-pinned Go SDK module;
shared synthetic contracts live in `tests/fixtures/sdk-contracts`. Each SDK owns
its language tests, dependency checks and release lifecycle. See
[repository ownership](docs/repository-migration.md).

### Fuzzing

Fuzz targets and the packages that contain them:

| Package | Targets |
| --- | --- |
| `internal/platform/canonical` | `FuzzEmail`, `FuzzDomain`, `FuzzUsername`, `FuzzPhone` |
| `internal/application` | `FuzzMatchRedirect`, `FuzzValidateRedirectRegistration`, `FuzzClaimMappings` |
| `internal/token` | `FuzzRejectDuplicateKeys` |
| `internal/authorization` | `FuzzPolicyDefinition` |
| `internal/platform/reqctx` | `FuzzParseTraceparent` |
| `internal/egress` | `FuzzAllowed` |

```sh
go test ./internal/application -run '^$' -fuzz '^FuzzMatchRedirect$' -fuzztime 60s
make fuzz    # Service fuzz targets; Go SDK verification fuzzing runs in its repository
```

CI runs a smoke of every target except `FuzzUsername` and `FuzzPhone`: 30
seconds each, 15 seconds for `FuzzParseTraceparent`, `FuzzAllowed` and
`FuzzClaimMappings`; CI also runs `FuzzValidateRedirectRegistration` and
`FuzzDomain`, which `make fuzz` does not.
When a fuzzer finds a failure, commit the generated file under
`testdata/fuzz/<Target>/` with the fix so it becomes a permanent regression input.

### Lint and supply-chain checks

```sh
make lint    # go vet + scripts/check-secrets.sh + scripts/check-licenses.sh
make vuln    # govulncheck
gofmt -l .   # must print nothing (CI fails otherwise)
```

- `scripts/check-secrets.sh` fails on likely committed secrets (private keys,
  `pa_*` bearer prefixes, `whsec_` webhook secrets, cloud and chat tokens). Paths
  under `tests/`, `docs/`, `*_test.go` and `deploy/compose/secrets/` are excluded;
  use obviously fake values there anyway.
- `scripts/check-licenses.sh` fails on dependencies whose license is not one of
  Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC or MPL-2.0. New dependencies
  also need an entry in `NOTICE`.
- CI additionally runs `staticcheck`, a container build, the Compose smoke test, and
  `govulncheck` (pinned `v1.8.0`) over the source and, in `-mode=binary`, over
  unstripped rebuilds of the shipped binaries. Service CI, releases and the
  Dockerfile pin Go 1.27.2; reviewed patch updates keep those pins aligned.
  `go.mod` declares minimum Go 1.27.1. The release workflow requires the full
  CI result for the exact tagged commit, reusing an already successful main
  run only when its immutable commit matches, otherwise calling the reusable
  CI workflow before publishing.

## Review rules

### Security-sensitive areas

The release review policy requires **two maintainer approvals, including a
designated security reviewer**. The organization has separate `@proudbase/maintainers`
and `@proudbase/security-reviewers` teams; [CODEOWNERS](.github/CODEOWNERS)
requires the security team on sensitive paths. Both teams initially contain the
owner, so team separation does not establish a second independent reviewer.
A second qualified reviewer is still needed to fulfill that policy. The owner
authorized the initial prerelease without an external security review; no
independent review is claimed. Security-sensitive paths include:

- Authentication, tokens, authorization and sessions: `internal/authentication/`,
  `internal/authorization/`, `internal/token/`, `internal/oauth/`,
  `internal/session/`, `internal/credential/`, `internal/passkey/`,
  `internal/federation/`, `internal/impersonation/`, `internal/machine/`,
  `internal/certauth/`, `internal/saml/`, `internal/workload/`,
  `internal/directory/`, `internal/registry/`, `internal/realm/`
  (authentication flow and MFA policy), `internal/application/` (client
  authentication and redirect URI validation), and in `internal/httpapi/`
  the files `auth.go` (API bearer authentication) and `clientcert.go`
  (client certificates behind a proxy)
- Keys and cryptographic material: `internal/keys/`, `internal/platform/secret/`
- Trust boundaries: `internal/provisioning/` (SCIM), `internal/provision/`
  (bootstrap), `internal/audit/`, `internal/egress/`, `internal/configuration/`
  (including declarative import), `internal/restore/`, `internal/ssf/`
  (shared signals), `internal/identity/` (account state and erasure)
- Extensions: `internal/hooks/`, `internal/webhooks/`, `internal/plugin/`,
  `internal/contracts/`
- Migration adapters, which import password verifiers and MFA seeds:
  `internal/migrate/`
- Schema and shared public contracts: `migrations/`, `api/`,
  `tests/fixtures/sdk-contracts/`. Client-library changes are reviewed in their
  separate SDK repositories.
- Supply chain and release infrastructure: `.github/` (workflows,
  `CODEOWNERS` itself), `Dockerfile`, `.dockerignore`, `Makefile` and
  `scripts/offline-bundle.sh` (the release workflow runs `make bundle`),
  `go.mod`, `go.sum`, `scripts/check-secrets.sh`, `scripts/check-licenses.sh`
- Security documentation: `SECURITY.md`, `docs/threat-models/`,
  `docs/protocols/tokens.md`, `docs/protocols/oauth-oidc-profile.md`,
  `docs/operations/keys.md`, `docs/operations/incidents.md`,
  `docs/operations/revocation-exposure.md`,
  `docs/operations/account-recovery.md`, and ADRs
  [0010](docs/architecture-decisions/0010-opaque-support-tokens.md),
  [0014](docs/architecture-decisions/0014-support-impersonation.md) and
  [0015](docs/architecture-decisions/0015-key-hierarchy.md)

Changes elsewhere that alter a trust boundary (for example a new route that skips
`a.admin`/`a.self`/`a.tenant` in `internal/httpapi`, or a change to rate limits
in `internal/ratelimit`) should request a security reviewer too.

### What reviewers expect

- **Passing tests are not sufficient.** Generated or happy-path tests passing does
  not establish that a security-sensitive change is correct. Reviewers check the
  invariant itself: tenant scoping in every query, transaction boundaries,
  fail-closed error handling, audit inside the same transaction, and secrets never
  logged or returned twice (QA-001, GOV-004).
- **Negative tests are mandatory.** A change to an enabled feature includes the
  denied paths: wrong tenant, wrong audience, replayed proof, expired artifact,
  concurrent use, missing permission (docs/plan.md §33.2).
- **Every security fix adds a regression fixture** that fails before the fix and
  passes after it, built from synthetic data only, and names the affected
  versions in the changelog entry (QA-008; the full rule is in
  [SECURITY.md](SECURITY.md#security-regressions-qa-008)).
- **Requirement IDs.** The pull request description lists the requirement and test
  IDs from docs/plan.md that the change implements, changes or affects. Code
  comments already use these IDs; keep them accurate.
- **Documentation parity.** Behavior, configuration keys, routes, metrics and
  limitations described in `README.md`, `CHANGELOG.md` and `docs/` must match the
  code in the same pull request (GOV-008). Documenting a capability the code does
  not have is a defect.
- **No new unauthenticated surfaces** without an explicit trust-class decision
  (docs/plan.md §25.2).

## Database migrations

Migrations live in `migrations/` as numbered `NNNN_description.sql` files embedded
in every binary and applied in lexical order under a PostgreSQL advisory lock.
The runner records a SHA-256 checksum per file.

- **Never edit an applied migration.** A changed checksum makes `migrate` fail. Add
  a new file instead.
- **Use expand → migrate → contract** (DEP-012):
  1. *Expand*: add nullable columns, new tables or new indexes in a way that the
     currently released binary ignores. Do not rename or drop anything.
  2. *Migrate*: ship code that writes both shapes and backfills in bounded batches
     (from the worker or a job), never in one long transaction on a hot table.
  3. *Contract*: drop or rename old structures in a later release, once no
     supported binary reads them.
- A binary refuses to run `migrate` against a database containing a migration it
  does not know, and the worker refuses to start while the schema is behind. Keep
  each release's migrations backward compatible with the previous release's
  binaries so mixed-version rolling upgrades work: an older server keeps running
  against newer *expand* migrations but refuses to start once a newer *contract*
  migration has been applied (TEST-061, `TestMixedVersionWindow`).
- Migrations are *expand* by default. Mark a destructive one with a
  `-- proudauth:compat=contract` line; it is applied only when `migrate` is given
  `-backup-reference <id>` (recorded in `schema_migrations`). Optional
  `-- proudauth:precondition <SQL>` lines must return true before the migration
  runs, and `migrate -plan` reports pending migrations and precondition results
  without applying anything (OPS-008, `TestMigrationSafetyGates`).
- Every tenant-owned table carries `realm_id` (and `organization_id` where
  relevant) with composite foreign keys (DB-001). Bearer secrets are stored only as
  digests; recoverable secrets only as AES-GCM ciphertext with a key version
  (DB-008).
- Describe upgrade and rollback consequences in the pull request.

## Pull request checklist

The [pull request template](.github/pull_request_template.md) mirrors the feature
definition of done (docs/plan.md §37.2). Fill it in honestly; "not applicable" is
an acceptable answer, a silent omission is not.

## Commit and code style

- `gofmt`-formatted Go; no new dependencies without a reason in the pull request.
- Small, focused commits with a package prefix (`oauth:`, `session:`, `docs:`).
- Errors returned to clients use stable codes from `internal/platform/problem`
  (custom APIs) or the protocol's own error format (OAuth endpoints). Do not put
  secrets, tokens or stack traces in error details or logs.
