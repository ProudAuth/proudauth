# Service repository migration gates

The service repository is independently buildable as
`github.com/proudauth/proudauth`. The source-ownership split uses separate public
SDK and website repositories under `ProudAuth`; it keeps the service a modular
monolith with transactional security boundaries. Publication and release
evidence comes from the repository's GitHub Actions and Releases pages, rather
than from a local staging directory. Original private Git history is not exported.

## What belongs here

Server, worker, CLI, benchmark runner, domain code, SQL migrations, public API
contracts, service tests, portable deployment files, operational documentation,
requirements and architecture decisions belong to the service. SDK packages and
the website renderer have standalone owners and release lifecycles.

The CLI imports the admin client from `github.com/proudauth/proudauth-sdk-go`;
service end-to-end tests import its admin, verifier and OIDC packages.
`go.mod` pins `v0.0.0-20261013190527-116f9fa19d0b`, corresponding to public
commit `116f9fa19d0b0174a0c270763e2ef6abf872233b`; `go.sum` verifies the module.
No local `replace` directive, Go workspace or sibling checkout is required.
SDK implementation sources are absent from this repository.

Synthetic contracts are service-owned at `tests/fixtures/sdk-contracts`.
Each SDK owns an identical copy of both JSON tables plus a checksum manifest;
changes require coordinated updates and verification in all five repositories.
[SDK repository evidence](integrations/sdk-repositories.json) pins every tested
source revision, successful CI run, workflow bytes and shared-contract hashes.

## Preserved verification gates

1. Service security tests still run with the race detector against real
   PostgreSQL. The end-to-end suites continue to exercise the published Go SDK
   against real service endpoints. SDK verifier fuzz targets execute in the Go
   SDK pipeline; nine untrusted-input service fuzz targets remain in service CI.
2. Service governance contracts still require build, formatting, vet, pinned
   static and vulnerability checks, secret/license checks, release dependencies
   and supply-chain artifacts. `TestSDKRepositoryBoundaries` verifies the
   independently owned SDK checks, immutable revisions and matching JSON
   contracts; Node's dependency audit remains in the Node SDK pipeline.
3. CODEOWNERS uses actual `ProudAuth/maintainers` and
   `ProudAuth/security-reviewers` teams. Sensitive paths require the security
   team alone. Both teams initially contain the owner; that does not establish
   a second independent reviewer. CONTRIBUTING states the remaining review
   policy limitation and the owner's initial-prerelease exception plainly.
4. The original checkout's protected
   `tests/contract/traceability_test.go` remains unchanged, with SHA-256
   `8d9bf0ca7adec58839b4ae73c138497337e2324ea8821afac320b57df5a6f227`.
   The new repository copy changes only obsolete SDK path classification and
   the OSS-004 source-location description. It preserves all required IDs,
   missing-evidence checks, unoffered capabilities and external-review status.
   The generated matrix credits local tests; it does not represent independent
   SDK test citations as if they executed in the service pipeline.
5. The reproducibility wrapper snapshots service inputs and uses the populated,
   checksum-verified dependency cache, including the normal Go SDK module.
   Network/download isolation, two OS builders, all 12 release binary targets,
   mismatch rejection and owned-resource cleanup remain unchanged.
6. Image smoke, full CI, dependency/security scans and publication privacy checks
   remain required before a version tag. Snapshot notes and metadata do not
   replace those live verification results or establish registry publication.

## Historical measurement provenance

[Local split verification](operations/release-results/2026-10-13-repository-split.json)
records 645 top-level tests and 499 subtests passing with the race detector
against dedicated PostgreSQL 18.6, with zero failed or skipped tests. Build,
vet, formatting, module checksums, license and secret checks pass. This local
Go 1.27.1 run retains its own scope; final Go 1.27.2 hosted CI and release
artifacts remain bound to their actual commit and workflow evidence.

The original laptop benchmark JSON and initial failure evidence remain in
`docs/operations/bench-results`. Numeric measurements, outcomes and recorded
binary/source hashes are preserved. Local ephemeral paths and the personal
checkout path were replaced in exported copies, with original/export digests in
`export-provenance.json`; exported artifact checksum manifests were recalculated.
The untouched original checkout retains the frozen originals.

The source baseline was the private repository's
`5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11` plus its uncommitted worktree at export
time. This identifies the input baseline, not a public Git commit or a benchmark
build commit. Older measurements retain their original recorded source digests.

No `.env`, installation keys, database dumps, private screenshot state, image
archives, dependency cache, generated binary, benchmark seed or private history
is included in this snapshot. Live containers and Cloudflare routes are untouched.
