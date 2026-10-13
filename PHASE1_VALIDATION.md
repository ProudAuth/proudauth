# Local service snapshot validation — 2026-10-13

This validates the unpublished migration preview only. It does not validate a
public repository, release, Docker build or running installation.

| Check | Result |
| --- | --- |
| Offline `go build -mod=readonly -trimpath ./cmd/...` | Pass; all four command packages build |
| `make -n image VERSION=0.2.0-dev` | Resolves to the expected Docker build command |
| `TestDeployImageLocalStack` | Pass; credential initialization/idempotence, config, storage layout and API drift |
| `TestDeployImageHardening` | Pass; pinned build/runtime and non-root image controls |
| Benchmark artifact/provenance verification | Pass; 279 manifest entries, no mismatches |
| Measurement JSON preservation | Pass; numeric/result JSON byte-identical to originals |
| Exported benchmark privacy patterns | Pass; no local/personal paths, key blocks or bearer patterns found |
| Full snapshot publication audit | Pass after removing two personal-cache paths from exported Syft metadata; no publication findings |
| Private installation-state exclusion | Pass; no `.env`, secret/archive/cache/backup directories copied |
| Protected traceability test | Byte-identical to the input worktree |
| Repository secret scanner and shell syntax | Pass |
| `TestCIStaticAndDependencyChecks` | Blocked: retained governance check expects the removed local Node SDK audit |
| `TestCodeOwnersReviewBoundaries` | Blocked: retained check expects old `@proudauth/security-reviewers`, while actual owner is corrected |
| `TestRequirementsTraceability` | Blocked: matrix stale after source/evidence separation |

The focused contract command ran five checks in 1.251 seconds; it correctly
exited nonzero for the three recorded migration blockers. No contract was weakened
to force a pass. No full Go/E2E suite, benchmark measurement, image build,
dependency download, commit, push or GitHub change was performed.

There are 16 redacted measurement metadata files and 10 recalculated artifact
manifests, including nested manifests verified from leaves to parents. Original
binary/source hashes remain recorded as historical measurement identifiers;
they do not identify this preview's build.

The exported Syft catalogue also replaces two personal cache-directory paths
in its tool descriptor. Package/file inventory and image identity are unchanged;
the original source/image SPDX SBOM bytes remain unchanged. The catalogue and
its applicable artifact manifest have new hashes recorded in
[release export provenance](docs/operations/release-results/export-provenance.json).
These are unsigned local-preparation records; no original signature or
attestation is claimed to verify changed exported bytes.

The source baseline is private HEAD
`5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11` plus its current uncommitted worktree.
The original checkout, live containers, private credentials and Cloudflare
configuration were untouched. See [migration gates](docs/repository-migration.md).
