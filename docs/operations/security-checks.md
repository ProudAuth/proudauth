# Security checks and their exceptions

Requirements: QA-002 (static and dependency checks with triaged exceptions),
SEC-016 (supply-chain safeguards), DEP-003 (immutable, pinned artifacts).
This page lists every automated check, what it covers, and every exception
to it with its reason. An exception not listed here is a defect: report it
like any other ([CONTRIBUTING.md](../../CONTRIBUTING.md)). Changes to this
page need a security reviewer (`.github/CODEOWNERS`).

## Checks

| Check | Where | Covers | Fails on |
| --- | --- | --- | --- |
| Build, `go vet`, `gofmt` | CI job `test` | All Go code | Any error or unformatted file |
| Go tests against PostgreSQL | CI job `test` | Unit, contract and end-to-end tests, including `TestRequirementsTraceability` (every plan requirement has evidence, [requirements-traceability.md](../requirements-traceability.md)) and `TestReleaseToolchainPinned` | Any failure |
| Fuzz smoke | CI job `test` (15–30 s per target) | Redirect matching and registration, email and domain canonicalization, duplicate JSON keys, policy definitions, trace headers, the egress policy, claim mappings; SDK verifier fuzzing is owned by the Go SDK | A crash |
| Secret scan | `scripts/check-secrets.sh`, CI job `checks` | Every tracked and untracked file except the exceptions below | Private keys, ProudAuth token formats, webhook secrets, cloud and chat tokens |
| License policy | `scripts/check-licenses.sh`, CI job `checks` | Every Go module that provides a package to the binaries or their tests | A module outside Apache-2.0, MIT, BSD-2/3-Clause, ISC or MPL-2.0, a module without a license file, or a module missing from the module cache |
| Vulnerability review (source) | `govulncheck ./...`, CI job `checks` | Reachable vulnerabilities in Go code and its modules | Any reachable vulnerability |
| Vulnerability review (binaries) | `govulncheck -mode=binary`, CI job `image` and the release workflow | The shipped binaries, every platform in a release | Any vulnerability in the binary |
| Static analysis | `staticcheck`, CI job `checks` | All Go code | Any finding |
| Kubernetes manifests | `make k8s-validate`, CI job `checks` | `deploy/kubernetes` renders | A render error |
| Independent SDK CI | Five public [SDK repositories](../integrations/sdk-compatibility.md) | Go race tests and verifier fuzzing; Node type checks, dependency audit and tests; Dart analysis, format and tests; PHP syntax/strict tests and Composer validation; .NET locked restore/build/tests/format/packages on three operating systems | Any check failure in the owning repository |
| SDK contract ownership | `TestSDKRepositoryBoundaries` | Normal pinned Go module, successful immutable SDK CI snapshots and matching synthetic contract hashes ([evidence](../integrations/sdk-repositories.json)) | A local replacement, missing pipeline check, stale source/workflow metadata or mismatched fixture |
| Image smoke test | CI job `image` (`scripts/smoke-test.sh`) | The image starts read-only in the Compose stack: liveness, readiness, discovery, JWKS, and the password grant refused | Any failure |
| Contribution provenance | CI job `dco` | Every commit of a pull request carries `Signed-off-by` | A missing sign-off |
| Dependency updates | `.github/dependabot.yml`; each SDK owns its update rules | Service Go modules (including the pinned Go SDK), GitHub Actions, Docker base images; language dependency manifests in standalone SDKs | Reviewed pull requests, not a gate |

## Exceptions

| Exception | Scope | Reason | Compensating control | Revisit when |
| --- | --- | --- | --- | --- |
| Secret scan skips `tests/`, `*_test.go`, `docs/` | Test fixtures, documentation examples | These hold test-only keys and example values on purpose (fixtures say so in their README); scanning them would make the check permanently red | Code review; production configuration refuses literal secrets in YAML (`Validate()`), and the committed `deploy/prod/.env` must stay empty (`TestDeployDevAndProd`) | A real secret is ever found in an excluded path |
| Shared contract fixture keys are excluded as test data | `tests/fixtures/sdk-contracts/` | The vectors pin signature behaviour; keys sign nothing real | README marks every key test-only; pinned SDK snapshots check both JSON fixture hashes | A fixture gains real operational data or keys |
| `npm audit` fails only on high and critical | Independent `proudauth-sdk-node` | The SDK has no runtime dependencies; advisories affect TypeScript and type packages used to build and test | Dependency-update reviews; low and moderate advisories are reviewed there | The SDK gains a runtime dependency |
| No automated license check for npm, pub and Composer dependencies | Independent Node, Dart and PHP SDK repositories | Node.js and PHP have no runtime dependencies; Dart's are `crypto` and `http` (BSD-3-Clause, Dart team) | Dependency changes are reviewed in the owning SDK repository | Any SDK gains a runtime dependency |
| No dedicated vulnerability scanner for Dart and PHP in CI | Independent Dart and PHP SDK repositories | PHP has none; Dart dependencies receive advisory/update review | Owning SDK dependency alerts and pull requests | Either SDK gains further runtime dependencies |
| No static analyser for PHP beyond `php -l` | Independent `proudauth-sdk-php` | No additional PHP analysis tool is pinned yet | `declare(strict_types=1)`; warnings/deprecations fail tests on PHP 8.2 and 8.5 | Before a PHP package registry release |
| CI does not scan the image's OS layer | `gcr.io/distroless/static-debian12:nonroot` | The base has no package manager or shell; the binaries are static | The local Grype profile below found zero OS-package matches; release SBOM attestations and Dependabot retain their separate controls | Before each release |

## Base-image pins — 2026-10-13

The Dockerfile's two base images now carry immutable OCI index digests
(DEP-003, SEC-016), read from locally cached Docker image descriptors:

| Base | SHA-256 index digest |
| --- | --- |
| `golang:1.27.2-trixie` | `e58d6f83b3416618d8bcac2b3dde1b7f7e3c4a77d25e88637f8bbae81536c48d` |
| `gcr.io/distroless/static-debian12:nonroot` | `afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` |

The cached builder reports `GOLANG_VERSION=1.27.2`, matching the release
workflow; both descriptors are OCI indexes. No registry lookup or image
download was used. `TestReleaseToolchainPinned` checks version alignment
and immutable base references. Pinning is not a current vulnerability scan,
an image build/smoke result or independent reproduction; those retain their
separate gates. Dependabot should review digest updates with the version tags.

## Two-OS binary reproduction — 2026-10-13

The frozen development checkout now has a measured macOS/Linux binary
reproduction profile (M0, DEP-003, SEC-016). **All 12 release targets are
byte-identical** across the host and a separate Linux container, on both
an initial run and an independent invocation of the final runner:

| Target platform | `identity-server` SHA-256 prefix | `identity-worker` prefix | `identity-cli` prefix | Result |
| --- | --- | --- | --- | --- |
| Linux amd64 | `930690b409fc` | `9c76f1b85e77` | `524969383118` | identical |
| Linux arm64 | `fdfb3127b59c` | `5c0ce64465d0` | `fb2dc2452f54` | identical |
| Darwin amd64 | `aa58d509e8b9` | `1aa40e4c71b4` | `815b47083ca2` | identical |
| Darwin arm64 | `35d29d799d46` | `a1e1458b8fce` | `6cc1afffd4cb` | identical |

[Full hashes and comparison](release-results/2026-10-13-repro/comparison.json),
[frozen input manifest](release-results/2026-10-13-repro/source-snapshot.json)
[host toolchain](release-results/2026-10-13-repro/host-toolchain.txt),
[scoped verification](release-results/2026-10-13-repro/verification.json)
and [artifact hashes](release-results/2026-10-13-repro/artifact-sha256.json)
identify 504 source/input files, version `dev-repro-20261013`, and snapshot
SHA-256 `1f0e4064801707023be84691cb60db9a47369b46df80d3b15c3ba818ae49b89b`.
The final comparison completed at `2026-10-12T22:14:28.120724Z`
(2026-10-13 local time). `identity-bench` is outside this release target set.

**Environment:** Mac16,8 / Apple M4 Pro, 12 CPUs, 24 GiB, macOS 27.0.1
(26A434), Darwin 27.0.0; the Docker Desktop Linux VM shares the host.
Both compilers report **Go 1.27.2**. The installed host Go remains 1.27.1;
the runner bootstraps a temporary Darwin toolchain from the Go source in
the pinned cached builder image. The Linux compiler is the image's supplied
binary. The image reference/digest is the Go base above, with its untagged
repository digest resolved locally. No tag, module or toolchain is downloaded.
The two builders use separate writable caches and one frozen source tree;
Linux mounts the populated module cache read-only and has network `none`.
Proxy/sumdb/toolchain downloads are disabled before Go preflight. Caller
workspaces, flags and experiments are cleared.

Flags match the release profile: `CGO_ENABLED=0`, `GOAMD64=v1`,
`GOARM64=v8.0`, `-mod=readonly -buildvcs=false -trimpath`, and
`-ldflags="-s -w -buildid= -X main.version=dev-repro-20261013"`.
The container, temporary SDK, both caches, input copy and all 24 built
binaries are removed; only hashes and metadata remain.

Reproduce using the cached image and modules:

```sh
REPRO_VERSION=dev-repro-20261013 \
  REPRO_OUT="$PWD/repro-results/private-run" make repro-local
```

`REPRO_OUT` must be fresh or empty. The executable orchestration regression
checks an untagged cached digest, download/flag isolation, all 12 outputs,
one deliberately different binary, wrong SDK/version refusals and owned
resource cleanup. Three race repetitions pass (three top-level executions,
12 subtests, 6.527s); controlled compilers check the wrapper, while the
published real builds establish byte equality.
All 41 contract checks and 16 subtests pass (33.584s), with vet,
formatting, shell/Make recipe, secret and license checks. Two evidence
rows match the complete isolated preview; the protected traceability
contract is unchanged. Earlier full-module checks retain their own build.

**One physical host, two OS environments.** This is a frozen development
binary profile, not a tagged release, off-host/independent-organization build,
container-image or archive reproduction, current vulnerability audit,
provenance attestation or qualified security review. Release/package evidence
and remaining supply-chain gates retain their own scope.

## Current dependency and supply-chain checks — 2026-10-13

[Structured results](release-results/2026-10-13-assurance.json) record Go
1.27.2, Staticcheck 2026.2.2, govulncheck v1.8.0, source hashes and exact
upstream references (QA-002, SEC-016, DEP-003):

| Check | Result |
| --- | --- |
| Staticcheck on all Go packages and tests | Pass, zero findings after resolving 20 unused-code/style/deprecation findings |
| Go source vulnerability scan | Pass, zero reachable or imported-package findings |
| All 12 server/worker/CLI targets (Linux/macOS, amd64/arm64) | Pass, all builds and symbol-bearing binary vulnerability scans |
| npm audit of the unchanged SDK lock | Pass, zero advisories in all severity categories |
| External workflow Actions | Eight actions resolved to full commit SHAs; all 25 references pinned with their previous tag as a comment |
| Dockerfile frontend | `docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e`, verified against the registry manifest bytes |

The prior Staticcheck 2025.1.1 pin fails to decode Go 1.27 export-data
version 5. The tested [stable 2026.2.2 release](https://github.com/dominikh/go-tools/releases/tag/2026.2.2)
replaces it; CI's checks stay enabled. Contract checks reject floating
action references and an unpinned Dockerfile frontend.

The [canonical Go vulnerability database](https://go.dev/doc/security/vuln/database)
was downloaded for these checks; its modification time is
`2026-10-08T22:31:09Z`, with the zip's download time and hash recorded
separately. Final source and binary scans use this frozen database explicitly
through `-db`. Earlier HTTP scan output retains its separate scope.

**Triage:** [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) concerns the
unmaintained OpenPGP packages in `golang.org/x/crypto`, with no known fixed
version. It appears only at module level: none of those packages occurs in
the current 498-package dependency graph, including tests, or any scanned
binary. The required Argon2/bcrypt dependency remains; no scanner suppression
is configured. Reassess this disposition if the dependency graph changes.
These checks establish snapshot results. The local image and SBOM profile
below adds artifact evidence; official signatures/provenance and publication
retain their separate gates.

## Local image and release preparation — 2026-10-13

[Frozen verification](release-results/2026-10-13-local-preparation/verification.json),
[image checks](release-results/2026-10-13-local-preparation/image-check.json)
and [asset hashes](release-results/2026-10-13-local-preparation/assets.json)
record development version `dev-check-20261013-9e46df90789bcd6d` on Go 1.27.2.
The actual Dockerfile and its immutable references were used (SEC-016,
DEP-003, DEP-004, DEP-017). Necessary scanner/build downloads were authorized;
runtime checks used dedicated containers and a fresh database.

| Check | Result |
| --- | --- |
| Linux arm64 image in production mode | Pass: TLS with hostname verification, non-root UID/GID 65532, read-only root, all capabilities dropped, no new privileges |
| Image smoke | Liveness/readiness/discovery/JWKS: 200; anonymous password grant: 401; implicit flow: 400; worker tasks: exit 0, no errors |
| Image's three symbol-bearing binary scans | Pass: zero reachable or imported-package findings |
| Image OS inventory with Grype 0.120.1 | Zero OS-package vulnerability matches; Debian 12 identified, database built `2026-10-12T06:45:22Z` |
| Stripped binary builds | All 12 server/worker/CLI targets build; all three Linux arm64 image binaries equal their host cross-builds |
| Source and image SBOMs | SPDX 2.3: 166 source packages; 103 image packages including the image identity, 952 hashed files |
| Binary-only offline bundle | 582 internal file checksums verified, six Linux binaries match the release-profile builds, no local secret paths included |

The [source SBOM](release-results/2026-10-13-local-preparation/source-sbom.spdx.json)
excludes local operational secrets and build output. The
[image SBOM](release-results/2026-10-13-local-preparation/image-sbom.spdx.json)
records the final smoke-tested image. The
[Grype result](release-results/2026-10-13-local-preparation/grype-results.json)
contains three module-level GO-2026-5932 matches, one per stripped binary;
the affected OpenPGP packages remain absent, as triaged above. No findings
are suppressed. The scanned earlier image and final image have equal hashes
for all 952 files and equal inventories of 102 package instances, with
[comparison evidence](release-results/2026-10-13-local-preparation/catalog-equivalence.json).
Their manifest/config identities differ between local builds.

In the repository migration export, two personal cache-directory paths in the
Syft catalogue's tool descriptor are redacted. Package/file inventory and image
identity are unchanged; original source/image SPDX SBOM bytes are unchanged.
[Export provenance](release-results/export-provenance.json) records the new
catalogue and artifact-manifest hashes. No release signature or attestation is
claimed to survive these changed metadata bytes.

The database uses PostgreSQL 18.6, `shared_buffers=128MB`,
`max_connections=80`, 2 GiB tmpfs and a dedicated Docker network. Its
`postgres` role and unencrypted database transport are local smoke fixtures;
SMTP is configured but delivery and administrator sign-in are outside this
image smoke. The recorded configuration uses file references and contains
no secret values. This is one laptop and one image architecture.

Containers, images and newly created build-cache records are removed; all
868 pre-existing cache records remain. Temporary binaries/archives and
private scanner caches are removed after verification. Hashes and SBOMs
are retained. **This is local preparation, not a published release:** no
commit/tag, upload, release signature or trusted provenance attestation was
created. Unsigned BuildKit metadata is not a CI attestation (GOV-005).

## Open items

These are known gaps, not accepted exceptions:

- **Qualified independent security review has not happened.** The
  [review scope](../threat-models/review-scope.md) is ready. The owner
  [excluded this condition from the 2026-10-13 delivery gate](../plan.md#354-delivery-checkpoint--2026-10-13).
  Internal correctness tests and build reproduction establish their own
  evidence; no independent review has been performed or claimed.
- **Off-host release and image reproduction remain unverified.** The
  two-OS development binary profile above is measured on one physical host;
  no independent machine/organization has reproduced an official release,
  container image or offline archive.
- **Historical release evidence remains snapshot-scoped.** The local records
  above predate a version tag and do not establish hosted signatures or
  attestations. The owner subsequently authorized the public repository split
  and an initial prerelease. Every published version must pass the complete
  configured workflow; its actual binaries, images, SBOMs, signatures and
  hosted attestations are checked on the service's
  [Releases page](https://github.com/proudauth/proudauth/releases). SDK source
  publication and successful independent CI do not establish a package
  registry release or replace service release evidence.
