# Restricted-network and air-gapped installation

Requirements: OSS-003, OSS-005, DEP-017, TEST-072 (docs/plan.md §30.1
"Restricted-network / air-gapped" profile).

## What the core needs at runtime

| Dependency | Needed for | Offline option |
| --- | --- | --- |
| PostgreSQL | Everything | Local instance |
| SMTP relay | Verification, password reset, invitations, magic links, security notices | A relay inside the network. Production mode refuses the development sink. |
| SMS gateway (optional) | SMS sign-in codes | An operator-run HTTPS gateway inside the network |
| DNS | Resolving the database, SMTP and webhook hosts; organization domain verification (TXT lookups when an administrator calls verify, and hourly by the worker's `domains.recheck` task for verified domains that are due) | Internal resolvers. Re-checks need the same TXT records as verification: if they stop resolving, verified domains lapse after realm policy `domains.lapse_after_failures` daily retries |

No project-operated service is contacted: there is no license check, activation,
update check or telemetry in the code (`privacy.telemetry_opt_in: true` is a
configuration error). Startup, login, token issuance, key rotation, migrations,
backups tooling and administration work without Internet access.

Outbound connections happen only to destinations an operator configures: the SMTP
relay, the SMS gateway (`delivery.sms.webhook_url`), webhook subscriptions,
back-channel logout URIs of registered clients and upstream identity providers.
Everything except SMTP goes through the egress policy, which by default refuses
private, loopback and link-local addresses. Inside an isolated network you will
usually need `delivery.egress_allowlist` with your internal CIDRs (webhooks,
back-channel logout, SMS gateway). Upstream identity providers do not use that
allowlist: set `federation.egress_allowlist` to the specific internal
provider CIDRs in production. The broad `federation.allow_private_network`
switch is rejected in production. `federation.ca_file` adds a private CA for
upstream TLS; HTTPS certificate and destination checks still apply.

LDAP and Active Directory servers of directory connectors are reached
through their own allowlist, `directory.egress_allowlist` (private CIDRs of
your domain controllers; `directory.allow_private_network` is rejected in
production), with `directory.ca_file` for a private CA
([directory.md](../integrations/directory.md#connections-tls-and-failover)).
Outbound SCIM connectors use the delivery allowlist. SAML needs no outbound
connection at all: metadata is uploaded, never fetched, and messages travel
through the user's browser ([saml.md](../integrations/saml.md)).

Password screening uses the embedded common-password list plus an optional
operator file (`security.password.blocklist_file`); no external breach service is
called (SEC-013).

`TestOfflineOperation` (`tests/e2e/network_test.go`, TEST-072) runs bootstrap,
sign-in, token issuance, administration and every worker task with all
non-loopback network access blocked: nothing phones home.

## Offline bundle

`make bundle VERSION=<version>` runs `scripts/offline-bundle.sh` on a connected
build host (Go toolchain and module cache required) and writes
`dist/proudauth-<version>-offline.tar.gz` plus a `.sha256` file. The bundle
contains:

- static `identity-server`, `identity-worker` and `identity-cli` binaries for
  Linux amd64 and arm64 (`bin/linux-<arch>/`);
- `migrations/` (for review; the binaries embed them), `deploy/` (Compose,
  Kubernetes, example production configuration; local development secrets are
  removed), `api/` (OpenAPI and JSON Schemas);
- `docs/` (architecture decisions, operations, threat models, protocols,
  integrations), `LICENSE`, `NOTICE`, `README.md`, `SECURITY.md`, `CHANGELOG.md`;
- `source-notes/` (module list, Go version, commit);
- `image-<version>.tar.gz` when `IMAGE=<image reference>` is set; Docker and
  that image must already be available locally. Inspection/export failures
  fail the build; no image is pulled;
- `SHA256SUMS` over every file and `VERIFY.md` with verification steps.

The bundle does not include a PostgreSQL image, an SBOM or provenance; the release
workflow produces an SBOM and build-provenance attestations separately. No release
has been published yet.

Version labels must start with a letter or digit and contain only letters,
digits, dot, underscore, plus or hyphen. `BUNDLE_OUT=<directory>` selects
the output directory (default `dist`). The script builds in a private
staging directory and checks image export before compression. Build/export
failures and interruptions preserve the previous archive/checksum pair;
failed publication restores it. A per-version output lock refuses concurrent
writers. Cleanup removes only the invocation's staging directory and lock.

### Local verification — 2026-10-13

[Structured results](release-results/2026-10-13-offline-bundle.json) record
three race-detector repetitions of build/export/hash/publication failures,
unsafe labels, interruption, concurrent writers and archive checksums
(15 top-level executions, 36 subtests, 9.980s). All 40 contract checks
and 12 subtests pass (33.652s), with vet, shell syntax, secret and license
checks. A real offline cross-build with cached Go 1.27.1 produced six
Linux amd64/arm64 executable ELF binaries without dynamic interpreters.
The 50748410-byte temporary archive has 573 regular files, 572 covered by
its internal manifest plus the manifest itself; every digest and the outer
archive checksum matched. Development Compose secrets and macOS AppleDouble
members are absent. The archive was removed after verification.

This is local development evidence, not a tagged release, Linux runtime
installation, container-image export, independent builder, current
vulnerability audit or SBOM/provenance attestation. The release workflow
retains its separate Go 1.27.2 toolchain and gates. Nothing was downloaded.

On the offline host:

```sh
sha256sum -c proudauth-<version>-offline.tar.gz.sha256
tar -xzf proudauth-<version>-offline.tar.gz && cd proudauth-<version>-offline
sha256sum -c SHA256SUMS
gunzip -c image-<version>.tar.gz | docker load     # if the image was included
```

Then follow [installation.md](installation.md) from step 2.

Building from source offline requires the Go toolchain and a populated module
cache (`go mod download` on a connected host, then copy `$(go env GOMODCACHE)`), or
`go mod vendor` and `-mod=vendor`. The container build also needs the base images
named in the `Dockerfile` mirrored into your registry.

## Not available offline

- Email providers, SMS gateways and webhook receivers outside the network.
- Upstream social or enterprise identity providers outside the network.
- Development tooling that downloads tools: `make vuln`, `make sbom`, CI's
  `staticcheck`.

## Upgrades offline

Repeat the bundle process for the new version, verify checksums, then follow
[upgrades.md](upgrades.md).
