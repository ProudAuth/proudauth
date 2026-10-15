# ProudAuth

**Identity infrastructure you can host and control.**

ProudAuth is an Apache-2.0 identity provider written in Go, backed by PostgreSQL.
It combines OAuth 2.0 and OpenID Connect, organizations, authentication,
authorization and audit evidence in one service, with a background worker and an
operator CLI. Applications provide their own sign-in interface and enforce their
business permissions.

[Website](https://proudauth.com) · [Documentation](https://proudauth.com/docs/) ·
[API contract](api/openapi/proudauth.yaml) · [Benchmarks](docs/operations/benchmarks.md#reference-results) ·
[Security](SECURITY.md)

**Current release: `v0.2.0-alpha.1` (pre-release).**
[Release assets](https://github.com/proudbase/proudauth/releases/tag/v0.2.0-alpha.1) ·
[Container package](https://github.com/orgs/proudbase/packages/container/package/proudauth) ·
[Docker Hub](https://hub.docker.com/r/mohamadalialghanem/proudauth)

## Why ProudAuth

| Capability | Service behavior |
| --- | --- |
| Standards | OAuth 2.0 / OpenID Connect, authorization code with mandatory PKCE, rotating refresh tokens, client credentials, discovery and JWKS |
| Authentication | Headless transactions, passwords, passkeys, TOTP, recovery and authentication policies |
| B2B identity | Realms, organizations, memberships, invitations, groups and delegated administration |
| Authorization | Scoped roles, restrictive attribute policies, relationship decisions and controlled support impersonation |
| Integration | OIDC/SAML federation, SCIM, directory integration, workload federation, signed webhooks and hooks |
| Operations | Transactional audit evidence, backup/restore tooling, private metrics, migrations and resource budgets |

The [capability inventory](docs/service-status.md) records implementation details
and gaps. A configuration key or table alone is not a supported feature.
No external security review or conformance certification has been completed.
This pre-release software is not a production-hardening approval.

## Install the release with Docker Compose

Requires Docker/Compose v2, POSIX `sh` and Python 3.9+. No Go compiler or source
checkout is needed. Pull the versioned image from either registry:

```sh
docker pull ghcr.io/proudbase/proudauth:0.2.0-alpha.1
# Docker Hub mirror:
docker pull mohamadalialghanem/proudauth:0.2.0-alpha.1
```

Download `proudauth-v0.2.0-alpha.1-compose.tar.gz` and `SHA256SUMS` from the
[release](https://github.com/proudbase/proudauth/releases/tag/v0.2.0-alpha.1),
verify the archive's checksum, extract it and enter its directory. It contains
the maintained `docker-compose.yaml`, adjacent `.env` examples and initializer:

```sh
tar -xzf proudauth-v0.2.0-alpha.1-compose.tar.gz
cd proudauth-v0.2.0-alpha.1-compose
./init.sh demo
# This quickstart uses the default host ports 8080 and 9090.
docker compose config --quiet
docker compose pull
docker compose up -d --wait
curl --fail http://localhost:8080/health/ready
docker compose exec server /usr/local/bin/identity-cli realm-create -name main
docker compose exec server /usr/local/bin/identity-cli bootstrap \
  -realm main -email admin@example.test -username root-admin
docker compose exec server /usr/local/bin/identity-cli setup-account \
  --url http://localhost:8080 --realm main
docker compose exec server /usr/local/bin/identity-cli login \
  --url http://localhost:8080 --realm main
```

The demo uses loopback HTTP and a private email sink. At the first login prompt,
use the bootstrap username `root-admin`; its email is not a sign-in identifier
until verified.
If you change the demo public port, complete setup/login with the
[released host CLI](deploy/release/README.md#nondefault-local-ports) using the
exact configured origin; container-local port 8080 is not a substitute issuer.

For production, copy
`.env.example` to `.env`, set **your** HTTPS issuer and real SMTP settings, store
your SMTP password in the private file and run `./init.sh production`.
The production profile uses Secure cookies, file-backed secrets and separate
schema-owner/runtime database roles. PostgreSQL has no host port; the operator
listener always binds to host loopback.

Follow the [complete Compose installation](deploy/release/README.md) for
verification, first administrator TOTP/email enrollment, proxying, persistence
and upgrades. [Every `.env` variable and secret file](docs/operations/environment.md)
is documented. Applications supply their own sign-in UI; `proudauth.com` hosts
project information and documentation. The pre-release does not establish
production hardening, external security review or certification.

## Develop from source

Requires the Go version in [go.mod](go.mod), Docker with Compose v2 and available
host ports. The default development stack uses HTTP and a private email sink.
Building from source may download dependencies or images.

```sh
git clone https://github.com/proudbase/proudauth.git
cd proudauth
make dev
```

In another terminal:

```sh
docker compose -f deploy/compose/compose.yaml exec server /usr/local/bin/identity-cli realm-create -config /etc/proudauth/config.yaml -name main
docker compose -f deploy/compose/compose.yaml exec server /usr/local/bin/identity-cli bootstrap -config /etc/proudauth/config.yaml -realm main -email admin@example.test -username root-admin
go build -o bin/identity-cli ./cmd/identity-cli
./bin/identity-cli setup-account --url http://localhost:8080 --realm main
./bin/identity-cli login --url http://localhost:8080 --realm main
```

Keep the one-time setup token private. First administrator sign-in requires email
verification and TOTP enrollment. Development email is available only on the
private operator listener at `127.0.0.1:9090`.

- API: `http://localhost:8080`
- Readiness: `http://localhost:8080/health/ready`
- Discovery: `http://localhost:8080/realms/main/.well-known/openid-configuration`

Browser sign-in requires your application's login UI;
[the headless API guide](docs/protocols/headless-authentication.md) explains the
flow. [deploy/](deploy/README.md) runs the same image from a `.env` file:
`dev/` with every local dependency, `prod/` with only ProudAuth.
Production requires HTTPS, SMTP, separated database roles and the
[installation runbook](docs/operations/installation.md).

## Build a Docker image

```sh
make image VERSION=0.2.0-alpha.1
# Equivalent:
docker build --build-arg VERSION=0.2.0-alpha.1 -t proudauth:0.2.0-alpha.1 .
```

The image includes `identity-server`, `identity-worker` and `identity-cli`.
The distroless runtime runs as non-root UID/GID 65532, with digest-pinned Go and
runtime images. Building locally does not publish a release. The release
workflow gates publication on CI, then produces checksums, SBOMs, image
signatures and provenance. Use the published immutable digest and verification
assets for deployment; a locally built image is not a signed release image.

## Measured reference results

The original 60-second runs used concurrency 32, 10,000 users, 500 small
organizations, one 5,000-member organization, 20 clients and 1,000 group members.
Latencies are histogram estimates in milliseconds.

| Scenario | Operations/s | p50 | p99 | p99.9 | Outcome |
| --- | ---: | ---: | ---: | ---: | --- |
| Client credentials | 1,036.6 | 30.72 | 38.91 | 47.10 | Pass |
| Introspection | 2,038.1 | 15.87 | 21.50 | 36.86 | Pass |
| Password login | 47.1 | 688.13 | 851.97 | 1,179.65 | Pass |
| Refresh | 815.2 | 38.91 | 55.30 | 73.73 | Pass |
| Policy | 736.9 | 43.01 | 57.34 | 102.40 | Pass |
| Mixed | 553.8 | 34.82 | 409.60 | 458.75 | Pass |

Environment: Apple M4 Pro / Mac16,8, 12 CPUs, 24 GiB, macOS 27.0.1,
Go 1.27.1 and PostgreSQL 18.6. Server, worker, database and generator shared one
laptop. These numbers refer to the recorded original development builds, not
this migration snapshot. They are **not guarantees or sizing advice**.

The [full report](docs/operations/benchmarks.md) includes all workload,
adversarial and extended scenarios, outcomes, criteria, configuration, soaks
and initial failures with corrections. [Raw artifacts](docs/operations/bench-results/)
retain numeric results and build hashes. Local paths in exported copies are
redacted with [provenance](docs/operations/bench-results/export-provenance.json).

```sh
# Temporary database/processes; cached images/modules, Docker, Go, curl,
# jq and python3 required. The runner disables downloads.
make bench-local
```

Read [capacity notes](docs/operations/capacity.md) before choosing a deployment
size. Benchmarks implement the NFR-003..NFR-008 measurement requirements.

## SDK ecosystem

SDKs are maintained in independent repositories:

| Language | Repository |
| --- | --- |
| Go | [proudauth-sdk-go](https://github.com/proudbase/proudauth-sdk-go) |
| Node.js / TypeScript | [proudauth-sdk-node](https://github.com/proudbase/proudauth-sdk-node) |
| Dart | [proudauth-sdk-dart](https://github.com/proudbase/proudauth-sdk-dart) |
| PHP | [proudauth-sdk-php](https://github.com/proudbase/proudauth-sdk-php) |
| .NET | [proudauth-sdk-dotnet](https://github.com/proudbase/proudauth-sdk-dotnet) |

The landing page and documentation renderer are maintained in
[proudauth-website](https://github.com/proudbase/proudauth-website).

## Develop and contribute

```sh
make build
make test-unit
make test-e2e   # requires PROUDAUTH_TEST_DATABASE_URL
make lint
```

Database tests skip without `PROUDAUTH_TEST_DATABASE_URL`; a fast successful run
is not full end-to-end validation. Repository ownership and SDK contracts are
recorded in [repository-migration.md](docs/repository-migration.md).
Read [CONTRIBUTING.md](CONTRIBUTING.md), [architecture decisions](docs/architecture-decisions/README.md)
and [security reporting](SECURITY.md). Contributions require DCO sign-off.

## License

[Apache License 2.0](LICENSE). One complete service edition, no paid feature gate
and no mandatory project cloud. Hosting, email, backups and operational work
still have costs. Attribution is in [NOTICE](NOTICE).
