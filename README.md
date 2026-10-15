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

The release installer is two files: `docker-compose.yaml` and `.env`. They run
the published image; PostgreSQL, the HTTPS proxy and SMTP are yours.

```sh
VERSION=v0.2.0-alpha.2
gh release download "$VERSION" --repo proudbase/proudauth \
  --pattern "proudauth-$VERSION-compose.tar.gz" --pattern SHA256SUMS
grep " proudauth-$VERSION-compose.tar.gz\$" SHA256SUMS | sha256sum -c -
tar -xzf "proudauth-$VERSION-compose.tar.gz" && cd "proudauth-$VERSION-compose"
# Fill every empty value in .env (the root key: openssl rand -hex 32), then:
chmod 600 .env
docker compose up -d --wait
```

Every start applies migrations and creates the `main` realm when it is missing.
The image is also available as `ghcr.io/proudbase/proudauth` and on Docker Hub
as `mohamadalialghanem/proudauth`. Follow the
[Compose installation guide](docs/operations/docker-compose.md) for the reverse
proxy, the first administrator, upgrades and limits;
[every `.env` variable](docs/operations/environment.md) is documented.
Applications supply their own sign-in UI; `proudauth.com` hosts project
information and documentation. The pre-release does not establish production
hardening, external security review or certification.

## Develop from source

Requires the Go version in [go.mod](go.mod) and Docker with Compose v2.
`deploy/dev/` runs the same image from this checkout with PostgreSQL, a Mailpit
mail catcher and Swagger UI; its `.env` needs no editing.

```sh
git clone https://github.com/proudbase/proudauth.git
cd proudauth/deploy/dev
docker compose up -d --build --wait     # or, from the repository root: make dev
docker compose exec server identity-cli bootstrap -realm main -email admin@example.test -username root-admin
docker compose exec server identity-cli setup-account --url http://localhost:8080 --realm main
docker compose exec server identity-cli login --url http://localhost:8080 --realm main
```

Keep the one-time setup token private. The first administrator sign-in enrolls
TOTP and verifies the email address; the code arrives in Mailpit.

- API: `http://localhost:8080`
- Discovery: `http://localhost:8080/realms/main/.well-known/openid-configuration`
- Email: `http://localhost:8025`
- Swagger UI: `http://localhost:8081`

Browser sign-in requires your application's login UI;
[the headless API guide](docs/protocols/headless-authentication.md) explains the
flow. See [deploy/](deploy/README.md) for every deployment folder.

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
