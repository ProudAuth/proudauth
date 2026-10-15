<p align="center">
  <a href="https://proudauth.com"><img src="https://raw.githubusercontent.com/ProudAuth/.github/main/assets/banner-proudauth.png" alt="ProudAuth: your identity server. Free. Private. Yours." width="100%"></a>
</p>

<p align="center">
  <a href="https://github.com/ProudAuth/proudauth/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/ProudAuth/proudauth?include_prereleases&label=release&style=for-the-badge&labelColor=06120e&color=3ee6b0"></a>
  <a href="https://github.com/ProudAuth/proudauth/pkgs/container/proudauth"><img alt="Docker image" src="https://img.shields.io/badge/docker-ghcr.io%2Fproudauth%2Fproudauth-3ee6b0?logo=docker&logoColor=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://github.com/ProudAuth/proudauth/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ProudAuth/proudauth/ci.yml?branch=main&label=ci&style=for-the-badge&labelColor=06120e"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
</p>

# ProudAuth

**Your own identity server. Free, private and on your infrastructure.**

ProudAuth is an open-source identity provider written in Go: sign-in with OAuth 2.0
and OpenID Connect, passkeys and MFA, organizations, roles and audit evidence, in
one Docker image. Your applications keep their own login screen.

[Quickstart](https://proudauth.com/docs/getting-started/quickstart/) ·
[Documentation](https://proudauth.com/docs/) ·
[Releases](https://github.com/proudauth/proudauth/releases) ·
[Container image](https://github.com/orgs/proudauth/packages/container/package/proudauth) ·
[Security](SECURITY.md)

**Current release: `v0.2.0-alpha.3`** (pre-release; no external security review yet).

## Install

You need Docker, a PostgreSQL database, an email (SMTP) account and a domain with HTTPS.

```sh
mkdir proudauth && cd proudauth
curl -fsSLO https://raw.githubusercontent.com/proudauth/proudauth/v0.2.0-alpha.3/deploy/prod/docker-compose.yaml
curl -fsSLO https://raw.githubusercontent.com/proudauth/proudauth/v0.2.0-alpha.3/deploy/prod/.env
```

Fill in the empty values in `.env`, then start:

```sh
docker compose pull
docker compose up -d
```

The [quickstart](https://proudauth.com/docs/getting-started/quickstart/) shows both
files to copy and creates your first administrator.

## What you get

- **Sign-in:** OAuth 2.0 / OpenID Connect with PKCE, passwords, passkeys, TOTP and a
  headless API for your own login UI.
- **Organizations:** realms, organizations, invitations, groups, roles and permissions.
- **Integrations:** OIDC and SAML federation, SCIM, signed webhooks and hooks.
- **Operations:** audit evidence, backups, migrations and private metrics.
- **SDKs:** [Go](https://github.com/proudauth/proudauth-sdk-go),
  [Node.js](https://github.com/proudauth/proudauth-sdk-node),
  [Dart](https://github.com/proudauth/proudauth-sdk-dart),
  [PHP](https://github.com/proudauth/proudauth-sdk-php) and
  [.NET](https://github.com/proudauth/proudauth-sdk-dotnet).

The [capability inventory](docs/service-status.md) lists what is implemented and
what is not; [benchmarks](docs/operations/benchmarks.md#reference-results) are
measured on one laptop and are not guarantees.

## Develop

```sh
git clone https://github.com/proudauth/proudauth.git && cd proudauth
make dev          # PostgreSQL, Mailpit and Swagger UI, image built from source
make test-unit
```

`deploy/dev` serves the API on `http://localhost:8080`, email on
`http://localhost:8025` and Swagger UI on `http://localhost:8081`. Read
[CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off required) and the
[architecture decisions](docs/architecture-decisions/).

## Build a Docker image

```sh
make image VERSION=0.2.0-alpha.3
# Equivalent:
docker build --build-arg VERSION=0.2.0-alpha.3 -t proudauth:0.2.0-alpha.3 .
```

The image includes `identity-server`, `identity-worker` and `identity-cli`.
The distroless runtime runs as non-root UID/GID 65532, with digest-pinned Go and
runtime images. Building locally does not publish a release. The release
workflow gates publication on CI, then produces checksums, SBOMs, image
signatures and provenance. Use the published immutable digest and verification
assets for deployment; a locally built image is not a signed release image.

## License

[Apache License 2.0](LICENSE). One complete service edition, no paid feature gate
and no mandatory project cloud. Hosting, email, backups and operational work
still have costs. Attribution is in [NOTICE](NOTICE).
