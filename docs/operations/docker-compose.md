# Install ProudAuth with Docker Compose

ProudAuth is one container image configured by environment variables. The
release installer is two files, `docker-compose.yaml` and `.env`, that run the
identity API, the background worker and their one-shot setup steps. PostgreSQL,
the HTTPS reverse proxy and the SMTP relay are yours; `.env` says where they are.
ProudAuth supplies identity APIs; your application supplies its sign-in interface.

Requirements:

- Docker Engine or Desktop with Compose v2 (`docker compose up --wait`).
- A PostgreSQL database whose user owns it (migrations run with it). PostgreSQL
  17 and 18 are tested.
- An HTTPS reverse proxy for your public origin, and an SMTP relay.

The image selects `linux/amd64` or `linux/arm64` automatically. This is a
pre-release; no external security review or conformance certification has been
completed.

## Download and verify

```sh
VERSION=v0.2.0-alpha.2
gh release download "$VERSION" --repo proudbase/proudauth \
  --pattern "proudauth-$VERSION-compose.tar.gz" --pattern SHA256SUMS
grep " proudauth-$VERSION-compose.tar.gz\$" SHA256SUMS | sha256sum -c -   # macOS: shasum -a 256 -c -
tar -xzf "proudauth-$VERSION-compose.tar.gz"
cd "proudauth-$VERSION-compose"
```

The archive holds `docker-compose.yaml`, `.env` (with the image already pinned
to this release), `LICENSE`, `NOTICE` and their `SHA256SUMS`. It is the
`deploy/prod/` folder of the source repository. Release provenance is described
in the [installation runbook](installation.md).

## Configure

Fill every empty value in `.env`, then make it private:

| Variable | Value |
| --- | --- |
| `PROUDAUTH_PUBLIC_ORIGIN` | Your HTTPS origin, for example `https://id.example.com`. It becomes the issuer of the realm when the realm is created; choose it once. |
| `PROUDAUTH_DATABASE_URL` | `postgres://USER:PASSWORD@HOST:5432/DB?sslmode=require`. PostgreSQL on the Docker host is `host.docker.internal`. |
| `PROUDAUTH_ROOT_KEY` | `openssl rand -hex 32`. Back it up with the database: without it, the stored keys cannot be read. |
| `PROUDAUTH_SMTP_HOST`, `PROUDAUTH_SMTP_USERNAME`, `PROUDAUTH_SMTP_PASSWORD`, `PROUDAUTH_EMAIL_FROM` | Your SMTP relay and an authorized sender address. |

```sh
chmod 600 .env
```

[Every variable](environment.md) is documented. Compose refuses to start while
a required value is empty, and the image refuses development settings in
production: plain HTTP origins, unencrypted SMTP, insecure cookies or debug logs.

## Start

```sh
docker compose up -d --wait
docker compose ps
```

Each start runs `migrate` (database migrations) and then `realm` (creates the
`main` realm when it is missing) as one-shot containers, then the server and the
worker. Once done, both setup steps change nothing. The containers run as UID
65532 with a read-only filesystem, no capabilities and no privilege escalation.

Point your reverse proxy at `PUBLIC_BIND:PUBLIC_PORT` (default
`127.0.0.1:8080`), terminating HTTPS for `PROUDAUTH_PUBLIC_ORIGIN` and forwarding
the original `Host` header: any other host is answered with `421`. To pass client
addresses in `X-Forwarded-For`, set `PROUDAUTH_TRUSTED_PROXIES` to the proxy's
address as the container sees it; for a proxy on the Docker host that is the
network gateway:

```sh
docker network inspect proudauth_default --format '{{(index .IPAM.Config 0).Gateway}}'
```

The private operator listener (`/status`, `/metrics`) is not published.

## First administrator

Once, create the administrator and set its password with the one-time token it
prints, then sign in. The first sign-in enrolls an authenticator app (TOTP) and
verifies the email address:

```sh
docker compose exec server identity-cli bootstrap -realm main -email you@example.com -username admin
docker compose exec server identity-cli setup-account --url https://id.example.com --realm main
docker compose exec server identity-cli login --url https://id.example.com --realm main
```

Use the username at the first login prompt: the email address becomes a sign-in
identifier once verified. Applications then sign users in through
[the headless API](../protocols/headless-authentication.md) or the browser flow
with their own login UI.

## Upgrade

Back up the database and keep the root key, set `PROUDAUTH_IMAGE` in `.env` to
the new release, review the migration plan, then start again:

```sh
docker compose pull
docker compose run --rm migrate -plan
docker compose up -d --wait
docker compose exec server identity-cli doctor
```

A contract (destructive) migration refuses to run without the verified backup's
identifier: run `docker compose run --rm migrate -backup-reference <backup-id>`
before `up`. See [upgrades](upgrades.md).

## Stop and inspect

```sh
docker compose logs --tail=100 server worker
docker compose down
```

Your data stays in your PostgreSQL. Do not copy credentials or logs with
sensitive operational data into issue reports.

## Development stack

`deploy/dev/` in the source repository has the same two files with development
values, plus PostgreSQL, a Mailpit mail catcher and Swagger UI. Nothing needs to
be filled in:

```sh
cd deploy/dev
docker compose up -d --build --wait
```

The API is at `http://localhost:8080`, every email at `http://localhost:8025`,
Swagger UI at `http://localhost:8081` and the operator listener at
`http://127.0.0.1:9090/status`. `docker compose down -v` deletes its data.

## Limits of this installer

- Secrets placed directly in `.env` reach the containers as environment
  variables, which `docker inspect` shows to anyone with Docker access. Where
  that matters, mount secret files and use `file:` references instead, for
  example `PROUDAUTH_ROOT_KEY=file:/run/secrets/root_key`.
- One database user both migrates and serves. Separate schema-owner and runtime
  roles (OPS-013) need the YAML configuration in the
  [installation runbook](installation.md).
- It is a single node: database high availability, TLS termination, backups,
  key rotation and disaster recovery remain yours.

[Full installation](installation.md), [configuration](configuration.md),
[backup/restore](backup-restore.md), [keys](keys.md), [upgrades](upgrades.md),
[benchmarks](benchmarks.md#reference-results) and [capacity](capacity.md).
DEP-002, DEP-003, DEP-004, DEP-006; capacity measurement: NFR-003..NFR-008.
