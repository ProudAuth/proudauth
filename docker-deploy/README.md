# Deploy an existing ProudAuth image

This portable development profile runs PostgreSQL, migrations, the server,
worker and Swagger UI. It uses loopback HTTP and a private development email
sink. Production needs HTTPS, SMTP and the service installation runbook.
No private image archive, environment file or credentials ship with this folder.

## Prepare images and credentials

Build the service image from the repository root:

```sh
make image VERSION=0.2.0-local
```

PostgreSQL and Swagger images listed in `.env.example` must also be present
locally. Compose uses `pull_policy: never`; startup never downloads an image.
An operator-owned Docker image archive can be loaded with `load-images.sh`.
It is not included in this public-source candidate.

From this directory:

```sh
./init-env.sh
# Review .env: image tags, platform, ports and public origin.
./start.sh
```

`init-env.sh` creates a random database password and 32-byte root key with mode
0600; existing credentials are preserved. `prepare-secrets.sh` creates a private
0700 secret directory and read-only file mounts. The supplied example targets
linux/arm64; set `PROUDAUTH_PLATFORM` to the architecture of your locally built
image. Repeating startup preserves the database and existing realm.

| Local URL | Purpose |
| --- | --- |
| `http://localhost:8080` | Public identity API |
| `http://localhost:8080/health/ready` | Readiness |
| `http://localhost:8080/realms/main/.well-known/openid-configuration` | Discovery |
| `http://127.0.0.1:8081/` | Swagger UI |
| `http://127.0.0.1:9090/status` | Private operator status |

Public ports bind to loopback; PostgreSQL has no published host port.
The root API URL is not a built-in browser login page. Applications supply a
login UI or use [headless authentication](../docs/protocols/headless-authentication.md).

## First administrator

```sh
docker compose exec server /usr/local/bin/identity-cli bootstrap -realm main -email admin@example.test -username admin
PA_ORIGIN=$(sed -n 's/^PROUDAUTH_PUBLIC_ORIGIN=//p' .env)
docker compose exec server /usr/local/bin/identity-cli setup-account --url "$PA_ORIGIN" --realm main
docker compose exec server /usr/local/bin/identity-cli login --url "$PA_ORIGIN" --realm main
```

Keep the one-time token private. First sign-in requires TOTP and email
verification. In this development profile, verification messages appear only
on the private operator mailbox:
`http://127.0.0.1:9090/dev/mailbox?realm=main&recipient=admin@example.test`.
CLI credentials are kept in the container's private temporary directory;
log in again after recreating the container.

## HTTPS proxy or tunnel

`config.tunnel.yaml` is an example for an operator-controlled HTTPS proxy. It
uses a strict public host and Secure cookies while retaining development email.
Set these values in your private `.env`, using your own hostname and the exact
trusted proxy address observed in your deployment:

```dotenv
PROUDAUTH_PUBLIC_ORIGIN=https://id.example.com
PROUDAUTH_CONFIG_FILE=config.tunnel.yaml
PROUDAUTH_TRUSTED_PROXIES=<trusted-proxy-IP>/32
```

Publish only the public API listener; keep port 9090, metrics and email private.
Stored realm issuers do not change when `.env` changes. For an existing realm,
plan an explicit client/issuer transition; do not overwrite issuer rows as a
routine deployment step. This configuration is a development demonstration,
not a production SMTP profile.

## Persistence and shutdown

```sh
docker compose ps
docker compose logs --tail=100 server worker
docker compose down
```

The last command keeps the database volume. `docker compose down -v` permanently
deletes this deployment's identity data. PostgreSQL 18 stores its data beneath
the mounted `/var/lib/postgresql` volume root. Keep the root key alongside a
separately protected backup; changing it loses access to encrypted key material.
Changing `.env` does not rotate an existing PostgreSQL role's password.

The Swagger specification is a read-only copy of `api/openapi/proudauth.yaml`.
After API changes, refresh it from the repository root:

```sh
cp api/openapi/proudauth.yaml docker-deploy/openapi/proudauth.yaml
```

For complete production controls see [installation](../docs/operations/installation.md),
[key custody](../docs/operations/keys.md) and [backup/restore](../docs/operations/backup-restore.md).
