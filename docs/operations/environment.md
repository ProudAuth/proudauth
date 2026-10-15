# Docker Compose environment

`deploy/prod/` (the release installer) and `deploy/dev/` each read one `.env`
file **next to `docker-compose.yaml`**. Both files list the same `PROUDAUTH_*`
variables; only the values differ. Values are literal `NAME=value` lines without
quotes, shell commands or `${...}` interpolation.

`docker-compose.yaml` passes the `PROUDAUTH_*` values to the image unchanged, so
the same names work with `docker run --env`, Kubernetes or systemd. The
[configuration reference](configuration.md#environment-overrides) maps each one
to its configuration key.

## Every `.env` variable

| Variable | Production (`deploy/prod`) | Development (`deploy/dev`) |
| --- | --- | --- |
| `PROUDAUTH_IMAGE` | Release image, pinned to the archive's version, for example `ghcr.io/proudauth/proudauth:0.2.0-alpha.4`. Use a digest for a controlled deployment. The Docker Hub mirror is `docker.io/mohamadalialghanem/proudauth`. | The same release image; `make dev` runs `proudauth:dev`, built from the checkout. |
| `PROUDAUTH_PUBLIC_ORIGIN` | **Required.** Your HTTPS origin without a path. It becomes a realm's issuer when the realm is created; changing it later does not move an existing realm. | `http://localhost:8080`; change it together with `PUBLIC_PORT`. |
| `PROUDAUTH_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of your reverse proxy as the container sees it. Empty trusts no forwarding headers. | Empty. |
| `PROUDAUTH_DATABASE_URL` | **Required.** `postgres://USER:PASSWORD@HOST:5432/DB?sslmode=require`; the user owns the database. `host.docker.internal` reaches the Docker host. | The bundled PostgreSQL container. |
| `PROUDAUTH_ROOT_KEY` | **Required.** 64 hexadecimal digits from `openssl rand -hex 32`. Back it up with the database. | A fixed, public development key. |
| `PROUDAUTH_SMTP_HOST` | **Required.** Your SMTP relay. | `mailpit`. |
| `PROUDAUTH_SMTP_PORT` | `587` for STARTTLS, `465` for implicit TLS. | `1025`. |
| `PROUDAUTH_SMTP_TLS` | `starttls` or `implicit`; `none` is refused in production. | `none`. |
| `PROUDAUTH_SMTP_USERNAME` | SMTP account; empty for an unauthenticated trusted relay. | Empty. |
| `PROUDAUTH_SMTP_PASSWORD` | SMTP password. | Empty. |
| `PROUDAUTH_EMAIL_FROM` | **Required.** A sender address your relay accepts; check its SPF/DKIM policy. | `no-reply@proudauth.localhost`. |
| `PROUDAUTH_LOG_LEVEL` | `info`, `warn` or `error`; `debug` is refused in production. | `info`. |
| `PUBLIC_BIND` | Host address the reverse proxy connects to; default `127.0.0.1`. | Always `127.0.0.1`. |
| `PUBLIC_PORT` | Host port of the identity API; default `8080`. | `8080`. |
| `OPERATOR_PORT` | Not published. | `9090`: `/status` and `/metrics` on `127.0.0.1`. |
| `MAIL_PORT` | — | `8025`: the Mailpit inbox. |
| `SWAGGER_PORT` | — | `8081`: Swagger UI for `api/openapi/`. |

Each `docker-compose.yaml` fixes what must not vary by installation:
`PROUDAUTH_MODE` (`production` or `development`), the email adapter (`smtp`),
and in production `PROUDAUTH_HOST_POLICY=strict`; in development it adds
`PROUDAUTH_COOKIE_INSECURE_DEV=true` and publishes the operator listener.

## Secrets

`PROUDAUTH_DATABASE_URL`, `PROUDAUTH_ROOT_KEY` and `PROUDAUTH_SMTP_PASSWORD` may
hold the secret itself. The image then treats it as the reference
`env:<variable>`: production accepts it, and configuration exports and support
bundles show the variable name, never the value. A value starting with `file:`
(or another secret reference) is used as given, for secrets mounted as files.

Keep the filled `.env` at mode `0600`, outside any Git checkout, and back it up
with the database: changing `PROUDAUTH_ROOT_KEY` makes stored keys unreadable,
and generating a new key is not recovery. Changing `.env` does not rotate a
PostgreSQL password. The committed `deploy/prod/.env` stays an empty template
(`TestDeployDevAndProd`), and the release and offline archives empty every
deployment value even when the packaging checkout holds a filled copy.

## Advanced settings

The complete configuration schema is in [configuration.md](configuration.md).
Settings without an environment variable (password blocklists, KMS, egress
allowlists, TLS inside the server, separate schema-owner and runtime database
roles, retention) need a YAML file: mount it and set `PROUDAUTH_CONFIG` to its
path in `docker-compose.yaml`; environment variables still override it. The
server rejects unknown YAML keys and invalid production settings, and
`identity-cli doctor` validates the configuration, database, schema and
root-key access.

See [Docker Compose installation](docker-compose.md), [key custody](keys.md),
[backup/restore](backup-restore.md) and [upgrades](upgrades.md). These
implement DEP-002, DEP-004 and DEP-006.
