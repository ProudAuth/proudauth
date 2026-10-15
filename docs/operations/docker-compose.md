# Install ProudAuth with Docker

Two files and two commands. You need Docker, a PostgreSQL database, an email
(SMTP) account and a domain with HTTPS.

## 1. Create `docker-compose.yaml`

In an empty folder, save this as `docker-compose.yaml`:

```yaml
# ProudAuth: the identity server and its worker, configured by .env.
# Start: docker compose pull && docker compose up -d
name: ${COMPOSE_PROJECT_NAME:-proudauth}

x-proudauth: &proudauth
  image: ${PROUDAUTH_IMAGE:?Set PROUDAUTH_IMAGE in .env}
  read_only: true
  tmpfs: ["/tmp:size=64m,mode=1777"]
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  stop_grace_period: 35s
  # PostgreSQL on this machine is host.docker.internal.
  extra_hosts: ["host.docker.internal:host-gateway"]
  environment:
    PROUDAUTH_MODE: production
    PROUDAUTH_HOST_POLICY: strict
    PROUDAUTH_PUBLIC_ORIGIN: ${PROUDAUTH_PUBLIC_ORIGIN:?Set PROUDAUTH_PUBLIC_ORIGIN (https) in .env}
    PROUDAUTH_TRUSTED_PROXIES: ${PROUDAUTH_TRUSTED_PROXIES:-}
    PROUDAUTH_DATABASE_URL: ${PROUDAUTH_DATABASE_URL:?Set PROUDAUTH_DATABASE_URL in .env}
    PROUDAUTH_ROOT_KEY: ${PROUDAUTH_ROOT_KEY:?Set PROUDAUTH_ROOT_KEY in .env (openssl rand -hex 32)}
    PROUDAUTH_EMAIL_ADAPTER: smtp
    PROUDAUTH_SMTP_HOST: ${PROUDAUTH_SMTP_HOST:?Set PROUDAUTH_SMTP_HOST in .env}
    PROUDAUTH_SMTP_PORT: ${PROUDAUTH_SMTP_PORT:-587}
    PROUDAUTH_SMTP_TLS: ${PROUDAUTH_SMTP_TLS:-starttls}
    PROUDAUTH_SMTP_USERNAME: ${PROUDAUTH_SMTP_USERNAME:-}
    PROUDAUTH_SMTP_PASSWORD: ${PROUDAUTH_SMTP_PASSWORD:-}
    PROUDAUTH_EMAIL_FROM: ${PROUDAUTH_EMAIL_FROM:?Set PROUDAUTH_EMAIL_FROM in .env}
    PROUDAUTH_LOG_LEVEL: ${PROUDAUTH_LOG_LEVEL:-info}
    XDG_CONFIG_HOME: /tmp/proudauth-cli

services:
  migrate:
    <<: *proudauth
    restart: "no"
    entrypoint: ["/usr/local/bin/identity-cli", "migrate"]

  realm:
    # Creates the main realm once.
    <<: *proudauth
    restart: "no"
    entrypoint: ["/usr/local/bin/identity-cli", "realm-create", "-if-missing"]
    depends_on:
      migrate: {condition: service_completed_successfully}

  server:
    <<: *proudauth
    restart: unless-stopped
    # Your HTTPS reverse proxy forwards to this port.
    ports: ["${PUBLIC_BIND:-127.0.0.1}:${PUBLIC_PORT:-8080}:8080"]
    depends_on:
      realm: {condition: service_completed_successfully}
    healthcheck:
      test: ["CMD", "/usr/local/bin/identity-cli", "doctor"]
      interval: 10s
      timeout: 10s
      retries: 12
      start_period: 10s

  worker:
    <<: *proudauth
    restart: unless-stopped
    entrypoint: ["/usr/local/bin/identity-worker"]
    depends_on:
      server: {condition: service_healthy}
    healthcheck:
      test: ["CMD", "/usr/local/bin/identity-cli", "doctor"]
      interval: 15s
      timeout: 10s
      retries: 8
      start_period: 10s
```

## 2. Create `.env`

Save this as `.env` next to it, then fill in the empty values:

```dotenv
# Fill in the empty values. Keep this file private (chmod 600 .env).

PROUDAUTH_IMAGE=ghcr.io/proudauth/proudauth:0.2.0-alpha.2

# Your HTTPS address, for example https://id.example.com (choose it once)
PROUDAUTH_PUBLIC_ORIGIN=
# Your reverse proxy's IP as the container sees it (optional)
PROUDAUTH_TRUSTED_PROXIES=

# postgres://USER:PASSWORD@HOST:5432/DB?sslmode=require
# (this machine: host.docker.internal; the user must own the database)
PROUDAUTH_DATABASE_URL=

# openssl rand -hex 32   (back it up with your database)
PROUDAUTH_ROOT_KEY=

# Your email (SMTP) service: port 587 with starttls, or 465 with implicit
PROUDAUTH_SMTP_HOST=
PROUDAUTH_SMTP_PORT=587
PROUDAUTH_SMTP_TLS=starttls
PROUDAUTH_SMTP_USERNAME=
PROUDAUTH_SMTP_PASSWORD=
PROUDAUTH_EMAIL_FROM=

PROUDAUTH_LOG_LEVEL=info
PUBLIC_BIND=127.0.0.1
PUBLIC_PORT=8080
```

| Value | What to put |
| --- | --- |
| `PROUDAUTH_PUBLIC_ORIGIN` | The HTTPS address of your identity server |
| `PROUDAUTH_DATABASE_URL` | Your PostgreSQL connection URL |
| `PROUDAUTH_ROOT_KEY` | The output of `openssl rand -hex 32` |
| `PROUDAUTH_SMTP_*`, `PROUDAUTH_EMAIL_FROM` | Your email service |

## 3. Start

```sh
docker compose pull
docker compose up -d
```

ProudAuth prepares the database and creates the `main` realm by itself. Point
your HTTPS reverse proxy at `127.0.0.1:8080`, then check:

```sh
curl https://id.example.com/realms/main/.well-known/openid-configuration
```

## 4. Create your administrator

```sh
docker compose exec server identity-cli bootstrap -realm main -email you@example.com -username admin
docker compose exec server identity-cli setup-account --url https://id.example.com --realm main
docker compose exec server identity-cli login --url https://id.example.com --realm main
```

The first sign-in adds an authenticator app and verifies your email.

## Good to know

- **Upgrade:** back up the database, change the version in `PROUDAUTH_IMAGE`,
  then `docker compose pull` and `docker compose up -d`.
- **Keep `PROUDAUTH_ROOT_KEY` safe** with your database backups: without it,
  stored keys cannot be read.
- **Reverse proxy:** forward the original `Host` header; other hosts get `421`.
  Set `PROUDAUTH_TRUSTED_PROXIES` to the proxy's address to pass client IPs.
- **Logs:** `docker compose logs -f server worker`.
- **Limits:** a single node; values in `.env` are visible to anyone with Docker
  access (`docker inspect`); separate database roles need the YAML
  configuration in the [installation runbook](installation.md).
- More: [every variable](environment.md), [installation runbook](installation.md),
  [backups](backup-restore.md), [keys](keys.md), [upgrades](upgrades.md).

DEP-002, DEP-003, DEP-004, DEP-006.
