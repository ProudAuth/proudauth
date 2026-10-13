# Docker Compose environment and secrets

The source-free release installer reads `.env` **next to
`docker-compose.yaml`** in `deploy/release/` or in the extracted release
archive. Copy `.env.example` for production, or run `./init.sh demo` for local
evaluation. Python 3.9+ safely parses the file; it never executes it as shell
code. Values are literal `NAME=value`, with optional matching quotes. Do not
use shell commands, variable interpolation or multiline values. Duplicate and
unknown variables are refused. Keep the supplied complete example when editing
it: `PROUDAUTH_IMAGE` must be present in `.env` for Compose. The initializer
uses defaults while generating configuration; it does not fill missing fields
back into `.env` for Compose.

`.env` has mode 0600. It contains deployment settings and SMTP account names,
but no root key, database password, SMTP password, administrator password or
token. The examples contain placeholders, not credentials. Production
initialization refuses the example public origin, SMTP host and sender.

## Every `.env` variable

| Variable | Production default | Required / behavior |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `proudauth` | Compose resource prefix; choose a unique lowercase name for independent installations. Changing it selects a different volume, not a migration. Demo defaults to `proudauth-demo`. |
| `PROUDAUTH_IMAGE` | `ghcr.io/proudbase/proudauth:0.2.0-alpha.1` | **Required in `.env`.** Explicit published image tag or verified digest. The Docker Hub mirror is `docker.io/mohamadalialghanem/proudauth:0.2.0-alpha.1`; check the release page for its published digest. Avoid `latest`; multi-architecture images select the host automatically. |
| `POSTGRES_IMAGE` | `postgres:18.6` | Explicit PostgreSQL image version or digest. Do not change major versions on an existing volume without a supported database upgrade. |
| `DEPLOYMENT_PROFILE` | `production` | `production` enables HTTPS/SMTP; `demo` enables the loopback-only development email sink and development cookies. |
| `PROUDAUTH_PUBLIC_ORIGIN` | `https://identity.example.com` | **Replace for production.** Your canonical HTTPS origin without a path, query or credentials. Demo uses `http://localhost:8080`. Stored realm issuers do not change when this setting changes. |
| `PROUDAUTH_REALM` | `main` | Default realm name; use it consistently in `realm-create`, `bootstrap`, CLI URLs and application configuration. The initializer does not automatically create it. |
| `PROUDAUTH_TRUSTED_PROXIES` | empty | Optional comma-separated trusted IPs/CIDRs. Set only to your exact proxy peers when forwarding headers are needed; empty trusts none. |
| `PUBLIC_BIND` | `127.0.0.1` | Host address for the public API port. Demo requires loopback. For a remote production proxy, use a private interface plus firewall rules. |
| `PUBLIC_PORT` | `8080` | Host public API port; container port remains 8080. For demo, update the public origin when changing this port. |
| `OPERATOR_PORT` | `9090` | Host operator port, always bound to `127.0.0.1`. Must differ from the public port; never tunnel or publish it. |
| `POSTGRES_MAX_CONNECTIONS` | `100` | PostgreSQL connection ceiling, accepted range 30–1000. Leave capacity for all pools and operator connections. |
| `POSTGRES_SHARED_BUFFERS` | `128MB` | Positive PostgreSQL memory size such as `128MB`; set according to available memory. |
| `POOL_MAX_CONNECTIONS` | `20` | Maximum database pool connections **per process**, range 2–200; the service's default minimum is two. Initializer requires `POSTGRES_MAX_CONNECTIONS >= 3 × POOL_MAX_CONNECTIONS + 10`. |
| `SMTP_HOST` | `smtp.example.com` | **Replace for production.** Reachable SMTP relay hostname; demo ignores email relay settings. |
| `SMTP_PORT` | `587` | SMTP port, 1–65535. Commonly 587 for STARTTLS or 465 for implicit TLS. |
| `SMTP_TLS` | `starttls` | `starttls` or `implicit`; unencrypted SMTP is not supported by this installer. |
| `SMTP_USERNAME` | `proudauth` | SMTP account name. With a nonempty name, production initialization requires a nonempty `secrets/smtp_password`. Empty is for an explicitly unauthenticated trusted relay. |
| `EMAIL_FROM` | `no-reply@example.com` | **Replace for production.** Sender address authorized by your relay; verify its delivery policy/DNS. |
| `LOG_LEVEL` | `info` | `info`, `warn` or `error`; production debug logging is deliberately unavailable through this installer. |

Example production overrides, beside your Compose file:

```dotenv
COMPOSE_PROJECT_NAME=my-identity
PROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:0.2.0-alpha.1
DEPLOYMENT_PROFILE=production
PROUDAUTH_PUBLIC_ORIGIN=https://identity.your-domain.com
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_TLS=starttls
SMTP_USERNAME=your-smtp-account
EMAIL_FROM=no-reply@your-domain.com
```

Copy the complete `.env.example` first, then replace its values. Run `./init.sh`
after changing settings and recreate the affected containers; editing `.env`
alone does not change generated `config.yaml`. Never change a persisted realm's
issuer as an ordinary configuration edit: plan a client/issuer transition.

## Generated and operator-owned secret files

| File under `secrets/` | Owner / use |
| --- | --- |
| `root_key` | Generated 32-byte random hex root encryption key; server, worker and operator/migration commands. Keep with your separately protected backups. |
| `postgres_password` | Generated PostgreSQL superuser password; only the PostgreSQL container receives it. |
| `owner_password` | Generated `proudauth_owner` password; PostgreSQL uses it only during first initialization. |
| `app_password` | Generated `proudauth_app` password; PostgreSQL uses it only during first initialization. |
| `database_url` | Generated runtime-role connection string; only runtime processes receive this DSN. |
| `owner_database_url` | Generated schema-owner connection string; only the migration service receives this DSN. |
| `metrics_token` | Generated 32-byte random hex bearer token protecting `/metrics` and `/status`; not an administrator API token. |
| `smtp_password` | Operator-supplied SMTP password; created empty initially. Required with authenticated SMTP in production; unused in the demo. Write its exact bytes without a trailing newline. |

The host secret directory is mode **0700**. Individual file-backed secrets are
mode **0444** so the non-root container UID 65532 can read its separate read-only
mount on native Linux. The private parent directory protects access on the host;
do not make the directory broadly accessible. Generated secret contents never
appear in `.env`, config output, image layers or the published release bundle.
This is local file custody, not an external secret manager.

`init.sh` is idempotent: it preserves secret values and existing mounted inodes
when their content is unchanged. It repairs permissions and refuses an existing
malformed secret or inconsistent DSN. It does **not** rotate database passwords,
root keys or SMTP credentials automatically.

## Advanced settings

The complete configuration schema is documented in
[configuration.md](configuration.md). The starter installer deliberately covers
the settings above. To manage additional settings (password blocklists, external
secrets/KMS, egress policy, TLS inside the server, additional root-key versions,
retention or pool minima), take ownership of `config.yaml` and keep it outside
initializer regeneration, or extend and review the deployment templates.
Mount any required files explicitly. The server rejects unknown YAML keys and
invalid production settings; `identity-cli doctor` validates the configuration,
database, schema and root-key access.

See [Docker Compose installation](docker-compose.md),
[key custody](keys.md), [backup/restore](backup-restore.md) and
[upgrades](upgrades.md). These implement DEP-002, DEP-004, DEP-006 and OPS-013.
