# Installation and bootstrap

This runbook installs a single-node production deployment (docs/plan.md §30.1)
and creates the first administrator through the local operator channel
(DEP-007, SEC-011). For a throwaway development stack use `make dev` instead
([quick start](../service-status.md#quick-start-development-only)).

## 1. Components

| Component | Role | Notes |
| --- | --- | --- |
| Reverse proxy / load balancer | TLS termination, routing to the public listener | The server can also terminate TLS itself (`server.tls_cert_file`, `server.tls_key_file`). |
| `identity-server` | Public listener (`server.public_listen`, default `:8080`) and internal listener (`server.internal_listen`, default `127.0.0.1:9090`) | Stateless; run one or more. |
| `identity-worker` | Deliveries, jobs, key lifecycle, audit sealing, retention | Required. Without it no email or webhook is sent and planned signing-key rotation never activates. Run one or more. |
| `identity-cli` | Operator commands with direct database and key access | Run only on trusted hosts. |
| PostgreSQL | All durable state | Tested with 17 and 18. Configure backups and HA yourself. |
| SMTP relay | Verification, recovery, invitation and security email | Production rejects the development sink. |

All three binaries are in the container image (`/usr/local/bin/`), built by the
`Dockerfile` as static binaries on a distroless, non-root (UID 65532) base. The
image works with a read-only root filesystem. The
[v0.2.0-alpha.1 pre-release](https://github.com/proudbase/proudauth/releases/tag/v0.2.0-alpha.1)
provides Linux/macOS binaries, checksums and source-free installation assets.
For a single-machine installation, follow the
[Docker Compose guide](docker-compose.md) and [complete `.env` reference](environment.md).
Pull `ghcr.io/proudbase/proudauth:0.2.0-alpha.1` or the maintainer's Docker Hub
mirror `mohamadalialghanem/proudauth:0.2.0-alpha.1`. The published registry image
supports Linux amd64 and arm64; the offline release image archive is amd64,
with binaries supplied for both Linux architectures. This is pre-release
software with no completed external security review or certification.
To build locally, use `make image VERSION=0.2.0-alpha.1` or `go build ./cmd/...`.

### Verifying a release

Releases are built only by `.github/workflows/release.yml` from a tag, after
the full CI suite passed on that commit (DEP-003, SEC-016). Each release has
`SHA256SUMS` over every file, build-provenance attestations for the files and
the image, an SBOM attestation for the image, and a keyless cosign signature
of the multi-platform image digest (`IMAGE_DIGEST`). Per-platform image SBOMs
are `image-sbom.spdx.json` (amd64) and `image-sbom-linux-arm64.spdx.json`.
Before installing:

```sh
sha256sum -c SHA256SUMS
gh attestation verify identity-server_linux_amd64 --repo proudbase/proudauth
gh attestation verify "oci://$(cat IMAGE_DIGEST)" --repo proudbase/proudauth
cosign verify "$(cat IMAGE_DIGEST)" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/proudbase/proudauth/\.github/workflows/release\.yml@refs/tags/v'
```

Deploy the image by its verified immutable digest (the content of `IMAGE_DIGEST`).
Base images and the builder use immutable digests; external GitHub Actions use
full commit references. Provenance establishes workflow identity and artifact
integrity. Independent-machine reproduction of this release and external
security review are not claimed
([security-checks.md](security-checks.md#open-items)).

## 2. Prepare secrets

Every secret is supplied as a reference: `file:/path` (contents trimmed),
`env:NAME`, `cred:NAME` (a systemd credential) or `vault:<mount>/data/<path>#<field>`
(HashiCorp Vault KV v2; see [configuration.md](configuration.md#loading-rules)).
Root, pepper and signing-wrap keys **must** be references in production; other
secrets should be.

```sh
install -d -m 700 /run/secrets
identity-cli generate-root-key > /run/secrets/root_key_v1        # 32 random bytes, hex
printf 'postgres://proudauth:...@db.internal:5432/proudauth?sslmode=verify-full' > /run/secrets/database_url
printf '%s' "$SMTP_PASSWORD" > /run/secrets/smtp_password
head -c 32 /dev/urandom | base64 > /run/secrets/metrics_token     # optional bearer for /metrics
chmod 600 /run/secrets/*
```

Optional: a separately custodied password pepper (`keys.pepper_keys`) and a
dedicated signing-key wrapping key (`keys.signing_wrap_keys`); both are 32-byte
keys and can be generated with `identity-cli generate-root-key`. Any of these
keys can instead be kept wrapped by a KMS or HSM and referenced as
`kms:<file>` ([keys.md](keys.md#kms-envelope-dep-016)). With separate database
roles ([below](#database-roles)), also store the migration connection
(`/run/secrets/migration_database_url`). Read
[keys.md](keys.md) before enabling a pepper: losing it makes every peppered
password verifier unusable.

Store a copy of each key **separately from database backups** (OPS-005).

## 3. Write the configuration

Settings with an environment variable need no file: `deploy/prod` configures
the image with `.env` alone ([environment.md](environment.md)). Write
`/etc/proudauth/config.yaml` for the rest, such as separate database roles,
root-key rotation, a pepper or a password blocklist; `PROUDAUTH_*` variables
still override it. `deploy/kubernetes/overlays/example/config.yaml` is a
validated production example, and the full key reference is
[configuration.md](configuration.md). At minimum set:

- `mode: production`
- `server.public_origin` — the external `https://` origin. Issuers are
  `<public_origin>/realms/<realm>`; they are never derived from `Host` or
  forwarded headers.
- `server.trusted_proxies` — the IPs/CIDRs of your proxies. `X-Forwarded-For` is
  used for the client IP only when the direct peer is in this list.
- `server.internal_listen` — a private interface.
- `storage.database_url`, `keys.root_keys`, `keys.active_version`
- `delivery.email.*` — `adapter: smtp`, host, port, TLS mode, username, password
  reference, `from`.

### Validation rules

`identity-server`, `identity-worker` and every operator command validate the
configuration at startup and refuse to run on errors. Unknown YAML keys are also
errors, and so are malformed `PROUDAUTH_*` boolean or integer overrides
([configuration.md](configuration.md#environment-overrides)). To check a changed
file before a restart, run `identity-cli config-diff -from <current> -to <new>`
([configuration.md](configuration.md#reviewing-a-change)).

Always enforced:

- `mode` is `production` or `development`.
- `server.public_origin` is set and is an absolute origin without path, query,
  fragment or userinfo; `https` in production.
- Each `server.trusted_proxies` entry is an IP address or CIDR.
- `storage.database_url` and at least one `keys.root_keys` entry are set.
- `identity.default_realm` is a valid lower-case realm name.
- `security.password.min_length >= 8`, `max_length >= 64`, `max_bytes >= max_length`.
- `0 < tokens.access_token_ttl <= tokens.max_access_token_ttl`.
- `0 < tokens.authorization_code_ttl <= 10m`; `0 <= tokens.clock_skew <= 60s`.
- `0 < impersonation.max_ttl <= 5m`; `0 < impersonation.handoff_ttl <= 30s`.
- `0 < security.admin_mfa_max_age <= 5m`.
- `0 < sessions.idle_timeout <= sessions.absolute_timeout`.
- `privacy.telemetry_opt_in` is `false` (no telemetry sink exists).
- Every `privacy.audit_retention_by_category` key is a known audit category
  (see [configuration.md](configuration.md#privacy)) other than `emergency`
  (emergency events are never pruned), and every value is at least `24h`.
- `sessions.cookie_same_site` is `lax`, `strict` or `none`.
- `keys.signing_algorithm` is `RS256`, `ES256`, `PS256` or `EdDSA`.
- `delivery.email.adapter` is `smtp` (then `smtp_host` and `from` are required) or
  `dev_sink`; `delivery.email.smtp_tls` is `starttls`, `implicit` or `none`.
- `delivery.sms.adapter` is `none`, `dev_sink` or `webhook`; `webhook` requires an
  absolute `sms.webhook_url` (`https` in production, `http` allowed in development)
  and `sms.webhook_secret`; `sms.allowed_countries` entries look like `+49`.
- Argon2id: `argon_time >= 1`, `argon_threads >= 1`, `argon_memory_kib >= 8192`.
- `workers`: `concurrency`, `batch_size`, `max_attempts >= 1`; `poll_interval`,
  `lease_duration`, `audit_seal_every > 0`.
- `0 < limits.default_page_size <= limits.max_page_size`.
- `federation.egress_allowlist` and `delivery.egress_allowlist` entries are CIDRs.

Additionally in production:

- every `keys.root_keys[].ref`, `keys.pepper_keys[].ref` and
  `keys.signing_wrap_keys[].ref` is a secret reference (`file:`, `env:`, `cred:`,
  `vault:` or a registered adapter);
- `delivery.email.adapter` and `delivery.sms.adapter` are not `dev_sink`;
- `delivery.email.smtp_tls` is not `none`;
- `sessions.cookie_insecure_dev` is `false`;
- `federation.allow_private_network` and `delivery.allow_private_webhooks` are
  `false` (use `federation.egress_allowlist` and `delivery.egress_allowlist`);
- `directory.allow_private_network` is `false` (use
  `directory.egress_allowlist`);
- `security.password.argon_memory_kib >= 19456`;
- `observability.log_level` is not `debug` (use `identity-cli debug-window`);
- `delivery.email.smtp_password`, `server.metrics_token`,
  `delivery.email.events_secret` and `delivery.sms.webhook_secret` (when set) are
  secret references;
- `storage.database_url` is a reference or contains no password.

Also enforced:

- `server.host_policy` is `any` or `strict`;
- `security.decision_cache_ttl` is between `0` and `10m`;
  `security.dynamic_group_max_staleness` is `0` or between `10m` and `168h`;
- each `security.challenge_providers` entry has a unique name, an absolute
  `verify_url` (`https`, or `http` in development), a secret (a secret
  reference in production) and a timeout of at most `10s`;
- each `security.policy_engines` entry has a unique name, an absolute `url`
  without userinfo (`https`, or `http` outside production), a `token` (a secret
  reference in production) and a timeout of at most `5s`;
- `server.mtls_listen` requires `server.tls_cert_file` (and its key);
  `server.mtls_origin` is an `https` origin; `server.client_cert_header`
  requires `server.trusted_proxies` ([mutual-tls.md](../protocols/mutual-tls.md));
- `keys.kms.command` names a program and `keys.kms.timeout` is at most `1m`;
  a `kms:` key reference requires `keys.kms.command`;
- `observability.otlp_endpoint` is an absolute `http(s)` URL without
  credentials, and `https` in production unless the host is loopback;
- `storage.runtime_role` is a lowercase role name;
- `saml.max_message_bytes` is between `16384` and `4194304`,
  `saml.max_clock_skew` between `0` and `30m`, and `saml.key_prepublish` and
  `saml.retired_key_publication` are not negative;
- `directory.egress_allowlist` entries are CIDRs; `directory.connect_timeout`
  is at most `1m`, `directory.operation_timeout` at most `2m`, and
  `directory.max_entries_per_run` between `0` and `1000000`;
- `privacy.history_retention` is at least `168h`; the `limits.*` safety
  limits are within their ranges ([configuration.md](configuration.md#limits));
- `security.password.legacy_hashes_until` is a `YYYY-MM-DD` date and
  `security.mfa_floor.require` is `none` or `all`;
- `privacy.residency.allowed_destinations` entries are host names or
  `.domain` suffixes, and when the list is set, `delivery.email.smtp_host`,
  `delivery.sms.webhook_url` and `observability.otlp_endpoint` must be inside
  it;
- in production, `storage.migration_database_url` (when set) is a secret
  reference.

Not enforced (operator responsibility): that the database connection uses TLS;
that `server.internal_listen` and `workers.metrics_listen` are private; that
`storage.runtime_role` names an existing role other than the owner (checked
only when the grants run after a migration).

## 4. Check and migrate

```sh
export PROUDAUTH_CONFIG=/etc/proudauth/config.yaml
identity-cli migrate -status     # lists each migration as pending or applied
identity-cli migrate             # applies pending migrations under an advisory lock
identity-cli doctor              # config, database, schema, per-realm signing key, keyring fingerprint
```

`doctor` exits non-zero if the configuration is invalid, the database is
unreachable, the schema is behind the binary, or a realm's active signing key
cannot be decrypted with the configured keys (wrong root key). Record the printed
key-hierarchy fingerprint; it changes if a different root key is configured.
It also prints the database role check ([below](#database-roles)) and the
number of accounts still on imported legacy password verifiers
(`accounts on legacy password hashes: N (until <date>)`, with `no deadline`
instead of a date while `security.password.legacy_hashes_until` is unset;
CRED-004, [migration.md](migration.md#credentials-and-factors)).

Alternatives to `identity-cli migrate`: `identity-server -migrate`, or
`storage.migrate_on_start: true`, which the server and the worker honor at
startup. Operator commands (`migrate -status`, `migrate -plan`, `doctor`,
`realm-create`, `bootstrap`, ...) never apply migrations, whatever
`migrate_on_start` says; only `identity-cli migrate` and server or worker
startup do. Every run that applies at least one migration is audited as the
operator event `operations.migrations.applied` (category `operations`, no
realm; metadata `migrations`): by `identity-cli migrate` with actor
`local:<OS user>` and the `backup_reference`, at startup with actor
`startup:<hostname>` and `trigger` `migrate_flag` or `migrate_on_start`. A run
whose grants or a later migration fail after earlier migrations committed
records no event. When `identity-cli migrate` applied migrations but cannot
write their audit record, it exits with an error ("migrations applied but
their audit record failed: ...") although the migrations stay applied
(OPS-013). Prefer an explicit migration step so it can be backed up
first (OPS-008).

### Database roles

OPS-013, `internal/storage/roles.go`, `TestRuntimeRoleSeparation`. Run the
service with a role that can read and write data but not change the schema,
and apply migrations with a separate owner role, so the service's own
credentials cannot alter tables or the audit triggers:

```sql
-- As a PostgreSQL administrator:
CREATE ROLE proudauth_owner LOGIN PASSWORD '...';   -- owns the schema; used only for migrations
CREATE ROLE proudauth_app   LOGIN PASSWORD '...';   -- the runtime role; data privileges only
CREATE DATABASE proudauth OWNER proudauth_owner;
-- PostgreSQL 14 and older let every role create objects in schema public.
-- The migration revokes that when proudauth_owner owns the schema; otherwise:
-- \c proudauth
-- REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

```yaml
storage:
  database_url: file:/run/secrets/database_url                       # postgres://proudauth_app@db.internal/proudauth?...
  migration_database_url: file:/run/secrets/migration_database_url   # postgres://proudauth_owner@db.internal/proudauth?...
  runtime_role: proudauth_app
```

- `storage.runtime_role` must be a lowercase role name
  (`^[a-z_][a-z0-9_]{0,62}$`); every binary checks it at startup. Do not set
  it to the owner role itself.
- `identity-cli migrate`, `identity-server -migrate` and `migrate_on_start`
  connect with `storage.migration_database_url` and, after every successful
  run, grant `storage.runtime_role` `USAGE` on schema `public`,
  `SELECT, INSERT, UPDATE, DELETE` on all its tables and
  `USAGE, SELECT, UPDATE` on all its sequences, set default privileges so
  that tables and sequences created later by the migration role are usable
  at once, revoke `CREATE` on schema `public` from `PUBLIC` and from the
  runtime role (PostgreSQL applies the revoke from `PUBLIC` only when the
  migration role owns the schema or is a superuser, and otherwise only
  warns), and revoke `DELETE` on `audit_events`, `audit_batches`, `audit_prunes` and
  `audit_prune_log`: the runtime role prunes audit events only through
  `proudauth_audit_prune` (`EXECUTE` granted;
  [data-inventory.md](data-inventory.md#audit-retention-and-legal-holds)).
  Run migrations through ProudAuth, not by hand.
- `identity-cli migrate -plan` is read-only and works with the runtime role:
  it connects with `storage.database_url`, never creates or alters
  `schema_migrations` (without the table every migration is listed as
  pending) and only runs the migrations' precondition queries.
- `identity-cli doctor` checks the runtime connection and prints
  `database role proudauth_app: data privileges only`, or a `WARNING` when
  the role is a superuser; owns the schema, inherits the owner's privileges
  (a member of the owner role) or can create roles; or can create objects in
  schema `public`. On PostgreSQL 14 and older, `CREATE` on `public` is
  granted to `PUBLIC`; the migration revokes it when the migration role owns
  the schema (the setup above). When `doctor` still warns about it, run
  `REVOKE CREATE ON SCHEMA public FROM PUBLIC` as the schema's owner.
  A member of the owner role without `INHERIT` (which can still `SET ROLE`)
  is not detected.
- Role separation stops schema changes, including disabling the audit
  triggers, and direct deletion of audit rows through the service's
  credentials: the guard trigger accepts a delete only from the table owner
  inside `proudauth_audit_prune`. The function never removes unsealed,
  `emergency`, legally held or (with a forked archive) unarchived events, but
  it does not check an event's age: a stolen runtime credential can still
  prune other sealed events early, and such a prune is recorded in
  `audit_prunes` like retention, so `identity-cli verify-audit` does not flag
  it; the audit archive keeps the copies. The runtime role also keeps write
  access to `audit_legal_holds`, `audit_archive_state` and
  `imported_audit_events`.
- Without separate roles the runtime credential is the owner: it can delete
  any audit row directly or disable the triggers. Separate the roles where
  the audit trail must resist a compromised service credential.

When upgrading an existing installation to separate roles, see
[upgrades.md](upgrades.md#separating-database-roles).

## 5. Start the processes

```sh
identity-server -config /etc/proudauth/config.yaml
identity-worker -config /etc/proudauth/config.yaml
```

`identity-worker` exits immediately if the schema is not current. Both stop
gracefully on `SIGINT`/`SIGTERM` (OPS-012):

- `identity-server` first answers `/health/ready` with
  `503 {"status":"draining"}` for `server.drain_delay` (5 s) while still serving,
  then stops accepting connections and lets in-flight requests finish for up to
  `server.shutdown_deadline` (20 s). A response is written only after its
  transaction has committed, so a request cut off by the deadline is never
  reported as successful.
- `identity-worker` stops claiming new work, lets the task in progress finish for
  up to `workers.drain_timeout` (20 s), and then returns the jobs, notification
  jobs and webhook deliveries it still holds to the queue so another worker picks
  them up at once (`TestWorkerShutdownReleasesLeases`).

Give the processes more time than that before they are killed: about 25 s for
the server and 30 s for the worker with the defaults (the worker allows another
5 s each for releasing its work and stopping `workers.metrics_listen`). The
Kubernetes manifests in `deploy/kubernetes/base` set
`terminationGracePeriodSeconds` to 30 (server) and 60 (worker); raise them if you
increase these settings. For systemd, set `TimeoutStopSec` accordingly.

Readiness: `GET /health/ready` on the public listener returns 200 only when the
database is reachable, the schema is current and every active realm has a usable
active signing key, and the process is not shutting down
([monitoring.md](monitoring.md)).

## 6. Create a realm

```sh
identity-cli realm-create -name main -display-name "Main" -login-ui-url https://login.example.com
```

This runs in one transaction and creates: the realm with the default policy
(registration `closed`, MFA `optional`, password login enabled, impersonation
disabled), the built-in permissions and roles, three system API resources
(`<issuer>/account`, `<issuer>/admin`, `<issuer>/userinfo`, all strict-online),
the OIDC scopes, the `proudauth-cli` native client (loopback redirect
`http://127.0.0.1/callback`, authorization code, refresh and device grants,
pre-authorized consent), and an active signing key.

`-login-ui-url` is the application-provided login interface the authorization
endpoint redirects browsers to. It can be set later through the realm policy
(`interaction.login_ui_url`).

## 7. Bootstrap the first administrator

```sh
identity-cli bootstrap -realm main -email admin@example.com -username root-admin -ttl 1h
```

- Creates a protected user with the `realm-admin` role and required actions
  `configure_totp` and `verify_email`, and prints a one-time setup token
  (default lifetime 1 h). A `-ttl` outside 1 minute to 24 hours is refused
  ("setup token lifetime ... outside 1m..24h"; DEP-005); it used to become
  1 h silently. There is no default password.
- Is refused once the realm has been bootstrapped. `-break-glass` creates an
  additional administrator after initialization; it is audited as
  `bootstrap.break_glass_admin_created` in the `emergency` category.
- Runs only through the local operator channel; there is no remote bootstrap
  endpoint.
- Usernames are 3–64 characters of `a-z 0-9 . _ -` after normalization, and
  reserved names such as `admin`, `administrator`, `root`, `system`, `support`,
  `security` and `operator` are rejected
  ([identifiers.md](../protocols/identifiers.md)).

Then, from an administrator workstation:

```sh
identity-cli setup-account --url https://id.example.com --realm main   # setup token + new password (15+ characters)
identity-cli login --url https://id.example.com --realm main           # password, TOTP enrollment, email verification code
```

The bootstrap setup token does not verify the email address, so the first login
sends a verification code by email. Recovery codes are printed once during TOTP
enrollment; store them offline. Credentials are saved with mode `0600` under the
user configuration directory (`proudauth/<realm>-admin.json`) and refreshed
automatically. `identity-cli login --device` uses the device flow instead and
requires a login UI that handles device user codes.

## 8. Configure the realm

Administration uses the API (`identity-cli api METHOD /path [json]`, the Go admin
SDK, or HTTP). Typical next steps:

- realm policy: `GET /settings`, then `PUT /settings` with `If-Match` and the full
  `policy` object (registration mode, MFA requirement, terms version, session
  limits, impersonation, login UI URL);
- API resources, scopes and clients: `POST /resources`, `POST /clients`,
  `PUT /clients/{client}/resource-grants/{resource}`, or
  `POST /configuration/validate` and `/configuration/imports`;
- resource servers that introspect: `POST /resources/{resource}/introspectors`.

Client secrets are shown once on creation. A configuration import returns the
generated secrets of the confidential clients it creates once, in
`client_secrets`; otherwise issue one with `POST /clients/{client}/credentials`.

## 9. Enabling support impersonation

Impersonation stays unavailable until all three switches are on (IMP-001):

1. deployment: `impersonation.enabled: true` (or `PROUDAUTH_IMPERSONATION_ENABLED=true`);
2. realm policy: `impersonation.enabled: true` (rejected if step 1 is off);
3. at least one API resource with `impersonation_enabled: true`,
   `verification_mode: strict_online`, an `impersonation_policy` listing
   `allowed_scopes` and a `contract_version`, implemented with the support contract
   ([docs/integrations/resource-servers.md](../integrations/resource-servers.md)).

Assign `support-operator` (and, if approvals are used, `support-approver`) to
dedicated staff accounts. Read [docs/threat-models/impersonation.md](../threat-models/impersonation.md) first.

## 10. Network exposure checklist

- Expose only the public listener through the proxy. Keep `server.internal_listen`
  on a private interface; `/metrics` and `/status` there are protected only by
  `server.metrics_token` when set, and `/status` names internal capabilities.
- Consider restricting `/api/v1/realms/*/users`, `/settings`, `/signing-key*`,
  `/emergency/*`, `/audit-*` and other administration paths to administrator
  networks at the proxy. The server separates them by token audience and
  permission, not by network.
- `mode: production` adds `Strict-Transport-Security`. Every response carries
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and a restrictive `Content-Security-Policy`,
  and `Cache-Control: no-store` except discovery and JWKS
  (`public, max-age=300`).
- Keep host clocks synchronized (NTP); `/status` reports skew against the
  database clock ([monitoring.md](monitoring.md)).
- Choose `server.host_policy: strict` when the server is reachable under
  host names other than the public origin's: other hosts then get `421`
  instead of being served ([below](#custom-domains)).
- For mutual TLS and X.509 sign-in, expose `server.mtls_listen` (TLS passed
  through to the server) at `server.mtls_origin`, or let the proxy request
  client certificates and forward them in `server.client_cert_header`; then
  the proxy **must remove that header from every incoming request**, or a
  client could present any certificate it likes
  ([mutual-tls.md](../protocols/mutual-tls.md#how-certificates-reach-the-server)).

## Custom domains

DEP-014, migrations `0041` and `0043`, `internal/realm/domains.go`,
`TestCustomDomains`.
A realm can be served on its own host name (for example
`login.acme.example`) besides `server.public_origin`. A custom domain changes
where browsers and clients send requests; it never changes the issuer, token
contents, subjects, email links or upstream redirect URIs, which keep using
the public origin.

1. **Register** (realm administrator, MFA session, `realm.settings.write`):

   ```sh
   identity-cli api POST /custom-domains '{"host":"login.acme.example"}'
   ```

   The response holds the domain (`id`, `host`, `state: "pending"`,
   `challenge_expires_at`, `passkeys_usable`) and the DNS record to publish:
   `dns_record_name` `_proudauth-challenge.login.acme.example`,
   `dns_record_type` `TXT`, `dns_record_value` `proudauth-domain=...`. The value
   is shown once (only a digest is stored) and is valid for 7 days. The
   public origin's host is refused (`422`), and a host the realm already
   registered gets `409` ("already registered in this realm"). A pending
   domain reserves nothing for other realms: several realms can register the
   same host, and only the first to verify it gets it.
2. **Publish the TXT record**, then
   `identity-cli api POST /custom-domains/{id}/verify`: `422` while the record is
   missing or different, `409` once the challenge expired (remove the domain
   and add it again) or the domain was removed, and `409` ("the host is
   already in use") when another realm verified the host first. Verification
   succeeds only for the pending challenge that was checked: a domain removed
   (or replaced) while its DNS lookup ran is not verified (`409`, "the domain
   changed during verification; check its state"). Audit:
   `realm.custom_domain.added`, `.verified`, `.removed` (category
   `configuration`, metadata `host`).
3. **Route and terminate TLS** for the host at your proxy or load balancer
   (ProudAuth does not obtain certificates) and forward the original `Host`
   header; `X-Forwarded-Host` is ignored.
4. **Turn on `server.host_policy: strict`** (restart) once every host the
   server should answer is either the public origin's or a verified custom
   domain. A custom domain then serves only its own realm's paths
   (`/realms/<realm>/…` and `/api/v1/realms/<realm>/…`); everything else on
   it, and every unknown host, gets `421 misdirected_request` (`/health/*`
   excepted). Verification and removal apply within 30 seconds on every
   server.
5. **Point clients and the login UI at the host** where you want it used:
   authorization requests and the login UI's transaction calls on the custom
   host get cookies for that host only, so sessions (and SSO) are not shared
   with the public origin or other custom domains. Cookie-authenticated calls
   accept `Origin: https://<verified custom host>` for that realm on the
   default port, or on the public origin's port when it names one (SEC-002);
   the same host on any other port is refused. Discovery
   on the custom host still names the public origin's endpoints, and DPoP
   proofs and client assertions must name the public-origin URLs.
6. **Passkeys** work on the host only when it is the realm's effective RP ID
   or under it (`passkeys_usable`). The effective RP ID is `webauthn.rp_id`
   when the realm sets it, otherwise the login UI's host, otherwise the
   issuer's host. When the realm configures no `webauthn.origins`, the
   accepted origins are derived: the RP origin plus `https://<host>` of every
   verified custom domain equal to or under the RP ID. With explicit
   `webauthn.origins`, list `https://<host>` there yourself. Passkeys
   registered under another RP ID do not work on the host.

`DELETE /custom-domains/{id}` removes a domain (`404` if unknown or already
removed); a removed or pending domain serves nothing. Every server caches
the verified hosts for up to 30 seconds and keeps its previous list when the
database cannot be read.
