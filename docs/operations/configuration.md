# Configuration reference

Source of truth: `internal/configuration/config.go` (`Config`, `Defaults()`,
`Validate()`, `applyEnv()`). This page lists every key, its default, and what it
does. Keys marked **no effect** are parsed and (where noted) validated but no code
reads them yet; they are listed so operators do not rely on them.
`api/schemas/config.schema.json` describes the same keys for editors and
validators; the contract test `TestConfigSchemaMatchesStructs` fails when the
server accepts a key the schema lacks or the schema lists a key the server
rejects. Prefer this page for what a key does.

## Loading rules

- The YAML file is given with `-config path` or `PROUDAUTH_CONFIG`. Without a file
  the defaults below apply (and validation fails until required keys are set).
- **Unknown keys are rejected**, so typos fail startup instead of being ignored.
- Environment overrides (below) are applied after the file.
- Durations use Go syntax: `90s`, `15m`, `12h`, `2160h` (no `d` unit).
- **Secret references** (DEP-006): values documented as "secret ref" accept
  - `file:/path` — file contents, surrounding whitespace trimmed (Docker/Kubernetes secrets);
  - `env:NAME` — an environment variable;
  - `cred:NAME` — a systemd credential (`$CREDENTIALS_DIRECTORY/NAME`, from `LoadCredential=`);
  - `vault:<mount>/data/<path>#<field>` — a HashiCorp Vault KV v2 field. `VAULT_ADDR`
    and `VAULT_TOKEN` (or `VAULT_TOKEN_FILE`) come from the process environment;
    `VAULT_ADDR` must be `https` unless it is a loopback address;
  - `kms:<path>` — a key file wrapped by a KMS or HSM, unwrapped at use by
    `keys.kms.command` ([below](#keys), [keys.md](keys.md#kms-envelope-dep-016));
  - any scheme registered by an operator-built adapter
    (`configuration.RegisterSecretResolver`).

  Any other string is used literally. In production, literals are refused for
  `keys.root_keys`, `keys.pepper_keys`, `keys.signing_wrap_keys`, the database
  password, `storage.migration_database_url`, SMTP password, metrics token,
  email-provider callback secret (`delivery.email.events_secret`), SMS webhook
  secret and challenge-provider secrets. A `vault:` request times out after
  5 seconds and a `kms:` unwrap after `keys.kms.timeout`; no reference takes
  longer than 5 minutes. References other than key material are resolved again at each
  use (SMTP password, SMS and callback secrets, challenge-provider secrets), so
  a `vault:` or `kms:` reference there calls Vault or the KMS command each time.
- Key material (`keys.*_keys[].ref`) must resolve to 32 bytes encoded as hex or
  base64 (standard or URL alphabet, padded or not).
- There is no live reload and no file watcher: every change to the file or the
  environment takes effect when a process restarts, so a half-written file can
  never weaken a running process. Review a change with `identity-cli config-diff`
  first ([below](#reviewing-a-change)). Realm policy, clients and other realm
  configuration are not in this file; they change through the administration API
  (or configuration import) and are versioned and audited there.
- Validation rules are listed in [installation.md](installation.md#validation-rules).

## Reviewing a change

`identity-cli config-diff` (DEP-020, `internal/configuration/diff.go`,
`TestDiffClassifiesAndRedacts`) compares the current file with a proposed one
without connecting to the database:

```sh
identity-cli config-diff -from /etc/proudauth/config.yaml -to ./config.next.yaml
identity-cli config-diff -from /etc/proudauth/config.yaml -to ./config.next.yaml -json
```

- `-from` defaults to `PROUDAUTH_CONFIG`; `-to` is required. Both files are loaded
  like a server loads them, including the environment overrides of the shell
  that runs the command.
- The proposed configuration is validated first; an invalid file stops the
  command (`proposed configuration is invalid: ...`) and nothing is compared. The
  current file is only loaded, not validated.
- Each changed key is printed as `<mark> key: old -> new (restart)`, where the
  mark `!` flags a change that moves a security boundary and needs a second
  reviewer: `mode`, `keys.*`, `sessions.*`, `tokens.*`, `security.*`,
  `impersonation.*`, `privacy.*`, `limits.*`, `webauthn.*`,
  `server.trusted_proxies`, `server.public_origin`, `server.internal_listen`,
  `server.metrics_token`, `server.host_policy`, `server.public_listen`,
  `server.tls_cert_file`, `server.tls_key_file`, `server.mtls_listen`,
  `server.mtls_origin`, `server.client_cert_header`,
  `federation.allow_private_network`, `federation.ca_file`, `saml.*`,
  `directory.enabled`, `directory.allow_private_network`,
  `directory.egress_allowlist`, `directory.ca_file`,
  `federation.egress_allowlist`, `delivery.allow_private_webhooks`,
  `delivery.egress_allowlist`, `delivery.email.allowed_sender_domains`,
  `delivery.email.events_secret`, `delivery.sms.webhook_secret`,
  `storage.database_url`, `storage.migration_database_url`,
  `storage.runtime_role`, `observability.metrics_enabled`,
  `observability.otlp_endpoint` and `workers.metrics_listen` (DEP-020,
  `TestDiffBoundaryKeys`, `TestDiffMutualTLSBoundaries`). Other keys are not
  flagged: review them yourself.
- Values are shown as in a support bundle: secret references are printed, literal
  secrets as `[REDACTED]`.
- `-json` prints `{"valid": true, "changes": [{"key", "old", "new", "effect",
  "security_boundary"}]}`. `effect` is always `restart`: every key in this file is
  read at process start.

## Environment overrides

| Variable | Overrides |
| --- | --- |
| `PROUDAUTH_CONFIG` | Path of the YAML file (flag default for all binaries) |
| `PROUDAUTH_MODE` | `mode` |
| `PROUDAUTH_PUBLIC_ORIGIN` | `server.public_origin` |
| `PROUDAUTH_PUBLIC_LISTEN` | `server.public_listen` |
| `PROUDAUTH_INTERNAL_LISTEN` | `server.internal_listen` |
| `PROUDAUTH_DATABASE_URL` | `storage.database_url`. A secret reference (`file:...`) is kept as given; a plain value becomes `env:PROUDAUTH_DATABASE_URL`, so production accepts it and redacted exports show the variable name, never the value. |
| `PROUDAUTH_ROOT_KEY` | Replaces `keys.root_keys` with a single version 1 entry and sets `keys.active_version: 1`. A secret reference is the entry's `ref`; a plain key (64 hex digits) becomes `env:PROUDAUTH_ROOT_KEY`. |
| `PROUDAUTH_MIGRATE_ON_START` | `storage.migrate_on_start` (boolean) |
| `PROUDAUTH_EMAIL_ADAPTER` | `delivery.email.adapter` |
| `PROUDAUTH_SMTP_HOST` | `delivery.email.smtp_host` |
| `PROUDAUTH_SMTP_PORT` | `delivery.email.smtp_port` |
| `PROUDAUTH_SMTP_TLS` | `delivery.email.smtp_tls` |
| `PROUDAUTH_SMTP_USERNAME` | `delivery.email.smtp_username` |
| `PROUDAUTH_SMTP_PASSWORD` | `delivery.email.smtp_password`; a plain value becomes `env:PROUDAUTH_SMTP_PASSWORD`, as for the database URL |
| `PROUDAUTH_EMAIL_FROM` | `delivery.email.from` |
| `PROUDAUTH_HOST_POLICY` | `server.host_policy` (`any` or `strict`) |
| `PROUDAUTH_LOG_LEVEL` | `observability.log_level` |
| `PROUDAUTH_IMPERSONATION_ENABLED` | `impersonation.enabled` (boolean) |
| `PROUDAUTH_TRUSTED_PROXIES` | `server.trusted_proxies` (comma-separated) |
| `PROUDAUTH_COOKIE_INSECURE_DEV` | `sessions.cookie_insecure_dev` (boolean) |
| `PROUDAUTH_ARGON_MEMORY_KIB` | `security.password.argon_memory_kib` |
| `PROUDAUTH_ARGON_TIME` | `security.password.argon_time` |
| `PROUDAUTH_ALLOW_PRIVATE_EGRESS` | Sets `federation.allow_private_network`, `delivery.allow_private_webhooks` and `directory.allow_private_network` |

Environment overrides fail closed (DEP-020, `TestEnvParseErrorsFailClosed`): a
boolean variable must be one of `true`, `True`, `TRUE`, `t`, `T`, `1`, `false`,
`False`, `FALSE`, `f`, `F` or `0` (Go `strconv.ParseBool`), and `PROUDAUTH_SMTP_PORT` (1–65535), `PROUDAUTH_ARGON_MEMORY_KIB`
(1–4194304) and `PROUDAUTH_ARGON_TIME` (1–100) must be integers in range.
Anything else stops every binary at startup with `environment: <VARIABLE>: ...`
instead of silently turning a protection off. Empty variables are ignored.

These variables alone configure every binary, without a YAML file
(`TestProductionFromEnvironmentOnly`). The Compose files in
[deploy/dev and deploy/prod](../../deploy/README.md) run the same image this way for
development and production. A secret placed directly in a variable stays in the
container's environment, which `docker inspect` shows to anyone with Docker
access; prefer `file:` references to mounted secrets where that matters.

## Top level

| Key | Default | Description |
| --- | --- | --- |
| `mode` | `production` | `production` or `development`. Development permits plain-HTTP origins, the mail sink, insecure cookies, literal root keys, and serves the mail sink viewer `GET /dev/mailbox?realm=<name>&recipient=<address>` on the private operator listener only (never on the public API). Never expose development mode. |

## `server`

| Key | Default | Description |
| --- | --- | --- |
| `public_listen` | `:8080` | Address of the public listener (protocol, interaction, self-service, admin APIs, `/health/*`). |
| `internal_listen` | `127.0.0.1:9090` | Address of the internal listener (`/metrics`, `/health/live`, `/status`). Bind to a private interface. |
| `public_origin` | — (required) | Canonical external origin, e.g. `https://id.example.com`. Issuer = `<public_origin>/realms/<realm>`, also on custom domains. Also an allowed `Origin` for cookie-authenticated transaction steps. Email links and upstream-provider redirect URIs always use it. |
| `host_policy` | `any` | `any`: the `Host` header is not checked. `strict` (DEP-014): requests are served only on the host of `public_origin` (everything) and on verified realm custom domains (`POST /custom-domains`), each only for its own realm's paths (`/realms/<realm>/…`, `/api/v1/realms/<realm>/…`); `/health/*` is served on any host, and other requests get `421 misdirected_request`. The check uses the request's `Host` (port ignored), never `X-Forwarded-Host`; verified domains are cached for up to 30 s. See [installation.md](installation.md#custom-domains). |
| `trusted_proxies` | `[]` | IPs/CIDRs whose `X-Forwarded-For` is trusted; the right-most untrusted hop is the client IP. Forwarded host/proto headers are never used. Also the only direct peers whose incoming `traceparent` sampled flag is honored (OPS-003). |
| `shutdown_deadline` | `20s` | After `drain_delay`, how long the listeners may take to finish in-flight requests before the process exits (OPS-012). |
| `drain_delay` | `5s` | On SIGINT/SIGTERM, `/health/ready` answers `503 {"status":"draining"}` for this long while both listeners keep serving, so load balancers stop routing new requests before the listeners close. `0` skips the delay. Set it to at least your load balancer's readiness interval times its failure threshold, and keep `drain_delay` + `shutdown_deadline` below the orchestrator's termination grace period (the Kubernetes manifests use 30 s). |
| `tls_cert_file` | `""` | When set (with `tls_key_file`), the public listener serves TLS. The internal listener is always plain HTTP. |
| `tls_key_file` | `""` | Private key for `tls_cert_file`. |
| `read_timeout` | `15s` | Public listener read timeout (header timeout is fixed at 5 s, idle timeout 120 s). |
| `write_timeout` | `30s` | Public listener write timeout. Request processing is also bounded at 30 s. |
| `metrics_token` | `""` | Secret ref. When set, `/metrics` and `/status` (on the internal listener and on `workers.metrics_listen`) require `Authorization: Bearer <token>`; if the reference cannot be resolved, both answer 401. |
| `mtls_listen` | `""` | Address of a second TLS listener for mutual TLS (TOK-019, MCH-014, PROV-016), for example `:8443`. It uses `tls_cert_file` and `tls_key_file` (required), asks clients for a certificate without verifying it at the TLS layer, requires TLS 1.2 or later and serves the same routes as the public listener, which never asks for a certificate ([mutual-tls.md](../protocols/mutual-tls.md)). |
| `mtls_origin` | `""` | Public `https` origin of the mutual-TLS listener; published in discovery as `mtls_endpoint_aliases` for the token, introspection, revocation, UserInfo, PAR and device authorization endpoints. |
| `client_cert_header` | `""` | Header in which a TLS-terminating proxy forwards the client certificate as URL-escaped PEM (for example nginx `$ssl_client_escaped_cert`). Honored only from `trusted_proxies`, which must be set (startup fails otherwise). The proxy must remove the header from client requests. Either this key or `mtls_listen` makes discovery advertise certificate-bound tokens and the mutual-TLS client authentication methods. |

## `identity`

| Key | Default | Description |
| --- | --- | --- |
| `default_realm` | `main` | Realm used by `identity-cli realm-create` and `bootstrap` when `-name`/`-realm` is omitted. The API commands (`setup-account`, `login`, `api`, …) default to `main` regardless. |

## `storage`

| Key | Default | Description |
| --- | --- | --- |
| `database_url` | — (required) | Secret ref or literal PostgreSQL URL (pgx syntax). The runtime connection of the server, the worker and operator commands. |
| `migration_database_url` | `""` | Secret ref (required in production when set). Connection used to apply migrations (OPS-013): a schema-owner role kept apart from the runtime role. `identity-cli migrate`, `identity-server -migrate` and `migrate_on_start` use it; empty uses `database_url`. `identity-cli migrate -plan` is read-only and always uses `database_url` ([installation.md](installation.md#database-roles)). |
| `runtime_role` | `""` | PostgreSQL role (`^[a-z_][a-z0-9_]{0,62}$`, checked at startup; that the role exists is checked only when the grants run) that receives, after every successful migration run, `USAGE` on schema `public`, `SELECT, INSERT, UPDATE, DELETE` on all its tables and `USAGE, SELECT, UPDATE` on all its sequences, with default privileges for tables and sequences the migration role creates later; `CREATE` on `public` is revoked from it and from `PUBLIC` (which PostgreSQL 14 and older grant to every role; the revoke takes effect only when the migration role owns the schema or is a superuser, otherwise PostgreSQL only warns), and so is `DELETE` on the audit tables (`audit_events`, `audit_batches`, `audit_prunes`, `audit_prune_log`), which it prunes only through `proudauth_audit_prune` (AUD-007). The service's own credentials then need no DDL rights ([installation.md](installation.md#database-roles)). |
| `max_conns` | `20` | Pool maximum per process. |
| `min_conns` | `2` | Pool minimum per process. |
| `migrate_on_start` | `false` | `identity-server` and `identity-worker` apply pending migrations at startup (never contract migrations), audited as `operations.migrations.applied` with `trigger: migrate_on_start`. `identity-cli` operator commands never apply migrations; only `identity-cli migrate` does. Prefer `false` and an explicit `identity-cli migrate` after a backup. |
| `statement_timeout` | `10s` | PostgreSQL `statement_timeout` for every connection. |

## `keys`

See [keys.md](keys.md) before changing anything here.

| Key | Default | Description |
| --- | --- | --- |
| `root_keys` | — (required) | List of `{version, ref}`; each ref resolves to a 32-byte key. Purpose keys are derived from these with HKDF. |
| `active_version` | `1` | Root version used for new encryptions and for derived values (pairwise subjects, CSRF, cursors). Must exist in `root_keys`. |
| `pepper_keys` | `[]` | Optional dedicated password-pepper keys `{version, ref}`. When non-empty, new password verifiers are peppered with the highest version. |
| `signing_wrap_keys` | `[]` | Optional dedicated keys for encrypting signing private keys; otherwise derived from root keys. |
| `kms.command` | `[]` | Program and arguments of an external key provider (DEP-016), run without a shell to unwrap `kms:<file>` references in `root_keys`, `pepper_keys` and `signing_wrap_keys`: the wrapped key on standard input, `KMS_KEY_REF=<file>` added to the inherited environment minus every `PROUDAUTH_*` variable, the unwrapped key (hex or base64, 32 bytes) on standard output (at most 8 KiB; standard error is discarded). A `kms:` key reference without a command stops startup. When the command exits (or times out) while a child process it started still holds its output open, ProudAuth waits at most 1 more second for the output to close. Keys are unwrapped when a process starts and then held in its memory ([keys.md](keys.md#kms-envelope-dep-016)). |
| `kms.timeout` | `10s` | Time limit per unwrap, at most `1m` (`0` means 10 s; negative values stop startup). Secret references of any scheme are resolved within at most 5 minutes in total. |
| `signing_algorithm` | `RS256` | Algorithm for new signing keys: `RS256` (RSA 3072), `PS256` (RSA 3072), `ES256` (P-256), `EdDSA` (Ed25519). |
| `rotation_interval` | `2160h` (90 d) | The worker starts a planned rotation when the active key is older than this and no rotation is pending. |
| `prepublish_period` | `48h` | A pending key is published in JWKS this long before the worker activates it. |
| `retirement_period` | `168h` (7 d) | After activation of a successor, the old key stays in JWKS for `tokens.max_access_token_ttl` + this period. |

## `sessions`

| Key | Default | Description |
| --- | --- | --- |
| `idle_timeout` | `30m` | IdP session idle timeout, and the idle window of refresh families issued for ordinary (not remember-me, not offline) sessions. Each family keeps the idle window it was issued with across rotations ([ADR 0011](../architecture-decisions/0011-refresh-token-families.md)). |
| `absolute_timeout` | `12h` | IdP session absolute lifetime; refresh families of session-bound grants never outlive it. Realm and organization policy may shorten both values. |
| `remember_me_idle` | `168h` | Idle lifetime when the user requested remember-me and the client allows it. |
| `remember_me_absolute` | `720h` | Absolute lifetime for remember-me sessions. |
| `offline_idle` | `168h` | Idle lifetime of refresh families for `offline_access` grants, kept across rotations. |
| `offline_absolute` | `720h` | Absolute lifetime of offline grants and their refresh families. |
| `max_concurrent` | `50` | Active sessions per user; creating one more revokes the least recently active. `0` disables the limit. Realm policy `sessions.max_concurrent` may set a lower value. |
| `cookie_same_site` | `lax` | SameSite for `pa_sid` and `pa_tx` cookies: `lax`, `strict`, `none`. |
| `cookie_insecure_dev` | `false` | Omits the `Secure` cookie attribute. Rejected in production. |

## `tokens`

| Key | Default | Description |
| --- | --- | --- |
| `access_token_ttl` | `5m` | Validated (must be `<= max_access_token_ttl`) but does not set issued lifetimes: every API resource has its own `access_token_ttl_seconds` (default 300 when created). |
| `max_access_token_ttl` | `60m` | Upper bound for resource and client access-token lifetimes; also part of the JWKS retention window for retiring keys. |
| `id_token_ttl` | `5m` | ID token lifetime. |
| `authorization_code_ttl` | `60s` | Authorization code lifetime (max 10 m). |
| `transaction_ttl` | `10m` | Authentication transaction lifetime and `pa_tx` cookie max-age. |
| `challenge_ttl` | `10m` | Email OTP / verification / reset code lifetime. |
| `invitation_ttl` | `72h` | Default invitation lifetime. |
| `clock_skew` | `60s` | Tolerance applied by the server's own JWT verification (0–60 s). |
| `device_code_ttl` | `10m` | Device authorization code lifetime. |
| `exchange_max_chain_depth` | `2` | Maximum `act` nesting depth produced by token exchange. |

## `security`

| Key | Default | Description |
| --- | --- | --- |
| `password.min_length` | `15` | Minimum characters after NFKC normalization (realm policy may raise it). |
| `password.max_length` | `128` | Maximum characters. |
| `password.max_bytes` | `1024` | Byte limit checked before hashing; longer input is rejected, never truncated. |
| `password.argon_time` | `3` | Argon2id iterations for new verifiers. |
| `password.argon_memory_kib` | `65536` | Argon2id memory (KiB); production minimum 19456. |
| `password.argon_threads` | `2` | Argon2id parallelism. |
| `password.blocklist_file` | `""` | Optional file of additional forbidden passwords (one per line, case-insensitive), added to the embedded list. Startup fails if the file cannot be read. |
| `password.history_count` | `0` | Deployment floor for password history: the effective history is the larger of this value and the realm policy `password.history_count`. A new password matching one of that many previous passwords is rejected (`policy_code: reused`). |
| `password.legacy_hashes_until` | `""` | End of the migration window for imported legacy verifiers (CRED-004): salted SHA-256 (`$legacy-sha256$`), bcrypt (`$2a$`, `$2b$`, `$2y$`) and PBKDF2 (`$pbkdf2-sha1$`, `$pbkdf2-sha256$`, `$pbkdf2-sha512$`) ([imported verifiers](migration-adapters.md#imported-password-verifiers)). A date `YYYY-MM-DD` in UTC, inclusive. Until then (or while empty) such verifiers verify and are rehashed to Argon2id at the next successful sign-in. From the next day they no longer verify: the attempt fails like a wrong password (`401 invalid_credentials`, counting towards the temporary lock) and records `credential.password.legacy_retired` (reason `LEGACY_HASH_RETIRED`, without a realm, so only in the `audit_events` table), and user imports refuse such records ("legacy password verifiers are no longer accepted"). Affected users recover their password. `identity-cli doctor` prints how many accounts still have one ([migration.md](migration.md#credentials-and-factors)). |
| `mfa_floor.require` | `none` | `all`: every account in every realm needs MFA at sign-in, and realm policies with `mfa.requirement` other than `required` are refused (MFA-005). |
| `mfa_floor.admin_phishing_resistant` | `false` | Holders of privileged realm roles and protected accounts need a passkey with user verification at sign-in, and realm policies with `mfa.admin_phishing_resistant: false` are refused. Applied at sign-in only where the realm has passkeys enabled (`login.passkeys` or `webauthn` among `mfa.allowed_factors`); elsewhere it has no effect. While it is set (as with the realm's own `mfa.admin_phishing_resistant`), self-service passkey enrollment (`POST /me/webauthn/registration-options`) requires user verification for every user, so no passkey enrolled then fails the profile later. |
| `mfa_floor.forbid_org_admin_waiver` | `false` | Organization administration (`org.update`, `org.delete`, `org.roles.write`, `org.roles.assign`, `org.domains.write`, `org.ownership.transfer`, `org.projects.share`, `org.relationships.write`, and requests on other organization routes that grant roles: members added with roles beyond `member`, invitations offering such roles or project roles and their reassignment, joining or moving under a group that grants roles, dynamic rules on such a group; MFA-003) always needs an MFA session, and realm policies with `mfa.org_admin_mfa_optional: true` are refused. |
| `otp_length` | `6` | Digits in emailed one-time codes. |
| `otp_max_attempts` | `5` | Verification attempts per issued code. |
| `totp_skew_steps` | `1` | Accepted TOTP time steps on each side of now (30 s steps): `0` to `2` (MFA-002); anything else stops startup. |
| `recovery_code_count` | `10` | Codes per recovery-code batch: `5` to `20` (MFA-002); anything else stops startup. |
| `recent_auth_window` | `10m` | Maximum age of the session's authentication for sensitive actions: identifier and factor changes, password change, personal tokens, deletion request, self export, job downloads, audit export, configuration import, organization deletion and ownership transfer. Recovery-code regeneration and signing-key rotation use a fixed 5 minutes. |
| `admin_mfa_max_age` | `5m` | Maximum age of MFA evidence for starting or approving support access (max 5 m). |
| `dynamic_group_max_staleness` | `1h` (`0` also means `1h`) | How old a dynamic group's last recomputation may be before its rule-derived members stop receiving the group's roles (AZ-010, TEN-014): `10m` to `168h`, anything else stops startup. A rule-derived membership also grants nothing while the group's rule has an `error`, so a stopped worker or a broken rule fails closed instead of freezing access. A rule that matches more than 10000 members records that as the rule's `error` and leaves the memberships unchanged; they grant nothing while the error stands. The worker task `groups.dynamic` runs every 5 minutes: it recomputes the 100 least recently computed groups, then continues in batches of up to 200 while groups are older than half of this value, at most 4900 groups per run (100 + 24 batches of 200). |
| `decision_cache_ttl` | `30s` | How long callers of `/authorization/check` and `/check-batch` may cache a decision under its `cache_key` (AZ-019); the response's `cache_ttl_seconds` carries it in whole seconds. `0` to `10m`; `0` disables caching, anything else stops startup. ProudAuth keeps no decision cache itself: the key is a contract for callers. Only decisions made by RBAC alone carry a key: denials for a missing permission (`NOT_PERMITTED`), and allows of a non-privileged action without applicable ABAC policies, active pre-action hooks or obligations; never decisions about support tokens or privileged actions, never decisions that consulted relationship tuples or were made in a realm with an external policy engine, and never when an applicable role assignment has conditions, starts in the future or expires within the TTL, or the subject has a rule-derived (dynamic) group membership or a group membership with a validity window. The key covers realm, subject, actor, client, the token's kind, audience and `acr`, organization, resource, action, the subject's authorization revision, a fingerprint of the applicable role assignments (direct, of the subject's groups and of their ancestor groups, expanded through composed roles with the versions of every role involved), the organization's state and authorization revision, the membership's state and revision, the policy version and the asserted context. Granting or removing a role on a group raises the membership revision of every member of that group and of its descendant groups, and changing a role's permissions raises the revisions of everyone holding it or a role that composes it, at any depth, including members of groups that hold them (AZ-019). |
| `allowed_algorithms` | `[RS256, ES256, PS256, EdDSA]` | Algorithms accepted by the server's own JWT verifier. |
| `challenge_providers` | `[]` | Bot and abuse challenge services (SEC-014) that a realm's `authentication_flow.challenge_provider` can name ([headless-authentication.md](../protocols/headless-authentication.md#authentication-flow-policy)); nothing is contacted unless one is configured here and named by a realm. Each entry: `name` (unique, `^[a-z0-9][a-z0-9-]{0,39}$`), `verify_url` (absolute `https`; `http` only in development), `site_key` (public key passed to the login UI), `secret` (secret ref in production; resolved at each verification), `send_remote_ip` (default `false`: the client address is not sent), `timeout` (default `3s`, at most `10s`). Verification posts the form fields `secret`, `response` and, with `send_remote_ip`, `remoteip` to `verify_url` and expects `200` with JSON `{"success": true}` (the siteverify interface of common providers); the call goes through the delivery egress policy (`delivery.egress_allowlist`) and `privacy.residency`. A provider that fails or times out makes the step answer `503`. Support bundles and `config-diff` show a literal `secret` as `[REDACTED]`. |
| `policy_engines` | `[]` | External policy decision points (AZ-026) that a realm's `policy_engine` policy can name ([policy-engines.md](../integrations/policy-engines.md)). Each entry: `name` (unique, `^[a-z0-9][a-z0-9-]{0,39}$`), `url` (absolute, no userinfo; `https`, `http` only outside production), `token` (required bearer token; a secret reference in production; resolved at each call), `timeout` (at most `5s`; `0` means 1 s). Calls may reach private addresses (the operator chose them), but follow no redirects, read at most 64 KiB, require `https` in production and apply `privacy.residency`. Support bundles and `config-diff` show a literal `token` as `[REDACTED]`. |
| `min_auth_response` | `250ms` | Minimum duration of the password step and of password-reset requests, so unknown accounts are not distinguishable by timing. |
| `rate_limits.login_per_identifier` | `10` | Password attempts per identifier per window; the identify step allows 3× this. |
| `rate_limits.login_per_ip` | `100` | Identify and password attempts per client IP per window. |
| `rate_limits.login_window` | `15m` | Window for login budgets. |
| `rate_limits.login_per_realm` | `50000` | Password attempts, and separately proof attempts (below), across the whole realm per `login_window` (aggregate ceiling, SEC-006). |
| `rate_limits.login_per_client` | `20000` | Proof attempts per OAuth client per `login_window` (REG-012): emailed and SMS codes, magic links, TOTP, HOTP and recovery codes, passkeys, certificates and challenge answers made in a transaction. Password attempts per client have their own budget of the same size (it used to be 10 × `token_per_client`). `0` disables both. |
| `rate_limits.login_per_organization` | `10000` | Password attempts, and separately proof attempts, per organization per `login_window`, counted for transactions that name an organization (the `organization` request parameter), so one tenant cannot use up sign-in capacity for the others (TEN-018). Excess returns `429 rate_limited`. `0` disables it. |
| `rate_limits.send_per_identifier` | `5` | Code/link sends per identifier per window. |
| `rate_limits.send_per_ip` | `50` | Code/link sends per IP per window. |
| `rate_limits.send_window` | `1h` | Window for send budgets. |
| `rate_limits.send_cooldown` | `30s` | Minimum interval between sends to one identifier. |
| `rate_limits.send_per_client` | `1000` | Code/link sends per OAuth client per `send_window`: sends started from an authentication or registration transaction, and identifier-verification codes requested through `POST /verification-challenges` (counted for the client of the caller's token). Password-reset sends have no client context. |
| `rate_limits.send_per_organization` | `500` | Code/link sends per requested organization per `send_window` (transactions that name an organization, and identifier-verification sends whose token is bound to an organization). |
| `rate_limits.send_per_realm` | `5000` | Code/link sends across the realm per `send_window`, including password-reset and recovery sends. |
| `rate_limits.otp_verify_per_account` | `10` | Proof attempts (codes, magic links, TOTP, recovery codes, passkeys, certificates, challenge answers, password-reset and identifier-verification codes) per subject per `otp_verify_window`, across transactions. The subject is the account; a certificate presented before `identify` counts against that certificate (its thumbprint) from the client's /24 (IPv4) or /48 (IPv6) network. Each attempt also counts against `login_per_ip` for the client's address and `login_per_realm`, and attempts made in an authentication transaction against `login_per_client` and, when the transaction names an organization, `login_per_organization` (REG-012, SEC-006). Exhausted budgets answer `429 rate_limited` without counting as a failed proof. |
| `rate_limits.otp_verify_window` | `15m` | Window for verification budgets. |
| `rate_limits.signup_per_ip` | `20` | Registrations per IP per window. |
| `rate_limits.signup_window` | `1h` | Window for registrations. |
| `rate_limits.signup_per_client` | `500` | Registrations per OAuth client per `signup_window`. |
| `rate_limits.signup_per_realm` | `2000` | Registrations across the realm per `signup_window`. |
| `rate_limits.token_per_client` | `600` | Token-endpoint requests per client per window. |
| `rate_limits.token_window` | `1m` | Window for the token budget. |
| `rate_limits.organization_per_window` | `2000` | Access tokens minted in one organization's context per `token_window`, for every grant type including token exchange; beyond it `429 slow_down` with `Retry-After` (TEN-018). Fails closed: an unreachable limiter gives `503 temporarily_unavailable`. |
| `rate_limits.temporary_lock` | `15m` | Duration of the temporary password lock. |
| `rate_limits.failures_before_lock` | `10` | Failed password attempts that trigger the temporary lock. Each failure counts against the identifier tried and, when it names an account, against the account as well. Once the identifier's count is reached, the password step returns `429` for that identifier and records `authentication.password.temporarily_locked` (each attempt during the lock also counts as a proof failure of the transaction). Once the account's count is reached, no password of the account is checked through any identifier, so guessing stays bounded per account; through an identifier whose own count is not reached yet the step answers `401 invalid_credentials`, exactly as for an identifier without an account (the attempt is recorded as `authentication.password.temporarily_locked` and counts against that identifier), so a lock reached through an account's email address does not reveal its username or phone number (API-009). Other sign-in methods (passkeys, codes, magic links, federation) are not blocked. `0` disables the lock. |
| `rate_limits.invitations_per_organization` | `500` | Invitations created or resent per organization per `invitation_window` (INV-009). Revoking and re-creating an invitation does not reset it. |
| `rate_limits.invitations_per_recipient` | `10` | Invitations created or resent to one address per `invitation_window`, across organizations of the realm. |
| `rate_limits.invitation_window` | `24h` | Window for invitation budgets. |

Rate-limit counters are fixed windows stored in PostgreSQL (`rate_limit_counters`)
with digested keys, so every node shares them. A budget whose limit (or window) is
`0` is not applied. Exhausted budgets on the custom APIs return `429 rate_limited`
with `Retry-After`; the token endpoint answers `429 slow_down`.

Fixed budgets (not configurable): shared-signals pushes 600 per minute per
transmitter and 1200 per minute per address; check-session origin checks 300
per minute per address; registry tokens 600 per minute per address, and 20
failed registry sign-ins per address per 15 minutes; dynamic client
registration 20 per hour per address and 500 per hour per realm.

## `impersonation`

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Deployment switch. Realm policy and a resource opt-in are also required. |
| `max_ttl` | `5m` | Maximum support grant and token lifetime (0 < x <= 5 m). Realm policy may shorten. |
| `require_ticket` | `false` | Require `ticket_reference` on every request (realm policy can also require it). |
| `handoff_ttl` | `30s` | Handoff code lifetime (0 < x <= 30 s), never beyond the grant expiry. |
| `min_reason_length` | `10` | Minimum trimmed length of the support reason (maximum 1000). |

## `federation`

Upstream OIDC and GitHub-style OAuth connections (`internal/federation`).
Connections themselves are realm data, managed through
`/api/v1/realms/{realm}/identity-providers`.

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | When `false`, the federation service is not created: no connection is offered and federation steps return `feature_disabled`. |
| `allow_private_network` | `false` | Lets upstream metadata, token, JWKS and API calls reach private, loopback and link-local addresses. Rejected in production; use `federation.egress_allowlist` instead. |
| `egress_allowlist` | `[]` | CIDRs that upstream provider connections may reach even if private (for example an internal enterprise IdP). The production alternative to `allow_private_network`; `delivery.egress_allowlist` does not apply to upstream providers. |
| `ca_file` | `""` | PEM bundle of additional trusted roots for upstream TLS (added to the system roots). Startup fails if the file is unreadable or contains no certificate. |
| `fetch_timeout` | `10s` | Timeout for each upstream HTTP call. |
| `max_response_bytes` | `1048576` | Maximum upstream response size read. |

OIDC discovery and JWKS caches last one hour per provider/issuer/URL in
each server process. Concurrent misses share one fetch; unknown keys and
failed metadata responses retry at most once a minute. Failure cooldowns
also cover malformed JSON, issuer mismatches, redirects, oversized replies
and timeouts (FED-017, NFR-006). A cancelled request stops its own wait;
the shared fetch retains its independent `fetch_timeout`, including DNS.
Valid cached signing keys remain usable within their ordinary TTL. Workload
JWKS uses its documented five-minute cache and transport/status fallback;
Shared Signals uses a ten-minute cache and bounds signature-triggered
refreshes by the same minute. Budgets are per process and cache identity,
not deployment-wide DB counters. Administrative configuration changes and
fresh connection diagnostics invalidate their provider caches deliberately.
No TLS, address/residency, response-size or signature check is relaxed.

## `saml`

SAML 2.0 identity provider (SAML applications) and broker (SAML connections),
`internal/saml` ([saml.md](../integrations/saml.md)). Applications,
connections and signing keys are realm data managed through
`/api/v1/realms/{realm}/saml/...`.

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Turns on both SAML roles, their protocol endpoints and their APIs. When `false`, every SAML route answers `404 feature_disabled` and nothing SAML-related is advertised. The broker also needs `federation.enabled`. SAML connections stay listed and offered after this is switched off, and sign-ins through them fail: disable them first. |
| `max_message_bytes` | `262144` | Largest decoded (and, for HTTP-Redirect, inflated) SAML message and largest uploaded metadata document; `16384`–`4194304`. HTTP-POST messages are also bounded by `limits.max_body_bytes` (raise both for unusually large responses). |
| `max_clock_skew` | `5m` | Upper bound for the `clock_skew_seconds` of applications and connections; `0`–`30m`. Their default skew is 120 seconds, so a value below `2m` makes every application and connection set its skew explicitly (`422` otherwise). |
| `key_prepublish` | `48h` | How long the next SAML signing key must have been published in metadata before `POST .../saml/signing-keys/{id}/activate` accepts it without `force`. Not negative. |
| `retired_key_publication` | `168h` | How long a replaced SAML signing key stays published in metadata after its successor is activated. Not negative. |

## `directory`

LDAP/Active Directory federation and synchronization, and outbound SCIM
provisioning, `internal/directory`
([directory.md](../integrations/directory.md),
[outbound-provisioning.md](../integrations/outbound-provisioning.md)).
Connectors are realm or organization data managed through
`/directory-connectors`; these keys are deployment-wide bounds.

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | When `false`, the connector APIs answer `404 feature_disabled`, no run is scheduled and nothing is delivered, and accounts that a directory sources **fail closed**: password sign-in answers `503 upstream_unavailable`, and password changes and edits of directory-managed attributes are refused. Local accounts are unaffected. Do not switch it off while runs are queued ([directory.md](../integrations/directory.md#not-supported)). |
| `allow_private_network` | `false` | Lets directory connections reach private, loopback and link-local addresses. Development only: **rejected in production**; use `directory.egress_allowlist`. `PROUDAUTH_ALLOW_PRIVATE_EGRESS` also sets it. |
| `egress_allowlist` | `[]` | CIDRs that directory (LDAP) connections may reach even if private, checked against every resolved address at connection time. In production, list your directory servers' networks here. Outbound SCIM connectors use `delivery.egress_allowlist` and `delivery.allow_private_webhooks` instead, and need `https` in production. |
| `ca_file` | `""` | PEM bundle of additional trusted roots for LDAPS and StartTLS (added to the system roots; each connector can add its own). Read only while `enabled` is `true`; startup fails if the file is unreadable or contains no certificate. |
| `connect_timeout` | `5s` | LDAP connection timeout, at most `1m`; a connector's `connect_timeout_seconds` overrides it. |
| `operation_timeout` | `10s` | Timeout of one LDAP operation, at most `2m`; a connector's `operation_timeout_seconds` overrides it. |
| `max_entries_per_run` | `100000` | Most entries one synchronization or reconciliation run processes, `0`–`1000000` (`0` means 100000); a run that exceeds it fails without deprovisioning. An LDAP connector's own `max_entries` can only lower this limit, never raise it. |

## `delivery`

| Key | Default | Description |
| --- | --- | --- |
| `email.adapter` | `smtp` | `smtp` or `dev_sink` (development only). |
| `email.smtp_host` | `""` | Required for `smtp`. |
| `email.smtp_port` | `587` | SMTP port. |
| `email.smtp_username` | `""` | SMTP AUTH username (empty: no authentication). |
| `email.smtp_password` | `""` | Secret ref. |
| `email.smtp_tls` | `starttls` | `starttls`, `implicit`, or `none` (rejected in production). |
| `email.from` | `""` | Sender address; required for `smtp`. Overridable per realm/organization through `PATCH /notification-settings`: a realm sender must use this address's domain or one in `email.allowed_sender_domains`, an organization sender one of the organization's verified domains (MSG-005). |
| `email.from_name` | `ProudAuth` | Sender display name. |
| `email.allowed_sender_domains` | `[]` | Additional domains a realm-level sender address (`PATCH /notification-settings` without `organization_id`) may use; the domain of `email.from` is always allowed. Entries are trimmed, lowercased and stripped of a trailing dot, then compared exactly with the address's canonical domain, which writes internationalized names in punycode: list such domains in that form. Others get `422` on `sender_address`. |
| `email.events_secret` | `""` | Secret ref. Enables `POST /api/v1/realms/{realm}/delivery-events` for bounce and complaint callbacks from the email provider (MSG-007); without it the route returns `404 feature_disabled`. Requests are signed like ProudAuth's own webhooks: `Webhook-Id`, `Webhook-Timestamp` (Unix seconds, ±5 minutes) and `Webhook-Signature: v1,<base64 HMAC-SHA256(key, "<id>.<timestamp>.<raw body>")>`, where the key is the base64 part of a `whsec_...` value, or the value itself otherwise. Body: `{"events": [{"type": "delivered" \| "bounce" \| "complaint", "recipient", "provider_message_id", "permanent"}]}`, 1–500 events, all applied or none; response `{"applied": n}`. A bounce marks the job whose `provider_message_id` (the `Message-ID` ProudAuth sent) matches `failed`; a permanent bounce or a complaint suppresses the recipient for optional notices in that realm. Security and account notices are still delivered, and feedback never verifies or changes an identifier. One secret serves every realm. Must be a secret reference in production; a literal is shown as `[REDACTED]` in support bundles. |
| `sms.adapter` | `none` | `none`, `dev_sink` (development only; messages go to the development mailbox) or `webhook`. ProudAuth ships no carrier integration: `webhook` posts each message to an operator-run gateway. |
| `sms.webhook_url` | `""` | Gateway URL for `webhook` (absolute; `https` in production). Subject to the egress policy (`delivery.egress_allowlist`; private addresses otherwise refused). |
| `sms.webhook_secret` | `""` | Secret ref (literal allowed only in development; redacted from support bundles). Each request carries `X-ProudAuth-Timestamp` and `X-ProudAuth-Signature: v1,<base64 HMAC-SHA256(secret, "<timestamp>.<body>")>`; body `{"id","to","text"}`. |
| `sms.allowed_countries` | `[]` | Calling-code prefixes such as `+1`, `+49`; empty allows all. Other numbers get `validation_failed` (`phone`), identically for unknown numbers. |
| `sms.daily_budget` | `1000` | Deployment-wide cap on SMS jobs created in the last 24 h; beyond it sends fail with `429` (`Retry-After: 3600`). A sign-in code requested for a number without an account gets the same `429`, body and `Retry-After` (API-009). `0` disables the cap. |
| `payload_retention` | `24h` | Encrypted notification payloads (recipient and template data) are purged this long after the job finished or expired. |
| `webhook_timeout` | `10s` | Timeout for webhook and back-channel logout HTTP calls. |
| `webhook_max_attempts` | `12` | Webhook attempts before `dead_letter`. |
| `allow_private_webhooks` | `false` | Allows webhook, back-channel logout and organization mail server destinations in private, loopback and link-local ranges. **Rejected in production**; use `egress_allowlist`. A webhook subscription (or hook) reaches private destinations only when it is itself created with `allow_private_network: true`, which the API refuses unless this key or `egress_allowlist` permits private destinations; other subscriptions are restricted to public addresses. |
| `egress_allowlist` | `[]` | CIDRs that outbound webhook, back-channel logout, hook, SMS gateway and organization mail server (TEN-022) connections may reach even if private (webhook subscriptions and hooks only with `allow_private_network: true`). An organization's own SMTP server is refused unless every address its host name resolves to is public or listed here. |

Outbound HTTPS connections other than those to upstream identity providers
and workload key sets (`federation.ca_file`) and to directories
(`directory.ca_file`), such as webhooks, hooks, back-channel logout, outbound
SCIM provisioning and the SMS gateway, verify certificates against the system
trust store only; there
is no `delivery` CA bundle. To reach a destination whose certificate comes
from a private CA, add the CA to the trust store of the host or container
image (on Linux the Go runtime also reads `SSL_CERT_FILE`, which replaces the
system bundle, and `SSL_CERT_DIR`). `scripts/interop-keycloak.sh` does this
for back-channel logout to Keycloak.

## `workers`

| Key | Default | Description |
| --- | --- | --- |
| `concurrency` | `4` | Maximum asynchronous jobs (exports, user imports, organization deletion) one worker runs in parallel per tick; each job is claimed with `FOR UPDATE SKIP LOCKED` and a lease. Other worker tasks run sequentially; run more worker processes to scale them. |
| `lease_duration` | `60s` | Lease on claimed notification jobs and jobs; expired leases are reclaimed. |
| `poll_interval` | `1s` | Worker scheduler tick. |
| `max_attempts` | `8` | Attempts for asynchronous jobs before `dead_letter`. Notification jobs use 5 attempts, back-channel logout 8, webhooks `delivery.webhook_max_attempts`. |
| `batch_size` | `100` | Rows claimed per task run (outbox, notifications, webhooks). |
| `audit_seal_every` | `30s` | Interval of the audit sealing task (up to 5000 events recorded more than 2 s earlier, by the database clock, per batch). The age of the oldest unsealed event is `proudauth_audit_unsealed_oldest_seconds` and `/status` `backlog_oldest_seconds.audit_sealing`. |
| `tenant_batch_share` | `25` | Fair share per batch (TEN-018): a worker claims at most this many due notifications of one organization (messages without an organization share one share per realm) and at most this many due deliveries of one webhook subscription in each run, so one tenant's backlog cannot hold up the others' messages. `0`, or a value above `batch_size`, means no cap. |
| `max_jobs_per_organization` | `2` | Most asynchronous jobs of one organization running at once across all workers (TEN-018); further jobs of that organization wait while other tenants' jobs are claimed. Jobs without an organization are not limited. While the cap is on, job claims are serialized by a database advisory lock so concurrent workers cannot exceed it together (`TestWorkerPoolBoundsAndTenantShares`). `0` disables the cap. |
| `drain_timeout` | `20s` | On SIGINT/SIGTERM the worker stops claiming work at once and lets the task in progress finish for at most this long (`0` or negative means 20 s); then its context is cancelled. The worker then returns what it still holds (running jobs back to `queued`, its notification jobs and webhook deliveries due immediately) so another worker resumes without waiting for `lease_duration` (OPS-012, `TestWorkerShutdownReleasesLeases`). |
| `metrics_listen` | `""` | When set (for example `127.0.0.1:9091`), `identity-worker` serves `/metrics`, `/status` and `/health/live` on this private address, with the same `server.metrics_token` and `observability.metrics_enabled` rules as the server's internal listener. Empty: the worker has no listener. |

## `observability`

| Key | Default | Description |
| --- | --- | --- |
| `log_level` | `info` | `debug`, `info`, `warn`, `error` (any other value means `info`). `debug` is rejected in production (SEC-015): open a time-limited, audited debug window with `identity-cli debug-window` instead ([support-bundle.md](support-bundle.md#debug-logging-windows)). |
| `log_format` | `json` | `json` or `text` (slog). Redaction applies to both. |
| `metrics_enabled` | `true` | When `false`, `/metrics` on the internal listener returns 404. |
| `trace_sampling` | `0` | Probability (0–1) of sampling a request, and each worker task run. An incoming `traceparent` always continues its trace ID, but its sampled flag is honored only when the request comes directly from an address in `server.trusted_proxies`; from anyone else this probability decides. Request logs always carry `trace_id`/`span_id`; sampled requests also emit a `span` log record (route, status, start, duration) and, with `otlp_endpoint`, exported spans. Outbound HTTP calls made while serving a request carry a `traceparent` ([monitoring.md](monitoring.md#tracing)). |
| `otlp_endpoint` | `""` | OTLP/HTTP endpoint that receives sampled spans of `identity-server` and `identity-worker` as JSON (OPS-003), for example `https://otel-collector:4318/v1/traces`; absolute URL without credentials, `https` in production unless the host is loopback; no authentication headers can be configured. Spans are sent in batches of up to 256 every 5 seconds from a queue of 4096; when the queue is full, the collector fails or the process is shutting down, spans are dropped, never delayed (no metric counts them). The exporter ignores proxy environment variables and never follows redirects; it is checked against `privacy.residency.allowed_destinations` at startup only and does not use the egress policy. Empty disables export ([monitoring.md](monitoring.md#tracing)). |
| `max_clock_skew` | `2s` | `/health/ready` returns 503 (`reason: clock_skew`) when the server clock differs from the database clock by more than this; `0` disables the check. |

## `privacy`

| Key | Default | Description |
| --- | --- | --- |
| `telemetry_opt_in` | `false` | Must remain `false`; `true` is a validation error because no telemetry sink exists. |
| `audit_retention` | `9600h` (400 d) | Sealed audit events older than this are deleted by `retention.cleanup` (every 5 minutes, up to 100 batches per run), except category `emergency`, categories listed in `audit_retention_by_category`, events of realms or organizations whose policy keeps evidence longer (realm `audit.retention_days`, organization `audit_retention_days`), events under an active legal hold and, while `audit_archive_dir` is set, events of batches not yet archived ([data-inventory.md](data-inventory.md#audit-retention-and-legal-holds)). Imported historical records (`imported_audit_events`, MIG-016) older than this, counted from their import, are deleted too (up to 1000 per run), unless the `imported` category sets its own value. See the verification caveat in [incidents.md](incidents.md#audit-chain-verification-failure). |
| `audit_retention_by_category` | `{}` | Retention per audit category, overriding `audit_retention` (AUD-009), for example `{data_access: 2160h, audit: 26280h}`. Allowed names: `account`, `application`, `audit`, `authorization`, `configuration`, `data_access`, `imported` (historical records imported with `POST /audit-imports`, counted from the import), `operations`, `privacy`, `security`, `support`, `token` (`configuration.AuditCategories` without `emergency`; the contract test `TestAuditCategoriesKnown` fails when the code records a category missing from that list). Any other name stops startup (`unknown category`), and `emergency` is rejected because emergency events are never pruned. Each value must be at least `24h`. |
| `audit_archive_dir` | `""` | Directory that receives every sealed audit batch as a write-once NDJSON file (AUD-008; worker task `audit.archive`, every minute, up to 500 batches per run). Mount storage you control independently of the database there, ideally with retention locks, and make it writable by `identity-worker`. While it is set, retention prunes only batches already archived, so a stopped archive also stops audit retention. After a database restore the archive continues in a `fork-*` subdirectory. Retention never deletes archived files. Verify with `identity-cli verify-audit-archive` ([incidents.md](incidents.md#audit-archive-aud-008)). Empty disables archiving. |
| `session_retention` | `720h` | Ended authorization grants (revoked, or past their expiry) are deleted this long after they ended, with their refresh families and tokens, authorization codes and opaque access tokens (at most 1000 grants per run); then client sessions and sessions that ended this long ago, a session only once no grant references it ([data-inventory.md](data-inventory.md#sessions-tokens-and-authentication)). |
| `history_retention` | `4320h` (180 d) | Operational history is deleted this long after it ended (PRV-004): revoked consents, invitations accepted, declined, expired or revoked, finished notification jobs (`accepted`, `failed`, `expired`, `suppressed`), delivered and dead-lettered webhook deliveries and delivered or failed back-channel logout deliveries (deliveries counted from their creation). At least `168h`. Audit events about them follow audit retention. |
| `export_retention` | `24h` | Lifetime of encrypted job results (exports) available for download. |
| `deletion_grace_period` | `336h` (14 d) | Delay between a self-service deletion request and permanent deletion. Until then the owner can cancel by signing in (the transaction's only action is `cancel_deletion`, USR-012); the `deletion_scheduled` notice names the time. |
| `backup_retention` | `0s` | How long you keep database backups (PRV-005). Informational: `GET /users/{user}/deletion-status` uses it to date when a deleted account leaves the last backup; `0` reports that stage as `unknown`. ProudAuth does not manage backups. |
| `residency.region` | `""` | Label of the deployment's region, reported by `/status` (PRV-003). |
| `residency.allowed_destinations` | `[]` | Host names, or `.domain` suffixes matching every host under that domain (case-insensitive), that outbound connectors may reach. Empty: no residency restriction. When set, it is checked when webhooks, pre-action hooks, organization mail servers (`PUT /organizations/{org}/notification-settings/smtp`, `422` on `host`), upstream identity providers (issuer, discovery, endpoint and JWKS URLs, `422`) and workload trusts (`jwks_uri`) are saved; at every connection of webhooks, hooks, back-channel logout, the SMS gateway, challenge providers, policy engines, organization mail servers, upstream identity providers and workload key sets; and at startup for `delivery.email.smtp_host` (the deployment relay is not checked again when it connects), `delivery.sms.webhook_url` and `observability.otlp_endpoint`. Destinations outside the list are refused like other egress-policy violations. It does not cover the database, backups, logs, Vault or a KMS command ([data-inventory.md](data-inventory.md#data-residency)). |
| `store_full_ip` | `false` | Audit `ip_context` and `sessions.client_ip` store the full IP instead of /24 (IPv4) or /48 (IPv6). `auth_transactions.client_ip` holds the full address while the transaction is pending, because per-IP budgets need it; unless this key is set, the client IP and user agent of finished transactions are cleared at the next cleanup run (every 5 minutes), and the rows are deleted 24 h after they finished (PRV-002, [data-inventory.md](data-inventory.md)). |

## `limits`

Explicit bounds on input size and work per request (NFR-001). Each key has a
**safe range**: every product feature works inside it, and a value outside
it stops startup (`limits.<key> must be <min>..<max>`). Lower bounds follow
from what the product itself sends or accepts: migration-adapter import
batches of up to 192 KiB and SAML POST messages need a 256 KiB body, and a
policy definition nested to its own limit (8 condition levels) inside a
configuration document needs a JSON depth of about 24. Raise a limit only
for a measured need: larger bodies, tokens and pages cost memory and time on
every request that uses them.

| Key | Default | Description |
| --- | --- | --- |
| `max_body_bytes` | `262144` | Request body limit in bytes, for every route; a larger body answers `413 payload_too_large`, whether its length is declared or found while reading. `262144`–`67108864`. |
| `max_header_bytes` | `16384` | Header limit of the public listener in bytes (request line and headers); beyond it the request is refused with `431`. `8192`–`1048576`. |
| `max_token_bytes` | `8192` | Largest token in bytes accepted by the server's verifier and introspection (larger tokens are invalid or inactive). `4096`–`65536`. |
| `max_json_depth` | `32` | Deepest JSON nesting accepted by the strict request decoder (`400`, "malformed JSON"). `32`–`256`. |
| `max_page_size` | `200` | Maximum `limit` for paginated lists; a larger `limit` is reduced to it. `1`–`1000`. |
| `default_page_size` | `50` | Page size when `limit` is missing or invalid. |
| `max_batch_size` | `100` | Maximum items in `POST /authorization/check-batch` and in bulk invitations (`POST /organizations/{org}/invitations/batch`; the error names the configured maximum, "1..<max> invitations (limits.max_batch_size)"). `1`–`10000`. |
| `max_group_depth` | `8` | Maximum group nesting depth (`422` when a change would exceed it). `1`–`32`. |
| `max_role_expansion` | `64` | Maximum roles reached through composite expansion; a role graph beyond it is refused at creation and evaluates to deny. `8`–`1024`. |
| `invitation_resends` | `5` | Times one invitation can be resent after its first send (INV-009): the default allows 5 resends (6 sends in all), `0` allows none; beyond it `429 rate_limited` ("resend limit reached for this invitation"). `0`–`20`. |
| `shared_invitation_max_uses` | `100` | Highest `max_uses` of a shared invitation link (`422` on `max_uses` above it). `1`–`10000`. |
| `shared_invitation_max_ttl` | `72h` | Longest lifetime of a shared invitation link: a `ttl_hours` of `0` or above it gets 24 hours (or this value, if shorter) instead of an error. `1h`–`720h`. |
| `client_secrets_max` | `3` | Active (overlapping) secrets per client; issuing one more answers `409 conflict` ("revoke an old secret first"). `1`–`10`. |
| `metadata_bytes` | `16384` | Size limit of organization `metadata`, of a user's `profile` and `admin_metadata`, and of an organization membership's `metadata` (USR-009) as JSON (`422` on the field). `admin_metadata` given in `POST /users` is not checked. `1024`–`262144`. |
| `max_inflight_requests` | `2000` | Concurrent requests per process before shedding with `503` and `Retry-After` (NFR-002); `1`–`100000`, `0` means `2000`; a separate pool of a quarter (plus one) serves `/health/*` and requests that carry an `Authorization` header to `/api/v1/realms/...` paths containing `/users`, `/settings`, `/signing-key`, `/emergency/`, `/sessions`, `/clients` or `/role-assignments` (not `/me/` paths). Anonymous requests to those paths use the main pool. |

## `extensions`

Trust for signed plugin packages (EXT-014, [plugins.md](../integrations/plugins.md)).
Realm-level extension settings are realm policy, not configuration:
`extensions.plugin_review` (`second_admin` by default, or `single_admin`) and
`extensions.workflow_publish_approval` (default `false`;
[workflows.md](../integrations/workflows.md#authority-and-accountability)).

| Key | Default | Description |
| --- | --- | --- |
| `plugin_publishers` | `[]` | Ed25519 publisher keys whose signatures make a plugin package uploadable and installable; with none, every upload is refused (`403`), and there is no unsigned mode. Each entry: `key_id` (unique; `^[a-z0-9][a-z0-9.-]{0,62}$`; packages name it in `signature.key_id`), `publisher` (same pattern; the manifest's `publisher` must equal it; several keys may share a publisher), `public_key` (standard base64 of the raw 32-byte public key; public keys are not secrets) and optional `not_after` (RFC 3339; packages are checked against it at upload, installation and rollback, not when an installed plugin is enabled again). Any violation stops startup; a `not_after` already in the past is accepted at startup and refused at use. Removing a key stops new uploads and installations signed with it, not plugins already installed. |

## `webauthn`

Deployment-wide passkey trust settings (PASS-009, PASS-010,
`internal/configuration/webauthn.go`). Realm passkey policy (attestation,
allow and block lists, related origins, `credProtect`) is realm policy under
`webauthn`, not configuration ([passkey-trust.md](passkey-trust.md)).
`identity-cli config-diff` marks every `webauthn.*` change as a security
boundary change.

| Key | Default | Description |
| --- | --- | --- |
| `metadata_file` | `""` | A FIDO Metadata Service (MDS3) BLOB that the operator downloads and refreshes; the server never fetches metadata. Verified at startup against the FIDO Alliance root (or `metadata_root_file`); an unreadable or invalid file stops startup. Read only at startup: replace the file and restart to refresh it. Its entries are trusted metadata for realms with `webauthn.require_trusted_attestation` |
| `metadata_root_file` | `""` | PEM root certificate of a private metadata service, used instead of the FIDO Alliance root. Requires `metadata_file` |
| `related_origins` | `false` | Lets realms declare WebAuthn Level 3 related origins and serves `/.well-known/webauthn`. Off by default because clients without Level 3 support refuse such origins; while off, realm policies with `webauthn.related_origins` are refused (`422`) |

## Values that are not configuration

Some limits are fixed in code: PAR request lifetime 60 s; device polling interval
5 s (+5 s per `slow_down`); DPoP proof age 2 minutes; client assertion lifetime at
most 5 minutes; handoff and impersonation caps; setup tokens 72 h for
administrator-created users and 2 h for assisted recovery; job download tokens
5 minutes; previous webhook secret valid 24 h after rotation; signing-key cache
5 s; realm cache 2 s (also the delay before an emergency grant control applies on
every node); registered-origin cache 5 s; maintenance and debug-window state
cache 2 s; debug windows at most 1 h in production (24 h otherwise); lifecycle
jobs at most 100 accounts per rule, realm and run; bulk user operations at most
1000 accounts per job. Shared signals: 5 streams per receiver, 8 push attempts,
undelivered events expire after 7 days and are deleted after 14, received-event
records kept 30 days, 50 transmitters per realm, transmitter key sets cached
10 minutes ([shared-signals.md](../integrations/shared-signals.md)).
Authentication flow revisions: 20 open drafts per realm, 200 simulation cases
per request. Federation transfers: 50000 entries per transfer, 2000 per
request. Registry tokens: 60–3600 s per registry service.
Protocol extensions: JARM responses expire after 10 minutes; `fapi2` clients
get authorization codes of at most 60 s and access tokens of at most
10 minutes; dynamic registration allows 20 registrations per hour per
network and 500 per realm; HOTP enrollment expires after 15 minutes and
resynchronization allows 5 attempts per 15 minutes; workload key sets are
cached 5 minutes (refetched at most once a minute for an unknown key) with a
60 s clock skew for assertions; relationship decisions stop at depth 6,
64 object reads and 1000 tuples per object, and `list-objects` at 5000
candidates and 1000 checks; policy engine answers at most 64 KiB; access
reviews cover at most 10000 assignments; elevation lasts 5 minutes to
7 days.
