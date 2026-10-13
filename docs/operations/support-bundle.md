# Support bundle and debug logging

Requirement: OPS-010, SEC-015. Code: `supportBundle` in `cmd/identity-cli/ops.go`,
`Config.Redacted` in `internal/configuration/config.go`; debug windows in
`cmd/identity-cli/operator.go` (`debug-window`), `internal/maintenance` and
`internal/observability`.

```sh
identity-cli support-bundle -config /etc/proudauth/config.yaml -out support-bundle.json
```

The command connects with the operator's configuration, writes one JSON file
to the path given with `-out` (required: diagnostic artifacts go only to a
location you choose, DEP-004; file mode `0600`) and records the audit event
`operations.support_bundle.generated` (actor `operator`, `local:<OS user>`).
If that audit record cannot be written, the command fails ("support bundle
written but its audit record failed: ..."): the file has been written by
then (OPS-013). `.dockerignore` excludes `support-bundle.json` so it is not baked into images.

**Review the file before sharing it.** It is plain JSON; open it and check.

## Contents

| Field | Content |
| --- | --- |
| `generated_at`, `version`, `go_version`, `os` | Time, ProudAuth release the CLI was built from (`dev` for builds without `-X main.version`), Go runtime version, OS/architecture of the CLI host |
| `configuration` | The full effective configuration after redaction (below) |
| `migrations` | Each embedded migration: name, checksum, applied time |
| `realms` | Per realm: name, state, policy revision, and signing-key metadata (kid, algorithm, state, created/activated/retiring/publish-until/compromised times) |
| `row_counts` | Row counts of `users`, `organizations`, `clients`, `sessions`, `outbox_events`, `notification_jobs`, `webhook_deliveries`, `jobs` |
| `backlogs` | Pending outbox events, dead-lettered jobs |
| `key_hierarchy_fingerprint` | Non-secret fingerprint of the active root key |

## Redaction

These configuration fields are replaced with `[REDACTED]` when they hold a literal
value; secret **references** (`file:/run/secrets/...`, `env:NAME`) are kept so the
reader can see where the secret comes from:

- `storage.database_url`, `storage.migration_database_url` (earlier versions
  included a literal migration connection, with its password, unredacted)
- `keys.root_keys[].ref`, `keys.pepper_keys[].ref`, `keys.signing_wrap_keys[].ref`
- `delivery.email.smtp_password`, `delivery.email.events_secret`
- `delivery.sms.webhook_secret`
- `server.metrics_token`
- `security.challenge_providers[].secret` (earlier versions included a literal
  secret unredacted) and `security.policy_engines[].token`
  (`TestRedactedHidesProviderSecrets`)

In production all of these must be references (DEP-006), except a
`storage.database_url` without an embedded password, which is still shown as
`[REDACTED]` when it is a literal.

Never included: key material, password verifiers, TOTP seeds, tokens, session or
grant rows, user records or other personal data, audit events.
`TestSupportBundleIsSanitized` (`cmd/identity-cli/ops_test.go`) generates a
bundle against a realm with a signing key and a pending bootstrap setup token
and checks the contents above, the file mode and the audit event, and that no
literal secret, root key, private key material or setup token is in the file.

Included and not redacted — decide whether you are comfortable sharing them:
`server.public_origin`, listener addresses, `server.trusted_proxies`, TLS
certificate and key **paths**, SMTP host, port and username, sender address,
`delivery.egress_allowlist`, `security.password.blocklist_file` path, realm names,
and every other non-secret setting.

## Debug logging windows

Production refuses `observability.log_level: debug`. To collect debug records
for a support case, an operator opens a time-limited window instead (SEC-015,
`TestDebugWindow`):

```sh
identity-cli debug-window -for 15m -component worker -reason "CASE-123 webhook retries"
identity-cli debug-window -close
```

- `-for` (default `15m`) is at most 1 hour in production and 24 hours in
  development; `-reason` is required to open a window. Opening a new window
  replaces the open one.
- `-component` limits the extra records to one log `component` (the value every
  record carries, for example `server`, `http`, `worker`, `audit` or
  `notification`); empty means all. The name is not checked against a list, so a
  misspelled component produces no extra records.
- Inside the window, records below the configured `observability.log_level` are
  written for that component; outside it nothing changes. Redaction is applied
  exactly as for other records: secret-named attributes become `[REDACTED]` and
  bearer-like values are masked.
- The window is stored in `system_state` (migration `0026`) and picked up by
  each server at its first request after its 2-second state cache expires and by
  each worker on its next scheduler tick. It ends by itself at `debug_until`; `-close` ends it earlier.
- Opening and closing are audited as `operations.debug_window.opened` and
  `operations.debug_window.closed` (actor `local:<OS user>`, metadata
  `duration_seconds`, `component` and `reason_text`), in the same transaction
  that stores the window, so neither is recorded without the other. The current window is shown
  by `identity-cli maintenance` and under `maintenance` in `/status`
  ([monitoring.md](monitoring.md#operator-status)).

Debug records can contain identifiers and request details that `info` records
do not; review them before sharing, as you would a support bundle.
