# Plugins

Requirements: EXT-014 (plugin lifecycle), with EXT-013, EXT-018, SEC-020,
AZ-006. Code: `internal/plugin` (package verification, review,
install/upgrade/rollback, enable/disable), `internal/httpapi/plugins.go`,
`internal/configuration/extensions.go` (trusted publisher keys), migration
`0071_plugins.sql`. Contracts:
[api/plugins/package.v1.json](../../api/plugins/package.v1.json) and
[api/plugins/manifest.v1.json](../../api/plugins/manifest.v1.json). Tests:
`TestPluginLifecycle`, `TestPluginSingleAdminReview` (`tests/e2e`), `internal/plugin`,
`TestPluginPublisherKeys` (`internal/configuration`).

A plugin is a **signed, versioned configuration bundle**: a set of pre-action
hooks, webhook subscriptions and [lifecycle workflows](workflows.md) that a
vendor or an internal team ships together, which a realm reviews once and
installs, upgrades, rolls back, disables or removes as a unit. A plugin
contains no code and can configure nothing the administration API cannot
([ADR 0021](../architecture-decisions/0021-no-embedded-code-execution.md));
the logic stays in the hook and webhook endpoints the plugin points to.

## Trust: publisher keys

Only packages signed by a key the **operator** trusts can be uploaded or
installed. The keys are deployment configuration
([configuration.md](../operations/configuration.md#extensions)):

```yaml
extensions:
  plugin_publishers:
    - key_id: acme-2026
      publisher: acme
      public_key: "base64 of the raw 32-byte Ed25519 public key"
      not_after: "2027-06-30T00:00:00Z"   # optional, RFC 3339
```

- `key_id` and `publisher` match `^[a-z0-9][a-z0-9.-]{0,62}$`; key IDs are
  unique, and one publisher may have several keys (for rotation).
  `public_key` is standard base64 of exactly 32 bytes; `not_after` is an
  RFC 3339 time. Startup fails on any violation; a `not_after` already in the
  past is accepted at startup and refused when the key is used.
- There is no unsigned or development mode, and no download from URLs or a
  marketplace: packages are uploaded, and only signatures by listed keys are
  accepted.
- A plugin name belongs, in each realm, to the publisher of its first upload
  (`409` for another publisher), permanently: plugin rows and versions are
  never deleted, even when the only version was rejected.
- Removing a key, or passing its `not_after`, stops new uploads,
  installations, rollbacks and enables of packages signed with it (`403`):
  enabling a plugin re-checks the signature, the key, contract compatibility
  and the enabling administrator's permissions like an installation. It does
  **not** stop what is already running: an enabled plugin's parts keep
  running until an administrator disables or uninstalls it. After a key
  compromise, disable or uninstall the plugins it signed.

## Package format

`POST /plugins` takes the package
([api/plugins/package.v1.json](../../api/plugins/package.v1.json)):

```json
{"manifest": "<base64 of the manifest bytes>",
 "payload": "<base64 of the payload bytes>",
 "signature": {"key_id": "acme-2026", "algorithm": "Ed25519", "value": "<base64>"}}
```

- **Signature:** Ed25519 over `"proudauth-plugin-v1\n"` followed by the
  manifest bytes (domain-separated). The manifest binds the payload through
  `payload_sha256`, the hex SHA-256 of the payload bytes. Both parts travel as
  base64 of their exact bytes, so JSON tooling on the way cannot break the
  signature.
- **Manifest** (`manifest_version` 1,
  [api/plugins/manifest.v1.json](../../api/plugins/manifest.v1.json)):
  `name` (`^[a-z0-9][a-z0-9-]{1,62}$`), `version` (strict
  `MAJOR.MINOR.PATCH`), `publisher` (must equal the signing key's
  publisher), `description`, `permissions` (1–50 known built-in permissions),
  `requires` (contract name → acceptable versions), `dependencies` (at most
  10, each `{name, min_version}`) and `payload_sha256`.
- **Payload:** `{"hooks": [...], "webhooks": [...], "workflows": [{name,
  description?, definition}]}`, at most 20 of each. Hooks and subscriptions
  use the request bodies of `POST /hooks` and `POST /webhooks`. Hooks may not
  set `owner_user_id` (the installer owns the parts it creates; parts that
  already exist keep their owner on upgrades); subscriptions are realm-wide
  (no `organization_id`). The payload has no JSON Schema of its own:
  `package.v1.json` describes it in text, and the parts are validated by the
  API's own rules. A workflow's `name` is checked only at installation, so an
  invalid name passes upload and review.
- **Compatibility:** each `requires` entry must name a contract the server
  supports with at least one acceptable version, otherwise `422` with
  `incompatible: true`; an unknown contract name means the server is too old.
  When given, a hook's `contract_version` must be among
  `requires.hook_contract`, a subscription's `event_version` among
  `requires.webhook_events`, and a workflow's `schema_version` among
  `requires.workflow_definition` ([extension-contracts.md](extension-contracts.md)).
- **Limits:** manifest 16 KiB, payload 160 KiB, and the whole request within
  `limits.max_body_bytes` (256 KiB by default, enough for a package at both
  maximums once base64-encoded). The manifest and payload are decoded
  strictly: an unknown member (for example `scripts`) is a `422`. Duplicate
  members inside them are not rejected; an unknown member of the outer request
  body is a `400`.
- **Order of checks:** sizes and base64, algorithm (`422`); key, expiry and
  signature (`403`); `manifest_version` and the manifest (`422`); publisher
  and payload digest (`403`); manifest rules, payload and part counts (`422`).
  A package that is not signed by a trusted key therefore never reaches the
  version or content checks.
- **Digest:** the server stores the exact signed bytes and a
  `package_digest`, the SHA-256 of the manifest bytes, a zero byte and the
  payload bytes. The API shows reviewers the manifest (as stored JSON) and the
  payload, but not the signature or the raw manifest bytes, so a reviewer
  cannot re-verify the signature through the API; compare the package file
  you were given instead.

## Lifecycle

1. **Upload** (`POST /plugins`, `realm.plugins.manage`, recent
   authentication; a user, not a service principal). The server checks the
   signature, digest, manifest and compatibility, and validates every part
   with the API's own validation (hooks, webhook subscriptions, workflow
   definitions with their references); errors point into the payload (for
   example `payload.hooks[0].kind`; at installation `payload.hooks.<member>`,
   and workflows by name, `payload.workflows[<name>]`). The manifest must declare every permission the
   parts need: `realm.hooks.write` for hooks, `realm.webhooks.write` for
   subscriptions, and `realm.workflows.write`, `realm.workflows.publish` and
   each step's permission for workflows (`422` lists what is missing). The
   uploader must hold every declared permission (`403
   grant_ceiling_exceeded`). The version is stored with its exact signed bytes
   as `pending_review`, or as `approved` when the realm policy is
   `extensions.plugin_review: single_admin` (recorded as reviewed by the
   uploader, with the policy noted in the audit event). The status follows
   the policy at upload time: a version uploaded under `single_admin` stays
   approved after the realm returns to `second_admin`. Uploading a version
   that exists is a `409`.
2. **Review** (`realm.plugins.approve`). `GET /plugins/{id}/versions/{version}`
   shows the manifest and payload. `POST …/versions/{version}/approve`
   (recent authentication) or `/reject`, each with an optional note of at
   most 500 characters. Only `pending_review` versions can be reviewed
   (`409` otherwise). The uploader cannot review their own version (`403`),
   and the approver must hold every declared permission.
3. **Install, upgrade or downgrade** (`POST …/versions/{version}/install`,
   `realm.plugins.manage`, recent authentication; a user), for approved
   versions and versions installed before (`403` while pending review, `409`
   for a rejected version). Signature, key
   validity, compatibility, part validation and the installer's permissions
   are checked again. Dependencies must be installed, enabled and at least
   `min_version` (`409` with `missing_dependency`). In one transaction the
   parts are reconciled by name: existing parts are updated and keep their IDs
   and signing secrets, so endpoints keep verifying across upgrades and
   rollbacks; new parts are created and their secrets are returned **once** in
   `signing_secrets`; parts the version no longer contains are removed
   (workflows that never ran are deleted; workflows that ran stay, disabled
   and retired, as evidence: see [Data](#data)). A part whose name collides
   with a hook, subscription or workflow the plugin does not manage is a
   `409`. Workflows are published with the installer as the accountable
   publisher (ceiling checked) and the reviewer recorded as the revision's
   approver; a workflow whose definition and publisher did not change keeps
   its revision. The plugin becomes `enabled`, the version `installed` (the
   one before it `superseded`), and the previous version is kept as
   `previous_version`. Each part gets the state its version declares (a hook
   the payload declares `disabled` stays disabled); a hook or subscription an
   administrator switched off with an emergency control stays off until they
   turn it back on; the parts of a disabled plugin come back with the
   installation. Installing a version below the `min_version` an enabled
   dependent plugin requires (a downgrade or a rollback) is refused (`409`,
   with `dependent` naming the plugin).
4. **Rollback** (`POST /plugins/{id}/rollback`, `realm.plugins.manage`,
   recent authentication) reinstalls `previous_version` without a new review
   (`409` when there is none); trust, compatibility, the installer's
   permissions and dependencies are checked again. `previous_version` then
   becomes the version rolled back from, so a second rollback goes forward
   again.
5. **Disable and enable** (`POST /plugins/{id}/disable`, `/enable`,
   `realm.plugins.manage`, optional `{"reason"}` of at most 64 characters,
   recorded as the audit reason code). Every hook, subscription and workflow
   of the plugin changes state in one transaction. Disabling is an emergency
   control: audited in category `emergency`, which raises `security.alert`.
   Disabled hooks are not called (**a disabled security hook stops
   restricting anything**, as with the [emergency control](../operations/incidents.md#emergency-controls-sec-020));
   disabled subscriptions keep their queued deliveries but get no deliveries
   for events published while they are disabled; disabled workflows neither
   fire nor advance. Disabling is refused (`409`) while an enabled plugin
   depends on this one, and enabling needs the dependencies enabled. A plugin
   that is not installed is a `409`; setting the state it already has does
   nothing and records nothing. The parts' own state changes are not audited
   one by one; the `plugin.enabled` or `plugin.disabled` event covers them.
6. **Uninstall** (`DELETE /plugins/{id}`, `realm.plugins.manage`, recent
   authentication) deletes the plugin's hooks and subscriptions (queued
   deliveries of those subscriptions are deleted with them); workflows that
   never ran are deleted, workflows that ran stay, disabled. The plugin
   becomes `inactive`, its versions stay stored, and `previous_version` names
   the removed version, so a rollback reinstalls it. Refused while enabled
   plugins depend on it.

States: a plugin is `inactive` (uploaded but never installed, or
uninstalled), `enabled` or `disabled`; a version is `pending_review`,
`approved`, `rejected`, `installed` or `superseded`.

**Parts never drift from the reviewed package.** Hooks, subscriptions and
workflows a plugin manages carry its `plugin_id`, and ordinary changes to them
answer `409`: `PUT` and `DELETE /hooks/{id}`, `PATCH` and `DELETE
/webhooks/{id}` (also a state-only `PATCH` that pauses a subscription), and
workflow revisions, approval, publication, rollback, enable, disable and
deletion. The emergency controls (`POST /emergency/controls`, for hooks and
subscriptions) and webhook secret rotation still apply to them; there is no
emergency control for a single workflow, so stop a plugin's workflows by
disabling the plugin. A part switched off by an emergency control stays off
through plugin upgrades, rollbacks and enables until the emergency control
turns it back on.

## API

All paths are under `/api/v1/realms/{realm}`, with an admin-audience token
from an MFA session. `{id}` is the plugin's ID or its name.

| Method and path | Permission | Notes |
| --- | --- | --- |
| `GET /plugins` | `realm.plugins.read` | Installed and uploaded plugins |
| `POST /plugins` | `realm.plugins.manage`, recent authentication | Upload a version ([lifecycle](#lifecycle)) |
| `GET /plugins/{id}` | `realm.plugins.read` | State, installed and previous version, parts |
| `DELETE /plugins/{id}` | `realm.plugins.manage`, recent authentication | Uninstall |
| `GET /plugins/{id}/versions` | `realm.plugins.read` | Every stored version with its review status |
| `GET /plugins/{id}/versions/{version}` | `realm.plugins.read` | Manifest and payload for review |
| `POST /plugins/{id}/versions/{version}/approve` | `realm.plugins.approve`, recent authentication | Not the uploader |
| `POST /plugins/{id}/versions/{version}/reject` | `realm.plugins.approve` | Not the uploader |
| `POST /plugins/{id}/versions/{version}/install` | `realm.plugins.manage`, recent authentication | Install, upgrade or downgrade; returns new parts' `signing_secrets` once |
| `POST /plugins/{id}/rollback` | `realm.plugins.manage`, recent authentication | Reinstall `previous_version` |
| `POST /plugins/{id}/enable`, `/disable` | `realm.plugins.manage` | Optional `reason`; disable is an emergency control |

Recent authentication applies to users only (service principals have none).
Upload and installation also refuse service principals (`403`).

Permissions: `realm.plugins.read` (normal), `realm.plugins.manage`
(privileged), `realm.plugins.approve` (privileged). The built-in
`realm-admin` role holds them through `realm.*`; `realm-auditor` holds
`realm.plugins.read`.

Realm policy: `extensions.plugin_review` is `second_admin` (default: a second
administrator approves every version) or `single_admin` (an upload is
approved by its uploader; the choice is recorded with every installation).

Audit events: `plugin.version.uploaded`, `plugin.version.approved`,
`plugin.version.rejected`, `plugin.installed`, `plugin.upgraded`,
`plugin.downgraded`, `plugin.rolled_back`, `plugin.enabled`,
`plugin.disabled`, `plugin.uninstalled`, and the parts' own `hook.*`,
`webhook.*` and `workflow.*` events, which carry `plugin_id` in their
metadata for plugin parts. Part state changes made by installing, enabling
or disabling a plugin have no per-part event. To find
everything a plugin did, combine `GET /audit-events` filtered by the
plugin's events with `GET /plugins/{id}` (its current parts).

## Not offered

- **Code in plugins** of any kind ([ADR 0021](../architecture-decisions/0021-no-embedded-code-execution.md)).
- **Parts other than hooks, webhook subscriptions and workflows** (roles,
  clients, claim mappings, resource types, policies). These create or shape
  authority and need their own ceiling and review rules before a package may
  carry them; reconciliation by name would extend to them.
- **Unsigned plugins, and fetching plugins from URLs or a marketplace.** No
  extra egress or supply-chain path: uploads only, signed by keys the operator
  trusts.
- **Configuration export or import and realm data export of plugins.** Plugin
  versions are stored with their exact signed bytes; re-upload the package in
  the target realm.

## Data

- Workflows a new version drops, or that an uninstall leaves, are kept
  disabled as evidence when they have runs, marked retired: enabling,
  upgrading or rolling back the plugin does not bring them back unless a
  version names them again.
- No retention or erasure job covers the plugin tables: uploaded versions,
  with the user IDs of uploader and reviewer and the review notes, are kept
  ([data-inventory.md](../operations/data-inventory.md)).

## Residual risks

- With `extensions.plugin_review: single_admin`, a realm gives up the second
  review by its own choice; the choice is audited with every installation.
- The endpoints a plugin's hooks and subscriptions point to are outside the
  signature: the package fixes their URLs, not what runs there.
- A publisher key that leaks lets its holder sign packages until the operator
  removes it; what it signed keeps running, and can be enabled again, until
  an administrator disables or uninstalls it.
