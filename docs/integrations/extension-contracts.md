# Extension contracts and versions

Requirements: EXT-018 (API evolution), with EXT-008, EXT-009..EXT-012,
EXT-014, EXT-015, API-013. Code: `internal/contracts` (contract registry,
event rendering; `internal/contracts/schemacheck` is the JSON Schema checker
the compatibility tests use), `internal/hooks/extensions.go`,
`internal/webhooks/extensions.go`, migration `0072_contract_versions.sql`.
Tests: `internal/contracts`, `internal/workflow` (stored-definition
fixtures), `TestContractVersions` (`tests/e2e`).

The contracts between ProudAuth and the systems that extend it are versioned
**independently of each other and of server releases**: a receiver of webhook
events, a hook endpoint, a plugin and a workflow definition each state the
version they speak, and a server upgrade inside the support window never
changes what an existing subscription, hook, plugin or workflow receives or
must send. The general compatibility policy for the API, events and SDKs is
in [compatibility.md](../protocols/compatibility.md).

## Contracts

| Contract | Versions | Chosen by | Default | Schemas |
| --- | --- | --- | --- | --- |
| `webhook_events` | 1 (supported, default), 2 (current) | The subscription's `event_version` | 1 | [api/events](../../api/events/README.md) (`envelope.vN.json`, `<type>.vN.json`) |
| `hook_contract` | 1 (current) | The hook's `contract_version`, sent in the `ProudAuth-Hook-Version` header | 1 | [api/hooks](../../api/hooks/README.md) |
| `plugin_manifest` | 1 (current) | The manifest's `manifest_version` | 1 | [api/plugins/manifest.v1.json](../../api/plugins/manifest.v1.json) |
| `workflow_definition` | 1 (current) | The definition's `schema_version` | 1 | [api/workflows/definition.v1.json](../../api/workflows/definition.v1.json) |
| `workflow_step_call` | 1 (current) | Fixed; `contract_version` in the body | 1 | [api/workflows/step-call.v1.json](../../api/workflows/step-call.v1.json) |
| `management_api` | 1 (current) | The `/api/v1` path prefix | 1 | [api/openapi/proudauth.yaml](../../api/openapi/proudauth.yaml) |

`GET /api/v1/realms/{realm}/extension-contracts` lists them. Any one of
`realm.plugins.read`, `realm.webhooks.read`, `realm.hooks.read` or
`realm.workflows.read` grants access:

```json
{"items": [
  {"name": "webhook_events", "description": "Webhook event envelope and per-type payload schemas (api/events). …",
   "versions": [{"version": 1, "status": "supported", "default": true}, {"version": 2, "status": "current"}]},
  {"name": "hook_contract", "description": "…", "versions": [{"version": 1, "status": "current", "default": true}]},
  …],
 "support_window_months": 12}
```

Each version has a `status` (`current` for the newest, `supported`, or
`deprecated` once a removal is announced), `default` on the version used when
a caller does not choose one, and `sunset` (the earliest removal date,
`YYYY-MM-DD`) once the version is deprecated. No version is deprecated today.
Plugins name these contracts in their manifest's `requires`
([plugins.md](plugins.md#package-format)).

## Webhook events

Each subscription chooses `event_version` (`1` or `2`) when it is created or
with `PATCH /webhooks/{id} {"event_version": 2}`; another value is a `422`.
Subscriptions created without it, and every subscription that existed before
migration `0072`, use version 1. The outbox stores each event once, and
deliveries are rendered to the subscription's version at fan-out
(`contracts.RenderEvent`):

- **Version 1** is the stored envelope, byte for byte (tested), so nothing
  changes for existing receivers.
- **Version 2** changes the envelope only; every event type's `data` is the
  same in both versions. `org_id` becomes `organization_id` (the name `data`,
  the session-event stream and the REST API use), `payload_form` (`minimal`
  or `standard`) states which payload form `data` is in, so a member the
  minimal form removed can be told from one that does not apply, and
  `event_version` is `2`. The body is serialized again, so member order,
  whitespace and escaping differ from version 1; verify the signature over
  the raw bytes you received, as always.
- The version applies when an event is fanned out to the subscription: the
  rendered body is stored with the delivery, so deliveries already queued,
  retried or replayed after a change of `event_version` (or `payload_form`)
  keep the rendering they were created with.

The signature scheme (`Webhook-Signature: v1,…`) is versioned separately from
the event schemas and is the same for both. Details and migration steps for
receivers: [webhooks.md](webhooks.md#event-versions).

## Hook contract

Each pre-action hook pins `contract_version` (`POST /hooks`, `PUT
/hooks/{id}`; `GET /hooks/{id}` shows it); existing hooks have `1`, and a
`PUT` without the member sets it back to the default, `1`. Every hook request
carries the header `ProudAuth-Hook-Version: <n>` (a decimal integer); the
request body does not repeat the version.

- A hook may echo `ProudAuth-Hook-Version` in its response. An echoed value
  that is not exactly the request's string (`01` is not `1`) makes the
  response malformed: the call fails the
  way its kind fails (closed for registration eligibility, profile
  validation and authorization decisions; claims enrichment fails closed
  unless the hook's `failure_mode` is `skip`; an `authentication.risk` hook's
  signal is missing), and the hook's diagnostics show `malformed_response`.
  A response without the header is read as the requested version.
- Responses are parsed strictly: an unknown member makes a response
  malformed. Within a version, requests carry exactly the members their
  schema lists; new request members arrive only with a new contract version.
- An answer outside the published bounds is malformed too, and nothing of it
  is used: a `token.claims` answer that sets a reserved claim (`iss`, `sub`,
  `aud`, `exp`, `scope`, `client_id`, `org_id`, `project_id`, `act`, `cnf`,
  `sid`, `acr`, `amr`, `token_kind`, … — the list in `internal/token`),
  `roles` or `permissions`, a claim name longer than 64 characters, more than
  20 claims or more than 4 KiB of serialized claims; an
  `authorization.decision` answer with more than five obligations (the
  decision is denied with `HOOK_INVALID_RESPONSE`, also when the hook
  denied). A hook that does not answer within its `timeout_ms` (100–5000,
  default 1500) or drops the connection fails the same way, with the
  diagnostics categories `timeout` and `unreachable`; an authorization
  decision is then denied with `HOOK_UNAVAILABLE`, and registration and
  token issuance answer `503` (`TestHookBounds`).
- The request and response bodies of every hook kind are published as JSON
  Schemas in [api/hooks](../../api/hooks/README.md), with the signature
  scheme hooks use. The request schemas are closed
  (`additionalProperties: false`) and describe exactly what a version
  sends, so a hook may validate requests strictly.
- There is only version 1. A breaking change would ship as version 2 with new
  `.v2.json` files; hooks opt in by changing `contract_version`.

## Plugin manifests and workflow definitions

An unsupported `manifest_version` or `schema_version` is a `422` that lists
the supported versions. A stored workflow definition that no longer parses
(after its version's sunset) never starts runs, and the worker logs a
warning; publishing a revision in a current version repairs it.
`internal/workflow/testdata/definition.v1.stored.json` holds stored-definition
fixtures that every release must keep accepting while version 1 is supported.

## Support window

- A version stays supported (deliverable and selectable) for at least **12
  months** after its successor is published (`contracts.SupportWindowMonths`).
- Deprecations are announced in the [CHANGELOG](../../CHANGELOG.md) and listed
  with their sunset date by `GET /extension-contracts`.
- The default version stays the oldest supported one until its sunset
  (API-013), so clients that never choose a version keep their behaviour
  across server upgrades. For webhook events this means new subscriptions
  still get version 1 unless they ask for 2.

## Compatibility tests

- `internal/contracts` (`TestPublishedExamplesValidate`,
  `TestRenderEveryVersion`, `TestValidatorRejects`,
  `TestSchemaFilesDeclareDraft`): every published example validates; every
  version 1 event example is rendered in every supported version with both
  payload-form labels and validated against that version's schema (the
  minimal stripping itself is covered by the end-to-end test), and version 1
  rendering is identical to the input; the validator rejects known-bad
  payloads; the hook, plugin and workflow schema directories are well formed
  and their examples validate.
- `internal/workflow`: every example in `definition.v1.json` and the
  stored-definition fixtures parse, and their canonical form validates.
- `TestContractVersions` (`tests/e2e`): live deliveries of events from several
  families to version 1 and 2 subscriptions in both payload forms validate
  against `<type>.v<N>.json`; subscriptions created before versioning receive
  exactly the stored envelope; changing a subscription's version takes effect;
  live requests to hooks of all five kinds validate against the request
  schemas and carry the version header, and the answers validate against the
  response schemas; a mismatched echoed version fails closed.
- The workflow and plugin end-to-end tests validate step-call bodies, plugin
  manifests and packages against their schemas.

## Other compatibility notes

- Events a lifecycle workflow run causes carry the run ID (`wrn_…`) as
  `correlation_id`; before workflows, events from background work had no
  correlation ID. The change is additive.
- The workflow step call has its own contract, `workflow_step_call`, with
  `contract_version` (1) in its body
  ([workflows.md](workflows.md#step-call-contract)); no endpoint chooses its
  version.
