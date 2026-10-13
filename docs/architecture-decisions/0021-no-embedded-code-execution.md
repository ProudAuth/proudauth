# 0021. Custom logic: out of process only, no embedded code execution

**Status:** Accepted

## Context

EXT-013 says that *optional* embedded logic must run in a sandbox with CPU,
memory, time, filesystem, network and capability restrictions. Identity
products often offer such logic (scripted authenticators, expression-based
mappers, server-side "actions" in JavaScript or WASM) so that customers can
change behaviour without deploying a service.

In ProudAuth, the identity server's process holds the unwrapped root, pepper
and signing-wrap keys, every signing key in use, the database pool with the
runtime role's privileges, and the state of every session. Code running in
that process runs inside the trust boundary that protects all realms of the
deployment ([system threat model](../threat-models/system.md)).

The extension points that need logic already exist in an out-of-process
form, each with its own limits, signing, egress policy and audit:

- pre-action hooks (EXT-009..EXT-012): synchronous, signed HTTPS calls through
  the egress policy, with a per-hook timeout of 100–5000 ms, a 64 KiB response
  limit, strict response parsing and fail-closed security decisions;
- webhooks (EXT-001..EXT-008): asynchronous, at-least-once, signed
  deliveries;
- lifecycle workflows (EXT-015, EXT-016): declarative definitions with a fixed
  step vocabulary ([workflows.md](../integrations/workflows.md));
- plugins (EXT-014): signed configuration bundles of hooks, webhook
  subscriptions and workflows ([plugins.md](../integrations/plugins.md)).

This decision is not a row of the decision register in docs/plan.md §37.1; it
records how the option in EXT-013 is handled.

## Decision

- **ProudAuth ships no embedded interpreter, scripting language, expression
  language or WASM runtime, and the option EXT-013 describes is not taken.**
  The status of embedded execution is `intentionally_unsupported`
  (the status values suggested in docs/plan.md §35). EXT-013 has nothing to sandbox.
- Custom logic runs outside the identity server, in a service the operator or
  administrator chooses and isolates: a pre-action hook, a webhook receiver,
  or the endpoint a workflow's `call_webhook` step calls. That service's
  answers pass through the same validation, authorization and audit as an
  administrator's request; hooks can deny or add obligations but never grant.
- The data formats that could carry code refuse it:
  - workflow definitions (`api/workflows/definition.v1.json`) are decoded
    strictly (`DisallowUnknownFields`, `internal/workflow/definition.go`), so
    a member such as `script` or `expression` is a `422`; there are no
    conditions, expressions or loops, and `notify` steps carry fixed notice
    codes, not text;
  - plugin manifests and payloads are decoded strictly
    (`internal/plugin/package.go`), so a `scripts` member is a `422`; a plugin
    can configure only what the administration API can;
  - claim mappings take attribute names only, with no expressions
    ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#clients)).
- If embedded logic is ever reconsidered, it needs a new ADR that meets
  EXT-013 in full: a separate process (or WASM with instruction metering and a
  hard memory cap) per tenant; no filesystem or network access (no WASI
  preopens or sockets); host calls only through explicit capabilities that go
  through the same authorization, egress policy and audit as the APIs;
  per-call time limits; and tests for each of those limits.

## Alternatives considered

- **An in-process interpreter (JavaScript, Lua, CEL, expression language)
  with resource limits**: rejected. Go cannot enforce a memory limit per
  goroutine or pre-empt a runaway interpreter reliably, and an interpreter
  escape exposes the keys and sessions of every realm. A limit that is not
  enforced is not a sandbox.
- **WASM in process with fuel metering**: deferred, not adopted. Metering
  bounds CPU, but memory caps, host-call capabilities and a supply chain for
  modules (signing, review) would each be new security-critical code, and the
  out-of-process forms already cover the use cases.
- **A separate sandbox process per tenant, managed by ProudAuth**: rejected
  for now. It is what an out-of-process hook or receiver already is, with the
  isolation chosen by the operator; managing it inside ProudAuth would add a
  process supervisor and an execution runtime to the trusted computing base.

## Consequences

- Behaviour that needs logic, such as branching in an onboarding process or a
  custom eligibility rule, needs a service: a hook, a webhook receiver, or a
  workflow step that calls an endpoint. That service is the operator's to
  run, secure and make highly available; a slow or unreachable hook adds
  latency or fails closed.
- Workflows cannot branch: decisions are approval steps, separate workflows,
  or a `call_webhook` to a service that applies its own logic and calls the
  administration API.
- No code supplied by tenants or vendors runs next to the keys, so
  [system.md](../threat-models/system.md) needs no sandbox-escape threat.
- Customers moving from products with scripted extensions (for example
  Keycloak authenticator scripts or ZITADEL actions) re-implement that logic
  as hooks or workflows; the migration adapters report such configuration as
  unsupported ([migration-adapters.md](../operations/migration-adapters.md)).

## Migration implications

None: nothing is removed. A future embedded runtime would be a new, opt-in
module with its own migration, configuration, threat-model section and tests,
and the strict decoders above would have to accept the new member only in a
new contract version ([extension-contracts.md](../integrations/extension-contracts.md)).

## Related requirement IDs

EXT-009..EXT-018, SEC-020, AZ-006, §22
