# Lifecycle workflows

Requirements: EXT-015 (lifecycle workflows), EXT-016 (workflow idempotency),
with EXT-013, EXT-018, AZ-006, AZ-018, SEC-020, TEN-018. Code:
`internal/workflow` (definitions, revisions, triggers, engine, approvals),
`internal/httpapi/workflows.go`, migration `0070_lifecycle_workflows.sql`.
Contracts: [api/workflows/definition.v1.json](../../api/workflows/definition.v1.json)
(definitions) and [api/workflows/step-call.v1.json](../../api/workflows/step-call.v1.json)
(the body a `call_webhook` step sends). Tests (`tests/e2e/workflows_test.go`):
`TestWorkflowOnboardingApprovalAndCompensation`, `TestWorkflowDelegationCeiling`,
`TestWorkflowIdempotency`, `TestWorkflowRevisionsRollbackAndDisable`,
`TestWorkflowScheduleAndOffboarding`, `TestWorkflowValidation`,
`TestWorkflowEndpointCompensation`; unit tests in `internal/workflow`.

A lifecycle workflow is a declarative, versioned sequence of steps that
ProudAuth runs for one user at a time: onboarding when a membership is added,
access that expires, an approval before a role is granted, offboarding when an
account is suspended. Runs are durable: every step attempt is recorded, a
crash or a lost lease never repeats an internal effect, and a failing run
compensates what it did.

Workflows are deliberately bounded. There are no expressions, conditions or
loops, and no embedded code ([ADR 0021](../architecture-decisions/0021-no-embedded-code-execution.md)).
Decisions are approval steps, separate workflows, or a `call_webhook` step to
a service that applies its own logic.

## Concepts

- **Workflow:** a realm-scoped definition with a unique `name` (1–100
  characters, no line breaks), an optional `description` (at most 500
  characters), an owner, and a state: `draft` (no revision published yet),
  `active` (triggers fire and runs advance) or `disabled` (nothing fires and
  runs in flight pause; compensation and cancellation still proceed, because
  they only remove access). Publishing makes a `draft` workflow `active` but
  never re-enables a `disabled` one.
- **Revision:** an immutable, numbered definition stored with its canonical
  JSON (the server's serialization) and its SHA-256 hash. Its status moves
  `draft` → (`approved`) → `published` → `superseded`, or `rejected`.
  Approval is needed only when the workflow `requires_approval`
  ([below](#authority-and-accountability)).
- **Run:** one execution of one revision for one subject (a user). A run is
  pinned to the revision it started with, so publishing or rolling back never
  changes a run in flight, and so is its accountable publisher. A run records
  the trigger type and key, an input snapshot (identifiers only) with its
  `input_version` (the event's `event_version` for event triggers, the
  definition's `schema_version` for schedule and manual runs), the
  accountable publisher, the starter of a manual run, the chain depth, its
  state, step index, context, error category and last error. Run states:
  `pending`, `running`, `waiting`, `awaiting_approval`, `compensating`,
  `succeeded`, `failed`, `compensated`, `compensation_failed`, `cancelled`. A
  run waiting for a retry stays `running` with a later due time.
- **Step attempt:** one row per attempt of a step (state `started`,
  `succeeded` or `failed`), with the attempt number, the idempotency key (the
  same for every attempt of the step), the resolved input and its
  `input_version` (`r<revision>:<first 16 hex digits of the definition
  hash>:i<run input version>`), the result, error category and message, the
  retry policy in force (`max_attempts`, `backoff_ms`), and the compensation
  strategy (`none`, `undo`, `notify_endpoint`, `impossible`), state
  (`pending`, `done`, `not_needed`, `impossible`, `failed`), attempts and
  result (EXT-016).
- **Approval:** a decision by named approvers, with an expiry; `pending`,
  `approved`, `rejected`, `expired` or `cancelled`.

## Definition

`schema_version` 1 ([api/workflows/definition.v1.json](../../api/workflows/definition.v1.json)):

```json
{"schema_version": 1,
 "triggers": [{"type": "event", "event_types": ["organization.membership.added"], "organization_id": "org_…"},
              {"type": "schedule", "every": "720h",
               "select": {"type": "role_holders", "role_id": "rol_…", "granted_before": "2160h"}},
              {"type": "manual"}],
 "steps": [{"id": "approve", "type": "approval", "approvers": ["usr_…"], "expires_in": "72h"},
           {"id": "grant", "type": "assign_role", "role_id": "rol_…", "scope": "organization", "expires_in": "720h"},
           {"id": "team", "type": "add_to_group", "group_id": "grp_…"},
           {"id": "tell", "type": "notify", "notice": "access_granted"},
           {"id": "sync", "type": "call_webhook", "subscription_id": "whk_…", "compensate": true,
            "retry": {"max_attempts": 5, "backoff": "30s"}},
           {"id": "done", "type": "end"}],
 "retry": {"max_attempts": 3, "backoff": "30s"}}
```

### Triggers

| Type | Members | Behaviour |
| --- | --- | --- |
| `event` | `event_types`, optional `organization_id` (only that organization's events) | Allowed event types: `user.created`, `user.suspended`, `user.reactivated`, `user.locked`, `organization.membership.added`, `organization.membership.removed`, `organization.membership.suspended`, `organization.membership.reactivated`. `user.signed_in` is excluded because of its volume. Runs start inside the outbox dispatcher's transaction, once per event and workflow: the event ID is the unique trigger key, so a redelivered event starts nothing. An event without `data.user_id` starts nothing (not audited) |
| `schedule` | `every` (1h..720h), `select` | At most one per definition. `select` is a fixed selector, never a free-form filter: `role_holders` (`role_id`, optional `organization_id`, optional `granted_before` 0..87600h; direct assignments to active users only, not roles held through groups) or `organization_members` (`organization_id`, optional `granted_before`, compared with the membership's age). One firing starts at most 500 runs; a truncated selection is recorded in the `workflow.schedule.fired` audit event. The first firing is one interval after publication (re-publishing keeps an earlier pending slot). The next firing time moves forward in the same transaction as the runs it starts, so each slot fires once across workers; slots missed while no worker ran are not replayed (one late firing happens). At most 20 workflows fire per pass |
| `manual` | — | Administrators start runs with `POST /workflows/{id}/runs` |

### Steps

| Type | Members | Effect | Compensation |
| --- | --- | --- | --- |
| `wait` | `duration` 1m..2160h | Parks the run | None |
| `approval` | `approvers` (1–10 distinct user IDs), `expires_in` 1h..720h | Eligible approvers get the `approval_requested` notice and decide through `/me/workflow-approvals`; the subject is never eligible, and approvers no longer active when the step starts are dropped (none left: `no_eligible_approver`). The first decision wins; rejection or expiry fails the run | None |
| `assign_role` | `role_id`, `scope` (`realm` or `organization`), optional `organization_id`, `expires_in` (1h..8760h), `reason` | Assigns the role with the publisher as actor, under the same ceiling, separation-of-duties, guest and membership rules as the API; a role already held counts as done. The assignment's reason is `workflow run <run_id>`, prefixed with the step's `reason` code when given (`OFFBOARDING: workflow run …`) | `undo`: removes the assignment the step created |
| `add_to_group` | `group_id`, optional `organization_id` | Adds the subject's membership to the group (the group's organization); the subject needs an active membership (`not_a_member` otherwise). Dynamic groups refuse it (permanent failure) | `undo`: removes the group membership the step added |
| `remove_access` | `access` (`membership`, `role` or `group`), with `role_id` and `scope`, or `group_id`; optional `organization_id`, `reason` (default `WORKFLOW`) | Removes the membership, role assignment or group membership | None: removals are never re-granted automatically |
| `notify` | `notice`, `recipient` (`subject`, or `approvers`: every eligible approver of the run's latest approval, which needs an earlier approval step), `template` (`workflow_notice`) | Queues the `workflow_notice` message to verified primary addresses of active recipients, in the step's transaction | `impossible` when something was sent, `not_needed` when nothing was |
| `call_webhook` | `subscription_id` (a realm-wide subscription), `timeout_ms` 100..10000 (default 5000), `compensate` | Signed `POST` of a [step call](#step-call-contract) to the subscription's destination | `notify_endpoint` when `compensate` is `true`, otherwise impossible |
| `suspend_user` | optional `reason` (default `WORKFLOW`) | Suspends the account, which revokes its sessions and queues `account_suspended`; never applied to the publisher (`self_action`) | None |
| `end` | `outcome` (`succeeded`) | Ends the run; must be the last step | None |

- A step's `organization_id` pins the organization. Otherwise the step uses
  the organization of the triggering event, of the selector or of the manual
  start; a step that needs an organization fails with
  `organization_required` when the run has none.
- Notice codes: `welcome`, `access_granted`, `access_expiring`,
  `access_removed`, `approval_requested`, `account_suspended`, `offboarding`.
  The text comes from the server: workflows cannot send free text. Realms
  change the wording of the `workflow_notice` template (English; variables
  `realm`, `workflow`, `notice`, `time`) through the template API. The
  workflow's name appears in the message, so keep names fit for end users.
  The template is mandatory: notification preferences cannot mute it, and it
  is sent even to addresses on the bounce and complaint suppression list.

### Limits and validation

- 1–5 triggers and 1–20 steps per definition; step IDs match
  `^[a-z][a-z0-9_-]{0,39}$` and are unique; a definition is at most 64 KiB.
- Retry policy (definition-wide `retry`, default 3 attempts and `30s`, or per
  step): 1–10 attempts; backoff 1s..1h, doubling per attempt and capped at 6
  hours with up to 20 % jitter included (a wait never exceeds 6 hours). Waits
  and approvals are never retried.
- Validation is strict: an unknown member, or a member that does not belong
  to the step's type, is a `422`. A member such as `script` or `expression`
  is therefore refused.
- Every reference must exist in the realm: roles (with a matching boundary;
  for `select.role_id` only existence is checked), groups, approvers (active
  users who are not guests), organizations (active) and webhook subscriptions
  (realm-wide; their state is not checked at publication).

## Authority and accountability

- **The publisher is the accountable actor.** Role assignments, group
  changes, removals, suspensions and the `workflow.step.*` and run outcome
  events of a run are recorded with the run's accountable publisher as actor.
  Other events have their own actor: `workflow.run.cancel_requested` the
  cancelling administrator, approval decisions the approver (category
  `authorization`), and `workflow.approval.expired`,
  `workflow.trigger.suppressed` and `workflow.schedule.fired` the system.
- **Delegation ceiling at publication.** The publisher needs
  `realm.workflows.publish`, and every step must pass the check that
  performing it directly would: the role ceiling for role steps;
  `org.groups.write` plus the ceiling for every role the group grants
  (including its ancestors) for group steps; `org.members.write` for
  membership removal; `realm.users.suspend` for suspension;
  `realm.webhooks.write` for endpoint calls. Steps whose organization comes
  from the trigger are checked in the organization every trigger pins when
  they all pin the same one, otherwise against the publisher's realm-wide
  authority over organizations; the exact organization is checked again at
  run time. A failure answers `403` (`forbidden` or
  `grant_ceiling_exceeded`) and names the step (`definition.steps[i]`).
- **Ceiling at run time.** Inside the transaction of every effect, the run's
  accountable publisher must still hold `realm.workflows.publish` and the
  step's authority. Otherwise the step fails permanently with
  `publisher_lacks_authority` and the run compensates (compensation calls to
  endpoints are not re-checked). The accountable publisher is fixed when a run
  starts: re-publishing (or rolling back) under another administrator makes
  that administrator accountable for **runs started afterwards**; runs
  already in flight keep failing until they end.
- **Manual runs.** The starter must be a user with `realm.workflows.run`
  whose own authority covers every step (`403` otherwise; service principals
  get `403`). Nobody starts a run about themselves (`403`).
- **Separation of duties.**
  - The subject is never an eligible approver (a decision by the subject is
    answered `404`, as for anyone not named).
  - A revision's author cannot approve or reject it (`403`).
  - A workflow with `requires_approval` can be published only from an
    approved revision (`403` otherwise). `requires_approval` is set when the
    workflow is created, from the request's `requires_approval` or the realm
    policy `extensions.workflow_publish_approval`; **changing the policy
    later does not change existing workflows**, and no endpoint changes the
    flag afterwards. When the realm's policy cannot be read, creation fails
    closed (approval required).
  - A role that `requires_approval` takes the decider of the run's latest
    approval step as its independent approver; the assignment still enforces
    approver ≠ publisher ≠ subject and that the approver could assign the
    role (AZ-018).

## Execution and idempotency (EXT-016)

The worker runs two tasks: `workflows.run` (every second) claims due runs with
a lease of `workers.lease_duration`, up to `workers.batch_size` but at most 50
per pass, and at most `workers.tenant_batch_share` per realm (TEN-018), and
advances each claimed run by at most 25 transitions before it yields;
`workflows.schedule` (every minute) fires schedules. Event-triggered runs are
started by the outbox dispatcher (`outbox.dispatch`), in its transaction: an
error there rolls back the whole dispatch batch, webhook fan-out included, and
it is retried. At shutdown the worker hands back its leases (OPS-012).

- **Internal effects** (role, group, removal, suspension, notification, end)
  commit in one transaction with the lease check (`UPDATE … WHERE lease_owner
  = <this worker>`), the accountable publisher's authority re-check, the
  effect, the succeeded attempt row, the run's advance and the audit event. A
  crash rolls all of it back, so a step that runs again after a crash never
  repeats an effect, and a worker that lost its lease cannot commit. If a
  succeeded attempt already exists for the current step, the step is
  skipped, never applied again. The lease owner is the worker's ID,
  `worker-<host name>-<process ID>-<random suffix>`, unique per worker
  process, so two workers on one host (or containers sharing a host name)
  never share lease ownership.
- **Endpoint calls** cannot be part of a database transaction: the attempt is
  recorded `started` under the lease, the call is made outside any
  transaction, and the outcome is recorded. A crash in between leaves a
  `started` attempt; the next claim records it `failed` with error category
  `interrupted` (transient, counted against `max_attempts`) and retries after
  the backoff with the **same `Idempotency-Key`** (`<run_id>.<step_id>`). Each
  attempt has its own `Webhook-Id` (the attempt ID). Delivery to endpoints is
  therefore at least once: **endpoints must deduplicate by
  `Idempotency-Key`.**
- **Failures.** Permanent: validation, authority, not-found and conflict
  errors (any error answered below HTTP 500, with its code as the category),
  `4xx` endpoint responses other than `408` and `429`, `410`, an approval
  rejected or expired. Transient, retried under the step's policy:
  infrastructure errors, `5xx` and `3xx` responses (redirects are not
  followed), timeouts, network errors and egress denials. When the attempts
  are exhausted or a failure is permanent, the run moves to `compensating`
  (recorded as `workflow.run.failed`) and pending approvals are cancelled.
- **Compensation** handles the succeeded attempts whose compensation state is
  `pending`, newest first, one at a time: a compensation waiting for a retry
  holds back the ones after it. `undo` reverses the run's own role assignment
  or group membership (one already removed counts as done);
  `notify_endpoint` calls the endpoint again with `action: "compensate"` and
  `Idempotency-Key: <key>.compensate`. Each compensation gets at most 5
  attempts in total (30 s backoff, doubling, with jitter), and none after a
  permanent error; then it is `failed`. Compensation states are fixed when
  the step succeeds: removals and suspensions are `not_needed`, notices
  `impossible` or `not_needed`, endpoint calls without compensation
  `impossible`. The run ends `compensated` (something was undone), `failed`
  (nothing to undo; a second `workflow.run.failed` event),
  `compensation_failed` (a compensation failed: an administrator must undo
  the rest by hand; diagnostics report `attention_required`) or `cancelled`.
- **Cancellation:** `POST /workflow-runs/{id}/cancel` (`409` once the run has
  finished, while it is `compensating`, or when a cancel was already
  requested) compensates like a failure. The audit trail is
  `workflow.run.cancel_requested`, `workflow.run.failed` (reason
  `cancelled`), then `workflow.run.cancelled`, or `compensation_failed` when
  a compensation failed.
- **Loop protection:** audit and outbox events a run causes carry the run ID
  as request and correlation ID (`correlation_id: "wrn_…"` in webhook
  events). An event caused by a run of a workflow never triggers that same
  workflow, and a run caused by another workflow's run has the parent's depth
  plus one; runs deeper than 3 are not started. Both are audited as
  `workflow.trigger.suppressed` (reason `WORKFLOW_LOOP`). An indirect cycle
  (A triggers B, B triggers A) is therefore stopped only by the depth limit,
  after up to three workflow-caused hops.

## Step call contract

A `call_webhook` step `POST`s to the destination of its webhook subscription
([api/workflows/step-call.v1.json](../../api/workflows/step-call.v1.json),
contract version 1):

```json
{"type": "workflow.step", "contract_version": 1, "action": "execute",
 "realm_id": "rlm_…", "organization_id": "org_…", "workflow_id": "wfl_…", "revision": 3,
 "run_id": "wrn_…", "step_id": "sync", "attempt": 1, "idempotency_key": "wrn_….sync",
 "subject": {"type": "user", "id": "usr_…"},
 "trigger": {"type": "event", "event_type": "organization.membership.added", "event_id": "obx_…"},
 "sent_at": "2026-10-11T09:00:00Z"}
```

- The body carries identifiers only; fetch anything else from the API.
- Headers: `Content-Type: application/json`, `Webhook-Id`,
  `Webhook-Timestamp` and `Webhook-Signature` (signed with the subscription's
  secret exactly like event deliveries, with a second signature while a
  rotated secret is in its overlap window;
  [verifying a delivery](webhooks.md#verifying-a-delivery)),
  `Idempotency-Key`, and `User-Agent: ProudAuth-Workflows/1`.
- Execute calls: `Webhook-Id` is the attempt ID (`wsa_…`) and changes per
  attempt; `attempt` is the step attempt number. Compensation calls:
  `Webhook-Id` is `<attempt ID>c` and stays the same for every compensation
  try; `attempt` is the compensation attempt number; the timeout is a fixed
  5 seconds.
- The timeout of an execute call is the smaller of `timeout_ms` and
  `delivery.webhook_timeout`. At most 64 KiB of the response is read, and its
  body is ignored.
- Answer `2xx` to complete the step. `410`, or a `4xx` other than `408` and
  `429`, fails the step permanently; anything else is retried.
- The subscription's egress policy applies: a private destination needs both
  the subscription's `allow_private_network` and an operator setting that
  allows private egress ([webhooks.md](webhooks.md#destination-rules-egress-policy)).
  So does its state: while it is `paused` the step is retried; while it is
  `disabled`, deleted, or its secret cannot be read, the step fails
  permanently.

## API

All paths are under `/api/v1/realms/{realm}`. Administration routes need an
admin-audience token from an MFA session; the self-service approval routes
need an ordinary account session (no MFA or recent authentication).

| Method and path | Permission | Notes |
| --- | --- | --- |
| `GET /workflows` | `realm.workflows.read` | At most 1000 |
| `POST /workflows` | `realm.workflows.write` | `{name, description?, definition, note?, requires_approval?, owner_user_id?}` → `201 {workflow, revision}`; `409` for a duplicate name. `owner_user_id` defaults to the caller and must be an active user |
| `GET /workflows/{id}` | `realm.workflows.read` | Sends an `ETag` (`If-Match` is not honoured) |
| `DELETE /workflows/{id}` | `realm.workflows.write` | `204`; only while it has no runs (`409` otherwise; possible again once retention has purged its finished runs) |
| `GET /workflows/{id}/diagnostics` | `realm.workflows.read` | [Diagnostics](#diagnostics) |
| `GET`, `POST /workflows/{id}/revisions` | `realm.workflows.read` / `realm.workflows.write` | `POST` stages a draft revision; lists hold at most 200 |
| `GET /workflows/{id}/revisions/{revision}` | `realm.workflows.read` | |
| `POST /workflows/{id}/revisions/{revision}/approve`, `/reject` | `realm.workflows.publish` | The revision's author cannot (`403`) |
| `POST /workflows/{id}/revisions/{revision}/publish` | `realm.workflows.publish`, recent authentication | Ceiling check; `409` for a published, rejected or superseded revision |
| `POST /workflows/{id}/rollback` `{revision}` | `realm.workflows.publish`, recent authentication | Publishes a new revision with the old content; the approval carries over; `409` for the active revision |
| `POST /workflows/{id}/enable`, `/disable` `{reason?}` | `realm.workflows.publish` | `reason` at most 64 characters; disabling is audited in category `emergency` (raises `security.alert`) |
| `GET`, `POST /workflows/{id}/runs` | `realm.workflows.read` / `realm.workflows.run` | Filters `state`, `subject_id` (default 50, at most 200); `POST {subject_id, organization_id?}` → `202`; `409` when the workflow is not active or has no manual trigger; `422` for an unknown subject or an inactive organization. `Idempotency-Key` is honoured: the response is replayed for 24 hours, and a digest of the key becomes the run's trigger key (`manual:<starter>:<digest>`), so the same key starts no second run for as long as the first run is kept |
| `GET /workflow-runs?workflow_id=&state=&subject_id=` | `realm.workflows.read` | Newest first, keyset-paged; an unknown `state` is a `422` |
| `GET /workflow-runs/{id}` | `realm.workflows.read` | With attempts and approvals |
| `POST /workflow-runs/{id}/cancel` | `realm.workflows.run` | `202` |
| `GET /me/workflow-approvals?state=` | Self-service | Approvals that name the caller (at most 500) |
| `POST /me/workflow-approvals/{id}/decision` `{decision: approve\|reject, comment?}` | Self-service | `comment` at most 500 characters; `404` when the caller is not an eligible approver (the subject included), `409` if already decided or expired |

Permissions (in the catalog, `GET /permissions`): `realm.workflows.read`
(normal), `realm.workflows.write` (high), `realm.workflows.publish`
(privileged), `realm.workflows.run` (high). The built-in `realm-admin` role
holds them through `realm.*`; `realm-auditor` holds `realm.workflows.read`.

Realm policy: `extensions.workflow_publish_approval` (boolean, default
`false`): workflows created while it is `true` need an approved revision
before publishing.

Workflows that a [plugin](plugins.md) installed carry its `plugin_id`; their
revisions, approval, publication, rollback, enable, disable and deletion
answer `409` through this API. Change them through the plugin.

### Diagnostics

`GET /workflows/{id}/diagnostics` summarizes a workflow without inputs,
results or subjects, from its last 500 runs and 1000 attempts: runs by state,
step failure categories, recent attempts and failures, p50 and p95 run
duration, pending approvals, the oldest due run (pending, running or
compensating), compensation failures, and `health`: `unknown` (no data),
`healthy`, `degraded` (more than 10 % of the attempts failed) or
`attention_required` (a compensation failed).

Error categories in attempts and runs: `subject_missing`, `group_missing`,
`not_a_member`, `self_action`, `no_recipients`, `no_eligible_approver`,
`approval_rejected`, `approval_expired`, `approval_missing`,
`organization_required`, `publisher_lacks_authority`, `retries_exhausted`,
`cancelled`, `definition_unavailable`, `interrupted`, `error`, the code of a
refused operation (`forbidden`, `conflict`, `not_found`, `validation_failed`,
`grant_ceiling_exceeded`, …), and for endpoint calls `http_<status>`,
`gone`, `timeout`, `network_error`, `egress_denied`, `subscription_missing`,
`subscription_paused`, `subscription_disabled`, `secret_unavailable` and
`invalid_destination`.

There are no workflow-specific metrics: the worker counts the two tasks in
`proudauth_worker_runs_total{task="workflows.run"|"workflows.schedule"}`,
and runs that end `failed`, `compensated` or `compensation_failed` in
`proudauth_jobs_failed_total{type="workflow"}`
([monitoring.md](../operations/monitoring.md#metrics)). `/status` has no
workflow backlog, and `proudauth_worker_active_leases` does not count
workflow runs.

### Audit events

- Definitions: `workflow.created`, `workflow.revision.staged`,
  `workflow.revision.approved`, `workflow.revision.rejected`,
  `workflow.published`, `workflow.rolled_back`, `workflow.enabled`,
  `workflow.disabled`, `workflow.deleted`.
- Runs: `workflow.run.started`, `.succeeded`, `.failed`, `.compensated`,
  `.compensation_failed`, `.cancelled`, `.cancel_requested`;
  `workflow.step.succeeded`, `.failed`, `.compensated`,
  `.compensation_failed`.
- Approvals: `workflow.approval.requested`, `.approved`, `.rejected`,
  `.expired` (cancelled approvals are not audited).
- Triggers: `workflow.schedule.fired`, `workflow.trigger.suppressed`.

### Retention

`retention.cleanup` deletes finished runs, with their attempts and
approvals, `privacy.history_retention` (180 days) after they ended; their
audit events follow audit retention. Workflows and revisions are kept until
the workflow is deleted. Account deletion does not touch workflow tables:
runs about a deleted account keep its user ID until they are purged
([data-inventory.md](../operations/data-inventory.md)).

## Not offered

- **Embedded code, expressions, conditions or loops** ([ADR 0021](../architecture-decisions/0021-no-embedded-code-execution.md)).
  Use an approval step, separate workflows, or a `call_webhook` to a service
  that applies its own logic.
- **Free-text notifications.** A phishing and abuse vector: notices are fixed
  codes with realm-controlled template wording.
- **Automatic reversal of removals or suspensions during compensation.**
  Re-granting access while a process is failing is unsafe; restoring access
  is an administrator action.
- **Subjects other than users** (service principals, groups) and **triggers on
  every event type**: steps act on a user, and high-volume events such as
  sign-ins would amplify load.
- **Catch-up of missed schedule slots,** to avoid storms after an outage; the
  next slot covers the population again.
- **An emergency control for one workflow** (`POST /emergency/controls` has no
  workflow target): use `POST /workflows/{id}/disable`, or disable the plugin
  that owns it.
- **Configuration export or import and realm data export of workflows.**
  Revisions are stored with their exact content; re-create them through the
  API (or ship them in a [plugin](plugins.md)).

## Residual risks

- Endpoints that ignore `Idempotency-Key` may act twice after a crash.
- An event committed shortly before a workflow is published may still
  trigger it (dispatch lag).
- Compensating an owner-role grant can hit the last-owner rule; the run then
  ends `compensation_failed` and needs an administrator.
- Runs in flight keep their accountable publisher; after that administrator
  loses authority they fail and compensate rather than continue under a
  successor.
- The tests do not cover the depth limit, the 500-subject cap, the per-realm
  share or the 25-transition limit, nor that disabling a workflow raises
  `security.alert` (tested for plugins only).
