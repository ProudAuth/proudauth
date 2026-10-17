# Monitoring

Requirements: OPS-001, OPS-002, OPS-003, OPS-004, OPS-011, OPS-012, OPS-015, SEC-015,
AUD-011, AUD-012, AUD-013, AUD-014, EXT-005, EXT-015, EXT-017, DEP-009. Code:
`internal/observability/observability.go`, `internal/server/server.go`
(`InternalHandler`, `refreshGauges`), `internal/httpapi/protocol.go` (`live`,
`ready`), `internal/httpapi/middleware.go`, `internal/worker/worker.go`
(`VerifyRecentAudit`), `internal/platform/tracing` (span export).

## Endpoints

| Listener | Path | Auth | Response |
| --- | --- | --- | --- |
| Public | `GET /health/live` | none | `200 {"status":"ok"}`; never touches dependencies. Use for liveness. |
| Public | `GET /health/ready` | none | `200 {"status":"ready"}` when the database answers, the schema is current and every active realm has a usable active signing key; otherwise `503 {"status":"unavailable"}` (database or schema) `503 {"status":"degraded"}` (signing key), or `503 {"status":"degraded","reason":"clock_skew"}` when the server clock differs from the database clock by more than `observability.max_clock_skew`. During shutdown it answers `503 {"status":"draining"}` for `server.drain_delay` before the listeners close (OPS-012). Maintenance mode does not change it. Use for readiness/load balancing. |
| Internal | `GET /health/live` | none | `200`, empty body. |
| Internal | `GET /metrics` | `Authorization: Bearer <server.metrics_token>` when configured | Prometheus text format (version 0.0.4). 404 when `observability.metrics_enabled: false`. Each scrape first refreshes the database, queue-age, clock-skew, worker-lease and audit-backlog gauges. |
| Internal | `GET /status` | `Authorization: Bearer <server.metrics_token>` when configured | Operator status JSON (OPS-015), see [below](#operator-status). |

The internal listener (`server.internal_listen`) must be on a private network:
`/metrics` and `/status` are protected only when `server.metrics_token` is set
(if that reference cannot be resolved at startup, both answer 401 to every
request), and `/health/live` never is. `identity-worker` has no listener unless
`workers.metrics_listen` is set; it then serves the same `/metrics`, `/status` and
`/health/live` on that private address, under the same token and
`metrics_enabled` rules.

### Operator status

`GET /status` (`operatorStatus` in `internal/server/server.go`,
`TestMaintenanceAndStatus`) always answers `200` with `Cache-Control: no-store`
(or `401` without the token):

```json
{
  "status": "degraded",
  "time": "2026-10-10T12:00:00Z",
  "capabilities": {"database": "ok", "schema": "ok", "signing": "ok", "outbox": "ok",
                   "email_delivery": "degraded", "webhooks": "ok", "jobs": "ok",
                   "audit_sealing": "ok"},
  "backlog_oldest_seconds": {"outbox": 0, "email_delivery": 412, "webhooks": 0, "jobs": 0,
                             "audit_sealing": 21},
  "clock_skew_ms": 3,
  "maintenance": {"mode": "off", "retry_after_seconds": 300},
  "key_provider": "kms_unwrapped",
  "residency": {"region": "eu-central", "destinations_restricted": true}
}
```

| Member | Meaning |
| --- | --- |
| `capabilities.database` | `ok`, or `unavailable` when the database does not answer; the response then holds only `time`, `capabilities.database` and `status: "unavailable"` |
| `capabilities.schema` | `degraded` (and top-level `schema: "behind"`) when migrations are pending for this binary |
| `capabilities.signing` | `unavailable` when any realm (including suspended ones) has no usable active signing key |
| `capabilities.outbox`, `.email_delivery`, `.webhooks`, `.jobs`, `.audit_sealing` | `degraded` when the matching `backlog_oldest_seconds` value exceeds 300 |
| `backlog_oldest_seconds` | Age in seconds of the oldest pending outbox event, of the oldest notification job and webhook delivery that is due (`queued`/`attempted`, `pending`/`retrying`), counted from when it became due, of the oldest `queued` job, and of the oldest audit event not yet sealed into a batch (`audit_sealing`, AUD-014; sealing takes events older than 2 s every `workers.audit_seal_every`); `0` when there is none |
| `clock_skew_ms` | Server clock minus database clock, including query latency |
| `maintenance` | The maintenance state: `mode`, `message`, `retry_after_seconds`, `updated_at`, `updated_by`, and `debug_until`/`debug_component` while a debug window is open ([incidents.md](incidents.md#maintenance-mode-ops-015)) |
| `status` | `unavailable` (database down), `maintenance` (any mode other than `off`), `degraded` (any capability not `ok`) or `ok` |
| `key_provider` | `kms_unwrapped` when `keys.kms.command` is configured (keys were unwrapped by the KMS command at start-up and are held in memory), otherwise `software` ([keys.md](keys.md#kms-envelope-dep-016)); present even when the database is down |
| `residency` | Only when `privacy.residency` sets a `region` or `allowed_destinations`: `region` and `destinations_restricted` (whether an allowlist is configured); present even when the database is down |

`/status` is meant for operators: it names internal capabilities and must not be
exposed publicly. Anonymous clients only ever see the generic `maintenance` or
`unavailable` problem responses.

## Metrics

All metrics are per process (`identity-server`, or `identity-worker` when
`workers.metrics_listen` is set); aggregate across instances in your monitoring
system. Labels never contain user IDs, emails or realm names: the `route`
label (also in request logs and spans) is the registered route pattern
without the method, for example `/api/v1/realms/{realm}/users/{user}`, and
`unmatched` for requests that match no route (OPS-002), so path values such
as slugs or external IDs never become labels. Each counter keeps at most 1000 label
combinations and each histogram 500; further combinations are dropped.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `proudauth_http_requests_total` | counter | `route`, `status` (`2xx`, `4xx`, ...) | Requests on the public listener. |
| `proudauth_http_request_duration_seconds` | histogram | `route` | Latency; buckets 5 ms – 10 s. |
| `proudauth_authentications_total` | counter | `outcome` (`success`, `failure`) | Transaction steps that completed a login, and steps rejected with `invalid_credentials`. |
| `proudauth_tokens_total` | counter | `grant_type`, `outcome` (`success` or the OAuth error code, e.g. `invalid_grant`) | Token endpoint results. |
| `proudauth_rate_limited_total` | counter | `surface` (holds the route label) | Requests rejected by abuse budgets (`rate_limited`). The token endpoint's own budget (`slow_down`) is counted in `proudauth_tokens_total` instead. |
| `proudauth_load_shed_total` | counter | `pool` (holds the route label) | Requests shed with 503 at `limits.max_inflight_requests`. |
| `proudauth_database_up` | gauge | — | 1/0; refreshed on every `/metrics` scrape and on every `/health/ready` request. |
| `proudauth_outbox_oldest_pending_seconds` | gauge | — | Age of the oldest pending outbox event (0 when none); refreshed on every scrape. |
| `proudauth_notification_oldest_due_seconds` | gauge | — | How long the oldest due notification job (`queued`/`attempted`) has waited since it became due (0 when none, or when the query fails); refreshed on every scrape (OPS-002). |
| `proudauth_webhook_oldest_due_seconds` | gauge | — | The same for webhook deliveries (`pending`/`retrying`). |
| `proudauth_jobs_oldest_queued_seconds` | gauge | — | The same for `queued` asynchronous jobs, from their `run_after`. |
| `proudauth_clock_skew_milliseconds` | gauge | — | Process clock minus database clock (includes query latency); refreshed on every scrape. |
| `proudauth_worker_active_leases` | gauge | — | Unexpired worker leases across `jobs`, `notification_jobs`, `webhook_deliveries` and `outbox_events`; refreshed on every scrape. |
| `proudauth_audit_unsealed_events` | gauge | — | Audit events not yet sealed into a hash-linked batch (AUD-014); refreshed on every scrape. |
| `proudauth_audit_unsealed_oldest_seconds` | gauge | — | Age of the oldest unsealed audit event, measured from its database `recorded_at` (0 when none); refreshed on every scrape. |
| `proudauth_security_signals_total` | counter | `signal` | Alertable security evidence (OPS-004), derived from audit events as they are written (`audit.SecuritySignal`). Values: `refresh_reuse`, `impersonation_denied`, `impersonation_activity`, `cross_tenant_denial`, `factor_recovery`, `signing_key_change`, `bootstrap`, `credential_issued`, `credential_compromised`, `emergency_action`, `protected_account_signin`, `privileged_grant`, `authentication_review` (a sign-in an authentication flow rule sent for review, AUT-014), `configuration_change` (AUD-012), and `audit_write_failed` when an audit insert fails; the worker adds `audit_failure` (below). Counted by the process that writes the event, when its transaction commits: attempts that are rolled back or retried are not counted. Audit write failures are counted immediately. (Events written outside a managed transaction, such as by the logout endpoint, are counted when written.) Each signal-bearing event of a realm is also published as a `security.alert` webhook event, but only when its transaction commits ([Security alerts](#security-alerts)). |
| `proudauth_signing_failures_total` | counter | `reason` (`no_active_key`, `key_unavailable`, `signer_error`, `sign_error`) | Token signing and key-provider failures. |
| `proudauth_hook_calls_total` | counter | `kind`, `outcome` (`ok`, `failure`) | Pre-action hook invocations. |

Set or incremented only inside `identity-worker`, so meaningful only through
its `workers.metrics_listen` listener (the server's `/metrics` never updates
them; the help text of `proudauth_jobs_failed_total` says so):

- `proudauth_worker_runs_total` (`task`, `outcome`): every periodic task run,
  for example `audit.seal`, `audit.archive`, `audit.verify_recent`,
  `retention.cleanup` or `groups.dynamic`, with `ok` or `error`.
  `lifecycle.expiry` (every 30 seconds) removes expired role assignments (at
  most 500 per run), which ends just-in-time elevations at their deadline,
  and closes and applies access review campaigns past their due date (at
  most 20 per run; [elevation-and-access-reviews.md](../integrations/elevation-and-access-reviews.md)).
  A `retention.cleanup` error names each failed step; the other steps still
  ran. The
  lifecycle workflow tasks are `workflows.run` (every second: advances due
  runs under leases) and `workflows.schedule` (every minute: fires schedule
  triggers); event-triggered runs start in `outbox.dispatch`
  ([workflows.md](../integrations/workflows.md#execution-and-idempotency-ext-016)).
- `proudauth_security_events_total` (`type`): outbox events whose type starts
  with `security.`, including `security.alert`.
- `proudauth_delivery_total` (`channel`, `outcome`): final outcomes of
  deliveries: `channel="webhook"` (`delivered`, `dead_letter`),
  `channel="notification"` (email and SMS jobs: `accepted` by the relay or
  gateway, `failed`, `expired`) and `channel="backchannel_logout"`
  (`delivered`, `failed`). Retries are not counted, and neither are
  back-channel deliveries dropped because the client or its URI no longer
  exists or bounces reported later through `POST /delivery-events`.
- `proudauth_audit_integrity_problems` (gauge): problems found by the last run
  of `audit.verify_recent` (hourly; the newest 200 sealed batches: event content
  hashes, batch digests, links, and signatures where present). A non-zero run
  also increments `proudauth_security_signals_total{signal="audit_failure"}`
  and logs `audit integrity problems`.
- `proudauth_jobs_failed_total` (`type`): asynchronous jobs (exports, imports,
  bulk operations, organization deletion) that reached `dead_letter`, by job
  type. Retried failures are not counted. `type="workflow"` counts lifecycle
  workflow runs that ended `failed`, `compensated` or `compensation_failed`.
  There are no other workflow metrics: `/status` has no workflow backlog and
  `proudauth_worker_active_leases` does not count workflow runs; use
  `GET /workflows/{id}/diagnostics`.
- `proudauth_key_rotations_refused_total` (`reason`: `pinned_resources`,
  `fapi2_clients`): scheduled signing-key rotations that `keys.lifecycle`
  refused for a realm because active business resources pin another
  algorithm than the realm's, or fapi2 clients need a FAPI 2.0 algorithm
  ([keys.md](keys.md#scheduled-automatic)). The other realms still rotate;
  the refused realm is retried every minute and logs
  `scheduled signing key rotation refused` with its `realm_id`.

The queue-age gauges are refreshed by whichever listener is scraped (the
server's internal listener or the worker's `workers.metrics_listen`), so
either one shows them. Not implemented from OPS-002: a metric for spans the
trace exporter dropped.

### Directory integration

PROV-018, `internal/directory/metrics.go`
([directory.md](../integrations/directory.md),
[outbound-provisioning.md](../integrations/outbound-provisioning.md)).
Labels are bounded enumerations; connector IDs, hosts and users never become
label values.

| Metric | Type | Labels | Updated by | Meaning |
| --- | --- | --- | --- | --- |
| `proudauth_directory_binds_total` | counter | `outcome` (`success`, `invalid_credentials`, `unavailable`, `disabled`, `busy`) | `identity-server` | Password sign-ins of directory-sourced accounts and first sign-in provisioning; `unavailable` is an outage or an attempt past `directory.sign_in_timeout`, `disabled` a disabled connector, organization or module, `busy` a sign-in refused at once because `directory.max_concurrent_binds` were in use |
| `proudauth_directory_failovers_total` | counter | `category` (`connect`, `dns`, `tls`, `timeout`, `network`, `server_unavailable`, `egress_denied`, `invalid_endpoint`) | the process doing the LDAP operation | Endpoint failures that moved an operation to the next configured endpoint; a failure of the last (or only) endpoint is not counted |
| `proudauth_directory_sync_runs_total` | counter | `mode`, `state` | `identity-worker` | Finished synchronization and reconciliation runs (`succeeded`, `failed`, `refused`, `cancelled`) |
| `proudauth_directory_sync_changes_total` | counter | `kind` | `identity-worker` | Records changed or reported by runs, by finding kind and counter |
| `proudauth_outbound_provisioning_total` | counter | `operation`, `outcome` (`delivered`, `retrying`, `dead_letter`) | `identity-worker` | Outbound SCIM delivery attempts |
| `proudauth_directory_sync_lag_seconds` | gauge | — | `identity-worker` (`directory.schedule`) | Seconds since the least recently successful synchronization among active, scheduled directory connectors (from creation when one never succeeded) |
| `proudauth_outbound_provisioning_backlog` | gauge | — | `identity-worker` (`directory.schedule`) | Open (`pending` or `retrying`) outbound deliveries across connectors |

Worker tasks (also in `proudauth_worker_runs_total`): `directory.schedule`
(every 15 seconds, before `jobs.run`: claims due synchronization and
reconciliation slots and queues `directory.sync` jobs, scans for changed
accounts for outbound connectors, refreshes the two gauges) and
`directory.outbound.deliver` (every 2 seconds). Runs are asynchronous jobs of
type `directory.sync`, so a failed one also shows in
`proudauth_jobs_failed_total{type="directory.sync"}`. Per connector, `GET
.../directory-connectors/{id}/health` gives `status`, `lag_seconds`,
`consecutive_failures`, `last_error`, endpoint health and delivery counts.

SAML has no metrics of its own: use the audit events `saml.request.rejected`
and `saml.response.rejected` (with their reasons), `saml.assertion.issued`
and `proudauth_http_requests_total` for the `/realms/{id}/saml/...` routes
([saml.md](../integrations/saml.md#audit-events)).

### Shared signals

AUD-016, ADV-007 ([shared-signals.md](../integrations/shared-signals.md)).
Security Event Tokens have no metric of their own and are not counted in
`proudauth_delivery_total`.

- Worker task `ssf.deliver` (every 2 seconds, up to 50 due push events per
  run) appears in `proudauth_worker_runs_total{task="ssf.deliver"}`; an
  `error` outcome means the queue query failed, not that a receiver refused
  a token. Failed and expiring events show in the per-stream view
  `GET /api/v1/realms/{realm}/ssf-streams/{id}/events` (`state`,
  `attempts`, `last_status_code`, `last_error` such as `rejected_<err>`,
  `http_<status>`, `network_error`, `egress_denied`,
  `transmitter_disabled`).
- `retention.cleanup` steps `ssf_events` (expires events undelivered after 7
  days, deletes finished ones after 14) and `ssf_received_events` (deletes
  received-event records after 30 days).
- Inbound pushes: audit events `ssf.event.received` (with `outcome`) and
  `ssf.event.replayed`; per transmitter,
  `GET /api/v1/realms/{realm}/ssf-transmitters/{id}/events`. Rejected pushes
  (bad secret, signature, issuer, audience or age) are answered to the
  transmitter and leave no record; watch
  `proudauth_http_requests_total` for the receiver route's `4xx`.

```sql
SELECT s.id, s.delivery_method, s.status, e.state, count(*)
  FROM ssf_events e JOIN ssf_streams s ON s.id = e.stream_id
 GROUP BY 1, 2, 3, 4;                                                    -- watch failed and expired
SELECT min(occurred_at) FROM ssf_events WHERE state = 'pending';         -- oldest undelivered event
```

## Logs

- Structured `log/slog` output to stderr, JSON by default (`observability.log_format`),
  level from `observability.log_level` (`debug` is refused in production). Records
  below that level are emitted only inside an operator debug window
  (`identity-cli debug-window`, SEC-015), optionally for one component, and still
  pass through redaction ([support-bundle.md](support-bundle.md#debug-logging-windows)).
- Every record carries `component` (default `server`; `http` for request lines,
  `audit` for security signals) and `event_code` (an explicit code such as
  `http.request` or the audit event type, otherwise the log message).
- Redaction runs before serialization: attributes whose key matches password,
  secret, token, authorization, cookie, otp, code_verifier, code, seed, private,
  assertion, pepper or api_key are replaced with `[REDACTED]`, and values that look
  like `pa_*` bearer secrets or JWTs are masked.
- One `http` line per request (`component: http`, `event_code: http.request`):
  `outcome` (`success`, `client_error`, `rate_limited`, `server_error`),
  `request_id`, `trace_id`, `span_id`, `method`, `route` (bounded label, not the
  raw path or query), `status`, `duration_ms`, `network` (client IP reduced to /24
  or /48).
- `X-Request-Id`: accepted from the client when 1–64 printable ASCII characters,
  otherwise generated; echoed in the response and stored in audit events
  (`request_id`). Use it to join logs and audit.
- A valid incoming W3C `traceparent` continues that trace. Its sampled flag
  is honored only when the request comes directly from an address in
  `server.trusted_proxies`; otherwise, and for requests without one (which
  get a new trace ID), the request is sampled with probability
  `observability.trace_sampling`. Sampled requests emit an extra `span` log line
  (`trace_id`, `span_id`, `name` = method and route, `status`, `start`,
  `duration_ms`). Outbound HTTP calls made while serving a request (pre-action
  hooks, upstream identity providers' discovery, JWKS, token and user
  endpoints, challenge-provider verification, the identity-provider test call)
  carry a W3C `traceparent` with the request's trace ID, its span ID as the
  parent ID (or, when spans are exported, a new client span's ID) and its
  sampled flag, and never `tracestate` or baggage (API-012, `egress.traceTransport`,
  `TestCorrelationPropagation`). Calls the worker makes (webhook deliveries,
  back-channel logout, SMS gateway) carry a `traceparent` only during a
  sampled task run, and SMTP is not HTTP. Spans can be exported to an
  OpenTelemetry collector ([Tracing](#tracing)).
- Webhook events carry `correlation_id`, the `X-Request-Id` of the request
  that caused them, equal to the `request_id` of its audit events; events from
  background work have none ([api/events](../../api/events/README.md#envelope)).
  Clients choose their own `X-Request-Id`, so it is a correlation aid, not
  evidence.
- Notable messages: `request failed` (5xx and unexpected errors), `panic`,
  `worker task failed` (with `task`), `security event` (warning, with `event_type`,
  logged by the worker for outbox events whose type starts with `security.`),
  `security signal` (warning, `component: audit`, `event_code` = audit event type,
  `signal`, `outcome`, `realm_id`, `org_id`, `request_id`), `audit persistence
  failed` (error), `audit integrity problems` (error, `component: worker`,
  `event_code: audit.integrity_failed`, `problems`), `notification delivery
  failed`, `DEVELOPMENT MODE: not for production use`.

## Tracing

OPS-003, `internal/platform/tracing`, `TestOTLPExporter`, `TestTraceExport`.
`identity-server` records spans of **sampled** requests (see `traceparent`
above) and `identity-worker` of sampled task runs; when
`observability.otlp_endpoint` is set, both export them as OTLP/HTTP JSON with
`service.name` `proudauth-server` or `proudauth-worker`
([configuration.md](configuration.md#observability)):

| Span | Name | Kind | Attributes | Status |
| --- | --- | --- | --- | --- |
| One per sampled request | `<METHOD> <route>` | server; parent is the span ID of the incoming `traceparent`, if any | `http.request.method`, `http.route`, `http.response.status_code` | error for 5xx |
| One per sampled worker task run (each run is sampled with probability `observability.trace_sampling` and starts a new trace) | `worker <task>`, for example `worker webhooks.deliver` | internal | `proudauth.worker.task`, `proudauth.worker.items` (items the run handled) | error when the task fails |
| One per outbound HTTP call made while serving a sampled request or in a sampled task run (pre-action hooks, upstream identity providers, challenge providers, the identity-provider test call, webhook deliveries, back-channel logout, the SMS gateway) | `<METHOD>` | client; its ID is sent as the parent in the outbound `traceparent` | `http.request.method`, `server.address` (host only), `http.response.status_code` | error for 5xx or a transport failure |

- Spans carry no headers, bodies, query strings or tokens. `http.route` is
  the route label used for metrics: ID-shaped path segments and the realm name
  become `{id}`, but other path segments stay, for example external-ID values
  in `/external-ids/{source}/<value>` and organization slugs or aliases where
  a path accepts them instead of an ID. Treat the collector as holding operational metadata of
  your deployment.
- Unsampled requests export nothing and keep propagating `traceparent` as
  before. An incoming sampled flag counts only from `server.trusted_proxies`,
  so other clients cannot make the server export spans for their requests;
  an incoming "not sampled" flag does not prevent local sampling either.
- Export is asynchronous: batches of up to 256 spans every 5 seconds from a
  queue of 4096. When the queue is full, the collector does not accept a
  batch or the process is shutting down, spans are dropped (never delaying
  requests); drops are counted only inside the exporter, not as a metric.
- Worker runs started with `identity-worker -once` export no spans, and the
  worker writes no `span` log line; the server writes it whether or not spans
  are exported.
- The exporter uses its own HTTP client, not the egress policy: it ignores
  proxy environment variables, treats a redirect as a failed export, and its
  endpoint must be `https` in production (loopback excepted) and is checked
  against `privacy.residency.allowed_destinations` only at startup. Use an
  endpoint on your own network.
- Other tracing back ends can be attached in code through the
  `tracing.Tracer` interface (`tracing.SetTracer`).

## Suggested alerts

| Condition | Source |
| --- | --- |
| Readiness failing on any instance | `/health/ready` |
| Database unreachable | `/status` `capabilities.database != "ok"`, or `proudauth_database_up == 0` with readiness scraped |
| Worker stopped or stuck | `proudauth_outbox_oldest_pending_seconds`, `proudauth_notification_oldest_due_seconds`, `proudauth_webhook_oldest_due_seconds` or `proudauth_jobs_oldest_queued_seconds` (or `/status` `backlog_oldest_seconds`) above a few minutes; `/status` `status == "degraded"`; `proudauth_worker_runs_total{outcome="error"}` increasing on the worker listener; growing `proudauth_audit_unsealed_events` |
| Maintenance left on | `/status` `maintenance.mode != "off"` outside a planned window; an open debug window (`maintenance.debug_until`) |
| Clock skew | `abs(proudauth_clock_skew_milliseconds) > 2000` or `/status` `clock_skew_ms`; readiness also fails with `reason: clock_skew` beyond `observability.max_clock_skew` (OPS-011) |
| Token signing failing | any increase of `proudauth_signing_failures_total` (no active key, or the key cannot be loaded or used) |
| Signing key not rotating | any increase of `proudauth_key_rotations_refused_total` on the worker listener: the log line names the realm; `POST /signing-key-rotations` in that realm answers `409` with the `resources` or `clients` to fix ([keys.md](keys.md#scheduled-automatic)) |
| Audit evidence not being written | any increase of `proudauth_security_signals_total{signal="audit_write_failed"}`; `audit persistence failed` log lines |
| Security signals | increases of `proudauth_security_signals_total` for `refresh_reuse`, `cross_tenant_denial`, `impersonation_denied`, `credential_compromised`, `signing_key_change`, `bootstrap` or `emergency_action`; review `factor_recovery`, `credential_issued`, `impersonation_activity`, `protected_account_signin`, `privileged_grant`, `authentication_review` and `configuration_change` against expected support and change activity (`privileged_grant` counts only privileged roles, so the `member` and `admin` grants of ordinary onboarding do not raise it; imports and organization templates that assign owner or privileged roles do). To route them to an alerting system, subscribe a webhook to `security.alert` ([below](#security-alerts)) |
| Pre-action hook failures | `proudauth_hook_calls_total{outcome="failure"}`; `GET /hooks/{id}/diagnostics` (`health: "degraded"` when more than 10 % of the last 100 calls failed; `recent_failures`, `latency_p95_ms`, and per call `error_category` and `status_code`, EXT-017); `GET /hooks/{id}` (`failures`, `last_error`) |
| Deliveries failing | `proudauth_delivery_total{outcome=~"dead_letter|failed|expired"}` rising on the worker listener, by `channel` |
| Webhook destination falling behind | `GET /webhooks/{id}/backlog` (EXT-005): `oldest_due_seconds` growing, `retrying` or `dead_letter` counts rising, `last_failure_category` (for example `egress_denied`, `http_500`) |
| Failed background jobs | any increase of `proudauth_jobs_failed_total` on the worker listener (a job reached `dead_letter`); `GET /jobs/{id}` shows `last_error` |
| 5xx rate | `proudauth_http_requests_total{status="5xx"}` |
| Refresh-token reuse | `proudauth_security_signals_total{signal="refresh_reuse"}`; `proudauth_tokens_total{outcome="invalid_grant"}` spike; audit `token.refresh.reuse_detected` |
| Credential stuffing | `proudauth_authentications_total{outcome="failure"}`, `proudauth_rate_limited_total`; audit `authentication.password.failed` |
| Client secret guessing | audit `client.authentication.failed` |
| Load shedding | `proudauth_load_shed_total` |
| Emergency and privileged actions | `GET /audit-events?category=emergency` (every event recorded by an emergency control, with the operator's reason; break-glass bootstrap); `signing_key.rotation.emergency`, `realm.suspended`, `client.suspended`, `organization.suspended`, `service_principal.disabled`, `support.impersonation.started`, `recovery.assisted`, `credential.password.compromised`; in the database only, operator events `operations.restore.reconciled`, `operations.maintenance.changed` and `operations.debug_window.opened` |
| Ownership and tenancy drift | audit `service_principal.owner_departed` (a service principal's owner left; MCH-007), `organization.domain.verification_lapsed` (a domain's DNS proof disappeared; TEN-009), `organization.domain.conflict` (an organization tried to verify a domain another organization holds; TEN-009); repeated `authorization.denied` from one actor (`category=authorization`: administrative requests refused for a missing permission; AZ-020) |
| SCIM provisioning connectors | A connector's `last_sync_at` older than the directory's sync interval, or `stats.errors` and `last_error` changing (`GET /organizations/{org}/provisioning-connectors/{id}`, PROV-018); unexpected `scim.user.provisioned` with `adopted: true` or `scim.user.updated` with `identity_changed: true` ([scim-provisioning.md](../integrations/scim-provisioning.md)) |
| Directory connectors (LDAP/AD) | `proudauth_directory_binds_total{outcome="unavailable"}` rising (directory users cannot sign in; audit `directory.authentication.unavailable`); `proudauth_directory_failovers_total` rising (a primary endpoint failing); `proudauth_directory_sync_lag_seconds` above the longest scheduled interval; `proudauth_directory_sync_runs_total{state=~"failed|refused"}` (a `refused` run hit the deletion threshold: check the directory before any `allow_mass_deprovision` override); `GET .../directory-connectors/{id}/health` `status` other than `healthy`; `directory.user.jit_refused` and `conflict` findings ([directory.md](../integrations/directory.md)) |
| Outbound provisioning | `proudauth_outbound_provisioning_backlog` growing, `proudauth_outbound_provisioning_total{outcome="dead_letter"}` rising, audit `directory.outbound.dead_lettered`; per connector `deliveries` and `oldest_due_seconds` in `.../health` ([outbound-provisioning.md](../integrations/outbound-provisioning.md)) |
| SAML | Bursts of `saml.response.rejected` (broker: `assertion_replay`, signature, `audience` or `unsolicited` reasons point to an attack or a misconfigured IdP) or `saml.request.rejected` (identity provider); forced `saml.signing_key.activated` in category `emergency`; SAML connection certificates expiring (`POST /identity-providers/{id}/test` reports those expiring within 30 days) ([saml.md](../integrations/saml.md)) |
| Audit sealing backlog | `proudauth_audit_unsealed_oldest_seconds` above 300 (also `/status` `capabilities.audit_sealing == "degraded"`); `proudauth_worker_runs_total{task="audit.seal",outcome="error"}` on the worker listener (AUD-014) |
| Audit integrity | `proudauth_audit_integrity_problems > 0` or any increase of `proudauth_security_signals_total{signal="audit_failure"}` on the worker listener; `audit integrity problems` log lines; `proudauth_worker_runs_total{task="audit.verify_recent",outcome="error"}`. The hourly check covers only the newest 200 batches, so also run `identity-cli verify-audit` on a schedule (non-zero exit; add `-require-signatures` once every batch was sealed with signing) and, with an archive, `identity-cli verify-audit-archive`. Batches pruned by retention are recorded in `audit_prunes` and still verify ([incidents.md](incidents.md#audit-chain-verification-failure)) |
| Audit archive or retention failing | `proudauth_worker_runs_total{task="audit.archive",outcome="error"}` or `{task="retention.cleanup",outcome="error"}` on the worker listener; archive progress `SELECT last_sequence FROM audit_archive_state` falling behind `SELECT max(sequence_number) FROM audit_batches` (while it does, retention does not prune the unarchived batches); a new archive fork after a restore: operator event `audit.archive.forked` in `audit_events` ([incidents.md](incidents.md#audit-archive-aud-008)) |
| Lifecycle workflows failing | `proudauth_jobs_failed_total{type="workflow"}` rising on the worker listener; `proudauth_worker_runs_total{task=~"workflows.run|workflows.schedule",outcome="error"}`; per workflow `GET /workflows/{id}/diagnostics` with `health: "degraded"` (more than 10 % of recent attempts failed) or `"attention_required"` (a compensation failed: undo the rest by hand), and `oldest_due` growing; audit `workflow.run.compensation_failed`, `workflow.step.failed` (a step category `publisher_lacks_authority` in the run's attempts means the accountable administrator lost authority) and `workflow.trigger.suppressed` (loops) ([workflows.md](../integrations/workflows.md#diagnostics)) |
| Extension changes | audit `workflow.published`, `workflow.rolled_back`, `workflow.disabled` and `plugin.disabled` (both category `emergency`, so they raise the `emergency_action` signal and a `security.alert`), `plugin.version.uploaded`, `plugin.installed`, `plugin.upgraded`, `plugin.downgraded`, `plugin.rolled_back`, `plugin.enabled` and `plugin.uninstalled` against planned changes ([plugins.md](../integrations/plugins.md)) |

### Audit queries

Audit events are queried with `GET /api/v1/realms/{realm}/audit-events`
(`realm.audit.read`) or, limited to one organization,
`GET /api/v1/realms/{realm}/organizations/{org}/audit-events` (`org.audit.read`),
or exported as NDJSON with `POST /audit-exports`. Results are newest first and
paginated with `limit` and `cursor`. Filters (AUD-011, `TestAuditSearchDimensions`;
all optional and combined with AND):

| Parameter | Matches |
| --- | --- |
| `id` | One event by its ID (`evt_...`), for example the `audit_event_id` of a `security.alert`; an unknown ID returns an empty list |
| `type`, `type_prefix` | Event type, exactly or by literal prefix (`type_prefix=support.impersonation.`); `_`, `%` and backslash have no wildcard/escape meaning |
| `actor_id`, `subject_id`, `target_id` | Actor, subject or target ID |
| `outcome` | `success`, `failure` or `denied` |
| `client_id`, `request_id` | OAuth client, `X-Request-Id` |
| `grant_id`, `impersonation_grant_id` | Authorization grant; support grant. `impersonation_grant_id` also returns the request-phase events of that grant (`support.impersonation.requested` and `.approved`, which target the grant's request); `support.impersonation.started` names the request in `metadata.request_id` (IMP-024) |
| `session_id` | The event's session or the actor's session |
| `category` | Audit category: `security` (the default), `account`, `authorization`, `configuration`, `token`, `support`, `privacy`, `emergency`, `data_access`, `audit` (legal holds, imported audit history), `application` (reported application activity), `operations` (asynchronous jobs requested and cancelled, delivery feedback) |
| `network` | An IP address or CIDR prefix (`203.0.113.7`, `2001:db8::/32`); matches events whose stored network context overlaps it. The context is /24 or /48 unless `privacy.store_full_ip` is set, so an address finds every event of its network; full addresses are never reconstructed. Invalid values get `422` |
| `organization_id` | Organization (realm route only; the organization route always uses its own) |
| `from`, `to` | RFC 3339; `from` inclusive, `to` exclusive |

Audit sequence cursors are MAC-bound to the realm, authorized organization,
route and URL-encoded filter parameters (API-004). Keep the filters when
following `next_cursor`; only `limit` may change. A changed filter or route
gets `400 invalid_request`, instead of silently skipping evidence. Older
development-build audit cursors must restart from the first page after
upgrading. `TestAuditTypePrefixIsLiteral` and
`TestAuditCompoundFiltersAndCursors` verify literal matching and exact
compound pages, including newer inserts, foreign scope and cursor changes.

Events are always limited to the realm. Operator events written by
`identity-cli` or at startup (`operations.*`, for example
`operations.migrations.applied`; category `operations` or, for restore
reconciliation, `emergency`) and `credential.password.legacy_retired` carry
no realm and therefore never appear here; read them from the `audit_events`
table. A correction of an event (`audit.correction`, AUD-007) is found with
`type=audit.correction&target_id=<event id>`
([data-inventory.md](data-inventory.md#audit-corrections)). Events with a
security signal are pushed as `security.alert` webhook events (below); for
anything else, poll the API or read the database.

Each event carries `source`: `server` for evidence ProudAuth recorded itself,
`application` for activity reported by a service (below). Audit history
imported from another system (MIG-016) is not in these results; it is listed
by `GET /imported-audit-events` with `source: "import"` and `verified: false`
([exit-and-export.md](exit-and-export.md#historical-audit-records-mig-016)),
and each import request appears here as one `audit.history.imported` event
(category `audit`).

### Security alerts

AUD-012, `internal/audit/audit.go` (`SecuritySignal`),
`internal/runtime/deps.go`, `TestSecurityAlerts`. Every audit event of a realm
that carries a security signal is also written to the outbox as the webhook
event `security.alert`, in the same transaction, so an alert exists exactly
when its evidence committed. Operator events without a realm raise no alert.
The alert holds identifiers only: `signal`, `audit_event_id`, `event_type`,
`actor_type`, `actor_id` and, when the event has a subject, `subject_type` and
`subject_id`; read the audit event for details. `org_id` is set when the event
belongs to an organization, so organization-scoped subscriptions receive their
organization's alerts.

Both payload forms carry every member of the alert, so the default `minimal`
form is enough ([api/events/README.md](../../api/events/README.md#payload-forms)).
Fetch the audit event with `GET /audit-events?id=<audit_event_id>` (or the
organization route for organization-scoped subscriptions). The signals are those of
`proudauth_security_signals_total` except `audit_write_failed` and
`audit_failure`, which have no audit event. The ones added for AUD-012 are:

| Signal | Raised by |
| --- | --- |
| `protected_account_signin` | `authentication.succeeded` of a protected account (platform administrator or break-glass account; `metadata.protected`) |
| `privileged_grant` | `role.assigned` of a privileged role (`metadata.privileged`): an owner role, a realm role, or a role holding a permission the catalog marks `privileged` (for example `org.delete`, `org.integrations.write`, `realm.users.import`), directly or through a role it composes. The built-in organization `admin` and `member` roles are not privileged |
| `authentication_review` | `authentication.flow.evaluated` with outcome `review`: a realm `authentication_flow` rule let a sign-in proceed but asked for review (AUT-014). The audit event's metadata names the rule, the signals consulted (`known_device`, `failed_attempts`, `risk`, `risk_reasons`) and the missing ones ([headless-authentication.md](../protocols/headless-authentication.md#authentication-flow-policy)) |
| `configuration_change` | `realm.policy.updated`, `federation.provider.*`, `hook.created`, `hook.updated`, `webhook.created`, `audit.legal_hold.released` |

### Reported application activity

AUD-013, `internal/httpapi/emergency.go` (`reportedActivityRoutes`),
`TestReportedApplicationActivity`. Services can file their own activity in the
realm's audit log, apart from ProudAuth's evidence:

```json
POST /api/v1/realms/{realm}/activity-events
{
  "type": "app.order.refunded",
  "occurred_at": "2026-10-11T09:30:00Z",
  "organization_id": "org_...",
  "subject": {"type": "user", "id": "usr_..."},
  "outcome": "success",
  "metadata": {"order": "ord_1"}
}
```

- The caller must be a service principal (a client-credentials token for the
  administration audience) holding `realm.activity.report`; user tokens get
  `403`. Grant the permission through a custom realm role.
- `type` is `app.` followed by 1–96 lowercase letters, digits, dots and
  underscores, so reported events never share a type with server events.
  `occurred_at` (default: now) must be within the last 24 hours and at most
  5 minutes ahead; `organization_id` must name an existing organization of the
  realm; `subject.type` is `user` or `service_principal` (the ID is not
  checked); `outcome` is `success` (default), `failure` or `denied`; `metadata`
  is at most 4 KiB as JSON and is redacted like server metadata.
- The event is recorded with `source: "application"`, category `application`,
  the service principal as actor and `reporting_service` and `client_id` set to
  the caller's client ID; it is sealed into the hash chain like any other event.
  The response is `202 {"id", "source", "reporting_service"}`.
- Query them with `GET /audit-events?category=application` or
  `?type_prefix=app.`. They are claims by the reporting service, not evidence
  that ProudAuth observed the action.

### Database queries for delivery health

```sql
SELECT state, count(*) FROM notification_jobs GROUP BY state;
SELECT state, count(*) FROM webhook_deliveries GROUP BY state;            -- watch dead_letter
SELECT state, count(*) FROM logout_deliveries GROUP BY state;             -- watch failed
SELECT type, state, count(*) FROM jobs GROUP BY type, state;              -- watch dead_letter
SELECT min(occurred_at) FROM outbox_events WHERE state = 'pending';
```
