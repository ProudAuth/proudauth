# Capacity notes

docs/plan.md §32 lists proposed performance targets. The project now publishes
[one laptop's measured reference results](benchmarks.md#reference-results)
(NFR-003..NFR-008), including workload, adversarial, refresh-race and a
10-minute mixed soak, [extended passkey/SCIM workload results](benchmarks.md#extended-workload-results-nfr-003-nfr-008)
and [SMTP worker acceptance results](benchmarks.md#smtp-worker-results-nfr-003-nfr-008),
plus [webhook delivery/retry results](benchmarks.md#webhook-worker-results-nfr-003-nfr-005-nfr-008)
and [TOTP guessing results](benchmarks.md#totp-guessing-results-nfr-006-nfr-008),
plus [SCIM User-filter results](benchmarks.md#scim-filter-results-nfr-004-nfr-006-nfr-008)
with the initial failure preserved alongside the passing correction,
[SCIM Group-filter results](benchmarks.md#scim-group-filter-results-nfr-004-nfr-006-nfr-008), and
[refresh results across three independent server processes](benchmarks.md#independent-server-process-results-nfr-003-nfr-007-nfr-008),
and [alpha.5 baselines of the four core token flows](benchmarks.md#alpha5-core-flow-baselines-nfr-003-nfr-008).
**They do not validate the proposed targets and are
not guarantees or sizing advice:** the load generator, server, worker and
PostgreSQL share that laptop. The benchmark tool
`identity-bench` ([benchmarks.md](benchmarks.md), NFR-003..NFR-008) seeds a
dedicated realm and measures workload, adversarial, stress and soak scenarios
against your own deployment, with portable JSON results. Extended scenarios
cover complete software-passkey sign-in, budgeted SCIM user lifecycles and
email enqueue through a worker's actual SMTP acceptance, independently and
in a mixed workload. Email latency includes API job polling and one realm's
worker scheduling/tenant share. Webhook cycles prove two signed callbacks
and delivered records, including controlled first-attempt rejection and
recovery under default backoff. TOTP guessing proves the unchanged account
budget across eight transactions, with post-run database/audit counts;
most samples are refusals after that budget is spent, so their throughput
does not measure successful MFA capacity. Email/SMS/HOTP guesses remain
unmeasured as sustained capacity profiles; [correctness bursts](consistency-tests.md#shared-otp-guessing-budgets--2026-10-12)
check their shared account limit and next-window recovery. The filter profile proves bounded, exact User searches across
10000 additional managed users plus parser-overflow and connector-budget
refusals. Most samples are `429` after that unchanged budget is spent;
aggregate throughput/latency therefore do not measure successful-query
capacity. The Group profile adds 500 Groups, including a 1000-member Group,
with exact member/projection/ETag checks. Correctness fixtures verify
Users/Groups at 20000/20001 resources. The [compound audit profile](benchmarks.md#compound-audit-filter-results-nfr-004-nfr-006-nfr-008)
adds 10000 public application reports and checks exact bounded sequence
pages under eleven simultaneous filters, literal prefixes and typed input/
cursor refusals. Its aggregate latency includes empty and refused searches.
Sustained scan-overflow capacity, larger Group populations and million-event
audit histories/retention remain unmeasured. The
[controlled workload metadata profile](benchmarks.md#controlled-metadata-fetch-results-nfr-006-nfr-008)
adds a passing 60-second/concurrency-32 measurement: 2617.9 operations/s,
p99 27.648 ms, all eight grant/refusal profiles, one cached valid-key contact,
two contacts per error source across a retry boundary, and zero redirect-
target/denied-IPv6 contacts. Cached refusals dominate; preparation and
unfinished timeout waiters are outside the latency histogram.
[Metadata/JWKS correctness bursts](consistency-tests.md#metadatajwks-fetch-bounds--2026-10-12)
now verify coalesced fetches, negative-response retry bounds and recovery
across OIDC, workload and Shared Signals. Sustained OIDC/Shared Signals,
multi-process aggregate fetch budgets and multi-host capacity remain open.
Physical authenticator latency, remote
HTTPS/multi-worker webhook capacity, remote/multi-worker email delivery
and multi-machine capacity are not yet covered. The native-process profile
measures only refresh and refresh races for 60 seconds; it does not prove
failover or sustained scaling. Partial
[cross-replica consistency tests](consistency-tests.md) prove recovery and
invitation single use, ownership transfer, role transitions, conditional
SCIM/admin User/Group conflicts, Group membership/deletion races, refresh
rotation and session/account-wide revocation,
including three grants sharing one browser SSO session,
through independent pools under concurrent bursts;
they are not capacity measurements. The notes below
describe where resources go, from the code, so
you can size a test environment and measure; they are not derived from those
reference numbers.

Before using a new result, check its [run completeness](benchmarks.md#run-completeness-nfr-005-nfr-008)
and the scenario's outcomes/receiver criteria. An interrupted soak may
retain useful completed windows and a partial last window; its overall
`complete: false` and failing CLI exit prevent treating it as a completed
sustained test. Earlier published files retain their recorded build/schema.

## Main cost drivers

| Operation | Dominant cost |
| --- | --- |
| Password step | One Argon2id evaluation: `security.password.argon_memory_kib` of memory (64 MiB default) and `argon_time` passes per attempt, also for unknown accounts (constant-cost dummy verification). Responses are padded to at least `security.min_auth_response` (250 ms). Peak memory ≈ concurrent password checks × 64 MiB. |
| Token issuance | Signature with the realm key: RSA-3072 (default `RS256`/`PS256`) is far more expensive than `ES256` or `EdDSA`. ID tokens add a second signature. Several inserts (grant, code, refresh family/token, audit). |
| Refresh | One transaction with a session row lock before the family lock for session-bound grants, live checks of session, user, client, organization and membership, two token inserts, an access-token signature and an audit row. Offline grants do not take the session lock. |
| Introspection | Client authentication plus several indexed reads (token or JTI revocation, live grant, client, user, session, membership). Support-token introspection adds permission checks **and writes one audit row per call**. |
| Any transaction step or token request | Each rate-limit check is one upsert statement into `rate_limit_counters`, however many budgets it counts (per-network budgets count two rows, the network and its wider /24 or /48, in the same statement): one for starting a transaction that does not reuse an SSO session; one for the identify step; one for the password step's budgets, plus up to two lock reads and, after a wrong password, up to two lock upserts; two for a code or link send (the cooldown first, then the other send budgets); one per token request and one more per access token minted in an organization's context. Only while an aggregate sign-in budget is exhausted, a password or proof attempt adds one indexed read of `known_sign_ins` and, for a known requester, one more upsert (the known-device quota). A completed sign-in adds one upsert of up to four `known_sign_ins` rows after it commits, which changes a row at most once an hour. |
| Admin lists | Bounded pages (`limits.default_page_size` 50, `limits.max_page_size` 200; a larger `limit` is reduced) read with keyset cursors (API-004), including `GET /webhooks/{id}/deliveries`, `GET /notification-jobs` and `GET /me/security-events` (newest first, `next_cursor` until the last page). Cursors are MAC-bound to the realm, the route and its query filters: a cursor from another route gets `400` ("invalid cursor"); they are not bound to IDs in the path or to the caller, which the queries' own filters cover. |
| SCIM User filters | Candidate mappings, realm-qualified users/identifiers and organization-qualified memberships load in batches. A scan still evaluates every candidate to compute an exact total, up to 20000; only the requested page is retained. Batching removes per-user round trips, not scan or memory costs. The real-query regression observes five queries at both eight and 64 users. |

Server-side signing-key sets are cached for 5 s per process; JWT verification on
resource servers with the Go SDK needs no network call after the first JWKS fetch.

Membership pages retain the API array contract when empty (`items: []`,
`next_cursor: ""`), before the first member and after removing the last live
one (`TestEmptyMembershipPagesAreArrays`, API-004). Removed history is
excluded by default; an explicit `state` filter can list it.

## Concurrency and pools

- Each process opens up to `storage.max_conns` (20) connections. Keep
  `processes × max_conns` below PostgreSQL's `max_connections` minus
  administrative headroom.
- `limits.max_inflight_requests` (2000) bounds concurrent requests per server
  process. A separate pool of a quarter of that (plus one) serves the public
  `/health/*` routes and requests to administrative paths (users, settings,
  signing keys, emergency actions, sessions, clients, role assignments) whose
  bearer is a JWT naming a signing key of the path's realm, so operators can
  act during overload (NFR-002); anonymous requests and other credentials
  use the main pool
  ([monitoring.md](monitoring.md#probes-and-load-shedding)). Excess requests
  get 503 with `Retry-After: 2` (`unavailable` problem details, or an OAuth
  `temporarily_unavailable` error on the OAuth and OIDC endpoints). The
  internal listener's `/health/live` and `/health/ready`, which the
  Kubernetes probes use, are not load-shed.
- Requests are cancelled after 30 s; statements after `storage.statement_timeout`.
- Each worker process runs its tasks one after another every
  `workers.poll_interval`; outbox, notifications and webhooks claim up to
  `workers.batch_size` rows per run, and the jobs task runs up to
  `workers.concurrency` asynchronous jobs (exports, imports, organization
  deletion) in parallel. Add worker processes to increase delivery throughput;
  they coordinate through `SKIP LOCKED` and leases: a notification, webhook
  or outbound provisioning delivery, workflow run or job claimed by one
  worker is not claimed by another until its lease expires. Every claim
  re-checks state, due time and lease on the row version it locks, so a
  delivery that another worker claimed or finished after the claim began is
  skipped rather than sent twice. Job claims are serialized while
  `workers.max_jobs_per_organization` is on so the cap holds across workers
  (DEP-011, DEP-015; `TestReplicasShareOneTimeState`,
  `TestWebhookDeliveryClaimedOnce`, `TestOutboundDeliveryClaimedOnce`,
  `TestWorkflowRunClaimRechecksState`, `TestJobLeasesRetriesAndDeadLetters`,
  `TestWorkerPoolBoundsAndTenantShares`).
- Full imports and membership/role assignments can enqueue outbox events
  faster than a single default worker dispatches them. Dispatch claims at
  most `workers.batch_size` per scheduled pass; all its other tasks share
  the same serial loop. New callbacks wait behind that committed backlog.
  Raising login/token budgets does not raise this capacity. The webhook
  benchmark's unmeasured readiness cycle crosses the setup backlog before
  warm-up and records the wait; measured delivery timeouts remain 30 seconds.
- Tenant fairness (TEN-018): each notification batch takes at most
  `workers.tenant_batch_share` (25) due messages of one organization (or of one
  realm, for messages without an organization) and each webhook batch at most as
  many deliveries of one subscription; at most
  `workers.max_jobs_per_organization` (2) jobs of one organization run at once.
  A large backlog of one tenant therefore drains over several runs instead of
  delaying everyone else. Sign-in and token issuance are bounded per
  organization by `security.rate_limits.login_per_organization` and
  `organization_per_window` ([configuration.md](configuration.md)). When an
  aggregate sign-in budget (client, organization or realm) is exhausted, only
  networks, remembered devices and identifiers with a successful sign-in in
  the last `known_quota_days` keep signing in, under quotas of their own
  (owner decision 9); `proudauth_rate_budget_utilization` shows how close
  each aggregate family is to its cap ([monitoring.md](monitoring.md#metrics)).

## Directory outages

A password sign-in still runs its Argon2id check, the timing pad and, for
directory-sourced accounts or first sign-in provisioning, the LDAP search and
bind inside one database transaction, holding one of the process's
transaction slots (15 with the default `storage.max_conns` of 20) that token
issuance and refresh also use. Moving that work out of the transaction is
planned for 0.2.0-alpha.8. Until then three bounds keep a slow or
unreachable directory, or a login burst, from taking every slot (NFR-002):

- `directory.sign_in_timeout` (8 s) ends one attempt's directory work in
  total, across every endpoint and JIT connector, with `503
  upstream_unavailable` (`Retry-After: 30`). Without it an endpoint that
  accepts connections and never answers held the attempt for each
  endpoint's connect and operation timeouts in turn, up to the 30 s request
  deadline.
- `directory.max_concurrent_binds` (half the transaction slots: 7 by
  default) bounds the sign-ins waiting on a directory. Beyond that, sign-ins
  that need a directory answer `503 unavailable` with
  `Retry-After: 5` at once (`proudauth_directory_binds_total{outcome="busy"}`),
  so during a full directory outage at least 8 slots stay free for
  `client_credentials`, refresh and local-account sign-ins.
- `security.password.max_concurrent_hashes` (unbounded unless set) bounds
  Argon2id work; beyond it password steps answer `503 unavailable` with
  `Retry-After: 2` at once, before any budget or failure is counted. Today
  the password step hashes inside its database transaction, so the
  transaction slots already bound it and the default leaves it off; once
  hashing leaves the transaction (planned for 0.2.0-alpha.8), size it with
  the hashing cost in [benchmarks.md](benchmarks.md) (about 47 sign-ins per
  second at the default Argon2id parameters on the reference host): raising
  it above the CPU count adds queueing, not throughput.

Clients should retry both 503 codes after `Retry-After`. Raising the bounds
trades directory-outage isolation for burst capacity; raising
`storage.max_conns` raises the default bind bound with it.

## Built-in bounds

| Bound | Value |
| --- | --- |
| Request body | `limits.max_body_bytes` (256 KiB) |
| Request headers | `limits.max_header_bytes` (16 KiB) |
| Token size | `limits.max_token_bytes` (8 KiB) |
| JSON nesting | 32 levels; duplicate members rejected |
| Scopes per request / resources per authorization request | 50 / 5 |
| Group depth / composite role expansion | `limits.max_group_depth` (8) / `limits.max_role_expansion` (64) |
| Decision batch, bulk invitations | `limits.max_batch_size` (100) |
| User import job | 1–1000 users |
| Migration adapters ([migration-adapters.md](migration-adapters.md)) | `identity-cli migrate-from` batches of up to 1000 records and below 192 KiB; `POST /migration-plans` 1–20 export documents within `limits.max_body_bytes` |
| Lifecycle workflows ([workflows.md](../integrations/workflows.md)) | Definitions of 1–5 triggers, 1–20 steps and at most 64 KiB; a schedule firing starts at most 500 runs and at most 20 workflows fire per pass; `workflows.run` claims at most `min(workers.batch_size, 50)` runs per pass, `workers.tenant_batch_share` per realm, 25 transitions per claim; chains stop beyond depth 3 |
| Plugins ([plugins.md](../integrations/plugins.md)) | Manifest 16 KiB, payload 160 KiB, at most 20 hooks, 20 webhook subscriptions and 20 workflows per package, 10 dependencies, 50 declared permissions |
| Audit export job | up to 2000 pages × 500 events |
| Configuration export job | Every active client and business resource, read 500 at a time; importing the document is bounded by `limits.max_body_bytes` |
| Realm data export job | No cap: the whole NDJSON file is built in the worker's memory and stored encrypted in one job row |
| Active client secrets | `limits.client_secrets_max` (3) per client |
| Invitations | `limits.invitation_resends` (5 resends after the first send), shared links `limits.shared_invitation_max_uses` (100) and `limits.shared_invitation_max_ttl` (72 h) |
| Organization metadata, user profile and admin metadata, membership metadata | `limits.metadata_bytes` (16 KiB) each |
| Relationships ([relationship-authorization.md](../integrations/relationship-authorization.md)) | 1–32 relations and 1–64 permissions per resource type; 1–100 tuple writes per request; decisions bounded at depth 6, 64 object reads and 1000 tuples per object; `list-objects` at most 500 per page, 5000 candidates and 1000 checks |
| Dynamic client registration ([dynamic-client-registration.md](../integrations/dynamic-client-registration.md)) | 20 registrations per hour per network, 500 per hour per realm; 1–20 redirect URIs; initial access tokens 1–1000 uses |
| Workload federation ([workload-federation.md](../integrations/workload-federation.md)) | Assertions at most 16 KiB; inline key sets 1–20 keys; 20 claim constraints of 1–50 values; key sets cached 5 minutes per server process |
| Access reviews ([elevation-and-access-reviews.md](../integrations/elevation-and-access-reviews.md)) | At most 10000 assignments per campaign, 1–20 reviewers; the worker closes at most 20 due campaigns per 30-second run |
| SCIM ([scim-provisioning.md](../integrations/scim-provisioning.md)) | 1200 requests per minute per connector; request body `limits.max_body_bytes`, at most 1 MiB; list pages of at most 200; a list without a single indexed `eq` filter examines at most 20,000 resources of the connector (`400 tooMany` beyond); filters of at most 1024 UTF-8 bytes and 64 nodes; 1–100 `PATCH` operations |

## Storage growth

| Table | Growth and cleanup |
| --- | --- |
| `audit_events`, `audit_batches` | One or more rows per security-relevant action and per support-token introspection, plus application activity reported by services (AUD-013). Sealed events past every retention that applies (`privacy.audit_retention_by_category`, otherwise `privacy.audit_retention`, 400 days; longer realm or organization retention) are deleted, except category `emergency` and events under a legal hold; batch rows and the `audit_prunes` / `audit_prune_log` ledgers are kept. Not partitioned ([partitioning policy](#partitioning-policy-db-012)). With `privacy.audit_archive_dir`, the archive directory grows by one file per sealed batch and is never pruned. |
| `hook_invocations` | One row per pre-action hook call (EXT-017); rows older than 7 days are deleted by the retention task. |
| `sessions`, `client_sessions`, `authorization_grants`, `refresh_families`, `refresh_tokens` | Grants that ended (revoked or expired) are deleted `privacy.session_retention` (30 days) later with their refresh families and tokens, codes and opaque tokens, at most 1000 grants per run; ended sessions and client sessions after the same period once no grant references them. Offline grants keep their session rows until they end. |
| `auth_transactions`, `challenges`, codes, opaque tokens, PAR, device codes, DPoP JTIs, client assertion JTIs, rate-limit counters, idempotency records | Deleted after expiry by the worker's retention task; the expiry sweeps use indexes (migration `0045`, DB-011). |
| `outbox_events` | Dispatched rows deleted after 7 days. |
| `known_sign_ins` | At most one row per realm and network (IPv4 /32, IPv6 /64), remembered device, and identifier with its wider network, that completed a sign-in within `security.rate_limits.known_quota_days` (30); older rows are deleted by the worker's retention task through the `last_seen_at` index (migration `0091`). |
| `workload_assertion_jtis` | One row per workload assertion with a `jti` that obtained a token; kept until the assertion's expiry plus 60 s clock skew, then deleted by the worker's retention task (and with the trust) |
| `resource_relationships`, `resource_shares`, `resource_types`, `elevations`, `access_review_items`, `client_registrations`, `client_registration_tokens`, `user_certificate_bindings` | Grow with use and are kept: tuples and types are removed only through their APIs; shares, elevations, review items, registrations, registration tokens and certificate bindings keep every row (revoked or ended ones included; account deletion removes the account's certificate bindings and the tuples naming it) |
| `notification_jobs` | Payloads purged after `delivery.payload_retention`; finished rows deleted after `privacy.history_retention` (180 days). |
| `webhook_deliveries`, `logout_deliveries` | Delivered, dead-lettered and failed rows (payloads included) deleted `privacy.history_retention` after they were created. |
| `consents`, `invitations` | Revoked consents and ended invitations deleted after `privacy.history_retention`. |
| `jobs` | Rows kept; results purged after `privacy.export_retention`. |
| `workflow_runs`, `workflow_step_attempts`, `workflow_approvals` | One run per triggering event (or schedule slot and subject, or manual start) and workflow, one attempt row per step attempt; finished runs with their attempts and approvals deleted `privacy.history_retention` after they ended (there is no index on the finish time for this delete). |
| `workflows`, `workflow_revisions`, `plugins`, `plugin_versions` | Kept; revisions until their workflow is deleted, plugins and versions (with the signed package bytes) without any cleanup. |

Plan PostgreSQL autovacuum, monitoring of table sizes, and your own archival for
the tables without cleanup.

Cleanup and lookup paths have indexes (DB-011): migration `0045` adds expiry
indexes on `authorization_codes`, `opaque_access_tokens` (also live tokens by
subject), `dpop_proof_jtis`, `pushed_authorization_requests`, `device_codes`
and `idempotency_records`, and indexes for dispatched outbox events, ended
sessions, the daily SMS budget and the notification payload purge. Building
them takes a `SHARE` lock on each table (writes wait) until the migration
commits: brief on small tables, but plan the upgrade of a large deployment
for a quiet period ([upgrades.md](upgrades.md#mixed-version-window)).

## Partitioning policy (DB-012)

No table is partitioned today. High-volume data is bounded by deletion
instead: sealed audit events by audit retention (event by event, recorded in
`audit_prunes` and `audit_prune_log`), imported audit records by the same
retention, dispatched outbox events after 7 days, hook invocations after
7 days, ended grants and sessions after `privacy.session_retention`, and
finished deliveries, notification jobs, revoked consents and ended
invitations after `privacy.history_retention`. Job rows have no retention job
and keep growing (above).

A table is partitioned only in a release that ships, with tests, all of the
following for it:

- **retention semantics:** what dropping a partition removes, and proof that it
  never removes events retention must keep (category `emergency`, legal holds,
  batches not yet archived) and that the audit chain still verifies;
- **query semantics:** the audit and delivery queries and indexes keep their
  results and ordering across partitions, including cursor pagination;
- **migration semantics:** an expand-only path from the unpartitioned table, a
  mixed-version window in which older binaries keep working (TEST-061), and a
  backfill that runs in bounded batches.

Until then, do not partition ProudAuth tables yourself: the migrations,
append-only triggers and retention queries assume the current layout.
