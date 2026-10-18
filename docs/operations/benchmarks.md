# Benchmarks

Requirements: NFR-003 (workload suite), NFR-004 (cardinality), NFR-005
(sustained runs), NFR-006 (adversarial resource use), NFR-007 (consistency
stress), NFR-008 (portable results). Code: `cmd/identity-bench`,
`internal/bench`; smoke test `TestBenchSuiteSmoke` (`tests/e2e/bench_test.go`).

`identity-bench` seeds a realm and measures a running deployment **only
through its public APIs**, so you can reproduce a run on your own hardware
and compare results. The project publishes **laptop reference results**:
the initial suite, extended workloads and SMTP/webhook worker profiles,
measured with `make bench-local`
on one laptop that also ran
the load generator and the database ([Reference results](#reference-results),
files in [bench-results/](bench-results/)). They describe that machine and
configuration only; they are not guarantees, targets or sizing advice, and
nothing in [capacity.md](capacity.md) is derived from them.

```text
identity-bench seed --url URL --realm REALM [sizing flags] --out seed.json
identity-bench run  --url URL --seed-file seed.json --scenario NAME [run flags] [--out result.json]
identity-bench list                     # scenario names
```

Exit codes: `2` for usage errors, `1` when seeding or a run fails to start
or complete (including a missing or malformed `--url` and leftover
arguments). A run whose outcomes break an invariant still exits `0`; read
the outcomes ([below](#scenarios-and-pass-criteria)).
An interrupted measurement, scenario-cleanup failure or result encoding/
write failure exits `1`; usable partial data is kept when it can be written.

## Before you start

- **Use a dedicated benchmark realm** (`identity-cli realm-create -name bench`),
  never a production realm. The seed creates hundreds to thousands of objects
  that no command removes, imports users with known passwords and makes the
  adversarial scenarios lock an account and exhaust send budgets.
- **Administrator token.** `seed` (and the `audit-query`, `import`,
  `passkey-assertion`, `scim`, `email-delivery`, `webhook-delivery`,
  `webhook-retry`, `mixed-delivery`, `mixed-email`,
  `mixed-extended`, `mixed`, `otp-guess`, `complex-filter` and
  `complex-group-filter`
  scenarios of `run`) need an admin-audience access token of that realm; the
  administration API accepts it only from an MFA session. Administrator
  tokens live 300 seconds and the built-in administration resource cannot be
  given longer ones, so for anything longer (seeding the `make bench` sizes,
  soak runs) point `PROUDAUTH_BENCH_ADMIN_CREDENTIALS` at the credentials
  file that `identity-cli login --realm bench` stores under the user
  configuration directory (`proudauth/bench-admin.json`): the tool refreshes
  the access token with its refresh token (client `proudauth-cli`) before it
  expires and rewrites the file (mode `0600`) after every refresh, so later
  commands and `identity-cli` go on with the rotated refresh token. Never run
  two commands on one file at the same time: both would present the same
  refresh token, and reuse detection revokes the session. Otherwise
  `PROUDAUTH_BENCH_ADMIN_TOKEN` takes an access token as it is; keep each
  command within its lifetime.
- **The seed file is a secret.** `seed.json` (always written with mode
  `0600`, also over an existing file) holds the client secrets of the
  benchmark clients. Keep it out of version
  control, and delete the benchmark realm's clients when you are done.
- **One load source.** Every simulated user comes from the benchmark host's
  address and signs in through one web client, so per-IP and per-client
  budgets stop the workloads long before the server saturates. For the
  deployment under test raise `security.rate_limits.login_per_ip` (default
  100 per 15 minutes), `login_per_realm` (50000), `login_per_client` (20000
  password attempts per client per 15 minutes; it used to follow
  `token_per_client`, and a soak run of `mixed` signs in tens of thousands of
  times through the one web client), `token_per_client` (600 per minute
  before 0.2.0-alpha.6, 2000 from it) and, from 0.2.0-alpha.6,
  `start_per_network` (300 transaction starts per network per 15 minutes),
  `token_failures_per_network` (300 failed token requests per network per
  minute, read before client authentication; `refresh-race` and
  `metadata-fetch` make token requests that fail on purpose),
  `token_per_network_client` (100 failed grants per network per public
  client per minute), `par_failures_per_network` (300 failed pushed requests
  per network per minute), `par_per_client` (2000 pushed requests per public
  client per minute), `device_per_network` (300 device authorizations per
  network per 15 minutes) and `user_code_failures_per_network` (30 wrong
  device user codes per network per 15 minutes); the wider /24 or /48
  budgets follow at `network_coarse_factor` times each raised value.
  `make bench-local` (`scripts/bench-local.sh`) raises all eleven to
  1000000 (`BENCH_LOGIN_PER_IP`, `BENCH_LOGIN_PER_REALM`,
  `BENCH_LOGIN_PER_CLIENT`, `BENCH_TOKEN_PER_CLIENT`,
  `BENCH_START_PER_NETWORK`, `BENCH_TOKEN_FAILURES_PER_NETWORK`,
  `BENCH_TOKEN_PER_NETWORK_CLIENT`, `BENCH_PAR_FAILURES_PER_NETWORK`,
  `BENCH_PAR_PER_CLIENT`, `BENCH_DEVICE_PER_NETWORK`,
  `BENCH_USER_CODE_FAILURES_PER_NETWORK` override each) and records them in
  `environment.json` under `raised_budgets`. **Publish the values
  you used with the results**. Leave the
  per-identifier, send and lock budgets as configured: the adversarial
  scenarios measure them ([configuration.md](configuration.md#security)), and
  the workloads sign users in in turn so no account reaches its
  per-identifier budget.
- **Concurrency and connections.** Each server process runs at most
  `storage.max_conns` − max(1, `max_conns`/4) transactions at once (15 of the
  default 20 connections; [capacity.md](capacity.md#concurrency-and-pools)).
  Sign-in steps hold their transaction through password hashing and the
  minimum response time, so password sign-ins per process are bounded by
  that number of transactions, not only by CPU.
- Record the deployment: versions, configuration (secrets redacted, for
  example from `identity-cli support-bundle`), instance sizes, PostgreSQL
  settings, network path between the load host and the server.

## Seeding (NFR-004)

`identity-bench seed` builds a deterministic dataset through the
administration API. Every name and password derives from `--seed`, so the
same flags recreate the same data in a fresh realm.

| Flag | Default | Creates |
| --- | --- | --- |
| `--url` | — (required) | Public origin of the deployment, for example `https://id.example.com` |
| `--realm` | `bench` | Realm to seed; it must exist |
| `--users` | `1000` | Accounts, imported in batches of at most 1000 records and 192 KiB with `POST /user-imports` |
| `--orgs` | `50` | Small organizations; every user is a member of one of them |
| `--large` | `0` (half of `--users`) | Members of one large organization |
| `--clients` | `10` | Machine clients, each with its own service principal |
| `--depth` | `3` | Length of a chain of composed organization roles (each level composes the previous one) |
| `--group-members` | `0` | Members of one large group in the large organization (`0`: no group) |
| `--seed` | time-based | Seed for names and passwords; printed when seeding ends. Set it to recreate a dataset |
| `--out` | `seed.json` | Seed file for `run` |

What the seed creates, with names prefixed `b<seed in hex>-` (for example
`b2a-` for seed 42), so different seeds never collide in one realm:

- an API resource `https://<prefix>api.bench.test` (offline verification,
  scopes `bench:read` and `bench:write`) and a permission
  `<prefix>bench.read`;
- the role chain `<prefix>reader-l1` … `<prefix>reader-l<depth>`, the top
  role assigned to every membership;
- machine clients `<prefix>svc-<n>` with `bench:read` for service principals;
- a resource-server client `<prefix>rs`, registered as introspector of the
  benchmark resource and, when the realm has them, given the built-in
  `resource-server` role and the `proudauth:admin` scope for policy checks;
- a first-party confidential web client `<prefix>web` (authorization code and
  refresh, redirect URI `https://app.bench.test/callback`, offline access),
  also granted the built-in account resource for passkey enrollment;
- the large organization `<prefix>large`, the small organizations
  `<prefix>o<n>` and the optional group `<prefix>everyone`;
- users `<prefix>u<n>@bench.test` with verified addresses (the import trusts
  email verification with a recorded reason) and deterministic passwords.

Passwords are imported as salted SHA-256 verifiers, which ProudAuth rehashes
to Argon2id at the first successful sign-in. Seeding is therefore fast, but a
user's first password sign-in also pays for the rehash: run a warm-up pass
over the users, or report first and later sign-ins separately.

Re-running `seed` with the same `--seed` against the same realm fails with
conflicts; use another seed (the default) or a new realm.

## Running

| Flag | Default | Meaning |
| --- | --- | --- |
| `--url` | — (required) | Public origin |
| `--seed-file` | `seed.json` | Output of `seed` |
| `--scenario` | `mixed` | Scenario name (`identity-bench list`) |
| `--concurrency` | `16` | Concurrent workers |
| `--duration` | `60s` | Measured time |
| `--ops` | `0` | Stop after this many operations; the run also stops at `--duration`, whichever comes first |
| `--warmup` | `5s` | Unmeasured operations at the run's concurrency before measuring; adversarial scenarios warm up with discovery requests only, so their budgets are intact when measuring starts (noted in `notes`) |
| `--seed` | `1` | Seed for the operation mix and choices |
| `--soak` | `0` | Total time of a [soak run](#soak-runs-nfr-005); `0` runs once |
| `--window` | `1m` | Window length of a soak run |
| `--out` | stdout | Result file (mode `0644`) |
| `--webhook-listen` | `127.0.0.1:0` | Callback listener for webhook workloads; `0` asks the OS for a free port |
| `--webhook-url` | inferred loopback URL | Reachable callback base when load host and server differ; production requires HTTPS through a caller-managed TLS proxy |
| `--webhook-private` | `false` (automatic for inferred loopback) | Subscription opts into private destinations permitted by the operator's egress policy |

Each scenario first prepares what it needs (tokens, sign-ins), unmeasured.
Operations that the end of the run interrupts are not counted.

## Scenarios and pass criteria

Outcomes are counted per label: `ok` (HTTP status below 400 and, where the
scenario checks one, the expected answer), `http_<status>`,
`transport_error`, and scenario-specific labels such as `inactive`,
`denied`, `setup_<outcome>`, `token_renewal_failed` or
`invariant_violation`. The criteria below are the ones `TestBenchSuiteSmoke`
applies; apply them to every run (`scripts/bench-local.sh` does).

Sign-ins (`password-login`, `refresh-race`, and the one sign-in per worker of
`refresh`) take the users in turn from a random starting point, leaving out
the policy subjects and the attacked account, so no account gets more
password attempts than its per-identifier budget (`login_per_identifier`, 10
per 15 minutes) before every other one had as many; random draws made a few
accounts fail with `429` by chance in long runs. Tokens a scenario prepares
(the machine tokens of `introspection`, the resource server's and the
subjects' tokens of `policy`, administrator tokens from
`PROUDAUTH_BENCH_ADMIN_CREDENTIALS`) are renewed in the background once a
fifth of their lifetime is left, so a run longer than the token lifetime
does not present expired tokens.

### Workloads (NFR-003)

| Scenario | One operation | Pass |
| --- | --- | --- |
| `client-credentials` | Client-credentials token for the benchmark resource, from a random machine client | only `ok` |
| `introspection` | Introspection of a machine token (one per machine client) by the resource-server client (`inactive` if the token is not active) | only `ok` |
| `password-login` | Complete headless sign-in of the next user: start a transaction, identify, password, then redeem the code with PKCE | only `ok` |
| `passkey-assertion` | Complete discoverable passkey sign-in: start, request assertion options, sign/verify an ES256 assertion, redeem the code with PKCE; confirm the token's subject and phishing-resistant assurance | only `ok` |
| `refresh` | Refresh-token rotation; each worker signs in once (`offline_access`) and keeps rotating its own token | only `ok` |
| `policy` | `POST /authorization/check` for one of 8 large-organization users against a random document (`denied` if refused) | only `ok` |
| `audit-query` | `GET /audit-events` with one of four filter sets (none, type, large organization, category) | only `ok` |
| `import` | Dry-run user import of 100 records | only `ok` |
| `scim` | Create, read, ETag-bound display-name patch, delete a user, then confirm `404`; five SCIM requests per completed cycle | only `ok` |
| `email-delivery` | Queue one test email to the administrator's verified address; follow its exact job through the worker until SMTP acceptance | only `ok`; the local receiver also confirms at least as many acceptances as completed email operations, without rejected sessions |
| `webhook-delivery` | Add/remove one isolated member, verify both signed request-correlated callbacks and both exact `delivered` records | only `ok`; two receiver acceptances per completed cycle, zero invalid callbacks |
| `webhook-retry` | Same cycle, returning `503` for each first valid attempt, then `204`; verify unchanged event/body, fresh timestamp and exactly two attempts | only `ok`; two controlled failures and two recoveries per completed cycle, zero invalid callbacks |
| `mixed` | client-credentials 40 %, introspection 25 %, policy 15 %, refresh 10 %, password-login 5 %, audit-query 5 %; outcomes are labelled `<scenario>:<outcome>` | every label ends in `:ok` |
| `mixed-extended` | client-credentials 30 %, introspection 20 %, policy 15 %, refresh 10 %, password-login 5 %, audit-query 5 %, passkey-assertion 5 %, SCIM 5 %, import 5 % | every label ends in `:ok` |
| `mixed-email` | client-credentials 25 %, introspection 15 %, policy 15 %, refresh 10 %, password-login 5 %, audit-query 5 %, passkey-assertion 5 %, SCIM 5 %, import 5 %, email-delivery 10 % | every label ends in `:ok`; receiver criterion above for its email operations |
| `mixed-delivery` | client-credentials 25 %, introspection 15 %, policy 10 %, refresh 10 %, password-login, audit-query, passkey-assertion, SCIM, import, email-delivery, webhook-delivery and webhook-retry 5 % each | every label ends in `:ok`; SMTP and callback receiver criteria above |

The extended scenarios need a freshly generated seed. Enable
`policy.login.passkeys` in the dedicated realm; `make bench-local` does this
when `passkey-assertion`, `mixed-extended`, `mixed-email` or `mixed-delivery`
is selected (including the selected soak). It also sets the
RP ID to `localhost` and origin to `http://localhost:<public port>` (an IP
issuer cannot supply a valid RP ID), preserving other policy values and
recording all three changes. Preparation imports one
additional user per load worker, signs each in with its synthetic password,
and registers a separate ES256 software credential through the ordinary
self-service API. Keys exist only in memory. Each worker owns its monotonic
counter. Measured sign-in uses no identifier/password step; it proves the
discoverable credential and checks the resulting subject and assurance.
This measures the server's complete passkey flow with software UP/UV and
`none` attestation, **not browser or physical authenticator latency**. It
requires a policy permitting password-first enrollment and these passkeys.

`scim` creates an additional organization-bound connector per worker, with
the seed's reader role as its ceiling/default role. Its **1200 requests per
minute per connector budget is unchanged**. Cycle starts are at least 300 ms
apart, limiting the five-request cycles to at most 1000 requests per minute
per connector. Pacing is **included in measured latency**: the result is a
budgeted lifecycle workload, not an unrestricted saturation measurement.
Users have no email; no existing-account adoption or mail delivery is involved.
Deleted resource absence and the patch's returned ID/display name are checked;
unexpected success statuses fail the criteria. Connectors and retired user
records remain in the disposable database until the deployment is removed.

`email-delivery` requires a reachable **SMTP adapter**; preparation checks
it with `POST /notification-settings/check` and refuses a development
mailbox. A measured operation queues a mandatory configuration-test message
through `POST /notification-tests` and polls `GET /notification-jobs`,
including cursor pages, until that exact email job is `accepted`. Failed,
expired, suppressed, missing or malformed jobs fail the criterion. The
**100 ms polling interval is included in latency and API/database load**;
an operation still pending after 30 seconds is `delivery_timeout`. This is
a closed-loop workload on one realm and one administrator destination,
under the worker's unchanged tenant share, batch size and polling interval.
It measures worker/provider acceptance, not mailbox delivery.

When an email workload is selected, `make bench-local` bootstraps through
the development mailbox, then restarts only its own server/worker with
`email.adapter=smtp`, `smtp_host=127.0.0.1`, an OS-allocated free port,
`smtp_tls=none`, no authentication and `from=noreply@bench.test`.
`identity-bench smtp-sink --listen 127.0.0.1:0 --port-file PORTFILE --out counts.json`
is a loopback-only acceptance receiver: it never relays or retains message
contents. It saves accepted-message/byte counts, rejected-session counts and
per-recipient SHA-256 counts. The runner records these separately (including
preparation, warm-up and drain after the duration boundary), checks the
receiver criterion, and removes the listener at exit. Plain-text SMTP is
development-only; this profile does not measure TLS/authentication, remote
relays, retries, provider quotas or inbox delivery. Ordinary identifier/IP
send and lock budgets remain unchanged; the privileged test-message API
sends only to the requesting administrator's verified address.

Webhook preparation imports an additional isolated user and creates an
organization and scoped subscription per worker, through public APIs. Both
normal and retry components have separate fixtures. Subscriptions choose
version 2 and minimal payloads. An unmeasured readiness cycle, with a
15-minute preparation deadline, waits through any full-seed outbox backlog
and proves actual delivery before warm-up. Its elapsed time is recorded in
`notes` and the `before`/`after` observation snapshots (`readiness_cycle_s`);
this does not increase the
measured operation's 30-second timeout or change worker settings.
An independent receiver checks HMAC-SHA256
over the exact raw body, freshness, single headers, realm/organization,
event/member identity and the operation's `correlation_id`. Old events and
work interrupted at warm-up/window boundaries cannot satisfy new cycles.
Operations reconcile an interrupted live membership, then add/remove it,
wait for both callbacks and poll the exact delivery records (`100ms`,
included in latency) until `delivered` with the expected attempts and `204`.
An unfinished operation after 30 seconds is `delivery_timeout`.

The local runner permits only **`127.0.0.1/32`** in
`delivery.egress_allowlist`; subscriptions explicitly opt into that private
destination. The listener uses an OS-allocated loopback port, is shared by
the two components of the mix, and is removed with the subscriptions after
the run (once after a soak, including failed preparation). Users,
organizations and membership history remain in the disposable realm until
the deployment is removed. No signing secret or payload is published.
For remote servers, supply a reachable `--webhook-url` and an explicit
listener; configure the operator's egress/residency policy accordingly.
The tool does not provision the TLS proxy. Plain HTTP callbacks measure the
local development profile, not remote HTTPS capacity or multiple workers.

`webhook-retry` leaves the production-default retry policy unchanged: its
first `503` is retried after 10–12.5 seconds, plus worker scheduling and
other task load. Both membership events are committed before waiting, so
they can retry in parallel. Results include optional `observations` with
before/after cumulative receiver counts and UTC retry/recovery times.
Counters include warm-up and boundary-interrupted cycles; they are not
throughput counts. Subtract snapshots for a window and use completed
operation counts for throughput. The runner checks every window's outcomes
and receiver invariants. Smoke tests accelerate a fake clock; reference
measurements use real time and the configured worker loop.

### Adversarial resource use (NFR-006)

These run under the budgets you configured and measure what abuse costs and
whether the budgets hold. Password and notification scenarios attack the
last seeded user, which the workloads never use. `otp-guess` creates its own
additional isolated account and factor through the public APIs.
`complex-filter` owns one additional connector and its managed users.
`complex-group-filter` owns another connector, its Groups and member Users.
`complex-audit-filter` owns one reporting service and additional application
reports in two seeded organizations.

| Scenario | One operation | Pass |
| --- | --- | --- |
| `unknown-key` | Introspects a well-formed token with a random `kid`, a random signature and a foreign issuer | some `ok` (`200` with `active: false`) and no `invariant_violation` (an active result) |
| `failed-password` | Starts a transaction for the attacked account and submits a wrong password | no `invariant_violation` (a `200`); `http_401` and, once the lock or budgets apply, `http_429` |
| `otp-guess` | Submits a well-formed wrong TOTP on one of eight prepared MFA transactions for one owned account | evaluated attempts return `400 invalid_proof`, then `429 rate_limited` with positive `Retry-After`; only those and independently proven `transaction_limit` outcomes. The local runner's unchanged default budget requires exactly ten `invalid_proof` outcomes and matching database/audit counts |
| `complex-filter` | Alternates two 64-node SCIM User scans with 65-node and 1025-byte expressions, on one connector managing as many additional users as `seed.spec.users` | some `bounded_true`, `bounded_false`, `invalid_filter_nodes` and `invalid_filter_bytes`; only those or SCIM `rate_limited` with positive `Retry-After`. Every valid result proves exact totals, clamped 200-item pages and owned IDs |
| `complex-group-filter` | Alternates 64-node member/name SCIM Group scans, 65-node and 1025-byte expressions; randomly excludes returned members while still filtering on them | some `bounded_true`, `bounded_false`, `invalid_filter_nodes` and `invalid_filter_bytes`; only those or SCIM `rate_limited` with positive `Retry-After`. Exact totals, 200-item pages, owned members/references, schemas and unchanged ETags; excluded members must stay absent |
| `complex-audit-filter` | One audit GET, alternating an eleven-parameter conjunction, two empty literal-prefix searches, invalid network/time, changed-filter cursor and resumed sequence page | all seven outcomes (`compound_match`, `compound_empty`, `literal_prefix_empty`, `invalid_network`, `invalid_time`, `cursor_scope_rejected`, `cursor_page`), with no others. Exact owned/order/provenance checks, 200-item cap despite `limit=1000`; typed `422` field refusals and `400` cursor refusal expose no result page |
| `metadata-fetch` | One workload-federation JWT bearer token request, alternating a valid control and seven upstream failure/egress profiles | all eight outcomes (`valid:ok`, `unknown_key_rejected`, `malformed_rejected`, `oversized_rejected`, `http_failure_rejected`, `redirect_rejected`, `timeout_rejected`, `private_rejected`), no others. Only the control issues a token; refusals are `400 invalid_grant` without tokens. Independent HTTPS receiver contacts every intended source, enforces at least 59.9-second spacing (100 ms clock-sampling tolerance), and observes zero redirect-target/private-destination contacts |
| `oversized-input` | Offers a 2 MiB body to `POST /auth/transactions` (`Content-Length` declared, `Expect: 100-continue`): the server must refuse it from the declared length before any of the body is sent. Sending whole bodies from one host at full concurrency measured the load generator instead (its network buffers filled, most operations ended in transport errors, and on macOS other local networking stalled) | only `http_413` |
| `notification-flood` | `POST /password-resets` for the attacked account | some `http_429`. Responses are `202` for known and unknown accounts alike, so count the messages your mail system received to confirm that the budget limited delivery |

Their warm-up sends only discovery requests and does not consume attack
budgets. Scenario notes declare budget use during fixture preparation;
repeated runs within a budget window can start with budgets already spent.
Password and notification runs show the transition from `401`/`202` to `429`.

`complex-filter` creates 2..20000 owned SCIM users through the public API,
matching the seed's user count (10000 for `make bench-local`). Half have
active memberships and half inactive; neither may disappear from the
connector's list. Fixture requests start at least 65 ms apart to preserve
the unchanged 1200/minute connector budget; this can take over ten minutes
at the default size, outside measurement. No counter is reset or raised.
The measured phase is unpaced at the requested concurrency. Accepted
64-node filters require a scan of the whole managed set, with exactly the
expected active/inactive totals and no foreign/duplicate rows; requests
for 1000 items must clamp to 200. Overflows must be SCIM `400 invalidFilter`
responses, never a successful page. Budget refusals must be SCIM `429`
with retry guidance. Overall latency includes those refusals and cannot
be used as successful-query capacity. It covers Users, not Group filters,
audit filters or the separate 20001-resource scan-overflow profile.

`complex-group-filter` prepares as many additional Groups as
`seed.spec.organizations` (500 at the `make bench` sizes), plus
`seed.spec.large_group_members` owned active SCIM Users (1000 by default).
The first Group contains every owned member; every other Group contains
one. Setup uses public APIs under the unchanged 1200/minute connector
budget, paced at least 65 ms apart, and consumes that budget. Nothing
resets or raises it before measurement. The two valid 64-node expressions
combine member presence with `hit.`/`miss.` name prefixes. They require
exact counts, page clamping, owned data and ETags; member projection must
not change matching or expose excluded members. Aggregate latency includes
budget refusals and is not successful Group-query capacity. Connector
authority and member/Group identities stay private and are cleared at
close; fixtures are removed with the disposable database.

`complex-audit-filter` prepares 16..20000 public application reports,
matching `seed.spec.users` (10000 by default). One isolated service has only
the reporting permission; a second service principal supplies a distinct
subject. Eight interleaved record profiles differ in literal underscore
type, organization, outcome, subject, request, occurrence time or type
family. Serial writes establish independent owned IDs and sequence order.
The measured compound search combines type prefix, organization, actor,
subject, client, request, category, outcome, stored source network and
inclusive/exclusive time bounds. It must return precisely the owned
matching page; a resumed page uses a cursor obtained with `limit=1` during
setup. Setup, synchronous reporter-token renewal and benign discovery
warm-up are unmeasured. No counters are reset. Every operation is one GET;
successful and refused profiles share aggregate latency. Audit filters are
fixed AND parameters, without SCIM's expression-node/scan limit. This is
application-reported evidence, explicitly separate from server events,
and measures neither retention/partitioning nor multi-host capacity.

`metadata-fetch` creates eight isolated machine clients and exact generic
workload trusts through public administration APIs. A fresh
`identity-bench metadata-receiver` binds HTTPS on IPv4 and IPv6 loopback;
the server explicitly trusts its ephemeral CA and permits only
`127.0.0.1/32`. The load generator proves both listeners are reachable.
ES256 assertions have matching issuer/audience/subject, twenty-minute
lifetimes and no required JTI; they renew before expiry. Each profile is
probed during preparation, including introspection of the valid control.
Those contacts spend the unchanged five-minute good-key cache and
one-minute unknown-key/failed-fetch cooldown; nothing resets those budgets.
The oversized reply is otherwise valid JWKS with padding over 1 MiB.
Redirect following and contacts to the live IPv6 key source are forbidden.
The timeout source holds beyond the server's ten-second deadline.
Receiver snapshots contain only counts, response-byte counts and request
start times; assertions, client references, tokens and private keys remain
private. Snapshot drain and client decommissioning occur outside the
measured interval. This controlled, single-process workload profile does
not measure sustained OIDC/Shared Signals or multi-process fetch capacity.
The runner supplies the receiver and CA automatically; standalone runs
use `--metadata-url` and `--metadata-ca` (or the corresponding
`PROUDAUTH_BENCH_METADATA_URL`/`PROUDAUTH_BENCH_METADATA_CA` variables).

`otp-guess` covers SHA1, six-digit, 30-second TOTP. Enrollment, activation
and eight password sign-ins are unmeasured; no password sign-in occurs during
measurement. The enrolled seed lets the tool exclude legitimate codes in
five steps on either side of its clock. This assumes the server/load-host
clocks differ by at most 60 seconds, the client's 30-second request deadline
and ProudAuth's supported skew of at most two steps. A failed transaction
is retired only after an authenticated state read proves
`too_many_failures`; a successful guess, missing retry guidance or other
closure fails the criteria.

The default account budget is ten OTP verifications per 15 minutes,
shared across transactions; each transaction allows five failed proofs.
`make bench-local` preserves both and checks stored failure/audit counts
after measuring. Factor/continuation authority stays in memory and is
cleared on close; fixtures remain in the disposable database until cleanup.
Keep measurement plus setup/warm-up within the prepared transaction TTL
(ten minutes by default); this profile is not a long soak. It does not
cover email/SMS challenge codes or HOTP. For another configured proof budget,
adapt fixture capacity and the expected count explicitly; eight transactions
provide at most forty evaluations before their own limits close them.

The oversized offer's reader cannot send body bytes, even if a server sends
`100 Continue`: that is `invariant_violation_body_requested`. The client
waits for header refusal through its request deadline, avoiding Go's default
one-second continue timeout falling back to an upload (NFR-006).

### Consistency stress (NFR-007)

| Scenario | One operation | Pass |
| --- | --- | --- |
| `refresh-race` | Signs a user in, then redeems its refresh token from 8 goroutines at once | only `ok` (exactly one redemption succeeded and every other attempt was refused or rate-limited). `invariant_violation_<n>_successes` reports more than one success (always a violation), and `invariant_violation_0_successes` that every attempt was answered and rejected. `one_success_with_http_5xx` and `one_success_with_transport_error` mean one attempt succeeded and others failed on the server or in transport: not shown to be refused, and a finding of their own. `inconclusive_rate_limited`, `inconclusive_http_5xx` and `inconclusive_transport_error` (checked in that order) mean no attempt succeeded and some were rate-limited, failed on the server or in transport: the race did not test the invariant, so fix the budgets or the load and run again. A failed sign-in before the race is reported as `setup_<outcome>` |

### Soak runs (NFR-005)

`--soak 2h --window 5m` prepares once, warms up once and then measures
consecutive windows, printing one line per window to standard error. The
result is `{"soak": true, "complete": true, "windows": [<result>, ...]}`,
one result (below) per window, so throughput and p99 can be compared across
the run.
Preparation and the single warm-up are outside the requested measured
budget. The final window is shortened when the total is not a multiple of
the window: `--soak 90s --window 1m` requests 60s and 30s, not two minutes.
Invocation time also includes fixture setup, window reporting and cleanup.

The tool does not cause the events a soak run should cross; schedule them
during the run and note their times: access-token expiry (the resource's
`access_token_ttl_seconds`), a planned signing-key rotation
(`POST /signing-key-rotations`, [keys.md](keys.md#planned-rotation-manual)),
the worker's retention and session clean-up, webhook retries, and database
maintenance (`VACUUM`, `ANALYZE`, backups).

`make bench-local` selects the soak with `BENCH_SOAK_SCENARIO` (`mixed` by
default). `BENCH_SOAK_SCENARIO=mixed-delivery` crosses actual webhook retry
backoff as part of the workload, while retaining the scheduled signing-key
rotation, database maintenance and worker cleanup tasks. It configures
passkeys, SMTP and the loopback egress CIDR even when that scenario is
selected only for the soak. Receiver snapshots record retry/recovery UTC
times for each window; this does not replace a longer sustained run.

## Results (NFR-008)

### Run completeness (NFR-005, NFR-008)

New results include `complete`: `true` when the requested measurement
finishes and scenario cleanup succeeds; `false` when it is interrupted or
cleanup fails. This is a lifecycle flag. Apply the outcome and receiver
criteria separately: a completed measurement can still contain violations.
A soak also has the flag on its envelope; completed earlier windows survive
interruption, and the partial final window is marked `complete: false`.
If cancellation occurs before measuring starts, there is no result to save.
Encoding/write errors and the run's original error are both reported.

The CLI returns exit status `1` for these failures even when it preserves
JSON. `make bench-local` requires a zero exit, `complete: true`, nonempty
soak windows, completed individual windows and the scenario criteria; it
labels any retained partial data before recording a failure. Use the current
benchmark binary when supplying `BENCH_BIN`. `complete` is an additive
field in format version `1`; published historical results retain the schema
and build identity of their recorded tool, and are not rewritten.

Regressions cover interruption after a full window, independent cleanup,
single-run and soak cleanup errors, result encoding/write errors, shortened
last windows and warm-up exclusion. A separate child-process test sends
`SIGTERM` to the actual CLI after its first window, verifies exit `1` and
reads the retained JSON. Its controlled HTTP fixture is a correctness test,
not a capacity measurement.

```json
{
  "tool": "identity-bench",
  "format_version": "1",
  "scenario": "client-credentials",
  "complete": true,
  "target": "https://id.example.com",
  "started_at": "2026-10-11T09:00:05Z",
  "duration_s": 60.0,
  "concurrency": 32,
  "seed": 1,
  "operations": 51234,
  "outcomes": {"ok": 51234},
  "throughput_per_s": 853.9,
  "latency_ms": {"mean": 37.2, "p50": 33.1, "p90": 52.4, "p99": 95.7, "p999": 160.2, "max": 233.0},
  "histogram": [{"le_ms": 32.768, "count": 20711}, {"le_ms": 34.816, "count": 7310}],
  "environment": {"go": "go1.27.1", "os": "linux", "arch": "amd64", "cpus": 16, "host": "bench-1"},
  "notes": ["weights: ..."]
}
```

The numbers above only illustrate the format.

| Member | Meaning |
| --- | --- |
| `tool`, `format_version` | `identity-bench` and the result format version (`1`) |
| `scenario`, `target`, `started_at` | What ran, against which origin, when measuring started (UTC) |
| `complete` | Measurement and scenario cleanup completed; does not replace outcome/receiver pass criteria |
| `duration_s`, `concurrency`, `seed` | Measured time, workers and the run seed |
| `operations`, `outcomes` | Operations measured, and the count per outcome label (errors included) |
| `throughput_per_s` | `operations` / `duration_s` |
| `latency_ms` | Mean, p50, p90, p99, p99.9 and maximum, in milliseconds |
| `histogram` | Log-linear buckets (16 per power of two, about 4 % wide) as upper bound `le_ms` and `count`; empty buckets are left out |
| `environment` | Go version, OS, architecture, CPU count and host name of the **load generator**, not of the server |
| `notes` | Scenario remarks, for example the `mixed` weights |
| `observations` | Optional `before`/`after` snapshots of callback receiver metadata, cumulative counters and retry/recovery times; subtract counts for a window, and use `operations` for throughput |

Publish, with every result: the seed file's `spec` member (sizing and seed,
without the secrets), the exact commands, the rate-limit and other
configuration changes, the server and database environment, and what you
found to be the bottleneck.

## Reproducing with `make bench`

```sh
identity-cli realm-create -name bench            # operator channel; then bootstrap an administrator
export BENCH_URL=https://id.example.com BENCH_REALM=bench
export PROUDAUTH_BENCH_ADMIN_TOKEN=...           # admin-audience token from an MFA session
make bench                                       # BENCH_SEED=<n> to recreate a dataset
```

`make bench` refuses to start (exit `2`) without `BENCH_URL` and either
`PROUDAUTH_BENCH_ADMIN_CREDENTIALS` or `PROUDAUTH_BENCH_ADMIN_TOKEN`.
Use the credentials file for seeding these sizes and for longer runs.
It builds `bin/identity-bench`, seeds 10000
users, 500 small organizations, a 5000-member large organization, 20 machine
clients and a 1000-member group into `bench-seed.json` (seed `BENCH_SEED`,
by default the current time, so reruns create fresh objects), and then runs
`client-credentials`, `introspection`, `password-login`, `refresh`,
`policy`, `audit-query` and `mixed` for 60 seconds each at concurrency 32,
writing `bench-<scenario>.json`. It stops at the first failing command. Run
`import`, the adversarial scenarios and `refresh-race` separately.

`TestBenchSuiteSmoke` runs the seed and every scenario briefly against the
in-process test server on each `go test ./tests/e2e` run with a database. It
checks that the scenarios work and meet the criteria above; it measures
nothing.

## Reference results

The 2026-10-11 laptop run uses the `make bench` cardinalities (NFR-004):
10000 users, 500 small organizations, a 5000-member large organization,
20 machine clients, a 1000-member group and three composed role levels,
dataset seed `1`. Seeding through public APIs took 175 seconds. The seed
file and administrator credentials are private temporary files and are
deleted with the deployment; only the seed's specification is published.

The source/build hashes below identify the measured checkout. The later
2026-10-11 SDK sender-verification and server DPoP header/method fixes are
covered by correctness tests and are not a new performance measurement.
The subsequent Group deletion/link-repair, expired-job attempt fencing,
directory failover deletion and shared passwordless proof-budget fixes
are also correctness-only changes; the published native-process refresh
results predate them.

### Environment and configuration (NFR-008)

- **Host:** Mac16,8, Apple M4 Pro, 12 CPUs (8 performance + 4 efficiency),
  25769803776 bytes RAM (24 GiB), AC power. macOS 27.0.1 (26A434), Darwin
  27.0.0; Go 1.27.1, `darwin/arm64`. Recorded with
  `sysctl -n hw.model machdep.cpu.brand_string hw.ncpu hw.memsize`,
  `sw_vers` and `go version`.
- **Database:** the local `postgres:18` image, PostgreSQL 18.6
  (Debian 18.6-1.pgdg13+2, Linux aarch64), in a dedicated container on
  Docker Desktop 29.7.2 (VM: 12 CPUs, 25161293824 bytes memory). Data on a
  dedicated Docker volume; host port 55591 bound to loopback.
  `shared_buffers=2GB`, `max_connections=200`,
  `effective_cache_size=6GB`, `work_mem=16MB`,
  `maintenance_work_mem=512MB`, `max_wal_size=4GB`,
  `checkpoint_timeout=15min`, `shared_preload_libraries=pg_stat_statements`;
  `fsync`, `synchronous_commit`, `full_page_writes` and autovacuum stay on.
  Exact settings are recorded with the results.
- **ProudAuth:** one host `identity-server` (loopback ports 18591/18592)
  and one host `identity-worker` (metrics port 18593), version `dev`, built
  from this checkout with cached dependencies only:
  `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -mod=readonly -buildvcs=false -trimpath`.
  No commit is used; the source digest is `75d05b2cd35a1cae` (first 16 hex
  characters of SHA-256 over the sorted per-file source hashes), with full
  binary SHA-256 hashes and Go build information in the results.
  The corrected oversized rerun has source digest `8b6f14c4e430790e`;
  server, worker and CLI binary hashes match, only `identity-bench` differs.
- **Configuration:** development mode for the email sink and loopback HTTP,
  insecure development cookies, signing-key prepublication shortened to
  `2m` for the soak event. Other production defaults remain, including
  RS256/RSA-3072, Argon2id 64 MiB/3 passes/2 threads, minimum auth response
  `250ms`, 20 database connections per process (15 concurrent transactions),
  `10s` statement timeout, `256KiB` request bodies, `300s` access tokens,
  worker concurrency 4, batch size 100 and `1s` polling. The generated YAML
  and effective configuration are published with secret values excluded.
- **Raised load-source budgets:** `security.rate_limits.login_per_ip`,
  `login_per_realm` and `login_per_client` are each **1000000 per 15m**;
  `token_per_client` is **1000000 per minute**. Identifier attempts remain
  10 per 15m, lock after 10 failures for 15m, sends 5 per identifier and
  50 per IP per hour, cooldown 30s. All other budgets remain at defaults.
- **Load path:** `identity-bench` runs on the same host over plain HTTP on
  loopback, with the server reaching PostgreSQL through Docker's published
  loopback port. No Go tests run during measurements. Existing containers
  are left untouched; the runner removes only its own processes and volume.

### Commands

From the checkout, the full run was invoked with:

```sh
BENCH_PREFIX=pa-bench-reference-20261011 \
BENCH_OUT="$PWD/bench-results/2026-10-11-reference" \
BENCH_HOST_LABEL=laptop make bench-local VERSION=dev
```

Use a fresh `BENCH_OUT` for a rerun: the runner refuses existing result
directories and existing containers or volumes with its chosen prefix.
`scripts/bench-local.sh` records the setup and cleanup sequence; it requires
the PostgreSQL image, Go toolchain and modules to be present locally and
disables downloads. Its measurement commands are:

```sh
# $BIN and $WORK are private temporary directories created by the runner.
export PROUDAUTH_BENCH_ADMIN_CREDENTIALS="$WORK/admin-credentials.json"
export PROUDAUTH_BENCH_ADMIN_TOKEN="$(jq -r .access_token "$WORK/admin-credentials.json")"
"$BIN/identity-bench" seed --url http://127.0.0.1:18591 --realm bench \
  --users 10000 --orgs 500 --large 5000 --clients 20 --group-members 1000 \
  --seed 1 --out "$WORK/seed.json"
for s in client-credentials introspection password-login refresh policy audit-query mixed import unknown-key failed-password oversized-input notification-flood refresh-race; do
  "$BIN/identity-bench" run --url http://127.0.0.1:18591 \
    --seed-file "$WORK/seed.json" --scenario "$s" --concurrency 32 \
    --warmup 5s --duration 60s --out "$OUT/$s.json"
done
"$BIN/identity-bench" run --url http://127.0.0.1:18591 \
  --seed-file "$WORK/seed.json" --scenario mixed --concurrency 32 \
  --warmup 5s --soak 10m --window 1m --out "$OUT/soak-mixed.json"
```

The runner reloads the administrator token from the rotated credentials
before each command. The run seed defaults to `1`, role depth to `3`.
It applies the pass criteria above to each scenario and each soak window,
and exits nonzero if any fail. CPU accounting and top statements include
unmeasured preparation and warm-up; operation counts and latency do not.

### Scenario results (NFR-003, NFR-006, NFR-007)

All runs below use 60 measured seconds, concurrency 32 and 5 seconds of
warm-up. Latencies are milliseconds, estimated from the histogram's upper
bucket bounds. Throughput counts completed operations, including expected
adversarial refusals. Raw JSON, histograms, metadata and the initial failing
result are in [2026-10-11-laptop/](bench-results/2026-10-11-laptop/).
For `mixed`, the table combines the six success labels; their individual
counts remain in JSON.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| client-credentials | 1036.6 | 30.72 | 38.91 | 47.10 | `ok`: 62199 | Pass |
| introspection | 2038.1 | 15.87 | 21.50 | 36.86 | `ok`: 122284 | Pass |
| password-login | 47.1 | 688.13 | 851.97 | 1179.65 | `ok`: 2828 | Pass |
| refresh | 815.2 | 38.91 | 55.30 | 73.73 | `ok`: 48911 | Pass |
| policy | 736.9 | 43.01 | 57.34 | 102.40 | `ok`: 44212 | Pass |
| audit-query | 751.8 | 43.01 | 77.82 | 110.59 | `ok`: 45108 | Pass |
| mixed | 553.8 | 34.82 | 409.60 | 458.75 | all six `:ok`: 33229 | Pass |
| import | 1219.4 | 25.60 | 43.01 | 86.02 | `ok`: 73170 | Pass |
| unknown-key | 2370.5 | 12.29 | 34.82 | 51.20 | `ok` (inactive): 142233 | Pass |
| failed-password | 825.4 | 38.91 | 69.63 | 188.42 | `http_401`: 10; `http_429`: 20; `identify_http_429`: 49493 | Pass |
| oversized-input, initial | 19694.3 | 1.22 | 3.84 | 73.73 | `http_413`: 1180006; `transport_error`: 1662 | **Fail** |
| oversized-input, corrected rerun | 22833.8 | 1.28 | 3.33 | 69.63 | `http_413`: 1370040 | Pass |
| notification-flood | 126.9 | 253.82 | 253.82 | 253.82 | `ok`: 3; `http_429`: 7613; delivered mail: 3 | Pass |
| refresh-race | 30.9 | 1015.81 | 1376.26 | 1593.67 | `ok`: 1856 (one winner each) | Pass |

All 13 scenarios have a passing selected result in
[`reference-summary.json`](bench-results/2026-10-11-laptop/reference-summary.json).
The original `summary.json` retains the oversized-input failure. Its client
could send the offered body after the one-second continue timeout: a
regression test reproduced a 1.5 MiB upload while waiting for a delayed 413.
The tool now cannot send body bytes and detects a request for them. No
ProudAuth server defect was found. The corrected run used a fresh deployment
with the same full dataset and configuration, without the first run's
accumulated audit/job history; its artifacts and exact build are in
[`oversized-rerun/`](bench-results/2026-10-11-laptop/oversized-rerun/).

```sh
BENCH_PREFIX=pa-bench-refusal-20261011 \
BENCH_OUT="$PWD/bench-results/2026-10-11-refusal" \
BENCH_HOST_LABEL=laptop BENCH_SCENARIOS=oversized-input BENCH_SOAK=0 \
  make bench-local VERSION=dev
```

The first setup attempt also exposed a tool defect: 1000-user imports
exceeded the default 256 KiB request limit. Seeding now caps encoded batches
at 192 KiB and 1000 records; `TestSeedImportsFitDefaultBodyLimit` covers the
full cardinalities and default limit. After the tool fixes,
`go test ./internal/bench ./cmd/identity-bench -count=1` passed, as did
`TestBenchSuiteSmoke` and `TestTokenIssuanceBeyondConnectionPool` against a
separate disposable PostgreSQL 18 database. Tests ran outside measurement.

`password-login` measured first sign-ins, including SHA-256-to-Argon2id
rehashing: 3059 password verifiers were Argon2id afterwards (including the
administrator and warm-up), 6942 remained imported SHA-256. The later mixed
runs include first and subsequent sign-ins; these are not separate steady
Argon2id login measurements. `import` measures accepted dry-run submissions,
not completed jobs. The database ended at 2232948415 bytes (2.08 GiB), with
approximately 79797 job rows (1.35 GiB including indexes/TOAST) and 431062
audit rows (408 MiB). Later scenarios and the soak inherit that accumulated
history and worker load; the seed does not start with a synthetic audit log.

These runs use local passwords only: no directory connector was configured,
so they say nothing about directory outages. A password step holds a
database transaction slot for its whole Argon2id check and, for
directory-sourced accounts, its LDAP search and bind. Since 0.2.0-alpha.5
`directory.sign_in_timeout` and `directory.max_concurrent_binds` bound the
directory work and answer `503 unavailable` at once when full;
`security.password.max_concurrent_hashes` can bound the hashing the same way
(off by default, since the transaction slots bound it today). An unreachable directory therefore holds at most half
the transaction slots, for at most 8 s per attempt, instead of letting
token issuance and refresh stall. The behaviour is covered by
`TestDirectorySignInDeadline`, not measured here
([capacity.md](capacity.md#directory-outages)).

### Short soak (NFR-005)

Ten consecutive one-minute windows of `mixed` completed 282941 operations;
every window passed, with only the six `:ok` labels. This is a short soak,
not the proposed multi-hour sustained test. Full per-label counts and
histograms are in `soak-mixed.json`.

| Window | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 1 | 482.5 | 40.96 | 442.37 | 491.52 | 28950; all six `:ok` | Pass |
| 2 | 476.7 | 43.01 | 458.75 | 507.90 | 28601; all six `:ok` | Pass |
| 3 | 460.6 | 45.06 | 458.75 | 524.29 | 27635; all six `:ok` | Pass |
| 4 | 472.6 | 43.01 | 458.75 | 507.90 | 28359; all six `:ok` | Pass |
| 5 | 477.9 | 43.01 | 442.37 | 491.52 | 28675; all six `:ok` | Pass |
| 6 | 479.5 | 40.96 | 458.75 | 507.90 | 28773; all six `:ok` | Pass |
| 7 | 467.8 | 43.01 | 458.75 | 524.29 | 28067; all six `:ok` | Pass |
| 8 | 437.8 | 47.10 | 475.14 | 557.06 | 26269; all six `:ok` | Pass |
| 9 | 477.9 | 43.01 | 442.37 | 491.52 | 28673; all six `:ok` | Pass |
| 10 | 482.3 | 40.96 | 442.37 | 507.90 | 28939; all six `:ok` | Pass |

The event log records UTC times: rotation requested at 09:48:49, new RS256
key active at 09:51:07; `VACUUM (ANALYZE)` at 09:52:29–09:52:32;
`pg_dump -Fc` to `/dev/null` at 09:53:32–09:54:37. The prepared tokens'
300-second lifetimes were crossed with renewal. Worker metrics recorded
two successful `retention.cleanup` runs, 20 `lifecycle.expiry` runs and
10 `keys.lifecycle` runs. Window 8 overlapped the backup and dipped to
438 operations/s, then recovered. Webhook delivery tasks ran, but no
webhooks or retries were injected. The results include `soak-events.tsv`
and `soak-worker-runs.tsv`; they do not establish delivery-worker capacity.

### Bottlenecks and limits of these numbers

Password login used 437 server CPU seconds in 65 seconds including warm-up,
with the default hashing cost, response padding and 15 transaction slots.
Audit querying was database-heavy: 468 PostgreSQL CPU seconds, with the
two most expensive filtered audit reads averaging 18.269 and 15.733 ms.
Docker VM/proxy CPU was substantial throughout (for example 407.53 CPU
seconds for client credentials, versus 83.67 inside PostgreSQL); database
round trips and virtualization therefore matter on this load path. These
are resource observations, not a CPU profile isolating one saturation point.

**One laptop, with the database, server, worker and load generator on the
same machine. These numbers are not guarantees, performance targets or
sizing advice.** They include loopback networking and Docker Desktop,
development email delivery, an evolving audit/job history and scheduled
maintenance. They do not characterize TLS, remote networks, real delivery,
multiple replicas, longer soaks or different instance sizes. Measure your
own deployment and workload; the proposed targets in docs/plan.md §32 have
not been validated by this run.

### Extended workload results (NFR-003, NFR-008)

The 2026-10-11 extended run adds passkey and SCIM coverage to the same
laptop, Go 1.27.1, PostgreSQL 18.6 image/settings and production-default
hashing/pools described above. It starts with a **fresh disposable database**
and the full seed-1 cardinalities, seeded in 169 seconds. Server, worker,
CLI and tool are built from source digest `84ae7e50370a9570`, version `dev`,
no commit; exact binary hashes and build information are included. This
build includes the DPoP correctness fixes; it is not a remeasurement of
the original workloads. There is no additional soak in this run.

The same four load-source budgets remain at 1000000: login/IP, realm and
client per 15 minutes, token/client per minute. **SCIM stays at 1200
requests/minute per connector.** The dedicated realm enables passkeys,
explicitly sets RP ID `localhost` and allowed origin
`http://localhost:18591`; other policy values are preserved. These changes
are recorded in `realm-benchmark-policy.json`. API/load traffic still uses
`http://127.0.0.1:18591`. Each passkey preparation adds 32 isolated users
and in-memory credentials; each SCIM preparation adds 32 connectors in
the large organization. The extended mix prepares another set of each.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| passkey-assertion | 176.2 | 180.22 | 221.18 | 237.57 | `ok`: 10570 | Pass |
| scim | 105.8 | 311.30 | 458.75 | 475.14 | `ok`: 6351 completed five-request cycles | Pass |
| mixed-extended | 409.4 | 45.06 | 442.37 | 475.14 | all nine `:ok`: 24562 | Pass |

Every row measures 60 seconds at concurrency 32 after five seconds of
warm-up. Full outcomes, histograms, environment/configuration, CPU time,
statement statistics, seed specification and artifact hashes are in
[2026-10-11-laptop-extended/](bench-results/2026-10-11-laptop-extended/).
The passkey flow includes software signing, server verification and PKCE
exchange, **not device/browser latency**. SCIM latency includes its 300 ms
cycle pacing; approximately 106 cycles/s is the aggregate budgeted rate
of 32 workers, **not a saturation ceiling**. Import outcomes in the mix
mean accepted dry-run submissions, not completed jobs. All nine mix
components actually ran; their individual counts remain in JSON.

```sh
BENCH_PREFIX=pa-bench-extended-20261011 \
BENCH_OUT="$PWD/docs/operations/bench-results/2026-10-11-laptop-extended" \
BENCH_HOST_LABEL=laptop \
BENCH_SCENARIOS='passkey-assertion scim mixed-extended' BENCH_SOAK=0 \
  make bench-local VERSION=dev
```

The initial attempt's passkey preparation stopped before measurement:
the IP issuer did not provide a valid WebAuthn RP ID. It is retained under
`initial-attempt/`; SCIM passed there with 6352 cycles (105.9/s), matching
the corrected run's 6351. The runner now configures localhost explicitly,
and `TestBenchSuiteSmoke` uses that same profile. All four binary hashes
match across these two attempts. Unit tests also guard against leaking
registration-only `credProps` outputs into assertion responses and against
polling missing/failed import-job resources. The complete smoke and
connection-pool regressions, benchmark unit/race tests and vet checks passed
using a separate disposable PostgreSQL deployment before measurement.
Both attempts compared artifacts against their private credentials before
cleanup; no seed file, connector token or private key is published.

**The cohosted-laptop caveats above apply in full: these results are not
guarantees, proposed-target validation or sizing advice.**

### SMTP worker results (NFR-003, NFR-008)

The 2026-10-11 SMTP run starts with another fresh PostgreSQL 18.6 database,
the full seed-1 cardinalities (165 seconds to seed), and the same Mac16,8
M4 Pro/24 GiB, macOS 27.0.1, Go 1.27.1, Docker Desktop topology, PostgreSQL
settings, hashing and pool defaults recorded above. Build version is `dev`,
no commit; source digest is `073a00abfb40351c`. Exact binary hashes, effective
configuration, environment and commands are in
[2026-10-11-laptop-email/](bench-results/2026-10-11-laptop-email/).

After first-administrator verification in the development mailbox, the
runner restarts its server/worker with the actual SMTP adapter:
`127.0.0.1:60854`, `smtp_tls=none`, no authentication,
`from=noreply@bench.test`. The same-host receiver only accepts and counts
mail; it neither persists message contents nor relays mail. Development
mode is needed for loopback HTTP and plain-text SMTP. The same four
load-source budgets are 1000000 (login/IP, realm and client per 15m,
token/client per minute); identifier/send/lock budgets stay at defaults.
Worker concurrency 4, batch 100, tenant share 25 and polling 1s are unchanged.
Passkeys use the recorded localhost RP/origin; SCIM's 1200/minute connector
budget is unchanged. Load generator, database, server, worker and SMTP
receiver all share this laptop. This run adds no soak or retry injection.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| email-delivery | 14.0 | 2031.62 | 5701.59 | 5701.59 | `ok`: 843 SMTP-accepted jobs | Pass |
| email-delivery, fresh repeat | 15.3 | 2031.62 | 4456.45 | 4508.49 | `ok`: 918 SMTP-accepted jobs | Pass |
| mixed-email | 170.4 | 19.46 | 2359.30 | 3145.73 | all ten `:ok`: 10224, including 994 emails | Pass |
| notification-flood | 125.3 | 262.14 | 277.84 | 277.84 | 3 `ok`, 7517 `http_429`; exactly 3 messages accepted by SMTP | Pass |

Each row measures 60 seconds at concurrency 32 after five seconds of
warm-up. All ten mix components actually ran. The independent receiver
counts 982 messages over the standalone preparation/warm-up/measurement/
drain interval and 1156 more over the mixed interval (including 32 passkey
enrollment notices); these are **not** measured throughput counts. No
receiver session was rejected. `smtp-observations.json` ties the counts to
each result; full outcomes and histograms remain in the scenario JSON.

The independent repeat is in `repeat-email/`: another full seed-1 database,
seeded in 170 seconds, with identical binary hashes, PostgreSQL settings,
budgets and worker defaults. Its SMTP receiver uses free port 63352 and
counts 1082 messages including warm-up/drain, with no rejected sessions.
The repeat selects only `email-delivery`, so it leaves passkeys disabled;
there is no passkey workload in either standalone measurement. The two
samples show 14.0–15.3 completed emails/s, the same p50 and a varying tail;
they do not establish long-term stability or a performance guarantee.

The standalone latency includes waiting for the serial worker tasks, its
one-realm tenant share and 100 ms API polling. In 65 seconds including
warm-up, the tool made 19497 job-list reads and 20481 role-expansion reads;
the former returned 3.61 million rows. It used 20.81 CPU seconds, versus
32.53 for the server, 27.01 for PostgreSQL, 1.02 for the worker and 0.23 for
the SMTP sink. The result describes the complete enqueue/observe workload
under these schedules and API costs, **not the SMTP transport's saturation
ceiling or a profile isolating one bottleneck**. Email-only and mixed
throughput should not be compared as equivalent operations.

```sh
BENCH_PREFIX=pa-bench-email-20261011 \
BENCH_OUT="$PWD/docs/operations/bench-results/2026-10-11-laptop-email" \
BENCH_HOST_LABEL=laptop \
BENCH_SCENARIOS='email-delivery mixed-email notification-flood' BENCH_SOAK=0 \
  make bench-local VERSION=dev
```

The repeat uses `BENCH_PREFIX=pa-bench-email-repeat-20261011`,
`BENCH_OUT="$PWD/docs/operations/bench-results/2026-10-11-laptop-email/repeat-email"`
and `BENCH_SCENARIOS=email-delivery`, with the other flags above unchanged.

The initial attempt stopped before seeding or measurement because the
runner omitted the SMTP sender address; the server correctly rejected that
configuration. Public evidence is retained under `initial-attempt/`, with
the same four binary hashes. The runner now supplies the sender, and the
smoke checks validate the full SMTP configuration. Benchmark unit/race
tests, all-scenario smoke, connection-pool regressions and vet passed
against a separate disposable database outside measurements. Soak fixture
preparation also now receives concurrency before it reserves credentials
or connectors; its regression checks reuse across windows. These are tool/
runner fixes, not changes to ProudAuth's delivery implementation.

**One laptop; numbers are not guarantees, proposed-target validation or
sizing advice.** This is one realm's closed-loop SMTP acceptance baseline.
It does not cover TLS/authentication, remote mail providers, retries,
mailbox arrival, multiple delivery workers/tenants or webhook capacity.
The runner checked published artifacts against its private credentials
before removing the database, processes, seed file and temporary secrets.

### Webhook worker results (NFR-003, NFR-005, NFR-008)

The corrected 2026-10-11 run uses another fresh PostgreSQL 18.6 database
and the complete seed-1 cardinalities (166 seconds to seed). The environment
is the same Mac16,8, Apple M4 Pro, 12 CPUs (8 performance/4 efficiency),
24 GiB, macOS 27.0.1 (26A434), Darwin 27.0.0, Go 1.27.1 and Docker Desktop
29.7.2 topology recorded above: one host server, one host worker, the load
generator and receivers on that laptop, with PostgreSQL on its dedicated
Docker volume and loopback port 55591. PostgreSQL settings are unchanged:
2 GB shared buffers, 200 connections, 6 GB effective cache, 16 MB work
memory, 512 MB maintenance memory, 4 GB maximum WAL, 15-minute checkpoints,
`pg_stat_statements`, durable commits and autovacuum enabled. Build version
is `dev`, no commit; source digest is `429a0fc8380c103d`. Full binary hashes,
Go build information, settings, redacted configuration, seed specification,
CPU accounting and statement statistics are in
[2026-10-11-laptop-webhooks/](bench-results/2026-10-11-laptop-webhooks/).

Development mode permits loopback HTTP and plain-text SMTP; the first admin
verifies email and enrolls TOTP before the runner restarts its server/worker
with the real SMTP adapter (`127.0.0.1:55778`, no TLS/authentication,
`from=noreply@bench.test`). Webhooks allow only `127.0.0.1/32` in the operator
egress policy, and each subscription opts into that private destination.
The normal receiver uses port 55808, retry 55944 and the 60-second mix 56052;
the OS allocates a separate receiver for the soak. Both callback profiles
prepare 32 isolated users, organizations and scoped subscriptions; the mix
prepares a set for each component. Subscriptions use version 2/minimal
payloads; keys exist only in memory. Passkeys retain the explicit localhost
RP/origin, software UP/UV and no attestation. SCIM remains at 1200 requests/
minute per connector, with its 300 ms cycle pacing included in latency.

All four load-source budgets remain 1000000 (login/IP, realm and client per
15 minutes, token/client per minute). Identifier/send/lock budgets and the
production defaults listed above remain unchanged, including RSA-3072,
Argon2id 64 MiB/3 passes/2 threads, 250 ms response padding, 20 connections
per process, 300-second access tokens, worker concurrency 4, batch 100,
tenant share 25 and polling 1s. Signing-key prepublication is 2m for the
scheduled rotation. Retry backoff is the unchanged 10–12.5 seconds after
the controlled first-attempt `503`, plus worker scheduling and task load.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| webhook-delivery | 20.8 | 1835.01 | 2097.15 | 2106.20 | `ok`: 1248 two-event cycles | Pass |
| webhook-retry | 2.1 | 14155.78 | 16079.92 | 16079.92 | `ok`: 128 two-event retry/recovery cycles | Pass |
| mixed-delivery | 40.9 | 12.29 | 15204.35 | 15728.64 | all twelve `:ok`: 2455; 110 normal cycles, 94 retry cycles, 117 emails | Pass |

Each row measures 60 seconds at concurrency 32 after five seconds of warm-up.
The receiver's measured snapshot differences confirm 2496 normal acceptances,
256 retry recoveries following 320 controlled `503`s, and in the mix 220
normal acceptances and 188 retry recoveries following 238 controlled `503`s.
Every callback profile has **zero invalid callbacks**. Only authenticated
events correlated to the current cycle can satisfy it; abandoned/old events
are counted separately. The larger first-attempt counts include unfinished
cycles, not additional successful operations. The SMTP receiver confirms
176 messages over the mix's preparation/warm-up/measurement/drain interval,
including enrollment notices, against 117 completed measured emails; no
SMTP session was rejected. These counters are not throughput counts.

The initial run, source digest `ad5dd5981535e25a`, started while seed outbox
events were still pending. All three 60-second profiles failed: 32 normal
and 32 retry `delivery_timeout`s; the mix had 15 normal and 17 retry
timeouts among 560 operations. Its ten-window soak failed in windows 1–3,
then passed in 4–10 after the queue drained. These results remain under
`initial-attempt/` with their original **FAIL** verdicts. This exposed a
tool preparation defect, rather than a signature or egress failure.

The corrected tool proves one unmeasured, public-API readiness cycle before
warm-up. On the fresh corrected database this took **344.370 seconds** for
the first normal profile; a diagnostic sample during preparation recorded
18162 pending events, oldest age 183.461s. Later readiness cycles took
12.365s for retries and 1.152s/12.369s for the mix's normal/retry components.
Server, worker and CLI binary hashes match both attempts; only the tool
changes. Measured timeouts remain 30 seconds and worker budgets remain
unchanged. Thus the passing reference assumes the seed backlog has been
crossed; **the initial burst's delivery delay is still an operational
finding**, not removed from the evidence. CPU/top-statement accounting
includes this untimed wait, setup and warm-up, not just the measured minute.

A separate ProudAuth defect found while building the workload is fixed:
empty organization-member pages returned `items: null` instead of the
required array. `TestEmptyMembershipPagesAreArrays` failed before the fix
and now checks both empty states and active/default filters. The complete
database-backed Go suite passed with the race detector after the server
fix. Benchmark unit/race tests and the complete 21-scenario smoke passed
again after the readiness change, outside measurement. The receiver checks
signatures independently of the server implementation, and regressions
cover wrong identity/signatures, changed/stale retries, exact delivered
records, cleanup, delayed setup callbacks and completed mixed operations
at a duration boundary. Full validation notes accompany the artifacts.

#### Delivery soak (NFR-005)

Ten consecutive one-minute windows of `mixed-delivery` complete **24687
operations**; every window passes with all twelve `:ok` components and the
receiver invariants. The same fixtures/listener are reused across windows
(port 56319; normal/retry readiness took 1.148s/11.248s). This is a short
ten-minute run, not multi-hour stability evidence. Full counts, histograms,
snapshots and UTC timestamps are in `soak-mixed-delivery.json`.

| Window | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 1 | 41.3 | 12.29 | 14680.06 | 16050.11 | 2479; all twelve `:ok` | Pass |
| 2 | 40.8 | 12.29 | 15204.35 | 15956.46 | 2451; all twelve `:ok` | Pass |
| 3 | 41.2 | 13.31 | 14155.78 | 15942.41 | 2474; all twelve `:ok` | Pass |
| 4 | 41.7 | 13.82 | 14155.78 | 16024.21 | 2500; all twelve `:ok` | Pass |
| 5 | 40.4 | 13.31 | 14680.06 | 16008.51 | 2424; all twelve `:ok` | Pass |
| 6 | 41.1 | 13.82 | 14680.06 | 16037.26 | 2469; all twelve `:ok` | Pass |
| 7 | 40.4 | 13.31 | 15204.35 | 16252.93 | 2423; all twelve `:ok` | Pass |
| 8 | 41.3 | 12.80 | 15204.35 | 16218.13 | 2479; all twelve `:ok` | Pass |
| 9 | 41.4 | 14.34 | 15204.35 | 16018.86 | 2484; all twelve `:ok` | Pass |
| 10 | 41.7 | 12.80 | 15204.35 | 16046.76 | 2504; all twelve `:ok` | Pass |

The measured windows include 1091 normal cycles, 969 retry cycles and 1192
SMTP-accepted emails. Callback snapshots increase by 2204 normal
acceptances and 1989 retry recoveries following 2428 controlled `503`s;
invalid callbacks stay zero. Counts include work interrupted at window
boundaries and cannot be substituted for completed cycles. The SMTP sink
adds 1270 acceptances including setup/warm-up/drain, with zero rejected
sessions. Retry timestamps span preparation through measurement: first
controlled rejection at 14:30:41.310 UTC, last at 14:40:56.302, last observed
recovery at 14:40:56.298. These are actual worker retries under real time.

Prepared tokens cross their 300-second lifetime with renewal. The event
log records rotation requested at 14:32:22 UTC and the new RS256 key active
at 14:35:09; `VACUUM (ANALYZE)` at 14:36:02–14:36:03 and `pg_dump -Fc` to
`/dev/null` at 14:37:03–14:37:04. Worker metrics record two successful
`retention.cleanup` runs, 21 `lifecycle.expiry` and ten `keys.lifecycle`
runs. This proves the tasks ran; it does not prove removal of session rows
under the unchanged 30-day session retention. Backup/restore correctness
has its separate [published drill evidence](backup-restore.md).

```sh
BENCH_PREFIX=pa-bench-webhooks-ready-20261011 \
BENCH_OUT="$PWD/docs/operations/bench-results/2026-10-11-laptop-webhooks" \
BENCH_HOST_LABEL=laptop \
BENCH_SCENARIOS='webhook-delivery webhook-retry mixed-delivery' \
BENCH_SOAK=10m BENCH_SOAK_WINDOW=1m BENCH_SOAK_SCENARIO=mixed-delivery \
  make bench-local VERSION=dev
```

The initial command uses prefix `pa-bench-webhooks-20261011` and the same
flags on its recorded build. Its files were retained under `initial-attempt/`
after the runner removed its resources. A rerun needs a fresh output path.

**One laptop; these are not guarantees, proposed-target validation or sizing
advice.** This closed-loop profile includes callback verification, exact
delivery-state polling (100 ms), a serial worker loop, real retry waits,
Docker/loopback networking and an evolving audit/job history. Two-event
cycles, retry cycles and weighted mixed operations are different units;
their throughput is not directly comparable.
Retry waits occupy the closed-loop load workers, so mix throughput depends
strongly on the chosen weights rather than measuring pure API saturation.
It does not establish remote
HTTPS capacity, real inbox delivery, multi-worker/tenant saturation or
multi-hour stability.

### TOTP guessing results (NFR-006, NFR-008)

The additional 2026-10-11 run publishes
[raw results and companion evidence](bench-results/2026-10-11-laptop-otp/)
for `otp-guess`. It uses the full seed-1 cardinalities above (10000 users,
500 small organizations, a 5000-member large organization, 20 machine
clients, 1000 group members, role depth three); public-API seeding took
173 seconds. The scenario adds one isolated account with a self-enrolled
TOTP factor and eight MFA transactions. No seed file, factor seed, guesses,
recovery codes or continuation authority are published.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `otp-guess` | 1464.1 | 22.53 | 27.65 | 40.96 | 10 `invalid_proof`; 87838 `rate_limited`; no accepted code or other outcome | Pass |

The result is complete: **87848 operations** in 60.000296417 seconds,
concurrency 32, five-second benign-discovery warm-up, measured from
15:57:25.254 to 15:58:25.254 UTC. Every rate-limit response provided a
positive integer `Retry-After`. The independent post-run
[budget evidence](bench-results/2026-10-11-laptop-otp/otp-budget-evidence.json)
confirms ten evaluated proofs, ten `mfa.totp.failed` audit events, eight
pending transactions, no failed transaction and a maximum of two failures
on one transaction. The account limit applies across the transactions;
this particular concurrent measurement did not reach any transaction's
five-failure limit. A separate sequential database-backed regression
exhausts and retires two transactions at five failures each, then observes
the same account budget on the remaining six.

The exact environment is recorded in `environment.json`: Mac16,8, Apple
M4 Pro, 12 CPUs (8 performance/4 efficiency), 25769803776 bytes RAM
(24 GiB), AC power; macOS 27.0.1 (26A434), Darwin 27.0.0; Go 1.27.1
`darwin/arm64`. It was collected with
`sysctl -n hw.model machdep.cpu.brand_string hw.ncpu hw.memsize`, `sw_vers`
and `go version`. Docker Desktop 29.7.2 provides a 12-CPU VM with
25161293824 bytes memory. Local PostgreSQL 18.6 (Debian
18.6-1.pgdg13+2, Linux aarch64) uses image ID
`sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722`,
one dedicated volume/container, loopback port 55591.
Settings are in `postgres/settings.tsv`: 2 GiB shared buffers, 200
connections, 6 GiB effective cache, 16 MiB work memory, 512 MiB maintenance
memory, 4 GiB maximum WAL, 15-minute checkpoints,
`shared_preload_libraries=pg_stat_statements`; autovacuum, fsync,
full-page writes and synchronous commit are on, WAL level is `replica`.

One host server and worker, and the load generator, share that machine.
ProudAuth is an untagged `dev` checkout with no Git commit; source digest
`856906a70f82cbc3`, exact binary hashes in `binary-sha256.txt`, Go/module
build details in `build-info.txt`. Binaries were built offline from cached
modules with `-mod=readonly -buildvcs=false -trimpath`. The redacted input
and effective configuration are published. Development mode supplies
plain loopback HTTP and the initial administrator's verification mailbox;
Argon2id remains 64 MiB/three passes/two threads with 250 ms password
response padding, RSA-3072/RS256 signing, 20 database connections per
process, and the default worker concurrency four/batch 100/tenant share
25/one-second polling. No Go tests ran during measurement.

Only the documented source budgets are raised: `login_per_ip`,
`login_per_realm`, `login_per_client` are 1000000 per 15 minutes;
`token_per_client` is 1000000 per minute. `otp_verify_per_account=10` per
15 minutes, the five-failure transaction bound, `totp_skew_steps=1`,
ten-minute transaction TTL and `login_per_identifier=10` per 15 minutes
remain unchanged. Preparation, warm-up and cleanup are outside the
measurement; all nine preparation password sign-ins remain within the
identifier budget. No soak or maintenance/expiry event was scheduled for
this one-minute profile.

```sh
BENCH_PREFIX=pa-bench-otp-20261011 \
BENCH_OUT="$PWD/docs/operations/bench-results/2026-10-11-laptop-otp" \
BENCH_HOST_LABEL=laptop BENCH_SCENARIOS=otp-guess BENCH_SOAK=0 \
  make bench-local VERSION=dev
```

`validation.txt` records unit/race, all 22 smoke scenarios, connection-pool
and concurrent/sequential OTP regression checks. No ProudAuth defect was
found in this profile. The runner's pass criteria additionally require
matching stored counts and remove all its own resources. The artifact
manifest preserves the raw evidence; earlier published runs remain intact.

**One laptop; these are not guarantees or sizing advice.** Most operations
are refusals after the account budget is spent, so this is abuse cost under
an enforced budget, not successful MFA capacity. Thirty-two load workers
contend on eight transaction rows; recorded top-statement time is dominated
by their transaction lookup/lock, not the short counter upsert. CPU totals
include setup/warm-up as well as measurement. This covers TOTP
SHA1/six-digit/30-second guessing on one realm and server, with the clock
assumptions above, not email/SMS codes, HOTP, multi-node attacks, a long
soak or the full NFR-006 requirement.

### SCIM filter results (NFR-004, NFR-006, NFR-008)

The corrected full-cardinality `complex-filter` measurement **passes**.
Its [raw result and companion files](bench-results/2026-10-11-laptop-filters/)
are published alongside the initial **failed** measurement. The
[raw result and sealed companion files](bench-results/2026-10-11-laptop-filters/initial-attempt/)
of that failure remain unchanged. Both use the full seed-1 dataset:
10000 users, 500 small organizations,
a 5000-member large organization, 20 machine clients, 1000 group members,
role depth three. Seeding took 176 seconds initially and 171 seconds on
the corrected run. The profile additionally
creates one connector managing 10000 new users, half active/half suspended;
public-API preparation took 659.472 seconds initially and 659.473 seconds
on the corrected run, outside measurement. Fixture
requests start at least 65 ms apart under the unchanged 1200/minute
connector budget; preparation consumes it and no counter is reset.

| Attempt/scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Initial `complex-filter` | 1.6 | 25.60 | 30001.23 | 30001.23 | 31 `invalid_filter_nodes`; 31 `invalid_filter_bytes`; 32 `transport_error`; no completed bounded query | Fail |
| Corrected `complex-filter` | 2223.4 | 7.17 | 63.49 | 1114.11 | 338 `bounded_true`; 339 `bounded_false`; 351 `invalid_filter_nodes`; 351 `invalid_filter_bytes`; 132026 `rate_limited`; no other outcome | Pass |

The initial completed 60.000550709-second lifecycle, concurrency 32, benign
warm-up five seconds, records 94 observations from 16:41:34.220 to
16:42:34.220 UTC. Fast overflow refusals explain the low median; they do
not prove valid-filter capacity. Valid 64-node scans hit the client's
30-second deadline, while server diagnostics report cancellation/500.
Recorded statement accounting (including fixture preparation) contains
504776 user loads, 504763 identifier reads, 504748 membership reads and
494792 mapping reads. Four round trips per candidate made concurrent
10000-user scans miss their deadline.

The corrected completed measurement lasts 60.001546834 seconds, from
17:24:03.119 to 17:25:03.120 UTC, with the same concurrency and warm-up.
All 133405 observations satisfy the criterion: both valid profiles prove
exact 5000-resource totals and owned, state-correct pages clamped from
1000 to 200; both overflow profiles are refused as SCIM `invalidFilter`;
connector-budget refusals are SCIM `429` errors with positive `Retry-After`.
There are 677 successful searches, 702 overflow refusals and 132026 budget
refusals, with no transport error or other outcome. The combined throughput
and percentiles mostly describe budget refusals (98.97% of observations).
The 677 successful searches average 11.3/s in this unpaced, budgeted mix;
neither number is independently measured successful-query saturation
capacity. Per-outcome latency distributions are not recorded.

Both measured checkouts are untagged `dev`, with no Git commit. Source
digests are `2a75087a131ed72d` initially and `7c4ba2cf48b6c9d3` after the
fix; binary hashes/build details are preserved in each directory. The exact
environment/configuration is recorded for both: Mac16,8, Apple M4 Pro,
12 CPUs (8 performance/4 efficiency), 25769803776 bytes RAM (24 GiB),
AC power; macOS 27.0.1 (26A434), Darwin 27.0.0; Go 1.27.1 `darwin/arm64`.
Docker Desktop 29.7.2 supplies 12 CPUs/25161293824 bytes to local
PostgreSQL 18.6 (Debian 18.6-1.pgdg13+2, aarch64), image ID
`sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722`.
Settings are 2 GiB shared buffers, 200 connections, 6 GiB effective cache,
16 MiB work memory, 512 MiB maintenance memory, 4 GiB maximum WAL,
15-minute checkpoints and `pg_stat_statements`; durability and autovacuum
remain on. One loopback PostgreSQL container/volume, server/worker and
load generator share the laptop. The redacted input/effective configuration
preserves production hashing/signing/pool/worker defaults; development mode
serves loopback HTTP and the administrator verification mailbox. Only
login/IP, realm and client budgets (1000000/15m) and token/client
(1000000/minute) are raised; the SCIM budget remains 1200/minute.
No Go tests ran during either measurement; no soak/event was scheduled.

The ProudAuth read path is now fixed with scoped batch reads and retention
of only the requested page. A real-query tracer regression failed before
the fix at 33 queries for eight users and 257 for 64; it now observes five
at both sizes and compares list data/ETags with single-resource reads.
Realm/identifier-order and read-failure regressions also pass. These are
correctness/structural checks alongside the separate corrected capacity
measurement. All Go package race checks pass after refreshing the evidence
matrix (the first full command failed solely on stale traceability; the
complete contract package then passed). The corrected statement snapshot,
including fixture preparation, records 691 batched user reads and 685
identifier reads, rather than half a million individual reads. CPU totals
also include fixture preparation and warm-up: 724.48 wall seconds, 194.42
server CPU seconds, 10.16 worker, 164.37 PostgreSQL, 700.07 Docker VM/proxy
and 47.95 load generator. They are not measured-phase CPU rates.
The initial failure remains labelled Fail, with its own source and manifest.

Reproduce on this checkout with a fresh output directory and resource
prefix (cached Go modules and local `postgres:18` required):

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PREFIX=pa-bench-filter-reference \
  BENCH_OUT="$PWD/bench-results-private/filters" \
  BENCH_HOST_LABEL=laptop BENCH_SCENARIOS=complex-filter BENCH_SOAK=0 \
  make bench-local VERSION=dev
```

The corrected run used prefix `pa-bench-filters-batched-20261011` and a
fresh directory before publication. The recorded build
digests identify the different implementations; the command on the current
checkout reproduces the corrected profile, not the historical defect.

**One laptop; no guarantee or sizing advice.** Aggregate observations mix
valid searches, overflow rejection and any connector-budget refusal.
This User profile does not cover Group/audit filters, the separate
20001-resource scan overflow, metadata fetching, multi-node consistency
or the full NFR-006 requirement. All run resources/private credentials
were removed by the cleanup trap; no connector tokens, seed file or
managed identity IDs are published.

### Independent server-process results (NFR-003, NFR-007, NFR-008)

The 2026-10-11 native-process run measures refresh through **three separate
host `identity-server` processes**, one worker and a loopback Go
`identity-bench replica-proxy`. Each server independently loads its keyring
and has its own pool and caches; all share one PostgreSQL database. The
proxy assigns each HTTP request round-robin, including requests on reused
connections, with no sticky sessions or cross-backend failover/replay.
It records counts only, without paths, headers or bodies.

Each profile ran for 60 seconds at concurrency 32 after five seconds of
warm-up. These are completed-operation latencies in milliseconds, including
proxy overhead; `Pass` applies to the scenario's documented correctness
criteria, not a performance target.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Verdict |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `refresh` | 941.1 | 34.82 | 51.20 | 139.26 | 56465 `ok` | Pass |
| `refresh-race` | 46.5 | 688.13 | 884.74 | 1015.81 | 2793 `ok` | Pass |

`refresh` serially rotates each worker's token. A `refresh-race` operation
includes password sign-in with `bench:read offline_access` and eight
simultaneous redemptions of one refresh token, requiring exactly one
success. At concurrency 32 this can create 256 simultaneous redemption
requests; the reported latency includes the whole operation. Offline
reuse revokes its family and grant while retaining the SSO session.

**Environment and configuration:** Mac16,8, Apple M4 Pro, 12 CPUs (8
performance + 4 efficiency), 25769803776 bytes RAM, AC power; macOS 27.0.1
(26A434), Darwin 27.0.0, Go 1.27.1 (`darwin/arm64`). The measurements use
Docker Desktop 29.7.2 and the existing local `postgres:18` image, PostgreSQL
18.6 (Debian 18.6-1.pgdg13+2, aarch64), image ID
`sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722`.
The dedicated database used `shared_buffers=2GB`, `max_connections=200`,
`effective_cache_size=6GB`, `work_mem=16MB`, `maintenance_work_mem=512MB`,
`max_wal_size=4GB`, `checkpoint_timeout=15min`, and `pg_stat_statements`;
fsync, synchronous commit, full-page writes and autovacuum stayed on.

ProudAuth build `dev` was built offline from this checkout with
`-mod=readonly -buildvcs=false -trimpath`; there is no Git commit. The
Go/SQL source digest is `f8e88eee8d5e7114`; binary hashes, build information
and runner/source-file hashes accompany the results. Production defaults
include RSA-3072, Argon2id 64 MiB/three passes, a 250 ms minimum authentication
response and pools of 20 connections per process. Development mode enables
loopback HTTP, insecure development cookies and the bootstrap email sink;
the root key and database credentials remain private file references.
`keys.prepublish_period=2m` is recorded, but this run performs no rotation
or soak. Login budgets per IP, realm and client are each 1000000 per 15
minutes; the token budget per client is 1000000 per minute. Identifier,
proof and notification budgets remain unchanged.

The seed is the standard 10000 users, 500 organizations, a 5000-member
large organization, 20 machine clients, 1000 group members and role depth
three, seed `1`, in realm `bench`; seeding took 178 seconds. The private
seed, admin tokens and key files are excluded. PostgreSQL used host port
57834; proxy 57835; servers' public/internal ports 57843/57836,
57844/57845 and 57846/57847; worker metrics 57837. Exact process IDs,
redacted node configurations and effective defaults are published.

Routing counts, including preparation/warm-up, show 20264/20264/20263
requests assigned to the servers during `refresh` and 41213/41213/41214
during `refresh-race`. There were zero proxy transport errors or response
aborts. Client cancellations at run boundaries were recorded separately
(64 and 74 respectively); cancelled proxy handlers can record `502` and
are not completed measured operations. Final shutdown drained all handlers.
Independent post-run SQL found 2797 new offline families, 2794 compromised
families, exactly 2794 reuse audit rows and outbox events, maximum token
generation/count two, and zero lineage or compromise violations. Three
families remained active; preparation and incomplete boundary operations
explain why these counts exceed the 2793 completed measured races. The
SQL verification runs after the timing/CPU snapshots.

CPU snapshots cover each entire 65-second CLI invocation, including
preparation/warm-up: aggregate server CPU 233.27/486.06 seconds, worker
0.98/0.84, PostgreSQL 132.98/84.38, load generator 6.62/20.29 and the
benchmark proxy 12.70/22.71, for refresh/race respectively. Docker VM/backend
CPU overlaps database CPU and must not be added to it. Per-node CPU and
PostgreSQL statement statistics are included.

[Results, validation and configuration](bench-results/2026-10-11-laptop-replicas/summary.json),
[routing](bench-results/2026-10-11-laptop-replicas/replica-routing.json),
[independent database checks](bench-results/2026-10-11-laptop-replicas/refresh-race-database.json)
and [artifact hashes](bench-results/2026-10-11-laptop-replicas/artifact-sha256.json)
are published. Reproduce with cached Go modules and local `postgres:18`:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PREFIX=pa-bench-replicas-reference \
  BENCH_PG_PORT=57834 BENCH_HTTP_PORT=57835 \
  BENCH_INTERNAL_PORT=57836 BENCH_WORKER_PORT=57837 \
  BENCH_OUT="$PWD/bench-results-private/replicas" \
  BENCH_HOST_LABEL=laptop-replicas make bench-replicas VERSION=dev
```

The runner requires unused ports and a fresh output directory, chooses
additional backend ports and removes its processes, container, volume and
private work directory with a trap. No dependencies were downloaded and
no Go tests ran during measurements.

**One laptop; no guarantees or sizing advice.** Load generation, the
proxy, database, three servers and worker share the machine. These closed-loop
profiles demonstrate this native-process topology only; older single-server
results used different builds and are not a scaling comparison. They do
not demonstrate multi-machine/network-fault/failover behavior, sustained
multi-hour load or the other replica consistency cases.

### SCIM Group filter results (NFR-004, NFR-006, NFR-008)

The 2026-10-12 `complex-group-filter` run uses the full documented seed:
10000 users, 500 organizations, a 5000-member large organization,
20 clients, a 1000-member seeded Group, role depth three, seed `1`.
Public-API seeding took **171 seconds**. The scenario then creates an
isolated connector, **500 additional Groups** and **1000 additional
managed Users**; its first Group has 1000 members and the others one
each (**1499 additional member links**). This adds 1000 organization
members to the seed's large organization. Unmeasured scenario preparation
took **101.496 seconds** under the unchanged connector budget; it was
followed by a 5-second warm-up and a **60-second**, concurrency-**32** run.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Result |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `complex-group-filter` | 3705.3 | 6.91 | 29.70 | 69.63 | 475 exact `bounded_true`; 476 exact `bounded_false`; 475 65-node and 475 1025-byte refusals; 220420 budget refusals; no transport or invariant failures | Pass |

All **222321** operations completed. Valid results prove exact totals,
clamped 200-item pages, owned data, member values/references, schemas and
unchanged ETags. Excluding returned members still evaluates member-dependent
filters and keeps the excluded field absent. Every `429` is a SCIM error
with positive `Retry-After`. **99.14% of operations are budget refusals**;
these aggregate throughput and latency values are not successful-query
capacity. The connector remains at 1200/minute; no counter was reset.

Environment: Mac16,8, Apple M4 Pro, 12 CPUs (8 performance + 4 efficiency),
25769803776 bytes RAM (24 GiB), AC power; macOS 27.0.1 (26A434), Darwin
27.0.0; Go 1.27.1 `darwin/arm64`; Docker 29.7.2; cached `postgres:18`,
PostgreSQL 18.6 on aarch64. Settings: `shared_buffers=2GB`,
`max_connections=200`, `work_mem=16MB`, `maintenance_work_mem=512MB`,
`effective_cache_size=6GB`, fsync/full-page writes/synchronous commit on,
`wal_level=replica`, `checkpoint_timeout=15min`, `max_wal_size=4GB`,
`pg_stat_statements` loaded. One host server and worker use the benchmark
configuration described above, including 64 MiB/three-pass Argon2,
RSA-3072, the 250 ms password timing floor and development mode for the
local bootstrap/email sink. Login IP/realm/client budgets and token-client
budget are each 1000000 in their documented windows; proof, send and
connector budgets stay unchanged. Loopback ports: PostgreSQL 56511,
public 56512, internal 56513, worker 56514. Source digest
`cb89a7606b47c21d`, development build, no Git commit; cached modules only.
The load generator and Docker database share the server's laptop.

[Raw results](bench-results/2026-10-12-laptop-groups/complex-group-filter.json),
[summary](bench-results/2026-10-12-laptop-groups/summary.json),
[environment](bench-results/2026-10-12-laptop-groups/environment.json),
[PostgreSQL settings](bench-results/2026-10-12-laptop-groups/postgres/settings.tsv)
and [redacted configuration](bench-results/2026-10-12-laptop-groups/proudauth-config.yaml)
record the build, settings, budgets and fixture observations. The
[artifact hashes](bench-results/2026-10-12-laptop-groups/artifact-sha256.json)
cover all 13 measured-build/configuration/result files. The
[query-work/boundary evidence](consistency-tests.md#scim-group-query-work-and-scan-boundaries--2026-10-12)
reproduces and fixes per-Group database reads, checks projection/ETags and
verifies Users/Groups at 20,000/20,001 resources. Those boundary fixtures
are correctness checks, not sustained scan-overflow measurements.

To reproduce with unused ports and a fresh output directory:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PREFIX=pa-bench-group-reference \
  BENCH_PG_PORT=56511 BENCH_HTTP_PORT=56512 \
  BENCH_INTERNAL_PORT=56513 BENCH_WORKER_PORT=56514 \
  BENCH_SCENARIOS=complex-group-filter BENCH_SOAK=0 \
  BENCH_OUT="$PWD/bench-results-private/groups" \
  BENCH_HOST_LABEL=laptop make bench-local
```

The runner removed its server, worker, container, volume and private
credential/seed directory with a trap. No Go tests ran during measurement
and nothing was downloaded. Completion bookkeeping in the external shell
wrapper used a reserved zsh variable and exited with an error after the
runner finished; saved JSON, the runner's passing summary and independently
verified cleanup establish the result. **One laptop; numbers are not
guarantees or sizing advice.** Larger Group populations, longer sustained
load, real directory counterparts and multiple machines remain open.
The compound audit baseline below adds separate evidence.

### Compound audit filter results (NFR-004, NFR-006, NFR-008)

The **2026-10-12** run adds **10000 public application reports** to the
full `make bench` seed (10000 users, 500 organizations, a 5000-member
organization, 20 clients and a 1000-member Group). Eight interleaved
record profiles leave **1250 exact compound matches**. PostgreSQL's final
table statistics estimate **36616 audit rows** (an estimate, not an exact
history count). The seed took **168 seconds** and additional report setup
**29.727 seconds**, followed by 5-second benign warm-up. Measurement is
**60 seconds**, concurrency **32**, with no Go tests running alongside it.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Result |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `complex-audit-filter` | 1274.0 | 25.60 | 34.82 | 45.06 | 10920 exact compound pages; 10919 exact resumed pages; 10921 empty compound and 10920 literal-percent empty pages; 10921 each invalid-network, invalid-time and changed-filter cursor refusals; no transport/invariant errors | Pass |

All **76443 operations** completed. Nonempty pages retain precisely the
owned event order, realm/organization, actor/subject, reporting service,
request, timestamp, ordinal and application provenance; `limit=1000`
clamps to 200. Input refusals are typed `422` field errors; changed-filter
cursors get `400 invalid_request`; errors expose no results. Aggregate
latency includes successful, empty and refused profiles and is not a
successful nonempty-page throughput guarantee. CPU totals in the summary
include setup/warm-up as well as measurement.

Environment: Mac16,8 / Apple M4 Pro, 12 CPUs (8 performance + 4 efficiency),
25769803776 bytes RAM (24 GiB), AC power; macOS 27.0.1 (26A434), Darwin
27.0.0; Go 1.27.1 `darwin/arm64`; Docker 29.7.2, its VM at 12 CPUs and
25161293824 bytes. Cached `postgres:18`, PostgreSQL 18.6 aarch64, image
`sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722`.
PostgreSQL settings: shared buffers 2 GB, max connections 200, work memory
16 MB, maintenance memory 512 MB, effective cache 6 GB, fsync/full-page
writes/synchronous commit on, WAL replica, checkpoint 15 minutes,
maximum WAL 4 GB, `pg_stat_statements` loaded. One host server and worker
retain the reference defaults (64 MiB/three-pass Argon2, RSA-3072, 250 ms
password floor), with development mode for localhost bootstrap/email sink.
Login IP/realm/client and token-client budgets are each 1000000 in their
documented windows; proof/send/connector budgets are unchanged. Ports:
PostgreSQL 58312, public 58313, internal 58314, worker 58315. Development
source digest **`33f1e749e5cbf702`**, no Git commit, cached modules only.
The load generator, server, worker and Docker database share one laptop.

[Raw result](bench-results/2026-10-12-laptop-audit-filter/complex-audit-filter.json),
[summary](bench-results/2026-10-12-laptop-audit-filter/summary.json),
[environment](bench-results/2026-10-12-laptop-audit-filter/environment.json),
[PostgreSQL settings](bench-results/2026-10-12-laptop-audit-filter/postgres/settings.tsv),
[redacted configuration](bench-results/2026-10-12-laptop-audit-filter/proudauth-config.yaml)
and [artifact hashes](bench-results/2026-10-12-laptop-audit-filter/artifact-sha256.json)
record all 13 measured-build/configuration/result artifacts.
[Correctness evidence](consistency-tests.md#audit-prefixes-compound-pages-and-cursors--2026-10-12)
preserves the prefix/cursor failures, correction and scoped race checks;
the earlier full-module result retains its own build.

To reproduce with unused ports and a fresh output directory:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PREFIX=pa-bench-audit-reference \
  BENCH_PG_PORT=58312 BENCH_HTTP_PORT=58313 \
  BENCH_INTERNAL_PORT=58314 BENCH_WORKER_PORT=58315 \
  BENCH_SCENARIOS=complex-audit-filter BENCH_SOAK=0 \
  BENCH_OUT="$PWD/bench-results-private/audit" \
  BENCH_HOST_LABEL=laptop make bench-local
```

The runner exits successfully and its trap removes the server, worker,
own PostgreSQL container/volume and private credential/seed directory.
No secrets or seed file are published; nothing was downloaded. **One
laptop: these numbers are not guarantees or sizing advice.** This is a
fixed compound-parameter profile, not a general expression language.
Million-event histories, retention/partition performance, longer soaks,
multiple machines/tenants and upstream metadata abuse remain unmeasured.

### Controlled metadata-fetch results (NFR-006, NFR-008)

On **2026-10-13 local time** (started `2026-10-12T21:28:55.132870Z`),
`metadata-fetch` completed **157079 operations in 60.000764 seconds** at
concurrency **32**, after a five-second benign warm-up and the full
documented seed: 10000 users, 500 organizations, a 5000-member organization,
20 machine clients and a 1000-member Group. Seeding took 169 seconds;
eight additional isolated workload clients were prepared through public APIs.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcome | Result |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `metadata-fetch` | 2617.9 | 9.216 | 27.648 | 34.816 | all eight required profiles; no unexpected completed outcomes | **pass** |

The independent receiver retained preparation and measurement contacts
without resets. Counts crossed one retry boundary; all five ordinary
retry spacings were **60.0027–60.0036 seconds**, and the timeout source's
spacing was **70.0027 seconds** (ten-second deadline plus cooldown).

| Profile | Completed outcomes | Upstream contacts, before → after | Result |
| --- | ---: | ---: | --- |
| Valid grant (`valid:ok`) | 19639 | 1 → 1 | pass: active control; five-minute key cache |
| Unknown key | 19639 | 1 → 2 | pass: `invalid_grant`, bounded refresh |
| Malformed JWKS | 19639 | 1 → 2 | pass: `invalid_grant`, bounded retries |
| Otherwise valid JWKS over 1 MiB | 19639 | 1 → 2 | pass: `invalid_grant`; 2097154 total source bytes |
| HTTP 503 | 19639 | 1 → 2 | pass: `invalid_grant`, bounded retries |
| Redirect | 19639 | 1 → 2 | pass: `invalid_grant`; redirect target received **zero** requests |
| Timeout | 19607 | 1 → 2 | pass: `invalid_grant`, deadline and cooldown |
| Live denied IPv6 destination | 19638 | 0 → 0 | pass: `invalid_grant`; reachable source received **zero** key requests |

**Environment:** Mac16,8 / Apple M4 Pro, 12 CPUs (8 performance + 4
efficiency), 25769803776 bytes RAM, AC power; macOS 27.0.1 (26A434),
Darwin 27.0.0; Go 1.27.1 `darwin/arm64`; Docker 29.7.2 with a 12-CPU,
25161293824-byte VM. Cached PostgreSQL **18.6** runs on the same laptop:
`shared_buffers=2GB`, `max_connections=200`, `work_mem=16MB`,
`maintenance_work_mem=512MB`, `effective_cache_size=6GB`, `max_wal_size=4GB`,
`checkpoint_timeout=15min`, `fsync`, `synchronous_commit`,
`full_page_writes` and autovacuum on, `wal_level=replica`,
`shared_preload_libraries=pg_stat_statements`. Complete settings are linked below.
Server, worker, load generator and HTTPS receiver run on the host. Checkout
source digest **`a9d95f06c64af14e`**, no Git commit; cached modules only.
Development mode supplies loopback HTTP/bootstrap email verification;
Argon2id remains 64 MiB/three passes, RSA signing keys 3072 bits and the
minimum authentication response 250 ms. Login per-IP/realm/client and token
per-client budgets are each **1000000**; metadata budgets stay unchanged.
The source uses HTTPS with an explicit ephemeral CA, verified certificates,
IPv4 egress allowance `127.0.0.1/32`, denied live `::1/128`, a 1 MiB
response cap, five-minute good-key cache and one-minute retry cooldown.

[Raw result](bench-results/2026-10-13-laptop-metadata/metadata-fetch.json),
[receiver counts](bench-results/2026-10-13-laptop-metadata/metadata-receiver.json),
[summary/CPU](bench-results/2026-10-13-laptop-metadata/summary.json),
[environment](bench-results/2026-10-13-laptop-metadata/environment.json),
[PostgreSQL settings](bench-results/2026-10-13-laptop-metadata/postgres/settings.tsv),
[redacted configuration](bench-results/2026-10-13-laptop-metadata/proudauth-config.yaml),
[scoped verification](bench-results/2026-10-13-laptop-metadata/verification.json)
and [artifact hashes](bench-results/2026-10-13-laptop-metadata/artifact-sha256.json)
identify the measured build. All 26 live smoke scenarios and all 36 contract
checks pass; unit/race, vet, formatting, secret and license checks pass.
Earlier full-module evidence retains its own build. CPU accounting covers 80.34 seconds including
preparation, warm-up, snapshot drain and cleanup: server 140.54, worker 1.32,
PostgreSQL 85.86, Docker VM/proxy 387.59, load generator 39.71 and receiver
0.12 CPU seconds; these are not utilization over the measured minute alone.

To reproduce, choose unused ports and a fresh output directory:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PREFIX=pa-bench-metadata-reference \
  BENCH_PG_PORT=61699 BENCH_HTTP_PORT=61700 \
  BENCH_INTERNAL_PORT=61701 BENCH_WORKER_PORT=61702 \
  BENCH_SCENARIOS=metadata-fetch BENCH_SOAK=0 \
  BENCH_OUT="$PWD/bench-results-private/metadata" \
  BENCH_HOST_LABEL=laptop make bench-local
```

**One laptop; load generator, receiver and database share it. These numbers
are not guarantees or sizing advice.** Cached refusals dominate aggregate
latency. The first ten-second timeout is an untimed preparation probe;
waiters on the second fetch cross the measurement deadline and unfinished
operations are omitted under the common run contract. Receiver drain
still verifies that fetch, outside the latency histogram. This is one
workload-federation process and a minute-scale abuse profile, without a
new soak; sustained OIDC/Shared Signals, multi-process aggregate budgets,
remote sources and multi-host capacity remain unmeasured. The runner's
cleanup trap removed native processes, its own container/volume and private
seed/credentials/CA working files. Nothing was downloaded or committed.

### Alpha.5 core-flow baselines (NFR-003, NFR-008)

On **2026-10-18 local time** (started `2026-10-17T23:39:55Z`, after a
172-second seed of 10000 users, 500 organizations, a 5000-member
organization, 20 machine clients and a 1000-member group, seed 1) the four
core token flows were measured again on the 0.2.0-alpha.5 tree, with the
hardened sign-in step (factor-step gating, upgrade proof), the optional
`security.password.max_concurrent_hashes` bound left off and the directory
bounds unused (local passwords only). Each scenario ran 60 measured seconds
at concurrency 32 after a five-second warm-up; latencies are milliseconds
from the histogram's upper bucket bounds.

| Scenario | Operations/s | p50 ms | p99 ms | p99.9 ms | Outcomes | Criterion | 2026-10-11 reference ops/s |
| --- | ---: | ---: | ---: | ---: | --- | --- | ---: |
| password-login | 47.8 | 655.36 | 851.97 | 1176.45 | `ok`: 2870 | Pass | 47.1 |
| refresh | 795.4 | 38.91 | 57.34 | 86.02 | `ok`: 47724 | Pass | 815.2 |
| client-credentials | 1008.2 | 31.74 | 38.91 | 77.82 | `ok`: 60490 | Pass | 1036.6 |
| introspection | 2012.9 | 15.87 | 20.48 | 30.72 | `ok`: 120772 | Pass | 2038.1 |

Throughput is within three percent of the 2026-10-11 reference in every
flow and p99 latency is unchanged or lower, so the alpha.5 security changes
on the sign-in and token paths cost nothing measurable on this machine. Both
runs share a laptop, so differences of this size are run-to-run noise, not a
trend. `password-login` again measured first sign-ins with
SHA-256-to-Argon2id rehashing: 3104 verifiers were Argon2id afterwards and
6897 remained imported SHA-256. The database ended at 292632255 bytes
(279 MiB) with 149606 audit rows. The scenario list of the invocation also
named `token`, which is not a scenario; `summary.json` keeps that failed
entry (`unknown scenario "token"`, zero operations) and the runner's
nonzero exit refers to it alone. The four valid scenarios passed.

**Environment:** Mac16,8 / Apple M4 Pro, 12 CPUs (8 performance + 4
efficiency), 25769803776 bytes RAM, AC power; macOS 27.0.1 (26A434),
Darwin 27.0.0; Go 1.27.1 `darwin/arm64`; Docker 29.7.2 with a 12-CPU,
25161293824-byte VM. PostgreSQL **18.6** (`postgres:18.6`, image
`sha256:74935e72…`) in one container on the same laptop with the settings
of the reference run (`shared_buffers=2GB`, `max_connections=200`,
`work_mem=16MB`, `effective_cache_size=6GB`, `pg_stat_statements`). Server,
worker and load generator run on the host over loopback HTTP. Checkout
source digest **`ed47a3d61d279094`**, no Git commit in the build; the tree
is the `main` merge of the alpha.5 integration branch. Development mode,
Argon2id 64 MiB/three passes, RSA 3072-bit signing keys, minimum
authentication response 250 ms; login per-IP/realm/client and token
per-client budgets **1000000** each.

[Per-scenario results](bench-results/2026-10-18-laptop-alpha5-baselines/),
[summary/CPU](bench-results/2026-10-18-laptop-alpha5-baselines/summary.json),
[environment](bench-results/2026-10-18-laptop-alpha5-baselines/environment.json),
[PostgreSQL settings](bench-results/2026-10-18-laptop-alpha5-baselines/postgres/settings.tsv),
top statements per scenario, [redacted
configuration](bench-results/2026-10-18-laptop-alpha5-baselines/proudauth-config.yaml)
and [artifact hashes](bench-results/2026-10-18-laptop-alpha5-baselines/artifact-sha256.json)
identify the measured build; the runner's private work directory appears as
`$WORK`. CPU accounting per scenario covers 65 wall seconds including
warm-up: `password-login` server 419.62, PostgreSQL 39.33; `refresh` server
203.74, PostgreSQL 85.22; `client-credentials` server 210.46, PostgreSQL
83.94; `introspection` server 123.98, PostgreSQL 96.12 CPU seconds, each
with roughly 190–450 Docker VM/proxy seconds on top.

To reproduce, choose unused ports and a fresh output directory:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PG_IMAGE=postgres:18.6 \
  BENCH_SCENARIOS="password-login refresh client-credentials introspection" \
  BENCH_SOAK=0 BENCH_OUT="$PWD/bench-results-private/alpha5-baselines" \
  BENCH_HOST_LABEL=laptop make bench-local
```

**One laptop; load generator and database share it. These numbers are not
guarantees or sizing advice.** They are a before/after check of the alpha.5
changes on the four most common flows, not a repeat of the full 13-scenario
reference, the soak or the adversarial profiles; those keep their 2026-10-11
to 2026-10-13 results above. Directory-backed sign-in under
`directory.sign_in_timeout` and `max_concurrent_binds`, and the password
hash bound, are covered by tests, not measured here.

### Alpha.6 budget-chain comparison (NFR-003, NFR-008)

On **2026-10-18 local time** (started `2026-10-18T16:41:23Z`, the same
laptop and PostgreSQL image as the alpha.5 baselines above, after the same
seed of 10000 users, 500 organizations, a 5000-member organization, 20
machine clients and a 1000-member group, seed 1) the four core token flows
were measured on the alpha.6 budget-chain tree (`alpha6-integration` at
commit `dfd7be6`, source digest **`5518509d1b5e3928`**): network-keyed
budgets with the wider /24 and /48 budgets, the transaction-start budget,
the known-device quota, the pre-authentication failure budgets on the token,
PAR, introspection and revocation endpoints, and the bounded audit
identifiers. Each scenario ran 60 measured seconds at concurrency 32 after a
five-second warm-up; the eleven budgets the bench can trip were raised to
1000000 (`environment.json`, `raised_budgets`), so the run measures the
code paths and not `429`s. Latencies are milliseconds from the histogram's
upper bucket bounds.

| Scenario | Operations/s | Alpha.5 ops/s | Change | p50 ms | Alpha.5 p50 | p99 ms | Alpha.5 p99 | Outcomes | Criterion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| password-login | 46.6 | 47.8 | −2.5% | 688.13 | 655.36 | 884.74 | 851.97 | `ok`: 2797 | Pass |
| refresh | 740.3 | 795.4 | −6.9% | 40.96 | 38.91 | 65.54 | 57.34 | `ok`: 44418 | Pass |
| client-credentials | 960.9 | 1008.2 | −4.7% | 32.77 | 31.74 | 55.30 | 38.91 | `ok`: 57653 | Pass |
| introspection | 1855.8 | 2012.9 | −7.8% | 17.41 | 15.87 | 25.60 | 20.48 | `ok`: 111350 | Pass |

Throughput is between 2.5 and 7.8 percent below the alpha.5 baselines in
every flow, inside the alpha.6 exit gate of no more than ten percent. p50
latency rose by 2 to 10 percent and p99 by 4 to 42 percent, most on
`client-credentials` (38.91 to 55.30 ms) and `introspection` (20.48 to
25.60 ms). The cost has a known source: every token, introspection and
revocation request now runs one read-only statement before client
authentication (`Limiter.Check` on the per-network failure budget and its
wider budget), `password-login` adds the transaction-start budget to the
start request and refreshes the sign-in's known-device facts at most once an
hour, and the budgets of a hit are still one statement. The known-device
quota costs nothing on this path: its lookup runs only when an aggregate
budget is exhausted, which the raised budgets never are. Both runs share
one laptop with the load generator and the database, so part of the p99
change is run-to-run noise; the throughput change is the number to watch.
`password-login` again measured first sign-ins with SHA-256-to-Argon2id
rehashing: 3019 verifiers were Argon2id afterwards and 6982 remained
imported SHA-256. The database ended at 284645055 bytes (271 MiB) with
142467 audit rows.

**Environment:** the alpha.5 machine (Mac16,8 / Apple M4 Pro, 12 CPUs,
25769803776 bytes RAM, AC power; macOS 27.0.1, Darwin 27.0.0; Go 1.27.1
`darwin/arm64`; Docker 29.7.2 with a 12-CPU VM; PostgreSQL **18.6**,
image `sha256:74935e72…`, in one container on the same laptop with the
reference settings). Server, worker and load generator run on the host over
loopback HTTP. Development mode, Argon2id 64 MiB/three passes, RSA 3072-bit
signing keys, minimum authentication response 250 ms.

[Per-scenario results](bench-results/2026-10-18-laptop-alpha6-budgets/),
[summary/CPU](bench-results/2026-10-18-laptop-alpha6-budgets/summary.json),
[environment and raised budgets](bench-results/2026-10-18-laptop-alpha6-budgets/environment.json),
[PostgreSQL settings](bench-results/2026-10-18-laptop-alpha6-budgets/postgres/settings.tsv),
top statements per scenario, [redacted
configuration](bench-results/2026-10-18-laptop-alpha6-budgets/proudauth-config.yaml)
and [artifact hashes](bench-results/2026-10-18-laptop-alpha6-budgets/artifact-sha256.json)
identify the measured build; the runner's private work directory appears as
`$WORK`. CPU accounting per scenario covers 65 wall seconds including
warm-up: `password-login` server 414.15, PostgreSQL 43.92; `refresh` server
184.97, PostgreSQL 90.40; `client-credentials` server 202.84, PostgreSQL
89.13; `introspection` server 121.60, PostgreSQL 100.91 CPU seconds, each
with roughly 190–450 Docker VM/proxy seconds on top.

To reproduce, choose unused ports and a fresh output directory:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  BENCH_PG_IMAGE=postgres:18.6 \
  BENCH_SCENARIOS="password-login refresh client-credentials introspection" \
  BENCH_SOAK=0 BENCH_OUT="$PWD/bench-results-private/alpha6-budgets" \
  BENCH_HOST_LABEL=laptop make bench-local
```

**One laptop; load generator and database share it. These numbers are not
guarantees or sizing advice.** They are a before/after check of the alpha.6
budget chain on the four most common flows against the alpha.5 baselines of
the same day, not a repeat of the full 13-scenario reference, the soak or the
adversarial profiles; those keep their 2026-10-11 to 2026-10-13 results
above. The new budgets' refusals (`429` with `Retry-After`) are covered by
tests, not measured here.

## Not covered yet

- **SCIM** bulk and real-directory load remain outside the
  published user lifecycle. `complex-filter` adds checked User-filter
  coverage with a passing 10000-managed-user measurement, under the
  unchanged connector budget. The Group-filter result adds 500 Groups with
  a 1000-member Group; larger Group populations and sustained scan-overflow
  capacity remain unmeasured. Correctness tests now cover the exact
  20000/20001-resource boundary for both Users and Groups.
- **Physical passkey authenticators/browser latency and attestation trust**:
  the software scenario validates signed server ceremonies only.
- **Remote HTTPS webhooks**, multi-tenant/multi-worker delivery, remote
  email delivery and SMTP retries remain unmeasured beyond the local
  callback/retry and SMTP acceptance profiles.
- **Email/SMS challenge-code and HOTP guessing** remain outside the TOTP
  capacity profile. [Cross-replica correctness bursts](consistency-tests.md#shared-otp-guessing-budgets--2026-10-12)
  check their combined account limit, stored failure/audit counts and
  next-window recovery; they do not establish sustained guessing capacity.
  The compound audit profile above now checks owned pages and invalid-input/
  cursor refusals. [Metadata/JWKS correctness bursts](consistency-tests.md#metadatajwks-fetch-bounds--2026-10-12)
  now prove shared fetches, failure cooldowns and protocol recovery. The
  [controlled workload metadata profile](#controlled-metadata-fetch-results-nfr-006-nfr-008)
  adds a passing measured minute with actual upstream counts; sustained
  OIDC/Shared Signals and multi-process metadata capacity remain unmeasured. The
  worker's queues can be watched through `/status` and
  `proudauth_delivery_total` during a run ([monitoring.md](monitoring.md)).
- **Multi-node consistency** has [partial cross-replica evidence](consistency-tests.md):
  recovery/invitation single use, self-releasing ownership transfer,
  role grant/edit/revoke, conditional SCIM/admin User and Group writes,
  Group membership/deletion races, refresh rotation
  and concurrent session/account-wide revocation, including three grants
  sharing one browser SSO session, pass repeated
  concurrency-32 bursts across three in-process servers with separate
  pools/keyrings/caches. Existing tests also check refresh/code/invitation
  single use across two apps and strict-online revocation through a peer's
  independent pool. The native-process results above add two 60-second
  refresh profiles across three separate servers. Full LDAP/AD directory
  reconciliation and its Group sync, longer shared-SSO refresh and revocation load,
  the other scenarios across separate
  processes, multiple machines, network faults and sustained multi-tenant
  load still need broader stress measurements.
- **Large audit volumes**: `audit-query` uses the seed's mutation history;
  `complex-audit-filter` adds 10000 owned application reports. Million-event
  histories and retention/partition capacity remain unmeasured; audit tables
  are not partitioned ([capacity.md](capacity.md#partitioning-policy-db-012)).
