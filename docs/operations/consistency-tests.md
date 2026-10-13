# Replica consistency evidence

The data-consistency stress requirement (NFR-007) covers invitations,
owner transfer, refresh rotation, recovery consumption, role changes,
connector sync and revocation across multiple nodes. The evidence below
is partial; it does not close the entire requirement or establish capacity.

## Complete current Go-module check — 2026-10-13

[Frozen full results](consistency-results/2026-10-13-full-final.json) now
cover the current development checkout on **Go 1.27.2**:
`go test -json -race -count=1 -p=2 -timeout=20m ./...` passes all **45**
packages with tests, **716** top-level tests and **562** subtests, with
**zero failures or skipped tests**. Another 29 packages have no tests.
E2E takes 784.853s, the complete contract package 36.401s, and the command
849.245s wall time including compilation. All 26 benchmark smoke scenarios
and connection-pool stress pass. Full vet, formatting of 593 Go files and
secret/license checks pass.

The report contains package/test results, 679 frozen Go/SQL/configuration
input hashes and
an empty pre-publication drift list; the protected traceability contract
retains its hash. It includes the Group/audit/metadata corrections and
earlier OTP, revocation, directory, replica and resource-boundary cases.
A temporary host SDK was bootstrapped from cached Go image source; all Go
subprocesses used 1.27.2. A dedicated PostgreSQL 18.6 container supplied
fresh databases, with its own loopback port and tmpfs data. Downloads were
disabled, no capacity measurement ran concurrently, and containers, SDK,
caches and private logs were removed. The installed Go remains 1.27.1.

The final check follows Staticcheck cleanup and immutable workflow/frontend
pins. An initial run exposed a sign error introduced in the session-lifetime
test's time calculation; the test now measures its injected clock against
its starting value and exact 12h limit. Three targeted race repetitions
pass, followed by this passing full check. Production session limits did
not change. The protected traceability contract is unchanged.

[Supplementary results](consistency-results/2026-10-13-supplementary.json)
record all 11 CI fuzz targets passing (30s or 15s each), Kubernetes rendering,
vet, secret/license checks and formatting. Earlier
[Go 1.27.2 results](consistency-results/2026-10-13-full-go1272.json) and
capacity profiles retain their original hashes and topology. Current
[artifact/dependency checks](security-checks.md#current-dependency-and-supply-chain-checks--2026-10-13)
and [image/package preparation](security-checks.md#local-image-and-release-preparation--2026-10-13)
retain their separate evidence. This full local check is not official
release provenance or a qualified external security review.

## Recovery and invitation stress — 2026-10-11

`TestReplicaRecoveryConsumptionStress` and
`TestReplicaInvitationAcceptanceStress` in
[replica_consistency_test.go](../../tests/e2e/replica_consistency_test.go)
drive three in-process HTTP servers against one PostgreSQL database.
Each server has its own runtime, connection pool, transaction semaphore,
keyring and signing-key cache. The two peers use the same public origin
through independent HTTP transports, as behind a load balancer. Root-key
material is equivalent but copied into separate keyrings; no application
cache or in-memory one-use authority is shared.

Every burst starts at one barrier with concurrency 32. Responses are
counted individually, including unexpected or missing observations, and
each independent pool reads the committed evidence afterward.

| Case, per execution | Requests | Exact outcomes | Stored invariant | Result |
| --- | ---: | --- | --- | --- |
| Recovery: six codes, eight transactions per round | 192 | 6 successful uses; 54 `invalid_proof`; 18 `transaction_invalid` for the already completed winning transaction; 114 `rate_limited`, each with positive `Retry-After` | Each round adds exactly one consumed verifier, one completed transaction and one success audit. Nine failed-proof audits agree with nine stored transaction failures; only that code is spent. | Pass |
| Invitations: eight invitations | 256 | 8 accepted; 248 `invitation_invalid`; no other outcome | Each invitation has one use, its expected acceptor/membership, exactly the invited role, one acceptance audit and one membership outbox event. No duplicate membership or grant. | Pass |

The account verification budget remains ten per 15 minutes and the
password identifier budget remains ten per 15 minutes. Recovery fixtures
therefore prepare eight pending transactions, then submit the same code
four times per transaction across all three replicas. Three requests on
the winning transaction encounter its completed state before proof
evaluation; ten other requests evaluate the proof and nineteen receive
budget refusals. The deterministic test clock advances by 16 minutes
between rounds; no rate counter is deleted/reset or limit raised. This
does not demonstrate elapsed-time window rollover or a sustained soak.
The first setup attempted 32 pending password transactions and was
correctly refused at the eleventh password request; the fixture was
corrected without changing server limits or production behavior.

The two stress cases and four existing lifecycle/replica/revocation cases
passed three times with the race detector, in a 43.006-second package run:
18 test executions, including 576 recovery submissions and 768 invitation
acceptances. The supporting cases are `TestRecoveryCodeLifecycle`,
`TestInvitationLifecycle`, `TestReplicasShareOneTimeState` and
`TestSharedRevocationAcrossNodes`. This targeted run does not claim a new
full-suite execution or a throughput/latency measurement.

Go vet, changed-file formatting and repository secret/license checks also
pass. After updating seven evidence rows, the complete contract package
passes with `-race -count=1` (28.711 seconds); its protected traceability
test remains unchanged. Previously published benchmark artifacts and
their hash manifests remain intact.

Environment: Mac16,8, Apple M4 Pro, 12 CPUs, 24 GiB RAM; macOS 27.0.1
(26A434); Go 1.27.1 `darwin/arm64`; local PostgreSQL 18.6 (`postgres:18`,
no pull), `max_connections=120`, `shared_buffers=128MB`, 1 GiB tmpfs data,
random loopback port. The three application pools allow 20/10/10
connections. Harness defaults deliberately use 8 MiB/one-pass Argon2,
RSA-2048 and no password timing floor; this is not the production-default
benchmark configuration. A cleanup trap removed the dedicated
`pa-bench-replica-check-20261011204234-13590` container and temporary
directory. No seed, recovery code, invitation secret, token or root key is
published; no download or Git commit was made.

To repeat, set `PROUDAUTH_TEST_DATABASE_URL` to a dedicated PostgreSQL
instance whose test role can create/drop databases. The harness migrates
fresh databases and drops them after each test. Keep
`PROUDAUTH_TEST_KEEP_DB` and `PROUDAUTH_REGENERATE_TRACEABILITY` unset:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -timeout=10m -v ./tests/e2e \
  -run '^(TestReplicaRecoveryConsumptionStress|TestReplicaInvitationAcceptanceStress|TestRecoveryCodeLifecycle|TestInvitationLifecycle|TestReplicasShareOneTimeState|TestSharedRevocationAcrossNodes)$'
```

## Ownership, roles and connector sync — 2026-10-11

Five additional cases in
[replica_authority_test.go](../../tests/e2e/replica_authority_test.go)
use the same three independent runtimes/pools/keyrings and public origin.
The fixture writes use authorized APIs; SQL reads verify the committed
effects from each pool. HTTP bursts start at one barrier at concurrency 32.

| Case, per execution | Work | Outcomes | Stored and public invariant | Result |
| --- | ---: | --- | --- | --- |
| Ownership, six rounds | 192 requests | 6 transfers; 186 `403 forbidden` | Each self-releasing transfer leaves exactly one active owner and one transfer audit. The caller retains ordinary membership but loses transfer authority; deleting the remaining owner role returns `409 last_owner` on every replica. | Pass |
| Roles, six grant/edit/revoke rounds | 576 requests | Each phase has 6 winners and 186 refusals: grant `409 conflict`, edit `412 precondition_failed`, revoke `404 not_found` | One assignment, one conditional permission revision, then one real deletion. Edit and revoke each advance holder/membership revisions once; audit/outbox counts agree, and live permissions reflect the winning role then its removal on every replica. | Pass |
| SCIM/admin sync, six rounds | 192 requests | 6 writers; 186 stale-write `412` errors in the correct SCIM/admin format | Six user-version increments and six mutation audits. The mapping counter advances only for a connector write; unchanged name/display/family/external-ID/state data survive. | Pass |
| Template application | 32 requests | 32 completed applications: one changes the setup, 31 return unchanged plans | One policy-version increment, one role, one group and one group grant; no lock-upgrade deadline or duplicate setup. | Pass |
| Expired role cleanup | Six competing worker calls over 32 grants | All calls complete; their actual deletion counts sum to 32 | No remaining grant, exactly 32 unassignment audits and 32 outbox events. A grant already removed by another worker is harmless and never counted twice. | Pass |

The initial concurrency-32 ownership burst failed at the 30-second client
deadline. Transfers first took `FOR SHARE`, then tried upgrading to
`FOR UPDATE`; writers waited on one another's shared locks. Transfers now
take the exclusive organization lock immediately, before checking active
state and rechecking authority. Non-dry template applications use the same
lock mode because they can update organization policy; grant issuance and
other read checks retain shared locking.

The initial role-revocation burst reported 27 successful deletes for one
assignment. `UnassignTx` ignored a zero-row delete and could still advance
revisions and write transition evidence. Only a real deletion now reaches
those effects; a losing API request gets `404`. Expiry workers tolerate
another worker's already completed deletion without counting it or
aborting their remaining cleanup. Both fixes have database-backed
regressions. An intermediate check also corrected the test's outbox JSON
query to `payload.data`; that was a fixture error, not a server defect.

The seven replica stress cases (including recovery/invitations above) and
five supporting owner/role/template/SCIM/elevation cases passed three
times under `-race -count=3`: 36 top-level executions, 78.002 seconds.
The five added cases contain 2976 HTTP mutation requests across the three
repetitions, plus 18 cleanup-worker invocations producing 96 actual expiry
transitions. All seven stress cases together contain 4320 HTTP requests;
preparation and verification calls are additional and unmeasured.

Environment and harness limits are the same as above. The dedicated
PostgreSQL container was `pa-bench-authority-check-20261011210417-17384`,
random loopback port 63085, with tmpfs data and a cleanup trap. No benchmark
ran concurrently. The untagged checkout's post-fix build-source digest is
`5a67bc848693654f`; the authority test file SHA-256 is
`1df680f951327c8696cbe4269deb75781f81ac2d89758c7f071f8eeef3cc2d11`.
Earlier capacity artifacts retain their historical build digests and hashes;
these fixes do not constitute new performance measurements.

The subsequent full checkout check, `go test -race -count=1 -p=2
-timeout=20m ./...`, passed with exit status 0 in the same offline Go
environment. End-to-end tests took 682.268 seconds; the complete contract
package passed in that run in 30.486 seconds. This includes all 23 benchmark
smoke scenarios and connection-pool regressions. Its separate PostgreSQL
18.6 container was `pa-bench-authority-check-20261011211022-19162`, loopback
port 51240, with 2 GiB tmpfs data, `shared_buffers=128MB` and
`max_connections=200`. Cleanup removed the dedicated containers; the
protected contract test's SHA-256 is unchanged and all 230 historical
published manifest hash entries still match. This verifies correctness,
not new throughput or latency numbers.

Repeat on a dedicated test database with the same offline environment:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -timeout=15m -v ./tests/e2e \
  -run '^(TestReplica.*Stress|TestLastOwnerProtection|TestRolePermissionEditRace|TestSCIMAdminRaceNeverLosesChanges|TestOrganizationTemplates|TestJustInTimeElevation)$'
```

## Refresh and revocation — 2026-10-11

Two new stress cases in [replica_tokens_test.go](../../tests/e2e/replica_tokens_test.go)
use the same three independent runtimes/pools/keyrings and concurrency-32
barriers. [grant_revocation_test.go](../../tests/e2e/grant_revocation_test.go)
adds live-grant checks for UserInfo, account APIs and exchanged descendants.
These exercise NFR-007, SES-006..SES-008 and SES-023 without raising the
harness's existing budgets or sharing one-use/application state.

| Case, per execution | Work | Outcomes and invariant | Result |
| --- | ---: | --- | --- |
| Refresh: session JWT, session opaque, offline JWT; four rounds each | 768 burst requests: 384 foreign-client attempts, 384 owning-client attempts | All 384 foreign attempts return `400 invalid_grant` without changing the family. Owning bursts produce exactly 12 successors and 372 `invalid_grant` refusals; each family has two exact parent/child records, one consumed parent, both tokens revoked and one reuse audit/outbox event. Original/successor access tokens are inactive on every node; an offline grant's SSO session and another user's token survive. | Pass |
| Revocation: one session and account-wide; three rounds each | 384 burst requests: 192 mixed race requests, then 192 post-response checks | All 96 administrative revocation calls complete. A pre-commit refresh can win once per family; stored generations/children exactly match observed successes. Every post-commit burst yields 16 `invalid_grant` refresh refusals and 16 inactive introspections. The bound session has one transition/audit/outbox/revocation record. Account-wide revocation also ends offline grants and account API access; one-session revocation leaves the separate account session and other user active. | Pass |
| Grant-level JWT regression: session and offline | Public grant revocations and checks through all three nodes | Linked business JWTs, UserInfo, account tokens and exchanged descendants stop online after their grant ends. Unrelated grants and SSO sessions stay active. Missing, unknown and foreign-client grant links fail closed; further exchange/refresh is refused. | Pass |

The initial targeted run failed in 44.420 seconds. Session-bound refresh took
the family before updating its session, while logout took the session before
its families; the one-session race reached 30-second HTTP deadlines. Refresh
now locks its session first, and account-wide revocation visits session IDs
in order. Offline rotation retains its independent session policy.

The initial offline-JWT case also observed `active: true` after confirmed
reuse had revoked its grant. JWTs lacked a serialized grant link, so live
checks could see an active user/SSO context while missing the revoked grant.
New user JWTs carry reserved `grant_id`; exchanges retain that originating
link. Online introspection, UserInfo, IdP user APIs and exchange check the
active, unexpired realm/subject-bound grant; ordinary JWTs also match its
client. Grant-store errors fail closed. Earlier development user/exchanged
JWTs without the link are refused online and need a fresh access token
([upgrade instructions](upgrades.md)). Offline verification is unchanged.

The account-wide fixture initially attempted its next sign-in in the same
fake-clock second as revocation. The documented account revocation correctly
includes that second. Subsequent fixtures advance the shared clock by two
seconds; no revocation record is deleted and no policy is relaxed.

All nine replica stress cases, the new grant-level regression and ten
supporting lifecycle/profile/exchange cases passed three race-detector
repetitions: 60 top-level executions in 143.320 seconds. The two new stress
cases contain 3456 burst requests across those repetitions; all nine stress
cases contain 7776, excluding preparation and verification requests.
Session/token unit checks also pass with the race detector (1.478/1.483s).
This is targeted correctness evidence, not a full-suite or capacity result.

Environment and harness limits remain as above. PostgreSQL 18.6 ran in
`pa-bench-token-check-20261011213754-22472`, random loopback port 57672,
with 1 GiB tmpfs, `shared_buffers=128MB` and `max_connections=120`.
The wrapper exited 0 and removed its container. The initial failed run's
container was also removed. No benchmark ran concurrently, no download or
Git commit was made and no token/client secret is published. The new
untagged build-source digest is `709600ab984f92de`; historical benchmark
artifacts retain their original digests and hashes.

The baseline harness retains `token_per_client=10000` and
`login_per_ip=10000`, with reduced hashing and no password timing floor as
described above. These settings are for correctness tests, not laptop capacity.

The subsequent full offline check, `go test -race -count=1 -p=2
-timeout=20m ./...`, passed with exit status 0: end-to-end 688.735 seconds,
complete contract package 31.410 seconds, including all 23 benchmark smoke
scenarios and connection-pool checks. It used PostgreSQL 18.6 in
`pa-bench-token-check-20261011214450-23393`, random loopback port 49417,
2 GiB tmpfs data, `shared_buffers=128MB` and `max_connections=200`.
The cleanup trap removed the container; no dedicated container/volume or
traceability-preview directory remains. Vet and repository secret/license
checks pass. Fourteen evidence rows were refreshed; the protected contract
test is unchanged and all 230 historical published manifest entries still
match. No new performance measurement is claimed.

Repeat with a dedicated test database and the same offline environment:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -timeout=15m -v ./tests/e2e \
  -run '^(TestReplica.*Stress|TestGrantRevocationStopsJWTAuthority|TestRefreshFamilyLineage|TestRefreshReuseEndsSession|TestLogoutEverywhereEndsOfflineTokens|TestSessionRevocationVisibility|TestAccessTokenProfile|TestIntrospectionExchangeAndMachines|TestExchangeChainLimits|TestClaimMappings|TestSharedRevocationAcrossNodes|TestRefreshNeverShortensSession)$'
```

## Native server-process refresh measurements — 2026-10-11

[Two reference profiles](benchmarks.md#independent-server-process-results-nfr-003-nfr-007-nfr-008)
add NFR-007 evidence through three separate host server processes with
independent pools/keyrings/caches and a shared PostgreSQL database. A
per-request loopback proxy distributes requests without sticky sessions or
cross-backend failover. Both 60-second concurrency-32 profiles pass:
56465 refresh operations and 2793 eight-way offline refresh races.
Counts prove every process received requests. Independent SQL verifies
one successor generation, revoked compromised families/grants, exactly
one reuse audit/outbox event per compromised family, and retained offline
SSO sessions. Boundary operations are distinguished from completed races.
These measurements complement the in-process tests above; their full
environment, raw results, verification counts and reproduction command
are published with the capacity results (NFR-003, NFR-008).

## Shared SSO revocation races — 2026-10-11

`TestReplicaSharedSSORevocationStress` in
[replica_sso_test.go](../../tests/e2e/replica_sso_test.go) adds NFR-007,
ARC-005/ARC-006 and SES-005/SES-007/SES-008/SES-014/SES-015/SES-021/SES-023
evidence. A real browser sign-in and silent authorization through different
nodes create three distinct grants/families on **the same SSO session**:
web BFF session-bound, notes BFF session-bound and notes BFF offline.
This includes two grants belonging to one client. Separate sessions of the
same user and another user's token serve as scope controls.

Each profile runs three rounds. Each round starts 32 requests together,
waits for every response, then starts 32 more to rotate surviving families
once, reject ended families and check online access-token authority.

| Profile | Burst requests per execution | Required scope after the race | Result |
| --- | ---: | --- | --- |
| Client-local grant revocation | 192 | Sixteen revocation receipts race one refresh per family and thirteen offline introspections. Only the web grant ends; the notes grants, shared SSO session and separate same-user session survive. | Pass |
| Offline refresh reuse | 192 | Thirty redemptions produce exactly one successor and 29 `invalid_grant` refusals; both session-bound families refresh independently. Only the offline grant ends; shared SSO and the same client's session-bound grant remain usable. | Pass |
| Session-bound refresh reuse | 192 | Thirty redemptions produce one successor and 29 refusals, racing one refresh of each other family. Shared SSO and both session-bound grants end; the offline grant and the separate same-user session survive. | Pass |
| One-session administrator revocation | 192 | Sixteen receipts race one refresh per family and thirteen offline introspections. Shared SSO and its bound grants end; offline authority and the same user's separate session survive. | Pass |
| Account-wide administrator revocation | 192 | Sixteen receipts race the three families and introspection. All of this user's session/offline authority ends, including the separate session; another user's token survives. | Pass |

Every independent pool checks each measured family's state, exact successor
generation/token count, consumed predecessors, root digest and parent lineage.
Reuse commits exactly one reuse audit and outbox event for the affected
family, with zero reuse events for the other families. A terminated shared
session has exactly one revocation audit, outbox event and durable session
revocation marker, and both client sessions are logged out. A surviving
session has none of these termination records. Original and successor
tokens are introspected through every node; old browser cookies permit
silent SSO only while their session remains active.

The five profiles pass **three race-detector repetitions**, totaling 45
rounds and 2880 barrier-started requests (excluding setup, sequential
checks and supporting tests). `TestLogoutScopes` and
`TestGrantRevocationStopsJWTAuthority` also pass three times in the same
59.209-second package run. No production behavior needed changing. This
is targeted correctness evidence, not a fresh full-suite run or capacity
measurement. All three servers remain in-process with separate runtimes,
pools, transaction limits and keyrings; this shared-SSO test does not run
through the native-process benchmark proxy.

Go vet, changed-file formatting and the secret scan pass. Ten refreshed
evidence rows match the current sources; the complete contract package
passes with `-race -count=1` (27.729 seconds). Its protected traceability
test is unchanged, and all 167 published benchmark manifest entries verify.

Environment: the laptop/Go configuration above; local PostgreSQL 18.6,
`max_connections=120`, `shared_buffers=128MB`, 1 GiB tmpfs data, loopback
port 59057. Harness password/signature/timing settings remain the reduced
correctness-test defaults above. A cleanup trap stopped and removed
`pa-bench-sso-check-20261011230236-35952` and its private temporary files.
Nothing was downloaded; no credentials or seed are published.

Repeat with an isolated `PROUDAUTH_TEST_DATABASE_URL` whose role can
create/drop migrated test databases, with keep/regeneration flags unset:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -failfast -timeout=10m -v ./tests/e2e \
  -run '^(TestReplicaSharedSSORevocationStress|TestLogoutScopes|TestGrantRevocationStopsJWTAuthority)$'
```

## SCIM Group races — 2026-10-11

`TestReplicaSCIMGroupConditionalStress` and
`TestReplicaSCIMGroupMembershipStress` in
[replica_scim_groups_test.go](../../tests/e2e/replica_scim_groups_test.go)
add NFR-007, PROV-003/PROV-007/PROV-008, TEN-013, AZ-010, API-010 and
TEST-050 evidence across the same three independent runtimes/pools/keyrings.
Fixture writes use the public connector and administrator APIs; every
pool verifies stored versions, membership revisions, role assignments and
audit records, and evaluates effective group-derived permissions.

| Case, per execution | Barrier requests | Required behavior | Result |
| --- | ---: | --- | --- |
| Six conditional rename rounds | 192 | Sixteen SCIM and sixteen administrator writers read their respective tags. Exactly one rename commits per round, with 31 `412` refusals. Name/version agree on every node; original member, external ID, description, metadata and connector/admin role assignments survive. | Pass |
| Four concurrent membership/deletion rounds | 256 | Sixteen conditional SCIM replacements race sixteen idempotent administrator additions. At most one replacement commits; otherwise every connector writer is stale. The administrator's distinct added member always survives. A subsequent 32-request conditional deletion has one `204` and 31 SCIM `404` responses. | Pass |
| Four SCIM-first membership/deletion rounds | 256 | A successful public replacement receipt precedes 32 administrator additions. All return `204`, while adding the distinct member exactly once; both the replacement member and administrator's member retain the group's roles. Concurrent deletion commits once. | Pass |
| Four administrator-first membership/deletion rounds | 256 | An administrator addition receipt precedes 32 connector writes with the old tag. All are SCIM `412` errors and the old member plus administrator's added member remain. Concurrent deletion commits once. | Pass |

The explicit receipt ordering covers both causal orders without relying on
the scheduler to produce each one during the mixed burst. The recorded
mixed bursts happened to accept one connector replacement in all twelve
rounds across three repetitions; the invariant also permits zero when the
administrator addition makes the tag stale first.

Each member transition bumps only that membership's revision once and has
exactly one add/remove audit. Repeated administrator additions create no
duplicate rows or audits. Both approved connector roles and administrator
roles stay assigned until controlled deletion, which leaves zero group,
mapping, group-member and role-assignment rows, one `group.deleted` audit
and two `role.unassigned` audits with `GROUP_DELETED`. All organization
memberships remain active, and none retains the removed group's
`orders.read` permission. These are local inbound SCIM Group writes, not
LDAP/AD full reconciliation or Group-filter capacity measurements.

Both stress cases and `TestSCIMProvisioning`/
`TestSCIMAdminRaceNeverLosesChanges` pass three race-detector repetitions
in a **34.090-second** package run. The new cases account for 2880
barrier-started requests, excluding setup, forced first receipts,
sequential validation and supporting tests. No production behavior
needed changing, and no fresh full-suite or performance run is claimed.
The servers are in-process with independent pools/caches, not three
native processes or machines.

Go vet, changed-file formatting and the secret scan pass. Eight evidence
rows are refreshed; the complete contract package passes with
`-race -count=1` (27.862 seconds), and its protected traceability test remains
unchanged.

Environment: the same laptop and Go version; dedicated local PostgreSQL
18.6, `shared_buffers=128MB`, `max_connections=120`, 1 GiB tmpfs data,
loopback port 62231. The correctness harness uses the reduced hashing,
signature and timing settings described above. The cleanup trap removed
`pa-bench-group-check-20261011231423-37825` and its private temporary files.
No dependency downloads, private connector tokens or seed publication.

Repeat with an isolated `PROUDAUTH_TEST_DATABASE_URL` whose role can
create/drop test databases, with keep/regeneration flags unset:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -failfast -timeout=10m -v ./tests/e2e \
  -run '^(TestReplicaSCIMGroupConditionalStress|TestReplicaSCIMGroupMembershipStress|TestSCIMProvisioning|TestSCIMAdminRaceNeverLosesChanges)$'
```

## Mixed group deletion and link repair — 2026-10-11

[group_delete_consistency_test.go](../../tests/e2e/group_delete_consistency_test.go)
adds five cases for TEN-013, PROV-004/PROV-007/PROV-008/PROV-010/PROV-012/
PROV-017, DB-014, QA-008, TEST-050 and NFR-007.
Before the fix, a controlled deletion waiting for the group already held
its membership: an independent member edit hit PostgreSQL `55P03` at the
200 ms lock timeout. A second regression found the deleted group's
connector mapping still present on all three pools; reprovisioning the
same external ID returned `409 uniqueness`. Both cases failed in the
3.469-second pre-fix run.

Group deletion, SCIM writes and directory Group application now lock the
group before mappings and members. The owned-group join retains connector
scope before acquiring the lock. Local deletion removes inbound/directory
Group mappings in its transaction; outbound mappings remain until the
downstream acknowledges deletion. A later SCIM create using that external ID or directory apply
repairs a legacy mapping only when its local group no longer exists,
without adopting a live group or clearing outward cleanup authority.

| Case | Post-fix required evidence | Result |
| --- | --- | --- |
| Held-group deletion | While deletion waits for a held group row, an independent membership edit commits without waiting on the deletion. All three pools see the active membership and preserved edit after deletion. | Pass |
| Inbound external-ID reuse | Administrator deletion removes the mapping. The same external ID creates a distinct new group; a reconstructed legacy orphan also repairs on create. | Pass |
| Directory legacy repair | A real local LDAP full sync repairs an orphaned local Group link. A second full sync retains exactly one group, link, mapped role and member, without duplicate replacement. | Pass |
| Outbound cleanup | A real loopback SCIM adapter first creates a remote group. Local deletion retains its outbound mapping; reconciliation deletes the remote group and only then clears that mapping. | Pass |
| Mixed administrator/SCIM bursts | Six rounds of 16 administrator deletions plus 16 conditional SCIM member removals across three independent replicas: exactly one deletion per round; every other result is a documented success/stale/missing response. | Pass |

The mixed burst checks zero remaining group, inbound link, group-member
and role-assignment rows, exactly one deletion audit, two unassignment
audits and at most one connector removal audit. The organization membership
remains active with exactly one revision bump, and no replica retains its
group-derived permission. A connector's post-commit representation read
may encounter the competing deletion and return `404`; committed effects
are therefore checked independently from SQL/audit records. Reusing the
external ID in the next round proves no stale map prevents further sync.

The five new cases, the two earlier SCIM Group stress cases,
`TestDirectorySynchronization` and `TestOutboundProvisioning` pass three
race-detector repetitions in **61.154 seconds** (27 top-level executions).
The new mixed case contributes 576 barrier-started requests; the earlier
Group cases add 2880 in the same run. Group bursts and the lock-guard
regression use three in-process replicas with independent pools/keyrings;
directory/outbound lifecycle fixtures use one runtime and actual loopback
LDAP/SCIM test services. Controlled SQL holds the group row and reconstructs
legacy orphan records; primary lifecycle requests use public APIs.

Environment: the same laptop/Go configuration, dedicated local PostgreSQL
18.6, `shared_buffers=128MB`, `max_connections=120`, 2 GiB tmpfs data,
loopback port 65257; reduced correctness-harness hashing/signature/timing
settings. Go/SQL source digest `4e129f47e0b1c385`, no Git commit. Existing
capacity artifacts remain pinned to their older builds; these changes
are not a new capacity measurement, native-process or fault/failover test.

The full offline `go test -race -count=1 -p=2 -timeout=20m ./...` check also
passes after these fixes and all newer replica/proxy additions: end-to-end
737.637 seconds, complete contract package 30.951 seconds, every Go package,
all 23 benchmark smoke scenarios and connection-pool checks. Vet, formatting
and secret/license checks pass; eleven evidence rows are refreshed and the
protected traceability test is unchanged. All 167 published benchmark
manifest entries verify unchanged. The cleanup trap removed the dedicated
verification container and private files; Go's temporary build tree is gone.

Repeat against an isolated `PROUDAUTH_TEST_DATABASE_URL` with create/drop
permission and keep/regeneration flags unset:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -failfast -timeout=10m -v ./tests/e2e \
  -run '^(TestGroupDeletionWaitsBeforeLockingMembers|TestGroupDeletionReleasesConnectorExternalID|TestDirectoryGroupRepairsDeletedLocalMapping|TestGroupDeletionPreservesOutboundCleanup|TestReplicaMixedGroupDeletionStress|TestReplicaSCIMGroupConditionalStress|TestReplicaSCIMGroupMembershipStress|TestDirectorySynchronization|TestOutboundProvisioning)$'
```

## Directory synchronization across replicas — 2026-10-12

`TestReplicaDirectorySynchronizationStress` in
[replica_directory_test.go](../../tests/e2e/replica_directory_test.go) adds
multi-runtime evidence for PROV-007, PROV-012, PROV-017, PROV-018,
TEST-048, TEST-049 and NFR-007. Three HTTP servers have independent
runtimes, pools (20/10/10 connections), transaction semaphores, keyrings and
caches. They share one database and a deterministic clock. A real loopback
LDAPS transport connects to the local test directory, which implements the
Active Directory attributes, USN cursor and paging used by this profile;
this is not a Windows AD interoperability run.

Each of four phases starts 32 public run requests: exactly one returns
`202`, and all 31 conflicts identify the accepted run. Three separate
workers then compete through the production `jobs.run` task and its real
job leases. The owning handler is held at the first page's progress
callback, after the page transactions; both other workers finish without
claiming work. All pools observe one running run and job with an unexpired
lease and one attempt. Another 32 public requests during the partial scan
all conflict with that run. Releasing the callback completes the actual
handler once, with one successful job and no remaining lease.

| Phase | Source and durable evidence on every pool | Result |
| --- | --- | --- |
| Paged full sync | Eight users at page size two; eight active organization memberships, eight User links, one Group link/group, two Group members and one directory role. Exactly eight provisioning audits and two member-add audits. | Pass |
| Incremental dry-run | One changed user's display name and one removed source Group member; a `uSNChanged>=` filter reads one user. The plan reports one update, while complete snapshots of the cursor, links, users, memberships, Group, members and roles remain unchanged. | Pass |
| Applied incremental | The same one-user change applies once, the Group loses exactly its removed member, and the cursor advances on all pools. Exactly one user-update audit and one member-remove audit. | Pass |
| Repeated full sync | All eight users are scanned again; no creation, attribute update or duplicated link, role or member. Provisioning, user-update and member-mutation audits do not repeat. The original Group ID, administrator role, description and metadata survive. | Pass |

Every phase checks one request audit and one operator run action; applied
runs also have one completion audit. Dry-run completion changes the run
report, not synchronized state, and does not emit an applied completion
audit. Effective `orders.read` authority remains for the retained member,
disappears for the removed member after the applied incremental run, and
never appears for the changed user outside the mapped Group. These checks
use each independent authorization service as well as stored row counts.

The new case, `TestDirectorySynchronization` and
`TestDirectoryGroupRepairsDeletedLocalMapping` pass three race-detector
repetitions: **nine top-level executions in 20.691 seconds**. The new case
contributes 768 barrier-started public requests, 12 accepted runs and 12
handler executions; the supporting cases retain conflict, deletion-safety
and legacy-link coverage. No new production defect was found.

The complete contract package passes in 27.851 seconds. Vet, formatting,
secret/license and edited-document local-link checks pass. Seven evidence
rows match a generated preview; the protected traceability test is unchanged.
The preview files were removed after comparison.

Environment: Mac16,8 / Apple M4 Pro, 12 CPUs, 24 GiB RAM; macOS 27.0.1
(26A434), Go 1.27.1; dedicated PostgreSQL 18.6 with
`shared_buffers=128MB`, `max_connections=120`, 1 GiB tmpfs data and loopback
port 62058. The correctness harness uses 8 MiB/one-pass password hashing,
RSA-2048 and no artificial authentication delay. Go/SQL production source
digest remains `4e129f47e0b1c385`, no Git commit. The existing full-suite
result above predates this new test; this addition was checked with the
targeted command below. Existing capacity artifacts retain their recorded
builds and measurements. Cleanup removed the dedicated container and its
tmpfs data.

This adds full/incremental LDAP and Group consistency evidence to NFR-007;
it does not close that entire requirement. Competing directory schedules,
lease expiry/crash resumption, real AD/OpenLDAP counterpart runs, separate
processes or machines, network failures and sustained multi-node capacity
remain outside this new case.

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -failfast -timeout=5m -v ./tests/e2e \
  -run '^(TestReplicaDirectorySynchronizationStress|TestDirectorySynchronization|TestDirectoryGroupRepairsDeletedLocalMapping)$'
```

## Directory schedules and expired worker leases — 2026-10-12

[replica_directory_recovery_test.go](../../tests/e2e/replica_directory_recovery_test.go)
adds `TestReplicaDirectoryScheduleStress` and
`TestReplicaDirectoryExpiredLeaseRecovery` for PROV-007, PROV-012,
PROV-018, DEP-011, TEST-058 and NFR-007. The same three independent
HTTP runtimes/pools and loopback LDAPS test directory are used.

The first expiry regression failed in **1.718 seconds**: after two users
committed, the original worker paused, its lease expired and another worker
finished the run. The old worker resumed, reported success, overwrote the
run/result as `failed` and emitted a second completion audit. All three
pools saw `failed/succeeded/failed` for run/job/job-result state.

Job progress and terminal writes now require a running, unexpired claim
with both worker ID and attempt number. `Job.LockLease` holds that claim
inside each directory mutation transaction before domain rows. This fences
LDAP user/link writes, Group membership/roles, deprovisioning, outbound
reconciliation mapping/delivery writes, findings, status and cursors.
Lease loss propagates without publishing a replacement failure or emitting
dead-letter evidence. Run endpoint/mode updates commit with final evidence;
a failed final transaction is returned rather than reported as complete.
Other job handlers retain their existing domain idempotency rules; this
new transaction guard is applied to directory synchronization/reconciliation.

| Case, per execution | Required evidence | Result |
| --- | --- | --- |
| Blocked due schedules | 32 schedulers compete while a manual run is queued; zero scheduled runs and both next-run timestamps remain null after rollback. | Pass |
| Full/incremental slots | 32 competing schedulers accept one full slot, none at 59 seconds, one changed-user incremental slot at 60 seconds, and one full slot at 300 seconds even though incremental work is overdue. Further claims return zero; next timestamps are exactly 60/300 seconds after the appropriate slot. | Pass |
| Scheduled worker execution | The initial manual run and three scheduled runs each execute through one leased handler, with 32 public conflicts during its first page. All pools retain eight users, nine links and eight provisioning audits; each scheduled run emits one completion audit and no manual-request audit. | Pass |
| Expired-worker recovery | A real handler commits two users/checkpoint, pauses, then loses its lease after a deterministic clock advance. The replacement imports the other six and completes one run at attempt two. Returning the old handler without a heartbeat reaches the domain-transaction fence and stops with lease loss. Full snapshots remain unchanged; both original user IDs, eight total provisioning audits, one Group/two members/one role, the recovered cursor and one completion audit survive on every pool. | Pass |
| Generic job attempts | [lease_fence_test.go](../../internal/jobs/lease_fence_test.go) covers success, transient retry, permanent failure, cancellation, reused worker ID and expired lease without takeover. Stale progress/transaction guards fail, and stale finalizers leave the replacement's complete row, protected result and dead-letter count unchanged. | Pass |

The two new replica cases, the earlier full/incremental replica case,
`TestJobAttemptFencing` and `TestJobLeasesRetriesAndDeadLetters` pass three
race-detector repetitions: **15 top-level executions**; end-to-end package
**18.473 seconds**, jobs package **6.024 seconds**. The fencing test adds
18 outcome subtests. Scheduling contributes 864 barrier-started scheduler
calls and 384 public conflicts; the earlier sync case adds 768 public
requests in the same command. These are correctness counts, not capacity.

Environment: the same Mac16,8 / M4 Pro, 12 CPUs, 24 GiB, macOS 27.0.1
(26A434), Go 1.27.1; dedicated PostgreSQL 18.6,
`shared_buffers=128MB`, `max_connections=120`, 2 GiB tmpfs data, loopback
port 63537. The reduced correctness-harness settings remain as above.
Go/SQL production source digest `0a51116192cb1f18`, no Git commit.
Existing capacity artifacts predate this fix and remain pinned to their
recorded builds.

The completed full offline check,
`go test -json -race -count=1 -p=2 -timeout=20m ./...`, passes on this
frozen build: **E2E 728.781 seconds**, complete contract package
**30.465 seconds**. All 42 packages with tests pass; 32 other packages
have no test files. Across the module, 686 top-level tests and 452 subtests
pass with no failed or skipped tests, including all 23 benchmark smoke
scenarios, connection-pool checks and the new directory/fencing cases.
[Machine-readable result](consistency-results/2026-10-12-directory-lease.json)
records the source hashes, environment, package outcomes and selected cases.

An earlier full invocation lost its terminal observation after interruption
and was not counted as passing. The completed rerun used the same dedicated
PostgreSQL settings on loopback port 53361, with a private JSON event log.
The cleanup trap removed its container; the private log and work directory
were removed after verification. Vet, formatting, secret/license and local
document-link checks pass. Six refreshed evidence rows match the reviewed
preview, and the protected traceability test remains unchanged.

The clock/handler barrier models a stalled worker returning after takeover;
it does not kill a native process or test a physical machine/network/DB
failure. Real AD/OpenLDAP counterpart interoperability, multi-tenant
directory capacity and sustained fault/recovery load remain open.

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -race -count=3 -p=2 -failfast -timeout=5m -v \
  ./internal/jobs ./tests/e2e \
  -run '^(TestJobAttemptFencing|TestJobLeasesRetriesAndDeadLetters|TestReplicaDirectoryScheduleStress|TestReplicaDirectoryExpiredLeaseRecovery|TestReplicaDirectorySynchronizationStress)$'
```

## Native directory worker process death — 2026-10-12

`TestDirectoryProcessCrashRecovery` in
[directory_process_crash_test.go](../../tests/e2e/directory_process_crash_test.go)
adds actual OS process-death evidence for PROV-007, PROV-012, PROV-018,
DEP-011, TEST-058 and NFR-007. A separately exec'd copy of the compiled,
race-instrumented test binary builds an independent application/pool/keyring
and executes the production `jobs.run` task with its directory handler.
It uses equivalent private root-key material and the same fixture database.
Configuration and root material stay in the child's environment; neither
is published. The HTTP servers remain three independent runtimes/pools
in the parent process, and the LDAPS test directory stays alive.

The child acknowledges the first page only after its two entry
transactions and real job progress/checkpoint commit. The parent then
calls `os.Process.Kill` and reaps it, asserting signal termination
(`ExitCode() == -1` on this macOS run). This bypasses graceful worker drain
and lease release. Every pool still sees a running run/job with the dead
worker's unexpired lease, one attempt and no finish timestamp. All three
early replacements claim zero jobs; 32 public requests still conflict with
the original run. A deterministic clock advance expires the lease; three
workers compete through the real jobs task, and exactly one handler repeats
the scan at attempt two. Another 32 requests conflict during recovery.

| Profile, per execution | Committed before kill | Required recovered state on every pool | Result |
| --- | --- | --- | --- |
| Full | Two imported users and checkpoint `processed=2`; no cursor advance. | Six remaining creations, eight original accounts/active organization memberships, eight User links plus one Group link, two Group members/one mapped role, eight provisioning audits, one completion audit and the recovered cursor. Both partial account IDs survive. | Pass |
| Incremental | A successful full baseline, then four source display-name changes and removal of one source Group member. Two changes and checkpoint `processed=2` commit; the baseline cursor remains. | A USN-filtered rescan sees four users and applies only the other two updates. All eight original IDs/memberships survive, exactly four update audits exist, the Group retains one member, and there is one removal audit and one recovered completion audit. The changed names and Group-derived permission agree on every pool. | Pass |

Both profiles require exactly one successful job at attempt two, no
remaining lease, matching run/job-result state and matching connector/run
cursors, without error/conflict findings. Failed setup paths also kill and
reap the child. Each parent execution adds 224 barrier-started public
requests (the incremental profile includes a baseline sync).

Three race-detector repetitions, alongside the prior directory
schedule/expiry/sync cases and recovery/refresh stress, pass **18 top-level
executions and 15 subtests in 59.209 seconds**. The new case contributes
**six verified OS kills** and 672 public requests; the combined command
contains 4704 public burst requests. No new production defect was found.
[Structured results and test hashes](consistency-results/2026-10-12-directory-native-crash.json)
retain all three case timings and the exact command/environment.

Environment: the same Mac16,8 / M4 Pro, 12 CPUs, 24 GiB, macOS 27.0.1
(26A434), Go 1.27.1; dedicated PostgreSQL 18.6,
`shared_buffers=128MB`, `max_connections=120`, 1 GiB tmpfs data,
2 GiB memory limit, loopback port 63434. The correctness-harness settings
remain reduced as above. Production Go/SQL digest remains
`0a51116192cb1f18`, no Git commit. This addition changes tests only;
the earlier full-module result predates it and retains its own frozen
test hashes. Targeted race repetitions and vet validate the new test and
shared-fixture changes. The complete contract package passes in 27.762
seconds. Formatting, secret/license and local-document-link checks pass;
six refreshed evidence rows match their reviewed preview and the protected
traceability test remains unchanged. The dedicated container, killed child
processes and private logs are removed after verification.

This executes the real worker task inside a test binary, rather than
the production `identity-worker` entrypoint. Lease expiry is still modeled
with the shared clock; the OS kill is real. It does not kill the HTTP
servers, directory or database, or establish physical host/network/DB
failover, real AD/OpenLDAP interoperability or directory capacity.

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -json -race -count=3 -failfast -timeout=5m ./tests/e2e \
  -run '^(TestDirectoryProcessCrashRecovery|TestReplicaDirectoryScheduleStress|TestReplicaDirectoryExpiredLeaseRecovery|TestReplicaDirectorySynchronizationStress|TestReplicaRecoveryConsumptionStress|TestReplicaRefreshRotationStress)$'
```

## Directory transport interruption and complete-source deletion — 2026-10-12

`TestDirectoryTransportScanConsistency` in
[directory_transport_consistency_test.go](../../tests/e2e/directory_transport_consistency_test.go)
adds PROV-007, PROV-012, PROV-014, PROV-017, PROV-018, TEST-058 and
NFR-007 evidence across three independent HTTP runtimes/pools. Two local
LDAPS test endpoints share immutable user IDs; the replacement represents
a configured domain controller with a complete view missing one previously
linked user. The connector explicitly uses `remove_membership` with the
unchanged 20% deletion threshold. The first endpoint's live connections
are dropped after a committed/checkpointed user page.

Before the fix, both full failover and incremental-to-full failover reported
`succeeded` after reading all seven replacement users, yet all three pools
still showed eight active memberships, an active link for the absent user
and zero deprovision audits. The first endpoint's partial `seen` set was
retained across retry and suppressed deletion of that user. The pre-fix
command failed in **5.757 seconds**; the separate exhaustion/recovery
profile already passed.

Each endpoint scan now starts with an empty deletion-presence set. Applied
entry transactions and their findings/counts remain idempotent and retain
their audit evidence, but only the endpoint that finishes its complete scan
determines missing accounts. This is a connector-scoped source snapshot,
not a union of a failed partial scan and its replacement.

| Profile | Required evidence on every pool | Result |
| --- | --- | --- |
| Full scan, connection dropped | Retry the complete seven-user replacement view; remove exactly one absent organization membership, mark its link missing, retain all original account/link IDs, one Group/member role and one completion audit. Eight provisioning audits remain unchanged; exactly one deprovision audit exists. | Pass |
| Incremental, connection dropped | Two changed-user transactions commit on the first controller. The different replacement controller promotes the operation to full, reads seven users and applies the same complete-source deletion. Its controller-qualified cursor, final endpoint and full mode are durable on all pools. | Pass |
| Every endpoint unavailable | A two-user partial scan ends failed with no cursor advance, no deprovision, eight active memberships and the original Group authority. After restoring transport, a new full run reads seven users, removes the absent membership once and creates no replacement accounts. | Pass |

The first two profiles also verify the removed user's effective authority
is absent while the retained Group member keeps it. The exhaustion profile
keeps both permissions until the complete retry succeeds. The baseline
and run requests use public APIs; faults close actual loopback TLS sockets.
No deletion threshold or proof/connector budget is raised.

The new test, single-runtime sync/sign-in support and the prior native
worker-death/replica schedule/expiry/sync cases pass three race-detector
repetitions: **21 top-level executions, 15 subtests, 57.890 seconds**.
All three transport profiles pass three times after the correction; the
same command retains six actual worker-process kills. Vet passes.

Environment: the same Mac16,8 / M4 Pro, 12 CPUs, 24 GiB, macOS 27.0.1
(26A434), Go 1.27.1; dedicated PostgreSQL 18.6,
`shared_buffers=128MB`, `max_connections=120`, 2 GiB tmpfs data,
3 GiB memory limit, loopback port 52821. The reduced correctness-harness
settings remain as above. Production Go/SQL digest `f66bc581a3dc5efb`,
no Git commit. The full offline race-detector check passes on this frozen
build: **E2E 734.223 seconds**, complete contract package **30.697 seconds**,
42 packages with tests and 32 without test files. Across the module,
**688 top-level tests and 457 subtests** pass, with none failed or skipped,
including the native worker-death case, all 23 benchmark smoke scenarios
and connection-pool checks. [Structured results](consistency-results/2026-10-12-directory-transport.json)
record source hashes, package outcomes and the full command. The full run
uses the same database settings on loopback port 56370; its cleanup trap
removes the dedicated container. Private raw logs are removed after
verification and are not published. Formatting and secret/license checks
pass; seven refreshed traceability rows match the reviewed preview, and
the protected contract test remains unchanged.
Capacity artifacts and earlier correctness reports retain their original
builds/hashes; this is not a capacity or physical DB/host failure result.

The replacement is an operator-configured, trusted endpoint, and its
complete full view remains subject to the connector's deletion threshold.
The test service implements AD attributes, paging and USN tracking; it is
not real AD/OpenLDAP interoperability. Physical network partitions,
production-entrypoint worker/server profiles, database failover and
sustained multi-tenant fault load remain open.

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -json -race -count=3 -failfast -timeout=5m ./tests/e2e \
  -run '^(TestDirectoryTransportScanConsistency|TestDirectorySynchronization|TestLDAPDirectorySignIn|TestDirectoryProcessCrashRecovery|TestReplicaDirectoryExpiredLeaseRecovery|TestReplicaDirectoryScheduleStress|TestReplicaDirectorySynchronizationStress)$'
```

## Shared OTP guessing budgets — 2026-10-12

`TestReplicaOTPGuessBudgets` in
[replica_otp_budgets_test.go](../../tests/e2e/replica_otp_budgets_test.go)
covers distributed proof attempts (TEST-021, NFR-006, NFR-007), including
the opt-in HOTP profile (MFA-013). Eight headless transactions store eight
distinct source IPs accepted through configured loopback trusted proxies.
A barrier releases 32 guesses across three independent runtimes/pools.

Before the correction, email and SMS passwordless transactions had not
authenticated their user, so each used an identifier budget while HOTP
used an account budget. One account's mixed burst evaluated **28** wrong
proofs and limited only **4**, instead of **10/22**. The regression failed
in **6.973 seconds**; the separate email, SMS and HOTP profiles passed.
An issued login challenge now supplies its realm/transaction-bound user
solely for budget selection. It does not authenticate the transaction.
Known users also keep one account key during registration verification;
phantom challenges keep identifier budgets, and lookup errors fail closed.

| Profile, per execution | Guess outcomes | Required stored evidence on all three pools | Result |
| --- | --- | --- | --- |
| Email login codes | 10 `invalid_proof`, 22 `rate_limited` | Ten challenge attempts, transaction failures and OTP failure audits; all eight transactions remain pending. | Pass |
| SMS login codes | 10 `invalid_proof`, 22 `rate_limited` | The same exact counts; the phone was added and verified through account APIs before setup. | Pass |
| HOTP | 10 `invalid_proof`, 22 `rate_limited` | Ten transaction failures and HOTP failure audits; the active counter stays at one. | Pass |
| Email + SMS + HOTP for one account | 10 `invalid_proof`, 22 `rate_limited` total | Challenge attempts equal evaluated email/SMS guesses; separate OTP/HOTP audit totals agree with each observed class. The counter stays unchanged. | Pass |
| Unknown email account | 10 `invalid_proof`, 22 `rate_limited` | Ten challenge attempts/failures/audits, no notification or authenticated user; a later proof remains invalid. | Pass |

Every budget refusal has positive `Retry-After`. No transaction has more
than four failures in these bursts. A valid known-account code is refused
while the budget is exhausted; after advancing the deterministic clock
into a new window, a fresh proof completes exactly once on every pool.
Email/SMS challenges show one attempt/consumption; HOTP advances from one
to two with one use audit. This checks window semantics, not elapsed-time
rollover or a sustained soak. The default account limit remains ten per
15 minutes, challenge limit five, and identifier login limit ten per
15 minutes. No proof or connector budget is raised.

All five profiles and five supporting cases pass three race-detector
repetitions: **18 top-level executions, 33 subtests, 76.485 seconds**.
The new case contains **480 guessing requests** in that command, plus
exhausted-budget and next-window controls. Supporting cases cover the
TOTP benchmark's five-failure transaction retirement, HOTP lifecycle,
passwordless/send budgets, per-client verification and recovery single
use. Vet, formatting and secret/license checks pass.

Environment (NFR-008): Mac16,8 / Apple M4 Pro, 12 CPUs, 24 GiB, macOS
27.0.1 (26A434), Go 1.27.1 `darwin/arm64`; dedicated cached PostgreSQL
18.6, `shared_buffers=128MB`, `max_connections=120`, 2 GiB tmpfs data,
3 GiB memory limit, dynamically allocated loopback port. Pools allow
20/10/10 connections. Harness settings use 8 MiB/one-pass Argon2,
RSA-2048, no password timing floor and local email/SMS sinks. Source
budgets retain harness values: login/send per IP 10000, sends per
identifier 50/hour with a one-second cooldown, tokens per client
10000/minute; realm/client verification limits retain configuration
defaults. Source digest `d5f3fe38b61f4a4e`, no Git commit. The full offline
race-detector command passes: **E2E 748.725 seconds**, complete contract
package **32.698 seconds**; all 42 packages with tests pass and 32 have no
test files. **689 top-level tests and 462 subtests** pass, with none failed
or skipped, including all 23 benchmark smoke scenarios and pool checks.
The full run uses loopback port 56309 with the same PostgreSQL settings.
Four refreshed evidence rows match the complete isolated preview; the
protected contract test remains unchanged.
[Structured results](consistency-results/2026-10-12-otp-budgets.json)
record frozen files, exact commands and per-profile durations. A final
fixture-only refinement excludes accidentally correct phantom codes
using their private verifier. The production code and assertions are
unchanged; all five profiles pass three more repetitions (**25.725 seconds**,
3 top-level executions and 15 subtests). Earlier full/targeted test hashes
remain recorded alongside this final fixture check. Cleanup
traps remove each dedicated database container; raw logs and all fixture
secrets stay private and are removed after verification.

This is one laptop's correctness evidence. It does not measure production
hashing, provider delivery latency, multiple machines, sustained guessing
throughput or physical network faults. Earlier capacity artifacts retain
their own builds. Finish the server rollout before relying on the shared
limit; [upgrade guidance](upgrades.md#mixed-version-window) explains the
old counter namespace and verification-window caveat.

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  GOFLAGS='-mod=readonly -buildvcs=false' \
  go test -json -race -count=3 -failfast -timeout=5m ./tests/e2e \
  -run '^(TestReplicaOTPGuessBudgets|TestBenchOTPGuessesShareAccountBudget|TestHOTP|TestPasswordlessAndAbuseBudgets|TestVerificationBudgetPerClient|TestReplicaRecoveryConsumptionStress)$'
```

## SCIM Group query work and scan boundaries — 2026-10-12

[scim_group_list_work_test.go](../../tests/e2e/scim_group_list_work_test.go)
and [scim_scan_boundary_test.go](../../tests/e2e/scim_scan_boundary_test.go)
cover PROV-002, PROV-004, PROV-008, NFR-004 and NFR-006. The pre-fix
Group regression failed in **2.583 seconds**: 8 managed Groups used
**17** database round trips and 64 used **129**, with or without returned
members. Valid data/projection checks still passed. The fixed scan uses
**three** at both sizes, with exact member-dependent totals and identical
individual-read content/ETags. Missing or foreign organization mappings
cannot widen the result set.

Metadata is read in one scoped batch; ordered member rows are streamed
through one Group's collection at a time. Empty Groups are included and
only the requested matched page is retained. Database errors invalidate
the scan rather than returning a successful partial total/page. Existing
locked-table/statement-timeout regressions remain passing.

| Boundary profile | Required result | Result |
| --- | --- | --- |
| 20,000 managed Users | Exact total 20,000; a requested 1000-row page is clamped to 200. | Pass |
| 20,000 managed Groups | The same full total/page bound, including empty member collections. | Pass |
| 20,001, either type | Unfiltered and compound `and`/`or`/`not` scans return `400 tooMany`, without resources or a partial total. | Pass |
| Indexed equality above the bound | `id`/`externalId` and `userName` (Users) or `displayName` (Groups) return the exact owned resource with bounded query work. | Pass |
| Concurrency 32 above the bound | Per type, 16 broad/compound refusals and 16 exact indexed successes; no successful truncated scan. | Pass |

The large boundary rows are direct SQL fixtures in isolated databases,
not API seeding or capacity measurements. No rate counter is reset.
All eight backend cases pass three race-detector repetitions:
**24 top-level executions, 30 subtests, 71.106 seconds**. The complete
benchmark smoke also passes (**48.164 seconds**, all **24 scenarios**),
including `complex-group-filter`; its live fixture regression passes
separately (4.713 seconds). A new tool fixture initially read nested
metadata through a top-level accessor and was corrected before measurement.
Bench/provisioning unit/race checks and vet pass.

[Structured results](consistency-results/2026-10-12-scim-group-scans.json)
record per-case durations and frozen files. Source digest
`cb89a7606b47c21d`, no Git commit. Same Mac16,8 / M4 Pro, 12 CPUs,
24 GiB, macOS 27.0.1 (26A434), Go 1.27.1; dedicated cached PostgreSQL
18.6, `shared_buffers=128MB`, `max_connections=120`, 2 GiB tmpfs and
3 GiB memory limit, random loopback ports. Harness settings are reduced
Argon2/RSA and local sinks as above. Full offline verification has not
yet been rerun on this build.
The complete contract package passes with the race detector (**28.439
seconds**) after six evidence rows were refreshed. The protected
traceability test remains unchanged. Formatting and repository secret/
license checks pass.
Cleanup traps remove each database container; private logs and fixtures
are removed after final verification. This is
one laptop's correctness evidence, not sustained multi-machine capacity.

## Audit prefixes, compound pages and cursors — 2026-10-12

The audit search regressions cover AUD-006, AUD-011 and API-004. Before
the correction, a literal underscore prefix returned six events instead
of two, a percent prefix six instead of one, and a backslash prefix none
instead of one. SQL `LIKE` now escapes those characters before adding
the trailing prefix wildcard.

Audit cursor MACs previously bound only realm and organization. Thirteen
changed-filter profiles and a different audit route accepted the original
cursor. Canonical URL encoding now binds the route and filter values as
well as the authorized scope. Removing any of fourteen filters or changing
the route gets `400`; changing page size remains valid. Older development
cursors restart from the first page ([upgrades](upgrades.md)).

Controlled audit rows differ in realm, organization, type, actor, subject,
target, client, request, grant, session, category, outcome, network or
inclusive/exclusive time. Their conjunction returns exactly nine original
events across bounded sequence pages, without duplicates or rows inserted
after the first page. The foreign realm row and other organization remain
excluded. These direct isolated database fixtures prove search behavior,
not public reporting throughput.

Six audit cases pass three race-detector repetitions: **18 top-level
executions, 57 subtests, 24.627 seconds**, with no failures or skips.
The new public-report benchmark fixture passes all seven profiles nine
times (**3.104 seconds**); the complete smoke passes all **25 scenarios**
(**49.248 seconds**). Bench/audit unit/race checks pass (**13.422 / 4.502
seconds**). [Structured evidence](consistency-results/2026-10-12-audit-filters.json)
records failures and frozen files. Production digest `33f1e749e5cbf702`,
development build, no Git commit. Correctness runs use the same laptop and
harness profile above, with dedicated cached PostgreSQL 18.6 containers,
128 MB shared buffers, 120 connections, 2 GiB tmpfs and 3 GiB memory limit.
The full-module result remains on its earlier recorded build; it has not
been rerun for this checkpoint. The complete contract package passes with
the race detector (**36 top-level tests, 27.762 seconds**, no failures or
skips) after six evidence rows were refreshed from a complete isolated
preview. The protected traceability test is unchanged. Vet, formatting and
secret/license checks pass. Cleanup traps remove each owned database;
private fixtures/logs are removed after final verification. No independent
review or multi-machine capacity follows from these checks.

## Metadata/JWKS fetch bounds — 2026-10-12

Real loopback HTTPS bursts cover FED-017 and NFR-006, with explicit test
CA trust and a `127.0.0.1/32` egress allowlist. Before the correction,
32 concurrent cold discovery or unknown-key calls made **32 outbound
fetches**; their next eligible burst brought the count to **64**. Invalid
discovery/JWKS JSON made **32 / 64 / 96** cumulative fetches across an
initial, same-window and next-window burst, instead of **1 / 1 / 2**.
The pre-fix package failed in **3.088 seconds**.

OIDC metadata, workload JWKS and Shared Signals JWKS now share bounded
fetches and retain negative-response retry budgets. Successful cache TTLs
remain one hour, five minutes and ten minutes respectively; each cache
identity/process may retry once a minute after completion. Known valid
keys remain usable within their normal TTL. Workload transport/status
fallback retains the last good set; malformed/oversized/empty responses
do not enable that fallback after expiry. Transmitter signature retries
also respect the minute. Administrative provider updates/fresh diagnostics
explicitly invalidate their caches.

Nine OIDC profiles prove cold/expired and unknown-key behavior, bad JSON,
issuer mismatch, refused redirect, oversized body, HTTP failure, timeout
and recovery. The shared-cache tests prove independent identities, caller
cancellation without cancelling healthy waiters, generation invalidation,
timeout cooldown, bounded DNS and actual idle-connection cleanup through
the trace wrapper. Workload and Signals bursts verify their own fallback/
signature-refresh semantics. All four packages pass three race-detector
repetitions: **39 top-level checks, 51 subtests**, no failures/skips;
egress **1.687s**, federation **5.608s**, workload **1.776s**, SSF **1.707s**.

Six existing public-API cases also pass three repetitions: **18 top-level
executions, 36 subtests, 36.488 seconds**. Mandatory SSO retries retain
the upstream error without fetching again or offering a local password;
after a controlled minute, exactly one fetch restores the redirect.
The original immediate-recovery fixture expectation was updated to assert
this cooldown and recovery explicitly.

[Structured results](consistency-results/2026-10-12-metadata-fetches.json)
record counts, frozen source hashes and environment. Development production
digest **`202b6eeb35806acd`**, no Git commit. Same Mac16,8/M4 Pro, 12 CPUs,
24 GiB, Go 1.27.1; local TLS fixtures and fake DNS open no external
connections. Public API cases use isolated cached PostgreSQL 18.6 with
128 MB shared buffers, 120 connections, 2 GiB tmpfs and 3 GiB memory limit;
the harness uses reduced crypto and a controlled clock. Earlier full-module
and benchmark measurements retain their own builds; neither was rerun for
this checkpoint. **These bursts are correctness/resource-bound evidence,
not sustained metadata capacity or multi-process aggregate limits.**
The complete contract package passes with the race detector: **36 tests,
32.574 seconds**, no failures/skips, after five evidence rows were refreshed
from the complete isolated preview. The protected traceability test remains
unchanged. Vet, formatting and secret/license checks pass. All owned
database containers and private work are removed after final verification.
Independent review remains open.

## Remaining coverage

Ownership, role grant/edit/revoke and conditional SCIM/admin User/Group writes now
have cross-replica burst evidence alongside recovery, invitations, refresh
rotation and concurrent session/account-wide revocation.
Paged full/incremental LDAP and mapped Group sync now have replica evidence,
including competing schedules and a stalled worker returning after lease
takeover, plus OS-killed worker-task recovery for full/incremental sync.
Loopback transport interruption now covers complete-source failover deletion
and exhaustion that cannot deprovision from partial data.
Shared email/SMS/HOTP guessing bursts now enforce a common account limit
across source IPs and replicas, with exact stored failures/audits and
controlled next-window recovery. Sustained OTP attack capacity and real
elapsed-time window rollover remain unmeasured beyond the published TOTP
baseline.
This does not establish real AD/OpenLDAP interoperability or
remote multi-worker connector delivery capacity. Longer mixed
Group/shared-SSO load and failure coverage remain open. The other
consistency cases across separate server processes, multiple machines, network faults,
database failover during these races, multiple tenants/workers, realistic
hashing and multi-hour stress remain outside these tests. Existing
[capacity measurements](benchmarks.md#reference-results) and
[restore drills](backup-restore.md) retain their own scopes and limits.
