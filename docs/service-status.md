# Service capability inventory

This inventory records the source snapshot before repository separation. SDK
implementation references describe the original monorepo; the ecosystem migration
is tracked in [repository-migration.md](repository-migration.md). Pre-release and
external-review limitations remain applicable.

The language-SDK Make commands in this archived inventory describe that
snapshot. Current service commands are `make build`, `make test`,
`make test-unit`, `make test-e2e`, `make image VERSION=<version>` and the documented
benchmark/deployment entry points. SDK commands now run in the individual
[public SDK repositories](integrations/sdk-compatibility.md); the service owns
`tests/fixtures/sdk-contracts` and imports a pinned Go SDK module. The repository
split's [local verification](operations/release-results/2026-10-13-repository-split.json)
is separate evidence from the older inventory below.

ProudAuth is a self-hosted identity provider and OAuth 2.0 / OpenID Connect
authorization server written in Go. It runs as a modular monolith
(`identity-server`), a background worker (`identity-worker`) and an operator CLI
(`identity-cli`) on top of PostgreSQL. Applications delegate sign-in, account
lifecycle, organizations and token issuance to it; resource servers verify its
tokens and keep enforcing their own business authorization.

The product specification is [docs/plan.md](plan.md). Requirement IDs used
throughout the code and documentation (for example `TOK-002`, `IMP-010`,
`TEST-060`) refer to that document.

## Project status

The website and documentation renderer move to the standalone website repository.
This service snapshot retains the specification, runbooks and API contracts.

- **Pre-release (0.x).** 0.2.0 prereleases are published, starting with
  `v0.2.0-alpha.1` on 2026-10-13, as
  [GitHub Releases](https://github.com/proudauth/proudauth/releases) and images at
  `ghcr.io/proudauth/proudauth`. APIs, schema and configuration can still change
  between prereleases; [CHANGELOG.md](../CHANGELOG.md) lists each one.
- **Not independently reviewed.** No external security review has been performed
  (SEC-018, QA-005). Do not treat this software as hardened for production use.
- **No certification.** Nothing has been submitted to an OpenID or FAPI conformance
  suite, and the project holds no certification (QA-006). See
  [docs/integrations/interoperability.md](integrations/interoperability.md#conformance-claims).
- Only a subset of the specification is implemented. The table below and
  [CHANGELOG.md](../CHANGELOG.md) list what exists and what does not.

## What "free" means

ProudAuth is licensed under [Apache-2.0](../LICENSE). "Free" means there is no
software license fee and no feature is gated behind payment (OSS-009). Running it
still costs money: compute, storage and backups, domain names and TLS, email
delivery, SMS if you add it, hardware security modules if you use them, and the
operational labor of running an identity provider safely.

## Commitments

These are project rules (plan.md §2.1) and the current state of the code:

| ID | Commitment | State in this repository |
| --- | --- | --- |
| OSS-001 | One complete edition | There is one source tree and one build. No `ee/` directory, no build tags that remove features. |
| OSS-002 | No commercial unlocks | No license server, activation key or usage counter exists in the code. |
| OSS-003 | No mandatory vendor cloud | Startup, login, key rotation, backup tooling and administration call no project-operated service. |
| OSS-004 | Complete source | Server, worker, CLI, SDKs, migrations, Dockerfile, Compose file and tests are in this repository. |
| OSS-005 | Offline operation | Core operation needs PostgreSQL and, for email, an SMTP relay you choose; `TestOfflineOperation` runs bootstrap, sign-in, token issuance, administration and every worker task with outbound network blocked (TEST-072). See [docs/operations/offline-install.md](operations/offline-install.md). |
| OSS-006 | No hidden telemetry | No telemetry sink exists. `privacy.telemetry_opt_in: true` is a configuration error. Metrics are served only on your internal listener, and spans are exported only to an OTLP endpoint you configure. Challenge providers are contacted only when you configure one. |
| OSS-007 | Operator-controlled limits | Rate limits, payload, metadata and page sizes, batch sizes, invitation and client-secret limits are configuration keys ([docs/operations/configuration.md](operations/configuration.md)). |
| OSS-008 | Portable exit | A realm data export (`POST /data-exports`) writes accounts, organizations, memberships, groups, role assignments, policies, projects, integrations and the configuration as NDJSON with stable IDs; configuration and audit exports complete it. Credential secrets and live tokens are left out, and the file lists what it excludes ([docs/operations/exit-and-export.md](operations/exit-and-export.md#realm-data-export)). |

## Feature status

"Implemented" means there is code, an HTTP route or CLI command, and at least one
test. "Not implemented" may mean that a database table or configuration key
exists without behavior behind it; those are listed explicitly so they are not
mistaken for features.

| Area | Implemented | Not implemented |
| --- | --- | --- |
| OAuth / OIDC | Authorization code with mandatory PKCE `S256`; refresh-token rotation with reuse detection; client credentials; device authorization (RFC 8628); token exchange (RFC 8693, access-token subjects only); PAR (RFC 9126); DPoP proofs at the token endpoint (RFC 9449); resource indicators (one audience per token); introspection (RFC 7662) restricted to registered resource servers; revocation (RFC 7009); OIDC discovery and RFC 8414 metadata; JWKS; UserInfo; OIDC `claims` parameter (narrows ID-token and UserInfo release; `acr` requests raise assurance); `prompt=select_account`; RP-initiated logout (reporting, and on request redirecting to, the upstream provider's logout); back-channel logout; `iss` authorization response parameter (RFC 9207); per-resource signing algorithm; scope step-up (required assurance and authentication age per scope, enforced at authorization, issuance and refresh); realm access-token lifetime limits by subject type and assurance; pairwise subjects per reviewed sector; claim mappings from approved user and profile attributes (no expressions, attribute values only with the `profile` scope), separate for ID and access tokens; fixed client environments (development, staging, production) with token exchange refused across environments; token exchange bounded by the organization's scope ceiling and scope permissions; front-channel logout; encrypted ID tokens and signed or encrypted UserInfo; JARM (`query.jwt`); dynamic client registration (RFC 7591/7592, off by default, initial access tokens or approval); mTLS client authentication and certificate-bound access tokens (RFC 8705); a FAPI 2.0 client profile (not certified, no conformance-suite run) | Implicit and password grants (excluded by design); JAR request objects; CIBA; `form_post` and `fragment` response modes; request-level DPoP/certificate enforcement in Node.js, Dart, PHP and .NET (Go `SenderVerifier` supports both; all ordinary SDK paths reject bound tokens) |
| Sign-in | Headless authentication transactions (identify, password, email OTP, SMS OTP, magic links, TOTP, HOTP, passkeys, X.509 certificates through mutual TLS or a trusted proxy, recovery code, required actions, profile completion against a realm attribute schema, organization and account selection, consent); browser flow through an application-provided login UI with cookie + CSRF protection and concurrent transactions per browser; remembered devices (opt-in MFA prompt skip that adds no assurance); transient sessions; guest identities (realm policy `registration.allow_guests`, anonymous assurance, no organization access) upgraded in place to registered accounts; temporary password lock; pre-action hooks for registration eligibility and profile validation; realm authentication flow rules (by client, organization, method, resource, network, device, recent failures, privilege, assurance and risk-hook signals) that allow, require MFA or phishing-resistant MFA, challenge, send for review or deny, with operator-configured challenge providers and an emailed-code alternative; required actions guarded by per-action permissions | Cross-device magic links; a built-in risk engine or challenge provider |
| Passkeys | WebAuthn registration and assertion (`go-webauthn`), discoverable (username-less) and identified sign-in, synced-passkey counter handling, phishing-resistant profile for administrators, self-service management; attestation policy with a privacy-preserving default (no attestation requested), trusted attestation against an operator FIDO metadata BLOB or realm trusted authenticators, authenticator allow and block lists enforced at registration and sign-in; operator-gated WebAuthn Level 3 related origins; `credProtect` ([docs/operations/passkey-trust.md](operations/passkey-trust.md)) | Hardware and platform authenticator testing (attestation is tested only with a software authenticator); loading a real FIDO metadata BLOB is untested; PRF, `largeBlob` and other extensions |
| Federation | Upstream OpenID Connect and GitHub-style OAuth 2.0 connections through adapters (`oidc`, `github`, `google`, `microsoft`, and operator-built ones registered in code) that fix each provider's identifier and email semantics: PKCE, state/nonce/issuer validation, JIT provisioning with organization membership, account linking with proof of control of the local account, tenant and email-domain restrictions, trusted upstream MFA, SSO-mandatory organizations without password fallback, organization-scoped connections managed by organization administrators, self-service linked identities; upstream logout on request; SAML 2.0 (off by default, `saml.enabled`) as identity provider for SAML applications (SP-initiated SSO over Redirect and POST, per-application persistent NameIDs, attribute mapping, optional encrypted assertions, IdP-initiated SSO opt-in, signed SP-initiated logout reporting partial logout) and as broker for enterprise SAML connections (signed requests, pinned certificates with rollover overlap, replay and wrapping defenses), with a separate SAML key set per realm ([docs/integrations/saml.md](integrations/saml.md)); LDAP/Active Directory sign-in by bind with failover and fail-closed outages ([docs/integrations/directory.md](integrations/directory.md)) | Upstream products beyond the published Keycloak 26.8.0 OIDC/SAML profiles; real LDAP/Active Directory deployments (directory tests use controlled servers); SAML Artifact binding, SOAP, ECP, metadata fetching and signing, IdP-initiated logout, encrypted assertions at the broker; Kerberos/SPNEGO; SASL binds |
| Accounts | Registration modes (public, closed, invitation-only, domain-restricted) at realm and organization level; registration approval queue (`registration.require_approval`); email verification; password reset; administrator-created accounts with one-time setup tokens; custom profile attributes (realm policy `profile.attributes`); self-service profile, identifiers (with verification challenges), sessions (with device labels), remembered devices, consents (with terms versions and history; administrators can view and revoke them and pre-authorize third-party clients for the realm or an organization), account activity (`GET /me/activity`), effective permissions, notification preferences for optional notices, deletion request, data export; administrator revocation of one session or all; per-realm concurrent-session limit and per-client maximum session age; account merges confirmed by both owners and executed by an administrator, with subject aliases and a `user.merged` event; lifecycle jobs with a dry-run preview (dormant-account report or suspension, unused guest and unverified-registration clean-up, scheduled deactivation); external IDs per source system; required action `verify_contact` to re-confirm the contact address at sign-in; optional audit evidence of administrative account reads; profile attribute visibility (`self`, `admin`, `internal`); account deletion refused while the account owns projects, clients, service principals, resources or connections, with a one-call ownership transfer | Moving the merged-away account's grants, consents, credentials or roles (excluded by design; the merge plan lists roles and credentials for review) |
| Credentials and MFA | Argon2id password verifiers with rehash; imported salted SHA-256, bcrypt (cost 10–15) and PBKDF2 (10,000–2,000,000 iterations) verifiers accepted until an operator deadline (`security.password.legacy_hashes_until`) and rehashed at sign-in; an operator MFA floor that realm policies cannot lower (`security.mfa_floor`); length-based policy with an embedded common-password list and an optional operator list; optional pepper; TOTP; HOTP (RFC 4226, opt-in per realm, with resynchronization); passkeys; X.509 certificates bound to accounts (smart cards can count as phishing-resistant MFA); recovery codes; recovery-restricted sessions and account state (reads, factor enrollment and ending sessions only, until TOTP or a passkey is used or enrolled); adding a factor requires an MFA session when one is enrolled; administrator-assisted recovery with optional cooling-off period and second-operator approval | Security questions (excluded by design); OCSP and CRL fetching for certificates |
| Organizations | Organizations, memberships (including `invited` and `pending_approval` states), invitations (secret rotation on resend, non-consuming inspect, bulk creation, administrator reassignment, binding to the account that held the address, project-access invitations backed by project grants, per-organization and per-recipient budgets), join requests with expiry, reviewer assignment, withdrawal and notices, groups with cycle and depth limits (adding members and moving groups need the authority to assign every role of the group chain), DNS TXT domain verification (a domain another organization holds verified ends in `conflict`) with periodic re-verification and opt-in subdomain routing (exact domains win), aliases that keep former slugs resolving, versioned onboarding templates (policy, roles, groups, organization-owned service principals without credentials, organization webhook subscriptions) with dry run and conflict reporting, dynamic groups derived from administrator-controlled profile attributes (audited per member; roles withheld when the group's recomputation is stale), ownership transfer, last-owner protection, asynchronous deletion with a preview that also disables the organization's integrations at once, per-organization sign-in and token issuance budgets and fair shares of worker capacity, organization scope ceilings (`allowed_scopes`); organization switches held to the target organization's SSO, sign-in method and session-lifetime rules | Templates for clients, identity providers and credentials |
| Authorization | Scoped RBAC with built-in roles, delegation ceilings, composite roles, incompatible roles checked through groups, ancestor groups and composites, membership-scoped assignments, conditional assignments (client, resource, assurance, authentication age, time windows); scopes that require permissions; two-party approval for roles marked `requires_approval` (`/role-assignment-requests`; no end-to-end test yet); policy decision API (single and batch) with step-up obligations and a cache contract (`cache_key` covering token evidence and the applicable assignments, `cache_ttl_seconds` up to 10 minutes) for RBAC-only decisions; versioned ABAC policies that can only restrict RBAC (approval, publish, diff, rollback); policy simulation (`/authorization/simulate`); authorization hooks that can deny but never grant; permission inspection with provenance (realm, organization, self); decision audit with optional sampling of ordinary allows, and audited refusals of administrative requests; bounded relationship-based authorization (registered resource types, relationship tuples per organization, object-level decisions, `list-objects`, sharing of objects between users of an organization, which is not UMA); external policy engines (operator-configured, `restrict` or `decide` mode, fail closed by default); just-in-time role elevation with approval and automatic expiry; access review campaigns with evidence export (not a certification); inactive accounts and service principals hold no permissions | Zanzibar-style consistency tokens, caveats or watch APIs for relationships; an embedded policy engine |
| Support impersonation | Request, optional approval (second operator, organization owner or the customer in self-service), issue, revoke, destination-bound handoff codes, customer visibility and opt-out; capability conditions on operator role assignments (organizations, target categories, modes, scopes); opaque 5-minute tokens validated online on every introspection; one operation classification shared by the SDKs and the decision API, with a per-resource write allowlist (`impersonation_policy.write_actions`) | See [docs/threat-models/impersonation.md](threat-models/impersonation.md) for residual gaps |
| Machine identities | Service principals, client credentials, scoped API keys, personal access tokens (bounded by the owner's current authority and organization policy), credential inventory with risk flags and bulk revocation, one expiry notification per credential; owner-departure policy for service principals (report, or disable after a grace period); an ownership report of integrations without an accountable owner; workload identity federation (RFC 7523 `jwt-bearer` with GitHub Actions, Kubernetes, SPIFFE JWT-SVID and generic issuer profiles, no stored secret); mutual-TLS client authentication and certificate-bound tokens; agents (service principals with an accountable human owner, two-party approval of privileged roles and an `agent` token claim); acting on behalf of users only through token exchange | Workload assertions that represent users; testing against real CI systems, clusters or SPIFFE deployments |
| Evidence | Audit events written in the same transaction as the change; append-only trigger; corrections as new linked events (`POST /audit-events/{id}/corrections`); secret redaction; hash-linked batches signed with an Ed25519 key derived from the root key; retention per category, extendable per realm and organization, with legal holds, that records pruned batches so the chain still verifies and that, with separate database roles, the service's credentials can only run through an owner-run pruning function; write-once archive of sealed batches to an operator-mounted directory, verifiable without the database (`identity-cli verify-audit-archive`), that retention waits for and that continues in a fork directory after a database restore; historical audit records imported from a previous system, kept apart from local evidence, labelled unverified, redacted and included in the personal data export; chain verification (CLI, API and an hourly worker check); scoped query by actor, subject, target, client, session, grant, category, network and time; NDJSON export; application activity reported by services, kept apart from server evidence; security-signal metrics and `security.alert` webhook events; audit backlog and integrity metrics | Built-in upload to object storage or WORM services (the archive writes to a directory you mount) |
| Integrations | Integration patterns for HTTP, GraphQL, gRPC, WebSockets, streams, jobs, message consumers and multi-issuer services ([docs/integrations/patterns.md](integrations/patterns.md)); signed webhooks with retries, dead-lettering, replay, secret rotation and a per-subscription backlog view; event catalog with JSON Schemas (`api/events`); SSRF-restricted egress with per-subscription private-network opt-in; synchronous pre-action hooks (registration eligibility, profile validation, token-claims enrichment, authorization decisions, authentication risk; signed, fail-closed for security decisions; per-hook diagnostics with latency and error categories); session-event stream (`GET /session-events`, long-poll with resumable cursor, SES-019); lifecycle workflows (event, schedule and manual triggers; approval, role, group, removal, notice, endpoint-call and suspension steps; publisher accountability under the delegation ceiling; durable, idempotent runs with compensation; [docs/integrations/workflows.md](integrations/workflows.md)); signed plugins bundling hooks, webhook subscriptions and workflows, with operator-trusted publisher keys, second-administrator review, install, upgrade, rollback and emergency disable ([docs/integrations/plugins.md](integrations/plugins.md)); independently versioned extension contracts (webhook `event_version` 1 and 2, hook `contract_version` with `ProudAuth-Hook-Version`, `GET /extension-contracts`; [docs/integrations/extension-contracts.md](integrations/extension-contracts.md)) | Embedded or sandboxed code execution (excluded by design, [ADR 0021](architecture-decisions/0021-no-embedded-code-execution.md)); workflow conditions and loops; plugin parts other than hooks, subscriptions and workflows; plugins and workflows in the configuration and realm data exports |
| Provisioning | SCIM 2.0 inbound provisioning of users and groups ([docs/integrations/scim-provisioning.md](integrations/scim-provisioning.md)): per-organization connectors with their own bearer token, allowed resource types and a role ceiling within their creator's; filters, PATCH and ETags (no bulk or sort); connector-scoped external IDs; existing accounts adopted only through a domain the organization verified; deprovisioning that suspends or removes only the organization's membership; roles only through approved group mappings; per-connector evidence (last sync, last error, counters); bounded, resumable user import jobs in a declared format (`GET /user-import-formats`) with a dry-run plan, conflict reporting that never merges accounts by identifier, and totals (Argon2id with capped parameters, bcrypt, PBKDF2 and salted SHA-256 verifiers; TOTP seeds with explicit authorization; names, locale, suspended state, required actions and administrator metadata; mapped roles limited to the requester's delegation ceiling; deleted accounts never recreated; submitted records encrypted and erased after the job); a reconciliation report per source system; a migration runbook ([docs/operations/migration.md](operations/migration.md)); first-party migration adapters for Keycloak 26.x, ZITADEL v4.x and SuperTokens core 12.x (`identity-cli migrate-from`, `GET /migration-adapters`, `POST /migration-plans`) with a reviewed role mapping and a capability report of what converts, converts with loss or is unsupported ([docs/operations/migration-adapters.md](operations/migration-adapters.md)); bulk suspend, reactivate, lock, session revocation and required actions for up to 1000 accounts per job, with dry run and a per-account report; LDAP/Active Directory synchronization for realm (workforce) and organization connectors with full and incremental runs, dry runs, conflict reports, a deletion threshold and read-only, import-only or write-back attribute authority enforced on every edit path; outbound SCIM 2.0 provisioning with retries, dead-lettering and reconciliation; connector health and evidence ([docs/integrations/directory.md](integrations/directory.md), [docs/integrations/outbound-provisioning.md](integrations/outbound-provisioning.md)) | Password and identifier write-back to directories; nested directory groups; SCIM bulk operations (inbound and outbound) and sorting; outbound SCIM extension schemas; migration adapters for other products or major versions; imports that update existing accounts; migrating passkeys, identity-provider links, phone numbers and sessions |
| Delivery | SMTP; SMS through an operator-run HTTPS gateway (signed requests, country allowlist, daily budget, explicit realm risk acceptance; the gateway adapter is unit-tested against a local HTTP server, end-to-end tests use the development sink); development sink for email and SMS; per-realm/organization templates and sender settings (sender domains approved by the operator or verified by the organization); an organization's own SMTP server with an encrypted, organization-bound password; signed bounce/complaint callbacks that suppress optional notices; SMTP configuration check; notices in the recipient's locale and time zone | Direct carrier/provider integrations |
| Operations | Benchmark suite `identity-bench` (workload, adversarial, stress and soak scenarios with portable JSON results; published laptop reference numbers and a reproducible offline runner ([benchmarks.md](operations/benchmarks.md#reference-results))); Docker image (release workflow publishes it by digest with SBOMs, provenance attestations and a keyless cosign signature); Compose development stack; Kustomize manifests (`deploy/kubernetes`); offline bundle (`make bundle`); migrations with advisory lock, checksum checks, per-migration lock and statement timeouts with bounded retries, no-transaction migrations for concurrent index builds (invalid indexes rebuilt), mixed-version window and safety gates (read-only `migrate -plan`, `-backup-reference` for contract migrations, preconditions), audited also when applied at startup; a CI lint for blocking and destructive migration DDL; warnings for migrations applied out of order; database-enforced realm boundaries for role assignments; health/readiness (including clock-skew check and a draining phase on shutdown); graceful worker shutdown that hands back held work; Prometheus-format metrics on the server and, optionally, the worker, including the age of the oldest due notification, webhook delivery and job; W3C `traceparent` propagation to hooks and upstream providers (sampling requested only by trusted proxies), span export of server requests and worker task runs over OTLP/HTTP, and request IDs in webhook events; `/status` with per-capability state, backlogs, key provider and residency (behind `server.metrics_token` when set); delivery outcome metrics for webhooks, notifications and back-channel logout; maintenance mode (`restricted`, `unavailable`); audited emergency controls for grant classes, clients, identity providers, organizations, service principals, hooks and webhooks; time-limited, audited debug logging windows; `identity-cli config-diff`; support bundle; revocation log export and restore reconciliation; configuration-as-code validate/import/export (import needs the permission of every change; optional reconcile of existing clients, resources and roles); a realm data export for portable exit; retention of ended grants, sessions and operational history; secret references `file:`, `env:`, `cred:` (systemd) and `vault:` (HashiCorp Vault KV v2); root, pepper and signing-wrap keys wrapped by any KMS or HSM with a command-line client (`kms:`, unwrapped into memory at start-up); separate schema-owner and runtime database roles; verified realm custom domains with optional strict `Host` checking; a data residency allowlist for outbound connectors; a per-account deletion propagation report | Helm chart; signing or decryption inside an HSM; built-in KMS clients; a metric for dropped spans |
| API contracts | OpenAPI document (`api/openapi/proudauth.yaml`), configuration and import JSON Schemas (`api/schemas`), event schemas (`api/events`, versions 1 and 2) with a `correlation_id` linking events to the causing request; pre-action hook, plugin and lifecycle workflow schemas (`api/hooks`, `api/plugins`, `api/workflows`), versioned independently with schema-validated compatibility tests; a compatibility and deprecation policy ([docs/protocols/compatibility.md](protocols/compatibility.md)); contract tests check that documented routes equal registered routes and that the configuration schema covers every deployment key | Generated clients |
| SDKs | Go: resource-server verifier (offline, introspection and bounded-state modes, multi-issuer, `net/http` middleware and metadata authentication for gRPC, WebSockets and message headers), support-access guard, OIDC/BFF client, admin client (0.2.0, one-time secrets wrapped, deprecation reporting). Node.js/TypeScript (`sdk/node`, 0.2.0 on npm as `@proudauth/sdk`): the same areas plus Express/Connect, `node:http` and Fastify adapters, unit-tested in CI against local mock HTTP servers only. Dart (`sdk/dart`, unpublished 0.2.0, Dart 3.4+, no Flutter dependency) and PHP (`sdk/php`, unpublished 0.2.0, PHP 8.2+): the same areas, with a framework-neutral bearer helper plus a `dart:io` adapter (Dart) and a request authenticator for plain PHP and PSR-15 (PHP), unit-tested in CI without a ProudAuth server. .NET (`sdk/dotnet`, unpublished 0.2.0, .NET 8+): the same areas, with ASP.NET Core authentication and middleware. Shared accepted/rejected access-token and support-operation fixtures (`sdk/fixtures`) that all five SDKs and independent verifiers run; `identity-cli config-export`, `config-plan` (with drift) and `config-apply`; a compatibility and security-update policy ([docs/integrations/sdk-compatibility.md](integrations/sdk-compatibility.md)) | Other languages (Python, Java, Ruby, Rust, Swift, Kotlin); Flutter/mobile sign-in (the Dart SDK is for backends); a webhook signature verifier; framework adapters beyond those listed |
| Sign-in policy history | Versioned authentication flow definitions with reachability and bypass analysis, simulation against the live flow, publication only from a current base, and rollback; bypass paths refused on every flow change ([docs/protocols/authentication-flows.md](protocols/authentication-flows.md)); OpenID Connect Session Management 1.0 (check-session iframe, `session_state`), opt-in per realm ([oauth-oidc-profile.md](protocols/oauth-oidc-profile.md#session-management-oidc-014)) | Session-management checks that survive third-party cookie blocking (a browser limitation); a built-in risk engine |
| Security events | Declared OpenID Shared Signals Framework 1.0 transmitter (CAEP and RISC events about each receiver's own users, push and poll), and a receiver for registered transmitters with replay defenses, subject mapping and explicit action policies ([docs/integrations/shared-signals.md](integrations/shared-signals.md)) | Long polling; polling remote transmitters; conformance testing; tests against third-party SSF implementations |
| Cross-tenant and cross-system access | Organization relationships that grant nothing by themselves, and partner project access with owner-issued grants of a role subset ([docs/integrations/partner-access.md](integrations/partner-access.md)); federation transfer of account links to a new connection or upstream tenant through a reviewed, second-approved map ([docs/operations/federation-transfer.md](operations/federation-transfer.md)); container-registry token bridge (Distribution token protocol) ([docs/integrations/container-registry.md](integrations/container-registry.md)); historical entitlement reconstruction for investigations ([docs/operations/investigations.md](operations/investigations.md)) | Inherited access along organization hierarchies (excluded by design); registry catalog access; tests against real registries |
| Not offered (P3) | — | Push or out-of-band approval, CIBA, UMA, verifiable credential issuance and presentation, JAR request objects, with reasons ([docs/protocols/compatibility.md](protocols/compatibility.md#capabilities-not-offered)); active-active multi-region writes ([disaster-region recovery profile](operations/backup-restore.md#disaster-region-recovery-dep-019), [isolation tiers](operations/isolation-tiers.md)) |

## Quick start (development only)

`deploy/dev/` runs the image in `development` mode: plain HTTP on
`localhost:8080`, insecure cookies, a public development root key and a Mailpit
mail catcher instead of a real SMTP relay. Never expose it to a network.
PostgreSQL 18 persists its versioned data under `/var/lib/postgresql` in the
`pgdata` volume.

Requirements: Docker with Compose v2, and Go (version from `go.mod`) to build the
CLI locally.

```sh
# 1. Build the image and start PostgreSQL, Mailpit, Swagger UI, migrations, the
#    default realm, server and worker (deploy/dev/.env needs no editing).
make dev        # builds proudauth:dev, then runs deploy/dev on it

# 2. In another terminal, create the first administrator through the local
#    operator channel (the CLI inside the server container).
COMPOSE="docker compose -f deploy/dev/docker-compose.yaml"
$COMPOSE exec server identity-cli bootstrap -realm main -email admin@example.test -username root-admin
# -> prints a one-time setup token (default lifetime 1h, maximum 24h)

# 3. Build the CLI on the host, set the first password, then sign in.
go build -o bin/identity-cli ./cmd/identity-cli
./bin/identity-cli setup-account --url http://localhost:8080 --realm main   # prompts for token and password (15+ characters)
./bin/identity-cli login --url http://localhost:8080 --realm main           # identifier, password, TOTP enrollment, email code
```

The bootstrap administrator must enroll TOTP and verify the email address on first
sign-in. The verification code arrives in Mailpit at `http://localhost:8025`.

After login, `./bin/identity-cli users`, `orgs`, `invite`, `revoke-sessions`,
`clients`, `roles`, `assign-role`, `grant-scopes`, `sessions`, `invitations`,
`support-grants`, `permissions`, `config-export`, `config-plan`, `config-apply`
and `api METHOD /path [json]` call the administration API with the stored token. `identity-cli password-calibrate`
benchmarks Argon2id on the host and suggests parameters.

`make smoke` (with the stack running) checks liveness, readiness, discovery, JWKS
and that the password grant is refused.

The authorization endpoint redirects browsers to a login interface that you
provide; set it with `identity-cli realm-create -login-ui-url ...` or the realm
policy `interaction.login_ui_url`. Without one, only the headless transaction API
can be used. See [docs/protocols/headless-authentication.md](protocols/headless-authentication.md).

Production installation is described in
[docs/operations/installation.md](operations/installation.md).

## Building and testing

```sh
make build      # go build -trimpath ./...
make test       # go vet ./... && go test -count=1 ./...
make test-unit  # ./internal/... and ./sdk/...
make test-e2e   # ./tests/...
make test-node  # Node.js SDK tests (cd sdk/node && npm ci && npm test)
make test-dart  # Dart SDK: dart pub get, analyze, format check, dart test
make test-php   # PHP SDK: php -l on every file, then tests/run.php
make test-dotnet # .NET SDK: locked restore, build and shared/security tests
make pack-dotnet # build local NuGet packages
make lint       # go vet, scripts/check-secrets.sh, scripts/check-licenses.sh
make vuln       # govulncheck
make sbom       # CycloneDX SBOM
make image      # container image
make fuzz       # short local fuzz runs (CI runs a larger set)
make bundle     # offline installation bundle in dist/ (scripts/offline-bundle.sh)
make k8s-validate  # render deploy/kubernetes/overlays/example with kubectl kustomize
make bench      # benchmark a running deployment (BENCH_URL, PROUDAUTH_BENCH_ADMIN_TOKEN; docs/operations/benchmarks.md)
```

CI runs the complete Go suite with the race detector and verbose test progress;
each package has a 30-minute deadline and the test job has a 45-minute deadline.
The full E2E package can exceed 20 minutes on a shared hosted runner.

Integration and end-to-end tests need a real PostgreSQL. They read
`PROUDAUTH_TEST_DATABASE_URL`, which must name a role allowed to `CREATE DATABASE`
(each test creates and drops its own database). **When the variable is unset those
tests are skipped and the run still reports `ok`.** Use `-v` and look for `SKIP`.

```sh
docker run -d --name proudauth-pg -e POSTGRES_USER=proudauth -e POSTGRES_PASSWORD=devpassword \
  -e POSTGRES_DB=proudauth -p 127.0.0.1:55432:5432 postgres:18.6
export PROUDAUTH_TEST_DATABASE_URL='postgres://proudauth:devpassword@127.0.0.1:55432/proudauth?sslmode=disable'
make test
```

`PROUDAUTH_TEST_LOG=1` prints server warnings from the in-process test harness;
`PROUDAUTH_TEST_KEEP_DB=1` keeps test databases for inspection. PostgreSQL 18.x
is the only supported version: CI and the Compose file run PostgreSQL 18.6. No
other versions are tested.
Contribution rules, fuzzing and review requirements are in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Repository layout

```text
cmd/identity-server/   public listener (protocol, interaction, self-service, admin APIs) + internal listener
cmd/identity-worker/   outbox, deliveries, jobs, key lifecycle, audit sealing, retention
cmd/identity-cli/      operator commands (local DB/key access) and API commands (OAuth login)
cmd/identity-bench/    benchmark tool: seeds a realm and measures a deployment through its public APIs
internal/              domain modules: authentication, authorization, oauth, token, keys, session,
                       organization, identity, impersonation, machine, audit, webhooks, egress, ...
migrations/            ordered SQL migrations embedded in the binaries
proudauth-sdk-*        Go, Node.js, Dart, PHP and .NET SDKs: separate repositories under github.com/proudauth
api/                   OpenAPI document, configuration/import JSON Schemas, event schemas
examples/              backend-for-frontend, protected-orders-api, protected-billing-api, machine-client
tests/e2e/             in-process end-to-end and security regression tests
tests/contract/        OpenAPI-vs-router and schema well-formedness checks
deploy/                dev/ and prod/ (Compose + .env; prod/ is the release installer), kubernetes/
scripts/               secret scan, license check, Compose smoke test, offline bundle
docs/                  specification, ADRs, operations, protocols, integrations, threat models
```

## Documentation

- Architecture decisions: [docs/architecture-decisions/](architecture-decisions/README.md)
- Operations (installation, configuration, keys, backup/restore, incidents, upgrades,
  monitoring, capacity and benchmarks, data inventory, revocation exposure, migration, export): [docs/operations/](operations/README.md)
- Protocols (identifiers, OAuth/OIDC profile, tokens, headless authentication, compatibility, signed and encrypted responses, mutual TLS): [docs/protocols/](protocols/README.md)
- Integrations (resource servers, integration patterns, BFF, machine clients, webhooks, SCIM provisioning, SDK compatibility, interoperability, lifecycle workflows, plugins, extension contracts, SAML, LDAP/Active Directory, outbound provisioning, dynamic client registration, workload federation, relationship-based authorization, policy engines, elevation and access reviews): [docs/integrations/](integrations/README.md)
- Threat models: [docs/threat-models/](threat-models/README.md)
- Security reporting: [SECURITY.md](../SECURITY.md)
- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md), [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

## License

Apache License 2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE). Third-party
dependencies keep their own licenses; `scripts/check-licenses.sh` enforces the
allowed set (Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0).
