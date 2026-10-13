# SDK compatibility, adapters and automation

Requirements: SDK-010 (dependency and compatibility policy), SDK-011
(framework adapters), SDK-012 (administrative automation). Code: `proudauth-sdk-go`
(`verifier`, `oidcclient`, `admin`), `proudauth-sdk-node` (`@proudauth/sdk`),
`proudauth-sdk-dart` (`proudauth_sdk`), `proudauth-sdk-php` (`proudauth/sdk`),
`proudauth-sdk-dotnet` (`ProudAuth.Sdk`, `ProudAuth.Sdk.AspNetCore`),
`cmd/identity-cli/config_cmds.go`.

All five SDKs have independently buildable public repositories and their own CI:

| Language | Source repository | Package identity |
| --- | --- | --- |
| Go | [proudauth-sdk-go](https://github.com/proudbase/proudauth-sdk-go) | `github.com/proudbase/proudauth-sdk-go` |
| Node.js/TypeScript | [proudauth-sdk-node](https://github.com/proudbase/proudauth-sdk-node) | `@proudauth/sdk` |
| Dart | [proudauth-sdk-dart](https://github.com/proudbase/proudauth-sdk-dart) | `proudauth_sdk` |
| PHP | [proudauth-sdk-php](https://github.com/proudbase/proudauth-sdk-php) | `proudauth/sdk` |
| .NET | [proudauth-sdk-dotnet](https://github.com/proudbase/proudauth-sdk-dotnet) | `ProudAuth.Sdk`, `ProudAuth.Sdk.AspNetCore` |

The source API version is **0.2.0**. npm, pub.dev, Packagist and NuGet packages
have not been published; public source availability does not establish registry
publication. PHP's Composer manifest now lives at its repository root, so a VCS
repository can consume it without a subtree split. The service pins the Go SDK
as a normal checksum-verified module dependency, without a local replacement.

[Pinned SDK evidence](sdk-repositories.json) records immutable source revisions,
successful independent CI runs, workflow bytes and shared-contract hashes. The
service contract checks that these fixtures match `tests/fixtures/sdk-contracts`;
its Go end-to-end tests exercise the published Go SDK against the service.
The latest .NET pipeline runs 344 tests on Linux, macOS and Windows, including
strict RS256 encoding and invalid EC-key rejection regressions. Historical
local-check tables below retain their original snapshot scope and counts.

## Supported runtimes

| SDK | Requirement | Tested with |
| --- | --- | --- |
| Go: `verifier`, `oidcclient`, `admin` in `github.com/proudbase/proudauth-sdk-go` | Separate module; `go 1.27.1` is its minimum Go version | Independent SDK CI runs tests with the race detector and both verifier fuzz targets; [exact source and run](sdk-repositories.json). Earlier monorepo checks below retain their historical versions |
| Node.js: `@proudauth/sdk` (`proudauth-sdk-node`) | `engines: {"node": ">=20.10"}`; ESM only; no runtime dependencies (`node:crypto`, `node:http` and the global `fetch`) | Independent CI passes on Node.js 20.10, 22 and 24 ([pinned snapshot](sdk-repositories.json)); earlier local Node.js 25.9.0/npm 11.12.1/TypeScript 5.9.3 results below retain their scope |
| Dart: `proudauth_sdk` (`proudauth-sdk-dart`) | `sdk: ^3.4.0`; runtime dependencies `crypto` and `http`; no Flutter dependency. Signature verification (RS256, PS256, ES256, EdDSA) is implemented in the package on `BigInt` (verification only, not constant-time: every input is public). Only `package:proudauth_sdk/io.dart` imports `dart:io` | Dart 3.13.3 locally ([results below](#local-sdk-checks--2026-10-13)) and configured in CI (job `dart-sdk`); 3.4 is declared, not tested. The development dependencies (`lints` 6.1, `test` 1.31) need Dart 3.8 or later to run the tests |
| PHP: `proudauth/sdk` (`proudauth-sdk-php`) | `php: >=8.2` with `ext-curl`, `ext-json`, `ext-openssl` and `ext-sodium`; no Composer dependencies (`ext-mbstring` is suggested for non-ASCII operation names) | PHP 8.5.8 locally ([results below](#local-sdk-checks--2026-10-13)). CI is configured for PHP 8.2 and 8.5 (job `php-sdk`); this local check does not exercise 8.2, 8.3 or 8.4 |
| .NET: `ProudAuth.Sdk`, `ProudAuth.Sdk.AspNetCore` (`proudauth-sdk-dotnet`) | `net8.0`; BouncyCastle.Cryptography 2.7.0 for Ed25519 and RSA-PSS. The ASP.NET package requires the ASP.NET Core shared framework; the core package does not | 344 tests pass in independent CI on Linux, macOS and Windows; [published validation](https://github.com/proudbase/proudauth-sdk-dotnet/blob/main/VALIDATION.md) |

Other runtime versions may work but are not tested
([interoperability.md](interoperability.md#tested-profiles)).

## Local SDK checks — 2026-10-13

[Structured results](../operations/consistency-results/2026-10-13-sdk-offline.json)
record the complete local SDK checks, exact runtimes, commands and 205 input
hashes (SDK-009, SDK-010, QA-002, QA-004). Node.js, Dart and PHP ran from
private source copies on Mac16,8 / Apple M4 Pro, 12 CPUs, 24 GiB, macOS
27.0.1 (26A434). Existing installed/cached dependencies were used; no package
was installed or downloaded, and the shared SDK sources/locks did not change.

| SDK | Check | Result |
| --- | --- | --- |
| Go 1.27.2 | Four SDK packages in the linked complete `go test -race` run | Pass: 29 top-level tests, 39 subtests, zero failures/skips |
| Node.js 25.9.0 | `npm ls --offline --json --depth=0`; `npm --offline test` (TypeScript build and all tests) | Pass: 116 tests, zero failures/skips/cancellations |
| Dart 3.13.3 | `dart pub get --offline --enforce-lockfile`; `dart analyze`; `dart format --output=none --set-exit-if-changed .`; `dart test --reporter=json` | Pass: 216 tests, zero failures/skips; 42 formatted files, zero changes; lock unchanged |
| PHP 8.5.8 | `php -l` on all 90 source/test PHP files; `php -d error_reporting=-1 -d display_errors=1 tests/run.php` | Pass: 157 tests, 3078 assertions, zero failures/warnings/deprecations |

The Go SDK was not rerun for this table: all 20 recorded SDK input hashes
match the complete Go check. One extensionless fuzz corpus was not hashed
in that earlier manifest; its named passing execution and current hash are
listed separately. The other SDKs exercise controlled fixtures and HTTP
counterparts, not a new live-server interoperability run. These results do
not establish a current vulnerability audit, minimum-runtime compatibility,
independent security review or package publication. Private build outputs
and test workspaces are removed after publication.

## Language policy (SDK-006)

- **Maintained languages:** Go and Node.js/TypeScript first, as the plan
  proposes, then Dart, PHP and .NET. Go is the server's own language, Node.js
  covers the most common API back ends, and Dart and PHP were added on request
  for Dart back ends (not Flutter apps: mobile and browser clients use standard
  OAuth libraries) and PHP-FPM applications. The .NET SDK supports .NET 8+ backends and
  ASP.NET Core applications. All five implement the same
  surface (verifier, introspection with `SupportGuard`, bounded-state
  verification, OIDC/BFF client, administration client) at the same version.
  The Go SDK additionally provides request-level DPoP/mTLS verification via
  `SenderVerifier`; Node.js, Dart, PHP and .NET currently reject bound tokens.
  All five token-only paths reject `cnf` instead of silently treating the
  token as bearer authority. See the
  [sender profile](resource-servers.md#sender-constrained-tokens).
- **Next candidates:** Python and Java, in that order, when someone
  will maintain them. A language is added only with the shared fixtures
  passing, CI running its tests and a security reviewer for its directory;
  an unmaintained SDK is deprecated through the CHANGELOG rather than left to
  drift (GOV-006).
- **No SDK is required.** Everything an SDK does goes through standard
  protocols and documented APIs: OAuth 2.0 and OpenID Connect discovery,
  JWKS, RFC 9068-style JWT access tokens verified as described in
  [tokens.md](../protocols/tokens.md), RFC 7662 introspection, the session
  event stream and the OpenAPI document. A verifier built on any JWT library
  can prove it matches the SDKs with the shared fixtures
  ([tests/fixtures/sdk-contracts/README.md](../../tests/fixtures/sdk-contracts/README.md)); the server never
  treats an SDK client differently (the `ProudAuth-SDK` header is not acted
  on).

## Versions

- **0.x:** any minor version (0.y) can contain breaking changes. Each one is
  listed in [CHANGELOG.md](../../CHANGELOG.md) under **Changed** or
  **Removed** with the upgrade step; patch versions only fix defects.
- **From 1.0:** semantic versioning: breaking changes only in a new major
  version, with the deprecation window of
  [compatibility.md](../protocols/compatibility.md#deprecation-process).
- **Which version is which.** Each SDK has its own release lifecycle; the Go
  SDK's `admin.Version` names its source API version at run time. The Node.js
  SDK exports `SDK_VERSION` from `@proudauth/sdk/admin`, the Dart SDK
  `sdkVersion`, the PHP SDK `ProudAuth\Sdk\Version::SDK_VERSION`, and .NET
  `AdminClient.SdkVersion`. Every
  administration client sends it with each request: `ProudAuth-SDK:
  go/0.2.0`, `node/0.2.0`, `dart/0.2.0`, `php/0.2.0` or `dotnet/0.2.0`, and a `User-Agent`
  ending in `proudauth-sdk-<language>/0.2.0` after your own user-agent value.
  The server neither logs nor acts on these headers; your proxy logs can.

### Breaking changes in 0.2.0

The administration clients return one-time secrets wrapped (SDK-007,
SDK-008), so they cannot end up in logs, error reports or serialized copies of
a response:

- **Go:** results decoded into `*map[string]any` or `*any` (for example
  `CreateClient`, `CreateUser`, `Invite`, `RotateClientSecret`,
  `IssueImpersonation`, and `Do` with such a target) hold an `admin.Secret`
  instead of a `string` for the members `client_secret`, `client_secrets`,
  `api_key`, `signing_secret`, `setup_token`, `recovery_codes`,
  `invitation_secret`, `access_token`, `refresh_token`, `id_token`,
  `handoff_code`, `download_token`, `token`, `secret` and `webhook_secrets`,
  at any depth (arrays and objects under those names are wrapped element by
  element). A type assertion `.(string)` on them now fails: use
  `.(admin.Secret).Reveal()`. `String`, `Format`, `GoString`, `LogValue` and
  `MarshalJSON` print `[REDACTED]`, so marshalling such a map no longer
  preserves the secret. Results decoded into your own structs are not
  wrapped; declare the field as `admin.Secret` (it implements
  `UnmarshalJSON`) to get the same protection.
- **Node.js:** all response `data` (typed helpers, pages and lists included)
  wraps the same members in `Secret` instances: `reveal()` returns the value;
  `toString()`, `toJSON()` and `util.inspect` print `[REDACTED]`. The
  TypeScript types still describe these members as strings, so code that
  passed them on as strings must call `reveal()`.
- **Dart and PHP** start at 0.2.0 with the same wrapping: the same members
  are `Secret` instances whose `reveal()` returns the value. Dart's
  `toString()` and `jsonEncode` print `[REDACTED]`; PHP's `__toString()`,
  `json_encode` and `var_dump` print `[REDACTED]`, and `serialize()` and
  `clone` are refused.

- **.NET** starts at 0.2.0: `AdminObject` results wrap the same secret
  members recursively in `Secret`; call `Reveal()` to store the value.
  `ToString()`, debugger display and `System.Text.Json` output redact it.

`identity-cli api` prints raw responses on purpose, one-time secrets
included.

The Go verifier no longer exports its security lists as variables:
`verifier.ProtectedOperations`, `verifier.WriteSegments` and
`verifier.DefaultOnlineKinds` became `verifier.ProtectedOperationList()`,
`verifier.WriteSegmentList()` and `verifier.DefaultOnlineKindList()`, which
return copies, so no importing code can weaken them; code that assigned to
the variables no longer compiles. Bounded-state verification (every SDK) keeps
known revocations across `Start`, rewinds to the oldest retained event on
`410 cursor_expired` and replays at once
([resource-servers.md](resource-servers.md#1-register-the-api)).

## Protocol and schema compatibility

| Contract | Version marker | The SDKs rely on |
| --- | --- | --- |
| Custom APIs | Path `/api/v1/` | Administration client routes, RFC 9457 problems (`code`, `request_id`), cursor pagination, `Idempotency-Key`, `If-Match` |
| OAuth 2.0 / OpenID Connect | Standards and discovery | Authorization code with PKCE, refresh rotation, introspection (RFC 7662), revocation (RFC 7009), RP-initiated logout ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md)) |
| Access tokens | `typ: at+jwt`, `token_kind` | The verification algorithm of [tokens.md](../protocols/tokens.md), pinned by the shared fixtures `tests/fixtures/sdk-contracts/access-tokens/cases.json` ([tests/fixtures/sdk-contracts/README.md](../../tests/fixtures/sdk-contracts/README.md)) |
| Events and the session-event stream | `event_type` + `event_version` (every type is at version 1) | Bounded-state verification reads `GET /session-events` ([api/events](../../api/events/README.md)) |
| Configuration documents | `format: proudauth.realm-config.v1` | `identity-cli config-*` ([below](#administrative-automation-sdk-012)) |

The service tests the Go SDK revision pinned in `go.mod` against its own
server. Other SDKs run their controlled HTTP counterparts in independent CI;
the [source-pinned SDK evidence](sdk-repositories.json) records exact versions.
No
combination of an older SDK with a newer server (or the reverse) is tested.
Changes to these contracts follow
[compatibility.md](../protocols/compatibility.md): additive within a
version, deprecation window otherwise, security exceptions announced as such.

### Deprecation reporting

Deprecated operations are reported through the `Deprecation` and `Sunset`
response headers (API-013). The SDKs surface them so a deprecation shows up
in your telemetry before the removal:

- **Go:** `admin.Response` has `Deprecation` and `Sunset`; the optional
  `Client.OnDeprecated func(method, path, deprecation, sunset string)` is
  called for every response that carries `Deprecation` (also error
  responses).
- **Node.js:** `AdminResponse` has `deprecation` and `sunset`; the client
  option `onDeprecated({method, path, deprecation, sunset})` is called the
  same way.
- **Dart:** the `AdminClient` option `onDeprecated` receives a
  `DeprecationNotice` (`method`, `path`, `deprecation`, `sunset`).
- **PHP:** the `AdminClient` argument `onDeprecated` is called as
  `($method, $path, $deprecation, $sunset)`.

- **.NET:** `AdminResponse<T>` exposes `Deprecation` and `Sunset`;
  `AdminClientOptions.OnDeprecated` receives a `DeprecationNotice`.

All five pass the path without its query string, so search terms such as an
email address do not reach your telemetry.

No operation is deprecated today, so the server sends neither header yet.

## Security updates

The SDKs follow the server's supported-versions table in
[SECURITY.md](../../SECURITY.md#supported-versions): during 0.x the latest
minor release and the previous one (until the next minor is published) get
security fixes; today, with nothing tagged, only `main` does. Report SDK
vulnerabilities privately as described there. A fix is published as a GitHub
security advisory and a release, with a **Security fixes** entry in the
CHANGELOG that names the affected SDK versions and the regression test or
fixture added with it (QA-008).

## Interoperability tests

| What | Where |
| --- | --- |
| All five SDKs accept and reject the same 22 access tokens | `tests/fixtures/sdk-contracts/access-tokens/cases.json`, run by `proudauth-sdk-go/verifier/fixtures_test.go`, `proudauth-sdk-node/test/fixtures.test.ts`, `proudauth-sdk-dart/test/fixtures_test.dart`, `proudauth-sdk-php/tests/FixturesTest.php` and `proudauth-sdk-dotnet/tests/ProudAuth.Sdk.Tests/Program.cs` (the Go test regenerates them with `PROUDAUTH_REGENERATE_FIXTURES=1`) |
| All five SDKs classify support-token operations the same way | `tests/fixtures/sdk-contracts/support-operations/cases.json`, run by `proudauth-sdk-go/verifier/support_test.go`, `proudauth-sdk-node/test/support-operations.test.ts`, `proudauth-sdk-dart/test/support_operations_test.dart`, `proudauth-sdk-php/tests/SupportOperationsTest.php` and `proudauth-sdk-dotnet/tests/ProudAuth.Sdk.Tests/Program.cs` |
| Dart, PHP and .NET signature verification agrees with Go | Vectors signed by Go's standard library (valid and tampered signatures, malformed keys, Go-signed tokens): `proudauth-sdk-dart/test/vectors/` (`crypto_vectors_test.dart`, `verifier_test.dart`) and `proudauth-sdk-php/tests/vectors/signatures.json` (`CryptoVectorsTest.php`). The .NET tests consume the Dart vector files as independent Go oracles. All keys are test-only |
| Go administration client against the server | `TestAdminSDKInterop` (`tests/e2e/sdk_admin_test.go`): pagination, problem details, idempotent retries, `admin.Secret` for a new client secret, `If-Match` |
| Go verifier against the server | `TestTokenVerificationNegatives`, `TestSigningKeyRotation`, `TestBoundedStateVerification`, and the example APIs in `TestTenantIsolationAcrossServices` and `TestRevocationConsistencyModes` (middleware, introspector, `SupportGuard`) |
| Go OIDC client against the server | `TestBackendForFrontendExample`, `TestOIDCClientValidationFixtures` (`tests/e2e/bff_test.go`) |
| Node.js SDK | Unit tests against local mock servers only (`proudauth-sdk-node/test`, CI job `node-sdk`); **no test runs it against a ProudAuth server** |
| Dart SDK | Unit tests against local mock servers and mock HTTP clients only (`proudauth-sdk-dart/test`, CI job `dart-sdk`); **no test runs it against a ProudAuth server** |
| PHP SDK | Unit tests with a fake transport, plus one suite against a `php -S` server on loopback (`proudauth-sdk-php/tests`, CI job `php-sdk`); **no test runs it against a ProudAuth server** |

| .NET SDK | Shared fixtures and Go signature vectors, controlled HTTP clients, ASP.NET adapter tests and a loopback Kestrel redirect test; independent SDK CI on three operating systems ([published validation](https://github.com/proudbase/proudauth-sdk-dotnet/blob/main/VALIDATION.md)). This CI does not run against a ProudAuth server |

## Framework adapters (SDK-011)

The adapters only extract the bearer token, call one authenticator
(`Verifier`, `Introspector`, `BoundedVerifier`, `MultiIssuer` /
`MultiIssuerVerifier`) and translate its error into a response; every
security decision stays in that authenticator, so adapters cannot drift
apart in what they accept.

| Adapter | SDK | Use |
| --- | --- | --- |
| `verifier.Middleware(a, next)` | Go | `net/http`; claims via `verifier.FromContext(r.Context())` |
| `verifier.AuthenticateMetadata(ctx, a, md)` | Go | gRPC metadata, message headers, WebSocket upgrade headers: a `map[string][]string` with exactly one `authorization: Bearer <token>` entry (keys matched without case; more than one value is `ErrMalformed`) |
| `middleware(authenticator, options)` | Node.js `./verifier` and `./introspection` | Express and Connect; claims via `getClaims(req)` or `req.auth` |
| `requireScopes(...scopes)` | Node.js | Express and Connect, after `middleware`: `403 insufficient_scope` |
| `protect(authenticator, handler, options)` | Node.js | `node:http`; the handler receives the claims |
| `fastifyHook(authenticator, options)` | Node.js `./verifier` | Fastify `onRequest` or `preHandler` hook; on failure it sends the response and returns the reply, so the route never runs |
| `guard.middleware({operation, read})` | Node.js `./introspection` | Express and Connect for routes that also serve support sessions (`SupportGuard`) |
| `authorizeBearer(authenticator, authorization:, requestUri:, requiredScopes:)` | Dart | Any framework (shelf, gRPC interceptors, WebSockets): returns `AuthAccepted(claims)` or `AuthRejected(challenge)`, where the challenge carries the status and headers to send |
| `protect(authenticator, handler)`, `protectOperation(guard, handler, operation:, read:)` | Dart `package:proudauth_sdk/io.dart` | `dart:io` `HttpServer`; claims via `claimsOf(request)`; `requiredScopes:` answers `403 insufficient_scope` |
| `RequestAuthenticator::authenticate($authorization, $uri)` | PHP | Any framework (a PSR-15 wrapper is shown in `proudauth-sdk-php/README.md`); returns `Claims` or throws `VerifierException`, which `Challenge::fromThrowable()` turns into the response |
| `RequestAuthenticator::protect($handler)`, `authenticateGlobals()` | PHP | Plain PHP (PHP-FPM, `php -S`) reading the request superglobals; a `VerifierException` thrown in the handler (for example by `requireScope`) is answered with its challenge |
| `SupportGuard::route($operation, $read)` | PHP | Routes that also serve support sessions |
| `AddProudAuth` / `UseProudAuth` | .NET `ProudAuth.Sdk.AspNetCore` | ASP.NET Core authentication scheme and middleware; verified claims via `HttpContext.GetProudAuthClaims()`; support routes use `SupportGuard.Route` |

Failure responses (RFC 6750):

| Outcome | Go `Middleware` | Node.js, Dart, PHP and .NET adapters |
| --- | --- | --- |
| No bearer token | `401`, `WWW-Authenticate: Bearer` | `401`, `Bearer` (with `realm="…"` when configured) |
| `access_token` in the query string | `400`, `Bearer error="invalid_request"` | same |
| Invalid, expired, wrong issuer or audience, inactive | `401`, `Bearer error="invalid_token"` | same |
| Missing scope or organization (`ErrScope`, `ErrOrganization`; Node.js `scope`, `organization`) | `403`, `Bearer error="insufficient_scope"` | same, with `scope="…"` from `requireScopes` |
| Support-policy denial | `403` | `403` |
| JWKS, introspection or event stream unavailable, stale bounded state | `503` | `503` |
| Misconfiguration (for example an introspector told to accept support tokens) | `500` | `500` |

Every failure response carries `Cache-Control: no-store` and a short
plain-text body without token material. The Go middleware only authenticates;
scope and organization checks happen in your handler (`claims.RequireScope`,
`claims.RequireOrganization`), which should answer with the same statuses.
No SDK handles CORS: an `OPTIONS` preflight carries no
`Authorization` header and gets `401`, so answer preflights before the
adapter ([patterns.md](patterns.md#http-apis-int-001)). A gRPC interceptor
is a few lines around `AuthenticateMetadata` (its doc comment shows one); the
SDK has no gRPC dependency. Usage patterns for GraphQL, gRPC, WebSockets and
other transports are in [patterns.md](patterns.md).

## Administrative automation (SDK-012)

Configuration as code uses the same API as everything else: the realm
configuration document `proudauth.realm-config.v1`
([exit-and-export.md](../operations/exit-and-export.md#configuration-import),
`api/schemas/config-document.schema.json`). `identity-cli` wraps it in three
commands that use the credentials stored by
`identity-cli login --url https://id.example.com --realm <realm>` (an
admin-audience session, refreshed automatically):

```sh
identity-cli config-export --realm main -o realm-config.json      # export job, download; file mode 0600
identity-cli config-plan   --realm main -f realm-config.json      # dry run: create, update, drift, errors, notes
identity-cli config-apply  --realm main -f realm-config.json --secrets-out new-secrets.json
identity-cli config-apply  --realm main -f realm-config.json -reconcile   # also update differing clients, resources, roles
```

| Command | Behavior |
| --- | --- |
| `config-export [--realm R] [-o FILE] [--wait D]` | Starts `POST /configuration/exports`, waits for the job (default 2 minutes), downloads the document and writes it with mode `0600` (default `realm-config.json`). The document holds no secrets; its `excluded` member lists what was left out |
| `config-plan [--realm R] -f FILE [-reconcile]` | Calls `POST /configuration/validate` (with `?mode=reconcile` for `-reconcile`) and prints what would be created and updated, **drift**, errors and notes. Exits `1` when the plan has errors; drift alone does not fail it. `/validate` needs `realm.configuration.import` and reports a missing or stale `expected_policy_revision` and every missing per-change permission (`<item>: requires <permission>`) as plan errors |
| `config-apply [--realm R] -f FILE [-reconcile] [--yes] [--secrets-out FILE]` | Prints the plan, stops on errors or when there is nothing to create or update, asks you to type `yes` unless `--yes` is given, then calls `POST /configuration/imports` (with `?mode=reconcile` for `-reconcile`). The import needs the write permission of every change and, for a realm policy change, `expected_policy_revision` in the document (`403` or `422` otherwise). Secrets generated for new confidential clients are shown once on standard output, or written to `--secrets-out` (mode `0600`) |

**Drift** lists existing objects whose current settings differ from the
document, as `<kind> <id>: <fields> differ`: resources (`name`,
`verification_mode`, `access_token_ttl`, `requires_organization`,
`signing_algorithm`, `impersonation_enabled`, `impersonation_policy`,
`scopes`), clients (`name`, `client_type`, `grant_types`, `redirect_uris`,
`post_logout_redirect_uris`, `first_party`, `consent_mode`, `allowed_origins`,
`backchannel_logout_uri`, `allow_offline_access`, `allow_remember_me`,
`token_endpoint_auth_method`, `security_profile`, `protocol_options`) and
roles (`permissions`, `denied_permissions`, `requires_approval`). Without
`-reconcile` an import never changes existing resources, clients, roles or
permissions, so drift is for review: fix it through the API, or decide that
the document is out of date. With `-reconcile`, differing objects are updated
in the same atomic import (SDK-012): a client's whole registration is
replaced from the document (keeping its project, owner, default resource and
service principal links), a resource takes the members the document gives
and keeps the others, and a role's permissions are added or removed to match
(within your delegation ceiling). Each update needs its write permission and
is audited like the API call. A resource's scopes, a client's type, a role's
denied permissions and approval flag stay drift, and nothing is deleted.
The realm policy (merged over the current one) and client resource grants
**are** updated in place; see the caveats in
[exit-and-export.md](../operations/exit-and-export.md#configuration-import).

Exit codes: `0` on success, `1` on errors (including a refused confirmation),
`2` on usage errors. Output files are always written with mode `0600`, also
when they exist already (a new file replaces them). Infrastructure tools
(Terraform providers and the like) can build on the same endpoints; none is
provided.
