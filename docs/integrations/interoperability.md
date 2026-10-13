# Interoperability matrix

Requirements: QA-004 (publish tested counterparts and exact versions), QA-006
(distinguish internal tests from conformance and certification).

A tested profile below means that the named counterpart, at the named version,
exercised the listed surface in the owning service or SDK test suite. It is not a claim
of compatibility with every feature of that counterpart, or with other versions
of it.

## Conformance claims

| Level | What it means | ProudAuth today |
| --- | --- | --- |
| Internal tests | Service tests against the pinned Go SDK, examples and test doubles; independently owned SDK tests with immutable CI evidence | Yes: the exact scope in [Tested profiles](#tested-profiles) and [SDK snapshots](sdk-repositories.json) |
| Conformance-suite participation | Running a published suite (for example the OpenID Foundation OP or FAPI test plans, FIDO conformance tools, SAML or SCIM test suites) and publishing the plan, suite version and results | **None.** No suite has been run and no results are published |
| Certification | A certificate granted by the body that owns the profile (for example OpenID Certification, FIDO Certified), with its published evidence | **None.** ProudAuth holds no certification, and the repository contains no certification evidence |

Rules for claims (QA-006, [ADR 0020](../architecture-decisions/0020-compliance-posture.md)):

- Documentation that describes protocol behavior ("RFC 9449 proofs at the token
  endpoint", "OpenID Connect discovery") describes what the code implements and
  the internal tests exercise, not conformance.
- A claim at the second or third level is added here only together with its
  evidence: suite name and version, test plan, ProudAuth commit or release, and a
  link to the published results or certificate.
- Certification applies to a deployed product version, not to this source tree.
  An operator who certifies a deployment holds that certificate; it does not
  extend to the project or to other deployments.

## Tested profiles

### Toolchains and runtimes

| Component | Exact version tested | Where it is pinned |
| --- | --- | --- |
| Go | 1.27.2 (service CI, release and container image); 1.27.1 (local migration race suite) | Service workflow and Dockerfile pin the exact release toolchain; `go.mod` declares minimum Go 1.27.1. Independent Go SDK CI records its own toolchain in its pinned workflow |
| PostgreSQL | 18.6 in migrated service CI/local verification and published Compose profile | See service workflow and Compose image references; earlier archived profiles below retain their original database versions |
| Node.js | 20.10, 22 and 24 | Independent Node SDK CI matrix; `package.json` declares `>=20.10`; [tested source and workflow](sdk-repositories.json) |
| TypeScript, Node.js type definitions | 5.9.3, `@types/node` 25.9.8 | `proudauth-sdk-node/package.json` (development dependencies; the SDK has no runtime dependencies) |
| Dart | 3.13.3 | Independent Dart SDK CI pins this toolchain and its dependency lock; minimum package runtime `^3.4.0` is declared, not tested |
| PHP | 8.2 and 8.5 | Independent PHP SDK CI matrix with strict warning/error handling and Composer validation; no Composer runtime dependencies |
| .NET | .NET 8 on Ubuntu 24.04, macOS 14 and Windows 2022 | Independent .NET SDK CI: 344 tests per OS, locked BouncyCastle.Cryptography 2.7.0, Release build/format/two packages; [exact source and runs](sdk-repositories.json) |
| Server libraries at the protocol boundary | `github.com/go-webauthn/webauthn` v0.18.2, `github.com/go-jose/go-jose/v4` v4.1.5, `github.com/jackc/pgx/v5` v5.11.0 | `go.mod` |
| SAML and LDAP libraries | `github.com/russellhaering/goxmldsig` v1.6.1 and `github.com/beevik/etree` v1.7.0 (XML signatures; also used by the test SP and IdP), `github.com/go-ldap/ldap/v3` v3.4.15 with `github.com/go-asn1-ber/asn1-ber` v1.5.8 | `go.mod` |

### Counterparts

Everything here is **internal testing**: the server runs in-process
(`tests/e2e/harness_test.go`) against real PostgreSQL. Service end-to-end tests
use the checksum-pinned public Go SDK; the other SDKs execute their controlled
counterparts in their independently pinned repositories. The source API versions
remain the Go SDK's `admin.Version`, Node.js `SDK_VERSION`, Dart `sdkVersion` and
PHP SDK `Version::SDK_VERSION` and .NET SDK `AdminClient.SdkVersion`, all 0.2.0.

| Counterpart (pinned source or service checkout) | Protocol surface exercised | Tests |
| --- | --- | --- |
| `proudauth-sdk-go/verifier` `Verifier` (offline) | JWT access-token verification: audience, issuer, type, algorithm allowlist, duplicate members, unknown-`kid` refresh bounding, time checks, planned and emergency key rotation | `TestTokenVerificationNegatives`, `TestSigningKeyRotation`, `TestRevocationConsistencyModes`; fuzz `FuzzVerify` |
| `proudauth-sdk-go/verifier` `Introspector` and `SupportGuard` via `examples/protected-orders-api` | RFC 7662 introspection with client authentication; strict-online denial on outage; support-access contract with actor-aware audit; policy decision API with obligations | `TestTenantIsolationAcrossServices`, `TestRevocationConsistencyModes`, `TestSupportImpersonation`, `TestImpersonationDenials`, `TestPolicyDecisionContract` |
| `examples/protected-billing-api` | Offline verification and organization filtering | `TestTenantIsolationAcrossServices`, `TestRevocationConsistencyModes` |
| `proudauth-sdk-go/verifier` `BoundedState` and `BoundedVerifier` | Bounded-state verification: local JWT checks plus revocations replayed from the session-event stream (`GET /session-events`); fail-closed when state is stale | `TestBoundedStateVerification`, `TestSessionEventStream` |
| `proudauth-sdk-go/verifier` `MultiIssuer`, `AuthenticateMetadata` | Issuer selection and refusal of unregistered issuers; bearer extraction from metadata maps | Unit tests only (`proudauth-sdk-go/verifier/multi_test.go`, `metadata_test.go`), against locally signed tokens, not a running server |
| `proudauth-sdk-go/oidcclient` + `examples/backend-for-frontend` | Authorization code + PKCE through the browser flow, `state`, `nonce`, RFC 9207 `iss`, ID-token validation (issuer, audience, `azp`, nonce, `at_hash`, signature, expiry, `typ`), serialized refresh, RFC 7009 revocation, RP-initiated logout URL | `TestBackendForFrontendExample`, `TestOIDCClientValidationFixtures` |
| `proudauth-sdk-go/admin` 0.2.0 | Cursor pagination, RFC 9457 problems with `code` and `request_id`, idempotent retry with the same key, client creation with the one-time secret wrapped in `admin.Secret`, `If-Match` (a `W/"v0"` precondition is refused with `412`, the current `ETag` succeeds) | `TestAdminSDKInterop` (`tests/e2e/sdk_admin_test.go`) |
| Test harness HTTP clients | Headless transactions; browser transactions with cookie, CSRF and `Origin`, including concurrent transactions in one browser; SSO with `prompt` (including `select_account`)/`max_age`; OIDC `claims` parameter; RP-initiated logout, including the `upstream_logout` extension; device authorization (RFC 8628); PAR (RFC 9126); DPoP proofs at the token endpoint (RFC 9449); token exchange (RFC 8693); client credentials; UserInfo audience rules; discovery and RFC 8414 metadata; custom domains under `server.host_policy: strict` | `TestBrowserFlowCSRFSSOAndLogout`, `TestConcurrentBrowserTransactions`, `TestClaimsRequestAndStaticClaims`, `TestDeviceFlowAndPAR`, `TestDPoPBoundTokens`, `TestIntrospectionExchangeAndMachines`, `TestDiscoveryAccuracy`, `TestAuthorizationCodeBinding`, `TestRefreshRotation`, `TestMultiFactorAndProofs`, `TestFederationAdapters`, `TestCustomDomains` |
| Test HTTP receivers | Back-channel logout token delivery (`logout+jwt`); signed webhook deliveries and receiver-side verification; signed pre-action hook calls verified by the receiving hook, including `authentication.risk` hooks; a siteverify-style challenge provider | `TestBackchannelLogoutDelivery`, `TestWebhooksAndBackchannelLogout`, `TestPreActionHooks`, `TestAuthenticationFlowPolicy` |
| Software WebAuthn authenticator (test double, ES256, `none` attestation) | Passkey registration and assertion ceremonies as produced by the browser API | `TestPasskeys` |
| Software WebAuthn authenticator with `packed` attestation under a test vendor CA, and with `credProtect` | Trusted attestation against realm trusted authenticators, refused `none` and foreign-chain attestation, AAGUID allow and block lists at registration and sign-in, related origins and `/.well-known/webauthn`, `credProtect` requested and enforced (PASS-009, PASS-010). Trusted attestation through a FIDO MDS3 BLOB signed under a test root (and refusal of a BLOB with a bad signature) | `TestPasskeyAttestationTrust`, `TestPasskeyAdvancedCapabilities`, `TestPasskeyFIDOMetadata` |
| Test SSF receiver and transmitter (Go HTTP servers and `go-jose`) | Shared Signals: transmitter metadata, stream management, subjects, verification, RFC 8936 poll with acknowledgements, RFC 8935 push with the receiver's `Authorization` value and `400` handling, SET signatures checked against the realm JWKS; inbound push with signature, issuer, audience, age and replay checks, subject mapping and action policy (AUD-016, ADV-007) | `TestSharedSignalsTransmitter`, `TestSharedSignalsReceiver` |
| Test harness check-session client (Go) | `session_state` in authorization responses, recomputed in Go for the RP origin and refused for others; the iframe's origin check endpoint; `pa_opbs` set and cleared (OIDC-014). The iframe's script is not executed | `TestCheckSessionIframe` |
| Test harness registry client (Go HTTP) | Distribution token endpoint with personal access tokens, API keys, machine-client secrets, anonymous pulls, the failed-sign-in throttle, scope and permission capping, organization-bound rules, `401` with `WWW-Authenticate: Basic`, unknown and disabled services (ADV-010). No registry implementation is run | `TestRegistryTokenBridge` |
| Development SMS sink and email sink (in-process) | SMS one-time codes, magic links (fragment-carried secret, transaction binding), temporary password lock, per-organization issuance budget | `TestPasswordlessAndAbuseBudgets` |
| Fake upstream OIDC provider and GitHub-style OAuth API (test doubles over TLS) | Upstream federation: PKCE, response validation, JIT provisioning, linking with proof of control, tenant restriction, upstream MFA mapping; an adapter registered by the test (`federation.RegisterAdapter`) whose email assertions are not trusted; upstream logout redirect and return | `TestFederation`, `TestFederationAdapters` |
| Test harness SCIM client (Okta- and Azure AD-style requests) | SCIM 2.0 provisioning: connector creation within the creator's ceiling, discovery documents, user create, adoption through a verified domain, `PATCH` with `"op": "Replace"` and `"value": "False"`, filters (including value paths and case-exact `externalId`), attribute selection, `If-Match`, groups with mapped roles and `members[value eq "..."]` removal, token rotation and disabling | `TestSCIMProvisioning` |
| Test SAML service provider and identity provider (`tests/e2e/saml_helpers_test.go`, written on `etree`, `goxmldsig` and the Go standard library, independently of `internal/saml`) | SAML 2.0 Web SSO in both roles: HTTP-Redirect and HTTP-POST `AuthnRequest`s with detached and enveloped signatures, signed responses and assertions, DEFLATE, encrypted assertions (AES-GCM with both RSA-OAEP key transports), SP-initiated single logout, SP metadata, certificate overlap, and the negative cases of TEST-051 (wrapping, replay, DTD/XXE, SHA-1, audience, destination) | `TestSAMLIdentityProvider`, `TestSAMLKeyRollover`, `TestSAMLBroker` |
| In-process LDAP server `internal/directory/ldaptest` | LDAPv3 simple bind over LDAPS and StartTLS, OpenLDAP- and Active Directory-style entries, simple paged results, `uSNChanged`/`highestCommittedUSN` and `modifyTimestamp` change tracking, `userAccountControl`, groups, endpoint failover, write-back modifies | `TestLDAPDirectorySignIn`, `TestDirectorySynchronization`, `TestDirectoryAuthority`, `TestDirectoryTenantIsolation`, unit tests in `internal/directory` |
| In-process SCIM double (`tests/e2e/outbound_test.go`) | Outbound SCIM 2.0: `POST`, `PUT`, `PATCH active`, `GET /Users` with `externalId` filters, `/Groups`, `409` and `5xx` answers, `ServiceProviderConfig` | `TestOutboundProvisioning` |
| `google` and `microsoft` adapters | Connection defaults and validation only (fixed issuer and `hd` tenant claim; `tid` tenant claim, required tenants and refused `trusted_verified_email` linking). No sign-in runs through them | `TestFederationAdapters` |
| OTLP exporter and `tracing.Tracer` | OTLP/HTTP JSON payload shape against a local HTTP receiver; server and client spans recorded through the `Tracer` interface | `TestOTLPExporter` (`internal/platform/tracing`), `TestTraceExport` |
| `keys.kms.command` | The `kms:` reference contract (wrapped key on standard input, unwrapped key on standard output, failure handling) with a stand-in command (`sed`, `false`) | `internal/configuration/kms_test.go` |
| `cmd/identity-bench` | Seeding and every benchmark scenario, briefly, against the in-process server ([benchmarks.md](../operations/benchmarks.md)) | `TestBenchSuiteSmoke` |
| `proudauth-sdk-node` 0.2.0 (Node.js 20.10, 22, 24) | Unit tests with `node --test` against local mock HTTP servers, including bounded-state verification, framework adapters, `MultiIssuerVerifier` and `Secret`; independent Node SDK CI; **not** run against a live ProudAuth server | SDK `test/*.test.ts`; [pinned evidence](sdk-repositories.json) |
| `proudauth-sdk-dart` 0.2.0 (Dart 3.13.3) | Unit tests with `dart test` against mock servers and clients, signature vectors/tokens signed by Go, bounded-state verification, `dart:io`, `MultiIssuerVerifier` and `Secret`; independent Dart SDK CI; **not** run against a live ProudAuth server | SDK `test/*_test.dart`; [pinned evidence](sdk-repositories.json) |
| `proudauth-sdk-php` 0.2.0 (PHP 8.2, 8.5) | Unit tests with a fake transport and one suite against a loopback `php -S` server, signature vectors, bounded-state verification, `RequestAuthenticator`, `MultiIssuerVerifier` and `Secret`; independent PHP SDK CI; **not** run against a live ProudAuth server | SDK `tests/*Test.php`; [pinned evidence](sdk-repositories.json) |
| `proudauth-sdk-dotnet` 0.2.0 (.NET 8+) | Shared fixtures, Go signature vectors, controlled HTTP clients, concurrency/failure cases, ASP.NET adapters and a loopback Kestrel redirect test; 344 independent CI tests on Linux, macOS and Windows | SDK `tests/ProudAuth.Sdk.Tests/Program.cs`; [published validation](https://github.com/proudbase/proudauth-sdk-dotnet/blob/main/VALIDATION.md) |
| Shared verification fixtures `tests/fixtures/sdk-contracts/access-tokens/cases.json` (SDK-009) | 22 accepted and rejected access tokens (issuer, audience, time claims, signature, unknown and confused keys, `alg: none`, token type and kind, duplicate members, malformed input) signed with test-only keys, so a verifier built on another JWT library can be checked against the same cases ([tests/fixtures/sdk-contracts/README.md](../../tests/fixtures/sdk-contracts/README.md)) | `proudauth-sdk-go/verifier/fixtures_test.go`, `proudauth-sdk-node/test/fixtures.test.ts`, `proudauth-sdk-dart/test/fixtures_test.dart`, `proudauth-sdk-php/tests/FixturesTest.php`, `proudauth-sdk-dotnet/tests/ProudAuth.Sdk.Tests/Program.cs`; the Dart and PHP SDKs verify signatures with their own code (Dart on `BigInt`, PHP on OpenSSL and libsodium), so these runs also check those implementations; no third-party JWT library is run against them in this repository |
| Shared support-operation cases `tests/fixtures/sdk-contracts/support-operations/cases.json` | How `SupportGuard` classifies operations of support tokens (protected, write, allowlisted write), so every SDK and the server's decision API decide the same | `proudauth-sdk-go/verifier/support_test.go`, `proudauth-sdk-node/test/support-operations.test.ts`, `proudauth-sdk-dart/test/support_operations_test.dart`, `proudauth-sdk-php/tests/SupportOperationsTest.php`, `proudauth-sdk-dotnet/tests/ProudAuth.Sdk.Tests/Program.cs`, `internal/authorization/support_test.go` (classification only) |
| OpenAPI document `api/openapi/proudauth.yaml` | Static check that documented routes equal registered routes; JSON Schemas well-formed | `tests/contract` |

The Compose smoke test (`scripts/smoke-test.sh`, CI job `image`) additionally
checks the built container image: liveness, readiness, discovery, JWKS and that the
password grant is refused.

### Third-party products

Third-party software is exercised in two ways. For the migration adapters
(MIG-002, MIG-018), exports produced by the real products are committed
under `internal/migrate/testdata/`, converted, planned and imported through
the import APIs, after which the migrated users sign in with their source
passwords. Protocol counterparts run live against ProudAuth built from the
same commit: libraries in an end-to-end test, products in a script that
starts them in throwaway containers (and in the `interop.yml` workflow).

| Product | Exact version | What was produced or exercised | Tests |
| --- | --- | --- | --- |
| Keycloak | 26.8.0 (`quay.io/keycloak/keycloak:26.8.0`, dev-file H2) | Realm export JSON with users, credentials and groups | `TestMigrateFromKeycloak` |
| ZITADEL | v4.16.3 (`ghcr.io/zitadel/zitadel:v4.16.3`, PostgreSQL 18) | Admin API v1 data export | `TestMigrateFromZitadel` |
| SuperTokens | core 12.0.7, PostgreSQL plugin 9.5.5, CDI 5.4 | `proudauth.supertokens-export.v1` read from the core database | `TestMigrateFromSuperTokens` |
| `github.com/coreos/go-oidc/v3` with `golang.org/x/oauth2` (independent OpenID Connect relying-party libraries) | v3.18.0 and v0.37.0 (`go.mod`; used only by the test) | **Relying party** (OIDC-001, OIDC-003, TOK-011): discovery (`NewProvider`); authorization request from `AuthCodeURL` with `state`, `nonce` and S256 PKCE (`GenerateVerifier`, `S256ChallengeOption`); code exchange with `VerifierOption` and `client_secret_basic` (a different verifier is refused); ID-token verification by the library (issuer, audience, expiry, RS256 signature through the JWKS) plus `nonce`, `azp` and `at_hash`; `UserInfo`; refresh through `TokenSource` with a rotated refresh token. Refused by the library: an ID token issued to another client, a tampered one, one without a signature, and, with a key set fetched after an emergency rotation, one signed by the withdrawn key; after a planned rotation the library's remote key set fetches the new `kid`. The sign-in between the authorization request and the code goes through the headless interaction API, because the library has no login UI. **Not covered:** browser redirects and cookies, logout (RP-initiated, front- and back-channel), DPoP, PAR, `private_key_jwt`, the `claims` parameter, ES256 or PS256 ID tokens | `TestOIDCRelyingPartyLibrary` (`tests/e2e/oidc_library_test.go`) |
| ZITADEL | v4.16.3 (`ghcr.io/zitadel/zitadel:v4.16.3`, `start-from-init`, PostgreSQL 18.6 from `postgres:18`) | **SCIM 2.0 service provider for outbound provisioning** (PROV-010, PROV-017): `/scim/v2/{orgId}/Users` with `POST`, `PUT`, `PATCH` (`active`), `DELETE`, `GET` with `externalId eq` filters and `startIndex`/`count` paging; bearer personal access token of a service account holding only `ORG_USER_MANAGER`; attributes `userName`, `displayName`, `name.givenName`, `name.familyName`, `emails` (verified primary address), `active`, `externalId`; an organization connector deactivating and a realm connector (`eligible_organization_ids`) deleting; create, profile and email changes, account and membership suspension and reactivation, removal, deletion; a refused create (no verified email) delivered after verification; a revoked token (`401`), credential rotation and replay; reconciliation dry run and repair of drift, a deleted user and an unmanaged one left alone. ZITADEL requires one media type in `Accept`, and `name` and `emails`; it has no `/Groups` ([outbound-provisioning.md](outbound-provisioning.md#zitadel-v4163)). **Not covered:** groups, TLS, custom attribute mappings, `eligible_group_ids`, retries on `429` and `5xx`, `userName` changes, merged accounts; ZITADEL's OpenID Connect roles (upstream provider for ProudAuth federation, which needs an `https` issuer, or relying party of ProudAuth) are not exercised, Keycloak covers both | `scripts/interop-zitadel.sh` (`make interop-zitadel`, workflow `interop.yml`) |
| Keycloak | 26.8.0 (`quay.io/keycloak/keycloak:26.8.0`, `start-dev` with its H2 database, HTTPS) | Both directions of both protocols ([profiles](#keycloak-2680-protocol-profiles)): **relying party** (an "OpenID Connect v1.0" identity provider brokering to ProudAuth; RP-initiated and back-channel logout), **upstream OpenID Provider** of a ProudAuth OIDC connection (upstream logout), **SAML service provider** (a "SAML v2.0" identity provider) of a ProudAuth SAML application (encrypted assertions, single logout), **SAML identity provider** (a SAML client) of a ProudAuth SAML connection; replayed and tampered messages and wrong client secrets refused. **Not covered:** [listed below](#not-covered-with-keycloak) | `scripts/interop-keycloak.sh` (`make interop-keycloak`, workflow `interop.yml`) |

A tested profile is one export, or the listed profile, of one version; it is
not compatibility with every feature of that product (QA-004). Other releases
of the same major version are accepted but untested
([migration-adapters.md](../operations/migration-adapters.md#supported-and-tested-versions-mig-002)).

#### Keycloak 26.8.0 protocol profiles

`scripts/interop-keycloak.sh` (`make interop-keycloak`; weekly and on demand in
the `interop.yml` workflow on `ubuntu-24.04`) runs four scenarios against
Keycloak 26.8.0 and stops at the first failed assertion; a run takes about
half a minute once the images are present. Last passing runs: 2026-10-11,
seven consecutive runs of the final script on linux/arm64 (Docker Desktop on
macOS), one of them under `dash` (Ubuntu's `/bin/sh`); the test
certificates were also generated with LibreSSL 3.3 in an earlier passing
run. The weekly workflow runs it on linux/amd64.

Set-up, all in throwaway containers on one Docker network:

- **Keycloak** 26.8.0, `start-dev`: its H2 database, the host name taken
  from the request, HTTPS only, with a certificate from a test CA the script
  generates and that CA in `--truststore-paths`. Realms, clients and identity
  providers are created through the admin REST API.
- **ProudAuth**: `identity-server`, `identity-worker` and `identity-cli`
  built from the same checkout (static Linux binaries in
  `gcr.io/distroless/static-debian12:nonroot`) on PostgreSQL 18 (`postgres:18`,
  18.6 at the last run), `mode: development` with TLS on the public listener
  (`server.tls_cert_file`), `federation.allow_private_network`,
  `federation.ca_file` (the test CA), `delivery.allow_private_webhooks` with
  `SSL_CERT_FILE` naming the test CA (back-channel logout), `saml.enabled`
  and the development email sink.
- **Login UI and browser**: the realm's `interaction.login_ui_url` is
  served by nobody; the script plays the login UI through the transaction
  API in browser mode (the `pa_tx` cookie, `X-CSRF-Token`, `Origin`), and
  plays the browser with curl and one cookie jar per user, submitting the
  HTML forms it meets (Keycloak's login form and logout confirmation, the
  auto-submitting SAML forms of both products). Host names resolve to the
  published ports through `curl --resolve`, so issuers and entity IDs are
  the same inside and outside Docker.

| Scenario | Configuration | Profile exercised | Checked |
| --- | --- | --- | --- |
| 1. ProudAuth OpenID Provider, Keycloak relying party | Keycloak identity provider of type `oidc` filled by importing ProudAuth's discovery document; a confidential ProudAuth client with Keycloak's broker endpoint as redirect URI, `.../broker/{alias}/endpoint/logout_response` as post-logout redirect URI and Keycloak's `.../protocol/openid-connect/logout/backchannel-logout` as `backchannel_logout_uri` | Authorization code; PKCE `S256`; `client_secret_basic`; scope `openid email profile` without `resource` (the access token's audience is UserInfo); `state`, `nonce` and the RFC 9207 `iss` response parameter; RS256 ID token verified by Keycloak through the JWKS; UserInfo; RP-initiated logout with `id_token_hint`, `post_logout_redirect_uri` and `state`; back-channel logout token with `sid` | Keycloak creates the user with ProudAuth's email and names, linked to ProudAuth's `sub`; logout ends the sessions on both sides; revoking the user's ProudAuth sessions ends Keycloak's brokered session |
| 2. Keycloak OpenID Provider, ProudAuth OIDC connection | ProudAuth connection with adapter `oidc`, the Keycloak realm as issuer and `jit_provisioning`; a confidential Keycloak client requiring PKCE `S256`, with ProudAuth's callback as redirect URI and `.../oidc/logout/upstream-return` as post-logout redirect URI | Discovery; authorization code; PKCE `S256`; `client_secret_basic` (form-encoded credentials); scope `openid email profile`; `nonce`; RS256 ID token verified against Keycloak's JWKS; Keycloak's login form; upstream logout (FED-013) with `client_id` and `post_logout_redirect_uri`, which Keycloak confirms on its logout page | A just-in-time account with Keycloak's verified email, linked to the Keycloak realm's issuer and user ID; a second sign-in (`prompt=login`, Keycloak's SSO session) reuses the link; upstream logout ends the Keycloak session |
| 3a. ProudAuth SAML identity provider, Keycloak service provider | Keycloak identity provider of type `saml` imported from ProudAuth's IdP metadata, with "HTTP-POST binding response", "Want AuthnRequests signed", signature validation, signed assertions, a persistent NameID policy and attribute importers; a ProudAuth SAML application from Keycloak's SP metadata (`require_signed_requests` from `AuthnRequestsSigned`); a second pair with "Want assertions encrypted" and `encrypt_assertions` | `AuthnRequest` over HTTP-Redirect signed with RSA-SHA256; response over HTTP-POST with response and assertion signed (RSA-SHA256, SHA-256 digests, exclusive canonicalization); persistent NameID; attributes `email`, `firstName`, `lastName`; an encrypted assertion (AES-256-GCM, RSA-OAEP with MGF1); SP-initiated single logout over HTTP-Redirect, signed both ways | Keycloak creates the users linked to the persistent NameID (`sps_...`); single logout ends the ProudAuth session and Keycloak's |
| 3b. Keycloak SAML identity provider, ProudAuth SAML connection | ProudAuth SAML connection from Keycloak's IdP metadata with a persistent NameID, `email_attribute`, `trust_email_verified`, `require_signed_assertions` and `jit_provisioning`; a Keycloak SAML client made from ProudAuth's SP metadata by Keycloak's client description converter, with user property mappers for `email`, `givenName` and `sn`, and the realm's default client scopes (`role_list` included) | `AuthnRequest` over HTTP-Redirect signed with RSA-SHA256; response over HTTP-POST with response and assertion signed (RSA-SHA256, exclusive canonicalization, `KeyInfo` with `KeyName` and the certificate); persistent NameID (`G-...`); one `Role` attribute element per role | A just-in-time account linked to Keycloak's entity ID and NameID, with Keycloak's email in its ID token |
| 4. Refusals (TEST-028, TEST-051) | — | A replayed authorization code; a Keycloak identity provider configured with a wrong client secret; a ProudAuth connection configured with a wrong upstream client secret; a replayed federation callback; Keycloak's `AuthnRequest` with a changed `RelayState`, replayed, and asking for an HTTP-Redirect response ("HTTP-POST binding response" off); Keycloak's SAML response with a changed email attribute, and the good response replayed | `invalid_grant` ("authorization code already used", the grant is revoked); `401 invalid_client` and a Keycloak error page, no user; `federation_error=upstream_invalid_response`, no account; `400`; `400` with reasons `saml_signature`, `saml_request_replay` and `saml_unregistered_acs`; `upstream_invalid_response` (audit reason `response_signature:invalid`), no account, then `400 invalid_proof` |

What the runs found:

- **Defect, fixed:** the SAML broker refused every response that repeated
  an attribute name (`duplicate_attribute`). Keycloak's default client scope
  `role_list` (mapper "role list" with "Single Role Attribute" off) sends one
  `Role` element per role, and Keycloak users normally hold roles
  (`default-roles-<realm>`), so no such user could sign in through a SAML
  connection to Keycloak in its default configuration. Repeated names are now
  one multi-valued attribute; the connection's subject and email attributes
  must still appear once ([saml.md](saml.md#response-validation),
  `TestSAMLBroker`).
- **Keycloak settings that matter:** ProudAuth's SAML applications receive
  responses over HTTP-POST only, so the Keycloak identity provider needs
  "HTTP-POST binding response"; without it Keycloak asks for HTTP-Redirect
  and ProudAuth answers `saml_unregistered_acs` (checked by the script). Keycloak's SP metadata lists
  an HTTP-Redirect ACS as its default; ProudAuth registers only the HTTP-POST
  one. ProudAuth's IdP metadata says `WantAuthnRequestsSigned="false"`
  because signing is decided per application, so turn on "Want
  AuthnRequests signed" at Keycloak when the application requires signed
  requests (the default when its metadata has a certificate).
- **Documentation gap, fixed:** back-channel logout, webhook and hook
  deliveries trust the system roots only (there is no `delivery` CA file); a
  private CA goes into the system trust store
  ([configuration.md](../operations/configuration.md#delivery)).

##### Not covered with Keycloak

- Keycloak in production mode (`start`, an external database, fixed host
  names, a reverse proxy) and other Keycloak releases.
- ProudAuth in production mode: the run uses development mode for the email
  sink and for private-network egress (`allow_private_network`,
  `allow_private_webhooks`); production uses `federation.egress_allowlist`
  and `delivery.egress_allowlist`, which are not exercised.
- OpenID Connect: `client_secret_post`, `client_secret_jwt` and
  `private_key_jwt` between the products; ES256, PS256 or EdDSA keys;
  pairwise subjects; refresh tokens and `offline_access`; PAR, DPoP, JARM,
  encrypted ID tokens and the `claims` parameter; `prompt`, `max_age`,
  `login_hint` or `acr_values` forwarded by Keycloak; front-channel logout;
  logout from Keycloak towards ProudAuth when ProudAuth is the relying party
  (ProudAuth accepts no logout from upstream providers, FED-013).
- SAML: `AuthnRequest`s over HTTP-POST; IdP-initiated SSO; Artifact and SOAP
  (not supported); encrypted assertions from Keycloak (the broker refuses
  them); unsigned requests; `emailAddress`, `transient` and `unspecified`
  NameIDs; `ForceAuthn`, `IsPassive` and `RequestedAuthnContext`; logout
  initiated by ProudAuth (not supported) or by Keycloak as identity provider;
  a signing-key rollover while Keycloak holds ProudAuth's metadata.
- Real browsers (cookies, `SameSite`, Keycloak's scripts), load, and clock
  skew between the hosts.

## Untested claims

These are described in the documentation, or follow from the standards
ProudAuth implements, but no test in this repository exercises them against the
real counterpart. Treat them as expectations to verify in your environment:

- **Third-party relying parties and gateways** (for example
  `openid-client`, Spring Security, oauth2-proxy, Envoy): expected to work
  through standard discovery, PKCE and JWKS; not run. Only `go-oidc` with
  `golang.org/x/oauth2` and Keycloak 26.8.0 (identity brokering) have run,
  in the profiles listed under [Third-party products](#third-party-products).
- **Real upstream identity providers** (Google, Microsoft Entra ID, Okta,
  GitHub, …). The `google` and `microsoft` adapters encode those providers'
  documented issuers, tenant claims and email semantics; only test doubles
  have signed users in, and only the configuration of these two adapters is
  tested. Upstream end-session endpoints of these providers are not tested.
  The only real provider that has signed users in is Keycloak 26.8.0,
  through the generic `oidc` adapter and a SAML connection
  ([profiles](#keycloak-2680-protocol-profiles)).
- **SCIM clients of real directories** (Okta, Microsoft Entra ID, Google
  Workspace, HR systems): the request shapes they are known to send are
  covered by `TestSCIMProvisioning`; no real directory has provisioned against
  ProudAuth and no SCIM conformance suite has been run
  ([scim-provisioning.md](scim-provisioning.md)).
- **SAML service providers and identity providers** other than Keycloak
  26.8.0 (for example Shibboleth, SimpleSAMLphp, Okta, Microsoft Entra ID,
  ADFS, SaaS applications): both SAML roles have been exercised against the
  test SP and IdP in this repository and against Keycloak 26.8.0
  ([profiles](#keycloak-2680-protocol-profiles)), and against nothing else.
  SAML-010 asks for tests against multiple independent implementations;
  Keycloak is one, and no SAML conformance suite has been run
  ([saml.md](saml.md#testing-and-interoperability-status)).
- **Real directories** (Microsoft Active Directory, OpenLDAP, 389 Directory
  Server, other LDAP servers): LDAP sign-in, synchronization, failover and
  write-back have run only against the in-process `ldaptest` server
  ([directory.md](directory.md#testing-and-interoperability-status)).
- **Downstream SCIM services** for outbound provisioning (SaaS applications,
  directories) other than ZITADEL v4.16.3: only the in-process SCIM double
  and ZITADEL, in the profile listed above, have received pushes; no SCIM
  conformance suite has been run
  ([outbound-provisioning.md](outbound-provisioning.md#testing-and-interoperability-status)).
- **Challenge providers.** The verification request follows the siteverify
  interface several bot-detection services use; only a test double answers it.
- **KMS and HSM command-line tools** (AWS KMS, Google Cloud KMS, HashiCorp
  Vault transit, PKCS#11 tools): the `kms:` contract is tested with a stand-in
  command only ([keys.md](../operations/keys.md#kms-envelope-dep-016)).
- **OpenTelemetry collectors and tracing back ends**: only the OTLP/HTTP JSON
  payload shape is tested.
- **Real browsers** (cookies, SameSite and CORS behavior are exercised only
  through Go HTTP clients), and custom domains behind a real reverse proxy and
  TLS certificates.
- **Hardware or platform authenticators**, and attestation formats other than
  `none` and the test double's `packed` attestation; a real FIDO Alliance
  Metadata Service BLOB (tests load a BLOB signed under a test root); related
  origins in browsers with WebAuthn Level 3 support
  ([passkey-trust.md](../operations/passkey-trust.md)).
- **The check-session iframe in real browsers**, including how third-party
  cookie blocking and partitioning affect it
  ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#session-management-oidc-014)).
- **Real shared-signals transmitters and receivers** (CAEP and RISC
  implementations of identity providers, SaaS platforms or security
  products): only the test servers in this repository have exchanged events,
  and no SSF interoperability suite has been run
  ([shared-signals.md](shared-signals.md)).
- **Container registries** (Distribution, Harbor, cloud registries) and the
  Docker client: the token endpoint was driven directly by the test harness
  ([container-registry.md](container-registry.md)).
- **Workload identity issuers** (GitHub Actions, Kubernetes service-account
  token issuers, SPIFFE implementations such as SPIRE): the `jwt-bearer`
  grant is tested only with tokens the test suite signs in their shapes,
  with key sets served locally ([workload-federation.md](workload-federation.md)).
- **Mutual TLS behind real proxies and with real certificate authorities**
  (nginx or Envoy forwarding client certificates, smart cards for X.509
  sign-in): tests use in-process TLS and certificates generated by the test
  suite ([mutual-tls.md](../protocols/mutual-tls.md)).
- **FAPI 2.0.** The `fapi2` client profile is tested by `TestFAPI2Profile`
  only. **It is not certified by the OpenID Foundation and no FAPI
  conformance suite has been run** ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#fapi-20-security-profile-adv-001)).
- **Dynamic registration, JARM, encrypted responses and front-channel logout
  with third-party clients** (relying-party libraries, OpenID Connect
  conformance tools): exercised only by the test harness's own clients
  (`TestDynamicClientRegistration`, `TestJARM`, `TestEncryptedResponses`,
  `TestFrontChannelLogout`); front-channel frames were not run in a real
  browser.
- **External policy engines** (Open Policy Agent and others): the engine
  contract is tested against a local HTTP double (`TestExternalPolicyEngine`),
  not against a real engine.
- **Real SMTP servers and real SMS gateways** (end-to-end tests use the
  development sinks; the `webhook` SMS adapter is unit-tested against a local
  HTTP server in `internal/notification/sms_test.go`).
- **Other runtime versions**: PostgreSQL other than 17 and 18, Node.js other
  than 22 (including the declared minimum 20.10), Dart other than 3.13.3
  (including the declared minimum 3.4), PHP 8.3 and 8.4, Go releases other
  than the 1.27 patch release CI used (including the `go.mod` minimum
  1.27.1).
- **Mixed-version deployments with two real binaries.** TEST-061 is covered at
  the storage layer (`TestMixedVersionWindow` simulates migrations from a newer
  release).
- **Operation in a network-isolated container.** TEST-072 is covered in-process
  (`TestOfflineOperation` blocks non-loopback dialing and DNS).
- **Multi-node behavior** (several servers and workers against one database):
  the suite runs one in-process server; see
  [benchmarks.md](../operations/benchmarks.md#not-covered-yet).

Contributions that add interoperability tests against named third-party
versions are welcome; record the exact versions in
[Tested profiles](#tested-profiles) when they land.
