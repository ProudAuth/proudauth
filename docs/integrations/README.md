# Integrations

How applications and services integrate with ProudAuth (docs/plan.md §28).

| Document | For |
| --- | --- |
| [resource-servers.md](resource-servers.md) | APIs that accept ProudAuth tokens: offline vs strict-online validation, authorization checklist, policy decisions, token exchange, the support-access contract |
| [backend-for-frontend.md](backend-for-frontend.md) | Web applications using a server-side BFF with the OIDC client SDK |
| [machine-clients.md](machine-clients.md) | Services using client credentials, API keys and personal access tokens; agents, acting on behalf of a user, and the ownership report |
| [webhooks.md](webhooks.md) | Systems consuming signed event deliveries |
| [scim-provisioning.md](scim-provisioning.md) | Directories and HR systems provisioning an organization's users and groups through SCIM 2.0: connectors, role ceilings and group mappings, supported operations and filters, deprovisioning semantics (PROV-001..PROV-009, PROV-018) |
| [patterns.md](patterns.md) | HTTP, GraphQL, gRPC, WebSockets, long-lived streams, background jobs, message consumers, download grants, multi-issuer applications and contract validation (INT-001..INT-010) |
| [sdk-compatibility.md](sdk-compatibility.md) | SDK runtimes, versioning and breaking changes, protocol compatibility, deprecation reporting, security updates, framework adapters and `identity-cli config-*` automation (SDK-010..SDK-012) |
| [interoperability.md](interoperability.md) | Tested profiles with exact versions, untested claims, and conformance and certification status (QA-004, QA-006) |
| [saml.md](saml.md) | SAML 2.0 service providers signing users in through a realm (SAML applications) and enterprise SAML identity providers used for sign-in (SAML connections): endpoints, registration, NameIDs and attributes, signing keys and rollover, response validation, single logout subset, XML safety, what is not supported; tested against Keycloak 26.8.0 in both roles (APP-018, FED-014, SAML-001..SAML-010) |
| [directory.md](directory.md) | LDAP and Active Directory: realm and organization connectors, TLS and failover, sign-in by bind, first sign-in provisioning, synchronization, conflicts and deletion safety, directory-authoritative attributes and write-back, connector evidence; why Kerberos/SPNEGO is not offered (PROV-011..PROV-015, PROV-017, PROV-018, FED-015, USR-022) |
| [workflows.md](workflows.md) | Lifecycle workflows: event, schedule and manual triggers, the bounded step vocabulary, approvals, publisher accountability and delegation ceilings, durable runs with idempotent steps and compensation, the step-call contract for endpoints, API and diagnostics (EXT-015, EXT-016) |
| [plugins.md](plugins.md) | Signed plugin packages of hooks, webhook subscriptions and workflows: publisher keys, package format, review, install, upgrade, rollback, disable and uninstall, data kept (EXT-014) |
| [extension-contracts.md](extension-contracts.md) | Independently versioned extension contracts: webhook event versions 1 and 2, the hook contract and `ProudAuth-Hook-Version`, plugin manifest and workflow definition versions, `GET /extension-contracts`, support window and compatibility tests (EXT-018) |
| [outbound-provisioning.md](outbound-provisioning.md) | Pushing accounts and groups to downstream SCIM 2.0 services: eligibility, mapping, deliveries and retries, idempotency, reconciliation; the tested ZITADEL v4.16.3 profile (PROV-010, PROV-017) |
| [shared-signals.md](shared-signals.md) | Security events with other systems: the declared Shared Signals (SSF 1.0, CAEP, RISC) transmitter profile, receivers and streams, push and poll delivery, subjects and privacy; the receiver for registered transmitters with replay defenses, subject mapping and explicit action policies (AUD-016, ADV-007) |
| [partner-access.md](partner-access.md) | Organization relationships (parent/child, partner) that grant nothing by themselves, and partner project access: owner-issued project grants with a delegated role subset, partner-side assignments and what ends them (TEN-021, TEN-020) |
| [container-registry.md](container-registry.md) | Container registries using ProudAuth as their Distribution token server: registry services, repository rules, credentials, token format and errors (ADV-010) |
| [dynamic-client-registration.md](dynamic-client-registration.md) | Software registering its own OAuth clients (RFC 7591/7592): realm policy, initial access tokens, metadata rules, approval of open registrations, registration management, limits (APP-016, APP-017, ADV-003) |
| [workload-federation.md](workload-federation.md) | Workloads (GitHub Actions, Kubernetes, SPIFFE, other JWT issuers) obtaining service tokens without stored secrets through the `jwt-bearer` grant: workload trusts, profiles, verification, key fetching (MCH-011..MCH-013, ADV-004) |
| [relationship-authorization.md](relationship-authorization.md) | Object-level authorization: resource types, relationship tuples, object decisions, `list-objects` and user-managed sharing, with their bounds (AZ-021, AZ-022, AZ-023, AZ-027) |
| [policy-engines.md](policy-engines.md) | Connecting an external policy decision point (for example Open Policy Agent) to the decision API: operator configuration, realm policy, call contract, `restrict` and `decide` modes, failure behavior (AZ-026) |
| [elevation-and-access-reviews.md](elevation-and-access-reviews.md) | Just-in-time role elevation with approval and automatic expiry, and access review campaigns with evidence export (AZ-024, AZ-025) |

Reference implementations in the SDK repositories (`proudauth-sdk-*`) and in
this repository (`examples/`):

| Path | What it shows |
| --- | --- |
| `proudauth-sdk-go/verifier` | Offline JWT verification, strict-online introspection, bounded-state verification fed by the session-event stream, `SupportGuard`, `net/http` `Middleware`, `AuthenticateMetadata` (gRPC, WebSocket and message headers), `MultiIssuer` |
| `proudauth-sdk-go/oidcclient` | Authorization code + PKCE, ID-token validation, serialized refresh, logout |
| `proudauth-sdk-go/admin` | Typed administration client (0.2.0) with problem details, pagination, idempotency keys, one-time secrets wrapped in `admin.Secret`, deprecation reporting |
| `proudauth-sdk-node` | Node.js/TypeScript SDK (0.2.0 on npm): verifier, introspection and `SupportGuard`, bounded-state verification, `MultiIssuerVerifier`, OIDC BFF client, admin client with `Secret`, Express/Connect, `node:http` and Fastify adapters; see interoperability.md for its test status |
| `proudauth-sdk-dart` | Dart SDK (unpublished 0.2.0, no Flutter dependency): the same areas, with signature verification implemented in the package, `authorizeBearer` and a `dart:io` adapter |
| `proudauth-sdk-php` | PHP 8.2+ SDK (unpublished 0.2.0, no Composer dependencies): the same areas, with a shared key-set store for PHP-FPM workers and `RequestAuthenticator` for plain PHP and PSR-15 |
| `proudauth-sdk-dotnet` | .NET 8+ SDK (unpublished 0.2.0): the same areas, with ASP.NET Core authentication and middleware; [usage and test status](https://github.com/proudauth/proudauth-sdk-dotnet/blob/main/README.md) |
| `examples/protected-orders-api` | Strict-online API with support contract and policy decisions |
| `examples/protected-billing-api` | Offline-verifying API |
| `examples/backend-for-frontend` | BFF using `oidcclient` |
| `examples/machine-client` | Client-credentials token request |

## Maturity and maintenance (GOV-006)

Every integration below is maintained by this repository's maintainers (no
community-maintained or unmaintained adapters exist) and follows the 0.x
versioning of the project: the service publishes 0.2.0 prereleases, and the SDKs
version independently ([sdk-compatibility.md](sdk-compatibility.md)).
**Maturity** says how far it has been exercised:

- **In-repo tested**: tested end to end only against test doubles or
  counterparts in this repository ([interoperability.md](interoperability.md#counterparts)).
- **Product-tested**: also exercised against a named release of a real third
  party product ([interoperability.md](interoperability.md#third-party-products)).
- **Unit-tested**: tested in isolation, not end to end.

| Integration | Maturity | Not tested against |
| --- | --- | --- |
| SMTP email delivery | In-repo tested (development sink; SMTP adapter against a local server) | Real mail servers and providers |
| SMS `webhook` adapter | Unit-tested against a local HTTP server | Real SMS gateways |
| OIDC and OAuth upstream federation (generic, `google`, `microsoft`, `github`) | Product-tested: the generic `oidc` adapter with Keycloak 26.8.0 as upstream OpenID Provider (`scripts/interop-keycloak.sh`: code + PKCE, `client_secret_basic`, just-in-time account and link, upstream logout); all adapters in-repo tested (fake provider over TLS) | Google, Microsoft Entra ID, GitHub, Okta; other Keycloak releases |
| OpenID Connect provider for third-party relying parties (libraries and products) | Product-tested: `github.com/coreos/go-oidc/v3` v3.18.0 with `golang.org/x/oauth2` v0.37.0 (`TestOIDCRelyingPartyLibrary`: discovery, code + PKCE, ID-token and JWKS verification across key rotation, UserInfo, refresh); Keycloak 26.8.0 identity brokering (`scripts/interop-keycloak.sh`: code + PKCE, `client_secret_basic`, ID token through the JWKS, UserInfo, RP-initiated and back-channel logout) | Other libraries and gateways (`openid-client`, Spring Security, oauth2-proxy); real browsers |
| SAML applications and SAML connections | Product-tested: Keycloak 26.8.0 as service provider and as identity provider (`scripts/interop-keycloak.sh`: signed HTTP-Redirect requests, signed HTTP-POST responses, persistent NameIDs, encrypted assertions to Keycloak, single logout); in-repo tested against the test SP and IdP (built on the same XML library) | Other SPs and IdPs (Shibboleth, SimpleSAMLphp, Okta, Microsoft Entra ID, ADFS); other Keycloak releases |
| LDAP and Active Directory connectors | In-repo tested (in-process LDAP server) | OpenLDAP, Active Directory |
| SCIM inbound provisioning | In-repo tested (Okta- and Azure AD-style requests from the test harness) | Directory products' SCIM clients |
| SCIM outbound provisioning | Product-tested: ZITADEL v4.16.3 as the SCIM service provider (`scripts/interop-zitadel.sh`; users only, ZITADEL has no groups); in-repo tested against a SCIM double | Other SCIM service providers (SaaS applications, directories); group pushes against a real product |
| Webhooks, hooks, workflows, plugins | In-repo tested | — (contracts are ProudAuth's own) |
| Shared signals transmitter and receiver | In-repo tested | Other SSF implementations |
| Container-registry token bridge | In-repo tested | A real registry (Distribution, Harbor) |
| KMS command adapter | Unit-tested | Any real KMS |
| Migration adapters (Keycloak, ZITADEL, SuperTokens) | Product-tested (one export per product version) | Other releases |
| Go, Node.js, Dart, PHP and .NET SDKs | In-repo tested (Go against the server; the others against mock servers and the shared fixtures) | Their use against a running server, except Go |
| Kubernetes manifests and Compose stack | Compose: CI smoke test; Kubernetes: render check only | A cluster |

Fewer, tested integrations are preferred to many untested ones: a new adapter
is added with tests, a named maintainer and an entry here, and one that loses
its maintainer is deprecated through the CHANGELOG.

Protocol details: [docs/protocols/](../protocols/README.md).
