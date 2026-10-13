# Self-Hosted Identity Provider — Complete Backend Product Specification

**Document version:** 1.0  
**Research date:** 2026-10-10  
**Scope:** Backend-only identity, authentication, authorization, provisioning, and identity operations.  
**Distribution goal:** Fully open-source, fully self-hostable, no paid feature gates.  
**Implementation status:** Proposed requirements and architecture; not an implemented product, audited system, or certification.  
**Reference products:** ZITADEL, Keycloak, and SuperTokens.  
**Intended readers:** Backend engineers, security engineers, maintainers, platform operators, and contributors.

> Build one identity authority that issues trustworthy, narrowly scoped tokens for all participating services. Do not build one universal token that bypasses those services' authorization boundaries.

This document combines a broad reference-product-inspired capability inventory with original implementation requirements. It covers consumer authentication, business organizations, enterprise identity, support impersonation, machine identities, and production operations. It is not a claim that every reference product implements every listed capability, that all their editions are free, or that a finite specification can anticipate every future integration. The advanced backlog deliberately includes capabilities beyond the common intersection of those products.

**Catalogue at a glance:** 578 individually identified requirements; 38 chapters; 144 proposed API route families; 72 end-to-end/security acceptance scenarios; 54 primary references. Route families can contain multiple methods or paths. The acceptance scenarios supplement, rather than replace, the feature-level tests.

## Contents

<!-- TOC -->

- [1. Product Definition and Reading Guide](#1-product-definition-and-reading-guide)
- [2. Free and Open-Source Product Commitments](#2-free-and-open-source-product-commitments)
- [3. Reference Capability Map](#3-reference-capability-map)
- [4. Domain Model and Trust Boundaries](#4-domain-model-and-trust-boundaries)
- [5. Reference Backend Architecture](#5-reference-backend-architecture)
- [6. Organizations, Tenants, Groups, and Delegated Administration](#6-organizations-tenants-groups-and-delegated-administration)
- [7. Projects, Applications, Clients, and API Resources](#7-projects-applications-clients-and-api-resources)
- [8. Registration, Invitations, Join Requests, and Onboarding](#8-registration-invitations-join-requests-and-onboarding)
- [9. Authentication Transactions and Login Flows](#9-authentication-transactions-and-login-flows)
- [10. Passwords, Passkeys, MFA, and Recovery](#10-passwords-passkeys-mfa-and-recovery)
- [11. Social Login and Upstream Identity Federation](#11-social-login-and-upstream-identity-federation)
- [12. User Management, Profiles, Linking, and Account Lifecycle](#12-user-management-profiles-linking-and-account-lifecycle)
- [13. Sessions, Devices, SSO, and Logout](#13-sessions-devices-sso-and-logout)
- [14. Token Platform and Cryptographic Contract](#14-token-platform-and-cryptographic-contract)
- [15. Roles, Permissions, Policies, and Resource Authorization](#15-roles-permissions-policies-and-resource-authorization)
- [16. Administrator-to-Customer Impersonation](#16-administrator-to-customer-impersonation)
- [17. Service Accounts, API Keys, and Workload Identity](#17-service-accounts-api-keys-and-workload-identity)
- [18. Protocol and Interoperability Roadmap](#18-protocol-and-interoperability-roadmap)
- [19. SCIM, Directories, and Enterprise Provisioning](#19-scim-directories-and-enterprise-provisioning)
- [20. Email, SMS, Localization, and Communication Policies](#20-email-sms-localization-and-communication-policies)
- [21. Audit, Security Events, and Evidence](#21-audit-security-events-and-evidence)
- [22. Webhooks, Hooks, Workflows, and Extension Interfaces](#22-webhooks-hooks-workflows-and-extension-interfaces)
- [23. Security, Privacy, and Threat Model](#23-security-privacy-and-threat-model)
- [24. Persistence Model and Database Invariants](#24-persistence-model-and-database-invariants)
- [25. API Conventions and Trust Classes](#25-api-conventions-and-trust-classes)
- [26. Proposed API Inventory](#26-proposed-api-inventory)
- [27. End-to-End Backend Workflows](#27-end-to-end-backend-workflows)
- [28. Service Integration, SDKs, and Backend Consumer Contracts](#28-service-integration-sdks-and-backend-consumer-contracts)
- [29. Specialized and Advanced Extension Profiles](#29-specialized-and-advanced-extension-profiles)
- [30. Deployment, Self-Hosting, and High Availability](#30-deployment-self-hosting-and-high-availability)
- [31. Reliability, Observability, and Incident Operations](#31-reliability-observability-and-incident-operations)
- [32. Nonfunctional Targets and Capacity Validation](#32-nonfunctional-targets-and-capacity-validation)
- [33. Verification, Security Tests, and Acceptance Scenarios](#33-verification-security-tests-and-acceptance-scenarios)
- [34. Import, Migration, Export, and Exit Strategy](#34-import-migration-export-and-exit-strategy)
- [35. Delivery Roadmap and Release Gates](#35-delivery-roadmap-and-release-gates)
- [36. Repository Structure, Governance, and Contribution Contract](#36-repository-structure-governance-and-contribution-contract)
- [37. Architecture Decision Register and Completion Checklist](#37-architecture-decision-register-and-completion-checklist)
- [38. Primary Sources and Research Notes](#38-primary-sources-and-research-notes)
<!-- /TOC -->

## 1. Product Definition and Reading Guide

### 1.1 Mission

Provide a standalone, API-first identity provider and authorization server that an operator can run entirely on infrastructure they control. Applications delegate account authentication and identity lifecycle to this service. Backend services accept its access tokens, validate the intended audience and tenant, and enforce permissions on their own resources.

The product must support a small deployment without a complex platform team and a larger deployment with isolated identity domains, multiple organizations, enterprise federation, audit pipelines, and highly available infrastructure.

### 1.2 Scope boundaries

**Included:** Public authentication protocol endpoints; headless authentication APIs; account self-service APIs; administrative APIs; organization and invitation management; token issuance and verification contracts; RBAC and policy evaluation; service identities; federation; provisioning; event delivery; CLI; backend SDKs; deployment tooling; migrations; audit and observability.

**Excluded as product deliverables:** An administrative dashboard, login-page design, frontend component libraries, mobile applications, visual workflow designers, and application-specific screens. Branding, localization, consent, and authentication interaction metadata remain backend capabilities because external clients need them.

**Not excluded by “backend-only”:** Browser redirects, OAuth callbacks, SAML POST responses, WebAuthn ceremony verification, and browser-session security. Interactive authentication still needs an application-provided browser or native interaction surface. Headless does not mean replacing secure authorization flows with a public password-to-token endpoint. [OIDC-CORE] [PKCE] [NATIVE]

**Not the responsibility of the IdP:** Orders, invoices, files, subscriptions, business ownership records, financial settlement, application billing, and domain-specific authorization facts. Applications remain responsible for enforcing access to those records. The IdP can provide identities, claims, permissions, and policy decisions; it cannot infer business authorization from a valid signature alone. [OWASP-AUTHZ]

### 1.3 Requirement notation

Each identified requirement has a category identifier and delivery priority:

| Priority | Meaning                                                                |
| -------- | ---------------------------------------------------------------------- |
| P0       | Required for the first secure, useful production baseline.             |
| P1       | Required for the full general-purpose platform release.                |
| P2       | Enterprise, interoperability, or scale expansion.                      |
| P3       | Specialized or emerging capability; included in the long-term backlog. |

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` express requirements of **this proposed product**, not an assertion that a standard mandates every chosen default. All numerical limits, lifetimes, architecture choices, and service-level objectives are proposed design decisions unless explicitly attributed to a source.

A later delivery priority never permits an unsafe partial implementation. For example, impersonation must remain unavailable until its authorization, audit, expiry, downstream enforcement, and revocation controls are complete.

A feature is not complete until its API, storage, authorization rules, audit events, negative tests, documentation, and upgrade behavior are complete.

## 2. Free and Open-Source Product Commitments

### 2.1 Distribution requirements

- **OSS-001 [P0] — One complete edition.** All implemented authentication methods, MFA, organizations, SSO, SCIM, auditing, impersonation, authorization, and operational capabilities MUST be available in the same open-source distribution.
- **OSS-002 [P0] — No commercial unlocks.** No license server, activation key, per-user charge, monthly-active-user limit, organization limit, administrator-seat limit, or paid security extension may gate functionality.
- **OSS-003 [P0] — No mandatory vendor cloud.** Startup, login, key rotation, backups, upgrades, and ordinary administration MUST work without contacting a project-operated service.
- **OSS-004 [P0] — Complete source.** Server, workers, CLI, SDKs, deployment manifests, migrations, build definitions, tests, and first-party extensions MUST be publicly buildable from the published source.
- **OSS-005 [P0] — Offline operation.** Support deployments with no outbound Internet access when all enabled authentication and delivery dependencies are local. External social login and public SMS delivery naturally require their respective external providers.
- **OSS-006 [P0] — No hidden telemetry.** Telemetry to third parties is disabled by default. Local logs and metrics do not require enrollment. Any optional telemetry must expose its schema and destination.
- **OSS-007 [P0] — Operator-controlled limits.** Rate limits, payload limits, and resource quotas exist for safety and fairness, not monetization, and remain configurable by the operator.
- **OSS-008 [P1] — Portable exit.** Provide documented exports for identities, organizations, memberships, policies, clients, configuration, and audit records, with explicit treatment of credentials that cannot be safely exported or migrated.
- **OSS-009 [P0] — Honest cost statement.** “Free” means no software license or feature-access fee. Compute, storage, domains, email delivery, SMS, hardware security modules, and operational labor can still cost money.

### 2.2 License decision

**Proposed default for independently written project code: Apache-2.0.** This is a product-governance choice intended to make reuse straightforward, not a legal opinion about every dependency. An alternative is AGPL-3.0 for maintainers who prefer network-copyleft obligations. Select one deliberately before accepting contributions. The Apache license and the Open Source Definition are primary references for this decision. [APACHE] [OSD]

Do not add “noncommercial,” “no competing service,” or other field-of-use restrictions while describing the project as open source under the Open Source Definition. Free software availability also does not prohibit someone from offering paid hosting or support. [OSD]

### 2.3 Reference-product licensing caveats

| Product     | Evidence reviewed                                                                                                                                                                    | Consequence for this project                                                                                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keycloak    | Its repository license is Apache-2.0. [KC-LICENSE]                                                                                                                                   | Review notices, dependencies, and the exact component before reusing code.                                                                                                         |
| ZITADEL     | Its current main-branch license is GNU AGPL version 3. [ZT-LICENSE]                                                                                                                  | Do not assume older licensing descriptions apply to current code or that copied code can simply be distributed as Apache-only.                                                     |
| SuperTokens | The core license distinguishes ordinary Apache-2.0 content from `ee/` content and third-party components; pricing documents paid add-ons for self-hosting. [ST-LICENSE] [ST-PRICING] | Do not treat the entire product or every documented feature as freely reusable Apache code. Implement the desired behavior independently or use appropriately licensed components. |

This is a repository/documentation snapshot, not a legal compatibility determination. Pin exact dependency versions, keep license notices and an SBOM, and review licensing before incorporating third-party code. Product names here indicate inspiration, not affiliation.

## 3. Reference Capability Map

### 3.1 What to learn from each reference

**Keycloak:** Broad protocol interoperability, identity brokering, directory federation, extensible authentication flows, user administration, organizations, sessions, administrative permissions, and impersonation. Its authorization-services documentation also provides a reference for resource/scope policies and permission evaluation. Feature maturity is separately documented and must not be inferred merely from a feature appearing in an administration guide. [KC-ADMIN] [KC-AUTHZ] [KC-FEATURES]

**ZITADEL:** API-oriented identity infrastructure, organizations and delegated project access, human and service identities, authentication policies, event-driven customization, auditability, and token exchange. Its documented impersonation/delegation flow is an important reference for explicitly authorized subject changes. [ZT-DOCS] [ZT-ORG] [ZT-EXCHANGE]

**SuperTokens:** Application-backend integration, composable authentication capabilities, passwordless and social login, session management, account lifecycle, account linking, tenant-specific authentication, and customization hooks. Its documentation distinguishes a trusted core from the application-facing API layer, and includes a user-impersonation implementation guide. These integration patterns are useful even though this proposed product must also expose a standalone standards-based IdP surface. [ST-DOCS] [ST-IMPERSONATION] [ST-SESSION]

### 3.2 Consolidated coverage index

| Capability family               | Target coverage in this document                                                                                           |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Account creation and onboarding | Public, closed, invitation-only, approval-based, imported, federated, anonymous-to-registered, and progressive onboarding. |
| Authentication                  | Password, passkeys, security keys, email codes/links, optional SMS, MFA, enterprise and social federation.                 |
| Identity lifecycle              | Profile, identifiers, linking, recovery, suspension, deletion, export, migration, and provisioning.                        |
| Organizations                   | Memberships, invitations, groups, domain discovery, delegated management, project access, and isolation.                   |
| Authorization                   | Roles, permissions, scopes, ABAC, resource relationships, policy APIs, and decision auditing.                              |
| Token platform                  | OAuth/OIDC, JWT and opaque access tokens, rotation, introspection, revocation, exchange, and proof-of-possession profiles. |
| Privileged support              | Explicit, time-limited, attributable, restricted, revocable customer-account impersonation.                                |
| Non-human identities            | Service accounts, client credentials, personal tokens, scoped API keys, and workload federation.                           |
| Enterprise interoperability     | SAML, SCIM, LDAP/AD, optional Kerberos/X.509, dynamic registration, and high-assurance profiles.                           |
| Extension and operations        | Hooks, webhooks, jobs, notifications, CLI/SDKs, audit, observability, backup, HA, and incident response.                   |

The remainder specifies **the target product**, not a vendor-by-vendor compatibility promise. A release-specific vendor comparison should be maintained separately by implementers when interoperability with a particular deployed version is required.

## 4. Domain Model and Trust Boundaries

### 4.1 Canonical vocabulary

| Entity                     | Meaning and boundary                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Deployment                 | An operator-run installation, including its database and key-management environment.                                      |
| Identity domain / realm    | A security boundary with a canonical issuer, user namespace, clients, signing configuration, and policies.                |
| Organization / tenant      | A business access boundary inside an identity domain; it contains memberships and organization-scoped configuration.      |
| User                       | A human principal with an immutable internal identifier inside one identity domain.                                       |
| Identifier                 | A username, email, phone number, or external identifier used to locate an account; it is not the immutable user identity. |
| External identity          | A binding to a configured upstream provider using a stable upstream subject, not merely an email address.                 |
| Membership                 | A user's relationship to an organization, with state, role assignments, and lifecycle timestamps.                         |
| Group / team               | An organization-scoped collection of members, optionally hierarchical.                                                    |
| Project                    | A logical product or integration boundary grouping clients, API resources, roles, and delegated organization access.      |
| Application / OAuth client | A registered software client with allowed flows, redirects, audiences, and credentials.                                   |
| API resource               | A resource-server registration with a stable audience and declared scopes or permissions.                                 |
| Service principal          | A non-human identity with its own credentials, owner, grants, and lifecycle.                                              |
| Session                    | A server-side record of authenticated continuity, distinct from any individual access token.                              |
| Grant                      | A persisted authorization relationship for a subject, client, resources, scopes, and conditions.                          |
| Actor                      | The authenticated principal actually performing an action, especially in delegated or impersonated sessions.              |
| Subject                    | The principal whose identity or rights are represented by the issued token.                                               |

### 4.2 Core isolation rules

- **DOM-001 [P0] — Stable identifiers.** User, organization, membership, client, and resource IDs MUST be opaque and immutable. Email addresses MUST NOT serve as primary keys or durable subject identifiers.
- **DOM-002 [P0] — Realm-qualified identity.** A principal is identified externally by issuer plus subject. Identical subject strings from different issuers MUST NOT be treated as the same person.
- **DOM-003 [P0] — One organization context.** An organization-scoped access token MUST represent one active organization. A separate account-management token may discover the caller's memberships but is not a business-service token.
- **DOM-004 [P0] — Explicit trust direction.** Trusting an upstream provider does not automatically trust all of its organizations, claims, administrators, or authentication-strength assertions.
- **DOM-005 [P0] — Separate administrative trust.** Deployment operators, realm administrators, organization administrators, support operators, end users, and service principals MUST have separate permission namespaces.
- **DOM-006 [P0] — No cross-realm linking by email.** Cross-realm account merging or automatic identity convergence is prohibited. Any future transfer uses an explicit export/import and re-verification workflow.
- **DOM-007 [P0] — Organization-aware storage.** Scoped writes, reads, unique indexes, caches, jobs, and audit queries MUST include realm and organization context where applicable.
- **DOM-008 [P0] — Least disclosure.** Authentication to one organization MUST NOT disclose another organization's membership, policy, identity provider, or private attributes without permission.
- **DOM-009 [P1] — Ownership is explicit.** Every credential, client, provider connection, policy, and integration must have an accountable owner and a decommissioning path.

### 4.3 Recommended tenancy model

Use realm-wide human identities plus organization memberships as the default. This supports one person belonging to several customer organizations without duplicating their credentials. Organization-specific aliases and profiles may be layered on memberships.

For customers that require genuinely independent identity namespaces, use separate realms. A separate realm with a separate issuer does **not** by itself provide physical isolation from the same deployment administrator, database operator, or host. Separate deployments, keys, and infrastructure are the stronger isolation option.

Never let an organization administrator modify a shared user's global credentials or profile as a side effect of managing one membership. Organization-owned, directory-managed accounts require explicit ownership rules and a transfer/release workflow.

## 5. Reference Backend Architecture

### 5.1 Initial deployment shape

**Proposed implementation choice:** A modular monolith with independently runnable background workers, PostgreSQL as the durable source of truth, and an optional shared cache. Go is a reasonable reference language, but the public contracts and requirements are language-neutral. No mandatory message broker, service mesh, managed cloud database, or proprietary secret manager is required.

```text
Applications / customer-owned login surfaces / backend services
                          |
                    TLS / reverse proxy
                          |
       +------------------+-------------------+
       |                  |                   |
 OAuth/OIDC/SAML     Headless and         Admin and
 protocol APIs      self-service APIs    provisioning APIs
       |                  |                   |
       +------------------+-------------------+
                          |
 Authentication | Identity | Tenancy | Authorization | Tokens
                          |
           Transactional persistence + durable outbox
                          |
             PostgreSQL             Key-store adapter
                  |                 (local or external)
                  |
    Workers: notifications, federation sync, webhooks,
             audit export, cleanup, scheduled lifecycle jobs
                  |
        Optional cache / optional external event sink
```

Public and administrative APIs can run in one binary while being exposed on different listeners or routes. A trusted deployment bootstrap channel is separate from both.

### 5.2 Architectural requirements

- **ARC-001 [P0] — Module boundaries.** Identity, credentials, authentication transactions, sessions, tokens, authorization, organizations, integrations, and audit MUST expose explicit internal interfaces rather than sharing arbitrary table access.
- **ARC-002 [P0] — Durable correctness.** One-time credential consumption, refresh-token rotation, invitation acceptance, ownership transfer, and permission changes MUST rely on durable transactional consistency, not an eventually consistent cache.
- **ARC-003 [P0] — Transactional outbox.** Security-relevant state changes and their audit/outbox records MUST commit together. Workers deliver external side effects after commit.
- **ARC-004 [P0] — No distributed transaction dependency.** Failed email, webhook, or external-directory delivery MUST not leave a half-created local security state. Persist a recoverable job and expose its status.
- **ARC-005 [P0] — Shared revocation authority.** Every node must observe authoritative revocation state according to the resource's declared consistency mode. In-memory-only revocation is insufficient for multiple nodes.
- **ARC-006 [P0] — Stateless request processing.** Requests may reach any node. Browser transactions and grants remain retrievable without sticky sessions.
- **ARC-007 [P1] — Extension isolation.** Untrusted extensions MUST NOT execute in the token signer's security context or obtain direct database/signing-key access.
- **ARC-008 [P0] — Auditable configuration.** Security-sensitive configuration changes use the same permission checks, versioning, and audit path whether initiated through API, CLI, or configuration import.
- **ARC-009 [P0] — No custom cryptographic primitives.** Use maintained, vetted implementations for JOSE, OAuth/OIDC, WebAuthn, password hashing, TLS, and SAML parsing. Application glue still requires threat modeling and conformance tests.
- **ARC-010 [P1] — Split only when measured.** Extract modules into services only when independent scaling, isolation, or ownership justifies the network and consistency cost.

Full event sourcing is optional, not a prerequisite. A relational state model plus append-only audit and an outbox is the initial design; audit events are not automatically sufficient to reconstruct every secret or historical state.

## 6. Organizations, Tenants, Groups, and Delegated Administration

- **TEN-001 [P0] — Organization lifecycle.** Create, retrieve, search, update, suspend, reactivate, archive, and delete organizations through permission-controlled APIs.
- **TEN-002 [P0] — Organization metadata.** Support display name, slug, locale, time zone, validated custom metadata, contact information, and externally assigned IDs without using mutable fields as security keys.
- **TEN-003 [P0] — Membership lifecycle.** Support invited, pending approval, active, suspended, expired, and removed memberships. Each state has documented login and token-issuance consequences.
- **TEN-004 [P0] — Multiple memberships.** A person may join several organizations with different roles. Membership suspension in one organization must not silently suspend unrelated memberships.
- **TEN-005 [P0] — Organization switching.** Issue a new organization-scoped grant after checking active membership, client access, provider restrictions, and required authentication strength. Never change tenant context by trusting a header alone.
- **TEN-006 [P0] — Safe ownership.** Prevent removal, suspension, or demotion of the last active organization owner without an atomic transfer or authorized recovery workflow.
- **TEN-007 [P0] — Delegated administrators.** Organization administrators may manage only permitted members, groups, invitations, provider settings, and roles inside their boundary.
- **TEN-008 [P0] — Assignment ceilings.** An administrator cannot grant permissions outside their explicit delegable set, even if they can create a role or edit a group.
- **TEN-009 [P1] — Verified domains.** Register and verify organization domains with expiring proof challenges, conflict checks, ownership-change handling, and periodic re-verification policies.
- **TEN-010 [P1] — Domain-based discovery.** Route authentication to an organization's configured provider using verified routing configuration. A matching email domain is not proof of membership.
- **TEN-011 [P1] — Multiple domains and providers.** Support aliases, several domains, shared-provider configurations, and explicit conflict-resolution rules without ambiguous silent routing.
- **TEN-012 [P1] — Organization policies.** Override allowed login methods, session lifetimes, MFA requirements, registration mode, invitations, and domain restrictions only within operator-defined safety floors.
- **TEN-013 [P1] — Groups and teams.** Create and manage groups, membership, metadata, and role assignments. Nesting must reject cycles and enforce depth and evaluation limits.
- **TEN-014 [P1] — Dynamic groups.** Optionally derive membership from authoritative attributes with explicit source ownership, recomputation status, and prevention of user-controlled privilege escalation.
- **TEN-015 [P1] — Membership provenance.** Record whether membership came from invitation, administrator assignment, directory synchronization, domain policy, or approved self-join.
- **TEN-016 [P1] — Just-in-time membership.** Allow provider-driven membership only for approved connections and claims, with an explicit default role and no implicit owner/admin assignment.
- **TEN-017 [P1] — Tenant onboarding templates.** Provision repeatable default roles, clients, policies, and integrations using versioned templates with dry-run and diff support.
- **TEN-018 [P1] — Resource fairness.** Apply independent safety quotas and rate budgets so one organization cannot exhaust all authentication workers or notification capacity.
- **TEN-019 [P2] — Stronger isolation tiers.** Provide documented realm-per-customer and deployment-per-customer patterns, including issuer, key, migration, and operational tradeoffs.
- **TEN-020 [P2] — Partner/delegated project access.** Permit a project owner to grant selected project roles to another organization, which may assign only that approved subset to its members.
- **TEN-021 [P2] — Organization relationships.** Represent parent/child or partner relationships explicitly. They MUST NOT imply inherited cross-organization access unless a policy grants it.
- **TEN-022 [P1] — Customer-owned credentials.** Tenant-specific SMTP, upstream IdP, SCIM, and webhook credentials are encrypted and usable only by the intended tenant integration.
- **TEN-023 [P0] — Shared-user safeguards.** A tenant administrator cannot read another tenant's attributes or reset a realm-wide user's MFA merely by having access to one membership.
- **TEN-024 [P1] — Organization deletion workflow.** Preview affected members, grants, clients, and exports; revoke access; retain required audit records; delete asynchronously with retryable progress.

## 7. Projects, Applications, Clients, and API Resources

- **APP-001 [P0] — Project lifecycle.** Manage projects, descriptions, owners, environments, organization grants, and associated clients and API resources.
- **APP-002 [P0] — Client types.** Represent confidential web/BFF, public browser, native, device/CLI, and machine clients with different permitted credentials and grant types.
- **APP-003 [P0] — Client credentials.** Generate high-entropy secrets, display them once, store verifiers rather than recoverable plaintext where possible, and support overlapping rotations with bounded expiry.
- **APP-004 [P0] — Redirect registration.** Require exact registered redirect matching, with only protocol-defined native-loopback exceptions. Reject wildcard production redirects, user-info components, fragments, and open redirect chains.
- **APP-005 [P0] — Origin registration.** Maintain explicit browser origins independently from redirects and audiences. Reject credentialed CORS requests from unregistered origins.
- **APP-006 [P0] — API audiences.** Register each resource server with a stable audience identifier and allowed clients. Audience values are not arbitrary user-controlled URLs.
- **APP-007 [P0] — Scopes.** Declare supported scopes, allowed requesting clients, consent descriptions, default grants, and resource associations. Requesting a scope does not grant it.
- **APP-008 [P0] — Client lifecycle.** Suspend, reactivate, rotate credentials, and decommission clients, with corresponding effects on refresh grants and future issuance.
- **APP-009 [P1] — Asymmetric client authentication.** Support registered public keys and `private_key_jwt`, including assertion replay protection, bounded lifetime, and correct token-endpoint audience validation.
- **APP-010 [P1] — Client policy profiles.** Apply reusable security profiles for public, confidential, privileged, third-party, and high-assurance clients.
- **APP-011 [P1] — Claims configuration.** Map approved attributes to claims using bounded expressions, separate ID-token/access-token policies, and protected reserved claim names.
- **APP-012 [P1] — Pairwise subjects.** Offer client/sector-specific subject identifiers without breaking the operator's internal user identity model or permitted lifecycle operations.
- **APP-013 [P1] — Consent management.** Track user, client, scopes, resources, terms version, timestamps, revocation, and whether consent is required or administratively pre-authorized.
- **APP-014 [P1] — Client ownership.** Support named technical contacts, credential-expiry alerts, owner transfer, and orphaned-client detection.
- **APP-015 [P1] — Environment separation.** Development, staging, and production clients use separate credentials and redirect allowlists; production cannot trust development issuers by accident.
- **APP-016 [P2] — Dynamic registration.** Provide OAuth/OIDC dynamic client registration with approval, registration access tokens, metadata validation, rate limits, and default denial of privileged scopes.
- **APP-017 [P2] — Client registration management.** Support secure retrieval, update, credential rotation, and deletion of dynamically registered clients without broad admin credentials.
- **APP-018 [P2] — SAML applications.** Register entity IDs, assertion-consumer endpoints, bindings, signing/encryption certificates, attribute mappings, and logout destinations.
- **APP-019 [P2] — Client configuration as code.** Validate, export, diff, import, and reconcile project/client configuration without placing plaintext secrets in version control.
- **APP-020 [P1] — Negative capability declaration.** Discovery and client metadata MUST advertise only enabled, tested flows and algorithms; absent features must not appear supported.

Protocol foundations: [OIDC-CORE] [OIDC-DISCOVERY] [AS-METADATA] [PKCE] [NATIVE] [RESOURCE].

## 8. Registration, Invitations, Join Requests, and Onboarding

### 8.1 Registration

- **REG-001 [P0] — Registration modes.** Configure public registration, closed registration, invitation-only registration, domain-restricted registration, and administrator-created accounts per realm and organization policy.
- **REG-002 [P0] — Identifier policy.** Define allowed login identifiers, realm-scoped uniqueness, canonicalization, maximum lengths, and reserved names. Preserve original display values separately.
- **REG-003 [P0] — Safe email normalization.** Normalize domains consistently, document local-part comparison rules, and do not universally strip dots or `+` tags from email addresses.
- **REG-004 [P0] — Verification.** Verify email or phone identifiers with purpose-specific challenges before treating the corresponding identifier as verified. Verification does not automatically satisfy MFA.
- **REG-005 [P0] — Duplicate handling.** Prevent duplicate identities with transactional unique constraints. Public responses must not unnecessarily reveal that an account exists.
- **REG-006 [P0] — Terms acceptance.** Record policy/terms version, acceptance time, scope, and provenance when onboarding requires acceptance.
- **REG-007 [P1] — Progressive profiling.** Require missing attributes at defined policy checkpoints; never let profile completion become a route for editing protected authorization attributes.
- **REG-008 [P1] — Approval queues.** Support pending-registration or join approvals, reviewer permissions, expiry, reasons, and audit trails.
- **REG-009 [P1] — Federated registration.** Allow just-in-time account creation from explicitly trusted provider connections and stable upstream subjects.
- **REG-010 [P1] — Anonymous upgrade.** Permit low-privilege guest identities to become registered accounts without inheriting another user's identity or automatically merging unrelated application data.
- **REG-011 [P1] — Abandoned onboarding.** Expire unverified registrations and unfinished enrollment secrets using configurable cleanup policies.
- **REG-012 [P0] — Abuse resistance.** Enforce signup, challenge-send, resend, and verification budgets per identity hint, IP/network signal, client, realm, and organization.

### 8.2 Invitations

- **INV-001 [P0] — Invitation lifecycle.** Create, list, inspect, resend, revoke, decline, accept, and expire invitations with clear state transitions.
- **INV-002 [P0] — Bound purpose.** Bind each invitation to realm, organization, intended verified identifier or subject, permitted roles, inviter, expiry, and a specific invitation purpose.
- **INV-003 [P0] — Secret handling.** Use an opaque, high-entropy invitation secret, store its digest, and never return that secret in listing or audit APIs.
- **INV-004 [P0] — One successful redemption.** Accept the invitation and create membership/role assignments in one transaction; concurrent redemption cannot create multiple grants.
- **INV-005 [P0] — Existing-account acceptance.** Require an authenticated account that controls the invited identifier; never silently link an unrelated signed-in account from possession of a forwarded URL alone.
- **INV-006 [P0] — New-account acceptance.** Carry the invitation through registration, required verification, and policy-required authentication before final membership activation.
- **INV-007 [P0] — Role ceiling.** The inviter may grant only delegable roles. Recheck the invitation's authorization basis and current role definitions at acceptance, not only at creation.
- **INV-008 [P0] — Suspended destinations.** Reject acceptance when the organization, target subject, issuer, or applicable invitation policy is no longer eligible.
- **INV-009 [P0] — Safe resending.** A resend creates a new secret/version and invalidates the previous one. Resend limits must not reset the overall abuse budget.
- **INV-010 [P0] — Non-mutating link previews.** Email-scanner GET requests and link previews MUST NOT accept invitations or consume secrets. Require an explicit protected confirmation action.
- **INV-011 [P1] — Bulk invitation.** Accept bounded batches, validate each entry, return per-item results, support idempotency, and queue delivery independently.
- **INV-012 [P1] — Application invitations.** Support invitations to specific projects or application access in addition to organization membership, with separate grant semantics.
- **INV-013 [P1] — Join requests.** Support requesting access, approval/denial, expiry, reviewer assignments, and notification without exposing private membership lists.
- **INV-014 [P1] — Identifier changes.** Handle changed or recycled invited addresses by requiring a fresh invitation or explicit administrator-reviewed reassignment.
- **INV-015 [P1] — Shared invitation links.** Optional multi-use links must have limited roles, limited uses, short expiry, explicit audience/domain policy, and no owner/admin grants by default.
- **INV-016 [P0] — Audit.** Record inviter, recipient reference, organization, role IDs, acceptance subject, delivery attempts, state changes, and administrative overrides without recording the secret.

### 8.3 Invitation state machine

```text
created -> pending_delivery -> pending_acceptance -> accepted
                    |                 |
                    |                 +-> declined
                    |                 +-> expired
                    +-----------------+-> revoked

Delivery failure is retryable delivery state, not acceptance authority.
A resend rotates the secret while preserving the invitation's audit history.
```

## 9. Authentication Transactions and Login Flows

### 9.1 Headless interaction contract

Authentication is a server-controlled transaction, not a series of independently trusted client flags. It binds the realm, initiating client, redirect, requested organization, PKCE challenge, required assurance, consent requirements, completed factors, expiry, and anti-forgery context.

- **AUT-001 [P0] — Transaction creation.** Start a short-lived authentication transaction only after validating client, redirect, request parameters, and applicable policy.
- **AUT-002 [P0] — Structured next actions.** Return machine-readable next steps such as identify, password, external redirect, passkey, TOTP, verification, consent, or required profile fields.
- **AUT-003 [P0] — Continuation protection.** Protect every continuation with transaction-bound secrets or cookies plus applicable CSRF/origin controls. A transaction ID alone is not sufficient authorization.
- **AUT-004 [P0] — Server-owned completion.** Only the server may mark factors, verification, consent, or required actions complete. Ignore client-submitted `authenticated`, `mfa_passed`, or role flags.
- **AUT-005 [P0] — Account/password login.** Support permitted username/email/password combinations with generic failure responses and bounded timing differences.
- **AUT-006 [P0] — Multi-step enforcement.** Do not issue normal access or refresh tokens while required verification, MFA, terms, or account-state checks remain incomplete.
- **AUT-007 [P0] — Anti-fixation.** Rotate pre-authentication session handles after successful authentication and after privileged context changes.
- **AUT-008 [P0] — Restart and expiry.** Expired, cancelled, consumed, or policy-invalidated transactions cannot be resumed; restart behavior must be explicit and safe.
- **AUT-009 [P1] — Identifier-first login.** Support organization/provider discovery without exposing private account or membership information through unrestricted enumeration endpoints.
- **AUT-010 [P1] — Step-up authentication.** Request fresh or stronger authentication for sensitive scopes/actions, with a bound return transaction and no downgrade on fallback.
- **AUT-011 [P1] — Account selection.** Support selecting among authenticated accounts or organizations without confusing the subject bound to the original request.
- **AUT-012 [P1] — Authentication policy engine.** Evaluate client, organization, method, risk signals, prior assurance, and action requirements using a versioned, bounded flow definition.
- **AUT-013 [P1] — Remembered devices.** Support revocable, expiring remembered-device grants that reduce prompts only where policy allows; never treat a browser fingerprint as cryptographic device proof.
- **AUT-014 [P1] — Risk signals.** Consume local or optional external signals and produce explainable allow, deny, challenge, or review outcomes. Missing signals must not silently satisfy stricter policy.
- **AUT-015 [P0] — Authentication context.** Store accurate factor evidence, authentication times, and assurance context. Define local assurance profiles instead of claiming external certification from an `acr` string.
- **AUT-016 [P0] — Multiple browser tabs.** Isolate concurrent transactions so one tab cannot consume another client's code or complete another organization's login accidentally.
- **AUT-017 [P0] — Reauthentication semantics.** A valid session does not bypass a client's fresh-authentication request. Session refresh must not fabricate a new password/passkey authentication time.
- **AUT-018 [P1] — Required actions.** Support forced credential update, verified-contact update, factor enrollment, terms acceptance, and profile completion with per-action permissions and audit.
- **AUT-019 [P2] — Declarative flows.** Version authentication-flow definitions; validate reachability, prohibit bypass paths, simulate policy changes, and publish rollback-safe revisions.
- **AUT-020 [P0] — Safe redirects.** Return only prevalidated redirects or opaque continuation references. Never reflect untrusted `return_to` destinations.

Protocol references for interactive and step-up behavior: [OIDC-CORE] [STEPUP]. These headless transaction APIs are project-specific and MUST NOT be advertised as an independently standardized OAuth grant.

### 9.2 Passwordless email and optional phone methods

- **PWDLESS-001 [P1] — Email OTP.** Create short-lived, attempt-limited codes tied to transaction, purpose, identifier, and account context.
- **PWDLESS-002 [P1] — Magic links.** Use single-use high-entropy secrets with explicit confirmation, expiration, anti-login-CSRF protection, and scanner-safe behavior.
- **PWDLESS-003 [P1] — Cross-device completion.** Default to initiation-context binding. Cross-device links require a deliberately designed confirmation/pairing flow, not silently relaxed session binding.
- **PWDLESS-004 [P1] — Send and resend budgets.** Apply cooldowns, aggregate spending/safety limits, and abuse protection to prevent email bombing or SMS cost attacks.
- **PWDLESS-005 [P1] — Optional SMS login.** Expose an interchangeable provider interface; keep SMS disabled where the operator cannot accept its assurance and delivery risks.
- **PWDLESS-006 [P1] — Channel independence.** Email verification, passwordless email login, and an email code must not automatically count as separate independent authentication factors.
- **PWDLESS-007 [P1] — Code storage.** Store low-entropy OTP verifiers using keyed protection plus strict online attempt limits; an unsalted or unkeyed fast digest of a six-digit code is insufficient against database disclosure.
- **PWDLESS-008 [P1] — Safe account resolution.** A passwordless challenge cannot become an account-linking or account-creation permission unless that exact workflow was authorized.

## 10. Passwords, Passkeys, MFA, and Recovery

### 10.1 Password credentials

- **CRED-001 [P0] — Password hashing.** Use Argon2id for ordinary deployments with versioned, benchmarked parameters and unique salts; use an appropriate reviewed alternative for deployment profiles with different cryptographic requirements. [OWASP-PASSWORD]
- **CRED-002 [P0] — Password policy.** Proposed default: minimum 15 characters, support at least 64 and default maximum 128 Unicode characters, allow password managers and paste, and reject common/compromised passwords. Do not impose arbitrary composition rules or scheduled changes without a compromise or specific policy reason. These choices are informed by NIST password guidance. [NIST]
- **CRED-003 [P0] — Bounded processing.** Enforce input byte limits before hashing, document Unicode normalization, and never silently truncate passwords.
- **CRED-004 [P0] — Hash upgrades.** Rehash after a successful login when parameters or algorithms are obsolete. Preserve supported legacy-hash verification only during a controlled migration.
- **CRED-005 [P0] — Secret non-disclosure.** No administrative API can reveal an existing password, password hash, password-reset secret, or reusable session secret.
- **CRED-006 [P0] — Password change.** Require recent authentication and appropriate factor policy; notify the account owner and revoke sessions according to a documented rule.
- **CRED-007 [P0] — Password reset.** Use single-use, purpose-bound, expiring reset challenges and generic public responses. Resetting a password MUST NOT automatically remove MFA requirements.
- **CRED-008 [P0] — Compromise response.** Support marking credentials compromised, forcing a secure recovery workflow, and invalidating affected refresh grants and sessions.
- **CRED-009 [P1] — Pepper support.** Optionally support externally protected password peppers with explicit rotation/recovery implications and key-version tracking.
- **CRED-010 [P1] — Password history.** Offer bounded history only where policy requires it, with the same storage protections as active verifiers and a clear retention limit.

### 10.2 Passkeys and hardware security keys

- **PASS-001 [P1] — Registration ceremonies.** Generate and verify WebAuthn registration options and responses; bind challenge, user, realm, RP ID, origin, ceremony type, and expiry.
- **PASS-002 [P1] — Authentication ceremonies.** Verify challenge, origin, RP-ID hash, signature, credential ownership, and required user presence/verification before completing authentication.
- **PASS-003 [P1] — Discoverable credentials.** Support username-less passkey login and non-discoverable security-key flows according to client and authenticator capabilities.
- **PASS-004 [P1] — Multiple authenticators.** Let users register, name, list, and remove multiple credentials after appropriate recent authentication; expose safe metadata only.
- **PASS-005 [P1] — Lost-key handling.** Support a documented recovery route without silently allowing a weaker factor to bypass a tenant's minimum assurance.
- **PASS-006 [P1] — Synced passkeys.** Record backup eligibility/state where supplied and apply explicit policy for synced versus device-bound authenticators.
- **PASS-007 [P1] — Counter semantics.** Treat signature-counter anomalies as a risk signal with authenticator-aware handling; do not assume every valid synced passkey has a strictly increasing counter.
- **PASS-008 [P1] — RP-ID planning.** Document how custom login domains affect credential scope and migration. Passkeys are not portable to arbitrary new RP IDs merely by changing issuer configuration.
- **PASS-009 [P2] — Attestation policy.** Support optional attestation verification, trusted metadata, authenticator restrictions, and privacy-conscious defaults.
- **PASS-010 [P2] — Advanced WebAuthn capabilities.** Gate optional extensions and related-origin behavior on supported specification versions, explicit trust configuration, and tests rather than permissive fallback.

The WebAuthn specification is the primary ceremony and authenticator reference. Client-side biometric/PIN interaction remains outside the backend deliverable. [WEBAUTHN]

### 10.3 MFA and recovery

- **MFA-001 [P0] — TOTP.** Support enrollment, proof-before-activation, authentication, removal, and recovery; encrypt TOTP seeds because validation requires access to the secret.
- **MFA-002 [P0] — TOTP replay control.** Bound clock tolerance, reject already-consumed time-step proofs where required, rate-limit attempts, and handle concurrent submissions transactionally.
- **MFA-003 [P0] — Administrative MFA.** Privileged administrators and impersonation actors MUST use MFA; production bootstrap must lead to enrollment rather than a permanently exempt account.
- **MFA-004 [P0] — Recovery codes.** Generate high-entropy single-use codes, show them once, store protected verifiers, and consume them atomically. Regeneration invalidates all previous codes.
- **MFA-005 [P1] — Factor policies.** Require selected factor combinations per realm, organization, client, role, or operation, while preventing administrators from lowering an operator-defined safety floor.
- **MFA-006 [P0] — Factor enrollment protection.** Adding or replacing a factor requires recent suitable authentication; possession of a stolen long-lived session is not enough.
- **MFA-007 [P1] — WebAuthn assurance.** Count a user-verified authenticator according to its documented profile; do not blindly require two separate screens when a permitted multi-factor authenticator already supplies the required evidence.
- **MFA-008 [P0] — Recovery policy.** Distinguish lost password, lost factor, lost contact address, compromised account, and directory-managed account recovery.
- **MFA-009 [P1] — Support-assisted recovery.** Require explicit permission, evidence/reason, notifications, cooling-off or approval where configured, and immutable attribution. Support must not simply read or replace secrets silently.
- **MFA-010 [P0] — Recovery restrictions.** Sessions authenticated only through recovery receive reduced privileges until the required factor assurance is restored.
- **MFA-011 [P0] — No security questions.** Knowledge-based personal questions are not an accepted recovery factor in the default product.
- **MFA-012 [P0] — Factor lifecycle audit.** Audit enrollment start/completion, use, removal, resets, failed proof attempts, and recovery without storing submitted codes or seeds in logs.
- **MFA-013 [P2] — HOTP compatibility.** Optional HOTP requires atomic counter advancement, bounded resynchronization, and separate policy from TOTP.
- **MFA-014 [P3] — Push or out-of-band approval.** Optional push requires transaction binding, anti-fatigue controls, explicit device enrollment, and no blind approve/deny prompts for privileged operations.

NIST is an assurance-design reference; implementing these features does not by itself establish compliance with every NIST assurance requirement. [NIST]

## 11. Social Login and Upstream Identity Federation

- **FED-001 [P1] — Generic OIDC broker.** Configure upstream issuer, client registration, claims, scopes, discovery behavior, and provider-specific policy.
- **FED-002 [P1] — Social provider adapters.** Supply maintained adapters for selected providers and a generic extension interface; keep their identity semantics distinct from ordinary OIDC where necessary.
- **FED-003 [P1] — Stable subject binding.** Resolve external identities by configured connection plus validated upstream issuer/subject, not by a mutable display name or email alone.
- **FED-004 [P1] — Safe linking.** Require proof of control of both identities, or an explicitly reviewed trusted-provider linking policy with verified-identifier and organization constraints.
- **FED-005 [P1] — First-login conflict workflow.** Detect collisions and request safe account verification instead of attaching the external identity to an existing account automatically.
- **FED-006 [P1] — Provider-specific configuration.** Allow different connections, credentials, domain routing, and allowed upstream tenants for different organizations.
- **FED-007 [P1] — Callback validation.** Validate state, nonce when applicable, issuer, code/client binding, redirect, signatures, and upstream token claims using protocol-specific rules.
- **FED-008 [P1] — Claims ownership.** Mark provider-authoritative fields and update rules. A federated claim must not overwrite protected local administrative assignments without an explicit mapping policy.
- **FED-009 [P1] — Assurance mapping.** Trust upstream MFA/assurance claims only from configured issuers and known semantics; otherwise require a local step-up.
- **FED-010 [P1] — Token custody.** Do not retain upstream access/refresh tokens unless an enabled integration requires them. Encrypt retained tokens and restrict downstream retrieval to explicit audiences and grants.
- **FED-011 [P1] — Unlink protection.** Prevent removal of the last viable sign-in or recovery method unless a secure replacement or account-deletion workflow is completed.
- **FED-012 [P1] — Provider outage policy.** Expose clear retry/failure states. Do not silently bypass an organization's mandatory enterprise SSO by offering an unauthorized local password login.
- **FED-013 [P1] — Federation logout.** Define local versus upstream logout separately and report incomplete upstream logout honestly.
- **FED-014 [P2] — SAML broker.** Authenticate against enterprise SAML IdPs with explicit metadata, validation, attribute mapping, replay protection, and certificate rollover.
- **FED-015 [P2] — Inbound workforce federation.** Support directory-backed and workforce identity sources without assuming that a successfully authenticated workforce user belongs to every customer organization.
- **FED-016 [P2] — Federation transfer.** Support changing provider connections or upstream tenant IDs using a reviewed migration map and collision reporting, not a bulk email-based relink.
- **FED-017 [P1] — Configuration fetch safety.** Discovery, JWKS, metadata, and callback URLs must pass SSRF controls, response-size limits, TLS validation, and redirect restrictions.
- **FED-018 [P1] — Upstream scope minimization.** Request only necessary upstream claims and API scopes; adding provider API access requires separate consent and credential-retention policy.

Federation and brokering are reference capability families, while these isolation and linking rules are target-product decisions. [KC-ADMIN] [ST-DOCS] [JWT-BCP]

## 12. User Management, Profiles, Linking, and Account Lifecycle

- **USR-001 [P0] — User administration.** Create, retrieve, search, update permitted fields, suspend, reactivate, and delete users through explicitly scoped administrative APIs.
- **USR-002 [P0] — Self-service profile.** Allow users to view and change permitted profile fields without exposing administrator-only or tenant-private attributes.
- **USR-003 [P0] — Account state.** Define pending verification, active, suspended, locked, recovery-restricted, pending deletion, and deleted states, with separate temporary abuse locks.
- **USR-004 [P0] — Identifier changes.** Require suitable reauthentication and proof of the new address/number; notify the old contact when safe and applicable. Do not mark a changed identifier verified automatically.
- **USR-005 [P0] — Administrative verification overrides.** Require a separate privileged permission and reason to override identifier verification; ordinary profile-edit permission is insufficient.
- **USR-006 [P0] — Search boundaries.** Search and pagination must filter by the caller's administrative scope before returning counts or records. Partial masking does not fix an unauthorized search.
- **USR-007 [P1] — Custom attribute schemas.** Support typed attributes with validation, size limits, visibility, mutability, source ownership, and claim-mapping eligibility.
- **USR-008 [P1] — Multiple identifiers.** Permit several verified emails/phone numbers where enabled, with one primary contact and explicit uniqueness and recovery rules.
- **USR-009 [P1] — User metadata classes.** Separate user-editable metadata, administrator-controlled metadata, organization membership metadata, and confidential internal metadata.
- **USR-010 [P1] — Account linking management.** List, link, and unlink identities; show provenance and last use; require strong proof and audit each binding change.
- **USR-011 [P1] — Account merge workflow.** Treat merging as a privileged migration with conflict resolution, consent/verification, subject mapping, credential review, and application notifications. Do not merge grants blindly.
- **USR-012 [P1] — Deletion requests.** Support a self-service deletion request, recent authentication, configured delay/cancellation, dependency checks, and eventual completion status.
- **USR-013 [P1] — Data export.** Produce a scoped, expiring, auditable export of the caller's permitted identity data without password hashes, seeds, reusable tokens, or other people's attributes.
- **USR-014 [P1] — Administrative deactivation.** Revoke sessions/grants, stop future issuance, and publish deactivation events according to documented consistency guarantees.
- **USR-015 [P1] — User lifecycle jobs.** Support dormant-account review, verification expiry, scheduled deactivation, membership expiry, and deletion cleanup with dry-run and bounded batches.
- **USR-016 [P1] — Bulk operations.** Import, suspend, reactivate, or modify users in bounded jobs with per-record validation, progress, idempotency, and a safe failure report.
- **USR-017 [P1] — External IDs.** Store connector-scoped external IDs and migration mappings without making external IDs globally unique by accident.
- **USR-018 [P1] — Support visibility controls.** Permit masked views for support roles and log access to sensitive identity data where policy requires it.
- **USR-019 [P1] — Account activity API.** Expose safe recent sign-ins, sessions, authenticator activity, security changes, and impersonation history to the account owner.
- **USR-020 [P1] — Ownership transfer.** Transfer organization/project ownership explicitly before deleting accounts that are the last owners of critical resources.
- **USR-021 [P1] — Recycled identifiers.** Do not restore an old user's grants merely because a new account controls a previously used email address or telephone number.
- **USR-022 [P2] — Directory-authoritative accounts.** Declare which operations are locally editable, externally managed, or require write-back; refuse unsupported local edits rather than silently diverging.

## 13. Sessions, Devices, SSO, and Logout

### 13.1 Session capabilities

- **SES-001 [P0] — Durable sessions.** Persist user, client association, realm, authentication evidence, creation time, last meaningful activity, expiry, revocation, and grant relationships.
- **SES-002 [P0] — Session limits.** Configure idle timeout, absolute timeout, concurrent-session limits, and per-client restrictions without allowing refresh to extend an absolute bound.
- **SES-003 [P0] — Session listing.** Let users and appropriately scoped administrators list safe session metadata and revoke individual sessions or all sessions.
- **SES-004 [P0] — Local logout.** End the relevant server-side session/grant and instruct the client to clear local credentials. Clearing a cookie alone is not server-side revocation.
- **SES-005 [P0] — Logout all devices.** Revoke all affected refresh grants and online session authority, and publish invalidation events to participating applications.
- **SES-006 [P0] — Refresh families.** Model refresh tokens as a rotation family with durable parent/child lineage, client binding, compromise state, and independent expiry constraints.
- **SES-007 [P0] — Atomic rotation.** At most one request can replace a refresh token. A reused predecessor cannot create another valid branch of the family.
- **SES-008 [P0] — Reuse detection.** On confirmed reuse, invalidate the family and raise a security event. Document the effect on related sessions and whether the user must authenticate again.
- **SES-009 [P0] — Concurrent refresh behavior.** First-party SDKs serialize refresh per session. The baseline server rejects reuse; any retry-grace feature requires separately reviewed sender binding and replay semantics.
- **SES-010 [P0] — Browser cookies.** Session cookies must be Secure and HttpOnly, with appropriate SameSite, narrow scope, and CSRF/origin controls. Cross-site integrations require explicit design rather than blanket weakening.
- **SES-011 [P0] — Header sessions.** Native and backend clients may use Authorization headers; this does not permit application API services to accept refresh tokens.
- **SES-012 [P1] — Remember-me grants.** Make persistence an explicit opt-in with bounded idle/absolute lifetimes and clear revocation behavior.
- **SES-013 [P1] — Device metadata.** Record useful browser/device descriptions, first/last activity, and approximate network context while acknowledging that user-agent strings and IP addresses are not strong identity proofs.
- **SES-014 [P1] — SSO session.** Reuse the IdP session across registered applications only after client-specific consent, organization access, and assurance checks.
- **SES-015 [P1] — Client sessions.** Distinguish the IdP's global SSO session, client-local application sessions, organization grants, and refresh families so logout scope is predictable.
- **SES-016 [P1] — RP-initiated logout.** Validate logout hints and registered post-logout destinations, and apply required confirmation behavior. [OIDC-RPLOGOUT]
- **SES-017 [P1] — Back-channel logout.** Send signed, audience-bound logout tokens to registered clients with retry, replay protection, and observable delivery state. [OIDC-BACKLOGOUT]
- **SES-018 [P2] — Front-channel logout.** Offer optional protocol support, while documenting browser/privacy constraints and not treating it as guaranteed universal logout.
- **SES-019 [P1] — Session event stream.** Provide authenticated invalidation/change notifications for applications, with replay/catch-up support and a declared consistency model.
- **SES-020 [P1] — Transient sessions.** Support short-lived non-persistent login where appropriate without minting long-lived refresh authority.
- **SES-021 [P1] — Offline access.** Require explicit client permission and consent/policy for grants that survive ordinary browser-session termination, with independent revocation and expiry.
- **SES-022 [P1] — Session migration.** Migrate session data only when trust, secrets, subject mappings, and expiry semantics can be established; otherwise require reauthentication.
- **SES-023 [P0] — Token revocation honesty.** Local JWT verification alone cannot observe a newly revoked session. The product MUST state this limitation and offer strict online enforcement for resources that require it. [INTROSPECTION] [REVOCATION]

### 13.2 Three revocation-consistency modes

| Mode           | Enforcement                                                                                                | Revocation consequence                                                                                                                              |
| -------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Offline JWT    | Verify signature, claims, audience, tenant, and local policy without consulting live server state.         | Access can continue until token expiry, plus the permitted clock tolerance. Refresh is denied after authoritative revocation.                       |
| Bounded-online | Consult live state or use a cache/event-driven state replica with an explicit maximum freshness age.       | Enforcement delay is bounded only when the freshness contract and failure policy are enforced; missed events cannot be ignored indefinitely.        |
| Strict-online  | Check authoritative active-session/grant state for every protected operation with no positive-state cache. | Requests authorized after revocation commits must be denied. Requests already authorized or in flight require separate business-operation controls. |

A `session_version` or `authz_version` claim is useful only when checked against trusted current state. Merely adding a version number to a JWT does not make revocation immediate.

**Default decisions:** Ordinary low-risk services may use short-lived JWTs. Identity administration, credential changes, and impersonation require strict-online checks. Higher-risk business operations must explicitly choose and test their enforcement mode.

## 14. Token Platform and Cryptographic Contract

### 14.1 Token types and separation

| Artifact                            | Intended consumer                             | Required treatment                                                                                                |
| ----------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Authorization code                  | Token endpoint                                | Opaque, short-lived, one-time, bound to client, redirect, PKCE, and authorization transaction.                    |
| Access token                        | Specific resource server(s)                   | JWT or opaque; audience-, subject-, tenant-, scope-, and lifetime-bound.                                          |
| ID token                            | OIDC client                                   | Evidence about an authentication event; never accepted as an application API access token.                        |
| Refresh token                       | Token endpoint                                | Opaque secret, rotation family, client binding, expiry, reuse detection; never sent to business APIs.             |
| IdP session handle                  | IdP session endpoints                         | Server-side session reference; not a universal API bearer credential.                                             |
| Invitation/reset/verification token | Dedicated workflow endpoint                   | Purpose-specific, expiring, single-use; cannot authorize arbitrary account operations.                            |
| Personal access token               | Explicitly permitted API or exchange endpoint | Scoped, expiring, revocable, owner-bound; separate policy from browser sessions.                                  |
| API key                             | Declared integration surface                  | High-entropy, scoped, verifiable by digest, not a global administrator password.                                  |
| Logout/security-event token         | Registered event recipient                    | Its own token type and validation rules; not an access token.                                                     |
| Impersonation access token          | Explicitly opted-in application resource      | Short-lived, actor-attributed, restricted, online-revocable; rejected by identity credential/admin mutation APIs. |

Token typing and separate validation rules are essential to prevent cross-token confusion. [JWT-BCP] [JWT-AT]

### 14.2 Issuance and lifecycle requirements

- **TOK-001 [P0] — Standards-based issuance.** Implement authorization code with PKCE, refresh-token, and client-credentials grants as the baseline. Do not expose an unrestricted “mint token for user ID” API.
- **TOK-002 [P0] — PKCE policy.** Require `S256` for authorization-code clients in the baseline profile, including confidential clients. Bind the challenge to the exact code transaction. [PKCE]
- **TOK-003 [P0] — Opaque artifacts.** Generate codes and reusable bearer secrets with a cryptographically secure random generator; persist digests and purpose metadata instead of plaintext where possible.
- **TOK-004 [P0] — JWT access profile.** Use asymmetric signatures, explicit `at+jwt` typing, and the mandatory claims of the selected JWT access-token profile. [JWT-AT]
- **TOK-005 [P0] — Algorithm policy.** Allowlist algorithms per issuer/client profile and enforce key type/use. Reject unsigned tokens and symmetric/asymmetric confusion on resource-server verification paths. [JWT-BCP]
- **TOK-006 [P0] — Independent signing authority.** Resource servers receive public verification keys, never a shared secret that also enables them to mint other services' identity tokens.
- **TOK-007 [P0] — Narrow audiences.** Grant only registered resource audiences explicitly allowed for the client and subject. Do not make every service trust a single wildcard audience. [RESOURCE]
- **TOK-008 [P0] — Scope reduction.** Token scopes must be a subset of approved client, subject, consent, organization, and resource policy. Refresh and exchange cannot silently expand that set.
- **TOK-009 [P0] — Introspection.** Provide authenticated token introspection, restrict callers to permitted resources, and return minimal claims. Inactive tokens return the protocol's inactive response rather than private status detail. [INTROSPECTION]
- **TOK-010 [P0] — Revocation endpoint.** Implement protocol-compatible revocation with caller/client binding and documented effects on the token, family, grant, and session. [REVOCATION]
- **TOK-011 [P0] — JWKS.** Publish public verification keys with stable key IDs, appropriate cache controls, and no private key material.
- **TOK-012 [P0] — Rotation windows.** Prepublish new verification keys, switch issuance safely, and retain old public keys until legitimate dependent artifacts and verifier caches have aged out.
- **TOK-013 [P0] — Emergency key response.** Support immediate issuance shutdown or key rollover, explicit compromised-key rejection policy, and verifier notification. Removing a JWKS key alone does not purge every verifier's cache.
- **TOK-014 [P0] — Token minimization.** Keep access claims compact and non-sensitive. Avoid emails, phone numbers, full profiles, and unbounded permission/resource lists unless an audience explicitly requires them.
- **TOK-015 [P1] — Claim namespaces.** Reserve standard and security-critical claims; tenant-defined mappings cannot override subject, actor, issuer, audience, expiry, client ID, or token type.
- **TOK-016 [P1] — Token exchange.** Support explicit policy-controlled exchanges between registered clients/resources; validate subject-token origin, presenting client authority, audience transitions, and scope attenuation. [EXCHANGE]
- **TOK-017 [P1] — Exchange provenance.** Preserve necessary actor/delegation provenance and impose maximum chain depth. An exchanged token must not disguise a machine actor as an independently authenticated human.
- **TOK-018 [P1] — Token lifetime policies.** Configure lifetimes by realm, client, resource, subject type, assurance, and impersonation status, subject to operator safety bounds.
- **TOK-019 [P2] — Sender-constrained access.** Support DPoP and/or mutual-TLS-bound tokens under explicit resource/client profiles rather than silently falling back to bearer tokens. [DPOP] [MTLS]
- **TOK-020 [P2] — Encrypted ID tokens.** Support tested JWE profiles where client requirements justify encryption; do not use token encryption as a substitute for audience or authorization checks.
- **TOK-021 [P1] — Credential expiry alerts.** Notify owners before client credentials, signing certificates, or configured integration keys expire.
- **TOK-022 [P0] — Issuer stability.** Construct issuer and protocol endpoints from trusted configuration, not attacker-controlled Host or forwarded headers.
- **TOK-023 [P0] — No query bearer tokens.** Business APIs must not accept ordinary access tokens in query strings. Dedicated one-time redirect artifacts are a different, narrowly scoped mechanism.
- **TOK-024 [P0] — Safe token responses.** Token and sensitive authentication responses use no-store caching policy, do not include tokens in logs, and are excluded from analytics capture.

### 14.3 Example ordinary JWT access token

Illustrative decoded header and payload, not a signed credential. Times are example NumericDate values, not a usable live token. `org_id`, `project_id`, `authz_version`, and `token_kind` are product-defined claims; this profile documents them for participating services.

```json
{
  "alg": "RS256",
  "kid": "realm-a-signing-key-2026-10",
  "typ": "at+jwt"
}
```

```json
{
  "iss": "https://identity.example.com/realms/main",
  "sub": "usr_01JEXAMPLE",
  "aud": "https://api.example.com/orders",
  "client_id": "customer-web-bff",
  "iat": 1791590400,
  "exp": 1791590700,
  "jti": "tok_01JEXAMPLE",
  "sid": "ses_01JEXAMPLE",
  "scope": "orders:read orders:create",
  "org_id": "org_01JEXAMPLE",
  "project_id": "prj_commerce",
  "token_kind": "user_access",
  "authz_version": 43
}
```

The role/permission model may supply optional compact claims, but object ownership and current access remain resource-server decisions. `authz_version` is a hint for a real consistency check, not an automatic authorization guarantee.

### 14.4 Required resource-server verification algorithm

```text
1. Select a preconfigured trusted issuer/profile; never fetch arbitrary token URLs.
2. Parse with strict size, structure, and duplicate-field rules.
3. Require the expected token kind and an allowlisted asymmetric algorithm.
4. Resolve kid only from that issuer's trusted verification-key set.
5. Verify the signature and the profile's required claims.
6. Validate exact issuer, expected audience, expiry, and not-before when present.
7. Validate allowed client and subject type where the API requires them.
8. Match organization context to the requested resource using trusted data.
9. Enforce required scopes and current permission/ownership policy.
10. Enforce live revocation/freshness mode and any assurance requirement.
11. Enforce actor/impersonation restrictions when present.
12. Deny on missing, malformed, ambiguous, or unverifiable security context.
```

An unknown `kid` may trigger one bounded/coalesced refresh of the trusted JWKS. It must not cause unbounded network fetches for attacker-generated key IDs. Retain known keys only according to the configured cache/retirement policy; never fail open on failed verification. [JWT-BCP]

### 14.5 Proposed default lifetimes

| Item                               | Baseline default                 | Notes                                                                     |
| ---------------------------------- | -------------------------------- | ------------------------------------------------------------------------- |
| Authorization code                 | 60 seconds                       | One successful redemption.                                                |
| Authentication transaction         | 10 minutes                       | Earlier invalidation on cancellation, consumption, or policy change.      |
| Ordinary access token              | 5 minutes                        | May be shorter for privileged resources.                                  |
| Ordinary IdP session               | 30-minute idle; 12-hour absolute | Refresh cannot outlive the applicable parent session.                     |
| Remember-me grant                  | 7-day idle; 30-day absolute      | Requires client/policy permission.                                        |
| Explicit offline grant             | 7-day idle; 30-day absolute      | Separate opt-in authority, not accidental browser persistence.            |
| Impersonation grant and token      | At most 5 minutes                | No refresh token and no automatic extension.                              |
| Recent administrative MFA evidence | At most 5 minutes old            | Reassess at support-grant creation and sensitive operations.              |
| Verification/reset challenge       | 10 minutes                       | Resend rotates the challenge under an aggregate attempt budget.           |
| Invitation                         | 72 hours                         | Configurable; single-use secret.                                          |
| Permitted verifier clock tolerance | At most 60 seconds               | Adds to practical offline-token acceptance windows; monitor clock health. |
| Positive authorization cache       | Resource-specific                | Zero for strict-online resources and all impersonation.                   |

These are product defaults, not benchmark results or universal security guarantees.

## 15. Roles, Permissions, Policies, and Resource Authorization

### 15.1 Authorization capabilities

- **AZ-001 [P0] — Permission registry.** Define namespaced permissions such as `org.members.read`, `org.invites.create`, and `orders.refund`, with descriptions and resource ownership.
- **AZ-002 [P0] — Roles.** Create reusable roles, attach permissions, assign them to users/service principals, and scope assignments by realm, organization, or project.
- **AZ-003 [P0] — Membership-scoped roles.** Organization role assignments must reference the relevant membership, not a global user-role flag that leaks to every tenant.
- **AZ-004 [P0] — Multiple roles.** Compute effective permissions deterministically, document combination rules, and apply explicit denies and policy constraints consistently.
- **AZ-005 [P0] — Administrative boundaries.** Separate platform, realm, organization, project, support, and application permissions; a customer application role must never imply IdP administration.
- **AZ-006 [P0] — Grant ceilings.** Creating roles, editing permission membership, assigning roles, and delegating administration require checks against the actor's allowed delegation scope.
- **AZ-007 [P0] — Deny by default.** Missing policy, missing attributes, unsupported resource types, and evaluation errors must not become authorization success.
- **AZ-008 [P0] — Backend enforcement.** Every protected endpoint checks authorization. UI visibility, possession of a user ID, and successful authentication are insufficient.
- **AZ-009 [P0] — Authorization inspection.** Provide “my effective permissions” and scoped administrator inspection APIs, with provenance and sensitive-policy redaction.
- **AZ-010 [P1] — Group-derived roles.** Resolve permissions from group membership with cycle/depth limits and clear handling of stale directory state.
- **AZ-011 [P1] — Composite roles.** Support role composition only with cycle checks, bounded expansion, and prevention of indirect grant-ceiling bypasses.
- **AZ-012 [P1] — Conditional grants.** Support expiry, activation windows, client restrictions, assurance conditions, and permitted resource sets.
- **AZ-013 [P1] — Policy decision API.** Evaluate subject, actor, action, resource, organization, and trusted context, returning allow/deny, reason code, policy version, and required obligations.
- **AZ-014 [P1] — Batch checks.** Evaluate bounded batches with equivalent semantics to individual checks and resource-by-resource results.
- **AZ-015 [P1] — ABAC.** Evaluate typed subject/resource/environment attributes using a deterministic, bounded, side-effect-free policy language.
- **AZ-016 [P1] — Trusted attribute sources.** Distinguish resource-server-authoritative attributes from browser input. The caller cannot assert ownership, administrator status, or MFA completion.
- **AZ-017 [P1] — Policy versioning.** Publish immutable revisions, staged changes, validation, simulation, rollback, and human-readable diffs.
- **AZ-018 [P1] — Separation of duties.** Support incompatible role constraints, approval requirements, and prohibition of self-approval for selected privileged grants.
- **AZ-019 [P1] — Authorization cache contract.** Key caches by tenant, subject, actor, client, resource, action, policy version, and relevant context. Enforce a freshness bound and invalidation strategy.
- **AZ-020 [P1] — Decision audit.** Log privileged decisions and policy changes, with optional sampled ordinary allow decisions and full denial context subject to privacy limits.
- **AZ-021 [P2] — Relationship-based authorization.** Support a bounded resource-relationship model or a documented adapter to a separately deployed open authorization engine.
- **AZ-022 [P2] — Resource registration.** Allow services to register resource types and permission schemas without making the IdP the owner of all application resource data.
- **AZ-023 [P2] — Resource listing semantics.** Authorized list operations must use policy-aware filtering or verified batch decisions; never return unauthorized objects and expect clients to hide them.
- **AZ-024 [P2] — Temporary privilege elevation.** Offer just-in-time role grants with approval, expiry, reason, and automatic removal, distinct from user impersonation.
- **AZ-025 [P2] — Access reviews.** Provide membership/role certification campaigns, reviewer decisions, expiry, and evidence exports without claiming regulatory certification.
- **AZ-026 [P2] — External policy adapters.** Support replaceable policy engines with authenticated calls, timeouts, explicit failure behavior, and equivalent tenant/actor context.
- **AZ-027 [P2] — Delegated resource access.** Optionally support UMA-style or equivalent user-managed sharing through an explicit protocol profile and consent model.

Reference foundations: [OWASP-AUTHZ] [KC-AUTHZ]. The proposed APIs, defaults, and storage model are independent design choices.

### 15.2 Scope, role, permission, and ownership are different

```text
scope       = what this client/token is authorized to request
role        = a named bundle assigned to a principal in a boundary
permission  = an allowed action under the active policy
ownership   = an application fact about a specific resource
```

For example, `orders:read` scope permits the client to request order reads. A user's organization role and application record ownership determine which orders may actually be read. A token for Organization A must not access an order stored under Organization B, even when both organizations use the same `orders:read` scope.

### 15.3 Policy decision contract

The service calling this endpoint authenticates itself with a token for the authorization API. A referenced user token or delegation handle must be validated; a free-form subject ID is allowed only for callers explicitly authorized to evaluate that subject.

```json
{
  "subject_token": "REDACTED_USER_ACCESS_TOKEN",
  "action": "orders.refund",
  "resource": {
    "type": "order",
    "id": "ord_123",
    "org_id": "org_01JEXAMPLE"
  },
  "context": {
    "request_id": "req_123",
    "operation_amount_minor": 1500,
    "currency": "USD"
  }
}
```

```json
{
  "decision_id": "dec_123",
  "allowed": false,
  "reason_code": "STEP_UP_REQUIRED",
  "policy_version": "orders-policy-17",
  "obligations": [
    {
      "type": "reauthenticate",
      "required_profile": "phishing_resistant",
      "max_age_seconds": 300
    }
  ],
  "cache_ttl_seconds": 0
}
```

Obligations are mandatory conditions, not informational hints. A caller unable to enforce a returned obligation must deny the operation. Transaction amounts and ownership must come from trusted service data, not directly from the browser request.

## 16. Administrator-to-Customer Impersonation

### 16.1 Product objective

Allow explicitly authorized support personnel to inspect or reproduce a customer's application experience without knowing the customer's password, changing their credentials, or disguising the true actor in audit records.

This is **controlled, attributable support access**, not permission to become an arbitrary user everywhere. The chosen token representation retains an actor while using the customer as the effective subject. OAuth token exchange supplies relevant actor/delegation concepts but does not itself authorize an administrator to select any target. [EXCHANGE] [ZT-EXCHANGE]

### 16.2 Non-negotiable requirements

- **IMP-001 [P0] — Disabled until complete.** Impersonation is disabled by default and cannot be enabled until downstream resources opt in to its required verification and restriction contract.
- **IMP-002 [P0] — Dedicated permission.** Require a separate `support.impersonation.start` capability scoped to permitted organizations, subject categories, resources, and actions.
- **IMP-003 [P0] — Recent MFA.** Require a live administrator session with recent approved MFA. Possession of an ordinary administrator access token alone is insufficient.
- **IMP-004 [P0] — Explicit target.** Validate the target user, active membership, target organization, client, resource audience, and support-access policy using authoritative state.
- **IMP-005 [P0] — Required reason.** Require a meaningful support reason and optional/required ticket reference according to policy. Store those details server-side, not in public token claims.
- **IMP-006 [P0] — Actor attribution.** Every grant, token introspection result, audit event, and downstream security context must identify the real administrator and effective customer subject.
- **IMP-007 [P0] — Least privilege.** Effective capabilities are the intersection of the target's current permissions, the actor's explicitly permitted support capabilities, the requested scopes, and the resource's support policy.
- **IMP-008 [P0] — No privilege union.** Never combine the administrator's own business permissions with the target's permissions to create a stronger effective user.
- **IMP-009 [P0] — Short lifetime.** Default maximum lifetime is five minutes, with no refresh token, offline access, or silent renewal. A new grant requires a new authorized start operation.
- **IMP-010 [P0] — Strict online revocation.** All impersonation operations require an authoritative active-grant check. An offline JWT-only resource cannot participate.
- **IMP-011 [P0] — Read-only default.** Default support access excludes state-changing business operations. Any additional capability requires an explicit allowlist and policy review.
- **IMP-012 [P0] — Protected identity operations.** Always prohibit password changes/resets, MFA changes, email/phone changes, account linking, credential export, API-key creation, personal-token creation, consent modification, and IdP administrative mutation using impersonation tokens.
- **IMP-013 [P0] — Sensitive business exclusions.** Deny payments, refunds, ownership transfers, private secret reads, destructive actions, and similar high-risk operations unless a separately designed support workflow authorizes the real administrator directly.
- **IMP-014 [P0] — No nested impersonation.** An impersonated session cannot create another impersonation or exchange itself into ordinary unrestricted customer credentials.
- **IMP-015 [P0] — Target exclusions.** Disallow impersonating platform/realm administrators, emergency accounts, service principals, and other protected users by default.
- **IMP-016 [P0] — Stop and revoke.** The actor, an authorized administrator, and the target where policy permits can end the support grant. Actor suspension or loss of required support permission invalidates it.
- **IMP-017 [P0] — Membership changes.** Target suspension, organization suspension, membership removal, or target permission reduction must affect subsequent checks immediately under the strict-online contract.
- **IMP-018 [P0] — Honest assurance.** Do not copy the target's historical MFA evidence into the support session or claim that the target just authenticated. Record actor assurance separately.
- **IMP-019 [P0] — Session separation.** Support access uses an isolated session context and must not overwrite the administrator's ordinary session or expose the administrator's tokens to the customer application.
- **IMP-020 [P0] — Durable audit before access.** Commit the support grant and its audit record before returning usable authority. Failure to persist the audit record must prevent access.
- **IMP-021 [P1] — Customer visibility.** Expose active/past support sessions and configurable notifications. Provide machine-readable context so external UIs can display a support-session indicator.
- **IMP-022 [P1] — Approval/consent policies.** Support customer approval, organization-owner approval, or two-person approval for configured cases, without letting the requester approve their own grant.
- **IMP-023 [P1] — Grant inventory.** List active grants by actor, target, organization, reason reference, and expiry; permit authorized emergency termination.
- **IMP-024 [P1] — Exportable evidence.** Correlate grant creation, approval, token issuance, downstream activity, and termination by a support-grant ID.

### 16.3 Recommended flow

```text
Administrator authenticates normally and performs recent MFA
  -> calls protected impersonation-request API
  -> server validates target, organization, audience, support scope, and reason
  -> optional independent approval/customer consent
  -> server commits grant + audit + outbox record
  -> returns a short-lived opaque support access token to the trusted support BFF
  -> resource server introspects and checks support restrictions on every request
  -> resource server logs actor, subject, organization, grant, and operation
  -> expiry, stop, suspension, or permission change invalidates the grant
```

Do not put the access token in a browser URL. To enter an external application's support view, use a single-use, destination-bound handoff code redeemed by that application's trusted backend, with a maximum 30-second lifetime and its own replay protection.

### 16.4 Example introspection result

```json
{
  "active": true,
  "iss": "https://identity.example.com/realms/main",
  "sub": "usr_customer",
  "aud": "https://api.example.com/orders",
  "client_id": "support-bff",
  "scope": "orders:read",
  "exp": 1791590700,
  "jti": "tok_support_123",
  "act": {
    "iss": "https://identity.example.com/realms/main",
    "sub": "usr_support_agent"
  },
  "org_id": "org_customer",
  "token_kind": "impersonation_access",
  "impersonation_grant_id": "imp_123",
  "support_mode": "read_only"
}
```

`act` follows the actor concept in token exchange; the other support-specific fields are this product's extension contract. A downstream service must not grant authority just because an actor claim exists. It must validate the complete support-grant policy.

### 16.5 Mandatory adversarial tests

A support user cannot target another tenant, escalate through a target administrator, mint credentials, remove MFA, obtain offline access, extend expiry through token exchange, hide their actor identity, reuse a consumed handoff code, or continue after grant revocation. An application that drops the actor context or ignores support restrictions must fail integration contract validation for impersonation.

## 17. Service Accounts, API Keys, and Workload Identity

- **MCH-001 [P0] — Service principals.** Create non-human principals with owners, descriptions, allowed organizations/resources, permissions, and independent disable/delete operations.
- **MCH-002 [P0] — Client credentials.** Authenticate eligible confidential clients and issue short-lived access tokens representing the service principal, not a fabricated human login.
- **MCH-003 [P0] — No implicit refresh.** Client-credentials grants do not receive refresh tokens in the baseline; services reauthenticate to obtain new short-lived access.
- **MCH-004 [P0] — Narrow service access.** Bind machine tokens to permitted audiences and scopes, and exclude all human-only endpoints unless explicitly designed for service administration.
- **MCH-005 [P1] — Scoped API keys.** Generate prefix-plus-secret keys with owner, scopes, resource restrictions, expiration, last-use metadata, and immediate online revocation.
- **MCH-006 [P1] — Personal access tokens.** Allow user-issued automation credentials only after recent authentication, within the user's own delegable permissions and organization policy.
- **MCH-007 [P1] — Owner changes.** Define whether service ownership transfer, employee departure, or user suspension revokes related automation credentials; do not leave orphaned access indefinitely.
- **MCH-008 [P1] — Safe display.** Show secrets once; subsequent APIs expose only key ID, non-secret prefix, metadata, and status.
- **MCH-009 [P1] — Credential rotation.** Permit controlled overlapping credentials, owners' expiry notifications, and tested zero-downtime rotation.
- **MCH-010 [P1] — Signed assertions.** Support asymmetric client assertions with registered keys, replay detection, expiration, and exact audience validation.
- **MCH-011 [P2] — Workload federation.** Exchange trusted workload assertions for narrowly scoped local tokens, using explicit issuer, audience, subject-pattern, environment, and repository/namespace constraints.
- **MCH-012 [P2] — Kubernetes/workload adapters.** Provide adapter profiles for selected workload identity sources without assuming that every token from a cluster is authorized for every local service account.
- **MCH-013 [P2] — SPIFFE/SPIRE integration.** Support a reviewed workload-identity adapter where required; this is not a requirement to implement an independent certificate authority or service mesh.
- **MCH-014 [P2] — Certificate authentication.** Support mutual-TLS client authentication and certificate-bound tokens with certificate rotation and trust-store management. [MTLS]
- **MCH-015 [P2] — On-behalf-of delegation.** Preserve both the human subject and calling service actor, check each audience transition, and prevent a service from turning its own credential into arbitrary user authority.
- **MCH-016 [P1] — Secret inventory.** List expiring, unused, over-privileged, and ownerless automation credentials and provide safe bulk revocation workflows.
- **MCH-017 [P2] — Agent permissions.** Treat autonomous agents as service principals or explicit delegates with bounded scopes, approvals, and audit; never exempt them from ordinary authorization because they are “AI.”

## 18. Protocol and Interoperability Roadmap

### 18.1 Standards profiles

| Protocol/capability                        | Priority | Required product stance                                                                                       |
| ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------- |
| OAuth authorization code + PKCE            | P0       | Baseline interactive flow; S256 and single-use code binding. [PKCE]                                           |
| OIDC code flow                             | P0       | Authentication claims, ID tokens, UserInfo, and explicit relying-party contracts. [OIDC-CORE]                 |
| OIDC discovery / OAuth server metadata     | P0       | Accurate metadata per canonical issuer. [OIDC-DISCOVERY] [AS-METADATA]                                        |
| Client credentials                         | P0       | Non-human access with narrow resource authorization. [OAUTH2]                                                 |
| Refresh tokens                             | P0       | Rotation, family state, client binding, and reuse handling. [OAUTH-BCP]                                       |
| JWT access-token profile                   | P0       | Typed asymmetric JWTs with profile-required claims. [JWT-AT]                                                  |
| Introspection / revocation                 | P0       | Authenticated, scoped, standards-compatible endpoints. [INTROSPECTION] [REVOCATION]                           |
| RP-initiated / back-channel logout         | P1       | Separate local/IdP/client logout semantics. [OIDC-RPLOGOUT] [OIDC-BACKLOGOUT]                                 |
| Device authorization                       | P1       | CLI/device pairing with polling intervals, expiry, consent, and phishing-resistant approval context. [DEVICE] |
| Token exchange                             | P1       | Explicitly authorized audience transitions and provenance. [EXCHANGE]                                         |
| Resource indicators                        | P1       | Explicit selection of registered target resources. [RESOURCE]                                                 |
| OAuth step-up challenge                    | P1       | Machine-readable stronger/fresher authentication requirements. [STEPUP]                                       |
| SAML 2.0 IdP and broker                    | P2       | Separate outbound-IdP and inbound-SP profiles with tested bindings. [SAML]                                    |
| SCIM 2.0                                   | P2       | User/group provisioning with advertised capability limits. [SCIM-SCHEMA] [SCIM-PROTOCOL]                      |
| Pushed authorization requests (PAR)        | P2       | Authenticated request submission, bound request references, and expiry. [PAR]                                 |
| JWT-secured authorization requests (JAR)   | P2       | Signed request objects, conflict rules, replay protection, and trusted keys. [JAR]                            |
| JWT-secured authorization responses (JARM) | P2       | Optional signed/encrypted response profile with independent tests. [JARM]                                     |
| Rich authorization requests                | P2       | Typed `authorization_details` schemas and resource-side enforcement. [RAR]                                    |
| DPoP                                       | P2       | Proof validation, nonce/replay controls, method/URI and access-token binding. [DPOP]                          |
| Mutual-TLS and bound tokens                | P2       | Client-certificate authentication and resource-side binding enforcement. [MTLS]                               |
| Dynamic client registration/management     | P2       | Restricted, rate-limited onboarding, not open privileged registration. [DCR] [DCRM]                           |
| JWT/SAML bearer assertion grants           | P2       | Optional, explicitly trusted assertion profiles with replay and client/subject constraints.                   |
| OIDC CIBA                                  | P3       | Separate reviewed back-channel authentication capability; not equivalent to device authorization. [CIBA]      |
| UMA/resource-sharing profile               | P3       | Optional delegated sharing protocol on top of the authorization model.                                        |
| Shared security-event signals              | P3       | Optional standardized event transport with issuer/audience trust, replay controls, and privacy limits. [SSF]  |
| OpenID credential issuance/presentation    | P3       | Separate verifiable-credential module; no implied inclusion in baseline account login. [VCI]                  |
| Container registry token adapter           | P3       | Optional registry-scoped tokens and repository/action claims with dedicated audience policy.                  |

### 18.2 Explicitly excluded insecure defaults

Do not implement the resource-owner password credentials grant as a substitute for headless login. Do not enable implicit-flow access-token issuance, wildcard redirect matching, unsigned assertions, or globally reusable bearer credentials as compatibility shortcuts. RFC 9700 is the baseline OAuth security reference. [OAUTH-BCP]

OAuth 2.1 was presented as an Internet-Draft in the reviewed IETF tracker. Describe implemented RFCs and tested profiles rather than claiming certification against an unspecified “OAuth 2.1” release. The FAPI 2.0 Security Profile is available as a final specification, but FAPI conformance is a separate, testable delivery goal rather than a label granted by enabling PAR or DPoP alone. [OAUTH21] [FAPI]

### 18.3 SAML implementation requirements

- **SAML-001 [P2] — Distinct roles.** Implement outbound IdP behavior and inbound broker/SP behavior as explicit profiles with their own metadata and trusted counterparties.
- **SAML-002 [P2] — Metadata and rollover.** Validate metadata and trusted signing/encryption keys, support controlled certificate overlap, and audit changes.
- **SAML-003 [P2] — Assertion validation.** Enforce trusted issuer, audience, destination/recipient, time conditions, subject confirmation, request correlation where applicable, and replay prevention. [SAML]
- **SAML-004 [P2] — XML parser safety.** Reject unsafe external entities, oversized documents, duplicate/ambiguous IDs, and signature-wrapping attempts using reviewed libraries and attack fixtures.
- **SAML-005 [P2] — Binding policy.** Explicitly advertise and test supported Redirect, POST, and optional Artifact bindings. Do not advertise unsupported bindings.
- **SAML-006 [P2] — Identifier and attribute rules.** Configure NameID formats and approved attribute mappings with stable-subject and protected-claim rules.
- **SAML-007 [P2] — IdP-initiated login.** Keep unsolicited-response flows disabled by default; enable only with a documented, separately reviewed correlation and destination policy.
- **SAML-008 [P2] — Logout.** Support a declared subset of SAML logout behavior and expose partial failures rather than promising universal logout across arbitrary SPs.
- **SAML-009 [P2] — Cryptographic floor.** Reject deprecated signature/digest/encryption configurations according to the selected security profile; compatibility exceptions require explicit operator approval and warnings.
- **SAML-010 [P2] — Interoperability fixtures.** Test multiple independent IdP/SP implementations, certificate rollover, time skew, invalid assertions, and replay.

### 18.4 OIDC relying-party contract

These requirements clarify the supported code-flow profile rather than adding a new login protocol. Optional extensions remain disabled and unadvertised until implemented. [OIDC-CORE] [OIDC-DISCOVERY]

- **OIDC-001 [P0] — Required request validation.** Validate response type, client, registered redirect, requested scopes, PKCE, and supported response mode before creating authorization authority; return errors only through a validated destination or a safe local error response.
- **OIDC-002 [P0] — State and nonce handling.** Preserve the relying party's state and bind any supplied nonce into the resulting ID token as required. Client examples validate returned state and the nonce they requested; neither replaces server-side transaction binding or PKCE.
- **OIDC-003 [P0] — ID-token profile.** Produce the required issuer, subject, audience, expiry, issued-at, and conditional claims using the selected profile. Document authorized-party and multi-audience handling; an ID token authenticates the subject to its relying client, not to arbitrary business APIs.
- **OIDC-004 [P0] — Session freshness.** Honor applicable `max_age` and `prompt=login` semantics, preserve genuine authentication time, and include `auth_time` when required. A refresh operation alone cannot satisfy a fresh-authentication requirement.
- **OIDC-005 [P1] — Prompt behavior.** Implement the declared `none`, `login`, `consent`, and `select_account` behaviors and invalid combinations. Noninteractive requests return the applicable interaction-required errors when policy cannot be satisfied silently.
- **OIDC-006 [P0] — UserInfo.** Accept only an appropriate access token authorized for this endpoint; enforce scopes and return a stable `sub` matching the relevant client identity. Do not accept an unrelated business-audience token merely because it carries `openid` text.
- **OIDC-007 [P1] — Standard claims.** Define supported `profile`, `email`, `phone`, and `address` claims with correct data types, verification provenance, release policy, and minimal disclosure. Scope request does not compel release of absent or unauthorized attributes.
- **OIDC-008 [P1] — Claims requests.** Support the optional `claims` parameter only under a documented capability profile, distinguishing essential/requested claims and ID-token versus UserInfo release without allowing protected-claim override.
- **OIDC-009 [P1] — Authentication context.** Publish recognized assurance values and map `acr_values`/essential assurance requests according to the supported profile. Fail a guaranteed assurance request rather than inventing evidence when it cannot be met.
- **OIDC-010 [P1] — Subject privacy.** Support public and optional pairwise subjects with deterministic, secret-protected derivation or durable mappings, reviewed sector-identifier registration, and safe key/mapping lifecycle.
- **OIDC-011 [P1] — Interaction hints.** Treat `login_hint`, supported identity hints, locale preferences, and display preferences as hints, not authentication or organization-membership evidence. Validate any token-form hint before using protected contents.
- **OIDC-012 [P1] — Offline consent semantics.** Implement the selected OIDC `offline_access` policy and required consent behavior explicitly, separately from ordinary browser-session persistence and remember-me settings.
- **OIDC-013 [P2] — Signed/encrypted responses.** Offer signed UserInfo and encrypted ID-token/UserInfo profiles only with registered recipient keys, algorithm allowlists, correct validation order, rotation, and interoperability tests. Encryption is not a substitute for audience validation or confidentiality at the consuming application.
- **OIDC-014 [P2] — Session management extension.** Optionally implement the separately version-pinned OIDC browser session-management profile with origin checks and documented browser limitations; ordinary backend session APIs alone do not claim that extension.
- **OIDC-015 [P1] — Metadata accuracy.** Discovery describes actual supported grants, response modes, subject types, scopes, claims, authentication methods, algorithms, and optional capabilities for this issuer/configuration, with safe cache behavior.
- **OIDC-016 [P0] — Client validation examples.** Include client-side validation fixtures for exact issuer/audience, signature, expiry, nonce when supplied, authorized-party rules, and applicable token/code-hash claims. Client examples must not trust an ID-token payload before verification.

## 19. SCIM, Directories, and Enterprise Provisioning

- **PROV-001 [P2] — SCIM server.** Expose Users, Groups, Schemas, ResourceTypes, and ServiceProviderConfig with protocol-compatible representations and errors. [SCIM-SCHEMA] [SCIM-PROTOCOL]
- **PROV-002 [P2] — SCIM operations.** Implement the advertised subset of create, read, list, replace, PATCH, and delete, including filter, pagination, and attribute-selection semantics.
- **PROV-003 [P2] — Connector identity.** Authenticate each provisioner separately and bind it to an organization, allowed resource types, and administrative permission ceiling.
- **PROV-004 [P2] — External IDs and idempotency.** Enforce connector-scoped external-ID uniqueness and stable retry behavior without treating all connectors' IDs as one namespace.
- **PROV-005 [P2] — Deprovisioning semantics.** For a shared realm-wide user, a tenant-scoped SCIM `active=false` or delete normally removes/suspends that organization's access, not unrelated memberships or the global account.
- **PROV-006 [P2] — Protected accounts.** A directory connector cannot overwrite deployment administrators, emergency accounts, or owner assignments outside its approved scope.
- **PROV-007 [P2] — Group mapping.** Synchronize external groups to local groups/roles through approved mappings, with grant ceilings and controlled deletion behavior.
- **PROV-008 [P2] — Concurrency.** Support resource versions/ETags and conditional updates where advertised; reject stale writes instead of overwriting unrelated changes.
- **PROV-009 [P2] — Bulk safety.** Advertise bulk only if implemented with limits, per-operation status, authorization, and predictable partial-failure behavior.
- **PROV-010 [P2] — Outbound provisioning.** Offer connectors that push eligible identity/group lifecycle to downstream systems, with retries, mapping configuration, and reconciliation reports.
- **PROV-011 [P2] — LDAP/AD federation.** Support secure bind/search, trusted certificates, connection timeouts, pagination, filters, attribute mappings, and documented user-storage modes.
- **PROV-012 [P2] — Directory synchronization.** Provide full/incremental sync, scheduling, change cursors, dry-run, conflict reports, deletion detection, and safe resumability.
- **PROV-013 [P2] — Directory write-back.** Make read-only, import-only, and permitted write-back modes explicit. Password write-back requires a reviewed connector and transport policy.
- **PROV-014 [P2] — Failover.** Support multiple configured directory endpoints and safe retry behavior without falling back to an unauthorized identity source.
- **PROV-015 [P2] — Kerberos/SPNEGO adapter.** Add only as an optional enterprise module with explicit keytab custody, service-principal configuration, trust boundaries, and negative tests.
- **PROV-016 [P2] — X.509 user authentication.** Support optional certificate-based authentication with chain validation, identity mapping, revocation policy, and trusted proxy handling.
- **PROV-017 [P2] — Reconciliation.** Detect divergence between external and local records, identify the authoritative source per attribute, and prevent oscillating overwrites.
- **PROV-018 [P2] — Operational evidence.** Expose connector health, last successful sync, lag, changed-record counts, failures, and operator actions without leaking directory credentials.

Directory federation and enterprise authentication are reference-product capability families; connector-specific support remains subject to explicit implementation and testing. [KC-ADMIN]

## 20. Email, SMS, Localization, and Communication Policies

- **MSG-001 [P0] — Pluggable email delivery.** Provide standard SMTP and an adapter interface for other transports, with no mandatory hosted email vendor.
- **MSG-002 [P0] — Durable delivery jobs.** Enqueue messages transactionally with the action that requires them; expose queued, attempted, delivered/accepted, failed, and expired states accurately.
- **MSG-003 [P0] — Security templates.** Support verification, reset, invitation, MFA changes, new login alerts, account suspension, and support-access notifications.
- **MSG-004 [P0] — Safe templates.** Validate templates and escape untrusted values; prohibit arbitrary code execution, secret interpolation, and untrusted redirect construction.
- **MSG-005 [P1] — Per-organization configuration.** Allow approved sender identity, reply-to, locale, and template overrides without cross-tenant secret reuse or domain spoofing.
- **MSG-006 [P1] — Localization data.** Support translated messages, locale fallback, time-zone-aware timestamps, and machine-readable validation/error codes independent of presentation language.
- **MSG-007 [P1] — Delivery feedback.** Process authenticated bounce/complaint/status callbacks and update notification eligibility without treating provider delivery status as identity verification.
- **MSG-008 [P1] — Optional SMS adapters.** Support replaceable gateways, country restrictions, resend budgets, and cost/safety ceilings, all operator-controlled rather than paid feature gates.
- **MSG-009 [P1] — Secret-bearing job retention.** Minimize and encrypt persisted message bodies containing one-time links; delete delivery payloads after bounded retention, while retaining non-secret delivery evidence.
- **MSG-010 [P1] — Notification preferences.** Distinguish optional activity notifications from mandatory security notifications that a compromised account must not quietly disable.
- **MSG-011 [P0] — Local development sink.** Provide a local/test-only delivery sink that never ships enabled in production and does not expose secrets through public APIs.
- **MSG-012 [P1] — Sender diagnostics.** Provide test delivery and configuration validation with redacted results, permission checks, and clear distinction between provider acceptance and actual inbox delivery.

## 21. Audit, Security Events, and Evidence

- **AUD-001 [P0] — Structured events.** Record event ID, schema version, occurred/recorded times, realm, organization, actor, subject, action, target, result, reason code, request ID, and relevant grant/session IDs.
- **AUD-002 [P0] — Security coverage.** Audit sign-in outcomes, recovery, credential changes, invitation lifecycle, authorization changes, client/provider changes, provisioning, token-family compromise, and impersonation.
- **AUD-003 [P0] — Secret exclusion.** Never log passwords, full bearer tokens, OTPs, private keys, TOTP seeds, session cookies, or raw invitation/reset secrets.
- **AUD-004 [P0] — Atomic administrative audit.** Privileged state mutations and their audit events must commit together; storage failure must prevent unaudited privileged success.
- **AUD-005 [P0] — Actor preservation.** Record real actor and effective subject independently, including service delegation and support impersonation.
- **AUD-006 [P0] — Scoped querying.** Audit search, export, counts, and aggregations obey tenant boundaries and dedicated audit-reader permissions.
- **AUD-007 [P1] — Append-only application model.** Normal application and tenant-admin credentials cannot edit historical audit entries; corrections are new linked events.
- **AUD-008 [P1] — Tamper evidence.** Offer signed/hash-linked batches and export to an independently controlled append-only/WORM destination, with integrity-verification tools.
- **AUD-009 [P1] — Retention policy.** Configure retention by event category and scope, with privacy-conscious redaction and legal-hold hooks where applicable.
- **AUD-010 [P1] — Export.** Stream or export bounded audit ranges in documented machine-readable formats with pagination, checksums, and restricted download authority.
- **AUD-011 [P1] — Search dimensions.** Filter by time, actor, subject, organization, client, action, result, IP-derived risk context, and correlation ID without exposing hidden scopes.
- **AUD-012 [P1] — Security alerts.** Emit alerts for repeated compromise signals, emergency-account use, support-access anomalies, suspicious grants, and signing/configuration changes.
- **AUD-013 [P1] — Event provenance.** Distinguish server-generated authoritative events from externally reported application activity and identify the reporting service.
- **AUD-014 [P1] — Failure observability.** Alert on audit backlog, exporter failure, integrity mismatch, retention-job failure, and missing expected event sequences.
- **AUD-015 [P1] — Data-access evidence.** Optionally log privileged reads of sensitive user fields and exports; avoid indiscriminate raw request capture.
- **AUD-016 [P2] — Security-event interoperability.** Support a declared shared-signals/security-event profile as a separately tested adapter. [SSF]

**Important limit:** An operator who controls the application, database, signing keys, host, and every backup can potentially alter or destroy local evidence. “Append-only” is not absolute immutability. Independent key custody, external anchors, and separately controlled retention are required for stronger tamper-evidence guarantees.

### Example audit event

```json
{
  "id": "evt_123",
  "schema_version": 1,
  "type": "support.impersonation.started",
  "occurred_at": "2026-10-10T12:00:00Z",
  "realm_id": "realm_main",
  "org_id": "org_customer",
  "actor": { "type": "user", "id": "usr_support_agent" },
  "subject": { "type": "user", "id": "usr_customer" },
  "target": { "type": "impersonation_grant", "id": "imp_123" },
  "outcome": "success",
  "reason_code": "APPROVED_SUPPORT_REQUEST",
  "request_id": "req_123",
  "metadata": {
    "ticket_reference": "SUP-1042",
    "audience": "https://api.example.com/orders",
    "expires_at": "2026-10-10T12:05:00Z"
  }
}
```

The free-form reason and ticket reference are sensitive operational data and must follow audit access and retention policy.

## 22. Webhooks, Hooks, Workflows, and Extension Interfaces

- **EXT-001 [P1] — Webhook subscriptions.** Register destinations, event types, tenant scopes, signing configuration, secret rotation, status, and owner.
- **EXT-002 [P1] — At-least-once delivery.** Document duplicate delivery and possible ordering differences. Consumers must deduplicate by stable event ID.
- **EXT-003 [P1] — Signed deliveries.** Sign the exact transmitted body together with timestamp and event/delivery identifiers using a versioned scheme and rotatable secret or key.
- **EXT-004 [P1] — Replay protection.** Document verification, clock tolerance, event-ID deduplication, key rollover, and retry handling. A valid signature alone is not proof of freshness.
- **EXT-005 [P1] — Retry management.** Use bounded exponential backoff with jitter, retry budgets, dead-letter state, manual replay, and observable per-destination backlog.
- **EXT-006 [P1] — SSRF defense.** Validate destinations at registration and connection time, block unsafe address ranges by default, constrain redirects, and prevent DNS-rebinding bypasses.
- **EXT-007 [P1] — Private destinations.** Allow operator-approved internal webhook destinations only through an explicit egress policy rather than disabling SSRF controls globally.
- **EXT-008 [P1] — Event schemas.** Publish versioned payload schemas, compatibility rules, secret redaction, and minimal-PII event forms.
- **EXT-009 [P1] — Pre-action hooks.** Offer bounded hooks for registration eligibility, profile validation, claims enrichment, and policy decisions with explicit timeout/failure behavior.
- **EXT-010 [P1] — Post-action hooks.** Run side-effecting integrations asynchronously after authoritative state commits; a timeout must not retroactively create inconsistent security state.
- **EXT-011 [P1] — Protected decisions.** Hooks may not override reserved identity claims, skip required authentication, expand client scope ceilings, or suppress mandatory audit.
- **EXT-012 [P1] — Failure policy.** Security-decision hooks fail closed. Non-security analytics/notification hooks may fail asynchronously without blocking unrelated login.
- **EXT-013 [P2] — Sandboxed execution.** Optional embedded logic uses a sandbox with CPU, memory, time, filesystem, network, and capability restrictions.
- **EXT-014 [P2] — Plugin lifecycle.** Support signed/versioned plugin packages, declared permissions, dependency checks, review requirements, and safe disable/rollback.
- **EXT-015 [P2] — Lifecycle workflows.** Define event-triggered and scheduled onboarding, access expiry, approval, and offboarding steps as versioned jobs with durable state.
- **EXT-016 [P2] — Workflow idempotency.** Each step records attempts, input version, result, retry policy, and compensation strategy for external effects.
- **EXT-017 [P1] — Extension diagnostics.** Expose health, execution latency, failures, and redacted traces per extension without revealing secrets or another tenant's payloads.
- **EXT-018 [P2] — API evolution.** Version plugin, hook, and webhook contracts independently and test compatibility across supported server upgrades.

### Example webhook envelope

```json
{
  "event_id": "evt_membership_123",
  "event_type": "organization.membership.removed",
  "event_version": 1,
  "occurred_at": "2026-10-10T12:10:00Z",
  "realm_id": "realm_main",
  "org_id": "org_customer",
  "data": {
    "user_id": "usr_customer",
    "membership_id": "mem_123",
    "authorization_revision": 44
  }
}
```

An ordinary asynchronous webhook is not a strict revocation mechanism. A resource promising immediate denial must use the strict-online contract or an equally strong, tested enforcement design.

## 23. Security, Privacy, and Threat Model

### 23.1 Security requirements

- **SEC-001 [P0] — TLS and proxy trust.** Require HTTPS in production and trust forwarded host/protocol/client-IP headers only from explicitly configured proxies.
- **SEC-002 [P0] — CSRF protection.** Protect all cookie-authenticated state changes with appropriate anti-forgery tokens and origin checks; SameSite alone is not the complete design.
- **SEC-003 [P0] — CORS allowlists.** Allow only registered origins and methods; never combine wildcard origins with credentialed cross-origin requests.
- **SEC-004 [P0] — Input validation.** Apply schema validation, length/depth limits, strict parsing, safe query construction, and rejection of ambiguous duplicate fields.
- **SEC-005 [P0] — Enumeration resistance.** Normalize public login/reset/invitation responses, apply timing controls, and limit discovery/search endpoints that reveal account or tenant existence.
- **SEC-006 [P0] — Abuse throttling.** Use layered per-subject, network, client, realm, and tenant budgets with concurrency-safe counters and protection against attacker-induced permanent lockouts.
- **SEC-007 [P0] — Session and token leakage prevention.** Redact authorization headers/cookies, avoid token-bearing URLs, and apply no-store/referrer policies to sensitive flows.
- **SEC-008 [P0] — Race-condition protection.** Treat replay, duplicate submission, concurrent rotation, last-owner deletion, and role-edit races as first-class threat scenarios.
- **SEC-009 [P0] — Security state authority.** Signing, privileged issuance, and strict-online authorization must fail closed if authoritative state or key integrity cannot be established.
- **SEC-010 [P0] — Secret encryption.** Encrypt recoverable secrets with authenticated encryption and key-versioned envelope protection; separate encryption, token-signing, webhook, and password-pepper keys.
- **SEC-011 [P0] — Bootstrap lockdown.** Prevent remote creation of the first administrator after initialization and prohibit default production credentials.
- **SEC-012 [P1] — Phishing-resistant administration.** Offer an administrative profile requiring passkeys/security keys and disallowing weaker recovery without a reviewed emergency process.
- **SEC-013 [P1] — Breached-credential screening.** Support local/offline screening datasets or a privacy-preserving optional integration; core availability must not depend on a mandatory third-party lookup.
- **SEC-014 [P1] — Risk and bot adapters.** Permit optional local or external challenge providers, with accessibility alternatives and no hidden tracking dependency.
- **SEC-015 [P1] — Safe logs and diagnostics.** Debug modes must be time-limited, scoped, audited, and still redact secrets; support bundles must be inspectable before export.
- **SEC-016 [P1] — Supply-chain safeguards.** Pin dependencies, scan artifacts, generate an SBOM, sign release artifacts, and document build provenance and reproducibility limits.
- **SEC-017 [P0] — Isolation tests.** Include tenant-crossing and role-escalation tests for every resource family, worker, export, and integration path.
- **SEC-018 [P1] — Independent review.** Complete focused external security review before broad production adoption, then repeat on major protocol or trust-boundary changes.
- **SEC-019 [P0] — Disclosure process.** Publish a security contact, private reporting route, supported-version policy, triage expectations, and advisory/release procedure.
- **SEC-020 [P1] — Emergency controls.** Provide audited controls to disable a client, provider, organization, signing profile, extension, or grant class without arbitrary database edits.

### 23.2 Threat-to-control matrix

| Threat                               | Required control and test                                                                                                  |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Cross-tenant object access           | Tenant-qualified storage, token/resource matching, query filters, and negative tests using two organizations.              |
| Account takeover by linking          | Stable upstream subjects, proof of both identities, safe conflict flow, and recycled-email tests.                          |
| Code interception or substitution    | S256, single-use code, client/redirect binding, and concurrent redemption tests.                                           |
| OAuth confused deputy                | Registered audiences, client/resource grant checks, token-exchange transition policy, and forbidden-audience tests.        |
| Stolen refresh credential            | Atomic rotation, family compromise handling, expiry, and lost-response/concurrency tests.                                  |
| JWT confusion                        | Token typing, algorithm allowlists, issuer/audience validation, and ID-token-as-access-token rejection.                    |
| Support impersonation abuse          | Dedicated permission, recent MFA, short lifetime, actor audit, online checks, and protected-action denial.                 |
| User-controlled privilege attributes | Attribute ownership, reserved claims, delegation ceilings, and profile/group mapping tests.                                |
| SSRF through extensions/federation   | Egress policy, connection-time address checks, restricted redirects, and rebinding fixtures.                               |
| Database disclosure                  | Password verifiers, encrypted recoverable secrets, digest-only bearer artifacts, and separated keys.                       |
| Malicious deployment operator        | Explicit threat-model limit; external audit anchoring, separate key custody, and infrastructure separation where required. |
| Cache or event-stream outage         | Declared freshness/failure policy; no fail-open fallback for privileged or support operations.                             |

Security foundations used in this design include OAuth security guidance, JWT validation guidance, and OWASP authorization guidance. [OAUTH-BCP] [JWT-BCP] [OWASP-AUTHZ]

### 23.3 Privacy and data-governance requirements

- **PRV-001 [P1] — Data inventory.** Publish a field-level inventory of personal data, secrets, purpose, ownership, retention, exportability, and deletion behavior.
- **PRV-002 [P1] — Data minimization.** Avoid storing full provider tokens, raw IP histories, user-agent histories, or contact attributes unless the enabled feature needs them.
- **PRV-003 [P1] — Region control.** Keep identity storage, backups, logs, message payloads, and external connector destinations under operator-configured residency policy.
- **PRV-004 [P1] — Retention jobs.** Enforce documented retention for sessions, challenges, audit, delivery payloads, exports, and deleted-account tombstones.
- **PRV-005 [P1] — Deletion propagation.** Track cleanup across primary storage, projections, caches, exports, connectors, and backups. Do not claim immediate erasure from retained backups.
- **PRV-006 [P1] — Restore reconciliation.** Reapply post-backup deletion/revocation records after restoration so restoring an old backup does not silently resurrect deleted or compromised access.
- **PRV-007 [P1] — Consent distinction.** Authentication consent, application scopes, terms acceptance, and marketing preferences are separate records with separate purposes.
- **PRV-008 [P1] — Restricted exports.** Require appropriate authorization, recent authentication where needed, audit, short-lived download credentials, and encrypted storage for exports.
- **PRV-009 [P1] — No automatic compliance claim.** Provide evidence-producing controls, but do not label the software GDPR-, HIPAA-, SOC 2-, ISO-, FIPS-, or NIST-certified merely because these controls exist.

Legal applicability and certification scope require deployment-specific review. This specification is not legal advice and does not assert that every named framework applies to every deployment.

## 24. Persistence Model and Database Invariants

### 24.1 Logical tables

The table names below are a proposed logical model, not a finished SQL migration. Every row has creation/update timestamps and a version where meaningful. Realm/organization columns are required wherever the ownership boundary applies.

| Table / aggregate              | Important fields and relationships                                                                       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `realms`                       | ID, canonical issuer, state, policy revision, key-set reference.                                         |
| `organizations`                | Realm ID, organization ID, slug, state, owner-transfer policy, metadata schema.                          |
| `organization_domains`         | Organization, normalized domain, challenge digest, verification state, expiry, recheck time.             |
| `users`                        | Realm ID, internal user ID, state, profile version, credential/session authorization revisions.          |
| `user_identifiers`             | User, type, original/canonical value, verified time, primary flag, source, uniqueness scope.             |
| `user_attributes`              | User, schema key, typed value, source, visibility, mutability policy.                                    |
| `external_identities`          | User, connection, validated upstream issuer/subject, linking provenance.                                 |
| `memberships`                  | Realm, organization, user, state, source, external ID, joined/expired times, revision.                   |
| `groups`                       | Organization, group ID, parent, metadata, external mapping.                                              |
| `group_memberships`            | Organization, group, user/membership, source, validity window.                                           |
| `projects`                     | Realm, project, owner organization, state, configuration revision.                                       |
| `project_grants`               | Project, granted organization, allowed role subset, validity, delegation policy.                         |
| `clients`                      | Project, client ID, client type, auth methods, allowed grants, state, security profile.                  |
| `client_redirects`             | Client, exact URI, purpose, environment.                                                                 |
| `client_keys`                  | Client, key ID, public key or secret verifier, status, validity window.                                  |
| `api_resources`                | Resource ID, audience, owner, verification/revocation mode, impersonation opt-in policy.                 |
| `scopes`                       | Resource, name, description, consent metadata, sensitivity.                                              |
| `client_resource_grants`       | Client, resource, allowed scopes, subject constraints, exchange policy.                                  |
| `credentials`                  | User, credential type, verifier/encrypted secret reference, algorithm, parameters, state.                |
| `webauthn_credentials`         | User, credential ID, public key, RP ID, counter, backup flags, metadata.                                 |
| `recovery_codes`               | User, code digest/key version, created/consumed time, batch ID.                                          |
| `auth_transactions`            | Client, realm, organization, redirect, PKCE, required/completed steps, expiry, protected continuation.   |
| `challenges`                   | Purpose, transaction, subject/identifier reference, verifier, attempt budget, expiry, consumed time.     |
| `sessions`                     | User, authentication evidence, original auth time, idle/absolute expiry, revoked time, revision.         |
| `client_sessions`              | IdP session, client, client session reference, logout destination, state.                                |
| `authorization_grants`         | Subject, client, organization, resources/scopes, consent, session/offline policy, validity.              |
| `authorization_codes`          | Digest, client, redirect, PKCE challenge, grant, expiry, consumption status.                             |
| `refresh_families`             | Grant, client, current generation, compromise/revocation state, idle/absolute expiry.                    |
| `refresh_tokens`               | Digest, family, generation, parent, child, issued/consumed/revoked time.                                 |
| `opaque_access_tokens`         | Digest, grant, audience, claims/context reference, expiry, revocation.                                   |
| `token_revocations`            | Token/family/session/key reference, reason, effective time, revision.                                    |
| `roles`                        | Realm/organization/project boundary, name, description, protected flag, version.                         |
| `permissions`                  | Namespace, action, resource type, owner, sensitivity.                                                    |
| `role_permissions`             | Role, permission, grant provenance.                                                                      |
| `role_assignments`             | Role, subject or membership, organization/project boundary, expiry, approver.                            |
| `policies` / `policy_versions` | Policy ID, immutable definition, schema, status, author, approval, hash.                                 |
| `resource_relationships`       | Optional tenant-qualified subject/relation/object tuples with source and revision.                       |
| `consents`                     | User, client, resource/scope set, policy version, granted/revoked time.                                  |
| `invitations`                  | Organization, target reference, allowed roles, inviter, digest, secret version, expiry, state.           |
| `join_requests`                | User, organization/project, reason, reviewers, state, decision time.                                     |
| `impersonation_requests`       | Actor, target, organization, resource, reason, ticket, approval state.                                   |
| `impersonation_grants`         | Request, actor session, target membership, scope ceiling, expiry, revoked time.                          |
| `service_principals`           | Realm, owner, purpose, state, allowed organizations, permission revision.                                |
| `api_keys` / `personal_tokens` | Owner, non-secret prefix, secret digest, scopes, audience, expiry, last use, state.                      |
| `identity_providers`           | Tenant scope, type, issuer/metadata, encrypted credential reference, mapping revision.                   |
| `provisioning_connectors`      | Scope, connector identity, mapping, ownership rules, cursor, last sync.                                  |
| `notification_templates`       | Scope, event type, locale, validated template version.                                                   |
| `notification_jobs`            | Event reference, encrypted/minimized payload, destination reference, attempts, status, expiry.           |
| `webhook_subscriptions`        | Scope, destination, event filters, signing-secret reference, egress policy.                              |
| `webhook_deliveries`           | Event, subscription, attempt, next retry, response category, status.                                     |
| `audit_events`                 | Append-only event envelope, privacy policy, correlation and integrity metadata.                          |
| `outbox_events`                | Aggregate/event ID, payload/schema, published state, attempt lease, creation time.                       |
| `jobs`                         | Type, scope, input reference, state, lease, checkpoints, result, retry policy.                           |
| `idempotency_records`          | Actor, route, scope, key digest, request hash, result reference, expiry.                                 |
| `signing_key_metadata`         | Realm, key ID, algorithm, storage reference, lifecycle dates, compromise state.                          |
| `encryption_key_versions`      | Key-store reference, active/retiring status, ciphertext usage metadata.                                  |
| `deletion_tombstones`          | Non-sensitive subject/membership reference, deletion/revocation revision, restore reconciliation policy. |

### 24.2 Database invariants

- **DB-001 [P0] — Composite boundaries.** Foreign keys and unique constraints must prevent referencing another realm or organization accidentally; application checks are not the only defense.
- **DB-002 [P0] — Identifier uniqueness.** Enforce documented canonical identifier uniqueness transactionally, including account creation and identifier changes racing with one another.
- **DB-003 [P0] — External identity uniqueness.** A configured connection's validated upstream subject maps to at most one local user in its intended identity domain.
- **DB-004 [P0] — Single active membership.** The same user cannot acquire duplicate active membership records for one organization through invitation/import races.
- **DB-005 [P0] — One-time consumption.** Challenges, recovery codes, authorization codes, and invitation secrets use conditional atomic writes or equivalent serialization.
- **DB-006 [P0] — Refresh lineage.** A consumed refresh generation has at most one authorized successor; compromise state is checked in the same critical transaction as rotation.
- **DB-007 [P0] — Last-owner safety.** Membership/role changes that affect the last owner serialize on an authoritative ownership constraint.
- **DB-008 [P0] — Secret storage classes.** Distinguish irreversible password verifiers, high-entropy bearer digests, keyed low-entropy-code verifiers, and encrypted recoverable integration/TOTP secrets.
- **DB-009 [P0] — Audit/outbox coupling.** Commit mutation, audit, and outbox in a single database transaction; external dispatch happens afterward.
- **DB-010 [P1] — Optimistic concurrency.** Use resource versions for policy/profile/configuration updates and reject stale mutations with a conflict/precondition response.
- **DB-011 [P1] — Tenant-aware indexes.** Index normal lookup and cleanup paths by scope and expiry; do not let unbounded table scans become the default authentication path.
- **DB-012 [P1] — Partitioning policy.** Partition high-volume audit/delivery data only with tested retention, query, and migration semantics.
- **DB-013 [P1] — Optional row security.** Database row-level security may add defense in depth, but its interaction with workers, migrations, and database owners must be tested.
- **DB-014 [P1] — Transaction retries.** Retry deadlock/serialization failures only for operations with safe idempotency; do not repeat external effects or return an uncommitted token.

### 24.3 Refresh-rotation transaction sketch

```text
BEGIN
  lock the refresh family and presented token generation
  verify digest, client binding, grant state, session/offline policy, and expiry
  if the generation was already consumed:
      mark family compromised and record revocation + audit + outbox
      COMMIT
      return protocol error; do not issue a token
  re-evaluate permitted scope and organization access
  mark current generation consumed
  create exactly one successor digest and a new bounded access grant artifact
  append audit/outbox records as required
COMMIT
return the newly generated refresh secret and access token
```

A response lost after commit does not justify branching the refresh family. The baseline client must reauthenticate if it cannot safely recover. An advanced idempotent retry design requires its own sender-bound protocol, secure response retention, and threat review.

## 25. API Conventions and Trust Classes

### 25.1 Conventions

- **API-001 [P0] — Versioned custom APIs.** Use `/api/v1` for product-specific management and interaction APIs. Standard OAuth/OIDC/SAML/SCIM behavior follows its own protocol rather than a custom response wrapper.
- **API-002 [P0] — Schema-first contracts.** Publish complete OpenAPI for custom HTTP APIs and schemas/examples for events; generated clients must match the deployed server's supported API version.
- **API-003 [P0] — Scope-derived access.** Derive authenticated identity from validated credentials. Path/body organization IDs are selectors that must be checked, not proof of access.
- **API-004 [P0] — Bounded pagination.** Ordinary lists use stable opaque cursors, maximum page sizes, allowlisted filters/sorts, and scope-safe counts; SCIM retains its specified pagination semantics.
- **API-005 [P0] — Idempotency.** Support actor/tenant/route-bound idempotency keys on eligible creates and jobs; reject reuse with a different request body.
- **API-006 [P0] — Secret response policy.** One-time secret creation is explicitly documented. Generic idempotency middleware must not turn single-use protocol artifacts into reusable credentials or expose another caller's secret response.
- **API-007 [P0] — Error contracts.** Custom APIs use stable codes and problem details without stack traces or secrets; standard protocol endpoints retain their required errors. [PROBLEM]
- **API-008 [P0] — Authentication errors.** Return 401 for missing/invalid credentials and 403 for authenticated but disallowed requests, using 404 where resource-existence concealment is the documented policy.
- **API-009 [P0] — Abuse responses.** Return appropriate throttling responses and retry guidance without disclosing protected per-user state or allowing an identifier probe.
- **API-010 [P1] — Conditional updates.** Provide ETags/versions and `If-Match` support for sensitive editable resources; reject stale state.
- **API-011 [P1] — Asynchronous jobs.** Long-running imports, exports, syncs, and deletions return job references with status, progress, cancellation where safe, and protected results.
- **API-012 [P1] — Correlation.** Accept or generate safe request IDs, propagate trace context with limits, and correlate audit/events without logging bearer credentials.
- **API-013 [P1] — Compatibility.** Document deprecations, supported API versions, additive changes, and required client upgrades before removing security-relevant behavior.
- **API-014 [P1] — Optional gRPC.** A gRPC management interface may be added, but it must enforce the same domain logic, authorization, and audit as HTTP; no privileged alternate path.

### 25.2 Trust classes

| Class                      | Examples                                                  | Authentication requirement                                                               |
| -------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Public metadata            | Discovery, public JWKS                                    | No user token; bounded and cacheable.                                                    |
| Public protocol initiation | Authorization request, registration start, reset request  | May be unauthenticated; validate client/context, rate-limit, and protect against abuse.  |
| Transaction-bound          | Factor proof, consent completion, invitation confirmation | Purpose-bound transaction authority and required CSRF/origin/user proof.                 |
| User self-service          | Profile, sessions, security settings                      | User access for the self-service audience plus action policy/recent authentication.      |
| Administrative             | Users, tenants, roles, clients, integrations              | Administrative audience, scoped permission, and stricter online/MFA policy.              |
| Resource-server            | Introspection, authorization decisions                    | Authenticated service with resource-bound permission; user subject separately validated. |
| Provisioning               | SCIM/directory connector actions                          | Connector identity with a narrow organization and attribute/grant ceiling.               |
| Operator-only              | Bootstrap, key custody, emergency configuration           | Restricted local/operator channel; never an unauthenticated public convenience endpoint. |

“Every service depends on its token” applies to protected business and management access. Discovery and initial authentication cannot require an already-existing end-user token.

## 26. Proposed API Inventory

### 26.1 Routing notation

`R` means `/api/v1/realms/{realm}`. `I` means the configured issuer base, for example `https://identity.example.com/realms/main`. `S` means the tenant-scoped SCIM base configured for a specific connector. All illustrative route names are product decisions except discovery locations and protocol requirements defined by their specifications.

Grouped HTTP methods below describe route families; the implementation must publish full request/response schemas and individual operation permissions. Optional P1–P3 operations must not appear enabled in a P0-only deployment.

### 26.2 Protocol and authentication APIs

| Method and route                                             | Operation                                                       | Trust / main requirement                            |
| ------------------------------------------------------------ | --------------------------------------------------------------- | --------------------------------------------------- |
| `GET I/.well-known/openid-configuration`                     | OIDC discovery                                                  | Public, canonical issuer metadata.                  |
| `GET /.well-known/oauth-authorization-server/realms/{realm}` | OAuth metadata for a path-based issuer                          | Public; use the applicable RFC 8414 location rules. |
| `GET I/jwks`                                                 | Public verification keys                                        | Public; no private material.                        |
| `GET/POST I/oauth/authorize`                                 | Start authorization                                             | Registered client/redirect and interaction policy.  |
| `POST I/oauth/token`                                         | Code, refresh, client-credentials, and enabled extension grants | Grant-specific client and credential validation.    |
| `POST I/oauth/introspect`                                    | Check token activity/context                                    | Authorized resource-server client.                  |
| `POST I/oauth/revoke`                                        | Revoke eligible credential/grant                                | Bound client/token authority.                       |
| `GET/POST I/oidc/userinfo`                                   | Return permitted user claims                                    | Access token intended for UserInfo.                 |
| `GET/POST I/oidc/logout`                                     | RP-initiated logout                                             | Protocol validation and confirmation policy.        |
| `POST I/oauth/device_authorization`                          | Device-flow initiation                                          | Registered eligible client; abuse protection.       |
| `POST I/oauth/par`                                           | Pushed authorization request                                    | Eligible authenticated client/profile.              |
| `POST I/oauth/register`                                      | Dynamic client registration                                     | Restricted registration policy/token.               |
| `GET/PUT/DELETE I/oauth/register/{client_id}`                | Manage dynamic registration                                     | Registration access token bound to client.          |
| `POST I/oauth/backchannel-authentication`                    | Optional CIBA request                                           | Approved CIBA client and consent flow.              |
| `GET I/saml/metadata`                                        | SAML metadata                                                   | Public declared metadata.                           |
| `GET/POST I/saml/sso`                                        | SAML IdP sign-in                                                | Registered SP and validated request.                |
| `POST I/saml/acs/{connection}`                               | Upstream SAML response                                          | Validated assertion and broker transaction.         |
| `GET/POST I/saml/slo`                                        | SAML logout                                                     | Profile-specific validation.                        |
| `POST R/auth/transactions`                                   | Start headless transaction                                      | Registered client/context and abuse controls.       |
| `GET R/auth/transactions/{id}`                               | Fetch safe next-action state                                    | Bound continuation authority.                       |
| `POST R/auth/transactions/{id}/identify`                     | Submit identifier                                               | Transaction-bound, enumeration-safe.                |
| `POST R/auth/transactions/{id}/password`                     | Submit password proof                                           | Transaction-bound and rate-limited.                 |
| `POST R/auth/transactions/{id}/otp/send`                     | Send allowed challenge                                          | Purpose/identifier-bound send budget.               |
| `POST R/auth/transactions/{id}/otp/verify`                   | Verify challenge                                                | Attempt-limited atomic consumption.                 |
| `POST R/auth/transactions/{id}/webauthn/options`             | Begin authentication ceremony                                   | Bound transaction and RP configuration.             |
| `POST R/auth/transactions/{id}/webauthn/verify`              | Complete authentication ceremony                                | Validated challenge and authenticator response.     |
| `POST R/auth/transactions/{id}/totp`                         | Verify TOTP factor                                              | Correct enrollment and anti-replay policy.          |
| `POST R/auth/transactions/{id}/recovery-code`                | Use recovery factor                                             | Restricted recovery context.                        |
| `POST R/auth/transactions/{id}/consent`                      | Accept/deny requested consent                                   | Authenticated transaction and CSRF protection.      |
| `POST R/auth/transactions/{id}/cancel`                       | Cancel login                                                    | Bound continuation authority.                       |
| `POST R/registrations`                                       | Start account creation                                          | Current registration mode and validation.           |
| `POST R/verification-challenges`                             | Request identifier verification                                 | Purpose-bound policy and send budget.               |
| `POST R/verification-challenges/{id}/consume`                | Complete identifier proof                                       | Single-use, account/transaction binding.            |
| `POST R/password-resets`                                     | Request recovery                                                | Generic public response and rate limits.            |
| `POST R/password-resets/complete`                            | Set replacement password                                        | Valid recovery authority; preserve MFA policy.      |
| `GET/POST R/federation/{connection}/callback`                | Upstream callback                                               | Provider-specific transaction validation.           |

### 26.3 Self-service and tenant APIs

| Method and route                                                          | Operation                          | Trust / main requirement                                                                                |
| ------------------------------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `GET/PATCH R/me`                                                          | Read/update profile                | Self-service audience and field-level policy.                                                           |
| `GET/POST/DELETE R/me/identifiers[/{id}]`                                 | Manage identifiers                 | Ownership proof and recent authentication.                                                              |
| `POST R/me/password`                                                      | Change password                    | Recent approved authentication.                                                                         |
| `GET R/me/credentials`                                                    | List safe authenticator metadata   | Self only; no verifiers/seeds.                                                                          |
| `POST R/me/webauthn/registration-options`                                 | Start passkey enrollment           | Recent suitable authentication.                                                                         |
| `POST R/me/webauthn/registration-complete`                                | Finish passkey enrollment          | Valid bound ceremony.                                                                                   |
| `DELETE R/me/credentials/{id}`                                            | Remove credential                  | Reauthentication and last-method safeguards.                                                            |
| `POST R/me/totp/enroll`                                                   | Begin TOTP enrollment              | Recent authentication; temporary seed protection.                                                       |
| `POST R/me/totp/activate`                                                 | Activate proved TOTP seed          | Successful bound proof.                                                                                 |
| `DELETE R/me/totp`                                                        | Remove TOTP                        | Recovery and assurance policy.                                                                          |
| `POST R/me/recovery-codes/regenerate`                                     | Replace recovery-code batch        | Strong recent authentication; show once.                                                                |
| `GET R/me/sessions`                                                       | List own sessions                  | Safe metadata.                                                                                          |
| `DELETE R/me/sessions/{id}`                                               | Revoke one session                 | Ownership and revocation semantics.                                                                     |
| `POST R/me/sessions/revoke-all`                                           | Revoke all own sessions            | Recent auth/policy; strict invalidation.                                                                |
| `GET R/me/organizations`                                                  | List own memberships               | Self-service scope, no business API authority.                                                          |
| `POST R/me/organization-grants`                                           | Select/request organization access | Current membership/client/assurance checks; return a bound continuation or grant, not arbitrary scopes. |
| `GET/DELETE R/me/consents[/{id}]`                                         | Inspect/revoke consent             | Self and affected-grant policy.                                                                         |
| `GET/POST/DELETE R/me/linked-identities[/{id}]`                           | Manage external identity links     | Proof-of-control workflow.                                                                              |
| `GET R/me/security-events`                                                | View own security history          | Redacted self-scoped audit view.                                                                        |
| `POST R/me/exports`                                                       | Request data export                | Recent authentication, audited job.                                                                     |
| `POST/DELETE R/me/deletion-request`                                       | Request/cancel account deletion    | Ownership and lifecycle checks.                                                                         |
| `GET/POST/DELETE R/me/personal-tokens[/{id}]`                             | Manage automation tokens           | Own grant ceiling, expiry, show-once creation.                                                          |
| `GET R/me/impersonation-grants`                                           | View support access                | Customer visibility policy.                                                                             |
| `POST R/me/impersonation-grants/{id}/revoke`                              | End support access                 | Target-linked grant and policy.                                                                         |
| `GET/POST R/organizations`                                                | List/create organizations          | Realm policy and scoped administration.                                                                 |
| `GET/PATCH/DELETE R/organizations/{org}`                                  | Organization lifecycle             | Scoped admin; safe deletion job.                                                                        |
| `POST R/organizations/{org}/suspend`                                      | Suspend organization               | Dedicated permission and audit.                                                                         |
| `POST R/organizations/{org}/reactivate`                                   | Reactivate organization            | Policy checks; no expired-grant resurrection.                                                           |
| `POST R/organizations/{org}/ownership-transfers`                          | Transfer ownership                 | Strong auth, receiver/approval policy.                                                                  |
| `GET/POST/DELETE R/organizations/{org}/domains[/{id}]`                    | Manage domains                     | Domain-policy permission.                                                                               |
| `POST R/organizations/{org}/domains/{id}/verify`                          | Verify domain control              | Bound proof and conflict checks.                                                                        |
| `GET/POST R/organizations/{org}/members`                                  | List/add members                   | Scoped membership-admin permission.                                                                     |
| `GET/PATCH/DELETE R/organizations/{org}/members/{membership}`             | Manage membership                  | Last-owner, provenance, and role ceilings.                                                              |
| `GET/POST R/organizations/{org}/invitations`                              | List/create invites                | Invitation permission and allowed roles.                                                                |
| `POST R/organizations/{org}/invitations/{id}/resend`                      | Rotate/resend invite               | Scoped permission and send budget.                                                                      |
| `POST R/organizations/{org}/invitations/{id}/revoke`                      | Revoke invitation                  | Scoped invitation permission.                                                                           |
| `POST R/invitations/inspect`                                              | Inspect minimal invite context     | Secret submitted in protected body; no consumption.                                                     |
| `POST R/invitations/accept`                                               | Accept invitation                  | Required identity proof and atomic grant.                                                               |
| `POST R/invitations/decline`                                              | Decline invitation                 | Bound invitation authority.                                                                             |
| `GET/POST R/organizations/{org}/join-requests`                            | Request/list access requests       | Requester identity or reviewer permission.                                                              |
| `POST R/organizations/{org}/join-requests/{id}/decision`                  | Approve/deny join request          | Reviewer ceiling and no self-approval.                                                                  |
| `GET/POST/PATCH/DELETE R/organizations/{org}/groups[/{group}]`            | Manage groups                      | Group administration and nesting constraints.                                                           |
| `GET/POST/DELETE R/organizations/{org}/groups/{group}/members[/{member}]` | Manage group members               | Membership scope and source ownership.                                                                  |

### 26.4 Administration, authorization, support, and operations APIs

| Method and route                                              | Operation                             | Trust / main requirement                                        |
| ------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------------------- |
| `GET/POST/PATCH/DELETE R/users[/{user}]`                      | User administration                   | Realm/tenant-scoped user permission and field policy.           |
| `POST R/users/{user}/suspend`                                 | Suspend account                       | Global-account authority, not ordinary tenant membership admin. |
| `POST R/users/{user}/reactivate`                              | Reactivate account                    | Dedicated permission and audit.                                 |
| `POST R/users/{user}/required-actions`                        | Set required actions                  | Action-specific administrative ceiling.                         |
| `POST R/users/{user}/revoke-sessions`                         | Revoke eligible sessions              | Scope-aware session-administration permission.                  |
| `POST R/users/{user}/recovery-requests`                       | Begin assisted recovery               | Dedicated high-assurance workflow; no direct secret disclosure. |
| `POST R/user-imports`                                         | Start bulk identity import            | Privileged validated job.                                       |
| `GET/POST/PATCH/DELETE R/projects[/{project}]`                | Manage projects                       | Project ownership/administration.                               |
| `GET/POST/PATCH/DELETE R/projects/{project}/grants[/{grant}]` | Delegated organization project access | Owner grant ceiling and recipient scope.                        |
| `GET/POST/PATCH/DELETE R/clients[/{client}]`                  | Manage clients                        | Client admin and security-profile policy.                       |
| `POST R/clients/{client}/credentials`                         | Issue client credential               | Dedicated credential permission; show once.                     |
| `DELETE R/clients/{client}/credentials/{id}`                  | Revoke client credential              | Bound client administration.                                    |
| `GET/POST/PATCH/DELETE R/resources[/{resource}]`              | Manage API registrations              | Resource ownership and audience uniqueness.                     |
| `GET/POST/PATCH/DELETE R/scopes[/{scope}]`                    | Manage scope definitions              | Resource/schema administration.                                 |
| `GET/POST/PATCH/DELETE R/roles[/{role}]`                      | Manage roles                          | Explicit boundary and delegation ceiling.                       |
| `GET/POST/DELETE R/roles/{role}/permissions[/{permission}]`   | Change role contents                  | Indirect escalation checks.                                     |
| `GET/POST/DELETE R/role-assignments[/{assignment}]`           | Assign/revoke roles                   | Subject/boundary/grant-ceiling checks.                          |
| `GET R/me/permissions`                                        | Inspect own effective permission set  | Scope-safe compact result.                                      |
| `POST R/authorization/check`                                  | Evaluate one decision                 | Authenticated resource service and trusted subject context.     |
| `POST R/authorization/check-batch`                            | Evaluate bounded decisions            | Same policy as individual decisions.                            |
| `POST R/authorization/simulate`                               | Test policy changes                   | Policy-admin privilege; no production mutation.                 |
| `GET/POST/PATCH/DELETE R/policies[/{policy}]`                 | Manage policy definitions             | Policy-owner permission.                                        |
| `POST R/policies/{policy}/publish`                            | Activate validated revision           | Approval and version checks.                                    |
| `POST R/impersonation-requests`                               | Request support access                | Dedicated permission, recent MFA, target policy.                |
| `POST R/impersonation-requests/{id}/approve`                  | Approve support access                | Independent eligible approver.                                  |
| `POST R/impersonation-requests/{id}/issue`                    | Issue authorized support grant        | Live actor/target checks and durable audit.                     |
| `GET R/impersonation-grants`                                  | List support grants                   | Scoped support/audit permission.                                |
| `POST R/impersonation-grants/{id}/revoke`                     | End support grant                     | Actor/target/admin policy.                                      |
| `POST R/impersonation-grants/{id}/handoffs`                   | Create destination-bound entry code   | Trusted actor/support BFF and approved destination.             |
| `POST R/impersonation-handoffs/redeem`                        | Redeem support entry code             | Registered destination backend; one use.                        |
| `GET/POST/PATCH/DELETE R/service-principals[/{id}]`           | Machine-identity lifecycle            | Service-owner/administrator permission.                         |
| `GET/POST/DELETE R/api-keys[/{id}]`                           | Integration key lifecycle             | Owner scope, permission ceiling, show-once creation.            |
| `GET/POST/PATCH/DELETE R/identity-providers[/{id}]`           | Federation configuration              | Scoped IdP-admin permission and safe egress.                    |
| `POST R/identity-providers/{id}/test`                         | Validate provider configuration       | Redacted diagnostic and no policy bypass.                       |
| `GET/POST/PATCH/DELETE R/provisioning-connectors[/{id}]`      | Directory/provisioner configuration   | Connector-admin scope.                                          |
| `POST R/provisioning-connectors/{id}/sync`                    | Start synchronization                 | Scoped durable job with dry-run option.                         |
| `GET/POST/PATCH/DELETE R/webhooks[/{id}]`                     | Webhook subscriptions                 | Scoped integration permission.                                  |
| `GET R/webhooks/{id}/deliveries`                              | Delivery history                      | Scoped redacted diagnostics.                                    |
| `POST R/webhooks/{id}/deliveries/{delivery}/replay`           | Retry delivery                        | Authorized replay; stable original event ID.                    |
| `GET/PATCH R/notification-settings`                           | Delivery configuration                | Scoped secret-aware configuration access.                       |
| `GET/POST/PATCH/DELETE R/templates[/{id}]`                    | Notification/localization templates   | Template administration and validation.                         |
| `POST R/notification-tests`                                   | Send configuration test               | Restricted destination and send budgets.                        |
| `GET R/audit-events`                                          | Query evidence                        | Scoped audit-reader permission.                                 |
| `POST R/audit-exports`                                        | Export evidence                       | Stronger export permission and protected job.                   |
| `GET R/jobs/{id}`                                             | Inspect job                           | Job-owner or scoped administrator.                              |
| `POST R/jobs/{id}/cancel`                                     | Cancel eligible work                  | Safe cancellation policy.                                       |
| `GET/PATCH R/settings`                                        | Realm/security settings               | Field-specific operator/realm permissions.                      |
| `GET R/signing-keys`                                          | List public lifecycle metadata        | Restricted key metadata, no private keys.                       |
| `POST R/signing-key-rotations`                                | Start signing rotation                | Operator-only high-assurance action.                            |
| `POST R/configuration/validate`                               | Validate config-as-code               | Scoped admin, no mutation.                                      |
| `POST R/configuration/imports`                                | Reconcile approved configuration      | Diff/approval checks and secret references.                     |
| `POST R/configuration/exports`                                | Export configuration                  | Redacted by default; privileged job.                            |
| `GET /health/live`                                            | Process liveness                      | Minimal non-sensitive status.                                   |
| `GET /health/ready`                                           | Dependency/readiness result           | No secret/config details on public route.                       |
| `GET /metrics`                                                | Operational metrics                   | Restricted internal listener/authentication.                    |

### 26.5 SCIM route families

| Method and route                     | Operation                    | Main requirement                                       |
| ------------------------------------ | ---------------------------- | ------------------------------------------------------ |
| `GET S/ServiceProviderConfig`        | Advertised SCIM capabilities | Connector-scoped metadata policy.                      |
| `GET S/ResourceTypes`                | Resource-type discovery      | Accurate supported resource definitions.               |
| `GET S/Schemas[/{id}]`               | Schema discovery             | Include only supported schema/extensions.              |
| `GET/POST S/Users`                   | List/create users            | Connector scope, filters, pagination, ownership rules. |
| `GET/PUT/PATCH/DELETE S/Users/{id}`  | User lifecycle               | Version and shared-user deprovisioning policy.         |
| `POST S/Users/.search`               | Query users                  | Same filtering and disclosure policy as listing.       |
| `GET/POST S/Groups`                  | List/create groups           | Connector scope and grant ceilings.                    |
| `GET/PUT/PATCH/DELETE S/Groups/{id}` | Group lifecycle              | Mapping ownership and membership rules.                |
| `POST S/Groups/.search`              | Query groups                 | Bounded supported filters.                             |
| `POST S/Bulk`                        | Optional batch operations    | Advertise only when implemented and tested.            |

The server must support the protocol's exact capitalization, content types, schemas, status codes, and error semantics where required. [SCIM-PROTOCOL]

## 27. End-to-End Backend Workflows

These flows are acceptance contracts, not implementations. Every state transition must use the same domain services whether invoked through a protocol endpoint, custom API, CLI, connector, or background job.

### 27.1 New account and first organization

1. A permitted application starts a registration transaction, bound to its client and proposed interaction context. Public registration policy is checked before expensive work or outbound messages.
2. The user proves control of required contact information and enrolls an allowed credential through the transaction. Verification is purpose-bound; an email-login OTP is not automatically an invitation-acceptance proof or password-reset authorization.
3. The backend records accepted terms versions, required attributes, risk outcome, and completed authentication steps. Missing prerequisites leave the transaction incomplete without issuing a usable application token.
4. When organization creation is permitted, user creation, organization creation, initial owner membership, and audit/outbox records are committed with defined atomicity. A retried completion must not create another organization or another owner grant.
5. An authorization code is returned through the registered interaction contract. The client exchanges it with PKCE and any required client authentication. The resulting business access token names one permitted organization and API audience.
6. Notifications and onboarding integrations run after commit. A delivery failure does not silently undo a committed account or grant extra permissions.

An account may exist without a business organization. Such a user receives only an appropriate account-management session/token until membership or an explicitly supported personal-resource model is established.

### 27.2 Invitation into an existing organization

An authorized inviter proposes an invitation within their delegation ceiling. The server records the tenant, intended verified identity, role references, expiry, inviter, and approval state; it stores a verifier rather than the raw invitation secret. The recipient follows the invitation into an authentication transaction, proves the required identity, and explicitly accepts. The server then locks or atomically consumes the invitation, revalidates the inviter's current authority and current role definitions, and creates or updates the correct membership. Existing membership must not duplicate or silently accumulate unintended privileges.

Membership creation is not itself permission to reuse an old application token. The client requests a fresh organization-bound grant. If the inviter has been suspended, the organization disabled, or the proposed roles elevated beyond the inviter's ceiling, acceptance fails safely and produces an actionable, non-sensitive error.

### 27.3 Interactive sign-in, SSO, and step-up

A relying application sends an authorization request with registered redirect, state, PKCE, requested scopes, and supported organization/resource context. The IdP validates the request before redirecting or invoking an upstream provider. An existing session can satisfy sign-in only if current user, membership, client, authentication-age, and factor policies allow it. Otherwise, the transaction requests additional interaction. Consent and organization selection occur without expanding the originally authorized request.

A backend requiring stronger authentication returns a documented challenge rather than inventing a stronger claim or silently rejecting all sessions. The application starts a correlated step-up flow, obtains a newly authorized token, and retries only the intended action. The resource server checks the returned assurance and freshness; merely observing another redirect is not proof of step-up. [OIDC-CORE] [STEPUP]

### 27.4 API request and service-to-service delegation

```text
Application -> Orders API: access token, audience=orders, organization=A
Orders API  -> Local verifier: signature/type/issuer/audience/expiry checks
Orders API  -> State/PDP, when required: live status + scoped authorization
Orders API  -> Orders database: object belongs to organization A; ownership rules
Orders API  -> Response: permitted data only

If Orders must call Billing for this user:
Orders API  -> IdP token exchange: authenticate Orders; present valid user grant
IdP        -> Orders API: narrowed billing token; preserve subject/actor provenance
Orders API -> Billing API: billing-audience token
Billing API-> Own authorization checks: actor, subject, tenant, scopes, live policy
```

The Orders token is not automatically a Billing token. A pure machine task uses a machine grant instead of manufacturing a human subject. Arbitrary service chains and transitive permission growth are disallowed; each accepted delegation path is explicitly registered. [RESOURCE] [EXCHANGE]

### 27.5 Administrator support impersonation

The administrator authenticates normally, completes the required recent MFA, identifies a permitted customer and organization, supplies a reason, and requests an approved support profile. Policy checks the target, actor, customer settings, permitted resources, actor's delegation ceiling, and required independent approvals. The server durably records the grant and issues an opaque, short-lived support token through a secure backend channel or destination-bound one-time handoff.

The customer application creates an isolated support session, not a replacement for the administrator's primary session. Every protected support request performs strict online validation and preserves both identities in audit. Forbidden credential and security-setting operations remain forbidden even when the effective customer could normally perform them. Revocation, actor suspension, target suspension, expiry, or loss of membership ends future authorization. No refresh token or invisible extension is issued. Application-specific writes require explicit opt-in and narrower permissions than general customer access.

### 27.6 Account recovery

A recovery request returns an enumeration-resistant public result. The server delivers a short-lived, purpose-bound proof through an allowed channel and applies independent request and verification budgets. Successful password replacement consumes that proof atomically, updates the credential verifier, and applies the configured session-revocation policy. It does not erase MFA requirements. Recovery of lost MFA is a separate higher-risk process using approved recovery factors or a controlled assisted-recovery workflow.

A support operator cannot bypass this sequence by impersonating the user, changing their email, and then invoking ordinary recovery. Recovery events are visible to the real account owner through appropriate notifications and account activity records.

### 27.7 Employee offboarding and tenant removal

Removing a membership revokes the user's grants for that organization, invalidates relevant policy caches, stops current support grants scoped to that membership, and handles owned automation credentials according to policy. It does not globally delete a shared identity who still belongs to other organizations. Enterprise provisioning follows the same distinction.

Strict-online APIs deny subsequent requests after the authoritative change becomes visible. Offline-verifying services retain only the documented remaining token-validity window. Queued jobs and long-lived connections need their own cancellation or reauthorization contracts; a logout event alone does not retroactively cancel every business operation.

### 27.8 Emergency account and realm shutdown

Operators can disable an individual credential, user, service account, client, organization, or entire realm without deleting forensic evidence. Shutdown stops new grants and applies the selected online denial/revocation mechanism to existing grants. Emergency signing-key rotation is a separate operation with a separately documented impact on offline verifiers. A break-glass operator account is not a universal customer impersonation credential and must not bypass audit.

## 28. Service Integration, SDKs, and Backend Consumer Contracts

### 28.1 Required integration packages

- **SDK-001 [P0] — First-party verifier.** Publish at least one production-quality backend verification package with configured issuer/audience, key caching, supported algorithms, token-type rules, tenant extraction, clear errors, and negative test vectors.
- **SDK-002 [P0] — Online verification.** Include authenticated introspection, bounded-state checks, and strict-online support-token verification as separate explicit modes; do not silently downgrade on timeouts.
- **SDK-003 [P0] — Administration client.** Provide an OpenAPI-derived or equivalently typed client and CLI for setup, users, invitations, organizations, clients, roles, grants, sessions, and impersonation.
- **SDK-004 [P0] — OAuth client example.** Supply a runnable backend-for-frontend example using code flow, PKCE, client authentication, server-side token storage, state/nonce validation as applicable, logout, and refresh serialization. UI design remains outside scope.
- **SDK-005 [P0] — Resource-server example.** Supply a separate API that verifies audience, organization, current permission policy, and object ownership; demonstrate allowed and denied requests.
- **SDK-006 [P1] — Supported-language policy.** Select maintained language targets, proposed in order: Go and TypeScript/Node.js, then Python, Java, and .NET. Equivalent protocol compatibility must not depend on using a first-party SDK.
- **SDK-007 [P1] — Generated-client parity.** Generated API clients preserve structured errors, pagination, cancellation, request deadlines, idempotency, version headers, and secret-redaction rules.
- **SDK-008 [P0] — Safe diagnostics.** Expose actionable error categories without logging bearer tokens, proofs, passwords, client secrets, or sensitive user attributes.
- **SDK-009 [P1] — Verification fixtures.** Publish accepted/rejected token fixtures and behavioral tests so independent services can validate integration correctness without real customer data.
- **SDK-010 [P1] — Dependency and compatibility policy.** Publish runtime support, semantic-version rules, protocol/schema compatibility, security-update policy, and SDK/server interoperability tests.
- **SDK-011 [P1] — Framework adapters.** Provide thin adapters for selected HTTP frameworks; security decisions must remain in the common verification and authorization implementation, not drift across adapters.
- **SDK-012 [P1] — Administrative automation.** Provide declarative configuration reconciliation and a stable CLI; infrastructure-provider integrations can build on the same APIs rather than private database access.

### 28.2 Required resource-server checklist

Every integrated API must explicitly configure trusted issuers and its own audience. It must reject an ID token, unrelated machine token, incorrect tenant, or support token it does not implement. It derives tenant scope from verified authority, then compares route/body identifiers and resource ownership against that scope. It must not trust a browser-provided role, group, actor header, or organization identifier merely because another field contains a valid JWT.

The service documents which operations use offline, bounded-online, or strict-online validation, along with their revocation exposure. Policy errors and dependency failures have distinct telemetry but cannot become authorization success. Permission changes are handled through appropriately fresh checks, not by assuming token claims refresh themselves.

A reverse proxy may centralize authentication, but the downstream trust boundary still needs protection. Strip untrusted incoming identity headers, authenticate the proxy-to-service channel, and preserve tenant/actor metadata in a signed or otherwise integrity-protected context. Network placement alone is not sufficient authority.

### 28.3 HTTP, GraphQL, gRPC, WebSocket, and streaming

- **INT-001 [P1] — HTTP.** Define standard bearer/proof handling, 401/403 semantics, WWW-Authenticate challenges where applicable, and safe browser CORS behavior.
- **INT-002 [P1] — GraphQL.** Authenticate the request and authorize individual resolvers/objects. A permitted top-level query does not authorize every nested field or batched operation.
- **INT-003 [P1] — gRPC.** Verify credentials from approved metadata, enforce per-method and object permissions, and document how long-running streams handle expiry and revocation.
- **INT-004 [P1] — WebSockets.** Authenticate a connection using a safe client-compatible method, bind its scope, and reauthorize messages/subscriptions when required. Do not place reusable bearer credentials in logged connection URLs.
- **INT-005 [P1] — Long-lived streams.** Define maximum connection authorization age and renewal/disconnect behavior; an initial successful handshake is not permanent access.
- **INT-006 [P1] — Background jobs.** Store the authorized action, initiating subject/actor, tenant, approval, and expiry/revalidation policy rather than treating a serialized browser access token as indefinite job authority.
- **INT-007 [P1] — Message consumers.** Authenticate producer/service identity and validate trusted job metadata. Arbitrary message-body `user_id` values do not authorize user impersonation.
- **INT-008 [P1] — File and download grants.** Where application services issue one-time download links, keep those separate from IdP bearer tokens, with application-owned object binding, expiry, and disclosure controls.
- **INT-009 [P1] — Multi-issuer applications.** Support explicit issuer registration and tenant mapping; reject a token from an unrelated valid issuer even when subject IDs or emails collide.
- **INT-010 [P1] — Contract validation.** Before a service opts into impersonation or sensitive online authorization, run the shared integration tests for actor propagation, denial, expiry, failure behavior, and revocation.

### 28.4 Browser and native boundaries despite backend-only delivery

For browser applications, prefer a backend-for-frontend when appropriate to the application: store refresh tokens server-side and use narrowly scoped, secure browser-session cookies with CSRF protection. This is a recommended integration pattern, not a claim that every browser application must use the same architecture. A public client must never be issued a secret and told to keep it confidential in shipped browser code.

Native integrations use the applicable authorization-code/PKCE and external-user-agent profile, with precisely validated application redirects and platform-specific protections. Passkey creation and assertion still require a compatible user-agent/platform ceremony. The backend verifies those results; it cannot silently obtain a user's platform credential by calling an API itself. [NATIVE] [WEBAUTHN]

## 29. Specialized and Advanced Extension Profiles

These features extend the product's long-term scope. Each must have a pinned specification/profile, threat model, independently testable implementation, and honest maturity label. Merely adding a route or configuration switch does not establish protocol support.

- **ADV-001 [P2] — Hardened financial/API profile.** Offer a separately configured FAPI 2.0 profile with the profile's complete client/server requirements, interoperability tests, and explicit certification status. Do not reuse ordinary defaults while applying a financial-grade label. [FAPI]
- **ADV-002 [P2] — JARM.** Support registered response-signing/encryption policy, client key lifecycle, issuer/audience and response validation, and tested interactions with the selected authorization flow. [JARM]
- **ADV-003 [P2] — Restricted dynamic registration.** Implement approved software onboarding, initial registration authority, metadata validation, credential issuance/rotation, registration management tokens, and administrative disablement. Public self-registration must not permit privileged scopes, arbitrary trusted redirect patterns, or unrestricted metadata fetching. [DCR] [DCRM]
- **ADV-004 [P2] — JWT assertion profiles.** Distinguish client authentication from authorization grants; bind issuer, subject, audience, expiry, replay ID, and local authorization mapping to the selected profile. [JWT-ASSERTION]
- **ADV-005 [P3] — CIBA.** Implement a complete selected back-channel authentication profile with authenticated initiator, user-identification policy, transaction expiry, notification/polling rules, user-visible binding context, and anti-push-fatigue controls. Do not reinterpret a generic webhook as CIBA support. [CIBA]
- **ADV-006 [P3] — User-managed sharing.** Evaluate a version-pinned UMA profile only after resource ownership, consent, delegation, policy evaluation, permission tickets, revocation, and resource-server responsibilities are clearly modeled.
- **ADV-007 [P3] — Shared security signals.** Support approved SSF-based event exchange with source trust, receiver registration, event-subject mapping, replay defenses, retention, delivery failure, and privacy controls. Incoming events must map to an explicit local action policy. [SSF]
- **ADV-008 [P3] — Verifiable credential issuance.** Isolate credential-issuer keys, credential configurations, subject eligibility, authorized claims, wallet binding, and lifecycle/status strategy from ordinary OAuth account-token issuance. Support only named, versioned formats and profiles. [VCI]
- **ADV-009 [P3] — Credential presentation and wallet federation.** Treat verifier trust, holder binding, replay protection, selective-disclosure policy, status checks, and identity-linking authority as a separate design. Possession of an arbitrary credential must not automatically create a verified local account or privileged membership.
- **ADV-010 [P3] — Registry token bridge.** Provide an optional container-registry authorization adapter mapping authenticated principals to exact repository/action permissions with a dedicated token audience and signing policy.
- **ADV-011 [P3] — Historical entitlement evidence.** Provide policy-version and grant-history reconstruction for authorized investigations without claiming to reproduce missing application-owned facts or deleted third-party state.
- **ADV-012 [P3] — Advanced risk integrations.** Add external device-posture, fraud, or adaptive-authentication signals only through versioned, privacy-reviewed interfaces with deterministic fallback policy. No opaque risk score alone may silently override an explicit deny or elevate privileges.

Advanced credential, registry, UMA, and risk integrations are product backlog items, not claims of current support in the three reference products. Exact profiles not cited here require a separate primary-source review before implementation.

## 30. Deployment, Self-Hosting, and High Availability

### 30.1 Deployment profiles

| Profile                         | Intended use                       | Required behavior                                                                                                                                                          |
| ------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local development               | Contributor or integration sandbox | Container Compose, seeded non-production fixtures, local message sink, no production claim.                                                                                |
| Single-node production          | Small installation                 | TLS termination, durable PostgreSQL, protected keys/secrets, worker, backups, restricted admin surface, observable health.                                                 |
| Highly available                | Redundant production               | Multiple stateless API instances and workers, HA database, shared security state, safe job leases, coherent issuer configuration.                                          |
| Restricted-network / air-gapped | Controlled environments            | Offline installation artifacts, local dependencies where applicable, no license or telemetry dependency, documented unavailable external integrations.                     |
| Strongly isolated tenants       | Additional isolation requirement   | Separate realm/deployment/database/key boundaries according to the selected assurance requirement, not an unsupported promise of physical isolation from one shared table. |

- **DEP-001 [P0] — Small baseline.** The minimum supported production deployment uses the server/worker and PostgreSQL. Optional caching, queues, or object storage must not be mandatory commercial services.
- **DEP-002 [P0] — Reproducible local setup.** Publish a working Compose configuration, configuration reference, environment template without real secrets, and smoke-test command.
- **DEP-003 [P0] — Immutable artifact.** Publish versioned container images and checksums from release source; pin dependencies and produce an SBOM and provenance record.
- **DEP-004 [P0] — Process hardening.** Run as a non-root user by default, support read-only application filesystems, and require explicit writable locations for temporary files and diagnostic artifacts.
- **DEP-005 [P0] — Trusted external URLs.** Configure canonical issuer, public origin, allowed proxy hops, callback domains, and TLS assumptions explicitly. Never derive security URLs from an arbitrary Host header.
- **DEP-006 [P0] — Secret injection.** Support secret references/files and an operator-approved secret manager adapter. Keep bootstrap secrets, database passwords, encryption keys, and connector credentials out of image layers and ordinary config exports.
- **DEP-007 [P0] — Bootstrap.** Use a local/operator-only, expiring, one-time initial-administrator enrollment mechanism. Do not ship a universal default administrator password or anonymously open setup endpoint after initialization.
- **DEP-008 [P0] — Key persistence.** Persist or reference production signing/encryption keys durably; a process restart must not silently create a new issuer key identity and invalidate unrelated sessions.
- **DEP-009 [P0] — Health contracts.** Separate liveness from readiness. Dependency degradation must remove unsafe instances from new traffic without restart loops that destroy forensic or diagnostic state.
- **DEP-010 [P1] — Horizontal scale.** Use database transactions or an explicitly correct shared coordination primitive for one-time proofs, refresh rotation, invitation consumption, and worker ownership.
- **DEP-011 [P1] — Worker leases.** Jobs use bounded leases, retry classification, idempotency, and dead-letter handling. A duplicate worker must not create duplicate grants or unlimited notifications.
- **DEP-012 [P1] — Rolling upgrades.** Define supported mixed-version windows, expand/migrate/contract schema changes, feature rollout gates, and rollback restrictions before altering shared state.
- **DEP-013 [P1] — Kubernetes packaging.** Publish maintained Helm or equivalent manifests with secure defaults, resource settings, disruption budgets, probes, secret references, and migration-job guidance; Kubernetes is not required to use the product.
- **DEP-014 [P1] — Multiple hostnames.** Support verified custom domains only with explicit DNS/TLS/routing management and issuer/cookie/WebAuthn implications. A vanity login hostname does not silently rename existing subjects or issuer identifiers.
- **DEP-015 [P1] — Capacity isolation.** Separate interactive authentication capacity from expensive exports, scans, connector syncs, and notification bursts; enforce fair tenant quotas and bounded worker pools.
- **DEP-016 [P1] — External key providers.** Support a documented KMS/HSM interface as an optional deployment capability without making one paid provider mandatory or calling ordinary software keys hardware-protected.
- **DEP-017 [P1] — Air-gap bundle.** Provide images/packages, migrations, source/notice files, checksums, verification instructions, and documentation sufficient for offline installation and upgrades.
- **DEP-018 [P1] — Region topology.** Begin with a single authoritative write region. Any later multi-region design must specify consistency, replication delay, failover, signing-key access, residency, and revocation semantics.
- **DEP-019 [P2] — Disaster-region recovery.** Support a tested standby/recovery profile before advertising active-active identity writes or global immediate revocation.
- **DEP-020 [P1] — Configuration reconciliation.** Validate and diff configuration changes before applying them; declare which changes are dynamic, require restart, or change security boundaries. No unreviewed file watcher may weaken policy on transient parse errors.

### 30.2 Suggested configuration families

```text
server: listeners, public_origin, trusted_proxies, shutdown_deadline
identity: canonical_issuers, realms, organization_policy
storage: database_reference, pool_limits, migration_policy
keys: signing_provider, encryption_provider, active_key_ids, rotation_policy
sessions: ordinary, remember_me, offline_grants, reuse_policy
security: passwords, factors, recovery, rate_limits, allowed_algorithms
resources: audiences, verification_modes, introspection_client_policy
impersonation: enabled, allowed_resources, assurance, approvals, maximum_ttl
federation: enabled_adapters, metadata_egress_policy, source_trust
delivery: smtp_reference, sms_adapter, templates, send_budgets
workers: concurrency, lease_duration, retries, retention_jobs
observability: logs, metrics, tracing, redaction, sampling
privacy: retention, export_policy, deletion_policy, telemetry_opt_in
```

A configuration schema must expose units, allowed ranges, defaults, sensitivity, reload behavior, and incompatible combinations. Invalid issuer/key/tenant settings prevent readiness; they must not fall back to guessed production values.

## 31. Reliability, Observability, and Incident Operations

### 31.1 Operational requirements

- **OPS-001 [P0] — Structured logs.** Emit machine-readable severity, component, event code, request/trace ID, outcome, and safe scope identifiers. Apply redaction before log serialization, not only in a downstream collector.
- **OPS-002 [P0] — Metrics.** Measure login and token success/error rates, latency, rate-limit decisions, database health, key-provider failures, active worker leases, queue age, and delivery outcomes without putting user IDs, email addresses, or raw tenant names in unrestricted high-cardinality labels.
- **OPS-003 [P1] — Tracing.** Support an open tracing interface with configurable sampling and disabled sensitive attribute capture. Propagate a trace identifier, not bearer credentials, into diagnostic context.
- **OPS-004 [P0] — Alertable security failures.** Provide signals for refresh reuse, suspicious impersonation activity, cross-tenant denials, factor recovery, disabled audit persistence, signing-key problems, bootstrap attempts, and unusual credential issuance.
- **OPS-005 [P0] — Backup completeness.** Back up authoritative data and the protected key material or references necessary to decrypt it; database backups alone are insufficient when encryption keys are lost.
- **OPS-006 [P0] — Restore testing.** Publish and execute a restore procedure that verifies identities, memberships, credentials, policy versions, key access, and security-state consistency using synthetic accounts.
- **OPS-007 [P1] — Point-in-time recovery.** Support an operator-controlled recovery method and document its storage/encryption prerequisites, retention, and expected data-loss window.
- **OPS-008 [P0] — Migration safety.** Back up and validate preconditions before destructive schema transitions; report incompatible binaries/configuration rather than attempting unsafe automatic recovery.
- **OPS-009 [P1] — Retention jobs.** Enforce configurable cleanup for expired transactions, consumed proofs, delivery payloads, audit/export artifacts, and soft-deleted records without deleting active evidence or breaking referential boundaries.
- **OPS-010 [P1] — Support bundle.** Export an explicitly reviewed diagnostic bundle containing version/configuration summaries and sanitized health information; never include private keys or raw token/session dumps by default.
- **OPS-011 [P0] — Clock health.** Document trusted time synchronization and alert on excessive skew. All nodes use consistent UTC instants for expiry and audit; local display timezone is not a security-policy clock.
- **OPS-012 [P1] — Graceful shutdown.** Stop new requests, drain bounded work, release or expire leases, and avoid reporting success for an uncommitted operation.
- **OPS-013 [P1] — Operator accountability.** Protect and audit operational settings, exports, key changes, support-bundle generation, and break-glass use. Separate database superuser access from normal application administration.
- **OPS-014 [P1] — Security-state restoration.** A restore plan explicitly addresses reappearance of revoked credentials, consumed invitations, deleted accounts, and old grants. Reapply independently retained revocation/deletion records or perform a documented invalidation/re-enrollment procedure before reopening traffic.
- **OPS-015 [P1] — Status and maintenance.** Provide machine-readable degraded capability status for authenticated operators and configurable maintenance behavior without disclosing internal topology to unauthenticated clients.
- **OPS-016 [P1] — Repeatable runbooks.** Maintain tested procedures for compromised keys, database loss, connector compromise, abuse spikes, notification outages, owner recovery, and privacy deletion errors.

### 31.2 Failure-mode contract

| Failure                                   | Required behavior                                                                                                                         | Forbidden shortcut                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Authoritative database unavailable        | Stop new grants and security mutations; strict-online checks fail closed. Existing offline JWTs follow their published lifetime exposure. | Mint stateless replacement refresh tokens or assume all users remain active.            |
| Optional cache unavailable                | Use a safe authoritative path where capacity permits; apply backpressure or fail closed when required state cannot be checked.            | Treat a cache miss/error as a positive authorization decision.                          |
| Signing provider unavailable              | No new signed tokens requiring that key; report degraded readiness for affected flows.                                                    | Generate an unpersisted emergency production key without an approved rotation.          |
| Audit/outbox transaction cannot commit    | Reject the privileged mutation/grant.                                                                                                     | Complete the action and promise to reconstruct evidence later.                          |
| Email/SMS delivery unavailable            | Retain bounded retryable work and expose generic user-facing pending/failure behavior.                                                    | Mark contact verified or recovery complete without proof.                               |
| Required upstream SSO unavailable         | Explain retry/unavailability through the interaction API; preserve organization policy.                                                   | Open a local-password bypass for an SSO-mandatory organization.                         |
| PDP unavailable                           | Protected decisions fail closed; only explicitly documented, still-valid cache decisions may be used in a bounded-online profile.         | Convert evaluation errors into allow.                                                   |
| Webhook receiver unavailable              | Retry with backoff, record failure, dead-letter when appropriate; core committed state remains authoritative.                             | Undo unrelated committed identities or assume all relying services received revocation. |
| One API node crashes                      | Retry only operations whose protocol/idempotency semantics permit it; shared security state determines the outcome.                       | Accept duplicate proof use because a different node did not see the first request.      |
| Worker crashes after external side effect | Retry with stable event/idempotency identifiers and reconciliation; expose unavoidable delivery ambiguity.                                | Claim exactly-once external email delivery.                                             |
| Security-state replication is delayed     | Route strict-online decisions to an authoritative consistent source or deny.                                                              | Read a stale replica while advertising immediate revocation.                            |
| Clock drift exceeds policy                | Remove affected instances from sensitive issuance/validation and alert.                                                                   | Increase all expiry tolerances indefinitely.                                            |

Availability degradation must be explicit. A system that signs tokens while ignoring unavailable authorization state is not “highly available authentication”; it has changed its security contract.

### 31.3 Incident runbook outlines

**Signing-key compromise:** Stop affected signing, activate a reviewed replacement, revoke or invalidate affected grants where needed, publish updated verification metadata, and coordinate emergency trust removal with relying services. Record which offline services could still accept compromised-key tokens until their trust caches are updated; ordinary token expiry alone cannot constrain an attacker who possesses a still-trusted signing key. Preserve key-use evidence and investigate how the private key was exposed.

**User or administrator compromise:** Disable the affected identity/credentials as appropriate, revoke sessions and automation keys, stop support grants, inspect actor-aware audit, repair unauthorized grants, and require approved recovery. Do not only reset the password while leaving independent API keys active.

**Connector or provisioning compromise:** Disable the connector credential, suspend automated trust mappings, inventory identities/memberships/grants it changed, compare to authoritative source evidence, and apply a scoped remediation plan. A malicious provisioner must not be able to destroy unrelated organizations during remediation.

**Restore after data loss:** Restore data and key access in an isolated environment; reconcile revocations, proof-consumption state, deletions, and issuer configuration; invalidate uncertain grants according to the approved plan; test representative flows; then resume traffic. Replaying notification outbox records must not resend stale recovery secrets or duplicate business entitlements.

## 32. Nonfunctional Targets and Capacity Validation

All values in this section are **proposed acceptance targets, not measurements or vendor benchmarks**. A release must publish the actual result with hardware, database topology, software versions, policy complexity, network assumptions, and workload mix. Operators may select stricter targets or a smaller supported footprint.

### 32.1 Initial target profile

| Dimension                          | Proposed initial target or constraint                                                                              | Validation condition                                                                                         |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Interactive correctness            | No grant before all required authentication/authorization steps complete                                           | Positive and negative end-to-end suites.                                                                     |
| Tenant isolation                   | No cross-tenant disclosure or mutation in the isolation test corpus                                                | Every scoped route, query, export, hook, and connector covered.                                              |
| Warm JWT verification              | p95 at or below 5 ms inside a sample resource-server process                                                       | Excludes network and business queries; algorithm, token size, and hardware disclosed.                        |
| Token refresh / client credentials | p95 at or below 200 ms server-side at the declared sustainable load                                                | Includes authoritative checks and durable writes where applicable.                                           |
| Introspection                      | p95 at or below 100 ms server-side for the baseline policy profile                                                 | Strict-online path uses authoritative state, not an undisclosed positive cache.                              |
| Password verification              | Operator-calibrated resource cost, with an initial target budget around 250–750 ms per hash on deployment hardware | Security floor and capacity reviewed together; not weakened just to match another endpoint's latency.        |
| Common list/read APIs              | p95 at or below 200 ms at declared load                                                                            | Bounded page size and indexed tenant scope; count queries measured separately.                               |
| HA service availability            | An initial operational SLO proposal of 99.9% per month                                                             | Define successful operations, maintenance policy, dependency attribution, and error budget before reporting. |
| Core data recovery point           | Proposed RPO at most 5 minutes for the documented backup/replication profile                                       | Measured by restore exercises; security-state reconciliation may require invalidation.                       |
| Core recovery time                 | Proposed RTO at most 60 minutes for the documented standby/restore profile                                         | Includes key access and correctness checks, not only starting a container.                                   |
| Ordinary access-token exposure     | Five-minute default lifetime plus permitted clock tolerance for an honestly offline verifier                       | No claim of instantaneous revocation.                                                                        |
| Support-token revocation           | Authoritative validation for each newly authorized operation; zero positive-cache TTL                              | In-flight business actions need separate cancellation design.                                                |
| Data export                        | Streaming or asynchronous bounded-memory execution                                                                 | Large exports must not exhaust authentication workers.                                                       |
| Minimum implementation footprint   | Core server/worker + PostgreSQL                                                                                    | No mandatory paid service or unnecessary distributed broker.                                                 |

Targets are not universal sizing guidance. In particular, password hashing, public-key operations, database write contention, and policy complexity have different resource profiles. Publish measured throughput rather than inventing a single requests-per-second promise for all operations.

### 32.2 Capacity requirements

- **NFR-001 [P0] — Explicit limits.** Bound token/request/header sizes, nested JSON/XML depth, search complexity, group recursion, policy execution, batch size, page size, transaction attempts, and connection duration. Document units and safe operator ranges.
- **NFR-002 [P0] — Load shedding.** Reject excess work predictably with suitable errors/retry guidance while preserving capacity for already-authenticated administration and recovery from an incident.
- **NFR-003 [P1] — Workload suite.** Benchmark password login, passkey assertion, refresh, client credentials, introspection, policy evaluation, SCIM/import, audit querying, and delivery workers independently and in a mixed workload.
- **NFR-004 [P1] — Cardinality suite.** Test many users, many small organizations, one large organization, large groups, deep-but-bounded role graphs, many clients, and large audit partitions.
- **NFR-005 [P1] — Sustained tests.** Run soak tests across token expiry, signing rotation, session cleanup, retries, and database maintenance rather than measuring a brief warm-cache spike.
- **NFR-006 [P1] — Adversarial resource use.** Measure unknown-key floods, failed passwords, OTP guessing, oversized inputs, complex filters, metadata fetch attempts, and notification spam under enforced budgets.
- **NFR-007 [P1] — Data-consistency stress.** Exercise concurrent invites, owner transfer, refresh rotation, recovery consumption, role changes, connector sync, and revocation across multiple nodes.
- **NFR-008 [P1] — Portable results.** Publish benchmark scripts, generated-data seeds, configuration, histograms, errors, and bottlenecks so operators can reproduce results on their own hardware.
- **NFR-009 [P1] — Accessibility of integration metadata.** Supply language tags, machine-readable interaction requirements, and clear error codes to help consuming interfaces provide accessible experiences; backend delivery does not certify frontend accessibility.
- **NFR-010 [P1] — Compatibility and time.** Test UTC handling, daylight-saving-independent expiry, supported Unicode/profile inputs, stable identifiers, and versioned client compatibility without locale-dependent security comparisons.

## 33. Verification, Security Tests, and Acceptance Scenarios

### 33.1 Test layers

Unit tests cover policy decisions, domain invariants, canonicalization, proof lifecycle, and cryptographic-library integration. Integration tests use the actual database and exercise transactions, migrations, outbox jobs, and concurrent mutations. Protocol tests run independent relying clients and negative fixtures. End-to-end tests run an IdP, two organizations, multiple users, multiple clients, at least two protected APIs, an administrator, and a machine principal. Operational tests exercise failures, restores, rolling upgrades, and key rotation.

Use synthetic identities and controlled test providers. Production credentials, real customer contact lists, and uncontrolled SMS delivery do not belong in CI. Security testing must be authorized and limited to project-controlled fixtures.

### 33.2 Mandatory regression matrix

Each scenario below is a release-blocking requirement when the corresponding feature is enabled. A later-phase feature may remain absent, but it may not ship without its negative tests.

| Test ID  | Scenario                                                                                       | Required outcome                                                                                       |
| -------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| TEST-001 | JWT has a valid signature but the wrong API audience                                           | Reject before business processing.                                                                     |
| TEST-002 | ID token is sent to a business API                                                             | Reject as the wrong token class.                                                                       |
| TEST-003 | Token comes from an unconfigured issuer with a familiar email/subject                          | Reject without token-driven metadata fetching.                                                         |
| TEST-004 | Unsupported algorithm, `none`, malformed header, or ambiguous key selection                    | Reject consistently; no algorithm fallback.                                                            |
| TEST-005 | Unknown `kid` flood                                                                            | Bounded metadata refresh; no request storm or fail-open verification.                                  |
| TEST-006 | Expired, not-yet-valid, or excessively future-issued token                                     | Reject according to the documented clock policy.                                                       |
| TEST-007 | Organization A token accesses a known Organization B object ID                                 | No disclosure or mutation, including nested resources.                                                 |
| TEST-008 | Organization ID in route/body disagrees with verified token scope                              | Reject; never silently switch tenant.                                                                  |
| TEST-009 | Search, totals, exports, or cursor from another tenant                                         | No cross-tenant records, counts, or reusable cursor authority.                                         |
| TEST-010 | A delegated administrator creates/edits a role above their grant ceiling                       | Reject direct and indirect/composite escalation.                                                       |
| TEST-011 | Concurrent attempts remove or demote the last owner                                            | Preserve at least one valid owner or execute an explicitly authorized shutdown workflow.               |
| TEST-012 | An organization administrator changes a shared user's global password/MFA                      | Reject absent separate realm-wide authority.                                                           |
| TEST-013 | A user self-edits an attribute consumed by a privileged policy                                 | Protected attribute ownership prevents escalation.                                                     |
| TEST-014 | Cyclic or oversized group/role graph                                                           | Reject or bound evaluation without hanging or allowing.                                                |
| TEST-015 | Invite is accepted by the wrong verified identity                                              | Reject without leaking the invited user's private data.                                                |
| TEST-016 | Two nodes consume the same invitation concurrently                                             | At most one accepted transition; no duplicate grants.                                                  |
| TEST-017 | Inviter loses authority or role definition expands before acceptance                           | Revalidate and deny unauthorized membership privileges.                                                |
| TEST-018 | Email scanner follows a magic/invitation link                                                  | Safe GET does not complete account access or consume an acceptance action.                             |
| TEST-019 | Resent proof or invite attempts to reuse the replaced secret                                   | Replaced secret is invalid.                                                                            |
| TEST-020 | Public registration/recovery targets existing versus absent contact                            | Apply the documented enumeration-resistant response policy.                                            |
| TEST-021 | OTP guesses are distributed across sessions/IPs                                                | Combined budgets constrain attempts without a trivial permanent account-lockout attack.                |
| TEST-022 | MFA requirement is skipped through an alternate login, recovery, or callback route             | No successful grant before required assurance.                                                         |
| TEST-023 | TOTP/recovery code is reused concurrently                                                      | Atomic one-use/replay policy is enforced.                                                              |
| TEST-024 | Passkey assertion has wrong challenge, origin, RP ID, or verification flags                    | Reject; do not substitute client-reported success.                                                     |
| TEST-025 | A synchronized passkey counter changes unexpectedly                                            | Apply the documented backup-aware policy rather than an unreviewed universal counter assumption.       |
| TEST-026 | Attacker links a social account using only matching email text                                 | No implicit linking without the explicit trusted linking policy and required proofs.                   |
| TEST-027 | Enterprise SSO fails for an SSO-mandatory organization                                         | No local-password fallback that weakens policy.                                                        |
| TEST-028 | OAuth state/nonce or PKCE verifier is incorrect, or code is replayed                           | Reject; authorization code remains bound to the original transaction/client.                           |
| TEST-029 | Redirect uses wildcard tricks, userinfo, ambiguous encoding, or untrusted host                 | Reject outside the precise registered matching rules.                                                  |
| TEST-030 | Parallel refresh calls use one refresh token                                                   | No two independent successors; documented strict reuse handling applies.                               |
| TEST-031 | A previously rotated refresh token is presented                                                | Family compromise/revocation policy is applied and audited.                                            |
| TEST-032 | A session exceeds its absolute lifetime despite repeated refresh                               | No further session extension through idle-time reset.                                                  |
| TEST-033 | Membership is removed while user remains in another organization                               | Removed tenant access ends according to the service's verification mode; unrelated membership remains. |
| TEST-034 | A role or session version changes but an API only verifies JWT locally                         | Test exposes the published stale-token window; no false immediate-revocation claim.                    |
| TEST-035 | Strict-online authorization state is unavailable or replica is stale                           | Deny rather than use an unauthorized stale positive result.                                            |
| TEST-036 | Signing keys rotate during active sessions and cached JWKS use                                 | Valid planned-overlap tokens work; retired/compromised trust follows the declared policy.              |
| TEST-037 | Unauthorized client introspects tokens from another resource                                   | Deny disclosure according to introspection-client scope.                                               |
| TEST-038 | A client exchanges a token for an unauthorized audience or arbitrary subject                   | Reject; no subject-selection privilege from exchange alone.                                            |
| TEST-039 | Machine token calls human self-service or support-impersonation routes                         | Reject unless the route has an explicit independently reviewed service-identity contract.              |
| TEST-040 | Administrator requests impersonation without permission, current MFA, or reason                | Reject before a support credential is issued.                                                          |
| TEST-041 | Support flow targets another tenant, administrator, service principal, or nested impersonation | Reject under the declared target restrictions.                                                         |
| TEST-042 | Support token attempts password/MFA/email/API-key/PAT/security changes                         | Reject even if the customer would normally be entitled to perform the action.                          |
| TEST-043 | Support token is refreshed, replayed after revoke, or used after expiry                        | No silent renewal; future protected requests denied.                                                   |
| TEST-044 | Actor loses permission/session or target loses eligible membership during support              | Strict-online validation denies subsequent authorization.                                              |
| TEST-045 | Support request passes but actor identity is dropped from downstream audit                     | Integration fails support-mode contract validation.                                                    |
| TEST-046 | One-time support handoff is replayed or redeemed by another destination                        | Reject; no reusable access token appears in redirect URLs.                                             |
| TEST-047 | Support issuance succeeds but durable audit transaction fails                                  | No usable grant is issued.                                                                             |
| TEST-048 | SCIM deactivates a user shared with another organization                                       | Apply connector-scoped deprovisioning, not unauthorized global deletion.                               |
| TEST-049 | SCIM sync maps a group to an out-of-ceiling owner/admin role                                   | Reject and expose a scoped reconciliation error.                                                       |
| TEST-050 | Stale ETag or competing SCIM/admin mutation                                                    | Enforce conflict/ownership policy without silently losing protected changes.                           |
| TEST-051 | SAML has invalid audience/correlation/signature, duplicate IDs, or assertion replay            | Reject with bounded parser resources and no unsafe identity creation.                                  |
| TEST-052 | Metadata/webhook URL resolves or redirects into forbidden networks                             | Egress policy applies to every actual connection, including re-resolution.                             |
| TEST-053 | Hook times out, crashes, or attempts a protected-claim mutation                                | Apply declared fail-closed/bounded behavior; no authority escalation.                                  |
| TEST-054 | Webhook is duplicated, replayed, delayed, or signed with an invalid key                        | Receiver fixtures verify signatures/replay policy and idempotent handling.                             |
| TEST-055 | Attacker submits forged trusted-proxy identity headers                                         | Downstream does not accept unauthenticated identity context.                                           |
| TEST-056 | Browser sends forged cross-site credential-changing request                                    | CSRF and origin/session defenses reject it.                                                            |
| TEST-057 | Audit/log/export/support bundle contains a secret-bearing fixture                              | Automated secret/redaction tests fail the build.                                                       |
| TEST-058 | A job is retried after commit or worker lease expiry                                           | No duplicate role grants, proof consumption, or unbounded side effects.                                |
| TEST-059 | Database/cache/key provider/SMTP fails during each sensitive transition                        | Observed result matches the failure-mode contract; no partial unauthorized success.                    |
| TEST-060 | Backup is restored after revocation, deletion, or proof consumption                            | Reconciliation/invalidation prevents unsafe resurrection before traffic resumes.                       |
| TEST-061 | Upgrade runs across supported mixed server versions                                            | Shared state remains compatible; unsupported version combinations fail clearly.                        |
| TEST-062 | Long-lived stream outlives its authorization or membership                                     | Renewal/recheck/disconnect contract is enforced.                                                       |
| TEST-063 | Queue message supplies arbitrary subject/tenant metadata                                       | Consumer requires an authenticated producer and approved job authority.                                |
| TEST-064 | Organization deletion races with invitation acceptance or token issuance                       | No grant to a deleted/disabled tenant and no orphaned privileged state.                                |
| TEST-065 | Revoked PAT/service key is used through a different authentication adapter                     | Central credential state prevents alternate-path acceptance.                                           |
| TEST-066 | Dynamic client registration requests privileged scopes or unsafe metadata URLs                 | Registration policy rejects privilege and egress escalation.                                           |
| TEST-067 | DPoP/mTLS token is presented without the correct sender proof                                  | Bound-resource request is rejected.                                                                    |
| TEST-068 | Device/CIBA user approval is expired, replayed, or bound to the wrong client request           | No unintended grant; correct transaction and user-visible context required.                            |
| TEST-069 | Administrator exports another tenant's protected fields through a job                          | Job and download authorization preserve field and tenant scope.                                        |
| TEST-070 | A reset-password completion is used to bypass missing MFA                                      | Password changes if valid, but account access still requires the approved assurance/recovery policy.   |
| TEST-071 | A customer revokes or opts out of support access                                               | New support grants stop and active grants are handled under the documented policy.                     |
| TEST-072 | Installation has outbound network blocked                                                      | Core local operation works without activation, telemetry, or commercial license checks.                |

### 33.3 Release-quality requirements

- **QA-001 [P0] — Security properties before coverage percentage.** Require direct tests for critical invariants; a high line-coverage number is not a substitute.
- **QA-002 [P0] — Static/dependency checks.** Run linting, type checks, dependency vulnerability review, secret scanning, and license-policy checks in CI with triaged exceptions.
- **QA-003 [P1] — Fuzz/property tests.** Fuzz token/request parsing, redirect normalization, SAML where enabled, SCIM filters, policy inputs, and state-machine boundaries; use property tests for tenant isolation and one-time transitions.
- **QA-004 [P1] — Interoperability matrix.** Publish tested external clients/connectors and exact versions; a tested profile is not universal compatibility with every feature of that product.
- **QA-005 [P1] — Independent review.** Obtain qualified external review of authentication, recovery, authorization, cryptographic usage, and impersonation before claiming a hardened general-purpose release.
- **QA-006 [P1] — Conformance claims.** Distinguish internal test success, participation in a conformance suite, and actual granted certification. Publish evidence for any certification claim.
- **QA-007 [P0] — No demo bypasses in production.** Production mode must reject development signing keys, seeded passwords, email sinks presented as real verification, and insecure authentication shortcuts.
- **QA-008 [P1] — Reproducible regressions.** Every security fix adds a controlled regression fixture and identifies affected versions without exposing customer data.

## 34. Import, Migration, Export, and Exit Strategy

- **MIG-001 [P1] — Migration inventory.** Document source-system users, subject IDs, organizations, memberships, clients, credentials, factors, grants, consents, and data ownership before writing data.
- **MIG-002 [P1] — Source version pinning.** Each adapter names supported source products/versions and validates export schema; never infer compatibility only from a familiar product name.
- **MIG-003 [P1] — Dry run.** Produce scoped counts, conflicts, validation errors, proposed identifier mappings, and protected-field/role changes without mutating target authority.
- **MIG-004 [P1] — Stable mapping.** Store source-qualified immutable mappings. Matching email alone cannot merge identities, preserve account control, or link enterprise sources safely.
- **MIG-005 [P1] — Permission translation.** Map roles/groups/policies through an explicit reviewed translation; unknown source permissions must not become target administrator access.
- **MIG-006 [P1] — Password migration.** Import password verifiers only when the source format, parameters, pepper availability, licensing, and security floor permit safe verification. Rehash on successful login when supported, otherwise require recovery/re-enrollment. Never require users' plaintext passwords in an export.
- **MIG-007 [P1] — MFA migration.** Transfer TOTP seeds only through a protected, explicitly authorized path when technically compatible; reencrypt into the target key hierarchy. Factors without transferable private material require re-enrollment.
- **MIG-008 [P1] — Passkey migration constraints.** Preserve the credential's RP-ID/origin and credential-record requirements only through a reviewed compatible migration. Changing the identity hostname may require a supported transition or new enrollment; backend database copying does not change a passkey's relying-party binding. [WEBAUTHN]
- **MIG-009 [P1] — Verified attributes.** Preserve verification flags only when the source and import process are explicitly trusted for that assertion; provenance must remain auditable.
- **MIG-010 [P1] — Session transition.** Do not promise portable live sessions or refresh tokens across unrelated issuers. Plan reauthentication or an explicitly bounded, reviewed bridge and communicate the cutover impact.
- **MIG-011 [P1] — Resumable batches.** Support validated checkpoints, source-qualified idempotency, bounded batches, restart, and cancellation without partially elevating memberships.
- **MIG-012 [P1] — Reconciliation.** Compare counts, scoped memberships, privileged assignments, selected credential usability, and application subject mapping before production cutover.
- **MIG-013 [P1] — Cutover and rollback.** Freeze or reconcile source writes, update relying-service trust deliberately, preserve issuer/subject identity mappings, and define when rollback is no longer safe after independent writes.
- **MIG-014 [P1] — Exit exports.** Export documented portable identity/configuration formats with versions and stable IDs. Exclude raw active bearer credentials; credential-secret export requires a separate high-assurance, explicitly approved process or remains unsupported.
- **MIG-015 [P1] — Secure artifacts.** Encrypt migration/export artifacts, require narrowly scoped download authorization, set expiry/retention, audit access, and avoid sending customer identity archives as ordinary email attachments.
- **MIG-016 [P1] — Historical evidence.** Preserve imported audit provenance separately from locally authoritative events; never relabel unverified historical source records as events directly witnessed by the new server.
- **MIG-017 [P1] — Deletion continuity.** Carry deletion/suppression obligations into import and restore processes so an old source export does not recreate an account removed after the export was produced.
- **MIG-018 [P2] — First-party migration adapters.** Prioritize documented adapters for selected Keycloak, ZITADEL, and SuperTokens exports/APIs, with exact tested versions and a capability report showing unsupported credential or policy conversions.

A clean exit path is a product requirement, not a promise that all credentials, protocol relationships, or historical application subjects can be transformed losslessly. The migration tool must show incompatibilities before cutover.

## 35. Delivery Roadmap and Release Gates

The complete catalogue is the target product, not a suggestion to release every protocol in the first milestone. Priority affects scheduling, never the safety requirements of an enabled feature. Every implemented feature remains free in every phase.

### 35.1 Milestones

| Milestone                                     | Scope                                                                                                                                                                                                                                                        | Exit gate                                                                                                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M0 — Foundations                              | License/governance, threat model, trust boundaries, database migrations, durable keys, issuer model, CI, development deployment, API/error conventions.                                                                                                      | Reproducible build; no default production secrets; signed-token verifier negative tests; tenant/database invariants proven in integration tests.                          |
| M1 — Secure identity core                     | P0 account registration, verification, password authentication/recovery, required MFA, authentication transactions, sessions, code/PKCE, client credentials, token validation/introspection/revocation, users/clients/resources, basic operational controls. | Full positive/negative authentication lifecycle; atomic refresh and proof use; accurate metadata; independently integrated example resource API.                          |
| M2 — Complete P0 backend                      | P0 organizations, memberships, invitations, RBAC/delegation ceilings, administration API/CLI, audit, secure support impersonation, first verifier/admin client, backup/restore and production packaging.                                                     | All P0 requirements and applicable TEST cases pass; no cross-tenant access; support resource contract passes; documented revocation exposure and incident runbooks.       |
| M3 — Full general-purpose platform            | Remaining P1: richer passwordless/passkey/social/federation options, richer policies/groups/lifecycle, device flow, logout integrations, API keys/PATs, token exchange, jobs/webhooks, import/export, language SDK expansion, supported HA/upgrade paths.    | Each enabled feature has API/schema, permissions, evidence, failure behavior, migration path, and interoperability tests; independent security review findings addressed. |
| M4 — Enterprise and advanced interoperability | P2 SAML, SCIM/directories, advanced client and sender-constrained profiles, workload federation, richer policy/delegation, specialized deployment adapters, tested migration adapters.                                                                       | Named protocol profiles and compatible counterpart versions published; provisioning and federation attack suites pass; capacity/restore results published.                |
| M5 — Specialized extensions                   | Selected P3 CIBA/UMA/signals/credential/registry/risk capabilities based on real requirements and maintained profiles.                                                                                                                                       | Separate threat model and interoperability evidence; no weakening of core trust boundaries or undocumented compliance claims.                                             |

Milestones are dependency and readiness gates, not time estimates. A smaller early release must clearly state its implemented subset and must not advertise unimplemented advanced capabilities.

### 35.2 Non-negotiable dependency chains

```text
Stable realm/organization model
    -> identity/membership invariants
    -> scoped roles and delegation ceilings
    -> safe administrative APIs and invitations

Durable secrets + client registry + authentication transactions
    -> code/PKCE + typed access tokens + refresh state
    -> resource verifier + online validation
    -> token exchange / sender-constrained profiles

Recent administrator MFA + scoped permission checks + atomic audit
    -> bounded support grants
    -> isolated handoff/session + strict resource validation
    -> enabled customer impersonation

Reliable source ownership + tenant-safe lifecycle services
    -> provisioning connectors
    -> SCIM/directory sync and migration adapters

Shared security-state consistency + restore reconciliation
    -> supported HA deployment
    -> explicitly designed disaster-region recovery
```

### 35.3 Scope control rules

Do not replace a missing core permission check with a plugin, a missing recovery policy with manual database edits, a missing UI with an insecure OAuth grant, or a missing revocation design with a marketing promise. Do not implement multiple protocol variants before one complete secure baseline works across independent applications.

An issue tracker should import requirement IDs and record implementation status, owner, dependencies, test evidence, documentation, and release. Suggested status values are `not_started`, `designing`, `implementing`, `testing`, `released`, `deprecated`, and `intentionally_unsupported`. Requirement priority is not implementation status.

### 35.4 Delivery checkpoint — 2026-10-13

This checkpoint records implementation evidence; the requirements and exit
gates above remain the acceptance contract, with the delivery exception below.
The checkout is an untagged
development version, not an independently reviewed or certified release.
Implementation extends into P2/M4; current local Go, SDK, dependency,
image and packaging checks pass. Official release publication remains open.
Selected P3 capabilities exist, but M5 is not complete. Priority coverage
does not establish that an earlier release gate has been closed.

**Owner-directed delivery exception — 2026-10-13.** The owner requested
completion of the project while skipping the independent security review.
SEC-018 and QA-005 have not been performed and remain recorded as external
open items in the traceability matrix; their review condition is excluded
from this delivery's completion gate. All other implementation, verification
and release work remains in scope. This exception establishes no independent
review or certification claim and does not change authentication or
authorization controls.

**Owner-directed source handoff — 2026-10-13.** The owner subsequently
authorized a source commit and push, and explicitly chose to keep the GitHub
repository private with commit/push only. A public release, source tag,
artifact signatures and hosted attestations are outside this handoff. Their
absence remains recorded; no official release or public-source claim is made.

The current complete Go 1.27.2 check below includes the benchmark-proxy,
replica stress, native directory process-death, transport interruption,
shared OTP, Group/audit filtering and metadata-fetch corrections, plus
all 26 benchmark smoke scenarios and the packaging/reproduction checks.
Capacity measurements and earlier correctness reports retain their own
recorded builds, compilers, hashes and topology limits.

The [current dependency/supply-chain checks](operations/security-checks.md#current-dependency-and-supply-chain-checks--2026-10-13)
now pass on development source digest `9e46df90789bcd6d`: Staticcheck
2026.2.2, a frozen official Go vulnerability database for source/all 12
binary targets, and npm audit. Workflow Actions and the Dockerfile frontend
are immutable. The obsolete Staticcheck pin and 20 findings were corrected;
the [final full check](operations/consistency-results/2026-10-13-full-final.json)
passes 45 test packages, 716 top-level tests and 562 subtests, with no failures
or skips. All 11 CI fuzz targets also pass. The
[local release preparation](operations/security-checks.md#local-image-and-release-preparation--2026-10-13)
adds production TLS/read-only image checks, source/image SBOMs, zero OS-package
vulnerability matches, all 12 stripped target builds and 582 verified offline
bundle files. The owner has now authorized committing and pushing the source.
The GitHub destination remains private by the owner's decision. Signatures,
trusted provenance and official release publication are deferred from this
source-only handoff; the publication workflow remains available for a future
versioned release.

The [current local SDK profiles](integrations/sdk-compatibility.md#local-sdk-checks--2026-10-13)
also pass without downloads: Node.js 25.9.0 has 116 tests, Dart 3.13.3 has
216, and PHP 8.5.8 has 157 with 3078 assertions. Type/analyzer/format/lint
checks pass, with frozen hashes and unchanged source/locks. Go SDK evidence
comes from the complete Go 1.27.2 check. Declared minimum runtime coverage,
external security assurance and registry publication
remain separate gates (SDK-009, SDK-010, QA-002, QA-004).

The Group-filter, audit-filter and metadata-fetch checkpoints below changed
the production build after the earlier Go 1.27.1 full-module result. Their
targeted counts/measurements remain separate; the new complete check now
includes their current implementation.

The controlled HTTPS metadata benchmark below changes the benchmark tool
and adds a measured workload-federation profile; it retains the preceding
server fetch-budget correction and its separately frozen evidence.

| Gate | Current evidence and remaining work |
| --- | --- |
| Core and tenant/backend correctness (M0–M2) — current full check, 2026-10-13 | The complete offline `go test -json -race -count=1 -p=2 -timeout=20m ./...` passes on Go 1.27.2: 45 test packages, 716 top-level tests and 562 subtests, zero failures/skips; 29 packages have no tests. E2E takes 784.853s, contract 36.401s, and total wall time 849.245s. All 26 benchmark smoke scenarios and connection-pool stress pass. [Frozen final result](operations/consistency-results/2026-10-13-full-final.json) retains package/test results, 679 Go/SQL/configuration input hashes and an empty source drift list. [Supplementary checks](operations/consistency-results/2026-10-13-supplementary.json) pass all 11 CI fuzz targets, vet, formatting of 593 Go files, secret/license checks and Kubernetes rendering. Production source digest `9e46df90789bcd6d`; the frozen verification did not use a Git commit. The protected traceability test is unchanged. Earlier full/capacity profiles retain their builds; current dependency/image/package evidence is separate from official release publication. Rollout caveats remain in [upgrades.md](operations/upgrades.md). |
| General platform assurance (M3) | Code, SDKs, runbooks and integration evidence exist. The owner excludes independent review from this delivery's completion gate under the exception above; it has not been performed and [review-scope.md](threat-models/review-scope.md) remains the commissioning brief. Remaining local assurance and release checks are still required. |
| Two-OS development binary reproduction — 2026-10-13 (M0, DEP-003, SEC-016) | [Published hash comparisons](operations/security-checks.md#two-os-binary-reproduction--2026-10-13) prove all 12 release binary targets byte-identical between Go 1.27.2 on macOS and a network-disabled Linux container, across two invocations with separate caches and the same 504-file frozen snapshot. `make repro-local` uses only cached modules/image source, bootstraps a private host SDK when required and cleans its own SDK/cache/binary/container resources. Download/flag isolation, untagged-digest lookup, deliberate mismatch and wrong SDK/version refusal checks pass three race repetitions (three top-level executions, 12 subtests, 6.527s). All 41 contract checks and 16 subtests pass (33.584s), plus vet, formatting and secret/license checks; [scoped verification](operations/release-results/2026-10-13-repro/verification.json) retains source hashes and protected-test checks. One physical host and an untagged development version; official release, off-host/independent-organization, image/archive reproduction, vulnerability audit, provenance and independent security review remain open. |
| Offline packaging and base pins — 2026-10-13 (DEP-003, DEP-017, SEC-016, QA-008) | [Executable packaging checks](operations/offline-install.md#local-verification--2026-10-13) preserve previous assets after build/export/hash/publication failures, reject unsafe version labels, refuse concurrent writers and clean up on interruption; three race repetitions pass (15 top-level executions, 36 subtests, 9.980s). Real cached-Go cross-builds produce six Linux amd64/arm64 static-profile ELF binaries; all 572 content checksums and the outer 50.7 MB archive checksum match, with no development secrets/AppleDouble members. All 40 contract checks pass (33.652s), plus vet, shell syntax and secret/license scans. [Base-image pins](operations/security-checks.md#base-image-pins--2026-10-13) now use cached OCI index digests with the exact release Go version. [Structured evidence](operations/release-results/2026-10-13-offline-bundle.json) retains source/binary hashes and limits; temporary binary archive removed. No download, commit/tag, image build or release publication occurred. Frontend/Action pins, current vulnerability audit, independent reproduction, official provenance and external security review remain open. |
| Controlled metadata capacity — 2026-10-13 (MCH-011, NFR-006, NFR-008) | [Published full-seed results](operations/benchmarks.md#controlled-metadata-fetch-results-nfr-006-nfr-008) pass a 60-second/concurrency-32 run: 157079 operations, 2617.9 operations/s, p99 27.648 ms. All eight workload grant/refusal profiles occur; independent HTTPS counts show one valid-key contact, two per error source across an unchanged cooldown, zero redirect-target/denied-live-IPv6 key contacts and a ten-second timeout plus minute retry spacing. All 26 benchmark smoke scenarios pass (53.280s); all 36 contract checks pass (28.111s), with bench/CLI unit-race and vet checks; [scoped verification](operations/bench-results/2026-10-13-laptop-metadata/verification.json) preserves commands/hashes. Current checkout source digest `a9d95f06c64af14e`, no Git commit; this addition changes the benchmark tool, not the preceding server fetch-budget behavior. Latency mostly covers cached refusals; unfinished duration-boundary timeout waiters are omitted. Sustained OIDC/Shared Signals, multi-process aggregate metadata bounds, longer soaks and independent assurance remain open. |
| Enterprise evidence (M4) | Published counterpart profiles include Keycloak 26.8.0 and ZITADEL v4.16.3. The provisioning/federation attack suites pass locally. [Capacity reference results](operations/benchmarks.md#reference-results) and [restore results](operations/backup-restore.md) are published with laptop/topology caveats. |
| Extended workload evidence (NFR-003, NFR-008) | Complete software-passkey sign-in, a budgeted SCIM user lifecycle and the nine-component extended mix have [published passing results](operations/benchmarks.md#extended-workload-results-nfr-003-nfr-008). Physical authenticator latency and delivery-worker capacity remain outside this measurement; connector budgets stay unchanged. |
| Email worker evidence (NFR-003, NFR-008) | [Published SMTP acceptance results](operations/benchmarks.md#smtp-worker-results-nfr-003-nfr-008) cover an independent email workload, all ten components of an email mix and notification-flood budgets confirmed by receiver counts. Unit/race, full benchmark smoke and connection-pool checks pass. This is one realm's cohosted closed-loop baseline with API polling, not remote/mailbox delivery or webhook/multi-worker capacity. |
| Webhook worker evidence (NFR-003, NFR-005, NFR-008) | [Published delivery/retry results](operations/benchmarks.md#webhook-worker-results-nfr-003-nfr-005-nfr-008) prove signed, correlated callbacks and delivered records, plus all twelve mixed components. Every window of a ten-minute delivery soak passes across actual retries, token renewal, key activation, retention tasks and database maintenance. Initial seed-backlog failures remain published; an untimed readiness cycle now crosses setup work without changing measured deadlines or worker budgets. This is a single-worker loopback baseline, not remote HTTPS, multiple tenants/workers or multi-hour capacity. |
| Benchmark result integrity (NFR-005, NFR-008) | [Run completeness](operations/benchmarks.md#run-completeness-nfr-005-nfr-008) is explicit. Interrupted runs and cleanup failures preserve usable evidence and fail instead of reporting success; encoding/write failures also fail. The local runner requires completed runs/windows and outcome/receiver criteria. Soaks exclude setup/warm-up from the measured budget and shorten their final window. Unit/race, actual CLI signal/exit and all 23 database-backed smoke scenarios pass. Warm-up notes distinguish fixture budget use from benign warm-up. Earlier reference artifacts retain their recorded build/schema and hashes; the completeness fix itself is not a new capacity measurement. |
| OTP abuse evidence (NFR-006, NFR-008) | [Published TOTP guessing results](operations/benchmarks.md#totp-guessing-results-nfr-006-nfr-008) pass at concurrency 32 on the full seed cardinalities: exactly ten wrong proofs are evaluated across eight transactions, then the unchanged account budget refuses every remaining measured guess. Independent stored failure/audit counts agree; regressions prove five-failure transaction retirement. [Shared email/SMS/HOTP budget evidence](operations/consistency-tests.md#shared-otp-guessing-budgets--2026-10-12) fixes a mixed-method bypass (28 evaluations instead of ten, pre-fix 6.973s). Five profiles across three independent pools and eight source IPs pass three race-detector repetitions with five supporting cases: 18 top-level executions, 33 subtests, 76.485s; 480 new guessing requests each obey the ten-proof limit, audit/failure counts and next-window authority. [Structured results](operations/consistency-results/2026-10-12-otp-budgets.json) identify frozen source digest `d5f3fe38b61f4a4e`; its full offline check passes (E2E 748.725s, contract 32.698s, 689 top-level tests and 462 subtests). A final fixture-only refinement also passes three repetitions (25.725s); both sets of frozen test hashes remain recorded. These bursts are correctness evidence, not sustained email/SMS/HOTP capacity; metadata-fetch abuse, multiple machines and longer sustained measurements remain open. |
| SCIM filter and read correctness (PROV-002, PROV-004, PROV-005, NFR-006) | [Published full-cardinality results](operations/benchmarks.md#scim-filter-results-nfr-004-nfr-006-nfr-008) preserve the initial timeout failure alongside the passing correction. At concurrency 32, 10000 additional managed users yield 677 exact, bounded 64-node searches, 702 parser-overflow refusals and 132026 unchanged-budget refusals, without transport errors. Aggregate 2223.4 operations/s and latency mostly describe `429`, not successful-query capacity. Scoped batch reads replace per-candidate round trips; a real-query tracer observes five queries at both tested sizes, with equivalent individual data/ETags and realm isolation. Read-error suppression and initially inactive creation were fixed with regressions. All Go package checks pass after the traceability refresh. [Group-filter results](operations/benchmarks.md#scim-group-filter-results-nfr-004-nfr-006-nfr-008) add a passing 60-second/concurrency-32 run on the full seed plus 500 owned Groups and 1000 owned member Users (one 1000-member Group): 3705.3 operations/s, 951 exact searches, 950 parser refusals and 220420 unchanged-budget refusals. New [query-work/boundary evidence](operations/consistency-tests.md#scim-group-query-work-and-scan-boundaries--2026-10-12) fixes 17/129 per-Group queries to three at 8/64 Groups, retaining member projection/ETags, foreign/missing mapping boundaries and read-error propagation. Users/Groups at 20000 resources retain exact totals/pages; 20001 broad/compound scans refuse atomically while indexed lookup remains exact at concurrency 32. Eight backend cases pass three repetitions (24 top-level executions, 30 subtests, 71.106s); all 24 benchmark smoke scenarios pass (48.164s), with bench/provisioning unit/race and vet checks. The measured production digest was `cb89a7606b47c21d`; the current Go 1.27.2 full check above includes these Group corrections. Audit filtering and controlled workload-metadata capacity now have separate evidence below; sustained scan-overflow/larger Group capacity, other metadata protocols and multi-host capacity remain open. |
| Audit filter correctness and capacity — 2026-10-12 (AUD-006, AUD-011, NFR-004, NFR-006, NFR-008) | [Scoped regressions](operations/consistency-tests.md#audit-prefixes-compound-pages-and-cursors--2026-10-12) fix wildcard interpretation of literal event prefixes and cursors accepted after filter/route changes. Exact conjunctions/pages retain foreign-scope boundaries and sequence stability; 18 top-level executions and 57 subtests pass in three race repetitions (24.627s). All 25 benchmark smoke scenarios pass (49.248s). [Published capacity](operations/benchmarks.md#compound-audit-filter-results-nfr-004-nfr-006-nfr-008) adds 10000 public application reports to the full seed: 76443 operations, 1274.0 operations/s, p99 34.82ms at concurrency 32 for 60 seconds; all seven exact-page/input/cursor profiles pass. Current development production digest `33f1e749e5cbf702`, no Git commit. Aggregate latency includes empty and refused searches. Earlier evidence retains its build; the current Go 1.27.2 full check above includes these audit corrections. Million-event retention/partitioning, other sustained metadata profiles and multi-host capacity remain open; the controlled workload-metadata measurement has its own limits. |
| Metadata/JWKS resource bounds — 2026-10-12 (FED-017, MCH-011, ADV-004, ADV-007, NFR-006) | [Published correctness counts](operations/consistency-tests.md#metadatajwks-fetch-bounds--2026-10-12) reproduce 32 cold/unknown-key fetches per concurrency-32 burst, and 96 invalid-response fetches across three bursts instead of two. OIDC, workload and Shared Signals now coalesce misses and enforce failed-fetch/signature-refresh cooldowns per process/cache identity. Nine TLS profiles, cancellation/invalidation/DNS/idle-client checks and protocol fallback checks pass three race repetitions (39 top-level checks, 51 subtests); six public-API cases pass three times (18 top-level executions, 36 subtests, 36.488s), including mandatory-SSO cooldown and recovery. Current production digest `202b6eeb35806acd`, no Git commit. Earlier benchmark evidence retains its recorded build; the current Go 1.27.2 full check above includes these fetch-bound corrections. Controlled workload-metadata capacity is published separately; sustained OIDC/Shared Signals capacity, multi-process aggregate bounds and independent assurance remain open. |
| Resource sender boundary (M4) | Go `SenderVerifier` enforces DPoP or certificate bindings for actual JWT/opaque resource requests; ordinary token-only methods in all four SDKs reject bound tokens. The server refuses multiple DPoP headers and mismatched method casing. The [declared profile and limits](integrations/resource-servers.md#sender-constrained-tokens) identify the replay-store and TLS proxy responsibilities. |
| Replica consistency (NFR-007) | [Nine replica stress cases](operations/consistency-tests.md) pass three race-detector repetitions across three in-process HTTP servers with independent pools, transaction limits, keyrings and caches (143.320s, with eleven supporting cases). Concurrency-32 bursts cover recovery/invitations, ownership, role changes, SCIM/admin User conflicts, refresh rotation and concurrent session/account-wide revocation; template/expiry-worker effects have exact durable counts. Those fixes remove refresh/logout lock-order stalls and require live JWT grant authority, including UserInfo/account APIs and exchanged descendants. These nine cases contain 7776 burst requests across three repetitions. [Native-process refresh results](operations/benchmarks.md#independent-server-process-results-nfr-003-nfr-007-nfr-008) add two passing 60-second profiles across three separate servers, with balanced routing and independent SQL lineage/reuse counts. [Shared-SSO races](operations/consistency-tests.md#shared-sso-revocation-races--2026-10-11) also pass five logout/reuse scopes over three repetitions (2880 additional burst requests), with exact lineage and session/reuse evidence. [SCIM Group races](operations/consistency-tests.md#scim-group-races--2026-10-11) pass three repetitions (2880 additional burst requests), covering conditional renames, membership conflicts in both causal orders and controlled deletion without losing organization memberships. [Mixed deletion/link-repair regressions](operations/consistency-tests.md#mixed-group-deletion-and-link-repair--2026-10-11) reproduce and fix the member-before-group lock order and stranded external IDs; 27 targeted executions pass (61.154s), including 576 additional mixed-deletion burst requests, legacy LDAP repair and actual outbound cleanup. Longer shared-SSO load, other native worker/server process faults, other scenarios across separate processes, multiple machines, network failures and sustained multi-node capacity remain open; the directory consistency profile below adds full/incremental and Group sync evidence. |
| Directory worker consistency — 2026-10-12 (NFR-007) | [Full/incremental replica evidence](operations/consistency-tests.md#directory-synchronization-across-replicas--2026-10-12) passes three race-detector repetitions with two supporting cases (nine executions, 20.691s). Four phases compete at concurrency 32 across three independent HTTP runtimes/pools and three leased workers: paged full sync, incremental dry-run, applied incremental and repeated full sync. The new case adds 768 public requests, 12 sole run/job/handler executions, durable cursor and exact account/link/Group/audit effects, unchanged dry-run snapshots and effective permission checks on every pool. Administrator roles/metadata survive. The original addition changed tests only; the latest full-suite result above includes it. The scheduling/expired-worker profile below adds separate evidence; real AD counterpart interoperability, production-entrypoint directory worker/server profiles and network faults remain open. |
| Directory scheduling and expired attempts — 2026-10-12 (NFR-007, DEP-011) | [Failure and correction](operations/consistency-tests.md#directory-schedules-and-expired-worker-leases--2026-10-12): a stalled worker overwrote a successfully recovered run/result as failed and emitted two completion audits (pre-fix 1.718s). Job progress/final writes now require the unexpired worker/attempt claim; directory mutation transactions lock that claim before domain rows. The returning worker cannot overwrite account/link/Group/delivery state, findings or cursor. Three race-detector repetitions pass across three replica cases and two jobs cases: 15 top-level executions (E2E 18.473s, jobs 6.024s), with 18 fencing outcome subtests, 864 concurrent scheduler calls and 1152 public burst requests in the command. Full/incremental schedule claims, rollback when blocked and repeated scans have exact durable counts. Production source digest `0a51116192cb1f18`; full offline verification passes (E2E 728.781s, contract 30.465s); the [recorded frozen-build result](operations/consistency-results/2026-10-12-directory-lease.json) preserves that evidence. The native worker-task kill profile below adds separate evidence; other process/profile faults, real directory counterpart interoperability, network/DB failover and sustained multi-tenant capacity remain open. |
| Native directory worker-task death — 2026-10-12 (NFR-007, DEP-011) | [OS-kill evidence](operations/consistency-tests.md#native-directory-worker-process-death--2026-10-12) and [structured results](operations/consistency-results/2026-10-12-directory-native-crash.json): a separately execd real jobs task commits/checkpoints the first LDAPS page and is killed/reaped. Three independent HTTP runtimes/pools refuse early takeover; after a controlled lease expiry, exactly one worker repeats the full or incremental scan at attempt two. All pools retain original account IDs, eight memberships/nine links, exact Group authority, cursor and one completion audit; committed user mutations do not repeat. Three race-detector repetitions pass with five supporting cases (18 top-level executions, 15 subtests, 59.209s), including six actual worker kills and 672 new public requests (4704 in the combined command). The original tests-only addition records production digest `0a51116192cb1f18`; the current full-module result above also includes this case, and earlier reports retain their frozen hashes. Worker task runs in a test binary; production entrypoint/drain, host/network/DB failure, real AD/OpenLDAP counterparts and sustained multi-tenant directory capacity remain open. |
| Directory transport consistency — 2026-10-12 (NFR-007, PROV-014) | [Failure and correction](operations/consistency-tests.md#directory-transport-interruption-and-complete-source-deletion--2026-10-12): a first page committed before actual LDAPS sockets closed; complete full/promoted incremental failover still retained an absent membership (two failing profiles, pre-fix 5.757s). Each endpoint now resets its deletion-presence set, so only the completed full source view determines deprovisioning, within the unchanged 20% threshold. Transport exhaustion does not deprovision or advance a cursor; a later complete retry does. Three race-detector repetitions pass with six supporting cases (21 top-level executions, 15 subtests, 57.890s), preserving exact accounts/links/Group authority/audits on all three pools. Production digest `f66bc581a3dc5efb`; [full offline verification](operations/consistency-results/2026-10-12-directory-transport.json) passes (E2E 734.223s, contract 30.697s, 688 top-level tests and 457 subtests, none failed/skipped). Trusted test endpoints model AD paging/USN; physical network partitions, DB/host failover, real counterpart interoperability and sustained multi-tenant fault load remain open. |
| Specialized scope (M5) | The current selected profiles are documented in [compatibility.md](protocols/compatibility.md). Unoffered optional gRPC management, Kerberos/SPNEGO, push approval, CIBA, UMA and credential/wallet profiles remain deliberately absent; no unsupported profile is enabled by this checkpoint. |

Next engineering work is to broaden measured capacity coverage (remote HTTPS
and multiple delivery workers/tenants, longer soaks, additional adversarial
and multi-node cases; physical passkeys and
richer SCIM profiles beyond the new baseline),
and close the supply-chain items in
[security-checks.md](operations/security-checks.md#open-items). Local offline
verification does not replace a current vulnerability audit, a second build
environment, release provenance or the independent security review.

## 36. Repository Structure, Governance, and Contribution Contract

### 36.1 Suggested repository layout

The following is an illustrative Go-oriented modular-monolith layout. Module boundaries matter more than exact directory names; another implementation language can preserve the same architecture.

The service now lives in `proudbase/proudauth`; each SDK and the website has an
independently buildable public repository. This source-ownership split preserves
the transactional modular monolith and OSS-004's complete-source requirement;
it does not split identity domains into distributed services. The CLI imports a
pinned Go SDK module and common synthetic vectors live in `tests/fixtures/sdk-contracts`.
See [repository migration](repository-migration.md) and
[SDK repository evidence](integrations/sdk-repositories.json).

```text
/
  cmd/
    identity-server/          # Public/protocol/admin listeners
    identity-worker/          # Durable background jobs
    identity-cli/             # Bootstrap and administrative automation
  internal/
    realm/                    # Issuer and realm boundaries
    organization/             # Memberships, groups, invitations, ownership
    identity/                 # Users, profiles, linking, lifecycle
    authentication/           # Transactions, credentials, factors, recovery
    session/                  # Sessions, grants, refresh families
    oauth/                    # OAuth/OIDC protocol adapters
    token/                    # Signing, verification profiles, key lifecycle
    authorization/            # Roles, policies, scoped decision service
    impersonation/            # Support grants and actor-aware restrictions
    machine/                  # Service principals and automation credentials
    federation/               # Upstream identity adapters
    provisioning/             # SCIM and directory connectors
    notification/             # Delivery, templates, localization
    audit/                    # Durable evidence and scoped querying
    events/                   # Outbox, webhook dispatch, replay
    jobs/                     # Leases, retries, retention, import/export
    storage/                  # Database implementations and unit-of-work
    configuration/            # Validation, reload policy, secret references
    observability/            # Logs, metrics, traces, redaction
  api/
    openapi/                  # Custom API contract and compatibility checks
    events/                   # Versioned event schemas
    schemas/                  # Config, policy, and import/export schemas
  migrations/
  examples/
    backend-for-frontend/
    protected-orders-api/
    protected-billing-api/
    machine-client/
    support-mode-integration/
  deploy/
    compose/
    kubernetes/
    offline-bundle/
  tests/
    fixtures/sdk-contracts/   # Shared synthetic vectors; SDKs own copied fixtures
    unit/
    integration/
    protocol/
    security/
    concurrency/
    migration/
    restore/
    load/
  docs/
    architecture-decisions/
    protocols/
    operations/
    integrations/
    threat-models/
  LICENSE
  NOTICE
  SECURITY.md
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  CHANGELOG.md
```

### 36.2 Maintainer requirements

- **GOV-001 [P0] — Public decision process.** Record architecture decisions and compatibility changes in versioned documents with rationale, alternatives, and migration implications.
- **GOV-002 [P0] — Contribution provenance.** Adopt a clear DCO or other deliberately selected contribution process and review rights to contributed code, fixtures, documentation, and bundled assets.
- **GOV-003 [P0] — Security reporting.** Publish a private reporting channel, response/triage process, coordinated disclosure policy, and supported-version policy without exposing unresolved vulnerabilities through ordinary public issue templates.
- **GOV-004 [P0] — Review boundaries.** Require appropriate reviewers for authentication, authorization, cryptography usage, migrations, impersonation, and release infrastructure; do not merge security-sensitive changes solely because generated tests pass.
- **GOV-005 [P1] — Release transparency.** Publish release notes, source tags, artifacts, SBOM/provenance, breaking changes, known limitations, and security advisories through an auditable release process.
- **GOV-006 [P1] — Sustainable maintenance.** Prefer fewer maintained, tested adapters over many unsupported checkboxes; name the maturity and maintainer status of each integration.
- **GOV-007 [P0] — No privileged paid branch.** Funding through donations, support, or optional hosting must not create an unavailable security feature, hidden enterprise-only API, or mandatory hosted control plane in the project specification.
- **GOV-008 [P1] — Documentation parity.** Every release updates protocol metadata, API references, example integrations, operator defaults, and limitations together; stale examples that bypass current security rules are release defects.

Third-party extensions may have their own licenses and trust properties. They are not automatically included in the project's “all first-party features are free and open source” guarantee. Clearly identify their origin and do not install them silently.

## 37. Architecture Decision Register and Completion Checklist

### 37.1 Proposed decisions to adopt or replace explicitly

| Decision                | Proposed baseline                                                                                        | Consequence / unresolved work                                                                                 |
| ----------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Product form            | Standalone modular-monolith IdP with worker processes                                                    | Do not split security authority across loosely synchronized microservices without a measured need.            |
| Implementation language | Go reference implementation                                                                              | Select supported runtime/toolchain and vetted protocol/crypto libraries in an implementation ADR.             |
| First-party license     | Apache-2.0 for independently written code                                                                | Maintainers must formally adopt it and review dependencies; do not copy incompatible licensed code.           |
| Durable store           | PostgreSQL                                                                                               | Pin supported versions and define migrations, HA, backup, and transaction isolation.                          |
| Cache/broker            | Optional optimization; durable database outbox baseline                                                  | Cache outages cannot become positive authorization.                                                           |
| Identity boundaries     | Realm = issuer/user namespace; organization = business tenant within realm                               | Separate deployments are available where stronger isolation is required.                                      |
| Stable account key      | Local immutable user ID; external identity keyed by trusted issuer/subject/source                        | Email changes cannot rename or merge identity authority.                                                      |
| Interactive protocol    | Authorization code with PKCE; explicitly registered clients/redirects                                    | Backend-only does not enable an insecure password-grant shortcut.                                             |
| Ordinary access token   | Short-lived asymmetric JWT with explicit API audience and token class                                    | Offline revocation is bounded by validity/trust policy, not immediate.                                        |
| High-risk/support token | Opaque token and authoritative per-operation validation                                                  | Availability must support strict-online checks or operations fail closed.                                     |
| Refresh model           | Opaque, rotated, client-bound family with atomic state                                                   | Baseline SDK serializes refresh; strict replay handling can require reauthentication after ambiguous retries. |
| Organization context    | One business organization per business access token                                                      | Switching organizations produces a freshly authorized grant.                                                  |
| Authorization           | Scoped RBAC/delegation core; typed bounded policies; optional relationship adapter                       | Applications enforce business object ownership and required obligations.                                      |
| Impersonation           | Explicit support grant; recent MFA; reason; actor preserved; short expiry; no refresh; read-only default | Enable only for services that implement the support contract.                                                 |
| Keys                    | Durable asymmetric signing keys and separate protected encryption/purpose keys                           | Select key-provider adapters, rotation procedures, and recovery strategy.                                     |
| Email/SMS               | Replaceable operator-configured delivery adapters                                                        | The software is free; third-party transport can cost money or be unavailable offline.                         |
| Browser integration     | External consuming UI, preferably BFF where appropriate                                                  | Provide API/interaction contracts and backend examples, not a mandatory hosted login UI product.              |
| Enterprise protocols    | Versioned, separately tested SAML/SCIM and other profiles                                                | Advertise capabilities only after their full security requirements are implemented.                           |
| HA topology             | One authoritative write region before advanced regional writes                                           | Specify consistency and recovery before promising global immediate revocation.                                |
| Compliance posture      | Evidence and controls, not automatic legal/regulatory certification                                      | Operators assess their deployment and obligations separately.                                                 |

A substituted decision must preserve the security invariant or explicitly update this specification, threat model, tests, and migration plan. For example, choosing a different database is not permission to remove atomic proof consumption.

### 37.2 Feature definition of done

For each shipped requirement, maintain a linked record with:

- [ ] Clear behavior, explicit non-goals, priority, and maturity status.
- [ ] Public/admin/protocol API schema, authentication class, permissions, and tenant boundaries.
- [ ] Persistent model, invariants, migration, retention, and recovery behavior.
- [ ] Actor/subject-aware audit, appropriate user/security notifications, and redaction tests.
- [ ] Positive, negative, concurrent, failure, and interoperability tests as applicable.
- [ ] Safe defaults, resource limits, configuration schema, and operational metrics.
- [ ] Example backend integration, SDK/CLI coverage where relevant, and operator runbook.
- [ ] Dependency/license review and no paid activation dependency.
- [ ] Review of threat-model changes, rollback limits, and security-sensitive extension points.

### 37.3 Final platform acceptance

A secure product release must demonstrate one real end-to-end path for every primary user need: create an account; verify and sign in; enroll/use the required MFA; create an organization; invite a member; assign bounded permissions; administer users safely; access two differently scoped backend services; rotate and revoke credentials/sessions; and perform tightly controlled customer support impersonation with complete actor-aware evidence.

It must also demonstrate the denied paths: a valid token for the wrong service, a token for the wrong organization, an unauthorized invitation, an escalated role, a reused proof, a suspended actor, a prohibited impersonation action, and an unavailable strict-online authority. Successful login demonstrations alone are not acceptance of an identity platform.

**Recommended first implementation slice:** build one realm, two organizations, two resource audiences, three human users with different memberships, one organization administrator, one restricted support operator, and one machine principal. Implement the complete token/permission boundary around that small dataset before expanding adapter count or protocol breadth. The support operator must not be the deployment superuser in this fixture.

## 38. Primary Sources and Research Notes

### 38.1 How to interpret the references

Sources were reviewed for this specification on **2026-10-10**. Product `latest` documentation and main-branch license files are mutable; a production implementation must pin exact product releases, source revisions, standards versions, and dependency notices. The source index establishes design foundations and limited product/license observations. It does **not** mean that a source mandates every original requirement, lifetime, architecture choice, or proposed feature in this document.

The specification uses original wording and proposed engineering requirements rather than copying product documentation. A source citation next to a topic identifies the relevant primary reference; it is not a statement of product equivalence, endorsement, certification, or legal clearance. Uncited numerical settings are proposed project defaults. Specialized future profiles need their own version-pinned review before implementation.

Citation labels link to entries below. Source URLs are provided in code formatting for convenient copying. No paid vendor documentation or proprietary implementation is required to read this specification.

### 38.2 Reference products and licensing

| Reference                                         | Primary source                                                                                                  | Source URL                                                                                                  |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| <a id="ref-kc-admin"></a>KC-ADMIN                 | Keycloak Server Administration Guide; feature-family reference, not an assertion of universal feature maturity. | `https://www.keycloak.org/docs/latest/server_admin/index.html`                                              |
| <a id="ref-kc-authz"></a>KC-AUTHZ                 | Keycloak Authorization Services Guide.                                                                          | `https://www.keycloak.org/docs/latest/authorization_services/index.html`                                    |
| <a id="ref-kc-features"></a>KC-FEATURES           | Keycloak supported/preview feature configuration and maturity information.                                      | `https://www.keycloak.org/server/features`                                                                  |
| <a id="ref-kc-license"></a>KC-LICENSE             | Keycloak repository license, main branch.                                                                       | `https://github.com/keycloak/keycloak/blob/main/LICENSE.txt`                                                |
| <a id="ref-zt-docs"></a>ZT-DOCS                   | ZITADEL official documentation entry point and capability organization.                                         | `https://zitadel.com/docs`                                                                                  |
| <a id="ref-zt-org"></a>ZT-ORG                     | ZITADEL official multi-tenancy/organizations explanation.                                                       | `https://zitadel.com/blog/multi-tenancy-with-organizations`                                                 |
| <a id="ref-zt-exchange"></a>ZT-EXCHANGE           | ZITADEL token-exchange integration guide.                                                                       | `https://zitadel.com/docs/guides/integrate/token-exchange`                                                  |
| <a id="ref-zt-license"></a>ZT-LICENSE             | ZITADEL repository license, main branch.                                                                        | `https://github.com/zitadel/zitadel/blob/main/LICENSE`                                                      |
| <a id="ref-st-docs"></a>ST-DOCS                   | SuperTokens official authentication/session/integration documentation.                                          | `https://supertokens.com/docs`                                                                              |
| <a id="ref-st-impersonation"></a>ST-IMPERSONATION | SuperTokens user-impersonation integration guide.                                                               | `https://supertokens.com/docs/post-authentication/session-management/advanced-workflows/user-impersonation` |
| <a id="ref-st-session"></a>ST-SESSION             | SuperTokens session-management security guide.                                                                  | `https://supertokens.com/docs/post-authentication/session-management/security`                              |
| <a id="ref-st-license"></a>ST-LICENSE             | SuperTokens Core license and enterprise/third-party exceptions.                                                 | `https://github.com/supertokens/supertokens-core/blob/master/LICENSE.md`                                    |
| <a id="ref-st-pricing"></a>ST-PRICING             | SuperTokens official hosted/self-hosted pricing and paid-feature distinction.                                   | `https://supertokens.com/pricing`                                                                           |
| <a id="ref-apache"></a>APACHE                     | Apache License, Version 2.0.                                                                                    | `https://www.apache.org/licenses/LICENSE-2.0`                                                               |
| <a id="ref-osd"></a>OSD                           | Open Source Initiative, Open Source Definition.                                                                 | `https://opensource.org/osd`                                                                                |

### 38.3 Core authentication, OAuth, and token security

| Reference                                       | Primary source                                                                                                                                | Source URL                                                                         |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| <a id="ref-oauth2"></a>OAUTH2                   | IETF RFC 6749, OAuth 2.0 Authorization Framework; read together with later security guidance, not as permission to enable deprecated flows.   | `https://www.rfc-editor.org/rfc/rfc6749.html`                                      |
| <a id="ref-oauth-bcp"></a>OAUTH-BCP             | IETF RFC 9700, Best Current Practice for OAuth 2.0 Security.                                                                                  | `https://www.rfc-editor.org/rfc/rfc9700.html`                                      |
| <a id="ref-oauth21"></a>OAUTH21                 | IETF OAuth 2.1 draft tracker; maturity/status must be checked, not presumed from the version number.                                          | `https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/`                          |
| <a id="ref-oidc-core"></a>OIDC-CORE             | OpenID Connect Core 1.0, including incorporated errata.                                                                                       | `https://openid.net/specs/openid-connect-core-1_0.html`                            |
| <a id="ref-oidc-discovery"></a>OIDC-DISCOVERY   | OpenID Connect Discovery 1.0.                                                                                                                 | `https://openid.net/specs/openid-connect-discovery-1_0.html`                       |
| <a id="ref-as-metadata"></a>AS-METADATA         | IETF RFC 8414, OAuth 2.0 Authorization Server Metadata.                                                                                       | `https://www.rfc-editor.org/rfc/rfc8414.html`                                      |
| <a id="ref-pkce"></a>PKCE                       | IETF RFC 7636, Proof Key for Code Exchange.                                                                                                   | `https://www.rfc-editor.org/rfc/rfc7636.html`                                      |
| <a id="ref-native"></a>NATIVE                   | IETF RFC 8252, OAuth 2.0 for Native Apps.                                                                                                     | `https://www.rfc-editor.org/rfc/rfc8252.html`                                      |
| <a id="ref-jwt-bcp"></a>JWT-BCP                 | IETF RFC 8725, JSON Web Token Best Current Practices.                                                                                         | `https://www.rfc-editor.org/rfc/rfc8725.html`                                      |
| <a id="ref-jwt-at"></a>JWT-AT                   | IETF RFC 9068, JWT Profile for OAuth 2.0 Access Tokens.                                                                                       | `https://www.rfc-editor.org/rfc/rfc9068.html`                                      |
| <a id="ref-introspection"></a>INTROSPECTION     | IETF RFC 7662, OAuth 2.0 Token Introspection.                                                                                                 | `https://www.rfc-editor.org/rfc/rfc7662.html`                                      |
| <a id="ref-revocation"></a>REVOCATION           | IETF RFC 7009, OAuth 2.0 Token Revocation.                                                                                                    | `https://www.rfc-editor.org/rfc/rfc7009.html`                                      |
| <a id="ref-exchange"></a>EXCHANGE               | IETF RFC 8693, OAuth 2.0 Token Exchange, including actor/delegation semantics.                                                                | `https://www.rfc-editor.org/rfc/rfc8693.html`                                      |
| <a id="ref-resource"></a>RESOURCE               | IETF RFC 8707, Resource Indicators for OAuth 2.0.                                                                                             | `https://datatracker.ietf.org/doc/html/rfc8707`                                    |
| <a id="ref-device"></a>DEVICE                   | IETF RFC 8628, OAuth 2.0 Device Authorization Grant.                                                                                          | `https://www.rfc-editor.org/rfc/rfc8628.html`                                      |
| <a id="ref-stepup"></a>STEPUP                   | IETF RFC 9470, OAuth 2.0 Step Up Authentication Challenge Protocol.                                                                           | `https://www.rfc-editor.org/rfc/rfc9470.html`                                      |
| <a id="ref-oidc-rplogout"></a>OIDC-RPLOGOUT     | OpenID Connect RP-Initiated Logout 1.0.                                                                                                       | `https://openid.net/specs/openid-connect-rpinitiated-1_0.html`                     |
| <a id="ref-oidc-backlogout"></a>OIDC-BACKLOGOUT | OpenID Connect Back-Channel Logout 1.0.                                                                                                       | `https://openid.net/specs/openid-connect-backchannel-1_0.html`                     |
| <a id="ref-nist"></a>NIST                       | NIST SP 800-63B-4, Authentication and Authenticator Management; assurance and authenticator design reference, not a blanket compliance claim. | `https://pages.nist.gov/800-63-4/sp800-63b.html`                                   |
| <a id="ref-webauthn"></a>WEBAUTHN               | W3C Web Authentication Level 3 specification; select supported features and check maturity/version before implementation.                     | `https://www.w3.org/TR/webauthn-3/`                                                |
| <a id="ref-owasp-password"></a>OWASP-PASSWORD   | OWASP Password Storage Cheat Sheet.                                                                                                           | `https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html` |
| <a id="ref-owasp-authz"></a>OWASP-AUTHZ         | OWASP Authorization Cheat Sheet.                                                                                                              | `https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html`    |

### 38.4 Enterprise protocols, advanced profiles, and API contracts

| Reference                                   | Primary source                                                                                                                                      | Source URL                                                                                  |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| <a id="ref-saml"></a>SAML                   | OASIS Assertions and Protocols for SAML V2.0, core standard; implementation must also pin the applicable bindings/profiles/metadata specifications. | `https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf`                       |
| <a id="ref-scim-schema"></a>SCIM-SCHEMA     | IETF RFC 7643, SCIM Core Schema.                                                                                                                    | `https://www.rfc-editor.org/rfc/rfc7643.html`                                               |
| <a id="ref-scim-protocol"></a>SCIM-PROTOCOL | IETF RFC 7644, SCIM Protocol.                                                                                                                       | `https://www.rfc-editor.org/rfc/rfc7644.html`                                               |
| <a id="ref-par"></a>PAR                     | IETF RFC 9126, OAuth 2.0 Pushed Authorization Requests.                                                                                             | `https://www.rfc-editor.org/rfc/rfc9126.html`                                               |
| <a id="ref-jar"></a>JAR                     | IETF RFC 9101, JWT-Secured Authorization Request.                                                                                                   | `https://www.rfc-editor.org/rfc/rfc9101.html`                                               |
| <a id="ref-jarm"></a>JARM                   | OpenID Foundation, JWT Secured Authorization Response Mode for OAuth 2.0, final specification.                                                      | `https://openid.net/specs/oauth-v2-jarm-final.html`                                         |
| <a id="ref-rar"></a>RAR                     | IETF RFC 9396, OAuth 2.0 Rich Authorization Requests.                                                                                               | `https://www.rfc-editor.org/rfc/rfc9396.html`                                               |
| <a id="ref-dpop"></a>DPOP                   | IETF RFC 9449, Demonstrating Proof of Possession.                                                                                                   | `https://www.rfc-editor.org/rfc/rfc9449.html`                                               |
| <a id="ref-mtls"></a>MTLS                   | IETF RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.                                                      | `https://datatracker.ietf.org/doc/html/rfc8705`                                             |
| <a id="ref-dcr"></a>DCR                     | IETF RFC 7591, OAuth 2.0 Dynamic Client Registration.                                                                                               | `https://www.rfc-editor.org/rfc/rfc7591.html`                                               |
| <a id="ref-dcrm"></a>DCRM                   | IETF RFC 7592, OAuth 2.0 Dynamic Client Registration Management.                                                                                    | `https://www.rfc-editor.org/rfc/rfc7592.html`                                               |
| <a id="ref-jwt-assertion"></a>JWT-ASSERTION | IETF RFC 7523, JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants.                                                            | `https://www.rfc-editor.org/rfc/rfc7523.html`                                               |
| <a id="ref-fapi"></a>FAPI                   | OpenID Foundation, FAPI 2.0 Security Profile, final specification.                                                                                  | `https://openid.net/specs/fapi-security-profile-2_0-final.html`                             |
| <a id="ref-ciba"></a>CIBA                   | OpenID Connect Client-Initiated Backchannel Authentication Core 1.0.                                                                                | `https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html` |
| <a id="ref-ssf"></a>SSF                     | OpenID Shared Signals Framework 1.0.                                                                                                                | `https://openid.net/specs/openid-sharedsignals-framework-1_0.html`                          |
| <a id="ref-vci"></a>VCI                     | OpenID for Verifiable Credential Issuance 1.0, final specification.                                                                                 | `https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html`           |
| <a id="ref-problem"></a>PROBLEM             | IETF RFC 9457, Problem Details for HTTP APIs; used for proposed custom APIs, not to overwrite protocol-specific errors.                             | `https://www.rfc-editor.org/rfc/rfc9457.html`                                               |

<!-- REFERENCE DEFINITIONS -->

[KC-ADMIN]: #ref-kc-admin
[KC-AUTHZ]: #ref-kc-authz
[KC-FEATURES]: #ref-kc-features
[KC-LICENSE]: #ref-kc-license
[ZT-DOCS]: #ref-zt-docs
[ZT-ORG]: #ref-zt-org
[ZT-EXCHANGE]: #ref-zt-exchange
[ZT-LICENSE]: #ref-zt-license
[ST-DOCS]: #ref-st-docs
[ST-IMPERSONATION]: #ref-st-impersonation
[ST-SESSION]: #ref-st-session
[ST-LICENSE]: #ref-st-license
[ST-PRICING]: #ref-st-pricing
[APACHE]: #ref-apache
[OSD]: #ref-osd
[OAUTH2]: #ref-oauth2
[OAUTH-BCP]: #ref-oauth-bcp
[OAUTH21]: #ref-oauth21
[OIDC-CORE]: #ref-oidc-core
[OIDC-DISCOVERY]: #ref-oidc-discovery
[AS-METADATA]: #ref-as-metadata
[PKCE]: #ref-pkce
[NATIVE]: #ref-native
[JWT-BCP]: #ref-jwt-bcp
[JWT-AT]: #ref-jwt-at
[INTROSPECTION]: #ref-introspection
[REVOCATION]: #ref-revocation
[EXCHANGE]: #ref-exchange
[RESOURCE]: #ref-resource
[DEVICE]: #ref-device
[STEPUP]: #ref-stepup
[OIDC-RPLOGOUT]: #ref-oidc-rplogout
[OIDC-BACKLOGOUT]: #ref-oidc-backlogout
[NIST]: #ref-nist
[WEBAUTHN]: #ref-webauthn
[OWASP-PASSWORD]: #ref-owasp-password
[OWASP-AUTHZ]: #ref-owasp-authz
[SAML]: #ref-saml
[SCIM-SCHEMA]: #ref-scim-schema
[SCIM-PROTOCOL]: #ref-scim-protocol
[PAR]: #ref-par
[JAR]: #ref-jar
[JARM]: #ref-jarm
[RAR]: #ref-rar
[DPOP]: #ref-dpop
[MTLS]: #ref-mtls
[DCR]: #ref-dcr
[DCRM]: #ref-dcrm
[JWT-ASSERTION]: #ref-jwt-assertion
[FAPI]: #ref-fapi
[CIBA]: #ref-ciba
[SSF]: #ref-ssf
[VCI]: #ref-vci
[PROBLEM]: #ref-problem

---

**End of specification.** All capabilities described here are intended for the same freely available open-source project. Delivery phases express engineering sequence, not commercial editions.
