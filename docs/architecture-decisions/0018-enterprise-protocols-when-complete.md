# 0018. Federation and enterprise protocols: ship each only when complete

**Status:** Accepted (updated 2026-10-11: SAML and directory integration
are now implemented; see [the update](#update-2026-10-11-saml-and-directory-integration))

## Context

Upstream federation, SAML, SCIM and LDAP each have large attack surfaces (account
takeover through linking, mix-up and issuer confusion, signature wrapping, XML
parsing, SSRF through metadata, connector privilege). docs/plan.md requires that a
capability be advertised only after its security requirements and negative tests
are complete (APP-020, §18, §29).

## Decision

- **Upstream federation (FED-*) is implemented** in `internal/federation` and
  `internal/authentication/federation.go` through adapters: `oidc` (OpenID
  Connect, discovery or explicit endpoints, ID-token validation with asymmetric
  algorithms), `github` (GitHub-style OAuth 2.0 with immutable numeric account
  IDs and the verified-email API) and, since Update 2026-10 (FED-002,
  migration `0040`), `google` (fixed issuer, Workspace domains through the `hd`
  claim) and `microsoft` (Entra ID per-tenant issuer selected by `tid`,
  mandatory tenant list, email never treated as verified). Each adapter states
  whether the provider's email assertions may support trusted linking, and
  operators who build their own binary can register more
  (`federation.RegisterAdapter`); a generic OIDC connection is not used to
  model a social provider whose identifiers or email semantics differ.
  RP-initiated logout reports the upstream session separately and can send
  the browser to the provider's end-session endpoint (FED-013).
  Controls: single-use hashed `state`, PKCE, nonce, issuer and audience checks, egress policy on every upstream call, upstream tokens never
  stored, linking policies `verify_existing` (default), `trusted_verified_email`
  and `create_only`, local proof of control before linking an existing account,
  tenant and email-domain restrictions, upstream MFA trusted only when the
  connection says so, and SSO-mandatory organizations. Connections are realm data
  managed at `/identity-providers`; `federation.enabled: false` turns the module
  off.
- **SCIM 2.0 inbound provisioning (PROV-001..PROV-009, PROV-018) is
  implemented** in `internal/provisioning` and `internal/httpapi/scim.go`
  (Update 2026-10, migration `0042`): per-organization connectors with their
  own bearer token (`pa_scim_`, stored as a digest), allowed resource types and
  a role ceiling that must lie within the creating administrator's own
  delegation ceiling; Users and Groups with filters, `PATCH` and ETags;
  connector-scoped external IDs; adoption of existing accounts only through a
  domain the organization verified; deprovisioning that affects only the
  connector's organization; roles only through approved group mappings.
  `ServiceProviderConfig` advertises no bulk, sort or password change
  ([scim-provisioning.md](../integrations/scim-provisioning.md)).
- **Not implemented and not advertised:** SAML IdP and broker (SAML-*),
  LDAP/AD federation, directory sync and outbound provisioning
  (PROV-010..PROV-017; SAML and these PROV items were implemented later,
  see the update below), SCIM bulk operations, JAR, CIBA, UMA. (Dynamic
  client registration, JARM and mTLS-bound tokens were in this list at
  acceptance; they were implemented later, see
  [the protocol update](#update-2026-10-11-oauth-and-machine-identity-protocols).)
- Discovery is generated from implemented features only
  (`internal/oauth/discovery.go`). At acceptance `registration_endpoint`,
  `frontchannel_logout_supported` and `tls_client_certificate_bound_access_tokens`
  were absent or `false`; each is now published only when its feature is
  available (registration enabled for the realm, always, and client
  certificates able to reach the server, respectively).
- The connector table also accepts the kinds `ldap` (refused by the API) and
  `scim_outbound` (stored, never authenticates), and has a `cursor` column;
  none of them has behavior. Organization deletion counts and disables an
  organization's connectors. (Superseded by the update below: both kinds now
  have behavior and are managed at `/directory-connectors`.)
- `server.RegisterModules` is the extension point for adding these as modules that
  register their own routes and discovery flags once complete.

## Alternatives considered

- **Shipping partial adapters marked "beta"**: rejected; a partial SAML
  implementation is a vulnerability, not a feature.
- **Email-match linking by default**: rejected (FED-004, TEST-026); it is an opt-in
  linking policy limited to upstream-verified addresses.

## Consequences

- Enterprise SSO is available only for OIDC-capable upstreams; SAML-only
  enterprise identity providers cannot be connected. (At acceptance; since
  the update below they can, through SAML connections.)
- Federation is tested only against test doubles (`TestFederation`,
  `TestFederationAdapters`), not against real providers; the `google` and
  `microsoft` adapters are tested for their configuration rules only
  ([interoperability.md](../integrations/interoperability.md)).
- In production mode `federation.allow_private_network` is rejected; upstream
  providers on private networks are reachable only through specific CIDRs in
  `federation.egress_allowlist` (the delivery egress allowlist does not apply to
  federation).
- The SSO-mandatory path (no local-password fallback) is covered by
  `TestFederation` (TEST-027).
- SCIM is tested only with Okta- and Azure AD-style requests from the test
  suite (`TestSCIMProvisioning`), not against real directories; no SCIM
  conformance suite has been run.

## Update (2026-10-11): SAML and directory integration

The decision stands: a capability ships only with its security requirements
and negative tests, and nothing unsupported is advertised. The reasoning
above, written when SAML and directory integration did not exist, is kept
as the record of why they were deferred. These were implemented after
acceptance:

- **SAML 2.0** (SAML-001..SAML-010, APP-018, FED-014, TEST-051; migration
  `0060`; `internal/saml`, `internal/saml/idp`,
  `internal/federation/saml.go` and `saml_response.go`), off unless
  `saml.enabled` is set. Two separate profiles with their own metadata and
  counterparties. *Identity provider:* SAML applications backed by a client
  record that is not an OAuth client, so login methods, MFA, step-up,
  consent and organization policy apply unchanged; SP-initiated SSO over
  HTTP-Redirect and HTTP-POST with responses over HTTP-POST only to exactly
  registered ACS URLs; persistent (per-application), `emailAddress`
  (verified only), `unspecified` and transient NameIDs; attribute mappings
  with protected names; optional encrypted assertions (AES-GCM with
  RSA-OAEP only); IdP-initiated SSO off by default and per application;
  SP-initiated single logout from signed requests only, reporting
  `PartialLogout`. *Broker:* SAML connections are federation connections of
  kind `saml` that share linking, JIT, organization and SSO-mandatory rules;
  signed HTTP-Redirect `AuthnRequest`s; responses correlated to a single-use
  request, verified against pinned certificates and validated for issuer,
  audience, destination, recipient, time and replay; unsolicited responses
  always refused. *Shared:* a per-realm RSA key set separate from the JWT
  keys, with pre-published rollover; a parser that refuses DTDs, comments,
  duplicate IDs and oversized or deep input before a tree is built;
  signatures through `goxmldsig`, SHA-1 refused with no compatibility
  exception (SAML-009 allows exceptions with operator approval; none is
  offered). See [saml.md](../integrations/saml.md) and the
  [SAML threat model](../threat-models/saml.md).
- **Directory integration** (PROV-010..PROV-014, PROV-017, PROV-018,
  FED-015, USR-022; migration `0065`; `internal/directory`), on unless
  `directory.enabled` is `false`: LDAP and Active Directory connectors per
  realm (workforce, no organization access) or per organization, with
  ordered endpoints, always-verified TLS, failover only on transport errors
  and sign-in by a bind as the user that fails closed; first sign-in
  provisioning for realm connectors only; full and incremental
  synchronization with change cursors, dry runs, conflict reports that never
  merge accounts, and a deletion threshold; read-only, import-only and
  write-back modes enforced on every local edit path; outbound SCIM 2.0
  provisioning with retries, dead-lettering, idempotency through
  `externalId` and reconciliation. `/provisioning-connectors` now manages
  only `scim_inbound` connectors; `ldap` and `scim_outbound` connectors are
  managed at `/directory-connectors`, with the new read permission
  `realm.provisioning.read`. See [directory.md](../integrations/directory.md),
  [outbound-provisioning.md](../integrations/outbound-provisioning.md) and
  the [directory threat model](../threat-models/directory.md).

Still **not implemented and not advertised** in these areas:

- SAML: Artifact binding, SOAP, attribute queries, ECP, proxying and
  `Scoping`; metadata signing and fetching metadata from URLs;
  IdP-initiated logout and logout propagation to other service providers;
  encrypted assertions and upstream single logout at the broker.
- Directories: **Kerberos/SPNEGO (PROV-015)**, because keytab custody and
  rollover across nodes, the trust boundary of accepting a domain's tickets
  and PAC claims, protocol hardening (shared replay cache, channel binding,
  encryption-type limits, `Negotiate` through the external login UI) and a
  KDC test harness for negative tests do not exist; a partial adapter would
  be a vulnerability. **Password write-back** (PROV-013), which needs a
  service account with reset rights over every user and a reviewed
  connector and transport policy; identifier write-back; SASL binds; nested
  group expansion; a lookup-only user-storage mode; SCIM bulk operations in
  either direction.

This update does not change the status of the other items in the
**Not implemented** list of the decision.

Consequences of the update:

- SAML-only enterprise identity providers can be connected, and a realm can
  sign users in to SAML service providers, once `saml.enabled` is set.
- **There has been no interoperability testing against third-party
  products.** SAML is tested only against the repository's own test SP and
  IdP (written on `etree` and `goxmldsig`, independently of
  `internal/saml`); LDAP only against the in-process `ldaptest` server;
  outbound SCIM only against an in-process SCIM double. SAML-010 and QA-004
  remain open ([interoperability.md](../integrations/interoperability.md)).
  (Later, 2026-10: both SAML roles have since been tested against Keycloak
  26.8.0, `scripts/interop-keycloak.sh`, which found and fixed the refusal
  of repeated attribute names; other products remain untested.)
- A directory outage blocks password sign-in for the accounts that
  directory sources (`503 upstream_unavailable`); there is deliberately no
  local fallback (TEST-027).
- One SAML key set per realm serves both roles, so its compromise affects
  both; rollover needs counterparties to refresh metadata.

Migration implications of the update: `0060_saml.sql` and
`0065_directory_integration.sql` are expand-only. `0060` adds
`clients.protocol` and seven `saml_*` tables; `0065` makes
`provisioning_connectors.organization_id` nullable, adds columns to
`provisioning_connectors` and `connector_external_ids`, and adds
`directory_sync_runs`, `directory_sync_findings` and `outbound_deliveries`.
Older binaries in a mixed-version window have no SAML or directory routes
and authenticate only `scim_inbound` connectors, so they ignore the new
rows; enable SAML and create directory connectors after the rollout.

## Update (2026-10-11): OAuth and machine-identity protocols

The same rule applied to the remaining OAuth items: each shipped with its
negative tests and is advertised only when usable. Implemented after
acceptance:

- **Dynamic client registration** (APP-016, APP-017, ADV-003; RFC 7591/7592;
  migration `0052`; `TestDynamicClientRegistration`): off by default per
  realm; registration needs an administrator-issued initial access token
  bound to non-privileged scopes, or is held for approval when open; no
  software statements, no `jwks_uri`, no metadata fetching; registered
  clients are third-party clients that ask for consent
  ([dynamic-client-registration.md](../integrations/dynamic-client-registration.md)).
- **JARM, encrypted ID tokens, signed and encrypted UserInfo** (ADV-002,
  TOK-020, OIDC-013; migration `0050`): per-client options, encryption only
  with `RSA-OAEP-256` or ECDH-ES and AES-GCM
  ([response-security.md](../protocols/response-security.md)).
- **Front-channel logout** (SES-018): a script-free page that frames only the
  registered URIs; back-channel logout stays the reliable mechanism.
- **Mutual TLS** (TOK-019, MCH-014, PROV-016; migration `0056`):
  `tls_client_auth`, `self_signed_tls_client_auth`, certificate-bound tokens
  and X.509 sign-in, through a separate listener or a trusted proxy, with
  realm trust anchors and uploaded CRLs ([mutual-tls.md](../protocols/mutual-tls.md)).
- **Workload identity federation** (MCH-011..MCH-013, ADV-004; RFC 7523;
  migration `0051`): a machine client exchanges a JWT from a trusted external
  workload issuer (GitHub Actions, Kubernetes, SPIFFE or generic profiles)
  for its service principal's token. It is a new federation surface: key sets
  are fetched under the same egress rules as upstream identity providers,
  and assertions never become user identities
  ([workload-federation.md](../integrations/workload-federation.md)).
- **FAPI 2.0 security profile** (ADV-001): a client profile `fapi2` with the
  FAPI 2.0 rules. Not certified by the OpenID Foundation; no conformance
  suite has been run.

Still not implemented: JAR (signed request objects), CIBA, UMA, OCSP,
fetching CRLs, `jwks_uri` for client keys, user assertions in `jwt-bearer`.
Consequence: these features are tested only against the repository's own
test clients, test certificate authorities and locally signed workload
tokens, not against real CI systems, clusters, SPIFFE deployments or FAPI
conformance tools ([interoperability.md](../integrations/interoperability.md#untested-claims)).
Migrations `0049`–`0056` are expand-only (`0056` re-creates the
`clients.token_endpoint_auth_method` check with two more values).

## Migration implications

New protocol modules must add their own migrations (expand-only), discovery
entries, threat-model sections and interoperability evidence (QA-004). Federation
added `federation_requests` and columns on `identity_providers` and
`external_identities` (migration `0006_federation.sql`); migration `0040`
widened the adapter check to any registered adapter name, so older binaries
in a mixed-version window do not know the newer adapters. SCIM added no
table; migration `0042` widened the `memberships.source` check with `scim`
(expand-only).

## Related requirement IDs

APP-020, OIDC-015, FED-001..FED-018, SAML-001..SAML-010, PROV-001..PROV-018, QA-004, QA-006, TEST-026, TEST-027, §18, §19, §29; update 2026-10-11: APP-018, USR-022, TEST-051, TEST-052; APP-016, APP-017, ADV-001..ADV-004, SES-018, TOK-019, TOK-020, OIDC-013, MCH-011..MCH-014, PROV-016, TEST-066, TEST-067

## Updates

**Update — 2026-10-18.** Recorded under the dated-update rule
([README](README.md#changing-a-decision)). Apart from the two updates of
2026-10-11 above, the Decision list was edited in place in 2026-10: the
`google` and `microsoft` adapters (FED-002, migration `0040`) and SCIM 2.0
inbound provisioning (PROV-001..PROV-009, PROV-018, migration `0042`) were
added, and the **Not implemented**, discovery and connector-kind items were
annotated with what the updates changed. Each shipped under the rule this
record decides, which is unchanged. The file was renamed from
`0018-enterprise-protocols-deferred.md` because most of what it deferred has
shipped; the title was already accurate.
