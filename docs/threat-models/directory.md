# Directory integration threat model

Scope: LDAP and Active Directory federation, directory synchronization,
directory-authoritative accounts and outbound SCIM provisioning
([docs/integrations/directory.md](../integrations/directory.md),
[outbound-provisioning.md](../integrations/outbound-provisioning.md);
PROV-010..PROV-014, PROV-017, PROV-018, FED-015, USR-022). Inbound SCIM is
covered in [system.md](system.md). Method as in system.md. This is the
project's own code review, not an independent assessment (SEC-018). LDAP
sign-in, synchronization, failover and write-back are tested only against the
in-process `ldaptest` server, which serves OpenLDAP- and Active
Directory-style entries; no real OpenLDAP, Active Directory or other LDAP
server has been exercised yet. Outbound SCIM is tested against an in-process
SCIM double and, weekly in the `interop` workflow
(`scripts/interop-zitadel.sh`), against one third-party SCIM service provider,
ZITADEL v4.16.3, for users only (no groups), in the profile listed in
[interoperability.md](../integrations/interoperability.md#third-party-products);
no other downstream SCIM service has received pushes, and no SCIM conformance
suite has been run (QA-004).

## Assets

| Asset | Where | Why it matters |
| --- | --- | --- |
| Service-account bind passwords, downstream bearer tokens | `provisioning_connectors.secret_ciphertext` (AES-256-GCM, associated data `directory-connector-credential:<connector id>`) | Read the directory (and write the write-back attributes); act as ProudAuth at the downstream |
| User passwords of directory-sourced accounts | Only in transit: forwarded in a bind to the account's own directory | Account takeover in the directory and everywhere it is trusted |
| Links | `connector_external_ids` (immutable ID, DN, snapshot of imported values, source state) | Decide which directory owns an account |
| Connector definitions | `provisioning_connectors.config` (endpoints, filters, mappings, ceilings) | Decide which servers receive passwords and what a directory may change |
| Run evidence | `directory_sync_runs`, `directory_sync_findings` | Plans and conflicts; must not leak other tenants' accounts |

## Trust boundaries

| Boundary | Inside | Outside | Enforcement |
| --- | --- | --- | --- |
| Server/worker → directory | Configured endpoints of a connector | Other LDAP servers, referral targets | Endpoint list only; TLS with verification; egress policy at connection time (`directory.allow_private_network`, `directory.egress_allowlist`, residency); referrals never followed |
| Worker → downstream SCIM | The connector's `base_url` | Other hosts | Webhook egress policy at save and at connection; no redirects; bounded size and time |
| Realm directory administration | Realm administrators (`realm.provisioning.manage`; reads also `realm.provisioning.read`) | Organization administrators | Administration audience, MFA session |
| Organization directory administration | Holders of `org.integrations.write` in that organization | Other organizations | `orgGuard`; other organizations' connectors are `404`; ceilings bounded by the creator's |
| Directory → accounts | The connector's own linked accounts and its organization | Protected and privileged accounts, other organizations, accounts another source owns | Adoption and deprovisioning rules; one directory per account |

## STRIDE

| Threat | Mitigation (code) | Tests | Residual |
| --- | --- | --- | --- |
| I: service credential disclosure | Encrypted under the key hierarchy with row-bound associated data; write-only API; rotation with `PUT .../credential`; never in responses, run errors, findings, logs or audit metadata; health, test results and errors expose categories and host names only (`directory/directory.go`, `evidence.go`) | Leak assertions in `TestLDAPDirectorySignIn` and `TestOutboundProvisioning` (responses and audit metadata) | The service account should be read-only except for the attributes permitted for write-back; ProudAuth cannot check its rights |
| I: user password exposure | Passwords are only sent in a bind to the account's own configured directory over TLS (cleartext `ldap://` without StartTLS only in development mode); never stored, logged or hashed locally; empty passwords never sent (no unauthenticated binds); more than 1024 bytes refused (`directory/auth.go`, `ldapconn.go`) | `TestLDAPDirectorySignIn`, `TestTLS` | A compromised directory server (or its TLS key) sees every password of its users at sign-in |
| T/E: LDAP filter injection | Every value in a filter is escaped (`ldap.EscapeFilter`; binary GUIDs byte by byte); DNs are never built from input (binds use DNs the directory returned); operator filters are compiled and validated when saved | `TestFiltersEscapeInput` (`*@corp.test` becomes `\2a@corp.test`), escaped identifiers in `TestLDAPDirectorySignIn` | — |
| S: source confusion during failover (PROV-014) | Only configured endpoints; failover only on transport errors; answers about the request (wrong password, no such object, refused bind) are final and never retried elsewhere; referrals never followed; a USN cursor is bound to its domain controller | `TestFailoverOnTransportErrorsOnly`, `TestClassify` | Endpoints of one connector must be replicas of the same directory; ProudAuth cannot verify that |
| S/I: man in the middle | TLS 1.2 or later, certificate and host name always verified (system roots, `directory.ca_file`, connector roots); StartTLS before any bind; no skip-verify option | `TestTLS` | — |
| E/I: SSRF through connector endpoints (TEST-052) | Egress policy against every resolved address at connection time, plus residency; organization administrators reach only public addresses or operator-allowlisted ranges; outbound HTTP refuses redirects and bounds response size and time | Egress opt-in in `TestOutboundProvisioning`; `TestDirectoryTenantIsolation` | An organization connector can probe whether a public host answers LDAP |
| D: fallback to a weaker source (TEST-027, FED-012) | Directory outage, disabled connector or disabled module → `503 upstream_unavailable` for directory-sourced accounts, never a local password or another directory; local accounts unaffected | `TestLDAPDirectorySignIn` | A long directory outage blocks password sign-in for its users |
| I/E: tenant directory receives others' passwords | First sign-in provisioning is realm-only; organization connectors only ever bind accounts they link | `TestDirectoryTenantIsolation`, `TestLDAPConfigRules` | — |
| E: account takeover through linking | Never by email text alone: adoption only by organization connectors, through a verified email in a domain the organization verified, of a non-protected, non-privileged account no other connector manages; realm connectors never adopt; first-sign-in conflicts are refused; adoption revokes the local password | `TestDirectorySynchronization` | An inbound SCIM connector can adopt a directory-sourced account into its organization (it manages only that membership) |
| E/I: tenant isolation (TEST-007, TEST-009) | Organization connectors are visible and manageable only in their organization; they create memberships, groups and roles only there, within a ceiling bounded by the creator's; deprovisioning removes only their organization's access; outbound organization connectors receive only their members; findings never contain other accounts' IDs or attribute values | `TestDirectoryTenantIsolation`, `TestOutboundProvisioning` | An organization connector, like inbound SCIM, can create realm accounts with usernames not yet taken (username squatting); emails are verified only through the organization's verified domains |
| E: privilege through groups (PROV-006, TEST-049) | Protected accounts and privileged realm role holders are never changed or deprovisioned; group roles must stay within the ceiling at every run, including roles granted by others or inherited | `TestDirectorySynchronization` | Organization connectors reactivate a membership on re-enable whoever suspended it |
| D/T: mass deletion or misconfiguration | Deletion threshold with an explicit, audited override; incremental runs never deprovision; failed runs and runs over `max_entries` deprovision nothing; deletion detection only after a complete scan; dry runs | `TestDirectorySynchronization` | A wrong `user_filter` below the threshold still deprovisions up to the threshold |
| T: oscillating overwrites (PROV-017) | One authority per attribute; one directory per account; write-back first, local edit refused when it fails; synchronization compares with the current local value | `TestDirectoryAuthority` | — |
| T: local edits diverge from the directory (USR-022) | One authority check in every edit path, including password set and reactivation; `409` names the managed attributes | `TestDirectoryAuthority` | — |
| E: forged queue input (TEST-063) | The job names only the run; the handler loads run and connector from the database and re-checks the requester's authority (INT-006) | — | — |
| T: duplicate effects on retry (TEST-058) | Per-entry idempotent application; deliveries coalesced and generation-checked; downstream create made idempotent through `externalId`; a resource the connector did not create is never adopted | `TestOutboundProvisioning` | — |
| I: timing reveals unknown identifiers | The password step's minimum response time (`security.min_auth_response`) | — | Directory round trips longer than that bound, and `503` answers, are not masked |
| T: loops between inbound and outbound | `exclude_created_via` and one directory per account; outbound never reads back into local accounts | — | An operator must configure the exclusion |
| R: unaudited connector actions | `directory.*` audit events with the connector as actor or target; operator actions in the connector's evidence | All directory e2e tests | — |

## Not offered, with reasons

Kerberos/SPNEGO (PROV-015) and password write-back (PROV-013) are not
implemented; the reasons are in
[directory.md](../integrations/directory.md#kerberos-and-spnego-are-not-offered)
and [ADR 0018](../architecture-decisions/0018-enterprise-protocols-deferred.md).
