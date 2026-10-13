# Threat models

| Document | Scope |
| --- | --- |
| [system.md](system.md) | Whole system: assets, trust boundaries, STRIDE per component (protocol endpoints, headless transactions, self-service and tenant APIs, administration API, support access, workers and egress, database, keys, SDK verifiers, operator channel), including migration adapters, lifecycle workflows, plugins and extension contract versions, mapped to code and tests |
| [impersonation.md](impersonation.md) | Support impersonation in detail (§16, IMP-001..IMP-024) |
| [saml.md](saml.md) | SAML 2.0 identity provider and broker: XML parsing, signature wrapping, algorithm downgrade, replay, unsolicited responses, ACS and RelayState redirection, linking by email, signing-key compromise, logout (SAML-001..SAML-010, TEST-051) |
| [directory.md](directory.md) | LDAP/Active Directory federation and synchronization and outbound SCIM: credential custody, password forwarding, filter injection, failover source confusion, egress, tenant isolation, linking, mass deletion, write-back (PROV-010..PROV-018, FED-015, USR-022) |
| [cross-system-trust.md](cross-system-trust.md) | Trust across systems and tenants: OIDC session-management iframe, shared-signals transmitter and receiver, container-registry tokens, passkey attestation trust and related origins, federation transfer, organization relationships and partner project access, flow revisions, historical entitlement evidence, external risk signals (OIDC-014, AUD-016, ADV-007, ADV-010, PASS-009, PASS-010, FED-016, TEN-020, TEN-021, AUT-019, ADV-011, ADV-012) |
| [review-scope.md](review-scope.md) | Brief for the independent security review that SEC-018 and QA-005 require and that has not taken place: priority areas, code, evidence and how to run it |
| [attack-suites.md](attack-suites.md) | The provisioning and federation attack suites of the M4 exit gate: each attack and the tests that mount it (`make attack-suites`) |

These are maintained by the project, based on code review. They are not an
independent assessment (SEC-018 has not been performed).

Update a threat model in the same pull request when a change:

- adds or changes a trust boundary, endpoint class, token type or credential;
- changes a mitigation listed here, or the test that covers it;
- closes or introduces a residual risk.

Report vulnerabilities through [SECURITY.md](../../SECURITY.md), not by editing
these documents.
