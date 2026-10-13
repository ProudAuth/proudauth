# Provisioning and federation attack suites

The M4 exit gate of [docs/plan.md](../plan.md) (section 35.1) requires that
"provisioning and federation attack suites pass". These are the two suites:
each row is an attack against a trust boundary, and the tests named there
mount it and assert that it fails. Run them on their own with

```sh
PROUDAUTH_TEST_DATABASE_URL=... make attack-suites
```

(`make attack-provisioning` and `make attack-federation` run one suite each).
CI runs them in the `test` job as a separate step after the full test run, so
a failure names the suite. `TestAttackSuitesExist` (`tests/contract`) fails
when a test named here no longer exists, so the suites cannot silently lose a
test. The analysis behind each row is in [system.md](system.md),
[directory.md](directory.md), [cross-system-trust.md](cross-system-trust.md)
and the SAML and provisioning integration documents; the tests run against
in-process counterparts, and the third-party runs are listed in
[interoperability.md](../integrations/interoperability.md#third-party-products).

## Provisioning suite

| Attack | Expected result | Tests |
| --- | --- | --- |
| A SCIM or directory connector reads or writes accounts of another organization, or of protected and administrator accounts | Out of reach: other organizations' accounts are invisible, protected accounts are refused | `TestSCIMProvisioning`, `TestDirectoryTenantIsolation` |
| Account takeover by provisioning an address that matches an existing account | Adoption only through the organization's verified domain; otherwise a conflict is reported, never a merge | `TestSCIMProvisioning`, `TestDirectorySynchronization` |
| Privilege escalation through provisioned groups | Group roles only from approved mappings, within the connector's role ceiling | `TestSCIMProvisioning`, `TestDirectorySynchronization` |
| Mass deprovisioning through a directory outage or a bad filter (TEST-048, TEST-049) | Deletion detection stops behind the safety threshold; dry runs and overrides are explicit and audited | `TestDirectorySynchronization` |
| Lost update: a SCIM write racing an administrator's change (TEST-050) | Stale `If-Match` answers `412`; no change is silently reverted | `TestSCIMAdminRaceNeverLosesChanges`, `TestSCIMProvisioning` |
| Filter injection in SCIM queries and LDAP searches | Malformed SCIM filters refused; user input never changes an LDAP filter's structure (RFC 4515) | `TestParseFilterRejects`, `TestFiltersEscapeInput` |
| Local edits of directory-managed attributes, including the password | Refused with `409 externally_managed`; write-back writes the directory first or refuses | `TestDirectoryAuthority`, `TestDirectoryManagedPasswordReset` |
| Outbound provisioning sends a change twice or deletes resources it did not create | Each delivery claimed once; reconciliation never deletes foreign resources | `TestOutboundProvisioning`, `TestOutboundDeliveryClaimedOnce` |
| Connector URLs pointing into private networks (TEST-052) | The egress policy is applied at connection time, after DNS resolution and on every redirect | `TestConnectionTimeEnforcement`, `TestBlockedRanges` |
| Provisioned data left behind after erasure | Erasure redacts directory links and findings; retention prunes run history | `TestDirectoryErasureAndRetention` |

## Federation suite

| Attack | Expected result | Tests |
| --- | --- | --- |
| Linking an external identity to an account by matching email text only (TEST-026) | No implicit linking: proof of control of the local account is required, with a code or link sent for that link | `TestFederation`, `TestPasswordlessLinkPurpose` |
| Same `sub` from two issuers treated as one person (DOM-002) | Two distinct accounts, each bound to its issuer | `TestSameSubjectFromTwoIssuers` |
| Issuer mix-up, a foreign upstream tenant, or untrusted upstream assurance | Refused; adapters keep fixed issuers and tenant rules | `TestFederation`, `TestFederationAdapters` |
| Local password fallback for an SSO-mandatory organization (TEST-027) | No fallback: the organization's connection is required | `TestFederation`, `TestLDAPDirectorySignIn` |
| One organization's connection used to sign in to another (FED-006) | Refused at sign-in and when creating organizations | `TestFederation`, `TestOrganizationCreationRefusesForeignConnection` |
| SAML signature wrapping, invalid audience, destination or correlation, duplicate IDs, replay, weak algorithms (TEST-051, SAML-004) | Refused with bounded parsing; XML entities, DTDs, comments in values and oversize or deep documents rejected | `TestSAMLBroker`, `TestSignVerifyAndWrapping`, `TestParserRefusals`, `TestSHA1Refused` |
| Malicious SAML requests to the identity provider (forged ACS, unsolicited responses outside policy) | Request validation, registered endpoints only, IdP-initiated sign-in only where enabled | `TestSAMLIdentityProvider` |
| A sign-in already at the upstream finishing after the connection was disabled | Ends with `connection_disabled`; the upstream is not contacted again | `TestRunbookConnectorCompromise` |
| Forged or replayed workload assertions | Issuer, key, algorithm, audience, lifetime, subject, claims and `jti` must all match; replays refused | `TestWorkloadFederation` |
| Forged, replayed or out-of-scope shared-signals events | Push secret, signature, issuer, audience, age and replay checks; only the explicit action policy applies | `TestSharedSignalsReceiver` |
| Account takeover through bulk relinking | Reviewed transfer map with collision reporting, second approval, never by email | `TestFederationTransfer` |
| Cross-realm convergence of identities | No merge or link across realms | `TestNoCrossRealmConvergence` |
