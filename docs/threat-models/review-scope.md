# Independent security review: scope and starting points

SEC-018 and QA-005 require a focused external review before broad production
use and before any claim of a hardened release. **No such review has taken
place.** This page is the brief for the reviewers when one is commissioned:
what to look at first, where the evidence is, and how to run it. It makes no
claim that anything here is secure.

For the 2026-10-13 delivery, the owner requested completion without this
review ([delivery exception](../plan.md#354-delivery-checkpoint--2026-10-13)).
The review has not been performed; this brief remains available for a later
review, and its absence no longer blocks that delivery's completion.

## Priority areas (QA-005)

| Area | Code | Threat analysis | Tests to start from |
| --- | --- | --- | --- |
| Authentication: headless transactions, passwords, factors, passkeys, certificates, federation | `internal/authentication`, `internal/credential`, `internal/passkey`, `internal/certauth`, `internal/federation`, `internal/saml` | [system.md](system.md), [saml.md](saml.md), [attack-suites.md](attack-suites.md#federation-suite) | `TestMultiFactorAndProofs`, `TestPasswordlessAndAbuseBudgets`, `TestIdentifierProbeResponses`, `TestCertificateSignIn`, the federation attack suite |
| Recovery: password reset, recovery codes, assisted recovery, lost contact, deletion cancellation | `internal/authentication/recovery.go`, `assisted.go`, `recovery_contact.go`, `deletion.go` | [account-recovery.md](../operations/account-recovery.md) | `TestRegistrationAndRecovery`, `TestScheduledAssistedRecovery`, `TestLostContactAndFactorRecovery`, `TestAdminIdentifierChangeGuards`, `TestDeletionCancelAtSignIn` |
| Authorization: roles, delegation ceilings, project scope, relationships, decision API, support guard | `internal/authorization`, `internal/httpapi/decision.go` | [ADR 0013](../architecture-decisions/0013-authorization-model.md) | `TestDelegationCeilings`, `TestProjectScopedRoles`, `TestTenantCrossingMatrix`, `TestAuthenticatedRoutesCheckPermissions` |
| Cryptographic usage: key hierarchy, token signing, AEAD bindings, peppering, OTP verifiers, SDK verifiers (the Dart SDK implements RS256, PS256, ES256 and EdDSA verification itself) | `internal/keys`, `internal/token`, `internal/platform/secret`, `standalone SDK repositories` | [ADR 0015](../architecture-decisions/0015-key-hierarchy.md), [keys.md](../operations/keys.md) | `TestEncryptRoundTripAndBinding`, `TestSigningKeyRotation`, `TestSharedRevocationAcrossNodes`, the SDK signature vectors (`proudauth-sdk-dart/test/vectors`, `proudauth-sdk-php/tests/vectors`) |
| Support impersonation | `internal/impersonation`, `standalone SDK repositories` `SupportGuard` | [impersonation.md](impersonation.md) | `TestSupportImpersonation`, `TestSupportSessionSeparation`, `TestSupportGrantEndings`, `tests/fixtures/sdk-contracts/support-operations` |

Also in scope as trust boundaries: the egress policy (`internal/egress`),
plugins and hooks (`internal/plugin`, `internal/hooks`), restore
reconciliation (`internal/restore`) and the configuration validator
(`internal/configuration`).

The 2026-10-11 changes add a resource-server sender boundary in
`proudauth-sdk-go/verifier/sender.go` and reject `cnf` through ordinary methods in all
four SDKs. Review proof parsing, public-origin/path binding, the shared atomic
replay-store contract, TLS proxy/certificate callbacks and fail-closed mode
selection against `TestResourceSenderVerifier`, `TestSenderProofs` and
`TestSenderReplayConcurrencyAndFailure`. Also review the Go SDK's redirect
boundary (`proudauth-sdk-go/internal/httpclient`) and the server's exact DPoP method and
single-header checks (`TestDPoPBoundTokens`). These are internal correctness
tests and have not received independent review.

## Evidence available to reviewers

- **Requirements traceability:** [requirements-traceability.md](../requirements-traceability.md)
  lists every requirement of the specification with the tests that cite it.
  A citation shows where a requirement is handled, not that it is right.
- **Threat models:** this directory; each row names its mitigation, its test
  and the residual risk.
- **Interoperability:** [interoperability.md](../integrations/interoperability.md),
  including the third-party products exercised.
- **Supply chain:** [security-checks.md](../operations/security-checks.md)
  lists every CI check and its exceptions.

## Running everything

```sh
docker run -d --name proudauth-pg -e POSTGRES_USER=proudauth -e POSTGRES_PASSWORD=devpassword \
  -e POSTGRES_DB=proudauth -p 127.0.0.1:55432:5432 postgres:17
export PROUDAUTH_TEST_DATABASE_URL='postgres://proudauth:devpassword@127.0.0.1:55432/proudauth?sslmode=disable'
go test ./... -count=1          # unit, contract and end-to-end tests (without the
                                # variable the database tests are skipped)
make attack-suites              # provisioning and federation attack suites
make test-node test-dart test-php
make dr-drill                   # standby promotion and point-in-time recovery
```

## After the review

Record the reviewer, scope, dates, version reviewed and the findings'
disposition in `SECURITY.md` and the CHANGELOG, update the README's "not
independently reviewed" notice, and repeat the review on major protocol or
trust-boundary changes (SEC-018).
