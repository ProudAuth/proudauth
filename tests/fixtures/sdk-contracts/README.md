# Verification fixtures

Shared test vectors for anyone verifying ProudAuth access tokens: the Go,
Node.js, Dart, PHP and .NET SDKs, and independent services that verify tokens with their own JWT
library (SDK-009). They contain no customer data and use **test-only keys**;
never configure these keys anywhere a real token could be accepted.

## access-tokens/cases.json

| Member | Meaning |
| --- | --- |
| `issuer`, `audience` | The verifier configuration the cases assume |
| `now` | The verification time, in Unix seconds; evaluate every case at this instant with the default 30-second clock tolerance |
| `jwks` | The key set to serve (or load) as the issuer's JWKS: one RS256 and one EdDSA public key |
| `cases[]` | `name`, the compact JWT `token`, `expect` (`accept` or the error category the SDKs report) and `why` |

Error categories match the SDK error codes: `issuer`, `audience`, `expired`,
`not_yet_valid`, `future_issued`, `signature`, `unknown_key`, `algorithm`,
`token_type`, `token_kind`, `duplicate_claim`, `malformed`, `sender_constraint`. A verifier built on
another library passes when it accepts exactly the `accept` cases and rejects
every other case; the exact error it reports may differ.

What the cases cover: exact issuer and single-audience matching, mandatory and
checked `exp`/`nbf`/`iat`, signature tampering, unknown key IDs and key
confusion under a known key ID, unsigned (`alg: none`) tokens, ID tokens sent
as access tokens (`typ` must be `at+jwt`), support tokens that may only be
validated online (`token_kind: impersonation_access`), missing `client_id`,
duplicate JSON members, malformed input, and token-only rejection of DPoP,
certificate, unknown and null `cnf` bindings. There are 22 cases: two accepted
and twenty rejected.

All five SDKs run these cases in their test suites
(`proudauth-sdk-go/verifier/fixtures_test.go`, `proudauth-sdk-node/test/fixtures.test.ts`,
`proudauth-sdk-dart/test/fixtures_test.dart`, `proudauth-sdk-php/tests/FixturesTest.php`,
`proudauth-sdk-dotnet/tests/ProudAuth.Sdk.Tests/Program.cs`).
Regenerate them (new keys and tokens) from a checkout of
[`proudauth-sdk-go`](https://github.com/proudbase/proudauth-sdk-go) with:

```bash
PROUDAUTH_REGENERATE_FIXTURES=1 go test ./verifier -run TestFixtures
```

Copy the changed contract JSON into the service and every maintained SDK,
refresh each checksum manifest, and run all owning pipelines before updating
the service's pinned [SDK evidence](../../../docs/integrations/sdk-repositories.json).

## support-operations/cases.json

How operations are classified for support (impersonation) tokens (IMP-011,
IMP-012, IMP-013), by the SDK `SupportGuard` and by the server's
authorization decision API. Six test suites read this file, so the guards
and the server cannot drift apart:

- all five SDKs run every case through `SupportGuard`
  (`proudauth-sdk-go/verifier/support_test.go`, `proudauth-sdk-node/test/support-operations.test.ts`,
  `proudauth-sdk-dart/test/support_operations_test.dart`,
  `proudauth-sdk-php/tests/SupportOperationsTest.php`,
  `proudauth-sdk-dotnet/tests/ProudAuth.Sdk.Tests/Program.cs`);
- the server checks the `protected` and `write` classification of every
  `classification_only[]` and `cases[]` entry against
  `authorization.IsSupportForbidden` and `authorization.IsWriteAction`
  (`internal/authorization/support_test.go`). It does not evaluate `expect`:
  the server's write allowlist is the resource's
  `impersonation_policy.write_actions`, not `write_operations`.

A change to the classification rules therefore needs the SDKs and
`internal/authorization` (`catalog.go`) changed together.

| Member | Meaning |
| --- | --- |
| `write_operations` | The guard's write allowlist for the cases |
| `classification_only[]` | `operation` with the expected `protected` and `write` classification only |
| `cases[]` | `operation`, the caller-declared `read`, the token's `support_mode`, the expected `protected` and `write` classification, and `expect`: `allow`, `protected_operation` or `write_not_allowlisted` |

The rules the cases pin down:

- An operation name is trimmed, lowercased, `-` is read as `_`, and the name
  is split into segments on `.`, `:` and `/`.
- It is **protected** (always denied) when the segments of a protected entry
  appear anywhere in it as a contiguous run, with or without a trailing `s`
  (`payments.create`, `refunds.issue`, `secrets.read`, `read.payments`,
  `orders.purge`). Substrings do not count (`secretary.list` is not
  protected). An empty operation is protected.
- It is a **write** when any segment is a write verb (`create`, `update`,
  `delete`, `cancel`, `issue`, ...), even when the caller declared a read.
- A write is allowed only in `allowlisted_write` mode and only when the whole
  name matches a write allowlist entry, case-insensitively.
