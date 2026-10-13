# Security policy

This policy implements GOV-003 and SEC-019 of [docs/plan.md](docs/plan.md).
ProudAuth is pre-release software that has not had an independent security review;
see [README.md](README.md#why-proudauth).

## Reporting a vulnerability

**Do not report vulnerabilities in public issues, pull requests, discussions or
chat.** The public issue templates are for bugs and features only.

Use **GitHub private vulnerability reporting** through the repository's
[security advisory form](https://github.com/proudbase/proudauth/security/advisories/new)
(Security tab, "Report a vulnerability"). Reports are private to the reporter
and maintainers. There is no monitored project security mailbox advertised here.

This local snapshot has not been published. Before public source publication,
maintainers must enable private vulnerability reporting and verify this route.
SDK vulnerabilities belong to the corresponding language repository's private
advisory form; reports affecting the shared protocol can also go to the service
maintainer. Never put reproduction secrets in a public issue.

Please include:

- the affected commit, tag or image digest;
- the component (for example `internal/oauth`, `sdk/go/verifier`, a migration);
- reproduction steps or a proof of concept against a local development stack;
- the impact you believe it has (for example tenant crossing, token forgery,
  privilege escalation, secret disclosure, denial of service);
- whether the issue is already public or being exploited.

Test only against your own installation. Do not access data that is not yours,
and do not run denial-of-service or social-engineering tests against anyone.

## What happens next

| Step | Target |
| --- | --- |
| Acknowledge receipt | within 3 business days |
| Initial assessment (validity, severity, affected versions, fix plan) | within 10 business days of acknowledgement |
| Status updates to the reporter | at least every 14 days until resolution |

Targets are commitments of effort by a volunteer project, not contractual service
levels. If you receive no acknowledgement within 3 business days, follow up on the
advisory or open a public issue that says only "security report awaiting
acknowledgement" with no details.

Maintainers triage with a security reviewer (see [CODEOWNERS](.github/CODEOWNERS)).
Severity is assessed from impact and exploitability; the CVSS score, if assigned,
is advisory.

## Coordinated disclosure

- The default embargo is **90 days** from acknowledgement, or until a fixed release
  is published, whichever comes first.
- The embargo can be shortened when a fix is released earlier or the issue is
  being exploited publicly, and extended by mutual agreement when a fix needs more
  time.
- Fixes are developed in a private security advisory fork. Each fix adds a
  regression test or fixture that reproduces the issue (QA-008).
- Publication consists of a GitHub security advisory (with a CVE where
  appropriate), a release containing the fix, and a `Security` entry in
  [CHANGELOG.md](CHANGELOG.md) that names affected versions.
- Reporters are credited in the advisory unless they ask not to be.

## Security regressions (QA-008)

Every security fix is reproducible without customer data:

- **A regression test or fixture lands with the fix.** It fails before the fix
  and passes after it: an end-to-end scenario in `tests/e2e`, a unit test next
  to the code, a fuzz input committed under `testdata/fuzz/<Target>/`, or a
  case in the shared SDK fixtures (`sdk/fixtures`). Name it in the pull
  request and in the CHANGELOG entry.
- **Synthetic data only.** Fixtures use test-only keys, `example.test` style
  names and generated IDs. A reproduction taken from a report or an incident is
  rebuilt with synthetic values; tokens, logs, database rows, IP addresses or
  tenant names from a real deployment are never committed.
- **The CHANGELOG entry** under **Security fixes** names the affected versions
  (or states that only untagged development commits were affected), the
  version that contains the fix, the advisory once published, the requirement
  ID and the regression test. It describes the flaw and its impact, not the
  reporter's deployment, customers or data.
- When a fix cannot be covered by an automated test (for example a failure
  that needs fault injection the suite does not have), the CHANGELOG entry says
  "No regression test covers it yet" so the gap stays visible; several current
  entries do.

## Supported versions

While the project is in the 0.x series:

| Version | Security fixes |
| --- | --- |
| Latest 0.y minor release | Yes |
| Previous 0.(y-1) minor release | Yes, until the next minor release after it is published |
| Older releases and untagged commits | No |

No release has been tagged yet, so today only the `main` branch receives fixes.
After 1.0 this table will be replaced by a policy published with the 1.0 release.
The same lines apply to the Go, Node.js, Dart, PHP and .NET SDKs, whose versioning is described
in [docs/integrations/sdk-compatibility.md](docs/integrations/sdk-compatibility.md).

## Scope

In scope:

- code in this repository: `cmd/`, `internal/`, `migrations/`, the transitional Go SDK and shared fixtures in `sdk/`, `scripts/`, and the API contracts in `api/`;
- the `Dockerfile`, `deploy/` files and `.github/workflows/` (supply-chain issues);
- the example applications in `examples/` where a flaw would mislead integrators
  into an insecure pattern;
- documented security properties in `docs/` that the code does not actually
  provide.

Out of scope:

- deployments run by third parties (report to their operator);
- vulnerabilities in dependencies that ProudAuth does not reach (report upstream;
  tell us if ProudAuth is affected);
- findings that require a malicious deployment operator with database, key or host
  access — this is an explicit threat-model limit
  ([docs/threat-models/system.md](docs/threat-models/system.md)), although reports
  that strengthen tamper evidence are welcome;
- the development Compose stack being insecure (it is documented as development
  only), unless it can be started in `production` mode with those settings;
- missing features that are documented as not implemented.

## Safe harbor

We will not pursue or support legal action against people who, in good faith:

- follow this policy and report through a private channel;
- test only against systems they own or are authorized to test;
- avoid privacy violations, data destruction and service degradation;
- do not exploit a finding beyond what is needed to demonstrate it;
- give us reasonable time to fix the issue before public disclosure.

This statement covers the ProudAuth project. It cannot authorize testing of
someone else's deployment.

## Security-relevant documentation

- Threat models: [docs/threat-models/](docs/threat-models/README.md)
- Incident runbooks: [docs/operations/incidents.md](docs/operations/incidents.md)
- Revocation exposure: [docs/operations/revocation-exposure.md](docs/operations/revocation-exposure.md)
- Key management: [docs/operations/keys.md](docs/operations/keys.md)
