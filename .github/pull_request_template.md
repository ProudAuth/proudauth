<!--
Security fixes for undisclosed vulnerabilities are prepared in a private security
advisory, not in a public pull request (SECURITY.md).
-->

## Summary

<!-- What changes and why. -->

## Requirement and test IDs

<!-- Requirement IDs from docs/plan.md that this implements or affects
(e.g. TOK-008, IMP-012) and acceptance tests added or changed (e.g. TEST-030). -->

## Definition of done (docs/plan.md §37.2)

Tick each item or write "n/a" with a reason. Reviewers check these.

- [ ] Clear behavior, explicit non-goals, priority and maturity status are stated
      (and `README.md` / `CHANGELOG.md` feature status is updated).
- [ ] API schema, authentication class (docs/plan.md §25.2), permissions and tenant
      boundaries are defined; path/body IDs are only selectors. New or changed
      routes and events are reflected in `api/` (`tests/contract` passes).
- [ ] Persistent model, invariants, migration (expand → migrate → contract),
      retention and recovery/restore behavior are covered.
- [ ] Actor/subject-aware audit is written in the same transaction; user/security
      notifications are added where needed; redaction is tested.
- [ ] Positive, negative, concurrent, failure and interoperability tests are
      included as applicable (wrong tenant, wrong audience, replay, expiry,
      missing permission, dependency failure).
- [ ] Safe defaults, resource limits, configuration keys (documented in
      `docs/operations/configuration.md`) and operational metrics are in place.
- [ ] Example integration, SDK/CLI coverage and operator runbook are updated where
      relevant.
- [ ] Dependency and license review is done (`make lint`, `NOTICE`), and nothing
      requires a paid activation or a project-operated service.
- [ ] Threat-model changes, rollback limits and security-sensitive extension points
      are reviewed (`docs/threat-models/` updated if a trust boundary changed).

## Security-sensitive paths

- [ ] This PR touches a path listed in CONTRIBUTING.md ("Security-sensitive
      areas"); it needs two maintainer approvals including a security reviewer.
- [ ] Every security fix in this PR adds a regression test or fixture (QA-008).

## Verification

<!-- How you tested it. Paste the relevant `go test -v` lines showing that database
tests RAN (not SKIP), e.g. with PROUDAUTH_TEST_DATABASE_URL set. -->

## DCO

- [ ] All commits are signed off (`git commit -s`).
