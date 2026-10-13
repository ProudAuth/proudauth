---
name: Bug report
about: Report incorrect behavior that is NOT a security vulnerability
title: "bug: "
labels: ["bug", "needs-triage"]
---

<!--
STOP: if this issue could let someone bypass authentication or authorization, read
or change another tenant's data, forge or reuse a token, escalate privileges, or
expose a secret, do NOT file it here. Report it privately as described in
SECURITY.md (GitHub "Report a vulnerability"). Public issues are visible to everyone.

Never paste real tokens, passwords, client secrets, root keys, cookies, setup or
invitation secrets, or personal data. Redact them, e.g. pa_rt_[REDACTED].
-->

## What happened

<!-- A clear description of the incorrect behavior. -->

## What you expected

## How to reproduce

1.
2.
3.

<!-- Prefer a reproduction against the development Compose stack (make dev) or a
failing test in tests/e2e. Include the HTTP method, route and the problem `code`
from the response body; omit secrets. -->

## Environment

- ProudAuth version / commit / image digest:
- Mode (`development` or `production`):
- Deployment (Compose, binaries, other):
- PostgreSQL version:
- Go version (if built from source):
- OS / architecture:

## Logs and evidence

<!-- Relevant log lines with request_id, and `identity-cli doctor` output if
relevant. Logs are redacted by the server, but check again before pasting. A
support bundle (identity-cli support-bundle) excludes keys and personal data;
review it before attaching. -->

## Requirement IDs (optional)

<!-- If you know which requirement in docs/plan.md this violates (e.g. SES-007,
TEST-030), list it. -->
