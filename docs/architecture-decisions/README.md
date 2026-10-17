# Architecture decision records

These records implement GOV-001: architecture and compatibility decisions are
versioned with their rationale, alternatives and migration implications. Each ADR
corresponds to one row of the decision register in docs/plan.md §37.1. It keeps the
decision as accepted and, through dated updates, records what the code does today,
including where it falls short of the register.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-modular-monolith.md) | Product form: modular monolith with worker processes | Accepted |
| [0002](0002-go-implementation.md) | Implementation language and libraries: Go | Accepted |
| [0003](0003-apache-2-license.md) | First-party license: Apache-2.0 | Accepted |
| [0004](0004-persistence.md) | Durable store: PostgreSQL | Accepted |
| [0005](0005-database-outbox-no-broker.md) | Cache and broker: none required; transactional outbox in PostgreSQL | Accepted |
| [0006](0006-realm-and-organization-boundaries.md) | Identity boundaries: realm = issuer and user namespace; organization = business tenant | Accepted |
| [0007](0007-stable-account-key.md) | Stable account key: immutable local IDs; external identity keyed by issuer and subject | Accepted |
| [0008](0008-authorization-code-pkce-only.md) | Interactive protocol: authorization code with PKCE only | Accepted |
| [0009](0009-jwt-access-tokens.md) | Ordinary access tokens: short-lived asymmetric JWTs with one audience | Accepted |
| [0010](0010-opaque-support-tokens.md) | High-risk and support tokens: opaque, validated online | Accepted |
| [0011](0011-refresh-token-families.md) | Refresh model: opaque, rotated, client-bound families | Accepted |
| [0012](0012-one-organization-per-token.md) | Organization context: one organization per business token | Accepted |
| [0013](0013-authorization-model.md) | Authorization: scoped RBAC with delegation ceilings and a decision API | Accepted |
| [0014](0014-support-impersonation.md) | Impersonation: explicit, short, actor-preserving support grants | Accepted |
| [0015](0015-key-hierarchy.md) | Keys: root keys, HKDF purpose keys, AES-256-GCM, wrapped signing keys | Accepted |
| [0016](0016-delivery-adapters.md) | Email and SMS: replaceable operator-configured adapters | Accepted |
| [0017](0017-external-login-ui.md) | Browser integration: external login UI and headless transactions | Accepted |
| [0018](0018-enterprise-protocols-when-complete.md) | Federation and enterprise protocols: ship each only when complete | Accepted |
| [0019](0019-single-write-region.md) | HA topology: one authoritative write region | Accepted |
| [0020](0020-compliance-posture.md) | Compliance posture: evidence and controls, no certification claims | Accepted |
| [0021](0021-no-embedded-code-execution.md) | Custom logic: out of process only, no embedded code execution (EXT-013; not a §37.1 register row) | Accepted |
| [0022](0022-shared-signals-adapter.md) | Security-event exchange: an audit-log adapter out, explicit action policies in (AUD-016, ADV-007; not a §37.1 register row) | Accepted |

## Format

Each record has: **Status**, **Context**, **Decision**, **Alternatives
considered**, **Consequences**, **Migration implications** and **Related
requirement IDs** (from docs/plan.md). A record changed after acceptance ends
with **Updates** (see below).

## Changing a decision

The text of an accepted record is not rewritten. How a change is recorded
depends on what changed:

- **The decision stands, but the code has changed** (a capability implemented,
  a scope extended or narrowed, a defect fixed): add a dated paragraph that
  starts with `**Update — YYYY-MM-DD.**` to a `## Updates` section at the end
  of the record, newest last. It says what changed and why, with requirement
  IDs, migrations and tests. The original Context, Decision and Consequences
  stay as accepted; a statement the update overtakes may get a short pointer
  to it, but is not rewritten.
- **The decision is reversed or substituted:** add a new ADR with the next
  number whose status reads `Accepted; supersedes NNNN`, set the old record's
  status to `Superseded by NNNN`, link the two, and update the threat model,
  tests and operations documents in the same pull request. docs/plan.md §37.1
  requires that a substituted decision preserve the security invariant it
  protects (for example, choosing another database does not remove atomic
  one-time proof consumption).
- **Editorial fixes** that change neither the decision nor what the record
  says the code does (a broken link, a typo, a renamed path or file) are made
  in place.

Records amended before this rule was written (2026-10-18) carry inline
"Update 2026-10" notes and `## Update (2026-10…)` sections, which stay as they
are. Where such an edit changed the Decision text without an update section,
the record now has a dated update that says so (0007, 0008, 0014, 0015, 0017
and 0018).
