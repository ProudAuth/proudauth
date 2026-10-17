# 0004. Durable store: PostgreSQL

**Status:** Accepted

## Context

All security-critical transitions (code redemption, refresh rotation, invitation
acceptance, last-owner protection, audit + outbox coupling) need durable
transactions, row locks and unique constraints that every node observes
(ARC-002, ARC-005, DB-001..DB-014).

## Decision

PostgreSQL is the only durable store and the authority for all security state.

- **Driver:** pgx v5 pool; every connection sets `timezone=UTC`,
  `application_name=proudauth` and `statement_timeout` (`storage.statement_timeout`,
  default 10s).
- **Isolation:** `storage.DB.Tx` runs READ COMMITTED transactions and relies on
  explicit `SELECT ... FOR UPDATE`, conditional `UPDATE ... WHERE consumed_at IS
  NULL`, partial unique indexes and advisory locks. Serialization failures and
  deadlocks (`40001`, `40P01`) are retried up to 4 attempts; nothing is retried
  after commit. A transaction that calls out of the process must not be
  repeated (DB-014): the token endpoint and authentication steps run once
  (`storage.NoRetry`) when the realm has an active pre-action hook, and tokens
  are returned only after their transaction commits. Webhooks, email and SMS
  leave through the outbox and notification jobs after commit. Other outbound
  calls made inside a retried transaction (challenge-provider verification,
  cached federation discovery) and rate-limit counters, which are written
  outside the transaction, can still repeat on a retry.
- **Schema conventions** (`migrations/0001_core.sql`):
  - opaque, prefixed, immutable text IDs (`usr_`, `org_`, ... + lowercase ULID);
  - tenant-owned rows carry `realm_id`, organization-owned rows also
    `organization_id`, with composite foreign keys to `(realm_id, id)`;
  - bearer artifacts stored as SHA-256 digests; low-entropy codes as keyed HMAC
    verifiers; recoverable secrets as AES-256-GCM ciphertext with a key version;
  - `audit_events` and `audit_batches` are append-only by trigger.
- **Migrations:** numbered SQL files embedded in every binary
  (`migrations/embed.go`), applied in lexical order under
  `pg_advisory_lock(727274001)`, each in its own transaction, with a SHA-256
  checksum recorded in `schema_migrations`.
- **Tested versions:** PostgreSQL 18.x is the only supported version; CI and the
  development Compose file run 18.6.

## Alternatives considered

- **MySQL/MariaDB**: lacks the partial indexes and `SKIP LOCKED`/advisory-lock
  combination relied on throughout.
- **Key-value or document stores**: would push uniqueness and one-time consumption
  into application code.
- **Event sourcing**: optional per §5.2; rejected as a prerequisite. A relational
  model plus append-only audit and outbox is used.

## Consequences

- PostgreSQL availability is the availability of the identity provider: when it
  is unavailable, issuance, strict-online checks and administration fail closed
  (§31.2).
- Rate-limit counters also live in PostgreSQL (`rate_limit_counters`), adding write
  load per authentication attempt.
- Row-level security (DB-013) is not used; isolation relies on query predicates and
  composite keys, covered by isolation tests.
- Database superusers can read and alter everything not encrypted by the keyring;
  see the operator limit in [docs/threat-models/system.md](../threat-models/system.md).

## Migration implications

- Applied migrations must never change (checksum mismatch aborts `migrate`).
- A binary refuses to migrate a database that contains a migration it does not know
  (protects against running an older binary's migrator on a newer schema).
- Schema changes follow expand → migrate → contract
  ([docs/operations/upgrades.md](../operations/upgrades.md)).

## Related requirement IDs

ARC-002, ARC-003, ARC-005, DB-001..DB-014, DEP-010, DEP-012, OPS-008, TEST-061, §24

## Updates

**Update — 2026-10-18.** The "Tested versions" statement was changed in place:
it named major version 17 for CI and 18 for the development Compose file, and
now reads "PostgreSQL 18.x is the only supported version; CI and the
development Compose file run 18.6" (owner decision 4,
`docs/releases/2026-10-alpha.5-decisions.md`): CI runs `postgres:18.6`, and no
other version is tested. The decision itself (PostgreSQL as the only durable
store) is unchanged.
