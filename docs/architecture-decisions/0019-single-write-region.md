# 0019. HA topology: one authoritative write region

**Status:** Accepted

## Context

Immediate revocation and one-time consumption require a single authoritative
source of truth. Multi-region writes would need a consistency and failover design
that does not exist yet (DEP-018, DEP-019, §31.2).

## Decision

- One PostgreSQL primary is authoritative for all security state.
- Any number of `identity-server` and `identity-worker` processes may run against
  it. Requests carry no node affinity: transactions, grants and sessions are in the
  database (ARC-006). Workers coordinate through row locks, `SKIP LOCKED`, leases
  and advisory locks.
- The application reads only from the primary. No code path reads from replicas,
  so strict-online checks never see replica lag.
- Database high availability (synchronous standby, failover) is the operator's
  responsibility and outside the application.
- **Supported disaster-region recovery profile (DEP-019):** one writing region
  and a warm standby in another region (a PostgreSQL streaming replica, or
  base backups plus a WAL archive), with the same keys or KMS access available
  there and the application stopped until promotion. Promotion follows a
  runbook: fence the old primary, promote, start with the same keys, run
  `identity-cli restore-reconcile` with the revocation log (and
  `-invalidate-all-sessions` when the log does not cover the gap) whenever
  committed transactions may have been lost, then switch traffic
  ([backup-restore.md](../operations/backup-restore.md#disaster-region-recovery-dep-019)).
  Active-active identity writes and globally immediate revocation are not
  advertised; they need a new ADR.

## Alternatives considered

- **Active-active regions**: rejected until a design specifies replication delay,
  signing-key access, residency and revocation semantics (DEP-018).
- **Read replicas for introspection**: rejected; would weaken strict-online mode
  (TEST-035).

## Consequences

- Latency for distant regions is bounded by the distance to the primary.
- Failover to a standby that lags the primary can lose recent revocations; treat a
  lossy failover as a restore and run reconciliation
  ([docs/operations/backup-restore.md](../operations/backup-restore.md)).
- Database unavailability stops issuance, refresh, introspection and
  administration; offline-verified JWTs keep working until expiry.
- Recovery point and recovery time depend on replication lag and on how fast
  the operator fences and promotes; the project does not measure them. Only the
  reconciliation step is tested (`TestRestoreReconciliation`); replication,
  promotion and traffic switching are exercised only in operators' drills.
- Revocation stays bounded by access-token lifetime for offline verifiers in
  every region; short lifetimes, strict-online resources or bounded-state
  verification are the remedies ([revocation-exposure.md](../operations/revocation-exposure.md)).

## Migration implications

A future multi-region design needs a new ADR and must preserve the invariants in
§24.2 and the failure-mode contract in §31.2.

## Related requirement IDs

ARC-005, ARC-006, DEP-010, DEP-011, DEP-018, DEP-019, OPS-007, TEST-035, §31.2
