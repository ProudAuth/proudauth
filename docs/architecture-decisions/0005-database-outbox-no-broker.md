# 0005. Cache and broker: none required; transactional outbox in PostgreSQL

**Status:** Accepted

## Context

External side effects (email, webhooks, back-channel logout) must not leave
half-created security state, and their triggering changes must not commit without
their audit and outbox records (ARC-003, ARC-004, DB-009). A cache outage must
never become a positive authorization decision (§31.2).

## Decision

- No cache and no message broker are required or supported.
- Mutations write the audit event (`audit_events`) and, where other systems must
  learn about it, an outbox event (`outbox_events`) in the same transaction.
- `identity-worker` claims pending outbox rows with `FOR UPDATE SKIP LOCKED`,
  fans them out into `webhook_deliveries` (unique per subscription and event, so
  re-dispatch is idempotent) and marks them dispatched in one transaction.
- Notification jobs, webhook deliveries, back-channel logout deliveries and jobs
  are separate tables with leases, attempt counters and backoff.
- In-process caches are short and bounded: realm lookups (2 s), signing-key sets
  (5 s), registered CORS origins (5 s). Revocation, session, grant and membership
  checks read PostgreSQL directly, so every node sees them as soon as they
  commit; a compromised signing key is dropped by every node within its 5 s
  key cache (`TestSharedRevocationAcrossNodes`, ARC-005).

## Alternatives considered

- **Redis or similar for sessions and revocation**: rejected; a stale or
  unavailable cache would weaken strict-online checks.
- **Kafka/NATS for events**: rejected as mandatory infrastructure (DEP-001); an
  external sink can be fed from webhooks.

## Consequences

- Delivery is at-least-once. Webhook consumers must deduplicate by `event_id`
  ([docs/integrations/webhooks.md](../integrations/webhooks.md)).
- Without a running worker nothing is delivered and planned key rotation never
  activates the prepublished key.
- Realm suspension is observed by other nodes within the 2 s realm cache, and
  grant-issuing paths re-check realm state in their transaction.

## Migration implications

Introducing an optional cache later requires a declared freshness bound and a
fail-closed policy for privileged and support decisions, plus a new ADR.

## Related requirement IDs

ARC-003, ARC-004, ARC-005, DB-009, DEP-011, EXT-002, EXT-005, §31.2, §37.1
