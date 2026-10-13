# 0022. Security-event exchange: an audit-log adapter out, explicit action policies in

**Status:** Accepted

## Context

docs/plan.md asks for a declared shared-signals profile as a separately
tested adapter (AUD-016) and, as a P3 item, for approved inbound event
exchange with source trust, receiver registration, subject mapping, replay
defenses, retention, delivery failure and privacy controls, where incoming
events map to an explicit local action policy (ADV-007). ProudAuth already
records every security-relevant change as an audit event in the same
transaction ([ADR 0005](0005-database-outbox-no-broker.md)) and publishes
webhooks from a transactional outbox. Security events are sensitive: they
reveal account states and sign-in activity to another system, and inbound
events can end sessions or suspend accounts.

## Decision

- **Transmitter as an adapter over the audit log.** CAEP and RISC events are
  derived from audit events by a fixed mapping (`internal/ssf/ssf.go`
  `mapAudit`) and queued in the transaction that records the audit evidence,
  so an event exists exactly when its evidence does. Delivery follows SSF 1.0
  with RFC 8935 push (worker task `ssf.deliver`) and RFC 8936 poll; tokens are
  Security Event Tokens signed with the realm's keys.
- **Opt-in and declared.** Realm policy `shared_signals.enabled` (default
  off) publishes the metadata and stream API. The supported event types and
  delivery methods are listed in the metadata and in
  [shared-signals.md](../integrations/shared-signals.md); nothing else is
  claimed.
- **Receivers are machine clients with a dedicated permission**
  (`realm.ssf_streams.manage`) and receive events only about users who
  authorized them, unless an administrator widens a stream to every user.
- **Inbound events only from registered transmitters**, each with its own
  push secret, keys, issuer, subject mapping and an action policy per event
  type whose default is "record only". The allowed actions per event type are
  fixed in code (`AllowedActions`): outside signals can end sessions, suspend
  ordinary accounts or mark a password compromised, but never re-enable an
  account, change identifiers or suspend a protected account.
- **Push only, inbound.** ProudAuth does not poll remote transmitters and
  does not manage streams at them.

## Alternatives considered

- **Reusing webhooks for security events.** Rejected: webhook payloads are
  ProudAuth's own schema, delivered per subscription without per-user
  scoping, and SSF receivers expect SETs, stream management and subject
  semantics.
- **A message broker between audit and delivery.** Rejected for the same
  reasons as in ADR 0005; the event table and worker leases suffice at the
  expected volume.
- **Open or dynamic transmitter registration, or inbound events with implied
  actions.** Rejected by ADV-007: source trust and every effect must be an
  explicit administrator decision.
- **Polling remote transmitters.** Deferred: it needs outbound credentials
  per transmitter and a scheduler; push covers the transmitters we know of.

## Consequences

- Events cover exactly what the audit log records about users; anything not
  audited (or audited about service principals) produces no event.
- The realm's ordinary signing keys sign SETs; receivers must check `typ`.
- Events are retained for 7 days undelivered and 14 days in total; received
  events are kept 30 days as minimal records. Monitoring relies on the
  worker metrics and the per-stream event view
  ([monitoring.md](../operations/monitoring.md#shared-signals)).
- No conformance suite has been run; interoperability is limited to the
  test receivers and transmitters in this repository
  ([ADR 0020](0020-compliance-posture.md)).

## Migration implications

Migrations `0058_shared_signals` (streams, stream subjects, events) and
`0083_ssf_receiver` (transmitters, received events) are additive. Older
binaries in a mixed-version window neither queue events nor accept pushes;
enable `shared_signals.enabled` and register transmitters only after every
server runs a version that has them.

## Related requirement IDs

AUD-016, ADV-007, AUD-002, SES-017, SES-023, PRV-001, QA-004, QA-006
