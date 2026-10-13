# 0001. Product form: modular monolith with worker processes

**Status:** Accepted

## Context

An identity provider's security properties depend on transactional consistency:
one-time proof consumption, refresh rotation, invitation acceptance and
permission changes must not be split across loosely synchronized services
(ARC-002). The project also targets small deployments without a platform team
(DEP-001) and must allow later extraction of modules only when measured need
justifies it (ARC-010).

## Decision

Ship three binaries built from one module (`github.com/proudbase/proudauth`):

- `identity-server` (`cmd/identity-server`): one public HTTP listener
  (`server.public_listen`) serving protocol endpoints (`/realms/{realm}/...`),
  interaction, self-service, tenant and administration APIs
  (`/api/v1/realms/{realm}/...`) and `/health/*`; plus an internal listener
  (`server.internal_listen`) serving `/metrics`, `/health/live` and `/status`.
- `identity-worker` (`cmd/identity-worker`): outbox dispatch, notification,
  webhook and back-channel logout delivery, jobs, signing-key lifecycle, audit
  sealing, expiry and retention. Several workers may run; work is claimed with
  `FOR UPDATE SKIP LOCKED` and leases.
- `identity-cli` (`cmd/identity-cli`): the operator-only channel (migrations,
  realm creation, bootstrap, doctor, audit verification, support bundle,
  revocation log, restore reconciliation) and an API client that authenticates
  like any other OAuth client.

Domain logic lives in `internal/` packages (realm, identity, authentication,
session, oauth, token, authorization, organization, impersonation, machine,
audit, webhooks, notification, jobs, ...) that share a `runtime.Deps` bundle
(database, configuration, clock, keyring, audit recorder, outbox, logger) and call
each other through service types. `server.RegisterModules` exists for optional
modules that add routes and discovery capabilities only when complete.

## Alternatives considered

- **Microservices per domain** (sessions, tokens, users): rejected because
  revocation and one-time consumption would need distributed transactions or
  eventual consistency in security decisions.
- **Single binary that also runs the worker loop**: rejected so that background
  delivery and retention can scale and fail independently of request serving.
- **Separate admin binary/listener**: not adopted. Administration is separated by
  token audience, scope and permission on the same listener; network separation is
  left to the reverse proxy.

## Consequences

- One deployable artifact and one schema; horizontal scaling by adding server and
  worker processes against the same PostgreSQL (ARC-006).
- Public and administrative routes share a listener. Operators who want admin APIs
  unreachable from the Internet must restrict `/api/v1/realms/*/users`,
  `/settings`, `/signing-key*` and similar paths at the proxy.
- The internal listener has no authentication except an optional bearer token for
  `/metrics` and `/status` (`server.metrics_token`); it must be bound to a private
  interface.
- Metrics are per process. The worker has no listener unless
  `workers.metrics_listen` is set; worker-side counters are scrapable only there
  (see [docs/operations/monitoring.md](../operations/monitoring.md)).

## Migration implications

Extracting a module into a separate service later must keep every invariant that
currently relies on a single PostgreSQL transaction (audit + mutation + outbox,
DB-009) or replace it with an equally strong, tested mechanism and a new ADR.

## Related requirement IDs

ARC-001, ARC-002, ARC-003, ARC-006, ARC-010, DEP-001, DEP-011, OPS-012, §5.1, §37.1
