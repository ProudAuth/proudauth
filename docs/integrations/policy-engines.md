# External policy engines

Requirement: AZ-026. Code: `internal/httpapi/policyengine.go`,
`internal/httpapi/decision.go`, `internal/configuration/config.go`
(`security.policy_engines`), `internal/realm/policy.go` (`policy_engine`).
Test: `TestExternalPolicyEngine` (`tests/e2e/policyengine_test.go`). Design:
[ADR 0013](../architecture-decisions/0013-authorization-model.md#update-2026-10).

An operator can connect an external policy decision point (for example an
Open Policy Agent server, or any service that answers the contract below) to
the decision API (`POST /authorization/check` and `/check-batch`,
[resource-servers.md](resource-servers.md#4-policy-decisions-optional)). The
engine sees the decision ProudAuth made locally and can deny it or, when the
realm allows, decide it. It never changes what ProudAuth itself authorizes
(administration APIs, token issuance); only answers of the decision API.

## Operator configuration

`security.policy_engines` ([configuration.md](../operations/configuration.md#security)):

```yaml
security:
  policy_engines:
    - name: opa
      url: https://opa.internal:8181/v1/data/proudauth/allow
      token: file:/run/secrets/opa-token
      timeout: 1s
```

| Member | Rules |
| --- | --- |
| `name` | Unique, `^[a-z0-9][a-z0-9-]{0,39}$` |
| `url` | Absolute URL with a host and no userinfo; `https` (`http` only outside production) |
| `token` | Required; sent as `Authorization: Bearer <token>`. A secret reference in production; resolved at each call |
| `timeout` | At most `5s`; `0` or omitted means 1 second |

The startup check refuses anything else. Support bundles and
`identity-cli config-diff` show a literal token as `[REDACTED]` and a secret
reference as written ([support-bundle.md](../operations/support-bundle.md)).

Calls go through an egress policy that **allows private addresses** (the
operator chose the destination; unspecified and multicast addresses stay
blocked), requires `https` in production, follows no redirects, uses no
proxy, reads at most 64 KiB and applies `privacy.residency.allowed_destinations`.

## Realm policy

A realm opts in with the realm policy `policy_engine`
(`PUT /api/v1/realms/{realm}/settings` or a configuration import):

```json
"policy_engine": {"name": "opa", "mode": "restrict", "on_error": "deny"}
```

| Member | Values |
| --- | --- |
| `name` | A configured engine; another name is `422` ("no policy engine with this name is configured (security.policy_engines)") |
| `mode` | `restrict` (default): the engine can only deny. `decide`: the engine is also asked when local rules deny, and may allow |
| `on_error` | `deny` (default): an unavailable engine denies. `local`: the local decision stands |

`mode` or `on_error` without `name` is `422`.

## The call

`POST <url>` with `Content-Type: application/json`, the bearer token, and:

```json
{"input": {
  "realm": "main", "organization_id": "org_...",
  "subject": {"type": "user", "id": "usr_..."}, "actor": "svc_...",
  "client_id": "web-bff", "audience": "https://orders.example.com",
  "token_kind": "user_access", "acr": "urn:proudauth:acr:mfa", "auth_time": 1791590390,
  "support_mode": "",
  "action": "orders.refund",
  "resource": {"type": "order", "id": "ord_123", "org_id": "org_..."},
  "context": {"operation_amount_minor": 1500},
  "local": {"allowed": true, "reason_code": "ALLOWED"},
  "time": 1791590400}}
```

`realm` is the realm name; empty members (`organization_id`, `client_id`,
`audience`, `token_kind`, `acr`) and a zero `auth_time` are left out;
`actor` is the token's `act.sub`; `resource.org_id` is the organization the
decision resolved; `resource.project_id` is present when the request named a
(validated) project; `context` is what the caller asserted; times are Unix
seconds. `local` is ProudAuth's own result: `{true, "ALLOWED"}`, or in
`decide` mode after a local denial `{false, "NOT_PERMITTED"}`.

Accepted answers (`200`, JSON):

- `{"allowed": true|false, "reason_code": "...", "obligations": [...], "policy_version": "..."}`;
- the OPA data API forms `{"result": true|false}` or `{"result": {"allowed": ..., ...}}`.

`reason_code` is at most 64 characters and `policy_version` at most 128.
Anything else (another status, a timeout or transport error, more than
64 KiB, invalid JSON, a missing or non-boolean `allowed`, a token reference
that does not resolve, or an engine name no longer configured) makes the
engine **unavailable**, logged as `policy engine unavailable`.

## How it combines with local rules

Local rules are RBAC and relationships
([relationship-authorization.md](relationship-authorization.md)), the
step-up check for privileged permissions, published ABAC policies and, last,
authorization hooks.

| Situation | `restrict` | `decide` |
| --- | --- | --- |
| Local rules allow | Engine asked after RBAC/relationships, step-up and ABAC policies, before hooks. Its denial is the answer (`reason_code` from the engine, default `EXTERNAL_POLICY_DENIED`, with its obligations); its allow adds its obligations | Same |
| Local rules deny (no permission, no relationship) | Engine not called; `NOT_PERMITTED` | Engine asked with `local.allowed: false`. Its allow continues through step-up, ABAC policies and hooks, which can still deny; its denial is final (`EXTERNAL_POLICY_DENIED` by default, without obligations) |
| Engine unavailable | `EXTERNAL_POLICY_UNAVAILABLE`, or the local result with `on_error: local` | Same (after a local denial, `on_error: local` gives `NOT_PERMITTED`) |

The decision's `policy_version` gains `;engine:<name>:<engine policy_version>`
when the engine answered. Decisions in a realm with an engine are **never
cacheable** (`cache_ttl_seconds: 0`, no `cache_key`): ProudAuth cannot know
what the engine's answer depends on.

`list-objects` does not call the engine.

## Trust and limits

- The engine is trusted for what it answers: in `decide` mode it can grant
  any application action in the realm's decision API, including to subjects
  without a role. Use `restrict` unless the engine is the authoritative policy
  for your applications.
- Each decision waits for the engine up to its timeout; batch checks call it
  once per check.
- Requests are authenticated with the bearer token only; the engine must keep
  its endpoint private and verify the token. The input carries subject IDs,
  the token's client and assurance and whatever `context` the calling service
  sent ([data-inventory.md](../operations/data-inventory.md#data-sent-outside-the-deployment)).
- No caching, retries or circuit breaker: an engine that is down is reported
  on every decision.

Threats and mitigations: [system threat model](../threat-models/system.md)
(workers and outbound connections).
