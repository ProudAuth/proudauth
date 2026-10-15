# API conventions

These rules apply across the ProudAuth custom HTTP API
(`/api/v1/realms/{realm}/...`) and the protocol endpoints under the path-based
issuer (`/realms/{realm}`). The contract is
[`api/openapi/proudauth.yaml`](../../api/openapi/proudauth.yaml), derived from
`internal/httpapi`; `tests/contract` verifies that every registered route is
documented there and nothing else. The normative source is
[docs/plan.md](../plan.md) section 25.

- **Errors.** Custom APIs return RFC 9457 problem details
  (`application/problem+json`, schema `Problem`) with a stable `code` and the
  `request_id`. OAuth/OIDC endpoints return standard OAuth errors (`OAuthError`).
- **Strict JSON.** Request bodies must be `application/json`, are size-bounded,
  and are rejected when they contain duplicate or unknown members
  (`additionalProperties: false`).
- **Authentication.** Bearer tokens only in the `Authorization` header (never
  query strings). 401 for missing/invalid credentials, 403 for
  authenticated-but-disallowed, 404 where existence is concealed.
- **Idempotency.** Every authenticated POST accepts `Idempotency-Key` (24 hours,
  actor/realm/route-bound, matched on the exact path and body). Only successful
  responses are recorded, and responses that carried one-time secrets are never
  replayed.
- **One-time secrets.** Fields marked `x-secret: true` (client secrets, API keys,
  personal tokens, setup tokens, recovery codes, signing secrets, handoff codes,
  download tokens, continuation tokens) are returned exactly once.
- **Concurrency.** Editable resources return a weak `ETag` (`W/"v{version}"`);
  send it in `If-Match`. Stale versions return 412; where `If-Match` is required,
  omitting it returns 428.
- **Pagination.** Cursor-paginated lists accept `cursor` and `limit` and return
  `next_cursor` (empty string on the last page).
- **Correlation.** `X-Request-Id` is accepted (printable ASCII, at most 64
  characters) or generated, and echoed on every response.
- **Throttling.** 429 and 503 responses include `Retry-After`.
- **Trust classes and permissions.** `x-trust-class` records the section 25.2
  trust class of each operation; `x-permissions` lists the permissions the server
  checks (any one suffices unless noted). Organization-scoped `org.*` permissions
  are evaluated in the organization named by the path, whose existence is
  concealed (404) from callers without any permission in it.
