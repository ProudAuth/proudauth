# API conventions

These rules apply across the ProudAuth custom HTTP API
(`/api/v1/realms/{realm}/...`) and the protocol endpoints under the path-based
issuer (`/realms/{realm}`). The contract is
[`api/openapi/proudauth.yaml`](../../api/openapi/proudauth.yaml), derived from
`internal/httpapi`; `tests/contract` verifies that every registered route is
documented there and nothing else. The normative source is
[docs/plan.md](../plan.md) section 25.

- **Errors.** The error format follows the route class (API-001, API-007):
  - *Protocol endpoints*, every path under `/realms/{realm}/oauth/` and
    `/realms/{realm}/oidc/` (authorization, token, introspection, revocation,
    device authorization, PAR, dynamic client registration, UserInfo, session
    check and logout), return standard OAuth errors (RFC 6749 §5.2,
    `application/json`, schema `OAuthError`): `error` and, when there is
    one, `error_description`, nothing else. This includes the refusals
    decided before the endpoint runs: load shedding and maintenance (`503
    temporarily_unavailable`), a body over `limits.max_body_bytes` (`413
    invalid_request`), a host the host policy does not serve (`421
    invalid_request`) and an unknown realm (`404 invalid_request`). The HTTP
    status is kept; the code is `invalid_request` for 4xx refusals without a
    protocol code of their own, `invalid_token` for 401, `access_denied` for
    403, `slow_down` for 429, `temporarily_unavailable` for 503 and
    `server_error` for other 5xx.
  - *Everything else*, the custom APIs and the issuer's metadata documents
    (discovery, JWKS), returns RFC 9457 problem details
    (`application/problem+json`, schema `Problem`) with a stable `code` and
    the `request_id`. SCIM, the Shared Signals receiver and the container
    registry token endpoint keep their own protocols' formats.
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
- **Throttling.** Every 429 and 503 response includes `Retry-After`, in
  whole seconds, in every error format: the delay the refusal names (a
  budget's remaining window, `5` for a full directory bound, the operator's
  maintenance delay), or 2 seconds when it names none, including
  maintenance with `retry_after_seconds` 0 (`problem.DefaultRetryAfter`,
  `TestRetryAfterOnThrottlingAndUnavailable`, `TestProtocolErrorFormat`).
  A limit that never resets is not a 429: the invitation resend cap is `409
  conflict`.
- **Trust classes and permissions.** `x-trust-class` records the section 25.2
  trust class of each operation; `x-permissions` lists the permissions the server
  checks (any one suffices unless noted). Organization-scoped `org.*` permissions
  are evaluated in the organization named by the path, whose existence is
  concealed (404) from callers without any permission in it.
