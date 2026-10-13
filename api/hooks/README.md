# ProudAuth pre-action hook contract (v1)

Machine-readable [JSON Schema draft 2020-12](https://json-schema.org/draft/2020-12/schema) definitions of the requests ProudAuth sends to synchronous pre-action hooks and of the answers it accepts (EXT-009..EXT-012, EXT-018).

- `<kind>.request.v1.json`: the JSON body ProudAuth POSTs to a hook of that kind.
- `<kind>.response.v1.json`: the JSON body the hook must answer with (HTTP 200).
- `common.v1.json`: shared definitions and the request headers (`x-headers`).

Every schema's `$id` is `https://auth.proudbase.com/schemas/hooks/<file name>`; each one includes `examples`.

| Kind | Request member | Failure behaviour |
| --- | --- | --- |
| `registration.eligibility` | `client_id`, `registration` | fail closed (EXT-012) |
| `profile.validation` | `user_id`, `profile` | fail closed |
| `token.claims` | `token` | fail closed, unless the hook's `failure_mode` is `skip` |
| `authorization.decision` | `decision` | fail closed (deny) |
| `authentication.risk` | `authentication` | the risk signal is missing; flow rules decide |

## Contract versions

The hook contract is versioned independently of webhook event schemas, plugin manifests, workflow definitions and server releases (EXT-018).

- Each hook registration pins `contract_version` (default `1`). Existing hooks keep the version they were created with across server upgrades.
- Every request carries the header `ProudAuth-Hook-Version: <n>`.
- A hook may echo `ProudAuth-Hook-Version` in its response. An echoed value other than the request's makes the response malformed, so the call fails the way the hook kind fails (closed for security decisions). A response without the header is read as the requested version.
- Responses are parsed strictly: unknown members make a response malformed. Request schemas are closed (`additionalProperties: false`): within a contract version a request carries only the members its schema lists, so a hook may validate requests strictly. New request members arrive with a new contract version, which a hook only receives after its `contract_version` is changed.
- An answer outside the bounds the response schemas describe is malformed as a whole: a `token.claims` answer setting a reserved claim, `roles` or `permissions`, a claim name over 64 characters, more than 20 claims or more than 4 KiB of claims; an `authorization.decision` answer with more than five obligations. No answer within the hook's `timeout_ms` fails the same way. The hook's diagnostics show `malformed_response`, `timeout` or `unreachable`.
- A breaking change ships as version 2 with new `.v2.json` files. Hooks opt in by updating `contract_version`; version 1 stays supported for at least 12 months after version 2 is published (`GET /api/v1/realms/{realm}/extension-contracts` lists versions and sunset dates).

## Signature

Requests are signed like webhook deliveries: `Webhook-Signature: v1,<base64 HMAC-SHA256>` over `<Webhook-Id>.<Webhook-Timestamp>.<raw body>`, keyed with the base64-decoded signing secret after its `hksec_` prefix. Reject stale timestamps (5 minutes is a reasonable tolerance) and verify against the raw body bytes.
