# 0008. Interactive protocol: authorization code with PKCE only

**Status:** Accepted

## Context

A backend-only product is tempted to offer a "username and password to token"
endpoint for convenience. RFC 9700 and docs/plan.md §18.2 exclude the password
grant and the implicit flow; TOK-002 requires PKCE `S256` for every
authorization-code client, including confidential ones.

## Decision

- `response_type=code` is the only response type and `response_mode=query` the
  only response mode.
- Every authorization request must carry `code_challenge_method=S256` and a
  43-character base64url challenge. `plain` and missing challenges are rejected.
  The token endpoint verifies a 43–128 character verifier.
- Authorization codes are opaque (`pa_ac_` + 256 random bits), stored as SHA-256
  digests, bound to client, exact redirect URI, PKCE challenge, nonce and
  transaction, valid for `tokens.authorization_code_ttl` (60 s), and consumable
  once. A replayed code revokes the grant it produced.
- Redirect URIs match exactly. The only exception is RFC 8252 native loopback
  (`http://127.0.0.1` or `[::1]`, any port) for `native` and `device` clients.
- `password` and `implicit` are rejected at client registration and at the token
  endpoint (`unsupported_grant_type`). The discovery document does not list them.
- Request objects (`request`) are rejected. The OIDC `claims` parameter was
  rejected at acceptance; since the 2026-10 update it is accepted and validated,
  but it only narrows ID-token and UserInfo release within the granted scopes and
  can raise the assurance requirement through `acr`
  ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#claims-parameter)).
- Interactive authentication itself happens in a server-controlled transaction
  driven by an application-provided UI or the headless API
  ([0017](0017-external-login-ui.md)); its only output is an authorization code.

## Alternatives considered

- **Resource-owner password grant** for first-party apps: rejected (§18.2).
- **Optional PKCE for confidential clients**: rejected (TOK-002).
- **`form_post` response mode**: not implemented; would need its own tests and
  discovery entry.

## Consequences

- Every client, including CLIs, completes a code exchange; the bundled CLI drives
  the headless API with its own PKCE verifier and loopback redirect.
- Clients that require JAR or `form_post` are not supported. JARM was added
  later (ADV-002) as the `query.jwt` / `jwt` response modes of the same code
  flow, with its own tests and discovery entries
  ([response-security.md](../protocols/response-security.md#jarm-adv-002)).

## Migration implications

Adding a response mode or request-object support must be reflected in discovery
only once implemented and tested (APP-020, OIDC-015).

## Related requirement IDs

TOK-001, TOK-002, TOK-003, APP-004, OIDC-001, OIDC-002, AUT-020, TEST-028, TEST-029, §18.1, §18.2
