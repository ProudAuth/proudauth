# 0017. Browser integration: external login UI and headless transactions

**Status:** Accepted

## Context

The product delivers no login pages or admin dashboard (§1.2), yet browser
redirects, CSRF defenses and session cookies remain backend responsibilities. A
"headless" API must not become a password-to-token shortcut (§1.2, AUT-003).

## Decision

- The authorization endpoint validates the request, starts a server-side
  authentication transaction and redirects the browser to the configured login UI
  (`clients.login_ui_url`, else realm `interaction.login_ui_url`) with only
  `transaction_id` and `realm` in the URL. The continuation secret is set as an
  HttpOnly cookie `pa_tx`, originally scoped to `/api/v1/realms/{realm}/auth/`
  and since the 2026-10 update to the transaction's own path
  (`/api/v1/realms/{realm}/auth/transactions/{id}`), so concurrent transactions
  in one browser do not overwrite each other (AUT-016).
- The login UI drives `/api/v1/realms/{realm}/auth/transactions/{id}/...` steps.
  Browser callers authenticate steps with the cookie plus an `X-CSRF-Token` derived
  from the continuation and an allowed `Origin` (the public origin or a registered
  client origin). Headless callers (backends, CLIs) start transactions with
  `POST /auth/transactions` and send the continuation in `X-Transaction-Token`.
- Completion yields an authorization code in `redirect_to`; tokens are only
  obtainable by the client with its PKCE verifier at the token endpoint.
- Browser applications are encouraged to use a backend-for-frontend that keeps
  tokens server-side (`examples/backend-for-frontend`, `proudauth-sdk-go/oidcclient`).
- IdP session cookie `pa_sid` (HttpOnly, `Secure` unless
  `sessions.cookie_insecure_dev`, SameSite from `sessions.cookie_same_site`,
  default `lax`) is scoped to `/realms/{realm}/` and enables SSO at the
  authorization endpoint.

## Alternatives considered

- **Bundled hosted login pages**: out of scope by product definition.
- **Token-returning headless login**: rejected (§18.2).

## Consequences

- Each deployment must provide a login UI for browser flows; without one the
  authorization endpoint returns `temporarily_unavailable` and only the headless
  API works.
- The device flow's `verification_uri` is the client's `login_ui_url`, else the
  realm's login UI URL; when neither is set, device authorization requests are
  refused with `invalid_request` (the server has no `/device` page).
- Browser-mode registration uses the transaction-scoped route
  `POST /api/v1/realms/{realm}/auth/transactions/{id}/registration`, which lies
  inside the per-transaction cookie path; the realm-level
  `POST /api/v1/realms/{realm}/registrations` serves headless clients that send
  `X-Transaction-Token`.
- The full step reference is in
  [docs/protocols/headless-authentication.md](../protocols/headless-authentication.md).

## Migration implications

Changing cookie names, paths or the CSRF derivation breaks in-flight transactions
only (10-minute lifetime) but requires login UI updates.

## Related requirement IDs

AUT-001..AUT-008, AUT-016, AUT-020, SES-010, SEC-002, SEC-003, SDK-004, §1.2, §9.1, §28.4
