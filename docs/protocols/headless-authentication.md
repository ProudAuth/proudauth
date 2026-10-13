# Headless authentication transactions

Requirements: §9.1 (AUT-001..AUT-020), §27.1, §27.6, SEC-002, SEC-005. Code:
`internal/authentication` (`transaction.go`, `steps.go`, `registration.go`,
`recovery.go`, `webauthn.go`, `federation.go`, `magiclink.go`, `challenges.go`,
`flow.go`),
`internal/httpapi/interaction.go`,
`internal/httpapi/federation.go`.

ProudAuth ships no login pages. Sign-in is a **server-controlled transaction**
that an application-provided login UI (browser) or a backend/CLI (headless) drives
step by step. The only output of a completed transaction is an OAuth authorization
code bound to the client, redirect URI and PKCE challenge; tokens are obtained at the
token endpoint. This API is project-specific and is not an OAuth grant (§9.1).

Base path: `/api/v1/realms/{realm}/auth/transactions`. Request bodies are strict
JSON: `Content-Type: application/json`, unknown fields rejected, duplicate members
rejected, at most 32 levels deep.

## Starting a transaction

| Mode | How it starts | Continuation authority |
| --- | --- | --- |
| **Browser** | The client sends the user to `GET /realms/{realm}/oauth/authorize?...`. The server validates the request, creates the transaction and redirects to the login UI with `?transaction_id=...&realm=...`. | HttpOnly cookie `pa_tx` (path `/api/v1/realms/{realm}/auth/transactions/{id}`, lifetime `tokens.transaction_ttl`), so several transactions in one browser (for example in two tabs) each keep their own cookie (`TestConcurrentBrowserTransactions`). Mutating steps also need an allowed `Origin` and the `X-CSRF-Token` header. |
| **Headless** | `POST /auth/transactions` with the authorization parameters as JSON. | `continuation_token` (`pa_tx_...`) returned once; send it as `X-Transaction-Token` on every call. |

Headless start request (same rules as the authorization endpoint; `prompt=none` is
not allowed here):

```json
{
  "client_id": "web-bff",
  "redirect_uri": "https://app.example.com/callback",
  "scope": "openid orders:read",
  "resource": ["https://orders.example.com"],
  "state": "af0ifjsldkj",
  "nonce": "n-0S6_WzA2Mj",
  "code_challenge": "<43-char base64url S256 challenge>",
  "code_challenge_method": "S256",
  "organization": "acme",
  "login_hint": "alice@example.com",
  "ui_locales": "en",
  "intent": "login"
}
```

Other start fields: `prompt`, `max_age`, `acr_values`, `claims` (the OIDC claims
request as a JSON string; see
[oauth-oidc-profile.md](oauth-oidc-profile.md#claims-parameter)), `request_uri` (a
PAR reference), `intent: "register"`, `device_user_code` (see Device flow), and
`response_mode` (`query`, the default, or `query.jwt`/`jwt`: `redirect_to`
then carries one signed `response` parameter, JARM, ADV-002,
[response-security.md](response-security.md#jarm-adv-002); other values are
`400 invalid_request`).

The transaction stores `login_hint` (at most 254 bytes), `ui_locales` (at most
64 bytes) and the `User-Agent` (at most 256 bytes) shortened to that length on
a UTF-8 character boundary, with invalid UTF-8 sequences removed, so such input
never makes the start fail. The authorization endpoint refuses a `login_hint`
longer than 512 bytes (`invalid_request`).

Response `201`:

```json
{ "transaction_id": "atx_01k7...", "continuation_token": "pa_tx_...", "state": { ... } }
```

**Authority rules (AUT-003):** the transaction ID alone never authorizes anything.
A headless transaction cannot be continued with a cookie, and a browser transaction
step sent with only a cookie but without a valid CSRF token or allowed `Origin` is
rejected with `403`. Allowed origins are `server.public_origin` and the registered
`allowed_origins` of active clients; a missing `Origin` header is rejected.

### Browser specifics

1. The login UI calls `GET /auth/transactions/{id}` with credentials (cookie). The
   response contains `csrf_token`, readable only by an allowed origin through CORS.
2. Each mutating step sends the cookie, `Origin`, and `X-CSRF-Token: <csrf_token>`.
3. On completion the server sets the IdP session cookie `pa_sid` (path
   `/realms/{realm}/`; a browser-session cookie for transient sessions) for later
   SSO and clears `pa_tx`; when a device was remembered it also sets the HttpOnly
   cookie `pa_rd` (path `/api/v1/realms/{realm}/auth/`). The login UI navigates the
   browser to `redirect_to`.

## Transaction state

Every step returns the full state:

```json
{
  "id": "atx_01k7...",
  "status": "pending",
  "expires_at": "2026-10-10T12:10:00Z",
  "intent": "login",
  "client": { "client_id": "web-bff", "name": "Customer web BFF" },
  "next_actions": [
    { "type": "password", "required": false, "fields": ["password"] },
    { "type": "email_otp", "required": false, "fields": ["code"], "options": { "send_required": true } }
  ],
  "completed_factors": [],
  "user": { "display_name": "Alice", "email_hint": "a***@example.com" },
  "locale": "en"
}
```

| Field | Meaning |
| --- | --- |
| `status` | `pending`, `completed`, `cancelled`, `expired`, `failed` |
| `intent` | `login`, `register`, `step_up`, `invitation`, `device` |
| `next_actions` | What the client may do next; `required: true` means it must be done |
| `completed_factors` | Factor types recorded so far (`pwd`, `otp`, `sms`, `magic_link`, `totp`, `hotp`, `recovery`, `hwk`, `swk`, `x509`, `fed`, `fed_mfa`, `anon` for guests) |
| `user` | Shown only after primary authentication; email masked |
| `redirect_to` | On completion: `redirect_uri?code=...&state=...&iss=...`. On cancel or failure: the redirect URI with an `error` |
| `error` | Blocking reason while `status` stays `pending` and `next_actions` is empty (`account_unavailable`, `organization_access_denied`, `no_organization`: the request needs an organization and the user has no active membership, `login_method_not_allowed`, `registration_pending_approval`, `guest_not_permitted`, `authentication_policy_denied`, `connection_not_allowed`: the sign-in used another organization's connection, FED-006), or failure code of a `failed` transaction (`too_many_failures`, `access_denied`) |
| `notice` | Non-terminal condition, e.g. `upstream_unavailable`, `account_conflict` |
| `one_time` | Secrets shown exactly once: `totp` (`secret`, `otpauth_uri`), `recovery_codes`, and for headless clients `remembered_device_token` (browsers get it only as the `pa_rd` cookie) |
| `webauthn` | Passkey ceremony options to pass to the WebAuthn browser API |
| `external_redirect` | Upstream identity provider URL to send the browser to |
| `csrf_token` | Browser mode, `GET` only |
| `locale` | The `ui_locales` value of the authorization request or headless start, as given (at most 64 bytes); omitted when none was sent ([Accessibility metadata](#accessibility-metadata)) |

The server marks factors and requirements complete; client-supplied flags such as
`mfa_passed` are rejected as unknown fields (AUT-004). When the only remaining action
would be `complete`, the server completes the transaction within the same request.

## Next actions and steps

| Action `type` | Step endpoint (`POST .../{id}/...`) | Body |
| --- | --- | --- |
| `identify` | `identify` | `{"identifier": "alice@example.com"}` (email, `+E.164` phone, or username) |
| `password` | `password` | `{"password": "..."}` (optionally also `identifier`) |
| `email_otp` | `otp/send` then `otp/verify` | `{"purpose": "login"}`, then `{"code": "123456"}` |
| `sms_otp` | `otp/send` then `otp/verify` | Same as `email_otp`, offered when the identifier is a phone number (see SMS codes) |
| `magic_link` | `otp/send`, then `magic-link` | `{"purpose": "magic_link"}`; then `{"token": "<secret from the link fragment>"}` (see Magic links) |
| `verify_email` | `otp/send` then `otp/verify` | `{"purpose": "verify_email"}`, then `{"code": "..."}` |
| `verify_contact` | `otp/send` then `otp/verify` | `{"purpose": "verify_contact"}`, then `{"code": "..."}` (see [Verified contact](#verified-contact-aut-018)) |
| `totp` | `totp` | `{"code": "123456"}` |
| `hotp` | `hotp` | `{"code": "123456"}` (counter-based code, MFA-013; see [HOTP](#hotp-counter-based-codes)) |
| `certificate` | `certificate` | `{}`; the certificate comes from the TLS connection or a trusted proxy, so send the step to the mutual-TLS endpoint (X.509 sign-in, PROV-016, [mutual-tls.md](mutual-tls.md#x509-sign-in-prov-016)) |
| `recovery_code` | `recovery-code` | `{"code": "abcde-fghjk-..."}` (session becomes recovery-restricted) |
| `webauthn` | `webauthn/options` then `webauthn/verify` | `{}` → `state.webauthn`; then `{"credential": <PublicKeyCredential JSON>}` |
| `enroll_totp` | `totp/enroll` then `totp/activate` | `{}` → `one_time.totp`; then `{"code": "..."}` → `one_time.recovery_codes` |
| `enroll_webauthn` | `webauthn/registration-options` then `webauthn/register` | `{}` → `state.webauthn`; then `{"credential": ..., "name": "Laptop"}` |
| `update_password` | `password/update` | `{"new_password": "..."}` |
| `accept_terms` | `terms` | `{"version": "<options.version>"}` |
| `complete_profile` | `profile` | `{"fields": {...}}` (only user-editable attributes of the realm's profile schema, realm policy `profile.attributes`; offered while required attributes are missing) |
| `select_organization` | `organization` | `{"organization_id": "org_..."}` (options list only the user's own active memberships) |
| `select_account` | `account` | `{"continue": true}` keeps the signed-in account, `{"continue": false}` signs in as someone else (offered for `prompt=select_account` with a reusable SSO session; `options.current_account` shows the display name and masked email) |
| `cancel_deletion` | `cancel-deletion` | `{}`. The only action of an account whose self-service deletion is pending, once it has completed every factor it needs (see [Pending deletion](#pending-deletion-usr-012)); `options.deletion_scheduled_at` and `options.deletion_requested_at` say when it was requested and when it is due. Cancelling makes the account active and the transaction continues; `cancel` abandons the sign-in and leaves the deletion scheduled |
| `remember_device` | `remember-device` | `{"remember": true}` (optional; offered with the MFA step when realm policy `login.remember_devices` is on, see Remembered devices) |
| `external_redirect` | `federation/start`, then browser round trip, then `resume` | `{"provider": "<connection alias or ID>"}` → `state.external_redirect` |
| `link_account` | sign in to the existing local account (password, passkey, or an emailed code or magic link sent after the link became pending; never an SMS code) in the same transaction, see [Upstream identity providers](#upstream-identity-providers) | — |
| `consent` | `consent` | `{"approve": true, "scopes": ["openid", "orders:read"]}` (subset of requested) |
| `challenge` | `challenge`, after `challenge/send` for an emailed code | `{"provider_response": "<token from the challenge provider's widget>"}` or `{"code": "123456"}`, exactly one (see [Authentication flow policy](#authentication-flow-policy)) |
| `register` | `registration` (or `POST /api/v1/realms/{realm}/registrations` with `transaction_id`) | see Registration |
| — | `remember-me` | `{"remember": true}` (honored only if the client allows remember-me) |
| — | `transient` | `{"transient": true}` requests a transient session: no remember-me, a browser-session `pa_sid` cookie, an absolute lifetime of at most 1 hour, and no refresh token (SES-020): `offline_access` is removed from the granted scopes even when it was requested and consented, so the grant is never offline (`TestOfflineConsentAndTransientSessions`). The same holds for a later authorization that reuses the transient session through SSO, and the token endpoint never mints a refresh token for a grant of a transient session, offline or not |
| — | `guest` | `{}` signs in as a new guest account (realm policy `registration.allow_guests`; see Guest identities) |
| — | `cancel` | `{}` |
| — | `resume` | `{}` re-evaluates after an out-of-band step |

### Evaluation order

0. Account confirmation (`select_account`) when `prompt=select_account` reuses an
   SSO session.
1. Primary authentication: password, email OTP (if `login.email_otp`), magic link
   (if `login.magic_link`, the identifier is an email and a login UI URL is
   configured), SMS code (if `login.sms_otp`, the identifier is a phone number and
   an SMS adapter is configured), passkey (if `login.passkeys` and the passkey
   service is enabled), an X.509 certificate (if `login.certificates`; offered
   before and after `identify`), or an upstream identity provider. If the
   organization requires SSO, only the provider is offered.
2. Email verification for accounts in `pending_verification`.
3. The realm's authentication flow rules, when it has any
   ([below](#authentication-flow-policy)): `deny` stops here, a `challenge`
   is answered before anything else, and `require_mfa` or
   `require_phishing_resistant` raise the MFA requirement of step 4.
4. MFA when required and an authenticator is enrolled: `totp`, `hotp` (only
   while the realm lists `hotp` in `mfa.allowed_factors`), `webauthn`,
   `recovery_code`. A certificate from a `multi_factor` trust anchor already
   counts as the second factor.
   An account in `pending_deletion` stops after this step (and after an MFA
   enrollment the realm requires): its only action is `cancel_deletion`
   ([below](#pending-deletion-usr-012)).
5. Required actions: MFA enrollment (`enroll_totp` and/or `enroll_webauthn`) when
   MFA is required but nothing is enrolled; administrator-set actions
   (`update_password`, `verify_email`, `verify_contact`, `configure_totp`;
   registering a passkey, in the transaction or through self-service, also
   completes `configure_totp`); `accept_terms` when the
   realm has a `terms_version` the user has not accepted; `complete_profile`.
   Completing the transaction records `user.required_actions.completed`
   (category `account`, metadata `actions` and `transaction_id`) listing the
   required actions completed in it.
6. Organization selection when a requested resource requires an organization.
7. Enterprise SSO when the organization's policy requires it.
8. Consent when the client requires it (`consent_mode: required`) or `prompt=consent`,
   unless an existing consent for the client's current terms version, or an
   administrator's pre-authorization, covers the requested scopes (see
   [Consent](#consent)).
9. Completion.

**MFA is required when** the realm sets `mfa.requirement: required`; the user has
TOTP enrolled, or HOTP while the realm allows it; the user holds a privileged realm role or is protected (bootstrap
administrators); the client sets `token_policy.require_mfa`; `acr_values` request
`mfa` or `phishing_resistant`, which includes a requested scope with a
`step_up_acr` or `sensitivity: privileged` (AUT-010,
[oauth-oidc-profile.md](oauth-oidc-profile.md#scope-step-up)); the admin API
audience is requested; or the selected organization's policy sets
`mfa_required`. A requested scope's `max_auth_age_seconds` lowers `max_age`, so
an older SSO session is not reused. Email OTP, SMS codes and magic links
are primary factors and never count as a second factor (PWDLESS-006). When the phishing-resistant profile
applies (realm `mfa.admin_phishing_resistant` for administrators, or an
`acr_values` request), only a user-verified passkey (or a certificate from a
`multi_factor` user trust anchor) satisfies it, also when a flow rule's
`require_mfa` applies; TOTP and HOTP are then not offered.

### HOTP (counter-based codes)

MFA-013, migration `0049`, `TestHOTP` (`tests/e2e/hotp_test.go`). Counter-based
one-time codes (RFC 4226: HMAC-SHA-1, 6 digits, 160-bit secret) are for
hardware tokens that have no clock. They are **opt-in per realm**: offered
only when realm policy `mfa.allowed_factors` lists `hotp` (the default list,
`totp`, `webauthn`, `recovery_code`, does not). Realm policy `mfa.hotp` (set
with `PUT /settings` or in a configuration document's `policy`, where the
schema describes it too):

| Member | Default | Rules |
| --- | --- | --- |
| `look_ahead` | `0` (= 10) | 0–50: how many counters past the stored one a sign-in code may be |
| `resync_window` | `0` (= 100) | 0, or the effective `look_ahead` up to 1000: how far a resynchronization may search |

Self-service (account-audience token, paths under `/api/v1/realms/{realm}/me`;
each needs recent authentication):

| Request | Effect |
| --- | --- |
| `POST /hotp/enroll` | `201 {"credential_id", "secret", "otpauth_uri", "counter": 0, "expires_at"}`: an `otpauth://hotp/...` URI with `counter=0`, valid 15 minutes. `409` when the realm does not allow `hotp`. When the account already has a second factor the realm allows, the session must have proved one (MFA-006, `403 step_up_required`) |
| `POST /hotp/activate {"code"}` | Accepts a code within `look_ahead` counters of 0, activates the token (replacing an active HOTP; one per account), removes the required action `configure_totp`, and returns `{"status": "hotp_enrolled"}` plus `recovery_codes` once, only when the account had none. A recovery-restricted session may enroll and activate HOTP like TOTP (MFA-010): activation lifts the restriction on the session and returns the account to `active` |
| `POST /hotp/resync {"code", "next_code"}` | For a token pressed too often: two **consecutive** codes, the first within `resync_window` counters of the stored one; the counter only moves forward. Needs a session that completed MFA with another factor (a recovery code, TOTP or a passkey), as regenerating recovery codes does (`403 mfa_required` with a `reauthenticate` obligation for `mfa`; a recovery-restricted session gets `403 recovery_restricted`). At most 5 attempts per 15 minutes per account (every attempt counts; the limit fails closed). A single code that far ahead is never accepted |
| `DELETE /hotp` | Removes the token and forgets the account's remembered devices; `409 last_sign_in_method` when it is the last second factor of an account that must use MFA (only factors the realm allows count as remaining). It works also after the realm stopped listing `hotp`, and such a token can always be removed (it satisfies nothing) |

At sign-in the action `hotp` (`{"code"}`, `POST .../{id}/hotp`) is offered
wherever `totp` is, except under the phishing-resistant profile. A code within
`look_ahead` counters of the stored counter is accepted once: the token's row
is locked and the counter is moved past the code with a conditional update,
so concurrent submissions of one code succeed once. A wrong code is
`400 invalid_proof` and counts like any failed proof. The session factor
`hotp` is a second factor: `amr` contains `hotp` and `mfa`, `acr` is
`urn:proudauth:acr:mfa`, it restores a recovery-restricted account, and it
allows remembering the device. An enrolled HOTP makes MFA required like TOTP.
When a realm stops listing `hotp`, HOTP is neither offered nor required and
satisfies nothing (MFA-005): such accounts sign in single-factor unless
something else requires MFA. It is not an enrolled factor anywhere else
either, like a TOTP the realm does not allow: adding another factor
(MFA-006) and changing the password (CRED-006) do not ask to prove it, and
the last-factor guard does not count it as a remaining factor.

An administrator's factor reset (assisted recovery with `reset_mfa`) revokes
HOTP too. The realm data export's `credentials` summary has `hotp`. Audit:
`mfa.hotp.enrollment_started`, `.enrolled`, `.proof_failed` (activation),
`.used`, `.failed` (sign-in), `.resynchronized`, `.resync_failed`, `.removed`.
`identity-cli login` prompts for an HOTP code; user imports do not carry HOTP
tokens (users enroll again).

### Verified contact (AUT-018)

An administrator can make a user confirm their contact address at the next
sign-in with the required action `verify_contact`
(`POST /users/{user}/required-actions`, bulk operations or `POST /users`;
setting or removing it needs `realm.users.write` besides
`realm.users.required_actions`). It is offered as
`{"type": "verify_contact", "required": true, "fields": ["code"],
"options": {"send_purpose": "verify_contact", "identifier": "<masked email>"}}`
after primary authentication:

1. `POST .../{id}/otp/send {"purpose": "verify_contact"}` emails a code to
   the account's primary email address, even when it is already verified.
2. `POST .../{id}/otp/verify {"code": "..."}` confirms it, removes
   `verify_contact` (and `verify_email`) from the account and lists it in
   `user.required_actions.completed`; `user.identifier.verified` is recorded.

The address's `verified_at` is set only when it was not verified before; a
re-confirmation leaves the earlier time. An account without a primary email
address cannot complete the action (`otp/send` answers `409 unexpected_step`),
so its sign-in stays blocked until an administrator removes the action:
use it only for accounts with an email address.

### Remembered devices

When realm policy sets `login.remember_devices` (lifetime
`login.remember_device_days`, 1–90, default 30), the MFA step offers an optional
`remember_device` action (AUT-013, `internal/authentication/devices.go`):

- If the user opts in and completes a genuine second factor (TOTP, HOTP, passkey or
  trusted upstream MFA) in that transaction, completion creates a remembered
  device: a random bearer secret, stored only as a digest. Browsers receive it as
  the HttpOnly `pa_rd` cookie; headless clients receive it once in
  `one_time.remembered_device_token` and send it back as `X-Remembered-Device`.
- A later transaction presenting a valid secret for the same user may skip the
  MFA prompt. It never does for privileged or protected accounts, the
  phishing-resistant profile, clients with `token_policy.require_mfa`,
  `acr_values` asking for `mfa` or `phishing_resistant`, `prompt=login` or
  `max_age` (including those added by scopes with a step-up policy). A remembered device adds no factor: the session is single-factor,
  so resources and permissions that require MFA still demand a step-up.
- Users list and revoke their devices at `/me/remembered-devices`; devices are
  also revoked whenever all of a user's sessions are revoked (for example by a
  password reset or an administrator's `revoke-sessions`). Tested by
  `TestRememberedDevices`.

### Pending deletion (USR-012)

A self-service deletion request (`POST /me/deletion-request`, recent
authentication, no sole ownerships or owned objects) puts the account in
`pending_deletion` for `privacy.deletion_grace_period` (default 14 days),
revokes every session and grant, offline ones included, and queues the
mandatory `deletion_scheduled` notice ("sign in and cancel the request")
to the verified primary email in the same database transaction. The account
then holds no session and none is created for it, so `DELETE
/me/deletion-request` cannot be reached; the owner cancels while signing in
(`internal/authentication/deletion.go`):

- Sign-in works as usual: password, passkey, emailed code, magic link,
  certificate or upstream provider, then every factor the account would
  normally need (TOTP, HOTP, passkey or recovery code; a required MFA
  enrollment first). A wrong or missing factor never reaches the next point.
- Once they are done, the state's only action is `cancel_deletion`, with
  `options.deletion_scheduled_at` and `options.deletion_requested_at`.
  Nothing is issued: no session, cookie, authorization code or token, and
  other steps cannot complete the transaction.
- `POST .../{id}/cancel-deletion` with `{}` cancels the deletion (audit
  `user.deletion.cancelled`, metadata `via: sign_in`); the account is active
  again and the same transaction continues through the remaining steps
  (required actions, organization, consent) to its normal completion. The
  sessions and grants the request revoked stay revoked.
- `cancel`, or letting the transaction expire, changes nothing: the worker
  erases the account once `deletion_scheduled_at` has passed, after which
  sign-in fails like for an unknown account.

Tested by `TestDeletionCancelAtSignIn` and `TestDeletionCompletesWithoutCancel`.

### Consent

APP-013, migration `0029`, `internal/authentication/consent.go`,
`TestConsentManagement`. The `consent` action lists the requested scopes
(`options.scopes`: `name`, `description` from the scope's consent text,
`sensitivity`) and, when the client sets one, `options.terms_version`. Approving
records one live consent per user and client with the granted scopes, the
resources and that terms version, replacing the previous one.

- **Coverage.** Consent is needed for clients with `consent_mode: required`,
  for `prompt=consent`, and when a third-party client (not `first_party`) that
  is allowed offline access requests `offline_access`. Except with
  `prompt=consent`, which always asks, a live consent covers the request when it
  includes every requested scope and was given for the client's current
  `consent_terms_version`. A new version therefore asks again; grants made under
  the old one are not revoked.
- **Pre-authorization.** An administrator with `realm.clients.write` consents on
  behalf of the realm or one organization:
  `POST /api/v1/realms/{realm}/clients/{client}/consent-preauthorizations
  {"scopes": [...], "organization_id": "org_...", "reason": "..."}` (`scopes`:
  1–50 existing scopes, never `offline_access`; `reason` at least 5 characters;
  `organization_id` optional). It is bound to the client's current terms version.
  A transaction for that organization (selected or requested), or any
  transaction for a realm-wide one, is not asked when a pre-authorization covers
  every requested scope, unless it uses `prompt=consent` or needs the user's own
  consent for `offline_access`; for clients with `consent_mode: required`,
  completion then records a consent with `mode: preauthorized` and its
  `preauthorization_id` when the user has no live consent. `GET` on the same path
  (`realm.clients.read`) lists the client's pre-authorizations, and
  `DELETE .../consent-preauthorizations/{id}` revokes one together with every
  consent based on it and the client's grants for those users. Audited
  `consent.preauthorized` and `consent.preauthorization_revoked` (category
  `configuration`).
- **Viewing and revoking.** Users list their consents with `GET /me/consents`
  and administrators with `GET /users/{user}/consents` (`realm.users.read`);
  `?history=true` adds revoked consents. Items carry `id`, `client`, `client_id`,
  `client_name`, `scopes`, `resource_ids`, `terms_version`, `mode` (`user` or
  `preauthorized`), `preauthorization_id`, `granted_at` and `revoked_at`.
  `DELETE /me/consents/{id}` and `DELETE /users/{user}/consents/{id}`
  (`realm.users.write`) revoke a consent and the client's grants for the user
  (audit `consent.revoked`).

## Authentication flow policy

AUT-012, AUT-014, SEC-014, migration `0040`, `internal/authentication/flow.go`,
`TestAuthenticationFlowPolicy`. A realm can make sign-in depend on its
context: an ordered list of up to 50 rules in realm policy
`authentication_flow`, set with `PUT /api/v1/realms/{realm}/settings`
(`realm.settings.write`, `If-Match`) or a configuration import, and validated
there (`422 validation_failed`, field paths such as
`authentication_flow.rules[0].outcome`). Every change to the flow is also
recorded as a numbered revision, a change in which an earlier, weaker rule
makes a stricter one unreachable is refused, and drafts can be analysed,
simulated, published and rolled back through
`/authentication-flow/revisions` (AUT-019,
[authentication-flows.md](authentication-flows.md)).

```json
"authentication_flow": {
  "rules": [
    {"name": "high risk", "when": {"risk_at_least": "high"}, "outcome": "deny", "on_missing_signal": "skip"},
    {"name": "admins off the office network", "when": {"privileged": true, "outside_networks": ["198.51.100.0/24"]},
     "outcome": "require_phishing_resistant"},
    {"name": "new device on the web app", "when": {"new_device": true, "clients": ["web-bff"]}, "outcome": "challenge"},
    {"name": "repeated failures", "when": {"failed_attempts_at_least": 5}, "outcome": "review"}
  ],
  "challenge_provider": "bot-check",
  "email_code_alternative": true
}
```

| Member | Rules |
| --- | --- |
| `rules[].name` | Required, unique, at most 100 characters; recorded with each decision |
| `rules[].when` | Conditions that must all hold; an empty `when` matches every sign-in (below) |
| `rules[].outcome` | `allow`, `require_mfa`, `require_phishing_resistant`, `challenge`, `review` or `deny` |
| `rules[].on_missing_signal` | `apply` (default) or `skip`: what a rule does when a signal it needs is unavailable |
| `challenge_provider` | Name of an operator-configured provider (`security.challenge_providers`, [configuration.md](../operations/configuration.md#security)); a name the deployment does not configure is refused. Optional |
| `email_code_alternative` | Default `true`: a `challenge` can also be answered with a code sent to the account's verified primary email address |

| Condition | Matches when |
| --- | --- |
| `clients` | The OAuth `client_id` is listed |
| `organizations` | The selected or requested organization ID is listed |
| `methods` | The primary method used: `password`, `passkey`, `email_otp`, `magic_link`, `sms_otp`, `sso` (an upstream provider) or `certificate` (X.509 sign-in) |
| `resources` | A requested resource audience is listed |
| `networks`, `outside_networks` | The client address recorded when the transaction started is inside one of the CIDRs, or inside none of them |
| `new_device` | `true`: the browser or client presented no valid remembered-device secret for the account; `false`: it did |
| `failed_attempts_at_least` | The account had at least this many failed sign-in attempts in the last hour (1–1000; audit events `authentication.*` with outcome `failure` about the account, such as wrong passwords and failed challenges) |
| `risk_at_least` | `authentication.risk` hooks report at least `low`, `medium` or `high` ([below](#risk-hooks)) |
| `privileged` | `true`: the account is protected or holds a privileged realm role; `false`: it does not |
| `assurance_below` | The factors completed so far give an `acr` below `urn:proudauth:acr:mfa` or `urn:proudauth:acr:phishing_resistant` |

Each list holds at most 50 entries; client, organization and resource
values are not checked for existence.

**Evaluation.** The rules are evaluated once the account is known (after
the primary factor, or when an SSO session is reused) and the decision is
kept in the transaction: it is re-evaluated only when the organization
changes (for example after `select_organization`) or the realm policy
revision changes. A challenge already answered in the transaction stays
answered after such a re-evaluation (an emailed challenge code that was sent
but not yet used is dropped; send a new one). A `GET` of the transaction that
re-evaluates stores the new decision, so polling does not call risk hooks
again. The first rule whose conditions all hold decides; when no
rule matches, the outcome is `allow`. An `allow` outcome only stops the
evaluation of later rules: every other requirement (MFA, organization policy,
required actions) still applies. A signal is **missing** when no risk hook is
active, a risk hook fails or answers outside its contract, or the client
address is unknown. A rule that needs a missing signal applies its outcome as
if the condition held, unless it says `on_missing_signal: skip`; an `allow`
rule never applies on a missing signal, so a missing signal never satisfies a
stricter policy. Every decision is audited as `authentication.flow.evaluated`
(category `security`; outcome `denied` for `deny`) with `outcome`, `rule`,
`policy_revision`, `transaction_id`, the signals consulted (`known_device`,
`failed_attempts`, `risk`, `risk_reasons`) and `missing_signals`.

| Outcome | Effect |
| --- | --- |
| `allow` | None beyond stopping rule evaluation |
| `require_mfa` | A second factor in this transaction (or in the SSO session it reuses) is required; a remembered device does not count. Accounts without one enroll TOTP or a passkey in the transaction. A phishing-resistant requirement already in force is not weakened |
| `require_phishing_resistant` | Only a user-verified passkey satisfies the transaction; accounts without a passkey must enroll one. When passkeys are not enabled the transaction stops with `authentication_policy_denied` |
| `challenge` | The `challenge` next action ([below](#challenges)) must be answered before MFA and required actions: factor enrollment in the transaction is not offered until it is, so a holder of only the first factor cannot answer it with a factor of their own making. A second factor already enrolled (a passkey, or TOTP outside the phishing-resistant profile) also answers it; a remembered device does not. A recovery code is not offered while a challenge is pending, but the `recovery-code` step still accepts an unused code, which answers the challenge and makes the session recovery-restricted. With no way to answer, the transaction stops with `authentication_policy_denied` |
| `review` | The sign-in proceeds; the decision raises the security signal `authentication_review`, published as a `security.alert` webhook event ([monitoring.md](../operations/monitoring.md#security-alerts)) |
| `deny` | The transaction stops with `error: "authentication_policy_denied"`, `status` stays `pending` and `next_actions` is empty; cancel it and inform the user. The client receives no error redirect |

### Challenges

While a challenge is pending, `next_actions` offers:

```json
{"type": "challenge", "required": true, "fields": ["provider_response", "code"],
 "options": {"provider": {"name": "bot-check", "site_key": "6Lc..."},
             "email_code": {"send_required": true}}}
```

`provider` appears when the realm names a provider that the deployment
configures, `email_code` when `email_code_alternative` is on and the account's
primary email address is verified (`send_required` is `true` until a code was
sent); the code is sent only to that address. A `webauthn` action is added
when the account has a passkey (required only when no `challenge` option
exists; `webauthn/options` is accepted while the challenge is pending), and an
optional `totp` (or `hotp`) action when it has TOTP (or an allowed HOTP) and the phishing-resistant profile does
not apply. `enroll_totp`, `enroll_webauthn` and `remember_device` are not
offered until the challenge is answered.

| Step (`POST .../{id}/...`) | Body | Result |
| --- | --- | --- |
| `challenge/send` | `{}` | Emails a 6-digit code (template `login_code`, valid `tokens.challenge_ttl`) to the verified primary address; `409 unexpected_step` without one or when the alternative is off. Send budgets and the 30-second cooldown apply (`429`) |
| `challenge` | `{"provider_response": "..."}` or `{"code": "..."}` | The provider's answer is verified with the provider (`security.challenge_providers`); the code against the last one sent. A wrong answer is `400 invalid_proof` and counts toward the transaction's failure limit; both or neither member is `422 validation_failed`; `409 unexpected_step` when no challenge is pending or the chosen answer is not offered; `503 unavailable` when the provider cannot be reached or answers outside its contract (not counted as a failure; the `detail` suggests the emailed code only when that option is offered to the account, otherwise "try again later") |

Answers are audited as `authentication.challenge.passed` (with the rule) or
`authentication.challenge.failed`, metadata `method` (`provider` or
`email_code`). The provider is called only to verify an answer: no provider
is built in, and none is contacted unless the operator configures it and the
realm names it. The client address is sent to it only with `send_remote_ip`.
The emailed code, passkeys and TOTP are the alternatives for users who cannot
complete the provider's challenge. The provider is called outside any database
transaction: the transaction's continuation proof and the pending challenge
are checked first, then the provider is asked, and its answer is applied in
the step's own transaction, so no database lock is held while the provider
answers.

### Risk hooks

A pre-action hook of kind `authentication.risk` (`POST /hooks`, timeout
100–5000 ms) is called only when a rule reaches a `risk_at_least` condition,
at most once per decision. It receives a signed request (like other hooks) with

```json
{"hook_kind": "authentication.risk", "realm_id": "rlm_...",
 "authentication": {"user_id": "usr_...", "client_id": "web-bff", "organization_id": "org_...",
                    "method": "password", "network": "203.0.113.0/24", "known_device": false, "failed_attempts": 2}}
```

(`network` is the client address reduced to /24 or /48) and must answer `200`
with exactly `{"level": "low" | "medium" | "high", "reasons": ["..."]}`. The
highest level of all active risk hooks counts (every active hook is called,
also after one fails); up to 10 distinct reasons of
at most 64 characters are kept (longer ones are dropped). A hook that fails,
times out or answers anything else never blocks by itself: when all hooks
fail, the signal is missing; when some answer, their highest level is a lower
bound, which satisfies a `risk_at_least` at or below it and is otherwise
treated as missing (recorded as `risk: "at_least_<level>"`).

Like every hook, a risk hook speaks the version of the hook contract it was
registered with (`contract_version`, default and only version `1`), sent as
the `ProudAuth-Hook-Version` request header; a response that echoes another
version counts as a failed answer. The request and response bodies of every
hook kind are published as JSON Schemas in
[api/hooks](../../api/hooks/README.md)
([extension-contracts.md](../integrations/extension-contracts.md#hook-contract)).

## Errors

Custom-API errors are RFC 9457 problem details (`application/problem+json`) with a
stable `code` and `request_id`:

| Status | `code` | When |
| --- | --- | --- |
| 400 | `transaction_invalid` | Unknown ID, wrong continuation, mode mismatch, transaction no longer pending |
| 410 | `transaction_expired` | Past `expires_at`; start again |
| 401 | `invalid_credentials` | Wrong password, or the account cannot sign in (indistinguishable) |
| 400 | `invalid_proof` | Wrong, expired or reused code; failed passkey ceremony |
| 409 | `unexpected_step` | Step not currently offered |
| 403 | `forbidden` | Browser CSRF/origin failure |
| 403 | `account_unavailable` | The step that would complete sign-in found the account no longer able to authenticate (suspended, locked or deactivated while the transaction was pending); until then the same condition is the state's `error` |
| 422 | `validation_failed` | Malformed field (`errors` map lists fields) |
| 422 | `password_policy` | New password rejected; `policy_code` is `too_short`, `too_long`, `compromised`, `repetitive`, `contains_identifier` or `invalid_encoding` |
| 429 | `rate_limited` | Budget exhausted, temporary password lock, or the deployment's daily SMS budget; honor `Retry-After` |
| 404 | `feature_disabled` | Passkeys or federation not enabled |
| 503 | `unavailable` | A challenge provider could not verify the answer (see [Challenges](#challenges)) |
| 503 | `upstream_unavailable` | The password of an account an LDAP or Active Directory connector sources could not be checked: the directory is unreachable, or its connector or the directory module is disabled; also first sign-in provisioning when a directory is unreachable. Honor `Retry-After` (30 s); there is no fallback to a local password ([directory.md](../integrations/directory.md#sign-in-with-directory-passwords)) |

Proof failures (wrong password, code, TOTP, HOTP, recovery code, passkey, refused certificate, challenge answer) are counted per
transaction; after **5** the transaction becomes `failed` with
`error: "too_many_failures"`, and `redirect_to` carries an error for the client.
Budgets also apply across transactions per identifier, IP, client and subject,
and every proof attempt also counts against realm-wide, per-client and (when
the request named an organization) per-organization budgets (REG-012); an
exhausted budget answers `429 rate_limited` and does not count as a failure
([configuration.md](../operations/configuration.md#security)).

### Enumeration resistance

- `identify` accepts any syntactically valid identifier; nothing reveals whether an
  account exists. An email address whose domain an active organization verified
  selects that organization when the request named none, and routes to its
  connection when the organization requires SSO; this depends only on the
  domain's routing configuration (exact domain first, then the longest parent
  domain with `include_subdomains`, TEN-011), never on the account
  ([identifiers.md](identifiers.md#organization-slugs-and-domains)).
- A wrong password and a non-existent or suspended account produce the same
  `invalid_credentials`, padded to at least `security.min_auth_response`, with a
  full-cost dummy hash for unknown accounts.
- `otp/send` with `purpose: login` behaves identically for unknown addresses (a
  challenge is created; nothing is sent).
- Registration with an address that already belongs to a verified account returns
  the same response as a new address and emails the existing owner instead.
- Password-reset requests always return `202` with a `reset_id`.

## Accessibility metadata

NFR-009. The transaction API gives a login UI what it needs to present each
step accessibly; it does not render anything itself, and backend delivery
does not make a frontend accessible or certify it.

- **Language.** `locale` in the transaction state repeats the `ui_locales`
  value the client sent (as given, at most 64 bytes; ProudAuth neither
  validates nor negotiates it), so the UI can set its language tag. Messages
  ProudAuth sends during the transaction, such as emailed codes, use the same
  value as their locale: each tag of the space-separated list is tried in
  order, followed by its base language (at most five tags), before English,
  so `ui_locales=fr-CA es` gets the Spanish template when no French one exists
  ([0016-delivery-adapters.md](../architecture-decisions/0016-delivery-adapters.md)).
- **Machine-readable requirements.** `next_actions` lists every possible next
  step with its `type`, whether it is `required`, the input `fields` it takes
  and `options` (for example `send_required`, the challenge provider's
  `site_key`, the scopes of a consent with their descriptions). The UI decides
  how to present them; no prose or markup comes from the server.
- **Alternatives.** Steps that some users cannot complete come with
  alternatives where the policy allows: an emailed code instead of a
  challenge provider's puzzle, passkeys or TOTP, magic links or codes instead
  of passwords.
- **Stable codes.** Blocking reasons in `error`, conditions in `notice`, and
  problem `code` values (with field names in `errors`) are stable identifiers
  ([Errors](#errors)); map them to your own localized, accessible messages
  rather than showing `detail` texts, which are English and may change.

## Magic links

Offered as `magic_link` when the realm policy enables `login.magic_link`, the
identifier is an email address and a login UI URL is known (the client's
`login_ui_url`, else the realm's `interaction.login_ui_url`).

1. `POST .../{id}/otp/send {"purpose": "magic_link"}`. If an active account owns the
   address, it receives a link to the login UI:
   `<login UI>?transaction_id=atx_...#magic_link=<secret>`. The response is the same
   when no account exists.
2. The login UI reads the secret from the URL **fragment** (never sent to a server,
   so link scanners cannot consume it), asks the user to confirm, and posts it with
   the transaction's continuation: `POST .../{id}/magic-link {"token": "..."}`.

The link is single-use, valid 10 minutes, allows 3 attempts and is bound to the
transaction that requested it. A link opened in a browser that does not hold the
transaction's continuation cannot complete sign-in; there is no cross-device mode.
A link presented to a different transaction is consumed and rejected.

## SMS codes

Offered as `sms_otp` when realm policy enables `login.sms_otp`, the identifier is a
`+E.164` phone number and the deployment configures `delivery.sms`
([configuration.md](../operations/configuration.md#delivery)). The flow is that of
`email_otp`. Numbers outside `delivery.sms.allowed_countries` get
`validation_failed` (`phone`) whether or not an account exists; the deployment-wide
`delivery.sms.daily_budget` returns `429` when exhausted, also with the same body
and `Retry-After` whether or not an account exists: both are checked before the
number is looked up (API-009). SMS codes are a primary
factor (`amr` `sms`; on their own `acr` is `urn:proudauth:acr:single_factor`), never MFA. Enabling `login.sms_otp`
requires the realm policy to set `login.sms_risk_accepted: true` as an explicit
acknowledgement of SIM-swap and delivery risks (PWDLESS-005); otherwise the policy
update is rejected.

## Completion

On completion, in one database transaction, the server creates or reuses the IdP
session (a new session handle is issued after authentication, AUT-007), records
consent, creates the authorization grant, issues the authorization code (60 s),
records the client session, writes the `authentication.succeeded` audit event and
the `user.signed_in` outbox event, and optionally queues a new-login notification.

- Headless clients read `code` from `redirect_to` without following it and redeem
  it at `POST /realms/{realm}/oauth/token` with their `code_verifier`.
- Browser clients navigate to `redirect_to`; the application backend redeems the
  code.

## Registration

1. Start a transaction with `intent: "register"` (or `prompt=create`), or use a fresh
   login transaction before any identifier was submitted.
2. Submit the registration with the continuation. Browser login UIs call
   `POST /api/v1/realms/{realm}/auth/transactions/{id}/registration` (cookie +
   CSRF + Origin, like every other step; `pa_tx` is scoped to this path).
   Headless clients may use the same route with `X-Transaction-Token`, or
   `POST /api/v1/realms/{realm}/registrations` with `transaction_id` in the body
   (the transaction-scoped route takes the same body without `transaction_id`):

   ```json
   { "transaction_id": "atx_...", "email": "frank@example.com", "password": "...",
     "username": "frank", "given_name": "Frank", "family_name": "F.", "display_name": "Frank",
     "locale": "en", "terms_version": "2026-10", "profile": {},
     "organization": { "slug": "newco", "display_name": "NewCo" },
     "invitation": "pa_inv_..." }
   ```

3. The realm's registration mode is enforced first (`public`, `closed`,
   `invitation_only`, `domain_restricted` with allowed domains). A verification
   code is emailed; continue with `otp/verify`.
4. After verification and any remaining requirements, the transaction completes. If
   `organization` was given and the realm allows organization creation, the
   organization and the owner membership are created exactly once. An invitation
   addressed to the registered email is accepted at the same time (INV-006).

**Approval queue (REG-008).** When realm policy sets
`registration.require_approval`, a registration without an invitation is queued in
`registration_approvals`, and so are accounts created just in time by an upstream
identity provider (`TestFederation`) and guest accounts upgraded to registered
ones (see Guest identities). After email verification and the other requirements the
transaction stops with `error: "registration_pending_approval"` (and so does every
later sign-in) until a reviewer with `realm.registrations.review` approves it:
`GET /api/v1/realms/{realm}/registration-approvals?state=pending` lists the queue
(masked email), and `POST .../registration-approvals/{id}/decision`
`{"approve": true|false, "reason": "..."}` decides. Applicants cannot review their
own registration. The applicant's verified address receives the decision either
way, and a denied account is suspended. Requests not decided within 14 days
expire (worker task `registration.approvals_expiry`, hourly) and the account is
suspended, never approved (`TestRegistrationApprovalQueue`).

Unverified registrations are deleted after
`lifecycle.unverified_account_ttl_hours` (realm policy, default 72 h) by the
worker task `lifecycle.users`
([data-inventory.md](../operations/data-inventory.md#account-lifecycle-jobs)).

## Guest identities

When realm policy sets `registration.allow_guests` (REG-010,
`internal/authentication/guest.go`), a login transaction that has not identified
anyone accepts `POST .../{id}/guest` with `{}`. It creates a guest account (no
identifier, no credential) under the sign-up budgets (`signup_per_ip`,
`signup_per_client`, `signup_per_realm`) and records the factor `anon`; the
session's `acr` is `urn:proudauth:acr:anonymous`, the lowest assurance. The step is
not listed in `next_actions`; offer it only when the realm allows guests
(otherwise it returns `409 unexpected_step`).

Guests are low-privilege: they cannot join organizations or hold role assignments,
and a transaction that requires MFA (see "MFA is required when" above, for example
the admin API audience or a realm with `mfa.requirement: required`) or a resource
that requires an organization stops with `error: "guest_not_permitted"`.

A guest becomes a registered account in place, keeping its user ID:

1. With an account-audience token, `POST /api/v1/realms/{realm}/me/upgrade`
   `{"email": "...", "password": "..."}` sets the password (password policy
   applies) and adds the address unverified → `202 {"status": "verify_email",
   "identifier_id": "..."}`.
2. `POST /api/v1/realms/{realm}/verification-challenges {"identifier_id": "..."}`
   emails a code (`201 {"challenge_id": "..."}`);
   `POST .../verification-challenges/{challenge_id}/consume {"code": "..."}`
   verifies the address, and the account stops being a guest once it has a
   verified email and an active password.

An upgrade is a registration, checked in step 1 before anything changes:

- the realm's `registration.mode` applies: `closed` and `invitation_only` refuse
  every upgrade, and `domain_restricted` refuses addresses outside
  `registration.allowed_domains` (`403`);
- the registration mode of the organization the address's domain routes to
  (verified domain discovery) applies as for self-registration;
- registration-eligibility hooks are called with `guest_upgrade: true` (and
  `invited: false`) and can refuse it.

A refused upgrade leaves the account a guest. In realms with
`registration.require_approval`, completing the upgrade (step 2) queues the
account for review and ends its sessions; sign-in then stops with
`registration_pending_approval` until a reviewer approves it, exactly like a
self-registration (REG-008).

An address another account has already verified cannot be verified again, so an
upgrade never links to or merges with an existing account, and guest accounts
cannot take part in an administrator account merge (`TestGuestIdentities`).
Guest accounts that are not used for `lifecycle.guest_ttl_days` (realm policy,
default 30) are deleted by the worker task `lifecycle.users`.

## Password reset

Outside transactions:

1. `POST /api/v1/realms/{realm}/password-resets {"identifier": "...", "locale": "en"}`
   → `202 {"reset_id": "...", "message": "..."}` for every input. A code is sent only
   to a verified email of an existing account.
2. `POST /api/v1/realms/{realm}/password-resets/complete {"reset_id": "...", "code": "...", "new_password": "..."}`
   → `{"status": "password_reset", "mfa_unchanged": true}`.

Completion consumes the code once, applies the password policy, revokes all
sessions and grants of the user, and **does not remove MFA**: the next sign-in still
requires the enrolled second factor (CRED-007, TEST-070).

## Account setup tokens

Administrator-created accounts (`POST /users`) and the bootstrap administrator
receive a one-time setup token (emailed, or returned once to the operator).
`POST /api/v1/realms/{realm}/account-setup {"setup_token": "...", "password": "..."}`
sets the first password. An emailed token also verifies the email address; an
operator-printed bootstrap token does not.

## Device flow

The device client calls `POST /realms/{realm}/oauth/device_authorization` and shows
`user_code` and `verification_uri` (the realm's login UI URL; the server has no
device page of its own). The login UI starts a transaction with
`{"device_user_code": "WDJB-MJHT"}`; the response includes
`device_request: {client_name, client_id, scopes, expires_at}` so the user can see
which client is asking. Consent is always shown. On completion the device code is
approved and no `redirect_to` is returned; the device receives tokens by polling.

## Upstream identity providers

When the realm has active upstream connections, unauthenticated transactions offer
an optional `external_redirect` action listing providers:

1. `POST .../{id}/federation/start {"provider": "<alias>"}` returns
   `state.external_redirect`; send the browser there.
2. The provider redirects to `/api/v1/realms/{realm}/federation/{alias}/callback` (register this URL at the upstream).
   The server consumes the single-use `state`, exchanges the code (PKCE), validates
   the upstream response, and updates the transaction. It then redirects the browser
   to the login UI with `transaction_id` (and `federation_error` on failure). Without
   a login UI it returns JSON. A connection disabled while the user was at the
   upstream (for example by the emergency control) ends the round trip with
   `connection_disabled`: the upstream is not contacted again and no one is
   signed in or linked.
3. The client calls `POST .../{id}/resume` with its continuation to continue. A
   callback URL replayed in another browser cannot complete the login, because
   completion requires the continuation.

If the upstream identity matches an existing local account that is not yet linked,
the transaction requires `link_account`: the user must sign in to that local account
in the same transaction before the link is created (FED-004, FED-005).

**Proof of control for linking.** A passwordless challenge proves control for
linking only when it was issued for that link (PWDLESS-008):

- A password or a passkey of the account proves control.
- An email code (`otp/send` with `purpose: login`) or a magic link (`purpose:
  magic_link`) requested while the link is pending is sent with the template
  `account_link_code` or `account_link_magic_link`, which names the connection
  (`provider`) and says that it will be linked to the account, and the challenge
  is bound to that link. A sign-in code or magic link requested before the link
  became pending is refused (`409 unexpected_step` for the code, which the
  transaction forgets when the link becomes pending, `400 invalid_proof` for the
  link), and a linking code or link never serves as a plain sign-in.
- An SMS code never proves control for linking (PWDLESS-006): `otp/send` for a
  phone number is `409 unexpected_step` while a link is pending, and identifying
  with another identifier (such as a phone number) abandons the pending link.
- A code or link for an identifier without an account creates no account and
  completes nothing (`400 invalid_proof`).

**SAML connections** (kind `saml`, FED-014) are offered in the same list and
started the same way; `external_redirect` then carries a signed SAML
`AuthnRequest` (HTTP-Redirect binding). The IdP posts its response to
`/realms/{realm}/saml/acs/{alias}` instead of the callback above (register the
connection's SP metadata, `/realms/{realm}/saml/sp/{alias}`, at the IdP), and
the browser comes back to the login UI the same way. Steps 3 and the linking
rules are unchanged ([saml.md](../integrations/saml.md#sign-in-flow)).
