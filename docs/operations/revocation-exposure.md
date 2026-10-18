# Revocation exposure statement

Requirement SES-023: local JWT verification cannot observe a revocation that
happens after the token was issued. This page states, for each kind of
consumer and each revocation event, when access actually stops. It applies to the
code in this repository with default configuration.

## Consumers

| Consumer | How it validates | Sees revocation |
| --- | --- | --- |
| **IdP's own APIs** (`/api/v1/realms/{realm}/me/...`, tenant and admin APIs, UserInfo) | JWT signature, then live checks on every request: JTI revocation list, client active, session active and owned by the subject (user tokens), user able to authenticate, service principal active (machine tokens) | Immediately after the revoking transaction commits |
| **Strict-online resource servers** (introspection via `POST /realms/{realm}/oauth/introspect`, e.g. Go SDK `verifier.Introspector` / `SupportGuard`) | Every request introspected; no positive cache | Immediately for the checks listed under "Introspection checks" below |
| **Offline resource servers** (local JWT verification, e.g. Go SDK `verifier.Verifier`) | Signature, issuer, audience, type, times; no server state | **Not until the token expires**, plus clock tolerance |
| **Bounded-state resource servers** (Go SDK `verifier.BoundedVerifier` with `BoundedState`, Node.js `bounded-state`) | Local JWT verification plus session, subject, organization and membership revocations replayed from `GET /session-events` | After the next stream sync that includes the change; checks fail closed (`ErrStateStale`) once the replayed state is older than `MaxStaleness`. Revocations before the state's `Start` are not replayed |
| **Refresh** (token endpoint) | Live checks in the rotation transaction | Immediately: no new access token after revocation |
| **Relying parties with back-channel logout** | Signed `logout+jwt` POSTed by the worker | Asynchronously, after the worker delivers (retries up to 8 times) |
| **Webhook subscribers** | `session.revoked`, `user.suspended`, `organization.membership.removed`, ... | Asynchronously, at least once; not a revocation mechanism (§22) |
| **Shared-signals receivers** (AUD-016) | CAEP `session-revoked` and RISC events as Security Event Tokens, pushed by the worker or polled ([shared-signals.md](../integrations/shared-signals.md)) | Asynchronously: after the next `ssf.deliver` run (every 2 s, retries up to 8 times) or the receiver's next poll; only for users the stream covers |
| **Relying parties using the check-session iframe** (OIDC-014) | Browser cookie compared in an iframe | Only when the browser next reaches ProudAuth (sign-in, silent authorization, logout); revocations made on the server are not visible to the iframe ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#session-management-oidc-014)) |

### Offline exposure window

`window = remaining token lifetime + verifier clock tolerance`

- Access-token lifetime is set per API resource: `access_token_ttl_seconds`,
  default **300 s**, range 30–3600 s, optionally shortened per client and capped by
  `tokens.max_access_token_ttl` (60 min).
- Clock tolerance: the Go SDK verifier defaults to 30 s (maximum 60 s); the
  server's own verifier uses `tokens.clock_skew` (60 s).
- Default worst case for an offline verifier: **about 5.5 minutes** after
  revocation. Longer resource lifetimes lengthen it proportionally.

### Introspection checks

For JWT access tokens: signature and key not compromised; resource registered for
the caller and active; JTI not revoked; client active; user able to authenticate
(or service principal active); session active if the token has `sid`, otherwise
(offline grants) no account-wide revocation of the user's tokens at or after the
token's `iat` (SES-005: one lookup on the `token_revocations` index); membership
and organization active if the token has `org_id`. User and exchanged JWTs also
require a signed `grant_id` whose grant is active, unexpired, in the same realm
and owned by the subject. Ordinary user tokens must match its client; an exchange
retains its originating grant. UserInfo and IdP user APIs enforce the same live
grant rule. A missing grant link fails closed; obtain fresh tokens when upgrading
an earlier development build ([upgrades.md](upgrades.md)).

For opaque tokens additionally: token not revoked or expired; grant active. For
support tokens: grant active and unexpired; actor and target users active; target
membership and organization active; actor session active; actor still holds
`support.impersonation.start` in the organization. For API keys and personal
tokens: credential active and unexpired; owner active; owner's membership active
when the credential is organization-bound; for a user-owned credential, created
after the owner's latest password-reset, password-compromise or
assisted-recovery revocation record (CRED-008, MCH-007).

## Events

| Event | IdP APIs and introspection | Refresh | Offline JWT verifiers | Notifications |
| --- | --- | --- | --- | --- |
| Single logout (`/oidc/logout`, `DELETE /me/sessions/{id}`) | Session revoked → tokens with that `sid` inactive. Grants of that session (except offline grants) and their refresh families revoked | Denied for the session's grants; **offline grants survive** | Valid until expiry | Back-channel logout for clients with a client session; `session.revoked` |
| Logout everywhere (`/me/sessions/revoke-all`), admin `revoke-sessions`, user suspend/lock, password marked compromised, password reset, assisted recovery, deletion request, account deletion | All sessions, all grants **including offline**, refresh families, opaque tokens and support grants (as actor or target) revoked. Every access token of the user issued at or before the revocation is inactive at once, offline-grant tokens without `sid` included (a user-level `token_revocations` record, SES-005; a JWT issued in the same second as the revocation counts as before it). Suspension/lock/deletion also make every token of the user inactive (user state check). **Password reset, password marked compromised and assisted recovery also revoke the user's personal access tokens and user-owned API keys** (`automation_credential.revoked`); the other events in this row leave them active, except that suspension, lock and a deletion request make them inactive through the owner state check and deletion revokes them | Denied | Valid until expiry | Back-channel logout per session; `session.revoked`, `user.suspended`, ...; `credentials_revoked` notice naming the revoked tokens and keys |
| Membership removed or suspended | User's grants for that organization revoked; tokens with that `org_id` inactive | Denied | Valid until expiry | `organization.membership.removed` / `.suspended` |
| Organization suspended, archived or deleted | All grants and support grants bound to it revoked; tokens with that `org_id` inactive | Denied | Valid until expiry | `organization.*` |
| Role or permission change | Not reflected in tokens (tokens carry scopes, not roles). Introspection returns the current `authz_version`; the decision API evaluates current permissions | Scopes unchanged (they follow the client's resource grant and consent) | Unchanged | `authorization.role.*` |
| Client suspended or decommissioned | Client's grants, refresh families and opaque tokens revoked; its tokens inactive (client check) | Denied | Valid until expiry | `client.state_changed` |
| Client secret revoked | No new client authentication with it; issued tokens unaffected | Denied if the client cannot authenticate | Valid until expiry | — |
| Token revocation endpoint (RFC 7009) | Refresh token: its grant, families and opaque tokens revoked; linked JWTs and exchanged descendants inactive online, including offline-grant JWTs without `sid`. JWT access token: JTI recorded, inactive at introspection and IdP APIs. Opaque token: revoked | As left | **JWT still valid until expiry** | — |
| Confirmed refresh reuse | Family compromised and grant revoked; linked JWTs, opaque tokens and exchanged descendants inactive online. The session is also revoked for session-bound grants; offline-grant reuse leaves the SSO session intact | Denied; authenticate again for that grant | Valid until expiry | `security.refresh_reuse_detected`; `session.revoked` for a session-bound grant |
| Consent revoked (`DELETE /me/consents/{id}`, `DELETE /users/{user}/consents/{id}`, or a revoked consent pre-authorization) | The client's grants for the user, their refresh families and opaque tokens revoked | Denied | Valid until expiry | — |
| Client `consent_terms_version` changed | Nothing revoked; the next authorization asks for consent again | Unaffected | Unaffected | — |
| Service principal disabled (also by the owner-departure policy `machine.owner_departure: disable`) | Service tokens inactive; client credentials fail | — | Valid until expiry | `service_principal.state_changed` |
| API key / personal token revoked, owner deactivated, or the owner's password reset, marked compromised or recovered by an administrator | Inactive at the next introspection | — | — (opaque only) | `credentials_revoked` to the owner for the last three |
| Support grant revoked or expired | Inactive at the next introspection | Never refreshable | — (opaque only) | `support.impersonation.ended` (on revoke) |
| Emergency signing-key rotation | Tokens signed with the compromised key rejected within 5 s | Unaffected (refresh tokens are not signed) | **Accepted until the verifier drops the key from its JWKS cache** | `signing_key.rotated` |
| Realm suspended | New authorizations, token requests and refresh fail; IdP custom APIs reject | Denied | Valid until expiry | — |

## Membership states (TEN-003)

| State | How it arises | Sign-in to the organization | Token issuance in its context | Leaves the state when |
| --- | --- | --- | --- | --- |
| `invited` | An administrator invited an existing account by `user_id` | No | No | Accepted (→ `active`), or the invitation is revoked, declined, reassigned or expires (→ `removed`) |
| `pending_approval` | The user filed a join request | No | No | A reviewer approves (→ `active`) or denies, the user withdraws the request, or it expires after 14 days (→ `removed`) |
| `active` | Acceptance, approval, administrator add, JIT federation, import, creator | Yes | Yes, within roles, scopes and policy | Suspended, expired or removed |
| `suspended` | An organization administrator suspended the member | No | No; existing grants, refresh families and opaque tokens in the organization are revoked at once | Reactivated (→ `active`) or removed |
| `expired` | The membership reached its `expires_at` (worker sweep) | No | No; grants revoked by the sweep | Never (a new membership is needed) |
| `removed` | Removal, offboarding, deletion | No | No; grants revoked in the removal transaction; `organization.membership.removed` is published | Never |

Address-only invitations never create an `invited` membership, so member lists do
not reveal whether an address belongs to an existing account (DOM-008). JWT access
tokens already issued remain verifiable offline until expiry; strict-online
resources and introspection see the change immediately.

## Caveats

- **Offline-grant JWTs have no `sid`.** Introspection and UserInfo cannot tie them
  to a session, so they check the user-level revocation record instead: after
  "logout everywhere" (and the other account-wide revocations in the table
  above) they are inactive at once (SES-005, `TestLogoutEverywhereEndsOfflineTokens`).
  Revocations that keep offline grants (the surviving account of an account
  merge, a received shared signal that does not cover offline access) record
  only their sessions, so offline-grant tokens stay active until expiry, like the
  grants they come from. Offline verifiers still accept every unexpired token.
  Because `iat` has one-second resolution, a token issued in the same second as
  an account-wide revocation is treated as issued before it.
- **Realm suspension does not affect introspection.** Introspection keeps
  reporting unexpired tokens active; combine suspension with session revocation.
- `authz_version` in a JWT is a hint. It means something only when compared to the
  value introspection returns.
- Requests already authorized or in flight when a revocation commits complete
  (§13.2); long-running jobs or streams need their own re-checks.
- The IdP does not enforce a resource's `verification_mode`; `bounded_online`
  is met only if the resource uses the SDKs' bounded-state mode (or an equivalent
  consumer of the session-event stream) with a staleness bound it chooses.
- DPoP-bound tokens (`cnf.jkt`) are not enforced by the Go SDK verifier; see
  [docs/protocols/oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md).

## Default lifetimes

| Artifact | Default | Configuration |
| --- | --- | --- |
| Access token | 300 s per resource (30–3600 s) | resource `access_token_ttl_seconds`, client `token_policy.access_token_ttl_seconds`, realm policy `tokens.*` limits (all tokens, service principals, single-factor sessions; [tokens.md](../protocols/tokens.md#access-token-lifetime)), cap `tokens.max_access_token_ttl` (60 min) |
| ID token | 5 min | `tokens.id_token_ttl` |
| Authorization code | 60 s | `tokens.authorization_code_ttl` |
| Authentication transaction | 10 min | `tokens.transaction_ttl` |
| IdP session | 30 min idle, 12 h absolute | `sessions.idle_timeout`, `sessions.absolute_timeout`; realm/organization policy may shorten. A refresh of one of the session's grants is activity: it moves the idle expiry to the refresh family's window from now when that is later, and never shortens the session's own idle or absolute expiry (`TestRefreshNeverShortensSession`) |
| Remember-me session | 7 d idle, 30 d absolute | `sessions.remember_me_*` (client must allow remember-me) |
| Offline grant | 7 d idle, 30 d absolute | `sessions.offline_*` (client must allow `offline_access`) |
| Refresh family (session-bound) | The idle window it was issued with (ordinary, remember-me or offline), kept across rotations; never beyond the session's absolute expiry | Client `token_policy.refresh_idle_seconds` / `refresh_absolute_seconds` may shorten ([ADR 0011](../architecture-decisions/0011-refresh-token-families.md)) |
| Support grant and token | ≤ 5 min | `impersonation.max_ttl`, realm `impersonation.max_ttl_seconds`, `tokens.impersonation_access_token_ttl_seconds` and `tokens.access_token_ttl_seconds` (the smallest applies) |
| Support handoff code | ≤ 30 s | `impersonation.handoff_ttl` |
| Email codes (verification, login, reset) | 10 min | `tokens.challenge_ttl` |
| Invitation | 72 h | `tokens.invitation_ttl` |
| Device code | 10 min | `tokens.device_code_ttl` |
| Pushed authorization request | 60 s | fixed |
| Clock tolerance | 60 s server, 30 s Go SDK | `tokens.clock_skew`; `verifier.Config.ClockSkew` |
