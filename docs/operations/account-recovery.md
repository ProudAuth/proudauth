# Account recovery policy

ProudAuth treats each recovery situation as a separate path with its own proof,
evidence and consequences (MFA-008). No path silently lowers the assurance an
account or tenant requires: recovery never removes an MFA requirement, and a
session that started from a recovery factor is *recovery restricted* until a
strong factor is enrolled again (MFA-010).

| Situation | Who acts | Proof required | What happens | Evidence |
| --- | --- | --- | --- | --- |
| Lost password | The user | Control of a verified email address (single-use, purpose-bound reset challenge) | Password replaced; **all sessions and offline grants revoked**, and the account's personal access tokens and user-owned API keys ([below](#rules-that-apply-to-every-path)); MFA unchanged and still required at the next sign-in | `recovery.password_reset.requested` / `.completed`, `automation_credential.revoked`, owner notices (`password_changed`, `credentials_revoked`) |
| Lost factor (TOTP device, HOTP token, passkey) | The user | Password plus a recovery code | Recovery-restricted session and account: the session can only read, enroll a new factor and end sessions or remembered devices ([below](#recovery-restricted-sessions-mfa-010-usr-003)) | `mfa.recovery_code.used`, `user.recovery_restricted`, owner notice |
| Lost factor without recovery codes | A support operator with `support.recovery.assist` or an administrator with `realm.users.credentials.manage` (resetting MFA always requires `realm.users.credentials.manage`) | Out-of-band identity proofing recorded as `reason` and `evidence_reference` | `POST /users/{user}/recovery-requests` with `reset_mfa: true`: factors (TOTP, HOTP, passkeys, recovery codes) revoked, `configure_totp` required action set, sessions, personal access tokens and user-owned API keys revoked, single-use setup link sent to the verified address | `recovery.assisted` (actor, reason, evidence), `automation_credential.revoked`, owner notices to the primary verified email address |
| Lost contact address | An administrator holding **both** `realm.users.verification.override` and `realm.users.credentials.manage`, from an MFA session with recent authentication, never for their own account | Out-of-band identity proofing for the new address, recorded as `reason` in every step | The owner does not sign in until step 4: 1. `POST /users/{user}/identifiers` `{"type":"email","value":"<new address>","reason":"..."}` adds the address unverified and not primary (`409` if another account has verified it); 2. `POST /users/{user}/verification-overrides` `{"identifier_id":"<id from step 1>","reason":"..."}` (USR-005); 3. `POST /users/{user}/identifiers/{id}/primary` `{"reason":"..."}` (`422` for an unverified address); 4. `POST /users/{user}/recovery-requests` as above: the setup link goes to the primary address, now the new one. Assisted recovery answers `409` while the primary address is unverified, so it is never delivered to an address nobody proved control of. The previous verified primary address receives an `identifier_changed` notice at steps 1 and 3 (it never names the new address; USR-004). Once signed in, the owner removes the lost address (`DELETE /me/identifiers/{id}`) | `user.identifier.added`, `user.identifier.verification_overridden`, `user.identifier.primary_changed` (actor, reason), `recovery.assisted` |
| Compromised account | An administrator (`realm.users.suspend`, `realm.users.credentials.manage`) | Incident evidence | Lock or suspend; `POST /users/{user}/credentials/password/compromised` (state `compromised`, every session and offline grant revoked, and the account's personal access tokens and user-owned API keys); then assisted recovery once the owner is re-proofed | `credential.password.compromised`, `automation_credential.revoked`, `security.credential_compromised` event, alert signal `credential_compromised`, owner notice `credentials_revoked` |
| Organization owner unreachable or departed | A realm administrator (`realm-admin` holds `org.ownership.transfer` in every organization) | Confirmation through the organization's own channel, recorded as evidence | `POST /organizations/{org}/ownership-transfers` makes an active member an owner; the former owner's role is removed separately ([incidents.md](incidents.md#organization-owner-recovery)) | `organization.ownership.transferred` |
| Code factors turned off after repeated failures | The user, or an administrator | A passkey; or control of a verified email address (password reset); or out-of-band identity proofing (assisted recovery) | After `security.second_factor.failure_disable_at` (100) consecutive failed TOTP, HOTP, recovery-code or sign-in code proofs, those factors are refused (`403 code_factors_disabled`; sign-in codes are not sent); a passkey sign-in, a completed password reset or an assisted recovery turns them back on ([below](#code-factors-turned-off-after-repeated-failures)) | `mfa.code_factors.failure_notice`, `.disabled`, `.restored`, owner notice `second_factor_failures` |
| Directory-managed or federated account | The upstream directory or identity provider | The upstream's own recovery | ProudAuth does not reset a credential it does not own: users of SSO-required organizations have no local password fallback (FED-012). Unlinking or relinking an upstream identity is an administrator action with evidence. For accounts an LDAP or Active Directory connector sources, a password change and the completion of a password reset or account setup answer `409 conflict` (`externally_managed`), an account the directory disabled cannot be reactivated locally, and the password is changed in the directory; MFA factors stay local and follow the paths above ([directory.md](../integrations/directory.md#directory-authoritative-accounts-and-write-back)) | `federation.identity.unlinked` / `.linked`; `directory.user.*` |

## Cooling-off and second-operator approval (MFA-009)

Realms can slow assisted recovery down with `recovery.cooling_off_hours`
(0–168) and `recovery.require_approval` (migration `0020`,
`internal/authentication/assisted.go`). When either is set, the assisted
recovery request is **scheduled** instead of executed:
`POST /users/{user}/recovery-requests` returns
`202 {"status": "recovery_scheduled", "recovery_id", "effective_at", "approval_required"}`,
where `effective_at` is now plus the cooling-off period. The owner is notified at
once at the primary verified email address (the notice states the effective
time in the account's `zoneinfo` time zone, or UTC; MSG-006), can see the request at
`GET /me/assisted-recoveries` and cancel it with
`POST /me/assisted-recoveries/{id}/cancel` (until it runs), and — when approval is
required — an operator other than the requester and the owner must call
`POST /assisted-recoveries/{id}/approve`. Approving needs
`support.recovery.assist`, and approving a request with `reset_mfa` also needs
`realm.users.credentials.manage` (`403` otherwise), so the approver holds the
same authority a factor reset requires. The worker task
`recovery.assisted_due` (every minute) runs requests whose `effective_at` has
passed and that need no approval or were approved, with the same effects as an
immediate recovery and the request ID in the `recovery.assisted` evidence
(`recovery.assisted.scheduled`, `.approved` and `.cancelled` record the earlier
steps). Requests not executed within seven days after `effective_at` expire.
Scheduling requires a verified primary email address, so the operator never
receives a setup token in this mode (`TestScheduledAssistedRecovery`).

When a request is due, the worker checks the conditions again in the
transaction that would execute it:

- the account must still exist and not be deleted, otherwise the request is
  cancelled with reason code `account_unavailable`;
- the requester must still have the authority the request route requires:
  `support.recovery.assist` or `realm.users.credentials.manage` in the realm,
  and `realm.users.credentials.manage` for `reset_mfa`; otherwise it is
  cancelled with `requester_no_longer_authorized`;
- the primary email address, which would receive the setup link, must be
  verified, otherwise the request is cancelled with `contact_unverified`
  (`TestAdminIdentifierChangeGuards`).

Each cancellation is audited as `recovery.assisted.cancelled` with actor
`system` and the reason code, and are not counted as executed recoveries. Each due request runs in its own transaction, so
a request that fails is retried on the next run without holding up the others.
Deleting the account cancels its pending and approved requests.

## Code factors turned off after repeated failures

Owner decision 10 of 0.2.0-alpha.6 (SEC-006, MFA-002, TEST-021; migration
`0088`). Every account keeps a count of consecutive failed code-factor
proofs: TOTP, HOTP, recovery codes and emailed or texted sign-in codes, across
transactions and proof-budget windows. Passkeys never count. With the
defaults ([configuration.md](configuration.md#security),
`security.second_factor`):

- from the 10th failure on, every TOTP, HOTP or recovery-code step waits a
  delay that starts at 2 s and doubles per failure up to 1 hour
  (`429 rate_limited` with `Retry-After`);
- at the 20th, the owner receives one mandatory `second_factor_failures`
  notice ("someone who knows your password or your address may be trying to
  guess a code"), recorded as `mfa.code_factors.failure_notice`;
- at the 100th, the account's code factors are turned off
  (`mfa.code_factors.disabled`): TOTP, HOTP and recovery-code steps answer
  `403 code_factors_disabled`, also with a valid code, which stays unused, and
  sign-in codes are no longer sent (the sign-in step looks exactly as for an
  address without an account).

The owner gets back in without anyone's help, so an attacker who knows the
password can turn code factors off but cannot lock the owner out:

1. **Passkey.** Signing in with a passkey works as usual and turns code
   factors back on.
2. **Password reset from the email address.** `POST /password-resets` sends a
   reset code to the verified address; completing the reset replaces the
   password (the old one was probably known to whoever made the guesses),
   revokes every session, offline grant and personal access token, and turns
   code factors back on. MFA stays required: the next sign-in asks for the
   TOTP, HOTP or recovery code again.
3. **Assisted recovery.** An administrator's assisted recovery
   (`POST /users/{user}/recovery-requests`, [above](#account-recovery-policy))
   turns them back on as well, with or without `reset_mfa`; with cooling-off or
   approval configured, only when the scheduled recovery runs.

Each of these is recorded as `mfa.code_factors.restored` with the `cause`
(`passkey`, `password_reset`, `assisted_recovery`; also `sign_in`, `totp`,
`hotp`, `recovery_code` when the count is reset before it reached the
ceiling). Before the ceiling, any successful TOTP, HOTP, recovery-code or
passkey proof and any completed sign-in reset the count; a correct password
alone never does. Administrators see the count, when the owner was warned,
when code factors were turned off and until when the backoff runs in
`GET /users/{user}` (`second_factor_failures`). The notice and the audit
trail are the signal to look at the account: guesses at the second factor
mean the password is very likely known to someone else.

Whoever controls the account's mailbox can also turn code factors back on
with a password reset, which changes the password and ends every session;
the owner then sees the `password_changed` notice
([incidents.md](incidents.md#abuse-spikes) lists the signals to watch).

## Recovery-restricted sessions (MFA-010, USR-003)

A sign-in whose second factor is a recovery code, and that used no TOTP or
passkey, creates a **recovery-restricted** session (`recovery_restricted: true`
in `GET /me/sessions`). Recovery codes never satisfy the
phishing-resistant profile (privileged or protected accounts when the realm
sets `mfa.admin_phishing_resistant` or the operator sets
`security.mfa_floor.admin_phishing_resistant`, and requests whose
`acr_values` ask for phishing-resistant authentication). There, an account
that holds no user-verified passkey may use one as an upgrade proof that
only unlocks registering a user-verified passkey in the same sign-in
([headless-authentication.md](../protocols/headless-authentication.md#evaluation-order),
step 5); the code is consumed, the session is the passkey's and is not
restricted. An account that has a user-verified passkey must use it; when it
is lost, the account recovers through assisted recovery.

**Account state.** The same sign-in moves an `active` account to the state
`recovery_restricted` (audit and outbox event `user.recovery_restricted`,
reason `RECOVERY_CODE_USED`). The account can still sign in. It returns to
`active` (`user.reactivated`, reason `FACTOR_ASSURANCE_RESTORED`) at the next
sign-in with TOTP, HOTP (in realms that allow it) or a passkey, or when a new
TOTP, HOTP token or passkey is enrolled from the restricted session. Neither change revokes sessions. A sign-in whose
only second factor is upstream MFA from a federated connection does not
restore the account.

**What a restricted session may do.** Every `GET` and `HEAD`, and only these
writes:

| Request | Purpose |
| --- | --- |
| `POST /me/totp/enroll`, `POST /me/totp/activate` | Enroll a new TOTP |
| `POST /me/hotp/enroll`, `POST /me/hotp/activate` | Enroll a new HOTP token (MFA-013; only in realms that list `hotp` in `mfa.allowed_factors`) |
| `POST /me/webauthn/registration-options`, `POST /me/webauthn/registration-complete` | Register a new passkey |
| `DELETE /me/sessions/{id}`, `POST /me/sessions/revoke-all` | End sessions |
| `DELETE /me/remembered-devices`, `DELETE /me/remembered-devices/{id}` | Forget remembered devices |

Every other write under `/api/v1/realms/{realm}` (self-service, organization
and administration APIs: password change, identifiers and verification
challenges, profile, deletion request, data export, personal tokens, consents,
notification preferences, support-access settings, recovery-code
regeneration, factor removal, organization switch, organization
administration, ...) is refused with `403` and problem code
`recovery_restricted`. Administration-API reads are refused too
(`403 mfa_required`, "recovery-restricted sessions cannot perform
administration; enroll a new factor first"), admin-audience tokens are not
issued to such a session (`invalid_grant`), and it cannot start or approve
support access. Tokens for account and business resources are still issued.
The enrollment requests still need recent authentication
(`security.recent_auth_window`).

**Leaving the restriction.** Completing a TOTP or HOTP activation or a
passkey registration from the restricted session lifts the restriction on
that session and returns the account to `active`. Signing in again with the new
factor gives a session that was never restricted.

Covered by `TestMultiFactorAndProofs` (subtest "recovery codes are single use
and restrict the session"): refused writes, allowed enrollment, and the
account state before and after a strong sign-in; `TestHOTP` covers HOTP
enrollment from a restricted session.

## Rules that apply to every path

- **Password change (CRED-006).** `POST /me/password` requires recent
  authentication (`security.recent_auth_window`, default 10 minutes), the current
  password, and — when the account has TOTP, HOTP or a passkey — a session that
  completed MFA (otherwise `step_up_required`). A TOTP or HOTP the realm's
  `mfa.allowed_factors` no longer allows satisfies nothing (MFA-005) and does
  not count here. A wrong current password counts against the account's
  temporary password lock, the one password sign-in uses
  (`security.rate_limits.failures_before_lock`, 10 per `temporary_lock`,
  15 minutes): once it is reached, the change answers `429 rate_limited`
  without checking the password, and password sign-in to the account is
  locked as well until the window ends; each refusal is audited as
  `credential.password.change_failed` (`INVALID_CREDENTIALS` or
  `TEMPORARY_LOCK`). The owner is notified. When the
  realm sets `password.revoke_sessions_on_change` (the default), every other
  session of the user is revoked in the same transaction; the session that made
  the change stays signed in. Password resets always revoke all sessions.
- **Personal access tokens (CRED-008, MCH-007).** A password reset, marking
  the password compromised and assisted recovery revoke the account's personal
  access tokens and the API keys the user owns in the same transaction
  (`revoke_reason` `password_reset`, `credential_compromised` or
  `assisted_recovery`), audit each as `automation_credential.revoked`, and
  send the mandatory `credentials_revoked` notice, which names them by name
  and display prefix. Introspection treats a user-owned credential created
  before such a revocation as inactive even if its row was missed. Someone
  who briefly controlled the account cannot keep access through a token
  minted then. Recovery-restricted sessions cannot mint new tokens, and an
  account with a second factor mints only from an MFA session (MCH-006).
  "Log out everywhere", a password change and an administrator's session
  revocation leave personal access tokens alone
  ([machine-clients.md](../integrations/machine-clients.md#when-the-owners-account-is-recovered),
  `TestPersonalAccessTokensEndWithAccountRecovery`).
- **No knowledge-based questions** and no support-visible secrets: operators never
  see passwords, TOTP seeds, recovery codes or passkeys. A setup token is returned
  to the operator only when the account has no deliverable address, and that
  hand-off is part of the `recovery.assisted` evidence.
- **Lost passkeys (PASS-005).** A lost passkey is a lost factor: recovery codes
  or assisted recovery. Where the phishing-resistant profile applies, TOTP and
  recovery codes never satisfy that profile. An account with a user-verified
  passkey gets "a phishing-resistant authenticator is required" for them at
  sign-in, so it uses assisted recovery. An account without one (it holds only
  TOTP, HOTP, recovery codes or a passkey never used with user verification)
  proves one of them as an upgrade proof and then registers a user-verified
  passkey in the same sign-in; with the password alone it cannot register
  one, and `totp/enroll` and `totp/activate` are refused there, so the
  existing TOTP and recovery codes cannot be replaced either (MFA-006).
- **Adding a factor needs an existing one (MFA-006).** When the account
  already has an active TOTP, HOTP or passkey, `POST /me/totp/enroll`,
  `/me/totp/activate`, `/me/hotp/enroll`, `/me/hotp/activate`,
  `/me/webauthn/registration-options` and
  `/me/webauthn/registration-complete` need a session that completed MFA
  (a TOTP or HOTP the realm no longer allows does not count, since it could
  not be proved; the last-factor guard does not count it either):
  a password alone, or a password plus a remembered device, gets
  `403 step_up_required` ("verify an existing factor before adding another")
  with the obligation `{"type": "reauthenticate", "required_profile": "mfa"}`.
  A recovery-code session counts as MFA, so it may enroll a replacement.
- **Attribution.** Every recovery action records the human actor, the reason and
  the evidence reference in the append-only audit log and raises the
  `factor_recovery` security signal (OPS-004).
