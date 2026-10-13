# Account recovery policy

ProudAuth treats each recovery situation as a separate path with its own proof,
evidence and consequences (MFA-008). No path silently lowers the assurance an
account or tenant requires: recovery never removes an MFA requirement, and a
session that started from a recovery factor is *recovery restricted* until a
strong factor is enrolled again (MFA-010).

| Situation | Who acts | Proof required | What happens | Evidence |
| --- | --- | --- | --- | --- |
| Lost password | The user | Control of a verified email address (single-use, purpose-bound reset challenge) | Password replaced; **all sessions and offline grants revoked**; MFA unchanged and still required at the next sign-in | `recovery.password_reset.requested` / `.completed`, owner notice |
| Lost factor (TOTP device, HOTP token, passkey) | The user | Password plus a recovery code | Recovery-restricted session and account: the session can only read, enroll a new factor and end sessions or remembered devices ([below](#recovery-restricted-sessions-mfa-010-usr-003)) | `mfa.recovery_code.used`, `user.recovery_restricted`, owner notice |
| Lost factor without recovery codes | A support operator with `support.recovery.assist` or an administrator with `realm.users.credentials.manage` (resetting MFA always requires `realm.users.credentials.manage`) | Out-of-band identity proofing recorded as `reason` and `evidence_reference` | `POST /users/{user}/recovery-requests` with `reset_mfa: true`: factors (TOTP, HOTP, passkeys, recovery codes) revoked, `configure_totp` required action set, sessions revoked, single-use setup link sent to the verified address | `recovery.assisted` (actor, reason, evidence), owner notice to the primary verified email address |
| Lost contact address | An administrator holding **both** `realm.users.verification.override` and `realm.users.credentials.manage`, from an MFA session with recent authentication, never for their own account | Out-of-band identity proofing for the new address, recorded as `reason` in every step | The owner does not sign in until step 4: 1. `POST /users/{user}/identifiers` `{"type":"email","value":"<new address>","reason":"..."}` adds the address unverified and not primary (`409` if another account has verified it); 2. `POST /users/{user}/verification-overrides` `{"identifier_id":"<id from step 1>","reason":"..."}` (USR-005); 3. `POST /users/{user}/identifiers/{id}/primary` `{"reason":"..."}` (`422` for an unverified address); 4. `POST /users/{user}/recovery-requests` as above: the setup link goes to the primary address, now the new one. Assisted recovery answers `409` while the primary address is unverified, so it is never delivered to an address nobody proved control of. The previous verified primary address receives an `identifier_changed` notice at steps 1 and 3 (it never names the new address; USR-004). Once signed in, the owner removes the lost address (`DELETE /me/identifiers/{id}`) | `user.identifier.added`, `user.identifier.verification_overridden`, `user.identifier.primary_changed` (actor, reason), `recovery.assisted` |
| Compromised account | An administrator (`realm.users.suspend`, `realm.users.credentials.manage`) | Incident evidence | Lock or suspend; `POST /users/{user}/credentials/password/compromised` (state `compromised`, every session and offline grant revoked); then assisted recovery once the owner is re-proofed | `credential.password.compromised`, `security.credential_compromised` event, alert signal `credential_compromised` |
| Organization owner unreachable or departed | A realm administrator (`realm-admin` holds `org.ownership.transfer` in every organization) | Confirmation through the organization's own channel, recorded as evidence | `POST /organizations/{org}/ownership-transfers` makes an active member an owner; the former owner's role is removed separately ([incidents.md](incidents.md#organization-owner-recovery)) | `organization.ownership.transferred` |
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

## Recovery-restricted sessions (MFA-010, USR-003)

A sign-in whose second factor is a recovery code, and that used no TOTP or
passkey, creates a **recovery-restricted** session (`recovery_restricted: true`
in `GET /me/sessions`). Recovery codes are refused where the
phishing-resistant profile applies (with passkeys enabled: privileged or
protected accounts when the realm sets `mfa.admin_phishing_resistant`, and
requests whose `acr_values` ask for phishing-resistant authentication); those
accounts recover through assisted recovery.

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
  not count here. The owner is notified. When the
  realm sets `password.revoke_sessions_on_change` (the default), every other
  session of the user is revoked in the same transaction; the session that made
  the change stays signed in. Password resets always revoke all sessions.
- **No knowledge-based questions** and no support-visible secrets: operators never
  see passwords, TOTP seeds, recovery codes or passkeys. A setup token is returned
  to the operator only when the account has no deliverable address, and that
  hand-off is part of the `recovery.assisted` evidence.
- **Lost passkeys (PASS-005).** A lost passkey is a lost factor: recovery codes
  or assisted recovery. Where the phishing-resistant profile applies, a
  recovery code is refused at sign-in ("a phishing-resistant authenticator is
  required"), so those accounts use assisted recovery; TOTP and recovery codes
  never satisfy that profile.
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
