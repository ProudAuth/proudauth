# Support impersonation threat model

Scope: support access as implemented in `internal/impersonation`, the routes in
`internal/httpapi/admin.go` and `internal/httpapi/selfservice.go`, introspection in
`internal/oauth/introspect.go`, the decision API in `internal/httpapi/decision.go`,
and the downstream guard `verifier.SupportGuard` in `proudauth-sdk-go/verifier/introspect.go`.
Requirements: docs/plan.md §16 (IMP-001..IMP-024). Design:
[ADR 0014](../architecture-decisions/0014-support-impersonation.md).

## Assets

- The customer's data and actions in downstream applications.
- The customer's identity and credentials (must never change under support access).
- Accountability: the record that a named operator, not the customer, acted.
- The support token (`pa_it_...`) and handoff code (`pa_hc_...`).

## Actors

| Actor | Trust |
| --- | --- |
| Support operator | Authenticated administrator with `support.impersonation.start` in the target organization; may be malicious or compromised |
| Approver | Second operator (`support.impersonation.approve`), organization owner (`org.support_access.approve`), or the customer, depending on policy |
| Customer (target) | Can view, revoke and (if the realm allows) opt out |
| Support backend | Confidential client that receives the token |
| Destination application backend | Confidential client that redeems handoff codes |
| Resource server | Registered introspector for the audience; must implement the contract |
| Attacker | Holds a stolen admin token, support token, handoff code or browser URL |

## Flow and checks

1. **Enablement (IMP-001).** `impersonation.enabled` (deployment), realm policy
   `impersonation.enabled`, and at least one active resource with
   `impersonation_enabled` and `verification_mode: strict_online`. Checked at
   request, approval and issuance (`Service.enabled`), and again on every use of a
   live grant (`ValidateGrant`, step 5).
2. **Request** `POST /impersonation-requests` (admin audience). `checkActor`:
   `user_access` token on a live session of the same user, MFA within
   `security.admin_mfa_max_age` and not recovery-restricted, user active, permission
   `support.impersonation.start` in the target organization. Reason length
   ≥ `impersonation.min_reason_length` (≤ 1000); ticket when the deployment or realm
   requires it. Target: not self, active member of an active organization, not
   opted out (when the realm permits opt-out), organization not opted out, and
   the target exclusions of `checkTarget` (IMP-015): active, not `protected`, no
   privileged realm role, not holding `org.roles.assign`,
   `org.ownership.transfer` or `org.members.write` in the organization. Client:
   active, confidential, in the resource's `support_client_ids` when set.
   Scopes: subset of the resource's `allowed_scopes` (plus `write_scopes` only
   in `allowlisted_write`). Request expires after 15 minutes.
3. **Approval** (`approval` from realm policy, overridden by organization policy;
   `allowlisted_write` forces `second_operator` when policy says `none`).
   Requester cannot approve. Second operator and organization owner go through
   `checkActor` with their permission; `customer` requires the target user, who
   is emailed at request time and sees the request in
   `GET /me/impersonation-requests` (IMP-022, `TestCustomerApprovedSupportAccess`).
   Approval re-runs `checkTarget`, so a request whose target became a realm or
   organization administrator after it was made cannot be approved.
   `POST /impersonation-requests/{id}/deny` refuses a pending or approved request:
   the requester can withdraw it, and whoever may approve under the request's
   policy can deny it; other callers get `404`.
4. **Issue** `POST /impersonation-requests/{id}/issue` by the requester only.
   Re-runs `checkActor`, organization and membership liveness, the target
   exclusions (`checkTarget`, as in step 2: a target promoted to realm or
   organization administrator after the request gets `403
   impersonation_denied`), client and resource eligibility, recomputes scopes;
   inserts the grant, the opaque token, the `support.impersonation.started`
   audit event, the outbox event and (if `notify_customer`) the notification
   in **one transaction**; the token is returned only after commit (IMP-020).
5. **Use.** The resource introspects every request. Introspection returns
   `active: true` only if the token, its resource and client are active **and**
   `ValidateGrant` passes: grant active and unexpired; actor and target users
   active; target membership active; the target exclusions still hold
   (`checkTarget`: not `protected`, no privileged realm role, no organization
   administrator permission; IMP-015, TEST-041), so a target promoted during
   the grant ends it at the next use; organization active; actor session live;
   actor still holds `support.impersonation.start` in the organization, within any
   capability conditions on the operator's role assignment (`organization_ids`,
   `subject_categories`, `support_modes`, `support_scopes`; IMP-002, IMP-007,
   `TestSupportCapabilityProfile`); the deployment and realm switches are still on;
   the resource is still active, strict-online and opted in; and neither the
   organization nor (where the realm permits it) the customer has opted out. The
   response carries `act`, `support_mode`, `impersonation_grant_id` and
   `token_kind: impersonation_access`; each active result is audited as
   `support.token.introspected`. These checks make a token inactive; they do
   not revoke the grant, which stays `active` in the inventory until it
   expires, and works again if the condition is undone before then (for
   example the promotion is reversed). Assigning a role does not revoke
   pending requests or live grants targeting the subject; issuance and
   introspection refuse them instead.
6. **Handoff** (optional). `POST /impersonation-grants/{id}/handoffs` returns a
   single-use code valid ≤ `impersonation.handoff_ttl` (30 s, capped at the grant
   expiry), bound to a confidential destination client allowed by the resource.
   The destination backend redeems it with client authentication at
   `POST /impersonation-handoffs/redeem` for its own support token on the same grant.
7. **End.** Expiry (≤ 5 minutes), revocation by the actor, the target
   (`/me/impersonation-grants/{id}/revoke`), a holder of
   `support.impersonation.revoke`, or the customer opting out; revocation also
   revokes the grant's tokens and unconsumed handoff codes.

## Threats

| # | Threat | Mitigation | Tests |
| --- | --- | --- | --- |
| I-1 | Operator without authority starts support access | Dedicated permission scoped to the organization; admin audience; live MFA session | TEST-040 |
| I-2 | Stolen admin access token used to start access | Session must be live and MFA recent; token kind must be `user_access` (no machine or exchanged tokens) | TEST-040, TEST-039 |
| I-3 | Impersonating a more privileged user to escalate | Protected users, privileged realm roles and organization administrators excluded at request, approval, issuance and every introspection (`checkTarget`), so a target promoted after the request is neither issued a grant nor kept impersonated | TEST-041 (`TestImpersonationDenials`, "targets promoted after the request"; `TestCustomerApprovedSupportAccess`) |
| I-4 | Support token used against the IdP (change password, MFA, create keys, start nested support) | `pa_it_` tokens are rejected by every IdP API (`403 impersonation_restricted`); the `support.token.rejected` audit event names the operator as actor, the customer as subject, the support grant, the organization and the route when the token is known (IMP-006); token exchange refuses them; no refresh token issued | TEST-042, TEST-043 |
| I-5 | Support token used for protected business operations | `SupportGuard` denies the protected operations (identity and money operations, ownership transfer, secrets, delete, purge: Go `verifier.ProtectedOperationList()` plus the guard's own `ProtectedOperations`) wherever their segments occur in the operation name, treats any operation with a write-verb segment as a write, and denies writes outside `WriteOperations`; the decision API applies the same rule (`authorization.ImpersonationForbiddenActions`, `authorization.WriteSegments`), denies non-read actions in read-only mode and, in `allowlisted_write` mode, writes not listed in the resource's `impersonation_policy.write_actions` (`SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED`) | TEST-042; all five SDKs and the server's classification run `tests/fixtures/sdk-contracts/support-operations/cases.json` |
| I-6 | Token outlives the reason for access | ≤ 5 min (config validation caps `impersonation.max_ttl`), per-request online validation of grant, actor, target, membership, organization, actor session, actor permission | TEST-043, TEST-044 |
| I-7 | Operator acting under the customer's name | `act` in introspection; grant stores actor and actor MFA time; IdP audit events carry actor and grant ID; `SupportGuard` records the actor before access | TEST-045 |
| I-8 | Support token leaked through a browser URL | Handoff codes are short, single-use, destination-bound and redeemed by an authenticated backend | TEST-046 |
| I-9 | Access granted although evidence was not recorded | Grant, token and audit event in one transaction; `SupportGuard` denies when its auditor fails | TEST-047 |
| I-10 | Customer unaware or unable to stop access | `/me/impersonation-grants` (list, revoke), opt-out (`PUT /me/support-access`) that revokes active grants, optional email notification | TEST-071 |
| I-11 | Self-approval or collusion | Requester cannot approve; operator and organization-owner approvers need their own permission and recent MFA (customer approval needs neither, see residual risk 10); `allowlisted_write` always needs an approver (a second operator when policy says `none`) | `TestCustomerApprovedSupportAccess`; other approval paths by code review |
| I-12 | Target's historical MFA reused as support assurance | Support tokens carry no `acr`/`amr`/`auth_time` of the target; actor MFA time stored separately | — |
| I-13 | Support token accepted by a non-participating resource | Opaque tokens are only usable through introspection, which is restricted to registered introspectors of the token's audience | TEST-037 |
| I-14 | Feature enabled with no resource ready | Request refused until a strict-online resource opts in | `IMP-001` subtest |

## Residual risks and gaps

These are known differences from §16; treat them as limitations.

1. **No intersection with the target's current permissions at the IdP (IMP-007,
   IMP-017).** The scope ceiling is the resource's support policy ∩ requested
   scopes (∩ the operator's `support_scopes` capability when set); the target's
   permissions are not part of it. A resource gets the target's
   current permissions only by calling the decision API (`POST
   /authorization/check`) with the support token, which evaluates the target's
   effective permissions, or by checking its own data. A reduction of the target's
   permissions therefore affects support access only where the resource does so.
2. **Disabling ends live grants, but realm state is not re-checked.**
   `ValidateGrant` re-checks the deployment switch, the realm switch, the
   resource's `impersonation_enabled` flag and verification mode, the
   organization's `support_access_opt_out` policy and the customer's opt-out on
   every introspection, so turning any of them off makes live support tokens
   inactive immediately (no test exercises this yet). Realm state (for example a
   suspended realm) is not part of that check, and there is no bulk-revoke
   endpoint; the grants stay `active` in the inventory until they expire.
3. **Denial evidence is recorded after rollback; self-targeting is not.**
   `RequestAccess` writes `support.impersonation.denied` and `RedeemHandoff` writes
   `support.handoff.rejected` after the failed transaction rolls back, so the
   evidence survives (and feeds the `impersonation_denied` security signal). An
   operator targeting themselves is refused without an audit event. No test
   asserts these denial events.
4. **Protected actions and write allowlist (resolved).**
   `authorization.ImpersonationForbiddenActions` equals the SDKs' protected
   operations (Go `verifier.ProtectedOperationList()`, Node.js
   `PROTECTED_OPERATIONS`; including `secret` and `purge`), and
   `IsSupportForbidden` and `IsWriteAction` use the SDK rule: segments split on
   `.`, `:` and `/`, matched as a contiguous run with simple plurals, and any
   write-verb segment makes an action a write whatever its suffix (IMP-011,
   IMP-013). The decision API denies protected actions for every support token
   in either mode, and allows an `allowlisted_write` grant only the writes the
   resource lists in `impersonation_policy.write_actions`. The server's
   classification runs the shared fixture too
   (`TestSupportClassificationMatchesSDKTable`); the decision API's
   `write_actions` check has no end-to-end test. The Go SDK keeps the lists
   unexported and hands out copies (`verifier.ProtectedOperationList()`,
   `verifier.WriteSegmentList()`, `verifier.DefaultOnlineKindList()`), and the
   Node.js SDK freezes them, so code in the same process cannot weaken them.
   In Node.js, a list passed as the second argument of
   `isProtectedOperation(op, list)` replaces the defaults (`SupportGuard`
   merges its own list with them).
5. **Target revocation is unconditional.** The target can always revoke; there is
   no policy to disable it (IMP-016 says "where policy permits").
6. **Resource enforcement is the resource's responsibility.** A resource that
   introspects but ignores `token_kind`, `support_mode` and `act` is not prevented
   from treating the token as the customer's own. Use `SupportGuard` or an
   equivalent and call `Validate()` at startup.
7. **Evidence of one grant** (IMP-024): the audit filter
   `impersonation_grant_id` (query and export) also returns the grant's
   request-phase events (`support.impersonation.requested` and `.approved`,
   which target the request), and `support.impersonation.started` carries
   `request_id`. A denied request never becomes a grant, so
   `support.impersonation.request_denied` is found by the request ID
   (`target_id`), not by this filter. Any request presenting a `pa_it_`-shaped
   bearer to an IdP API writes a `support.token.rejected` event, including
   unknown tokens, until its network has presented
   `security.rate_limits.api_token_failures_per_network` of them (300 per
   `token_window` by default) in the window: further ones get
   `429 rate_limited` and are neither looked up nor recorded, so a refusal
   from a flooding network can be missing from the evidence (SEC-006).
8. **Grant inventory filters** are actor, target, organization, state and
   `ticket_reference` (IMP-023); results are cursor-paginated, but the underlying
   query still returns at most the 500 newest matching grants.
9. **Introspection audit is best-effort.** `support.token.introspected` is written
   outside a transaction and its error is ignored; the authoritative per-request
   record is the resource's `SupportAuditor`.
10. **Customer approval** uses the tenant route with an account-audience token; the
    customer does not need MFA to approve.
11. **Customer-visible reason only before approval.** Requests awaiting the
    customer's approval show the reason and ticket in `GET /me/impersonation-requests`,
    and the approval email includes the reason (IMP-022). Issued grants listed in
    `/me/impersonation-grants` still omit the reason.

## Not impersonation: just-in-time elevation

Just-in-time elevation (AZ-024,
[elevation-and-access-reviews.md](../integrations/elevation-and-access-reviews.md))
is sometimes confused with support access. It is different: the elevated
person acts **as themselves**, with a role they were made eligible for, for a
bounded time, after an independent approval (always, for privileged roles).
Their tokens and audit events name them; no customer's identity is involved,
no support token exists and none of the controls above apply. The threats are
those of any role assignment (delegation ceilings, separation of duties,
self-approval) and are covered in the
[system threat model](system.md#4-administration-api). Use support access to
act for a customer, and elevation to hold more of your own authority for a
while; neither substitutes for the other.
