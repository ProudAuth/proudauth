# 0014. Impersonation: explicit, short, actor-preserving support grants

**Status:** Accepted

## Context

Support staff need to see what a customer sees without learning or changing the
customer's credentials, and without disguising who acted (§16.1). IMP-001..IMP-024
list non-negotiable controls.

## Decision

- **Disabled by default at three levels**: deployment configuration
  (`impersonation.enabled: false`), realm policy (`impersonation.enabled`), and at
  least one API resource must opt in (`impersonation_enabled` with
  `verification_mode: strict_online` and a recorded `contract_version`). Otherwise
  requests fail with `feature_disabled`.
- **Flow**: `POST /impersonation-requests` (admin audience, MFA within
  `security.admin_mfa_max_age`, permission `support.impersonation.start` in the
  target organization, reason of at least `impersonation.min_reason_length`
  characters, ticket when required) → optional independent approval
  (`second_operator`, `organization_owner` or `customer`; writes always need one)
  → `POST /impersonation-requests/{id}/issue` by the same operator, which re-checks
  everything and commits grant, audit and outbox before returning an opaque
  `pa_it_` token ([0010](0010-opaque-support-tokens.md)).
- **Targets excluded**: self, protected users, holders of privileged realm roles,
  organization administrators (`org.roles.assign`, `org.ownership.transfer` or
  `org.members.write`), non-members, suspended users, opted-out customers or
  organizations.
- **Scope**: the resource's `impersonation_policy.allowed_scopes` (and
  `write_scopes` only in `allowlisted_write` mode). The operator's own permissions
  are never added.
- **Lifetime**: at most 5 minutes (`impersonation.max_ttl`, realm
  `impersonation.max_ttl_seconds`, and the realm token-lifetime limits
  `tokens.impersonation_access_token_ttl_seconds` and
  `tokens.access_token_ttl_seconds`; the smallest applies); no refresh;
  exchange refused.
- **Handoff**: `POST /impersonation-grants/{id}/handoffs` creates a single-use code
  (`pa_hc_`, at most 30 s) bound to a confidential destination client, redeemed by
  that client's backend at `POST /impersonation-handoffs/redeem`.
- **Revocation**: by the actor, the target (`/me/impersonation-grants/{id}/revoke`
  or opting out), or a holder of `support.impersonation.revoke`. Introspection
  also stops succeeding when the actor or target is no longer active, the target's
  membership or the organization is no longer active, the actor's session ends, or
  the actor loses `support.impersonation.start`.
- **Downstream contract**: resources use `verifier.SupportGuard`, which
  introspects every request, requires the actor claim, denies protected
  operations, allows writes only for allowlisted operations in
  `allowlisted_write` mode, and writes an audit record before access.
- **One classification rule** (IMP-011, IMP-013; 2026-10 update): the SDKs'
  `SupportGuard` and the decision API classify operations the same way,
  pinned by the shared table `tests/fixtures/sdk-contracts/support-operations/cases.json`
  that the SDKs and the server's tests run. An operation is protected when
  the segments of a protected entry occur as a contiguous run in its name
  (split on `.`, `:` and `/`, simple plurals tolerated), and it is a write
  when any segment is a write verb, whatever its suffix. The decision API
  allows an `allowlisted_write` support token a write only when the resource
  lists the action in `impersonation_policy.write_actions`
  (`SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED` otherwise), the server-side
  counterpart of the guard's `WriteOperations`
  ([resource-servers.md](../integrations/resource-servers.md#6-support-access-contract)).

## Alternatives considered

- **Logging in as the customer** (shared session or password reset): violates
  IMP-006 and IMP-012.
- **JWT support tokens**: cannot meet strict-online revocation (IMP-010).

## Consequences

Detailed threats and residual gaps are in
[docs/threat-models/impersonation.md](../threat-models/impersonation.md). Notable
gaps: the IdP does not intersect the support scope with the target's current
permissions at issuance (resources must call the decision API or check their own
data), and a resource that does not use `SupportGuard` (or an equivalent) is not
prevented from accepting the token beyond what introspection reports. At
acceptance, turning the feature off did not end live grants and denied requests
were not persisted; since the 2026-10 update every introspection re-checks the
deployment, realm, resource, organization and customer switches, and denials are
audited after the failed transaction rolls back.

## Migration implications

The introspection fields `act`, `support_mode`, `impersonation_grant_id` and
`token_kind: impersonation_access` are part of the resource contract.
`impersonation_policy.write_actions` is a new, optional resource member (also
in the configuration document); a resource registered before it allows no
support writes through the decision API until it is set. An action with a
write-verb segment is a write even when it ends in a read suffix (for example
`orders.cancel.view`).

## Related requirement IDs

IMP-001..IMP-024, MFA-003, INT-010, TEST-040..TEST-047, TEST-071, §16

## Updates

**Update — 2026-10-18.** Recorded under the dated-update rule
([README](README.md#changing-a-decision)). Two changes were written into this
record in place in 2026-10. The **One classification rule** item was added to
the Decision with a security fix: the server classified support actions
differently from the SDKs, and an `allowlisted_write` support token could
perform any write through the decision API (IMP-011, IMP-013,
`TestSupportClassificationMatchesSDKTable`, `TestSupportWritesNeedAllowlist`).
The last sentence of Consequences records a fix: turning support access off
now ends live grants at their next introspection, and denied requests are
audited. The decision is unchanged.
