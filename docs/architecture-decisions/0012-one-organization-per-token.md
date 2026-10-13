# 0012. Organization context: one organization per business token

**Status:** Accepted

## Context

A user may belong to several organizations. If a token represented all of them,
any service bug in tenant filtering would cross tenants. DOM-003 and TEN-005
require exactly one active organization per business token and a fresh grant to
switch.

## Decision

- An authorization grant (`authorization_grants.organization_id`) names at most one
  organization. Access tokens for resources with `requires_organization` (the
  default for `business` resources) carry that organization as `org_id`; issuance
  fails with `invalid_target` when the grant has none.
- The organization is chosen during the authentication transaction: an
  `organization` request parameter (bound only after active membership is
  confirmed; a non-member is blocked, never silently switched) or a
  `select_organization` next action listing only the caller's own active
  memberships.
- Switching organizations: `POST /api/v1/realms/{realm}/me/organization-grants`
  (user tokens of the requesting client; PKCE `S256` and a registered
  `redirect_uri`) re-checks membership and organization state and holds the
  current session to the target organization's sign-in rules as a sign-in
  into it would (TEN-005, TEN-012):
  - `policy.mfa_required` without an MFA session: `403 step_up_required` with
    obligation `{"type": "reauthenticate", "required_profile": "mfa"}`;
  - `policy.sso_required`: the session must contain a federated factor from
    `policy.sso_provider_id` (any federated factor when it is unset),
    otherwise `403 sso_required`;
  - `policy.allowed_login_methods`: one of the session's factors must be an
    allowed method, otherwise `403 step_up_required` with obligation
    `{"type": "reauthenticate", "allowed_login_methods": [...]}`;
  - `policy.session_absolute_seconds`: the new grant expires at the earlier
    of the session's absolute expiry and `auth_time` plus that lifetime; once
    it has passed, `403 step_up_required` with obligation
    `{"type": "reauthenticate"}`.

  On success it creates a new grant (without `offline_access`), records
  `organization.context.switched` and returns `{"redirect_to": ...}` carrying
  an authorization code for the requesting client. `session_idle_seconds` is
  not checked. A client that must use pushed authorization requests
  (`fapi2`, `high_assurance` or `token_policy.require_par`) gets `403`: it
  switches with a new pushed authorization request naming the organization.
- Account, admin and UserInfo tokens never carry `org_id`.
- Issuance and every refresh re-check that the organization is active (locked
  `FOR SHARE`) and the membership is active.
- Machine tokens: `organization` must be the service principal's owner
  organization or in its `allowed_organization_ids`.
- Token exchange preserves the subject token's organization.

## Alternatives considered

- **List of organizations in the token**: rejected (DOM-003).
- **Organization selected by request header at the resource**: rejected; headers
  are not authority (TEN-005, §28.2).

## Consequences

- Resource servers must compare `org_id` with the organization of the object they
  serve, taken from their own data (`Claims.RequireOrganization` in the Go SDK).
- Users working in two organizations hold two grants and two token sets.

## Migration implications

None; organization context is per grant and is not persisted in clients.

## Related requirement IDs

DOM-003, TEN-005, TEN-012, MCH-004, TEST-007, TEST-008, TEST-033, §15.2, §37.1
