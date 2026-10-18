# 0013. Authorization: scoped RBAC with delegation ceilings and a decision API

**Status:** Accepted

## Context

The IdP must separate IdP administration from application permissions
(AZ-005), prevent delegated administrators from granting more than they hold
(AZ-006, TEN-008), deny by default (AZ-007), and offer resource servers a policy
decision contract (§15.3) while applications keep enforcing object ownership.

## Decision

- **Permissions** are namespaced. Built-in namespaces: `realm.*` (identity-domain
  administration), `org.*` (delegated organization administration), `support.*`
  (support operators). Applications register their own permissions
  (`POST /api/v1/realms/{realm}/permissions`); they can never imply IdP
  administration.
- **Roles** have a boundary (`realm`, `organization`, `project`), may include
  `allow` and explicit `deny` permissions (deny overrides allow), and may be
  composite (cycle-checked, expansion bounded by `limits.max_role_expansion`).
  Built-in roles: `realm-admin`, `user-admin`, `realm-auditor`,
  `support-operator`, `support-approver`, `resource-server`, and organization roles
  `owner`, `admin`, `member` (`internal/authorization/catalog.go`).
- **Assignments** are scoped to a realm, organization or project. Users receive
  organization roles only through their membership; groups can hold roles, with
  group nesting bounded by `limits.max_group_depth`.
  A revocation updates holder revisions and emits audit/outbox evidence
  only when its delete removes a row. Concurrent API losers receive
  `404`; expiry workers tolerate assignments another worker already
  removed, without counting or recording an additional transition.
- **Ceilings**: creating or editing a role, and assigning one, requires the actor to
  effectively hold every permission involved, including through composites.
  Incompatible roles are rejected at assignment.
- **Decision API**: `POST /api/v1/realms/{realm}/authorization/check` and
  `/check-batch` (admin audience, `realm.authorization.check`). The subject is a
  `subject_token` that the calling service could introspect, or a free-form subject
  only for callers holding `realm.authorization.simulate`. The decision denies on
  missing input, organization mismatch, unknown subject or missing permission;
  permissions marked `privileged` require authentication within 5 minutes with an
  MFA or phishing-resistant ACR, otherwise the response carries
  `reason_code: STEP_UP_REQUIRED` and a `reauthenticate` obligation. Support tokens
  are denied protected identity actions and, in read-only mode, any action not
  ending in `.read`, `.list`, `.view`, `.get` or `.search`. `cache_ttl_seconds` was
  always 0 at acceptance (see the update below). Denials and privileged or
  support decisions are audited.

## Alternatives considered

- **Global user roles**: leak across tenants (AZ-003).
- **Embedding an external policy engine** (OPA, Cedar, OpenFGA): not embedded.
  Since Update 2026-10 an operator-configured engine can be called by the
  decision API through an adapter (AZ-026, [below](#update-2026-10)), and a
  bounded relationship model is built in (AZ-021); neither engine runs inside
  the server.

## Consequences

- Applications still enforce ownership of their own objects (§15.2); the decision
  API answers "may this subject perform this action in this organization".
- At acceptance, ABAC policy authoring, versioning and simulation were not
  implemented, and `requires_approval` relied on a caller-asserted `approver_id`.
  Both have since changed; see the update below.
- Relationship-based authorization, which this record left out at
  acceptance, now exists in a bounded form (see the update below). The
  `App.PolicyEval` extension point in `internal/httpapi/app.go` is still never
  set; published policies are evaluated directly by the decision code instead.

## Update (2026-10)

The decision above stands. RBAC remains the source of grants for IdP
administration; for application permissions in the decision API, relationship
tuples and an external engine in `decide` mode can also grant (both described
below). These additions were implemented after acceptance; most of them only
restrict:

- **ABAC policies** (AZ-013, AZ-015..AZ-017, AZ-019; `internal/authorization/policy.go`,
  `policystore.go`, routes in `internal/httpapi/policies.go`). Policies are typed,
  bounded documents (at most 50 rules, condition depth 8, 64 condition nodes)
  scoped to the realm or one organization, with `deny` and `require` rules over
  `subject.*`, `resource.*`, `context.*` and `environment.*` attributes. They are
  evaluated after RBAC by `/authorization/check` and `/check-batch` and can only
  deny or add obligations, never grant. Evaluation is three-valued: a condition
  over a missing or mistyped attribute applies the rule, so missing input denies
  (`POLICY_ATTRIBUTE_MISSING`) rather than allows. Subject attributes come from the
  validated subject token and the IdP's records; resource and context attributes
  are asserted by the authenticated calling service. The decision's
  `policy_version` names every evaluated revision (`name@version`).
- **Versioning and publishing** (`/api/v1/realms/{realm}/policies`): revisions are
  immutable and hashed; only a published revision is evaluated; staging,
  `diff`, `rollback` (a new revision with the old content) and disabling are
  audited. Other nodes see a newly published revision within 5 seconds
  (`PolicyCacheTTL`). Permissions: `realm.policies.read`, `realm.policies.write`,
  `realm.policies.publish`.
- **Simulation** (`POST /api/v1/realms/{realm}/authorization/simulate`,
  `realm.authorization.simulate`): evaluates up to `limits.max_batch_size` checks
  against the current policies and, optionally, a candidate revision or draft
  definition, returns `current` and `candidate` decisions and a `changed` count,
  and is not audited as real decisions. `subject_attributes` (assumed `acr`,
  authentication age, client, organization) are accepted only here; a real
  `/authorization/check` with them is denied
  (`SUBJECT_ATTRIBUTES_SIMULATION_ONLY`, AZ-016).
- **Conditional grants** (AZ-012, `conditions.go`): role assignments may carry
  `conditions` (`client_ids`, `resources`, `min_assurance`,
  `max_auth_age_seconds`, `active_hours_utc`, `weekdays`, and for support operators
  `organization_ids`, `subject_categories`, `support_modes`, `support_scopes`) plus
  `valid_from`/`expires_at`. A condition that cannot be evaluated fails closed.
- **Separation of duties** (AZ-018): assigning a role with `requires_approval`
  through `POST /role-assignments` (or the organization member-roles route) now
  returns `202 pending_approval` and creates a request under
  `/role-assignment-requests`. The approver is the authenticated caller of
  `.../approve`, must differ from the requester and the subject, must be able to
  grant the role, and needs recent authentication; the requester's authority is
  re-checked at approval and requests expire after 7 days. A policy created with
  `requires_approval` publishes only revisions approved by someone other than their
  author. The policy rule is covered by `TestPoliciesAndConditionalGrants`; the
  role-assignment request workflow has no end-to-end test yet.
- **Incompatible roles** (AZ-018, `rbac.go` `HeldRoles`, `checkSeparation`,
  `TestSeparationOfDuties`): a role's `incompatible_role_ids` (set when the
  role is created; the relation is symmetric) are checked against everything
  the subject would hold: direct and membership-bound assignments, the roles
  of the user's groups and of those groups' ancestors, all expanded through
  composites, and the incoming role with its own composites. The check runs on
  role assignment (users and service principals; for a group grant, every
  member of the group and of its descendant groups), on adding a member to a
  group, on moving a group under another parent, and for SCIM group members
  and mapped roles. A conflict is `409 conflict` ("the subject would hold roles
  that are incompatible with each other (AZ-018)"). For service principals only
  direct assignments count. A dynamic group's recomputation leaves out a
  member whose roles would conflict with the group's (or its ancestors')
  roles and records `group.member.skipped` (category `authorization`,
  metadata `membership_id` and `source: "dynamic"`, once per new skip: a
  member skipped at the previous recomputation is not recorded again, as
  remembered by each worker process, so a restart or a new rule records a
  lasting skip once more; any error of the check counts as a conflict;
  `member_count` leaves skipped members out). A group move is checked against the roles of the old ancestors
  too, so moving a group away from a conflicting parent can be refused.
  Validation errors about `incompatible_role_ids` are reported under the field
  `composite_role_ids`.
- **Group grants need the authority of the whole chain** (TEN-008, TEN-013):
  adding or removing a group member, deleting a group, or moving a group
  under another parent requires that the administrator could assign every
  role of the group (or new parent) and its ancestors
  ([ADR 0006](0006-realm-and-organization-boundaries.md#update-2026-10)).
  Removing a member and deleting a group require it since 0.2.0-alpha.6;
  before, they needed only `org.groups.write`.
- **Conditional role-permission edits** (API-010):
  `POST /roles/{role}/permissions` and
  `POST /organizations/{org}/roles/{role}/permissions` accept an optional
  `If-Match` with the role's version (`W/"v<N>"`; a stale or malformed value is
  `412`). The realm route returns the new `ETag`; the organization route does
  not, so read the role again to get it. The version is compared before the
  caller's authority, so an unauthorized caller with a stale tag gets `412`
  rather than `403`.
- **Authorization hooks** (`authorization.decision`, `internal/hooks`) run last and
  can deny or add obligations, never grant; an unreachable hook denies
  (`TestPreActionHooks`).
- **Decision audit** (AZ-020, `internal/httpapi/decision.go`,
  `TestDecisionAuditSampling`): `/authorization/check` and `/check-batch` record
  the audit event `authorization.decision` (category `authorization`: decision
  ID, action, resource type and ID, reason code, subject, and for support tokens
  the support grant) for every denial, every privileged action and every
  decision about a support token. Once the subject token has been resolved,
  denials also carry the subject (`subject`), the support operator for support
  tokens (`metadata.actor`, from `act.sub`; for any token with an `act` claim
  also the whole delegation chain, `metadata.actor_chain`, AUD-005) and `impersonation_grant_id`
  (IMP-006); denials before that (`INVALID_REQUEST`, an inactive or
  unevaluable subject token) have no subject. The event's organization is the
  one named in the request's `resource`. Ordinary allowed decisions are not recorded
  unless realm policy `data_access.sample_allowed_decisions_percent` (0–100,
  default 0) samples them; sampled events carry `metadata.sampled: true`.
  Simulations are never recorded. Every refused authenticated API request is
  recorded once as `authorization.denied` (reason `PERMISSION_REQUIRED`,
  metadata `method` and `route` with IDs replaced by `{id}`, `permission` when
  one permission was missing, `concealed` when an organization's existence was
  hidden with 404), never the request body or query. A support token
  (`pa_it_`) presented to an identity-provider API is refused with
  `403 impersonation_restricted` and recorded as `support.token.rejected`
  (category `support`, reason `IMPERSONATION_RESTRICTED`, metadata `route`):
  when the token is known, the actor is the support operator (type `user`),
  the subject the customer, with the support grant and organization; an
  unknown token is recorded with actor type `support_token`, ID `unknown`.

- **Decision cache contract** (AZ-019, `internal/httpapi/decision.go`
  `cacheHint`, `TestDecisionCacheContract`): a decision made by RBAC alone (a
  `NOT_PERMITTED` denial, or an allow of a non-privileged action with no
  applicable ABAC policy, no active pre-action hook and no obligation, never
  for support tokens) carries `cache_key` and `cache_ttl_seconds`
  (`security.decision_cache_ttl`, 30 s by default, at most 10 minutes, `0`
  disables). Callers may reuse it for that long for requests with the same
  key; the server itself caches nothing. Update 2026-10: the key is a SHA-256
  over realm, subject, actor, client, the token's kind, audience and `acr`,
  organization, resource type and ID, the resource's project (with the
  project's state, owner and the organization's project grant), action, the
  subject's authorization revision, a fingerprint of the applicable role assignments (direct, of the
  subject's groups and of their ancestor groups, expanded through composed
  roles with the version of every role involved), the organization's state
  and authorization revision, the membership's state and revision, the policy
  version and the asserted context. Decisions are not cacheable when an
  applicable assignment has conditions, a future start or an expiry within
  the TTL, or the subject has rule-derived group memberships or group
  memberships with a validity window, so conditional grants never reuse a
  decision made for another token; nor when relationships were consulted or
  the realm uses an external policy engine. Role edits and (un)assignments
  bump the holders' revisions, service principals included, and a change to
  a role's permissions also bumps the holders of every role composing it, at
  any depth, and the members of groups holding them. Granting or removing a
  role on a group raises the membership revision of every member of the
  group and of its descendant groups (AZ-019). The TTL still bounds any change
  the key does not see. The SDK middleware does not cache decisions.
- **Stale group state** (AZ-010, `rbac.go` `groupClosure`): rule-derived
  (dynamic) group memberships count only while the group was recomputed
  within `security.dynamic_group_max_staleness` (1 hour by default) and its
  rule has no error; nested-group depth and cycle limits apply as before.
- **Relationship-based authorization, bounded** (AZ-021, AZ-022, AZ-023,
  AZ-027; migration `0053`, `relations.go`, `shares.go`,
  [relationship-authorization.md](../integrations/relationship-authorization.md)).
  Services register resource types (relations, `implied_by`, and which
  registered application permission each relation or one-hop
  `link.relation` gives) and write relationship tuples inside one
  organization; subjects are confined to that organization. When RBAC does
  not grant an action on an object of a registered type, `/authorization/check`
  evaluates the tuples (direct, implied relations, groups with ancestors,
  the organization as every active member, links), bounded at depth 6,
  64 object reads and 1000 tuples per object; a bound is a denial. Step-up,
  ABAC policies, an engine in `restrict` mode and hooks still apply to a
  relationship allow, and such decisions are never cacheable.
  `POST /authorization/list-objects` returns only objects verified one by one
  (at most 5000 candidates and 1000 checks), or `all: true` when an
  organization-wide grant covers the action. Users can share objects with
  members of the same organization (offer, accept, revoke) for relations the
  type marks shareable. Built-in permissions `realm.resource_types.*` and
  `realm.relationships.*` are held by `resource-server` (and the `.read` ones
  by `realm-auditor`). Relationship tuples can only grant registered
  application permissions, never IdP administration. Rejected alternative:
  a general Zanzibar-style service with arbitrary rewrites and consistency
  tokens; the bounds keep every decision's cost predictable.
- **External policy engines** (AZ-026, `policyengine.go`,
  [policy-engines.md](../integrations/policy-engines.md)): the operator
  configures engines (`security.policy_engines`: HTTPS URL, bearer token,
  timeout at most 5 s) and a realm names one in its policy (`policy_engine`).
  In `restrict` mode (default) the engine is asked after local rules allow
  and can only deny; in `decide` mode it is also asked after a local denial
  and may allow, with step-up, ABAC policies and hooks still applying after
  it. An unavailable engine denies (`EXTERNAL_POLICY_UNAVAILABLE`) unless the
  realm sets `on_error: local`. Decisions in such realms are never
  cacheable, and `policy_version` names the engine's version.
- **Just-in-time elevation** (AZ-024, migration `0054`, `elevation.go`,
  [elevation-and-access-reviews.md](../integrations/elevation-and-access-reviews.md)):
  administrators who could assign a role make another active user eligible
  for it at a scope, for at most 7 days at a time; the user asks from a
  recent MFA session with a reason; an approver who could assign the role
  and is not the requester approves (always required for privileged roles);
  the grant is an ordinary role assignment (`source: elevation`) with
  `expires_at`, removed by the expiry sweep. Separation of duties and
  delegation ceilings apply as for any assignment.
- **Access reviews** (AZ-025, migration `0055`, `reviews.go`, same page):
  campaigns snapshot up to 10000 role assignments of the realm or one
  organization, named reviewers keep or revoke each item (never their own),
  and closing (by an administrator or at the due date) revokes what was
  decided; the evidence export records every decision and outcome and states
  that it is not a regulatory certification. Permission
  `realm.access_reviews.manage` (privileged; `realm-admin` through `realm.*`).
- **Privileged roles** are recognized the same way everywhere (access reviews,
  elevation, migration reconciliation, exports, approvals; `rbac.go`
  `IsPrivilegedRole`): a role is privileged when it, or any role it composes
  at any depth, is marked privileged or holds a privileged permission,
  including wildcard grants (`*`, `x.*`) and custom permissions registered
  as privileged; a composition too large to inspect (more than 64 roles,
  the role and the existing roles it reaches) counts as privileged.
  Migration reconciliation uses the equivalent SQL condition
  (`PrivilegedRoleSQL`), with the same 64-role cap
  (`TestPrivilegedRoleCapConsistent`).
- **Agents** (MCH-017, [machine-clients.md](../integrations/machine-clients.md#agents)):
  service principals marked `is_agent` need an accountable human owner, and
  assigning them a privileged role always goes through the two-party request
  (`202 pending_approval`; neither requester nor subject may approve), whether
  or not the role is marked `requires_approval`. Their tokens carry
  `agent: true` (and `act.agent` after token exchange). Otherwise agents are
  ordinary service principals: no exemption from any check.
- **Inactive subjects hold nothing** (`rbac.go` `subjectActive`,
  `TestInactiveSubjectsHoldNoPermissions`): users that are suspended, locked,
  pending verification or deletion, or deleted, and service principals that
  are disabled or deleted, have no effective permissions anywhere, in
  decisions and in the worker's job re-checks (`recovery_restricted` accounts
  keep theirs).
- **Project-scoped assignments are evaluated** (AZ-002, `rbac.go`
  `EffectiveInProject`, `ProjectContext`, `TestProjectScopedRoles`). Before
  this fix, assignments with `scope.type: project` were stored but never
  evaluated by token issuance or the decision API. They now count, in
  addition to realm and organization assignments, wherever a resource
  belongs to a project: token scope policy (`required_permissions`) for a
  resource with a `project_id` (authorization code, refresh, device, token
  exchange, client credentials, personal tokens and API keys); the decision
  API when the request names `resource.project_id`; and the inspection views
  `GET /me/permissions` and `GET /subjects/{subject}/permissions` with
  `?project_id=`. They are the subject's own assignments (users and service
  principals; group-held project assignments are still not evaluated) and
  apply only to that project, only while it is active, and, in an
  organization's context, only when the project belongs to that organization:
  the organization owns it (`owner_organization_id`) or holds an active,
  unexpired project grant for it. A project role therefore grants nothing for
  another project, at organization or realm level, or in an unrelated
  tenant's context. The decision API validates `resource.project_id`: an
  unknown project denies with `UNKNOWN_PROJECT`, one outside the decision's
  organization (`resource.org_id`, or the subject token's) with
  `PROJECT_ORGANIZATION_MISMATCH`; the inspection views answer `422`. Explicit
  denies of any held role (realm, organization or project) override project
  allows, as everywhere (AZ-004); delegation ceilings are unchanged (project
  roles never carry identity-provider permissions, so they confer no
  administration); ABAC policies and engines see `resource.project_id`.
- **Composite roles are bounded per project** (AZ-011, `rbac.go`
  `validateRoleRefs`, `checkCompositeGraph`, `TestCompositeRoleBounds`,
  `TestCompositeRoleGraphChecks`): a project role may compose only roles of
  its own project (`422`, "cannot compose another project's role"). Creating
  a composite role checks, in one linear walk, that no cycle is formed and
  that the role with every role it reaches stays within
  `limits.max_role_expansion` (`422`, field `composite_role_ids`); before, the
  walk only bounded path depth, enumerated every path of a diamond-shaped
  composition, and a composite set larger than the bound failed with `500`.
  Composites are immutable after creation, so a cycle cannot be created
  through the API. Roles that are each within the bound can still together
  exceed it for a subject holding several of them; evaluation then fails
  closed: `Check` denies and the decision API answers `EVALUATION_ERROR`.
- **Backend enforcement is a contract test** (AZ-008,
  `tests/contract/authz_enforcement_test.go`
  `TestAuthenticatedRoutesCheckPermissions`): `a.admin`, `a.tenant`, `a.self`
  and `a.protected` only authenticate. Every route registered through them
  (directly or through a local wrapper) must reach a permission check
  (`a.can`, `a.requirePerm`, `a.orgGuard`, `a.dirScope`, `Authz.Check`,
  `Require`, `CheckAssignable`, `CheckObject`) or a service operation that
  authorizes the acting caller itself (role administration, approvals,
  elevation, support access), found by following App methods and local
  closures statically. The remaining routes are listed with their reason:
  self-service on the caller's own account, and items addressed to the
  caller (invitations, shares, approvals, reviews); a self-service exemption
  must be registered through `a.self`. A new route without a check, or a
  stale exemption, fails the test.

Tests: `TestPoliciesAndConditionalGrants` (`tests/e2e/policies_test.go`),
`TestPolicyDecisionContract`, `TestDelegationCeilings`,
`TestDecisionCacheContract`, `TestDynamicGroups`,
`TestRelationshipAuthorization`, `TestExternalPolicyEngine`,
`TestJustInTimeElevation`, `TestAccessReviews`, `TestProjectScopedRoles`,
`TestCompositeRoleBounds` (`tests/e2e/project_roles_test.go`),
`TestCompositeRoleGraphChecks`, `TestAuthenticatedRoutesCheckPermissions`.

## Migration implications

Built-in permission names are part of the API; renaming one requires a migration
of `role_permissions` and documentation of the change.

## Related requirement IDs

AZ-001..AZ-027, MCH-017, TEN-007, TEN-008, DOM-005, TEST-010, TEST-011, TEST-014, §15
