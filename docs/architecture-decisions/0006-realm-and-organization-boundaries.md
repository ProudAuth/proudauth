# 0006. Identity boundaries: realm = issuer and user namespace; organization = business tenant

**Status:** Accepted

## Context

The product must serve one person who belongs to several customer organizations
without duplicating credentials, while also allowing genuinely separate identity
namespaces (§4.3). An organization administrator must not be able to alter a
shared user's global credentials (TEN-023).

## Decision

- **Realm** (`realms` table): the security boundary with a canonical issuer
  `server.public_origin + "/realms/" + name`, its own users, identifiers, clients,
  API resources, roles, signing keys (`signing_keys.realm_id`) and security policy
  (`realms.settings`). Realms are created only through the operator CLI
  (`identity-cli realm-create`). A realm can be suspended
  (`POST /api/v1/realms/{realm}/emergency/realm-state`), which stops grant issuance
  and the custom APIs for that realm.
- **Organization** (`organizations` table): a business tenant inside a realm.
  Users are realm-wide; their relationship to an organization is a `memberships`
  row (one live membership per user and organization, DB-004). Organization roles
  are assigned through the membership (`role_assignments.membership_id`, enforced
  by a CHECK constraint, AZ-003).
- Organization policy (`organizations.policy`) can only tighten realm policy (MFA
  required, shorter session lifetimes, allowed email domains, support-access
  opt-out and approval mode).
- Global account operations (suspend, delete, credential and MFA reset) require
  realm permissions (`realm.users.*`); organization permissions (`org.*`) cannot
  reach them.

## Alternatives considered

- **Organization = realm** (one user namespace per customer): forces duplicate
  accounts for people in several organizations.
- **Single global namespace without realms**: no way to give a customer an
  independent issuer and user namespace.

## Consequences

- Separate realms share the deployment, database, root keys and operators. They
  are **not** physical isolation (§4.3, TEN-019). Stronger isolation needs separate
  deployments with separate keys and databases.
- Organization administration is reachable with an account-audience token
  (`/api/v1/realms/{realm}/organizations/...`); realm administration requires an
  admin-audience token from an MFA session.
- The `sso_required` organization policy (with `sso_provider_id`) requires a
  federated factor from that organization's connection; no local-password
  alternative is offered to SSO-routed users, and switching into the organization
  without a federated factor from `sso_provider_id` (any federated factor when it
  is unset) returns `sso_required`. `TestFederation` covers this
  (TEST-027); the switch rules are listed in
  [ADR 0012](0012-one-organization-per-token.md#decision).

## Update (2026-10)

The decision stands. These additions to the organization boundary were made
after acceptance:

- **Join requests** (INV-013, `internal/organization/groups.go`,
  `TestMembershipLifecycle`): a request creates a `pending_approval` membership
  that grants nothing until a reviewer decides. Reviewers (users holding
  `org.join_requests.review` in the organization, at most 20 notified) are
  emailed that a request waits, without the requester's identity. An
  administrator with `org.members.write` can assign 1–10 reviewers to a request
  (`POST /organizations/{org}/join-requests/{id}/reviewers`); every assignee must
  hold `org.join_requests.review` and none may be the requester, and then only
  the assignees or a reviewer who also holds `org.members.write` can decide.
  Self-approval is refused. The requester sees only their own requests
  (`GET /me/join-requests`, never reviewers or member lists), can withdraw a
  pending one (`POST .../join-requests/{id}/withdraw`), and is emailed the
  decision. Requests expire after 14 days.
- **Domain re-verification** (TEN-009, migration `0030`, `TestDomainReverification`):
  a verified domain keeps a digest of the DNS proof that verified it and is
  re-checked by the worker (`domains.recheck`) every realm policy
  `domains.recheck_days`; after `domains.lapse_after_failures` consecutive
  failed daily retries the verification lapses (state `expired`), so a domain
  whose proof was removed, for example after the domain changed hands, stops
  routing sign-ins and satisfying domain rules. See
  [identifiers.md](../protocols/identifiers.md#organization-slugs-and-domains).
- **Tenant fairness** (TEN-018, `TestTenantFairness`): organizations share the
  deployment, so one tenant's load is bounded: per-organization password and
  token budgets (`security.rate_limits.login_per_organization`,
  `organization_per_window`), a per-organization share of each worker batch of
  notifications (`workers.tenant_batch_share`) and a cap on an organization's
  concurrently running jobs (`workers.max_jobs_per_organization`). These bound
  starvation; they are not isolation (§4.3).
- **Aliases and domain routing** (TEN-011, migration `0034`,
  `TestOrganizationAliasesAndDomainRouting`): a renamed organization keeps its
  former slug as an alias, administrators can reserve more aliases, and a name
  is never shared by two organizations of a realm, so a link or `organization`
  parameter that used an old name cannot start pointing at another tenant.
  Email-domain routing has one explicit rule instead of silent ambiguity: an
  exact verified domain wins, otherwise the longest verified parent domain
  that opted into `include_subdomains`. See
  [identifiers.md](../protocols/identifiers.md#organization-slugs-and-domains).
- **Onboarding templates** (TEN-017, migration `0032`,
  `internal/organization/templates.go`, `TestOrganizationTemplates`): realm
  administrators keep versioned templates (organization policy, custom roles,
  groups and the roles granted to them); an organization administrator with
  `org.update` applies one, after an optional dry run, in one transaction. An
  application only adds what is missing and replaces the organization policy;
  it never rewrites an existing role (a role with other permissions is a
  conflict and the application fails with `409`), and roles and grants are
  created with the applying administrator's authority, so templates cannot
  exceed delegation ceilings, and template roles cannot carry `realm.*` or
  `support.*` permissions. A template can also define up to 20 service
  principals and 20 webhook subscriptions: service principals are created
  owned by the organization, allowed only for it, named
  `<organization slug>-<name>` and given roles in its scope, never
  credentials. An existing service principal counts as the template's only
  when its name is exactly `<slug>-<name>` for the organization's current
  slug or one of its former slugs (aliases); one with that name owned
  elsewhere is a conflict ("service principal ... exists outside this
  organization"). Subscriptions are organization-scoped, HTTPS and limited to
  public addresses, and their signing secrets are returned once in
  `webhook_secrets`. Applying them needs `org.service_principals.write` or
  `org.integrations.write` in the organization, otherwise the plan reports a
  conflict. A grant that direct assignment would hold for a second
  administrator (a role that requires approval, or a privileged role for an
  agent service principal, AZ-018, MCH-017) is a conflict too ("... needs an
  independent approver: assign it through POST /role-assignments"); once it is
  approved directly, the template reports it unchanged. Templates do not
  cover clients, identity providers or credentials.
- **Dynamic groups** (TEN-014, migration `0033`, `internal/organization/dynamic.go`,
  `TestDynamicGroups`): a group can take its members from a rule over realm
  profile attributes (`all` of up to 5 `equals` / `in` conditions). Only
  attributes the realm schema marks as not `user_editable` qualify, because a
  group can carry roles and users must not be able to grant themselves those
  roles by editing their profile; setting a rule needs the authority to grant
  the group's roles. Rules are recomputed when set and every 10 minutes by the
  worker (`groups.dynamic`), with `recomputed_at`, `member_count` and `error`
  reported; a rule that stops validating fails closed and removes every
  rule-derived member. A rule that matches more than 10000 members records
  that as its `error` and leaves the memberships unchanged; they grant nothing
  while the error stands. `member_count` counts actual members, not those
  skipped for incompatible roles. Manual membership changes are refused while a rule is
  set. Every member a rule adds or removes is audited (`group.member.added` /
  `.removed` with `source: "dynamic"`, or `dynamic_rule_set` for manual
  members dropped when a rule is set). Rule-derived memberships grant roles
  only while the group was recomputed within
  `security.dynamic_group_max_staleness` (1 hour by default) and its rule has
  no error (AZ-010), so a stopped worker does not freeze access. Removing the
  rule keeps the members listed, but their rule-derived memberships then grant
  nothing; remove and re-add a member to keep their roles.
- **Group authority** (TEN-008, TEN-013, AZ-018,
  `internal/organization/groups.go`): adding a member to a group
  (`POST /organizations/{org}/groups/{group}/members`, `org.groups.write`;
  a removed or expired membership is refused with `422` on `membership_id`,
  "the membership has ended")
  requires that the administrator could assign every role granted to the
  group **and to its ancestor groups** (`403 forbidden` without
  `org.roles.assign`, `403 grant_ceiling_exceeded` for a role beyond their
  delegable set). Moving a group under another parent
  (`PATCH /organizations/{org}/groups/{group}` with `parent_id`; `""` moves it
  to the top level) requires the same for the roles of the new parent and its
  ancestors, and counts the height of the moved subtree against
  `limits.max_group_depth` (`422` on `parent_id`: depth limit, cycle or unknown
  parent). Both run the separation-of-duties check
  ([ADR 0013](0013-authorization-model.md#update-2026-10)). `group.updated`
  carries `parent_id` and `previous_parent_id` when the parent changed, and
  every group update increments the membership revision of every member of
  the group's subtree, which changes their decision cache keys and token
  authorization version.
- **Domain conflicts** (TEN-009): verifying a domain
  (`POST /organizations/{org}/domains/{id}/verify`) that another organization
  of the realm already holds verified sets the claim's state to `conflict`,
  records `organization.domain.conflict` (category `security`, outcome
  `denied`, metadata `domain`) and answers `409 conflict` ("domain is verified
  by another organization"). Two verifications racing for the same domain also
  get `409`, without the `conflict` state or audit event. The worker's
  re-verification only re-checks domains that are already verified. A
  removed or expired claim can no longer be verified (`409`, "the domain
  claim is <state>; add the domain again"), and a verification that races a
  removal fails (`409`, "the domain claim changed; add the domain again"). An
  expired claim must be removed (`DELETE .../domains/{id}`) before the domain
  can be added again.
- **Organization connections** (TEN-007, FED-006): `policy.sso_provider_id`
  must name a realm-wide connection or the organization's own; another
  organization's connection is refused when the policy changes
  (`PATCH /organizations/{org}`, `422` on `policy.sso_provider_id`).
  `POST /organizations` validates a policy given at creation the same way,
  and there only a realm-wide connection can be named (the organization has
  no connection of its own yet): `422` on `policy.sso_provider_id`
  ("unknown connection, or one that belongs to another organization"). An
  organization's own connection never authenticates into another
  organization's context:
  - it is offered only in transactions for that organization or without an
    organization context, and starting it in a transaction for another
    organization is refused (`422` on `provider`);
  - a transaction whose organization context (requested or selected)
    differs from the connection's organization is blocked: its state
    carries `error: "connection_not_allowed"` and no next action;
  - choosing another organization after signing in through it
    (`select_organization`) and switching to another organization
    (`POST /me/organization-grants`) get `403` ("the connection used to sign
    in belongs to another organization").

  Without an organization context the connection can still be used, and an
  unknown or deleted connection counts as another organization's.
- **Provisioning connectors** (PROV-001..PROV-009): an organization's members
  and groups can be provisioned through SCIM 2.0 by connectors bound to the
  organization; a connector acts only on what it provisioned, deprovisioning
  removes only the organization membership, and roles come only from approved
  mappings within a ceiling no wider than the creating administrator's
  ([scim-provisioning.md](../integrations/scim-provisioning.md)).
- **Organization mail servers** (TEN-022): an organization's owner can send its
  mail through the organization's own SMTP server; the password is encrypted
  under a key bound to the realm and organization and is never used for another
  tenant ([ADR 0016](0016-delivery-adapters.md#decision)).

## Migration implications

Moving users between realms is not supported and must never be done by email
matching (DOM-006); it requires export, import into the target realm and
re-verification.

## Related requirement IDs

DOM-002, DOM-003, DOM-005, DOM-006, DOM-007, DOM-008, TEN-003, TEN-004, TEN-007, TEN-008, TEN-009, TEN-011, TEN-012, TEN-013, TEN-014, TEN-015, TEN-017, TEN-018, TEN-019, TEN-022, TEN-023, INV-013, AZ-003, AZ-010, AZ-018, FED-006, PROV-001..PROV-009, §4.3
