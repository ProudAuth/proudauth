# Organization relationships and partner project access

Two features let organizations of one realm work together without giving up
their boundaries:

- **Organization relationships** (TEN-021) record that two organizations are
  related: `parent_child` or `partner`. A relationship **grants nothing** by
  itself.
- **Partner project access** (TEN-020) lets the organization that owns a
  project share selected project roles with a related organization, which can
  assign only that subset to its own members. It completes the project
  grants introduced for project-access invitations (INV-012).

Code: `internal/organization/relationships.go`,
`internal/application/projectgrants.go`, `internal/httpapi/orgrelations.go`,
migration `0081_organization_relationships`. Test:
`TestOrganizationRelationshipsAndPartnerProjects`
(`tests/e2e/orgrelations_test.go`). Boundaries in general:
[ADR 0006](../architecture-decisions/0006-realm-and-organization-boundaries.md).

## Relationships (TEN-021)

### What a relationship does and does not do

A relationship is a recorded, reviewed fact. No membership, role or
permission follows from it: the owner of a parent organization cannot read a
child's members, and partners cannot read each other's members (both are
tested). Access across organizations still needs one of:

- a project grant (below), or
- an explicit role assignment by someone with authority in the target
  organization.

The only thing a relationship enables is that an organization administrator
may share a project with the related organization (a realm administrator can
share without one). Policies that should depend on relationships (for
example ABAC policies or a policy engine) must test for them explicitly; none
does by default.

### API

| Method and path (under `/api/v1/realms/{realm}`) | Permission | Effect |
| --- | --- | --- |
| `GET /organization-relationships` | `realm.organizations.read` | Every relationship of the realm (at most 500, newest first) |
| `GET /organizations/{org}/organization-relationships` | `org.relationships.read` | The organization's relationships in both directions |
| `POST /organizations/{org}/organization-relationships` | `org.relationships.write` | `{"kind", "target_organization_id", "note"}` → `201` |
| `POST /organizations/{org}/organization-relationships/{id}/accept` | `org.relationships.write` | Only the target organization; `proposed` → `active` |
| `POST /organizations/{org}/organization-relationships/{id}/decline` | `org.relationships.write` | Only the target organization; `proposed` → `declined` |
| `POST /organizations/{org}/organization-relationships/{id}/end` | `org.relationships.write` | Either side; `proposed` or `active` → `ended` (`204`) |

The path segment is `organization-relationships` because
`/organizations/{org}/relationships` holds relationship tuples for
relationship-based authorization (AZ-021,
[relationship-authorization.md](relationship-authorization.md)).

- `kind` is `parent_child` (the organization in the path is the **parent**,
  the target is the child) or `partner`. `note` is at most 500 characters.
- When the caller holds `realm.organizations.write` in the realm, the
  relationship is `active` at once (audit `organization.relationship.created`).
  Otherwise it is `proposed` (audit `organization.relationship.proposed`) and
  takes effect only when an administrator of the target organization accepts
  it. The proposing side cannot accept its own proposal (`403`).
- Both organizations must be active organizations of the realm (`422`).
- One live (`proposed` or `active`) relationship per pair and kind (`409`); a
  child has at most one parent (`409`); a parent/child link may not create a
  cycle (`409`), and hierarchies are at most 10 levels deep (`409`).
- Accepting or declining anything but a proposal, or ending a relationship
  that already ended, is `409`. A relationship of another organization is
  `404`.

A relationship returns `id`, `kind`, `source_organization_id`,
`target_organization_id`, `state` (`proposed`, `active`, `declined`,
`ended`), `note`, `created_by`, `decided_by_id`, `created_at`, `decided_at`
and `ended_at`.

Permissions (built-in catalog): `org.relationships.read` (sensitivity
`normal`; organization `admin` and `owner`), `org.relationships.write`
(`high`; `admin` and `owner`). Like other permissions that change authority
in an organization, users exercising `org.relationships.write` need an MFA
session unless the realm waived it for organization administrators.

Audit (category `authorization`): `organization.relationship.proposed`,
`.created`, `.accepted`, `.declined`, `.ended`.

## Partner project access (TEN-020)

### Owner side: sharing a project

| Method and path (under `/api/v1/realms/{realm}/organizations/{org}`) | Permission | Effect |
| --- | --- | --- |
| `GET /projects/{project}/grants` | `org.projects.share` | The project's grants |
| `POST /projects/{project}/grants` | `org.projects.share` | `{"organization_id", "allowed_role_ids", "valid_until"}` → `201` |
| `POST /projects/{project}/grants/{id}/revoke` | `org.projects.share` | `204`; revoking a revoked grant is a no-op |

- `{org}` must own the project; otherwise `404`.
- The grantee must have an **active relationship** (either kind, either
  direction) with the owner organization (`422` on `organization_id`),
  unless the caller holds `realm.projects.write`.
- `allowed_role_ids` (at most 50) is the subset of the project's own roles
  the grantee may hand out; every role must be a project role of that project
  (`422`). An empty list delegates nothing. `valid_until` is optional and
  must be in the future.
- One grant per project and organization (`409`); the owner organization
  itself needs none (`422`); the project must be active (`409`).
- `org.projects.share` has sensitivity `privileged`: organization owners hold
  it through `org.*`, the built-in `admin` role does not. It needs an MFA
  session like other organization-authority permissions.

Realm administrators keep `GET`/`POST /api/v1/realms/{realm}/projects/{project}/grants`
and `.../grants/{id}/revoke`, which do not require a relationship.

Audit (category `authorization`): `project.grant.created` (project, allowed
roles) and `project.grant.revoked` (number of assignments removed).

### Partner side: assigning the shared roles

| Method and path (under `/api/v1/realms/{realm}/organizations/{org}`) | Permission | Effect |
| --- | --- | --- |
| `GET /project-grants` | `org.roles.read` | Live grants the organization holds (active and not past `valid_until`) |
| `GET /project-role-assignments` | `org.roles.read` | Project roles this organization assigned (at most 1000) |
| `POST /project-role-assignments` | `org.roles.assign` | `{"project_id", "role_id", "user_id", "expires_at"}` → `201` |
| `DELETE /project-role-assignments/{id}` | `org.roles.assign` | `204`; only assignments this organization made (`404` otherwise) |

Rules for an assignment:

- The user must be an active member of `{org}` (`422` on `user_id`).
- The role must be a role of that project (`422`), and the project active.
- For a project `{org}` does **not** own, the organization needs a live
  grant for it (`403` "the organization has no access to this project") and
  the role must be in the grant's `allowed_role_ids` (`403`
  `grant_ceiling_exceeded`). The assignment is recorded against the grant.
- For a project `{org}` owns, its administrators with `org.roles.assign` can
  assign any role of the project to their own members.
- A caller whose own delegation ceiling already covers the role (for example
  a realm administrator) is not limited by the grant, and the assignment is
  then not tied to it.
- `expires_at` is optional.

Partner members can also be invited to the project through project-access
invitations (INV-012), which use the same grant ceiling.

Where the roles take effect (AZ-002): a project role counts only for
resources of its project — token scopes of a resource whose `project_id` is
the project, and decisions naming it in `resource.project_id` — never at
organization or realm level. In an organization's context it counts only
while the project belongs to that organization: the owner, or a grantee
whose grant is live. So partner members use their project roles in the
partner organization's context (or with no organization, for resources that
do not require one), and lose them there when the grant ends.

### What ends partner access

| Event | Effect |
| --- | --- |
| The owner revokes the grant | Every assignment made through it is removed in the same transaction, both those from project invitations and those assigned directly |
| `valid_until` passes | The grant ends (the worker's expiry task, within a pass of the deadline): it becomes `revoked`, every assignment made through it is removed, and `project.grant.expired` is recorded |
| The member leaves or is removed from the partner organization | The project roles that organization assigned to them are removed |
| The relationship ends | No new grants by organization administrators; **existing grants stay** until the owner revokes them |
| The assignment's `expires_at` passes | The assignment stops counting, as for any expiring role assignment |

Removing an assignment, one at a time or with a revoked or expired grant,
increments the holder's authorization revision, so cached decisions are
re-evaluated; a single removal is audited as `authorization.role.unassigned`,
a grant's removals by its `project.grant.revoked` or `project.grant.expired`
event (`assignments_removed`).

## Not supported

- Inherited access along parent/child links (by design; TEN-021 forbids
  implicit cross-organization access).
- Sharing a whole organization rather than a project.
- Grants that delegate the right to re-share (a grantee cannot create grants
  for a third organization).
