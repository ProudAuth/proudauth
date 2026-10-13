# Historical entitlement evidence

For an authorized investigation, ProudAuth can reconstruct what a user or
service principal was entitled to at a past instant (ADV-011): account state,
organization and group memberships, role assignments and the permissions they
carried, live OAuth grants, the ABAC policy versions published and the realm
policy revision in force. It is a reconstruction from retained evidence, not a
replay of decisions, and it says where evidence is missing.

Code: `internal/authorization/history.go`,
`internal/httpapi/investigations.go`. No migration: it reads `audit_events`,
`authorization_grants`, `policies`/`policy_versions` and
`configuration_revisions`. Test: `TestHistoricalEntitlements`
(`tests/e2e/investigations_test.go`).

## Request

```
POST /api/v1/realms/{realm}/investigations/entitlements
{"subject_type": "user", "subject_id": "usr_...", "at": "2026-09-30T14:00:00Z",
 "reason": "INC-2041: access review of the billing export"}
```

- Permission `realm.audit.read` (held by `realm-admin` and `realm-auditor`),
  with an administrator token from an MFA session like every administration
  call.
- `subject_type` is `user` or `service_principal`; `at` an RFC 3339 instant
  in the past (`422` otherwise); `reason` (1–500 characters) is the
  investigation reference and is required.
- Every reconstruction is itself audited as
  `investigation.entitlements.reconstructed` (category `audit`) with the
  subject, the instant and the reason. The response is `Cache-Control:
  no-store`.

## What is reconstructed, and from what

| Response member | Source | Notes |
| --- | --- | --- |
| `account_state` | User lifecycle audit events (`user.created`, `user.imported`, `user.suspended`, `user.locked`, `user.reactivated`, `user.recovery_restricted`, `user.deleted`) | `unknown` when no event survives; `not_created` when the evidence is complete and shows no creation. **Service principals are always reported `active`**: their state changes are not reconstructed |
| `memberships` | `organization.membership.added`, `.removed`, `.expired` | With `since` and the evidence event ID |
| `groups` | `group.member.added`, `.removed` for those memberships | Dynamic groups only as far as membership changes were recorded |
| `assignments` | `role.assigned` and `role.unassigned` for the subject and for its groups (`via`: `direct` or `group:<id>`) | Organization roles end with the membership; roles assigned through a project grant end with `project.grant.revoked`; `expires_at` is honoured |
| `assignments[].permissions`, `denied_permissions` | `role.created` and `role.permissions.changed` events of each role | `permissions_evidence`: `reconstructed`; `current_definition` for built-in roles and roles created before the retained evidence (shown as they are now); `unknown` when the role no longer exists. Changes to a role's denied permissions after creation are not replayed |
| `permissions` | The assignments above | Allowed minus denied permissions |
| `oauth_grants` | `authorization_grants` rows created before the instant and not revoked or expired at it | At most 500. Ended grants are deleted `privacy.session_retention` (30 days by default) after they ended, so older grants are missing |
| `policies_in_force` | `policy_versions`: for each ABAC policy, the latest version published at the instant | Name, version, definition hash, publication time |
| `realm_policy_revision` | `configuration_revisions` | The realm policy revision in force; read the flow rules of that time from the [flow revisions](../protocols/authentication-flows.md#revisions) |
| `completeness` | — | `evidence_from` (the oldest retained server audit event), `complete`, `caveats` |

`complete` is `false` when the instant precedes `evidence_from` or when the
subject has more than 20000 relevant events (the reconstruction is then
truncated). `caveats` always state that application-owned facts and the
decisions of hooks and external policy engines are not reproduced, and add
entries for incomplete evidence, dynamic groups and roles shown with their
current definition.

## What it never claims

- Application-owned facts: data and authorization rules inside your
  applications, and third-party state.
- What hooks, external policy engines or ABAC conditions decided at the time
  (the policy versions are listed, the decisions are not).
- Relationship tuples (AZ-021) history, elevation eligibility state, support
  impersonation grants, API keys and personal access tokens, and SCIM
  connector state.
- Anything the audit retention already removed. How far back reconstruction
  can go is bounded by audit retention (`privacy.audit_retention` and its
  per-category, realm and organization extensions); a legal hold keeps the
  evidence of an organization or person
  ([data-inventory.md](data-inventory.md#audit-retention-and-legal-holds)).
  Imported audit history (`imported_audit_events`) is not used.

Treat the result as investigation evidence to corroborate, not as proof that
an access did or did not happen: combine it with the audit events themselves
(`GET /audit-events`) and with your applications' own logs.
