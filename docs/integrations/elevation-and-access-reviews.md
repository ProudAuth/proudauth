# Just-in-time elevation and access reviews

Requirements: AZ-024 (just-in-time elevation), AZ-025 (access reviews). Code:
`internal/authorization/elevation.go`, `internal/authorization/reviews.go`,
`internal/httpapi/elevation.go`, `internal/httpapi/reviews.go`, migrations
`0054` and `0055`. Tests: `TestJustInTimeElevation`
(`tests/e2e/elevation_test.go`), `TestAccessReviews`
(`tests/e2e/reviews_test.go`). Design:
[ADR 0013](../architecture-decisions/0013-authorization-model.md#update-2026-10).

Both features work on ordinary role assignments: elevation creates one that
ends on its own, and a review decides which existing ones stay. Paths are
relative to `/api/v1/realms/{realm}`. Administration routes need an
admin-audience token from an MFA session; `/me/...` routes need an
account-audience token of a user.

## Just-in-time elevation

A person who needs a powerful role only now and then is made **eligible**
for it instead of holding it. When the work comes up they ask for it with a
reason and a duration, someone else approves, and the role assignment ends by
itself at the deadline. Elevation is the person acting as themselves with
more rights; it is unrelated to support impersonation, where an operator acts
as a customer ([impersonation.md](../threat-models/impersonation.md)).

### Eligibilities

| Method and path | Authority | Effect |
| --- | --- | --- |
| `POST /elevation-eligibilities` | Could assign the role at the scope (below); MFA session | Make a person eligible → `201` |
| `GET /elevation-eligibilities?user_id=` | `realm.roles.read` | Active eligibilities, newest first (at most 500) |
| `DELETE /elevation-eligibilities/{id}` | `realm.roles.assign` | Revoke; pending requests under it are cancelled and an active elevation ends now (`204`) |

```json
POST /api/v1/realms/main/elevation-eligibilities
{"user_id": "usr_...", "role_id": "rol_billing_admin",
 "scope": {"type": "organization", "id": "org_..."},
 "max_duration_seconds": 3600, "requires_approval": true}
```

| Member | Rules |
| --- | --- |
| `user_id` | An active user who is not a guest, and not the creator (`422`, "make someone else eligible") |
| `role_id` | A role whose boundary fits the scope (`422` otherwise) |
| `scope` | `{type: realm \| organization \| project, id}`; default the realm |
| `max_duration_seconds` | 300–604800 (five minutes to seven days), default 3600 |
| `requires_approval` | Default `true`. A privileged role (privileged itself, holding a privileged permission, or composing such a role at any depth) always needs approval: `false` is `422` |

The creator must be able to assign that role at that scope: `realm.roles.assign`
(or `org.roles.assign` in the organization) and the delegation ceiling, as for
a direct assignment (`403 forbidden` or `403 grant_ceiling_exceeded`
otherwise). Eligibility grants nothing by itself.

### Requests

| Method and path | Who | Effect |
| --- | --- | --- |
| `GET /me/elevation-eligibilities` | The eligible user | Their active eligibilities |
| `POST /me/elevations` | The eligible user | Ask: `{"eligibility_id", "duration_seconds", "reason"}` → `201` |
| `GET /me/elevations?state=` | The user | Their requests and elevations |
| `POST /me/elevations/{id}/end` | The user | End their elevation now, or withdraw a pending request (`204`) |
| `GET /elevations?state=&user_id=` | `realm.roles.read` | All requests, newest first (at most 500) |
| `POST /elevations/{id}/approve` | Could assign the role at the scope, not the requester; users with recent authentication | Approve → the role is assigned (`200`) |
| `POST /elevations/{id}/reject` | Same | Reject (`200`) |
| `POST /elevations/{id}/end` | `realm.roles.assign` | End an active elevation now, or cancel a pending request (`204`) |

- `duration_seconds` is 300 up to the eligibility's maximum (default the
  maximum); `reason` 3–500 characters.
- Asking needs a session with recent authentication
  (`security.recent_auth_window`; otherwise `403
  recent_authentication_required`) that completed MFA (otherwise `403
  step_up_required` with a `reauthenticate` obligation for `mfa`).
- One request at a time per eligibility: another while one is pending or
  active is `409`.
- Approval: the approver must be able to assign the role at the scope (`403`
  "the approver could not assign this role") and must not be the requester
  (`403`, "self-approval is not permitted"). Deciding a request that is not
  pending is `409`. Without `requires_approval`, the request is active at once.
- States: `pending`, `active`, `rejected`, `ended` (ended early by the user,
  an administrator, the eligibility's revocation or the account's deletion),
  `expired`, `cancelled` (a withdrawn or revoked pending request, or one of
  a deleted account).

**What is granted.** An active elevation is an ordinary role assignment with
`source: "elevation"`, `reason: "elevation: <reason>"`, the approver as
`approved_by_id`, and `expires_at` = approval time + duration (the request
time without approval). Everything that applies to assignments applies:
incompatible roles (separation of duties), an active membership for an
organization scope, and decisions and tokens see the role while it lasts.
The worker task `lifecycle.expiry` (every 30 seconds, up to 500 expired
assignments per run) removes the assignment at the deadline and marks the
elevation `expired`; API views show `expired` as soon as the deadline passes,
but the `state` filter matches the stored state, so until the sweep ran such
an elevation is found under `state=active`. An assignment that cannot be
removed because it is the last owner role of an organization stays.

Audit: `authorization.elevation.eligibility_created`, `.eligibility_revoked`,
`.requested` (reason and duration), `.approved`, `.rejected`, `.started`,
`.ended` and `.expired`. The sweep that ends an elevation at its deadline
records `role.unassigned` and `authorization.elevation.expired` (actor
`system`, subject the person, target the role, metadata `elevation_id`,
`assignment_id` and `ends_at`) in the same transaction. A cancelled pending
request records no elevation event.

**Account deletion** revokes the account's eligibilities, cancels its
pending requests and ends an active elevation (state `ended`); the
elevation's role assignment expires at once and the next `lifecycle.expiry`
run removes it (`role.unassigned`). No elevation event is recorded for
these; `user.deleted` is the evidence.

## Access reviews

An access review campaign asks named reviewers whether each of a set of role
assignments should stay, applies the decisions when it closes, and keeps the
evidence. Administration needs `realm.access_reviews.manage`, a privileged
permission that only `realm-admin` holds (through `realm.*`).

| Method and path | Effect |
| --- | --- |
| `POST /access-reviews` | Start a campaign (`201`) |
| `GET /access-reviews?state=open\|closed\|cancelled` | Campaigns, newest first (at most 200) |
| `GET /access-reviews/{id}` | One campaign with `items_total`, `items_decided`, `overdue` (open past `due_at`) and `summary` |
| `GET /access-reviews/{id}/items?decision=undecided\|keep\|revoke&limit=&cursor=` | Items (`limit` 1–500, default 100) |
| `POST /access-reviews/{id}/close` | Close and apply (`200`) |
| `POST /access-reviews/{id}/cancel` | Cancel; nothing is applied (`204`) |
| `GET /access-reviews/{id}/evidence` | The evidence document |

```json
POST /api/v1/realms/main/access-reviews
{"name": "Q4 privileged access", "description": "Quarterly review",
 "organization_id": "org_...", "reviewer_ids": ["usr_...", "usr_..."],
 "role_ids": [], "privileged_only": true, "on_no_decision": "keep",
 "due_at": "2026-12-15T00:00:00Z"}
```

| Member | Rules |
| --- | --- |
| `name`, `description` | Name required, at most 200 characters; description at most 2000 |
| `organization_id` | Optional active organization: only assignments scoped to that organization (not its projects). Without it, every assignment of the realm, whatever its scope |
| `reviewer_ids` | 1–20 active users |
| `role_ids` | Optional filter; empty means every role |
| `privileged_only` | Only assignments of privileged roles (default `false`) |
| `on_no_decision` | `keep` (default) or `revoke`: what closing does with undecided items |
| `due_at` | In the future, at most 366 days ahead |

Starting a campaign **snapshots** the matching assignments of users, groups
and service principals as items (role, subject, scope, source, granted by,
granted at, privileged). At most 10000 assignments can be covered (`422`
above, counted before the `privileged_only` filter): narrow it by
organization or roles. Expired or not-yet-valid assignments are included.

**Reviewers** use their own account token:

| Method and path | Effect |
| --- | --- |
| `GET /me/access-reviews?state=` | Campaigns the caller reviews (`state` defaults to `open`) |
| `GET /me/access-reviews/{id}/items` | Items, with the same filters; `404` unless the caller is a reviewer |
| `POST /me/access-reviews/{id}/items/{item}/decision` | `{"decision": "keep" \| "revoke", "comment": "..."}` (comment at most 1000 characters, required to revoke) |

A reviewer never decides about their own access (`403` for items whose
subject is the reviewer; a grant to a group they belong to is not covered by
this rule). Decisions can be changed until the campaign closes (`409`
afterwards).

**Closing** (by an administrator, or by the worker task `lifecycle.expiry`
when `due_at` has passed, up to 20 campaigns per run, actor `system`)
revokes every item decided `revoke`, and the undecided ones when
`on_no_decision` is `revoke`, if the assignment still exists. Each item
records its outcome: `kept`, `revoked`, `already_removed` or `revoke_failed`
(for example the last owner role of an organization). The `summary` counts
each outcome plus `undecided`. Each revocation is its own transaction, so a
close interrupted half-way is completed by the next close attempt; revocations
are recorded as ordinary `role.unassigned` events.

**Evidence.** `GET /access-reviews/{id}/evidence` returns the campaign, every
item with its decision, reviewer, time, comment, outcome and `applied_at`,
`generated_at`, and the statement "Records the decisions of the named
reviewers and their outcome. It documents an access review; it is not a
regulatory certification." It is audited as `access_review.evidence_exported`.
Such a document supports an assessment; it does not make a deployment
compliant with anything ([ADR 0020](../architecture-decisions/0020-compliance-posture.md)).

Audit: `access_review.started`, `.item_decided`, `.closed` (with the
summary), `.cancelled` and `.evidence_exported`.

## Limits

- Elevation grants a role. It takes effect wherever ProudAuth evaluates
  permissions (its own APIs, the decision API, scope `required_permissions`
  at the next token issuance) and stops there at the deadline; access tokens
  issued meanwhile keep their scopes until they expire.
- An access review decides on assignments, not on group memberships or
  relationship tuples; a group's members are reviewed through the group's
  own assignments.
- Campaign closing is not atomic across items, and nothing reminds reviewers
  of a due date; poll `GET /me/access-reviews`.
- Eligibilities, elevations, campaigns and items are kept; no retention job
  removes them ([data-inventory.md](../operations/data-inventory.md#organizations-authorization-support)).
