# Relationship-based authorization

Requirements: AZ-021, AZ-022, AZ-023, AZ-027. Code:
`internal/authorization/relations.go`, `internal/authorization/shares.go`,
`internal/httpapi/relations.go`, `internal/httpapi/decision.go`, migration
`0053`. Test: `TestRelationshipAuthorization` (`tests/e2e/relations_test.go`).
Design: [ADR 0013](../architecture-decisions/0013-authorization-model.md#update-2026-10).

RBAC answers "may this subject do this action in this organization". Some
applications also need "may this subject do this action **on this object**"
(a document, a project board, a folder) based on who owns, edits or was
given the object. ProudAuth offers a bounded relationship model for that:

- a service **registers resource types**: the relations its objects have
  (`owner`, `editor`, `viewer`, `parent`, ...) and which application
  permission each relation gives;
- the service **writes relationship tuples** ("user X is `editor` of
  document D in organization O"); ProudAuth stores relationships, never the
  objects themselves;
- the decision API then answers object-level questions, and
  `list-objects` lists the objects a subject may act on;
- users can **share** an object with another member of the same
  organization.

Relationships only add a way to be granted an application permission; they
never grant IdP administration (only registered application permissions can
be mapped) and they never cross organizations. Your service still owns its
objects and must still check the decision for every request (§15.2).

## Permissions

| Permission | Allows | Built-in roles |
| --- | --- | --- |
| `realm.resource_types.read` | Read resource types | `resource-server`, `realm-auditor` |
| `realm.resource_types.write` | Register, replace and delete resource types | `resource-server` |
| `realm.relationships.read` | List relationship tuples | `resource-server`, `realm-auditor` |
| `realm.relationships.write` | Write relationship tuples | `resource-server` |

`realm-admin` holds all of them through `realm.*`. They are added to the
built-in roles of existing realms when the server starts. The routes below
are administration routes (admin-audience token; a human caller also needs
an MFA session); a service uses its service principal with the
`resource-server` role, as for the decision API
([resource-servers.md](resource-servers.md#4-policy-decisions-optional)).

## Resource types

Paths are relative to `/api/v1/realms/{realm}`.

| Method and path | Permission | Effect |
| --- | --- | --- |
| `GET /resource-types` | `realm.resource_types.read` | List types (at most 500, by name; `{items, next_cursor}`) |
| `GET /resource-types/{name}` | `realm.resource_types.read` | One type; `ETag: W/"v<N>"` |
| `PUT /resource-types/{name}` | `realm.resource_types.write` | Register (`201`) or replace (`200`) a type |
| `DELETE /resource-types/{name}` | `realm.resource_types.write` | Delete (`204`); `409` while tuples use it |

```json
PUT /api/v1/realms/main/resource-types/document
{
  "resource_id": "res_docs",
  "relations": [
    {"name": "parent", "subject_types": ["folder"]},
    {"name": "owner", "subject_types": ["user"]},
    {"name": "editor", "subject_types": ["user", "group"], "implied_by": ["owner"]},
    {"name": "viewer", "subject_types": ["user", "group", "organization", "service_principal"], "implied_by": ["editor"]}
  ],
  "permissions": {
    "documents.read": ["viewer", "parent.viewer"],
    "documents.write": ["editor"],
    "documents.share": ["owner"]
  },
  "shareable_relations": ["viewer", "editor"],
  "share_permission": "documents.share"
}
```

| Member | Rules |
| --- | --- |
| `{name}` (path) | `^[a-z][a-z0-9_]{1,62}$`: 2–63 lower-case letters, digits and underscores, starting with a letter |
| `resource_id` | An active business API resource of the realm (`422` otherwise). It cannot change on replace (`422`, "a type stays with the resource that registered it"). Any holder of `realm.resource_types.write` can name any business resource |
| `relations` | 1–32 relations. Names follow the type-name rule and are unique. Each relation has `subject_types`, `implied_by` or both. `subject_types`: `user`, `service_principal`, `group`, `organization`, this type's own name, or another registered type (an object of that type, for links such as `parent`). `implied_by` names other relations of this type whose holders also hold this one; a cycle is refused (`422`, "implied_by relations form a cycle at ...") |
| `permissions` | 1–64 entries. Each key is an application permission registered with `POST /permissions` (built-in permissions are refused: "register the application permission first"), mapped to 1–16 entries: `relation` (holders of that relation, including through `implied_by`) or `link.relation` (holders of `relation` on the object named by this object's `link` relation, whose subject types must include a resource type) |
| `shareable_relations` | Relations users may share ([Sharing](#sharing)); each must exist |
| `share_permission` | Required with `shareable_relations`: one of the type's permission keys. A user must hold it on an object to share it |

The request is strict JSON (there is no `description` member). A replace is
a full replacement and needs `If-Match` with the current `ETag` (`428`
without it, `412` when stale); the body is validated first, so an invalid
body is `422` even without `If-Match`. Tuples already written are not
re-validated against a replaced type. `DELETE` refuses a type while any
tuple names it as object or subject type, expired ones included (`409`,
"relationships still use this type; remove them first"); it does not check
other types that use it as a subject type, or pending shares.

Audited as `authorization.resource_type.registered`, `.updated` and
`.deleted`.

## Writing relationships

```json
POST /api/v1/realms/main/organizations/org_.../relationships
{"writes": [
  {"op": "add", "object_type": "document", "object_id": "doc_42", "relation": "owner",
   "subject_type": "user", "subject_id": "usr_..."},
  {"op": "add", "object_type": "document", "object_id": "doc_42", "relation": "parent",
   "subject_type": "folder", "subject_id": "fld_7"},
  {"op": "add", "object_type": "document", "object_id": "doc_42", "relation": "viewer",
   "subject_type": "group", "subject_id": "grp_...", "expires_at": "2026-12-31T00:00:00Z"},
  {"op": "remove", "object_type": "document", "object_id": "doc_41", "relation": "viewer",
   "subject_type": "user", "subject_id": "usr_..."}
]}
```

- `realm.relationships.write`; 1–100 writes, applied in one transaction (all
  or nothing); answer `200 {"status": "written", "writes": N}`. The
  organization must be active (`404` otherwise).
- `op` is `add` or `remove`. `object_type` must be registered and
  `relation` one of its relations. `object_id` is your own identifier: 1–256
  characters without control characters.
- `add` checks that `subject_type` is one of the relation's subject types and
  that the subject belongs to the organization:

  | `subject_type` | Accepted when |
  | --- | --- |
  | `user` | The user has an active membership in the organization |
  | `group` | The group belongs to the organization |
  | `organization` | `subject_id` is the organization itself (meaning: every active member) |
  | `service_principal` | The principal is active and allowed in the organization (owner organization or `allowed_organization_ids`) |
  | a registered type | Any well-formed object ID |

  Otherwise `422` with the reason. `expires_at`, when given, must be in the
  future; the tuple then lapses on its own. Adding an existing tuple updates
  its `expires_at`.
- `remove` is idempotent and does not validate the subject.
- Audited as `authorization.relationships.written` (metadata `added`,
  `removed`, `source` and the writes, including subject IDs).

`GET /organizations/{org}/relationships` (`realm.relationships.read`) lists
tuples, expired ones included, filtered by `object_type`, `object_id`,
`subject_type` and `subject_id`; `limit` 1–500 (default 100) and `cursor`
(the `id` of the last tuple). Items: `id`, `organization_id`,
`object_type`, `object_id`, `relation`, `subject_type`, `subject_id`,
`source` (`api`, or `share:<id>`), `expires_at`, `created_by_id`,
`created_at`.

## Object-level decisions

`POST /authorization/check` and `/check-batch`
([resource-servers.md](resource-servers.md#4-policy-decisions-optional)) take
the object in `resource`:

```json
{"subject_token": "<the caller's access token>", "action": "documents.write",
 "resource": {"type": "document", "id": "doc_42", "org_id": "org_..."}}
```

1. RBAC first. When the subject's roles in the organization grant the action,
   relationships are not consulted (and such a decision can be cacheable as
   before).
2. Otherwise, when `resource.type` is a registered type, `resource.id` is set
   and there is an organization (`resource.org_id`, else the token's
   `org_id`), the action is looked up in the type's `permissions` and the
   subject is matched against the mapped relations of that object.
   Relationships count only with the tenant eligibility RBAC applies,
   checked on every decision: the organization must be `active` (a
   `suspended`, `archived` or `deleting` organization grants nothing through
   relationships, also to a realm-scoped token that names it only in
   `resource.org_id`), and the subject must be an active user or service
   principal eligible in it (below); otherwise the decision is
   `NOT_PERMITTED` without reading any tuple.
   - tuples naming the subject directly, and relations implied through
     `implied_by`;
   - for users: only through an `active` membership whose `expires_at` has
     not passed (a membership past its end counts as gone at once, before the
     expiry sweep stores it as `expired`), with the account `active` or
     `recovery_restricted`. Then also tuples naming a group the user belongs
     to (also through ancestor groups, honoring membership validity windows;
     a rule-derived membership counts only while its dynamic group was
     recomputed within `security.dynamic_group_max_staleness` and its rule
     has no error, as for RBAC), and tuples naming the organization (every
     eligible member);
   - service principals match only tuples that name them directly, and only
     while the principal is `active` and allowed in the organization (its
     owner organization or `allowed_organization_ids`), also when the
     decision names it as an explicit `subject`;
   - `link.relation`: the relation on the object(s) this object's link relation
     names, **one hop** (a linked type's own links are not followed);
   - expired tuples never match.
3. The evaluation is bounded: depth 6, at most 64 object reads per decision and
   1000 tuples per object. Reaching a bound is a denial.
4. A relationship allow then passes through the usual later checks: step-up
   for privileged permissions, published ABAC policies, an external policy
   engine in `restrict` mode ([policy-engines.md](policy-engines.md)) and
   authorization hooks, any of which can still deny.

Reason codes stay the ordinary ones: `ALLOWED`, or `NOT_PERMITTED` for a
relationship denial and for a reached bound; a database error is
`EVALUATION_ERROR`. A decision that consulted relationships is **never
cacheable** (`cache_ttl_seconds: 0`, no `cache_key`), because tuples have no
revision the cache key could cover.

## Listing objects

```json
POST /api/v1/realms/main/authorization/list-objects
{"subject_token": "<token>", "action": "documents.read",
 "resource": {"type": "document", "org_id": "org_..."}, "limit": 100, "cursor": ""}
```

Needs `realm.authorization.check`; the subject is a `subject_token` or, for
callers with `realm.authorization.simulate`, a `subject`, as for
`/authorization/check`. The answer:

```json
{"all": false, "objects": ["doc_17", "doc_42"], "organization_id": "org_...",
 "truncated": false, "next_cursor": "doc_42"}
```

- `all: true` (and an empty `objects`) when an organization-wide RBAC grant
  covers the action for every object; filter nothing then.
- Otherwise every listed object was verified with the same evaluation as a
  check; an unverified object is never returned. The same tenant
  eligibility applies: an organization that is not `active`, or a subject
  not eligible in it, lists no objects (`objects: []`). Objects are ordered by ID
  after `cursor`; `next_cursor` is present when `objects` holds `limit`
  entries.
- `limit` is 1–500 (default 100); a larger value is clamped to 500.
- Bounds: at most 5000 candidates and 1000 checks per call; reaching either
  sets `truncated: true`. An object whose own evaluation hits a bound (depth,
  object reads, or more than 1000 tuples on one object) cannot be verified:
  it is left out and `truncated` is `true` too, so the list is known to be
  incomplete; check such objects one by one.
- Step-up, ABAC policies, policy engines and hooks are **not** applied here:
  use the list to filter, and check the object before acting on it.
- Support tokens may list only read actions (ending in `.read`, `.list`,
  `.view`, `.get` or `.search`); otherwise `403`.
- Errors: `422` without `action` or `resource.type`, without an organization
  ("objects are listed within one organization") or for an unregistered type
  that RBAC does not grant; `403` for an unusable subject token or an
  organization mismatch.

## Sharing

Users share objects with other members through self-service (account-audience
token, users only). Paths are relative to `/api/v1/realms/{realm}`:

| Method and path | Who | Effect |
| --- | --- | --- |
| `POST /me/shares` | Sharer, with recent authentication | Offer: `{"organization_id", "resource_type", "object_id", "relation", "recipient_user_id", "message", "expires_at"}` → `201`, state `pending` |
| `GET /me/shares?direction=received\|sent&state=` | Either | Newest first (`direction` defaults to `received`) |
| `POST /me/shares/{id}/accept` | Recipient | Re-checks that the relation is still shareable and that the sharer may still share the object, then writes the tuple (with the share's `expires_at`, source `share:<id>`) → state `accepted` |
| `POST /me/shares/{id}/decline` | Recipient | State `declined` |
| `DELETE /me/shares/{id}` | Sharer (withdraw) or recipient (give back) | Removes the tuple; state `revoked` (`204`) |

Rules: the sharer must hold the type's `share_permission` on the object
(`403` "you may not share this object"); `relation` must be one of the
type's `shareable_relations` (`422`); the recipient must be an active member
of the same organization and not the sharer (`422`); `message` at most 500
characters; one pending or accepted share per object, relation and recipient
(`409`). Accepting a share that is no longer valid is `409`. Audited as
`authorization.share.offered`, `.accepted`, `.declined`, `.revoked` and
`.expired` (acceptance also records `authorization.relationships.written`).

**Expiry.** A share with `expires_at` ends then. Accepting an offer past it
is `409` ("the offer expired") and stores the state `expired` in its own
transaction (the refused request's transaction rolls back). The worker task
`lifecycle.expiry` (every 30 seconds) stores `expired` for every pending or
accepted share past its `expires_at` and removes the tuple an accepted one
wrote (it already granted nothing; a tuple extended by a later write is
kept), recording `authorization.share.expired` (actor `system`, metadata
`previous_state`). Listings show such a share as `expired`, and `state=`
filters by that, before the sweep stores it; an expired share does not count
as the one pending or accepted share per object, relation and recipient.

## Data and limits

- Tuples (`resource_relationships`), types (`resource_types`) and shares
  (`resource_shares`) are kept until removed through these APIs. Deleting an
  account removes the tuples that name it as subject, ends the pending and
  accepted shares to or from it (removing the tuple of an accepted share it
  made) and clears their message
  ([data-inventory.md](../operations/data-inventory.md#account-deletion)).
  Deleting an organization does not remove them; tuples of former members
  are inert because subjects must be eligible members, and an organization
  that is not active matches nothing. They are not in the
  realm data export ([data-inventory.md](../operations/data-inventory.md#organizations-authorization-support)).
- One organization per tuple; there is no realm-wide or cross-organization
  relationship.
- No caveats or conditions on tuples other than `expires_at`, no
  intersection or exclusion operators, no Zanzibar-style consistency tokens,
  and no watch API. Relationship decisions are evaluated live and never
  cached.

Threats and mitigations: [system threat model](../threat-models/system.md)
(self-service and tenant APIs).
