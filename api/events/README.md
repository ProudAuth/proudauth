# ProudAuth event schemas (v1 and v2)

Machine-readable [JSON Schema draft 2020-12](https://json-schema.org/draft/2020-12/schema) definitions for every event ProudAuth writes to its transactional outbox and delivers to webhook subscriptions (plan §22, EXT-008; API-002).

- `envelope.v1.json`: the JSON body of every webhook delivery. It also documents the signature headers (`x-headers`, `x-signature`, including a test vector).
- `<event_type>.v1.json`: one schema per event type, for example `organization.membership.removed.v1.json`. Each one is the envelope (`allOf: [{"$ref": "envelope.v1.json"}]`) narrowed to one `event_type` and its exact `data` shape.

Every schema's `$id` is `https://auth.proudbase.com/schemas/events/<file name>`. Each one includes `examples`: the standard payload form first, then the minimal form when the two differ.

The schemas are derived from the server code (`internal/events`, `internal/webhooks` and the `Outbox.Publish` call sites). Each event schema names its emitting function or functions in `x-emitted-by`.

## Catalog

`org_id` shows when the envelope's `org_id` is set. A member marked † is sent only in the **standard** payload form (see [Payload forms](#payload-forms)).

| Event type | Emitted when | `org_id` | `data` members | Schema |
| --- | --- | --- | --- | --- |
| `user.created` | An account was created (registration, administrator, invitation, federation just-in-time provisioning, import) | never | `user_id`, `created_via`† (`import:<source_system>` for imports) | [user.created.v1.json](user.created.v1.json) |
| `user.signed_in` | A sign-in completed (authorization code or device flow), a browser session was created or reused, and a grant was issued to the client | if an org was selected | `user_id`, `session_id`, `client_id` | [user.signed_in.v1.json](user.signed_in.v1.json) |
| `user.suspended` | The account was suspended: by an admin (directly, through a bulk operation or a scheduled deactivation), because its registration was denied or its review expired, or by the dormant-account rule with `lifecycle.dormant_action: suspend`. All sessions and grants are revoked | never | `user_id`, `state` | [user.suspended.v1.json](user.suspended.v1.json) |
| `user.locked` | An admin locked the account. All sessions and grants are revoked | never | `user_id`, `state` | [user.locked.v1.json](user.locked.v1.json) |
| `user.reactivated` | The account returned to `active`: an admin reactivated it (from suspended, locked, `recovery_restricted` or pending deletion), or a `recovery_restricted` account regained factor assurance by signing in with TOTP or a passkey or by enrolling a new TOTP authenticator or passkey (audit reason `FACTOR_ASSURANCE_RESTORED`). Revoked sessions and grants are not restored | never | `user_id`, `state` | [user.reactivated.v1.json](user.reactivated.v1.json) |
| `user.recovery_restricted` | An `active` account signed in with a recovery code and no other strong factor (TOTP or passkey), so it moved to `recovery_restricted` (audit reason `RECOVERY_CODE_USED`). It stays there until a later TOTP or passkey sign-in or a new factor enrollment returns it to `active` with `user.reactivated`. No administrator action emits it, and sessions are not revoked | never | `user_id`, `state` | [user.recovery_restricted.v1.json](user.recovery_restricted.v1.json) |
| `user.deleted` | The account was erased: by an admin, by scheduled self-deletion, because an unverified registration or an unused guest account expired, or as the merged-away account of an account merge (together with `user.merged`) | never | `user_id` | [user.deleted.v1.json](user.deleted.v1.json) |
| `user.merged` | An administrator executed an account merge that both owners confirmed. `merged_user_id` no longer exists (it is now an alias, resolvable with `GET /subject-aliases/{id}`); remap data keyed by it to `user_id` | never | `user_id`, `merged_user_id` | [user.merged.v1.json](user.merged.v1.json) |
| `user.password_reset` | A self-service password reset completed. All sessions and grants are revoked | never | `user_id` | [user.password_reset.v1.json](user.password_reset.v1.json) |
| `session.revoked` | An active browser session was revoked (one event per session) | never | `user_id`, `session_id`, `reason` | [session.revoked.v1.json](session.revoked.v1.json) |
| `security.refresh_reuse_detected` | An already-rotated refresh token was presented again. The family, the grant and possibly the session are revoked | if the grant is org-bound | `subject_id`, `family_id` | [security.refresh_reuse_detected.v1.json](security.refresh_reuse_detected.v1.json) |
| `security.credential_compromised` | An admin marked the user's password as compromised | never | `user_id` | [security.credential_compromised.v1.json](security.credential_compromised.v1.json) |
| `security.alert` | An audit event of a realm carried an alertable security signal (AUD-012), published in the same transaction as the evidence. Besides the earlier signals (refresh reuse, support access, cross-tenant denials, factor recovery, signing keys, bootstrap, credentials, every `emergency`-category event), a protected account's sign-in, a sign-in an `authentication_flow` rule sent for review (`authentication_review`, AUT-014), an assignment of a privileged role (owner role, realm role, or a role with a catalog-privileged permission; not the built-in organization `member` and `admin` roles), and security configuration changes (`realm.policy.updated`, `federation.provider.*`, `hook.created`, `hook.updated`, `webhook.created`, `audit.legal_hold.released`) | when the audit event has one | `signal`, `audit_event_id`, `event_type`, `actor_type`, `actor_id`, optional `subject_type`, `subject_id` | [security.alert.v1.json](security.alert.v1.json) |
| `organization.created` | An organization was created | always | `organization_id`, `slug`† | [organization.created.v1.json](organization.created.v1.json) |
| `organization.suspended` | An admin suspended the organization. Its grants are revoked | always | `organization_id`, `state` | [organization.suspended.v1.json](organization.suspended.v1.json) |
| `organization.reactivated` | An admin set the organization back to `active` | always | `organization_id`, `state` | [organization.reactivated.v1.json](organization.reactivated.v1.json) |
| `organization.archived` | An admin archived the organization | always | `organization_id`, `state` | [organization.archived.v1.json](organization.archived.v1.json) |
| `organization.deleted` | Organization deletion started: access is revoked and clean-up continues asynchronously. The organization's own webhook subscriptions are disabled in the same transaction (and deleted when the deletion finishes), so only realm-wide subscriptions receive this event | always | `organization_id` | [organization.deleted.v1.json](organization.deleted.v1.json) |
| `organization.membership.added` | An admin added a member, or an invitation was accepted | always | `user_id`, `membership_id`, `source`† (invitations only) | [organization.membership.added.v1.json](organization.membership.added.v1.json) |
| `organization.membership.removed` | A membership was removed by an admin, by the member leaving, or by connector deprovisioning | always | `user_id`, `membership_id`, `authorization_revision` | [organization.membership.removed.v1.json](organization.membership.removed.v1.json) |
| `organization.membership.suspended` | An admin suspended a membership | always | `user_id`, `membership_id`, `authorization_revision` | [organization.membership.suspended.v1.json](organization.membership.suspended.v1.json) |
| `organization.membership.reactivated` | An admin reactivated a membership | always | `user_id`, `membership_id`, `authorization_revision` | [organization.membership.reactivated.v1.json](organization.membership.reactivated.v1.json) |
| `organization.invitation.created` | An invitation was created | always | `invitation_id` | [organization.invitation.created.v1.json](organization.invitation.created.v1.json) |
| `organization.join_request.created` | A user requested to join an organization | always | `join_request_id` | [organization.join_request.created.v1.json](organization.join_request.created.v1.json) |
| `authorization.role.assigned` | A role was assigned to a user, service principal or group, whether directly or as a side effect | if org-scoped | `subject_id`, `role_id`, `assignment_id` | [authorization.role.assigned.v1.json](authorization.role.assigned.v1.json) |
| `authorization.role.unassigned` | A role assignment was removed: by an admin, by ownership transfer, or by expiry | if org-scoped | `subject_id`, `role_id` | [authorization.role.unassigned.v1.json](authorization.role.unassigned.v1.json) |
| `client.state_changed` | An admin suspended, reactivated or decommissioned an OAuth client | never | `client_ref`, `state` | [client.state_changed.v1.json](client.state_changed.v1.json) |
| `service_principal.state_changed` | An admin disabled, re-enabled or deleted a service principal, or realm policy `machine.owner_departure: disable` disabled it after its owner left | never | `service_principal_id`, `state` | [service_principal.state_changed.v1.json](service_principal.state_changed.v1.json) |
| `signing_key.rotated` | A planned or emergency token signing-key rotation started | never | `mode`, `new_kid`, `previous_kid`, `previous_key_compromised` | [signing_key.rotated.v1.json](signing_key.rotated.v1.json) |
| `support.impersonation.started` | A support impersonation grant was issued | always | `grant_id`, `actor_user_id`, `target_user_id`, `expires_at`† | [support.impersonation.started.v1.json](support.impersonation.started.v1.json) |
| `support.impersonation.ended` | The actor, the customer or an admin revoked an impersonation grant | always | `grant_id`, `reason` | [support.impersonation.ended.v1.json](support.impersonation.ended.v1.json) |

### What does not produce an event

Do not infer state from the absence of events. These changes currently emit **no** webhook event of their own (an audit event among them that carries a security signal, for example every event an emergency control records, still produces a `security.alert`):

- requesting or cancelling a self-service deletion;
- membership expiry;
- memberships created by approving a join request, by organization creation (the creator), or by import jobs;
- role assignments deleted as a side effect of membership removal, service-principal deletion or user deletion;
- activation of a planned signing key;
- expiry of an impersonation grant, and grants revoked by the system;
- session expiry;
- emergency controls for grant types, identity providers, pre-action hooks and
  webhook subscriptions (the client, organization and service-principal controls
  emit `client.state_changed`, `organization.suspended`/`.reactivated` and
  `service_principal.state_changed` like the ordinary routes);
- scheduling or cancelling a deactivation, and dormant accounts reported (not
  suspended) by the lifecycle rule;
- external ID changes, and required actions added by a bulk operation;
- consents given or revoked, and consent pre-authorizations created or revoked
  (the grants they end are revoked without an event);
- join request decisions (an approval emits only the `authorization.role.assigned`
  of the member role), withdrawals, expiry and reviewer assignments;
- organization domains added, verified, re-checked, lapsed or switched to
  `include_subdomains`, and organization aliases added or removed;
- organization templates saved or applied (the roles they assign emit
  `authorization.role.assigned`; the service principals and webhook
  subscriptions they create emit no event of their own, and each webhook
  subscription's `webhook.created` audit event raises a `security.alert`);
- dynamic group rules set or removed, and group membership changes made by a
  rule;
- an organization's mail server set or cleared;
- legal holds placed or released (a release emits only `security.alert`), and
  application activity reported through `POST /activity-events`;
- a service principal's owner departure while the realm policy is `flag`;
- realm custom domains added, verified or removed;
- authentication flow decisions and flow challenges (a decision with outcome
  `review` raises a `security.alert` with signal `authentication_review`), and
  logouts, including the upstream part of a federated logout.

Each schema's `description` gives the exact conditions.

## Envelope

| Field | Type | Always present | Meaning |
| --- | --- | --- | --- |
| `event_id` | string `obx_` + 26-char lower-case ULID | yes | Stable, unique event ID. Equal to the `Webhook-Id` header. It does not change across retries, manual replays or subscriptions. |
| `event_type` | string | yes | Dotted event type (see the catalog). |
| `event_version` | integer | yes | Event schema version the subscription chose: `1` for the `.v1` schemas described here, `2` for the `.v2` schemas (see "Event versions" below). |
| `occurred_at` | RFC 3339 date-time (UTC) | yes | When the event was recorded, inside the transaction that made the change. |
| `realm_id` | string `rlm_…` | yes | Realm of the event. Events without a realm are never delivered. |
| `org_id` | string `org_…` | no | Organization the event is scoped to (see the `org_id` column in the catalog). |
| `correlation_id` | string | no | `X-Request-Id` of the API request that caused the event, equal to the `request_id` of the audit events that request recorded (API-012). Absent for events caused by background work (worker tasks, jobs), except events a lifecycle workflow run causes, which carry the run's ID (`wrn_…`, the `request_id` of the run's audit events). The value can come from the client (1–64 printable ASCII characters), so treat it as an opaque, untrusted string. |
| `data` | object | yes | Type-specific payload: identifiers, states, reasons and timestamps only. Never secrets, e-mail addresses or personal names. |

No other top-level members are sent: the envelope is the Go struct `events.Event`.

```json
{
  "event_id": "obx_01jbh0ybgaravg3xcq0zdp2egd",
  "event_type": "organization.membership.removed",
  "event_version": 1,
  "occurred_at": "2026-10-10T12:10:00.123456789Z",
  "realm_id": "rlm_01jbxe2ktygrnsjxt1j8etsahj",
  "org_id": "org_01jb8wmw5drxrge3rmw4nf61x1",
  "data": {
    "user_id": "usr_01jb4rsd73q99h2e30n9ak6n8d",
    "membership_id": "mem_01jbadj9t141gzfk8s7x1yyg4j",
    "authorization_revision": 44
  }
}
```

The body bytes are produced by PostgreSQL's `jsonb` rendering: keys are ordered by length, and separators include spaces. Never rely on key order or whitespace. Verify signatures over the raw bytes you received.

### Payload forms

A subscription's `payload_form` is `minimal` (the default) or `standard`.

- **standard** sends `data` exactly as emitted.
- **minimal** keeps only the `data` members whose names end in `_id`, plus these members that carry no personal data: `state`, `reason`, `authorization_revision`, `mode`, `signal`, `event_type`, `actor_type`, `subject_type`, `client_ref`, `new_kid`, `previous_kid` and `previous_key_compromised`. Everything else is removed (`webhooks.minimal`).

The per-type schemas accept both forms. `required` lists only the members that survive the minimal form. Standard-only members carry the annotation `"x-payload-form": "standard"`.

`client.state_changed`, `signing_key.rotated` and `security.alert` are complete in both forms.

### Which subscriptions receive an event

At dispatch time, an event is fanned out to every **active** subscription in its realm that meets both conditions:

- the subscription's `event_types` contains the event type or `"*"`;
- the subscription is realm-wide (no `organization_id`), or its `organization_id` equals the event's `org_id`. Events without `org_id` reach realm-wide subscriptions only.

Paused or disabled subscriptions do not get deliveries for events dispatched while they are inactive.

### Delivery semantics

- Each delivery is one `POST` to the destination URL. HTTPS is required in production mode, and redirects are not followed.
- **At-least-once, unordered.** Workers lease deliveries for one minute, and a crash or timeout can cause a redelivery. Deduplicate by `event_id`. Order events by `occurred_at` and by per-resource revisions (for example the membership `authorization_revision`), or re-read current state from the API.
- **Response handling:**
  - any `2xx` marks the delivery `delivered`;
  - `410 Gone` moves it straight to `dead_letter`, but the subscription stays active;
  - any other status (including `3xx`), a timeout (default `delivery.webhook_timeout` = 10 s), a network error or an egress-policy denial is retried.
- The response body is read (up to 64 KiB) and discarded.
- **Retries:** after failed attempt *n*, the next attempt waits 5 s × 2ⁿ plus up to 25 % random jitter: 10 s, 20 s, 40 s and so on.
  - After `delivery.webhook_max_attempts` attempts (default 12, about 5.7 h after the first attempt) the delivery becomes `dead_letter`.
  - Dead-lettered deliveries can be replayed manually with the same `event_id`.
- A webhook is a notification, not a revocation mechanism (plan §22). Resources that need immediate denial must check online.

## Signature verification

Every request carries these headers. HTTP header names are case-insensitive: they match the Standard Webhooks `webhook-id`, `webhook-timestamp` and `webhook-signature`.

| Header | Value |
| --- | --- |
| `Webhook-Id` | The envelope's `event_id` (same for every attempt and replay) |
| `Webhook-Timestamp` | Unix seconds at which **this attempt** was signed (fresh on every retry) |
| `Webhook-Signature` | One or more space-separated `v1,<base64 signature>` values |
| `Content-Type` | `application/json` |
| `User-Agent` | `ProudAuth-Webhooks/1` |

**Algorithm (scheme `v1`):**

```
key       = base64decode(secret without the "whsec_" prefix)   // 32 bytes; standard alphabet, padded (Standard Webhooks); secrets issued before v0.2 are unpadded
signed    = Webhook-Id + "." + Webhook-Timestamp + "." + raw_body_bytes
signature = "v1," + base64encode(HMAC-SHA256(key, signed))       // standard alphabet, padded
```

The signing secret (`whsec_…`) is returned once, when the subscription is created and on each `POST /api/v1/realms/{realm}/webhooks/{id}/rotate-secret`. After a rotation, the server keeps signing with the **previous** secret for 24 hours as well. During that window `Webhook-Signature` holds two values: the new secret's first, then the old one's.

Secrets issued now are padded; secrets issued before v0.2 have no `=` padding. Decoders that insist on padding, including some Standard Webhooks libraries, need the missing `=` appended for older secrets; decoders that refuse padding (Go's `base64.RawStdEncoding`) need trailing `=` stripped first.

**Steps:**

1. **Keep the raw body.** Read the request body as bytes before any JSON parsing. A framework that re-serializes JSON will break the signature.
2. **Read the headers.** Get `Webhook-Id`, `Webhook-Timestamp` and `Webhook-Signature`, and reject the request if any is missing.
3. **Check freshness (replay protection).** Parse `Webhook-Timestamp` as an integer and reject it if it is more than 5 minutes away from your clock, in either direction. This is the tolerance used by the server's own conformance test. Retries are re-signed with a new timestamp, so the tolerance never rejects a legitimate retry. A valid signature alone does not prove freshness.
4. **Compute** the expected value with each secret you currently accept: `"v1," + base64(HMAC-SHA256(key, id + "." + timestamp + "." + body))`.
5. **Compare** in constant time against every whitespace-separated value in `Webhook-Signature`. Accept if any value matches. Ignore values with an unknown version prefix, because future schemes may be added alongside `v1`.
6. **Parse** the body. Optionally check `event_id == Webhook-Id`, that `event_version` is the version your subscription chose, and validate against that version's schema.
7. **Deduplicate (idempotency).** Record `event_id` together with the side effects of handling it, in the same transaction. If the ID has already been processed, return `2xx` without repeating the work. Keep processed IDs well beyond the retry window (about 6 h), because manual replays can occur later. Alternatively, make the handlers naturally idempotent.
8. **Respond `2xx` quickly** (well within 10 s) and do slow work asynchronously. Return `410` only to stop a delivery permanently.

The Go reference is `webhooks.Sign` / `webhooks.VerifySignature` in `internal/webhooks/webhooks.go`. A Node.js equivalent:

```js
import crypto from "node:crypto";

const TOLERANCE_SECONDS = 300;

// headers: lower-cased header map; rawBody: Buffer with the exact bytes received.
export function verifyProudAuthWebhook(secret, headers, rawBody, nowSeconds = Math.floor(Date.now() / 1000)) {
  const id = headers["webhook-id"];
  const ts = headers["webhook-timestamp"];
  const signatures = headers["webhook-signature"];
  if (!id || !ts || !signatures) throw new Error("missing webhook headers");
  if (!/^\d+$/.test(ts)) throw new Error("invalid timestamp");
  if (Math.abs(nowSeconds - Number(ts)) > TOLERANCE_SECONDS) throw new Error("stale or future timestamp");

  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64"); // unpadded base64 is accepted
  const expected = Buffer.from(
    "v1," + crypto.createHmac("sha256", key).update(`${id}.${ts}.`).update(rawBody).digest("base64"),
  );
  const ok = signatures.split(/\s+/).some((s) => {
    const candidate = Buffer.from(s);
    return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
  });
  if (!ok) throw new Error("signature mismatch");

  const event = JSON.parse(rawBody.toString("utf8"));
  if (event.event_id !== id) throw new Error("Webhook-Id does not match event_id");
  return event; // then deduplicate by event.event_id
}
```

**Test vector** (also in `envelope.v1.json` → `x-signature.test_vector`, computed with the server's `webhooks.Sign`):

| | |
| --- | --- |
| secret | `whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` |
| previous secret | `whsec_ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8` |
| `Webhook-Id` | `obx_01jbh0ybgaravg3xcq0zdp2egd` |
| `Webhook-Timestamp` | `1791634200` |
| body | the envelope example above in `jsonb` rendering (exact bytes in `x-signature.test_vector.body`) |
| `Webhook-Signature` | `v1,ASDtwkTifq0FaSm8BE4GznwV77UL2zkJ40idI04PMrg= v1,zItisJJkVxbfnWI0JJt8SFFx4VqL9SbzPnGYELuRXcQ=` |

## Versioning policy

- Schemas are versioned with a `.vN` file suffix and a matching `event_version` value in the envelope. The `$id` of a published version never changes. Event schemas are versioned independently of the hook contract, plugin manifests, workflow definitions and server releases (EXT-018).
- **Each subscription chooses its version** with `event_version` (`1` or `2`). A subscription created without it gets `1`, and every subscription created before event versioning existed keeps `1`: its deliveries are byte-for-byte what it received before the upgrade. Change it with `PATCH /api/v1/realms/{realm}/webhooks/{id}` (`{"event_version": 2}`) when your consumer is ready.
- The outbox stores every event once; deliveries are rendered to the subscription's version at fan-out (`contracts.RenderEvent`).
- **Within a version, only additive, backward-compatible changes are allowed:**
  - new optional `data` members;
  - new optional envelope members;
  - new event types;
  - new values for fields documented as open-ended (`session.revoked` `reason`, `support.impersonation.ended` `reason`);
  - looser constraints.

  The files of that version are then updated in place.
- **Consumers must ignore unknown fields and unknown event types.** The schemas are deliberately closed (`additionalProperties: false`) so that they describe exactly what the current server sends. If you validate incoming deliveries, refresh the schemas when you upgrade ProudAuth, or treat unknown-member failures as non-fatal.
- **Any breaking change creates a new version** (`<event_type>.vN.json`, `envelope.vN.json`) and events with `event_version: N`. Breaking changes include:
  - removing, renaming or retyping a field;
  - making a field optional that was always present;
  - removing a member from the minimal form;
  - adding a value to a closed `enum` such as `state` or `mode`;
  - changing identifier formats;
  - changing the meaning of a field or of when an event is emitted.

### Version 2

Version 2 changes the envelope only; every event type's `data` is identical in both versions.

| | v1 | v2 |
| --- | --- | --- |
| Organization member | `org_id` | `organization_id` (the name `data`, the session change stream and the REST API use) |
| Payload form | not stated | `payload_form`: `minimal` or `standard`, so a member the minimal form removed is distinguishable from one that does not apply |
| `event_version` | `1` | `2` |

Signature headers, the signature scheme (`Webhook-Signature: v1,...`, versioned separately from event schemas), retries and deduplication by `event_id` are the same for both versions.

### Support window

A version stays supported (deliverable and selectable) for at least **12 months** after its successor is published. Deprecation is announced in the CHANGELOG and listed, with the earliest removal date, by `GET /api/v1/realms/{realm}/extension-contracts`. Version 1 remains the default for new subscriptions until its sunset, so clients written against it keep working across server upgrades. The server's compatibility tests render every supported version from live events and validate it against these files.

## Using the schemas

- Register every file under its `$id` (base `https://auth.proudbase.com/schemas/events/`) so that the relative `$ref`s (`envelope.v1.json`, `envelope.v2.json#/$defs/...`) resolve offline.
- Enable `format` assertion if you want `date-time` checked; it is an annotation only by default.
- The schemas carry annotation keywords prefixed with `x-`: `x-headers`, `x-signature`, `x-event-type`, `x-subscribable`, `x-emitted-by`, `x-org-scoped` and `x-payload-form`. Standard validators ignore them. Ajv in strict mode rejects unknown keywords, so use `strict: false` or `ajv.addVocabulary([...])` with these names.
- All files compile as draft 2020-12, and every embedded example validates against its schema and against the envelope.
