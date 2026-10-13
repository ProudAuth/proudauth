# Consuming webhooks

Requirements: §22 (EXT-001..EXT-008, EXT-018), AUD-012, TEST-052, TEST-054. Code:
`internal/webhooks/webhooks.go`, `internal/events/outbox.go`,
`internal/egress/egress.go`, `internal/contracts/events.go` (event versions).
Event catalog and JSON Schemas:
[api/events/README.md](../../api/events/README.md).

Webhooks tell other systems that something changed. They are **not** a revocation
mechanism: delivery is asynchronous and can be delayed or fail. A resource that
must stop access immediately has to validate online
([revocation-exposure.md](../operations/revocation-exposure.md)).

## Subscribing

Administration API (`realm.webhooks.write`):

```json
POST /api/v1/realms/main/webhooks
{
  "name": "membership sync",
  "destination_url": "https://hooks.example.com/proudauth",
  "event_types": ["organization.membership.removed", "session.revoked"],
  "organization_id": "",
  "payload_form": "minimal",
  "event_version": 2
}
```

- The response contains `signing_secret` (`whsec_...`) **once**. Store it in your
  secret manager.
- `event_types`: names from the catalog, or `"*"`. Unknown names are rejected.
- `organization_id` scopes the subscription to one organization's events;
  realm-wide subscriptions receive everything in the realm. When an
  organization's deletion starts, its subscriptions are disabled (and deleted,
  with their deliveries, when the deletion finishes), so they do not receive
  that organization's `organization.deleted`; realm-wide subscriptions do. Applying an
  organization template that defines `webhooks` also creates
  organization-scoped subscriptions (public HTTPS destinations only), and
  returns their secrets once in `webhook_secrets`.
- `payload_form`: `minimal` (default; `data` keeps only `*_id` members and the
  non-personal members listed in [api/events](../../api/events/README.md))
  or `standard` (full `data`). Both forms carry everything a `security.alert`
  (AUD-012) has.
- `event_version`: the envelope version deliveries are rendered in, `1`
  (default) or `2` ([Event versions](#event-versions)); another value is a
  `422`.
- Manage with `GET/PATCH/DELETE /webhooks/{id}`. `PATCH` is a partial update
  (optional `If-Match` with the `ETag` from `GET`): it accepts `name`,
  `destination_url`, `event_types`, `allow_private_network`, `payload_form`,
  `event_version` and `state`, and members it omits keep their current values. `organization_id`
  cannot be changed (a body containing it is rejected with `400`); create a new
  subscription instead. The update only applies if the subscription's version is
  still the one the request read: of two concurrent updates, the one that
  commits second fails with `412 precondition_failed` instead of overwriting the
  first, even without `If-Match`; read the subscription again and retry.
- `PATCH` with `"state": "paused"` or `"disabled"` stops deliveries (events
  published meanwhile are **not** queued for later), and `"active"` resumes them.
  A change of `state` alone does not re-resolve the destination, so it works
  while the receiver's DNS is failing. Administrators can also disable a
  subscription through the audited emergency controls
  ([incidents.md](../operations/incidents.md#emergency-controls-sec-020)).
- Subscriptions a [plugin](plugins.md) installed show its `plugin_id`. `PATCH`
  (including a state-only change) and `DELETE` answer `409` for them: change
  them through the plugin. Secret rotation and the emergency controls still
  work. A `call_webhook` step of a [lifecycle workflow](workflows.md) also
  posts to a realm-wide subscription's destination, with a different body
  ([step call](workflows.md#step-call-contract)).

### Destination rules (egress policy)

- `https` is required in production mode.
- Destinations resolving to private, loopback, link-local, CGNAT, multicast,
  documentation or other special ranges are refused, and the address is **checked
  again at every connection** (defeats DNS rebinding). A subscription may reach
  private addresses only when it is created or updated with
  `allow_private_network: true`, which is accepted only when the operator allows
  private egress (`delivery.egress_allowlist` with specific CIDRs, or
  `delivery.allow_private_webhooks`, which is rejected in production); it is then
  limited to what the operator policy allows. Subscriptions without the flag are
  held to a public-only policy: creating or updating one whose destination
  resolves to a private address is refused (`422` on `destination_url`), and a
  destination that becomes private later (DNS change) fails at delivery with
  `egress_denied` (`TestWebhooksAndBackchannelLogout`).
- A `PATCH` that changes anything besides `state` re-validates the resulting
  subscription against these rules, including its current
  `allow_private_network` setting.
- With a residency policy (`privacy.residency.allowed_destinations`), the
  destination's host must also be on that list, at registration and at every
  connection ([configuration.md](../operations/configuration.md#privacy)).
- IPv6 addresses that embed IPv4 ones (6to4 `2002::/16`, Teredo `2001::/32`,
  local-use NAT64 `64:ff9b:1::/48`) are refused like the other special
  ranges.
- Redirects are not followed; ambient HTTP proxies are not used; each attempt has a
  `delivery.webhook_timeout` (10 s) limit; at most 64 KiB of the response is read.

## Request format

```http
POST /proudauth HTTP/1.1
Content-Type: application/json
User-Agent: ProudAuth-Webhooks/1
Webhook-Id: obx_01jbh0ybgaravg3xcq0zdp2egd
Webhook-Timestamp: 1791590400
Webhook-Signature: v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=

{"data": {"user_id": "usr_...", "membership_id": "mem_...", "authorization_revision": 44}, "org_id": "org_...", "event_id": "obx_...", ...}
```

Envelope members (version 1): `event_id`, `event_type`, `event_version` (1), `occurred_at`,
`realm_id`, optional `org_id`, optional `correlation_id` (the `X-Request-Id`
of the API request that caused the event, also stored as `request_id` on its
audit events; absent for background work, API-012, except events a
[lifecycle workflow](workflows.md) run causes, which carry the run's ID
`wrn_…`), `data`. Key order and whitespace are not stable;
parse as JSON and verify the signature over the raw bytes.

### Event versions

Event schemas are versioned independently of server releases (EXT-018,
[extension-contracts.md](extension-contracts.md)), and each subscription
chooses its `event_version`:

| | Version 1 (default) | Version 2 |
| --- | --- | --- |
| Organization member | `org_id` | `organization_id` (the name `data`, the session-event stream and the REST API use) |
| Payload form | not stated | `payload_form`: `minimal` or `standard`, so a member the minimal form removed can be told from one that does not apply |
| `event_version` | `1` | `2` |
| `data` | identical in both versions | |
| Schemas | `envelope.v1.json`, `<type>.v1.json` | `envelope.v2.json`, `<type>.v2.json` |

- Every subscription created before event versioning (migration `0072`) and
  every subscription created without `event_version` uses version 1, and its
  deliveries are byte for byte what they were before.
- To move a receiver to version 2: deploy a receiver that accepts both
  envelopes (read `organization_id`, falling back to `org_id`), then
  `PATCH /webhooks/{id} {"event_version": 2}`. The change applies to events
  fanned out afterwards; deliveries already queued, retried or replayed keep
  the version they were rendered in.
- Version 2 bodies are serialized again from the stored event, so their
  member order and whitespace differ from version 1 (neither is stable).
- The signature scheme (`Webhook-Signature: v1,…`), headers, retries and
  deduplication by `event_id` are the same for both versions.
- A version stays supported for at least 12 months after its successor is
  published, and version 1 stays the default for new subscriptions until its
  sunset. `GET /extension-contracts` lists the versions and any sunset date;
  no version is deprecated today.

## Verifying a delivery

ProudAuth signs `"<Webhook-Id>.<Webhook-Timestamp>.<raw body>"` with HMAC-SHA256.

1. Take the secret string after the `whsec_` prefix and base64-decode it
   (standard alphabet) to get the 32-byte key. Secrets are issued padded
   (`=`); secrets issued before v0.2 are unpadded, so strip trailing `=` and
   decode without padding to accept both.
2. Compute `expected = "v1," + base64std(HMAC-SHA256(key, id + "." + timestamp + "." + body))`.
3. `Webhook-Signature` contains one or more space-separated signatures; accept the
   request if **any** equals `expected` (constant-time comparison).
4. Reject if `|now - Webhook-Timestamp|` exceeds your tolerance (for example
   5 minutes). A valid signature alone does not prove freshness (EXT-004).
5. Deduplicate by `Webhook-Id` (= `event_id`); keep processed IDs for longer than
   the retry horizon (days).
6. Respond `2xx` quickly and process asynchronously.

Example (Go):

```go
func verify(secret, id, ts, header string, body []byte, now time.Time) bool {
    key, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(secret, "whsec_"), "="))
    if err != nil { return false }
    sec, err := strconv.ParseInt(ts, 10, 64)
    if err != nil || now.Sub(time.Unix(sec, 0)).Abs() > 5*time.Minute { return false }
    m := hmac.New(sha256.New, key)
    m.Write([]byte(id + "." + ts + "."))
    m.Write(body)
    want := "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
    for _, got := range strings.Fields(header) {
        if hmac.Equal([]byte(got), []byte(want)) { return true }
    }
    return false
}
```

The server-side reference is `webhooks.VerifySignature` in `internal/webhooks`
(an internal package; neither the Go nor the Node SDK ships a webhook verifier).
`TestWebhooksAndBackchannelLogout` checks that tampered bodies, stale timestamps and
wrong keys fail verification; `TestPublishedSignatureVector` keeps the test vector in
`api/events/envelope.v1.json` (`x-signature`) identical to what the server signs, and
`TestWebhookSubscriptionLifecycle` checks rotation and retries end to end.

## Delivery semantics

- **At least once.** The same `event_id` can arrive more than once (worker crash
  after send, manual replay).
- **No ordering guarantee** across events. Use `occurred_at` and fetch current state
  from the API when order matters.
- **Retries:** non-2xx responses and network errors are retried with exponential
  backoff (5 s × 2^attempt, capped at 6 hours, plus up to 25 % jitter) until
  `delivery.webhook_max_attempts` (12) is reached; then the delivery is
  `dead_letter`. **HTTP 410 Gone** dead-letters immediately — use it to tell
  ProudAuth to stop.
- **Replay:** administrators can list deliveries (`GET /webhooks/{id}/deliveries`:
  state, attempts, last status, response category; newest first, paged with
  `limit` and `next_cursor`) and requeue one
  (`POST /webhooks/{id}/deliveries/{delivery}/replay`); the `event_id` stays the
  same. Delivered and dead-lettered deliveries are deleted
  `privacy.history_retention` (180 days by default) after they were created,
  so replay a dead letter before then.
- **Backlog** (EXT-005): `GET /webhooks/{id}/backlog` (`realm.webhooks.read`)
  summarizes one destination:

  ```json
  {"pending": 0, "retrying": 3, "dead_letter": 1, "delivered": 5120,
   "oldest_due_seconds": 95, "last_delivered_at": "2026-10-11T09:12:03Z",
   "last_failure_category": "http_500"}
  ```

  The counts cover every delivery row of the subscription; `oldest_due_seconds`
  is how long the oldest `pending` or `retrying` delivery has been due (0 when
  none is overdue); `last_failure_category` is the response category of the
  newest `retrying` or `dead_letter` delivery (the status class for HTTP
  failures, such as `http_500` for any 5xx answer or `http_400`, otherwise
  `gone`, `network_error`, `egress_denied`, `secret_unavailable`, ...). Watch it alongside
  `/status` `backlog_oldest_seconds.webhooks`, which covers all subscriptions.
- Events are produced only after the change committed (transactional outbox); a
  received event always reflects committed state.

## Secret rotation

`POST /webhooks/{id}/rotate-secret` returns a new secret. For the next 24 hours each
delivery carries two signatures (new and previous), so you can deploy the new
secret without downtime. After 24 hours only the new secret signs.

## What not to do

- Do not treat `session.revoked` or `organization.membership.removed` as the
  mechanism that stops API access; validate tokens online where that matters.
- Do not infer state from the absence of events; several changes emit none (see the
  catalog's "What does not produce an event").
- Do not authorize users from data in webhook payloads; payloads contain only
  identifiers and states.
