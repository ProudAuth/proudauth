# Shared signals (SSF, CAEP, RISC)

ProudAuth can send security events about users to other systems (transmitter,
AUD-016) and accept security events from systems an administrator trusts
(receiver, ADV-007). Both are opt-in. The transmitter is a declared profile
implemented as an adapter over the audit log; it is tested only against the
test receivers in this repository, and no shared-signals interoperability or
conformance suite has been run ([interoperability.md](interoperability.md)).

Code: `internal/ssf` (`ssf.go`, `deliver.go`, `receiver.go`),
`internal/httpapi/ssf.go`, `internal/httpapi/ssfreceiver.go`, migrations
`0058_shared_signals` and `0083_ssf_receiver`. Tests:
`TestSharedSignalsTransmitter` (`tests/e2e/ssf_test.go`) and
`TestSharedSignalsReceiver` (`tests/e2e/ssfreceiver_test.go`).

`I` below is the realm issuer, `<server.public_origin>/realms/<realm>`.

## Transmitter (AUD-016)

### Declared profile

| Item | What ProudAuth implements |
| --- | --- |
| Framework | OpenID Shared Signals Framework 1.0 transmitter (`spec_version` `1_0`): metadata, stream management, status, subjects, verification |
| Event types | CAEP 1.0 `session-revoked` and `credential-change`; RISC 1.0 `account-disabled`, `account-enabled`, `account-purged`, `credential-compromise`, `identifier-changed`; SSF `verification` and `stream-updated` |
| Token format | Security Event Tokens (RFC 8417), JOSE `typ: secevent+jwt`, signed with the realm's signing keys published at `I/jwks` |
| Delivery | Push (RFC 8935, `urn:ietf:rfc:8935`) and poll (RFC 8936, `urn:ietf:rfc:8936`) |
| Subject identifiers (RFC 9493) | In tokens: `iss_sub`, `complex` (session-revoked) and `opaque` (stream events). In subject management: `iss_sub` and `email` |
| Receiver authorization | OAuth 2.0 access tokens (`authorization_schemes`: `urn:ietf:rfc:6749`) |

### Turning it on

Realm policy `shared_signals.enabled` (default `false`), set with
`PUT /api/v1/realms/{realm}/settings`. While it is off, the metadata and
stream endpoints answer `404` and nothing is sent: due pushes wait (checked
again every 10 minutes, without using up their attempts) and polls return no
tokens. Events are still queued for existing streams and go out when the
transmitter is declared again, unless retention expired them.

Metadata (`Cache-Control: public, max-age=300`) is served at
`GET I/.well-known/ssf-configuration` and
`GET /.well-known/ssf-configuration/realms/{realm}`:

```json
{"spec_version": "1_0", "issuer": "I", "jwks_uri": "I/jwks",
 "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
 "configuration_endpoint": "I/ssf/streams", "status_endpoint": "I/ssf/streams/status",
 "add_subject_endpoint": "I/ssf/streams/subjects/add",
 "remove_subject_endpoint": "I/ssf/streams/subjects/remove",
 "verification_endpoint": "I/ssf/streams/verify",
 "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}],
 "default_subjects": "NONE", "events_supported": ["..."]}
```

### Receivers

A receiver is a client of the realm with a service principal; that service
principal must hold the permission `realm.ssf_streams.manage` (sensitivity
`high`; give it through a custom realm role). The receiver calls the stream
API with a client-credentials access token for the administration API
(resource `I/admin`, scope `proudauth:admin`), so the client needs the
`client_credentials` grant and a resource grant for the admin resource with
subject type `service_principal`. Human administrator tokens and machine
clients without the permission get `403`.

- Streams belong to the calling client; another receiver sees `404` for them.
- At most 5 streams per receiver (`409`).
- The `aud` of every token on a stream is the receiver's `client_id`.

### Stream API

| Method and path (under `I/ssf/streams`) | Body or query | Result |
| --- | --- | --- |
| `POST` | `{"delivery": {"method", "endpoint_url", "authorization_header"}, "events_requested": [...], "description", "subject_scope"}` | `201` with the stream. Without `delivery` the stream polls. `events_requested` at most 50 entries; `description` at most 500 characters |
| `GET` | `?stream_id=` | One stream; without `stream_id`, an array of the receiver's streams |
| `PATCH` | `{"stream_id", ...}` | Changes only the members given |
| `PUT` | `{"stream_id", "delivery", "events_requested", ...}` | Replaces the configuration; `delivery` and `events_requested` are required (`422`), an omitted `description` is cleared. Read-only members (`iss`, `aud`, `events_supported`, `events_delivered`, `min_verification_interval`, `status`, `reason`, `client_id`, timestamps) may be echoed and are ignored |
| `DELETE` | `?stream_id=` | `204`; queued events are discarded |
| `GET /status` | `?stream_id=` | `{"stream_id", "status", "reason"}` |
| `POST /status` | `{"stream_id", "status", "reason"}` | `status` `enabled`, `paused` or `disabled`; `reason` at most 500 characters |
| `POST /subjects/add` | `{"stream_id", "subject"}` | `200` ([Subjects](#which-users-a-stream-covers)) |
| `POST /subjects/remove` | `{"stream_id", "subject"}` | `204` |
| `POST /verify` | `{"stream_id", "state"}` | `204`; queues a verification event carrying `state` (at most 256 characters). The stream must be `enabled` (`409`); at most one request per 60 seconds per stream (`429`) |
| `POST /{stream_id}/poll` | RFC 8936 body | See [Poll](#poll) |

A stream returns `stream_id`, `iss`, `aud`, `delivery` (for poll streams
`endpoint_url` is the poll URL the transmitter assigned; the
`authorization_header` is never returned), `events_supported`,
`events_requested`, `events_delivered` (the requested types the transmitter
supports; unknown types are kept in `events_requested` and ignored),
`description`, `min_verification_interval` (60), `subject_scope`, `status`,
`reason`, `client_id`, `created_at` and `updated_at`.

Push `endpoint_url` must pass the webhook egress rules: `https` in production
mode, public addresses unless `delivery.allow_private_webhooks` or
`delivery.egress_allowlist` allow the destination
([configuration.md](../operations/configuration.md#delivery)); `422` on
`delivery.endpoint_url` otherwise. `authorization_header` is one header value
of at most 2048 characters, sent as `Authorization` with every push; it is
write-only and stored encrypted (bound to the stream). Changing the method or
the endpoint without giving a new value clears it.

Audit (category `security`): `ssf.stream.created`, `ssf.stream.updated`,
`ssf.stream.deleted`, `ssf.stream.status_changed`.

### Which users a stream covers

| `subject_scope` | Events about |
| --- | --- |
| `client_users` (default) | Users who have authorized the receiver client: an authorization grant for the user and that client exists (revoked grants count while their row is retained) |
| `listed` | The same users, narrowed to subjects the receiver added with `subjects/add` |
| `all` | Every user of the realm. Only an administrator can set it ([Administration](#administration)); a receiver that asks for `all` gets `403`, and once an administrator set it the receiver cannot change it (`403`). Echoing the current `all` back in a `PATCH` or `PUT` is accepted as no change |

`subjects/add` and `subjects/remove` accept `iss_sub` subjects (`iss` must be
the realm issuer; `sub` is the subject the receiver knows, pairwise for
pairwise clients) and `email` subjects (only verified addresses resolve).
Other formats are `422`. Adding a subject never widens a stream beyond the
receiver's own users: an unknown subject, or a user who never authorized the
receiver, is answered `200` like any other and has no effect on what is sent,
so the endpoint reveals nothing about accounts. A stream holds at most
100000 added subjects (`409`).

### Events

Events are queued in the same database transaction as the audit event they
come from, for every enabled or paused stream whose `events_delivered`
includes the type and whose scope covers the user. Only successful audit
events about users produce events.

| Event type | From | Event members |
| --- | --- | --- |
| CAEP `session-revoked` | `session.revoked` | `initiating_entity`: `admin`, `user`, `policy` or `system`, derived from the revocation reason |
| CAEP `credential-change` | Password changed or reset; TOTP or HOTP enrolled or removed; passkey enrolled or removed; client certificate bound or unbound | `credential_type` `password`, `app`, `fido2-roaming`, `fido2-platform` (platform attachment) or `x509`; `change_type` `create`, `update` or `delete` |
| RISC `account-disabled` | `user.suspended`, `user.locked` | — |
| RISC `account-enabled` | `user.reactivated` | — |
| RISC `account-purged` | `user.deleted` | — |
| RISC `credential-compromise` | `credential.password.compromised` | `credential_type: password` |
| RISC `identifier-changed` | `user.identifier.primary_changed` | — (the new value is not included; read it from UserInfo) |
| SSF `verification` | `POST /verify` | `state` when given |
| SSF `stream-updated` | An administrator changed the stream's status | `status`, `reason` |

Every event body also has `event_timestamp` (the audit event's time). The
token's claims are `iss`, `jti`, `iat` (the event time), `aud`, `events` and
`sub_id`:

```json
{"iss": "I", "jti": "set_...", "iat": 1760000000, "aud": "risk-rp",
 "sub_id": {"format": "complex",
            "user": {"format": "iss_sub", "iss": "I", "sub": "usr_..."},
            "session": {"format": "opaque", "id": "ses_..."}},
 "events": {"https://schemas.openid.net/secevent/caep/event-type/session-revoked":
            {"initiating_entity": "admin", "event_timestamp": 1760000000}}}
```

- `sub_id` is `iss_sub` with the subject the receiver knows (the stored
  pairwise value for pairwise clients), fixed when the event is queued so it
  survives the account's erasure; `complex` with the session ID for
  session revocations; `opaque` with the stream ID for verification and
  stream-updated events.
- Verification and stream-updated events are always delivered, whatever
  `events_requested` says.
- A token is signed once; a re-delivery or re-poll returns the identical token.

Not emitted: CAEP `assurance-level-change`, `token-claims-change` and
`device-compliance-change`; RISC `account-credential-change-required`,
`recovery-activated`, `recovery-information-changed`, `opt-in` and `opt-out`;
events about service principals or organizations. There are no
transmitter-initiated default subjects (`default_subjects: NONE`).

### Push

The worker task `ssf.deliver` (every 2 seconds, up to 50 events per run)
POSTs each due token to the stream's endpoint with
`Content-Type: application/secevent+jwt`, `Accept: application/json` and the
stored `Authorization` value.

- `2xx`: delivered.
- `400`: the receiver rejected the token (RFC 8935 §2.4); the event fails
  without retry, recording the receiver's `err` code.
- Anything else, network errors and egress refusals: retried with
  exponential backoff (20 seconds, doubling) up to 8 attempts, then failed.
- Paused streams keep queueing and deliver when enabled again; disabling a
  stream expires its queued events and queues nothing more.

### Poll

`POST I/ssf/streams/{stream_id}/poll` (RFC 8936) with
`{"ack": [...], "setErrs": {"<jti>": {"err": "...", "description": "..."}}, "maxEvents": n, "returnImmediately": bool}`:

- acknowledged tokens (at most 1000 per request) are finished; tokens named in
  `setErrs` are marked failed;
- the response is `{"sets": {"<jti>": "<token>"}, "moreAvailable": bool}`
  with at most `maxEvents` tokens (default 50, at most 100; `0` only
  acknowledges);
- returned tokens stay outstanding and are returned again by later polls
  until acknowledged or reported;
- polling a push stream is `409`.

**Long polling is not supported**: `returnImmediately: false` is accepted but
the request always answers at once.

### Retention

Events still `pending` 7 days after they occurred, and polled events still
not acknowledged by then, are marked `expired`; a push the receiver accepted
stays `delivered`. Finished events (acknowledged, delivered pushes, failed
and expired) are deleted 14 days after they occurred (`retention.cleanup`
step `ssf_events`). Deleting a stream deletes its events. Erasing an account
(PRV-005) removes it from every stream's subjects and expires the events
queued about it, dropping their subject and token.

### Administration

| Method and path (under `/api/v1/realms/{realm}`) | Permission | Effect |
| --- | --- | --- |
| `GET /ssf-streams`, `GET /ssf-streams/{id}` | `realm.ssf_streams.read` (granted to `realm-auditor`) | Every stream of the realm |
| `GET /ssf-streams/{id}/events` | `realm.ssf_streams.read` | Delivery state of the newest 200 events (`jti`, `event_type`, `state`, `attempts`, `occurred_at`, `delivered_at`, `last_status_code`, `last_error`); never the tokens |
| `PATCH /ssf-streams/{id}` | `realm.settings.write` | `{"subject_scope": ...}`, including `all` |
| `POST /ssf-streams/{id}/status` | `realm.settings.write` | `{"status", "reason"}`; the receiver gets a `stream-updated` event |
| `DELETE /ssf-streams/{id}` | `realm.settings.write` | Removes the stream and its queued events |

Event states: `pending`, `delivered` (pushed, or returned by a poll and not
yet acknowledged), `acknowledged`, `failed`, `expired`. Monitoring:
[monitoring.md](../operations/monitoring.md#shared-signals).

## Receiver (ADV-007)

ProudAuth accepts Security Event Tokens **pushed** (RFC 8935) by transmitters
an administrator registered. Source trust is explicit: there is no dynamic or
open registration and ProudAuth never polls a remote transmitter. Configure
the stream at the transmitter with the push endpoint, audience and push secret
returned at registration. The receiver works whether or not the realm's own
transmitter (`shared_signals.enabled`) is on.

### Registering a transmitter

| Method and path (under `/api/v1/realms/{realm}`) | Permission | Effect |
| --- | --- | --- |
| `GET /ssf-transmitters`, `GET /ssf-transmitters/{id}` | `realm.settings.read` | Registered transmitters (with `ETag`) |
| `POST /ssf-transmitters` | `realm.settings.write` | `201 {"transmitter", "push_secret"}`; the secret (`pa_ssfp_...`) is shown once and stored as a digest |
| `PUT /ssf-transmitters/{id}` | `realm.settings.write` | Replaces the settings; `If-Match` optional (`412` when stale) |
| `POST /ssf-transmitters/{id}/rotate-secret` | `realm.settings.write` | New push secret, returned once; the old one stops working at once |
| `DELETE /ssf-transmitters/{id}` | `realm.settings.write` | Removes the transmitter and its received-event records |
| `GET /ssf-transmitters/{id}/events` | `realm.settings.read` | The newest 500 received-event records |

```json
{"name": "partner-idp", "issuer": "https://idp.partner.example",
 "jwks_uri": "https://idp.partner.example/jwks", "provider_id": "idp_...",
 "allow_email_subjects": false, "max_event_age_seconds": 86400,
 "actions": {"https://schemas.openid.net/secevent/caep/event-type/session-revoked": "revoke_sessions",
             "https://schemas.openid.net/secevent/risc/event-type/account-disabled": "suspend_user"}}
```

| Member | Rules |
| --- | --- |
| `name` | 1–100 characters, unique in the realm |
| `issuer` | The transmitter's `iss`: an `https` URL or a URN, at most 512 characters, unique in the realm |
| `jwks_uri` or `jwks` | Exactly one. `jwks_uri` is fetched under the delivery egress policy, cached 10 minutes and refreshed for a failed signature at most once per minute per transmitter/URL/server process. Concurrent and failed fetches share that budget; `jwks` is a static set of public keys (at most 64 KiB) |
| `provider_id` | A federation connection of the realm; needed to map `iss_sub` subjects |
| `allow_email_subjects` | Default `false`; when `true`, `email` subjects map to verified addresses |
| `actions` | Event type → action ([Action policy](#action-policy)) |
| `max_event_age_seconds` | Default 86400, 60–604800 |
| `state` | `active` (default) or `disabled`; a disabled transmitter's pushes get `401` |

At most 50 transmitters per realm (`409`). The response's `push_endpoint` and
`audience` are both `I/ssf/receivers/{id}/events`.

Audit (category `security`): `ssf.transmitter.registered`,
`ssf.transmitter.updated` (also for secret rotation), `ssf.transmitter.deleted`.

### Checks on every push

`POST I/ssf/receivers/{id}/events` with `Authorization: Bearer <push secret>`
and the token as the body. Pushes are limited to 600 per minute per
transmitter and 1200 per minute per client address (`429`
`{"err": "too_many_requests"}` with `Retry-After`; `503` if the limiter is
unavailable). Then:

1. The push secret matches and the transmitter is `active`; otherwise `401`
   `authentication_failed`.
2. The body is one token of at most 64 KiB with exactly one signature using
   RS256, PS256, ES256 or EdDSA; JOSE `typ`, when present, is `secevent+jwt`
   or `JWT`. The signature verifies with the transmitter's keys (by `kid`, or
   every key when the token has none).
3. `iss` equals the registered issuer; `aud` contains the push endpoint;
   `jti` is present (at most 256 characters); `iat` is no older than
   `max_event_age_seconds` and at most 5 minutes in the future; the token
   carries 1 to 10 events.
4. **Replays**: `(transmitter, jti)` is recorded once. A replay is answered
   `202` without effect and audited as `ssf.event.replayed` (outcome
   `denied`).

Failures answer RFC 8935 errors, `{"err", "description"}`: `400` with
`invalid_request`, `invalid_key`, `invalid_issuer` or `invalid_audience`, or
`401` with `authentication_failed`. Accepted tokens get `202`.

### Subject mapping

| Subject format | Maps to |
| --- | --- |
| `iss_sub` (or a plain `sub` claim) | The external identity link of the transmitter's `provider_id` whose upstream issuer and subject equal `iss` and `sub`; nothing without `provider_id` |
| `email` | A user whose **verified** email address it is, only with `allow_email_subjects` |
| `complex` | Its `user` member, mapped as above |
| anything else | Unmatched |

An unmatched subject is recorded as `subject_unknown` (`no_subject` when the
token has none) and answered `202` like any accepted event, so the endpoint
does not reveal which accounts exist.

### Action policy

Every event maps to an explicit local action. Event types the policy does not
list, unknown types and events without a matched subject are only recorded.

| Event type | Allowed actions |
| --- | --- |
| CAEP `session-revoked` | `record_only`, `revoke_sessions`, `revoke_all` |
| CAEP `credential-change`, `assurance-level-change` | `record_only`, `revoke_sessions` |
| RISC `credential-compromise` | `record_only`, `revoke_all`, `mark_password_compromised` |
| RISC `account-disabled`, `account-purged` | `record_only`, `revoke_all`, `suspend_user` |
| RISC `account-enabled`, `identifier-changed` | `record_only` only: an outside signal never re-enables an account or changes identifiers |

- `revoke_sessions` revokes the user's active sessions; `revoke_all` also
  revokes the user's authorization grants and refresh-token families
  (including offline access).
- `suspend_user` suspends the account. **Protected accounts** (platform
  administrators, break-glass accounts) are never suspended by an outside
  signal: their sessions and grants are revoked instead (outcome
  `protected_account_sessions_revoked`). An account that is not active is
  left alone (outcome `already_<state>`).
- `mark_password_compromised` revokes sessions and grants and marks the
  user's active password compromised, as
  `POST /users/{user}/credentials/password/compromised` does; the marking runs
  after the receiving transaction commits.
- SSF `verification` events are accepted with outcome `verified`.

Revocations made here are ordinary revocations: they reach back-channel
logout, the session-event stream and this realm's own SSF streams
(`session-revoked`), so a signal can propagate onward.

### Records and retention

Each accepted token leaves a record with `jti`, the event type (the first in
sorted order when a token carries several), the subject format, the matched
user ID, the action and the outcome (`recorded`, `applied`, `verified`,
`subject_unknown`, `no_subject`, `unsupported_event`,
`protected_account_sessions_revoked`, `already_<state>`). Records never hold
the token or the subject identifiers; they are deleted after 30 days
(`retention.cleanup` step `ssf_received_events`) and with their transmitter.
Audit: `ssf.event.received` (category `security`, subject the matched user,
metadata `jti`, `event_types`, `action`, `outcome`).

### Not supported

Polling remote transmitters (RFC 8936 as a client); stream management at a
remote transmitter (configure it there); dynamic transmitter registration;
encrypted tokens; actions for CAEP `token-claims-change` and
`device-compliance-change`; acting on organizations or service principals.

## Not supported on either side

Long polling; receiver-initiated transmitter discovery; SSF events about
service principals; any certification or conformance claim for SSF, CAEP or
RISC.
