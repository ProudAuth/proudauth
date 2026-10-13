# Federation transfer

A federation transfer (FED-016) moves account links from one upstream
provider connection to another through a reviewed migration map, with
collision reporting. Use it when an organization changes identity provider,
or when the same provider moves the organization to a new upstream tenant
(new issuer). It never relinks accounts by email address: each entry names
the subject at the source and the subject the same person has at the target,
and an entry applies only when it resolves to exactly one existing link.

Code: `internal/federation/transfer.go`, `internal/httpapi/fedtransfer.go`,
migration `0080_federation_transfers`. Test: `TestFederationTransfer`
(`tests/e2e/fedtransfer_test.go`), against test-double providers only.

## Why a transfer and not an edit

A connection's issuer (OIDC) or IdP entity ID (SAML) and its adapter cannot
change while identities are linked to it: such an update is `409` ("cannot
change while identities are linked; use a reviewed migration"), and a
connection with links cannot be deleted (`409`; disable it instead).
Changing the issuer in place would silently re-key every linked subject. To
move to a new tenant, create a **new connection** with the new issuer and
transfer the links to it.

## Procedure

1. **Create the target connection** (`POST /identity-providers`, or the
   SAML connection API) and keep the source connection enabled. Do not let
   the people being moved sign in through the target connection before the
   transfer: such a sign-in can create a link, or a new account, that then
   shows up as a collision.
2. **Build the map.** For each person, `source_subject` (as the source
   provider identifies them; see the account's linked identities) and
   `target_subject` (as the target provider will identify them). Get the
   target subjects from the target provider (its directory export or API);
   do not derive them from email addresses unless the provider guarantees
   that mapping.
3. **Create the transfer** as a draft, add entries in batches, and review the
   analysis ([below](#analysis)).
4. **Approve** with a second administrator.
5. **Apply** during a quiet period.
6. **Disable the source connection** (or limit it); users then sign in through
   the target connection into their existing accounts. Entries that did not
   apply stay in the report for manual follow-up.

## API

Routes under `/api/v1/realms/{realm}/federation-transfers`. They need
`realm.identity_providers.read` (reads) or `realm.identity_providers.write`
(changes), and `feature_disabled` is returned when federation is not enabled.

| Method and path | Body | Result |
| --- | --- | --- |
| `GET` | — | Transfers, newest first (at most 200), as a paginated list |
| `POST` | See below | `201` with the transfer (state `draft`) and its analysis summary; `ETag` |
| `GET /{id}` | — | The transfer with `summary`; `ETag` |
| `GET /{id}/entries` | `?outcome=&after=&limit=` | `{"items": [...], "next_after": <seq>}`; filter by outcome and page by `seq` |
| `POST /{id}/entries` | `{"entries": [...]}` | Adds 1 to 2000 entries to a **draft `map`** transfer (`409` otherwise) and analyses again; at most 50000 entries per transfer |
| `POST /{id}/approve` | — (`If-Match` optional) | Draft → `approved`. Must be an administrator other than the author (`403`); `409` when nothing in the transfer can be applied; `412` when `If-Match` is stale |
| `POST /{id}/apply` | — | Approved → `applied` ([Apply](#apply)); `409` in any other state |
| `POST /{id}/cancel` | — | `204`; draft or approved → `cancelled`. `409` once applied or cancelled |

Create body:

```json
{"source_provider_id": "idp_old", "target_provider_id": "idp_new",
 "mode": "map", "reason": "CHG-1234: move to new Entra tenant",
 "entries": [{"source_subject": "00u1abc", "target_subject": "a1b2c3"},
             {"source_subject": "00u1def", "source_issuer": "https://old.example",
              "target_subject": "d4e5f6", "target_tenant": "contoso"}]}
```

| Member | Rules |
| --- | --- |
| `source_provider_id`, `target_provider_id` | Connections of the realm (ID or alias); different connections; both realm-wide or both of the same organization (`422`) |
| `mode` | `map`: the entries given (more can be added while it is a draft). `same_subject`: one entry per existing link of the source, keeping the subject (an upstream tenant move where subjects do not change); no `entries` allowed, and at most 50000 source links |
| `target_tenant` | For `same_subject` mode, the tenant substituted into a multi-tenant target issuer (`{tenant}`). In `map` mode each entry carries its own `target_tenant` |
| `reason` | Required, 1–500 characters |
| `entries[]` | `source_subject` and `target_subject` required, single-line, at most 255 characters; `source_issuer` (at most 512) picks one issuer when the source subject is linked under several; `target_tenant` (at most 128) for multi-tenant targets. At most 2000 per request |

## Analysis

Every entry is classified against the current links when the transfer is
created, when entries are added, at approval and again at apply. The
transfer's `summary` counts each outcome plus `total`.

| Outcome | Meaning | At apply |
| --- | --- | --- |
| `ready` | Exactly one source link matches; the target subject is free; the account has no link at the target | The link moves |
| `already_linked` | The target subject is already linked to the same account | The source link is removed |
| `missing_source` | No link at the source for this subject | Skipped |
| `ambiguous_source` | The subject is linked under several source issuers; give `source_issuer` | Skipped |
| `duplicate_source` | The map names this source twice | Skipped |
| `duplicate_target` | Two entries give the same target subject | Skipped |
| `collision_target` | The target subject is linked to another account | Skipped |
| `collision_user` | The account already has a link at the target connection, or several entries would move the same account | Skipped |
| `target_tenant_required` | The target issuer contains `{tenant}` and the entry has no tenant | Skipped |
| `applied` | Moved (or its source link removed) by the apply | — |

Each entry also returns `seq`, the matched `user_id` (when there is one) and a
`detail` for some outcomes.

## Apply

Apply runs in one transaction, locks the links of both connections and
analyses again, so anything that became a collision since approval is
skipped and reported, never forced. For each entry still `ready`, the link
keeps its ID and account and gets the target connection, issuer (with the
tenant substituted), subject and tenant, `linking_provenance:
federation_transfer`, and the target's claim-mapping revision. **Upstream
tokens stored for the old connection are dropped.** For `already_linked`
entries the redundant source link is deleted. Sessions are not touched.

A transfer applies once. Entries that were skipped stay in the report with
their outcome; fix them by hand (link the account through the target
connection, or create a new transfer for the remaining entries).

Audit (category `security`): `federation.transfer.created` (connections,
mode, entry count, reason), `.approved` (summary), `.applied` (`moved`,
`dropped_source_links`, summary) and `.cancelled`.

Retention: the per-entry map of a transfer (upstream subjects at both
connections and the matched account) is deleted 180 days after the transfer
was applied or cancelled (`retention.cleanup` step
`federation_transfer_entries`); the transfer row and its summary stay as
evidence. Erasing an account (PRV-005) replaces the subjects in its entries
with `[erased]`.

## Limits and what is not supported

- No email-based or attribute-based matching, and no automatic relinking at
  the next sign-in.
- Up to 50000 entries per transfer; split larger populations.
- The approval check compares administrator IDs only; apply can be done by
  the author or the approver.
- Links that are not in the map stay at the source connection.
- The transfer does not change organization domain routing, SSO-mandatory
  settings or the source connection's state; do those separately.
