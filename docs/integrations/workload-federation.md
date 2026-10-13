# Workload identity federation

Requirements: MCH-011, MCH-012, MCH-013, ADV-004 (RFC 7523 §2.1). Code:
`internal/workload/workload.go`, `internal/oauth/jwtbearer.go`,
`internal/httpapi/workload.go`, migration `0051`. Test:
`TestWorkloadFederation` (`tests/e2e/workload_test.go`).

A workload that already holds an identity token from its platform (a GitHub
Actions job, a Kubernetes pod, a SPIFFE workload, or any issuer of signed
JWTs) can exchange that token for a ProudAuth service token without a
stored client secret. The administrator binds a machine client to a
**workload trust**: the issuer, its keys, the exact audience, the subject
and optional claim constraints. A matching assertion presented with the
`jwt-bearer` grant yields a token for the client's service principal.

The assertion is never mapped to a human account: this grant only ever
issues service tokens. User authorization grants from external JWTs are not
offered.

## Setting up the client

```sh
# Machine client whose only grant is jwt-bearer: no secret is issued
identity-cli api POST /clients '{"client_id": "deploy-job", "name": "Deploy pipeline",
  "client_type": "machine", "service_principal_id": "svc_...",
  "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "token_endpoint_auth_method": "none"}'
identity-cli api PUT /clients/cli_.../resource-grants/res_deploy \
  '{"allowed_scopes": ["deploy:write"], "subject_types": ["service_principal"]}'
```

- Machine clients may register `urn:ietf:params:oauth:grant-type:jwt-bearer`.
  It needs a service principal (`422` on `service_principal_id` otherwise).
- When `jwt-bearer` is the client's only grant (listed explicitly), it may use
  `token_endpoint_auth_method: none`: the assertion is the credential and the
  client sends only `client_id`. Otherwise (`422`, "machine clients must
  authenticate unless their only grant is ...") machine clients
  authenticate as usual, and a client with a secret or `private_key_jwt` can
  use the grant too. The configuration export writes such a client with
  `token_endpoint_auth_method: none`, and the configuration document schema
  accepts `none` for a machine client exactly in this case (its
  `grant_types` must be present and list only `jwt-bearer`), so the export
  validates and imports.
- Resource grants, organizations and scope policy work as for
  `client_credentials` ([machine-clients.md](machine-clients.md)).

## Trusts

Paths are relative to `/api/v1/realms/{realm}/clients/{client}` (`{client}`
is the client's internal reference, `cli_...`):

| Method and path | Permission | Effect |
| --- | --- | --- |
| `GET /workload-trusts` | `realm.clients.read` | List (`{items, next_cursor}`, at most 200) |
| `POST /workload-trusts` | `realm.clients.credentials` | Create → `201` with `ETag` |
| `GET /workload-trusts/{id}` | `realm.clients.read` | One trust; `ETag: W/"v<N>"` |
| `PUT /workload-trusts/{id}` | `realm.clients.credentials` | Replace the whole trust (omitted members return to their defaults); `If-Match` required (`428` without, `412` when stale). `state: disabled` stops the trust at once |
| `DELETE /workload-trusts/{id}` | `realm.clients.credentials` | Delete (`204`). Tokens already issued expire on their own; they never outlive the assertion they came from |

Creating or replacing a trust needs a machine client with a service
principal and the `jwt-bearer` grant (`409` otherwise). Changes are audited as
`client.workload_trust.created`, `.updated` and `.deleted` (category
`configuration`, with profile, issuer, subject and audience).

```json
POST /api/v1/realms/main/clients/cli_.../workload-trusts
{"name": "deploys from main", "profile": "github_actions",
 "audience": "https://id.example.com/realms/main",
 "subject": "repo:acme/payments:ref:refs/heads/main",
 "claim_constraints": {"repository_owner": ["acme"], "workflow": ["deploy"]}}
```

| Member | Rules |
| --- | --- |
| `name` | Required, at most 100 characters |
| `profile` | `generic` (default), `github_actions`, `kubernetes` or `spiffe` (below) |
| `issuer` | Exact `iss`; an `https` URL (`http` only outside production), no userinfo or fragment |
| `jwks_uri` / `jwks` | Exactly one: an `https` URL of the issuer's key set, or an inline set of 1–20 public keys |
| `audience` | Required, at most 512 characters. The assertion's `aud` (string or array) must contain it; other values may be present |
| `subject` | Exact `sub`, or per profile a prefix ending in `*`; at most 512 characters |
| `algorithms` | Subset of `RS256`, `PS256`, `ES256`, `ES384`, `EdDSA` (no HMAC, no `none`); required for `generic` |
| `max_assertion_lifetime_seconds` | 60–86400 (default 3600): `exp` minus the earlier of `iat` and `nbf` (or now, when the assertion has neither) |
| `claim_constraints` | Up to 20 claims, each with 1–50 accepted values. Nested claims use `/` (`kubernetes.io/namespace`, up to 5 segments). `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` and `jti` cannot be constrained. Strings match exactly; booleans as `true`/`false`; integers as decimal text; arrays and objects never match |
| `require_jti` | When `true`, assertions without `jti` are refused. A `jti` that is present is always single-use per trust |
| `state` | `active` (default) or `disabled` |

**Profiles** fix or default what each platform's tokens look like:

| Profile | Defaults and rules |
| --- | --- |
| `github_actions` | `issuer` defaults to `https://token.actions.githubusercontent.com` and the key set to `<issuer>/.well-known/jwks` (both can be overridden); algorithms `RS256`; `require_jti` defaults to `true` (an explicit `false` is accepted). `subject` must name one repository: `repo:<owner>/<repo>:<rest>`; a trailing `*` may cover refs or environments (`repo:acme/payments:ref:*`, `repo:acme/payments:environment:*`) but never other repositories, and `<rest>` must not be empty, so `repo:acme/payments:*` is refused |
| `kubernetes` | `issuer` (the cluster's service-account issuer) and `jwks` or `jwks_uri` are required; algorithms `RS256`, `ES256`. `subject` is exactly one service account, `system:serviceaccount:<namespace>:<name>`, no wildcards |
| `spiffe` | `subject` is a SPIFFE ID `spiffe://<trust domain>/<path>`, optionally ending in `*` as a path prefix (`spiffe://prod.example/ns/payments/*`; a bare trust domain is refused). `issuer` defaults to `spiffe://<trust domain>`, so JWT-SVIDs without `iss` match. Algorithms `RS256`, `ES256`, `PS256` |
| `generic` | `subject` is exact or a non-empty prefix followed by one trailing `*`; `issuer`, a key set and `algorithms` are required |

The `*` is a plain string prefix: `spiffe://td/ns/pay*` also matches
`spiffe://td/ns/payroll`. Prefer prefixes that end in `/` or `:` before the
`*`.

## Requesting a token

```sh
curl -sS https://id.example.com/realms/main/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d client_id=deploy-job \
  -d assertion="$ACTIONS_ID_TOKEN" \
  -d resource=https://deploy.example.com -d scope=deploy:write
```

The assertion goes in `assertion`. It is never accepted as `client_assertion`
(client authentication), and a client assertion is never accepted as the
grant's assertion.

**Verification**, in order:

1. At most 16 KiB; a JWS signed with one of the supported algorithms
   (unsigned and encrypted tokens are refused); a `sub`.
2. The active trusts of this client for the assertion's `iss` (for SPIFFE
   without `iss`, the trust domain of `sub`) are tried in creation order; the
   first that accepts wins.
3. Per trust: the algorithm is one of the trust's; the key is found by `kid`
   (all keys when there is none; keys with a `use` other than `sig` are
   skipped) and the signature verifies; `exp` is present and not past (60 s
   clock skew); `iat` and `nbf` are not more than 60 s in the future; the
   lifetime is within the trust's maximum; `aud` contains the audience; the
   subject and claim constraints match; `jti` is present when required, at
   most 256 characters and not seen before by this trust.
4. The token request is checked as for `client_credentials` (resource,
   organization, scopes). Only a request accepted by all of these spends the
   `jti`: it is recorded in the transaction that issues the token, so an
   assertion whose request is refused for its resource, organization or
   scope can be retried with a corrected request, and of two concurrent
   requests with the same assertion exactly one gets a token (the other is
   refused as a replay, audited with reason `<trust id>: replayed jti`).

**Key sets** from `jwks_uri` are fetched under the federation egress rules:
`federation.allow_private_network` (refused in production),
`federation.egress_allowlist`, `federation.ca_file` (when `federation.enabled`),
`federation.fetch_timeout`, `federation.max_response_bytes`,
`privacy.residency.allowed_destinations` (checked when the trust is saved and
at every connection) and no redirects
([configuration.md](../operations/configuration.md#federation)). Each server
process caches a set for 5 minutes per URL, fetches again when an unknown
`kid` appears (at most once a minute), and keeps serving the last good set
while the issuer answers with a transport error or a non-`200` status. A
response that is too large, not JSON or empty is an error ("issuer keys
unavailable"), not a reason to use the cached set. Concurrent cold, expired
or unknown-key requests share one bounded fetch. Failed responses consume
the same one-minute retry budget; repeated assertions during an outage do
not repeatedly fetch. Cancellation stops one waiter without cancelling
other callers' shared fetch. The budget is per URL per server process
(NFR-006), so multiple processes can each fetch once.

**The token** is a `service_access` token for the client's service principal,
exactly as with `client_credentials`: one resource (`resource`, or the
scopes' resource, or the client's default; never the account or UserInfo
audience), the resource grant's scopes, `organization` for
organization-bound resources, DPoP or certificate binding when the request
carries them, no refresh token. Its lifetime is the usual one
([tokens.md](../protocols/tokens.md#access-token-lifetime)) and never longer
than the assertion's remaining lifetime. It is audited as `token.issued` with
`grant_type` `urn:ietf:params:oauth:grant-type:jwt-bearer`, `audience`,
`workload_trust_id`, `workload_issuer`, `workload_subject` and
`workload_profile`.

**Errors.** A refused assertion is `400 {"error": "invalid_grant",
"error_description": "the assertion was not accepted"}`; the reason is not
returned but audited as `workload.assertion.rejected` (category `token`,
metadata `reason`, for example `<trust id>: audience does not match`).
Without `assertion`: `400 invalid_request`. A client without a service
principal or without the grant: `400 unauthorized_client`. An inactive
service principal: `400 invalid_grant`. The per-client token budget applies
first. Discovery lists the grant in `grant_types_supported`.

## Limits

- A trust is per client. The same assertion can be used once per trust that
  accepts it: give overlapping trusts of one client distinct subjects.
- An assertion expired by less than the clock skew is refused without a
  `workload.assertion.rejected` event.
- Used `jti` values are kept until the assertion's expiry plus the clock
  skew; the worker's retention task deletes expired ones (step
  `workload_assertion_jtis`), and deleting a trust deletes its records.
- The emergency control for grant classes does not cover `jwt-bearer`;
  disable the trusts or the client instead.
- Trusts are not part of configuration-as-code documents or the realm data
  export (the client itself is).
- Tested only with tokens the test suite signs in the shape of GitHub Actions,
  Kubernetes and SPIFFE tokens, not against those platforms
  ([interoperability.md](interoperability.md#untested-claims)).

Threats and mitigations: [system threat model](../threat-models/system.md)
(public protocol endpoints; workers and outbound connections).
