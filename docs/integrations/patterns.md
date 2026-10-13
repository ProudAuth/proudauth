# Integration patterns

Requirements: INT-001..INT-010. Each section says what to do in your service
and which SDK function does the ProudAuth-specific part. Everything here
builds on [resource-servers.md](resource-servers.md): a valid token
authenticates a caller; your service still decides, per object, what that
caller may do. SDK names: Go `proudauth-sdk-go/verifier` (`verifier.`), Node.js
`@proudauth/sdk/verifier`, `/introspection` and `/bounded-state`
([sdk-compatibility.md](sdk-compatibility.md#framework-adapters-sdk-011)).

## HTTP APIs (INT-001)

- **Bearer tokens in the `Authorization` header only.** `verifier.BearerToken`
  and the Node.js adapters refuse `?access_token=` with `400
  invalid_request`, so tokens never land in access logs. DPoP-bound tokens
  (`cnf.jkt`) are not verified by the SDKs; verify the proof yourself if you
  require sender-constrained tokens.
- **401 vs 403 vs 404.** `401` with `WWW-Authenticate: Bearer` (adding
  `error="invalid_token"` for a bad token) when the caller is not
  authenticated; `403` (`error="insufficient_scope"` for a missing scope) when
  it is but may not act; `404` for an object of another organization, so its
  existence is not disclosed; `503` when the issuer's keys, introspection or
  revocation state are unavailable. Never fall back to "allow". The adapters
  produce the authentication cases; your handler produces the rest
  ([resource-servers.md](resource-servers.md#7-errors-to-return)).
- **Browser callers (CORS).** Answer `OPTIONS` preflights before the
  authentication adapter (they carry no token). Allow only your application's
  origins, never `*` together with credentials, and list `WWW-Authenticate` in
  `Access-Control-Expose-Headers` if the browser code reads it. Prefer a
  backend-for-frontend, which keeps tokens out of the browser altogether
  ([backend-for-frontend.md](backend-for-frontend.md)).

## GraphQL (INT-002)

Authenticate the HTTP request once (`verifier.Middleware`, `middleware`,
`fastifyHook`) and put the claims in the resolver context
(`verifier.FromContext`, `getClaims`). Then authorize **in each resolver
that returns or changes an object**, not only in the top-level query:

- check scopes and `claims.RequireOrganization(object.OrgID)` against the
  object loaded from your store, also for nested fields, connections and
  each item of a batched or aliased operation;
- apply list filters by organization in the data loader's query, not after
  loading;
- for role-based permissions, call `POST /authorization/check-batch` once per
  request with one check per object (at most `limits.max_batch_size`, 100 by
  default) instead of one call per field;
- bound query depth and cost: a permitted query must not be able to walk to
  objects the caller cannot reach directly.

## gRPC (INT-003)

- Read credentials from the `authorization` metadata key only:
  `verifier.AuthenticateMetadata(ctx, authenticator, md)` takes the incoming
  metadata map and requires exactly one `Bearer` value. Wrap it in a unary and
  a stream interceptor (the function's doc comment shows one) and store the
  claims with `verifier.WithClaims`.
- Keep a per-method table of required scopes or permissions and **deny methods
  that are missing from it**; check objects inside the method as for HTTP.
  Return `Unauthenticated` for authentication failures, `PermissionDenied` or
  `NotFound` for authorization failures and `Unavailable` when verification
  dependencies are down.
- **Streams outlive tokens.** A stream authenticated at open must end or be
  re-authorized when the token expires (`claims.Expiry`), and should stop when
  the session, user, organization or membership is revoked. See
  [long-lived streams](#long-lived-streams-int-005).

## WebSockets (INT-004)

- **No reusable tokens in URLs.** Query strings end up in proxy and access
  logs. Authenticate the upgrade request: from a backend-for-frontend's
  session cookie (same-site, checked `Origin`), or with the `Authorization`
  header where the client can send one (`AuthenticateMetadata` accepts the
  upgrade request's header map). If a browser client can do neither, exchange
  the session for a single-use, short-lived ticket of your own (seconds, bound
  to the user and the channel) and pass that, never the access token.
- Check `Origin` on the upgrade.
- Bind the connection to the subject, organization and scopes that were
  authorized, and **authorize every subscription and every message that acts
  on an object** against that binding; a connection is not a blanket grant.
- Apply the stream rules below.

## Long-lived streams (INT-005)

An initial handshake is not permanent access. For server-sent events, gRPC
streams, WebSockets and long polls:

- set a **maximum authorization age**: at the latest when the token used at
  open expires (`claims.Expiry`, a few minutes by default), require a fresh
  token on the connection or close it;
- **react to revocation** in between: with bounded-state verification,
  call `BoundedState.Check(claims)` (Node.js `state.check(claims)`) on a
  timer and close the stream on `ErrRevoked` or `ErrStateStale`; with
  strict-online validation, re-introspect on the same timer. The state is fed
  by ProudAuth's session-event stream (`GET /session-events`), whose own
  consumers are re-checked on every long poll and about every 2 seconds
  while one waits, so a consumer that loses its session or
  `realm.session_events.read` is cut off with `401` or `403` (TEST-062;
  [resource-servers.md](resource-servers.md#1-register-the-api));
- on renewal, compare the new token's `sub`, `org_id` and scopes with the
  binding; a different subject means a new connection.

No SDK helper enforces a maximum age; it is your timer.

## Background jobs (INT-006)

Do not store a user's access or refresh token as the job's authority. Store
the authorization decision instead:

| Store | Why |
| --- | --- |
| The action and its parameters, as approved | The job does only that |
| The initiating subject, and the actor if a support operator or service acted for them (`act`) | Attribution and re-checks |
| The organization | Tenant scope of everything the job touches |
| The approval (who, when), if your process needs one | Separation of duties |
| An expiry, and when to re-validate | Long or delayed jobs must not run on stale authority |

Run the job as a **service principal** of your own (client credentials,
[machine-clients.md](machine-clients.md)) limited to what jobs need. Before
acting, and again at checkpoints of long jobs, re-check that the initiating
subject still may: `POST /authorization/check` with
`"subject": {"type": "user", "id": "usr_..."}` instead of a subject token.
Naming a subject requires `realm.authorization.simulate` (a high-sensitivity
permission; grant it through a custom realm role to the job runner only), and
conditions that need session evidence (MFA, authentication age) fail closed
for such checks. ProudAuth's own jobs follow this pattern: a job records its
requester, and for audit and configuration exports, user imports and bulk user
operations the worker re-checks the permission the request needed when it
runs the job, and the download endpoint checks it again before handing out the
result ([exit-and-export.md](../operations/exit-and-export.md)).

## Message consumers (INT-007)

- **Authenticate the producer**, not the message: broker credentials or ACLs
  per producing service, or a token of the producer's service principal
  carried with the message and verified like any other.
- **A `user_id` in a message body is data, not authority.** It names whom the
  message is about; whether the producer may act for that user follows from
  the producer's identity and from records you trust (a job row as above),
  never from the body.
- ProudAuth's own webhooks are signed (HMAC over ID, timestamp and body);
  verify the signature and timestamp and deduplicate by `Webhook-Id`
  ([webhooks.md](webhooks.md)). Events are notifications, not revocation:
  stop access through the verification profile, not by waiting for an event.

## File and download grants (INT-008)

Links your service hands out for downloads are **your** grants, separate from
ProudAuth tokens: generate a random, single-use or short-lived secret, bind it
to the object and the user it was issued for, store only its digest, check
the binding at download, and keep it out of logs (put it in a path segment
you redact, or exchange it for a cookie). Never put a ProudAuth access token
in a URL.

ProudAuth's own exports work this way: `POST /jobs/{id}/downloads` returns a
`download_token` that is single-use, valid 5 minutes, bound to the job and
its requester (and, for users, to recent authentication), and it is redeemed
in the body of `POST /job-downloads`, not in a URL
([exit-and-export.md](../operations/exit-and-export.md)).

## Multi-issuer applications (INT-009)

An application that accepts tokens from several realms or deployments
registers each issuer explicitly and maps it to its own tenant:

```go
mi, err := verifier.NewMultiIssuer(map[string]verifier.IssuerRegistration{
    "https://id.example.com/realms/acme":   {Verifier: acmeVerifier, Tenant: "acme"},
    "https://id.example.com/realms/globex": {Verifier: globexVerifier, Tenant: "globex"},
})
tc, err := mi.VerifyTenant(ctx, raw) // tc.Tenant, tc.Subject, ...
```

Node.js: `new MultiIssuerVerifier({[issuer]: {verifier, tenant}})` and
`verifyTenant(raw)` → `{claims, tenant}`. Each registration's verifier must be
configured for exactly that issuer. The token's `iss` is read unverified only
to pick the registration; that verifier then checks everything, `iss`
included. A token from any other issuer fails (`ErrIssuer`,
`VerifierError('issuer')`) even when it is validly signed and its subject or
email matches a known user. **Key your records by (tenant, subject)**:
subjects are unique per issuer only, and emails are not identifiers. The
multi-issuer verifiers handle JWT access tokens; for introspection, route by
your own tenant routing to one `Introspector` per issuer.

## Contract validation before sensitive online authorization (INT-010)

Before a service accepts support (impersonation) tokens, or relies on online
validation for sensitive operations, test its integration for: actor
propagation (`act` kept in your audit), denial (protected operations, writes
without `allowlisted_write`, tokens of other audiences), expiry, failure
behavior (introspection or audit store down → deny) and revocation (a revoked
grant or session stops the next request). The reference implementation and
its tests are `examples/protected-orders-api` with `SupportGuard`, exercised
by `TestSupportImpersonation`, `TestImpersonationDenials` and
`TestRevocationConsistencyModes`; reuse their cases. There is no packaged test
kit for third-party services.

ProudAuth records the outcome on the resource, not in tokens:
`impersonation_policy.contract_version` names the support contract version
the service was validated against and is required when
`impersonation_enabled` is true (`422` on
`impersonation_policy.contract_version` otherwise);
`impersonation_policy.contract_validated_at` is a free-form note for when
that validation happened. The server checks neither value beyond the
presence of `contract_version`, so keep the evidence of the test run with
your change record. `SupportGuard.Validate()` only checks that an
introspector and an auditor are configured; it is not a contract test.

## Object-level authorization with relationships (AZ-021..AZ-023, AZ-027)

When access depends on the object (documents shared with a team, a project
board an editor was added to, files inherited from a folder), you can keep
those relationships in ProudAuth instead of your own tables
([relationship-authorization.md](relationship-authorization.md)):

1. **At deployment**, register your types once (`PUT /resource-types/{name}`):
   relations, `implied_by` (an `owner` is also an `editor`), links
   (`parent.viewer`) and which application permission each relation gives.
   Register those permissions first (`POST /permissions`).
2. **When objects change**, write the tuples in the same unit of work that
   creates, moves or shares the object
   (`POST /organizations/{org}/relationships`, up to 100 writes, atomic). Use
   an outbox or retry if your store and ProudAuth can disagree: a missing
   tuple denies, a stale one keeps access until removed. Remove tuples when an
   object is deleted; ProudAuth knows nothing about your objects' lifecycle.
3. **On each request**, call `/authorization/check` with `resource.type`,
   `resource.id` and the organization; enforce obligations as usual. Such
   decisions are never cacheable, so batch them (`/check-batch`) instead of
   caching.
4. **For lists**, call `/authorization/list-objects` and filter your query by
   the returned IDs (or skip the filter when `all` is `true`). Treat
   `truncated: true` as "there may be more": page with `next_cursor`, or
   narrow the query. The list applies no step-up, ABAC policies or hooks, so
   check an object again before acting on it.

Keep tenant checks in your service as before: tuples live in one
organization, and the decision still needs the organization from your own
data, never from the request.
