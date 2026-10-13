# Integrating a resource server (API)

Requirements: §14.4, §28.2, SDK-001, SDK-002, SDK-005, INT-010, §16. Reference
code: `proudauth-sdk-go/verifier`, `examples/protected-orders-api` (strict-online, support
contract, policy decisions) and `examples/protected-billing-api` (offline). Both
examples run in `tests/e2e/isolation_test.go` and `impersonation_test.go`.

A valid signature is not authorization. Your API must still check audience,
tenant, scopes and object ownership against its own data (§1.2, §15.2).

## 1. Register the API

Administrators register the API as a resource (admin API, `realm.resources.write`):

```sh
identity-cli api POST /resources '{
  "name": "Orders API",
  "audience": "https://orders.example.com",
  "verification_mode": "strict_online",
  "token_format": "jwt",
  "access_token_ttl_seconds": 300,
  "scopes": [{"name": "orders:read"}, {"name": "orders:write"}]
}'
```

- `audience`: a stable `https` URI or URN; it becomes the token's `aud`.
- `requires_organization` defaults to `true` for business resources: every token
  carries exactly one `org_id`.
- `verification_mode` (`offline`, `bounded_online`, `strict_online`) declares how
  you validate. The IdP enforces it only for support access (which requires
  `strict_online`) and for `token_format: opaque` (which cannot be `offline`).
  For `bounded_online`, the SDKs provide a bounded-state mode (`proudauth-sdk-go/verifier`
  `BoundedState` and `BoundedVerifier`; Node.js `@proudauth/sdk/bounded-state`;
  Dart `package:proudauth_sdk/bounded_state.dart`; PHP
  `ProudAuth\Sdk\BoundedState`; .NET `ProudAuth.Sdk.BoundedState`):
  tokens are verified locally and checked against session, subject, organization
  and membership revocations replayed from the session-event stream
  (`GET /api/v1/realms/{realm}/session-events`, which needs an admin-audience
  service token with `realm.session_events.read`). When the replayed state is
  older than `MaxStaleness`, every check fails closed (`ErrStateStale`); it never
  falls back to offline acceptance. Revocations before `Start` are not replayed
  (`TestBoundedStateVerification`). In Go, `Sync` before a successful `Start`
  returns `ErrNotStarted` (there is no stream position yet), and `Run` calls
  `Start` itself when needed. The Node.js `BoundedState` has no such guard:
  call `start()` before `run(signal)` or `sync(waitSeconds, signal)`, which
  otherwise read the stream from its oldest retained event.
  - `Start` / `start()` moves the position to "now" and keeps the revocations
    already replayed (the stream has no snapshot that could supersede them).
    It also counts as fresh, so events between the old position and now are
    skipped: restart only when you accept that gap.
  - The state counts as fresh for `MaxStaleness` only after a sync has read
    to the end of the stream (a page of fewer than 500 events).
  - The stream keeps 7 days of history. A cursor expires only when stream
    events after it were pruned, so a caught-up consumer on a quiet realm
    keeps its cursor when its last event ages out (realms pruned before
    migration `0046` keep the older rule until their next pruning).
  - A `410 cursor_expired` (events after the cursor were pruned) rewinds the
    position to the beginning of the retained history (an empty cursor) and
    returns Go `ErrCursorExpired` / Node.js `CursorExpiredError` (code
    `unavailable`); `Run` / `run()` replays that history at once (once in a
    row; a second `410` in a row backs off) and keeps following the stream. A
    revocation time only moves forward, so a replay never weakens the state.
    The `410` problem's `title` says what to do: "Events after the cursor are
    no longer retained. Resynchronize by reading the retained history from its
    beginning (no cursor)."
  - `authorization.role.unassigned` and `security.refresh_reuse_detected` name
    the affected user in `data.subject_id`; every SDK reads it there and act
    only on user subjects (`usr_...`): a refresh-token reuse revokes the user,
    and a role unassignment revokes the user's membership in the event's
    `organization_id` (`TestBoundedStateSubjectIDEvents`).
  - The server accepts `wait` of 0–25 seconds (`422` above). Go `Sync` and
    Node.js `sync` send at most 25 seconds, whatever they are given.
  - `user.recovery_restricted` is not a revocation: the server keeps those
    sessions valid.
  - In Node.js, aborting the `signal` given to `run()` stops an in-flight long
    poll and a backoff wait at once.
- Clients may request your scopes only after an administrator grants them
  (`PUT /clients/{client}/resource-grants/{resource}`).

For online validation, give your API its own confidential client (type `machine`
with a service principal, or `confidential`) and register it as an introspector:

```sh
identity-cli api POST /resources/res_.../introspectors '{"client": "cli_..."}'
```

An introspector learns about tokens for its own audiences only; for any other
token it receives `{"active": false}`.

## 2. Choose a validation mode

| Mode | Use | Revocation exposure |
| --- | --- | --- |
| Offline (`verifier.Verifier`) | Low-risk reads, high request rates | Until token expiry + clock skew (default ≈ 5.5 min) |
| Strict-online (`verifier.Introspector`) | Administration, money movement, anything that must stop on revocation | Next request after the revocation commits; IdP outage → deny |
| Support access (`verifier.SupportGuard`) | Required for impersonation | Next request; IdP outage → deny |

Document per operation which mode you use (§28.2). Details:
[docs/operations/revocation-exposure.md](../operations/revocation-exposure.md).

### Offline

```go
v, err := verifier.New(verifier.Config{
    Issuer:   "https://id.example.com/realms/main", // exact; tokens from other issuers fail before any fetch
    Audience: "https://billing.example.com",
    // Algorithms default to RS256, PS256, ES256, EdDSA; HS* and none are refused.
    // ClockSkew defaults to 30s (max 60s). JWKSURL defaults to Issuer + "/jwks".
})
if err != nil { log.Fatal(err) }
http.Handle("/invoices", verifier.Middleware(v, invoicesHandler))
```

`Middleware` answers `401` with `WWW-Authenticate: Bearer error="invalid_token"`
on any verification failure and `503` when the JWKS cannot be fetched. Tokens are
read from the `Authorization` header only; `?access_token=` is refused.

The verifier caches the JWKS and re-fetches it only when it meets an unknown `kid`,
at most once per `MinRefreshInterval` (30 s), coalescing concurrent requests. It
has no time-based refresh, so after an **emergency key rotation** restart your
service or make it fetch again ([keys.md](../operations/keys.md#emergency-rotation)).

### Strict-online

```go
in := &verifier.Introspector{
    Endpoint: "https://id.example.com/realms/main/oauth/introspect",
    ClientID: "orders-rs", ClientSecret: secret,
    Issuer:   "https://id.example.com/realms/main",
    Audience: "https://orders.example.com",
    Timeout:  3 * time.Second,
}
claims, err := in.Authenticate(ctx, rawToken)
switch {
case errors.Is(err, verifier.ErrUnavailable): // IdP unreachable: fail closed with 503
case err != nil:                               // inactive, wrong issuer/audience/kind: 401
}
```

There is no positive cache, and failures never fall back to offline checks.
`AcceptedKinds` defaults to `user_access`, `service_access`, `exchange_access`,
`api_key`, `personal_access` (Go `verifier.DefaultOnlineKindList()`, a copy;
Node.js `DEFAULT_ONLINE_KINDS`); support tokens are rejected unless routed through
`SupportGuard`.

## 3. Authorize every request

After authentication (§28.2 checklist):

1. **Tenant**: load the object from your own store and call
   `claims.RequireOrganization(object.OrgID)`. Never take the organization from a
   header, path or body as authority. Return `404` for another tenant's objects to
   avoid disclosing existence (TEST-007, TEST-008).
2. **Scopes**: `claims.RequireScope("orders:read")`.
3. **Lists**: filter by `claims.OrgID` in the query; never return foreign rows for
   the client to hide.
4. **Ownership and business rules**: your data.
5. **Permissions** that depend on roles: call the policy decision API (below), or
   keep your own policy. Tokens carry scopes, not roles.
6. **Kind**: reject token kinds you do not support (machine tokens on user-only
   routes, `exchange_access` where no delegation is expected). Tokens of agent
   service principals carry `agent: true`, and tokens an agent obtained by
   exchange carry `act.agent: true` (MCH-017,
   [machine-clients.md](machine-clients.md#agents)); decide whether your API
   accepts them for an operation.
7. **Assurance**: for sensitive actions check `claims.ACR` / `claims.AuthTime`, or rely
   on the decision API's step-up obligation.
8. **Sender constraint**: honor `cnf` ([below](#sender-constrained-tokens)).

### Sender-constrained tokens

A token with `cnf` may only be used by its holder (TOK-019):

- `cnf.jkt` (DPoP, RFC 9449): require the `DPoP` scheme and verify the proof
  for your request (method, URL, `ath`, key thumbprint and single-use JTI).
- `cnf["x5t#S256"]` (mutual TLS, RFC 8705): require that the request arrived
  with a TLS client certificate whose SHA-256 thumbprint (base64url of the DER
  certificate) equals it; behind a TLS-terminating proxy, have the proxy pass
  the certificate to you.

Introspection returns `cnf` for JWT and opaque tokens. All five SDKs refuse
tokens containing `cnf` through their ordinary token-only verification and
introspection methods (`sender_constraint`), including unknown or malformed
bindings. They cannot authenticate the sender without the request.

The Go SDK supplies `SenderVerifier` for request-level verification with
either the offline `Verifier` or strict-online `Introspector`. Its returned
`Claims.Confirmation` contains the binding that it has enforced. Node.js,
Dart, PHP and .NET currently reject bound tokens; request-level proof verification
is not implemented in those SDKs. The IdP's own APIs and UserInfo also enforce
both bindings ([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#mutual-tls-rfc-8705)).

```go
// v is a Verifier pinned to your issuer and API audience.
// This store is appropriate for ONE resource-server process only.
replay, err := verifier.NewMemoryProofReplayStore(10000)
if err != nil { log.Fatal(err) }
sender, err := verifier.NewSenderVerifier(verifier.SenderConfig{
    Offline: v, // alternatively Online: an authenticated Introspector
    PublicOrigin: "https://api.example.com",
    Replay: replay,
    RequireBinding: true, // omit to also permit ordinary bearer tokens
})
if err != nil { log.Fatal(err) }
handler := verifier.Middleware(sender, businessHandler)
// Serve handler over TLS with ClientAuth: tls.RequestClientCert (or a
// stricter client-certificate policy) when accepting certificate bindings.
```

This profile implements [RFC 9449 §§4.3 and 7](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3)
and [RFC 8705 §3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3):
DPoP proof signatures use RS256/PS256 with RSA keys of at least 2048 bits,
ES256/P-256 or EdDSA/Ed25519; proofs are at most 4096 bytes, at most two
minutes old and at most 30 seconds in the future, with JTIs of 1–128 bytes.
The method matches exactly, the URL excludes query/fragment, and both the
access-token hash and bound key thumbprint must match. Duplicate JSON members,
ambiguous headers, private JWKs, unsupported critical headers and replay are
refused. Nonces are not issued by this resource profile.

Every instance of an API behind a load balancer must use the **same atomic
`ProofReplayStore`**, with a deployment-specific namespace. Store outages deny
requests; a full memory store returns `ErrUnavailable` instead of evicting
unexpired entries. The store receives only a SHA-256 digest of the binding
and JTI and an expiry, and must reserve that digest once until expiry. No
positive introspection result is cached.

`PublicOrigin` is configuration, never a request `Host` or forwarded header.
Use ASCII hostnames (punycode/A-labels for internationalized domains).
The public path must reach the handler without rewriting. Direct requests
need TLS. A plaintext backend hop requires an explicit `IsTrustedTLSProxy`
callback that authenticates the TLS-terminating proxy through a protected
deployment boundary; `X-Forwarded-Proto` alone grants no trust. For forwarded
client certificates, the optional `ClientCertificate` callback must check
that same proxy boundary and obtain its authenticated handshake evidence;
untrusted certificate headers are ignored by default. TLS binding verifies
possession and the token's leaf-certificate digest, and does not replace your
deployment's certificate trust policy. Unknown or combined `cnf` methods are
refused. Token-only and metadata calls to `SenderVerifier` fail closed.

`TestResourceSenderVerifier` exercises a separate TLS API with actual ProudAuth
JWT/opaque DPoP tokens and certificate-bound JWTs, including missing/wrong
proofs and replay. Unit tests cover all four algorithms, concurrent one-use
reservation, store failure/capacity, time/URL/hash/key mismatches and spoofed
proxy headers (TEST-067).

## 4. Policy decisions (optional)

`POST /api/v1/realms/{realm}/authorization/check` evaluates the subject's current
permissions. The caller needs an admin-audience token with permission
`realm.authorization.check` (built-in role `resource-server` assigned to your
service principal, and a client resource grant for the `<issuer>/admin` audience
with scope `proudauth:admin`):

```json
POST /api/v1/realms/main/authorization/check
{ "subject_token": "<the caller's access token>",
  "action": "orders.refund",
  "resource": { "type": "order", "id": "ord_123", "org_id": "org_01k7..." },
  "context": { "operation_amount_minor": 1500 } }
```

```json
{ "decision_id": "dec_...", "allowed": false, "reason_code": "STEP_UP_REQUIRED",
  "policy_version": "realm-policy-3",
  "obligations": [{ "type": "reauthenticate", "required_profile": "mfa", "max_age_seconds": 300 }],
  "cache_ttl_seconds": 0 }
```

- `subject_token` is introspected with your client's introspection rights, so it
  must be a token for one of your audiences.
- Take `org_id` and amounts from your data, not from the browser.
- **Projects.** When the resource belongs to a project, send its
  `resource.project_id` (from your data, like `org_id`): the subject's roles
  assigned at that project's scope are then evaluated as well as realm and
  organization roles, and only for that project. The project must exist
  (`UNKNOWN_PROJECT` otherwise) and, when there is an organization
  (`resource.org_id` or the token's `org_id`), belong to it: owned by it or
  shared with it through an active project grant
  (`PROJECT_ORGANIZATION_MISMATCH` otherwise). Without `project_id`, project
  roles never count. Scopes of a project's resources that set
  `required_permissions` are granted at token issuance the same way.
- **Obligations are mandatory.** If you cannot enforce one, deny
  (`examples/protected-orders-api` treats any obligation as a denial).
- Batch: `POST /authorization/check-batch {"checks": [...]}` (≤ 100).
- Reason codes include `ALLOWED`, `NOT_PERMITTED`, `STEP_UP_REQUIRED`,
  `ORGANIZATION_MISMATCH`, `UNKNOWN_PROJECT`, `PROJECT_ORGANIZATION_MISMATCH`,
  `SUBJECT_TOKEN_INACTIVE`, `INVALID_REQUEST`,
  `EVALUATION_ERROR`, `SUPPORT_ACCESS_FORBIDDEN_ACTION`, `SUPPORT_ACCESS_READ_ONLY`,
  `SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED` (support tokens: see
  [section 6](#6-support-access-contract)), and in realms with an external
  policy engine `EXTERNAL_POLICY_DENIED` (or the engine's own reason code) and
  `EXTERNAL_POLICY_UNAVAILABLE` ([policy-engines.md](policy-engines.md)).
- A subject whose account is not active (suspended, locked, pending
  verification or deletion, deleted) or whose service principal is disabled or
  deleted holds no permissions: such decisions are denials.
- **Objects.** When the action depends on the object (who owns, edits or was
  given it), register a resource type and write relationship tuples; the
  decision then also evaluates the object named in `resource.type` and
  `resource.id`, and `POST /authorization/list-objects` returns the objects a
  subject may act on ([relationship-authorization.md](relationship-authorization.md)).
  Decisions that consulted relationships or an external engine are never
  cacheable (`cache_ttl_seconds: 0`).

## 5. Calling another API on behalf of the user

Use token exchange, not token forwarding. The administrator grants your client the
target resource with an exchange policy:

```json
PUT /clients/{client}/resource-grants/{billing-resource}
{ "allowed_scopes": ["billing:read"], "subject_types": ["user", "service_principal"],
  "exchange_policy": { "accept_from_audiences": ["https://orders.example.com"] } }
```

Then exchange the incoming token at the token endpoint
(`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token=<incoming>`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
`resource=https://billing.example.com`). The result names the user as `sub`, your
service as `act.sub`, keeps the organization, and never outlives the incoming token
([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#token-exchange-rfc-8693)).
The downstream API must check `act` if it treats delegated calls differently.

## 6. Support-access contract

A resource may accept support (impersonation) tokens only if it implements this
contract; otherwise leave `impersonation_enabled` off and those tokens are
rejected by the default introspector settings (TEST-045).

Registration (`PUT` replaces the whole resource definition, so send every
member you want to keep):

```json
PUT /resources/{resource}   (with If-Match)
{ "name": "Orders API", "verification_mode": "strict_online", "impersonation_enabled": true,
  "impersonation_policy": {
    "allowed_scopes": ["orders:read"],
    "write_scopes": ["orders:write"],
    "write_actions": ["orders.annotate"],
    "support_client_ids": ["support-bff"],
    "contract_version": "support-contract-1" } }
```

`impersonation_enabled: true` requires `verification_mode: strict_online` and
a non-empty `impersonation_policy.contract_version` (`422` otherwise, INT-010):
the version of the support contract your service was tested against. An
optional free-form `impersonation_policy.contract_validated_at` records when;
ProudAuth stores both but checks neither further. Run the contract cases
first ([patterns.md](patterns.md#contract-validation-before-sensitive-online-authorization-int-010)).

Implementation with `verifier.SupportGuard`:

```go
guard := &verifier.SupportGuard{
    Introspector:    introspector,                  // Issuer and Audience are required
    Auditor:         myAuditStore,                  // persists verifier.SupportEvent; errors deny access
    WriteOperations: []string{"orders.annotate"},   // only in allowlisted_write mode
}
if err := guard.Validate(); err != nil { log.Fatal(err) } // refuse to start without the contract
// Route support tokens (prefix "pa_it_") to the guard on every request:
claims, err := guard.Authorize(ctx, raw, "orders.read", true /* read-only operation */)
```

What the guard enforces per request:

- online introspection; the token must be `impersonation_access` with an actor
  (`act.sub`) and a grant ID;
- protected operations are always denied (IMP-012, IMP-013). The entries are
  `password.change`, `password.reset`, `mfa.change`, `identifier.change`,
  `account.link`, `credential.export`, `api_key.create`,
  `personal_token.create`, `consent.modify`, `idp.admin`, `payment`, `refund`,
  `ownership.transfer`, `secret.read`, `secret`, `delete` and `purge`
  (Go `verifier.ProtectedOperationList()`, which returns a copy; Node.js
  `PROTECTED_OPERATIONS`, frozen; add your own with
  `SupportGuard.ProtectedOperations` / `protectedOperations`). The operation name is
  trimmed, lowercased, `-` is read as `_`, and it is split into segments on
  `.`, `:` and `/`; an entry matches when its segments occur as a contiguous
  run anywhere in the name, with or without a trailing `s`. So
  `payments.create`, `refunds.issue`, `secrets.read`, `users.password.change`
  and `orders.purge` are protected, `secretary.list` is not, and an empty
  operation is protected;
- an operation is a write when any segment is a write verb (`create`,
  `update`, `delete`, `cancel`, `issue`, `approve`, `send`, ...;
  Go `verifier.WriteSegmentList()`, Node.js `WRITE_SEGMENTS`; test one with
  `IsWriteOperation` / `isWriteOperation`), even when the caller passes
  `read = true`;
- writes are denied unless the grant is `allowlisted_write` and the whole
  operation name is in `WriteOperations` (case-insensitive);
- a `SupportEvent` (grant, actor, subject, organization, operation, allowed, time) is
  recorded **before** access; if recording fails, access is denied.

All five SDKs and the server run the same cases from
`tests/fixtures/sdk-contracts/support-operations/cases.json`
([tests/fixtures/sdk-contracts/README.md](../../tests/fixtures/sdk-contracts/README.md#support-operationscasesjson)),
and the decision API applies the same rule to support tokens passed as
`subject_token` (`internal/authorization/catalog.go`):

- a protected action is denied with `SUPPORT_ACCESS_FORBIDDEN_ACTION`;
- an action is a read only when it ends in `.read`, `.list`, `.view`, `.get` or
  `.search` and has no write-verb segment; any other action is a write;
- a write by a `read_only` grant is denied with `SUPPORT_ACCESS_READ_ONLY`;
- a write by an `allowlisted_write` grant is allowed only when the action is
  listed, whole and case-insensitively, in `impersonation_policy.write_actions`
  of the resource the support token was issued for; otherwise it is denied
  with `SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED`. Without `write_actions` the
  decision API allows no support writes. Keep `write_actions` equal to your
  guard's `WriteOperations`.

What remains your responsibility:

- tenant and ownership checks as for any token (the token's `sub` is the customer);
- show a support indicator and keep actor and subject in your own logs (IMP-006,
  IMP-021);
- the support scope is the resource's allowed scopes, **not** intersected with the
  customer's own permissions by the IdP; call the decision API with the support
  token as `subject_token` (it evaluates the customer's permissions and applies the
  read-only rule) or apply your own permission check (IMP-007);
- never treat an `act` claim in some other token as support authority.

Handoff into a support UI: the support backend obtains a single-use code
(`POST /impersonation-grants/{id}/handoffs {"destination_client_id": "..."}`), and the
destination's backend redeems it within 30 s at
`POST /api/v1/realms/{realm}/impersonation-handoffs/redeem` (form `handoff_code`,
client authentication) to receive its own support token. Never put a support token
in a URL.

## 7. Errors to return

| Situation | Status |
| --- | --- |
| Missing, malformed, expired, wrong audience/issuer/kind, inactive | `401` with `WWW-Authenticate: Bearer error="invalid_token"` |
| Authenticated but missing scope/permission, support policy denial | `403` |
| Object in another tenant | `404` |
| IdP or JWKS unavailable in strict-online mode | `503` (never allow) |

## Not provided

- Request-level DPoP or client-certificate verification in Node.js, Dart,
  PHP and .NET. Their ordinary verifier/introspection paths reject `cnf` tokens. Use
  the Go `SenderVerifier` or a separately reviewed resource implementation
  for bound tokens ([Sender-constrained tokens](#sender-constrained-tokens)).
- Framework adapters other than the Go `net/http` middleware and
  `AuthenticateMetadata` (gRPC metadata, WebSocket upgrade and message
  headers), the Node.js Express/Connect `middleware`, `node:http`
  `protect` and Fastify `fastifyHook` helpers, the Dart `authorizeBearer`
  function and `dart:io` `protect`, and the PHP `RequestAuthenticator`
  (with a PSR-15 example in its README)
  ([sdk-compatibility.md](sdk-compatibility.md#framework-adapters-sdk-011)).
  Patterns for GraphQL, gRPC, WebSockets, streams, jobs and multi-issuer
  services are in [patterns.md](patterns.md).
