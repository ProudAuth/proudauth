# Container registry token bridge

ProudAuth can act as the token server of a container registry that uses the
Distribution (Docker Registry v2) token authentication protocol (ADV-010).
`docker login` and `docker pull`/`push` then authenticate with ProudAuth
credentials, and each registry token lists exactly the repository actions the
principal's permissions allow. The bridge is optional: nothing is served
until an administrator configures a registry service.

Code: `internal/registry/registry.go`, `internal/httpapi/registry.go`,
migration `0082_registry_services`. Test: `TestRegistryTokenBridge`
(`tests/e2e/registry_test.go`), which drives the token endpoint directly. No
registry implementation (Distribution, Harbor, cloud registries) has been run
against it ([interoperability.md](interoperability.md#untested-claims)). The
test covers personal access tokens, API keys, machine-client secrets,
anonymous pulls and the failed-sign-in throttle.

`I` below is the realm issuer, `<server.public_origin>/realms/<realm>`.

## How it fits together

1. An administrator creates an **API resource** for the registry (for example
   audience `https://registry.example.com`) with the scopes `pull`, `push`
   and `delete`, and registers **permissions** for the actions (for example
   `images.pull`, `images.push`).
2. The administrator configures a **registry service** that names the
   registry's service name, the resource, and rules mapping repository
   patterns to those permissions.
3. Users create personal access tokens (or administrators API keys) for the
   registry's resource with the scopes they need; machine clients get a
   resource grant for it.
4. The registry sends clients to `I/registry/token`; ProudAuth authenticates
   them and issues a short-lived token for the registry's audience.

Credentials never reach the registry; it only sees registry tokens.

## Registry configuration

Configure the registry's token authentication with:

| Setting (Distribution names) | Value |
| --- | --- |
| `auth.token.realm` | `I/registry/token` |
| `auth.token.service` | The service name of the registry service in ProudAuth |
| `auth.token.issuer` | `I` |
| Verification keys | The realm's signing keys (`I/jwks`). Distribution 3 can read a JWK set from a file (`auth.token.jwks`): save the JWKS and refresh the file after every signing-key rotation. Registries that only accept a certificate bundle (`rootcertbundle`) need a certificate for the realm's signing key, which ProudAuth does not issue |

Check your registry's documentation for the exact configuration names of
your version.

## Registry services

| Method and path (under `/api/v1/realms/{realm}`) | Permission | Effect |
| --- | --- | --- |
| `GET /registry-services`, `GET /registry-services/{id}` | `realm.resources.read` | List (ordered by service name), one service (with `ETag`) |
| `POST /registry-services` | `realm.resources.write` | `201` |
| `PUT /registry-services/{id}` | `realm.resources.write` | Replaces the settings; `If-Match` optional (`412` when stale) |
| `DELETE /registry-services/{id}` | `realm.resources.write` | `204` |

```json
{"service": "registry.example.com", "audience": "https://registry.example.com",
 "token_ttl_seconds": 300,
 "rules": [
   {"repository": "public/*", "anonymous_pull": true},
   {"repository": "acme/*", "organization_id": "org_...", "pull": "images.pull", "push": "images.push"},
   {"repository": "*", "pull": "images.pull"}],
 "state": "active"}
```

| Member | Rules |
| --- | --- |
| `service` | The registry's service name and the token audience; no spaces or slashes, at most 255 characters, unique in the realm (`409`). It cannot change on `PUT` (`422`): configure a new service instead |
| `audience` | Audience of the API resource whose credentials the bridge accepts (`422` when no such resource exists). On `PUT`, omitted means unchanged |
| `token_ttl_seconds` | 60–3600, default 300 |
| `rules` | 1 to 200 rules, evaluated in order ([below](#rules)) |
| `state` | `active` (default) or `disabled`. A disabled service answers like an unknown one |

Audit (category `authorization`): `registry.service.created`, `.updated`,
`.deleted`.

### Rules

- `repository` is a pattern in Go `path.Match` syntax: `acme/*` matches
  `acme/app` but not `acme/team/app`; no spaces or colons. **The first rule
  whose pattern matches the repository applies**; later rules are not
  consulted for it.
- `pull`, `push`, `delete` name the permission each action requires; the
  permission must be registered in the realm (`422`). A rule must map at
  least one action or allow anonymous pulls.
- `organization_id`, when set, evaluates the permissions in that organization
  (the principal's roles there), and admits only credentials bound to that
  organization or to none. Without it, permissions are evaluated realm-wide,
  and credentials bound to an organization never match the rule.
- `anonymous_pull: true` grants `pull` to anyone, signed in or not.

## Token endpoint

`GET I/registry/token?service=<service>&scope=repository:<name>:<actions>`
(`scope` may repeat or hold several space-separated scopes; at most 50 are
considered). Each client address may request 600 tokens per minute, and
after 20 failed sign-ins within 15 minutes it is refused (`429`
`TOOMANYREQUESTS`, valid credentials included) until the window passes.
Credentials arrive as HTTP Basic:

| Password | Principal | Actions capped by |
| --- | --- | --- |
| A personal access token (`pa_pat_`) or API key minted for the registry's resource | The token's user or service principal, and its organization binding | The credential's scopes (`pull`, `push`, `delete`) |
| A machine client's secret, with the `client_id` as user name | The client's service principal (must be active) | The `allowed_scopes` of the client's resource grant to the registry's resource (the grant must allow subject type `service_principal`); without such a grant only anonymous actions |
| No `Authorization` header | Anonymous | Only `anonymous_pull` rules |

The Basic user name is ignored for personal access tokens and API keys, so
`docker login -u anything -p pa_pat_...` works. A personal access token or API
key for another resource is invalid here.

An action is granted when the first matching rule maps it to a permission the
principal holds (in the rule's organization, or realm-wide), and the
credential's scopes include the action; `pull` is also granted by
`anonymous_pull`. Only `repository` scopes are evaluated: other types (for
example `registry:catalog:*`) are dropped. Ungranted actions are left out of
the token, which is how the protocol denies; a request without scopes (the
`docker login` probe) gets a token with an empty access list.

Response (`Cache-Control: no-store`):

```json
{"token": "eyJ...", "access_token": "eyJ...", "expires_in": 300, "issued_at": "2026-10-11T09:00:00Z"}
```

The token is a JWT signed with the realm's active signing key (`kid` in the
header): `iss` = `I`, `aud` = the service name, `sub` = the user or service
principal ID (empty for anonymous callers), `iat`, `nbf` (30 seconds before
issuance), `exp` (`token_ttl_seconds` after issuance), `jti` and
`access: [{"type": "repository", "name": "...", "actions": [...]}]`.

Errors use the Distribution error format `{"errors": [{"code", "message"}]}`:

| Status | `code` | When |
| --- | --- | --- |
| 400 | `UNSUPPORTED` | Unknown or disabled `service` |
| 401 | `UNAUTHORIZED` | Invalid credentials; with `WWW-Authenticate: Basic realm="I"` |

Audit (category `token`): `registry.token.issued` (actor, service, the granted
`repository:actions` list) and `registry.token.denied` (invalid credentials;
the actor is recorded as anonymous).

## Security notes

- Registry tokens are short-lived bearer tokens for one registry audience.
  Revoking the personal access token, API key or client secret, or removing
  the permission, stops new tokens at once; tokens already issued stay valid
  until they expire (at most `token_ttl_seconds`). The registry does not call
  back to ProudAuth.
- The registry trusts every token the realm's signing keys sign with its
  service name as audience; keep service names distinct from other audiences.
- Every issued token, anonymous ones included, is audited as
  `registry.token.issued`; anonymous callers are recorded with an anonymous
  actor.

## Not supported

Repository catalog access (`registry:catalog:*`), the OAuth2 `POST` form of
the Distribution token endpoint and refresh tokens, per-tag rules, rules that
depend on anything other than repository name and organization, and issuing
certificates for registries that need a certificate bundle.
