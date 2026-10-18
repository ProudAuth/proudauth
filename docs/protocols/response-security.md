# Signed and encrypted responses

Requirements: TOK-020 (encrypted ID tokens), OIDC-013 (signed and encrypted
UserInfo), ADV-002 (JARM, JWT-secured authorization responses). Code:
`internal/application/protocol_options.go`, `internal/oauth/jwe.go`,
`internal/oauth/jarm.go`, `internal/oauth/mint.go`,
`internal/oauth/discovery.go`, migration `0050`. Tests:
`TestEncryptedResponses` and `TestJARM` (`tests/e2e/jwe_test.go`),
`TestLogoutHintTypes` (`tests/e2e/logout_hint_test.go`),
`TestConfigClientProtocolOptions` (`tests/e2e/ops_test.go`).

By default ID tokens are signed JWTs, UserInfo is plain JSON and the
authorization response is a set of query parameters. A client can ask for
more, per client:

- an **encrypted ID token** (nested JWT: signed, then encrypted to the client);
- a **signed and/or encrypted UserInfo** response (`application/jwt`);
- a **JWT-secured authorization response** (JARM): the redirect carries one
  signed (optionally encrypted) `response` parameter instead of `code` and
  `state`.

Encryption keeps the content from the browser, proxies and logs on the way;
it is not a substitute for validating the signature, issuer, audience and
nonce of what is inside.

## Client options

Set on the client (`POST` or `PUT /api/v1/realms/{realm}/clients/...`, the
configuration document's clients, or [dynamic registration](../integrations/dynamic-client-registration.md)).
They are stored together in `clients.protocol_options` and appear in the
client view only when set.

| Option | Values |
| --- | --- |
| `id_token_encrypted_response_alg` | `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` |
| `id_token_encrypted_response_enc` | `A128GCM` or `A256GCM`; required with the `alg` |
| `userinfo_signed_response_alg` | The realm's signing algorithm (`keys.signing_algorithm`: `RS256`, `PS256`, `ES256` or `EdDSA`) |
| `userinfo_encrypted_response_alg`, `userinfo_encrypted_response_enc` | As for ID tokens |
| `authorization_signed_response_alg` | The realm's signing algorithm (JARM) |
| `authorization_encrypted_response_alg`, `authorization_encrypted_response_enc` | As for ID tokens (JARM) |

Validation (`422 validation_failed`, field named in `errors`):

- an `_enc` without its `_alg` ("requires <name>_alg");
- another key-management algorithm: `RSA1_5`, `RSA-OAEP` (SHA-1) and the
  direct and AES key-wrap modes are not offered;
- an `_alg` without `_enc`, or another content encryption: the specification
  default `A128CBC-HS256` is not offered, so `_enc` is always explicit;
- a signing algorithm other than the realm's ("must be the realm's signing
  algorithm (<alg>)").

Responses are always signed with the realm's active key. The registered
signing value is only checked when the client is saved: if the realm's
algorithm changes later, responses are signed with the new algorithm and the
next update of such a client fails until the value is changed. Plan an
algorithm change with these clients ([keys.md](../operations/keys.md)).

## Encryption keys

ProudAuth encrypts to the client's own registered public keys
(`POST /clients/{client}/credentials {"jwks": {...}}`, the same keys used for
`private_key_jwt`; dynamic registration's inline `jwks`). `jwks_uri` is not
supported. For each response it takes the newest active key that fits:

- an RSA key for `RSA-OAEP-256`, an EC key for the `ECDH-ES` algorithms
  (OKP keys are never used);
- a key with `use: enc` is preferred over a key without `use`; a key with
  `use: sig` is never used;
- a key that names an `alg` must name the requested one.

Keys registered in one call share a creation time, so register one
encryption key per key type. The JWE header carries `alg`, `enc`, `typ:
JWT`, `cty: JWT` (only for nested tokens; an encrypt-only UserInfo response
has no `cty`) and the `kid` of the recipient key when it has one (and `epk`
for ECDH-ES).

No key is checked at registration. When no key fits at issuance:

- token endpoint: `400 {"error": "unauthorized_client", "error_description":
  "the client has no registered public key for the requested response
  encryption"}`. This is a configuration problem, not a use of the
  credential: the issuance is rolled back, so the authorization code (or
  device code, or refresh token) is not consumed. Presenting it again before
  a key is registered gets the same answer, never code-replay handling, and
  the grant stays intact; after the key is registered the same code can be
  redeemed while it is still valid (60 s). The same applies when the realm
  has no active signing key (`503 temporarily_unavailable`);
- UserInfo: `400 {"error": "invalid_request", ...}` with the same description.

## Encrypted ID tokens

With `id_token_encrypted_response_alg`, every ID token issued to the client
(authorization code and refresh grants with `openid`) is a nested JWT: the
usual signed ID token ([tokens.md](tokens.md#id-token-claims)), encrypted as
a compact JWE (five segments). Decrypt it, then validate the inner token as
always. Send the **inner, signed** token as `id_token_hint` at the logout
endpoint; ProudAuth does not accept encrypted hints.

## Signed and encrypted UserInfo

For a client with `userinfo_signed_response_alg` or
`userinfo_encrypted_response_alg`, `GET`/`POST I/oidc/userinfo` answers
`Content-Type: application/jwt`:

| Options | Body |
| --- | --- |
| Signed | JWS (`typ: userinfo+jwt`) with the usual claims plus `iss` (the realm issuer) and `aud` (the client ID); no `iat` or `exp` |
| Encrypted | JWE whose payload is the plain JSON claims (no `iss` or `aud` added). Its header has no `cty` |
| Both | Nested: the signed JWS, encrypted (`cty: JWT`) |

Clients without these options keep getting `application/json`. The signed
response has its own `typ` so it is never taken for an ID token, for example
as `id_token_hint` at logout (decision 15); before 0.2.0-alpha.6 it was typed
`JWT`.

## JARM (ADV-002)

Ask for it per request with `response_mode`:

| `response_mode` | Response |
| --- | --- |
| absent or `query` | `code`, `state`, `iss` as query parameters |
| `query.jwt`, or `jwt` (the same for the code flow) | One query parameter `response` |

It is accepted at `I/oauth/authorize`, in pushed authorization requests
(stored with the request) and in the headless start
(`POST /api/v1/realms/{realm}/auth/transactions` with the body member
`response_mode`). `fragment`, `fragment.jwt`, `form_post` and
`form_post.jwt` are refused ("unsupported response_mode: query, query.jwt or
jwt", `invalid_request`): at the authorization endpoint as an error redirect
in plain query mode, at PAR as `400` JSON, at the headless start as a `400`
problem.

`response` is a JWT signed with the realm's active key (`typ:
oauth-authz-resp+jwt`; `JWT` before 0.2.0-alpha.6) with:

- `iss` (the realm issuer), `aud` (the client ID), `exp` (10 minutes);
- the response parameters: `code` and `state` (plus `session_state` where the
  realm enables session checks), or `error`, `error_description` (for
  authorization-request validation errors) and `state`.

With `authorization_encrypted_response_alg` it is then encrypted to the
client (nested, `cty: JWT`). Validate it like any JWT from the issuer:
signature against the JWKS, `typ` `oauth-authz-resp+jwt`, `iss`, `aud` equal
to your client ID, `exp`, then compare `state`.

Anyone who knows a client ID and one of its redirect URIs can get a signed
error response from the authorization endpoint (an invalid request is enough).
Its own `typ` and the ID-token checks of the logout endpoint keep it from
passing as an `id_token_hint`; before 0.2.0-alpha.6 it was typed `JWT`, and a
lured `GET` to the logout endpoint with such a response as hint ended the
browser's session ([oauth-oidc-profile.md](oauth-oidc-profile.md#logout),
`TestLogoutHintTypes`).

Errors returned to the redirect URI use the same mode: validation errors
once the client and redirect URI are trusted, `prompt=none` failures
(`login_required`, `consent_required`, `interaction_required`,
`account_selection_required`), and cancelled or failed transactions
(`access_denied`). Errors detected before the redirect URI is validated are
still answered as JSON, never redirected. When the JWT cannot be produced at
the authorization endpoint (for example no encryption key fits), the client
gets a plain `error=server_error` redirect with `state` and `iss` rather than
no answer; at the completion of a transaction the completion fails instead,
and a cancelled or failed transaction then has no `redirect_to`.

An organization switch (`POST /me/organization-grants`) still answers with a
plain query redirect.

## Discovery

| Member | Value |
| --- | --- |
| `response_modes_supported` | `["query", "query.jwt", "jwt"]` |
| `authorization_signing_alg_values_supported` | Algorithms of the published keys |
| `id_token_encryption_alg_values_supported`, `userinfo_encryption_alg_values_supported`, `authorization_encryption_alg_values_supported` | `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` |
| `id_token_encryption_enc_values_supported`, `userinfo_encryption_enc_values_supported`, `authorization_encryption_enc_values_supported` | `A128GCM`, `A256GCM` |
| `userinfo_signing_alg_values_supported` | `"none"` followed by the algorithms of the published keys |

## Not supported

Signed request objects (JAR, the `request` parameter) and request object
encryption; `jwks_uri` for client keys; `A128CBC-HS256` and other
CBC-HMAC content encryption; `RSA1_5` and `RSA-OAEP` with SHA-1;
`fragment.jwt`, `form_post` and `form_post.jwt`; signing responses with an
algorithm other than the realm's.

Tests cover the 422 cases, discovery, an RSA-encrypted ID token, ECDH-ES
nested UserInfo, encrypt-only UserInfo (no `cty`), a client with only a
signing key (token endpoint `400`, the code not consumed and redeemed once a
key is registered), JARM in the headless flow (signed, and encrypted on
cancel), the `typ` of each response, and a JARM error response from the
browser authorization endpoint and a signed UserInfo response refused as
logout hints (`TestLogoutHintTypes`). Not covered: a JARM code response
through the browser authorization endpoint and PAR, `prompt=none` errors in
JARM mode, the `server_error` fallback and the UserInfo `400`.
