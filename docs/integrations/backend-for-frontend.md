# Backend-for-frontend (BFF) integration

Requirements: §28.4, SDK-004, SES-009, OIDC-016. Reference code:
`proudauth-sdk-go/oidcclient` and `examples/backend-for-frontend` (exercised end to end by
`TestBackendForFrontendExample` and `TestOIDCClientValidationFixtures` in
`tests/e2e/bff_test.go`).

A BFF is a confidential client running next to your web front end. The browser
holds only an opaque, HttpOnly session cookie issued by the BFF; access and refresh
tokens stay on the server. This is the recommended pattern for browser
applications; a public browser client must never be given a secret.

## 1. Register the client

```json
POST /api/v1/realms/main/clients
{
  "client_id": "web-bff",
  "name": "Customer web BFF",
  "client_type": "confidential",
  "first_party": true,
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["https://app.example.com/callback"],
  "post_logout_redirect_uris": ["https://app.example.com/"],
  "backchannel_logout_uri": "https://app.example.com/backchannel-logout",
  "allow_offline_access": false,
  "allow_remember_me": true
}
```

The response contains `client_secret` once. Then grant the resources and scopes the
BFF may request:

```sh
identity-cli api PUT /clients/cli_.../resource-grants/res_orders '{"allowed_scopes":["orders:read"]}'
identity-cli api PUT /clients/cli_.../resource-grants/res_userinfo '{"allowed_scopes":["openid","profile","email"]}'
```

(`GET /resources` lists resource IDs; the UserInfo resource has `kind: userinfo`.)
`first_party: true` defaults consent to pre-authorized; third-party clients must use
`consent_mode: required`. The realm (or client) also needs a login UI URL for the
browser step ([headless-authentication.md](../protocols/headless-authentication.md)).

## 2. Configure the SDK

```go
c, err := oidcclient.New(oidcclient.Config{
    Issuer:       "https://id.example.com/realms/main", // discovery is fetched only from here
    ClientID:     "web-bff",
    ClientSecret: secret,                                // sent with HTTP Basic
    RedirectURI:  "https://app.example.com/callback",
    Scopes:       []string{"openid", "orders:read"},
    Resource:     "https://orders.example.com",          // audience of the access token
})
```

## 3. Login

```go
ar, err := c.AuthCodeURL(ctx, url.Values{"organization": {orgID}})
// Store ar (State, Nonce, PKCE Verifier) SERVER-SIDE, keyed by a random value in an
// HttpOnly, Secure cookie. Redirect the browser to ar.URL.
```

`AuthCodeURL` always adds `state`, `nonce` and an S256 PKCE challenge, and refuses
to let `extra` override them.

## 4. Callback

```go
tokens, idClaims, err := c.Exchange(ctx, ar, r.URL.Query())
```

`Exchange` checks:

- `state` equals the stored value (and the stored request is single-use in the
  example);
- the RFC 9207 `iss` parameter is present (the server advertises it) and equals the
  issuer — a mix-up defense;
- redeems the code with the PKCE verifier and client authentication;
- if `openid` was requested, an ID token is present and valid: signature from the
  issuer's JWKS, `typ` not `at+jwt`, exact issuer, audience contains the client,
  `azp` rules, `sub` present, not expired (30 s tolerance), not issued in the future,
  `nonce` matches, `at_hash` matches the access token.

Then create the browser session (an opaque random ID in a `Secure`, `HttpOnly`,
`SameSite=Lax` cookie) and store `c.NewSession(tokens)` server-side.

## 5. Calling APIs

```go
at, err := session.AccessToken(ctx) // refreshes once, serialized per session, when < 15 s remain
if errors.Is(err, oidcclient.ErrReauthenticate) { /* send the user to login */ }
req.Header.Set("Authorization", "Bearer "+at)
```

Refresh is serialized with a per-session mutex so concurrent browser requests never
present the same refresh token twice; the server would treat that as reuse, revoke
the family and log the user out (SES-009, TEST-030). A failed refresh drops the
tokens: the user must sign in again (there is no safe retry after a lost rotation
response). If a refreshed ID token arrives, it is validated and must have the same
subject.

To call a second API, either request a token for its audience by refreshing with
`resource=<audience>` (the audience must be part of the original grant) or use token
exchange from the first API ([resource-servers.md](resource-servers.md#5-calling-another-api-on-behalf-of-the-user)).

## 6. Logout

```go
_ = c.Revoke(ctx, tokens.RefreshToken)                        // RFC 7009; revokes the grant
u, _ := c.LogoutURL(ctx, idToken, "https://app.example.com/", state)
// delete the server-side session, clear the cookie, then send the browser to u
```

The logout URL carries `id_token_hint` and a registered `post_logout_redirect_uri`,
so the IdP ends its own session (single sign-out of the IdP session; other clients'
tokens remain valid until they expire or their back-channel logout is processed).

Protect the BFF's own state-changing routes against CSRF. The example checks
`Origin` on `POST /logout`; production code should also use anti-CSRF tokens for
other cookie-authenticated mutations (SEC-002).

## 7. Back-channel logout (recommended)

With `backchannel_logout_uri` registered, the worker POSTs
`logout_token=<JWT>` whenever an IdP session the BFF participated in is revoked
(logout elsewhere, administrator action, password reset, suspension). Validate the
logout token like an ID token, except `typ` must be `logout+jwt`: signature from the
JWKS, issuer, `aud` = your client ID, `iat`/`exp`, the
`http://schemas.openid.net/event/backchannel-logout` event, no `nonce`, and a
`jti` you have not seen. Then delete BFF sessions with that `sid` (or `sub`). The
SDK does not include a logout-token validator; the example BFF does not implement
this endpoint.

## Example limitations

`examples/backend-for-frontend` is a reference, not a production server: pending
logins and sessions are kept in process memory (lost on restart, not shared between
instances), there is no session expiry sweep, no back-channel logout handler, and
CSRF protection is limited to the `Origin` check on logout.
