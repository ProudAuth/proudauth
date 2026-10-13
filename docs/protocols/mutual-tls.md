# Mutual TLS and X.509 certificates

Requirements: TOK-019 (certificate-bound tokens), MCH-014 (mutual-TLS client
authentication, RFC 8705), PROV-016 (X.509 sign-in). Code:
`internal/certauth`, `internal/httpapi/certificates.go`,
`internal/httpapi/clientcert.go`, `internal/authentication/certificate.go`,
`internal/application/clientauth.go`, `cmd/identity-server/main.go`
(listener), migrations `0056` and `0086`. Tests: `TestMutualTLS` and
`TestCertificateSignIn` (`tests/e2e/mtls_test.go`); revocation and CRL
ordering in `internal/certauth/certauth_test.go`.

Certificates are used in three ways:

1. **Client authentication** at the token, introspection, revocation, PAR and
   device endpoints (`tls_client_auth`, `self_signed_tls_client_auth`).
2. **Certificate-bound access tokens**: a token carries the thumbprint of the
   client's certificate and is usable only on a connection presenting it.
3. **X.509 sign-in**: a person signs in with a certificate (for example a
   smart card) issued by a certificate authority the realm trusts.

The protocol rules for 1 and 2 are in
[oauth-oidc-profile.md](oauth-oidc-profile.md#mutual-tls-rfc-8705). This page
covers deployment, trust anchors and sign-in.

## How certificates reach the server

Browsers must never see a certificate prompt on the ordinary sign-in pages,
so the public listener never asks for one. Use one of two ways:

| Way | Configuration | Notes |
| --- | --- | --- |
| A second TLS listener | `server.mtls_listen` (for example `:8443`), `server.mtls_origin` (its public `https` origin) | Uses the same certificate as `server.tls_cert_file`/`tls_key_file` (required). It asks every client for a certificate but does not verify it at the TLS layer: which certificates count is decided per client and per realm trust anchor. TLS 1.2 or later. Shut down gracefully with the other listeners. It serves the same routes as the public listener |
| A TLS-terminating proxy | `server.client_cert_header` (for example `X-Client-Cert`) and `server.trusted_proxies` (required) | The proxy forwards the client certificate as URL-escaped PEM (nginx `$ssl_client_escaped_cert`; a literal `+` would become a space, so it must be percent-encoded). The header is honored only from a direct peer in `server.trusted_proxies`. **The proxy must remove the header from client requests**, or a client could claim any certificate. Only the leaf certificate arrives this way, so it must be issued directly by the trust anchor |

A certificate the TLS connection presents always wins over the header.
Startup refuses `mtls_listen` without `tls_cert_file`
("server.mtls_listen needs server.tls_cert_file and tls_key_file"), an
`mtls_origin` that is not an `https` origin, and `client_cert_header` without
`trusted_proxies` ([configuration.md](../operations/configuration.md#server)).

When either way is configured, discovery publishes
`tls_client_certificate_bound_access_tokens: true` and adds
`tls_client_auth` and `self_signed_tls_client_auth` to the token,
introspection and revocation authentication methods. With `mtls_origin` it
also publishes `mtls_endpoint_aliases`: the token, introspection,
revocation, UserInfo, PAR and device authorization endpoints on that origin
(`<mtls_origin>/realms/<realm>/...`). Clients send requests that need a
certificate to the alias. DPoP proofs (`htu`) and `private_key_jwt`
assertions (`aud`) must still name the public URLs, never the alias.

## Trust anchors

A realm trusts certificate authorities per purpose: `client` (mutual-TLS
client authentication) or `user` (X.509 sign-in). Paths are relative to
`/api/v1/realms/{realm}`:

| Method and path | Permission | Effect |
| --- | --- | --- |
| `POST /certificate-trust-anchors` | `realm.clients.credentials` for `client`, `realm.settings.write` for `user` | Trust a CA (`201`) |
| `GET /certificate-trust-anchors?purpose=client\|user` | `realm.settings.read` | Active anchors |
| `PUT /certificate-trust-anchors/{id}/crl` | As for `POST`, by the anchor's purpose | Replace the CRL `{"crl_pem": "..."}` (`200`) |
| `DELETE /certificate-trust-anchors/{id}` | As for `POST` | Stop trusting it (`204`) |

```json
POST /api/v1/realms/main/certificate-trust-anchors
{"purpose": "user", "name": "Corporate smart cards",
 "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
 "revocation": "crl", "crl_pem": "-----BEGIN X509 CRL-----\n...",
 "map_san_email": false, "multi_factor": true}
```

| Member | Rules |
| --- | --- |
| `purpose` | `client` or `user` |
| `name` | Required, at most 100 characters |
| `certificate_pem` | Exactly one PEM certificate: a CA (basic constraints CA), not expired |
| `revocation` | `none` (default) or `crl` (then `crl_pem` is required: a PEM X.509 CRL signed by this CA, with a `nextUpdate`; a list without one is `422`) |
| `map_san_email` | `user` anchors only: a certificate whose single e-mail address matches a verified address signs in that account without a binding |
| `multi_factor` | `user` anchors only: the certificate's key is protected by a second factor (a smart card and PIN), so sign-in counts as phishing-resistant MFA |

The answer carries `id`, `subject`, `fingerprint` (base64url SHA-256 of the CA
certificate), `not_after`, `crl_next_update` and the members above. Trusting
the same CA twice for one purpose is `409` while the first anchor is active;
after `DELETE` the CA can be trusted again, as a new anchor with a new `id`
(the removed anchor's bindings stay with it and sign nobody in: bind the
accounts to the new anchor). Audited as `certificate.trust_anchor.added`,
`.crl_updated` and `.removed`.

**Verification.** A certificate is accepted when it chains to an active
anchor of the purpose (anchors are tried in the order they were added;
intermediates come only from the TLS connection), every certificate of the
chain is valid now, and its extended key usage allows client authentication
(a certificate without that extension passes, as in Go). With `revocation:
crl`, the anchor's CRL must be current: once its `next_update` has passed,
every certificate of that anchor is refused until a new CRL is uploaded
(`REVOCATION_UNAVAILABLE` at sign-in). Every certificate of the chain below
the anchor is checked against the CRL of its issuer: the anchor's CRL
covers what the anchor issued itself, an intermediate (so a revoked
intermediate refuses every certificate below it) or the leaf when the
anchor issued it directly. A certificate issued by an intermediate needs
that intermediate's CRL, which an anchor does not hold: under `revocation:
crl` it is refused as `REVOCATION_UNAVAILABLE`. Trust the issuing CA itself
as the anchor, with its own CRL, when certificates come from an
intermediate. With `revocation: none`, chains through intermediates
presented on the TLS connection are accepted without revocation checks.

`PUT .../crl` takes a newer list only: a greater CRL number than the current
one, or, when either list has no number, a later `thisUpdate`; uploading the
identical list again is accepted. An equal number with other content, or an
older list, is `422`; a list without `nextUpdate` is `422`. Freshness is not
checked at upload. `PUT .../crl` switches an anchor with `revocation: none`
to CRL checking. Removing an anchor marks it removed (migration `0086` made
only active anchors unique, so the CA can be added again).

## Client authentication and bound tokens

A client registered with `token_endpoint_auth_method: tls_client_auth`
names exactly one of `tls_client_auth_subject_dn`, `_san_dns`, `_san_uri`,
`_san_ip` or `_san_email` (at most 1024 characters); its certificate must
chain to a `client` anchor. `self_signed_tls_client_auth` needs no anchor:
the certificate must equal the first `x5c` certificate of one of the
client's registered public keys (`POST /clients/{client}/credentials
{"jwks": ...}`), or match its `x5t#S256`. Both are for `confidential` and
`machine` clients only (`422`); no secret is issued.

`tls_client_certificate_bound_access_tokens: true` binds every access token
of the client to its certificate (`cnf.x5t#S256`), whatever the
authentication method. The token endpoint reports these tokens as
`token_type: Bearer` (RFC 8705 §3); present them with the `Bearer` scheme
over a connection with the same certificate. Details, errors and how the
IdP's APIs enforce the binding:
[oauth-oidc-profile.md](oauth-oidc-profile.md#mutual-tls-rfc-8705);
resource servers: [resource-servers.md](../integrations/resource-servers.md#sender-constrained-tokens).

## X.509 sign-in (PROV-016)

Enable it with the realm policy `login.certificates: true`. A pending
transaction without a primary factor then offers the optional action
`{"type": "certificate", "required": false, "fields": []}` (also before the
identifier is known), and the client answers with

```
POST /api/v1/realms/{realm}/auth/transactions/{id}/certificate
{}
```

**on a connection that carries the certificate**: the mutual-TLS listener, or
the proxy that forwards it. The certificate never comes from the body. For a
browser login UI, put the mutual-TLS listener on the same host as the public
origin (another port), so the transaction cookie reaches it; the request is
cross-origin, so the login UI's origin must be one of the client's registered
`allowed_origins`, and the `Origin` and CSRF checks apply as for every step
([headless-authentication.md](headless-authentication.md#browser-specifics)).

The account is found:

1. by a **binding**: an active binding of the anchor with the certificate's
   issuer DN and subject DN (a renewed certificate with the same names keeps
   working); or
2. with `map_san_email` on the anchor: the certificate carries exactly one
   e-mail address, and it matches a verified address of one account.

When the transaction already names an account (after `identify`), the
certificate must resolve to that account, and the account must be able to
sign in.

| Outcome | Result |
| --- | --- |
| Realm without `login.certificates` | `409 unexpected_step` |
| No certificate on the connection | `400 invalid_request` ("no client certificate was presented; use the mutual-TLS endpoint"); not counted as a failed proof |
| Refused certificate | `400 invalid_proof`, counted toward the transaction's 5 failures and the proof budgets (below), audited as `authentication.certificate.failed` (category `security`, metadata `subject_dn`, `issuer_dn`, `transaction_id`) with reason `CERTIFICATE_REVOKED`, `REVOCATION_UNAVAILABLE`, `CERTIFICATE_UNTRUSTED`, `CERTIFICATE_UNBOUND`, `CERTIFICATE_OTHER_ACCOUNT` or `ACCOUNT_UNAVAILABLE` |
| Accepted | The session gets the factor `x509`; audited as `authentication.certificate.used` (`anchor_id`, `subject_dn`, `multi_factor`) |

**Attempt budget.** Every attempt with a certificate (successes included)
counts against `rate_limits.otp_verify_per_account` (10 per 15 minutes by
default) for its subject: the account once the transaction names one (after
`identify`); before that, the certificate itself (its thumbprint) from the
client's /24 (IPv4) or /48 (IPv6) network, so one certificate or network
cannot use up a budget other people share. The per-address, per-realm,
per-client and per-organization budgets apply as for every proof
([configuration.md](../operations/configuration.md#security)). An exhausted
budget is `429 rate_limited`, not a failed proof.

`x509` is a primary factor (`amr` `x509`, a project-specific value). With a
`multi_factor` anchor it is also the second factor: `amr` adds `mfa` and the
session's `acr` is `urn:proudauth:acr:phishing_resistant`. Otherwise the
usual MFA rules follow. Organization policy `allowed_login_methods` and the
realm's authentication flow rules (`methods`) accept `certificate`.

**Bindings.** Administrators bind certificate identities to accounts:

| Method and path | Permission | Effect |
| --- | --- | --- |
| `POST /users/{user}/certificate-bindings` | `realm.users.credentials.manage`, MFA session | `{"anchor_id", "issuer_dn", "subject_dn"}` (RFC 4514 names, at most 1024 characters each) or `{"anchor_id", "certificate_pem"}` (a sample certificate; its names are used) → `201` |
| `GET /users/{user}/certificate-bindings` | `realm.users.read` | Active bindings (`id`, `anchor_id`, `issuer_dn`, `subject_dn`, `state`, `created_by_id`, `created_at`, `last_used_at`) |
| `DELETE /users/{user}/certificate-bindings/{id}` | `realm.users.credentials.manage` | Remove (`204`) |

`anchor_id` must be an active `user` anchor (`422`). A sample
`certificate_pem` must be accepted by that anchor (it chains to it, is valid,
and is not revoked under its policy); a certificate of another anchor is
`422`. An identity already bound, to another account or to this one, is
`409`. Binding and removal change the
account's credential revision and are audited as `credential.certificate.bound`
and `credential.certificate.unbound`.

## Known issues

- `self_signed_tls_client_auth` does not check the expiry of the registered
  key that carries the certificate.

## Not supported

OCSP; CRL distribution points or any fetching of revocation data (CRLs are
uploaded); intermediate certificates in the proxy header; mapping
certificates to accounts by other attributes than a binding or one SAN
e-mail address; verification of certificate-bound tokens in the SDK
verifiers.
