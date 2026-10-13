# SAML 2.0

Requirements: APP-018, FED-014, SAML-001..SAML-010, TEST-051 (docs/plan.md
§7, §11, §18.3, §26.2, §29). Code: `internal/saml` (XML parsing, bindings,
signatures, encryption, metadata, signing keys), `internal/saml/idp`
(identity provider), `internal/federation/saml.go` and `saml_response.go`
(broker), `internal/httpapi/saml.go` (routes). Tests:
`TestSAMLIdentityProvider` and `TestSAMLKeyRollover`
(`tests/e2e/saml_test.go`), `TestSAMLBroker`
(`tests/e2e/saml_broker_test.go`), and the unit tests in
`internal/saml/saml_test.go`. OpenAPI tag `SAML`. Migration
`0060_saml.sql`.

ProudAuth implements SAML 2.0 in two separate roles (SAML-001), each with
its own metadata and its own trusted counterparties:

| Role | What it does | Managed at | Counterparty trust |
| --- | --- | --- | --- |
| **Identity provider** | The realm signs users in to registered **SAML applications** (service providers) | `/api/v1/realms/{realm}/saml/applications` | Per application: entity ID, exactly registered assertion consumer service (ACS) URLs, SP signing certificates |
| **Broker** (service provider) | Users sign in through an enterprise SAML identity provider, a **SAML connection** (a federation connection of kind `saml`) | `/api/v1/realms/{realm}/saml/connections` | Per connection: the IdP's entity ID and its trusted signing certificates |

**Status.** Both roles are tested against the test SP and test IdP in this
repository (written on `etree`, `goxmldsig` and the Go standard library,
independently of `internal/saml`) and against one third-party product,
**Keycloak 26.8.0**, as service provider and as identity provider
(`scripts/interop-keycloak.sh`, the profiles in
[interoperability.md](interoperability.md#keycloak-2680-protocol-profiles)).
No other product (Shibboleth, SimpleSAMLphp, Okta, Microsoft Entra ID,
ADFS, ...) has been tested, and no SAML conformance suite has been run
([interoperability.md](interoperability.md#untested-claims)).
Unsupported features are listed in [Not supported](#not-supported); none of
them is advertised in metadata.

## Enabling SAML

Both roles are off by default. The `saml` configuration section
([configuration.md](../operations/configuration.md#saml)):

| Key | Default | Effect |
| --- | --- | --- |
| `saml.enabled` | `false` | Turns on both roles and their APIs. The broker also needs `federation.enabled` (default `true`) |
| `saml.max_message_bytes` | `262144` | Largest decoded (and, for HTTP-Redirect, inflated) message and largest uploaded metadata document; `16384`–`4194304` |
| `saml.max_clock_skew` | `5m` | Upper bound for the `clock_skew_seconds` of applications and connections; `0`–`30m` |
| `saml.key_prepublish` | `48h` | How long the next signing key must be published in metadata before it can be activated without `force` |
| `saml.retired_key_publication` | `168h` | How long a replaced signing key stays published in metadata |

While `saml.enabled` is `false`, every SAML route of an existing realm
answers `404 feature_disabled` and nothing SAML-related is advertised. OpenID
Connect discovery never mentions SAML.

HTTP-POST messages (SSO, single logout and the broker's ACS) are also
bounded by `limits.max_body_bytes` (256 KiB by default, roughly 180 KiB of
XML once the browser's form encoding and base64 are removed); a larger body
gets `413 payload_too_large`. Raise both limits together if an identity
provider sends unusually large responses.

## Endpoints

`I` is the realm's issuer, `{server.public_origin}/realms/{realm}`; `R` is
`/api/v1/realms/{realm}`.

| Route | Purpose | Trust class |
| --- | --- | --- |
| `GET I/saml/metadata` | Identity provider metadata | Public metadata |
| `GET I/saml/sso` | SSO, HTTP-Redirect binding | Public protocol initiation |
| `POST I/saml/sso` | SSO, HTTP-POST binding (continues with a `303` to `I/saml/sso/continue?request=...`) | Public protocol initiation |
| `GET I/saml/sso/continue` | Starts a recorded request (`?request=`) or completes it (`?code&state`, `?error&state`) | Transaction-bound (browser binding cookie) |
| `GET I/saml/idp-initiated?sp=<entity ID>` | IdP-initiated (unsolicited) SSO, only for applications that opted in | Public protocol initiation |
| `GET`, `POST I/saml/slo` | SP-initiated single logout | Public protocol initiation (signed request required) |
| `GET I/saml/sp/{connection}` | The broker's SP metadata for one connection (also its default SP entity ID) | Public metadata |
| `POST I/saml/acs/{connection}` | The broker's assertion consumer service (HTTP-POST) | Transaction-bound |
| `GET`, `POST R/saml/applications`; `GET`, `PUT`, `DELETE R/saml/applications/{id}` | SAML applications (`realm.clients.read`, `realm.clients.write`) | Administration |
| `GET`, `POST R/saml/connections`; `GET`, `PUT`, `DELETE R/saml/connections/{id}` | SAML connections (`realm.identity_providers.read`, `realm.identity_providers.write`) | Administration |
| `GET R/saml/signing-keys`; `POST R/saml/signing-keys`; `POST R/saml/signing-keys/{id}/activate` | The realm's SAML signing keys (`realm.keys.read`, `realm.keys.rotate`) | Administration |

Administration routes need an administration token from an MFA session,
like every realm administration route. `PUT` needs `If-Match` with the
`ETag` of the last `GET` (`428` without it, `412` when stale); `POST`
answers `201` with an `ETag`, `DELETE` `204`.

Cookies: `pa_saml` binds a SAML sign-in to the browser that started it
(random secret, `HttpOnly`, always `SameSite=Lax`, path
`/realms/{realm}/saml/`, lifetime `tokens.transaction_ttl`); `pa_tx` and
`pa_sid` are the same cookies as for OAuth sign-ins.

## Signing keys and rollover

SAML-002. SAML has its own signing keys, separate from the JWT signing keys
([keys.md](../operations/keys.md)): SAML counterparties pin X.509
certificates rather than fetching JWKs, cache metadata for long periods,
need RSA whatever algorithm the realm uses for tokens, and rotate on their
own schedule. One key set per realm serves both roles (identity provider
responses and the broker's `AuthnRequest`s).

- Keys are RSA 3072-bit with a self-signed SHA-256 certificate valid for 5
  years. The validity period does not establish trust; the published
  metadata does. Private keys are encrypted with the signing-wrap key
  (`keys.signing_wrap_keys`, or the root-derived key; associated data
  `saml-signing-key:<id>`), like token signing keys. The first key is created
  on first use.
- States: `pending` (the next key: **published in metadata, never signs**)
  → `active` → `retiring` (still published until `publish_until`, the
  activation time plus `saml.retired_key_publication`) → `retired` (by the
  worker's retention task).

Rollover runbook:

1. `POST R/saml/signing-keys` publishes the next key (`409` while one is
   already pending). Audit `saml.signing_key.prepared`.
2. Wait at least `saml.key_prepublish` (48 hours by default) so service
   providers and identity providers refresh the metadata. A counterparty
   that pins a single certificate by hand must add the new one now.
3. `POST R/saml/signing-keys/{id}/activate`. Before `saml.key_prepublish`
   has passed this answers `409`, unless the body is
   `{"force": true, "reason": "..."}` with a reason of at least 10
   characters; a forced activation is audited in category `emergency`
   (for a compromised key). Audit `saml.signing_key.activated`.
4. The previous key leaves the metadata after
   `saml.retired_key_publication`.

The metadata of both roles always lists the active key, the pending key and
retiring keys still inside their publication window. Retired keys stay in
`saml_signing_keys` with state `retired`; they are not deleted.

## Identity provider metadata

`GET I/saml/metadata` (`application/samlmetadata+xml`,
`Cache-Control: public, max-age=300`) is **unsigned** and lists the realm's
signing certificates, the four NameID formats, and HTTP-Redirect and
HTTP-POST endpoints for SSO and single logout. It always says
`WantAuthnRequestsSigned="false"`: whether requests must be signed is
decided per application (`require_signed_requests`). Give service providers
this URL or a copy of the document, and refresh their copy during a
[key rollover](#signing-keys-and-rollover).

## Identity provider: SAML applications

APP-018.

### Registering an application

`POST R/saml/applications` (`realm.clients.write`). The body may include
`metadata_xml`: the service provider's metadata as uploaded text, an
`EntityDescriptor` with an `SPSSODescriptor` (aggregates such as
`EntitiesDescriptor` are refused). **Metadata URLs are never fetched.**
Metadata fills the fields not given explicitly: entity ID, HTTP-POST ACS
endpoints (other bindings are ignored), logout endpoints, signing
certificates, and `require_signed_requests` from `AuthnRequestsSigned`. An
encryption key in the metadata is used only when `encrypt_assertions` is
`true`.

```json
POST /api/v1/realms/main/saml/applications
{
  "name": "Wiki",
  "entity_id": "https://wiki.example.com/saml/metadata",
  "assertion_consumer_services": [
    {"url": "https://wiki.example.com/saml/acs", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}
  ],
  "signing_certificates": ["MIID..."],
  "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  "attributes": [
    {"name": "mail", "source": "email"},
    {"name": "displayName", "source": "name"}
  ]
}
```

| Member | Rules |
| --- | --- |
| `entity_id` | Absolute URI (URL or URN), at most 1024 characters, unique in the realm (`409`) |
| `assertion_consumer_services` | 1 to 10 endpoints, **HTTP-POST only** (the Web SSO profile forbids HTTP-Redirect for responses; Artifact is not supported). The exact-redirect rules of APP-004 apply: at most 2048 bytes, `https` (plain `http` only to `localhost` or a loopback address, and only when the application's `environment` is not `production`), no fragment, userinfo, wildcards, path traversal or encoded separators, and no `localhost` at all for a `production` application. Each endpoint is `{binding, url, index, is_default}`; each `index` is unique (assigned in order when all are 0); one is the default (the first when none is marked) |
| `single_logout_services` | 0 to 4 endpoints, HTTP-Redirect or HTTP-POST, with an optional `response_url`; requires a signing certificate |
| `signing_certificates` | PEM or base64 DER; RSA of at least 2048 bits; not expired; at most 4 (for overlap during rollover; duplicates are dropped). They verify `AuthnRequest`s and `LogoutRequest`s |
| `require_signed_requests` | Default `true` when certificates are registered. `AuthnRequestsSigned="true"` in uploaded metadata can only turn it on |
| `name_id_format` | The full URN: `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` (default), `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` or `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`; short names are refused with `422` ([NameID formats](#nameid-formats)) |
| `attributes` | At most 50 mappings `{name, name_format, friendly_name, source, value}` ([Attribute mapping](#attribute-mapping)) |
| `sign_response`, `sign_assertion` | Both default to `true`; at least one must be `true` |
| `signature_algorithm` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (default), `#rsa-sha384` or `#rsa-sha512`; anything else, including SHA-1, is `422` |
| `encrypt_assertions`, `encryption_certificate`, `data_encryption_algorithm`, `key_transport_algorithm` | [Encrypted assertions](#encrypted-assertions) |
| `allow_idp_initiated`, `idp_initiated_relay_state` | Default `false`; the relay state (at most 1024 bytes) only together with the flag ([IdP-initiated SSO](#idp-initiated-sso)) |
| `clock_skew_seconds` | Default 120 (`0` also means 120); at most `saml.max_clock_skew`. With `saml.max_clock_skew` below `2m`, every application must set a value explicitly |
| `assertion_lifetime_seconds` | Default 300; 60 to 1800 |
| `additional_audiences` | At most 5 extra `Audience` values |
| `authn_context_map` | At most 20 entries `"<AuthnContextClassRef>": "urn:proudauth:acr:..."` that extend or override the built-in mapping ([Authentication context](#authentication-context)) |
| Client members | `name`, `description`, `project_id`, `environment` (fixed after creation), `first_party`, `consent_mode`, `consent_terms_version`, `require_mfa`, `max_session_age_seconds`, `allow_remember_me`, `login_ui_url`, `organization_id` |

The response describes the application with its backing `client_ref` and
`client_id`, its `state`, the parsed certificates, and `identity_provider`
(`entity_id`, `metadata_url`, `sso_url`, `slo_url`): the values to configure
at the service provider.

Changes to certificates, attributes, the entity ID and the IdP-initiated
settings are audited (`saml.application.created`, `.updated`, `.deleted`,
category `application`, with the fingerprints of certificates added and
removed).

### The backing client

Each SAML application is stored in `saml_service_providers` and **backed by
a client record** (`clients.protocol = "saml"`; confidential,
`private_key_jwt` with no key, grant `authorization_code`, one redirect URI
`I/saml/sso/continue`). The backing client is what lets the existing sign-in
machinery apply unchanged: login methods, MFA policy and step-up, consent
and administrative consent pre-authorization, organization policy, SSO
session reuse and `max_session_age_seconds`, client sessions, the client
lifecycle and audit (`client_id`).

The backing client is **not an OAuth client**: `/oauth/authorize` answers
`invalid_client` for it, OAuth client authentication (token, introspection,
revocation, PAR, device authorization) always fails for it, and
`PUT /clients/{id}` answers `409` ("change it through /saml/applications").
`GET /clients` lists it with `"protocol": "saml"`.

Lifecycle: suspend an application by suspending its client
(`/clients/{client}/...` lifecycle routes). `DELETE R/saml/applications/{id}`
deletes the application (its pending requests and logout records with it)
and decommissions the client, revoking its grants. The entity ID can then
be registered again; the persistent NameIDs of the old registration are not
reused.

### SP-initiated SSO

1. **Receive** (`GET` or `POST I/saml/sso`). Until the ACS is validated,
   every refusal is a **local `400` problem**, never a message to an
   unregistered URL. The checks, in order, with the problem's `reason`:
   - decoding and parsing: base64, DEFLATE bounded by
     `saml.max_message_bytes`, [XML safety](#xml-processing) →
     `saml_invalid_request`;
   - the root must be `samlp:AuthnRequest`, and its `Issuer` a registered,
     active application → `saml_unknown_service_provider`;
   - signature: for HTTP-Redirect, the detached signature over the raw query
     octets; for HTTP-POST, the enveloped signature (verified with
     `goxmldsig`; only the verified element is read). A signature that is
     present is always checked when the application has certificates, and
     an invalid one is never ignored; an unsigned request when signatures
     are required → `saml_signature`. Only RSA-SHA256, -SHA384 and -SHA512;
   - `Version="2.0"`, a valid `ID`, the `Issuer` of the verified element,
     `IssueInstant` no later than now plus the skew and no earlier than
     10 minutes plus the skew ago;
   - `Destination`, when present, equal to `I/saml/sso`; required on signed
     HTTP-POST requests;
   - ACS: `AssertionConsumerServiceURL` exactly registered, or
     `AssertionConsumerServiceIndex` registered, or the default; both given,
     or a `ProtocolBinding` other than HTTP-POST →
     `saml_unregistered_acs`;
   - each request ID is accepted once per application →
     `saml_request_replay`.
2. From here on, a request the identity provider **cannot honor** is
   answered with a **signed SAML error response** to the validated ACS
   (top-level status `Requester` or `Responder`, with a second-level code):
   a `Subject` in the request → `RequestUnsupported`; a
   `NameIDPolicy` `Format` that is neither `unspecified` nor the
   application's format, or a foreign `SPNameQualifier` →
   `InvalidNameIDPolicy`; a `RequestedAuthnContext` with only unknown class
   references, an `AuthnContextDeclRef`, an unknown comparison, or `better`
   than the strongest local level → `NoAuthnContext`; `IsPassive` together
   with `ForceAuthn` → `NoPassive`.
3. The accepted request is recorded (`saml_idp_requests`) and bound to the
   browser with the `pa_saml` secret. HTTP-Redirect continues at once;
   HTTP-POST continues with a `303` to `GET I/saml/sso/continue?request=...`
   (a cross-site `POST` carries no `SameSite=Lax` cookies; the `GET` carries
   the SSO session cookie).
4. **Start.** An authentication transaction is created for the backing
   client (browser mode) with the continuation endpoint as redirect URI, a
   PKCE verifier held by the server, a random `state`, scopes that describe
   the released data (`openid` plus `email`, `profile` or `phone` according
   to the attribute mapping; this is what consent shows), the application's
   organization as the requested organization, `ForceAuthn` as
   `prompt=login`, and the requested assurance as ACR values (step-up). The
   SSO session is reused when policy allows (SES-014,
   `max_session_age_seconds`).
   - If the transaction completes silently, the assertion is delivered at
     once (a `200` form, step 6).
   - `IsPassive` and not silently completable → `NoPassive` error response;
     the transaction is cancelled.
   - Otherwise `302` to the login interface (the application's
     `login_ui_url`, else the realm's) with `transaction_id`, setting
     `pa_tx`. Without a login interface the answer is `503`.
   - The emergency control for `authorization_code` (SEC-020), a suspended
     client or an inactive realm → `RequestDenied`.
5. **Complete** (`GET I/saml/sso/continue?code&state`). The login interface
   sends the browser to the transaction's `redirect_to`. The request is
   consumed once and only with the matching `pa_saml` cookie (another
   browser, or a replay → `400 transaction_invalid`, reason
   `saml_request_invalid`). The internal code is redeemed with the PKCE
   verifier and must belong to the request's transaction, the backing
   client and the continuation URI. Then: the grant and session must be
   active and the account able to authenticate; for an application bound to
   an organization the user must be an **active member** (otherwise
   `RequestDenied`); the session's ACR must meet the requested level
   (otherwise `NoAuthnContext`); the NameID is derived (no verified email
   for `emailAddress` → `InvalidNameIDPolicy`). `?error=` from a cancelled
   or failed transaction becomes `RequestDenied` (`access_denied`),
   `NoPassive` (login, interaction or consent required) or `AuthnFailed`.
6. **Delivery** is an auto-submitting HTML form (`SAMLResponse`,
   `RelayState`) to the registered ACS, with a per-response nonce in
   `Content-Security-Policy: default-src 'none'; script-src 'nonce-...';
   frame-ancestors 'none'; base-uri 'none'`, a Continue button for browsers
   without scripts, `Cache-Control: no-store` and
   `Referrer-Policy: no-referrer`. `form-action` is not restricted because
   some browsers apply it to the redirects the SP makes after its ACS; the
   form's action is always a registered ACS.

### Response contents

A `samlp:Response` (`Destination` = the ACS, `InResponseTo` unless
unsolicited, `Issuer` = the realm's issuer, `Status`) with one
`saml:Assertion`:

- `Issuer`; `Subject` with the `NameID` (with `NameQualifier` and
  `SPNameQualifier` for persistent and transient formats) and a **bearer**
  `SubjectConfirmation` (`Recipient` = the ACS, `InResponseTo`,
  `NotOnOrAfter` = now plus the assertion lifetime);
- `Conditions` (`NotBefore` = now minus the skew, `NotOnOrAfter` = now plus
  the lifetime) with one `AudienceRestriction` (the entity ID and
  `additional_audiences`);
- `AuthnStatement` (`AuthnInstant` = the authentication time,
  `SessionIndex` per session and application, `SessionNotOnOrAfter` = the
  session's absolute expiry, `AuthnContextClassRef`);
- `AttributeStatement` with the mapped attributes (no `xsi:type`).

Signatures follow `sign_assertion` and `sign_response`: enveloped, exclusive
canonicalization, the signature placed after `Issuer`, the X.509
certificate in `KeyInfo`. Error responses are always signed. Each assertion
is audited as `saml.assertion.issued` (category `token`: entity ID, ACS,
NameID format, authentication context, session, grant).

### NameID formats

SAML-006.

| Format | Value |
| --- | --- |
| `...:2.0:nameid-format:persistent` (default) | An opaque `sps_...` value: an HMAC-SHA256 under the deployment's pairwise-subject purpose key over the sector `saml:<application id>` and the account ID, truncated to 20 bytes and base64url-encoded. It is derived once and stored in `pairwise_subjects`, so it stays stable across root-key rotation; it differs for every application (no correlation between applications) and is deleted with the account |
| `...:1.1:nameid-format:emailAddress` | The account's **verified** email address only (the primary one first); none → `InvalidNameIDPolicy` |
| `...:1.1:nameid-format:unspecified` | The account's immutable ID (the same value as the OIDC public `sub`) |
| `...:2.0:nameid-format:transient` | A new random value for each assertion |

### Attribute mapping

SAML-006. Each mapping releases one attribute: `name` (sent as the SAML
attribute name), optional `name_format` (default `uri` when the name
contains `:`, otherwise `basic`) and `friendly_name`, and a `source`:

`email` (verified email only), `email_verified` (`true` when a verified
email is released), `name`, `given_name`, `family_name`,
`preferred_username` (the username), `locale`, `zoneinfo`, `phone_number`
(verified phone only), `user_id`, `subject` (the NameID value),
`organization_id` (the application's organization), or `static` with
`value`. Empty values are not released.

**Protected names** (compared case-insensitively) cannot carry static or
user-editable values:

- email names (`email`, `mail`, `emailaddress`,
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`,
  `urn:oid:0.9.2342.19200300.100.1.3`) accept only source `email`;
- identifier names (`uid`, `sub`, `nameid`, `upn`, `eppn`, `user_id`,
  `userid`, the WS-Federation `nameidentifier` and `upn` claim URIs, Azure's
  `objectidentifier`, `urn:oid:0.9.2342.19200300.100.1.1`, and the eduPerson
  principal, targeted and unique IDs) accept only `user_id`, `subject`,
  `email` or `preferred_username`.

### Authentication context

The requested `AuthnContextClassRef` values map to local assurance levels:

| Class references | Local level |
| --- | --- |
| `unspecified`, `Password`, `PasswordProtectedTransport` | Single factor (rank 1) |
| `MobileTwoFactorContract`, `TimeSyncToken`, `http://schemas.microsoft.com/claims/multipleauthn`, `https://refeds.org/profile/mfa`, `urn:proudauth:acr:mfa` | MFA (rank 3) |
| `urn:proudauth:acr:phishing_resistant` | Phishing-resistant (rank 4) |
| `urn:proudauth:acr:single_factor`, `urn:proudauth:acr:federated` | Rank 1 |

`authn_context_map` adds class references or overrides these. Comparison
`exact`, `minimum`, `maximum` (or none) requires the lowest requested rank;
`better` requires one above the highest. Ranks 3 and 4 become the
transaction's ACR requirement, so the user is stepped up or asked to
enroll a factor. The assertion states the strongest requested reference the
session meets; otherwise the mapped reference for the session's ACR;
otherwise `urn:proudauth:acr:mfa` or `urn:proudauth:acr:phishing_resistant`,
`PasswordProtectedTransport` for a password-only session, and
`unspecified` for anything else.

### Consent and organizations

Third-party applications (`first_party: false`, `consent_mode: required`)
ask for consent through the normal transaction, with the scopes described
in step 4 above. Consents are stored against the backing client and can be
revoked like any other; administrative pre-authorization applies.

`organization_id` binds the application to one organization: that
organization's policies (MFA, login methods, SSO-mandatory, the rule for
connections of other organizations) apply to the sign-in, and only its
active members receive assertions. Choosing an organization per request is
not supported.

### Encrypted assertions

Outbound only. With `encrypt_assertions: true` and an
`encryption_certificate` (or the encryption key from the SP's metadata), the
signed assertion is encrypted (sign, then encrypt) into a
`saml:EncryptedAssertion`:

| Member | Values |
| --- | --- |
| `data_encryption_algorithm` | `http://www.w3.org/2009/xmlenc11#aes256-gcm` (default) or `#aes128-gcm` (IV, ciphertext and tag) |
| `key_transport_algorithm` | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` (default; its SHA-1 digest is used only inside OAEP padding, not for collision resistance) or `http://www.w3.org/2009/xmlenc11#rsa-oaep` (SHA-256 digest, MGF1 with SHA-256) |

The SP's certificate is placed in the `EncryptedKey`'s `KeyInfo`. **AES-CBC
and RSA PKCS#1 v1.5 key transport are refused** (`422`, SAML-009). An
encryption certificate without `encrypt_assertions` is refused. A service
provider that supports only CBC cannot receive encrypted assertions; send it
signed assertions over TLS instead.

### IdP-initiated SSO

SAML-007. `GET I/saml/idp-initiated?sp=...` takes the application's entity
ID or its ID (an unknown one is `400`, reason
`saml_unknown_service_provider`). It is disabled by default: `403` (reason
`saml_unsolicited_disabled`). When an application sets
`allow_idp_initiated: true`:

- the response always goes to the application's **default ACS**;
- `RelayState` is only the registered `idp_initiated_relay_state`; a
  `RelayState` query parameter is ignored, so the endpoint is not a
  redirector;
- the response has no `InResponseTo`, and the sign-in is still a real
  sign-in bound to the browser (`pa_saml`) and audited.

Residual risk: unsolicited SSO allows login CSRF into the user's own account
at the service provider. Enable it only for applications that need to be
launched from a portal.

### Single logout

SAML-008. A declared subset:

- **Supported: SP-initiated `LogoutRequest`** over HTTP-Redirect or
  HTTP-POST, **always signed** with a registered certificate of the issuing
  application (an unsigned request gets `400` even when
  `require_signed_requests` is `false`). `Destination`, when present, must be
  `I/saml/slo`; `IssueInstant` within the same window as for SSO (no later
  than now plus the skew, no earlier than 10 minutes plus the skew ago);
  `NotOnOrAfter` is honored.
- The `NameID` (with its format, by default the application's) and the
  `SessionIndex` values select the sessions for which the application
  received assertions; without `SessionIndex`, every session of that subject
  with that application. Each selected session is **revoked** (grants,
  refresh tokens, opaque tokens; OIDC clients with back-channel logout
  receive logout tokens as for any revocation). The browser's `pa_sid`
  cookie is cleared when its own session ended.
- The answer is a signed `LogoutResponse` to the application's first
  registered logout endpoint (its `response_url` when set) in that
  endpoint's binding (HTTP-Redirect: signed query; HTTP-POST: enveloped
  signature in an auto-submitting form), with status `Success` and the
  second-level status **`PartialLogout`** when other SAML applications, or
  OIDC clients without back-channel logout, took part in the session: they
  are **not** notified.
- Audit `saml.logout.completed` (sessions ended, partial).

Not supported: IdP-initiated logout (sending `LogoutRequest`s to service
providers, front-channel propagation), so incoming `LogoutResponse`s are
refused with `400`; SOAP back-channel logout. Logging out through the OIDC
`/oidc/logout` endpoint does not notify SAML service providers.

## Broker: SAML connections

FED-014.

### Creating a connection

`POST R/saml/connections` (`realm.identity_providers.write`) creates an
`identity_providers` row with `kind` and `adapter` `saml` and `issuer` = the
IdP's entity ID; the SAML settings are stored in `saml_connections`. The
shared federation settings apply unchanged ([headless-authentication.md](../protocols/headless-authentication.md#upstream-identity-providers)):
`alias`, `linking_policy`, `jit_provisioning`, `jit_default_role_id`
(organization-scoped and assignable by the administrator),
`organization_id` (binding to an organization and the rule for connections
of other organizations, FED-006), `trust_upstream_mfa`,
`allowed_email_domains`, `claim_mapping` (keys are SAML attribute **names**;
defaults `displayName`, `givenName`, `sn`), the state (`active`,
`disabled`; emergency controls work), SSO-mandatory organizations
(`sso_provider_id` may name a SAML connection), identifier-based SSO
routing, self-service linking (`POST /me/linked-identities`) and unlinking.

| Member | Rules |
| --- | --- |
| `metadata_xml` | The IdP's metadata as uploaded text (an `IDPSSODescriptor`). **Never fetched.** Fills the entity ID, the **HTTP-Redirect** SSO endpoint, the signing certificates and `sign_authn_requests` (from `WantAuthnRequestsSigned`) when they are not given |
| `alias`, `display_name` | As for other connections; `alias` cannot change (`422`), `display_name` at most 100 characters |
| `idp_entity_id` | The IdP's entity ID; cannot change while identities are linked (`409`) |
| `sso_url` | The IdP's HTTP-Redirect SSO endpoint, at most 2048 characters, no userinfo or fragment; `https` (`http` only outside production); the residency policy applies |
| `signing_certificates` | 1 to 4 trusted certificates; RSA of at least 2048 bits; not expired |
| `sp_entity_id` | Default `I/saml/sp/{alias}` |
| `sign_authn_requests` | Default `true`; `WantAuthnRequestsSigned` in uploaded metadata can only turn it on |
| `require_signed_assertions` | Refuse responses where only the `Response` is signed |
| `name_id_format` | The format requested in `NameIDPolicy` |
| `subject_attribute` | Attribute (at most 256 characters, no whitespace) that carries the stable subject instead of the NameID; required with a transient NameID |
| `email_attribute` | Attribute (at most 256 characters, no whitespace) that carries the email address (otherwise an `emailAddress` NameID) |
| `trust_email_verified` | Treat the IdP's email as verified (SAML has no verification flag). Required, together with `allowed_email_domains`, for linking policy `trusted_verified_email` |
| `trusted_authn_contexts` | Up to 10 `AuthnContextClassRef` URIs (at most 256 characters each) accepted as upstream MFA; required with `trust_upstream_mfa` (FED-009) |
| `requested_authn_contexts` | Up to 10 URIs, sent as `RequestedAuthnContext` (comparison `minimum`) |
| `force_authn` | Send `ForceAuthn` |
| `clock_skew_seconds` | Default 120 (`0` also means 120); at most `saml.max_clock_skew` |

The `linking_policy` defaults to `verify_existing`. A disabled connection's
ACS answers `404 feature_disabled`. The response shows the settings under
`saml` (with parsed certificates) and, under `service_provider`, what the
IdP's administrator registers: `entity_id`, `acs_url` and `metadata_url`. SAML connections are listed by `GET /identity-providers` (kind `saml`) and
offered in transactions like other connections. `PUT /identity-providers/{id}`
answers `409` for them and `POST /identity-providers` refuses
`"adapter": "saml"`: change them through `R/saml/connections`.
`DELETE /identity-providers/{id}` works with the usual rule (no linked
identities). `POST /identity-providers/{id}/test` returns offline diagnostics
(valid certificates, those expiring within 30 days, expired ones and ones
not valid yet); nothing is fetched. Only realm administrators manage SAML connections. Audit
`federation.provider.created` and `.updated` with the certificate
fingerprints (`signing_certificates`, `signing_certificates_added`,
`signing_certificates_removed`).

### Sign-in flow

1. `POST R/auth/transactions/{id}/federation/start {"provider": "<alias>"}`
   returns `external_redirect`: the IdP's SSO URL with an HTTP-Redirect
   `AuthnRequest` (a 160-bit random `ID`, `Destination`,
   `AssertionConsumerServiceURL` = `I/saml/acs/{alias}`, `ProtocolBinding`
   HTTP-POST, `Issuer` = the SP entity ID, `NameIDPolicy` with
   `AllowCreate="true"`, optional `RequestedAuthnContext` and `ForceAuthn`), signed with RSA-SHA256 and the realm's SAML key unless
   `sign_authn_requests` is `false`, and a `RelayState` that is a 256-bit
   bearer secret. Only its digest is stored (`saml_broker_requests`, valid
   for 10 minutes).
2. The IdP posts `SAMLResponse` and `RelayState` to the ACS.
3. **Local refusals** (`400 invalid_proof`, audit `saml.response.rejected`
   with the reason; no transaction is touched and the pending request stays
   usable): unparseable or unsafe XML, not a `Response`, **unsolicited (no
   `InResponseTo`)**, or `InResponseTo` and `RelayState` not matching an
   unconsumed, unexpired request of this connection (this also refuses a
   replay of the same response).
4. Then the request is **consumed** and the response
   [validated](#response-validation). A failure is reported to the
   transaction as `upstream_invalid_response` (`upstream_denied` for a
   non-success status) and audited with the precise reason.
5. **Identity:** the subject is the `subject_attribute` value or the NameID
   (a transient NameID without a subject attribute → `transient_subject`),
   at most 255 characters; the issuer is the IdP's entity ID. The email
   comes from `email_attribute` or an `emailAddress` NameID and is
   **verified only with `trust_email_verified`**. Upstream MFA counts only
   with `trust_upstream_mfa` and an `AuthnContextClassRef` listed in
   `trusted_authn_contexts`.
6. The identity enters the shared federation pipeline: existing link,
   trusted-email linking, linking with proof of control of the local
   account (FED-005), JIT provisioning with organization membership and
   default role, the registration approval queue, account state checks.
   The browser is sent with a `303` to the login interface with
   `transaction_id` (`federation_error` on failure), or JSON is returned for
   realms without a login interface. The login completes only with the
   transaction's continuation, so a response posted from another browser
   cannot finish someone else's login.

### Response validation

SAML-003. All of these must hold:

- status `Success`; exactly one `Assertion`, a direct child of the
  `Response`, and no other `Assertion` anywhere (`assertion_count`); no
  `EncryptedAssertion` (`encrypted_assertion_unsupported`);
- signatures: a signed `Response`, a signed `Assertion`, or both, each
  verified against the connection's trusted certificates (any of them, for
  overlap). A signature that is present must verify; neither signed →
  `unsigned`. With only the `Response` signed, the assertion is read from
  the verified response (refused with `require_signed_assertions`). **Every
  value is read from verified elements**, which defeats signature wrapping;
- algorithms: RSA-SHA256, -SHA384 or -SHA512, digests SHA-256, -384 or -512,
  the enveloped-signature transform plus one canonicalization (exclusive or
  inclusive 1.0 or 1.1, never the `WithComments` variants); SHA-1 →
  `weak_algorithm`;
- exactly one `Signature` references the element, as its direct child, with
  exactly one `Reference` to `#<ID>`;
- `Response`: `Destination` = the ACS, `InResponseTo` = the request,
  `Issuer` (if present) = the IdP's entity ID, `IssueInstant` within
  [now − 10 minutes − skew, now + skew];
- `Assertion`: version 2.0, a valid `ID`, the `IssueInstant` window,
  `Issuer` = the IdP's entity ID (entity format only); exactly one direct
  `NameID` of at most 1024 characters (`subject` otherwise; an
  `EncryptedID` or `BaseID` is never read); a **bearer**
  `SubjectConfirmation` with
  `Recipient` = the ACS, `InResponseTo` = the request, `NotOnOrAfter` later
  than now − skew and `NotBefore` (if present) no later than now + skew;
- `Conditions` present: `NotBefore` ≤ now + skew, `NotOnOrAfter` > now −
  skew, at least one `AudienceRestriction`, and **every** restriction
  contains the SP entity ID; `OneTimeUse` and `ProxyRestriction` are
  accepted, any other condition → `unknown_condition`;
- at least one `AuthnStatement`, whose `SessionNotOnOrAfter` has not passed;
- **replay:** the assertion ID is recorded per connection
  (`saml_assertion_ids`) until it expires; a second use →
  `assertion_replay`;
- attributes: a value longer than 1024 characters (`attribute_value`)
  refuses the response. `Attribute` elements that repeat a `Name` are one
  multi-valued attribute (identity providers such as Keycloak send one
  element per value, for example one `Role` element per role), except the
  connection's `subject_attribute` and `email_attribute`: one of those
  appearing twice is ambiguous and refuses the response
  (`duplicate_attribute`). A multi-valued attribute never fills a
  single-valued field (subject, email, the `claim_mapping` profile fields).
  Attributes beyond the first 100 names, and attributes whose name is empty
  or longer than 256 characters, are dropped silently.

### SP metadata

`GET I/saml/sp/{alias}` returns the broker's metadata for one connection:
`entityID`, `AuthnRequestsSigned`, `WantAssertionsSigned="true"`, the realm's
SAML signing certificates (the pending key included), the requested
`NameIDFormat` and the HTTP-POST ACS. It has **no `SingleLogoutService` and
no encryption key**. Cacheable for 300 seconds.

### Rollover of the IdP's certificate

Update the connection with both the current and the next certificate (both
are trusted), then remove the old one after the IdP has switched. An expired
certificate verifies nothing and cannot be uploaded.

## XML processing

SAML-004, TEST-051. Every inbound message and every uploaded metadata
document goes through `saml.Parse` before a tree is built (a streaming pass
with Go's `encoding/xml` in strict mode):

- size at most `saml.max_message_bytes` after base64 decoding;
  HTTP-Redirect DEFLATE is inflated through a limited reader, so a
  compression bomb stops at the limit; the HTTP body is bounded as well;
- UTF-8 only (other declared encodings are refused);
- **no `DOCTYPE` or any other markup declaration**: without a DTD there are
  no external or internal entities, so XXE and entity expansion are
  impossible; unknown entity references are refused;
- **no comments** (this defeats NameID truncation through comments) and no
  processing instructions other than the XML declaration;
- depth at most 32, at most 4096 elements and 64 attributes per element, no
  duplicate attributes, exactly one root element;
- **no duplicate `ID` values** anywhere in the document;
- text values are the concatenation of all character data, and an element
  with child elements where text is expected is malformed;
- elements are matched by namespace URI, never by prefix.

Signatures are verified with `github.com/russellhaering/goxmldsig` v1.6.1
(no canonicalization or verification code of ProudAuth's own), with the
pinning rules above; the element consumed is the one `goxmldsig` returns,
parsed again from the digested canonical bytes. There is no SHA-1
compatibility switch and no per-counterparty algorithm exception
(SAML-009).

## Errors and reason codes

| Where | Status and `code` | `reason` or SAML status |
| --- | --- | --- |
| IdP SSO, before the ACS is validated | `400 invalid_request` | `saml_invalid_request`, `saml_unknown_service_provider`, `saml_signature`, `saml_unregistered_acs`, `saml_request_replay` |
| IdP continuation | `400 transaction_invalid` | `saml_request_invalid` |
| IdP-initiated SSO not enabled | `403 forbidden` | `saml_unsolicited_disabled` |
| No login interface configured | `503 unavailable` | — |
| IdP error responses (sent to the ACS) | `Requester` | `RequestUnsupported`, `InvalidNameIDPolicy` (also when no verified email exists for an `emailAddress` NameID) |
| | `Responder` | `NoPassive`, `NoAuthnContext`, `RequestDenied`, `AuthnFailed` |
| Single logout | `400 invalid_request` | `saml_logout_unsupported`, `saml_logout_response_unexpected` (a `LogoutResponse` over HTTP-Redirect, or in the `SAMLRequest` field; one posted as `SAMLResponse` gets `400 invalid_request` without a `reason`), `saml_unknown_service_provider`, `saml_signature`, `saml_invalid_request` |
| Broker ACS, not correlated to a request | `400 invalid_proof` | Audit reasons `decode`, `unsafe_xml`, `too_large`, `duplicate_id`, `malformed`, `not_a_response`, `unsolicited`, `unknown_request`, `expired_request` |
| Broker ACS, correlated | Transaction `notice` / `federation_error` | `upstream_invalid_response`, `upstream_denied` (and the linking outcomes). Audit reasons: `version`, `status`, `status_missing`, `encrypted_assertion_unsupported`, `assertion_count`, `response_signature:<x>` and `assertion_signature:<x>` (`weak_algorithm`, `ambiguous`, `malformed`, `invalid`), `unsigned`, `destination`, `in_response_to`, `issuer`, `issue_instant`, `assertion_malformed`, `subject`, `subject_confirmation`, `conditions`, `not_yet_valid`, `expired`, `audience`, `unknown_condition`, `authn_statement`, `upstream_session_expired`, `duplicate_attribute`, `attribute_value`, `subject_attribute`, `transient_subject`, `assertion_replay` |
| Administration | `422 validation_failed` with the field; `409` for conflicts (entity ID or alias in use, linked identities exist, a pending key exists, activation too early, the client is managed by a SAML application) | |

## Audit events

| Event | Category |
| --- | --- |
| `saml.request.rejected` | `security` |
| `saml.assertion.issued` | `token` |
| `saml.logout.completed` | `security` |
| `saml.response.rejected` | `security` |
| `saml.application.created`, `.updated`, `.deleted` | `application` |
| `saml.signing_key.created`, `.prepared`, `.activated` | `configuration` (`emergency` for a forced activation) |

The existing `federation.*`, `authentication.*`, `consent.*`,
`session.revoked` and `client.*` events are recorded as for OIDC sign-ins.
Find SAML events with `GET /audit-events?type_prefix=saml.`
([monitoring.md](../operations/monitoring.md#audit-queries)).

## Stored data and upgrade note

Migration `0060_saml.sql` is expand-only: it adds `clients.protocol`
(`oidc` by default, or `saml`) and the tables `saml_signing_keys`,
`saml_service_providers`, `saml_idp_requests`, `saml_idp_sessions`,
`saml_connections`, `saml_broker_requests` and `saml_assertion_ids`
([data-inventory.md](../operations/data-inventory.md#saml)). The worker's
`retention.cleanup` task (every 5 minutes) deletes identity provider
requests and session participation records 1 hour after they expired or
ended, broker requests 1 hour after they expired and replay records when
they expire, and retires signing keys after their publication window.
The configuration document (configuration export and import) does not
include SAML applications, SAML connections or SAML signing keys, and leaves
the backing clients of SAML applications out; recreate them through the
SAML API. Older binaries in a mixed-version window have no SAML
routes; enable `saml.enabled` after the rollout.

## Not supported

None of these is advertised in metadata:

- **Both roles:** Artifact binding, SOAP, attribute queries, ECP, proxying
  and `Scoping` (`IDPList` is ignored), `AuthnContextDeclRef`, a requested
  `Subject`, metadata signing, fetching metadata from a URL or refreshing it
  automatically, SHA-1 or any other algorithm exception.
- **Identity provider:** HTTP-Redirect or Artifact ACS endpoints (HTTP-POST
  only); IdP-initiated logout and front-channel logout propagation; SOAP
  logout; notifying SAML service providers from `/oidc/logout`; choosing an
  organization per request. Persistent NameIDs belong to an application
  registration: deleting and recreating an application changes them.
- **Broker:** encrypted assertions and encrypted NameIDs (refused; the SP
  metadata publishes no encryption key); sending `AuthnRequest`s with the
  HTTP-POST binding (only HTTP-Redirect SSO endpoints are used);
  IdP-initiated (unsolicited) responses, which are **always refused**;
  upstream single logout (logout is local only, and OIDC logout reports the
  upstream logout as `unsupported` for SAML connections); signatures whose
  `KeyInfo` carries only a key value or key name (the X.509 certificate
  must be in `KeyInfo`, or `KeyInfo` omitted); management of SAML
  connections by organization administrators.
- SAML connections stay listed and offered when `saml.enabled` is later
  switched off; sign-ins through them then fail with `feature_disabled`.
  Disable the connections first.
- `goxmldsig` checks certificate validity dates, so an expired trusted
  certificate stops working (deliberate).

## Testing and interoperability status

SAML-010 asks for tests against multiple independent IdP and SP
implementations; Keycloak 26.8.0 is the first third-party one.

- `TestSAMLIdentityProvider`: both bindings, session reuse, `ForceAuthn`,
  `IsPassive`, request validation (SHA-1, wrong key, unregistered ACS,
  unknown SP, wrong destination, stale request, replay, DTD/XXE),
  `NameIDPolicy`, browser binding, the IdP-initiated policy, backing client
  guards, registration rules, organization binding and consent, MFA step-up
  through `RequestedAuthnContext`, unknown contexts, encrypted assertions
  with both key transports, and signed single logout with `PartialLogout`
  and cookie clearing.
- `TestSAMLKeyRollover`: the pending key in metadata, the activation gate,
  the forced-activation reason, the publication window of the retiring key.
- `TestSAMLBroker`: signed `AuthnRequest`, SP metadata, JIT provisioning with
  organization membership, response and assertion-ID replay, unsigned
  responses, an untrusted key, SHA-1, wrong audience, destination and
  recipient, `InResponseTo` mismatch, expired and future assertions, skew
  tolerance, response-only signatures, transient NameIDs, error statuses,
  five signature-wrapping shapes (an unsigned assertion before or after the
  signed one, a signed assertion hidden in `Extensions`, an assertion
  swapped under a signed response, an injected `EncryptedAssertion`),
  unsolicited responses, a wrong `RelayState`, DTD/XXE, duplicate IDs, a
  comment in the NameID, oversized messages, certificate overlap and
  removal, `require_signed_assertions`, repeated attribute elements (merged,
  except a repeated email attribute), trusted email linking, self-service
  linking, administration guards and diagnostics.
- The test SP and IdP are written directly on `etree`, `goxmldsig` and the
  Go standard library, independently of `internal/saml`, so messages,
  signatures, DEFLATE and encryption are checked against a second
  implementation. They are still written by the same project.
- **Keycloak 26.8.0** (`scripts/interop-keycloak.sh`, `make
  interop-keycloak`, weekly in the `interop.yml` workflow), in both roles,
  each side configured from the other's metadata: as service provider of a
  SAML application (signed HTTP-Redirect `AuthnRequest`, response and
  assertion signed over HTTP-POST, persistent NameID, attributes, an
  encrypted assertion, signed single logout over HTTP-Redirect) and as
  identity provider of a SAML connection (signed HTTP-Redirect
  `AuthnRequest`, signed response and assertion, persistent NameID, email
  attribute, repeated `Role` attributes, just-in-time provisioning), with a
  tampered and a replayed `AuthnRequest` and SAML response refused. That run
  found the repeated-attribute refusal fixed above. Settings that matter on
  the Keycloak side and what is not covered:
  [interoperability.md](interoperability.md#keycloak-2680-protocol-profiles).
- **Not tested (QA-004):** other products (for example Shibboleth,
  SimpleSAMLphp, Okta, Microsoft Entra ID, ADFS) and other Keycloak
  releases. Treat compatibility with them as unverified and test it in your
  environment.

Threat analysis: [threat-models/saml.md](../threat-models/saml.md).
