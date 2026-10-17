# SAML threat model

Scope: the SAML 2.0 identity provider (SAML applications, APP-018) and broker
(SAML connections, FED-014) described in
[docs/integrations/saml.md](../integrations/saml.md). Method as in
[system.md](system.md): assets, trust boundaries and STRIDE, each mitigation
naming the code and the test that exercises it. This is the project's own
code review, not an independent assessment (SEC-018). Both SAML roles are
tested against the project's own test SP and IdP and, weekly in the `interop`
workflow (`scripts/interop-keycloak.sh`), against one third-party product,
Keycloak 26.8.0, in the profiles and with the gaps listed in
[interoperability.md](../integrations/interoperability.md#keycloak-2680-protocol-profiles).
No other SAML implementation (for example Shibboleth, SimpleSAMLphp or ADFS)
has been exercised, and no SAML conformance suite has been run (SAML-010,
QA-004).

## Assets

| Asset | Where | Why it matters |
| --- | --- | --- |
| SAML signing private keys | `saml_signing_keys` (encrypted with the signing-wrap key, associated data `saml-signing-key:<id>`) | Forge assertions to every SAML application of the realm, and `AuthnRequest`s from the broker |
| Trusted certificates of SAML connections | `saml_connections` | Whoever holds a trusted IdP key can sign in as any user of that connection |
| Registered ACS URLs, entity IDs and SP certificates | `saml_service_providers` | Decide where assertions go and whose requests are believed |
| Pending requests and browser bindings | `saml_idp_requests`, `saml_broker_requests` (digests of `RelayState`, `state` and the `pa_saml` secret; encrypted PKCE verifier) | Correlation and single use |
| Persistent NameIDs | `pairwise_subjects` (sector `saml:<application id>`) | Stable per-application identifiers; correlation if shared |
| Session participation | `saml_idp_sessions` (NameID digest only) | Single logout |

## Trust boundaries

| Boundary | Inside | Outside | Enforcement |
| --- | --- | --- | --- |
| Public metadata | — | Anyone | `I/saml/metadata`, `I/saml/sp/{connection}`: read-only, certificates only |
| Public protocol initiation (IdP) | — | Any browser or SP | `I/saml/sso`, `I/saml/idp-initiated`, `I/saml/slo`: issuer, signature and ACS validated before any state; nothing is sent to an unregistered URL |
| Transaction-bound (IdP continuation) | The browser that started the request | Other browsers | `pa_saml` secret, single-use request, PKCE verifier held by the server |
| Transaction-bound (broker ACS) | The pending transaction | Other browsers, unsolicited senders | `InResponseTo` and a 256-bit `RelayState` secret, single use, then the transaction's continuation |
| SAML counterparty | Registered SPs and configured IdPs | Everyone else | Exact entity IDs, pinned certificates, registered ACS URLs; metadata uploaded, never fetched |
| Administration | Realm administrators | Organization administrators, users | `realm.clients.*`, `realm.identity_providers.*`, `realm.keys.*` from an MFA session |

## STRIDE

| Threat | Mitigation (code) | Tests | Residual |
| --- | --- | --- | --- |
| T/E: XXE, entity expansion, SSRF through DTDs or external references | No DTD at all: `DOCTYPE` and every markup declaration are refused before a tree is built; strict `encoding/xml`; unknown entity references refused; metadata is uploaded and nothing is ever fetched (`saml/xml.go Parse`) | `TestParserRefusals`; DTD/XXE cases in `TestSAMLIdentityProvider` and `TestSAMLBroker` | — |
| D: oversized or deeply nested documents, compression bombs | Body bounded by `limits.max_body_bytes`; decoded and inflated size by `saml.max_message_bytes` (limited DEFLATE reader); depth 32, 4096 elements, 64 attributes per element; attribute counts and value lengths (`saml/binding.go`, `xml.go`) | `TestRedirectBinding` (inflation bound), oversized case in `TestSAMLBroker` | Each request still parses up to the configured bound |
| S/T: signature wrapping (XSW family) | Only the element returned by `goxmldsig` is consumed, parsed again from the digested canonical bytes; exactly one assertion, as a direct child of the response; exactly one `Signature` referencing the element, as its direct child, with exactly one `#ID` reference; duplicate IDs anywhere refused; a response-only signature reads the assertion from the verified response (`saml/dsig.go`, `federation/saml_response.go`) | `TestSignVerifyAndWrapping`; five wrapping shapes and duplicate IDs in `TestSAMLBroker` | Relies on `goxmldsig` v1.6.1 for canonicalization and verification; a flaw there affects both roles |
| T: NameID truncation through comments or split text nodes | Comments and processing instructions refused; text is the concatenation of all character data; elements with children where text is expected are malformed | Comment-in-NameID case in `TestSAMLBroker` | — |
| T: algorithm downgrade | RSA-SHA256/384/512 and SHA-256/384/512 digests only; no `WithComments` canonicalization; no SHA-1 switch or per-counterparty exception; encryption AES-GCM with RSA-OAEP only, CBC and PKCS#1 v1.5 refused (SAML-009) | `TestSHA1Refused`; SHA-1 cases in both e2e tests; encryption with both key transports | `rsa-oaep-mgf1p` uses SHA-1 inside OAEP padding (not a collision-resistance use) |
| S: forged assertion at the broker | Signature against the connection's pinned certificates (any of up to 4); issuer, audience (every `AudienceRestriction` must contain the SP entity ID), destination, recipient, bearer confirmation, time windows; unknown conditions refused; encrypted assertions refused (`federation/saml_response.go`) | `TestSAMLBroker` (untrusted key, wrong audience, destination and recipient, expired and future, unsigned) | Certificates expire silently into refusal; there is no metadata refresh to pick up a new IdP key automatically |
| S: replay of a response or assertion | Single-use request (`InResponseTo` plus a `RelayState` secret stored as a digest, 10 minutes); assertion IDs recorded per connection until expiry (`saml_assertion_ids`); IssueInstant window. IdP side: each request ID accepted once per application; the continuation is single use and bound to the browser | Response and assertion-ID replay in `TestSAMLBroker`; request replay in `TestSAMLIdentityProvider` | — |
| S: unsolicited response, login CSRF at the broker | `InResponseTo` is required; unsolicited responses are always refused; a correlated response completes only the transaction's own continuation | Unsolicited and wrong `RelayState` cases in `TestSAMLBroker` | — |
| S: login CSRF through IdP-initiated SSO (SAML-007) | Off by default (`403`); when enabled per application, the destination is the default ACS and `RelayState` only the registered value | IdP-initiated policy in `TestSAMLIdentityProvider` | When enabled, a forced sign-in into the user's own account at that SP remains possible |
| I: assertion theft through a leaked continuation URL | `pa_saml` binding secret, single-use request, internal code redeemed with a server-held PKCE verifier and bound to the transaction, client and continuation URI (`saml/idp/sso.go`) | Browser-binding case in `TestSAMLIdentityProvider` | — |
| S/I: open redirect or assertion delivery to an attacker's URL | ACS chosen only from the registry (exact URL or index, HTTP-POST only); every refusal before ACS validation is a local `400`; the auto-post form's action is always a registered ACS; IdP-initiated `RelayState` only from the registration | Unregistered ACS and unknown SP cases in `TestSAMLIdentityProvider` | `form-action` is not set in the form's CSP (some browsers apply it to the SP's later redirects) |
| E: account takeover by email | Broker email is verified only with `trust_email_verified`; `trusted_verified_email` linking also needs `allowed_email_domains`; otherwise proof of control of the local account (FED-005). A connection's email or subject attribute that appears twice in an assertion is refused as ambiguous (`duplicate_attribute`; other repeated attributes are merged into one multi-valued attribute, which never fills a single-valued field). The IdP releases only verified emails, and protected attribute names cannot carry static or user-editable values | Trusted email linking and repeated attribute elements in `TestSAMLBroker`; registration rules in `TestSAMLIdentityProvider` | An IdP marked `trust_email_verified` is trusted for every address in the allowed domains |
| E: tenant crossing | Applications bound to an organization deliver assertions only to its active members and apply its policies; organization-bound connections cannot sign in to other organizations (FED-006) | Organization binding in both e2e tests | Only realm administrators manage SAML; organization administrators cannot scope a connection themselves |
| E: SAML backing client used as an OAuth client | `/oauth/authorize` refuses it; OAuth client authentication always fails; `PUT /clients/{id}` refuses it (`application/saml_clients.go`, `clientauth.go`) | Backing-client guards in `TestSAMLIdentityProvider` | — |
| S/D: forged logout | `LogoutRequest`s must be signed with the application's registered key, name sessions issued to it, and pass the time window; partial logout is reported as `PartialLogout`, never claimed universal | Signed single logout in `TestSAMLIdentityProvider` | Other SAML applications and OIDC clients without back-channel logout are not notified |
| S: signing-key compromise | Pre-published rollover; forced activation with a reason (category `emergency`); keys encrypted at rest; one key set per realm | `TestSAMLKeyRollover` | A compromised key stays trusted by counterparties until they refresh metadata or remove its certificate; the key set serves both SAML roles of the realm |
| T: clock manipulation | Per-counterparty skew bounded by `saml.max_clock_skew`; `IssueInstant` windows | Skew tolerance in `TestSAMLBroker` | — |
| I: correlation across applications | Persistent NameIDs differ per application (`sps_` values from a keyed HMAC); `transient` per assertion | `TestSAMLIdentityProvider` | `unspecified` releases the account's immutable ID |
| R: unaudited SAML activity | `saml.request.rejected`, `saml.response.rejected` (with reasons), `saml.assertion.issued`, `saml.logout.completed`, application and key events | Both e2e tests | Rejections before the realm is resolved are not audited |

## Residual risks and open items

- Interoperability is tested against one third-party product, Keycloak
  26.8.0, in both roles (`scripts/interop-keycloak.sh`), and against no
  other; no conformance suite has been run. The test SP and IdP are
  independent of `internal/saml` but are written by this project.
- No metadata signing on either side and no metadata fetching: certificate
  changes of counterparties are manual and can be missed.
- Logout is a declared subset (SAML-008); sessions at other service
  providers survive a SAML logout.
- `goxmldsig` is the only XML signature implementation; its advisories must
  be tracked (`make vuln`).
