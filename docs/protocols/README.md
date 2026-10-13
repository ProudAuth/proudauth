# Protocols

| Document | Contents |
| --- | --- |
| [oauth-oidc-profile.md](oauth-oidc-profile.md) | Endpoints, client types and authentication, client environments and claim mappings, authorization request rules, `prompt` and the `claims` parameter, grants, PKCE, PAR, DPoP, resource indicators, token exchange, introspection, revocation, UserInfo, logout, discovery, and what is not supported |
| [tokens.md](tokens.md) | Token formats and prefixes, claim sets per `token_kind`, ID and logout tokens, verification algorithm, signing keys and JWKS |
| [headless-authentication.md](headless-authentication.md) | The authentication transaction API: browser vs headless continuation, next actions, steps, remembered devices, errors, registration and its approval queue, guest identities, password reset, device flow, upstream providers |
| [identifiers.md](identifiers.md) | Internal ID format, canonicalization rules for emails, usernames, phones, slugs and domains, organization aliases and email-domain routing, and subject aliases after account merges |
| [compatibility.md](compatibility.md) | Versioned surfaces, what changes without client work, the deprecation process and window, security exceptions, events, SDKs and configuration compatibility (API-013); declared protocol profiles (session management, shared signals, registry tokens, related origins) and the P3 capabilities not offered, with reasons |
| [authentication-flows.md](authentication-flows.md) | Versioned authentication flow definitions: drafts, reachability and bypass analysis, simulation, publishing and rollback (AUT-019); risk signals from external systems through risk hooks (ADV-012) |
| [response-security.md](response-security.md) | Encrypted ID tokens, signed and encrypted UserInfo, JWT-secured authorization responses (JARM): client options, algorithms, key selection, errors and discovery (TOK-020, OIDC-013, ADV-002) |
| [mutual-tls.md](mutual-tls.md) | Mutual TLS: the certificate listener or trusted proxy header, realm trust anchors and CRLs, `tls_client_auth` and `self_signed_tls_client_auth`, certificate-bound tokens, and X.509 sign-in with certificate bindings (TOK-019, MCH-014, PROV-016) |

Custom APIs live under `/api/v1/realms/{realm}`; protocol endpoints under
`/realms/{realm}` follow their RFCs' formats. Event payload schemas for webhooks are
described in [docs/integrations/webhooks.md](../integrations/webhooks.md).
The SAML 2.0 identity provider and broker endpoints under
`/realms/{realm}/saml/` are described in
[docs/integrations/saml.md](../integrations/saml.md).
