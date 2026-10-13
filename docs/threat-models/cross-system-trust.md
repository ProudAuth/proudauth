# Threat model: cross-system trust surfaces

Scope: features that extend trust across a system boundary or across tenants:
the OIDC session-management iframe (OIDC-014), the shared-signals transmitter
and receiver (AUD-016, ADV-007), the container-registry token bridge
(ADV-010), passkey attestation trust and related origins (PASS-009,
PASS-010), federation transfer (FED-016), organization relationships and
partner project access (TEN-021, TEN-020), authentication flow revisions
(AUT-019), historical entitlement evidence (ADV-011) and external risk
signals (ADV-012). The rest of the
system is in [system.md](system.md). Like that document, this reflects code
review, not an independent assessment (SEC-018 has not been done).

## Assets and boundaries

| Asset | Where |
| --- | --- |
| Browser session state readable by scripts (`pa_opbs`) | Cookie on `/realms/{realm}/` |
| Security events about users, and the push `Authorization` values of receivers | `ssf_events` (signed tokens), `ssf_streams.authorization_ciphertext` (AEAD) |
| Trust in outside transmitters: push secrets, keys, action policy | `ssf_transmitters` (secret as digest) |
| Registry access | Registry tokens (JWT, realm signing keys), registry service rules |
| Authenticator trust metadata | Operator MDS3 BLOB, `webauthn_trusted_authenticators` |
| Account links | `external_identities`, transfer maps |
| Cross-organization authority | `organization_relationships`, `project_grants`, project role assignments |
| Sign-in policy history | `auth_flow_revisions` |

| Boundary | Outside party | Enforcement |
| --- | --- | --- |
| RP page → check-session iframe | Any web origin that frames the iframe | `postMessage` answers only to origins registered for the named client; state recomputed with the sender's origin |
| SSF receiver → stream API | Machine clients | Admin-audience client-credentials token; `realm.ssf_streams.manage`; streams owned by the calling client |
| ProudAuth → SSF push endpoints | Receiver HTTP servers | Webhook egress policy, residency allowlist, `https` in production |
| Outside transmitter → push endpoint | Registered transmitters | Push secret, signature, issuer, audience, age, replay record, explicit action policy |
| Registry client → token endpoint | Docker clients, CI systems, anonymous users | HTTP Basic with a resource-bound credential or client secret; permission and scope checks per action |
| Organization → organization | Other tenants of the realm | Explicit relationships, owner-issued project grants, delegated role subsets |

## Threats

| Threat | Mitigation (code) | Tests | Residual |
| --- | --- | --- | --- |
| I: script-readable session state (OIDC-014) | Off by default (`sessions.check_session_iframe`); `pa_opbs` is a keyed digest of the session ID under the lookup key, never the session secret; scoped to the realm path; the iframe page allows only its own hashed inline script and `connect-src 'self'` (`httpapi/checksession.go`, `session/checksession.go`) | `TestCheckSessionIframe` | The cookie is `SameSite=None` and not `HttpOnly` by necessity: any script running on the IdP origin under the realm path could read it. It identifies the browser session to such a script, though it is no credential |
| S/I: an origin probing whether a user is signed in | The iframe answers `error` to origins not registered for the client (allowed origins or redirect-URI origins); `session_state` includes the RP origin and a fresh salt, so a value copied to another origin never reads `unchanged` | `TestCheckSessionIframe` (origin check and recomputation, in Go; the script itself is not run in a browser) | An origin registered for a client can poll the iframe with its own `session_state` values, which is the purpose of the extension. Browsers that partition third-party cookies make every check `changed`; server-side revocations are not visible to the iframe at all (use back-channel logout) |
| I: transmitter sends events about users unrelated to the receiver (AUD-016) | Default scope `client_users`: only users with an authorization grant for the receiver client; `listed` narrows further; `all` only by an administrator; adding subjects never widens the scope and answers alike for unknown subjects; pairwise clients get their pairwise `sub` (`internal/ssf/ssf.go`) | `TestSharedSignalsTransmitter` | Grants count while their rows are retained, including revoked grants (up to `privacy.session_retention` after they ended). An administrator-set `all` scope sends events about every user to that receiver. `identifier-changed` tells the receiver that an identifier changed (not the value) |
| S: a client manages streams it should not | Stream API requires a service-principal token for the admin audience with `realm.ssf_streams.manage`; human administrator tokens are refused; streams are filtered by the calling client | `TestSharedSignalsTransmitter` (human admin, client without the permission, other receiver) | The permission is realm-wide: a receiver with it can open streams about its own users without further review; audit `ssf.stream.created` is the review point |
| T/S: token confusion with security event tokens | `typ: secevent+jwt`, `aud` = the receiver's `client_id`, `events` claim | `TestSharedSignalsTransmitter` (typ, signature, audience) | The realm's ordinary signing keys sign them; receivers and resource servers must check `typ` |
| I: receiver push credentials leak | `authorization_header` is write-only, AEAD-encrypted and bound to the stream; never returned or logged | — | Readable by anyone holding the root keys and database |
| S: forged inbound events (ADV-007) | Per-transmitter push secret (digest), single signature with RS256/PS256/ES256/EdDSA keys of the registered set, `iss` = registered issuer, `aud` = push endpoint, `iat` age and future-skew limits, `jti` replay record (`internal/ssf/receiver.go`) | `TestSharedSignalsReceiver` | A compromised transmitter (or its signing key and push secret) can trigger every action its policy allows for the subjects it can name |
| E: an outside signal escalates or locks out | Explicit action policy per event type (default record only); `account-enabled` and `identifier-changed` can only be recorded; protected accounts are never suspended (sessions revoked instead); `iss_sub` maps only through the transmitter's federation connection, `email` only to verified addresses and only when allowed | `TestSharedSignalsReceiver` | `suspend_user` and `mark_password_compromised` let a trusted transmitter deny service to ordinary accounts; review action policies like any other trust decision |
| I: subject enumeration through the push endpoint | Unknown subjects are answered `202` like accepted events; records keep no token or subject identifiers | `TestSharedSignalsReceiver` | Timing is not equalized |
| S/E: registry tokens beyond a principal's rights (ADV-010) | Credentials must be minted for the registry's resource (or a machine client's grant to it); each action needs the rule's permission (in its organization or realm-wide) and the credential's scope; organization-bound credentials reach only that organization's rules; ungranted actions are omitted (`internal/registry/registry.go`) | `TestRegistryTokenBridge` | First matching rule wins: an early broad pattern decides for everything it matches. `anonymous_pull` exposes matching images to anyone. Tokens are bearer tokens valid up to `token_ttl_seconds` after revocation of the credential. Machine-client secrets and API keys are tested; a real registry is not |
| S: registry accepts other realm tokens | Registry tokens carry `aud` = service name and an `access` claim | — | The registry trusts every token the realm keys sign for that audience; keep service names distinct from API resource audiences |
| S: untrusted authenticator models (PASS-009) | Optional trusted attestation against operator FIDO metadata (verified against the FIDO root or a configured root at startup) or realm trusted authenticators; status reports checked; allow/block lists at registration and sign-in (`internal/passkey/trust.go`) | `TestPasskeyAttestationTrust` | Without trusted attestation the AAGUID is self-reported. The metadata BLOB is only as fresh as the operator keeps it, and is read at startup only. Real metadata and real authenticators are not tested |
| S: passkey use from foreign origins (PASS-010) | Related origins need the operator switch, an explicit RP ID and an explicit list (at most 20 origins, five registrable domains); no fallback | `TestPasskeyAdvancedCapabilities` | Every listed origin can run ceremonies for the realm's passkeys: a compromised related origin can phish assertions as the RP origin could |
| E: account takeover through relinking (FED-016) | No email matching; per-entry analysis with collision reporting; second administrator approves; apply re-analyses under lock and moves only `ready` entries; upstream tokens dropped (`internal/federation/transfer.go`) | `TestFederationTransfer` | The map's correctness is the administrators' responsibility: an approved entry that pairs one person's source subject with another person's target subject gives that other person the account. Two colluding administrators can approve any map |
| E: implicit cross-tenant access (TEN-021, TEN-020) | Relationships grant nothing; project grants only by the owner organization, only to related organizations (unless a realm administrator), only a subset of the project's roles; partner assignments only to the partner's active members, removed with the grant or the membership; organization-authority permissions need an MFA session (`internal/organization/relationships.go`, `internal/application/projectgrants.go`) | `TestOrganizationRelationshipsAndPartnerProjects`, `TestProjectGrantExpiry` | A grant past its `valid_until` is ended by the worker's expiry task (assignments removed, authorization revisions incremented, `project.grant.expired`), so it lasts until the next run of that task; ending a relationship leaves existing grants in place |
| T: silent weakening of sign-in policy (AUT-019) | Every flow change becomes an audited, published revision; bypass errors block publication, `PUT /settings` and imports; stale drafts are refused; warnings must be acknowledged in the revision API (`internal/realm/flowrev.go`) | `TestAuthenticationFlowRevisions`, `internal/realm/flowrev_test.go` | The analysis is conservative and rule-by-rule: overlap by several earlier rules is only a warning. `PUT /settings` and imports do not ask for warning acknowledgement |
| S/E: a risk service, or an attacker who reaches it, steers sign-in (ADV-012) | Risk signals enter only through `authentication.risk` hooks: signed requests, egress and residency policy, a bounded timeout, a versioned contract (`ProudAuth-Hook-Version`). Answers are only `low`/`medium`/`high` with reasons; anything else is a failed call. A level can only make a flow rule match: deny, challenge, review or a stronger factor; `allow` never removes requirements, and risk never reaches authorization decisions ([authentication-flows.md](../protocols/authentication-flows.md#risk-integrations-adv-012)) | `TestRiskNeverOverridesDeny` (`internal/realm/flowrev_test.go`), `TestAuthenticationFlowPolicy`, `TestAuthenticationFlowRevisions` | A compromised risk service can push every sign-in to `high` (denial of service, extra challenges) or keep `low` where a realm's rules relax on low risk; it can never lift a `deny` placed before the risk rules or skip MFA |
| I: risk hooks as a data channel (ADV-012) | Requests carry IDs, the primary method, the network reduced to /24 or /48, the remembered-device flag and the recent failure count; no credentials, tokens, email addresses or profile data | `TestAuthenticationFlowPolicy` (hook request contents) | The hook operator learns when and from which network each user signs in; treat it as a processor of sign-in metadata |
| F: risk service down or slow (ADV-012) | Deterministic fallback: a missing signal applies restrictive rules (unless `on_missing_signal: skip`) and never satisfies `allow`; with several hooks the highest answered level is a lower bound | `TestAuthenticationFlowPolicy`, `TestRiskNeverOverridesDeny` | An outage of the risk service turns every risk-gated sign-in into its restrictive path |
| I: investigation queries as a disclosure channel (ADV-011) | `realm.audit.read`, MFA session, required reason, audited reconstruction (`internal/authorization/history.go`) | `TestHistoricalEntitlements` | No second-person approval; the result is evidence for the auditor and should be handled as such |

## Not covered

- Real browsers running the check-session script, real SSF transmitters and
  receivers, real container registries, hardware authenticators and real
  FIDO metadata have not been tested
  ([interoperability.md](../integrations/interoperability.md#untested-claims)).
- The SSF push endpoint, the iframe's origin check and the registry token
  endpoint have no rate budget of their own; only the general request limits
  (body size, load shedding) apply. The credentials they accept are
  high-entropy secrets, so guessing is not the concern; volume is.
