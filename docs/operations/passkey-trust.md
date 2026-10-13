# Passkey attestation, authenticator restrictions and advanced WebAuthn options

This page covers the passkey policies a realm can set beyond the basics
(PASS-009, PASS-010): attestation, trusted authenticator metadata,
authenticator allow and block lists, WebAuthn Level 3 related origins and the
CTAP 2.1 `credProtect` extension. Passkey sign-in itself is described in
[headless-authentication.md](../protocols/headless-authentication.md).

Code: `internal/passkey/trust.go`, `internal/passkey/passkey.go`,
`internal/httpapi/webauthn_trust.go`, `internal/configuration/webauthn.go`,
migration `0059_webauthn_trust`. Ceremonies are verified by the
`go-webauthn` library. Tests: `TestPasskeyAttestationTrust` (a software
authenticator producing `packed` attestation under a test vendor CA) and
`TestPasskeyAdvancedCapabilities` and `TestPasskeyFIDOMetadata` (a metadata
BLOB signed under a test metadata root; a BLOB with a bad signature, or
checked against the FIDO production root, does not load)
(`tests/e2e/passkey_trust_test.go`). No hardware or platform authenticator
and no real FIDO Alliance BLOB has been used in tests
([interoperability.md](../integrations/interoperability.md#untested-claims)).

Realm policy members live under `webauthn` in the realm settings
(`PUT /api/v1/realms/{realm}/settings`, `realm.settings.write`). Deployment
keys live under `webauthn` in the configuration file
([configuration.md](configuration.md#webauthn)).

## Attestation (PASS-009)

| Realm policy | Default | Effect |
| --- | --- | --- |
| `webauthn.attestation` | empty (`none`) | Attestation conveyance requested at registration: `none`, `indirect`, `direct` or `enterprise`. The default asks for none, so registering a passkey discloses nothing about the authenticator model |
| `webauthn.require_trusted_attestation` | `false` | Refuse registrations whose attestation does not chain to trusted metadata. Needs `attestation` `direct` or `enterprise` (`422` on `webauthn.require_trusted_attestation` otherwise) |

With `require_trusted_attestation`, a registration succeeds only when:

1. the attestation statement carries a certificate chain (attestation types
   basic full, AttCA or AnonCA); `none` and self attestation are never
   trusted;
2. trusted metadata exists for the authenticator's AAGUID (a zero AAGUID never
   matches);
3. the chain verifies to one of that entry's root certificates; and
4. for FIDO metadata entries, the status reports do not mark the model
   compromised or revoked (the library's list of undesired statuses).

Otherwise registration answers `422` with `credential: attestation_not_trusted`
and records `mfa.webauthn.enrollment_failed` with that reason. When no trusted
metadata is configured at all (no operator file and no realm entries),
registration fails with `feature_disabled`.

**Trusted metadata** has two sources; for an AAGUID that both name, the
realm's entry wins:

- **Operator FIDO metadata.** `webauthn.metadata_file` names a FIDO Metadata
  Service (MDS3) BLOB that the operator downloads and refreshes; **the server
  never fetches metadata itself**. It is verified at startup against the FIDO
  Alliance root certificate, or against `webauthn.metadata_root_file` (a PEM
  root) for a private metadata service. A missing, unreadable or invalid file
  stops startup. Entries that fail to parse are skipped. The BLOB is read
  only at startup: refreshing it means replacing the file and restarting.
- **Realm trusted authenticators**, managed by realm administrators:

  | Method and path (under `/api/v1/realms/{realm}`) | Permission | Effect |
  | --- | --- | --- |
  | `GET /webauthn/trusted-authenticators` | `realm.settings.read` | List |
  | `POST /webauthn/trusted-authenticators` | `realm.settings.write` | `{"aaguid", "description", "root_certificates"}`: a lower-case, non-zero AAGUID; a description of 1–200 characters; 1 to 10 PEM certificates, one per entry, each an unexpired CA certificate. `201`; `409` for an AAGUID already trusted; at most 200 per realm (`409`) |
  | `DELETE /webauthn/trusted-authenticators/{id}` | `realm.settings.write` | `204`. Passkeys registered under the entry keep working; new registrations of that model need other trusted metadata |

  Audit (category `security`): `webauthn.trusted_authenticator.added`
  (AAGUID, number of roots) and `.removed`.

Each passkey records whether its attestation was trusted
(`attestation_trusted`) and where the trust came from (`attestation_source`:
`realm` or `fido_metadata`). Passkey lists show `aaguid`,
`attestation_trusted` and `attestation_format`, and the
`mfa.webauthn.enrolled` audit event records `attestation_trusted` and
`attestation_source`. Turning on `require_trusted_attestation` later does not
invalidate existing passkeys: they keep working until removed. Find them by
`attestation_trusted: false` in the passkey lists and ask their owners to
re-register.

## Authenticator restrictions (PASS-009)

| Realm policy | Effect |
| --- | --- |
| `webauthn.allowed_aaguids` | Only these authenticator models may register and sign in. A zero AAGUID (authenticators that do not name their model, which includes most synced passkeys) is refused unless `00000000-0000-0000-0000-000000000000` is listed |
| `webauthn.blocked_aaguids` | These models may not register or sign in |

The two lists are exclusive (`422` on `webauthn.blocked_aaguids` when both are
set); each holds at most 200 lower-case AAGUIDs. Both apply **at registration
and at every sign-in**: blocking a model takes effect at the next sign-in of
its passkeys, and an allow list that leaves a model out locks its users out
of passkey sign-in. At registration the refusal is `422` with
`credential: authenticator_not_allowed`. At sign-in the ceremony fails, counts
as a proof failure of the transaction, and is audited as
`mfa.webauthn.failed` with reason `authenticator_not_allowed`.

Without trusted attestation an AAGUID is **self-reported** by the
authenticator, so the lists are advisory against a modified or software
authenticator; combine them with `require_trusted_attestation` when the
restriction must hold.

## Related origins (PASS-010)

WebAuthn Level 3 related origin requests (§5.11) let a passkey registered for
the realm's RP ID be used from origins outside that domain.

- The operator must allow them: `webauthn.related_origins: true` in the
  configuration file. Without it, a realm policy that sets related origins is
  refused (`422`, "related origins are not enabled by the operator").
- The realm must set an explicit `webauthn.rp_id` (`422` on `webauthn.rp_id`
  otherwise) and lists the origins in `webauthn.related_origins`: at most 20
  `https://host[:port]` origins without path, query or fragment. Together with
  `webauthn.origins` they may span at most five registrable domains (`422`),
  the limit clients apply.
- The server then accepts ceremonies from those origins and serves
  `GET https://<rp_id>/.well-known/webauthn` with
  `{"origins": [...]}`: the RP origins and related origins of every active
  realm whose RP ID is the request's host and that lists related origins
  (`Cache-Control: public, max-age=300`). Any other host, and every host while
  the operator switch is off, gets `404`. The realm is chosen by the `Host`
  header, so the RP ID host's `/.well-known/webauthn` must reach ProudAuth
  with its original `Host`. With `server.host_policy: strict` the path is
  served only on the public origin's host (any other host, custom domains
  included, gets `421`), so related origins then work only when the RP ID is
  the public origin's host.

There is no permissive fallback: a browser without Level 3 support refuses
the cross-origin ceremony, and the server never accepts an origin that is not
listed. Turn this on only for audiences whose browsers support it.

## Credential protection (PASS-010)

| Realm policy | Effect |
| --- | --- |
| `webauthn.credential_protection` | Requests the CTAP 2.1 `credProtect` extension at registration with policy `userVerificationOptionalWithCredentialIDList` or `userVerificationRequired` |
| `webauthn.enforce_credential_protection` | `true`: an authenticator that does not apply the requested policy is refused; `false` (default): it is accepted without it. Needs `credential_protection` (`422`) |

## Other extensions

Registration requests only `credProps` (to learn whether the credential is
discoverable) and, when configured, `credProtect`. Extension outputs the
server did not request make the ceremony fail. Not supported: PRF and
`hmac-secret`, `largeBlob`, `credBlob`, `minPinLength`, `uvm`, `appid`
(U2F migration), payment, and ceremonies in cross-origin iframes (top-origin
checks).

## Changing these settings safely

- Realm `webauthn` changes are ordinary policy changes: versioned, audited as
  `realm.policy.updated` and visible in the configuration history.
- Deployment `webauthn.*` keys are classified as security-boundary changes by
  `identity-cli config-diff` ([configuration.md](configuration.md#reviewing-a-change)).
- Before adding an allow list or blocking a model, check which models your
  users hold (`aaguid` in passkey lists) so nobody is locked out without a
  fallback factor.
