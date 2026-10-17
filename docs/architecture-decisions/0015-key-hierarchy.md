# 0015. Keys: root keys, HKDF purpose keys, AES-256-GCM, wrapped signing keys

**Status:** Accepted

## Context

Signing keys must survive restarts (DEP-008), recoverable secrets must be
encrypted with authenticated encryption and versioned keys (SEC-010), and
encryption, signing, webhook and pepper keys must be separated. No paid KMS may be
mandatory (DEP-016, OSS-003).

## Decision

- **Root keys**: operators supply one or more versioned 256-bit root keys
  (`keys.root_keys`, hex or base64, via secret references such as `file:`,
  `env:`, `cred:` or `vault:`; literal values are rejected in production, as are
  literal pepper and signing-wrap keys). `keys.active_version` selects the key for new
  encryptions; older versions stay available for decryption.
- **Purpose keys**: derived per version with HKDF-SHA256
  (salt `proudauth/hkdf-salt/v1`, info `proudauth/v1/<purpose>`). Purposes:
  `data-encryption`, `signing-key-wrap`, `webhook-secrets`, `otp-verifier`,
  `password-pepper`, `pairwise-subject`, `lookup-digest`. Operators may supply a
  dedicated root for `password-pepper` (`keys.pepper_keys`) or `signing-key-wrap`
  (`keys.signing_wrap_keys`); for a dedicated purpose the highest version is active.
- **Encryption**: AES-256-GCM with a random 96-bit nonce; ciphertext layout
  `0x01 | key version (uint32) | nonce | sealed box`; associated data binds the
  ciphertext to its row (for example `totp:<credential id>`,
  `signing-key:<kid>`, `webhook:<subscription id>`).
- **Low-entropy codes** (OTP challenges, recovery codes) are stored as keyed
  HMAC-SHA256 verifiers with their key version.
- **Signing keys**: generated per realm (RSA 3072, ECDSA P-256 or Ed25519),
  stored as PKCS#8 encrypted under the signing-key-wrap key, with lifecycle states
  `pending → active → retiring → retired` and `compromised`. Only public JWKs are
  published.
- **Pepper**: when `keys.pepper_keys` is set, passwords are HMAC-keyed before
  Argon2id and the pepper version is stored in the verifier.
- `identity-cli doctor` prints a non-secret keyring fingerprint (HMAC under the
  active lookup key) to detect a restore with the wrong keys.
- **KMS envelope (Update 2026-10, DEP-016)**: root, pepper and signing-wrap
  keys may be stored wrapped by an external KMS or HSM and referenced as
  `kms:<file>`. Each process unwraps them once at start-up by running the
  operator's `keys.kms.command` (no shell; wrapped key on standard input,
  unwrapped key as hex or base64 on standard output) and then uses them in
  software exactly as before. No KMS is required or built in.

## Alternatives considered

- **Per-realm root keys**: more isolation, more custody burden; not implemented.
- **Keys operated inside a KMS or HSM** (signing and decryption by the
  device, keys never in process memory): not implemented. It would need a
  signing-provider interface for every algorithm, per-request device latency
  on token issuance and a re-encryption path for existing ciphertext. The
  envelope above was chosen instead (DEP-016 as unwrap-at-start): it protects
  keys at rest and controls who can start the service, but the keys are in
  process memory while it runs and must not be described as hardware-protected
  in use.
- **A built-in client for one cloud KMS**: rejected; it would make one
  vendor's service a dependency (OSS-003), while a command covers any KMS
  with a command-line client.

## Consequences

- Losing every root key version makes TOTP seeds, webhook secrets, signing keys,
  encrypted notification payloads and job results unrecoverable. Losing the
  pepper makes peppered password verifiers unusable. Back up keys separately from
  the database ([docs/operations/keys.md](../operations/keys.md)).
- There is no re-encryption tool. An old root version can be removed only when
  nothing still references it (see the root-key rotation procedure).
- Values derived from the *active* version change when `keys.active_version`
  changes: pairwise subjects not yet stored (issued values are kept in
  `pairwise_subjects` since migration `0018`), the CSRF tokens of in-flight browser
  transactions, pagination cursors and the keyring fingerprint.
- Audit batch signatures (Update 2026-10) use an Ed25519 key derived from the
  `signing-key-wrap` purpose key of a given version; removing that version makes
  older batch signatures unverifiable.

- With the KMS envelope, an attacker who can read a running process's memory,
  or run the unwrap command with the service's KMS credentials, still obtains
  the keys; the KMS's access policy and audit log are the controls, and
  revoking KMS access stops only future starts.

## Migration implications

Ciphertext and verifier formats carry their key version. The KMS envelope
changes only where key material comes from, not its value, so existing data
and the keyring fingerprint are unaffected when a key moves into the KMS.
Operating keys inside an HSM later would still have to read version-tagged
software-key ciphertext until it is rewrapped.

## Related requirement IDs

SEC-010, DEP-006, DEP-008, DEP-016, CRED-009, MFA-001, PWDLESS-007, TOK-011, TOK-012, TOK-013, OPS-005, §37.1

## Updates

**Update — 2026-10-18.** Recorded under the dated-update rule
([README](README.md#changing-a-decision)). The **KMS envelope** item (DEP-016,
`TestKMSUnwrap`) was added to the Decision in place in 2026-10, together with
the alternatives and the consequence that refer to it; the consequence on
audit batch signatures was added at the same time. The envelope changes only
where root, pepper and signing-wrap keys come from at start-up; how keys are
derived and used is unchanged.
