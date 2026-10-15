# Keys: custody, signing-key rotation and root-key rotation

Design: [ADR 0015](../architecture-decisions/0015-key-hierarchy.md). Code:
`internal/keys/keyring.go` (root keys and purpose keys), `internal/token/keys.go`
(signing-key lifecycle), `internal/credential/password.go` (pepper).

## Key inventory

| Key | Where it lives | Used for | If lost |
| --- | --- | --- | --- |
| Root keys (`keys.root_keys`, versioned) | Files, environment variables or secret stores you provide, optionally wrapped by a KMS or HSM (`kms:`) | HKDF-derived purpose keys: data encryption (TOTP seeds, notification payloads, job results, transaction-held invitation secrets, identity-provider client secrets), signing-key wrapping and audit batch signing (unless `signing_wrap_keys` is set), webhook and hook secrets, OTP/recovery-code verifiers, derivation of new pairwise subjects, lookup/CSRF/cursor MACs | Everything encrypted under that version is unrecoverable: signing keys (issuance stops), TOTP seeds (users must re-enroll), webhook and hook secrets, identity-provider client secrets, pending notifications and export results; outstanding codes and recovery codes fail; audit batches signed under that version can no longer be verified |
| Pepper keys (`keys.pepper_keys`, optional) | Separate files or variables, optionally KMS-wrapped | HMAC of passwords before Argon2id | Every password verifier carrying that pepper version fails; affected users must reset their password |
| Signing-wrap keys (`keys.signing_wrap_keys`, optional) | Separate files or variables, optionally KMS-wrapped | Encrypting signing private keys, and deriving the audit batch signing key, instead of the root-derived key | Active signing key cannot be decrypted; issuance stops until an emergency rotation creates a new key; audit batches signed under that version can no longer be verified |
| Signing keys | `signing_keys` table, PKCS#8 encrypted | Signing access tokens, ID tokens and logout tokens (purpose `token`) | Recoverable by rotation; verifiers must fetch the new JWKS |
| SAML signing keys (per realm, RSA 3072 with a self-signed certificate) | `saml_signing_keys` table, encrypted with the same wrapping key as signing keys (associated data `saml-signing-key:<id>`) | Signing SAML responses, assertions and logout messages and the broker's `AuthnRequest`s, for both SAML roles of the realm | SAML sign-ins stop until a new key is prepared and activated (with `force` before `saml.key_prepublish`), and every SAML counterparty must load the new certificate from metadata ([saml.md](../integrations/saml.md#signing-keys-and-rollover)) |
| Directory connector credentials | `provisioning_connectors.secret_ciphertext`, encrypted with the root-derived data key (associated data `directory-connector-credential:<connector id>`) | LDAP service-account binds and downstream SCIM bearer tokens | Directory sign-in and synchronization, and outbound deliveries, fail until the credential is set again with `PUT .../credential` ([directory.md](../integrations/directory.md#concepts)) |

All keys are used in software: even when a KMS or HSM wraps them at rest
([below](#kms-envelope-dep-016)), every process holds them unwrapped in memory
while it runs. No operation (signing, decryption) happens inside an HSM.

## Custody rules

- Keep root, pepper and wrap keys **out of database backups** and out of the
  container image (`.dockerignore` excludes `.env`, `*.key` and `*.pem` files). Back them up
  to separate, access-controlled storage; a database backup without its keys is
  only partially restorable (OPS-005).
- Use `file:` references with mode `0600` files owned by the service user,
  `env:` references populated by your secret manager, `cred:` references to
  systemd credentials, `vault:` references to HashiCorp Vault KV v2, or
  `kms:` references to files wrapped by your KMS
  ([configuration.md](configuration.md#loading-rules)). Production refuses
  literal root, pepper and signing-wrap keys.
- `identity-cli doctor` prints a non-secret **key hierarchy fingerprint** derived
  from the active root key. Record it with each backup; a different fingerprint
  after a restore means different keys are configured.
- `identity-cli support-bundle` never includes key values; it shows references
  (`file:/...`) and redacts literals.

## KMS envelope (DEP-016)

Root, pepper and signing-wrap keys can be kept **wrapped** (encrypted) by a
KMS or HSM, so the key files on a host are useless without access to the
KMS. ProudAuth calls a command you configure to unwrap them when a process
starts (`internal/configuration/kms.go`, `TestKMSUnwrap`). No provider is
built in or required: any KMS or HSM with a command-line client works.

```yaml
keys:
  kms:
    command: ["/usr/local/libexec/proudauth-unwrap"]   # program and arguments; no shell
    timeout: 10s
  root_keys:
    - {version: 1, ref: "kms:/etc/proudauth/root_key_v1.wrapped"}
  active_version: 1
```

- For each `kms:<file>` reference the process reads the file and runs
  `keys.kms.command` directly (no shell), with the file's content on standard
  input and `KMS_KEY_REF=<file>` added to its own environment, which the
  command inherits without the `PROUDAUTH_*` variables (cloud CLIs take their
  credentials and region from it). Other variables, including secrets
  referenced as `env:NAME` under another prefix, are passed on: use a wrapper
  script with a reduced environment if the process environment holds other
  secrets.
- The command must print the 32-byte key as hex or base64 on standard
  output (at most 8 KiB; surrounding whitespace is trimmed). Standard error is
  discarded. A non-zero exit, empty or oversized output, a timeout or a key
  that is not 32 bytes stops the process; the error names the file, never the
  key. A `kms:` reference without `keys.kms.command` is a startup error.
- Every process that loads keys unwraps them: `identity-server`,
  `identity-worker` and the `identity-cli` operator commands (`doctor`,
  `verify-audit`, `migrate`, …), each at its own start. Each unwrap is
  limited by `keys.kms.timeout` (default 10 seconds, at most 1 minute;
  [configuration.md](configuration.md#keys)). A command that leaves a child
  process holding its standard output open can outlast that limit.
- `/status` reports `key_provider: "kms_unwrapped"` when `keys.kms.command`
  is configured (whether or not a reference uses it) and `"software"`
  otherwise ([monitoring.md](monitoring.md#operator-status)).

What it protects, and what it does not:

| Protected | Not protected |
| --- | --- |
| Keys at rest: copies of the wrapped files, configuration and backups of the host are useless without the KMS | Keys **in use**: after start-up each process holds the unwrapped keys in memory (they are not zeroed); anyone who can read process memory, or run the command with the service's KMS credentials, obtains them |
| Who can start the service: the KMS's access policy decides which hosts or identities can unwrap, and its audit log, where it has one, records each unwrap | Signing and decryption inside the HSM: not supported. Signing keys stay PKCS#8-encrypted in the database under the (unwrapped) signing-wrap key |
| | Revocation in a running process: removing KMS access stops only future starts |

Wrapping does not change a key's value, so the key hierarchy fingerprint
printed by `identity-cli doctor` stays the same when you move an existing key
into the KMS; compare it before and after.

**Producing the wrapped file.** The output rule decides what to wrap: the
command must print hex or base64 text. With the AWS CLI (v2), which prints
the decrypted plaintext base64-encoded, wrap the raw 32 bytes:

```sh
# On a trusted host: a new key, wrapped under a KMS key you created for ProudAuth.
head -c 32 /dev/urandom > root_key_v2.bin
aws kms encrypt --key-id alias/proudauth-root --plaintext fileb://root_key_v2.bin \
  --query CiphertextBlob --output text | base64 --decode > root_key_v2.wrapped
shred -u root_key_v2.bin
```

```yaml
keys:
  kms:
    command: ["aws", "kms", "decrypt", "--ciphertext-blob", "fileb:///dev/stdin",
              "--query", "Plaintext", "--output", "text"]
```

An existing key generated by `identity-cli generate-root-key` is hex text:
decode it to its 32 raw bytes before encrypting it this way. Tools that print
the plaintext unchanged need a wrapper script that encodes it: Google Cloud's
`gcloud kms decrypt`, for example, writes the **raw plaintext bytes**, which
ProudAuth does not accept, so pipe its output through `base64` in the script
(or wrap the hex text instead of the raw bytes). HashiCorp Vault transit and
PKCS#11 tools fit the same way through a small wrapper. Keep the root-key
rotation rules below: every version still in use must stay unwrappable.

## Signing-key rotation

Signing keys are per realm. States: `pending` (published, not used) → `active`
(used for new tokens, exactly one per realm) → `retiring` (published, not used)
→ `retired` (not published) and `compromised` (not published, rejected).

JWKS (`GET /realms/{realm}/jwks`) contains pending, active and retiring keys and is
served with `Cache-Control: public, max-age=300`. Server nodes cache key sets for
5 seconds.

Without a usable active key (none active, or the key provider cannot unwrap it:
wrong root or signing-wrap keys, KMS or HSM unreachable) issuance stops
(SEC-009, docs/plan.md §31.2): the token endpoint answers
`503 temporarily_unavailable` for every grant, the authorization code, device
code or refresh token presented is not consumed (the request can be repeated
once the key is back), `/health/ready` reports `degraded`, and
`proudauth_signing_failures_total` counts `no_active_key` or
`key_unavailable`. No replacement key is created automatically
(`TestSigningKeyOutageDuringIssuance`, TEST-059).

### Scheduled (automatic)

The worker's `keys.lifecycle` task runs every minute and:

1. starts a planned rotation for each realm whose active key is older than
   `keys.rotation_interval` (90 days) and has no pending key;
2. activates pending keys older than `keys.prepublish_period` (48 h); the previous
   active key becomes `retiring` with `publish_until = now +
   tokens.max_access_token_ttl + keys.retirement_period` (default 60 min + 7 days);
3. retires keys whose `publish_until` has passed.

No worker, no rotation: a pending key is never activated without
`identity-worker`.

### Planned rotation (manual)

Requires permission `realm.keys.rotate`, an MFA session and authentication within
the last 5 minutes.

```sh
identity-cli login --url https://id.example.com --realm main     # fresh login for the 5-minute window
identity-cli api POST /signing-key-rotations '{"mode":"planned","reason":"CHG-1234"}'
identity-cli api GET /signing-keys                                # kid, algorithm, state, timestamps
```

- Optional `"algorithm"` (`RS256`, `PS256`, `ES256`, `EdDSA`) changes the algorithm
  of the new key; default is `keys.signing_algorithm`.
- Only one planned rotation can be pending (`409 conflict` otherwise).
- The new key is published immediately and becomes active after the prepublish
  period, giving verifiers time to fetch it. Tokens signed with the previous key
  remain verifiable until the retiring key leaves JWKS.
- Audit: `signing_key.rotation.planned`, later `signing_key.activated`. Outbox and
  webhooks: `signing_key.rotated`.

### Emergency rotation

Use when the active private key may be exposed (runbook:
[incidents.md](incidents.md#compromised-signing-key)).

```sh
identity-cli api POST /signing-key-rotations '{"mode":"emergency","reason":"INC-42 key exposure"}'
```

In one transaction:

- the current active key becomes `compromised` (removed from JWKS; the server's
  own verification and introspection reject tokens signed with it within the 5 s
  cache window: at once on the node that handled the request, within 5 seconds on
  every other server node, which until then also keeps signing new tokens with
  the compromised key from its cache; those tokens are rejected once the window
  ends, `TestSharedRevocationAcrossNodes`);
- any pending key is retired;
- a new key is created and becomes active immediately;
- a `token_revocations` row of type `key` is written (exported by
  `identity-cli revocation-log` so restores re-apply it);
- audit `signing_key.rotation.emergency`; outbox/webhook `signing_key.rotated`
  with `previous_key_compromised: true`.

Limits:

- Only the **active** key can be marked compromised through the API. A retiring or
  pending key that is suspected exposed cannot be targeted. As a last resort a
  database operator can run
  `UPDATE signing_keys SET state='compromised', compromised_at=now() WHERE kid='...'`;
  this bypasses ProudAuth's audit trail, so record it in your incident log.
- Removing a key from JWKS does not purge verifier caches. Offline verifiers keep
  accepting tokens signed with the old key until they refresh their key set. The Go
  SDK verifier (`proudauth-sdk-go/verifier`) only re-fetches JWKS when it sees an unknown
  `kid` (at most once per `MinRefreshInterval`, default 30 s), and a re-fetch
  replaces its whole key set. Restart or reconfigure offline verifiers after an
  emergency rotation; subscribe them to the `signing_key.rotated` webhook.
- Refresh tokens, sessions and opaque tokens are not signed and are unaffected.

## Root-key rotation

Root keys are versioned; `keys.active_version` encrypts new data, all listed
versions decrypt. There is **no re-encryption tool**, so an old version can only be
removed once nothing references it.

**Before you start:** values derived from the *active* version change when it
changes:

- **pairwise subjects** that have not been stored yet. Since migration
  `0018_pairwise_subjects.sql`, a pairwise `sub` is derived once and kept in
  `pairwise_subjects`, so values already issued stay stable across root-key
  rotation (`TestPairwiseSubjects`). A pairwise value issued before that migration
  is stored only the next time it is issued, using the active version at that
  moment; let pairwise clients sign their users in after upgrading before you
  change the active version;
- CSRF tokens of in-flight browser transactions and pagination cursors (short-lived);
- the keyring fingerprint printed by `doctor`.

Procedure:

1. Generate the new key: `identity-cli generate-root-key > /run/secrets/root_key_v2`.
2. **Distribute first.** Add `{version: 2, ref: "file:/run/secrets/root_key_v2"}` to
   `keys.root_keys` on every server, worker and CLI host while keeping
   `active_version: 1`. Restart all processes. Every node can now decrypt version 2.
3. **Activate.** Set `active_version: 2` everywhere and restart. New ciphertext,
   OTP verifiers, recovery codes and (unless `signing_wrap_keys` is set) newly
   generated signing keys use version 2.
4. Run `identity-cli doctor`; record the new fingerprint.
5. **Drain version 1** (only if you intend to remove it). Check each source:

   ```sql
   SELECT count(*) FROM signing_keys WHERE enc_key_version = 1 AND state NOT IN ('retired','compromised');
   SELECT count(*) FROM saml_signing_keys WHERE enc_key_version = 1 AND state <> 'retired';
   SELECT count(*) FROM credentials WHERE type IN ('totp','hotp') AND state IN ('active','pending') AND key_version = 1;
   SELECT count(*) FROM recovery_codes WHERE state = 'active' AND key_version = 1;
   SELECT count(*) FROM webhook_subscriptions WHERE key_version = 1 OR previous_secret_expires_at > now();
   SELECT count(*) FROM hooks WHERE key_version = 1;
   SELECT count(*) FROM identity_providers WHERE secret_ciphertext IS NOT NULL AND key_version = 1;
   SELECT count(*) FROM notification_settings WHERE smtp_secret_ciphertext IS NOT NULL AND key_version = 1;
   SELECT count(*) FROM provisioning_connectors WHERE secret_ciphertext IS NOT NULL AND key_version = 1;
   SELECT count(*) FROM ssf_streams WHERE substring(authorization_ciphertext from 2 for 4) = int4send(1);
   SELECT count(*) FROM notification_jobs WHERE payload_ciphertext IS NOT NULL AND key_version = 1;
   SELECT count(*) FROM jobs WHERE (result_ciphertext IS NOT NULL AND key_version = 1) OR (input_ciphertext IS NOT NULL AND input_key_version = 1);
   SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND expires_at > now() AND key_version = 1;
   SELECT count(*) FROM audit_batches WHERE signing_kid LIKE 'audit-ed25519-v1-%';
   ```

   `TestRunbookRootKeyCompromise` runs these checks after the steps below and
   then removes version 1.

   - Signing keys: run a planned signing-key rotation and wait until the old keys are
     `retired` (after an emergency rotation the new key is already under the new
     version; `compromised` keys are never decrypted again).
   - SAML signing keys: prepare a new key and activate it after
     `saml.key_prepublish` ([saml.md](../integrations/saml.md#signing-keys-and-rollover)),
     then wait until the old one is `retired`.
   - TOTP and HOTP seeds: no rewrap exists. Users enroll again
     (`POST /me/totp/enroll`, then `POST /me/totp/activate`, which replaces the
     active authenticator and regenerates recovery codes; `DELETE /me/totp` first
     is refused for accounts that must keep a second factor), or keep version 1.
   - Recovery codes: users regenerate them (`POST /me/recovery-codes/regenerate`);
     re-enrolling TOTP does this too.
   - Webhook secrets: `POST /webhooks/{id}/rotate-secret` for each subscription, then
     wait 24 h for the previous secret to expire; consumers must accept the new
     secret.
   - Hook signing secrets: no rotate endpoint exists; delete and re-create the hook
     (the receiver gets a new secret), or keep version 1.
   - Identity-provider client secrets: send the secret again in
     `PUT /identity-providers/{id}` (`client_secret`) so it is re-encrypted under
     the active version.
   - Organization mail-server passwords: send the password again with
     `PUT /organizations/{org}/notification-settings/smtp`.
   - Directory and outbound connector credentials: set them again with
     `PUT .../credential` ([directory.md](../integrations/directory.md#concepts)).
   - Shared-signals stream authorization headers: the receiver sends its
     `delivery.authorization_header` again (`PATCH /realms/{realm}/ssf/streams`,
     [shared-signals.md](../integrations/shared-signals.md)).
   - Audit batch signatures: their Ed25519 key is derived from the version named in
     the batch's key ID (from `keys.signing_wrap_keys` when configured, otherwise
     from the root key). Removing that version makes `identity-cli verify-audit`
     report those batches as failed; keep the version for as long as you need to
     verify the old batches.
   - Notification payloads, job results and challenges expire on their own
     (`delivery.payload_retention`, `privacy.export_retention`,
     `tokens.challenge_ttl`); a job's protected input is cleared when the job
     finishes.
6. Remove version 1 from `keys.root_keys` on every host and restart. If anything
   still references it, decryption fails at use (TOTP verification, webhook
   delivery marked `dead_letter` with `secret_unavailable`, signing).

Rotation of `signing_wrap_keys` follows the same pattern: the highest configured
version wraps new signing keys; older versions must stay until every non-retired
signing key wrapped with them is retired.

## Password pepper

- Enabling: add `keys.pepper_keys`. New and rehashed verifiers include `k=<version>`
  in the PHC string. Existing verifiers without a pepper keep working and are
  rehashed with the pepper on the next successful login.
- Rotating: add a higher version. Verifiers are rehashed on successful login.
  Users who do not sign in keep the old version, so the old pepper must stay
  configured until this query returns 0:
  `SELECT count(*) FROM credentials WHERE type='password' AND state='active' AND verifier LIKE '%,k=1$%';`
- **Never remove a pepper version that verifiers still reference**, and never
  remove `pepper_keys` entirely once used: every affected password would stop
  matching. Recovery is a password reset for each affected user. Such a sign-in
  fails closed like a wrong password, but it is not silent: the server logs
  `password verifier references an unavailable pepper version` (with the user and
  credential IDs) and records the audit event
  `credential.password.pepper_unavailable` (reason `PEPPER_UNAVAILABLE`), so a
  missing key shows up as a key problem rather than as users mistyping
  (`credential.ErrPepperUnavailable`, `TestMissingPepperVersionFailsClosed`).

## Related

- [backup-restore.md](backup-restore.md) — backing up keys with the database
- [revocation-exposure.md](revocation-exposure.md) — what key compromise means for
  offline verifiers
