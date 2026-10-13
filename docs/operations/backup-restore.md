# Backup, restore and restore reconciliation

Requirements: OPS-005, OPS-006, OPS-007, OPS-014, PRV-005, PRV-006, MIG-017,
TEST-060, docs/plan.md §31.3 ("Restore after data loss").

Restoring an older backup brings back everything that was true at backup time,
including sessions that were later revoked, accounts that were later deleted and
signing keys that were later found compromised, and one-time proofs (codes,
refresh tokens, recovery codes) that were later consumed. ProudAuth therefore pairs
database backups with an independently stored **revocation log**, a
**reconciliation** step that re-applies it and ends outstanding one-time
proofs, and a **restore marker** that keeps the restored database unready until
reconciliation has run. The end-to-end tests `TestRestoreReconciliation`
(`tests/e2e/restore_test.go`) and `TestRestoreProofConsumption`
(`tests/e2e/restore_proofs_test.go`) exercise this.

## What to back up

| Item | How | Notes |
| --- | --- | --- |
| PostgreSQL database | Your tooling: `pg_dump`/`pg_restore`, or physical base backups plus WAL archiving for point-in-time recovery | The application does not schedule or verify backups. Your recovery point objective is your WAL/backup interval. |
| Root keys, pepper keys, signing-wrap keys | Copy the key files/secrets to separate storage | Without the matching keys, encrypted columns cannot be read ([keys.md](keys.md)). Record the `identity-cli doctor` fingerprint with each backup. |
| Configuration file and secret references | Version control (without secret values) | |
| Revocation log | `identity-cli revocation-log` on a schedule, to storage independent of the database | See below. |
| Audit evidence (recommended) | `POST /api/v1/realms/{realm}/audit-exports` on a schedule, downloaded to independent storage; or the continuous audit archive (`privacy.audit_archive_dir`, AUD-008) on storage independent of the database | Events after the backup point are otherwise lost with the restore. The archive holds sealed batches only, within about a minute of sealing, and with an archive configured retention never prunes a batch before it is archived ([incidents.md](incidents.md#audit-archive-aud-008)). Imported audit history (`imported_audit_events`) is in neither; it is in the database backup only. |

### Point-in-time recovery and protecting backups (OPS-007)

Point-in-time recovery is PostgreSQL's own: a base backup plus continuous WAL
archiving, restored with `recovery_target_time`. ProudAuth adds nothing to
it and needs nothing from it beyond the restore procedure below.

- **Prerequisites:** `wal_level=replica` (or higher), `archive_mode=on`, an
  `archive_command` (or a backup tool such as pgBackRest, Barman or WAL-G)
  writing to storage outside the database host, and periodic base backups.
- **Data-loss window:** everything after the last archived WAL segment
  (`archive_timeout` bounds it on a quiet system) or, without WAL archiving,
  after the last dump. Revocations, deletions and consumed proofs inside that
  window are what the revocation log and reconciliation re-apply.
- **Restoring to a point in time:** copy the base backup into an empty data
  directory of a separate instance, create `recovery.signal`, and set
  `restore_command` (reading the archive, mounted read-only),
  `recovery_target_time` (with its time zone, e.g.
  `2026-10-11 06:42:42.089+00`) and `recovery_target_action = 'promote'`.
  PostgreSQL stops at the first commit after the target and logs
  `recovery stopping before commit of transaction ...`. A base backup
  carries the configuration files kept in the data directory
  (`postgresql.auto.conf` always, `postgresql.conf` where it lives there),
  so two settings must be overridden on the restored instance:
  `archive_mode`/`archive_command` (set `archive_mode=off`
  or another archive, so it does not write into the archive it reads) and
  `synchronous_standby_names` (clear it: with it set, every commit, starting
  with `identity-cli restore-begin`, waits for a standby that does not
  exist). Then follow the [restore procedure](#restore-procedure) from step 3,
  with revocation logs exported since before the target time.
- **Backups hold personal data and secrets in plaintext.** Database backups
  and WAL archives contain every `plain` column of the
  [data inventory](data-inventory.md) (names, email addresses, audit
  evidence) and the encrypted columns' ciphertext. Encrypt them at rest with
  a key that is not stored with them, restrict read access to the people who
  restore, and log that access. Keep the root keys in a separate location
  from the backups: a backup and its keys together are the whole identity
  store.
- **Retention:** keep backups only as long as your recovery objectives
  need, and set `privacy.backup_retention` to that period so erasure
  requests can state when deleted data leaves the backups
  ([Backups and erasure](#backups-and-erasure)). Thirty days of WAL and base
  backups is a reasonable default for most deployments.
- **Test it:** restore into a separate instance on a schedule and run the
  [restore drill](#restore-drills); an untested backup is not a backup.
  `make dr-drill` does this with throwaway containers
  ([What is tested](#what-is-tested)).

## The revocation log

```sh
identity-cli revocation-log -config /etc/proudauth/config.yaml \
  -since 2026-10-10T00:00:00Z -out /secure/revocations/2026-10.jsonl
```

- `-since` defaults to 24 hours ago. `-out` **appends** (file mode `0600`);
  without it the log goes to stdout. Overlapping runs produce duplicate lines;
  reconciliation is idempotent, so duplicates are harmless.
- Each run is audited (`operations.revocation_log.exported`). If that record
  cannot be written, the command exits with an error ("revocation log written
  but its audit record failed: ..."): the log has been written by then, so
  keep it, but treat the run as unaccounted for (OPS-013).
- Run it often (for example every 5 minutes with `-since` slightly before the
  previous run) and ship the file off the database host. Anything revoked between
  the last export and the incident is missing from the log.
- Each line is a JSON record with identifiers and digests only:

| `kind` | Source | Exported when |
| --- | --- | --- |
| `revocation` | `token_revocations` (types `session`, `user`, `family`, `client`, `key`, `jti`) | `effective_at >= since` |
| `tombstone` | `deletion_tombstones` (deleted accounts and their identifiers, as digests) | `created_at >= since` |
| `key_compromised` | `signing_keys` in state `compromised` | `compromised_at >= since` |
| `user_state` | users currently `suspended`, `locked`, `pending_deletion` or `deleted` | `updated_at >= since` |
| `invitation_consumed` | invitations currently `accepted`, `revoked` or `declined` | `updated_at >= since` |
| `password_changed` | the user's current active password credential (user ID and credential ID only, never a verifier) | credential `created_at >= since` |
| `client_credential_revoked` | client secrets and keys in state `revoked` | `revoked_at >= since` |
| `automation_credential_revoked` | API keys and personal access tokens in state `revoked` | `revoked_at >= since` |
| `membership_state` | memberships currently `removed`, `suspended` or `expired` | `updated_at >= since` |
| `refresh_rotated` | refresh families with a generation consumed (rotated) since, with the family's current generation number | token `consumed_at >= since` |
| `refresh_family_revoked` | refresh families in state `revoked` or `compromised` (`/oauth/revoke`, reuse detection, grant revocation) | `revoked_at >= since` |
| `grant_revoked` | authorization grants in state `revoked` | `revoked_at >= since` |
| `recovery_code_consumed` | recovery codes in state `consumed` (code ID only) | `consumed_at >= since` |
| `recovery_codes_replaced` | per user, the newest recovery-code batch ID | batch `created_at >= since` |
| `hotp_counter` | HOTP credentials with their counter (the next acceptable value; not secret) | `last_used_at >= since` |
| `initial_access_token` | initial access tokens with their use count and state; and, from the audit evidence (`client_registration.initial_token.revoked`), revoked ones | `last_used_at >= since`; event `occurred_at >= since` |
| `registration_token_rotated` | per dynamically registered client, the ID of its current registration access token | token `created_at >= since` |

## What reconciliation re-applies

`identity-cli restore-reconcile -log <file>` reads the log and, in one
transaction:

| Record | Effect on the restored database |
| --- | --- |
| `revocation` / `session` | Session revoked (cookie digest cleared) |
| `revocation` / `user` | All the user's sessions and refresh families revoked |
| `revocation` / `family` | Refresh family revoked |
| `revocation` / `grant` | Authorization grant revoked |
| `revocation` / `client` | All refresh families of the client revoked |
| `revocation` / `jti` | Revocation row restored (introspection and the IdP's own APIs reject the JWT) |
| every `revocation` | `token_revocations` row re-inserted if missing |
| `tombstone` (user) | The account is erased again with the same code as account deletion ([data-inventory.md](data-inventory.md#account-deletion)): identifiers, credentials, recovery codes, passkeys, external identities, password history, remembered devices, pairwise subject mappings and notification preferences deleted; sessions, grants, refresh families, opaque tokens, support grants and the user's API keys and personal tokens revoked; pending assisted recoveries and account merges cancelled, a pending registration approval expired; memberships removed; profile, metadata, locale, time zone and required actions cleared; state `deleted`; source-supplied details of the account's imported audit records cleared unless a legal hold covers them (MIG-016). `deleted_at` keeps the value the restored row has; a row restored before the deletion gets the reconciliation time. No `user.deleted` audit or webhook event is recorded |
| `tombstone` (identifier) | Tombstone re-inserted, so imports cannot recreate the address |
| `key_compromised` | Signing key marked `compromised` |
| `user_state` `suspended`/`locked` | Active user set to that state; sessions revoked (refresh families and grants are not: combine with `-invalidate-all-sessions` or the `revocation` records). A `pending_deletion` state is exported but not re-applied |
| `invitation_consumed` | Pending invitation set to `accepted`/`revoked`/`declined` |
| `password_changed` | Every other active password of the user (the restored, older one) marked `compromised`; if the current credential is not in the restore, `update_password` is added as a required action; when either applied, the user's sessions revoked (a restore that already holds the current password, for example from an overlapping log, is left alone) |
| `client_credential_revoked` | Client secret or key revoked again |
| `automation_credential_revoked` | API key or personal access token revoked again |
| `membership_state` | Active membership set to `removed`, `suspended` or `expired`; for `removed` and `expired`, its role assignments deleted |
| `refresh_rotated` | Family revoked when its restored generation is older than the exported one: its restored current token was consumed after the backup and the token its holder now has is not in the restore (the client signs in again) |
| `refresh_family_revoked` | Active family set to `revoked` (or `compromised`) again |
| `grant_revoked` | Grant revoked again with its refresh families and opaque access tokens |
| `recovery_code_consumed` | Active recovery code marked `consumed` |
| `recovery_codes_replaced` | Every active recovery code of the user outside the newest batch invalidated; when that batch was issued after the backup the user has no usable code and generates a new batch |
| `hotp_counter` | Counter raised to the exported value (never lowered), so codes used after the backup are refused |
| `initial_access_token` | Use count raised to the exported value; state `exhausted` or `revoked` re-applied (also when the raised count reaches `max_uses`) |
| `registration_token_rotated` | Every other active registration access token of the client revoked; when the current one is not in the restore, the registrant can no longer manage the client through `/oauth/register/{id}` (an administrator manages it through the client API) |

Every reconciliation, with or without a log, also ends **every outstanding
one-time proof** of the restored database, because a code or link consumed
after the backup is outstanding again in the restore and nothing outside the
database records the consumption: password-reset, verification, sign-in OTP,
magic-link, account-setup, identifier-change and registration codes and links
(`challenges`), authorization codes, pushed authorization requests, device
codes, pending sign-in transactions, passkey ceremonies, federation and SAML
request states, support handoff codes and job download tokens. Their holders
request new ones; administrators resend account-setup links. The report lists
the counts under `proofs_invalidated`.

`-invalidate-all-sessions` additionally revokes **every** active session, refresh
family and support grant, and revokes every pending invitation, in all realms. Use
it when you cannot show that the log covers the whole gap since the backup.

Reconciliation clears the [restore marker](#the-restore-marker) in the same
transaction. The command records audit event `operations.restore.reconciled`
(category `emergency`; the actor is the operator, `local:<OS user>`, OPS-013)
and prints a JSON report:

```json
{ "applied": { "revocation": 12, "tombstone": 3, "user_state": 1, "refresh_rotated": 40 },
  "sessions_revoked": 0, "refresh_families_revoked": 0,
  "proofs_invalidated": { "challenges": 7, "auth_transactions": 2 },
  "restore_marker_cleared": true }
```

`applied` counts the log records processed, by kind, including those that
changed nothing (on a promoted standby that lost nothing, every record is
already in effect). `sessions_revoked` and
`refresh_families_revoked` count only the `-invalidate-all-sessions` sweep,
so they are `0` without it even when the log revoked sessions.

It refuses to run with neither `-log` nor `-invalidate-all-sessions`; with
nothing to re-apply, pass an empty file as `-log` to end the outstanding proofs
and clear the marker. The whole log is read before anything changes: a
malformed line aborts the run without effect.

### The restore marker

A restored database must not serve traffic before reconciliation has run
(TEST-060). Right after restoring (and migrating, step 3 below), and before
any `identity-server` is started on it, run:

```sh
identity-cli restore-begin            # mark the database (audited: operations.restore.begun)
identity-cli restore-begin -status    # show the marker without setting it
```

While the marker is set, `GET /health/ready` answers `503`
`{"status":"unavailable","reason":"restore_pending"}` on every instance using
that database, so load balancers send it no traffic, and `identity-worker`
refuses to start (it would send the notifications, webhooks and jobs restored
with the backup). The API itself still answers on the isolated network, so the
emergency key rotation of step 5 works. `identity-cli restore-reconcile`
clears the marker in its transaction; nothing else does. Marking twice keeps
the first marker. A database that was never marked (every normal deployment)
has no marker and is unaffected. The marker lives in the restored database, so
an operator who forgets `restore-begin` gets no gate: make it part of the
runbook, directly after the restore command.

### What reconciliation does NOT cover

These post-backup changes are not in the revocation log and come back with the
restore. Handle them explicitly (for example from an independently exported audit
log). Password changes and resets, client-secret and API-key/personal-token
revocations, membership removal, suspension and expiry, and the proof
consumptions above are reconciled. `TestRestoreReconciliation` exercises the
password change and a removed membership; `TestRestoreProofConsumption`
(`tests/e2e/restore_proofs_test.go`) exercises the restore marker, every proof
consumption kind (a rotated and a revoked refresh token, a consumed and a
replaced recovery code, an advanced HOTP counter, used-up and revoked initial
access tokens, a rotated registration access token, a completed password reset,
an accepted invitation), a revoked client secret and personal access token and
a suspended membership, each presented again to an instance on the restored
database.

| Change after the backup | Consequence after restore | Remedy |
| --- | --- | --- |
| Password marked compromised without a new password being set | Password is active again | Mark it compromised again (`POST /users/{user}/credentials/password/compromised`) or set `update_password` as a required action |
| MFA enrollment or removal (TOTP, HOTP, passkeys); recovery codes invalidated by a factor removal without a new batch | Previous factor state returns | Ask affected users to review factors; assisted recovery if needed |
| Proofs whose consumption is kept only in a replay cache: DPoP proof `jti`s, client-assertion and workload-assertion `jti`s, SAML assertion IDs; TOTP time steps | Seen IDs are forgotten; a proof captured after the backup is accepted once more while it is itself still valid (its own `exp`, at most minutes; TOTP within its time step) | Keep the restored database unready (restore marker) for longer than the longest assertion lifetime you accept, which a restore normally takes anyway |
| Role unassigned without a membership change | Access returns | Unassign again |
| Organization suspended or deleted | Organization active again | Repeat the action |
| Support grant revoked | Grant active until its (≤ 5 min) expiry | Expires on its own; or `-invalidate-all-sessions` |
| User reactivated after a suspension that predates the backup | User stays suspended | Reactivate |
| Invitation accepted after the backup | Invitation is marked accepted, but the membership created after the backup is gone | Add the member or send a new invitation |
| Signing key created by an emergency rotation after the backup | New key lost; the compromised key is active in the restore | See the ordering rule in step 5 below |
| Anything created after the backup (users, organizations, clients, keys, audit events) | Lost | Recreate; audit events survive only if exported or archived |
| Account deleted after the backup | Erased again (table above), but `deleted_at` becomes the reconciliation time unless the restored row already had one, which shifts the dates of the [deletion report](data-inventory.md#deletion-propagation-report); no `user.deleted` event reaches webhook subscribers or back-channel logout | Record the original deletion time in the incident log; tell downstream systems that consumed `user.deleted` only if they were restored too |
| Self-service deletion requested after the backup (`pending_deletion`) | The request is lost; the account is active | Ask the user to request deletion again, or delete the account |

## Restore procedure

1. **Isolate.** Restore into an environment that receives no user traffic. Do not
   start `identity-worker` yet (it would send queued notifications and webhooks).
2. **Restore the database** to the chosen point in time.
3. **Configure the same keys** as at backup time, run `identity-cli doctor` and
   compare the fingerprint with the one recorded for the backup. If the binary is
   newer than the backup's schema, run `identity-cli migrate` (until then every
   instance reports unready because the schema is behind).
   Then **mark the database** with `identity-cli restore-begin`
   ([the restore marker](#the-restore-marker)): from now until step 6 it
   reports unready and workers refuse to start.
4. **Collect the revocation log** covering at least the backup time to now:
   concatenate exports whose `-since` is at or before the backup's point in time.
5. **Order rule for compromised keys.** If the log contains `key_compromised` for a
   key that is *active* in the restored database, reconciliation would leave the
   realm without an active signing key, and no CLI command can create one (keys are
   created only by realm creation and the rotation API). In that case first start
   `identity-server` on the isolated network, sign in as an administrator and run an
   emergency rotation (`POST /signing-key-rotations {"mode":"emergency"}`), then
   reconcile.
6. **Reconcile:**

   ```sh
   identity-cli restore-reconcile -log /secure/revocations/all.jsonl
   # or, if the gap is not fully covered:
   identity-cli restore-reconcile -log /secure/revocations/all.jsonl -invalidate-all-sessions
   ```

   The report must say `"restore_marker_cleared": true`; `GET /health/ready`
   then reports ready again.

7. **Apply the manual remedies** from the table above for anything you know changed
   after the backup.
8. **Review queued side effects** before starting workers:
   `SELECT template, state, count(*) FROM notification_jobs WHERE state IN ('queued','attempted') GROUP BY 1,2;`
   and `SELECT count(*) FROM outbox_events WHERE state='pending';`.
   Jobs past their `expires_at` are marked expired instead of sent; code-bearing
   messages expire with their code (`tokens.challenge_ttl`). Invitation and
   account-setup emails restored from the backup will be sent again, and pending
   outbox events are re-delivered to webhooks (consumers deduplicate by
   `event_id`).
   With an audit archive, the archive holds batches of the lost period that the
   restored database no longer has. Leave them in place: when the restored
   database seals a batch under a sequence number whose file holds other
   content, `audit.archive` continues in a new directory
   `fork-<sequence>-<batch id>/` inside the archive and records
   `audit.archive.forked` (operator event, in the database only), and
   `identity-cli verify-audit-archive` verifies the fork as a branch of the main
   archive ([incidents.md](incidents.md#audit-archive-aud-008)). Record the fork
   in your incident log; the main directory's newer files are the evidence of
   the lost period.
9. **Verify:** `identity-cli doctor`; `identity-cli verify-audit`; sign in with a
   synthetic account; request a token; introspect it; confirm a known-deleted
   account cannot sign in and a known-revoked session is inactive (OPS-006).
10. **Resume traffic**, then start `identity-worker`.

## Restore drills

Run the procedure regularly against a copy of production with synthetic accounts
(OPS-006). Measure the time from "start restore" to "traffic resumed", including
key retrieval and reconciliation; that is your real recovery time objective.

`TestRestoreDrill` (`tests/e2e/deployment_ops_test.go`) runs a small drill:
it copies the database, makes changes after the copy (an account deleted, a
user signed out everywhere, an invitation revoked), reconciles the copy with
the exported log, starts an instance on it with the same keys and checks the
key-hierarchy fingerprint, the signing key, readiness, a synthetic user's
sign-in, organization membership and token introspection, the policy
revision, and that none of the later changes is undone. The same copy started
with other root keys has another fingerprint, cannot use its signing key and
stays unready: a database backup without its keys cannot be put back into
service (OPS-005).

`make dr-drill` runs the procedure on a real point-in-time restore (base
backup plus archived WAL) and on a promoted streaming standby, and prints
the time to the first token ([What is tested](#what-is-tested)). It can
serve as a starting point for your own drill script.

## Disaster-region recovery (DEP-019)

The supported disaster-recovery profile is **one writing region with a warm
standby in another region**
([ADR 0019](../architecture-decisions/0019-single-write-region.md)). Active-active
identity writes and globally immediate revocation are **not** offered.

### The profile

| Component | Primary region | Standby region |
| --- | --- | --- |
| PostgreSQL | The only writable primary; every server and worker reads and writes it (no code path reads from replicas) | A streaming replica (asynchronous or synchronous), or base backups plus a WAL archive shipped to the region |
| `identity-server`, `identity-worker` | Serving | Installed with the same binary and configuration, **not running** (or not connected) until promotion |
| Root, pepper and signing-wrap keys, or KMS access | In use | The same key versions available: copies of the key files or secrets, or KMS keys usable from the standby region. Record the `identity-cli doctor` fingerprint on both sides |
| Configuration | `server.public_origin` and custom domains point here | Same file; the public origin and issuer do not change, only where DNS or the load balancer sends traffic. Egress allowlists and trusted proxies may need the standby's addresses |
| Revocation log, audit exports and archive | Exported on a schedule | Stored outside the primary region (in the standby region or a third place) |

Recovery point objective: the replication lag at the moment of failure (zero
committed transactions lost with synchronous replication that acknowledged
them), or your WAL archive interval. Recovery time objective: detection,
fencing, promotion, start-up, reconciliation and the DNS or load-balancer
switch. `make dr-drill` measures both for one small setup on one machine
([What is tested](#what-is-tested)); those numbers are not guarantees, so
measure yours in your own drills.

### Promotion runbook

1. **Declare and fence.** Make sure the old primary can no longer accept
   writes (stop it, cut its network, or revoke its credentials). Two writable
   primaries break one-time consumption of codes, refresh tokens and
   invitations; never run both.
2. **Promote** the standby database with your PostgreSQL tooling
   (`SELECT pg_promote()` or `pg_ctl promote`) and note the recovery point
   (`pg_last_xact_replay_timestamp()`, the last replayed transaction time).
   If the promoted node has `synchronous_standby_names` set, clear it
   (`ALTER SYSTEM RESET synchronous_standby_names; SELECT pg_reload_conf();`)
   until a new standby is attached: otherwise every commit waits for a
   standby that is gone, and `statement_timeout` does not end the wait. A
   setting made with `ALTER SYSTEM` on the primary is in
   `postgresql.auto.conf`, which `pg_basebackup` copies to the standby, so
   with synchronous replication it usually is set.
3. **Start one `identity-server`** in the standby region with the same keys,
   run `identity-cli doctor` and compare the fingerprint. Keep it out of the
   load balancer, or set maintenance mode
   (`identity-cli maintenance -mode unavailable`). When step 4 applies, run
   `identity-cli restore-begin` right after the promotion, before starting
   the server, so no instance reports ready before the reconciliation.
4. **Reconcile when anything may have been lost.** If the replica could lag
   (asynchronous replication, or WAL shipping), treat the promotion as a
   restore: collect the revocation logs exported since before the recovery
   point and run `identity-cli restore-reconcile -log ...`, adding
   `-invalidate-all-sessions` when the logs do not cover the whole gap up to
   the failure ([Restore procedure](#restore-procedure), steps 4–7, including
   the ordering rule for compromised signing keys). Reconciliation re-applies
   revocations, deletions, state changes and credential revocations that the
   lost window contained; anything revoked after the last log export is not in
   the log, which is what `-invalidate-all-sessions` is for.
5. **Review queued side effects** (notifications, outbox, webhook
   deliveries, shared-signals events) as in step 8 of the restore procedure,
   then start `identity-worker`.
6. **Switch traffic**: point DNS or the load balancer for the public origin
   (and custom domains) at the standby region and verify (synthetic sign-in,
   token, introspection). Mode `unavailable` refuses sign-in and token
   requests (`503`), so switch to `identity-cli maintenance -mode restricted`
   for the verification (sign-in, tokens and introspection work;
   administration and self-service changes are still refused; each instance
   applies a change within 2 seconds), then leave maintenance mode
   (`-mode off`).
7. **Rebuild redundancy**: create a new standby before the next incident; do
   not bring the old primary back as a writer without rebuilding it from the
   new primary.

What clients see after a lossy promotion: sessions, grants and refresh
tokens created after the recovery point do not exist, so those users and
clients sign in again; JWT access tokens issued in the lost window stay
valid for offline verifiers until they expire, while introspection reports
them inactive when their session is missing.

### What is not offered

- **Active-active identity writes.** Every write goes to one primary; there
  is no multi-region write design (DEP-018). Latency for distant users is
  bounded by the distance to the primary.
- **Globally immediate revocation.** Access tokens are self-contained JWTs:
  an offline verifier in any region accepts one until it expires. Keep
  access-token lifetimes short (`access_token_ttl_seconds` per resource,
  default 300 s), use `strict_online` resources (introspection on every
  request) or bounded-state verification where revocation must be prompt,
  and see [revocation-exposure.md](revocation-exposure.md).
- Read replicas for introspection or any other request path.
- Automated failover: detection, fencing and promotion are the operator's.

### What is tested

`TestRestoreReconciliation` (`tests/e2e/restore_test.go`) exercises the
revocation-log export and reconciliation on a copied database;
`TestRestoreProofConsumption` (`tests/e2e/restore_proofs_test.go`) adds the
restore marker (an instance on the restored copy is unready until
reconciliation, an unmarked deployment is ready) and proof consumption,
presented again to an instance on the restored copy.

`make dr-drill` (`scripts/dr-drill.sh`; weekly and on demand in
`.github/workflows/dr-drill.yml`) runs this profile and point-in-time
recovery against real PostgreSQL replication, with throwaway containers
(`postgres:18` by default, `DRILL_PG_IMAGE` to change it) and the
`identity-server`, `identity-worker` and `identity-cli` binaries built from
the checkout, on one host. It needs Docker, Go, curl, jq and python3.

1. **Setup:** a primary with `archive_mode=on` and an `archive_command`
   copying segments to an archive volume, a `replication` entry in
   `pg_hba.conf`, and a standby made with `pg_basebackup -R`, streaming
   synchronously (`synchronous_standby_names` set with `ALTER SYSTEM`) or,
   with `DRILL_SYNC=off`, asynchronously. ProudAuth on the primary:
   `migrate`, `realm-create`, `bootstrap`, the administrator's first sign-in
   (password, email verification, TOTP enrollment), a resource, a confidential
   client, an introspecting resource server and four users with sessions. A
   base backup is taken; a user is created; a target time is recorded; then
   another user is created, one user's sessions are revoked, one user is
   deleted, one is suspended and a refresh token is rotated; the revocation
   log is exported.
2. **Failover (promotion runbook):** a write load (single-row inserts, 60–90
   per second) runs while the primary is fenced: `identity-server` and
   `identity-worker` are killed, then the database container (`SIGKILL`, no
   shutdown checkpoint), and the drill checks that the old primary no longer
   answers. The standby is promoted with `pg_promote()`, its inherited
   `synchronous_standby_names` is cleared, and the recovery point is
   recorded. Then `restore-begin`, maintenance mode `unavailable`,
   `identity-server` on the promoted standby with the same keys (readiness
   `503 restore_pending`), `doctor` (fingerprint equal to the primary's),
   `identity-worker` refusing to start, `restore-reconcile -log`, readiness
   `200`, the side-effect queries of step 8, the worker started, a sign-in
   refused (`503`) under `unavailable`, then `restricted` and the checks:
   sign-in and token issuance, introspection of the new token, a refresh
   token issued by the old primary still accepted, the revoked session
   inactive at introspection and its refresh token refused, the deleted and
   the suspended users unable to sign in, the last user created before the
   failure able to, the administrator's TOTP sign-in (MFA secrets readable
   with the same keys), and `verify-audit`.
3. **Point-in-time recovery:** the base backup and the archive (read-only)
   restored into a fresh container with `recovery_target_time` between the
   two changes, `recovery_target_action = 'promote'`, `archive_mode=off`
   and `synchronous_standby_names` cleared. Before reconciliation the drill
   checks the target state in SQL: the earlier user is there, the later one
   is not, and the deleted user, the revoked sessions and the suspended user
   are back. After `restore-begin`, `doctor`, `restore-reconcile -log` and
   readiness: sign-in, token and introspection work, the earlier user signs
   in, the later one does not exist, and the revocation, the deletion, the
   suspension and the refresh-token rotation exported after the target are
   in effect again.

Measured on one laptop (Apple silicon, Docker Desktop, PostgreSQL 18.6,
ten runs on 2026-10-11, seven synchronous and three asynchronous): no
acknowledged transaction lost (RPO 0, out of 187–264 acknowledged per run,
replay lag under 3 ms at fencing, in both modes); 3.8–4.3 s from fencing to
the first token issued by the promoted standby (promotion about 0.4 s,
`identity-server` up after about 1.1 s, reconciliation done after about
1.3 s, and 2.2 s of it the drill's deliberate wait for every instance to
apply maintenance mode `restricted`); 2.2–2.8 s from starting the
point-in-time restore to the first token. These are drill numbers for a
tiny database with both "regions" on one machine, not guarantees: they
exclude detection and the DNS or load-balancer switch, and an asynchronous
standby over a real network loses what it had not received when the
primary failed. Not tested: cross-region networks and traffic switching,
failure detection, network partitions without a kill, a lagging
asynchronous standby, and databases of production size. Your restore and
failover drills are the evidence for your recovery objectives.

## Backups and erasure

Deleted accounts remain in older backups. ProudAuth does not rewrite backups;
reconciliation re-deletes them when such a backup is restored, provided the
deletion's tombstone is in the revocation log (PRV-005). Set your backup
retention with this in mind, and record it as `privacy.backup_retention`:
`GET /users/{user}/deletion-status` then reports until when a deleted account
can still exist in a backup (`unknown` without it;
[data-inventory.md](data-inventory.md#deletion-propagation-report)).
