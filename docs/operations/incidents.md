# Incident runbooks

Runbooks required by docs/plan.md §31.3 and OPS-016. API paths are relative to
`/api/v1/realms/{realm}` and need an admin-audience token from an MFA session
(`identity-cli login`, then `identity-cli api METHOD /path [json]`). `{user}` is a
user ID (`usr_...`); `{client}` is the client's internal `id` (`cli_...`) returned
by `POST /clients` and `GET /clients`, not its OAuth `client_id`.

General rules:

- Preserve evidence before changing state: export audit for the window
  (`POST /audit-exports {"from": "...", "to": "..."}`, then download the job
  result), place a legal hold so retention cannot prune it
  (`POST /audit-legal-holds {"reason": "...", "subject_id": "..."}`,
  `realm.audit.legal_hold`; see
  [data-inventory.md](data-inventory.md#audit-retention-and-legal-holds)), and
  keep database and log snapshots.
- Prefer API actions over database edits: they are audited and publish outbox
  events. Where this page says a database edit is the only option, record it in
  your incident log, because it bypasses ProudAuth's audit trail.
- Offline-verified JWTs remain valid until expiry whatever you revoke; see
  [revocation-exposure.md](revocation-exposure.md).

## Runbook coverage (OPS-016)

| Situation | Runbook | Exercised by end-to-end tests |
| --- | --- | --- |
| Compromised signing key | [below](#compromised-signing-key) | Emergency rotation: `TestSigningKeyRotation`; another node stops accepting the key within its 5-second key cache (`TestSharedRevocationAcrossNodes`) |
| Compromised root, pepper or wrap key, or KMS access | [below](#compromised-root-key-pepper-or-kms-access) | KMS access revoked, with a stand-in unwrap command (`TestRunbookKMSAccessRevoked`); a new root-key version, the emergency rotation, re-wrapping, the drain checks and removing the old version (`TestRunbookRootKeyCompromise`); a new pepper version, forced resets and removing the old one (`TestRunbookPepperCompromise`). Restarts are simulated by new server instances on the same database; revoking access in a real KMS and reviewing its audit log, and rotating `signing_wrap_keys`, are not tested |
| Compromised administrator account or client secret | [below](#compromised-administrator-account) | Suspension and its revocations as part of `TestRestoreReconciliation`; client suspension through emergency controls in `TestEmergencyControls` |
| Connector compromise (upstream provider, hook, webhook receiver, mail server, gateway) | [below](#compromised-connector) | Emergency controls for clients, organizations and grant types (`TestEmergencyControls`); the identity-provider (including a sign-in already at the upstream), hook, webhook and service-principal controls, sign-ins and links in the audit log, session revocation, link removal, sending the client secret again, webhook secret rotation and hook replacement (`TestRunbookConnectorCompromise`); replay (`TestRunbookWebhookOutage`); removing an organization's mail server (`TestTenantSMTPCredentials`); plugin and workflow disabling (`TestPluginLifecycle`, `TestWorkflowRevisionsRollbackAndDisable`). The SMS gateway, challenge providers and plugin publisher keys are operator configuration and are not tested |
| Provisioning connector (SCIM) token compromise | [below](#provisioning-connector-token-compromise) | Token rotation and disabling a connector (`TestSCIMProvisioning`) |
| SAML signing key or SAML counterparty compromise | [below](#saml-key-or-counterparty-compromise) | Forced key activation with a reason (`TestSAMLKeyRollover`); certificate replacement on a connection (`TestSAMLBroker`); the emergency controls on SAML connections and backing clients are not tested end to end |
| Federation-created verified addresses outside an organization's domains (upgrade from 0.2.0-alpha.4 or earlier) | [below](#federation-created-verified-addresses-outside-an-organizations-domains) | The query, against an account made as earlier releases did (`TestOrganizationJITEmailVerification`); the review steps are not tested |
| Directory or outbound connector compromise | [below](#directory-connector-compromise) | Disabling an LDAP connector (fail-closed sign-in, `TestLDAPDirectorySignIn`); rotating an outbound connector's credential (`TestOutboundProvisioning`); rotating an LDAP credential is not tested end to end |
| Abuse spikes | [below](#abuse-spikes) | Budgets and the temporary lock (`TestPasswordlessAndAbuseBudgets`), flow rules (`TestAuthenticationFlowPolicy`), adversarial benchmark scenarios ([benchmarks.md](benchmarks.md)) |
| Database outage | [below](#database-unavailable-or-degraded) | Strict-online denial during outages (TEST-035) |
| Database loss | [below](#database-loss) and [backup-restore.md](backup-restore.md) | The CLI commands of the runbook on a restored copy: `maintenance`, `doctor` (fingerprint), `migrate`, `restore-begin`, the ordering rule for a compromised active key, `revocation-log`, `restore-reconcile`, `verify-audit` (`TestDatabaseLossRunbookCommands`, `cmd/identity-cli`); reconciliation details (`TestRestoreReconciliation`); a synthetic sign-in and introspection on a reconciled copy (`TestRestoreDrill`) |
| Notification and webhook outages | [below](#email-or-webhook-delivery-outage) | Relay outage with job inspection, retries, expiry, the relay check, a test message and new codes (`TestRunbookEmailOutage`); webhook backlog, dead letters, replay, paused subscriptions and back-channel logout retries (`TestRunbookWebhookOutage`). suppressed jobs and provider feedback (`TestMessagingControls`). SMS jobs to a failing gateway are not tested |
| Organization owner recovery | [below](#organization-owner-recovery) and [account-recovery.md](account-recovery.md) | Assisted recovery (`TestScheduledAssistedRecovery`); last-owner protection (`TestLastOwnerProtection`); an administrator's ownership transfer and removing the former owner's role (`TestRunbookOrganizationOwnerRecovery`) |
| Privacy deletion errors | [below](#privacy-deletion-errors) | Deletion report (`TestDeletionPropagationStatus`); re-applying deletions after a restore (`TestRestoreReconciliation`) |
| Audit chain failure, audit archive | [below](#audit-chain-verification-failure) | `TestAuditSignaturesAndRetention`, `TestAuditArchive` |
| Support impersonation abuse | [below](#support-impersonation-abuse) | `TestSupportImpersonation`, `TestImpersonationDenials` |
| Maintenance | [below](#maintenance-mode-ops-015) | `TestMaintenanceAndStatus` |

Rehearse the untested procedures in a staging environment before you need
them.

## Compromised signing key

Signals: a signing private key or the key that wraps it (root key or
`keys.signing_wrap_keys`) was exposed; tokens with valid signatures that the IdP
did not issue (no matching `token.issued` audit event).

Impact while the key is trusted: anyone holding it can mint access tokens for any
subject and audience that offline verifiers will accept, and ID tokens that
clients will accept. The IdP's own account/admin APIs additionally require a live
session ID and an active user and client, but session IDs appear in tokens (`sid`),
so treat admin APIs as exposed too.

1. **Rotate now**:
   `identity-cli api POST /signing-key-rotations '{"mode":"emergency","reason":"INC-..."}'`
   (permission `realm.keys.rotate`, authentication within the last 5 minutes). The
   active key becomes `compromised`, leaves JWKS, and the IdP rejects its tokens
   within 5 seconds; a new key is active immediately on the node that handled
   the request. Other server nodes keep their cached key set for up to 5
   seconds: until then they still accept the key's tokens and sign new tokens
   with it (those are rejected too once the window ends). Repeat per affected
   realm.
2. If the exposed key is not the active one (a `retiring` or `pending` key), the API
   cannot mark it. Database operator, last resort:
   `UPDATE signing_keys SET state='compromised', compromised_at=now() WHERE kid='<kid>';`
3. **Make verifiers drop the key.** Offline verifiers keep their cached JWKS. Restart
   them or force a JWKS refresh. The Go SDK verifier refreshes only on an unknown
   `kid`; a restart is the reliable option. Subscribed webhook consumers receive
   `signing_key.rotated` with `previous_key_compromised: true`.
4. **Record the exposure window** per relying service: from key exposure until that
   service dropped the key. Ordinary token expiry does not bound it.
5. **Revoke what may have been abused.** Sessions are not signed and need no action
   for the key itself, but if forged tokens reached admin APIs, review admin audit
   events for the window and follow "Compromised administrator account".
6. **If the root key or wrap key leaked** (not only one signing key): every
   encrypted secret is exposed. Rotate the root key ([keys.md](keys.md#root-key-rotation)),
   rotate signing keys again so they are wrapped under the new key, rotate every
   webhook secret, and plan TOTP re-enrollment (assisted recovery with `reset_mfa`
   or user self-service).
7. **Restores:** the compromise is exported by `identity-cli revocation-log` as
   `key_compromised`; see the ordering rule in [backup-restore.md](backup-restore.md#restore-procedure).

## Compromised root key, pepper or KMS access

Signals: a root, pepper or signing-wrap key file or variable was exposed; the
wrapped key files **and** credentials allowed to unwrap them with your KMS
were exposed (with `kms:` references, either alone is not enough); the KMS's
audit log shows unwraps you cannot attribute to a process start.

1. **KMS access only** (no unwrapped key left the hosts): revoke the exposed
   credentials or identity in the KMS and review its log. Running processes
   are unaffected; new starts need the remaining authorized identities.
2. **An unwrapped root or signing-wrap key**: every encrypted secret and every
   signing key wrapped under it is exposed. Generate a new version (wrapped
   in the KMS if you use one), distribute it, make it active
   ([keys.md](keys.md#root-key-rotation)), then run an emergency signing-key
   rotation in every realm so new signing keys are wrapped under the new
   version (`POST /signing-key-rotations {"mode":"emergency",...}`), rotate
   every webhook secret (`POST /webhooks/{id}/rotate-secret`), re-create
   hooks, send identity-provider client secrets again
   (`PUT /identity-providers/{id}`) after rotating them at the provider,
   send organization mail-server passwords and connector credentials again,
   and plan TOTP re-enrollment (`POST /me/totp/enroll` and `/activate`
   replace the authenticator and the recovery codes). Drain the old version
   with the checks in keys.md (which also list SAML signing keys and
   shared-signals stream headers) before removing it.
3. **A pepper key**: add a new pepper version; verifiers are re-peppered at
   each user's next successful sign-in. Users who do not sign in keep the old
   version, so to retire it force resets
   (`POST /users/{user}/credentials/password/compromised`) for the accounts the
   query in [keys.md](keys.md#password-pepper) still finds.
4. Record the exposure window and treat audit batch signatures made under
   the exposed version as forgeable from then on: rely on the audit archive
   and exports taken earlier.

## Compromised administrator account

1. **Stop the account**: `POST /users/{user}/suspend {"reason":"INC-..."}`
   (`realm.users.suspend`; administrators cannot change their own state). Suspension
   revokes all sessions, refresh families, offline grants and support grants where
   the user is actor or target, writes a `user` revocation record, and makes the
   user's personal access tokens inactive at introspection.
   If the compromised account is the only realm administrator, create a new one
   from the operator channel: `identity-cli bootstrap -realm <r> -email ... -username ... -break-glass`.
2. **Revoke automation the account controls.** Step 4 revokes the user's own
   personal access tokens and API keys
   (`GET /api-keys?owner_type=user&owner_id={user}` lists them). API keys of
   service principals it owns are the principal's and stay: find the
   principals (`GET /service-principals`, check `owner_user_id`), list their
   keys (`GET /api-keys?owner_type=service_principal&owner_id={principal}`) and
   revoke with `DELETE /api-keys/{id}`. Disable service principals it created
   if in doubt (`POST /service-principals/{id}/disable`).
3. **Remove privileges**: `GET /role-assignments?subject_type=user&subject_id={user}`,
   then `DELETE /role-assignments/{assignment}`.
4. **Reset credentials**: `POST /users/{user}/credentials/password/compromised`
   (the password stops working; sessions, grants, personal access tokens and the
   user's own API keys are revoked, and the owner gets a `credentials_revoked`
   notice naming them) and, if the second
   factor may be compromised, assisted recovery:
   `POST /users/{user}/recovery-requests {"reason":"...","evidence_reference":"INC-...","reset_mfa":true}`
   (revokes TOTP, passkeys and recovery codes and forces TOTP re-enrollment).
5. **Investigate**: `GET /audit-events?actor_id={user}` and `?subject_id={user}`;
   look for `client.*`, `role.*`, `authorization.role.assigned`, `webhook.*`
   (exfiltration endpoints), `signing_key.*`, `realm.policy.updated`,
   `job.result.downloaded` (exports), `support.impersonation.*`,
   `automation_credential.created`, `bootstrap.*`. Undo unauthorized changes through
   the API.
6. **Reactivate** only after recovery: `POST /users/{user}/reactivate`.

The same steps apply to ordinary user accounts, using organization-scoped actions
where the realm-wide account must stay active.

**An owner who reports a takeover** does not need suspension. Their own password
reset (`POST /password-resets`), or assisted recovery when they lost the second
factor or the address, revokes every session and grant, offline ones included,
and every personal access token and API key the user owns, in one transaction
(CRED-008, MCH-007; [account-recovery.md](account-recovery.md#rules-that-apply-to-every-path)).
Tokens minted while someone else controlled the account stop at the next
introspection, and introspection refuses any user-owned credential created
before that revocation. Then review `automation_credential.created` events for
the account (`GET /audit-events?subject_id={user}`) for tokens the attacker
minted and what they could reach, and the service principals it owns as in
step 2. "Log out everywhere" alone does **not** end personal access tokens.

## Compromised client secret

1. **Inspect** the client: `GET /clients/{client}` returns its credentials (ID,
   display prefix, state, last use) and resource grants.
2. **Issue a replacement** and give the old secrets a short expiry:
   `POST /clients/{client}/credentials {"retire_others_after_seconds": 300}`
   (at most three active secrets). Deploy the new secret to the client.
3. **Revoke the exposed secret**: `DELETE /clients/{client}/credentials/{id}`.
4. **If tokens may have been obtained with it**: `POST /clients/{client}/suspend
   {"reason":"INC-..."}` revokes every refresh family, grant and opaque token of
   the client and makes introspection report its JWTs inactive. Reactivate with
   `POST /clients/{client}/reactivate` after the new secret is deployed. JWTs
   already issued remain valid at offline verifiers until expiry.
5. For `private_key_jwt` clients, add the new public key
   (`POST /clients/{client}/credentials {"jwks": {...}}`) and revoke the old key
   credential by ID.
6. Review `client.authentication.failed` and `token.issued` audit events for the
   client.

## Compromised connector

A system ProudAuth trusts or sends data to is compromised: an upstream
identity provider (or its client secret), a pre-action hook endpoint, a
webhook receiver, an organization's mail server, the SMS gateway or a
challenge provider.

1. **Switch it off** without database edits (`realm.emergency`, reason
   required; [emergency controls](#emergency-controls-sec-020)):

   ```sh
   identity-cli api POST /emergency/controls '{"target_type":"identity_provider","target_id":"<id>","action":"disable","reason":"INC-..."}'
   identity-cli api POST /emergency/controls '{"target_type":"hook","target_id":"<id>","action":"disable","reason":"INC-..."}'
   identity-cli api POST /emergency/controls '{"target_type":"webhook","target_id":"<id>","action":"disable","reason":"INC-..."}'
   ```

   Disabling a registration-eligibility, profile-validation or authorization
   hook **lifts** the restriction it enforced; disable it only if the
   endpoint's answers can no longer be trusted. An organization's mail
   server: `DELETE /organizations/{org}/notification-settings/smtp` (MFA
   session; mail falls back to the deployment relay). The deployment relay,
   the SMS gateway and challenge providers are operator configuration:
   change the file and restart, or turn off `login.sms_otp` and remove the
   realm's `authentication_flow.challenge_provider` (`PUT /settings`)
   meanwhile.
2. **Upstream identity provider:** find sign-ins through it in the window:
   `GET /audit-events?type=federation.login.succeeded&from=...&to=...`
   (metadata `provider` names the connection) and `federation.identity.linked`
   events. Revoke those users' sessions (`POST /users/{user}/revoke-sessions`),
   remove links created by the attacker
   (`DELETE /users/{user}/linked-identities/{id}`), and review accounts it
   created just in time (`created: true` in the sign-in event's metadata). Such
   an account has no other sign-in method, so its link cannot be removed
   (`409 last_sign_in_method`): suspend or delete the account instead
   (`POST /users/{user}/suspend`). Rotate the client secret at the
   provider and send it with `PUT /identity-providers/{id}` (`If-Match`)
   before enabling the connection again.
3. **Webhook receiver:** it received event payloads (identifiers; `standard`
   payloads also other data fields) and holds the signing secret. Rotate it
   (`POST /webhooks/{id}/rotate-secret`; the old secret stays valid for 24
   hours, so disable the subscription if the receiver itself is hostile) and
   review what it subscribed to.
4. **Hook endpoint:** hooks have no secret rotation; delete the hook and
   create a new one (new secret) once the endpoint is trusted again. Review
   `GET /hooks/{id}/diagnostics` and the decisions it influenced in the
   window. A hook or subscription that a plugin manages (it shows a
   `plugin_id`) cannot be deleted or patched (`409`): switch it off with the
   emergency control or `POST /plugins/{id}/disable`, and replace it with a
   new plugin version. Installing or enabling the plugin again turns its
   parts back on.
5. **Lifecycle workflow endpoint** (the destination of a `call_webhook`
   step's subscription): disable the subscription with the emergency
   control (steps then fail and their runs compensate) or the workflow with
   `POST /workflows/{id}/disable`; the endpoint received subject and run IDs
   ([workflows.md](../integrations/workflows.md#step-call-contract)).
6. **Plugin publisher key or plugin package:** remove the key from
   `extensions.plugin_publishers` and restart, which stops uploads,
   installations and rollbacks signed with it; then disable or uninstall
   every plugin it signed (`GET /plugins` shows the publisher), because
   enabling does not re-check signatures. Review `plugin.*` audit events and
   the parts' `hook.*`, `webhook.*` and `workflow.*` events
   ([plugins.md](../integrations/plugins.md)).
7. Record the window; the evidence is in the audit log
   (`federation.provider.*`, `hook.*`, `webhook.*`, `notification.smtp.*`,
   `workflow.*`, `plugin.*`).

## Provisioning connector token compromise

A SCIM connector token (`pa_scim_...`) leaked, or the directory that holds it
is compromised ([scim-provisioning.md](../integrations/scim-provisioning.md)).
Paths are relative to `/api/v1/realms/{realm}/organizations/{org}`; each
request needs `org.integrations.write` in the organization and an MFA session.

1. **Stop the token.** Either issue a new one (the old token stops working at
   once; give the new one to the directory only when the directory is trusted):

   ```sh
   identity-cli api POST /organizations/{org}/provisioning-connectors/{id}/token
   ```

   or disable the connector. `PUT` replaces the whole definition, so send the
   current members back with `"state": "disabled"` and the `ETag` of the
   `GET` as `If-Match`:

   ```sh
   identity-cli api GET /organizations/{org}/provisioning-connectors/{id}
   # PUT the returned name, allowed_resource_types, role_ceiling_ids,
   # group_role_mappings, default_role_id and config with "state": "disabled"
   # and the header If-Match: W/"v<N>"
   ```

   Maintenance mode `restricted` refuses both requests. If you cannot make
   them, suspending the organization with an emergency control
   (`target_type: organization`) also stops the connector, but stops the
   whole organization.
2. **Know the limits of what the token could do.** A connector acts only in
   its own organization and only on users and groups it provisioned: it could
   create accounts and memberships, adopt existing accounts whose verified
   email is in a domain the organization verified (never protected accounts or
   holders of realm-scoped roles), change the name, username and email of
   accounts it created that belong to no other organization, suspend or remove
   memberships in its organization, and grant roles only through
   `default_role_id` and `group_role_mappings`, within `role_ceiling_ids`. It
   cannot change credentials, sessions, the realm-wide account state or
   anything in another organization.
3. **Review its actions** in the window. Connector events carry the
   connector as actor (type `connector`):

   ```sh
   identity-cli api GET '/audit-events?actor_id=con_...&from=...&to=...'
   identity-cli api GET '/audit-events?type_prefix=scim.&organization_id=org_...&from=...'
   identity-cli api GET '/audit-events?type_prefix=provisioning.connector.&organization_id=org_...'
   ```

   Look for `scim.user.provisioned` with `adopted: true` (existing accounts
   brought into the organization), `scim.user.updated` with
   `identity_changed: true` (name, username or email changes),
   `scim.user.deprovisioned`, `organization.membership.added` /
   `.suspended` / `.removed`, `group.member.added` and `role.assigned`, and
   `provisioning.connector.*` for changes to the connector itself (a wider
   ceiling or new mappings). Organization administrators can run the same
   queries on `GET /organizations/{org}/audit-events` (`org.audit.read`).
4. **Undo** unauthorized changes through the API: memberships with
   `PATCH /organizations/{org}/members/{membership} {"state": "active"}` or
   `DELETE /organizations/{org}/members/{membership}`, roles with
   `DELETE /organizations/{org}/members/{membership}/roles/{assignment}` (and
   group role assignments with `DELETE /role-assignments/{assignment}`), and
   identifiers of affected accounts through the user administration API. If an
   email address was changed, treat the account as possibly taken over
   ([Compromised administrator account](#compromised-administrator-account),
   steps 1 and 4).
5. Review the connector's `role_ceiling_ids` and `group_role_mappings` before
   enabling it again, and rotate the token as the last step.

## SAML key or counterparty compromise

See [saml.md](../integrations/saml.md). Paths are relative to
`/api/v1/realms/{realm}`.

- **The realm's SAML signing key leaked.** Whoever holds it can sign
  assertions that every SAML application of the realm accepts, and
  `AuthnRequest`s from the broker. Prepare a new key and activate it at once
  (category `emergency`, the reason is recorded):

  ```sh
  identity-cli api POST /saml/signing-keys '{"reason":"INC-..."}'
  identity-cli api POST /saml/signing-keys/{id}/activate '{"force":true,"reason":"INC-... SAML key compromise"}'
  ```

  The old key stays published for `saml.retired_key_publication`, and
  service providers keep trusting it until they drop its certificate: tell
  every SP's administrator to load the new metadata (`GET
  /realms/{realm}/saml/metadata`) and remove the old certificate. Until they
  do, suspend applications whose SP cannot be updated quickly
  (`POST /emergency/controls` with `target_type: client` and the
  application's backing client ID).
- **A SAML connection's IdP, or its signing key, is compromised.** Disable
  the connection (`target_type: identity_provider`); review sign-ins and
  links in the window (`federation.login.succeeded` with metadata
  `provider`, `federation.identity.linked`, accounts created just in time)
  as for any upstream provider ([Compromised connector](#compromised-connector),
  step 2). Before enabling it again, replace its `signing_certificates`
  through `PUT /saml/connections/{id}`.
- **A service provider is compromised.** It received assertions (NameIDs and
  mapped attributes) and holds its own signing key: suspend its backing
  client (`target_type: client`), and replace its `signing_certificates`
  before reactivating it. Its users' sessions are not affected by suspending
  it; revoke them if the SP could have used its key to send forged logout or
  sign-in requests.
- Evidence: `saml.assertion.issued`, `saml.request.rejected`,
  `saml.response.rejected`, `saml.signing_key.*` and `saml.application.*`
  (`GET /audit-events?type_prefix=saml.`).

## Directory connector compromise

A directory server, the service account it uses, a downstream SCIM service
or its bearer token is compromised ([directory.md](../integrations/directory.md),
[outbound-provisioning.md](../integrations/outbound-provisioning.md)). There
is no emergency control for directory connectors.

1. **Stop the connector.** `PUT .../directory-connectors/{id}` with the
   current definition, `"state": "disabled"` and the `ETag` of the `GET` as
   `If-Match`. For an organization connector, suspending the organization
   (`target_type: organization`) also stops it. A disabled LDAP connector
   makes its users' password sign-ins fail closed (`503`); that is the
   intended effect if the directory itself is not trusted. Setting
   `directory.enabled: false` and restarting stops every connector at once,
   with the same effect for all directory-sourced accounts.
2. **Rotate the credential** with `PUT .../credential` once the directory or
   downstream is trusted again (change the service account's password, or
   issue a new downstream token, there first).
3. **Know what it could do.** A hostile directory sees the passwords of its
   users at sign-in and, for a realm connector with `jit_provisioning`, the
   passwords typed for identifiers unknown locally; it can create, update,
   suspend and (above the deletion threshold only with an operator override)
   deprovision the accounts and memberships it manages, and grant the roles
   its group mappings allow, within its ceiling. It cannot touch protected
   accounts, holders of privileged realm roles or other organizations. A
   downstream SCIM service received the pushed attributes and cannot change
   anything in ProudAuth.
4. **Review its actions**: `GET /audit-events?actor_id=con_...` and
   `type_prefix=directory.` (`directory.user.provisioned`, `.linked`,
   `.updated`, `.deprovisioned`, `directory.sync.*`), the connector's runs and
   findings, and `operator_actions` in `.../health`. Revoke the sessions of
   accounts it changed if their identity attributes or state were altered.

## Federation-created verified addresses outside an organization's domains

Up to 0.2.0-alpha.4, a just-in-time account created through an
organization-scoped connection took the upstream's `email_verified` for any
address, and an organization administrator could enable
`jit_provisioning` without `allowed_email_domains`. An organization's
upstream could so give a realm-wide account a verified address in another
organization's domain, or in a public one. The address's real owner could
then not verify it (a verified address belongs to one account), and the
other organization's SCIM connector could adopt the account. From 0.2.0-alpha.5 such an address stays
unverified behind `verify_email`, and organization administrators enable JIT
only for their own verified domains
([oauth-oidc-profile.md](../protocols/oauth-oidc-profile.md#upstream-identity-providers)).
Accounts created before the upgrade keep what they got. After upgrading:

1. **List them** (read-only, `psql` against the primary). The query lists
   every address that a connection's just-in-time account holds verified on
   that connection's word, where the domain is not, today, a verified domain
   of the connection's organization (nor a subdomain of one verified with
   `include_subdomains`):

   ```sql
   SELECT p.realm_id, p.organization_id, p.alias AS connection, e.user_id,
          i.original_value AS email, i.verified_at, d.organization_id AS domain_owner
   FROM external_identities e
   JOIN identity_providers p ON p.realm_id = e.realm_id AND p.id = e.provider_id
   JOIN user_identifiers i ON i.realm_id = e.realm_id AND i.user_id = e.user_id
   LEFT JOIN organization_domains d ON d.realm_id = i.realm_id AND d.state = 'verified'
        AND d.domain = split_part(i.canonical_value, '@', 2)
   WHERE e.linking_provenance = 'jit'
     AND p.organization_id IS NOT NULL
     AND i.type = 'email' AND i.verified_at IS NOT NULL
     AND i.verification_source = 'federation:' || p.alias
     AND NOT EXISTS (
       SELECT 1 FROM organization_domains c
       WHERE c.realm_id = p.realm_id AND c.organization_id = p.organization_id AND c.state = 'verified'
         AND (c.domain = split_part(i.canonical_value, '@', 2)
              OR (c.include_subdomains
                  AND right(split_part(i.canonical_value, '@', 2), length(c.domain) + 1) = '.' || c.domain)))
   ORDER BY p.realm_id, p.alias, i.verified_at;
   ```

   `domain_owner` names the organization that verified the domain, if any.
   A connection renamed since the account was created no longer matches
   `verification_source`; drop that condition to see those accounts too
   (an address the user verified again later then also appears).
2. **Review each row** with the domain's owner. Evidence:
   `GET /audit-events?type=user.created&subject_id={user}` (metadata
   `provider`, `email_verified`) and the connection's
   `federation.login.succeeded` events.
3. **Stop accounts that hold someone else's address**: revoke their
   sessions (`POST /users/{user}/revoke-sessions`) and suspend them
   (`POST /users/{user}/suspend {"reason":"INC-..."}`); a just-in-time
   account has no other sign-in method, so removing its link is refused
   (`409 last_sign_in_method`). If the account must stay, clearing the
   verification is a database edit (record it in your incident log):
   `UPDATE user_identifiers SET verified_at = NULL, verification_source = NULL WHERE id = '<identifier id>'`
   and `UPDATE users SET required_actions = array_append(required_actions, 'verify_email'), updated_at = now() WHERE id = '{user}'`.
4. **Fix the connection**: an organization's JIT connection without
   `allowed_email_domains`, or listing domains it has not verified, is
   refused (`422`) at its next `PUT` through
   `/organizations/{org}/identity-providers`. Review such connections now
   (`GET /identity-providers`, `jit_provisioning` and
   `config.allowed_email_domains`) and correct them, or disable them
   (`"state": "disabled"`).

The same applies to `google` connections with `trusted_verified_email` and
no `allowed_tenants`: earlier releases believed Google's `email_verified` for
any address. Links they made appear in `federation.identity.linked` events
(metadata `provenance: "trusted_verified_email"`); review those whose address
is neither Gmail nor in a domain the Google Workspace tenant runs.

## Abuse spikes

Signals: `proudauth_authentications_total{outcome="failure"}`,
`proudauth_rate_limited_total`, `proudauth_load_shed_total` rising; bursts of
`authentication.password.failed`, `authentication.password.temporarily_locked`,
`registration.*` or code sends; an SMS daily budget exhausted; mail provider
complaints ([monitoring.md](monitoring.md#suggested-alerts)).

1. **Find the source**: `GET /audit-events?type_prefix=authentication.&network=<cidr>&from=...`
   narrows by network (stored as /24 or /48), client and organization;
   proxy logs give full addresses.
2. **Contain within the realm, without a restart** (realm policy changes
   apply on every node within the 2-second realm cache):
   - `authentication_flow` rules: `deny` or `challenge` for the offending
     `networks`, clients or organizations, or for `failed_attempts_at_least`
     and `risk_at_least` with a risk hook
     ([headless-authentication.md](../protocols/headless-authentication.md#authentication-flow-policy));
   - close sign-up (`registration.mode: closed`) or turn off code and link
     sign-in (`login.email_otp`, `login.magic_link`, `login.sms_otp`);
   - stop an abused client or grant class with an emergency control.
3. **Tighten deployment budgets** (`security.rate_limits.*`,
   `delivery.sms.daily_budget`; restart) and block the source at the proxy.
4. Watch the side effects: the temporary password lock also locks out the
   real owners of attacked accounts for `security.rate_limits.temporary_lock`
   (other sign-in methods keep working), and budgets that fail closed answer
   `429` or `503` to legitimate users of the same client or organization.
5. Afterwards, review accounts that signed in from the source and revoke
   their sessions if needed; record the rules you added and remove them when
   the spike is over (each policy change is audited as `realm.policy.updated`).

## Mass session revocation

| Scope | Action | Notes |
| --- | --- | --- |
| One user | `POST /users/{user}/revoke-sessions` or `identity-cli revoke-sessions -realm r -user usr_...` | Revokes sessions, offline grants, support grants; queues back-channel logout; publishes `session.revoked` events. |
| One client | `POST /clients/{client}/suspend` | Revokes the client's refresh families and grants; sessions survive. |
| One organization | `POST /organizations/{org}/suspend` (`realm.organizations.suspend`, MFA session) | Revokes all grants bound to the organization; new grants and refreshes fail; introspection reports the organization's user tokens inactive (membership checks require an active organization). Reactivation does not restore revoked grants. |
| A realm, stop new grants | `POST /emergency/realm-state {"state":"suspended","reason":"..."}` (`realm.emergency`) | Stops authorization, token issuance and refresh, and the realm's account/admin/tenant APIs. **Introspection still reports unexpired tokens active**, and discovery/JWKS stay up; combine with session invalidation. Reactivate with `{"state":"active"}`. |
| Every session in the deployment | `identity-cli restore-reconcile -invalidate-all-sessions` (operator) | Revokes all active sessions, refresh families and support grants **and all pending invitations** in **all realms**, in one transaction, audited as `operations.restore.reconciled`. Like every reconciliation it also ends every outstanding one-time proof (reset, verification, sign-in and account-setup codes and links, authorization and device codes, pending sign-in transactions; [backup-restore.md](backup-restore.md#what-reconciliation-re-applies)), so users mid-sign-in start again and account-setup links must be sent again. It updates rows directly: no back-channel logout deliveries and no `session.revoked` webhooks are produced. |

After any mass revocation, JWT access tokens remain usable at offline verifiers for
up to their remaining lifetime (default 5 minutes plus clock tolerance).

## Database unavailable or degraded

Behavior (docs/plan.md §31.2):

- `/health/live` stays 200 (it never touches dependencies) — do not let your
  orchestrator restart processes because the database is down.
- `/health/ready` returns 503 `{"status":"unavailable"}`; remove instances from load
  balancing.
- New grants, refresh, introspection, UserInfo and all custom APIs fail; the SDK
  `Introspector` returns `ErrUnavailable` and strict-online resources deny
  (TEST-035). Offline-verified JWTs keep working until expiry.
- Workers log `worker task failed` and retry on their next tick; queued work is not
  lost.
- A failure in the middle of a sensitive transition (refresh rotation, code
  exchange, password reset, invitation acceptance, ...) rolls the whole
  transition back: the client gets an error and no token, the refresh token,
  code or reset code it presented stays unconsumed (no reuse or replay
  revocation), and repeating the request once the database is back succeeds
  (TEST-059, `TestTransactionFaultsLeaveNoPartialState`).
- Slow database: queries are cancelled after `storage.statement_timeout` (10 s);
  requests are bounded at 30 s; excess concurrency is shed with 503 once
  `limits.max_inflight_requests` is reached.

Steps:

1. Check `/status` on the internal listener (`capabilities`, `schema`,
   `backlog_oldest_seconds`, `clock_skew_ms`; see
   [monitoring.md](monitoring.md#operator-status)) and PostgreSQL itself.
2. If failover to a standby lost recent transactions, treat it as a restore:
   reconcile with the revocation log ([backup-restore.md](backup-restore.md)).
3. If readiness fails with the database up, run `identity-cli doctor`: a schema
   behind the binary needs `identity-cli migrate`; an unusable signing key means
   wrong root keys or a missing active key.

## Database loss

The database (or its storage) is lost or corrupted beyond repair, or a
failover lost committed transactions.

1. Put the service into maintenance (`identity-cli maintenance -mode unavailable
   -message "..."`) or take the instances out of the load balancer, and stop
   `identity-worker`.
2. Follow the [restore procedure](backup-restore.md#restore-procedure): restore
   the newest usable backup or point in time, configure the same keys and
   compare the `identity-cli doctor` fingerprint, migrate if the binary is
   newer, mark the database with `identity-cli restore-begin` (it then stays
   unready until reconciled), collect the revocation logs exported by `identity-cli revocation-log`
   since the backup, mind the ordering rule for compromised signing keys, and
   run `identity-cli restore-reconcile -log ...` (add
   `-invalidate-all-sessions` when the log does not cover the whole gap).
3. Apply the manual remedies for what reconciliation does not cover
   ([backup-restore.md](backup-restore.md#what-reconciliation-does-not-cover)),
   including audit evidence lost since the backup: it survives only in the
   audit archive and exports.
4. Verify (`identity-cli doctor`, `identity-cli verify-audit`, a synthetic
   sign-in and introspection), set maintenance `off`, then start the worker.

`TestRestoreReconciliation` exercises the export and reconciliation logic on a
copied database; measure your own recovery time in restore drills.

## Audit chain verification failure

Run `identity-cli verify-audit` (operator). It verifies the whole
`audit_batches` chain across all realms, including batch signatures, and prints
`batches_checked`, `events_checked`, `unsealed_events`,
`batches_signature_verified`, `batches_pruned_by_retention`, the `problems` list
and `ok`, plus the current audit signing key (`kid` and Ed25519 public key) for
independent verifiers; it exits non-zero when `ok` is false. Add
`-require-signatures` once every batch has been sealed with signing, so unsigned
batches count as problems. `GET /audit-integrity` (`realm.audit.read`) returns
only a cached deployment-wide summary (`ok`, `batches_checked`,
`events_checked`, the number of `problems`, `scope`, `checked_at`), recomputed at
most every 10 minutes; use the CLI for details. The worker also verifies the
newest 200 batches every hour (`audit.verify_recent`) and reports what it finds
as `proudauth_audit_integrity_problems` and an `audit integrity problems` log
line ([monitoring.md](monitoring.md#suggested-alerts)); it names no details, so
run the CLI.

Interpret problems:

| Problem | Likely cause |
| --- | --- |
| `batch <id> events digest mismatch` | Events of the batch were deleted or altered. Retention does **not** cause this: it removes sealed events whose retention has passed (`privacy.audit_retention`, or `privacy.audit_retention_by_category`, extended by realm or organization retention; never category `emergency` or events under a legal hold), records the first pass over each batch in the append-only `audit_prunes` ledger and later passes in the append-only `audit_prune_log`, and the verifier skips the digest check for batches in `audit_prunes` (`batches_pruned_by_retention`) while still checking their retained events and chain position. A mismatch on a batch without an `audit_prunes` row means events were removed by someone bypassing the triggers: security incident. Every prune goes through `proudauth_audit_prune`, which writes the ledger itself and does not check age, so a prune made with a stolen runtime credential looks like retention here: when in doubt, compare `audit_prunes` and `audit_prune_log` with the retention settings and the archived copies of the batch. |
| `batch <id> signature missing or invalid` | With `-require-signatures`: a batch sealed before signing was enabled (expected for old batches). Otherwise, or for recent batches: the signature or key ID was altered, or the root key (or `signing_wrap_keys`) version named in the key ID is no longer configured. |
| `event <id> content hash mismatch` | The row changed after it was written. The append-only trigger blocks normal updates, so someone with table-owner or superuser rights disabled or bypassed it. Treat as a security incident. |
| `batch sequence gap`, `previous hash mismatch`, `batch <id> hash mismatch` | Batch rows were deleted or altered (also requires bypassing the trigger). Security incident. |
| Large and growing `unsealed_events` | `identity-worker` is not running or its `audit.seal` task fails (also visible as `proudauth_audit_unsealed_oldest_seconds` and `/status` `audit_sealing`). Not tampering. |

### Audit archive (AUD-008)

With `privacy.audit_archive_dir` set, the worker task `audit.archive` copies
every sealed batch, within about a minute, to a write-once file
`batch-<12-digit sequence>.ndjson` in that directory: a header line
(`record: "batch"`, `batch_id`, `sequence`, `previous_hash`, `events_digest`,
`batch_hash`, `signature`, `signing_kid`, `event_count`, and `archived_events`
when the file holds fewer events than were sealed) followed by the batch's
events as stored, one JSON object per line. Files are created exclusively and
read-only (`0440`); an existing file is accepted only when it is
byte-identical. Progress is kept in `audit_archive_state` (`last_sequence` and
the current `directory`). Mount storage the operator controls independently
of the database there (a separate volume, object storage with retention locks
or a WORM device); ProudAuth never deletes archived files.

While an archive is configured, retention prunes only events of batches that
are already archived (sequence at most `audit_archive_state.last_sequence`):
nothing is pruned before the first archive run, and an archive that stops also
holds back retention, so every archived file is complete. Only batches pruned
before the archive was configured are archived without their pruned events;
their header records the number of events written as `archived_events`.

**After a database restore** the restored database seals new batches under
sequence numbers the archive already holds with other content (the lost
period). The worker re-archives from the restored `last_sequence`, accepts
files that are identical, and at the first sequence whose file differs it
leaves the existing file in place, creates
`fork-<12-digit sequence>-<batch id>/` in the archive directory, writes the
batch there and continues in that directory (migration `0039`). It records the
operator event `audit.archive.forked` (category `audit`, no realm; metadata
`sequence` and `directory`). The main directory keeps the lost period's files
as evidence; do not move or delete them.

`identity-cli verify-audit-archive [-config <file>] [-dir <path>]` (default
directory: `privacy.audit_archive_dir`) needs no database connection; it loads
the configured keys only to check signatures. It verifies the main directory
and every `fork-*` directory: each event's content hash, each complete batch's
events digest, each batch hash, a valid signature on every batch, and the
links between files. It prints the report of `verify-audit`
(`batches_checked`, `events_checked`, `batches_signature_verified`,
`batches_pruned_by_retention`, `problems`, `ok`) plus `first_sequence` and
`last_sequence` of the main directory and the `forks` it found, and exits
non-zero when `ok` is false. Problems in a fork are prefixed with its
directory name.

| Problem | Meaning |
| --- | --- |
| `batches N to M are missing from the archive` | Files are missing between two archived batches |
| `batch N does not link to the previous archived batch` | The file's `previous_hash` is not the previous file's `batch_hash`: a file was replaced or altered |
| `batch 1 does not start the chain` | The first batch's `previous_hash` is not 64 zeros |
| `<fork>/batch N does not link to archived batch N-1` | A fork's first batch does not continue the main archive's batch before it |
| `batch N: X events in the file, header records Y` | The line count differs from the header's `archived_events` |
| `batch N: events missing from the archived file` | The file holds fewer events than `event_count` and has no `archived_events`, or it follows a complete file (batches pruned before archiving form a leading run; their short files are counted in `batches_pruned_by_retention`) |
| `batch N events digest mismatch`, `batch N hash mismatch`, `event <id> content hash mismatch` | Content changed after archiving |
| `batch N signature missing or invalid` | The signature or key ID was altered, the batch was sealed before signing was enabled, or the keys for its key ID are not configured |
| `batch-<sequence>.ndjson: missing batch header`, `...: unreadable event` | The file is truncated or is not an archive file |

Limits: the verifier sees only files. It cannot tell that the newest files are
missing, or that leading files are missing when the first file is not batch 1:
check that `first_sequence` is `1` and compare the newest file (in the main
directory, or in the newest fork after a restore) with
`SELECT last_sequence, directory FROM audit_archive_state` and
`SELECT max(sequence_number) FROM audit_batches`. A fork's first link is
checked against the main directory only, so after a second restore that forks
a fork, check the new fork's first `previous_hash` against the earlier fork by
hand.

For suspected tampering:

1. Snapshot the database and PostgreSQL logs; restrict superuser access.
2. Compare affected events with the audit archive and with independently
   exported NDJSON audit exports (each archived or exported event includes its
   `content_hash`) to find the original values.
3. Identify who holds table-owner or superuser rights; the application role should
   not need them after migrations.
4. Remember the limit: an operator who controls the database, keys and backups can
   rewrite the entire chain consistently. Batches are hash-linked and signed with
   a key derived from the root key, so a rewrite also needs the keys; no external
   anchoring is built in, so only copies on storage the database operator cannot
   change (the audit archive, regular exports) and a recorded audit signing
   public key detect a full rewrite.

## Email or webhook delivery outage

Email:

1. Inspect `GET /notification-jobs?reference_type=...&reference_id=...` (state,
   attempts, `last_error`, masked recipient). Jobs retry with exponential backoff
   (10 s × 2^attempt) for 5 attempts, then `failed`; jobs past their expiry become
   `expired`.
2. Test the relay: `POST /notification-settings/check` connects, negotiates TLS and
   authenticates without sending anything and returns `{"ok", "stage"}`, where
   `stage` names the failing step (`connect`, `greeting`, `starttls`,
   `credentials`, `authentication`) or `ok` (`not_applicable` for the development
   sink); the server's error text stays in the operator log (`smtp.check_failed`). `POST /notification-tests` then sends a test
   message to the calling administrator's own verified address. Provider acceptance
   does not prove inbox delivery.
   Jobs in state `suppressed` were not sent on purpose: the recipient muted that
   optional notice, or the address is suppressed after a hard bounce or complaint
   reported through `POST /delivery-events`. Mandatory messages (codes, links,
   security notices) are never suppressed.
   An organization with its own mail server (TEN-022,
   `GET /organizations/{org}/notification-settings/smtp`) sends all its mail
   there, and `/notification-settings/check` does not test that server: if only
   one organization's mail fails, check its server with the organization's
   owner, or remove it (`DELETE .../notification-settings/smtp`,
   `org.integrations.write`) to fall back to the deployment relay. A server whose
   address the delivery egress policy refuses fails every attempt. A server
   that accepts connections and then never answers fails each attempt after
   the 30 s SMTP session deadline (`last_error` names an i/o timeout); the
   worker goes on with other jobs and tasks meanwhile.
3. One-time codes expire after `tokens.challenge_ttl` (10 min); after the outage
   users request a new code (send budgets and cooldowns still apply). Do not mark
   addresses verified to work around an outage; `POST /users/{user}/verification-overrides`
   exists for documented exceptions only and is audited.

SMS: jobs to the SMS gateway are notification jobs like email; inspect them
the same way. `proudauth_delivery_total{channel="notification"}` on the worker
listener shows `failed` and `expired` outcomes for both. Users can sign in with
other methods meanwhile; SMS codes are never a second factor.

Webhooks:

1. `GET /webhooks/{id}/backlog` summarizes one subscription (EXT-005): counts of
   `pending`, `retrying`, `dead_letter` and `delivered` deliveries,
   `oldest_due_seconds`, `last_delivered_at` and `last_failure_category`.
   `GET /webhooks/{id}/deliveries` shows state, attempts, last status and response
   category (`network_error`, `egress_denied`, `http_500` and other status
   classes such as `http_400`, `gone`, ...). Retries use
   exponential backoff with jitter (5 s × 2^attempt, capped at 6 h) up to
   `delivery.webhook_max_attempts` (12), then `dead_letter`. HTTP 410 dead-letters
   immediately.
2. After the receiver is fixed, replay: `POST /webhooks/{id}/deliveries/{delivery}/replay`
   (keeps the original `event_id`).
3. Paused subscriptions (`PATCH /webhooks/{id} {"state":"paused"}`) do not receive
   events published while paused; those are not queued for later.
4. Back-channel logout deliveries retry up to 8 times and then stay `failed`; there
   is no replay API.

## Organization owner recovery

An organization has lost access to its owner: the only owner left, lost
their credentials, or is suspended or compromised. Last-owner protection
keeps the organization from losing its last owner role, so recover the
account or add an owner.

1. **The owner can be identified and reached:** recover the account
   ([account-recovery.md](account-recovery.md)): lost factor with
   `POST /users/{user}/recovery-requests` (`reset_mfa`), lost contact address
   by adding, verifying (override) and promoting the new address first. For a compromised owner, follow
   [Compromised administrator account](#compromised-administrator-account)
   first.
2. **Ownership must move:** a realm administrator (the built-in `realm-admin`
   role holds `org.*` in every organization) confirms the request through the
   organization's own channel, records the evidence, and transfers ownership
   to an active member:

   ```sh
   identity-cli api GET /organizations/{org}/members                     # find the new owner's membership ID
   identity-cli api POST /organizations/{org}/ownership-transfers '{"membership_id":"mem_..."}'
   ```

   The member receives the owner role (audit
   `organization.ownership.transferred`). `release_current_owner` releases only
   the caller's own ownership, so remove the former owner's owner role
   afterwards if needed (`GET /role-assignments?subject_type=user&subject_id={user}`,
   `DELETE /role-assignments/{assignment}`); it is no longer the last owner.
   Transfers take the exclusive organization lock directly and check
   current authority after waiting. A caller whose authority came only
   from the owner role loses it after self-release; a realm administrator
   retains their independently granted recovery authority. Concurrent
   retries cannot remove the last active owner.
3. Tell the organization's members through your own channel; notices are not
   sent automatically.

## Privacy deletion errors

An account deletion did not propagate, a scheduled deletion did not run, or a
restore brought deleted data back.

1. **Check the report**: `GET /users/{user}/deletion-status`
   ([data-inventory.md](data-inventory.md#deletion-propagation-report)).
   `409` means the account is not deleted (its `state` is in the response).
2. **Scheduled self-service deletion not done**: accounts in
   `pending_deletion` are deleted by the worker task `lifecycle.expiry` once
   `deletion_scheduled_at` has passed. Check that `identity-worker` runs and
   look for `worker task failed` with `task=lifecycle.expiry` (one failing
   account stops the rest of that run). An administrator can delete at once
   with `DELETE /users/{user}`.
3. **Pending stages**:
   - `sessions_and_grants` should be `0` right after deletion; if not,
     revoke them (`identity-cli revoke-sessions -realm <r> -user usr_...`) and
     check again;
   - `connectors`: the `user.deleted` event has not reached every webhook
     receiver; fix the receiver and replay
     (`GET /webhooks/{id}/backlog`, `POST /webhooks/{id}/deliveries/{delivery}/replay`);
   - `exports`: purged by `retention.cleanup` after `privacy.export_retention`;
   - `imported_audit_history`: records left under a legal hold. Releasing the
     hold does not clear them later; once it is released, clear them with a
     reviewed database update mirroring account deletion and record it.
4. **Deleted data back after a restore**: run `identity-cli restore-reconcile`
   with revocation logs that contain the deletion's tombstone; it re-applies
   the deletion, including imported audit records. What it leaves is listed
   in [backup-restore.md](backup-restore.md#what-reconciliation-does-not-cover).
5. **Backups**: the `backups` stage dates when the last backup holding the
   account expires (`privacy.backup_retention`); ProudAuth does not delete
   backups.

## Support impersonation abuse

1. **Find grants**: `GET /impersonation-grants?actor_user_id=...&state=active`
   (`support.impersonation.read`; without it operators see only their own).
2. **End access**:
   - one grant: `POST /impersonation-grants/{id}/revoke {"reason":"INC-..."}`
     (`support.impersonation.revoke`, the actor, or the target customer);
   - all grants of an operator: remove their `support-operator` assignment
     (`DELETE /role-assignments/{id}`). Every introspection re-checks
     `support.impersonation.start`, so all their tokens stop working at the next
     request. Or suspend the operator (`POST /users/{user}/suspend`), which revokes
     their sessions and their grants.
3. **Stop new access**: set realm policy `impersonation.enabled: false`
   (`PUT /settings`) or deployment `impersonation.enabled: false` and restart.
   These switches block new requests, approvals and issuance, and every
   introspection re-checks them, so live support tokens become inactive at their
   next use. The grants themselves stay `active` until they expire (within
   `impersonation.max_ttl`, at most 5 minutes); revoke them as in step 2 to record
   the end explicitly.
4. **Evidence**: correlate by grant ID with
   `GET /audit-events?impersonation_grant_id=imp_...`: `support.impersonation.requested`,
   `.approved`, `.started`, `.revoked`, `support.handoff.*`, and
   `support.token.introspected` (one per introspection). Collect the resource
   servers' own `SupportEvent` records.
5. **Notify** affected customers if realm policy `notify_customer` was off; customers
   can view grants at `GET /me/impersonation-grants`.

## Emergency controls (SEC-020)

One audited endpoint switches off a grant class, client, identity provider,
organization, service principal, pre-action hook or webhook subscription without
database edits (`internal/httpapi/emergency.go`, `TestEmergencyControls`). It
needs `realm.emergency` (held by the built-in `realm-admin` role) and a reason:

```sh
identity-cli api POST /emergency/controls \
  '{"target_type":"grant_type","target_id":"refresh_token","action":"disable","reason":"INC-42 refresh token theft"}'
```

- `target_type`: `grant_type`, `client`, `identity_provider`, `organization`,
  `service_principal`, `hook` or `webhook`. `target_id` is the target's internal
  ID (for clients the `cli_...` ID, not the OAuth `client_id`) or, for
  `grant_type`, one of `authorization_code`, `refresh_token`,
  `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code` and
  `urn:ietf:params:oauth:grant-type:token-exchange`.
- `action`: `disable` or `enable`; `reason`: required, at most 500 characters.
- Response: `{"target_type", "target_id", "state": "disabled" | "enabled"}`.
- `GET /emergency/controls` (`realm.emergency`) shows what is switched off:
  `realm_state`, `disabled_grant_types`, and the IDs of suspended clients and
  organizations and of disabled identity providers, service principals, hooks and
  webhooks (up to 200 of each).

| Target | `disable` | `enable` | Audit event |
| --- | --- | --- | --- |
| `grant_type` | Adds the grant to `realms.disabled_grant_types`; every node applies it within the 2-second realm cache. The token endpoint refuses the grant, and for `authorization_code` and the device grant the authorization and device-authorization endpoints refuse to start the flow, with `unauthorized_client`. While `refresh_token` is disabled, refresh requests fail and code and device grants issue no refresh token. Tokens already issued stay valid until they expire. The operator CLI client `proudauth-cli` is exempt, so `identity-cli login` keeps working and the control can always be reversed. | Removes it; existing refresh tokens can be used again | `realm.grant_type.disabled` / `.enabled` (`emergency`) |
| `client` | Same as `POST /clients/{client}/suspend`: refresh families, grants and opaque tokens of the client are revoked | Sets the client `active`; revoked grants are not restored. Decommissioned clients cannot change state | `client.suspended` / `client.active` (`emergency`) |
| `identity_provider` | The connection becomes `disabled` without revalidating its configuration (works while the upstream is unreachable); starting a sign-in or link through it is refused with `422 validation_failed` (`provider`: "unknown or disabled connection"), and a round trip that was already at the upstream ends with `connection_disabled` when it returns, without contacting the upstream again or signing anyone in. `feature_disabled` when `federation.enabled` is `false` | Sets it `active` | `federation.provider.state_changed` (`emergency`) |
| `organization` | Same as `POST /organizations/{org}/suspend`: grants bound to the organization are revoked | Sets it `active`; revoked grants are not restored | `organization.suspended` / `.reactivated` (`emergency`) |
| `service_principal` | Same as `POST /service-principals/{id}/disable`: issuance stops, its API keys and opaque tokens are revoked | Sets it `active`; revoked keys stay revoked | `service_principal.disabled` / `.active` (`emergency`) |
| `hook` | The hook is no longer called, and its destination is not re-resolved. **A disabled registration-eligibility, profile-validation or authorization hook stops restricting anything**: the decision it enforced is lifted, not failed closed | Calls resume | `hook.state_changed` (`emergency`) |
| `webhook` | No deliveries are created for events published while it is disabled, and queued deliveries wait; the destination is not re-resolved | Queued deliveries resume | `webhook.state_changed` (`emergency`) |

Every audit event recorded while a control runs is filed in the `emergency`
category, and events without a reason of their own carry the operator's
`reason` as their reason code. Client, organization and service-principal
controls therefore produce the same event types as their ordinary routes, but in
that category and with the reason. Events in the `emergency` category are kept
beyond `privacy.audit_retention` and raise the `emergency_action` security
signal ([monitoring.md](monitoring.md#suggested-alerts)); list them with
`GET /audit-events?category=emergency`.

The endpoint stays available in maintenance mode `restricted` but not in
`unavailable` (see below). Signing keys are handled by emergency rotation (see
"Compromised signing key"), a whole realm by `POST /emergency/realm-state`.

Other controls:

| Control | Endpoint |
| --- | --- |
| Suspend / reactivate an organization | `POST /organizations/{org}/suspend`, `/reactivate` |
| Suspend / reactivate / decommission a client | `POST /clients/{client}/suspend`, `/reactivate`, `/decommission` |
| Disable a service principal | `POST /service-principals/{id}/disable` |
| Suspend / lock / reactivate a user | `POST /users/{user}/suspend`, `/lock`, `/reactivate` |
| Suspend, lock, reactivate or sign out many users | `POST /user-bulk-operations` ([exit-and-export.md](exit-and-export.md#bulk-user-operations)) |
| Pause a webhook | `PATCH /webhooks/{id} {"state":"paused"}` (a state-only change does not re-resolve the destination; refused with `409` for subscriptions a plugin manages) |
| Suspend a realm | `POST /emergency/realm-state` |
| Stop a lifecycle workflow | `POST /workflows/{id}/disable` (`realm.workflows.publish`; audited in category `emergency`; triggers stop and runs pause, compensation and cancellation continue; `409` for plugin workflows) ([workflows.md](../integrations/workflows.md)) |
| Stop a plugin | `POST /plugins/{id}/disable` (`realm.plugins.manage`; audited in category `emergency`; disables every hook, subscription and workflow of the plugin in one transaction) ([plugins.md](../integrations/plugins.md)) |

## Maintenance mode (OPS-015)

`identity-cli maintenance` (operator channel, `internal/maintenance`,
`TestMaintenanceAndStatus`) refuses requests deployment-wide while you work on
the database, keys or configuration:

```sh
identity-cli maintenance -mode restricted -message "Planned maintenance until 14:00 UTC" -retry-after 900
identity-cli maintenance              # print the current state
identity-cli maintenance -mode off
```

| Mode | Served on the public listener | Refused |
| --- | --- | --- |
| `off` | Everything | — |
| `restricted` | Every `GET`, `HEAD` and `OPTIONS` request; every request to the protocol endpoints under `/realms/{realm}/` (authorization, token, PAR, device authorization, introspection, revocation, UserInfo, logout) and `/.well-known/`; authentication transaction steps (`/auth/transactions/...`); emergency controls (`/emergency/...`); requests that only take access away (`DELETE` on `.../sessions...`, `POST` to paths ending in `/revoke`, `/revocations`, `/revoke-sessions`, `/suspend` or `/lock`) | Every other write: administration, self-service, tenant changes, `POST /registrations`, password resets and verification challenges, so configuration stays frozen |
| `unavailable` | `/health/*`, `/.well-known/*`, and per realm JWKS, discovery, introspection, revocation and `oidc/logout`: resource servers keep validating tokens and users can still sign out | Everything else, including reads and sign-in |

- The state is one row in `system_state` (migration `0025`); every server reads it
  at most every 2 seconds, so a change applies to the whole deployment within
  that time. If the database cannot be read, a server keeps the last state it
  saw.
- Refusals are `503` problem documents with code `maintenance` (on the OAuth
  and OIDC endpoints under `/realms/{realm}/oauth/` and `/oidc/`, an OAuth
  `temporarily_unavailable` error with the message as `error_description`), a
  `Retry-After` header (`-retry-after`, default 300 seconds, at most 86400;
  `0` sends the 2-second default) and, as `detail`, the `-message` (plain
  text, at most 200 characters, no `<`, `>` or line breaks). The message is shown to anonymous clients; do not put internal
  details in it. Running the command with `-mode` but without `-message` clears
  the message.
- Readiness is not affected: instances stay in load balancing and answer with
  the maintenance problem. `/status` on the internal listener reports the mode
  and turns its overall `status` into `maintenance`.
- `restricted` matches these requests by method and path only. It lets through
  `POST /users/{user}/revoke-sessions`, `POST /users/{user}/suspend` and
  `/lock`, client and organization suspension, and other `POST` routes ending in
  `/suspend`, so access can be taken away during maintenance; reactivation and
  other changes (including `POST /service-principals/{id}/disable`; use the
  emergency control instead) are refused.
- `identity-worker` is not paused: deliveries, jobs and other tasks keep running.
- Each change is audited as `operations.maintenance.changed` (actor
  `local:<OS user>`, metadata `mode`, `retry_after_seconds` and
  `public_message`) in the same transaction as the change, so a change is never
  stored without its audit event or the reverse.
- Server binaries that predate migration `0025` ignore the setting; finish a
  rolling upgrade before relying on it.
