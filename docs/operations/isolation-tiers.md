# Isolation tiers

ProudAuth can separate customers at three levels (TEN-019). This page
describes what each tier separates and what it still shares, so you can pick
the weakest tier that meets your customers' requirements. The boundaries
themselves are defined in
[ADR 0006](../architecture-decisions/0006-realm-and-organization-boundaries.md).

| Tier | Customer is | Separates | Still shares |
| --- | --- | --- | --- |
| 1. Organization per customer (default) | An organization in a shared realm | Memberships, roles, groups, policy, domains, connections, provisioning, webhooks and audit queries per organization; one organization per business token | Issuer, signing keys, realm policy, user accounts, clients |
| 2. Realm per customer | A realm in a shared deployment | Issuer, signing keys and rotation, realm policy, users, clients, organizations, audit queries and retention extensions | Database, root and pepper keys, KMS, binary and schema version, operators, worker capacity, deployment configuration, audit hash chain |
| 3. Deployment per customer | Its own ProudAuth installation | Everything: database, keys and KMS, operators, configuration, upgrade cadence, network boundary | Nothing at run time; you run N installations |

## 1. Organization per customer in a shared realm (default)

Customers are organizations of one realm. The realm's issuer
(`<server.public_origin>/realms/<realm>`) and signing keys are shared, and a
person has one account that can belong to several organizations.

- **Isolation:** every organization-scoped record carries `organization_id`;
  a business token names at most one organization
  ([ADR 0012](../architecture-decisions/0012-one-organization-per-token.md));
  organization administrators act only in their organization (TEN-*,
  `TestTenantIsolationAcrossServices`, `tenant_matrix_test.go`); resource
  servers filter by `org_id`.
- **Per-organization controls:** sign-in methods and SSO requirements,
  scope ceilings, connections, SCIM connectors, domains, webhook
  subscriptions, notification settings and an own SMTP server, audit
  retention extensions and legal holds, emergency suspension, asynchronous
  deletion.
- **Noisy neighbours:** per-organization sign-in and token budgets
  (`security.rate_limits.login_per_organization`, `organization_per_window`)
  and worker fair shares (`workers.tenant_batch_share`,
  `workers.max_jobs_per_organization`, TEN-018).
- **Cross-customer work** happens only through explicit
  [relationships and project grants](../integrations/partner-access.md).
- **Limits:** all customers trust the same issuer and keys; a realm policy
  change (password rules, MFA, flow rules) applies to all of them; a realm
  administrator sees every organization.

## 2. Realm per customer

Each customer gets a realm (`identity-cli realm-create -name <customer>`)
in the same deployment.

- **Separate issuer:** `<server.public_origin>/realms/<customer>`, with its
  own discovery document and JWKS. A verified custom domain
  ([installation.md](installation.md#custom-domains)) gives the customer
  their own host for browser and client traffic, but **the issuer, token
  contents and subjects keep the public origin**; the issuer path, not the
  host, is what separates realms.
- **Separate signing keys** per realm, rotated per realm (planned and
  emergency rotation, [keys.md](keys.md)); a compromised realm key does not
  affect other realms' tokens.
- **Separate configuration and data:** realm policy (password, MFA,
  passkeys, sessions, flow rules), users (an email address can exist in
  several realms as unrelated accounts), clients, resources, organizations,
  connections, hooks and webhooks. Realm administrators of one realm have no
  authority in another.
- **Per realm:** audit queries and exports, audit retention extensions, the
  realm data export for portable exit
  ([exit-and-export.md](exit-and-export.md#realm-data-export)), realm
  suspension as an emergency control (`POST /emergency/realm-state`), sign-in
  budgets per realm (`security.rate_limits.login_per_realm`,
  `send_per_realm`, `signup_per_realm`).
- **Shared:**
  - one PostgreSQL database and one schema version: **migrations and
    upgrades apply to all realms at once**, and a restore or
    restore reconciliation covers the whole database;
  - root keys, pepper keys, signing-wrap keys and the KMS command: one key
    custody for every realm (a root-key compromise affects every realm);
  - the deployment configuration (egress, residency allowlist, limits, MFA
    floor, token lifetime caps) and the operators who hold it;
  - the audit hash chain and archive, which are deployment-wide;
  - worker capacity: fair shares are per organization, and messages and
    jobs without an organization are shared per realm or not capped at all;
  - availability: one database outage or overload affects every realm.
- **Not available:** deleting a realm (there is no realm deletion API or
  command: suspend the realm, and delete its accounts one by one where
  erasure is required), per-realm database placement or data residency,
  per-realm key custody, per-realm upgrade timing.

## 3. Deployment per customer

Each customer gets an installation of its own
([installation.md](installation.md)): its own database, root and pepper keys
(or KMS keys), configuration, operators, backups, audit archive and network
boundary.

- **Separates everything** the realm tier shares: key custody, schema version
  and upgrade cadence, residency (database and outbound allowlist), egress
  rules, monitoring, backups and restores, blast radius of an outage or a
  compromise.
- **Costs:** every deployment is upgraded, migrated, monitored, backed up and
  drilled separately ([upgrades.md](upgrades.md),
  [backup-restore.md](backup-restore.md)); fleet tooling, configuration
  review (`identity-cli config-diff`) and alerting are yours to automate;
  capacity cannot be pooled. There is no shared sign-in across deployments
  unless one federates with another as an upstream provider.

## Choosing

| Concern | Organization | Realm | Deployment |
| --- | --- | --- | --- |
| Issuer | Shared | Own issuer path (shared host unless a custom domain serves it; the issuer always uses the public origin) | Own |
| Signing keys | Shared | Own, rotated per realm | Own |
| Root, pepper and wrap keys, KMS | Shared | Shared | Own |
| Schema migrations and upgrades | Shared | Shared, all realms at once | Own cadence |
| Backup and restore | Shared database | Shared database; no per-realm restore | Own |
| Data residency | Deployment-wide | Deployment-wide | Per deployment |
| Blast radius (outage, key or operator compromise) | Realm and deployment | Deployment | Customer |
| Accounts | One account across organizations | Separate per realm | Separate |
| Operating cost | Lowest | Low: one installation, more configuration | Highest: N installations |

Moving a customer to a stronger tier is a migration: the issuer changes,
relying parties must be reconfigured, subjects change (`usr_...` IDs are
per installation and realm) and passkeys must be registered again. Use the
configuration export and import for clients, resources and roles, and the
user import and runbook in [migration.md](migration.md) for accounts.
