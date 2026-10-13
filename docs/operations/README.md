# Operations

Runbooks and reference material for operators (docs/plan.md §30, §31, §34,
OPS-*). Every procedure here uses commands and endpoints that exist in this
repository; where the specification asks for something that is not implemented,
the document says so.

| Document | Contents |
| --- | --- |
| [installation.md](installation.md) | Production installation, database role separation, custom domains, bootstrap of the first administrator, configuration validation rules |
| [docker-compose.md](docker-compose.md) | Source-free release installation, image pulls, demo/production profiles, first administrator enrollment and lifecycle commands |
| [environment.md](environment.md) | Every adjacent `.env` variable, file-backed secrets, custody, idempotent initialization and configuration updates |
| [configuration.md](configuration.md) | Every configuration key with its default and effect; environment overrides; secret references; reviewing a change with `identity-cli config-diff` |
| [keys.md](keys.md) | Key hierarchy, root-key and pepper custody, KMS envelope (`kms:` references), planned and emergency signing-key rotation, root-key rotation |
| [backup-restore.md](backup-restore.md) | What to back up, restore procedure, restore reconciliation (`revocation-log`, `restore-begin`, `restore-reconcile`); the disaster-region recovery profile (warm standby, promotion runbook; DEP-019) |
| [account-recovery.md](account-recovery.md) | Recovery policy: lost password, lost factor, lost contact address, compromised account, directory-managed accounts; password change rule |
| [incidents.md](incidents.md) | Incident runbooks (OPS-016): compromised signing, root or KMS keys, admin account, client secret; connector compromise; provisioning connector (SCIM) token compromise; SAML key or counterparty compromise; directory connector compromise; abuse spikes; mass revocation; database outage and loss; audit chain failure and the audit archive; delivery outage; organization owner recovery; privacy deletion errors; impersonation abuse; emergency controls; maintenance mode |
| [upgrades.md](upgrades.md) | Expand/migrate/contract, mixed-version window, rollback limits |
| [monitoring.md](monitoring.md) | Health endpoints, server and worker metrics (including security signals and audit backlog and integrity), `/status`, logs, alert suggestions, audit query filters, `security.alert` events, reported application activity; directory and outbound provisioning metrics and worker tasks; shared-signals delivery (`ssf.deliver`) |
| [capacity.md](capacity.md) | Sizing notes, the limits that bound resource use, and the partitioning policy |
| [benchmarks.md](benchmarks.md) | The `identity-bench` suite: seeding, workload, adversarial, stress and soak scenarios, pass criteria, result format and how to reproduce; laptop results include independent server-process refresh profiles (NFR-003..NFR-008) |
| [consistency-tests.md](consistency-tests.md) | Cross-replica recovery/invitation, ownership, role, SCIM/admin, template, expiry-worker, refresh and revocation evidence; native-process refresh measurements, exact durable invariants, reproduction and remaining multi-node coverage |
| [support-bundle.md](support-bundle.md) | What `identity-cli support-bundle` collects and redacts; time-limited debug logging windows |
| [data-inventory.md](data-inventory.md) | Personal data and secrets per table: purpose, retention, protection; data residency; account deletion, its propagation report and lifecycle jobs; audit retention and legal holds; identity read evidence; SAML and directory integration tables; shared-signals, federation-transfer, organization-relationship, flow-revision and registry tables |
| [revocation-exposure.md](revocation-exposure.md) | What revocation is immediate and what is bounded by token lifetime |
| [offline-install.md](offline-install.md) | Restricted-network and air-gapped installation |
| [security-checks.md](security-checks.md) | Every CI security check (secret, license, vulnerability, static analysis), its scope, the triaged exceptions and the open supply-chain items (QA-002, SEC-016) |
| [migration.md](migration.md) | Migration runbook: source inventory, import format, dry run and conflicts, credentials and factors, audit history, reconciliation, cutover and rollback horizon, deletion continuity (MIG-001..MIG-018) |
| [exit-and-export.md](exit-and-export.md) | What can be exported and what cannot; the realm data export (format, kinds, exclusions); job authority; user import reference (formats, dry-run plans, conflicts, resumption, TOTP seeds, deletion continuity, reconciliation), historical audit import, configuration import (authority, `expected_policy_revision`, reconcile); external IDs; bulk user operations |
| [migration-adapters.md](migration-adapters.md) | First-party migration adapters (`identity-cli migrate-from`, `GET /migration-adapters`, `POST /migration-plans`) for Keycloak 26, ZITADEL v4 and SuperTokens core 12: tested versions, producing the exports, mappings per product, the reviewed mapping file, the capability report, imported bcrypt and PBKDF2 verifiers, what is never carried over (MIG-018) |
| [passkey-trust.md](passkey-trust.md) | Passkey attestation policy, trusted authenticator metadata (operator FIDO MDS3 BLOB, realm trusted authenticators), authenticator allow and block lists, WebAuthn Level 3 related origins, `credProtect` (PASS-009, PASS-010) |
| [federation-transfer.md](federation-transfer.md) | Moving account links to a new provider connection or upstream tenant with a reviewed migration map: analysis outcomes, second-administrator approval, apply, limits (FED-016) |
| [investigations.md](investigations.md) | Reconstructing a user's or service principal's entitlements at a past instant from retained evidence, with completeness and caveats (ADV-011) |
| [isolation-tiers.md](isolation-tiers.md) | Organization-, realm- and deployment-per-customer isolation: what each separates and shares, issuer, key, migration, backup, residency and cost tradeoffs (TEN-019) |

Command conventions: `identity-cli` operator commands read the same YAML
configuration as the server (`-config path` or `PROUDAUTH_CONFIG`) and connect
directly to the database with the configured keys. Go's flag parser accepts both
`-flag` and `--flag`.
