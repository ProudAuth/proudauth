# 0007. Stable account key: immutable local IDs; external identity keyed by issuer and subject

**Status:** Accepted

## Context

Email addresses and phone numbers change and are recycled. Using them as identity
keys enables account takeover by recycled or matching addresses (DOM-001, USR-021,
TEST-026).

## Decision

- Every principal has an opaque immutable ID: a type prefix and a lowercase ULID
  (`usr_01...`, `svc_01...`, `org_01...`), generated with `crypto/rand` entropy.
  Access tokens use the user ID as `sub` (or a pairwise value, below).
- Login identifiers are rows in `user_identifiers` with an original value (for
  display) and a canonical value (for comparison, see
  [docs/protocols/identifiers.md](../protocols/identifiers.md)). Uniqueness of the
  canonical value per realm and type is enforced only for verified identifiers and
  usernames, so an unverified claim never blocks the real owner.
- External identities (`external_identities`) are unique per provider, upstream
  issuer and upstream subject (DB-003). Upstream OpenID Connect and GitHub-style
  OAuth federation is implemented (`internal/federation`, `TestFederation`); SAML
  and LDAP were not at acceptance ([0018](0018-enterprise-protocols-deferred.md)).
  Update 2026-10-11: SAML connections key external identities the same way
  (issuer = the IdP's entity ID, subject = the NameID or a configured subject
  attribute), and LDAP/Active Directory accounts are linked by the entry's
  immutable ID (`entryUUID` or `objectGUID`) as a connector-scoped external ID
  in `connector_external_ids`, never by DN or username
  ([0018](0018-enterprise-protocols-deferred.md#update-2026-10-11-saml-and-directory-integration)).
- Clients may use pairwise subjects (`subject_type: pairwise` with a
  `sector_identifier`): `sub = "pws_" + base64url(HMAC(purpose key, sector || user ID))[:20 bytes]`,
  derived on first use and then stored in `pairwise_subjects` (migration `0018`).
- Deleting an account keeps the `users` row in state `deleted` with personal fields
  cleared, and writes digest-only tombstones for each identifier so imports and
  restores do not resurrect it.

## Alternatives considered

- **Email as primary key**: rejected (DOM-001).
- **Random UUIDv4**: equally opaque; ULID was chosen for index locality and
  sortable listings. Consequence: IDs reveal their creation time.

## Consequences

- Changing an email never changes the subject seen by applications.
- A new account that later verifies a previously used address receives a new ID
  and none of the old grants (USR-021).
- Pairwise subjects are derived with the **active root key version** the first
  time they are issued ([0015](0015-key-hierarchy.md)) and then kept in
  `pairwise_subjects`, so later changes of `keys.active_version` do not change
  them (Update 2026-10; `TestPairwiseSubjects`). Values issued before migration
  `0018` are stored only when next issued, with the version active at that time.
  Stored values are not removed when an account is deleted (the `users` row is
  kept).

## Migration implications

Imports store source-qualified mappings (`import_mappings`) and never merge by
email (MIG-004). The durable pairwise mapping table (`pairwise_subjects`,
migration `0018`) records values as they are issued; it was not backfilled.

## Related requirement IDs

DOM-001, DOM-002, DOM-006, DB-002, DB-003, REG-002, REG-003, USR-021, APP-012, OIDC-010, MIG-004, MIG-017
