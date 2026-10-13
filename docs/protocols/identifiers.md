# Identifiers

Requirements: DOM-001, REG-002, REG-003, DB-002, USR-021. Code:
`internal/platform/canonical/canonical.go` (comparison rules, referenced from its
package comment), `internal/identity/identity.go` (`CanonicalizeLogin`,
`FindByLogin`, `Mask`), `internal/platform/ids/ids.go`.

## Internal identifiers

Every object has an opaque, immutable ID: a type prefix, `_`, and a lowercase
26-character ULID, for example `usr_01k7…`. ULIDs combine a millisecond timestamp
with 80 random bits from `crypto/rand`, so **an ID reveals when the object was
created**. IDs carry no authority; possessing one never grants access.

Common prefixes: `rlm` realm, `org` organization, `usr` user, `mem` membership,
`grp` group, `cli` client (internal reference), `res` API resource, `svc`
service principal, `ses` session, `gnt` grant, `tok` access-token JTI, `imp`
support grant, `imq` support request, `evt` audit event, `obx` outbox event,
`job` job, `whk` webhook, `rol` role, `prm` permission, `ras` role assignment,
`inv` invitation.

User IDs are the `sub` of access tokens and of ID tokens for clients with public
subjects. Email addresses never serve as subject or key.

## Login identifiers

A user has zero or more rows in `user_identifiers` of type `email`, `phone` or
`username`. Each row keeps the **original value** (for display and for sending
mail) and a **canonical value** (for comparison and uniqueness).

### Email

Canonical form:

1. Trim surrounding whitespace; reject invalid UTF-8, empty input or more than
   254 bytes.
2. Apply Unicode NFC.
3. Split at the single `@` (more than one `@` is invalid). The local part must be
   at most 64 bytes, must not start or end with `.` or contain `..`, and must not
   contain space, tab, CR, LF, `< > ( ) [ ] , ; : \ "`, control characters or DEL.
4. Convert the domain to its IDNA ASCII form (lookup profile, BiDi rule, strict
   domain names), lowercase it, drop a trailing dot. The domain must contain at
   least one dot; every label must be 1–63 characters of `a-z 0-9 -` and not start
   or end with `-`.
5. Lowercase the local part.

Not done: dots and `+tag` suffixes are **not** removed, and provider-specific
aliasing is not applied, because many providers treat them as different
mailboxes. `First.Last+news@Example.COM` canonicalizes to
`first.last+news@example.com`, which is different from `firstlast@example.com`.

The display form keeps the original local-part case and the domain as entered
(after NFC and trimming), and is what notifications are sent to.

### Username

Canonical form: trim, Unicode NFKC, lowercase. Then it must be 3–64 characters from
`a-z 0-9 . _ -`. Reserved names are rejected for new usernames: `admin`,
`administrator`, `root`, `system`, `support`, `security`, `postmaster`,
`hostmaster`, `webmaster`, `abuse`, `noreply`, `no-reply`, `help`, `operator`,
`proudauth`, `anonymous`, `guest`, `null`, `undefined`, `me`.

At login, a reserved name is still looked up (lowercased) so existing accounts are
not locked out.

### Phone

Canonical form: E.164. Spaces, `-`, `.`, `(` and `)` are removed; the result must be
`+` followed by 8–15 digits, the first digit not `0`. Numbers without a leading
`+` are rejected (no country inference). `+1 (415) 555-0100` → `+14155550100`.

### Login input detection

`identify` and `password` steps classify the submitted identifier: contains `@` →
email; starts with `+` → phone; otherwise username.

## Uniqueness and verification

- Canonical values are unique per realm and type **only for verified emails and
  phones and for all usernames** (partial unique index `user_identifiers_unique`).
  An unverified claim on an address never blocks its real owner.
- Login matches an email or phone **only when it is verified**; usernames always
  match. Someone who adds a victim's address without verifying it cannot capture
  the victim's sign-in.
- A user has at most one primary identifier per type.
- New or changed identifiers start unverified and are verified with a
  purpose-bound code (USR-004). Administrators can override verification only with
  `realm.users.verification.override` and a reason (USR-005). For a lost contact
  address, an administrator with that permission and
  `realm.users.credentials.manage` can also add an email address to another
  account (`POST /users/{user}/identifiers`, unverified, refused when another
  account verified it) and make a verified one primary
  (`POST /users/{user}/identifiers/{id}/primary`), each with a reason; the
  previous primary address is notified
  ([account-recovery.md](../operations/account-recovery.md)).
- Changing an email never changes the user ID. When an account is deleted, digest
  tombstones of its identifiers prevent imports and restores from recreating it; a
  new account that later verifies the same address gets a new ID and none of the
  old grants (USR-021).
- An executed account merge (USR-011) deletes the merged-away account like any
  deletion; its user ID is never reused and becomes a **subject alias** of the
  surviving account. Applications that keyed data by the old ID remap it on the
  `user.merged` event (`data.user_id` = survivor, `data.merged_user_id` = alias)
  or later with `GET /api/v1/realms/{realm}/subject-aliases/{id}`
  (`realm.users.read`). Tokens, pairwise subjects and grants of the merged-away
  account are not carried over; the survivor signs in with its own `sub`.
  No session survives a merge (SES-022): every session of both accounts ends
  with a `session.revoked` event, together with its session-bound refresh
  tokens, so both owners sign in again (`TestAccountMergeEndsSessions`).

## Organization slugs and domains

- Slugs: lowercase `a-z 0-9 -`, 2–63 characters, no leading or trailing `-`;
  unique per realm among non-deleted organizations. Deleted organizations get a
  suffixed slug so the name can be reused.
- **Aliases** (TEN-011, migration `0034`, `TestOrganizationAliasesAndDomainRouting`):
  renaming an organization keeps its former slug as an alias, and
  `POST /organizations/{org}/aliases {"alias": "..."}` (`org.update`) reserves
  another name with the slug syntax; `GET /organizations/{org}/aliases`
  (`org.read`) returns `{"items": [...]}` and
  `DELETE /organizations/{org}/aliases/{alias}` releases one. An alias resolves
  to its organization wherever an organization is named by slug (the
  `organization` parameter of authorization and device requests, organization
  references in user imports). Names are unique per realm across slugs and aliases: adding an
  alias that another organization uses as slug or alias, or creating or
  renaming an organization to another organization's alias, fails with `409`.
  Renaming an organization to one of its own aliases removes that alias.
  When an organization's deletion completes (the `organization.delete` job),
  its aliases are released together with its slug, so another organization
  can take them; while the deletion is in progress they stay reserved. Audited
  `organization.alias.added` and `organization.alias.removed` (category
  `configuration`).
- Verified domains use the same domain canonicalization as email domains and are
  unique per realm among verified claims. Verifying a domain that another
  organization of the realm already holds verified does not move it: the
  claim's state becomes `conflict`, `organization.domain.conflict` is audited
  (category `security`, outcome `denied`) and the request fails with
  `409 conflict` ("domain is verified by another organization"). Remove the
  claim; the domain can be claimed again once the other organization's
  verification is removed or lapses.
- A domain is verified by publishing the TXT record
  `_proudauth-challenge.<domain>` returned by
  `POST /organizations/{org}/domains` (the challenge expires after 7 days) and
  calling `POST /organizations/{org}/domains/{id}/verify`. Verification is
  re-checked (TEN-009, migration `0030`, `TestDomainReverification`): the digest
  of the accepted record is kept, and the hourly worker task `domains.recheck`
  (up to 100 due domains per run) looks the record up again every realm policy
  `domains.recheck_days` (1–365; 0 or omitted means 30). While the record is
  published the domain stays `verified` until the next check (audit
  `organization.domain.rechecked`). A missing record is retried every 24 hours;
  after `domains.lapse_after_failures` consecutive failures (1–30; 0 or omitted
  means 3) the domain becomes `expired`, no longer counts as verified, and
  `organization.domain.verification_lapsed` is audited. To verify it again,
  remove it (`DELETE /organizations/{org}/domains/{id}`) and add it again for a
  new challenge. A changed `recheck_days` applies from the next verification or
  successful check. Domains verified before migration `0030` have no stored
  proof and are never re-checked; remove and re-add them to bring them under
  re-verification.
- **Email-domain routing** (TEN-011): at the `identify` step, an email address
  whose domain an active organization has verified selects that organization
  for the transaction (unless the request named one) and, when its policy sets
  `sso_required` with `sso_provider_id`, routes the user to that connection;
  registration applies that organization's `registration_mode` the same way.
  By default only the exact domain routes. `PATCH
  /organizations/{org}/domains/{id} {"include_subdomains": true}`
  (`org.domains.write`; audited `organization.domain.updated`) makes a domain
  route its subdomains as well. Routing is deterministic: an exact verified
  domain always wins, otherwise the longest verified parent domain with
  `include_subdomains` routes the address, so `eng.example.com` verified by one
  organization keeps routing there even if another organization verified
  `example.com` with subdomains. Suspended or deleted organizations, and
  domains that are not (or no longer) `verified`, never route.

## Masked forms

Support operators with `support.users.read` (without `realm.users.read`) see
masked identifiers: email `a***@example.com`, phone with all but the last four
digits as `*`, other values the first two characters followed by `***`.

## Fuzzing

`FuzzEmail`, `FuzzDomain`, `FuzzUsername` and `FuzzPhone` in
`internal/platform/canonical/fuzz_test.go` check that canonical forms are
idempotent, lowercase and ASCII where required.
