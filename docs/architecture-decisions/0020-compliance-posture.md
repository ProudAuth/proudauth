# 0020. Compliance posture: evidence and controls, no certification claims

**Status:** Accepted

## Context

Identity products are often marketed with regulatory labels. PRV-009 and QA-006
forbid claiming certification because controls exist, and §21 notes that an
operator who controls the database, keys and backups can alter local evidence.

## Decision

- The project makes no claim of GDPR, HIPAA, SOC 2, ISO 27001, FIPS 140, NIST
  800-63 or OpenID/FAPI certification or compliance.
- The software provides evidence-producing controls that operators may use in
  their own assessments:
  - transactional, actor-aware audit events with redaction, an append-only
    trigger, hash-linked batches and a verifier (`identity-cli verify-audit`,
    `GET /audit-integrity`), an optional write-once archive of sealed batches
    to a directory the operator controls, verifiable without the database
    (`identity-cli verify-audit-archive`, AUD-008), corrections recorded as
    new linked events instead of edits (AUD-007), retention per audit
    category that realms and organizations can only extend, with legal holds
    (AUD-009), and security alerts as webhook events (AUD-012);
  - scoped audit query and NDJSON export with a SHA-256 checksum;
  - data-subject export (`POST /me/exports`), deletion requests with a grace period,
    deletion tombstones and restore reconciliation;
  - a portable realm data export (`POST /data-exports`, OSS-008) that names
    what it leaves out;
  - configurable retention (`privacy.*`, including grants, sessions and
    operational history) and a data inventory
    ([docs/operations/data-inventory.md](../operations/data-inventory.md));
  - access review campaigns (AZ-025) whose evidence export records every
    reviewer decision and outcome and states that it "documents an access
    review; it is not a regulatory certification", and time-bound
    just-in-time elevation (AZ-024)
    ([elevation-and-access-reviews.md](../integrations/elevation-and-access-reviews.md)).
    They support a periodic access review that an operator's own control
    framework may require; running them does not make a deployment compliant.
- The FAPI 2.0 client profile (ADV-001) applies the FAPI 2.0 Security
  Profile's rules; it is not certified by the OpenID Foundation and no
  conformance suite has been run.
- Documentation states limitations next to each control (for example, audit
  batches are hash-linked and signed with a key derived from the root key, but not
  anchored externally; the archive is only as independent as the storage the
  operator mounts for it).

## Alternatives considered

- **Pursuing certification for the project**: certification applies to
  deployments and organizations, not to source code.

## Consequences

- Operators remain responsible for legal applicability, residency, retention
  periods, backups' erasure behavior and external anchoring of evidence.
- Interoperability statements list only what in-repo tests exercise
  ([docs/integrations/interoperability.md](../integrations/interoperability.md)).

## Migration implications

None.

## Related requirement IDs

OSS-008, PRV-001, PRV-004, PRV-005, PRV-006, PRV-009, AUD-007, AUD-008, AUD-009, AUD-010, AUD-012, AZ-024, AZ-025, ADV-001, QA-006, §21, §23.3
