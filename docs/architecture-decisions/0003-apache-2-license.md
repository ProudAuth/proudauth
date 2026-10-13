# 0003. First-party license: Apache-2.0

**Status:** Accepted

## Context

docs/plan.md §2.2 proposes Apache-2.0 for independently written code, with
AGPL-3.0 as the alternative, and requires the choice before contributions are
accepted. OSS-001/OSS-002 and GOV-007 forbid field-of-use restrictions and paid
feature branches.

## Decision

All first-party code, tests, documentation and deployment files are licensed
under Apache-2.0 (`LICENSE`, `NOTICE`). Contributions are accepted under the
Developer Certificate of Origin (`git commit -s`, see CONTRIBUTING.md).
Dependencies are restricted to Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC and
MPL-2.0, enforced by `scripts/check-licenses.sh` in CI.

## Alternatives considered

- **AGPL-3.0**: stronger network copyleft; rejected to keep embedding and
  redistribution straightforward for operators and integrators.
- **Open core / source-available**: rejected; incompatible with OSS-001, OSS-002
  and GOV-007.
- **CLA instead of DCO**: rejected; DCO records provenance without assigning
  rights to a single entity.

## Consequences

- Anyone may offer hosting or support commercially; the project cannot restrict
  that (docs/plan.md §2.2).
- Code from AGPL-licensed or source-available reference products (§2.3) cannot be
  copied in.
- `NOTICE` lists direct dependencies; release SBOMs are the authoritative list.

## Migration implications

Relicensing would require consent of all contributors or replacement of their
code. Keep DCO sign-offs complete so provenance can be audited.

## Related requirement IDs

OSS-001, OSS-002, OSS-004, GOV-002, GOV-007, SEC-016, §2.2, §2.3
