# Authentication flow revisions and risk integrations

This page covers how a realm's authentication flow is versioned, analysed,
simulated, published and rolled back (AUT-019), and how external risk signals
take part in it (ADV-012). The rules themselves (conditions, outcomes,
challenges, risk hooks) are described in
[headless-authentication.md](headless-authentication.md#authentication-flow-policy).

Code: `internal/realm/flowrev.go` (evaluation, analysis, revisions),
`internal/authentication/flowsim.go` (simulation),
`internal/httpapi/flowrev.go` (routes), migration
`0057_auth_flow_revisions`. Tests: `TestAuthenticationFlowRevisions`
(`tests/e2e/flowrev_test.go`), the analysis and evaluator unit tests in
`internal/realm/flowrev_test.go` (including `TestRiskNeverOverridesDeny`).

## Revisions

Every realm keeps a numbered history of its authentication flow definitions
(the `authentication_flow` member of the realm policy). Numbers are per realm
and start at 1. History is never rewritten: a rollback publishes a copy of an
earlier revision as a new revision.

| State | Meaning |
| --- | --- |
| `draft` | Saved with its analysis; not in force. At most 20 open drafts per realm (`409` beyond) |
| `published` | The live flow. Exactly one revision per realm is published (once the flow has changed at least once) |
| `superseded` | Was published; replaced by a later publication |
| `discarded` | A draft that was discarded |

**Every change to the live flow becomes a published revision**, whichever way
it is made:

- publishing a draft or rolling back through the revision API (below);
- `PUT /api/v1/realms/{realm}/settings` with a different `authentication_flow`;
  the revision's `note` is the request's `reason`;
- a configuration import that changes `authentication_flow`; the `note` is
  `configuration import`.

A settings change or import that leaves `authentication_flow` unchanged
creates no revision. Each published revision records `policy_revision`, the
realm policy revision its publication produced. That is the
`policy_revision` written into every `authentication.flow.evaluated` audit
event, so a decision maps to the published revision with the highest
`policy_revision` not above the event's (unrelated policy changes advance the
policy revision without creating a flow revision).

A revision returns `revision`, `state`, `definition`, `definition_hash`
(SHA-256 of the definition), `base_hash` (the hash of the live flow when the
revision was created), `note`, `analysis`, `rollback_of` (for rollbacks),
`policy_revision` (once published), `created_by`, `created_at`,
`published_by` and `published_at`.

## API

All routes are under `/api/v1/realms/{realm}/authentication-flow/revisions`
and need an administrator token like the rest of the administration API.

| Method and path | Permission | Body | Result |
| --- | --- | --- | --- |
| `GET` | `realm.settings.read` | — | The newest 200 revisions, newest first, as a paginated list (`items`, `next_cursor`) |
| `POST` | `realm.settings.write` | `{"definition": {...}, "note": "..."}` | `201` with the draft and its analysis. The definition is validated like `PUT /settings` (`422`, field paths such as `authentication_flow.rules[0].outcome`), including a challenge provider the deployment must configure. `note` at most 500 characters. A draft is saved even when its analysis has errors |
| `GET /{revision}` | `realm.settings.read` | — | One revision; `404` if unknown |
| `DELETE /{revision}` | `realm.settings.write` | — | `204`: the draft is `discarded`. `409` for any other state |
| `POST /{revision}/simulate` | `realm.settings.read` | `{"cases": [...]}` | Compares the live flow with this revision ([Simulation](#simulation)); any state can be simulated |
| `POST /{revision}/publish` | `realm.settings.write` | `{"acknowledge_warnings": bool, "reason": "..."}` | `200` with `revision`, `policy_revision` and `version` (and an `ETag` for the settings document). See [Publishing](#publishing) |
| `POST /{revision}/rollback` | `realm.settings.write` | `{"acknowledge_warnings": bool, "reason": "..."}` | `201`: the definition of `{revision}` is published as a new revision with `rollback_of` set; `reason` defaults to `rollback to revision N` |

Audit (category `security`): `realm.auth_flow.draft_created` (revision, rule
count, definition hash), `realm.auth_flow.draft_discarded` and
`realm.auth_flow.published` (revision, `policy_revision`, rule count,
`definition_hash`, with the reason). The policy change itself is also audited
as `realm.policy.updated` and kept in the configuration history, as for any
settings change.

### Publishing

Publishing goes through the same path as `PUT /settings`, so every policy
check applies (validation, the operator's MFA floor, configured challenge
providers), the realm policy revision advances and the change is in the
configuration history. It is refused when:

- the revision is not a draft (`409`; republish an earlier revision with
  `rollback` instead);
- **the live flow changed after the draft was created** (`409`): the draft
  stores the hash of the live flow it was based on, and any later publication,
  settings change or import that altered the flow makes it stale. Create a new
  draft from the current flow;
- the analysis finds a `bypass` error (`422`, field
  `authentication_flow.rules[<i>]`);
- the analysis has warnings and `acknowledge_warnings` is not `true` (`422`
  on `acknowledge_warnings`, naming the number of warnings).

Rollback requires a revision that was published (`published` or
`superseded`; `409` otherwise), re-validates it against today's policy rules
and runs the analysis again: a revision that the current analysis finds to
contain a bypass cannot be restored, and its warnings must be acknowledged
again.

## Analysis

Each revision stores an analysis, computed when it is saved and returned again
by simulation: `errors`, `warnings` and `unreachable_rules`. Each finding has
`severity`, `code`, `rule` (name), `index` (position in `rules`), `by` (the
earlier rule responsible, when there is one) and `message`.

Outcomes are ranked from least to most restrictive: `allow` < `review` <
`challenge` < `require_mfa` < `require_phishing_resistant` < `deny`.

| Code | Severity | Reported when |
| --- | --- | --- |
| `bypass` | error | An earlier, **weaker** rule matches every sign-in a later, stricter rule matches, so the stricter rule can never apply. Coverage includes sign-ins with a missing signal: an earlier rule that is skipped when its network or risk signal is missing (every `allow` rule, and rules with `on_missing_signal: skip`) only covers a later rule that is skipped on the same missing signal |
| `unreachable` | warning | An earlier rule that is equally or more restrictive matches every sign-in the rule matches; the rule is dead but nothing is weakened |
| `partial_bypass` | warning | An earlier, weaker rule decides some sign-ins a later, stricter rule also matches, for example `allow` for the office network before `require_mfa` for new devices. When the earlier rule covers every such sign-in whenever all signals are available, the message says so: the stricter rule is then reached only through missing signals |
| `skip_on_missing` | warning | A rule other than `allow` with a network or risk condition says `on_missing_signal: skip`, so it is skipped whenever that signal is unavailable (no client address, no risk hook, a failing hook) |
| `deny_all` | warning | A `deny` rule without conditions; it denies every sign-in that reaches it, administrators included |

**A `bypass` error is refused wherever the flow changes**: on publish and
rollback, on `PUT /settings` and on configuration import (`422`, field
`authentication_flow.rules[<i>]`). The check runs only when the flow itself
changes, so an existing flow that predates the analysis does not block
unrelated settings edits. Warnings never block `PUT /settings` or imports;
only the revision API asks for `acknowledge_warnings`.

Limits of the analysis:

- Coverage is checked rule against rule and conservatively: when containment
  is unclear (for example networks that only partly overlap) the rule is not
  reported as covered. A rule shadowed only by several earlier rules together
  is reported as `partial_bypass`, not as `bypass` or `unreachable`.
- Client, organization and resource values are compared as strings; they are
  not checked for existence.
- The analysis knows nothing about requirements outside the rule list (MFA
  policy, organization policy, scope step-up, required actions). An `allow`
  outcome never removes those requirements.

## Simulation

`POST .../revisions/{revision}/simulate` evaluates each case against the live
flow and against the revision with the evaluator sign-in uses
(`realm.EvaluateFlow`): first matching rule wins, a missing signal applies
restrictive rules unless they say `skip` and never satisfies `allow`.

```json
{"cases": [
  {"name": "admin off-network", "client_id": "web-bff", "method": "password",
   "ip": "203.0.113.7", "privileged": true, "known_device": true},
  {"name": "no address, no risk", "client_id": "web-bff", "method": "password"}
]}
```

| Case member | Meaning |
| --- | --- |
| `name` | Label; default `case <n>` |
| `client_id`, `organization_id`, `method`, `resources` | The sign-in's client, organization, primary method (`password`, `passkey`, `email_otp`, `magic_link`, `sms_otp`, `sso`, `certificate`) and requested resource audiences. Without `organization_id`, rules with `organizations` do not match |
| `ip` | Client address; **empty is a missing network signal** |
| `known_device` | `true` when a remembered device was presented |
| `failed_attempts` | Recent failed sign-in attempts of the account |
| `risk`, `risk_partial` | Risk level `low`, `medium` or `high`; **empty is a missing risk signal**. `risk_partial: true` makes the level a lower bound, as when one of several risk hooks failed |
| `privileged` | The account is protected or holds a privileged realm role |
| `assurance` | The `acr` reached before evaluation, for example `urn:proudauth:acr:mfa`; empty is single factor |

1 to 200 cases per request; an unknown method, risk level, address or
assurance profile is `422` on `cases[<i>].<member>`. The response has
`revision`, `live_policy_revision`, `results` (per case: `case`, `current` and
`candidate`, each `{"outcome", "rule", "missing_signals"}`, and `change`:
`unchanged`, `stricter`, `weaker` or `rule_changed` when the outcome is the same
but another rule decides it), `summary` (a count per `change`) and the
revision's `analysis`.

Simulation does not call risk hooks or challenge providers, and it does not
compute the other requirements of a sign-in (MFA enrollment, organization
policy, step-up); it shows only which rule decides and with what outcome.

## Risk integrations (ADV-012)

External device-posture, fraud and adaptive-authentication signals enter
ProudAuth through one interface only: pre-action hooks of kind
`authentication.risk`
([headless-authentication.md](headless-authentication.md#risk-hooks)). There
is no other way for an outside system to influence sign-in decisions.

- **Versioned contract.** Requests and answers follow
  `api/hooks/authentication.risk.request.v1.json` and
  `authentication.risk.response.v1.json`; each hook pins a `contract_version`
  that is sent as the `ProudAuth-Hook-Version` header
  ([api/hooks/README.md](../../api/hooks/README.md), EXT-018). Calls are
  signed, go through the egress policy and the residency allowlist, and are
  bounded by the hook's timeout (100–5000 ms).
- **Privacy-reviewed input.** The hook receives the user, client and
  organization IDs, the primary method, the client network reduced to /24 or
  /48 (never the full address), whether the device is remembered, and the
  recent failed-attempt count. No credentials, tokens, identifiers such as
  email addresses, or profile data are sent.
- **Named levels only.** The answer must be exactly
  `{"level": "low" | "medium" | "high", "reasons": [...]}`. There is no numeric
  or opaque score; anything else is a failed call.
- **Deterministic fallback.** Every active risk hook is called; the highest
  level wins. When all hooks fail, the risk signal is missing; when some
  answer, their highest level is a lower bound. A missing signal applies
  restrictive rules (unless they say `on_missing_signal: skip`) and never
  satisfies an `allow` rule (AUT-014). Simulation reproduces this with an
  empty `risk` or `risk_partial`.
- **What a verdict can do.** A risk level only feeds authentication flow
  rules: it can lead to `deny`, `challenge`, `review` or a stronger factor
  requirement. An `allow` outcome adds nothing and never removes MFA or
  other requirements. Risk never grants roles, permissions or scopes:
  authorization decisions do not read it.
- **Deny wins.** Rules are evaluated in order and the first match decides, so
  a `deny` rule placed before risk rules cannot be overridden by any verdict
  (`TestRiskNeverOverridesDeny`). The analysis reports an `allow` rule on low
  risk placed ahead of a stricter rule as `partial_bypass` or `bypass`.

Not provided: a built-in risk engine, device-posture or fraud adapters, and
any channel other than hooks for such signals. Inbound security events from
other systems (session revocations, compromised credentials) are a separate,
explicitly mapped mechanism ([shared-signals.md](../integrations/shared-signals.md#receiver-adv-007)).
