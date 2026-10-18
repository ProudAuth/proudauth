# 0016. Email and SMS: replaceable operator-configured adapters

**Status:** Accepted

## Context

Verification, recovery, invitation and security notices need delivery, but no
hosted email or SMS vendor may be mandatory (MSG-001, OSS-003, OSS-009), messages
must be enqueued with the change that requires them (MSG-002), and secret-bearing
payloads must be minimized and purged (MSG-009). A development sink must never be
usable in production (MSG-011, QA-007).

## Decision

- Messages are rows in `notification_jobs`, written in the same transaction as the
  triggering change. The recipient and template data (which can contain one-time
  codes or links) are stored only as AES-256-GCM ciphertext; a masked
  `recipient_hint` is kept for diagnostics.
- `identity-worker` delivers due jobs with leases and exponential backoff, records
  `accepted` when the provider accepts the message, and purges payloads after
  `delivery.payload_retention` (24 h) once the job is finished or expired.
- **Email adapters**: `smtp` (STARTTLS, implicit TLS, or plain only in
  development) and `dev_sink` (stores messages in `dev_mailbox`, readable through an
  unauthenticated development-only route). Production configuration rejects
  `dev_sink` and `smtp_tls: none`.
- Sender address and name can be overridden per realm or organization
  (`notification_settings`; a realm sender must use an operator-approved domain,
  an organization sender one of the organization's verified domains, MSG-005).
  `GET /notification-settings` returns the realm-level settings with an `ETag`
  derived from their content (`W/"c<hex>"`), and `PATCH` accepts it as an
  optional `If-Match` (`412` when the settings changed; API-010).
  `GET /notification-settings?organization_id=<org>` returns that
  organization's settings and tag, which a `PATCH` with the same
  `organization_id` compares with `If-Match` (the organization ID is not
  checked to exist, and the response does not repeat it). The comparison runs before the update's
  transaction, so two simultaneous `PATCH` requests can both pass it.
  Templates can be overridden per realm, organization and locale with
  validated variables and escaping.
- **Template safety** (MSG-004, `ValidateTemplate` in
  `internal/notification/notification.go`, `TestValidateTemplate`,
  `TestCustomTemplateSafety`): `POST /templates` accepts only `{{.name}}`
  actions naming a variable documented for that event (`GET /templates`
  lists them as `variables`); functions, pipelines, conditionals, ranges,
  template variables and nested templates are refused (`422`). Values are
  passed as data and stripped of control characters; the HTML body is
  rendered with `html/template`. In `body_html` a value may appear in text
  and in ordinary attributes such as `title` or `alt`, but a URL attribute
  (`href`, `src`, `action`, ...) may hold only exactly `{{.link}}`, the link
  the server builds from trusted configuration, so a client-controlled value
  (a display name, the sign-in device) can never become a link; values in
  `<script>`, `<style>`, `style` or `on*` attributes, `<meta>` elements and
  tag or attribute names are refused, and so is HTML that `html/template`
  cannot render (for example an unclosed attribute), which would otherwise
  fail every delivery of that event. Templates saved before these HTML
  checks are not re-validated.
- **Organization mail servers** (TEN-022, `internal/notification/tenantsmtp.go`,
  `TestTenantSMTPCredentials`): an organization can route its email through
  its own SMTP server (`PUT /organizations/{org}/notification-settings/smtp`
  with `host`, `port` 25/465/587/2525, `tls_mode` `starttls` or `implicit`,
  optional `username` and `password`; `GET` and `DELETE` on the same path).
  `GET` and `PUT` return an `ETag` derived from the stored settings
  (`W/"c<hex>"`; the password is reflected only as `has_password`, so a
  password change alone does not change it), and `PUT` accepts it as an
  optional `If-Match` (`412` when stale or when nothing is configured;
  API-010).
  Managing it needs `org.integrations.write`, a privileged permission held by
  the organization `owner` role (not `admin`), and, for users, an MFA session.
  Plain-text SMTP is refused because it would expose the tenant's credentials
  and mail. The password is stored AES-256-GCM-encrypted with the realm and
  organization as associated data, so it decrypts only when sending that
  organization's messages, and it is never returned (`has_password` only); a
  `PUT` without `password` keeps the stored one. At delivery the worker resolves
  the host and connects only when every address passes the delivery egress
  policy (`delivery.egress_allowlist`), trying each resolved address in turn
  until one connects (10 s per address), with TLS
  1.2 or later and the host name verified. Messages of that organization use
  this server instead of the deployment relay; other organizations' messages
  never do. The development sink still takes precedence, and
  `POST /notification-settings/check` tests only the deployment relay. Changes
  are audited (`notification.smtp.updated`, `notification.smtp.cleared`;
  category `configuration`) without the password.
- **Localization** (MSG-006, `internal/notification/notification.go`,
  `TestNoticeTimeZones`): when a message is enqueued for a known account
  (`Message.UserID`, or a `user` reference), the account's `locale` is used if
  the message sets none, and the template values `time`, `expires` and
  `scheduled` (written as RFC 3339 by `notification.Timestamp`) are rendered in
  the account's `zoneinfo` time zone, for example `2026-01-02 21:04 JST`.
  Without an account or a valid time zone they are rendered in UTC. A message
  that still has no locale at delivery uses the realm's or organization's
  default locale. Templates are looked up for that locale, then its base
  language (`pt-br`, then `pt`), then `en`. A locale that is a
  space-separated preference list, such as the `ui_locales` of the
  authentication transaction a code is sent for, is tried tag by tag (each
  followed by its base language, at most five tags) before `en`, so
  `fr-CA es` falls back to Spanish rather than English. For each, an organization override
  wins over a realm override, which wins over the built-in catalog (English,
  with Spanish for verification, sign-in code, account-link code, password
  reset and invitation messages).
- **SMS adapters**: `webhook` posts `{"id","to","text"}` to an operator-run HTTPS
  gateway with `X-ProudAuth-Timestamp` and an HMAC-SHA256 `X-ProudAuth-Signature`
  over `"<timestamp>.<body>"`, through the egress policy; the gateway relays to a
  carrier of the operator's choice. `dev_sink` stores SMS in `dev_mailbox`
  (development only). Before an SMS job is created, the number must match
  `delivery.sms.allowed_countries` and the deployment-wide
  `delivery.sms.daily_budget` must not be exhausted (MSG-008, PWDLESS-004). No
  carrier SDK is bundled.

## Alternatives considered

- **Synchronous sending inside the request**: couples availability to the mail
  provider and leaks timing; rejected.
- **Bundling a vendor SDK**: rejected (OSS-003).

## Consequences

- "Accepted" means the SMTP relay accepted the message, not that it reached an
  inbox (MSG-012). `POST /notification-settings/check` tests the relay connection,
  TLS and authentication without sending and reports only the failing stage.
- Bounce and complaint feedback arrives through `POST /delivery-events`, signed
  with `delivery.email.events_secret` (MSG-007). A permanent bounce or a complaint
  records the address in `notification_suppressions`. **Suppression and user
  preferences only affect optional notices**: a message enqueued as mandatory
  (verification, codes, magic links, resets, security and account notices) is
  still sent to a suppressed address and cannot be muted, so a compromised account
  or a hostile feedback source cannot silence security mail; optional notices
  (for example the new-login alert and the join-request notices) are stored as
  `suppressed` instead of sent. Users can mute only the new-login alert (MSG-010,
  `GET`/`PUT /me/notification-preferences`). Provider status never
  verifies or changes an identity.
- Operators pay for and operate their mail relay; offline installs need a local
  relay.

## Migration implications

Adding an adapter must keep the encrypted payload format and the job state
machine. Changing the SMS gateway request format is a breaking change for
operators' gateways.

## Related requirement IDs

MSG-001, MSG-002, MSG-003, MSG-004, MSG-005, MSG-006, MSG-007, MSG-008, MSG-009, MSG-010, MSG-011, MSG-012, PWDLESS-004, PWDLESS-005, TEN-022, OSS-009, QA-007, §20
