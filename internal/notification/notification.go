// Package notification implements durable, transactional message delivery with
// safe templates (§20). Messages are enqueued in the same transaction as the action
// that requires them (MSG-002); workers deliver after commit.
package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/jackc/pgx/v5"
	htmltok "golang.org/x/net/html"

	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Templates (MSG-003).
const (
	TplEmailVerification = "email_verification"
	TplLoginCode         = "login_code"
	TplMagicLink         = "magic_link"
	// TplAccountLinkCode and TplAccountLinkMagicLink carry the proof of
	// control that links an external identity to an existing account: they
	// say so and name the connection, so a code or link meant for linking is
	// never presented as a plain sign-in (PWDLESS-008).
	TplAccountLinkCode      = "account_link_code"
	TplAccountLinkMagicLink = "account_link_magic_link"
	TplPasswordReset        = "password_reset"
	TplPasswordChanged      = "password_changed"
	TplInvitation           = "invitation"
	TplMFAChanged           = "mfa_changed"
	TplNewLogin             = "new_login"
	TplAccountSuspended     = "account_suspended"
	TplSupportAccess        = "support_access"
	TplAccountSetup         = "account_setup"
	TplRegistrationExists   = "registration_exists"
	TplIdentifierChanged    = "identifier_changed"
	TplRecovery             = "recovery_notice"
	TplCredentialExpiry     = "credential_expiry"
	TplTest                 = "configuration_test"
	TplJoinRequest          = "join_request"
	TplDeletion             = "deletion_scheduled"
	TplSupportApproval      = "support_access_approval"
	TplRegistrationReview   = "registration_review"
	TplJoinDecision         = "join_request_decision"
	// TplWorkflowNotice is the only template lifecycle workflow notify steps
	// send (EXT-015): the definition picks a server-defined notice, never
	// free text; realms customize the wording like any other template.
	TplWorkflowNotice = "workflow_notice"
)

// Message is a message to enqueue. Data values are untrusted and are always escaped.
type Message struct {
	RealmID       string
	OrgID         string
	Channel       string // email | sms
	Template      string
	Locale        string
	Recipient     string
	Data          map[string]string
	Mandatory     bool // security notifications cannot be disabled by preferences (MSG-010)
	ReferenceType string
	ReferenceID   string
	TTL           time.Duration
	// UserID names the recipient's account, when there is one: its locale and
	// time zone localize the message (MSG-006). A user reference
	// (ReferenceType "user") serves the same purpose.
	UserID string
}

// Timestamp formats a time for a template value. Values under the keys in
// timeKeys are re-rendered in the recipient's time zone at enqueue (MSG-006).
func Timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

var timeKeys = []string{"time", "expires", "scheduled"}

// LocalTime renders t in the user's time zone (UTC when unknown), for times
// that appear inside free text rather than under a time key (MSG-006).
func (s *Service) LocalTime(ctx context.Context, q storage.Querier, userID string, t time.Time) string {
	zone := time.UTC
	var tz string
	if err := q.QueryRow(ctx, `SELECT coalesce(zoneinfo,'') FROM users WHERE id=$1`, userID).Scan(&tz); err == nil && tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			zone = loc
		}
	}
	return t.In(zone).Format("2 Jan 2006 15:04 MST")
}

// localize resolves the recipient's locale (when the message has none) and
// renders timestamps in the recipient's time zone, UTC when unknown.
func (s *Service) localize(ctx context.Context, q storage.Querier, m *Message) {
	userID := m.UserID
	if userID == "" && m.ReferenceType == "user" {
		userID = m.ReferenceID
	}
	zone := time.UTC
	if userID != "" {
		var tz, locale string
		if err := q.QueryRow(ctx, `SELECT coalesce(zoneinfo,''), coalesce(locale,'') FROM users WHERE id=$1`, userID).Scan(&tz, &locale); err == nil {
			if loc, err := time.LoadLocation(tz); err == nil && tz != "" {
				zone = loc
			}
			if m.Locale == "" {
				m.Locale = locale
			}
		}
	}
	if len(m.Data) == 0 {
		return
	}
	data := make(map[string]string, len(m.Data))
	for k, v := range m.Data {
		data[k] = v
		if slices.Contains(timeKeys, k) {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				data[k] = t.In(zone).Format("2 Jan 2006 15:04 MST")
			}
		}
	}
	m.Data = data
}

// Service enqueues and delivers notifications.
type Service struct {
	d       *runtime.Deps
	Email   EmailSender
	SMS     SMSSender
	Catalog *Catalog
	DevSink bool
	// SMSDevSink stores SMS in the development mailbox instead of sending.
	SMSDevSink bool
	// Observe, when set, sees each message's final state (metrics).
	Observe func(state string)
}

// Email is one outgoing message.
type Email struct {
	From, FromName, ReplyTo, To string
	Subject, Text, HTML         string
}

// EmailSender is the pluggable email transport (MSG-001).
type EmailSender interface {
	Send(ctx context.Context, e Email) (providerID string, err error)
}

// SMSSender is the optional SMS transport (MSG-008).
type SMSSender interface {
	Send(ctx context.Context, to, text string) (string, error)
}

// SMSEnabled reports whether an SMS transport is configured.
func (s *Service) SMSEnabled() bool { return s.SMS != nil || s.SMSDevSink }

// NewService builds the notification service.
func NewService(d *runtime.Deps) *Service {
	s := &Service{d: d, Catalog: DefaultCatalog()}
	switch d.Cfg.Delivery.Email.Adapter {
	case "dev_sink":
		s.DevSink = true
	case "smtp":
		s.Email = &SMTPSender{Host: d.Cfg.Delivery.Email.SMTPHost, Port: d.Cfg.Delivery.Email.SMTPPort,
			Username: d.Cfg.Delivery.Email.SMTPUsername, PasswordRef: d.Cfg.Delivery.Email.SMTPPassword, TLSMode: d.Cfg.Delivery.Email.SMTPTLS}
	}
	switch d.Cfg.Delivery.SMS.Adapter {
	case "dev_sink":
		s.SMSDevSink = true
	case "webhook":
		s.SMS = &WebhookSMSSender{URL: d.Cfg.Delivery.SMS.WebhookURL, SecretRef: d.Cfg.Delivery.SMS.WebhookSecret,
			Egress: egress.Policy{RequireHTTPS: d.Cfg.Mode == "production", AllowCIDRs: d.Cfg.Delivery.EgressAllowlist, Timeout: d.Cfg.Delivery.WebhookTimeout, MaxBytes: 64 << 10},
			Now:    func() int64 { return d.Now().Unix() }}
	}
	return s
}

type payload struct {
	Recipient string            `json:"r"`
	Data      map[string]string `json:"d"`
}

// EnqueueTx stores a message job through tx. The recipient and secret-bearing data
// are encrypted at rest and purged after bounded retention (MSG-009).
func (s *Service) EnqueueTx(ctx context.Context, q storage.Querier, m Message) (string, error) {
	if m.Channel == "" {
		m.Channel = "email"
	}
	if m.TTL == 0 {
		m.TTL = 24 * time.Hour
	}
	if _, ok := s.Catalog.lookup(m.Template, "en"); !ok {
		return "", fmt.Errorf("notification: unknown template %q", m.Template)
	}
	if m.Channel == "sms" {
		if err := s.SMSAdmissible(ctx, q, m.Recipient); err != nil {
			return "", err
		}
	}
	// Every message about an account records it, so deleting the account
	// purges the message with it (PRV-005): a user reference names it, and
	// otherwise a recipient address that is one of the account's
	// identifiers in the realm does.
	if m.UserID == "" && m.ReferenceType == "user" {
		m.UserID = m.ReferenceID
	}
	if m.UserID == "" {
		m.UserID = s.accountOf(ctx, q, m.RealmID, m.Channel, m.Recipient)
	}
	s.localize(ctx, q, &m)
	id := ids.New(ids.Notification)
	body, _ := json.Marshal(payload{Recipient: m.Recipient, Data: m.Data})
	ct, ver, err := s.d.Keys.Encrypt(keys.PurposeData, body, []byte("notification:"+id))
	if err != nil {
		return "", err
	}
	now := s.d.Now()
	state := "queued"
	var suppressed bool
	_ = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notification_suppressions WHERE realm_id=$1 AND recipient_digest=$2)`,
		m.RealmID, secret.Digest(strings.ToLower(m.Recipient))).Scan(&suppressed)
	if suppressed && !m.Mandatory {
		state = "suppressed"
	}
	// Optional notices honor the recipient's preferences (MSG-010).
	if !m.Mandatory && m.ReferenceType == "user" && s.muted(ctx, q, m.RealmID, m.ReferenceID, m.Template) {
		state = "suppressed"
	}
	_, err = q.Exec(ctx, `INSERT INTO notification_jobs (id, realm_id, organization_id, channel, template, locale, payload_ciphertext, key_version,
		recipient_hint, mandatory, reference_type, reference_id, state, next_attempt_at, expires_at, created_at, updated_at, user_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$14,$14,$16)`, id, m.RealmID, nilIfEmpty(m.OrgID), m.Channel, m.Template, m.Locale,
		ct, ver, hint(m.Recipient), m.Mandatory, nilIfEmpty(m.ReferenceType), nilIfEmpty(m.ReferenceID), state, now, now.Add(m.TTL), nilIfEmpty(m.UserID))
	return id, err
}

// SMSAdmissible applies the operator-controlled safety and cost ceilings an
// SMS must pass before it is queued (MSG-008, PWDLESS-004): a configured
// transport, the country restriction and the deployment's daily budget. It
// queues nothing, so a caller that must answer identically whether or not
// the number belongs to an account (API-009, SEC-005) runs it before it
// branches on the account and gets the same refusal, with the same body and
// Retry-After, that EnqueueTx returns.
func (s *Service) SMSAdmissible(ctx context.Context, q storage.Querier, recipient string) error {
	cfg := s.d.Cfg.Delivery.SMS
	if !s.SMSEnabled() {
		return problem.ErrFeatureDisabled.WithDetail("SMS delivery is not configured")
	}
	if !smsAllowed(cfg.AllowedCountries, recipient) {
		return problem.ErrValidation.WithField("phone", "SMS is not available for this country")
	}
	if cfg.DailyBudget > 0 {
		var sent int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM notification_jobs WHERE channel='sms' AND created_at > $1`, s.d.Now().Add(-24*time.Hour)).Scan(&sent); err != nil {
			return err
		}
		if sent >= cfg.DailyBudget {
			return problem.ErrRateLimited.WithDetail("the deployment's daily SMS budget is exhausted").WithRetryAfter(time.Hour)
		}
	}
	return nil
}

// accountOf returns the account of the realm whose e-mail address (or, for
// SMS, phone number) is recipient, or "".
func (s *Service) accountOf(ctx context.Context, q storage.Querier, realmID, channel, recipient string) string {
	typ, canon := "email", ""
	if channel == "sms" {
		typ = "phone"
		canon, _ = canonical.Phone(recipient)
	} else {
		canon, _, _ = canonical.Email(recipient)
	}
	if canon == "" || realmID == "" {
		return ""
	}
	var userID string
	_ = q.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type=$2 AND canonical_value=$3`, realmID, typ, canon).Scan(&userID)
	return userID
}

func hint(r string) string {
	if at := strings.LastIndexByte(r, '@'); at > 0 {
		return r[:1] + "***" + r[at:]
	}
	if len(r) > 4 {
		return "***" + r[len(r)-4:]
	}
	return "***"
}

// Job is delivery state visible to administrators (no payload).
type Job struct {
	ID            string    `json:"id"`
	Channel       string    `json:"channel"`
	Template      string    `json:"template"`
	RecipientHint string    `json:"recipient_hint"`
	State         string    `json:"state"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	ReferenceType string    `json:"reference_type,omitempty"`
	ReferenceID   string    `json:"reference_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// DeliverDue claims and delivers due jobs with leases (DEP-011). Delivery is
// at-least-once: a crash after the provider accepted a message may resend it, but a
// job never fans out into unlimited messages.
func (s *Service) DeliverDue(ctx context.Context, worker string, batch int, lease time.Duration) (int, error) {
	now := s.d.Now()
	rows, err := s.d.DB.Pool.Query(ctx, `UPDATE notification_jobs SET lease_owner=$1, lease_expires_at=$2, attempts=attempts+1, state='attempted', updated_at=$3
		WHERE id IN (SELECT id FROM notification_jobs WHERE id IN (
			-- Fair share (TEN-018): at most $5 due messages per tenant per batch.
			SELECT id FROM (SELECT id, next_attempt_at, row_number() OVER (PARTITION BY coalesce(organization_id, realm_id) ORDER BY next_attempt_at) AS rn
				FROM notification_jobs WHERE state IN ('queued','attempted') AND next_attempt_at <= $3
				AND (lease_expires_at IS NULL OR lease_expires_at < $3)) due
			WHERE rn <= $5 ORDER BY next_attempt_at LIMIT $4)
		-- Checked again on the row version the lock finds (DEP-011): a message
		-- another worker claimed or delivered after this statement's snapshot
		-- is skipped instead of being claimed and sent a second time.
		AND state IN ('queued','attempted') AND next_attempt_at <= $3 AND (lease_expires_at IS NULL OR lease_expires_at < $3)
		FOR UPDATE SKIP LOCKED)
		RETURNING id, realm_id, coalesce(organization_id,''), channel, template, locale, payload_ciphertext, attempts, max_attempts, expires_at`,
		worker, now.Add(lease), now, batch, tenantShare(s.d.Cfg.Workers.TenantBatchShare, batch))
	if err != nil {
		return 0, err
	}
	type job struct {
		id, realm, org, channel, tpl, locale string
		ct                                   []byte
		attempts, max                        int
		expires                              time.Time
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.realm, &j.org, &j.channel, &j.tpl, &j.locale, &j.ct, &j.attempts, &j.max, &j.expires); err != nil {
			rows.Close()
			return 0, err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		if now.After(j.expires) || j.ct == nil {
			s.finish(ctx, j.id, "expired", "", "")
			continue
		}
		pt, err := s.d.Keys.Decrypt(keys.PurposeData, j.ct, []byte("notification:"+j.id))
		if err != nil {
			s.finish(ctx, j.id, "failed", "payload_decrypt_failed", "")
			continue
		}
		var p payload
		_ = json.Unmarshal(pt, &p)
		providerID, err := s.deliver(ctx, j.realm, j.org, j.channel, j.tpl, j.locale, p)
		if err != nil {
			s.d.Log.Warn("notification delivery failed", "job", j.id, "attempt", j.attempts, "error", err)
			if j.attempts >= j.max {
				s.finish(ctx, j.id, "failed", truncate(err.Error(), 200), "")
			} else {
				backoff := time.Duration(1<<min(j.attempts, 10)) * 10 * time.Second
				_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE notification_jobs SET lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=$2, last_error=$3,
					updated_at=$4 WHERE id=$1`, j.id, s.d.Now().Add(backoff), truncate(err.Error(), 200), s.d.Now())
			}
			continue
		}
		s.finish(ctx, j.id, "accepted", "", providerID)
	}
	return len(jobs), nil
}

func (s *Service) finish(ctx context.Context, id, state, errMsg, providerID string) {
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE notification_jobs SET state=$2, last_error=nullif($3,''), provider_message_id=nullif($4,''),
		lease_owner=NULL, lease_expires_at=NULL, updated_at=$5 WHERE id=$1`, id, state, errMsg, providerID, s.d.Now())
	if s.Observe != nil {
		s.Observe(state)
	}
}

func (s *Service) deliver(ctx context.Context, realmID, orgID, channel, tpl, locale string, p payload) (string, error) {
	if locale == "" {
		// The tenant's default language applies when the caller had no
		// recipient preference (MSG-005, MSG-006).
		locale = s.settings(ctx, realmID, orgID).DefaultLocale
	}
	subject, text, html, err := s.Render(ctx, realmID, orgID, tpl, locale, p.Data)
	if err != nil {
		return "", err
	}
	if channel == "sms" {
		if s.SMSDevSink {
			_, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO dev_mailbox (id, realm_id, recipient, subject, body_text, template) VALUES ($1,$2,$3,$4,$5,$6)`,
				ids.New(ids.Mailbox), realmID, p.Recipient, "SMS", text, tpl)
			return "dev-sink", err
		}
		if s.SMS == nil {
			return "", errors.New("sms delivery is not configured")
		}
		return s.SMS.Send(ctx, p.Recipient, text)
	}
	if s.DevSink {
		_, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO dev_mailbox (id, realm_id, recipient, subject, body_text, template) VALUES ($1,$2,$3,$4,$5,$6)`,
			ids.New(ids.Mailbox), realmID, p.Recipient, subject, text, tpl)
		return "dev-sink", err
	}
	// An organization's own mail server carries its mail (TEN-022); its
	// credential is never used for any other tenant.
	sender := s.Email
	if ts, err := s.tenantSender(ctx, realmID, orgID); err != nil {
		return "", err
	} else if ts != nil {
		sender = ts
	}
	if sender == nil {
		return "", errors.New("email delivery is not configured")
	}
	from, fromName := s.d.Cfg.Delivery.Email.From, s.d.Cfg.Delivery.Email.FromName
	set := s.settings(ctx, realmID, orgID)
	if set.SenderAddress != "" {
		from = set.SenderAddress
	}
	if set.SenderName != "" {
		fromName = set.SenderName
	}
	return sender.Send(ctx, Email{From: from, FromName: fromName, ReplyTo: set.ReplyTo, To: p.Recipient, Subject: subject, Text: text, HTML: html})
}

// Render renders a template with escaping. Organization overrides are looked up
// first, then realm overrides, then the built-in catalog with locale fallback
// (MSG-005, MSG-006).
func (s *Service) Render(ctx context.Context, realmID, orgID, tpl, locale string, data map[string]string) (string, string, string, error) {
	t, err := s.templateFor(ctx, realmID, orgID, tpl, locale)
	if err != nil {
		return "", "", "", err
	}
	safe := map[string]string{}
	for k, v := range data {
		safe[k] = sanitizeValue(v)
	}
	var subj, text bytes.Buffer
	st, err := template.New("s").Option("missingkey=zero").Parse(t.Subject)
	if err != nil {
		return "", "", "", err
	}
	if err := st.Execute(&subj, safe); err != nil {
		return "", "", "", err
	}
	tt, err := template.New("t").Option("missingkey=zero").Parse(t.Text)
	if err != nil {
		return "", "", "", err
	}
	if err := tt.Execute(&text, safe); err != nil {
		return "", "", "", err
	}
	html := ""
	if t.HTML != "" {
		ht, err := htmltemplate.New("h").Option("missingkey=zero").Parse(t.HTML)
		if err != nil {
			return "", "", "", err
		}
		var hb bytes.Buffer
		if err := ht.Execute(&hb, safe); err != nil {
			return "", "", "", err
		}
		html = hb.String()
	}
	return strings.ReplaceAll(subj.String(), "\n", " "), text.String(), html, nil
}

func sanitizeValue(v string) string {
	// Strip control characters that could inject headers or confuse rendering.
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, truncate(v, 2048))
}

func (s *Service) templateFor(ctx context.Context, realmID, orgID, tpl, locale string) (Template, error) {
	for _, l := range fallbacks(locale) {
		var t Template
		err := s.d.DB.Pool.QueryRow(ctx, `SELECT subject, body_text, coalesce(body_html,'') FROM notification_templates
			WHERE realm_id=$1 AND coalesce(organization_id,'') IN ($2, '') AND event_type=$3 AND locale=$4 AND state='active'
			ORDER BY organization_id NULLS LAST LIMIT 1`, realmID, orgID, tpl, l).Scan(&t.Subject, &t.Text, &t.HTML)
		if err == nil {
			return t, nil
		}
		if !storage.IsNoRows(err) {
			return Template{}, err
		}
		if t, ok := s.Catalog.lookup(tpl, l); ok {
			return t, nil
		}
	}
	return Template{}, fmt.Errorf("notification: no template %s", tpl)
}

// maxLocaleTags bounds how many tags of a preference list are tried.
const maxLocaleTags = 5

// fallbacks lists the template locales to try, in order. The locale may be a
// single language tag or a space-separated preference list such as an OIDC
// ui_locales value ("fr-CA es en", NFR-009): each tag is tried, followed by
// its primary language, then English.
func fallbacks(locale string) []string {
	out := []string{}
	add := func(l string) {
		if l != "" && !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	tags := strings.Fields(strings.ToLower(locale))
	if len(tags) > maxLocaleTags {
		tags = tags[:maxLocaleTags]
	}
	for _, tag := range tags {
		add(tag)
		if i := strings.IndexAny(tag, "-_"); i > 0 {
			add(tag[:i])
		}
	}
	add("en")
	return out
}

// ValidateTemplate checks a custom template: it must parse, may only reference the
// documented variables, and cannot call functions or build URLs (MSG-004). The
// HTML body must also render without an html/template context error, and a
// value can appear there only as text or in an ordinary attribute: a URL
// attribute (href, src, ...) may hold only exactly {{.link}}, the link the
// server builds from trusted configuration, and no value may land in a script,
// a style, an event handler, a meta element, or a tag or attribute name.
func ValidateTemplate(subject, text, html string, allowed []string) error {
	allowedSet := map[string]bool{}
	for _, a := range allowed {
		allowedSet[a] = true
	}
	for _, src := range []string{subject, text, html} {
		if src == "" {
			continue
		}
		if len(src) > 32*1024 {
			return problem.ErrValidation.WithDetail("template too large")
		}
		for _, action := range actions(src) {
			a := strings.TrimSpace(action)
			if !strings.HasPrefix(a, ".") || strings.ContainsAny(a, " |()$") || !allowedSet[strings.TrimPrefix(a, ".")] {
				return problem.ErrValidation.WithDetail("template may only reference allowed variables: " + strings.Join(allowed, ", "))
			}
		}
		if _, err := template.New("v").Parse(src); err != nil {
			return problem.ErrValidation.WithDetail("template does not parse")
		}
	}
	if html != "" {
		return validateHTML(html, allowed)
	}
	return nil
}

// urlAttrs are the HTML attributes whose value is a URL.
var urlAttrs = map[string]bool{"href": true, "src": true, "srcset": true, "action": true, "formaction": true, "background": true,
	"cite": true, "poster": true, "data": true, "xlink:href": true, "ping": true, "longdesc": true, "usemap": true,
	"codebase": true, "archive": true, "manifest": true, "icon": true, "profile": true, "dynsrc": true, "lowsrc": true}

var linkAction = regexp.MustCompile(`^\{\{-?\s*\.link\s*-?\}\}$`)

// validateHTML checks where an HTML body's values land (MSG-004). Each action
// is replaced by a marker (one for {{.link}}, one for every other value) and
// the result is tokenized; the body is then rendered once with sample values,
// so a template that would fail at delivery is refused when it is saved.
func validateHTML(src string, allowed []string) error {
	// Lower case: the tokenizer lowercases tag and attribute names.
	const linkMark, valueMark = "palinkmark", "pavaluemark"
	var b strings.Builder
	for rest := src; ; {
		i := strings.Index(rest, "{{")
		j := strings.Index(rest[max(i, 0):], "}}")
		if i < 0 || j < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:i])
		if linkAction.MatchString(rest[i : i+j+2]) {
			b.WriteString(linkMark)
		} else {
			b.WriteString(valueMark)
		}
		rest = rest[i+j+2:]
	}
	marked := func(s string) bool { return strings.Contains(s, linkMark) || strings.Contains(s, valueMark) }
	refuse := func(detail string) error { return problem.ErrValidation.WithDetail(detail) }
	z := htmltok.NewTokenizer(strings.NewReader(b.String()))
	raw := ""
	for {
		switch z.Next() {
		case htmltok.ErrorToken:
			if z.Err() != io.EOF {
				return refuse("HTML template does not parse")
			}
			t, err := htmltemplate.New("v").Option("missingkey=zero").Parse(src)
			if err != nil {
				return refuse("HTML template does not parse")
			}
			sample := map[string]string{}
			for _, a := range allowed {
				sample[a] = "x"
			}
			if err := t.Execute(io.Discard, sample); err != nil {
				return refuse("HTML template is not well-formed (an unclosed tag, attribute or quote)")
			}
			return nil
		case htmltok.TextToken:
			if raw != "" && marked(string(z.Raw())) {
				return refuse("template values cannot be placed in a " + raw + " element")
			}
		case htmltok.EndTagToken:
			raw = ""
		case htmltok.StartTagToken, htmltok.SelfClosingTagToken:
			tok := z.Token()
			if tok.Data == "script" || tok.Data == "style" {
				raw = tok.Data
			}
			if marked(tok.Data) {
				return refuse("template values cannot form tag names")
			}
			for _, a := range tok.Attr {
				name := strings.ToLower(a.Key)
				switch {
				case marked(a.Key):
					return refuse("template values cannot form attribute names")
				case !marked(a.Val):
				case urlAttrs[name]:
					if strings.TrimSpace(a.Val) != linkMark {
						return refuse("a link may only be exactly {{.link}}: template values cannot build URLs")
					}
				case tok.Data == "meta" || name == "style" || strings.HasPrefix(name, "on"):
					return refuse("template values cannot be placed in styles, scripts or meta elements")
				}
			}
		}
	}
}

func actions(src string) []string {
	var out []string
	for {
		i := strings.Index(src, "{{")
		if i < 0 {
			return out
		}
		j := strings.Index(src[i:], "}}")
		if j < 0 {
			return append(out, "!")
		}
		out = append(out, strings.Trim(src[i+2:i+j], "- "))
		src = src[i+j+2:]
	}
}

// PurgePayloads removes secret-bearing payloads after retention while keeping
// non-secret delivery evidence (MSG-009).
func (s *Service) PurgePayloads(ctx context.Context, retention time.Duration) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE notification_jobs SET payload_ciphertext=NULL, payload_purged_at=$1
		WHERE payload_ciphertext IS NOT NULL AND (state IN ('accepted','failed','expired','suppressed') OR expires_at < $1) AND updated_at < $2`,
		s.d.Now(), s.d.Now().Add(-retention))
	return tag.RowsAffected(), err
}

// ListJobs lists delivery state for a reference.
//
// Newest first, limit items; with afterAt set, only jobs before (afterAt, afterID).
func (s *Service) ListJobs(ctx context.Context, realmID, refType, refID string, limit int, afterAt *time.Time, afterID string) ([]Job, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, channel, template, coalesce(recipient_hint,''), state, attempts, coalesce(last_error,''),
		coalesce(reference_type,''), coalesce(reference_id,''), created_at, updated_at FROM notification_jobs
		WHERE realm_id=$1 AND ($2='' OR reference_type=$2) AND ($3='' OR reference_id=$3)
		AND ($5::timestamptz IS NULL OR (created_at, id) < ($5, $6)) ORDER BY created_at DESC, id DESC LIMIT $4`, realmID, refType, refID, limit, afterAt, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Channel, &j.Template, &j.RecipientHint, &j.State, &j.Attempts, &j.LastError, &j.ReferenceType,
			&j.ReferenceID, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Suppress records a bounce/complaint suppression (MSG-007). Provider delivery
// status never verifies an identity.
func (s *Service) Suppress(ctx context.Context, q storage.Querier, realmID, recipient, reason string) error {
	_, err := q.Exec(ctx, `INSERT INTO notification_suppressions (realm_id, recipient_digest, reason) VALUES ($1,$2,$3)
		ON CONFLICT (realm_id, recipient_digest) DO UPDATE SET reason=EXCLUDED.reason`, realmID, secret.Digest(strings.ToLower(recipient)), reason)
	return err
}

// DevMailbox returns messages captured by the development sink. Only reachable in
// development mode (MSG-011).
func (s *Service) DevMailbox(ctx context.Context, realmID, recipient string) ([]map[string]any, error) {
	if s.d.Cfg.Mode != "development" {
		return nil, problem.ErrFeatureDisabled
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, recipient, subject, body_text, template, created_at FROM dev_mailbox
		WHERE realm_id=$1 AND ($2='' OR lower(recipient)=lower($2)) ORDER BY created_at DESC LIMIT 50`, realmID, recipient)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, r, sub, body, tpl string
		var at time.Time
		if err := rows.Scan(&id, &r, &sub, &body, &tpl, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "recipient": r, "subject": sub, "body": body, "template": tpl, "created_at": at})
	}
	return out, rows.Err()
}

// ---------- SMTP adapter ----------

// SMTPSender delivers through a standard SMTP relay (MSG-001).
type SMTPSender struct {
	Host        string
	Port        int
	Username    string
	PasswordRef string
	TLSMode     string
	Resolve     func(string) (string, error)
	// Dial, when set, opens the TCP connection (tenant servers use it to
	// enforce the egress policy on the resolved address).
	Dial func(ctx context.Context, host, port string) (net.Conn, error)
}

// smtpSessionBudget bounds one SMTP delivery from the established connection
// to QUIT: greeting, STARTTLS, AUTH, MAIL, RCPT, DATA. net/smtp ignores the
// context, so without a connection deadline a relay that accepts TCP and then
// stays silent would block the worker forever. A variable so tests can lower
// it.
var smtpSessionBudget = 30 * time.Second

// Send sends one message. The whole session runs under one connection
// deadline (smtpSessionBudget, or the context's deadline when sooner), and
// cancelling ctx closes the connection, so the worker's task timeout ends a
// stalled delivery; the same holds for organization mail servers (TEN-022),
// which come through Dial.
func (s *SMTPSender) Send(ctx context.Context, e Email) (string, error) {
	msgID := fmt.Sprintf("<%s@proudauth>", ids.New("msg"))
	msg := buildMessage(e, msgID, time.Now())
	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	deadline := smtpDeadline(ctx)
	var conn net.Conn
	var err error
	if s.Dial != nil {
		conn, err = s.Dial(ctx, s.Host, fmt.Sprint(s.Port))
	} else {
		dialer := &net.Dialer{Timeout: 10 * time.Second, Deadline: deadline}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return "", err
	}
	release, err := guardConn(ctx, conn, deadline)
	if err != nil {
		conn.Close()
		return "", err
	}
	defer release()
	err = s.session(ctx, conn, e.From, e.To, msg)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return "", fmt.Errorf("smtp delivery to %s: %w (%v)", addr, ctx.Err(), err)
		}
		return "", err
	}
	return msgID, nil
}

// smtpDeadline is when an SMTP session starting now must end: after
// smtpSessionBudget, or at the context's deadline when that is sooner.
func smtpDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(smtpSessionBudget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

// guardConn puts conn under deadline and closes it as soon as ctx ends,
// until release is called when the session returns.
func guardConn(ctx context.Context, conn net.Conn, deadline time.Time) (release func(), err error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	return func() { close(stop) }, nil
}

// session speaks SMTP on an established connection, which already carries
// the delivery deadline (the implicit TLS handshake included).
func (s *SMTPSender) session(ctx context.Context, conn net.Conn, from, to string, msg []byte) error {
	if s.TLSMode == "implicit" {
		tc := tls.Client(conn, &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.TLSMode == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if s.Username != "" {
		pw := s.PasswordRef
		if s.Resolve != nil {
			if pw, err = s.Resolve(s.PasswordRef); err != nil {
				return err
			}
		}
		if err := c.Auth(smtp.PlainAuth("", s.Username, pw, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMessage renders the RFC 5322 message. Non-ASCII Subject and sender
// names are RFC 2047 encoded words, and a body part with non-ASCII text is
// sent quoted-printable, so localized templates (MSG-006) reach 7-bit relays
// intact.
func buildMessage(e Email, msgID string, now time.Time) []byte {
	var b strings.Builder
	from := (&mail.Address{Name: headerSafe(e.FromName), Address: headerSafe(e.From)}).String()
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n",
		from, headerSafe(e.To), mime.QEncoding.Encode("utf-8", headerSafe(e.Subject)), msgID, now.UTC().Format(time.RFC1123Z))
	if e.ReplyTo != "" {
		fmt.Fprintf(&b, "Reply-To: %s\r\n", headerSafe(e.ReplyTo))
	}
	if e.HTML != "" {
		boundary := "pa-" + secretHex()
		fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		writePart(&b, "text/plain", e.Text)
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		writePart(&b, "text/html", e.HTML)
		fmt.Fprintf(&b, "--%s--\r\n", boundary)
	} else {
		writePart(&b, "text/plain", e.Text)
	}
	return []byte(b.String())
}

// writePart writes a Content-Type header, the blank line and the body,
// quoted-printable when the body has bytes outside US-ASCII.
func writePart(b *strings.Builder, contentType, body string) {
	fmt.Fprintf(b, "Content-Type: %s; charset=utf-8\r\n", contentType)
	if isASCII(body) {
		fmt.Fprintf(b, "\r\n%s\r\n", body)
		return
	}
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(b)
	_, _ = qp.Write([]byte(body))
	_ = qp.Close()
	b.WriteString("\r\n")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func headerSafe(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func secretHex() string { return fmt.Sprintf("%x", secret.Random(8)) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// EnqueueMany enqueues several messages in one transaction.
func (s *Service) EnqueueMany(ctx context.Context, tx pgx.Tx, msgs ...Message) error {
	for _, m := range msgs {
		if _, err := s.EnqueueTx(ctx, tx, m); err != nil {
			return err
		}
	}
	return nil
}

// DeliverySettings are the effective sender settings for a realm or
// organization (organization settings override realm settings field by field).
type DeliverySettings struct {
	SenderAddress, SenderName, ReplyTo, DefaultLocale string
}

func (s *Service) settings(ctx context.Context, realmID, orgID string) DeliverySettings {
	out := DeliverySettings{DefaultLocale: "en"}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT organization_id, coalesce(sender_address,''), coalesce(sender_name,''), coalesce(reply_to,''), default_locale
		FROM notification_settings WHERE realm_id=$1 AND organization_id IN ('', $2) ORDER BY organization_id`, realmID, orgID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var org string
		var d DeliverySettings
		if rows.Scan(&org, &d.SenderAddress, &d.SenderName, &d.ReplyTo, &d.DefaultLocale) != nil {
			continue
		}
		// Realm row first, then the organization row overrides set fields.
		if d.SenderAddress != "" {
			out.SenderAddress = d.SenderAddress
		}
		if d.SenderName != "" {
			out.SenderName = d.SenderName
		}
		if d.ReplyTo != "" {
			out.ReplyTo = d.ReplyTo
		}
		if d.DefaultLocale != "" {
			out.DefaultLocale = d.DefaultLocale
		}
	}
	return out
}

// Check verifies SMTP reachability, TLS and authentication without sending
// (MSG-012). Errors name the failing stage only; credentials never appear.
func (s *SMTPSender) Check(ctx context.Context) (stage string, err error) {
	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if s.TLSMode == "implicit" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return "connect", err
	}
	// The same session deadline as Send, so a silent relay cannot hold the
	// check past its request timeout.
	release, err := guardConn(ctx, conn, smtpDeadline(ctx))
	if err != nil {
		conn.Close()
		return "connect", err
	}
	defer release()
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return "greeting", err
	}
	defer c.Close()
	if s.TLSMode == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return "starttls", err
		}
	}
	if s.Username != "" {
		pw := s.PasswordRef
		if s.Resolve != nil {
			if pw, err = s.Resolve(s.PasswordRef); err != nil {
				return "credentials", err
			}
		}
		if err := c.Auth(smtp.PlainAuth("", s.Username, pw, s.Host)); err != nil {
			return "authentication", err
		}
	}
	return "ok", c.Quit()
}

// tenantShare is the per-tenant cap within one batch (TEN-018).
func tenantShare(share, batch int) int {
	if share <= 0 || share > batch {
		return batch
	}
	return share
}
