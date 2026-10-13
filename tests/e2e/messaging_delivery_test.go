package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/server"
	"github.com/proudbase/proudauth/internal/worker"
)

// recordingSender is an email adapter plugged into the delivery service in
// place of SMTP (MSG-001): it keeps what the worker hands it and refuses
// every message while err is set.
type recordingSender struct {
	mu   sync.Mutex
	sent []notification.Email
	err  error
}

func (s *recordingSender) Send(_ context.Context, e notification.Email) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	s.sent = append(s.sent, e)
	return fmt.Sprintf("rec-%d", len(s.sent)), nil
}

func (s *recordingSender) to(recipient string) []notification.Email {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []notification.Email
	for _, e := range s.sent {
		if e.To == recipient {
			out = append(out, e)
		}
	}
	return out
}

// useSender routes the harness's email through s instead of the
// development sink until the test ends.
func useSender(t *testing.T, h *Harness, s notification.EmailSender) {
	t.Helper()
	n := h.App.Notify
	sink, prev := n.DevSink, n.Email
	n.DevSink, n.Email = false, s
	t.Cleanup(func() { n.DevSink, n.Email = sink, prev })
}

// TestDeliveryJobStates covers MSG-002: a message is written in the
// transaction of the action that needs it (a rolled-back action leaves no
// message, and workers never see it before commit), and the administration
// API reports the queued, attempted, accepted, failed and expired states as
// they happen. It also covers MSG-001: the worker delivers through whatever
// email adapter is configured, here one that is not SMTP.
func TestDeliveryJobStates(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	notify := h.App.Notify
	rec := &recordingSender{}
	useSender(t, h, rec)
	msg := func(ref string, ttl time.Duration) notification.Message {
		return notification.Message{RealmID: h.Realm.ID, Template: notification.TplTest, Recipient: "ops@example.test", Mandatory: true,
			ReferenceType: "delivery_check", ReferenceID: ref, TTL: ttl, Data: map[string]string{"realm": "Main", "time": notification.Timestamp(h.Clock.Now())}}
	}
	exists := func(id string) bool {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_jobs WHERE id=$1`, id).Scan(&n)
		return n == 1
	}
	jobs := func() map[string]map[string]any {
		r := f.must(f.AdminAPI("GET", "/notification-jobs?reference_type=delivery_check", nil), 200, "delivery listing")
		out := map[string]map[string]any{}
		for _, it := range r.Get("items").([]any) {
			j := it.(map[string]any)
			out[j["reference_id"].(string)] = j
		}
		return out
	}
	enqueue := func(ref string, ttl time.Duration) string {
		id, err := notify.EnqueueTx(ctx, h.App.D.DB.Pool, msg(ref, ttl))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	// Transactional enqueue: the message shares the action's fate.
	failed := errors.New("the action failed after queuing its message")
	var rolledBack string
	err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		id, err := notify.EnqueueTx(ctx, tx, msg("rolled-back", 0))
		if err != nil {
			return err
		}
		rolledBack = id
		h.Deliver() // a worker running now cannot see the uncommitted message
		if exists(id) {
			t.Error("message visible outside its transaction before commit")
		}
		return failed
	})
	if !errors.Is(err, failed) || rolledBack == "" {
		t.Fatalf("transaction: %v", err)
	}
	if exists(rolledBack) || len(rec.to("ops@example.test")) != 0 {
		t.Fatal("a rolled-back action left its message behind")
	}
	// A real action: suspending an account commits its notice with it.
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "review"}), 200, "suspend")
	var notice string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM notification_jobs WHERE template='account_suspended' AND reference_type='user'
		AND reference_id=$1`, f.Users["carol"]).Scan(&notice)
	if notice != "queued" {
		t.Fatalf("suspension committed without its queued notice: %q", notice)
	}

	// States, as the administration API reports them.
	enqueue("accepted", 0)
	if j := jobs()["accepted"]; j["state"] != "queued" || j["attempts"] != 0.0 {
		t.Fatalf("new message: %v", j)
	}
	h.Deliver()
	if j := jobs()["accepted"]; j["state"] != "accepted" || j["attempts"] != 1.0 || j["recipient_hint"] != "o***@example.test" {
		t.Fatalf("accepted message: %v", j)
	}
	sent := rec.to("ops@example.test")
	if len(sent) != 1 || sent[0].Subject != "Main delivery test" || !strings.Contains(sent[0].Text, "configuration test") {
		t.Fatalf("adapter did not receive the rendered message: %+v", sent)
	}
	var provider string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(provider_message_id,'') FROM notification_jobs WHERE reference_id='accepted'`).Scan(&provider)
	if !strings.HasPrefix(provider, "rec-") {
		t.Fatalf("adapter's message ID not recorded: %q", provider)
	}

	rec.mu.Lock()
	rec.err = errors.New("550 relay refused")
	rec.mu.Unlock()
	enqueue("failing", 0)
	h.Deliver()
	if j := jobs()["failing"]; j["state"] != "attempted" || j["attempts"] != 1.0 || j["last_error"] != "550 relay refused" {
		t.Fatalf("message awaiting retry: %v", j)
	}
	for range 6 {
		h.Clock.Advance(5 * time.Minute) // past the retry backoff
		h.Deliver()
	}
	expiring := enqueue("expired", time.Minute)
	h.Clock.Advance(2 * time.Minute)
	h.Deliver()
	f.ReloginAdmin()
	all := jobs()
	if j := all["failing"]; j["state"] != "failed" || j["attempts"] != 5.0 || j["last_error"] != "550 relay refused" {
		t.Fatalf("message out of attempts: %v", j)
	}
	if j := all["expired"]; j["state"] != "expired" {
		t.Fatalf("message past its lifetime: %v", j)
	}
	var attempts int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT attempts FROM notification_jobs WHERE id=$1`, expiring).Scan(&attempts)
	if attempts != 1 || len(rec.to("ops@example.test")) != 1 {
		t.Fatalf("expired message was handed to the adapter: attempts %d, sent %d", attempts, len(rec.to("ops@example.test")))
	}
	if j := all["accepted"]; j["state"] != "accepted" {
		t.Fatalf("accepted message changed state: %v", j)
	}
}

// TestSecurityNotices covers MSG-003: verification, password reset,
// invitation, MFA change, new sign-in, account suspension and support-access
// notices are each sent by the action they report.
func TestSecurityNotices(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Notifications.NewLoginAlerts = true }), 200, "new sign-in alerts")
	expect := func(recipient, template string, wants ...string) string {
		t.Helper()
		mail := h.Mail(recipient, template)
		if mail == "" {
			t.Fatalf("no %s notice for %s", template, recipient)
		}
		for _, w := range wants {
			if !strings.Contains(mail, w) {
				t.Fatalf("%s notice lacks %q: %q", template, w, mail)
			}
		}
		return mail
	}

	// Verification of a newly added address.
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	id := f.must(h.API("POST", "/me/identifiers", bob, map[string]any{"type": "email", "value": "bob.alt@example.test"}), 201, "add address").Str("id")
	f.must(h.API("POST", "/verification-challenges", bob, map[string]any{"identifier_id": id}), 201, "verification challenge")
	if CodeFrom(expect("bob.alt@example.test", "email_verification", "verification code")) == "" {
		t.Fatal("verification notice carries no code")
	}
	// Password reset.
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/password-resets", JSON: map[string]any{"identifier": "carol@example.test"}}), 202, "reset")
	if CodeFrom(expect("carol@example.test", "password_reset", "reset your password")) == "" {
		t.Fatal("reset notice carries no code")
	}
	// Invitation.
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "dave@example.test",
		"role_ids": []string{f.Roles["orders-viewer"]}}), 201, "invite")
	if invitationFromMail(expect("dave@example.test", "invitation", "Acme Corp")) == "" {
		t.Fatal("invitation notice carries no invitation")
	}
	// MFA change.
	f.EnrollTOTP("bob")
	expect("bob@example.test", "mfa_changed", "authenticator app added")
	// New sign-in.
	f.AccountToken("carol")
	expect("carol@example.test", "new_login", "A new sign-in occurred")
	// Account suspension.
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
	expect("carol@example.test", "account_suspended", "Your account was suspended")
	// Support access.
	f.support(t).issue(t, f.Users["bob"], f.Acme)
	expect("bob@example.test", "support_access", "support operator was granted read-only access", "Acme Corp")
}

// userAgent sends every harness request with a chosen User-Agent, a value
// any client controls.
type userAgent string

func (ua userAgent) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", string(ua))
	return http.DefaultTransport.RoundTrip(r)
}

// TestCustomTemplateSafety covers MSG-004 through the template API: unsafe
// templates (undocumented or other events' variables, function calls, values
// placed in links, scripts or styles, broken HTML) are refused, and a custom
// HTML template renders a client-controlled value escaped, never as markup or
// a link.
func TestCustomTemplateSafety(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Notifications.NewLoginAlerts = true }), 200, "new sign-in alerts")
	post := func(text, html string) *Resp {
		return f.AdminAPI("POST", "/templates", map[string]any{"event_type": "new_login", "subject": "New sign-in to {{.realm}}",
			"body_text": text, "body_html": html})
	}
	for name, c := range map[string][2]string{
		"another event's secret": {"Code {{.code}}", ""},
		"undocumented variable":  {"{{.password}}", ""},
		"function call":          {`{{printf "%v" .}}`, ""},
		"nested template":        {`{{template "x"}}`, ""},
		"value as a link":        {"x", `<a href="{{.device}}">details</a>`},
		"value in a URL":         {"x", `<img src="https://pixel.test/t?d={{.device}}">`},
		"value in a script":      {"x", `<script>var d = {{.device}};</script>`},
		"value in a style":       {"x", `<p style="color: {{.device}}">x</p>`},
		"unclosed attribute":     {"x", `<p title="{{.device}}`},
	} {
		if r := post(c[0], c[1]); r.Status != 422 {
			t.Errorf("%s: unsafe template accepted: %d %s", name, r.Status, r.Raw)
		}
	}
	mustStatus(t, f.AdminAPI("POST", "/templates", map[string]any{"event_type": "no_such_event", "subject": "x", "body_text": "x"}), 422, "unknown event")
	tpl := f.must(post("Device: {{.device}} at {{.time}}", `<p>New sign-in from <b>{{.device}}</b> at {{.time}}.</p>`), 201, "safe template").Str("id")
	list := f.must(f.AdminAPI("GET", "/templates", nil), 200, "templates")
	if !strings.Contains(string(list.Raw), tpl) || !slices.Contains(list.Get("variables").(map[string]any)["new_login"].([]any), any("device")) {
		t.Fatalf("template listing: %s", list.Raw)
	}

	rec := &recordingSender{}
	useSender(t, h, rec)
	const hostile = `<a href="https://evil.test/">Verify now</a><script>steal()</script>`
	h.HTTP.Transport = userAgent(hostile)
	f.AccountToken("bob")
	h.HTTP.Transport = nil
	h.Deliver()
	sent := rec.to("bob@example.test")
	if len(sent) != 1 {
		t.Fatalf("new sign-in notices: %d", len(sent))
	}
	html := sent[0].HTML
	if strings.Contains(html, "<a href") || strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;a href=&#34;https://evil.test/&#34;&gt;") {
		t.Fatalf("client-controlled value not escaped in the HTML part: %q", html)
	}
	if sent[0].Subject != "New sign-in to Main" || !strings.Contains(sent[0].Text, "Device: "+hostile) {
		t.Fatalf("custom template not used: %+v", sent[0])
	}

	// Disabling the template restores the built-in wording.
	mustStatus(t, f.AdminAPI("DELETE", "/templates/"+tpl, nil), 204, "disable template")
	f.AccountToken("bob")
	h.Deliver()
	if sent := rec.to("bob@example.test"); len(sent) != 2 || !strings.Contains(sent[1].Text, "A new sign-in occurred") || sent[1].HTML != "" {
		t.Fatalf("built-in template after disabling the custom one: %+v", sent)
	}
}

// TestDeliveryPayloadRetention covers MSG-009: a message carrying a one-time
// code is stored only as ciphertext bound to its job, holding just the
// recipient and template values; the retention task removes the payload once
// the job finished (or, undelivered, expired) and the retention period
// passed, and keeps the non-secret delivery evidence.
func TestDeliveryPayloadRetention(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	reset := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/password-resets", JSON: map[string]any{"identifier": "bob@example.test"}})
	mustStatus(t, reset, 202, "reset")
	resetID := reset.Str("reset_id")
	code := CodeFrom(h.Mail("bob@example.test", "password_reset"))
	if code == "" {
		t.Fatal("no reset code delivered")
	}
	var jobID, row string
	var ct []byte
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id, (to_jsonb(j) - 'payload_ciphertext')::text, payload_ciphertext FROM notification_jobs j
		WHERE template='password_reset' AND reference_id=$1`, resetID).Scan(&jobID, &row, &ct); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, code) || strings.Contains(row, "bob@example.test") {
		t.Fatalf("job row holds the code or the address in clear: %s", row)
	}
	pt, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("notification:"+jobID))
	if err != nil || !strings.Contains(string(pt), code) {
		t.Fatalf("payload is not the encrypted message: %v", err)
	}
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(pt, &payload)
	if len(payload) != 2 || payload["r"] == nil || payload["d"] == nil {
		t.Fatalf("payload holds more than the recipient and template values: %s", pt)
	}
	if _, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("notification:ntf_other")); err == nil {
		t.Fatal("payload decrypts outside its job")
	}

	// An undelivered message that is still valid keeps its payload past the
	// retention period; it goes once it expired.
	pending, err := h.App.Notify.EnqueueTx(ctx, h.App.D.DB.Pool, notification.Message{RealmID: h.Realm.ID, Template: notification.TplTest,
		Recipient: "ops@example.test", Mandatory: true, TTL: 72 * time.Hour, Data: map[string]string{"realm": "Main"}})
	if err != nil {
		t.Fatal(err)
	}
	w := worker.New(h.App, "test")
	retain := func() {
		t.Helper()
		if _, err := w.Retention(ctx); err != nil {
			t.Fatalf("retention: %v", err)
		}
	}
	hasPayload := func(id string) bool {
		var has bool
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT payload_ciphertext IS NOT NULL FROM notification_jobs WHERE id=$1`, id).Scan(&has)
		return has
	}
	retain()
	if !hasPayload(jobID) || !hasPayload(pending) {
		t.Fatal("payload removed before the retention period")
	}
	h.Clock.Advance(h.Cfg.Delivery.PayloadRetention + time.Minute)
	retain()
	if hasPayload(jobID) {
		t.Fatal("delivered message kept its payload past the retention period")
	}
	if !hasPayload(pending) {
		t.Fatal("undelivered message lost its payload before it expired")
	}
	var state, template, hint, provider string
	var attempts int
	var purgedAt *time.Time
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, template, recipient_hint, attempts, coalesce(provider_message_id,''), payload_purged_at
		FROM notification_jobs WHERE id=$1`, jobID).Scan(&state, &template, &hint, &attempts, &provider, &purgedAt); err != nil {
		t.Fatal(err)
	}
	if state != "accepted" || template != "password_reset" || hint != "b***@example.test" || attempts != 1 || provider == "" || purgedAt == nil {
		t.Fatalf("delivery evidence after the purge: %s %s %s %d %q %v", state, template, hint, attempts, provider, purgedAt)
	}
	f.ReloginAdmin()
	r := f.must(f.AdminAPI("GET", "/notification-jobs?reference_type=challenge&reference_id="+resetID, nil), 200, "delivery listing")
	if items := r.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["state"] != "accepted" {
		t.Fatalf("delivery evidence not listed after the purge: %s", r.Raw)
	}
	h.Clock.Advance(72 * time.Hour)
	retain()
	if hasPayload(pending) {
		t.Fatal("expired, undelivered message kept its payload")
	}
}

// TestDevelopmentSinkIsPrivate covers MSG-011: the development mail sink
// captures messages for local testing, but its contents are served only on
// the private operator listener in development mode, never by the public
// listener or the administration API, and the service refuses to read it
// outside development mode.
func TestDevelopmentSinkIsPrivate(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/password-resets", JSON: map[string]any{"identifier": "bob@example.test"}}), 202, "reset")
	code := CodeFrom(h.Mail("bob@example.test", "password_reset"))
	if code == "" {
		t.Fatal("development sink did not capture the message")
	}
	for _, path := range []string{"/dev/mailbox?realm=main", "/dev/mailbox?realm=main&recipient=bob@example.test",
		"/api/v1/realms/main/dev/mailbox", "/realms/main/dev/mailbox"} {
		if r := h.Do(Req{Method: "GET", Path: path}); r.Status == 200 || strings.Contains(string(r.Raw), code) {
			t.Fatalf("public listener served the sink at %s: %d", path, r.Status)
		}
	}
	jobs := f.must(f.AdminAPI("GET", "/notification-jobs?reference_type=challenge", nil), 200, "delivery listing")
	if strings.Contains(string(jobs.Raw), code) || strings.Contains(string(jobs.Raw), "bob@example.test") {
		t.Fatalf("delivery listing exposes message contents: %s", jobs.Raw)
	}

	mailbox := func(mode configuration.Mode) (int, string, http.Header) {
		cfg := *h.Cfg
		cfg.Mode = mode
		env := &server.Env{Cfg: &cfg, Log: h.App.D.Log, DB: h.App.D.DB, Keys: h.App.D.Keys, Deps: h.App.D, Metrics: h.App.Metrics}
		srv := httptest.NewServer(server.InternalHandler(env, h.App))
		defer srv.Close()
		res, err := http.Get(srv.URL + "/dev/mailbox?realm=main&recipient=bob@example.test")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw), res.Header
	}
	if st, body, hdr := mailbox(configuration.ModeDevelopment); st != 200 || !strings.Contains(body, code) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("operator listener in development mode: %d %v", st, hdr)
	}
	if st, body, _ := mailbox(configuration.ModeProduction); st != 404 || strings.Contains(body, code) {
		t.Fatalf("operator listener in production mode served the sink: %d", st)
	}
	mode := h.App.D.Cfg.Mode
	h.App.D.Cfg.Mode = configuration.ModeProduction
	_, err := h.App.Notify.DevMailbox(ctx, h.Realm.ID, "")
	h.App.D.Cfg.Mode = mode
	if !errors.Is(err, problem.ErrFeatureDisabled) {
		t.Fatalf("sink readable outside development mode: %v", err)
	}
	// The shipped defaults are production mode without a sink (production
	// validation refuses one: TestValidateRejectsUnsafeSettings).
	if d := configuration.Defaults(); d.Mode != configuration.ModeProduction || d.Delivery.Email.Adapter == "dev_sink" || d.Delivery.SMS.Adapter == "dev_sink" {
		t.Fatalf("defaults enable the development sink: %s %+v", d.Mode, d.Delivery)
	}
}
