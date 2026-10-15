package e2e

import (
	"context"
	"encoding/json"
	"github.com/proudauth/proudauth/internal/keys"
	"strconv"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/webhooks"
)

// TestMessagingControls covers MSG-005 (approved sender domains), MSG-007
// (authenticated provider feedback), MSG-010 (preferences for optional
// notices only) and MSG-012 (delivery configuration check).
func TestMessagingControls(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Notifications.NewLoginAlerts = true }), 200, "new-login alerts")

	t.Run("MSG-010 optional notices follow preferences", func(t *testing.T) {
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		prefs := h.API("GET", "/me/notification-preferences", bob, nil)
		if prefs.Get("preferences").(map[string]any)["new_login"] != true {
			t.Fatalf("default preferences: %s", prefs.Raw)
		}
		mustStatus(t, h.API("PUT", "/me/notification-preferences", bob, map[string]any{"preferences": map[string]any{"password_changed": false}}), 422,
			"mandatory notice cannot be muted")
		mustStatus(t, h.API("PUT", "/me/notification-preferences", bob, map[string]any{"preferences": map[string]any{"new_login": false}}), 200, "mute")
		count := func(state string) int {
			var n int
			_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_jobs WHERE template='new_login' AND reference_id=$1
				AND (state='suppressed') = ($2='suppressed')`, f.Users["bob"], state).Scan(&n)
			return n
		}
		sentBefore, mutedBefore := count("sent"), count("suppressed")
		f.AccountToken("bob")
		if count("sent") != sentBefore || count("suppressed") != mutedBefore+1 {
			t.Fatalf("muted optional notice still sent: sent %d->%d, suppressed %d->%d", sentBefore, count("sent"), mutedBefore, count("suppressed"))
		}
	})

	t.Run("MSG-007 provider feedback is authenticated", func(t *testing.T) {
		h.App.D.Cfg.Delivery.Email.EventsSecret = "provider-feedback-secret"
		body, _ := json.Marshal(map[string]any{"events": []map[string]any{{"type": "complaint", "recipient": "carol@example.test"},
			{"type": "bounce", "recipient": "nobody@example.test", "permanent": true, "provider_message_id": "<x@proudauth>"}}})
		ts := h.Clock.Now().Unix()
		sig := webhooks.Sign("provider-feedback-secret", "evt_1", ts, body)
		post := func(signature string) *Resp {
			return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/delivery-events", RawBody: body, Headers: map[string]string{
				"Content-Type": "application/json", "Webhook-Id": "evt_1", "Webhook-Timestamp": strconv.FormatInt(ts, 10), "Webhook-Signature": signature}})
		}
		mustStatus(t, post("v1,AAAA"), 401, "forged feedback")
		r := post(sig)
		mustStatus(t, r, 200, "signed feedback")
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_suppressions WHERE realm_id=$1`, h.Realm.ID).Scan(&n)
		if n != 2 {
			t.Fatalf("suppressions recorded: %d", n)
		}
	})

	t.Run("MSG-005 sender domains and MSG-012 configuration check", func(t *testing.T) {
		mustStatus(t, f.AdminAPI("PATCH", "/notification-settings", map[string]any{"sender_address": "ceo@evil.test"}), 422, "unapproved realm sender")
		mustStatus(t, f.AdminAPI("PATCH", "/notification-settings", map[string]any{"organization_id": f.Acme, "sender_address": "billing@acme-unverified.test"}), 422,
			"organization sender outside verified domains")
		chk := f.must(f.AdminAPI("POST", "/notification-settings/check", nil), 200, "check")
		if chk.Get("ok") != true {
			t.Fatalf("delivery check: %s", chk.Raw)
		}
	})
}

// TestNoticeTimeZones covers MSG-006: timestamps in notices are rendered in
// the recipient's time zone (UTC when unknown), from a machine-readable value.
func TestNoticeTimeZones(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	me := f.must(h.API("GET", "/me", bob, nil), 200, "me")
	mustStatus(t, h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/me", Token: bob, JSON: map[string]any{"zoneinfo": "Asia/Tokyo"},
		Headers: map[string]string{"If-Match": me.Header.Get("ETag")}}), 200, "set time zone")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
	if mail := h.Mail("bob@example.test", "account_suspended"); !strings.Contains(mail, "JST") {
		t.Fatalf("notice not rendered in the recipient's time zone: %q", mail)
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
	if mail := h.Mail("carol@example.test", "account_suspended"); !strings.Contains(mail, "UTC") {
		t.Fatalf("notice without a known time zone is not in UTC: %q", mail)
	}
}

// TestTenantSMTPCredentials covers TEN-022: an organization's own mail server
// credential is encrypted, bound to that organization, never returned, and
// manageable only by that organization's integration administrators.
func TestTenantSMTPCredentials(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	path := "/organizations/" + f.Acme + "/notification-settings/smtp"
	mustStatus(t, h.API("PUT", path, alice, map[string]any{"host": "smtp.acme.test", "port": 25, "tls_mode": "none", "password": "x"}), 422, "plain-text SMTP")
	put := f.must(h.API("PUT", path, alice, map[string]any{"host": "smtp.acme.test", "port": 587, "tls_mode": "starttls", "username": "mailer",
		"password": "acme-smtp-secret-123"}), 200, "set tenant SMTP")
	if put.Get("has_password") != true || strings.Contains(string(put.Raw), "acme-smtp-secret-123") {
		t.Fatalf("tenant SMTP response: %s", put.Raw)
	}
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	if r := h.API("GET", path, carol, nil); r.Status != 404 {
		t.Fatalf("another organization's administrator read the mail server: %d", r.Status)
	}
	var ct []byte
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT smtp_secret_ciphertext FROM notification_settings WHERE organization_id=$1`, f.Acme).Scan(&ct)
	if len(ct) == 0 || strings.Contains(string(ct), "acme-smtp-secret-123") {
		t.Fatal("tenant SMTP password not stored encrypted")
	}
	if _, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("smtp:"+h.Realm.ID+":"+f.Globex)); err == nil {
		t.Fatal("tenant SMTP credential decrypts for another organization")
	}
	if pt, err := h.App.D.Keys.Decrypt(keys.PurposeData, ct, []byte("smtp:"+h.Realm.ID+":"+f.Acme)); err != nil || string(pt) != "acme-smtp-secret-123" {
		t.Fatal("tenant SMTP credential not usable by its own organization")
	}
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=notification.smtp.updated", nil), 200, "audit")
	if len(ev.Get("items").([]any)) != 1 || strings.Contains(string(ev.Raw), "acme-smtp-secret-123") {
		t.Fatalf("tenant SMTP change audit: %s", ev.Raw)
	}
	mustStatus(t, h.API("DELETE", path, alice, nil), 204, "clear")
	mustStatus(t, h.API("GET", path, alice, nil), 404, "cleared")
}
