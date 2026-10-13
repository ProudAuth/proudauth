package configuration

import (
	"strings"
	"testing"
)

// TestCallbackSecretsNeedReferences covers QA-008, DEP-006 and OPS-010: in
// production, delivery.email.events_secret (the email provider's callback
// secret) and delivery.sms.webhook_secret must be secret references whenever
// they are set, and Config.Redacted replaces literal values of both with
// [REDACTED] while leaving references visible.
func TestCallbackSecretsNeedReferences(t *testing.T) {
	fields := map[string]func(*Config, string){
		"delivery.email.events_secret": func(c *Config, v string) { c.Delivery.Email.EventsSecret = v },
		"delivery.sms.webhook_secret":  func(c *Config, v string) { c.Delivery.SMS.WebhookSecret = v },
	}
	for name, set := range fields {
		c := validProd()
		set(&c, "literal-callback-secret")
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), name+" must be a secret reference") {
			t.Errorf("literal %s accepted in production: %v", name, err)
		}
		for _, ref := range []string{"file:/run/secrets/callback_secret", "env:CALLBACK_SECRET"} {
			c := validProd()
			set(&c, ref)
			if err := c.Validate(); err != nil {
				t.Errorf("%s reference %q refused in production: %v", name, ref, err)
			}
		}
		dev := validDev()
		set(&dev, "literal-callback-secret")
		if err := dev.Validate(); err != nil {
			t.Errorf("literal %s refused in development: %v", name, err)
		}
	}

	c := validDev()
	c.Delivery.Email.EventsSecret = "literal-events-secret"
	c.Delivery.SMS.WebhookSecret = "literal-sms-secret"
	r := c.Redacted()
	if r.Delivery.Email.EventsSecret != "[REDACTED]" || r.Delivery.SMS.WebhookSecret != "[REDACTED]" {
		t.Fatalf("literal callback secrets not redacted: events %q, sms %q", r.Delivery.Email.EventsSecret, r.Delivery.SMS.WebhookSecret)
	}
	if c.Delivery.Email.EventsSecret != "literal-events-secret" {
		t.Fatal("redaction changed the live configuration")
	}
	c.Delivery.Email.EventsSecret = "file:/run/secrets/email_events"
	if got := c.Redacted().Delivery.Email.EventsSecret; got != "file:/run/secrets/email_events" {
		t.Fatalf("a secret reference must stay visible: %q", got)
	}
}
