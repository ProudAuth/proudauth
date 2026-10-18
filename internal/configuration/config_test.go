package configuration

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validDev() Config {
	c := Defaults()
	c.Mode = ModeDevelopment
	c.Server.PublicOrigin = "http://localhost:8080"
	c.Storage.DatabaseURL = "env:DATABASE_URL"
	c.Keys.RootKeys = []KeyRef{{Version: 1, Ref: "env:ROOT_KEY"}}
	c.Delivery.Email.Adapter = "dev_sink"
	return c
}

func validProd() Config {
	c := Defaults()
	c.Mode = ModeProduction
	c.Server.PublicOrigin = "https://id.example.com"
	c.Storage.DatabaseURL = "file:/run/secrets/database_url"
	c.Keys.RootKeys = []KeyRef{{Version: 1, Ref: "file:/run/secrets/root_key"}}
	c.Delivery.Email.SMTPHost = "smtp.example.com"
	c.Delivery.Email.From = "id@example.com"
	return c
}

func TestValidateBaselines(t *testing.T) {
	for name, c := range map[string]Config{"development": validDev(), "production": validProd()} {
		if err := c.Validate(); err != nil {
			t.Fatalf("%s baseline rejected: %v", name, err)
		}
	}
}

// TestValidateRejectsUnsafeSettings covers DEP-005, DEP-006, QA-007 and the
// runtime-safety floors that previously passed validation, and DEP-008: no
// process starts without durable root keys, so a restart can never generate
// a fresh key hierarchy.
// Requirements: MSG-011 (the email and SMS development sinks are refused in
// production), SEC-011 (no literal or default credentials in production).
func TestValidateRejectsUnsafeSettings(t *testing.T) {
	cases := map[string]struct {
		base   func() Config
		mutate func(*Config)
		want   string
	}{
		"http issuer in production":      {validProd, func(c *Config) { c.Server.PublicOrigin = "http://id.example.com" }, "https"},
		"issuer with path":               {validDev, func(c *Config) { c.Server.PublicOrigin = "http://localhost:8080/x" }, "public_origin"},
		"literal root key":               {validProd, func(c *Config) { c.Keys.RootKeys[0].Ref = "0123456789abcdef" }, "root_keys"},
		"no root keys":                   {validDev, func(c *Config) { c.Keys.RootKeys = nil }, "keys.root_keys is required"},
		"literal smtp password":          {validProd, func(c *Config) { c.Delivery.Email.SMTPPassword = "hunter2" }, "smtp_password"},
		"literal metrics token":          {validProd, func(c *Config) { c.Server.MetricsToken = "token" }, "metrics_token"},
		"database password in url":       {validProd, func(c *Config) { c.Storage.DatabaseURL = "postgres://u:pw@db/x" }, "database_url"},
		"dev sink in production":         {validProd, func(c *Config) { c.Delivery.Email.Adapter = "dev_sink" }, "dev_sink"},
		"sms dev sink in production":     {validProd, func(c *Config) { c.Delivery.SMS.Adapter = "dev_sink" }, "delivery.sms.adapter dev_sink"},
		"insecure cookies in production": {validProd, func(c *Config) { c.Sessions.CookieInsecureDev = true }, "cookie_insecure_dev"},
		"unknown smtp tls mode":          {validDev, func(c *Config) { c.Delivery.Email.SMTPTLS = "startls" }, "smtp_tls"},
		"zero argon time":                {validDev, func(c *Config) { c.Security.Password.ArgonTime = 0 }, "argon_time"},
		"zero argon threads":             {validDev, func(c *Config) { c.Security.Password.ArgonThreads = 0 }, "argon_time"},
		"zero poll interval":             {validDev, func(c *Config) { c.Workers.PollInterval = 0 }, "poll_interval"},
		"negative lease":                 {validDev, func(c *Config) { c.Workers.LeaseDuration = -time.Second }, "lease_duration"},
		"long clock skew":                {validDev, func(c *Config) { c.Tokens.ClockSkew = 2 * time.Minute }, "clock_skew"},
		"long impersonation":             {validDev, func(c *Config) { c.Impersonation.MaxTTL = time.Hour }, "impersonation.max_ttl"},
		"hmac signing":                   {validDev, func(c *Config) { c.Keys.SigningAlgorithm = "HS256" }, "signing_algorithm"},
		"telemetry":                      {validDev, func(c *Config) { c.Privacy.TelemetryOptIn = true }, "telemetry"},
		"bad proxy":                      {validDev, func(c *Config) { c.Server.TrustedProxies = []string{"not-an-ip"} }, "trusted_proxies"},
	}
	for name, tc := range cases {
		c := tc.base()
		tc.mutate(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error mentioning %q, got %v", name, tc.want, err)
		}
	}
}

// TestMigrationBounds covers OPS-008: migrations wait at most 5s for a lock
// and run each statement at most 10m unless configured otherwise; 0 (no
// limit) is accepted, negative values and values PostgreSQL cannot hold are
// refused.
func TestMigrationBounds(t *testing.T) {
	c := validDev()
	if c.Storage.MigrationLockTimeout != 5*time.Second || c.Storage.MigrationStatementTimeout != 10*time.Minute {
		t.Fatalf("defaults: %v %v", c.Storage.MigrationLockTimeout, c.Storage.MigrationStatementTimeout)
	}
	c.Storage.MigrationLockTimeout, c.Storage.MigrationStatementTimeout = 0, 0
	if err := c.Validate(); err != nil {
		t.Fatalf("0 (no limit) refused: %v", err)
	}
	for _, d := range []time.Duration{-time.Second, 25 * time.Hour} {
		c := validDev()
		c.Storage.MigrationLockTimeout = d
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "storage.migration_lock_timeout") {
			t.Errorf("migration_lock_timeout %v: %v", d, err)
		}
		c = validDev()
		c.Storage.MigrationStatementTimeout = d
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "storage.migration_statement_timeout") {
			t.Errorf("migration_statement_timeout %v: %v", d, err)
		}
	}
}

// TestRedactedHidesSecretValues covers OPS-010: the configuration summary in
// support bundles and config diffs carries no literal secret, including the
// schema owner's migration connection.
func TestRedactedHidesSecretValues(t *testing.T) {
	c := validDev()
	c.Delivery.Email.SMTPPassword = "literal-password"
	c.Storage.DatabaseURL = "postgres://u:pw@db/x"
	c.Storage.MigrationDatabaseURL = "postgres://owner:owner-pw@db/x"
	c.Delivery.Email.EventsSecret = "literal-events-secret"
	r := c.Redacted()
	if strings.Contains(r.Delivery.Email.SMTPPassword, "literal-password") || strings.Contains(r.Storage.DatabaseURL, "pw@") ||
		strings.Contains(r.Delivery.Email.EventsSecret, "literal-events-secret") {
		t.Fatalf("secrets leaked by Redacted: %+v", r.Delivery.Email)
	}
	if strings.Contains(r.Storage.MigrationDatabaseURL, "owner-pw") {
		t.Fatalf("migration database password leaked by Redacted: %q", r.Storage.MigrationDatabaseURL)
	}
	if c.Storage.MigrationDatabaseURL != "postgres://owner:owner-pw@db/x" {
		t.Fatal("redaction changed the live configuration")
	}
	ref := validDev()
	ref.Storage.MigrationDatabaseURL = "file:/run/secrets/migration_database_url"
	if got := ref.Redacted().Storage.MigrationDatabaseURL; got != "file:/run/secrets/migration_database_url" {
		t.Fatalf("a secret reference must stay visible: %q", got)
	}
}

// TestLimitRanges pins the safe operator ranges of the request limits
// (NFR-001): the defaults and both ends of each range are accepted, a value
// just outside is refused with a message naming the key and its range, and
// max_inflight_requests keeps 0 as "the default".
func TestLimitRanges(t *testing.T) {
	if base := validDev(); base.Validate() != nil {
		t.Fatalf("defaults: %v", base.Validate())
	}
	for _, c := range []struct {
		key      string
		set      func(*Config, int64)
		min, max int64
	}{
		{"max_body_bytes", func(c *Config, v int64) { c.Limits.MaxBodyBytes = v }, 256 << 10, 64 << 20},
		{"max_header_bytes", func(c *Config, v int64) { c.Limits.MaxHeaderBytes = int(v) }, 8 << 10, 1 << 20},
		{"max_token_bytes", func(c *Config, v int64) { c.Limits.MaxTokenBytes = int(v) }, 4 << 10, 64 << 10},
		{"max_json_depth", func(c *Config, v int64) { c.Limits.MaxJSONDepth = int(v) }, 32, 256},
		{"max_page_size", func(c *Config, v int64) { c.Limits.MaxPageSize = int(v); c.Limits.DefaultPageSize = 1 }, 1, 1000},
		{"max_group_depth", func(c *Config, v int64) { c.Limits.MaxGroupDepth = int(v) }, 1, 32},
		{"max_role_expansion", func(c *Config, v int64) { c.Limits.MaxRoleExpansion = int(v) }, 8, 1024},
		{"max_inflight_requests", func(c *Config, v int64) { c.Limits.MaxInflightRequests = int(v) }, 1, 100000},
	} {
		for _, v := range []int64{c.min, c.max} {
			cfg := validDev()
			c.set(&cfg, v)
			if err := cfg.Validate(); err != nil {
				t.Errorf("%s=%d refused: %v", c.key, v, err)
			}
		}
		for _, v := range []int64{c.min - 1, c.max + 1} {
			if c.key == "max_inflight_requests" && v == 0 {
				continue // 0 means the default
			}
			cfg := validDev()
			c.set(&cfg, v)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("limits.%s must be %d..%d", c.key, c.min, c.max)) {
				t.Errorf("%s=%d: %v", c.key, v, err)
			}
		}
	}
	cfg := validDev()
	cfg.Limits.MaxInflightRequests = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("max_inflight_requests=0 (default) refused: %v", err)
	}
}

// TestValidateRateLimits covers SEC-006 (ratelimiter-design-config): every
// rate_limits key refuses a negative value, which used to disable its budget
// silently; a positive limit refuses a zero window, which the limiter would
// skip; 0 still disables a budget, and the defaults validate. The negative
// cases walk the struct, so a new rate_limits key is covered without editing
// this test.
func TestValidateRateLimits(t *testing.T) {
	for name, c := range map[string]Config{"development": validDev(), "production": validProd()} {
		if err := c.Validate(); err != nil {
			t.Fatalf("%s defaults rejected: %v", name, err)
		}
	}
	typ := reflect.TypeOf(RateLimitConfig{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		key := strings.Split(f.Tag.Get("yaml"), ",")[0]
		c := validDev()
		v := reflect.ValueOf(&c.Security.RateLimits).Elem().Field(i)
		switch f.Type {
		case reflect.TypeOf(time.Duration(0)):
			v.SetInt(int64(-time.Second))
		case reflect.TypeOf(0):
			v.SetInt(-1)
		default:
			t.Fatalf("rate_limits.%s has type %s; extend this test", key, f.Type)
		}
		err := c.Validate()
		if want := "security.rate_limits." + key + " must not be negative"; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s=-1: want %q, got %v", key, want, err)
		}
	}
	windows := map[string]struct {
		set    func(*RateLimitConfig, time.Duration)
		limits []string
	}{
		"login_window": {func(r *RateLimitConfig, d time.Duration) { r.LoginWindow = d },
			[]string{"login_per_identifier", "login_per_ip", "login_per_realm", "login_per_client", "login_per_organization"}},
		"send_window": {func(r *RateLimitConfig, d time.Duration) { r.SendWindow = d },
			[]string{"send_per_identifier", "send_per_ip", "send_per_client", "send_per_organization", "send_per_realm"}},
		"otp_verify_window": {func(r *RateLimitConfig, d time.Duration) { r.OTPVerifyWindow = d }, []string{"otp_verify_per_account"}},
		"signup_window": {func(r *RateLimitConfig, d time.Duration) { r.SignupWindow = d },
			[]string{"signup_per_ip", "signup_per_client", "signup_per_realm"}},
		"token_window":   {func(r *RateLimitConfig, d time.Duration) { r.TokenWindow = d }, []string{"token_per_client", "organization_per_window"}},
		"temporary_lock": {func(r *RateLimitConfig, d time.Duration) { r.TemporaryLock = d }, []string{"failures_before_lock"}},
		"invitation_window": {func(r *RateLimitConfig, d time.Duration) { r.InvitationWindow = d },
			[]string{"invitations_per_organization", "invitations_per_recipient"}},
	}
	for window, w := range windows {
		c := validDev()
		w.set(&c.Security.RateLimits, 0)
		err := c.Validate()
		for _, l := range w.limits {
			want := "security.rate_limits." + l + " needs a positive security.rate_limits." + window
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s=0 with the default %s: want %q, got %v", window, l, want, err)
			}
		}
		// A zero window is fine once every budget it governs is disabled.
		c = validDev()
		w.set(&c.Security.RateLimits, 0)
		rv := reflect.ValueOf(&c.Security.RateLimits).Elem()
		for _, l := range w.limits {
			for i := range rv.NumField() {
				if strings.Split(rv.Type().Field(i).Tag.Get("yaml"), ",")[0] == l {
					rv.Field(i).SetInt(0)
				}
			}
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%s=0 with its budgets disabled refused: %v", window, err)
		}
	}
	// 0 disables: every key at 0 validates, send_cooldown included.
	c := validDev()
	c.Security.RateLimits = RateLimitConfig{}
	if err := c.Validate(); err != nil {
		t.Errorf("all rate limits disabled refused: %v", err)
	}
}
