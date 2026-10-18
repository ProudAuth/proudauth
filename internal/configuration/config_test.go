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
			[]string{"login_per_identifier", "login_per_ip", "login_per_realm", "login_per_client", "login_per_organization",
				"start_per_network", "known_login_per_network", "known_login_per_device", "known_login_per_identifier"}},
		"send_window": {func(r *RateLimitConfig, d time.Duration) { r.SendWindow = d },
			[]string{"send_per_identifier", "send_per_ip", "send_per_client", "send_per_organization", "send_per_realm"}},
		"otp_verify_window": {func(r *RateLimitConfig, d time.Duration) { r.OTPVerifyWindow = d }, []string{"otp_verify_per_account"}},
		"signup_window": {func(r *RateLimitConfig, d time.Duration) { r.SignupWindow = d },
			[]string{"signup_per_ip", "signup_per_client", "signup_per_realm"}},
		"token_window":   {func(r *RateLimitConfig, d time.Duration) { r.TokenWindow = d }, []string{"token_per_client", "organization_per_window"}},
		"temporary_lock": {func(r *RateLimitConfig, d time.Duration) { r.TemporaryLock = d }, []string{"failures_before_lock"}},
		"invitation_window": {func(r *RateLimitConfig, d time.Duration) { r.InvitationWindow = d },
			[]string{"invitations_per_organization", "invitations_per_recipient"}},
		"join_request_window": {func(r *RateLimitConfig, d time.Duration) { r.JoinRequestWindow = d },
			[]string{"join_requests_per_user", "join_requests_per_organization"}},
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

// TestNetworkBudgetConfig covers SEC-006 and ABU-001 (owner decision 9 of
// 0.2.0-alpha.6): the transaction-start budget defaults to 300 per network
// per login window, the wider /24 and /48 budgets to 10 times each
// per-network limit, and the known-device quota to facts of the last 30 days
// with 50 attempts per known network, 20 per remembered device and 10 per
// identifier per login window. The factor stops at 1000 and the days at
// 365; both refuse negative values and 0 turns each off.
func TestNetworkBudgetConfig(t *testing.T) {
	rl := Defaults().Security.RateLimits
	if rl.StartPerNetwork != 300 || rl.NetworkCoarseFactor != 10 || rl.KnownQuotaDays != 30 || rl.KnownLoginPerNetwork != 50 ||
		rl.KnownLoginPerDevice != 20 || rl.KnownLoginPerIdentifier != 10 {
		t.Fatalf("defaults: %+v", rl)
	}
	for _, c := range []struct {
		set  func(*RateLimitConfig)
		want string
	}{
		{func(r *RateLimitConfig) { r.NetworkCoarseFactor = MaxNetworkCoarseFactor + 1 }, "security.rate_limits.network_coarse_factor must be at most 1000"},
		{func(r *RateLimitConfig) { r.KnownQuotaDays = MaxKnownQuotaDays + 1 }, "security.rate_limits.known_quota_days must be at most 365"},
	} {
		cfg := validDev()
		c.set(&cfg.Security.RateLimits)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
	cfg := validDev()
	cfg.Security.RateLimits.NetworkCoarseFactor, cfg.Security.RateLimits.KnownQuotaDays = MaxNetworkCoarseFactor, MaxKnownQuotaDays
	if err := cfg.Validate(); err != nil {
		t.Errorf("maximum factor and days refused: %v", err)
	}
	cfg.Security.RateLimits.NetworkCoarseFactor, cfg.Security.RateLimits.KnownQuotaDays = 0, 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("factor and days 0 (off) refused: %v", err)
	}
}

// TestSecondFactorCeilingConfig covers SEC-006 and MFA-002 (owner decision 10
// of 0.2.0-alpha.6): the code-factor failure ceiling defaults to a backoff
// after 10 failures capped at an hour, a notice at 20 and code factors off at
// 100; 0 turns each threshold off; negative values, a backoff without a cap of
// at least the first delay, a cap above a day and a notice at or after the
// disable are refused. The delay starts at 2 s, doubles per failure and stops
// at the cap, so it never locks an account out for longer than the cap.
func TestSecondFactorCeilingConfig(t *testing.T) {
	d := Defaults().Security.SecondFactor
	if d != (SecondFactorConfig{FailureBackoffAfter: 10, FailureBackoffMax: time.Hour, FailureNoticeAt: 20, FailureDisableAt: 100}) {
		t.Fatalf("defaults: %+v", d)
	}
	for n, want := range map[int]time.Duration{0: 0, 9: 0, 10: 2 * time.Second, 11: 4 * time.Second, 12: 8 * time.Second,
		20: 2048 * time.Second, 21: time.Hour, 99: time.Hour, 1 << 20: time.Hour} {
		if got := d.BackoffDelay(n); got != want {
			t.Errorf("delay after %d failures: %s, want %s", n, got, want)
		}
	}
	if d.CodeFactorsDisabled(99) || !d.CodeFactorsDisabled(100) || !d.CodeFactorsDisabled(150) {
		t.Error("code factors must be off from failure_disable_at on")
	}
	off := SecondFactorConfig{}
	if off.BackoffDelay(1000) != 0 || off.CodeFactorsDisabled(1000) {
		t.Error("0 must turn the backoff and the disable off")
	}
	c := validDev()
	c.Security.SecondFactor = off
	if err := c.Validate(); err != nil {
		t.Fatalf("every threshold at 0 refused: %v", err)
	}
	for name, tc := range map[string]struct {
		set  func(*SecondFactorConfig)
		want string
	}{
		"negative backoff":    {func(s *SecondFactorConfig) { s.FailureBackoffAfter = -1 }, "failure_backoff_after must not be negative"},
		"negative notice":     {func(s *SecondFactorConfig) { s.FailureNoticeAt = -1 }, "failure_notice_at must not be negative"},
		"negative disable":    {func(s *SecondFactorConfig) { s.FailureDisableAt = -1 }, "failure_disable_at must not be negative"},
		"negative cap":        {func(s *SecondFactorConfig) { s.FailureBackoffMax = -time.Second }, "failure_backoff_max must not be negative"},
		"cap above a day":     {func(s *SecondFactorConfig) { s.FailureBackoffMax = 25 * time.Hour }, "failure_backoff_max must be at most 24h"},
		"backoff without cap": {func(s *SecondFactorConfig) { s.FailureBackoffMax = 0 }, "failure_backoff_max of at least 2s"},
		"notice at disable":   {func(s *SecondFactorConfig) { s.FailureNoticeAt = 100 }, "failure_notice_at must be below failure_disable_at"},
	} {
		c := validDev()
		tc.set(&c.Security.SecondFactor)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "security.second_factor."+tc.want) && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
	// A notice without a disable, and a disable without a notice, are fine.
	for _, s := range []SecondFactorConfig{{FailureNoticeAt: 20}, {FailureDisableAt: 5}, {FailureBackoffAfter: 3, FailureBackoffMax: 2 * time.Second}} {
		c := validDev()
		c.Security.SecondFactor = s
		if err := c.Validate(); err != nil {
			t.Errorf("%+v refused: %v", s, err)
		}
	}
}
