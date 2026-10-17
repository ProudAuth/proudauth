// Package configuration loads, validates and documents deployment configuration.
//
// Security URLs (issuer, public origin) come only from this trusted configuration,
// never from request Host or forwarded headers (TOK-022, DEP-005). Secrets are read
// from secret references ("file:/path", "env:NAME") so they stay out of images and
// ordinary config exports (DEP-006). Invalid security settings prevent readiness
// rather than falling back to guessed values (§30.2).
package configuration

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/proudauth/proudauth/internal/egress"
)

// Mode is the deployment mode. Production rejects development shortcuts (QA-007).
type Mode string

const (
	ModeProduction  Mode = "production"
	ModeDevelopment Mode = "development"
)

// Config is the complete deployment configuration.
type Config struct {
	Mode          Mode                `yaml:"mode"`
	Server        ServerConfig        `yaml:"server"`
	Identity      IdentityConfig      `yaml:"identity"`
	Storage       StorageConfig       `yaml:"storage"`
	Keys          KeysConfig          `yaml:"keys"`
	Sessions      SessionsConfig      `yaml:"sessions"`
	Tokens        TokensConfig        `yaml:"tokens"`
	Security      SecurityConfig      `yaml:"security"`
	Impersonation ImpersonationConfig `yaml:"impersonation"`
	Federation    FederationConfig    `yaml:"federation"`
	SAML          SAMLConfig          `yaml:"saml"`
	Directory     DirectoryConfig     `yaml:"directory"`
	Delivery      DeliveryConfig      `yaml:"delivery"`
	Workers       WorkersConfig       `yaml:"workers"`
	Observability ObservabilityConfig `yaml:"observability"`
	Privacy       PrivacyConfig       `yaml:"privacy"`
	Limits        LimitsConfig        `yaml:"limits"`
	// Extensions holds the trusted plugin publisher keys (EXT-014).
	Extensions ExtensionsConfig `yaml:"extensions"`
	// WebAuthn holds passkey trust settings: FIDO metadata and related
	// origins (PASS-009, PASS-010).
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
}

type ServerConfig struct {
	PublicListen   string `yaml:"public_listen"`
	InternalListen string `yaml:"internal_listen"` // metrics + operator status; bind to a private interface
	PublicOrigin   string `yaml:"public_origin"`
	// HostPolicy "strict" serves requests only on the public origin's host
	// and on verified realm custom domains (each limited to its realm), and
	// answers 421 otherwise; "any" (default) does not check Host (DEP-014).
	HostPolicy       string        `yaml:"host_policy"`
	TrustedProxies   []string      `yaml:"trusted_proxies"`
	ShutdownDeadline time.Duration `yaml:"shutdown_deadline"`
	// DrainDelay is how long readiness reports draining before listeners stop
	// accepting connections, so load balancers deregister the node first.
	DrainDelay   time.Duration `yaml:"drain_delay"`
	TLSCertFile  string        `yaml:"tls_cert_file"`
	TLSKeyFile   string        `yaml:"tls_key_file"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	MetricsToken string        `yaml:"metrics_token"` // secret ref; optional bearer for /metrics
	// MTLSListen, when set, is a second TLS listener (same certificate) that
	// asks clients for a certificate, for mutual-TLS client authentication
	// and certificate-bound tokens (TOK-019, MCH-014, RFC 8705). Browsers use
	// the public listener, which never asks.
	MTLSListen string `yaml:"mtls_listen"`
	// MTLSOrigin is the public origin of that listener, advertised as
	// mtls_endpoint_aliases.
	MTLSOrigin string `yaml:"mtls_origin"`
	// ClientCertHeader names the header in which a TLS-terminating proxy
	// listed in trusted_proxies forwards the client certificate (URL-escaped
	// PEM). It is ignored from any other peer.
	ClientCertHeader string `yaml:"client_cert_header"`
}

type IdentityConfig struct {
	DefaultRealm string `yaml:"default_realm"`
}

type StorageConfig struct {
	DatabaseURL string `yaml:"database_url"` // secret ref
	// MigrationDatabaseURL, when set, is used for migrations instead of
	// database_url: a schema-owner role separate from the runtime role
	// (OPS-013). Secret reference in production.
	MigrationDatabaseURL string `yaml:"migration_database_url"`
	// RuntimeRole, when set, is granted data privileges (no DDL) after each
	// migration run.
	RuntimeRole      string        `yaml:"runtime_role"`
	MaxConns         int32         `yaml:"max_conns"`
	MinConns         int32         `yaml:"min_conns"`
	MigrateOnStart   bool          `yaml:"migrate_on_start"`
	StatementTimeout time.Duration `yaml:"statement_timeout"`
}

type KeyRef struct {
	Version uint32 `yaml:"version"`
	Ref     string `yaml:"ref"` // secret ref to 32 random bytes (hex or base64)
}

type KeysConfig struct {
	RootKeys         []KeyRef      `yaml:"root_keys"`
	ActiveVersion    uint32        `yaml:"active_version"`
	PepperKeys       []KeyRef      `yaml:"pepper_keys"`
	SigningWrapKeys  []KeyRef      `yaml:"signing_wrap_keys"`
	SigningAlgorithm string        `yaml:"signing_algorithm"`
	RotationInterval time.Duration `yaml:"rotation_interval"`
	PrepublishPeriod time.Duration `yaml:"prepublish_period"`
	RetirementPeriod time.Duration `yaml:"retirement_period"`
	// KMS unwraps kms: key references at startup (DEP-016).
	KMS KMSConfig `yaml:"kms"`
}

type SessionsConfig struct {
	IdleTimeout        time.Duration `yaml:"idle_timeout"`
	AbsoluteTimeout    time.Duration `yaml:"absolute_timeout"`
	RememberMeIdle     time.Duration `yaml:"remember_me_idle"`
	RememberMeAbsolute time.Duration `yaml:"remember_me_absolute"`
	OfflineIdle        time.Duration `yaml:"offline_idle"`
	OfflineAbsolute    time.Duration `yaml:"offline_absolute"`
	MaxConcurrent      int           `yaml:"max_concurrent"`
	CookieSameSite     string        `yaml:"cookie_same_site"`
	CookieInsecureDev  bool          `yaml:"cookie_insecure_dev"`
}

type TokensConfig struct {
	AccessTokenTTL        time.Duration `yaml:"access_token_ttl"`
	MaxAccessTokenTTL     time.Duration `yaml:"max_access_token_ttl"`
	IDTokenTTL            time.Duration `yaml:"id_token_ttl"`
	AuthorizationCodeTTL  time.Duration `yaml:"authorization_code_ttl"`
	TransactionTTL        time.Duration `yaml:"transaction_ttl"`
	ChallengeTTL          time.Duration `yaml:"challenge_ttl"`
	InvitationTTL         time.Duration `yaml:"invitation_ttl"`
	ClockSkew             time.Duration `yaml:"clock_skew"`
	DeviceCodeTTL         time.Duration `yaml:"device_code_ttl"`
	ExchangeMaxChainDepth int           `yaml:"exchange_max_chain_depth"`
}

type PasswordConfig struct {
	MinLength      int    `yaml:"min_length"`
	MaxLength      int    `yaml:"max_length"`
	MaxBytes       int    `yaml:"max_bytes"`
	ArgonTime      uint32 `yaml:"argon_time"`
	ArgonMemoryKiB uint32 `yaml:"argon_memory_kib"`
	ArgonThreads   uint8  `yaml:"argon_threads"`
	BlocklistFile  string `yaml:"blocklist_file"`
	HistoryCount   int    `yaml:"history_count"`
	// MaxConcurrentHashes bounds the Argon2id password checks and hashes one
	// process runs at once; a full bound answers 503 unavailable at once
	// instead of queueing (NFR-002). 0 (the default): unbounded. Today the
	// password step hashes inside its database transaction, so the
	// transaction slots already bound it; the knob matters once hashing
	// leaves the transaction.
	MaxConcurrentHashes int `yaml:"max_concurrent_hashes"`
	// LegacyHashesUntil ends a controlled migration (CRED-004): after this
	// date (YYYY-MM-DD, UTC) imported legacy verifiers no longer verify or
	// import, and affected accounts recover their password. Empty: allowed.
	LegacyHashesUntil string `yaml:"legacy_hashes_until"`
}

// HashSlots is the bound on concurrent password hashing,
// security.password.max_concurrent_hashes; 0 is unbounded.
func (p PasswordConfig) HashSlots() int { return p.MaxConcurrentHashes }

// LegacyHashDeadline parses security.password.legacy_hashes_until (zero when unset).
func (p PasswordConfig) LegacyHashDeadline() time.Time {
	t, err := time.Parse("2006-01-02", p.LegacyHashesUntil)
	if err != nil {
		return time.Time{}
	}
	return t.Add(24 * time.Hour)
}

type RateLimitConfig struct {
	LoginPerIdentifier    int           `yaml:"login_per_identifier"`
	LoginPerIP            int           `yaml:"login_per_ip"`
	LoginWindow           time.Duration `yaml:"login_window"`
	SendPerIdentifier     int           `yaml:"send_per_identifier"`
	SendPerIP             int           `yaml:"send_per_ip"`
	SendWindow            time.Duration `yaml:"send_window"`
	SendCooldown          time.Duration `yaml:"send_cooldown"`
	OTPVerifyPerAccount   int           `yaml:"otp_verify_per_account"`
	OTPVerifyWindow       time.Duration `yaml:"otp_verify_window"`
	SignupPerIP           int           `yaml:"signup_per_ip"`
	SignupWindow          time.Duration `yaml:"signup_window"`
	TokenPerClient        int           `yaml:"token_per_client"`
	TokenWindow           time.Duration `yaml:"token_window"`
	OrganizationPerWindow int           `yaml:"organization_per_window"`
	TemporaryLock         time.Duration `yaml:"temporary_lock"`
	FailuresBeforeLock    int           `yaml:"failures_before_lock"`
	// Aggregate budgets (SEC-006, REG-012): per client, per organization and
	// realm-wide, so one integration or tenant cannot exhaust shared capacity.
	SignupPerClient     int `yaml:"signup_per_client"`
	SignupPerRealm      int `yaml:"signup_per_realm"`
	SendPerClient       int `yaml:"send_per_client"`
	SendPerOrganization int `yaml:"send_per_organization"`
	SendPerRealm        int `yaml:"send_per_realm"`
	LoginPerRealm       int `yaml:"login_per_realm"`
	// LoginPerClient bounds sign-in proof attempts made through one client
	// per login window (REG-012).
	LoginPerClient int `yaml:"login_per_client"`
	// Tenant fairness (TEN-018): password sign-in attempts per organization
	// per window (token issuance per organization is organization_per_window).
	LoginPerOrganization int `yaml:"login_per_organization"`
	// Invitation budgets (INV-009): aggregate per organization and per
	// recipient address; revoking and re-creating never resets them.
	InvitationsPerOrganization int           `yaml:"invitations_per_organization"`
	InvitationsPerRecipient    int           `yaml:"invitations_per_recipient"`
	InvitationWindow           time.Duration `yaml:"invitation_window"`
}

// MFAFloor is the operator's MFA safety floor (MFA-005): realm policies can
// be stricter but never lower it.
type MFAFloor struct {
	// Require is "none" (default), or "all": every account needs MFA.
	Require string `yaml:"require"`
	// AdminPhishingResistant forces phishing-resistant MFA for privileged
	// and protected accounts in every realm. It fails closed: realm policies
	// that leave passkeys disabled are refused (realm.CheckMFAFloor), and a
	// production server without passkeys does not start with it.
	AdminPhishingResistant bool `yaml:"admin_phishing_resistant"`
	// ForbidOrgAdminWaiver forbids realms from waiving MFA for organization
	// administration (mfa.org_admin_mfa_optional).
	ForbidOrgAdminWaiver bool `yaml:"forbid_org_admin_waiver"`
}

type SecurityConfig struct {
	MFAFloor          MFAFloor       `yaml:"mfa_floor"`
	Password          PasswordConfig `yaml:"password"`
	OTPLength         int            `yaml:"otp_length"`
	OTPMaxAttempts    int            `yaml:"otp_max_attempts"`
	TOTPSkewSteps     int            `yaml:"totp_skew_steps"`
	RecoveryCodeCount int            `yaml:"recovery_code_count"`
	RecentAuthWindow  time.Duration  `yaml:"recent_auth_window"`
	// DynamicGroupMaxStaleness bounds how old a dynamic group's last
	// recomputation may be before its rule-derived memberships stop granting
	// roles (AZ-010, TEN-014). Default 1h.
	DynamicGroupMaxStaleness time.Duration `yaml:"dynamic_group_max_staleness"`
	// DecisionCacheTTL bounds how long callers may cache a pure RBAC
	// authorization decision under its cache key (AZ-019); 0 disables caching.
	DecisionCacheTTL  time.Duration   `yaml:"decision_cache_ttl"`
	AdminMFAMaxAge    time.Duration   `yaml:"admin_mfa_max_age"`
	AllowedAlgorithms []string        `yaml:"allowed_algorithms"`
	RateLimits        RateLimitConfig `yaml:"rate_limits"`
	MinAuthResponse   time.Duration   `yaml:"min_auth_response"`
	// ChallengeProviders are optional bot and abuse challenge services that
	// realm authentication flows may require (SEC-014). None is built in or
	// contacted unless configured here and named by a realm.
	ChallengeProviders []ChallengeProviderConfig `yaml:"challenge_providers"`
	// PolicyEngines are external policy decision points a realm may delegate
	// authorization decisions to (AZ-026). Their endpoints and credentials
	// belong to the operator; realms only name one.
	PolicyEngines []PolicyEngineConfig `yaml:"policy_engines"`
}

// PolicyEngineConfig is an external policy engine called with an
// authenticated JSON POST: {"input": {...}} in, {"allowed": bool, ...} or an
// OPA-style {"result": ...} out.
type PolicyEngineConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// Token is sent as a bearer credential; a secret reference in production.
	Token   string        `yaml:"token"`
	Timeout time.Duration `yaml:"timeout"`
}

// ChallengeProviderConfig is a challenge service with a siteverify-style API:
// the server posts secret and response (and, only when SendRemoteIP is set,
// remoteip) as a form to VerifyURL and expects JSON {"success": true}.
type ChallengeProviderConfig struct {
	Name         string        `yaml:"name"`
	VerifyURL    string        `yaml:"verify_url"`
	SiteKey      string        `yaml:"site_key"`
	Secret       string        `yaml:"secret"`
	SendRemoteIP bool          `yaml:"send_remote_ip"`
	Timeout      time.Duration `yaml:"timeout"`
}

type ImpersonationConfig struct {
	Enabled         bool          `yaml:"enabled"`
	MaxTTL          time.Duration `yaml:"max_ttl"`
	RequireTicket   bool          `yaml:"require_ticket"`
	HandoffTTL      time.Duration `yaml:"handoff_ttl"`
	MinReasonLength int           `yaml:"min_reason_length"`
}

type FederationConfig struct {
	Enabled             bool `yaml:"enabled"`
	AllowPrivateNetwork bool `yaml:"allow_private_network"`
	// CAFile adds a PEM bundle of trusted roots for upstream providers that use a
	// private CA (in addition to the system roots).
	CAFile string `yaml:"ca_file"`
	// EgressAllowlist permits specific private ranges (e.g. an internal
	// enterprise IdP) without opening all private address space; it is the
	// production alternative to allow_private_network (FED-017, EXT-007).
	EgressAllowlist  []string      `yaml:"egress_allowlist"`
	FetchTimeout     time.Duration `yaml:"fetch_timeout"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
}

// SAMLConfig controls the SAML 2.0 identity provider (APP-018) and broker
// (FED-014) profiles. Both are off unless enabled; the broker also needs
// federation.enabled.
type SAMLConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxMessageBytes bounds a decoded (and inflated) SAML message and
	// uploaded metadata (SAML-004).
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxClockSkew is the largest clock skew a SAML application or connection
	// may configure (SAML-003).
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`
	// KeyPrepublish is how long a next SAML signing key must be published in
	// metadata before it may be activated without force (SAML-002).
	KeyPrepublish time.Duration `yaml:"key_prepublish"`
	// RetiredKeyPublication is how long a replaced signing key stays in
	// metadata after activation of its successor.
	RetiredKeyPublication time.Duration `yaml:"retired_key_publication"`
}

// DirectoryConfig configures LDAP/Active Directory federation and
// synchronization and outbound SCIM provisioning (PROV-010..PROV-014).
// Connectors themselves are realm or organization data managed through the
// API; these are deployment-wide bounds.
type DirectoryConfig struct {
	// Enabled turns the directory integration module on.
	Enabled bool `yaml:"enabled"`
	// AllowPrivateNetwork lets directory connections reach private and
	// loopback addresses (development only); production uses
	// EgressAllowlist for the directory networks.
	AllowPrivateNetwork bool     `yaml:"allow_private_network"`
	EgressAllowlist     []string `yaml:"egress_allowlist"`
	// CAFile adds trusted roots for directory TLS (LDAPS and StartTLS).
	CAFile           string        `yaml:"ca_file"`
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`
	OperationTimeout time.Duration `yaml:"operation_timeout"`
	// SignInTimeout bounds the directory work of one sign-in attempt (search
	// and bind, across every endpoint and connector it tries), so it ends
	// well before the 30 s request deadline. 0: 8 s.
	SignInTimeout time.Duration `yaml:"sign_in_timeout"`
	// MaxConcurrentBinds bounds the sign-in directory operations one process
	// runs at once; a full bound answers 503 unavailable at once
	// instead of queueing. 0: half the storage transaction slots.
	MaxConcurrentBinds int `yaml:"max_concurrent_binds"`
	// MaxEntriesPerRun bounds the entries one synchronization or
	// reconciliation run processes; connectors may set a lower bound.
	MaxEntriesPerRun int `yaml:"max_entries_per_run"`
}

type EmailConfig struct {
	Adapter      string `yaml:"adapter"` // smtp | dev_sink
	SMTPHost     string `yaml:"smtp_host"`
	SMTPPort     int    `yaml:"smtp_port"`
	SMTPUsername string `yaml:"smtp_username"`
	SMTPPassword string `yaml:"smtp_password"` // secret ref
	SMTPTLS      string `yaml:"smtp_tls"`      // starttls | implicit | none (none only in development)
	From         string `yaml:"from"`
	FromName     string `yaml:"from_name"`
	// EventsSecret (secret ref) authenticates provider bounce/complaint
	// callbacks (MSG-007); the callback endpoint is disabled without it.
	EventsSecret string `yaml:"events_secret"`
	// AllowedSenderDomains bounds realm-level sender addresses (MSG-005);
	// organization senders must use a verified organization domain.
	AllowedSenderDomains []string `yaml:"allowed_sender_domains"`
}

type SMSConfig struct {
	Adapter          string   `yaml:"adapter"` // none | dev_sink | webhook
	AllowedCountries []string `yaml:"allowed_countries"`
	WebhookURL       string   `yaml:"webhook_url"`
	// WebhookSecret signs gateway requests (secret reference).
	WebhookSecret string `yaml:"webhook_secret"`
	// DailyBudget caps SMS messages per 24 hours across the deployment (cost
	// ceiling); 0 disables the cap.
	DailyBudget int `yaml:"daily_budget"`
}

type DeliveryConfig struct {
	Email                EmailConfig   `yaml:"email"`
	SMS                  SMSConfig     `yaml:"sms"`
	PayloadRetention     time.Duration `yaml:"payload_retention"`
	WebhookTimeout       time.Duration `yaml:"webhook_timeout"`
	WebhookMaxAttempts   int           `yaml:"webhook_max_attempts"`
	AllowPrivateWebhooks bool          `yaml:"allow_private_webhooks"`
	EgressAllowlist      []string      `yaml:"egress_allowlist"`
}

type WorkersConfig struct {
	Concurrency    int           `yaml:"concurrency"`
	LeaseDuration  time.Duration `yaml:"lease_duration"`
	PollInterval   time.Duration `yaml:"poll_interval"`
	MaxAttempts    int           `yaml:"max_attempts"`
	BatchSize      int           `yaml:"batch_size"`
	AuditSealEvery time.Duration `yaml:"audit_seal_every"`
	// TenantBatchShare caps how many notifications or webhook deliveries of one
	// organization (or one webhook subscription) a worker claims per batch,
	// and MaxJobsPerOrganization how many of its jobs run at once, so one
	// tenant's backlog never starves the others (TEN-018).
	TenantBatchShare       int `yaml:"tenant_batch_share"`
	MaxJobsPerOrganization int `yaml:"max_jobs_per_organization"`
	// DrainTimeout bounds how long in-flight work may continue after a
	// shutdown signal before it is cancelled (OPS-012).
	DrainTimeout time.Duration `yaml:"drain_timeout"`
	// MetricsListen exposes the worker's /metrics, /status and /health/live on
	// a private address (empty: disabled).
	MetricsListen string `yaml:"metrics_listen"`
}

type ObservabilityConfig struct {
	LogLevel       string        `yaml:"log_level"`
	LogFormat      string        `yaml:"log_format"`
	MetricsEnabled bool          `yaml:"metrics_enabled"`
	TraceSampling  float64       `yaml:"trace_sampling"`
	MaxClockSkew   time.Duration `yaml:"max_clock_skew"`
	// OTLPEndpoint, when set, receives sampled spans as OTLP/HTTP JSON, for
	// example http://otel-collector:4318/v1/traces (OPS-003).
	OTLPEndpoint string `yaml:"otlp_endpoint"`
}

type PrivacyConfig struct {
	TelemetryOptIn bool          `yaml:"telemetry_opt_in"`
	AuditRetention time.Duration `yaml:"audit_retention"`
	// AuditRetentionByCategory overrides audit_retention per audit category
	// (AUD-009), e.g. a shorter period for data_access evidence. Emergency
	// events are never pruned.
	AuditRetentionByCategory map[string]time.Duration `yaml:"audit_retention_by_category"`
	SessionRetention         time.Duration            `yaml:"session_retention"`
	// HistoryRetention bounds operational history (PRV-004): revoked
	// consents, ended invitations and finished notification, webhook and
	// back-channel logout deliveries are deleted after it.
	HistoryRetention time.Duration `yaml:"history_retention"`
	// AuditArchiveDir, when set, receives every sealed audit batch as a
	// write-once file (AUD-008); mount storage the operator controls
	// independently there, ideally with retention locks.
	AuditArchiveDir     string        `yaml:"audit_archive_dir"`
	ExportRetention     time.Duration `yaml:"export_retention"`
	DeletionGracePeriod time.Duration `yaml:"deletion_grace_period"`
	StoreFullIP         bool          `yaml:"store_full_ip"`
	// BackupRetention is how long the operator keeps database backups; it
	// dates when a deletion leaves the last backup (PRV-005). Informational:
	// ProudAuth does not manage backups.
	BackupRetention time.Duration `yaml:"backup_retention"`
	// Residency is the operator's data residency policy (PRV-003).
	Residency ResidencyConfig `yaml:"residency"`
}

// ResidencyConfig keeps outbound connector destinations within operator-chosen
// hosts (PRV-003): webhooks, hooks, federation providers, challenge providers
// and organization mail servers. Region labels the deployment for operators
// and is reported by /status; where the database, backups and logs live is
// decided by the deployment, which ProudAuth cannot observe.
type ResidencyConfig struct {
	Region string `yaml:"region"`
	// AllowedDestinations are host names, or ".suffix" entries matching any
	// host under a domain; empty allows any host the egress policy allows.
	AllowedDestinations []string `yaml:"allowed_destinations"`
}

type LimitsConfig struct {
	MaxBodyBytes        int64 `yaml:"max_body_bytes"`
	MaxHeaderBytes      int   `yaml:"max_header_bytes"`
	MaxTokenBytes       int   `yaml:"max_token_bytes"`
	MaxJSONDepth        int   `yaml:"max_json_depth"`
	MaxPageSize         int   `yaml:"max_page_size"`
	DefaultPageSize     int   `yaml:"default_page_size"`
	MaxBatchSize        int   `yaml:"max_batch_size"`
	MaxGroupDepth       int   `yaml:"max_group_depth"`
	MaxRoleExpansion    int   `yaml:"max_role_expansion"`
	MaxInflightRequests int   `yaml:"max_inflight_requests"`
	// Safety limits that were fixed before (OSS-007).
	InvitationResends       int           `yaml:"invitation_resends"`
	SharedInvitationMaxUses int           `yaml:"shared_invitation_max_uses"`
	SharedInvitationMaxTTL  time.Duration `yaml:"shared_invitation_max_ttl"`
	ClientSecretsMax        int           `yaml:"client_secrets_max"`
	MetadataBytes           int           `yaml:"metadata_bytes"`
}

// Defaults returns the documented product defaults (§14.5).
func Defaults() Config {
	return Config{
		Mode: ModeProduction,
		Server: ServerConfig{
			PublicListen:     ":8080",
			InternalListen:   "127.0.0.1:9090",
			ShutdownDeadline: 20 * time.Second, DrainDelay: 5 * time.Second,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Identity: IdentityConfig{DefaultRealm: "main"},
		Storage:  StorageConfig{MaxConns: 20, MinConns: 2, StatementTimeout: 10 * time.Second},
		Keys: KeysConfig{
			ActiveVersion:    1,
			SigningAlgorithm: "RS256",
			RotationInterval: 90 * 24 * time.Hour,
			PrepublishPeriod: 48 * time.Hour,
			RetirementPeriod: 7 * 24 * time.Hour,
		},
		Sessions: SessionsConfig{
			IdleTimeout:        30 * time.Minute,
			AbsoluteTimeout:    12 * time.Hour,
			RememberMeIdle:     7 * 24 * time.Hour,
			RememberMeAbsolute: 30 * 24 * time.Hour,
			OfflineIdle:        7 * 24 * time.Hour,
			OfflineAbsolute:    30 * 24 * time.Hour,
			MaxConcurrent:      50,
			CookieSameSite:     "lax",
		},
		Tokens: TokensConfig{
			AccessTokenTTL:        5 * time.Minute,
			MaxAccessTokenTTL:     60 * time.Minute,
			IDTokenTTL:            5 * time.Minute,
			AuthorizationCodeTTL:  60 * time.Second,
			TransactionTTL:        10 * time.Minute,
			ChallengeTTL:          10 * time.Minute,
			InvitationTTL:         72 * time.Hour,
			ClockSkew:             60 * time.Second,
			DeviceCodeTTL:         10 * time.Minute,
			ExchangeMaxChainDepth: 2,
		},
		Security: SecurityConfig{
			Password: PasswordConfig{
				MinLength: 15, MaxLength: 128, MaxBytes: 1024,
				ArgonTime: 3, ArgonMemoryKiB: 64 * 1024, ArgonThreads: 2,
				HistoryCount: 0,
			},
			OTPLength:         6,
			OTPMaxAttempts:    5,
			TOTPSkewSteps:     1,
			RecoveryCodeCount: 10,
			RecentAuthWindow:  10 * time.Minute,
			DecisionCacheTTL:  30 * time.Second,
			AdminMFAMaxAge:    5 * time.Minute,
			AllowedAlgorithms: []string{"RS256", "ES256", "PS256", "EdDSA"},
			MinAuthResponse:   250 * time.Millisecond,
			RateLimits: RateLimitConfig{
				LoginPerIdentifier: 10, LoginPerIP: 100, LoginWindow: 15 * time.Minute,
				SendPerIdentifier: 5, SendPerIP: 50, SendWindow: time.Hour, SendCooldown: 30 * time.Second,
				OTPVerifyPerAccount: 10, OTPVerifyWindow: 15 * time.Minute,
				SignupPerIP: 20, SignupWindow: time.Hour,
				TokenPerClient: 600, TokenWindow: time.Minute,
				OrganizationPerWindow: 2000,
				TemporaryLock:         15 * time.Minute, FailuresBeforeLock: 10,
				SignupPerClient: 500, SignupPerRealm: 2000,
				SendPerClient: 1000, SendPerOrganization: 500, SendPerRealm: 5000,
				LoginPerRealm:              50000,
				LoginPerClient:             20000,
				LoginPerOrganization:       10000,
				InvitationsPerOrganization: 500, InvitationsPerRecipient: 10, InvitationWindow: 24 * time.Hour,
			},
		},
		Impersonation: ImpersonationConfig{
			Enabled: false, MaxTTL: 5 * time.Minute, RequireTicket: false,
			HandoffTTL: 30 * time.Second, MinReasonLength: 10,
		},
		Federation: FederationConfig{Enabled: true, FetchTimeout: 10 * time.Second, MaxResponseBytes: 1 << 20},
		Directory: DirectoryConfig{Enabled: true, ConnectTimeout: 5 * time.Second, OperationTimeout: 10 * time.Second,
			SignInTimeout: 8 * time.Second, MaxEntriesPerRun: 100000},
		SAML: SAMLConfig{MaxMessageBytes: 256 << 10, MaxClockSkew: 5 * time.Minute, KeyPrepublish: 48 * time.Hour,
			RetiredKeyPublication: 7 * 24 * time.Hour},
		Delivery: DeliveryConfig{
			Email:              EmailConfig{Adapter: "smtp", SMTPPort: 587, SMTPTLS: "starttls", FromName: "ProudAuth"},
			SMS:                SMSConfig{Adapter: "none", DailyBudget: 1000},
			PayloadRetention:   24 * time.Hour,
			WebhookTimeout:     10 * time.Second,
			WebhookMaxAttempts: 12,
		},
		Workers: WorkersConfig{
			Concurrency: 4, LeaseDuration: 60 * time.Second, PollInterval: time.Second,
			MaxAttempts: 8, BatchSize: 100, AuditSealEvery: 30 * time.Second, DrainTimeout: 20 * time.Second,
			TenantBatchShare: 25, MaxJobsPerOrganization: 2,
		},
		Observability: ObservabilityConfig{LogLevel: "info", LogFormat: "json", MetricsEnabled: true, MaxClockSkew: 2 * time.Second},
		Privacy: PrivacyConfig{
			AuditRetention: 400 * 24 * time.Hour, SessionRetention: 30 * 24 * time.Hour, HistoryRetention: 180 * 24 * time.Hour,
			ExportRetention: 24 * time.Hour, DeletionGracePeriod: 14 * 24 * time.Hour,
		},
		Limits: LimitsConfig{
			MaxBodyBytes: 256 << 10, MaxHeaderBytes: 16 << 10, MaxTokenBytes: 8 << 10, MaxJSONDepth: 32,
			MaxPageSize: 200, DefaultPageSize: 50, MaxBatchSize: 100, MaxGroupDepth: 8, MaxRoleExpansion: 64,
			MaxInflightRequests: 2000,
			InvitationResends:   5, SharedInvitationMaxUses: 100, SharedInvitationMaxTTL: 72 * time.Hour, ClientSecretsMax: 3, MetadataBytes: 16 << 10,
		},
	}
}

// Load reads YAML from path (optional) and applies PROUDAUTH_* environment overrides.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true) // reject unknown keys instead of silently ignoring typos
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("parse config: %w", err)
		}
	}
	if err := applyEnv(&cfg); err != nil {
		return cfg, fmt.Errorf("environment: %w", err)
	}
	ConfigureKMS(cfg.Keys.KMS)
	return cfg, nil
}

// applyEnv applies environment overrides. A malformed value is an error, never
// a silent zero: a typo must not quietly disable a protection (DEP-020).
func applyEnv(c *Config) error {
	var errs []error
	str := func(name string, dst *string) {
		if v := os.Getenv(name); v != "" {
			*dst = v
		}
	}
	boolean := func(name string, dst ...*bool) {
		if v := os.Getenv(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: not a boolean", name))
				return
			}
			for _, d := range dst {
				*d = b
			}
		}
	}
	// A secret given directly in a variable becomes the reference env:<name>:
	// the value stays in the process environment only, so production accepts
	// it and redacted exports name the variable, never the value (DEP-006).
	secretRef := func(name string, dst *string) {
		if v := os.Getenv(name); v != "" {
			if IsSecretRef(v) {
				*dst = v
			} else {
				*dst = "env:" + name
			}
		}
	}
	integer := func(name string, min, max int, set func(int)) {
		if v := os.Getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < min || n > max {
				errs = append(errs, fmt.Errorf("%s: must be an integer between %d and %d", name, min, max))
				return
			}
			set(n)
		}
	}
	if v := os.Getenv("PROUDAUTH_MODE"); v != "" {
		c.Mode = Mode(v)
	}
	str("PROUDAUTH_PUBLIC_ORIGIN", &c.Server.PublicOrigin)
	str("PROUDAUTH_PUBLIC_LISTEN", &c.Server.PublicListen)
	str("PROUDAUTH_INTERNAL_LISTEN", &c.Server.InternalListen)
	secretRef("PROUDAUTH_DATABASE_URL", &c.Storage.DatabaseURL)
	if os.Getenv("PROUDAUTH_ROOT_KEY") != "" {
		c.Keys.RootKeys = []KeyRef{{Version: 1}}
		secretRef("PROUDAUTH_ROOT_KEY", &c.Keys.RootKeys[0].Ref)
		c.Keys.ActiveVersion = 1
	}
	boolean("PROUDAUTH_MIGRATE_ON_START", &c.Storage.MigrateOnStart)
	str("PROUDAUTH_EMAIL_ADAPTER", &c.Delivery.Email.Adapter)
	str("PROUDAUTH_SMTP_HOST", &c.Delivery.Email.SMTPHost)
	integer("PROUDAUTH_SMTP_PORT", 1, 65535, func(n int) { c.Delivery.Email.SMTPPort = n })
	str("PROUDAUTH_SMTP_TLS", &c.Delivery.Email.SMTPTLS)
	str("PROUDAUTH_SMTP_USERNAME", &c.Delivery.Email.SMTPUsername)
	secretRef("PROUDAUTH_SMTP_PASSWORD", &c.Delivery.Email.SMTPPassword)
	str("PROUDAUTH_EMAIL_FROM", &c.Delivery.Email.From)
	str("PROUDAUTH_HOST_POLICY", &c.Server.HostPolicy)
	str("PROUDAUTH_LOG_LEVEL", &c.Observability.LogLevel)
	boolean("PROUDAUTH_IMPERSONATION_ENABLED", &c.Impersonation.Enabled)
	if v := os.Getenv("PROUDAUTH_TRUSTED_PROXIES"); v != "" {
		c.Server.TrustedProxies = strings.Split(v, ",")
	}
	boolean("PROUDAUTH_COOKIE_INSECURE_DEV", &c.Sessions.CookieInsecureDev)
	integer("PROUDAUTH_ARGON_MEMORY_KIB", 1, 1<<22, func(n int) { c.Security.Password.ArgonMemoryKiB = uint32(n) })
	integer("PROUDAUTH_ARGON_TIME", 1, 100, func(n int) { c.Security.Password.ArgonTime = uint32(n) })
	// One switch for every outbound integration's private-network egress
	// (development only; Validate refuses each of them in production).
	boolean("PROUDAUTH_ALLOW_PRIVATE_EGRESS", &c.Federation.AllowPrivateNetwork, &c.Delivery.AllowPrivateWebhooks, &c.Directory.AllowPrivateNetwork)
	return errors.Join(errs...)
}

// ResolveSecret resolves a secret reference: "file:/path", "env:NAME", or a literal
// (literals are refused in production for sensitive values by Validate).
func ResolveSecret(ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, "file:"):
		b, err := os.ReadFile(strings.TrimPrefix(ref, "file:"))
		if err != nil {
			return "", fmt.Errorf("secret file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	case strings.HasPrefix(ref, "env:"):
		v, ok := os.LookupEnv(strings.TrimPrefix(ref, "env:"))
		if !ok {
			return "", fmt.Errorf("secret env %s not set", strings.TrimPrefix(ref, "env:"))
		}
		return v, nil
	default:
		if fn, rest, ok := resolverFor(ref); ok {
			// Each resolver applies its own timeout (keys.kms.timeout for
			// kms:); this outer bound only stops a hung resolver.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			return fn(ctx, rest)
		}
		return ref, nil
	}
}

// DecodeKey decodes 32 key bytes from hex or base64 (std or url, padded or not).
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("key must be 32 bytes encoded as hex or base64")
}

// IsSecretRef reports whether a value is a reference rather than a literal.
func IsSecretRef(v string) bool {
	if strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "env:") {
		return true
	}
	_, _, ok := resolverFor(v)
	return ok
}

// Validate checks ranges, incompatible combinations and production safety rules.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if c.Mode != ModeProduction && c.Mode != ModeDevelopment {
		add("mode must be production or development")
	}
	u, err := url.Parse(c.Server.PublicOrigin)
	switch {
	case c.Server.PublicOrigin == "":
		add("server.public_origin is required (canonical issuer base; never derived from Host headers)")
	case err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		add("server.public_origin must be an absolute origin without path, query, fragment or userinfo")
	case c.Mode == ModeProduction && u.Scheme != "https":
		add("server.public_origin must use https in production (SEC-001)")
	case u.Scheme != "https" && u.Scheme != "http":
		add("server.public_origin must be http(s)")
	}
	for _, p := range c.Server.TrustedProxies {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(p)); err != nil {
			if net.ParseIP(strings.TrimSpace(p)) == nil {
				add("server.trusted_proxies entry %q is not an IP or CIDR", p)
			}
		}
	}
	if c.Storage.DatabaseURL == "" {
		add("storage.database_url is required")
	}
	if r := c.Storage.RuntimeRole; r != "" && !runtimeRoleName.MatchString(r) {
		add("storage.runtime_role must be a lowercase PostgreSQL role name (letters, digits, underscore)")
	}
	if _, ok := canonicalRealmName(c.Identity.DefaultRealm); !ok {
		add("identity.default_realm must be a lower-case realm name (letters, digits, dashes)")
	}
	if len(c.Keys.RootKeys) == 0 {
		add("keys.root_keys is required (DEP-008: keys must be durable across restarts)")
	}
	if c.Privacy.HistoryRetention < 7*24*time.Hour {
		add("privacy.history_retention must be at least 168h")
	}
	l := c.Limits
	switch {
	case l.InvitationResends < 0 || l.InvitationResends > 20:
		add("limits.invitation_resends must be 0..20")
	case l.SharedInvitationMaxUses < 1 || l.SharedInvitationMaxUses > 10000:
		add("limits.shared_invitation_max_uses must be 1..10000")
	case l.SharedInvitationMaxTTL < time.Hour || l.SharedInvitationMaxTTL > 30*24*time.Hour:
		add("limits.shared_invitation_max_ttl must be 1h..720h")
	case l.ClientSecretsMax < 1 || l.ClientSecretsMax > 10:
		add("limits.client_secrets_max must be 1..10")
	case l.MetadataBytes < 1024 || l.MetadataBytes > 256<<10:
		add("limits.metadata_bytes must be 1024..262144")
	case l.MaxBatchSize < 1 || l.MaxBatchSize > 10000:
		add("limits.max_batch_size must be 1..10000")
	}
	if v := c.Security.Password.LegacyHashesUntil; v != "" {
		if _, err := time.Parse("2006-01-02", v); err != nil {
			add("security.password.legacy_hashes_until must be a date (YYYY-MM-DD)")
		}
	}
	if r := c.Security.MFAFloor.Require; r != "" && r != "none" && r != "all" {
		add("security.mfa_floor.require must be none or all")
	}
	// A wide TOTP window multiplies the codes an attacker may guess (MFA-002).
	if c.Security.TOTPSkewSteps < 0 || c.Security.TOTPSkewSteps > 2 {
		add("security.totp_skew_steps must be 0..2")
	}
	if c.Security.RecoveryCodeCount < 5 || c.Security.RecoveryCodeCount > 20 {
		add("security.recovery_code_count must be 5..20")
	}
	for i, h := range c.Privacy.Residency.AllowedDestinations {
		h = strings.TrimPrefix(strings.TrimSpace(h), ".")
		if h == "" || strings.ContainsAny(h, "/:@ *") {
			add("privacy.residency.allowed_destinations[%d] must be a host name or a .domain suffix", i)
		}
	}
	// Operator delivery channels carry message payloads: they must respect
	// the residency policy too (PRV-003).
	if dest := c.Privacy.Residency.AllowedDestinations; len(dest) > 0 {
		if h := c.Delivery.Email.SMTPHost; c.Delivery.Email.Adapter == "smtp" && h != "" && !egress.HostMatches(h, dest) {
			add("delivery.email.smtp_host %q is outside privacy.residency.allowed_destinations", h)
		}
		if u, err := url.Parse(c.Delivery.SMS.WebhookURL); c.Delivery.SMS.Adapter == "webhook" && err == nil && !egress.HostMatches(u.Hostname(), dest) {
			add("delivery.sms.webhook_url is outside privacy.residency.allowed_destinations")
		}
	}
	if d := c.Security.DynamicGroupMaxStaleness; d != 0 && (d < 10*time.Minute || d > 7*24*time.Hour) {
		add("security.dynamic_group_max_staleness must be between 10m and 168h")
	}
	if d := c.Security.DecisionCacheTTL; d < 0 || d > 10*time.Minute {
		add("security.decision_cache_ttl must be between 0 and 10m")
	}
	if k := c.Keys.KMS; k.Enabled() && (k.Command[0] == "" || k.Timeout < 0 || k.Timeout > time.Minute) {
		add("keys.kms.command must name a program and keys.kms.timeout be at most 1m")
	}
	for _, ref := range append(append(append([]KeyRef{}, c.Keys.RootKeys...), c.Keys.PepperKeys...), c.Keys.SigningWrapKeys...) {
		if strings.HasPrefix(ref.Ref, "kms:") && !c.Keys.KMS.Enabled() {
			add("a kms: key reference needs keys.kms.command (DEP-016)")
			break
		}
	}
	if e := c.Observability.OTLPEndpoint; e != "" {
		if u, err := url.Parse(e); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			add("observability.otlp_endpoint must be an absolute http(s) URL without credentials")
		} else if dest := c.Privacy.Residency.AllowedDestinations; len(dest) > 0 && !egress.HostMatches(u.Hostname(), dest) {
			add("observability.otlp_endpoint is outside privacy.residency.allowed_destinations")
		} else if c.Mode == ModeProduction && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
			add("observability.otlp_endpoint must use https in production (spans leave the process)")
		}
	}
	switch c.Server.HostPolicy {
	case "", "any", "strict":
	default:
		add("server.host_policy must be any or strict")
	}
	if c.Server.MTLSListen != "" && c.Server.TLSCertFile == "" {
		add("server.mtls_listen needs server.tls_cert_file and tls_key_file")
	}
	if o := c.Server.MTLSOrigin; o != "" {
		if u, err := url.Parse(o); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" {
			add("server.mtls_origin must be an https origin")
		}
	}
	if c.Server.ClientCertHeader != "" && len(c.Server.TrustedProxies) == 0 {
		add("server.client_cert_header needs server.trusted_proxies: the header is honoured only from them")
	}
	providers := map[string]bool{}
	for i, p := range c.Security.ChallengeProviders {
		if !challengeProviderName.MatchString(p.Name) || providers[p.Name] {
			add("security.challenge_providers[%d].name must be unique lowercase letters, digits and dashes (at most 40)", i)
		}
		providers[p.Name] = true
		if u, err := url.Parse(p.VerifyURL); err != nil || u.Host == "" || (u.Scheme != "https" && (c.Mode == ModeProduction || u.Scheme != "http")) {
			add("security.challenge_providers[%d].verify_url must be an absolute https URL", i)
		}
		if p.Secret == "" || (c.Mode == ModeProduction && !IsSecretRef(p.Secret)) {
			add("security.challenge_providers[%d].secret is required (a secret reference in production)", i)
		}
		if p.Timeout < 0 || p.Timeout > 10*time.Second {
			add("security.challenge_providers[%d].timeout must be at most 10s", i)
		}
	}
	engines := map[string]bool{}
	for i, e := range c.Security.PolicyEngines {
		if !challengeProviderName.MatchString(e.Name) || engines[e.Name] {
			add("security.policy_engines[%d].name must be unique lowercase letters, digits and dashes (at most 40)", i)
		}
		engines[e.Name] = true
		if u, err := url.Parse(e.URL); err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && (c.Mode == ModeProduction || u.Scheme != "http")) {
			add("security.policy_engines[%d].url must be an absolute https URL", i)
		}
		if e.Token == "" || (c.Mode == ModeProduction && !IsSecretRef(e.Token)) {
			add("security.policy_engines[%d].token is required (a secret reference in production)", i)
		}
		if e.Timeout < 0 || e.Timeout > 5*time.Second {
			add("security.policy_engines[%d].timeout must be at most 5s", i)
		}
	}
	for cat, d := range c.Privacy.AuditRetentionByCategory {
		if cat == "emergency" {
			add("privacy.audit_retention_by_category: emergency events are never pruned")
		} else if !slices.Contains(AuditCategories, cat) {
			add("privacy.audit_retention_by_category: unknown category %q (one of %s)", cat,
				strings.Join(slices.DeleteFunc(slices.Clone(AuditCategories), func(c string) bool { return c == "emergency" }), ", "))
		}
		if d < 24*time.Hour {
			add("privacy.audit_retention_by_category.%s must be at least 24h", cat)
		}
	}
	// SAML message and skew bounds (SAML-003, SAML-004).
	if n := c.SAML.MaxMessageBytes; n < 16<<10 || n > 4<<20 {
		add("saml.max_message_bytes must be between 16384 and 4194304")
	}
	if s := c.SAML.MaxClockSkew; s < 0 || s > 30*time.Minute {
		add("saml.max_clock_skew must be between 0 and 30m")
	}
	if c.SAML.KeyPrepublish < 0 || c.SAML.RetiredKeyPublication < 0 {
		add("saml.key_prepublish and saml.retired_key_publication must not be negative")
	}
	if c.Mode == ModeProduction {
		if strings.EqualFold(c.Observability.LogLevel, "debug") {
			add("observability.log_level debug is not allowed in production; open a time-limited window with identity-cli debug-window (SEC-015)")
		}
		for _, k := range c.Keys.RootKeys {
			if !IsSecretRef(k.Ref) {
				add("keys.root_keys version %d must be a secret reference (file:, env:, cred:, vault: or a registered adapter) in production (DEP-006)", k.Version)
			}
		}
		for _, k := range c.Keys.PepperKeys {
			if !IsSecretRef(k.Ref) {
				add("keys.pepper_keys version %d must be a secret reference in production (DEP-006)", k.Version)
			}
		}
		for _, k := range c.Keys.SigningWrapKeys {
			if !IsSecretRef(k.Ref) {
				add("keys.signing_wrap_keys version %d must be a secret reference in production (DEP-006)", k.Version)
			}
		}
		if c.Delivery.Email.Adapter == "dev_sink" {
			add("delivery.email.adapter dev_sink is not allowed in production (MSG-011, QA-007)")
		}
		if c.Delivery.SMS.Adapter == "dev_sink" {
			add("delivery.sms.adapter dev_sink is not allowed in production (MSG-011, QA-007)")
		}
		if c.Delivery.Email.SMTPTLS == "none" {
			add("delivery.email.smtp_tls none is not allowed in production")
		}
		if c.Sessions.CookieInsecureDev {
			add("sessions.cookie_insecure_dev is not allowed in production (SES-010)")
		}
		if c.Federation.AllowPrivateNetwork {
			add("federation.allow_private_network must use an explicit egress allowlist in production (EXT-007)")
		}
		if c.Directory.AllowPrivateNetwork {
			add("directory.allow_private_network must use directory.egress_allowlist in production (EXT-007)")
		}
		if c.Delivery.AllowPrivateWebhooks {
			add("delivery.allow_private_webhooks must use delivery.egress_allowlist in production (EXT-007)")
		}
		if c.Security.Password.ArgonMemoryKiB < 19*1024 {
			add("security.password.argon_memory_kib must be at least 19456 in production (CRED-001)")
		}
		// Secrets must come from references, not literals, in production (DEP-006).
		for name, v := range map[string]string{"storage.migration_database_url": c.Storage.MigrationDatabaseURL,
			"delivery.email.smtp_password": c.Delivery.Email.SMTPPassword, "server.metrics_token": c.Server.MetricsToken,
			"delivery.email.events_secret": c.Delivery.Email.EventsSecret, "delivery.sms.webhook_secret": c.Delivery.SMS.WebhookSecret} {
			if v != "" && !IsSecretRef(v) {
				add("%s must be a secret reference (file:, env:, cred:, vault: or a registered adapter) in production (DEP-006)", name)
			}
		}
		if du, err := url.Parse(c.Storage.DatabaseURL); !IsSecretRef(c.Storage.DatabaseURL) && err == nil && du.User != nil {
			if _, hasPassword := du.User.Password(); hasPassword {
				add("storage.database_url embeds a password; use a file: or env: reference in production (DEP-006)")
			}
		}
	}
	switch c.Delivery.SMS.Adapter {
	case "", "none":
	case "dev_sink":
	case "webhook":
		if u, err := url.Parse(c.Delivery.SMS.WebhookURL); err != nil || u.Host == "" || (u.Scheme != "https" && (c.Mode == ModeProduction || u.Scheme != "http")) {
			add("delivery.sms.webhook_url must be an absolute https URL")
		}
		if c.Delivery.SMS.WebhookSecret == "" || (c.Mode == ModeProduction && !IsSecretRef(c.Delivery.SMS.WebhookSecret)) {
			add("delivery.sms.webhook_secret is required (a file: or env: reference in production)")
		}
	default:
		add("delivery.sms.adapter must be none, dev_sink or webhook")
	}
	for _, cidr := range append(append([]string{}, c.Federation.EgressAllowlist...), c.Delivery.EgressAllowlist...) {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			add("egress_allowlist entry %q is not a CIDR", cidr)
		}
	}
	for _, cidr := range c.Directory.EgressAllowlist {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			add("directory.egress_allowlist entry %q is not a CIDR", cidr)
		}
	}
	if c.Directory.ConnectTimeout < 0 || c.Directory.ConnectTimeout > time.Minute || c.Directory.OperationTimeout < 0 ||
		c.Directory.OperationTimeout > 2*time.Minute {
		add("directory.connect_timeout must be at most 1m and directory.operation_timeout at most 2m")
	}
	if c.Directory.SignInTimeout < 0 || c.Directory.SignInTimeout > 25*time.Second {
		add("directory.sign_in_timeout must be at most 25s, below the 30s request deadline (0 uses the 8s default)")
	}
	if c.Directory.MaxEntriesPerRun < 0 || c.Directory.MaxEntriesPerRun > 1_000_000 {
		add("directory.max_entries_per_run must be between 0 and 1000000")
	}
	for _, p := range c.Delivery.SMS.AllowedCountries {
		if len(p) < 2 || p[0] != '+' || strings.Trim(p[1:], "0123456789") != "" {
			add("delivery.sms.allowed_countries entries are country calling-code prefixes such as +1 or +49 (got %q)", p)
		}
	}
	switch c.Delivery.Email.SMTPTLS {
	case "starttls", "implicit", "none":
	default:
		add("delivery.email.smtp_tls must be starttls, implicit or none")
	}
	if c.Security.Password.ArgonTime < 1 || c.Security.Password.ArgonThreads < 1 || c.Security.Password.ArgonMemoryKiB < 8*1024 {
		add("security.password argon_time and argon_threads must be >= 1 and argon_memory_kib >= 8192")
	}
	w := c.Workers
	if w.Concurrency < 1 || w.BatchSize < 1 || w.MaxAttempts < 1 || w.PollInterval <= 0 || w.LeaseDuration <= 0 || w.AuditSealEvery <= 0 {
		add("workers: concurrency, batch_size and max_attempts must be >= 1; poll_interval, lease_duration and audit_seal_every must be positive")
	}
	if c.Security.Password.MinLength < 8 {
		add("security.password.min_length must be >= 8 (safety floor)")
	}
	if c.Security.Password.MaxLength < 64 {
		add("security.password.max_length must be >= 64 (CRED-002)")
	}
	if c.Security.Password.MaxBytes < c.Security.Password.MaxLength {
		add("security.password.max_bytes must be >= max_length")
	}
	if c.Tokens.AccessTokenTTL <= 0 || c.Tokens.AccessTokenTTL > c.Tokens.MaxAccessTokenTTL {
		add("tokens.access_token_ttl must be positive and <= max_access_token_ttl")
	}
	if c.Tokens.AuthorizationCodeTTL <= 0 || c.Tokens.AuthorizationCodeTTL > 10*time.Minute {
		add("tokens.authorization_code_ttl must be in (0, 10m]")
	}
	if c.Tokens.ClockSkew < 0 || c.Tokens.ClockSkew > 60*time.Second {
		add("tokens.clock_skew must be in [0, 60s] (§14.5)")
	}
	if c.Impersonation.MaxTTL <= 0 || c.Impersonation.MaxTTL > 5*time.Minute {
		add("impersonation.max_ttl must be in (0, 5m] (IMP-009)")
	}
	if c.Impersonation.HandoffTTL <= 0 || c.Impersonation.HandoffTTL > 30*time.Second {
		add("impersonation.handoff_ttl must be in (0, 30s] (§16.3)")
	}
	if c.Security.AdminMFAMaxAge <= 0 || c.Security.AdminMFAMaxAge > 5*time.Minute {
		add("security.admin_mfa_max_age must be in (0, 5m] (§14.5)")
	}
	if c.Sessions.IdleTimeout <= 0 || c.Sessions.AbsoluteTimeout < c.Sessions.IdleTimeout {
		add("sessions.idle_timeout must be positive and <= absolute_timeout")
	}
	if c.Privacy.TelemetryOptIn {
		add("privacy.telemetry_opt_in: no third-party telemetry sink is implemented; leave disabled (OSS-006)")
	}
	switch strings.ToLower(c.Sessions.CookieSameSite) {
	case "lax", "strict":
	case "none":
		if c.Mode == ModeProduction && c.Sessions.CookieInsecureDev {
			add("SameSite=None requires Secure cookies")
		}
	default:
		add("sessions.cookie_same_site must be lax, strict or none")
	}
	switch c.Keys.SigningAlgorithm {
	case "RS256", "ES256", "PS256", "EdDSA":
	default:
		add("keys.signing_algorithm must be RS256, ES256, PS256 or EdDSA")
	}
	switch c.Delivery.Email.Adapter {
	case "smtp":
		if c.Delivery.Email.SMTPHost == "" {
			add("delivery.email.smtp_host is required for the smtp adapter")
		}
		if c.Delivery.Email.From == "" {
			add("delivery.email.from is required for the smtp adapter")
		}
	case "dev_sink":
	default:
		add("delivery.email.adapter must be smtp or dev_sink")
	}
	if c.Limits.MaxPageSize <= 0 || c.Limits.DefaultPageSize <= 0 || c.Limits.DefaultPageSize > c.Limits.MaxPageSize {
		add("limits.default_page_size must be in (0, max_page_size]")
	}
	// Safe operator ranges (NFR-001): every product feature works inside
	// them. Lower bounds come from what the product itself sends or accepts
	// (migration-adapter batches up to 192 KiB, SAML POST messages, policy
	// definitions nested to their limit inside configuration documents);
	// upper bounds keep one request's memory and work bounded.
	for _, r := range []struct {
		key           string
		v, min, max   int64
		zeroIsDefault bool
	}{
		{"limits.max_body_bytes", c.Limits.MaxBodyBytes, 256 << 10, 64 << 20, false},
		{"limits.max_header_bytes", int64(c.Limits.MaxHeaderBytes), 8 << 10, 1 << 20, false},
		{"limits.max_token_bytes", int64(c.Limits.MaxTokenBytes), 4 << 10, 64 << 10, false},
		{"limits.max_json_depth", int64(c.Limits.MaxJSONDepth), 32, 256, false},
		{"limits.max_page_size", int64(c.Limits.MaxPageSize), 1, 1000, false},
		{"limits.max_group_depth", int64(c.Limits.MaxGroupDepth), 1, 32, false},
		{"limits.max_role_expansion", int64(c.Limits.MaxRoleExpansion), 8, 1024, false},
		{"limits.max_inflight_requests", int64(c.Limits.MaxInflightRequests), 1, 100000, true},
		{"directory.max_concurrent_binds", int64(c.Directory.MaxConcurrentBinds), 1, 10000, true},
		{"security.password.max_concurrent_hashes", int64(c.Security.Password.MaxConcurrentHashes), 1, 10000, true},
	} {
		if r.zeroIsDefault && r.v == 0 {
			continue
		}
		if r.v < r.min || r.v > r.max {
			add("%s must be %d..%d", r.key, r.min, r.max)
		}
	}
	errs = append(errs, c.Extensions.validate()...) // plugin publisher keys (EXT-014)
	errs = append(errs, c.WebAuthn.validate()...)   // passkey metadata (PASS-009)
	if len(errs) > 0 {
		return errors.New("invalid configuration:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}

// Issuer returns the canonical issuer for a realm name.
func (c *Config) Issuer(realm string) string {
	return strings.TrimSuffix(c.Server.PublicOrigin, "/") + "/realms/" + realm
}

// Redacted returns a copy safe for support bundles and exports (OPS-010).
func (c Config) Redacted() Config {
	r := c
	r.Storage.DatabaseURL = redactRef(c.Storage.DatabaseURL)
	r.Storage.MigrationDatabaseURL = redactRef(c.Storage.MigrationDatabaseURL)
	r.Keys.RootKeys = redactRefs(c.Keys.RootKeys)
	r.Keys.PepperKeys = redactRefs(c.Keys.PepperKeys)
	r.Keys.SigningWrapKeys = redactRefs(c.Keys.SigningWrapKeys)
	r.Delivery.Email.SMTPPassword = redactRef(c.Delivery.Email.SMTPPassword)
	r.Delivery.Email.EventsSecret = redactRef(c.Delivery.Email.EventsSecret)
	r.Delivery.SMS.WebhookSecret = redactRef(c.Delivery.SMS.WebhookSecret)
	r.Server.MetricsToken = redactRef(c.Server.MetricsToken)
	// Slices are copied: the copy must not share (and redact) the live
	// configuration's entries.
	r.Security.ChallengeProviders = slices.Clone(c.Security.ChallengeProviders)
	for i := range r.Security.ChallengeProviders {
		r.Security.ChallengeProviders[i].Secret = redactRef(r.Security.ChallengeProviders[i].Secret)
	}
	r.Security.PolicyEngines = slices.Clone(c.Security.PolicyEngines)
	for i := range r.Security.PolicyEngines {
		r.Security.PolicyEngines[i].Token = redactRef(r.Security.PolicyEngines[i].Token)
	}
	return r
}

func redactRef(v string) string {
	if v == "" || IsSecretRef(v) {
		return v
	}
	return "[REDACTED]"
}

func redactRefs(in []KeyRef) []KeyRef {
	out := make([]KeyRef, len(in))
	for i, k := range in {
		out[i] = KeyRef{Version: k.Version, Ref: redactRef(k.Ref)}
	}
	return out
}

func canonicalRealmName(n string) (string, bool) {
	if len(n) < 1 || len(n) > 63 || n[0] == '-' || n[len(n)-1] == '-' {
		return "", false
	}
	for _, c := range n {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return "", false
		}
	}
	return n, true
}

// AuditCategories are the audit event categories retention can be configured
// for; "imported" covers historical records imported from a source system.
// tests/contract checks that every category the code records is listed.
var AuditCategories = []string{"account", "application", "audit", "authorization", "configuration", "data_access", "emergency",
	"imported", "operations", "privacy", "security", "support", "token"}

var challengeProviderName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// ChallengeProvider returns a configured challenge provider by name.
// PolicyEngine returns the configured policy engine with that name.
func (c *Config) PolicyEngine(name string) (*PolicyEngineConfig, bool) {
	for i := range c.Security.PolicyEngines {
		if c.Security.PolicyEngines[i].Name == name {
			return &c.Security.PolicyEngines[i], true
		}
	}
	return nil, false
}

func (c *Config) ChallengeProvider(name string) (*ChallengeProviderConfig, bool) {
	for i := range c.Security.ChallengeProviders {
		if c.Security.ChallengeProviders[i].Name == name {
			return &c.Security.ChallengeProviders[i], true
		}
	}
	return nil, false
}

var runtimeRoleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
