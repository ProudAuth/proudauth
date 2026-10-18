package realm

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/proudauth/proudauth/internal/identity"
)

// Registration modes (REG-001).
const (
	RegistrationPublic           = "public"
	RegistrationClosed           = "closed"
	RegistrationInvitationOnly   = "invitation_only"
	RegistrationDomainRestricted = "domain_restricted"
)

// MFA requirement levels.
const (
	MFAOptional = "optional"
	MFARequired = "required"
)

// Policy is the realm security policy stored in realms.settings. Organization
// policies may tighten but never loosen it (TEN-012), and the realm itself may never
// go below operator safety floors held in deployment configuration.
type Policy struct {
	Registration  RegistrationPolicy  `json:"registration"`
	Login         LoginPolicy         `json:"login"`
	MFA           MFAPolicy           `json:"mfa"`
	Sessions      SessionPolicy       `json:"sessions"`
	Interaction   InteractionPolicy   `json:"interaction"`
	Impersonation ImpersonationPolicy `json:"impersonation"`
	Password      PasswordPolicy      `json:"password"`
	Notifications NotificationPolicy  `json:"notifications"`
	WebAuthn      WebAuthnPolicy      `json:"webauthn"`
	Lifecycle     LifecyclePolicy     `json:"lifecycle"`
	Profile       ProfilePolicy       `json:"profile"`
	Recovery      RecoveryPolicy      `json:"recovery"`
	DataAccess    DataAccessPolicy    `json:"data_access"`
	Tokens        TokenLifetimePolicy `json:"tokens"`
	Domains       DomainPolicy        `json:"domains"`
	Audit         AuditPolicy         `json:"audit"`
	Machine       MachinePolicy       `json:"machine"`
	// AuthFlow is the realm's authentication policy (AUT-012, AUT-014).
	AuthFlow AuthFlowPolicy `json:"authentication_flow"`
	// ClientRegistration governs OAuth dynamic client registration
	// (APP-016, ADV-003); off by default.
	ClientRegistration ClientRegistrationPolicy `json:"client_registration"`
	// PolicyEngine delegates authorization decisions to an external engine
	// the operator configured (AZ-026); empty keeps decisions local.
	PolicyEngine PolicyEnginePolicy `json:"policy_engine"`
	// Extensions governs plugin review and workflow publication (EXT-014,
	// EXT-015).
	Extensions ExtensionsPolicy `json:"extensions"`
	// SharedSignals declares the Shared Signals Framework transmitter
	// (AUD-016); off by default.
	SharedSignals SharedSignalsPolicy `json:"shared_signals"`
	// ClientAuth tunes client authentication at the protocol endpoints
	// (APP-009, MCH-010).
	ClientAuth ClientAuthPolicy `json:"client_auth"`
}

// ClientAuthPolicy tunes client authentication (APP-009, MCH-010). A
// private_key_jwt client assertion's aud must be a single JSON string equal
// to the realm's issuer (FAPI 2.0 Security Profile, RFC 7523bis; decision
// 16). AllowEndpointAudience re-admits, for clients other than fapi2 ones,
// what earlier versions accepted: the URL of the endpoint that receives the
// assertion (the token endpoint URL at the token endpoint) and an array of
// one or two values, each the issuer or that URL. Off by default; a fapi2
// client is held to the issuer-only rule whatever it says.
type ClientAuthPolicy struct {
	AllowEndpointAudience bool `json:"allow_endpoint_audience"`
}

// SharedSignalsPolicy turns on the SSF transmitter: transmitter metadata,
// stream management for receivers holding realm.ssf_streams.manage, and
// CAEP/RISC events about each receiver's own users.
type SharedSignalsPolicy struct {
	Enabled bool `json:"enabled"`
}

// PolicyEnginePolicy names an operator-configured policy engine and how its
// answers combine with local decisions (AZ-026). In restrict mode (default)
// the engine can only deny what local rules allow; in decide mode its answer
// is final in both directions, while published policies and hooks still
// restrict it. OnError decides what an unreachable or malformed engine
// means: deny (default) or the local decision.
type PolicyEnginePolicy struct {
	Name    string `json:"name,omitempty"`
	Mode    string `json:"mode,omitempty"`
	OnError string `json:"on_error,omitempty"`
}

// ClientRegistrationPolicy restricts dynamic client registration (APP-016,
// ADV-003). Registration needs an initial access token issued by an
// administrator unless Open is set; open registration is limited to the
// OpenID Connect scopes in OpenScopes and never yields privileged scopes.
type ClientRegistrationPolicy struct {
	Enabled bool `json:"enabled"`
	// Open accepts registrations without an initial access token.
	Open bool `json:"open,omitempty"`
	// RequireApproval keeps new registrations suspended until an
	// administrator approves them (open registrations always need it unless
	// this is explicitly false and Open is set).
	RequireApproval bool `json:"require_approval,omitempty"`
	// OpenScopes are the UserInfo scopes any registered client may request
	// (default openid, profile, email).
	OpenScopes []string `json:"open_scopes,omitempty"`
}

// RegistrationScopes returns the UserInfo scopes registered clients may use.
func (p ClientRegistrationPolicy) RegistrationScopes() []string {
	if len(p.OpenScopes) > 0 {
		return p.OpenScopes
	}
	return []string{"openid", "profile", "email"}
}

// AuthFlowPolicy is an ordered, bounded rule list evaluated once the account
// is known (AUT-012). The first rule whose conditions all match decides the
// outcome; without a match the login proceeds under the other policies. The
// realm policy revision versions it, and every decision records the revision
// and the rule that matched.
type AuthFlowPolicy struct {
	Rules []AuthFlowRule `json:"rules,omitempty"`
	// ChallengeProvider names an operator-configured challenge provider
	// (security.challenge_providers) offered for "challenge" outcomes (SEC-014).
	ChallengeProvider string `json:"challenge_provider,omitempty"`
	// EmailCodeAlternative offers a code sent to the account's verified email
	// as the accessible alternative to a provider challenge (default true).
	EmailCodeAlternative *bool `json:"email_code_alternative,omitempty"`
}

// EmailAlternative reports whether a challenge may be met with an emailed code.
func (p AuthFlowPolicy) EmailAlternative() bool {
	return p.EmailCodeAlternative == nil || *p.EmailCodeAlternative
}

// Authentication flow outcomes.
const (
	FlowAllow                    = "allow"
	FlowRequireMFA               = "require_mfa"
	FlowRequirePhishingResistant = "require_phishing_resistant"
	FlowChallenge                = "challenge"
	FlowReview                   = "review"
	FlowDeny                     = "deny"
)

// AuthFlowRule is one rule. OnMissingSignal decides a rule whose condition
// needs a signal that is unavailable (no risk hook, a failed risk hook, no
// client address): "apply" (default) applies a restrictive outcome as if the
// condition matched, "skip" ignores the rule. An allow rule never matches on
// a missing signal, so a missing signal never satisfies a stricter policy
// (AUT-014).
type AuthFlowRule struct {
	Name            string            `json:"name"`
	When            AuthFlowCondition `json:"when"`
	Outcome         string            `json:"outcome"`
	OnMissingSignal string            `json:"on_missing_signal,omitempty"`
}

// AuthFlowCondition lists conditions that must all hold; empty members are
// not checked.
type AuthFlowCondition struct {
	Clients       []string `json:"clients,omitempty"`       // OAuth client_id
	Organizations []string `json:"organizations,omitempty"` // organization IDs
	// Methods are primary methods: password, passkey, email_otp, magic_link,
	// sms_otp, sso (federation).
	Methods   []string `json:"methods,omitempty"`
	Resources []string `json:"resources,omitempty"` // resource audiences
	// Networks match when the client address is inside one of the CIDRs;
	// OutsideNetworks when it is inside none.
	Networks        []string `json:"networks,omitempty"`
	OutsideNetworks []string `json:"outside_networks,omitempty"`
	// NewDevice matches a device that is (true) or is not (false) remembered
	// for the account.
	NewDevice *bool `json:"new_device,omitempty"`
	// FailedAttemptsAtLeast matches when the account had at least this many
	// failed sign-in attempts in the last hour.
	FailedAttemptsAtLeast int `json:"failed_attempts_at_least,omitempty"`
	// RiskAtLeast matches the level reported by authentication.risk hooks:
	// low, medium or high.
	RiskAtLeast string `json:"risk_at_least,omitempty"`
	// Privileged matches accounts that are (or are not) protected or hold a
	// privileged realm role.
	Privileged *bool `json:"privileged,omitempty"`
	// AssuranceBelow matches when the factors completed so far give a lower
	// assurance than this ACR.
	AssuranceBelow string `json:"assurance_below,omitempty"`
}

// MachinePolicy decides what happens to a service principal whose accountable
// owner is suspended, locked or deleted (MCH-007). Personal tokens and user
// API keys stop working with their owner regardless.
type MachinePolicy struct {
	// OwnerDeparture is "flag" (default: report once, list in the credential
	// inventory as owner_departed) or "disable" (disable the service principal
	// and revoke its credentials, after OwnerDepartureGraceDays).
	OwnerDeparture          string `json:"owner_departure,omitempty"`
	OwnerDepartureGraceDays int    `json:"owner_departure_grace_days,omitempty"`
}

// DomainPolicy configures periodic re-verification of organization domains
// (TEN-009): how often the DNS proof is re-checked and after how many
// consecutive daily failures the verification lapses.
type DomainPolicy struct {
	RecheckDays        int `json:"recheck_days,omitempty"`
	LapseAfterFailures int `json:"lapse_after_failures,omitempty"`
}

// TokenLifetimePolicy bounds access-token lifetimes in the realm (TOK-018).
// Resources and clients set lifetimes; these realm limits only shorten them:
// for every access token, for service principals, for sessions below MFA and
// for support (impersonation) tokens. The operator maximum always applies.
type TokenLifetimePolicy struct {
	AccessTokenTTLSeconds              int `json:"access_token_ttl_seconds,omitempty"`
	ServiceAccessTokenTTLSeconds       int `json:"service_access_token_ttl_seconds,omitempty"`
	SingleFactorAccessTokenTTLSeconds  int `json:"single_factor_access_token_ttl_seconds,omitempty"`
	ImpersonationAccessTokenTTLSeconds int `json:"impersonation_access_token_ttl_seconds,omitempty"`
}

// DataAccessPolicy controls evidence of reads of identity data (USR-018,
// AUD-015). Reads are not logged by default; when enabled, every
// administrative or support read of an account record and every account
// search is recorded in the data_access audit category with the actor, the
// account and whether the view was masked — never the data itself.
type DataAccessPolicy struct {
	LogIdentityReads bool `json:"log_identity_reads,omitempty"`
	// SampleAllowedDecisionsPercent audits that share of ordinary allowed
	// authorization decisions (AZ-020); denials and privileged or support
	// decisions are always audited.
	SampleAllowedDecisionsPercent int `json:"sample_allowed_decisions_percent,omitempty"`
}

// RecoveryPolicy configures assisted recovery (MFA-009): a cooling-off period
// during which the owner is warned and can cancel, and an optional
// independent second-operator approval.
type RecoveryPolicy struct {
	CoolingOffHours int  `json:"cooling_off_hours,omitempty"`
	RequireApproval bool `json:"require_approval,omitempty"`
}

// ProfilePolicy holds the realm's custom profile attribute schema (USR-007).
// Self-service may only write attributes defined here as user-editable.
type ProfilePolicy struct {
	Attributes []identity.AttributeDef `json:"attributes,omitempty"`
}

// AttributeSchema returns the effective schema: the defined attributes, with
// registration.required_profile_fields marked required (REG-007, AUT-018). An
// empty schema still applies, so undefined attributes are always rejected.
func (p Policy) AttributeSchema() *identity.AttributeSchema {
	sch := &identity.AttributeSchema{Attributes: slices.Clone(p.Profile.Attributes)}
	for i := range sch.Attributes {
		if slices.Contains(p.Registration.RequiredProfileFields, sch.Attributes[i].Name) {
			sch.Attributes[i].Required = true
		}
	}
	return sch
}

type RegistrationPolicy struct {
	Mode                      string   `json:"mode"`
	AllowedDomains            []string `json:"allowed_domains,omitempty"`
	RequireEmailVerification  bool     `json:"require_email_verification"`
	AllowOrganizationCreation bool     `json:"allow_organization_creation"`
	TermsVersion              string   `json:"terms_version,omitempty"`
	RequiredProfileFields     []string `json:"required_profile_fields,omitempty"`
	// RequireApproval queues self-registered accounts for review (REG-008);
	// invited registrations are already approved by their invitation.
	RequireApproval bool `json:"require_approval,omitempty"`
	AllowGuests     bool `json:"allow_guests"`
}

type LoginPolicy struct {
	Identifiers []string `json:"identifiers"`
	Password    bool     `json:"password"`
	EmailOTP    bool     `json:"email_otp"`
	MagicLink   bool     `json:"magic_link"`
	Passkeys    bool     `json:"passkeys"`
	SMSOTP      bool     `json:"sms_otp"`
	// SMSRiskAccepted records the operator's explicit acceptance of SMS
	// assurance and delivery risks; SMS sign-in cannot be enabled without it
	// (PWDLESS-005).
	SMSRiskAccepted bool `json:"sms_risk_accepted,omitempty"`
	// Certificates offers X.509 sign-in (PROV-016) with certificates that
	// chain to a user trust anchor and are bound to the account; the login
	// surface submits that step over the mutual-TLS endpoint.
	Certificates    bool `json:"certificates,omitempty"`
	RememberDevices bool `json:"remember_devices"`
	// RememberDeviceDays bounds remembered-device lifetime (1..90, default 30).
	RememberDeviceDays int `json:"remember_device_days,omitempty"`
}

type MFAPolicy struct {
	Requirement            string   `json:"requirement"`
	AllowedFactors         []string `json:"allowed_factors"`
	AdminPhishingResistant bool     `json:"admin_phishing_resistant"`
	// OrgAdminMFAOptional waives MFA for organization administrators changing
	// roles, ownership, domains or organization policy. MFA is required by
	// default (MFA-003); realms set this only after an explicit decision.
	OrgAdminMFAOptional bool `json:"org_admin_mfa_optional,omitempty"`
	// HOTP tunes optional counter-based codes (MFA-013). They are offered
	// only when "hotp" is listed in allowed_factors, never by default.
	HOTP HOTPPolicy `json:"hotp,omitzero"`
}

// HOTPPolicy bounds counter-based codes (MFA-013), separately from TOTP.
type HOTPPolicy struct {
	// LookAhead is how many counters past the stored one a sign-in code may
	// be (default 10, at most 50).
	LookAhead int `json:"look_ahead,omitempty"`
	// ResyncWindow is how far an explicit resynchronization with two
	// consecutive codes may search (default 100, at most 1000).
	ResyncWindow int `json:"resync_window,omitempty"`
}

// HOTPAllowed reports whether the realm offers HOTP: only when listed.
func (m MFAPolicy) HOTPAllowed() bool { return slices.Contains(m.AllowedFactors, "hotp") }

// TOTPAllowed reports whether the realm accepts TOTP: when allowed_factors
// is empty or lists it (MFA-005).
func (m MFAPolicy) TOTPAllowed() bool {
	return len(m.AllowedFactors) == 0 || slices.Contains(m.AllowedFactors, "totp")
}

// PasskeysEnabled reports whether the realm offers passkeys, for sign-in
// (login.passkeys) or as a second factor (webauthn in mfa.allowed_factors).
// The phishing-resistant profile can only be met where it is true (SEC-012).
func (p Policy) PasskeysEnabled() bool {
	return p.Login.Passkeys || slices.Contains(p.MFA.AllowedFactors, "webauthn")
}

// CodeFactors lists the code-based second factors (credential types totp and
// hotp) the realm accepts. An enrolled factor the realm does not allow
// satisfies nothing at sign-in (MFA-005), so it does not count as an
// existing second factor anywhere else either: not for adding another factor
// (MFA-006), changing the password (CRED-006) or the last-factor guard.
func (m MFAPolicy) CodeFactors() []string {
	out := []string{}
	if m.TOTPAllowed() {
		out = append(out, "totp")
	}
	if m.HOTPAllowed() {
		out = append(out, "hotp")
	}
	return out
}

// HOTPLookAhead returns the effective sign-in window.
func (m MFAPolicy) HOTPLookAhead() int {
	if m.HOTP.LookAhead > 0 {
		return m.HOTP.LookAhead
	}
	return 10
}

// HOTPResyncWindow returns the effective resynchronization window.
func (m MFAPolicy) HOTPResyncWindow() int {
	if m.HOTP.ResyncWindow > 0 {
		return m.HOTP.ResyncWindow
	}
	return 100
}

type SessionPolicy struct {
	IdleSeconds     int `json:"idle_seconds,omitempty"`
	AbsoluteSeconds int `json:"absolute_seconds,omitempty"`
	MaxConcurrent   int `json:"max_concurrent,omitempty"`
	// CheckSessionIframe turns on OpenID Connect Session Management 1.0
	// (OIDC-014): a check_session_iframe in discovery and session_state in
	// authorization responses. Off by default: browsers that block
	// third-party cookies report every session as changed.
	CheckSessionIframe bool `json:"check_session_iframe,omitempty"`
}

type InteractionPolicy struct {
	LoginUIURL string `json:"login_ui_url,omitempty"`
}

type ImpersonationPolicy struct {
	Enabled             bool   `json:"enabled"`
	RequireTicket       bool   `json:"require_ticket"`
	Approval            string `json:"approval"` // none | second_operator | organization_owner | customer
	MaxTTLSeconds       int    `json:"max_ttl_seconds,omitempty"`
	NotifyCustomer      bool   `json:"notify_customer"`
	AllowCustomerOptOut bool   `json:"allow_customer_opt_out"`
}

type PasswordPolicy struct {
	MinLength              int  `json:"min_length,omitempty"`
	HistoryCount           int  `json:"history_count,omitempty"`
	RevokeSessionsOnChange bool `json:"revoke_sessions_on_change"`
}

type NotificationPolicy struct {
	NewLoginAlerts bool `json:"new_login_alerts"`
}

type WebAuthnPolicy struct {
	RPID             string   `json:"rp_id,omitempty"`
	RPName           string   `json:"rp_name,omitempty"`
	Origins          []string `json:"origins,omitempty"`
	AllowSynced      bool     `json:"allow_synced"`
	UserVerification string   `json:"user_verification,omitempty"`
	// Attestation is the attestation conveyance requested at registration
	// (PASS-009): none (default) asks for none, so registering reveals
	// nothing about the authenticator model; indirect, direct or
	// enterprise request it.
	Attestation string `json:"attestation,omitempty"`
	// RequireTrustedAttestation refuses a registration whose attestation
	// does not chain to trusted metadata for its AAGUID: the realm's trusted
	// authenticators or the operator's FIDO metadata (webauthn.metadata_file).
	// It needs attestation direct or enterprise.
	RequireTrustedAttestation bool `json:"require_trusted_attestation,omitempty"`
	// AllowedAAGUIDs, when set, admits only these authenticator models;
	// BlockedAAGUIDs refuses models (also at sign-in). An AAGUID is
	// self-reported unless the attestation is trusted.
	AllowedAAGUIDs []string `json:"allowed_aaguids,omitempty"`
	BlockedAAGUIDs []string `json:"blocked_aaguids,omitempty"`
	// RelatedOrigins (PASS-010) are origins outside the RP ID allowed to use
	// the realm's passkeys under WebAuthn Level 3 related origin requests,
	// published at https://{rp_id}/.well-known/webauthn. They need an
	// explicit rp_id and the operator's webauthn.related_origins switch;
	// clients without Level 3 support simply refuse them.
	RelatedOrigins []string `json:"related_origins,omitempty"`
	// CredentialProtection requests the CTAP 2.1 credProtect extension at
	// registration: userVerificationOptionalWithCredentialIDList or
	// userVerificationRequired. Enforced, an authenticator that does not
	// apply it is refused rather than accepted without it.
	CredentialProtection        string `json:"credential_protection,omitempty"`
	EnforceCredentialProtection bool   `json:"enforce_credential_protection,omitempty"`
}

type LifecyclePolicy struct {
	UnverifiedAccountTTLHours int `json:"unverified_account_ttl_hours,omitempty"`
	// DormantDays flags accounts without a sign-in for this many days
	// (0 disables the rule); DormantAction is "report" (default) or "suspend".
	DormantDays   int    `json:"dormant_days,omitempty"`
	DormantAction string `json:"dormant_action,omitempty"`
	// GuestTTLDays deletes guest accounts unused for this many days
	// (default 30).
	GuestTTLDays int `json:"guest_ttl_days,omitempty"`
}

// LifecycleRules converts the policy into account lifecycle rules (USR-015).
func (p Policy) LifecycleRules() identity.LifecycleRules {
	l := p.Lifecycle
	unverified := l.UnverifiedAccountTTLHours
	if unverified <= 0 {
		unverified = 72
	}
	guests := l.GuestTTLDays
	if guests <= 0 {
		guests = 30
	}
	return identity.LifecycleRules{UnverifiedTTL: time.Duration(unverified) * time.Hour, DormantAfter: time.Duration(l.DormantDays) * 24 * time.Hour,
		DormantAction: l.DormantAction, GuestTTL: time.Duration(guests) * 24 * time.Hour}
}

// DefaultPolicy is the safe default for new realms.
func DefaultPolicy() Policy {
	return Policy{
		Registration: RegistrationPolicy{
			Mode:                      RegistrationClosed,
			RequireEmailVerification:  true,
			AllowOrganizationCreation: false,
		},
		Login: LoginPolicy{Identifiers: []string{"email", "username"}, Password: true},
		MFA:   MFAPolicy{Requirement: MFAOptional, AllowedFactors: []string{"totp", "webauthn", "recovery_code"}},
		Impersonation: ImpersonationPolicy{
			Enabled: false, Approval: "none", NotifyCustomer: true, AllowCustomerOptOut: true,
		},
		Password:      PasswordPolicy{RevokeSessionsOnChange: true},
		Notifications: NotificationPolicy{NewLoginAlerts: false},
		WebAuthn:      WebAuthnPolicy{AllowSynced: true, UserVerification: "preferred"},
		Lifecycle:     LifecyclePolicy{UnverifiedAccountTTLHours: 72},
	}
}

// ParsePolicy decodes stored settings over defaults.
func ParsePolicy(raw []byte) Policy {
	p := DefaultPolicy()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	if p.MFA.Requirement == "" {
		p.MFA.Requirement = MFAOptional
	}
	if p.Registration.Mode == "" {
		p.Registration.Mode = RegistrationClosed
	}
	if p.Impersonation.Approval == "" {
		p.Impersonation.Approval = "none"
	}
	return p
}

// SessionBounds applies realm overrides within operator bounds: a realm may shorten
// but never lengthen operator lifetimes.
func (p Policy) SessionBounds(opIdle, opAbs time.Duration) (time.Duration, time.Duration) {
	idle, abs := opIdle, opAbs
	if p.Sessions.IdleSeconds > 0 && time.Duration(p.Sessions.IdleSeconds)*time.Second < idle {
		idle = time.Duration(p.Sessions.IdleSeconds) * time.Second
	}
	if p.Sessions.AbsoluteSeconds > 0 && time.Duration(p.Sessions.AbsoluteSeconds)*time.Second < abs {
		abs = time.Duration(p.Sessions.AbsoluteSeconds) * time.Second
	}
	return idle, abs
}

// MaxConcurrentSessions returns the effective per-user concurrent session
// limit: the realm may only tighten the operator limit.
func (p Policy) MaxConcurrentSessions(op int) int {
	if n := p.Sessions.MaxConcurrent; n > 0 && (op <= 0 || n < op) {
		return n
	}
	return op
}

// OrgPolicy is an organization override (TEN-012). Only tightening is honored.
// AuditPolicy scopes audit retention to the realm (AUD-009): evidence is
// kept at least RetentionDays, never less than the deployment's retention.
type AuditPolicy struct {
	RetentionDays int `json:"retention_days,omitempty"`
}

type OrgPolicy struct {
	// AuditRetentionDays keeps the organization's evidence longer than the
	// realm and deployment do (AUD-009); it never shortens retention.
	AuditRetentionDays     int      `json:"audit_retention_days,omitempty"`
	MFARequired            bool     `json:"mfa_required,omitempty"`
	AllowedLoginMethods    []string `json:"allowed_login_methods,omitempty"`
	SSORequired            bool     `json:"sso_required,omitempty"`
	SSOProviderID          string   `json:"sso_provider_id,omitempty"`
	SessionIdleSeconds     int      `json:"session_idle_seconds,omitempty"`
	SessionAbsoluteSeconds int      `json:"session_absolute_seconds,omitempty"`
	AllowedEmailDomains    []string `json:"allowed_email_domains,omitempty"`
	InvitationsEnabled     *bool    `json:"invitations_enabled,omitempty"`
	JoinRequestsEnabled    bool     `json:"join_requests_enabled,omitempty"`
	SupportAccessOptOut    bool     `json:"support_access_opt_out,omitempty"`
	ImpersonationApproval  string   `json:"impersonation_approval,omitempty"`
	// AllowedScopes, when set, is the organization's scope ceiling: tokens in
	// its context carry only these business scopes (TOK-008).
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	// RegistrationMode narrows realm registration for this organization's
	// context (REG-001): inherit (default), closed, invitation_only or
	// domain_restricted. It can only tighten the realm mode.
	RegistrationMode string `json:"registration_mode,omitempty"`
	// PersonalTokens set to "disabled" forbids personal access tokens in the
	// organization's context; PersonalTokenMaxDays caps their lifetime (MCH-006).
	PersonalTokens       string `json:"personal_tokens,omitempty"`
	PersonalTokenMaxDays int    `json:"personal_token_max_days,omitempty"`
}

// ParseOrgPolicy decodes an organization policy.
func ParseOrgPolicy(raw []byte) OrgPolicy {
	var p OrgPolicy
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	return p
}
