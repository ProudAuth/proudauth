// Package authentication implements server-controlled authentication transactions
// (§9), registration, recovery and factor management (§10).
//
// A transaction binds realm, client, redirect, PKCE challenge, requested
// organization/resources, required assurance, consent requirements and completed
// factors. Only the server marks steps complete (AUT-004); clients receive
// machine-readable next actions (AUT-002) and must present a transaction-bound
// continuation secret on every step (AUT-003).
package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/certauth"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/hooks"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/passkey"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

// Transaction statuses.
const (
	StatusPending   = "pending"
	StatusCompleted = "completed"
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"
	StatusFailed    = "failed"
)

// MaxFailures bounds failed proofs per transaction before restart is required.
const MaxFailures = 5

// Transaction mirrors auth_transactions.
type Transaction struct {
	ID                  string
	RealmID             string
	ClientRef           string
	Mode                string
	Intent              string
	ContinuationDigest  string
	CSRFDigest          string
	RedirectURI         string
	ResponseMode        string
	Scopes              []string
	ResourceIDs         []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string
	MaxAge              *int
	ACRValues           []string
	LoginHint           string
	UILocales           string
	RequestedOrgID      string
	InvitationID        string
	DeviceCodeID        string
	UserID              string
	IdentifiedVia       string
	Factors             []session.Factor
	ActionsDone         []string
	AuthTime            *time.Time
	SelectedOrgID       string
	GrantedScopes       []string
	ConsentDecided      bool
	RememberMe          bool
	SessionID           string
	ReusedSessionID     string
	Status              string
	FailureCount        int
	ClientIP            string
	UserAgent           string
	Pending             PendingState
	// deviceToken is the remembered-device secret presented with this request
	// (transient; never persisted).
	deviceToken string
	// flowChanged marks a new flow decision that must be saved.
	flowChanged bool
	ExpiresAt   time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
	Version     int64
}

// PendingState carries server-side intermediate state.
type PendingState struct {
	Identifier             string              `json:"identifier,omitempty"`
	IdentifierType         string              `json:"identifier_type,omitempty"`
	PhantomRegistration    bool                `json:"phantom_registration,omitempty"`
	RegistrationEmail      string              `json:"registration_email,omitempty"`
	CreateOrganization     *organization.Input `json:"create_organization,omitempty"`
	InvitationSecretDigest string              `json:"invitation_digest,omitempty"`
	InvitationSecretCT     []byte              `json:"invitation_ct,omitempty"`
	// InvitedOrgID is the organization of a registration invitation. The
	// invitation is accepted only when the transaction completes, after every
	// policy-required step (INV-006); until then it satisfies organization
	// selection for that organization.
	InvitedOrgID          string          `json:"invited_org_id,omitempty"`
	PendingTOTPCredential string          `json:"pending_totp,omitempty"`
	RecoveryCodesShown    bool            `json:"recovery_codes_shown,omitempty"`
	ExternalState         string          `json:"external_state,omitempty"`
	ExternalProvider      string          `json:"external_provider,omitempty"`
	WebAuthnSession       json.RawMessage `json:"webauthn_session,omitempty"`
	ErrorCode             string          `json:"error_code,omitempty"`
	StepUpOf              string          `json:"step_up_of,omitempty"`
	ClaimsRequest         string          `json:"claims_request,omitempty"`
	LoginOTPChallenge     string          `json:"login_otp_challenge,omitempty"`
	// SSORouted is set when identifier routing found an organization that
	// requires its enterprise connection (FED-012).
	SSORouted bool `json:"sso_routed,omitempty"`
	// PendingLink is an upstream identity awaiting proof of control of the
	// matching local account before it is linked (FED-004, FED-005).
	PendingLink *federation.Candidate `json:"pending_link,omitempty"`
	// ExternalError is a non-terminal upstream failure shown to the user.
	ExternalError string `json:"external_error,omitempty"`
	// RememberDevice records the user's opt-in to remember this device (AUT-013).
	RememberDevice bool `json:"remember_device,omitempty"`
	// Transient requests a non-persistent session without refresh authority
	// (SES-020), e.g. on a shared computer.
	Transient bool `json:"transient,omitempty"`
	// Flow is the authentication flow decision for the current account
	// (AUT-012), kept so risk hooks run once per sign-in.
	Flow *FlowDecision `json:"flow,omitempty"`
	// UpgradeProof records an existing second factor proved in this
	// transaction that the phishing-resistant profile does not accept
	// (MFA-006, SEC-012). It unlocks passkey registration and nothing else:
	// it is not a completed factor and never satisfies MFA.
	UpgradeProof *UpgradeProof `json:"upgrade_proof,omitempty"`
}

// UpgradeProof is the factor an account proved before registering its first
// user-verified passkey under the phishing-resistant profile.
type UpgradeProof struct {
	UserID       string    `json:"user_id"`
	Factor       string    `json:"factor"`
	CredentialID string    `json:"credential_id,omitempty"`
	At           time.Time `json:"at"`
}

func (t *Transaction) hasPrompt(p string) bool { return slices.Contains(t.Prompt, p) }

// Service is the authentication service.
type Service struct {
	d *runtime.Deps
	// AuthorizationResponse, when set, builds authorization responses in
	// JWT response modes (JARM, ADV-002); query responses need no hook.
	AuthorizationResponse func(ctx context.Context, realmID, clientRef, mode, redirectURI string, params map[string]string) (string, error)
	// Certs verifies user certificates for X.509 sign-in (PROV-016).
	Certs    *certauth.Service
	Realms   *realm.Service
	Apps     *application.Service
	Users    *identity.Service
	Sessions *session.Service
	Orgs     *organization.Service
	Authz    *authorization.Service
	Notify   *notification.Service
	Limiter  *ratelimit.Limiter
	Hasher   *credential.Hasher
	Policy   *credential.Policy
	Schema   func(realmID string) *identity.AttributeSchema
	// Federation brokers upstream sign-in (FED-001..013); nil disables it.
	Federation *federation.Service
	// Passkeys runs WebAuthn ceremonies (PASS-001..007); nil disables passkeys.
	Passkeys *passkey.Service
	// Hooks runs pre-action hooks (registration eligibility, profile
	// validation); nil disables them.
	Hooks *hooks.Service
	// Directory verifies passwords of directory-sourced accounts by a bind
	// against their directory and provisions accounts at first sign-in
	// (PROV-011, FED-015); nil disables directory sign-in.
	Directory DirectoryLogin
}

// NewService builds the service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

const txCols = `id, realm_id, client_ref, mode, intent, continuation_digest, coalesce(csrf_digest,''), coalesce(redirect_uri,''), response_mode,
	requested_scopes, requested_resource_ids, coalesce(state_param,''), coalesce(nonce,''), coalesce(code_challenge,''), coalesce(code_challenge_method,''),
	prompt, max_age, acr_values, coalesce(login_hint,''), coalesce(ui_locales,''), coalesce(requested_org_id,''), coalesce(invitation_id,''),
	coalesce(device_code_id,''), coalesce(user_id,''), coalesce(identified_via,''), completed_factors, required_actions_done, auth_time,
	coalesce(selected_org_id,''), granted_scopes, consent_decided, remember_me, coalesce(session_id,''), coalesce(reused_session_id,''), status,
	failure_count, coalesce(client_ip,''), coalesce(user_agent,''), pending_state, expires_at, completed_at, created_at, version`

func scanTx(row pgx.Row) (*Transaction, error) {
	var t Transaction
	var factors, pending []byte
	err := row.Scan(&t.ID, &t.RealmID, &t.ClientRef, &t.Mode, &t.Intent, &t.ContinuationDigest, &t.CSRFDigest, &t.RedirectURI, &t.ResponseMode,
		&t.Scopes, &t.ResourceIDs, &t.State, &t.Nonce, &t.CodeChallenge, &t.CodeChallengeMethod, &t.Prompt, &t.MaxAge, &t.ACRValues, &t.LoginHint,
		&t.UILocales, &t.RequestedOrgID, &t.InvitationID, &t.DeviceCodeID, &t.UserID, &t.IdentifiedVia, &factors, &t.ActionsDone, &t.AuthTime,
		&t.SelectedOrgID, &t.GrantedScopes, &t.ConsentDecided, &t.RememberMe, &t.SessionID, &t.ReusedSessionID, &t.Status, &t.FailureCount,
		&t.ClientIP, &t.UserAgent, &pending, &t.ExpiresAt, &t.CompletedAt, &t.CreatedAt, &t.Version)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(factors, &t.Factors)
	_ = json.Unmarshal(pending, &t.Pending)
	return &t, nil
}

// StartInput creates a transaction after the protocol layer validated the request (AUT-001).
type StartInput struct {
	RealmID         string
	Client          *application.Client
	Mode            string
	Intent          string
	RedirectURI     string
	ResponseMode    string
	Scopes          []string
	ResourceIDs     []string
	State           string
	Nonce           string
	CodeChallenge   string
	ChallengeMethod string
	Prompt          []string
	MaxAge          *int
	ACRValues       []string
	LoginHint       string
	UILocales       string
	OrgID           string
	InvitationID    string
	DeviceCodeID    string
	ClientIP        string
	UserAgent       string
	ReuseSession    *session.Session
	StepUpOf        string
	// ClaimsRequest is the validated OIDC claims parameter (OIDC-008).
	ClaimsRequest string
}

// Started is returned to the caller once.
type Started struct {
	Transaction  *Transaction
	Continuation string
	CSRF         string
}

// Start creates a transaction. Interaction-bound requests must carry an S256 PKCE
// challenge (TOK-002); the continuation secret is returned once and only its
// digest is stored.
func (s *Service) Start(ctx context.Context, in StartInput) (*Started, error) {
	if in.Client == nil || !in.Client.Active() {
		return nil, problem.ErrTransactionInvalid.WithDetail("client is not active")
	}
	if in.DeviceCodeID == "" {
		if in.CodeChallenge == "" || in.ChallengeMethod != "S256" {
			return nil, problem.ErrTransactionInvalid.WithDetail("PKCE with S256 is required")
		}
		if !application.MatchRedirect(in.Client.RedirectURIs, in.RedirectURI, in.Client.Type) {
			return nil, problem.ErrTransactionInvalid.WithDetail("redirect_uri is not registered")
		}
	}
	if in.Mode != "browser" && in.Mode != "headless" {
		in.Mode = "headless"
	}
	if in.Intent == "" {
		in.Intent = "login"
	}
	if in.ResponseMode == "" {
		in.ResponseMode = "query"
	}
	// Step-up for sensitive scopes (AUT-010): the scopes' assurance becomes a
	// requirement of this transaction and their authentication age bounds
	// session reuse, so an SSO session is stepped up (never downgraded) before
	// the scope is granted.
	if len(in.Scopes) > 0 && s.Apps != nil {
		defs, err := s.Apps.ScopesByName(ctx, nil, in.RealmID, in.Scopes)
		if err != nil {
			return nil, err
		}
		acr, maxAge := application.StepUp(defs)
		if acr != "" && !slices.Contains(in.ACRValues, acr) {
			in.ACRValues = append(slices.Clone(in.ACRValues), acr)
		}
		if maxAge > 0 && (in.MaxAge == nil || *in.MaxAge > maxAge) {
			in.MaxAge = &maxAge
		}
	}
	cont := secret.Token(secret.PrefixContinuation)
	csrf := ""
	var csrfDigest *string
	if in.Mode == "browser" {
		csrf = s.csrfFor(cont)
		d := secret.Digest(csrf)
		csrfDigest = &d
	}
	now := s.d.Now()
	t := &Transaction{ID: ids.New(ids.Transaction)}
	pending := PendingState{StepUpOf: in.StepUpOf, ClaimsRequest: in.ClaimsRequest}
	var userID *string
	var factors []session.Factor
	var authTime *time.Time
	var reused *string
	if sess := in.ReuseSession; sess != nil && !slices.Contains(in.Prompt, "login") {
		// Session reuse keeps the genuine authentication time and evidence (OIDC-004, AUT-017).
		fresh := in.MaxAge == nil || now.Sub(sess.AuthTime) <= time.Duration(*in.MaxAge)*time.Second
		// Per-client restriction (SES-002): a client may refuse SSO sessions older
		// than its own bound, whatever the request asks for.
		if limit := in.Client.TokenPolicy.MaxSessionAgeSeconds; limit > 0 && now.Sub(sess.AuthTime) > time.Duration(limit)*time.Second {
			fresh = false
		}
		if fresh {
			userID = &sess.UserID
			factors = sess.Factors
			at := sess.AuthTime
			authTime = &at
			reused = &sess.ID
		}
	}
	fj, _ := json.Marshal(nonNilFactors(factors))
	pj, _ := json.Marshal(pending)
	_, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO auth_transactions (id, realm_id, client_ref, mode, intent, continuation_digest, csrf_digest,
		redirect_uri, response_mode, requested_scopes, requested_resource_ids, state_param, nonce, code_challenge, code_challenge_method, prompt,
		max_age, acr_values, login_hint, ui_locales, requested_org_id, invitation_id, device_code_id, user_id, completed_factors, auth_time,
		reused_session_id, client_ip, user_agent, pending_state, expires_at, created_at, updated_at, identified_via)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$32,$33)`,
		t.ID, in.RealmID, in.Client.Ref, in.Mode, in.Intent, secret.Digest(cont), csrfDigest, nilIfEmpty(in.RedirectURI), in.ResponseMode,
		nonNil(in.Scopes), nonNil(in.ResourceIDs), nilIfEmpty(in.State), nilIfEmpty(in.Nonce), nilIfEmpty(in.CodeChallenge), nilIfEmpty(in.ChallengeMethod),
		nonNil(in.Prompt), in.MaxAge, nonNil(in.ACRValues), nilIfEmpty(truncate(in.LoginHint, 254)), nilIfEmpty(truncate(in.UILocales, 64)),
		nilIfEmpty(in.OrgID), nilIfEmpty(in.InvitationID), nilIfEmpty(in.DeviceCodeID), userID, fj, authTime, reused,
		nilIfEmpty(in.ClientIP), nilIfEmpty(truncate(in.UserAgent, 256)), pj, now.Add(s.d.Cfg.Tokens.TransactionTTL), now, map[bool]*string{true: strPtr("session"), false: nil}[reused != nil])
	if err != nil {
		return nil, err
	}
	tx, err := s.get(ctx, s.d.DB.Pool, in.RealmID, t.ID)
	if err != nil {
		return nil, err
	}
	return &Started{Transaction: tx, Continuation: cont, CSRF: csrf}, nil
}

func (s *Service) get(ctx context.Context, q storage.Querier, realmID, id string) (*Transaction, error) {
	t, err := scanTx(q.QueryRow(ctx, `SELECT `+txCols+` FROM auth_transactions WHERE realm_id=$1 AND id=$2`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrTransactionInvalid
		}
		return nil, err
	}
	return t, nil
}

// Proof is the continuation authority presented with each step.
type Proof struct {
	Continuation string
	CSRF         string
	// RememberedDevice is the device secret sent with the request (cookie or
	// X-Remembered-Device header), if any.
	RememberedDevice string
	// Browser is true when the continuation came from the transaction cookie; then
	// the CSRF token is mandatory (SEC-002).
	Browser bool
}

// lockTx loads a transaction FOR UPDATE and validates continuation authority,
// status and expiry (AUT-003, AUT-008). A transaction ID alone never suffices.
func (s *Service) lockTx(ctx context.Context, tx pgx.Tx, realmID, id string, p Proof) (*Transaction, error) {
	if !ids.Valid(id) {
		return nil, problem.ErrTransactionInvalid
	}
	t, err := scanTx(tx.QueryRow(ctx, `SELECT `+txCols+` FROM auth_transactions WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrTransactionInvalid
		}
		return nil, err
	}
	if p.Continuation == "" || !secret.Equal(secret.Digest(p.Continuation), t.ContinuationDigest) {
		return nil, problem.ErrTransactionInvalid
	}
	if t.Mode == "browser" && p.Browser {
		if p.CSRF == "" || !secret.Equal(s.csrfFor(p.Continuation), p.CSRF) {
			return nil, problem.ErrForbidden.WithDetail("missing or invalid CSRF token")
		}
	}
	if t.Mode == "headless" && p.Browser {
		return nil, problem.ErrTransactionInvalid
	}
	if t.Status != StatusPending {
		return nil, problem.ErrTransactionInvalid.WithDetail("the transaction is no longer active")
	}
	if !s.d.Now().Before(t.ExpiresAt) {
		_, _ = tx.Exec(ctx, `UPDATE auth_transactions SET status='expired' WHERE id=$1`, t.ID)
		return nil, problem.ErrTransactionExpired
	}
	return t, nil
}

// csrfFor derives the anti-forgery token from the continuation secret with a server
// key. The continuation lives in an HttpOnly cookie, so a cross-site attacker can
// neither read it nor compute the token (SEC-002).
func (s *Service) csrfFor(continuation string) string {
	return secret.PrefixCSRF + base64.RawURLEncoding.EncodeToString(s.d.Keys.DeriveBytes(keys.PurposeLookup, "csrf", continuation)[:24])
}

// CSRFToken returns the CSRF token for a browser transaction after validating the
// continuation cookie.
func (s *Service) CSRFToken(ctx context.Context, realmID, id string, p Proof) (string, error) {
	t, err := s.get(ctx, s.d.DB.Pool, realmID, id)
	if err != nil || t.Mode != "browser" || p.Continuation == "" || !secret.Equal(secret.Digest(p.Continuation), t.ContinuationDigest) {
		return "", problem.ErrTransactionInvalid
	}
	return s.csrfFor(p.Continuation), nil
}

// View loads a transaction for a GET (validated continuation, no mutation).
func (s *Service) View(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	var st *State
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// Locked like a step: a poll that saves a re-decided flow must not
		// overwrite a step running at the same time.
		t, err := scanTx(tx.QueryRow(ctx, `SELECT `+txCols+` FROM auth_transactions WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return problem.ErrTransactionInvalid
		}
		if p.Continuation == "" || !secret.Equal(secret.Digest(p.Continuation), t.ContinuationDigest) {
			return problem.ErrTransactionInvalid
		}
		if t.Status == StatusPending && !s.d.Now().Before(t.ExpiresAt) {
			return problem.ErrTransactionExpired
		}
		t.deviceToken = p.RememberedDevice
		if st, err = s.state(ctx, tx, t); err != nil {
			return err
		}
		if t.flowChanged {
			// Keep the decision so polling does not call risk hooks again.
			return s.save(ctx, tx, t)
		}
		return nil
	})
	return st, err
}

func (s *Service) save(ctx context.Context, tx pgx.Tx, t *Transaction) error {
	fj, _ := json.Marshal(nonNilFactors(t.Factors))
	pj, _ := json.Marshal(t.Pending)
	_, err := tx.Exec(ctx, `UPDATE auth_transactions SET intent=$18, user_id=$2, identified_via=$3, completed_factors=$4, required_actions_done=$5, auth_time=$6,
		selected_org_id=$7, granted_scopes=$8, consent_decided=$9, remember_me=$10, session_id=$11, status=$12, failure_count=$13, pending_state=$14,
		completed_at=$15, updated_at=$16, version=version+1, reused_session_id=$17, requested_org_id=$19 WHERE id=$1`, t.ID, nilIfEmpty(t.UserID), nilIfEmpty(t.IdentifiedVia),
		fj, nonNil(t.ActionsDone), t.AuthTime, nilIfEmpty(t.SelectedOrgID), t.GrantedScopes, t.ConsentDecided, t.RememberMe, nilIfEmpty(t.SessionID),
		t.Status, t.FailureCount, pj, t.CompletedAt, s.d.Now(), nilIfEmpty(t.ReusedSessionID), t.Intent, nilIfEmpty(t.RequestedOrgID))
	return err
}

// ---------- next actions ----------

// Action is a machine-readable next step (AUT-002).
type Action struct {
	Type     string         `json:"type"`
	Required bool           `json:"required"`
	Fields   []string       `json:"fields,omitempty"`
	Options  map[string]any `json:"options,omitempty"`
}

// State is the client-visible transaction state.
type State struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Intent      string         `json:"intent"`
	Client      map[string]any `json:"client"`
	NextActions []Action       `json:"next_actions"`
	Completed   []string       `json:"completed_factors"`
	User        map[string]any `json:"user,omitempty"`
	RedirectTo  string         `json:"redirect_to,omitempty"`
	Error       string         `json:"error,omitempty"`
	CSRF        string         `json:"csrf_token,omitempty"`
	Locale      string         `json:"locale,omitempty"`
	// Secrets displayed exactly once (e.g. new recovery codes).
	OneTime map[string]any `json:"one_time,omitempty"`
	// WebAuthn carries ceremony options for the client (not secret).
	WebAuthn any `json:"webauthn,omitempty"`
	// ExternalRedirect is the upstream authorization URL the browser must visit.
	ExternalRedirect string `json:"external_redirect,omitempty"`
	// Notice is a non-terminal condition to show (e.g. upstream_unavailable).
	Notice string `json:"notice,omitempty"`
	// Internal completion artifacts (not serialized).
	SessionCookie string      `json:"-"`
	Completion    *Completion `json:"-"`
}

// codeFactor reports an enrolled code factor (TOTP or HOTP) usable here: the
// phishing-resistant profile excludes both.
func (r *requirements) codeFactor() bool { return (r.hasTOTP || r.hasHOTP) && !r.phishingResistant }

// requirements describes what remains before issuance (AUT-006).
type requirements struct {
	user        *identity.User
	primaryDone bool
	mfaRequired bool
	mfaDone     bool
	hasTOTP     bool
	// hasHOTP: an active counter-based token in a realm that allows HOTP
	// (MFA-013).
	hasHOTP    bool
	hasPasskey bool
	// hasVerifiedPasskey: an active passkey that has completed a ceremony
	// with user verification, so it can meet the phishing-resistant profile.
	hasVerifiedPasskey bool
	hasRecovery        bool
	// totpDisallowed: the realm's allowed factors exclude TOTP (MFA-005).
	totpDisallowed bool
	// phishingResistant requires a user-verified passkey as the second factor and
	// excludes TOTP and recovery codes (SEC-012, admin_phishing_resistant policy or
	// an acr_values request for phishing resistance).
	phishingResistant bool
	// upgrade: the phishing-resistant profile applies, the account holds no
	// user-verified passkey but holds another second factor, and that factor
	// has not been proved in this transaction yet. Until it is, passkey
	// registration is not offered (MFA-006): whoever holds only the password
	// must not enroll a passkey of their own making (UpgradeProof).
	upgrade bool
	// mfaPrompt: MFA is pending and an enrolled factor can satisfy it.
	mfaPrompt        bool
	deviceRemembered string
	selectAccount    bool
	passkeysEnabled  bool
	actions          []string
	needOrg          bool
	orgOptions       []map[string]any
	needConsent      bool
	consentScopes    []application.Scope
	ssoRequired      bool
	ssoProviderID    string
	// cancelDeletion: a pending-deletion account completed every factor it
	// needs; its only possible action is cancel_deletion (USR-012).
	cancelDeletion bool
	blocked        string
	// flowChallenge: the authentication flow asks for a challenge (SEC-014);
	// challenge is set once nothing else is pending, with its options.
	flowChallenge     bool
	challenge         bool
	challengeProvider *configuration.ChallengeProviderConfig
	challengeEmail    bool
}

func (s *Service) evaluate(ctx context.Context, q storage.Querier, t *Transaction) (*requirements, error) {
	r := &requirements{}
	rlm, err := s.Realms.ByID(ctx, q, t.RealmID)
	if err != nil {
		return nil, err
	}
	client, err := s.Apps.ClientByRef(ctx, q, t.RealmID, t.ClientRef)
	if err != nil {
		return nil, err
	}
	if t.UserID == "" {
		return r, nil
	}
	u, err := s.Users.User(ctx, q, t.RealmID, t.UserID)
	if err != nil {
		return nil, err
	}
	r.user = u
	// prompt=select_account: a reused SSO session needs the user to confirm the
	// account (or switch) before anything else (OIDC-005, AUT-011).
	if t.hasPrompt("select_account") && t.ReusedSessionID != "" && !slices.Contains(t.ActionsDone, "select_account") {
		r.selectAccount = true
		return r, nil
	}
	_, mfa := session.AMRFromFactors(t.Factors)
	r.mfaDone = mfa != nil
	for _, f := range t.Factors {
		switch f.Type {
		case "pwd", "otp", "magic_link", "fed", "sms", "anon", "x509":
			r.primaryDone = true
		case "hwk", "swk":
			r.primaryDone = true
		}
	}
	if !r.primaryDone {
		return r, nil
	}
	if u.State == identity.StatePendingVerification {
		r.actions = append(r.actions, identity.ActionVerifyEmail)
		return r, nil
	}
	// A pending-deletion account is evaluated like any other until its factors
	// are done, then held at cancel_deletion (below, USR-012).
	if !u.CanAuthenticate(s.d.Now()) && !u.MayCancelDeletion(s.d.Now()) {
		r.blocked = "account_unavailable"
		return r, nil
	}
	// Enrolled factors.
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'),
		EXISTS (SELECT 1 FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active'),
		EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=$1 AND state='active'),
		EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=$1 AND state='active' AND user_verified),
		EXISTS (SELECT 1 FROM recovery_codes WHERE user_id=$1 AND state='active')`, u.ID).Scan(&r.hasTOTP, &r.hasHOTP, &r.hasPasskey,
		&r.hasVerifiedPasskey, &r.hasRecovery); err != nil {
		return nil, err
	}
	// Factor policy (MFA-005, MFA-013): factors the realm does not allow
	// never satisfy MFA and never make it required, even when enrolled; an
	// MFA requirement then needs an allowed one. Every narrowing happens
	// before the requirement is computed, so an enrolled factor the realm no
	// longer offers cannot leave the transaction waiting for a step it never
	// offers. HOTP is opt-in: it counts only while the realm lists it.
	r.passkeysEnabled = s.Passkeys != nil && rlm.Policy.PasskeysEnabled()
	r.hasHOTP = r.hasHOTP && rlm.Policy.MFA.HOTPAllowed()
	if !rlm.Policy.MFA.TOTPAllowed() {
		r.hasTOTP, r.totpDisallowed = false, true
	}
	if allowed := rlm.Policy.MFA.AllowedFactors; len(allowed) > 0 && !slices.Contains(allowed, "recovery_code") {
		r.hasRecovery = false
	}
	r.hasPasskey = r.hasPasskey && r.passkeysEnabled
	r.hasVerifiedPasskey = r.hasVerifiedPasskey && r.passkeysEnabled
	// MFA requirement (MFA-003, MFA-005, TEN-012).
	privileged, err := s.Authz.HoldsPrivilegedRealmRole(ctx, q, t.RealmID, u.ID)
	if err != nil {
		return nil, err
	}
	floor := s.d.Cfg.Security.MFAFloor
	r.mfaRequired = rlm.Policy.MFA.Requirement == realm.MFARequired || floor.Require == "all" || r.hasTOTP || r.hasHOTP || privileged || u.Protected ||
		client.TokenPolicy.RequireMFA || slices.ContainsFunc(t.ACRValues, func(a string) bool { return strings.Contains(a, "mfa") || strings.Contains(a, "phishing_resistant") })
	r.phishingResistant = r.passkeysEnabled && (((rlm.Policy.MFA.AdminPhishingResistant || floor.AdminPhishingResistant) && (privileged || u.Protected)) ||
		slices.ContainsFunc(t.ACRValues, func(a string) bool { return strings.Contains(a, "phishing_resistant") }))
	if r.phishingResistant {
		r.mfaRequired = true
		r.mfaDone = session.ACRFor(t.Factors) == session.ACRPhishingResistant
	}
	if r.mfaRequired && !r.mfaDone && t.deviceToken != "" &&
		rememberAllowed(rlm, t, r, privileged, u.Protected, client.TokenPolicy.RequireMFA) {
		if id := s.rememberedDevice(ctx, q, t.RealmID, u.ID, t.deviceToken); id != "" {
			// The prompt is skipped; no factor or assurance is added (AUT-013).
			r.mfaDone, r.deviceRemembered = true, id
		}
	}
	for _, rid := range t.ResourceIDs {
		if res, err := s.Apps.Resource(ctx, q, t.RealmID, rid); err == nil && res.Kind == application.KindAdmin {
			r.mfaRequired = true
		}
	}
	orgID := t.SelectedOrgID
	if orgID == "" {
		orgID = t.RequestedOrgID
	}
	if orgID != "" && s.ForeignConnection(ctx, q, t.RealmID, t.Factors, orgID) {
		r.blocked = "connection_not_allowed"
		return r, nil
	}
	if orgID != "" {
		if org, err := s.Orgs.Get(ctx, q, t.RealmID, orgID); err == nil {
			if org.Policy.MFARequired {
				r.mfaRequired = true
			}
			// Organization sign-in methods (TEN-012): a primary method the
			// organization does not allow cannot complete a login into it.
			if methods := org.Policy.AllowedLoginMethods; len(methods) > 0 && primaryDone(t) &&
				!slices.ContainsFunc(t.Factors, func(f session.Factor) bool { return slices.Contains(methods, loginMethodOf(f.Type)) }) {
				r.blocked = "login_method_not_allowed"
				return r, nil
			}
			if org.Policy.SSORequired && !slices.ContainsFunc(t.Factors, func(f session.Factor) bool {
				return f.Type == "fed" && (org.Policy.SSOProviderID == "" || f.Upstream == org.Policy.SSOProviderID)
			}) {
				r.ssoRequired = true
				r.ssoProviderID = org.Policy.SSOProviderID
			}
		}
	}
	// Authentication flow rules (AUT-012, AUT-014), decided once per account
	// and organization context and re-decided when the realm policy changes.
	if len(rlm.Policy.AuthFlow.Rules) > 0 {
		if d := t.Pending.Flow; d == nil || d.UserID != u.ID || d.OrgID != orgID || d.PolicyRevision != rlm.PolicyRevision {
			t.Pending.Flow = s.decideFlow(ctx, q, t, rlm, client, u, privileged, orgID)
			t.flowChanged = true
			// A challenge this account already answered in this transaction
			// stays answered when the organization context changes.
			if d != nil && d.UserID == u.ID && d.ChallengePassed {
				t.Pending.Flow.ChallengePassed = true
			}
		}
		if s.applyFlow(t, r) {
			return r, nil
		}
	}
	// Guests are low-privilege (REG-010): any context that needs MFA (an
	// administrative resource, a protected client or MFA-required realm) is
	// closed to them.
	if u.IsGuest && r.mfaRequired {
		r.blocked = "guest_not_permitted"
		return r, nil
	}
	// A flow challenge is met by a factor already enrolled or an explicit
	// challenge answer, before any factor can be enrolled in this transaction:
	// whoever holds only the first factor cannot answer it with a factor of
	// their own making. With no way to answer it, the login cannot continue.
	if r.flowChallenge && !r.mfaDone {
		s.challengeOptions(rlm, r)
		if r.challengeProvider == nil && !r.challengeEmail && !(r.hasPasskey && r.passkeysEnabled) && !r.codeFactor() {
			r.blocked = "authentication_policy_denied"
			return r, nil
		}
		r.challenge = true
		return r, nil
	}
	switch {
	case r.phishingResistant && !r.mfaDone && !r.hasVerifiedPasskey:
		// The phishing-resistant profile applies and no enrolled passkey can
		// meet it: the account registers one in the transaction (SEC-012).
		// An account that already holds another second factor (TOTP, HOTP,
		// recovery codes, or a passkey never used with user verification)
		// proves it first (MFA-006): someone holding only the password must
		// not register a passkey of their own making and take over the
		// account. The proof unlocks registration only; it is not MFA.
		hasOther := r.hasTOTP || r.hasHOTP || r.hasRecovery || r.hasPasskey
		if hasOther && (t.Pending.UpgradeProof == nil || t.Pending.UpgradeProof.UserID != u.ID) {
			r.upgrade = true
			return r, nil
		}
		r.actions = append(r.actions, identity.ActionConfigureTOTP)
	case r.mfaRequired && !r.mfaDone && (r.hasPasskey || r.codeFactor()):
		r.mfaPrompt = true
		return r, nil
	case r.mfaRequired && !r.mfaDone:
		// Required but not enrolled: enroll within the transaction (MFA-003).
		r.actions = append(r.actions, identity.ActionConfigureTOTP)
	}
	if u.State == identity.StatePendingDeletion {
		// Every factor the account needs is done (with an enrollment the
		// realm requires first): the owner can see when the deletion is due
		// and cancel it, nothing else. No session, code or token is issued
		// while the deletion is pending (USR-012).
		if len(r.actions) == 0 {
			r.cancelDeletion = true
		}
		return r, nil
	}
	for _, a := range u.RequiredActions {
		if a == identity.ActionVerifyEmail && hasVerifiedEmail(u) {
			continue
		}
		if !slices.Contains(t.ActionsDone, a) && !slices.Contains(r.actions, a) {
			r.actions = append(r.actions, a)
		}
	}
	if v := rlm.Policy.Registration.TermsVersion; v != "" && !slices.Contains(t.ActionsDone, identity.ActionAcceptTerms) {
		var accepted bool
		_ = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM terms_acceptances WHERE user_id=$1 AND document='terms' AND version=$2)`, u.ID, v).Scan(&accepted)
		if !accepted && !slices.Contains(r.actions, identity.ActionAcceptTerms) {
			r.actions = append(r.actions, identity.ActionAcceptTerms)
		}
	}
	if schema := s.schema(t.RealmID); schema != nil && len(schema.Missing(u.Profile)) > 0 && !slices.Contains(r.actions, identity.ActionCompleteProfile) {
		r.actions = append(r.actions, identity.ActionCompleteProfile)
	}
	if len(r.actions) > 0 {
		return r, nil
	}
	// Registration approval queue (REG-008): after email verification, nothing completes until
	// a reviewer approves the account.
	var awaitingApproval bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM registration_approvals WHERE user_id=$1 AND state<>'approved')`, u.ID).Scan(&awaitingApproval); err != nil {
		return nil, err
	}
	if awaitingApproval {
		r.blocked = "registration_pending_approval"
		return r, nil
	}
	// Organization context (DOM-003, TEN-005).
	needsOrg := false
	for _, rid := range t.ResourceIDs {
		res, err := s.Apps.Resource(ctx, q, t.RealmID, rid)
		if err != nil {
			return nil, err
		}
		if res.RequiresOrganization {
			needsOrg = true
		}
	}
	if needsOrg && t.SelectedOrgID == "" && t.RequestedOrgID != "" {
		// An explicitly requested organization binds automatically once membership is
		// confirmed; a requested organization the user does not belong to blocks the
		// transaction instead of silently switching tenant (TEN-005, TEST-008).
		if _, err := s.Orgs.ActiveMembership(ctx, q, t.RealmID, t.RequestedOrgID, u.ID); err != nil {
			r.blocked = "organization_access_denied"
			return r, nil
		}
		t.SelectedOrgID = t.RequestedOrgID
	}
	if needsOrg && u.IsGuest {
		r.blocked = "guest_not_permitted" // guests hold no organization access
		return r, nil
	}
	if needsOrg && t.SelectedOrgID == "" && len(t.Pending.InvitationSecretCT) > 0 && t.Pending.InvitedOrgID != "" {
		needsOrg = false // bound at completion, when the invitation is accepted
	}
	if needsOrg && t.SelectedOrgID == "" {
		r.needOrg = true
		mems, err := s.Orgs.UserMemberships(ctx, t.RealmID, u.ID)
		if err != nil {
			return nil, err
		}
		for _, m := range mems {
			if m["membership_state"] == "active" && m["organization_state"] == "active" {
				r.orgOptions = append(r.orgOptions, map[string]any{"organization_id": m["organization_id"], "display_name": m["display_name"], "slug": m["slug"]})
			}
		}
		if len(r.orgOptions) == 0 {
			// Nothing to select: the request needs an organization and the
			// user belongs to none, so the transaction says so instead of
			// offering an empty choice it can never leave (TEN-005).
			r.needOrg = false
			r.blocked = "no_organization"
		}
		return r, nil
	}
	if r.ssoRequired {
		return r, nil
	}
	// Consent (APP-013). Offline access by a third-party client always needs the
	// user's explicit consent, independent of remember-me (OIDC-012, SES-021).
	offlineConsent := slices.Contains(t.Scopes, "offline_access") && client.AllowOfflineAccess && !client.FirstParty
	if (client.ConsentMode == "required" || t.hasPrompt("consent") || offlineConsent) && !t.ConsentDecided {
		covered := false
		if !t.hasPrompt("consent") {
			// A live consent covers the request when it includes every requested
			// scope and was given for the client's current terms version.
			var scopes []string
			var terms string
			err := q.QueryRow(ctx, `SELECT scopes, coalesce(terms_version,'') FROM consents WHERE user_id=$1 AND client_ref=$2 AND revoked_at IS NULL`,
				u.ID, t.ClientRef).Scan(&scopes, &terms)
			if err == nil && terms == client.ConsentTermsVersion {
				covered = !slices.ContainsFunc(t.Scopes, func(sc string) bool { return !slices.Contains(scopes, sc) })
			}
			// An administrator may pre-authorize the client for the realm or for
			// the organization the user signs in to (APP-013); offline access by a
			// third-party client still needs the user's own consent.
			if !covered && !offlineConsent {
				id, err := s.consentPreauthorization(ctx, q, t, client)
				if err != nil {
					return nil, err
				}
				covered = id != ""
			}
		}
		if !covered {
			r.needConsent = true
			byName, err := s.Apps.ScopesByName(ctx, q, t.RealmID, t.Scopes)
			if err != nil {
				return nil, err
			}
			for _, name := range t.Scopes {
				if sc, ok := byName[name]; ok {
					r.consentScopes = append(r.consentScopes, sc)
				}
			}
		}
	}
	return r, nil
}

// consentPreauthorization returns the live administrative pre-authorization
// covering the transaction's client, organization, scopes and terms, if any.
func (s *Service) consentPreauthorization(ctx context.Context, q storage.Querier, t *Transaction, client *application.Client) (string, error) {
	org := t.SelectedOrgID
	if org == "" {
		org = t.RequestedOrgID
	}
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM consent_preauthorizations WHERE realm_id=$1 AND client_ref=$2 AND revoked_at IS NULL
		AND (organization_id IS NULL OR organization_id=$3) AND scopes @> $4 AND coalesce(terms_version,'') = $5
		ORDER BY organization_id NULLS LAST, granted_at LIMIT 1`, t.RealmID, t.ClientRef, org, nonNil(t.Scopes), client.ConsentTermsVersion).Scan(&id)
	if storage.IsNoRows(err) {
		return "", nil
	}
	return id, err
}

func hasVerifiedEmail(u *identity.User) bool {
	for _, i := range u.Identifiers {
		if i.Type == "email" && i.Verified() {
			return true
		}
	}
	return false
}

func (s *Service) schema(realmID string) *identity.AttributeSchema {
	if s.Schema == nil {
		return nil
	}
	return s.Schema(realmID)
}

// state renders next actions for the client.
func (s *Service) state(ctx context.Context, q storage.Querier, t *Transaction) (*State, error) {
	client, err := s.Apps.ClientByRef(ctx, q, t.RealmID, t.ClientRef)
	if err != nil {
		return nil, err
	}
	st := &State{ID: t.ID, Status: t.Status, ExpiresAt: t.ExpiresAt, Intent: t.Intent, Locale: t.UILocales,
		Client: map[string]any{"client_id": client.ClientID, "name": client.Name}, NextActions: []Action{}, Completed: []string{}}
	for _, f := range t.Factors {
		st.Completed = append(st.Completed, f.Type)
	}
	if t.Status != StatusPending {
		st.Error = t.Pending.ErrorCode
		return st, nil
	}
	st.Notice = t.Pending.ExternalError
	r, err := s.evaluate(ctx, q, t)
	if err != nil {
		return nil, err
	}
	rlm, err := s.Realms.ByID(ctx, q, t.RealmID)
	if err != nil {
		return nil, err
	}
	add := func(a Action) { st.NextActions = append(st.NextActions, a) }
	if r.blocked != "" {
		st.Error = r.blocked
		return st, nil
	}
	if r.user != nil && r.primaryDone {
		st.User = map[string]any{"display_name": r.user.DisplayName}
		if e := r.user.PrimaryEmail(); e != nil {
			st.User["email_hint"] = identity.Mask("email", e.Value)
		}
	}
	switch {
	case r.selectAccount:
		cur := map[string]any{"display_name": r.user.DisplayName}
		if e := r.user.PrimaryEmail(); e != nil {
			cur["email_hint"] = identity.Mask("email", e.Value)
		}
		add(Action{Type: "select_account", Required: true, Fields: []string{"continue"}, Options: map[string]any{"current_account": cur}})
	case t.Intent == "register" && t.UserID == "" && !t.Pending.PhantomRegistration:
		add(Action{Type: "register", Required: true, Fields: []string{"email", "password", "username", "given_name", "family_name", "terms_version", "organization"}})
	case t.Pending.PhantomRegistration:
		add(Action{Type: "verify_email", Required: true, Fields: []string{"code"}, Options: map[string]any{"resend": true}})
	case !r.primaryDone && t.Pending.SSORouted && t.Pending.ExternalProvider != "" && t.Pending.PendingLink == nil:
		// The organization requires its enterprise connection: no local password
		// fallback is offered, even when the upstream is failing (FED-012).
		add(Action{Type: "external_redirect", Required: true, Options: map[string]any{"reason": "sso_required",
			"providers": s.providerOptions(ctx, q, t, t.Pending.ExternalProvider)}})
	case !r.primaryDone:
		if l := t.Pending.PendingLink; l != nil {
			opts := map[string]any{"provider_id": l.ProviderID}
			if l.Email != "" {
				opts["email_hint"] = identity.Mask("email", l.Email)
			}
			add(Action{Type: "link_account", Required: true, Options: opts})
		}
		if rlm.Policy.Login.Certificates && s.Certs != nil {
			// X.509 sign-in (PROV-016): the login surface submits this step
			// over the mutual-TLS endpoint, which receives the certificate.
			add(Action{Type: "certificate", Required: false})
		}
		if t.Pending.Identifier == "" {
			add(Action{Type: "identify", Required: true, Fields: []string{"identifier"}})
			if rlm.Policy.Login.Passkeys && s.Passkeys != nil {
				add(Action{Type: "webauthn", Required: false, Options: map[string]any{"discoverable": true}})
			}
			if provs := s.providerOptions(ctx, q, t, ""); len(provs) > 0 {
				add(Action{Type: "external_redirect", Required: false, Options: map[string]any{"providers": provs}})
			}
		} else {
			if rlm.Policy.Login.Password {
				add(Action{Type: "password", Required: false, Fields: []string{"password"}})
			}
			if rlm.Policy.Login.EmailOTP && t.Pending.IdentifierType == "email" {
				add(Action{Type: "email_otp", Required: false, Fields: []string{"code"}, Options: map[string]any{"send_required": t.Pending.LoginOTPChallenge == ""}})
			}
			if rlm.Policy.Login.MagicLink && t.Pending.IdentifierType == "email" && s.magicLinkBase(ctx, q, t, rlm) != "" {
				add(Action{Type: "magic_link", Required: false, Fields: []string{"token"}, Options: map[string]any{"send_purpose": "magic_link"}})
			}
			if rlm.Policy.Login.SMSOTP && t.Pending.IdentifierType == "phone" && s.Notify != nil && s.Notify.SMSEnabled() {
				add(Action{Type: "sms_otp", Required: false, Fields: []string{"code"}, Options: map[string]any{"send_required": t.Pending.LoginOTPChallenge == ""}})
			}
			if rlm.Policy.Login.Passkeys && s.Passkeys != nil {
				add(Action{Type: "webauthn", Required: false})
			}
			if t.Pending.PendingLink == nil {
				if provs := s.providerOptions(ctx, q, t, ""); len(provs) > 0 {
					add(Action{Type: "external_redirect", Required: false, Options: map[string]any{"providers": provs}})
				}
			}
		}
	case r.challenge:
		opts := map[string]any{}
		if p := r.challengeProvider; p != nil {
			opts["provider"] = map[string]any{"name": p.Name, "site_key": p.SiteKey}
		}
		if r.challengeEmail {
			opts["email_code"] = map[string]any{"send_required": t.Pending.Flow.ChallengeCode == ""}
		}
		if len(opts) > 0 {
			add(Action{Type: "challenge", Required: true, Fields: []string{"provider_response", "code"}, Options: opts})
		}
		if r.hasPasskey && r.passkeysEnabled {
			add(Action{Type: "webauthn", Required: len(opts) == 0})
		}
		if r.hasTOTP && !r.phishingResistant {
			add(Action{Type: "totp", Required: false, Fields: []string{"code"}})
		}
		if r.hasHOTP && !r.phishingResistant {
			add(Action{Type: "hotp", Required: false, Fields: []string{"code"}})
		}
	case len(r.actions) > 0 && r.actions[0] == identity.ActionVerifyEmail:
		add(Action{Type: "verify_email", Required: true, Fields: []string{"code"}, Options: map[string]any{"resend": true}})
	case r.upgrade:
		// Upgrade proof (MFA-006, SEC-012): an existing second factor the
		// profile does not accept unlocks passkey registration; a passkey
		// that answers with user verification meets the profile directly.
		upgrade := map[string]any{"upgrade_proof": true}
		if r.hasPasskey {
			add(Action{Type: "webauthn", Required: false, Options: map[string]any{"upgrade_proof": true, "user_verification_required": false}})
		}
		if r.hasTOTP {
			add(Action{Type: "totp", Required: false, Fields: []string{"code"}, Options: upgrade})
		}
		if r.hasHOTP {
			add(Action{Type: "hotp", Required: false, Fields: []string{"code"}, Options: upgrade})
		}
		if r.hasRecovery {
			add(Action{Type: "recovery_code", Required: false, Fields: []string{"code"}, Options: upgrade})
		}
	case r.mfaPrompt:
		if r.hasTOTP && !r.phishingResistant {
			add(Action{Type: "totp", Required: false, Fields: []string{"code"}})
		}
		if r.hasHOTP && !r.phishingResistant {
			add(Action{Type: "hotp", Required: false, Fields: []string{"code"}})
		}
		if rlm.Policy.Login.RememberDevices && !r.phishingResistant {
			add(Action{Type: "remember_device", Required: false, Fields: []string{"remember"}, Options: map[string]any{"selected": t.Pending.RememberDevice,
				"days": RememberDays(rlm.Policy)}})
		}
		if r.hasPasskey && r.passkeysEnabled {
			add(Action{Type: "webauthn", Required: false, Options: map[string]any{"user_verification_required": r.phishingResistant}})
		}
		if r.hasRecovery && !r.phishingResistant {
			add(Action{Type: "recovery_code", Required: false, Fields: []string{"code"}})
		}
	case r.cancelDeletion:
		// The only capability of a pending-deletion account (USR-012): read
		// when the deletion is due, and cancel it (or abandon the sign-in).
		opts := map[string]any{}
		if r.user.DeletionScheduledAt != nil {
			opts["deletion_scheduled_at"] = r.user.DeletionScheduledAt
		}
		if r.user.DeletionRequestedAt != nil {
			opts["deletion_requested_at"] = r.user.DeletionRequestedAt
		}
		add(Action{Type: "cancel_deletion", Required: true, Options: opts})
	case len(r.actions) > 0:
		for _, a := range r.actions {
			switch a {
			case identity.ActionConfigureTOTP:
				// Either enrollment satisfies the MFA requirement; the phishing-resistant
				// profile accepts only a passkey (SEC-012).
				if !r.phishingResistant && !r.totpDisallowed {
					add(Action{Type: "enroll_totp", Required: !r.passkeysEnabled, Options: map[string]any{"started": t.Pending.PendingTOTPCredential != ""}})
				}
				if r.passkeysEnabled {
					add(Action{Type: "enroll_webauthn", Required: r.phishingResistant, Options: map[string]any{"user_verification_required": r.phishingResistant}})
				}
				if r.totpDisallowed && !r.passkeysEnabled {
					// Nothing can be enrolled (a realm policy saved before
					// ValidatePolicy refused such factor lists): say so
					// instead of waiting for a step that is never offered.
					st.Error, st.NextActions = "mfa_enrollment_unavailable", []Action{}
					return st, nil
				}
			case identity.ActionVerifyEmail:
				add(Action{Type: "verify_email", Required: true, Fields: []string{"code"}, Options: map[string]any{"resend": true}})
			case identity.ActionVerifyContact:
				opts := map[string]any{"send_purpose": "verify_contact"}
				if r.user != nil {
					if e := r.user.PrimaryEmail(); e != nil {
						opts["identifier"] = identity.Mask("email", e.Value)
					}
				}
				add(Action{Type: "verify_contact", Required: true, Fields: []string{"code"}, Options: opts})
			case identity.ActionUpdatePassword:
				add(Action{Type: "update_password", Required: true, Fields: []string{"new_password"}})
			case identity.ActionAcceptTerms:
				add(Action{Type: "accept_terms", Required: true, Fields: []string{"version"}, Options: map[string]any{"version": rlm.Policy.Registration.TermsVersion}})
			case identity.ActionCompleteProfile:
				missing := []string{}
				if sch := s.schema(t.RealmID); sch != nil && r.user != nil {
					missing = sch.Missing(r.user.Profile)
				}
				add(Action{Type: "complete_profile", Required: true, Fields: missing})
			}
		}
	case r.needOrg:
		add(Action{Type: "select_organization", Required: true, Options: map[string]any{"organizations": nonNilOptions(r.orgOptions)}})
	case r.ssoRequired:
		add(Action{Type: "external_redirect", Required: true, Options: map[string]any{"reason": "sso_required",
			"providers": s.providerOptions(ctx, q, t, r.ssoProviderID)}})
	case r.needConsent:
		scopes := []map[string]any{}
		for _, sc := range r.consentScopes {
			scopes = append(scopes, map[string]any{"name": sc.Name, "description": sc.ConsentText, "sensitivity": sc.Sensitivity})
		}
		opts := map[string]any{"scopes": scopes}
		if client, err := s.Apps.ClientByRef(ctx, q, t.RealmID, t.ClientRef); err == nil && client.ConsentTermsVersion != "" {
			opts["terms_version"] = client.ConsentTermsVersion
		}
		add(Action{Type: "consent", Required: true, Fields: []string{"approve", "scopes"}, Options: opts})
	default:
		add(Action{Type: "complete", Required: true})
	}
	return st, nil
}

// providerOptions lists the connections usable in this transaction: realm-wide
// connections, plus organization connections for the requested organization.
// With only set, just that connection is returned.
func (s *Service) providerOptions(ctx context.Context, q storage.Querier, t *Transaction, only string) []map[string]any {
	out := []map[string]any{}
	if s.Federation == nil {
		return out
	}
	list, err := s.Federation.List(ctx, q, t.RealmID, true)
	if err != nil {
		return out
	}
	for _, p := range list {
		if only != "" && p.ID != only {
			continue
		}
		if only == "" && p.OrganizationID != "" && p.OrganizationID != t.RequestedOrgID && p.OrganizationID != t.SelectedOrgID {
			continue
		}
		out = append(out, map[string]any{"id": p.ID, "alias": p.Alias, "display_name": p.DisplayName})
	}
	return out
}

func nonNilOptions(o []map[string]any) []map[string]any {
	if o == nil {
		return []map[string]any{}
	}
	return o
}

// ---------- helpers ----------

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strPtr(s string) *string { return &s }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilFactors(f []session.Factor) []session.Factor {
	if f == nil {
		return []session.Factor{}
	}
	return f
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence, and
// drops invalid sequences (they cannot be stored as text).
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func actorFor(t *Transaction) audit.Ref {
	if t.UserID != "" {
		return audit.Ref{Type: "user", ID: t.UserID}
	}
	return audit.Ref{Type: "anonymous", ID: "transaction:" + t.ID}
}
