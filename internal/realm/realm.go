// Package realm owns identity domains: canonical issuer, state and security policy.
package realm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Realm is an identity domain / security boundary (§4.1).
type Realm struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	DisplayName    string     `json:"display_name"`
	Issuer         string     `json:"issuer"`
	State          string     `json:"state"`
	Policy         Policy     `json:"policy"`
	PolicyRevision int64      `json:"policy_revision"`
	BootstrappedAt *time.Time `json:"bootstrapped_at,omitempty"`
	// DisabledGrantTypes lists grant types switched off by an emergency
	// control (SEC-020).
	DisabledGrantTypes []string  `json:"disabled_grant_types,omitempty"`
	Version            int64     `json:"version"`
	CreatedAt          time.Time `json:"created_at"`
}

// Active reports whether the realm may issue grants (§27.8 realm shutdown).
func (r *Realm) Active() bool { return r.State == "active" }

// GrantDisabled reports whether an emergency control has switched the grant
// type off realm-wide (SEC-020).
func (r *Realm) GrantDisabled(grant string) bool { return slices.Contains(r.DisabledGrantTypes, grant) }

// EmergencyGrantTypes are the grant classes an emergency control can disable.
var EmergencyGrantTypes = []string{"authorization_code", "refresh_token", "client_credentials",
	"urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"}

// Service manages realms.
type Service struct {
	d     *runtime.Deps
	mu    sync.Mutex
	cache map[string]cached
	TTL   time.Duration
	hosts hostCache
}

type cached struct {
	r  *Realm
	at time.Time
}

// NewService returns a realm service.
func NewService(d *runtime.Deps) *Service {
	return &Service{d: d, cache: map[string]cached{}, TTL: 2 * time.Second}
}

const selectRealm = `SELECT id, name, display_name, issuer, state, settings, policy_revision, bootstrapped_at, disabled_grant_types, version, created_at FROM realms`

func scanRealm(row pgx.Row) (*Realm, error) {
	var r Realm
	var settings []byte
	if err := row.Scan(&r.ID, &r.Name, &r.DisplayName, &r.Issuer, &r.State, &settings, &r.PolicyRevision, &r.BootstrappedAt, &r.DisabledGrantTypes,
		&r.Version, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.Policy = ParsePolicy(settings)
	return &r, nil
}

// ByName loads a realm by its name (route segment). Results are cached briefly; a
// realm suspension is therefore observed within TTL by every node, and every
// grant-issuing path additionally rechecks realm state in its transaction.
func (s *Service) ByName(ctx context.Context, name string) (*Realm, error) {
	s.mu.Lock()
	if c, ok := s.cache[name]; ok && s.d.Now().Sub(c.at) < s.TTL {
		s.mu.Unlock()
		return c.r, nil
	}
	s.mu.Unlock()
	r, err := scanRealm(s.d.DB.Pool.QueryRow(ctx, selectRealm+` WHERE name=$1`, name))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	s.mu.Lock()
	s.cache[name] = cached{r: r, at: s.d.Now()}
	s.mu.Unlock()
	return r, nil
}

// Cached returns the realm ByName last loaded for name, however old, without
// querying the database; ok is false when none is cached. It serves cheap
// decisions taken before authentication, such as admission to the reserved
// request pool (NFR-002); anything that grants access uses ByName.
func (s *Service) Cached(name string) (r *Realm, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cache[name]
	return c.r, ok
}

// Invalidate drops cached state for a realm.
func (s *Service) Invalidate(name string) {
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
}

// ByID loads a realm by ID without caching.
func (s *Service) ByID(ctx context.Context, q storage.Querier, id string) (*Realm, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := scanRealm(q.QueryRow(ctx, selectRealm+` WHERE id=$1`, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return r, err
}

// LockActive loads a realm FOR SHARE inside a grant-issuing transaction and fails if
// the realm is not active.
func (s *Service) LockActive(ctx context.Context, tx pgx.Tx, id string) (*Realm, error) {
	r, err := scanRealm(tx.QueryRow(ctx, selectRealm+` WHERE id=$1 FOR SHARE`, id))
	if err != nil {
		return nil, err
	}
	if !r.Active() {
		return nil, problem.ErrAccountState.WithDetail("The identity domain is not accepting sign-ins.")
	}
	return r, nil
}

// List returns all realms.
func (s *Service) List(ctx context.Context) ([]*Realm, error) {
	rows, err := s.d.DB.Pool.Query(ctx, selectRealm+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Realm
	for rows.Next() {
		r, err := scanRealm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateTx inserts a realm row.
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, name, displayName string, policy Policy) (*Realm, error) {
	settings, _ := json.Marshal(policy)
	now := s.d.Now()
	r := &Realm{ID: ids.New(ids.Realm), Name: name, DisplayName: displayName, Issuer: s.d.Cfg.Issuer(name),
		State: "active", Policy: policy, PolicyRevision: 1, Version: 1, CreatedAt: now}
	_, err := tx.Exec(ctx, `INSERT INTO realms (id, name, display_name, issuer, settings, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$6)`, r.ID, r.Name, r.DisplayName, r.Issuer, settings, now)
	if storage.IsUniqueViolation(err) {
		return nil, problem.ErrConflict.WithDetail("A realm with this name already exists.")
	}
	return r, err
}

// UpdatePolicy replaces the realm policy with optimistic concurrency, versioned
// configuration history and audit (ARC-008, DB-010).
func (s *Service) UpdatePolicy(ctx context.Context, realmID string, expectedVersion int64, p Policy, actor audit.Ref, reason string) (*Realm, error) {
	var out *Realm
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.UpdatePolicyTx(ctx, tx, realmID, expectedVersion, p, actor, reason)
		return err
	})
	if out != nil {
		s.Invalidate(out.Name)
	}
	return out, err
}

// UpdatePolicyTx replaces the realm policy inside tx. The caller must call
// Invalidate(realm name) after the transaction commits.
func (s *Service) UpdatePolicyTx(ctx context.Context, tx pgx.Tx, realmID string, expectedVersion int64, p Policy, actor audit.Ref, reason string) (*Realm, error) {
	var out *Realm
	err := func() error {
		cur, err := scanRealm(tx.QueryRow(ctx, selectRealm+` WHERE id=$1 FOR UPDATE`, realmID))
		if err != nil {
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if err := ValidatePolicy(p, s.d.Cfg.Impersonation.Enabled); err != nil {
			return err
		}
		if err := CheckMFAFloor(p, s.d.Cfg.Security.MFAFloor); err != nil {
			return err
		}
		if err := CheckChallengeProvider(p, s.d.Cfg); err != nil {
			return err
		}
		doc, _ := json.Marshal(p)
		sum := sha256.Sum256(doc)
		now := s.d.Now()
		if err := s.recordFlowChangeTx(ctx, tx, cur, p.AuthFlow, cur.PolicyRevision+1, actor, reason, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE realms SET settings=$2, policy_revision=policy_revision+1, version=version+1, updated_at=$3 WHERE id=$1`,
			realmID, doc, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO configuration_revisions (id, realm_id, scope_type, scope_id, revision, document, document_hash,
			changed_by_type, changed_by_id, reason, created_at) VALUES ($1,$2,'realm_policy',$2,$3,$4,$5,$6,$7,$8,$9)`,
			ids.New(ids.Config), realmID, cur.PolicyRevision+1, doc, hex.EncodeToString(sum[:]), actor.Type, actor.ID, reason, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.policy.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "realm", ID: realmID}, ReasonCode: reason,
			Metadata: map[string]any{"policy_revision": cur.PolicyRevision + 1, "document_hash": hex.EncodeToString(sum[:])}}); err != nil {
			return err
		}
		out, err = scanRealm(tx.QueryRow(ctx, selectRealm+` WHERE id=$1`, realmID))
		return err
	}()
	return out, err
}

// SetState suspends or reactivates a realm (emergency control, SEC-020, §27.8).
func (s *Service) SetState(ctx context.Context, realmID, state string, actor audit.Ref, reason string) error {
	if state != "active" && state != "suspended" {
		return problem.ErrValidation.WithField("state", "must be active or suspended")
	}
	var name string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE realms SET state=$2, version=version+1, updated_at=$3 WHERE id=$1 RETURNING name`,
			realmID, state, s.d.Now()).Scan(&name); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm." + map[string]string{"active": "reactivated", "suspended": "suspended"}[state],
			RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "realm", ID: realmID}, ReasonCode: reason})
		return err
	})
	s.Invalidate(name)
	return err
}

// SetGrantDisabled switches a grant class off or back on realm-wide (SEC-020).
// It is an emergency control: separate from policy edits, audited with a
// reason, and effective on every node within the realm cache TTL.
func (s *Service) SetGrantDisabled(ctx context.Context, realmID, grant string, disabled bool, actor audit.Ref, reason string) error {
	if !slices.Contains(EmergencyGrantTypes, grant) {
		return problem.ErrValidation.WithField("target_id", "not a grant type that can be disabled")
	}
	var name string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		q := `UPDATE realms SET disabled_grant_types=array_remove(disabled_grant_types, $2), version=version+1, updated_at=$3 WHERE id=$1 RETURNING name`
		if disabled {
			q = `UPDATE realms SET disabled_grant_types=array_append(array_remove(disabled_grant_types, $2), $2), version=version+1, updated_at=$3
				WHERE id=$1 RETURNING name`
		}
		if err := tx.QueryRow(ctx, q, realmID, grant, s.d.Now()).Scan(&name); err != nil {
			return err
		}
		typ := "realm.grant_type.enabled"
		if disabled {
			typ = "realm.grant_type.disabled"
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: typ, RealmID: realmID, Actor: actor, Category: "emergency",
			Target: &audit.Ref{Type: "realm", ID: realmID}, ReasonCode: reason, Metadata: map[string]any{"grant_type": grant}})
		return err
	})
	s.Invalidate(name)
	return err
}

// MarkBootstrapped records that the initial administrator exists so remote or
// repeated bootstrap is refused (SEC-011).
func (s *Service) MarkBootstrapped(ctx context.Context, tx pgx.Tx, realmID string) error {
	_, err := tx.Exec(ctx, `UPDATE realms SET bootstrapped_at=$2 WHERE id=$1`, realmID, s.d.Now())
	return err
}

// ValidatePolicy enforces safety floors that realm administrators cannot lower.
// CheckMFAFloor refuses realm MFA settings below the operator's floor
// (MFA-005). The floor is also applied at sign-in, so a policy saved before
// the floor was raised cannot lower it either. The phishing-resistant floor
// fails closed: a policy that leaves passkeys disabled is refused, since the
// profile could not be met there. A realm saved in that state before this
// check cannot meet it at sign-in; identity-cli doctor reports such realms.
func CheckMFAFloor(p Policy, f configuration.MFAFloor) error {
	switch {
	case f.Require == "all" && p.MFA.Requirement != MFARequired:
		return problem.ErrValidation.WithField("mfa.requirement", "the operator requires MFA for every account (security.mfa_floor.require)")
	case f.AdminPhishingResistant && !p.MFA.AdminPhishingResistant:
		return problem.ErrValidation.WithField("mfa.admin_phishing_resistant", "the operator requires phishing-resistant MFA for administrators")
	case f.AdminPhishingResistant && !p.PasskeysEnabled():
		// The floor fails closed: without passkeys the profile could not be
		// met, and administrators would sign in with phishable factors.
		return problem.ErrValidation.WithField("login.passkeys", "the operator requires phishing-resistant MFA for administrators: enable login.passkeys or list webauthn in mfa.allowed_factors")
	case f.ForbidOrgAdminWaiver && p.MFA.OrgAdminMFAOptional:
		return problem.ErrValidation.WithField("mfa.org_admin_mfa_optional", "the operator forbids waiving MFA for organization administration")
	}
	return nil
}

// PhishingResistantUnmet reports a realm where the phishing-resistant
// administrator profile is required, by the realm's own
// mfa.admin_phishing_resistant or by the operator floor, but passkeys are
// disabled, so sign-in cannot apply it. ValidatePolicy and CheckMFAFloor
// refuse such policies now; a realm saved before them may still be in that
// state, and identity-cli doctor reports it (SEC-012, MFA-005).
func PhishingResistantUnmet(p Policy, f configuration.MFAFloor) bool {
	return (p.MFA.AdminPhishingResistant || f.AdminPhishingResistant) && !p.PasskeysEnabled()
}

func ValidatePolicy(p Policy, operatorAllowsImpersonation bool) error {
	if err := validateAuthFlow(p.AuthFlow); err != nil {
		return err
	}
	if err := validateExtensions(p.Extensions); err != nil {
		return err
	}
	if d := p.Audit.RetentionDays; d != 0 && (d < 30 || d > 3650) {
		return problem.ErrValidation.WithField("audit.retention_days", "30..3650 days (it only ever extends the deployment's retention)")
	}
	switch p.Registration.Mode {
	case RegistrationPublic, RegistrationClosed, RegistrationInvitationOnly, RegistrationDomainRestricted:
	default:
		return problem.ErrValidation.WithField("registration.mode", "unsupported registration mode")
	}
	if p.Registration.Mode == RegistrationDomainRestricted && len(p.Registration.AllowedDomains) == 0 {
		return problem.ErrValidation.WithField("registration.allowed_domains", "required for domain_restricted mode")
	}
	for name, v := range map[string]int{"tokens.access_token_ttl_seconds": p.Tokens.AccessTokenTTLSeconds,
		"tokens.service_access_token_ttl_seconds":       p.Tokens.ServiceAccessTokenTTLSeconds,
		"tokens.single_factor_access_token_ttl_seconds": p.Tokens.SingleFactorAccessTokenTTLSeconds,
		"tokens.impersonation_access_token_ttl_seconds": p.Tokens.ImpersonationAccessTokenTTLSeconds} {
		if v != 0 && (v < 30 || v > 86400) {
			return problem.ErrValidation.WithField(name, "between 30 and 86400 seconds")
		}
	}
	if p.Domains.RecheckDays < 0 || p.Domains.RecheckDays > 365 || p.Domains.LapseAfterFailures < 0 || p.Domains.LapseAfterFailures > 30 {
		return problem.ErrValidation.WithField("domains", "recheck_days 0..365 and lapse_after_failures 0..30 (0 means the default: 30 days, 3 failures)")
	}
	if o := p.Machine.OwnerDeparture; o != "" && o != "flag" && o != "disable" {
		return problem.ErrValidation.WithField("machine.owner_departure", "flag or disable")
	}
	if g := p.Machine.OwnerDepartureGraceDays; g < 0 || g > 90 {
		return problem.ErrValidation.WithField("machine.owner_departure_grace_days", "between 0 and 90")
	}
	if n := p.DataAccess.SampleAllowedDecisionsPercent; n < 0 || n > 100 {
		return problem.ErrValidation.WithField("data_access.sample_allowed_decisions_percent", "between 0 and 100")
	}
	if a := p.Lifecycle.DormantAction; a != "" && a != "report" && a != "suspend" {
		return problem.ErrValidation.WithField("lifecycle.dormant_action", "report or suspend")
	}
	if p.Lifecycle.DormantDays < 0 || p.Lifecycle.DormantDays > 3650 || p.Lifecycle.GuestTTLDays < 0 || p.Lifecycle.GuestTTLDays > 3650 {
		return problem.ErrValidation.WithField("lifecycle", "day counts must be between 0 and 3650")
	}
	if p.MFA.Requirement != MFAOptional && p.MFA.Requirement != MFARequired {
		return problem.ErrValidation.WithField("mfa.requirement", "must be optional or required")
	}
	if !p.Login.Password && !p.Login.EmailOTP && !p.Login.MagicLink && !p.Login.Passkeys {
		return problem.ErrValidation.WithField("login", "at least one sign-in method must be enabled")
	}
	for _, id := range p.Login.Identifiers {
		if id != "email" && id != "username" && id != "phone" {
			return problem.ErrValidation.WithField("login.identifiers", "email, username or phone")
		}
	}
	if p.Login.RememberDeviceDays < 0 || p.Login.RememberDeviceDays > 90 {
		return problem.ErrValidation.WithField("login.remember_device_days", "0..90")
	}
	if p.Login.SMSOTP && len(p.Login.Identifiers) > 0 && !slices.Contains(p.Login.Identifiers, "phone") {
		return problem.ErrValidation.WithField("login.identifiers", "SMS sign-in requires phone in login.identifiers")
	}
	if p.Login.SMSOTP && !p.Login.SMSRiskAccepted {
		// SMS assurance risks must be accepted explicitly by the operator (PWDLESS-005).
		return problem.ErrValidation.WithField("login.sms_risk_accepted", "SMS sign-in requires explicit acceptance of SIM-swap and delivery risks")
	}
	if p.Impersonation.Enabled && !operatorAllowsImpersonation {
		return problem.ErrValidation.WithField("impersonation.enabled", "the operator has not enabled support impersonation for this deployment (IMP-001)")
	}
	switch p.Impersonation.Approval {
	case "none", "second_operator", "organization_owner", "customer":
	default:
		return problem.ErrValidation.WithField("impersonation.approval", "unsupported approval mode")
	}
	if p.Impersonation.MaxTTLSeconds < 0 || p.Impersonation.MaxTTLSeconds > 300 {
		return problem.ErrValidation.WithField("impersonation.max_ttl_seconds", "must be between 1 and 300 (IMP-009)")
	}
	if p.Sessions.IdleSeconds < 0 || p.Sessions.AbsoluteSeconds < 0 {
		return problem.ErrValidation.WithField("sessions", "lifetimes must be positive")
	}
	if p.Password.MinLength != 0 && p.Password.MinLength < 8 {
		return problem.ErrValidation.WithField("password.min_length", "cannot be below 8")
	}
	if p.Recovery.CoolingOffHours < 0 || p.Recovery.CoolingOffHours > 168 {
		return problem.ErrValidation.WithField("recovery.cooling_off_hours", "0..168")
	}
	// Each remembered password costs one full hash verification per change, so
	// the history is bounded (CRED-010).
	if p.Password.HistoryCount < 0 || p.Password.HistoryCount > 24 {
		return problem.ErrValidation.WithField("password.history_count", "0..24")
	}
	for _, f := range p.MFA.AllowedFactors {
		switch f {
		case "totp", "hotp", "webauthn", "recovery_code", "email_otp", "sms_otp":
		default:
			return problem.ErrValidation.WithField("mfa.allowed_factors", "unknown factor "+f)
		}
	}
	// MFA can be required of any account (privileged roles, protected
	// accounts, acr_values), and an account without a second factor then
	// enrolls one in the sign-in transaction (MFA-003). Only TOTP and
	// passkeys can be enrolled there: HOTP and recovery codes cannot, and
	// email or SMS codes are primary sign-in methods, never a second factor
	// (PWDLESS-006). A list without either leaves such sign-ins with no
	// action that could complete them (MFA-005).
	if len(p.MFA.AllowedFactors) > 0 && !p.MFA.TOTPAllowed() && !p.PasskeysEnabled() {
		return problem.ErrValidation.WithField("mfa.allowed_factors", "must allow a second factor that can be enrolled at sign-in: totp, or webauthn (or enable login.passkeys)")
	}
	if p.MFA.AdminPhishingResistant && !p.PasskeysEnabled() {
		// Only a user-verified passkey meets the profile (SEC-012).
		return problem.ErrValidation.WithField("mfa.admin_phishing_resistant", "requires passkeys: enable login.passkeys or list webauthn in mfa.allowed_factors")
	}
	for _, sc := range p.ClientRegistration.OpenScopes {
		switch sc {
		case "openid", "profile", "email", "phone", "address":
		default:
			return problem.ErrValidation.WithField("client_registration.open_scopes", "OpenID Connect scopes only: openid, profile, email, phone, address")
		}
	}
	if h := p.MFA.HOTP; h.LookAhead < 0 || h.LookAhead > 50 {
		return problem.ErrValidation.WithField("mfa.hotp.look_ahead", "0 (default 10) or 1..50")
	} else if h.ResyncWindow < 0 || h.ResyncWindow > 1000 || (h.ResyncWindow > 0 && h.ResyncWindow < p.MFA.HOTPLookAhead()) {
		return problem.ErrValidation.WithField("mfa.hotp.resync_window", "0 (default 100) or look_ahead..1000")
	}
	sch := identity.AttributeSchema{Attributes: p.Profile.Attributes}
	if err := sch.Validate(); err != nil {
		return err
	}
	for _, f := range p.Registration.RequiredProfileFields {
		if !slices.ContainsFunc(p.Profile.Attributes, func(d identity.AttributeDef) bool { return d.Name == f }) {
			return problem.ErrValidation.WithField("registration.required_profile_fields", "unknown attribute "+f)
		}
	}
	return validateWebAuthn(p.WebAuthn)
}

// validateWebAuthn checks the relying-party configuration (PASS-001, PASS-008):
// the RP ID must be a domain, every origin must be https (http only for
// localhost development) and its host must equal the RP ID or be a subdomain.
func validateWebAuthn(w WebAuthnPolicy) error {
	switch w.UserVerification {
	case "", "required", "preferred", "discouraged":
	default:
		return problem.ErrValidation.WithField("webauthn.user_verification", "must be required, preferred or discouraged")
	}
	if err := validateAttestation(w); err != nil {
		return err
	}
	if w.RPID == "" {
		if len(w.Origins) > 0 {
			return problem.ErrValidation.WithField("webauthn.rp_id", "required when origins are configured")
		}
		if len(w.RelatedOrigins) > 0 {
			return problem.ErrValidation.WithField("webauthn.rp_id", "required with related origins")
		}
		return nil
	}
	rp := strings.ToLower(w.RPID)
	if rp != w.RPID || strings.ContainsAny(rp, "/:@ ") || net.ParseIP(rp) != nil || (!strings.Contains(rp, ".") && rp != "localhost") {
		return problem.ErrValidation.WithField("webauthn.rp_id", "must be a lower-case domain name (not an IP address or URL)")
	}
	if len(w.Origins) == 0 {
		return problem.ErrValidation.WithField("webauthn.origins", "at least one origin is required with an explicit rp_id")
	}
	for _, o := range w.Origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return problem.ErrValidation.WithField("webauthn.origins", "origin must be scheme://host[:port]: "+o)
		}
		h := u.Hostname()
		if u.Scheme != "https" && !(u.Scheme == "http" && (h == "localhost" || strings.HasSuffix(h, ".localhost"))) {
			return problem.ErrValidation.WithField("webauthn.origins", "origins must use https: "+o)
		}
		if h != rp && !strings.HasSuffix(h, "."+rp) {
			return problem.ErrValidation.WithField("webauthn.origins", "origin host must equal the rp_id or be a subdomain of it: "+o)
		}
	}
	if len(w.RelatedOrigins) > 0 {
		if len(w.RelatedOrigins) > 20 {
			return problem.ErrValidation.WithField("webauthn.related_origins", "at most 20 origins")
		}
		for _, o := range w.RelatedOrigins {
			u, err := url.Parse(o)
			if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
				return problem.ErrValidation.WithField("webauthn.related_origins", "https://host[:port] origins: "+o)
			}
		}
		// The related origins document can name at most five registrable
		// domains (WebAuthn Level 3 §5.11); more would be ignored by clients.
		if _, err := protocol.NewRelatedOrigins(append(slices.Clone(w.Origins), w.RelatedOrigins...)...); err != nil {
			return problem.ErrValidation.WithField("webauthn.related_origins", "origins must span at most five registrable domains")
		}
	}
	return nil
}

// WebAuthnAttestations are the attestation conveyance values (PASS-009).
var WebAuthnAttestations = []string{"none", "indirect", "direct", "enterprise"}

// CredentialProtections are the credProtect policies a realm can request.
var CredentialProtections = []string{"userVerificationOptionalWithCredentialIDList", "userVerificationRequired"}

func validateAttestation(w WebAuthnPolicy) error {
	if w.Attestation != "" && !slices.Contains(WebAuthnAttestations, w.Attestation) {
		return problem.ErrValidation.WithField("webauthn.attestation", "none, indirect, direct or enterprise")
	}
	if w.RequireTrustedAttestation && w.Attestation != "direct" && w.Attestation != "enterprise" {
		return problem.ErrValidation.WithField("webauthn.require_trusted_attestation", "requires attestation direct or enterprise")
	}
	if len(w.AllowedAAGUIDs) > 0 && len(w.BlockedAAGUIDs) > 0 {
		return problem.ErrValidation.WithField("webauthn.blocked_aaguids", "use either allowed_aaguids or blocked_aaguids")
	}
	for name, list := range map[string][]string{"allowed_aaguids": w.AllowedAAGUIDs, "blocked_aaguids": w.BlockedAAGUIDs} {
		if len(list) > 200 {
			return problem.ErrValidation.WithField("webauthn."+name, "at most 200 AAGUIDs")
		}
		for _, a := range list {
			if !aaguidPattern.MatchString(a) {
				return problem.ErrValidation.WithField("webauthn."+name, "lower-case AAGUIDs such as 2fc0579f-8113-47ea-b116-bb5a8db9202a")
			}
		}
	}
	if w.CredentialProtection != "" && !slices.Contains(CredentialProtections, w.CredentialProtection) {
		return problem.ErrValidation.WithField("webauthn.credential_protection", strings.Join(CredentialProtections, " or "))
	}
	if w.EnforceCredentialProtection && w.CredentialProtection == "" {
		return problem.ErrValidation.WithField("webauthn.enforce_credential_protection", "name the credential_protection policy to enforce")
	}
	return nil
}

var aaguidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrRealmSuspended is returned when a suspended realm is used.
var ErrRealmSuspended = errors.New("realm suspended")

// Risk levels reported by authentication.risk hooks, in increasing order.
var RiskLevels = []string{"low", "medium", "high"}

// FlowMethods are the primary methods authentication flow rules can name.
var FlowMethods = []string{"password", "passkey", "email_otp", "magic_link", "sms_otp", "sso", "certificate"}

// FlowAssurances are the ACR values a rule can compare against.
var FlowAssurances = []string{"urn:proudauth:acr:mfa", "urn:proudauth:acr:phishing_resistant"}

// validateAuthFlow bounds the authentication flow definition (AUT-012).
func validateAuthFlow(f AuthFlowPolicy) error {
	field := func(i int, name string) string { return fmt.Sprintf("authentication_flow.rules[%d].%s", i, name) }
	if len(f.Rules) > 50 {
		return problem.ErrValidation.WithField("authentication_flow.rules", "at most 50 rules")
	}
	if f.ChallengeProvider != "" && !flowProviderName.MatchString(f.ChallengeProvider) {
		return problem.ErrValidation.WithField("authentication_flow.challenge_provider", "a configured challenge provider name")
	}
	names := map[string]bool{}
	for i, r := range f.Rules {
		if r.Name == "" || len(r.Name) > 100 || names[r.Name] {
			return problem.ErrValidation.WithField(field(i, "name"), "unique, 1 to 100 characters")
		}
		names[r.Name] = true
		switch r.Outcome {
		case FlowAllow, FlowRequireMFA, FlowRequirePhishingResistant, FlowChallenge, FlowReview, FlowDeny:
		default:
			return problem.ErrValidation.WithField(field(i, "outcome"), "allow, require_mfa, require_phishing_resistant, challenge, review or deny")
		}
		switch r.OnMissingSignal {
		case "", "apply", "skip":
		default:
			return problem.ErrValidation.WithField(field(i, "on_missing_signal"), "apply or skip")
		}
		w := r.When
		for name, list := range map[string][]string{"clients": w.Clients, "organizations": w.Organizations, "methods": w.Methods,
			"resources": w.Resources, "networks": w.Networks, "outside_networks": w.OutsideNetworks} {
			if len(list) > 50 {
				return problem.ErrValidation.WithField(field(i, "when."+name), "at most 50 entries")
			}
		}
		for _, m := range w.Methods {
			if !slices.Contains(FlowMethods, m) {
				return problem.ErrValidation.WithField(field(i, "when.methods"), strings.Join(FlowMethods, ", "))
			}
		}
		for _, c := range append(slices.Clone(w.Networks), w.OutsideNetworks...) {
			if _, err := netip.ParsePrefix(c); err != nil {
				return problem.ErrValidation.WithField(field(i, "when.networks"), "CIDR prefixes such as 203.0.113.0/24")
			}
		}
		if w.RiskAtLeast != "" && !slices.Contains(RiskLevels, w.RiskAtLeast) {
			return problem.ErrValidation.WithField(field(i, "when.risk_at_least"), "low, medium or high")
		}
		if w.AssuranceBelow != "" && !slices.Contains(FlowAssurances, w.AssuranceBelow) {
			return problem.ErrValidation.WithField(field(i, "when.assurance_below"), strings.Join(FlowAssurances, " or "))
		}
		if w.FailedAttemptsAtLeast < 0 || w.FailedAttemptsAtLeast > 1000 {
			return problem.ErrValidation.WithField(field(i, "when.failed_attempts_at_least"), "0 to 1000")
		}
	}
	return nil
}

var flowProviderName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// CheckChallengeProvider refuses a policy that names a challenge provider
// (SEC-014) or a policy engine (AZ-026) the operator has not configured.
func CheckChallengeProvider(p Policy, cfg *configuration.Config) error {
	// WebAuthn Level 3 related origins are an operator decision (PASS-010).
	if len(p.WebAuthn.RelatedOrigins) > 0 && !cfg.WebAuthn.RelatedOrigins {
		return problem.ErrValidation.WithField("webauthn.related_origins", "related origins are not enabled by the operator (webauthn.related_origins)")
	}
	if name := p.AuthFlow.ChallengeProvider; name != "" {
		if _, ok := cfg.ChallengeProvider(name); !ok {
			return problem.ErrValidation.WithField("authentication_flow.challenge_provider", "no challenge provider with this name is configured (security.challenge_providers)")
		}
	}
	pe := p.PolicyEngine
	switch {
	case pe.Name == "" && (pe.Mode != "" || pe.OnError != ""):
		return problem.ErrValidation.WithField("policy_engine.name", "name the engine the mode and on_error apply to")
	case pe.Name == "":
	case !func() bool { _, ok := cfg.PolicyEngine(pe.Name); return ok }():
		return problem.ErrValidation.WithField("policy_engine.name", "no policy engine with this name is configured (security.policy_engines)")
	case pe.Mode != "" && pe.Mode != "restrict" && pe.Mode != "decide":
		return problem.ErrValidation.WithField("policy_engine.mode", "restrict (default) or decide")
	case pe.OnError != "" && pe.OnError != "deny" && pe.OnError != "local":
		return problem.ErrValidation.WithField("policy_engine.on_error", "deny (default) or local")
	}
	return nil
}
