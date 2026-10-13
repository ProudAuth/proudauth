// Package identity owns users, login identifiers, profiles and account lifecycle (§12).
package identity

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
)

// Account states (USR-003).
const (
	StatePendingVerification = "pending_verification"
	StateActive              = "active"
	StateSuspended           = "suspended"
	StateLocked              = "locked"
	StateRecoveryRestricted  = "recovery_restricted"
	StatePendingDeletion     = "pending_deletion"
	StateDeleted             = "deleted"
)

// Required actions (AUT-018).
const (
	ActionUpdatePassword  = "update_password"
	ActionVerifyEmail     = "verify_email"
	ActionConfigureTOTP   = "configure_totp"
	ActionAcceptTerms     = "accept_terms"
	ActionCompleteProfile = "complete_profile"
	// ActionVerifyContact re-confirms the primary email address even when it
	// was verified before (AUT-018 verified-contact update).
	ActionVerifyContact = "verify_contact"
)

// ValidRequiredAction reports whether a is a supported required action.
// RequiredActionPermission is the permission needed, besides
// realm.users.required_actions, to add or remove a required action (AUT-018):
// forcing or waiving a credential change or factor enrollment is credential
// administration, and a contact re-verification is account administration.
func RequiredActionPermission(a string) string {
	switch a {
	case ActionUpdatePassword, ActionConfigureTOTP:
		return "realm.users.credentials.manage"
	case ActionVerifyEmail, ActionVerifyContact:
		return "realm.users.write"
	}
	return ""
}

func ValidRequiredAction(a string) bool {
	switch a {
	case ActionUpdatePassword, ActionVerifyEmail, ActionConfigureTOTP, ActionAcceptTerms, ActionCompleteProfile, ActionVerifyContact:
		return true
	}
	return false
}

// User is a human principal.
type User struct {
	ID                  string         `json:"id"`
	RealmID             string         `json:"realm_id"`
	State               string         `json:"state"`
	DisplayName         string         `json:"display_name,omitempty"`
	GivenName           string         `json:"given_name,omitempty"`
	FamilyName          string         `json:"family_name,omitempty"`
	Locale              string         `json:"locale,omitempty"`
	Zoneinfo            string         `json:"zoneinfo,omitempty"`
	Profile             map[string]any `json:"profile"`
	AdminMetadata       map[string]any `json:"admin_metadata,omitempty"`
	InternalMetadata    map[string]any `json:"-"`
	Protected           bool           `json:"protected"`
	IsGuest             bool           `json:"is_guest"`
	RequiredActions     []string       `json:"required_actions"`
	CredentialRevision  int64          `json:"-"`
	SessionRevision     int64          `json:"-"`
	AuthzRevision       int64          `json:"authz_revision"`
	LockedUntil         *time.Time     `json:"locked_until,omitempty"`
	LastLoginAt         *time.Time     `json:"last_login_at,omitempty"`
	DeletionRequestedAt *time.Time     `json:"deletion_requested_at,omitempty"`
	DeletionScheduledAt *time.Time     `json:"deletion_scheduled_at,omitempty"`
	// DeactivateAt is a scheduled deactivation (USR-015).
	DeactivateAt *time.Time   `json:"deactivate_at,omitempty"`
	CreatedVia   string       `json:"created_via"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	Version      int64        `json:"version"`
	Identifiers  []Identifier `json:"identifiers"`
}

// Identifier is a login/contact identifier (REG-002).
type Identifier struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Canonical  string     `json:"-"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	IsPrimary  bool       `json:"is_primary"`
	Source     string     `json:"source"`
}

// Verified reports whether the identifier is verified.
func (i Identifier) Verified() bool { return i.VerifiedAt != nil }

// PrimaryEmail returns the primary email identifier, if any.
func (u *User) PrimaryEmail() *Identifier {
	var any *Identifier
	for i := range u.Identifiers {
		id := &u.Identifiers[i]
		if id.Type != "email" {
			continue
		}
		if id.IsPrimary {
			return id
		}
		if any == nil {
			any = id
		}
	}
	return any
}

// Username returns the username identifier value.
func (u *User) Username() string {
	for _, i := range u.Identifiers {
		if i.Type == "username" {
			return i.Value
		}
	}
	return ""
}

// CanAuthenticate reports whether the account may complete sign-in.
func (u *User) CanAuthenticate(now time.Time) bool {
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return false
	}
	return u.State == StateActive || u.State == StateRecoveryRestricted
}

// MayCancelDeletion reports whether the account is waiting for its scheduled
// deletion and not locked: it may then complete authentication (every factor
// it would normally need) into a transaction whose only action is to cancel
// the deletion (USR-012). It never yields a session or tokens.
func (u *User) MayCancelDeletion(now time.Time) bool {
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return false
	}
	return u.State == StatePendingDeletion
}

// HasRequiredAction reports whether a is pending.
func (u *User) HasRequiredAction(a string) bool { return slices.Contains(u.RequiredActions, a) }

// SessionRevoker revokes a user's sessions and grants inside a transaction. The
// session module implements it; identity depends only on this interface (ARC-001).
type SessionRevoker interface {
	RevokeUserTx(ctx context.Context, tx pgx.Tx, realmID, userID, reason string, includeOffline bool) (int, error)
}

// Service manages users.
type Service struct {
	d        *runtime.Deps
	Sessions SessionRevoker
	// Authority, when set, refuses local edits of attributes an external
	// directory manages (USR-022); nil means every attribute is local.
	Authority AttributeAuthority
}

// NewService returns the identity service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

const userCols = `id, realm_id, state, coalesce(display_name,''), coalesce(given_name,''), coalesce(family_name,''), coalesce(locale,''),
	coalesce(zoneinfo,''), profile, admin_metadata, internal_metadata, protected, is_guest, required_actions, credential_revision,
	session_revision, authz_revision, locked_until, last_login_at, deletion_requested_at, deletion_scheduled_at, created_via,
	created_at, updated_at, version, deactivate_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var prof, adm, internal []byte
	if err := row.Scan(&u.ID, &u.RealmID, &u.State, &u.DisplayName, &u.GivenName, &u.FamilyName, &u.Locale, &u.Zoneinfo,
		&prof, &adm, &internal, &u.Protected, &u.IsGuest, &u.RequiredActions, &u.CredentialRevision, &u.SessionRevision,
		&u.AuthzRevision, &u.LockedUntil, &u.LastLoginAt, &u.DeletionRequestedAt, &u.DeletionScheduledAt, &u.CreatedVia,
		&u.CreatedAt, &u.UpdatedAt, &u.Version, &u.DeactivateAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(prof, &u.Profile)
	_ = json.Unmarshal(adm, &u.AdminMetadata)
	_ = json.Unmarshal(internal, &u.InternalMetadata)
	if u.Profile == nil {
		u.Profile = map[string]any{}
	}
	if u.RequiredActions == nil {
		u.RequiredActions = []string{}
	}
	return &u, nil
}

func (s *Service) loadIdentifiers(ctx context.Context, q storage.Querier, u *User) error {
	rows, err := q.Query(ctx, `SELECT id, type, original_value, canonical_value, verified_at, is_primary, source
		FROM user_identifiers WHERE user_id=$1 ORDER BY created_at, id`, u.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	u.Identifiers = []Identifier{}
	for rows.Next() {
		var i Identifier
		if err := rows.Scan(&i.ID, &i.Type, &i.Value, &i.Canonical, &i.VerifiedAt, &i.IsPrimary, &i.Source); err != nil {
			return err
		}
		u.Identifiers = append(u.Identifiers, i)
	}
	return rows.Err()
}

// User loads a user by ID within a realm.
func (s *Service) User(ctx context.Context, q storage.Querier, realmID, id string) (*User, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	if !ids.Valid(id) {
		return nil, problem.ErrNotFound
	}
	u, err := scanUser(q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE realm_id=$1 AND id=$2`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return u, s.loadIdentifiers(ctx, q, u)
}

// LockUser loads a user FOR UPDATE inside tx.
func (s *Service) LockUser(ctx context.Context, tx pgx.Tx, realmID, id string) (*User, error) {
	u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return u, s.loadIdentifiers(ctx, tx, u)
}

// CanonicalizeLogin canonicalizes a login identifier, detecting its type.
func CanonicalizeLogin(raw string) (typ, canon string, ok bool) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "@") {
		c, _, err := canonical.Email(raw)
		return "email", c, err == nil
	}
	if strings.HasPrefix(raw, "+") {
		c, err := canonical.Phone(raw)
		return "phone", c, err == nil
	}
	c, err := canonical.Username(raw)
	if err == canonical.ErrReservedName {
		// Reserved names are still looked up so existing accounts keep working.
		return "username", strings.ToLower(raw), true
	}
	return "username", c, err == nil
}

// FindByLogin resolves a login identifier to a user. Emails and phones only match
// when verified, so an unverified claim on someone's address never captures their
// sign-in (DOM-001, REG-004).
func (s *Service) FindByLogin(ctx context.Context, realmID, typ, canon string) (*User, error) {
	var id string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type=$2 AND canonical_value=$3
		AND (verified_at IS NOT NULL OR type='username') LIMIT 1`, realmID, typ, canon).Scan(&id)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return s.User(ctx, nil, realmID, id)
}

// FindPendingByEmail resolves an unverified registration by email (used only inside
// the registration transaction that created it).
func (s *Service) VerifiedEmailOwner(ctx context.Context, q storage.Querier, realmID, canon string) (string, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var id string
	err := q.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2 AND verified_at IS NOT NULL`,
		realmID, canon).Scan(&id)
	if storage.IsNoRows(err) {
		return "", nil
	}
	return id, err
}

// CreateInput describes a new user.
type CreateInput struct {
	Email              string
	EmailVerified      bool
	VerificationSource string
	Username           string
	Phone              string
	DisplayName        string
	GivenName          string
	FamilyName         string
	Locale             string
	Zoneinfo           string
	Profile            map[string]any
	AdminMetadata      map[string]any
	State              string
	CreatedVia         string
	Protected          bool
	IsGuest            bool
	RequiredActions    []string
}

// CreateTx creates a user and identifiers inside tx. Uniqueness of verified
// identifiers and usernames is enforced by database constraints (DB-002).
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, realmID string, in CreateInput) (*User, error) {
	if in.Email == "" && in.Username == "" && in.Phone == "" && !in.IsGuest {
		return nil, problem.ErrValidation.WithDetail("an email, username or phone is required")
	}
	if in.State == "" {
		in.State = StateActive
	}
	if in.CreatedVia == "" {
		in.CreatedVia = "admin"
	}
	if len(in.DisplayName) > 200 || len(in.GivenName) > 100 || len(in.FamilyName) > 100 {
		return nil, problem.ErrValidation.WithDetail("name fields are too long")
	}
	prof, err := json.Marshal(nonNil(in.Profile))
	if err != nil || len(prof) > s.d.Cfg.Limits.MetadataBytes {
		return nil, problem.ErrValidation.WithField("profile", "too large")
	}
	adm, _ := json.Marshal(nonNil(in.AdminMetadata))
	now := s.d.Now()
	u := &User{ID: ids.New(ids.User)}
	actions := in.RequiredActions
	if actions == nil {
		actions = []string{}
	}
	_, err = tx.Exec(ctx, `INSERT INTO users (id, realm_id, state, display_name, given_name, family_name, locale, zoneinfo, profile,
		admin_metadata, protected, is_guest, required_actions, created_via, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`, u.ID, realmID, in.State, nilIfEmpty(in.DisplayName),
		nilIfEmpty(in.GivenName), nilIfEmpty(in.FamilyName), nilIfEmpty(in.Locale), nilIfEmpty(in.Zoneinfo), prof, adm, in.Protected,
		in.IsGuest, actions, in.CreatedVia, now)
	if err != nil {
		return nil, err
	}
	if in.Email != "" {
		c, display, err := canonical.Email(in.Email)
		if err != nil {
			return nil, problem.ErrValidation.WithField("email", "invalid email address")
		}
		var verifiedAt *time.Time
		if in.EmailVerified {
			verifiedAt = &now
		}
		if err := s.insertIdentifier(ctx, tx, realmID, u.ID, "email", display, c, verifiedAt, in.VerificationSource, true, in.CreatedVia); err != nil {
			return nil, err
		}
	}
	if in.Username != "" {
		c, err := canonical.Username(in.Username)
		if err != nil {
			return nil, problem.ErrValidation.WithField("username", err.Error())
		}
		if err := s.insertIdentifier(ctx, tx, realmID, u.ID, "username", strings.TrimSpace(in.Username), c, nil, "", true, in.CreatedVia); err != nil {
			return nil, err
		}
	}
	if in.Phone != "" {
		c, err := canonical.Phone(in.Phone)
		if err != nil {
			return nil, problem.ErrValidation.WithField("phone", "must be E.164")
		}
		if err := s.insertIdentifier(ctx, tx, realmID, u.ID, "phone", c, c, nil, "", true, in.CreatedVia); err != nil {
			return nil, err
		}
	}
	// Downstream systems learn about new accounts without polling (EXT-008).
	if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "user.created", RealmID: realmID, AggregateType: "user", AggregateID: u.ID,
		Data: map[string]any{"user_id": u.ID, "created_via": in.CreatedVia}}); err != nil {
		return nil, err
	}
	return s.User(ctx, tx, realmID, u.ID)
}

func (s *Service) insertIdentifier(ctx context.Context, tx pgx.Tx, realmID, userID, typ, display, canon string, verifiedAt *time.Time, vsource string, primary bool, source string) error {
	_, err := tx.Exec(ctx, `INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value, verified_at,
		verification_source, is_primary, source, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		ids.New(ids.Identifier), realmID, userID, typ, display, canon, verifiedAt, nilIfEmpty(vsource), primary, source, s.d.Now())
	if storage.IsUniqueViolation(err) {
		return problem.ErrConflict.WithDetail("the identifier is already in use").WithField(typ, "already in use")
	}
	if err != nil {
		return err
	}
	return s.touchTx(ctx, tx, userID)
}

// touchTx records that an account's identifiers changed. They are part of
// the account (the administrative view; the userName and emails of outbound
// SCIM documents), and the outbound change scan finds changed accounts by
// users.updated_at, so a new, verified, promoted or removed address reaches
// downstream systems without waiting for a reconciliation (PROV-010).
func (s *Service) touchTx(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `UPDATE users SET updated_at=greatest(updated_at, $2) WHERE id=$1`, userID, s.d.Now())
	return err
}

// MarkIdentifierVerifiedTx marks an identifier verified after a purpose-bound proof
// (REG-004). A conflict means another account verified it first.
func (s *Service) MarkIdentifierVerifiedTx(ctx context.Context, tx pgx.Tx, realmID, userID, typ, canon, source string) error {
	tag, err := tx.Exec(ctx, `UPDATE user_identifiers SET verified_at=$5, verification_source=$6
		WHERE realm_id=$1 AND user_id=$2 AND type=$3 AND canonical_value=$4 AND verified_at IS NULL`,
		realmID, userID, typ, canon, s.d.Now(), source)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return problem.ErrConflict.WithDetail("the identifier is already verified by another account")
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return s.touchTx(ctx, tx, userID)
}

// ReconfirmIdentifierTx records a fresh proof of control of an identifier the
// account had already verified (the verify_contact required action, AUT-018):
// verified_at moves to the time of the new proof, so the record reflects the
// re-confirmation rather than the first verification. An identifier that is
// not verified is left to MarkIdentifierVerifiedTx.
func (s *Service) ReconfirmIdentifierTx(ctx context.Context, tx pgx.Tx, realmID, userID, typ, canon, source string) error {
	_, err := tx.Exec(ctx, `UPDATE user_identifiers SET verified_at=$5, verification_source=$6
		WHERE realm_id=$1 AND user_id=$2 AND type=$3 AND canonical_value=$4 AND verified_at IS NOT NULL`,
		realmID, userID, typ, canon, s.d.Now(), source)
	return err
}

// AddIdentifierTx adds an unverified identifier (USR-004: changed identifiers are
// never verified automatically).
func (s *Service) AddIdentifierTx(ctx context.Context, tx pgx.Tx, realmID, userID, typ, raw string, primary bool) (*Identifier, error) {
	var c, display string
	switch typ {
	case "email":
		cc, d, err := canonical.Email(raw)
		if err != nil {
			return nil, problem.ErrValidation.WithField("value", "invalid email")
		}
		c, display = cc, d
	case "phone":
		cc, err := canonical.Phone(raw)
		if err != nil {
			return nil, problem.ErrValidation.WithField("value", "invalid phone")
		}
		c, display = cc, cc
	case "username":
		cc, err := canonical.Username(raw)
		if err != nil {
			return nil, problem.ErrValidation.WithField("value", err.Error())
		}
		c, display = cc, strings.TrimSpace(raw)
	default:
		return nil, problem.ErrValidation.WithField("type", "email, phone or username")
	}
	if err := s.checkEdit(ctx, tx, realmID, userID, map[string]any{typ: display}); err != nil {
		return nil, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_identifiers WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= 10 {
		return nil, problem.ErrConflict.WithDetail("too many identifiers")
	}
	var exists bool
	_ = tx.QueryRow(ctx, `SELECT true FROM user_identifiers WHERE user_id=$1 AND type=$2 AND canonical_value=$3`, userID, typ, c).Scan(&exists)
	if exists {
		return nil, problem.ErrConflict.WithDetail("identifier already present on the account")
	}
	if typ == "username" {
		if _, err := tx.Exec(ctx, `DELETE FROM user_identifiers WHERE user_id=$1 AND type='username'`, userID); err != nil {
			return nil, err
		}
		primary = true
	}
	if err := s.insertIdentifier(ctx, tx, realmID, userID, typ, display, c, nil, "", false, "user"); err != nil {
		return nil, err
	}
	var out Identifier
	err := tx.QueryRow(ctx, `SELECT id, type, original_value, canonical_value, verified_at, is_primary, source FROM user_identifiers
		WHERE user_id=$1 AND type=$2 AND canonical_value=$3`, userID, typ, c).Scan(&out.ID, &out.Type, &out.Value, &out.Canonical, &out.VerifiedAt, &out.IsPrimary, &out.Source)
	_ = primary
	return &out, err
}

// PromoteIdentifierTx makes a verified identifier primary.
func (s *Service) PromoteIdentifierTx(ctx context.Context, tx pgx.Tx, userID, identifierID string) error {
	var typ string
	var verified *time.Time
	if err := tx.QueryRow(ctx, `SELECT type, verified_at FROM user_identifiers WHERE user_id=$1 AND id=$2`, userID, identifierID).Scan(&typ, &verified); err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	if verified == nil {
		return problem.ErrValidation.WithDetail("only verified identifiers can become primary")
	}
	if err := s.checkEdit(ctx, tx, "", userID, map[string]any{typ: identifierID}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_identifiers SET is_primary=false WHERE user_id=$1 AND type=$2`, userID, typ); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_identifiers SET is_primary=true WHERE user_id=$1 AND id=$2`, userID, identifierID); err != nil {
		return err
	}
	return s.touchTx(ctx, tx, userID)
}

// RemoveIdentifierTx removes an identifier unless it is the last way to sign in.
func (s *Service) RemoveIdentifierTx(ctx context.Context, tx pgx.Tx, userID, identifierID string) (*Identifier, error) {
	var id Identifier
	err := tx.QueryRow(ctx, `SELECT id, type, original_value, canonical_value, verified_at, is_primary, source FROM user_identifiers
		WHERE user_id=$1 AND id=$2`, userID, identifierID).Scan(&id.ID, &id.Type, &id.Value, &id.Canonical, &id.VerifiedAt, &id.IsPrimary, &id.Source)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if err := s.checkEdit(ctx, tx, "", userID, map[string]any{id.Type: nil}); err != nil {
		return nil, err
	}
	var remaining int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_identifiers WHERE user_id=$1 AND id<>$2 AND (verified_at IS NOT NULL OR type='username')`,
		userID, identifierID).Scan(&remaining); err != nil {
		return nil, err
	}
	if remaining == 0 {
		return nil, problem.ErrLastMethod
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_identifiers WHERE user_id=$1 AND id=$2`, userID, identifierID); err != nil {
		return nil, err
	}
	if id.IsPrimary {
		_, _ = tx.Exec(ctx, `UPDATE user_identifiers SET is_primary=true WHERE id = (SELECT id FROM user_identifiers
			WHERE user_id=$1 AND type=$2 AND verified_at IS NOT NULL ORDER BY created_at LIMIT 1)`, userID, id.Type)
	}
	if err := s.touchTx(ctx, tx, userID); err != nil {
		return nil, err
	}
	return &id, nil
}

// ProfilePatch contains self-editable profile fields (USR-002). Administrative and
// confidential metadata are deliberately absent so self-service can never edit
// attributes consumed by authorization policy (REG-007, TEST-013).
type ProfilePatch struct {
	DisplayName *string        `json:"display_name"`
	GivenName   *string        `json:"given_name"`
	FamilyName  *string        `json:"family_name"`
	Locale      *string        `json:"locale"`
	Zoneinfo    *string        `json:"zoneinfo"`
	Profile     map[string]any `json:"profile"`
}

// UpdateProfile applies a self-service patch.
func (s *Service) UpdateProfile(ctx context.Context, realmID, userID string, expectedVersion int64, p ProfilePatch, actor audit.Ref, schema *AttributeSchema) (*User, error) {
	var out *User
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		u, err := s.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if expectedVersion != 0 && u.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if err := s.checkEdit(ctx, tx, realmID, userID, profileChanges(u, p)); err != nil {
			return err
		}
		if p.Profile != nil {
			if schema != nil {
				if perr := schema.ValidateSelfEdit(u.Profile, p.Profile); perr != nil {
					return perr
				}
			}
			for k, v := range p.Profile {
				if v == nil {
					delete(u.Profile, k)
				} else {
					u.Profile[k] = v
				}
			}
		}
		prof, _ := json.Marshal(u.Profile)
		if len(prof) > s.d.Cfg.Limits.MetadataBytes {
			return problem.ErrValidation.WithField("profile", "too large")
		}
		set := func(cur string, v *string, max int, field string) (string, error) {
			if v == nil {
				return cur, nil
			}
			if len(*v) > max {
				return "", problem.ErrValidation.WithField(field, "too long")
			}
			return *v, nil
		}
		if u.DisplayName, err = set(u.DisplayName, p.DisplayName, 200, "display_name"); err != nil {
			return err
		}
		if u.GivenName, err = set(u.GivenName, p.GivenName, 100, "given_name"); err != nil {
			return err
		}
		if u.FamilyName, err = set(u.FamilyName, p.FamilyName, 100, "family_name"); err != nil {
			return err
		}
		if u.Locale, err = set(u.Locale, p.Locale, 35, "locale"); err != nil {
			return err
		}
		if u.Zoneinfo, err = set(u.Zoneinfo, p.Zoneinfo, 64, "zoneinfo"); err != nil {
			return err
		}
		if p.Zoneinfo != nil && *p.Zoneinfo != "" {
			if _, err := time.LoadLocation(*p.Zoneinfo); err != nil {
				return problem.ErrValidation.WithField("zoneinfo", "unknown time zone")
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET display_name=$3, given_name=$4, family_name=$5, locale=$6, zoneinfo=$7, profile=$8,
			version=version+1, updated_at=$9 WHERE realm_id=$1 AND id=$2`, realmID, userID, nilIfEmpty(u.DisplayName), nilIfEmpty(u.GivenName),
			nilIfEmpty(u.FamilyName), nilIfEmpty(u.Locale), nilIfEmpty(u.Zoneinfo), prof, s.d.Now()); err != nil {
			return err
		}
		if slices.Contains(u.RequiredActions, ActionCompleteProfile) && schema != nil && schema.Complete(u.Profile) {
			if _, err := tx.Exec(ctx, `UPDATE users SET required_actions=array_remove(required_actions, $2) WHERE id=$1`, userID, ActionCompleteProfile); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.profile.updated", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Category: "account"}); err != nil {
			return err
		}
		out, err = s.User(ctx, tx, realmID, userID)
		return err
	})
	return out, err
}

// AdminPatch contains administrator-editable fields.
type AdminPatch struct {
	ProfilePatch
	AdminMetadata map[string]any `json:"admin_metadata"`
}

// AdminUpdate applies an administrative patch (USR-001, USR-009).
func (s *Service) AdminUpdate(ctx context.Context, realmID, userID string, expectedVersion int64, p AdminPatch, actor audit.Ref) (*User, error) {
	var out *User
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		u, err := s.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if expectedVersion != 0 && u.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if u.State == StateDeleted {
			return problem.ErrNotFound
		}
		// Administrator metadata is always local; profile attributes a
		// directory manages are refused like self-service edits (USR-022).
		if err := s.checkEdit(ctx, tx, realmID, userID, profileChanges(u, p.ProfilePatch)); err != nil {
			return err
		}
		if p.AdminMetadata != nil {
			if u.AdminMetadata == nil {
				u.AdminMetadata = map[string]any{}
			}
			for k, v := range p.AdminMetadata {
				if v == nil {
					delete(u.AdminMetadata, k)
				} else {
					u.AdminMetadata[k] = v
				}
			}
		}
		if p.Profile != nil {
			for k, v := range p.Profile {
				if v == nil {
					delete(u.Profile, k)
				} else {
					u.Profile[k] = v
				}
			}
		}
		apply := func(cur string, v *string) string {
			if v != nil {
				return *v
			}
			return cur
		}
		// The same bounds as self-service edits (USR-007).
		for field, lim := range map[string]struct {
			v   *string
			max int
		}{"display_name": {p.DisplayName, 200}, "given_name": {p.GivenName, 100}, "family_name": {p.FamilyName, 100},
			"locale": {p.Locale, 35}, "zoneinfo": {p.Zoneinfo, 64}} {
			if lim.v != nil && len(*lim.v) > lim.max {
				return problem.ErrValidation.WithField(field, "too long")
			}
		}
		adm, _ := json.Marshal(nonNil(u.AdminMetadata))
		prof, _ := json.Marshal(u.Profile)
		if len(prof) > s.d.Cfg.Limits.MetadataBytes {
			return problem.ErrValidation.WithField("profile", "too large")
		}
		if len(adm) > s.d.Cfg.Limits.MetadataBytes {
			return problem.ErrValidation.WithField("admin_metadata", "too large")
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET display_name=$3, given_name=$4, family_name=$5, locale=$6, zoneinfo=$7, profile=$8,
			admin_metadata=$9, authz_revision=authz_revision+1, version=version+1, updated_at=$10 WHERE realm_id=$1 AND id=$2`, realmID, userID,
			nilIfEmpty(apply(u.DisplayName, p.DisplayName)), nilIfEmpty(apply(u.GivenName, p.GivenName)), nilIfEmpty(apply(u.FamilyName, p.FamilyName)),
			nilIfEmpty(apply(u.Locale, p.Locale)), nilIfEmpty(apply(u.Zoneinfo, p.Zoneinfo)), prof, adm, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.admin_updated", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"admin_metadata_keys": mapKeys(p.AdminMetadata)}}); err != nil {
			return err
		}
		out, err = s.User(ctx, tx, realmID, userID)
		return err
	})
	return out, err
}

// SetState changes account state with the documented consequences (USR-003,
// USR-014): suspension/lock/deletion revoke every session and grant and stop
// issuance; reactivation never resurrects revoked grants.
func (s *Service) SetState(ctx context.Context, realmID, userID, state string, actor audit.Ref, reason string) (*User, error) {
	var out *User
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.SetStateTx(ctx, tx, realmID, userID, state, actor, reason)
		return err
	})
	return out, err
}

// SetStateTx is SetState inside tx.
func (s *Service) SetStateTx(ctx context.Context, tx pgx.Tx, realmID, userID, state string, actor audit.Ref, reason string) (*User, error) {
	switch state {
	case StateActive, StateSuspended, StateLocked, StateRecoveryRestricted:
	default:
		return nil, problem.ErrValidation.WithField("state", "unsupported state transition")
	}
	u, err := s.LockUser(ctx, tx, realmID, userID)
	if err != nil {
		return nil, err
	}
	if u.State == StateDeleted || u.State == StatePendingDeletion && state != StateActive {
		return nil, problem.ErrConflict.WithDetail("account is being deleted")
	}
	if state == StateActive && u.State == StateSuspended {
		// A directory that disabled the account decides when it returns
		// (USR-022).
		if err := s.checkEdit(ctx, tx, realmID, userID, map[string]any{"state": state}); err != nil {
			return nil, err
		}
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE users SET state=$3, locked_until=NULL, session_revision=session_revision+1,
		authz_revision=authz_revision+1, version=version+1, updated_at=$4,
		deletion_requested_at=CASE WHEN $3='active' THEN NULL ELSE deletion_requested_at END,
		deletion_scheduled_at=CASE WHEN $3='active' THEN NULL ELSE deletion_scheduled_at END
		WHERE realm_id=$1 AND id=$2`, realmID, userID, state, now); err != nil {
		return nil, err
	}
	if state != StateActive && state != StateRecoveryRestricted && s.Sessions != nil {
		if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, userID, "account_"+state, true); err != nil {
			return nil, err
		}
	}
	evType := map[string]string{StateActive: "user.reactivated", StateSuspended: "user.suspended", StateLocked: "user.locked",
		StateRecoveryRestricted: "user.recovery_restricted"}[state]
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: evType, RealmID: realmID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: userID}, ReasonCode: reason, Metadata: map[string]any{"previous_state": u.State}}); err != nil {
		return nil, err
	}
	if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: evType, RealmID: realmID, AggregateType: "user", AggregateID: userID,
		Data: map[string]any{"user_id": userID, "state": state}}); err != nil {
		return nil, err
	}
	return s.User(ctx, tx, realmID, userID)
}

// SetRequiredActions replaces required actions (AUT-018) and returns the
// account's new version.
//
// prior is the set the caller authorized the change against: the update
// applies only if the stored set is still exactly that (AUT-018), so a
// concurrent change cannot slip an unauthorized addition or removal through.
// expectedVersion, when not zero, must also still be the account's version
// (API-010, SEC-008): a client that read the list, changed it and writes it
// back cannot overwrite a change made after its read (412).
func (s *Service) SetRequiredActions(ctx context.Context, realmID, userID string, expectedVersion int64, prior, actions []string, actor audit.Ref) (int64, error) {
	for _, a := range actions {
		if !ValidRequiredAction(a) {
			return 0, problem.ErrValidation.WithField("actions", "unsupported action "+a)
		}
	}
	var version int64
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE users SET required_actions=$3, version=version+1, updated_at=$4
			WHERE realm_id=$1 AND id=$2 AND state <> 'deleted' AND required_actions=$5::text[] AND ($6::bigint = 0 OR version=$6)
			RETURNING version`,
			realmID, userID, dedupe(actions), s.d.Now(), nonNilStrings(prior), expectedVersion).Scan(&version)
		if storage.IsNoRows(err) {
			var current int64
			if err := tx.QueryRow(ctx, `SELECT version FROM users WHERE realm_id=$1 AND id=$2 AND state <> 'deleted'`, realmID, userID).Scan(&current); err != nil {
				if storage.IsNoRows(err) {
					return problem.ErrNotFound
				}
				return err
			}
			if expectedVersion != 0 && current != expectedVersion {
				return problem.ErrPrecondition
			}
			return problem.ErrConflict.WithDetail("the required actions changed concurrently; retry")
		}
		if err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.required_actions.set", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"actions": actions}})
		return err
	})
	return version, err
}

// AddRequiredActionTx adds a required action. Adding moves the account's
// version, so an administrator's conditional edit taken before it is stale
// (SEC-008) instead of silently dropping the action.
func (s *Service) AddRequiredActionTx(ctx context.Context, tx pgx.Tx, userID, action string) error {
	_, err := tx.Exec(ctx, `UPDATE users SET required_actions=array_append(required_actions, $2), version=version+1
		WHERE id=$1 AND NOT ($2 = ANY(required_actions))`, userID, action)
	return err
}

// RemoveRequiredActionTx removes a completed required action, moving the
// account's version when it was present.
func (s *Service) RemoveRequiredActionTx(ctx context.Context, tx pgx.Tx, userID, action string) error {
	_, err := tx.Exec(ctx, `UPDATE users SET required_actions=array_remove(required_actions, $2), version=version+1
		WHERE id=$1 AND $2 = ANY(required_actions)`, userID, action)
	return err
}

// OverrideVerification marks an identifier verified administratively. It requires a
// separate privileged permission and a reason (USR-005), checked by the caller.
func (s *Service) OverrideVerification(ctx context.Context, realmID, userID, identifierID string, actor audit.Ref, reason string) error {
	if len(strings.TrimSpace(reason)) < 5 {
		return problem.ErrValidation.WithField("reason", "a reason is required")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var typ, canon string
		if err := tx.QueryRow(ctx, `SELECT type, canonical_value FROM user_identifiers WHERE realm_id=$1 AND user_id=$2 AND id=$3`,
			realmID, userID, identifierID).Scan(&typ, &canon); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if err := s.MarkIdentifierVerifiedTx(ctx, tx, realmID, userID, typ, canon, "admin_override"); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.identifier.verification_overridden", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, ReasonCode: "ADMIN_OVERRIDE", Metadata: map[string]any{"identifier_id": identifierID,
				"identifier_type": typ, "reason": reason}})
		return err
	})
}

// SearchFilter for administrative search. Callers must already have realm-wide
// user-read authority; tenant administrators list users through organization
// membership APIs instead, so search is never scoped by masking alone (USR-006).
type SearchFilter struct {
	Query string
	State string
	After string
	Limit int
	OrgID string
}

// Search returns users ordered by ID with a keyset cursor.
func (s *Service) Search(ctx context.Context, realmID string, f SearchFilter) ([]*User, error) {
	q := strings.ToLower(strings.TrimSpace(f.Query))
	if len(q) > 254 {
		return nil, problem.ErrValidation.WithField("q", "too long")
	}
	args := []any{realmID, f.After, f.Limit}
	sql := `SELECT ` + userCols + ` FROM users u WHERE realm_id=$1 AND ($2='' OR id > $2) AND state <> 'deleted'`
	if f.State != "" {
		args = append(args, f.State)
		sql += ` AND state = $` + itoa(len(args))
	}
	if q != "" {
		args = append(args, q)
		sql += ` AND (EXISTS (SELECT 1 FROM user_identifiers i WHERE i.user_id=u.id AND i.canonical_value = $` + itoa(len(args)) + `)
			OR lower(coalesce(display_name,'')) = $` + itoa(len(args)) + ` OR id = $` + itoa(len(args)) + `)`
	}
	if f.OrgID != "" {
		args = append(args, f.OrgID)
		sql += ` AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.organization_id=$` + itoa(len(args)) + ` AND m.state NOT IN ('removed','expired'))`
	}
	sql += ` ORDER BY id LIMIT $3`
	rows, err := s.d.DB.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	rows.Close()
	for _, u := range out {
		if err := s.loadIdentifiers(ctx, s.d.DB.Pool, u); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RecordLoginTx stores the last login time and clears temporary locks.
func (s *Service) RecordLoginTx(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `UPDATE users SET last_login_at=$2 WHERE id=$1`, userID, s.d.Now())
	return err
}

// BumpAuthzTx increments a user's authorization revision.
func (s *Service) BumpAuthzTx(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `UPDATE users SET authz_revision=authz_revision+1 WHERE id=$1`, userID)
	return err
}

// RequestDeletion schedules self-service deletion after a grace period (USR-012).
// ownedCheck runs before the change (dependency checks); notify, when set, runs
// after it in the same transaction with the updated account, so the
// deletion_scheduled notice commits with the request.
func (s *Service) RequestDeletion(ctx context.Context, realmID, userID string, grace time.Duration, actor audit.Ref, ownedCheck func(pgx.Tx) error,
	notify func(pgx.Tx, *User) error) (*User, error) {
	var out *User
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		u, err := s.LockUser(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if u.State == StatePendingDeletion || u.State == StateDeleted {
			return problem.ErrConflict.WithDetail("deletion already requested")
		}
		if ownedCheck != nil {
			if err := ownedCheck(tx); err != nil {
				return err
			}
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE users SET state='pending_deletion', deletion_requested_at=$3, deletion_scheduled_at=$4,
			session_revision=session_revision+1, version=version+1, updated_at=$3 WHERE realm_id=$1 AND id=$2`, realmID, userID, now, now.Add(grace)); err != nil {
			return err
		}
		if s.Sessions != nil {
			if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, userID, "deletion_requested", true); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.deletion.requested", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"scheduled_for": now.Add(grace)}}); err != nil {
			return err
		}
		out, err = s.User(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		if notify != nil {
			return notify(tx, out)
		}
		return nil
	})
	return out, err
}

// CancelDeletion cancels a pending deletion during the grace period.
func (s *Service) CancelDeletion(ctx context.Context, realmID, userID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.CancelDeletionTx(ctx, tx, realmID, userID, actor, "")
	})
}

// CancelDeletionTx is CancelDeletion inside tx. via records how the owner
// reached it ("sign_in" for the cancel_deletion step of an authentication
// transaction, USR-012). The account becomes active again; sessions and grants
// revoked by the request stay revoked, so the owner signs in anew.
func (s *Service) CancelDeletionTx(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref, via string) error {
	tag, err := tx.Exec(ctx, `UPDATE users SET state='active', deletion_requested_at=NULL, deletion_scheduled_at=NULL, version=version+1,
		updated_at=$3 WHERE realm_id=$1 AND id=$2 AND state='pending_deletion'`, realmID, userID, s.d.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return problem.ErrConflict.WithDetail("no pending deletion")
	}
	ev := audit.Event{Type: "user.deletion.cancelled", RealmID: realmID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: userID}}
	if via != "" {
		ev.Metadata = map[string]any{"via": via}
	}
	_, err = s.d.Audit.Record(ctx, tx, ev)
	return err
}

// DeleteNowTx erases identifying data and credentials, keeping a non-sensitive
// tombstone for restore reconciliation (PRV-005, PRV-006, MIG-017). Audit events
// remain under their retention policy.
func (s *Service) DeleteNowTx(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref, reason string) error {
	u, err := s.LockUser(ctx, tx, realmID, userID)
	if err != nil {
		return err
	}
	if u.State == StateDeleted {
		return nil
	}
	if s.Sessions != nil {
		if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, userID, "account_deleted", true); err != nil {
			return err
		}
	}
	for _, i := range u.Identifiers {
		if _, err := tx.Exec(ctx, `INSERT INTO deletion_tombstones (id, realm_id, reference_type, reference_digest, reference_id, action, created_at)
			VALUES ($1,$2,$3,$4,$5,'deleted',$6)`, ids.New(ids.Tombstone), realmID, "identifier:"+i.Type, secret.Digest(realmID+"|"+i.Type+"|"+i.Canonical), userID, s.d.Now()); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO deletion_tombstones (id, realm_id, reference_type, reference_digest, reference_id, action, created_at)
		VALUES ($1,$2,'user',$3,$4,'deleted',$5)`, ids.New(ids.Tombstone), realmID, secret.Digest(userID), userID, s.d.Now()); err != nil {
		return err
	}
	if err := EraseAccountDataTx(ctx, tx, realmID, userID, s.d.Now()); err != nil {
		return err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.deleted", RealmID: realmID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: userID}, ReasonCode: reason}); err != nil {
		return err
	}
	_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "user.deleted", RealmID: realmID, AggregateType: "user", AggregateID: userID,
		Data: map[string]any{"user_id": userID}})
	return err
}

// EraseAccountDataTx removes an account's identifying data and ends its
// access, keeping the users row as a deleted tombstone (PRV-005). Account
// deletion and backup-restore reconciliation (OPS-006) both use it, so a
// restored copy of a deleted account is erased exactly as the original was.
func EraseAccountDataTx(ctx context.Context, tx pgx.Tx, realmID, userID string, now time.Time) error {
	stmts := []string{
		`DELETE FROM user_identifiers WHERE user_id=$1`,
		`DELETE FROM credentials WHERE user_id=$1`,
		`DELETE FROM recovery_codes WHERE user_id=$1`,
		`DELETE FROM webauthn_credentials WHERE user_id=$1`,
		`DELETE FROM external_identities WHERE user_id=$1`,
		`DELETE FROM password_history WHERE user_id=$1`,
		`DELETE FROM remembered_devices WHERE user_id=$1`,
		// The users row is kept as a deleted tombstone, so rows that would
		// cascade from it are removed explicitly (PRV-005).
		`DELETE FROM pairwise_subjects WHERE user_id=$1`,
		`DELETE FROM notification_preferences WHERE user_id=$1`,
		// Shared-signals subjects (AUD-016), queued security events about the
		// account, and the upstream subjects of federation transfer entries
		// (FED-016) are identifying data too.
		`DELETE FROM ssf_stream_subjects WHERE user_id=$1`,
		`UPDATE ssf_events SET state='expired', subject=NULL, set_jwt=NULL WHERE user_id=$1 AND state IN ('pending','delivered')`,
		`UPDATE federation_transfer_entries SET source_subject='[erased]', target_subject='[erased]', source_issuer=NULL, target_tenant=NULL WHERE user_id=$1`,
		// Directory data about the account (PROV-011, PROV-012): run findings
		// lose the entry DNs that name it, and its directory link keeps only
		// the entry's immutable ID with source state 'deleted' (so the next
		// synchronization reports the entry instead of recreating the
		// account); the DN and the imported attribute snapshot go.
		`UPDATE directory_sync_findings f SET source_dn=NULL WHERE f.source_dn IS NOT NULL AND (f.local_id=$1 OR (f.run_id, f.external_id) IN
			(SELECT r.id, x.external_id FROM connector_external_ids x JOIN directory_sync_runs r ON r.connector_id=x.connector_id
				WHERE x.local_id=$1 AND x.resource_type='User' AND x.link_kind='directory'))`,
		`UPDATE connector_external_ids SET source_dn=NULL, snapshot=NULL, snapshot_digest=NULL, source_state='deleted', missing_since=NULL, updated_at=now()
			WHERE local_id=$1 AND resource_type='User' AND link_kind='directory'`,
		// Access ends: sessions, grants, refresh families, support access.
		`UPDATE sessions SET state='revoked', revoked_at=now(), revoke_reason='account_deleted', cookie_digest=NULL WHERE user_id=$1 AND state='active'`,
		`UPDATE refresh_families SET state='revoked', revoked_at=now(), revoke_reason='account_deleted'
			WHERE state='active' AND grant_id IN (SELECT id FROM authorization_grants WHERE subject_type='user' AND subject_id=$1)`,
		`UPDATE authorization_grants SET state='revoked', revoked_at=now(), revoke_reason='account_deleted' WHERE subject_type='user' AND subject_id=$1 AND state='active'`,
		`UPDATE opaque_access_tokens SET revoked_at=now() WHERE subject_id=$1 AND revoked_at IS NULL`,
		`UPDATE impersonation_grants SET state='revoked', revoked_at=now(), revoked_by_type='system', revoke_reason='account_deleted'
			WHERE (actor_user_id=$1 OR target_user_id=$1) AND state='active'`,
		// Pending work about the account ends with it.
		`UPDATE assisted_recoveries SET state='cancelled' WHERE user_id=$1 AND state IN ('pending','approved')`,
		`UPDATE account_merges SET state='cancelled' WHERE (source_id=$1 OR survivor_id=$1) AND state='pending'`,
		`UPDATE registration_approvals SET state='expired', decided_at=now() WHERE user_id=$1 AND state='pending'`,
		`UPDATE memberships SET state='removed', removed_at=now() WHERE user_id=$1 AND state NOT IN ('removed','expired')`,
		// Organization membership metadata (USR-009) about the account goes
		// with it, from every membership it ever had.
		`UPDATE memberships SET metadata='{}' WHERE user_id=$1 AND metadata <> '{}'::jsonb`,
		`UPDATE automation_credentials SET state='revoked', revoked_at=now(), revoke_reason='owner_deleted' WHERE owner_type='user' AND owner_id=$1 AND state='active'`,
		// Messages about the account: queued ones are not sent, and every
		// payload and recipient goes now rather than at payload retention.
		`UPDATE notification_jobs SET state=CASE WHEN state IN ('queued','attempted') THEN 'suppressed' ELSE state END, payload_ciphertext=NULL,
			recipient_ciphertext=NULL, payload_purged_at=now(), updated_at=now() WHERE user_id=$1 AND (payload_ciphertext IS NOT NULL OR recipient_ciphertext IS NOT NULL)`,
		`UPDATE users SET state='deleted', display_name=NULL, given_name=NULL, family_name=NULL, locale=NULL, zoneinfo=NULL,
			profile='{}', admin_metadata='{}', internal_metadata='{}', required_actions='{}', deleted_at=coalesce(deleted_at, now()), version=version+1 WHERE id=$1`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return err
		}
	}
	// Certificate bindings, relationship tuples and shares, elevation
	// eligibilities and requests, and older messages (erasure_references.go).
	if err := eraseReferencesTx(ctx, tx, userID, now); err != nil {
		return err
	}
	// Source-supplied details of imported history about the account go too
	// (MIG-016); the server's own evidence is governed by audit retention.
	return audit.RedactImportedSubjectTx(ctx, tx, realmID, userID, now)
}

// IsTombstoned reports whether an identifier was deleted after a backup/export was
// taken, so restores and imports do not resurrect it (MIG-017, PRV-006).
func (s *Service) IsTombstoned(ctx context.Context, q storage.Querier, realmID, typ, canon string) (bool, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM deletion_tombstones WHERE realm_id=$1 AND reference_type=$2 AND reference_digest=$3)`,
		realmID, "identifier:"+typ, secret.Digest(realmID+"|"+typ+"|"+canon)).Scan(&exists)
	return exists, err
}

// MaskedView returns a support-safe view with contact data masked (USR-018).
func MaskedView(u *User) map[string]any {
	ids := []map[string]any{}
	for _, i := range u.Identifiers {
		ids = append(ids, map[string]any{"id": i.ID, "type": i.Type, "value": Mask(i.Type, i.Value), "verified": i.Verified(), "is_primary": i.IsPrimary})
	}
	return map[string]any{"id": u.ID, "state": u.State, "display_name": u.DisplayName, "identifiers": ids,
		"created_at": u.CreatedAt, "last_login_at": u.LastLoginAt}
}

// Mask hides most of an identifier value.
func Mask(typ, v string) string {
	switch typ {
	case "email":
		at := strings.LastIndexByte(v, '@')
		if at <= 1 {
			return "***" + v[max(at, 0):]
		}
		return v[:1] + "***" + v[at:]
	case "phone":
		if len(v) > 4 {
			return strings.Repeat("*", len(v)-4) + v[len(v)-4:]
		}
		return "****"
	default:
		if len(v) > 2 {
			return v[:2] + "***"
		}
		return "***"
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mapKeys(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
