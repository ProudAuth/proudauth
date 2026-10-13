// Package organization owns organizations, memberships, invitations, groups,
// domains, join requests and ownership (§6, §8.2).
package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/ratelimit"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/storage"
)

// Organization is a business tenant inside a realm.
type Organization struct {
	ID            string          `json:"id"`
	RealmID       string          `json:"realm_id"`
	Slug          string          `json:"slug"`
	DisplayName   string          `json:"display_name"`
	State         string          `json:"state"`
	Locale        string          `json:"locale,omitempty"`
	TimeZone      string          `json:"time_zone,omitempty"`
	Metadata      map[string]any  `json:"metadata"`
	Contact       map[string]any  `json:"contact"`
	ExternalID    string          `json:"external_id,omitempty"`
	Policy        realm.OrgPolicy `json:"policy"`
	AuthzRevision int64           `json:"authz_revision"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Version       int64           `json:"version"`
}

// Membership is a user's relationship to an organization (TEN-003).
type Membership struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	UserID         string     `json:"user_id"`
	State          string     `json:"state"`
	Source         string     `json:"source"`
	SourceRef      string     `json:"source_reference,omitempty"`
	ExternalID     string     `json:"external_id,omitempty"`
	JoinedAt       *time.Time `json:"joined_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RemovedAt      *time.Time `json:"removed_at,omitempty"`
	Revision       int64      `json:"revision"`
	CreatedAt      time.Time  `json:"created_at"`
	Roles          []string   `json:"roles,omitempty"`
	DisplayName    string     `json:"display_name,omitempty"`
	Email          string     `json:"email,omitempty"`
	// Metadata is the organization's own data about this membership
	// (USR-009), separate from the user's profile, admin_metadata and
	// internal metadata. It is loaded only for callers that can manage the
	// organization's members (ListMembers withMetadata, MembershipMetadata);
	// otherwise it is nil and omitted. It never reaches tokens or the user's
	// own views.
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Service manages organizations.
type Service struct {
	d        *runtime.Deps
	Authz    *authorization.Service
	Sessions *session.Service
	Notify   *notification.Service
	Limiter  *ratelimit.Limiter
	// RecheckPolicy resolves a realm's domain re-verification policy (TEN-009).
	RecheckPolicy func(ctx context.Context, realmID string) DomainRecheckPolicy
	// Integrations creates the clients and integrations templates name (TEN-017).
	Integrations TemplateIntegrations
	// skips remembers which dynamic-group members the last recomputation
	// left out (AZ-018), so a skip is audited once, not on every run.
	skips dynamicSkips
}

// NewService returns the organization service.
func NewService(d *runtime.Deps, az *authorization.Service, ss *session.Service, n *notification.Service) *Service {
	return &Service{d: d, Authz: az, Sessions: ss, Notify: n}
}

const orgCols = `id, realm_id, slug, display_name, state, coalesce(locale,''), coalesce(time_zone,''), metadata, contact, coalesce(external_id,''),
	policy, authz_revision, created_at, updated_at, version`

func scanOrg(row pgx.Row) (*Organization, error) {
	var o Organization
	var meta, contact, policy []byte
	if err := row.Scan(&o.ID, &o.RealmID, &o.Slug, &o.DisplayName, &o.State, &o.Locale, &o.TimeZone, &meta, &contact, &o.ExternalID,
		&policy, &o.AuthzRevision, &o.CreatedAt, &o.UpdatedAt, &o.Version); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(meta, &o.Metadata)
	_ = json.Unmarshal(contact, &o.Contact)
	o.Policy = realm.ParseOrgPolicy(policy)
	if o.Metadata == nil {
		o.Metadata = map[string]any{}
	}
	if o.Contact == nil {
		o.Contact = map[string]any{}
	}
	return &o, nil
}

// Get loads an organization by ID within a realm.
func (s *Service) Get(ctx context.Context, q storage.Querier, realmID, id string) (*Organization, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	o, err := scanOrg(q.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE realm_id=$1 AND id=$2 AND state <> 'deleted'`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return o, nil
}

// Resolve loads by ID or slug.
func (s *Service) Resolve(ctx context.Context, realmID, idOrSlug string) (*Organization, error) {
	if strings.HasPrefix(idOrSlug, "org_") {
		return s.Get(ctx, nil, realmID, idOrSlug)
	}
	o, err := scanOrg(s.d.DB.Pool.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE realm_id=$1 AND slug=$2 AND state <> 'deleted'`, realmID, idOrSlug))
	if storage.IsNoRows(err) {
		// Aliases (TEN-011): former slugs keep resolving to their organization
		// and can never be claimed by another one.
		o, err = scanOrg(s.d.DB.Pool.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE realm_id=$1 AND state <> 'deleted' AND id =
			(SELECT organization_id FROM organization_aliases WHERE realm_id=$1 AND alias=lower($2))`, realmID, idOrSlug))
	}
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return o, nil
}

// slugFreeTx refuses a slug that is another organization's alias.
func (s *Service) slugFreeTx(ctx context.Context, tx pgx.Tx, realmID, slug, orgID string) error {
	var owner string
	err := tx.QueryRow(ctx, `SELECT organization_id FROM organization_aliases WHERE realm_id=$1 AND alias=$2`, realmID, slug).Scan(&owner)
	if err == nil && owner != orgID {
		return problem.ErrConflict.WithField("slug", "already in use")
	}
	return nil
}

// Aliases lists an organization's aliases.
func (s *Service) Aliases(ctx context.Context, realmID, orgID string) ([]string, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT alias FROM organization_aliases WHERE realm_id=$1 AND organization_id=$2 ORDER BY alias`, realmID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddAlias reserves an extra name for an organization. An alias may not be
// another organization's slug or alias.
func (s *Service) AddAlias(ctx context.Context, realmID, orgID, alias string, actor audit.Ref) error {
	alias, ok := canonical.Slug(alias)
	if !ok {
		return problem.ErrValidation.WithField("alias", "2-63 lowercase letters, digits or dashes")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.addAliasTx(ctx, tx, realmID, orgID, alias, actor)
	})
}

func (s *Service) addAliasTx(ctx context.Context, tx pgx.Tx, realmID, orgID, alias string, actor audit.Ref) error {
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE realm_id=$1 AND slug=$2 AND state <> 'deleted' AND id <> $3)`,
		realmID, alias, orgID).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return problem.ErrConflict.WithField("alias", "another organization uses this name")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO organization_aliases (realm_id, alias, organization_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, realmID, alias, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var owner string
		_ = tx.QueryRow(ctx, `SELECT organization_id FROM organization_aliases WHERE realm_id=$1 AND alias=$2`, realmID, alias).Scan(&owner)
		if owner != orgID {
			return problem.ErrConflict.WithField("alias", "another organization uses this name")
		}
		return nil
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.alias.added", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "configuration",
		Target: &audit.Ref{Type: "organization", ID: orgID}, Metadata: map[string]any{"alias": alias}})
	return err
}

// RemoveAlias releases an alias.
func (s *Service) RemoveAlias(ctx context.Context, realmID, orgID, alias string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM organization_aliases WHERE realm_id=$1 AND organization_id=$2 AND alias=lower($3)`, realmID, orgID, alias)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.alias.removed", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "organization", ID: orgID}, Metadata: map[string]any{"alias": strings.ToLower(alias)}})
		return err
	})
}

// LockActiveTx locks an organization FOR SHARE and requires it to be active. Grant
// issuance and invitation acceptance use it so they serialize with suspension and
// deletion (TEST-064).
func (s *Service) LockActiveTx(ctx context.Context, tx pgx.Tx, realmID, id string) (*Organization, error) {
	return s.lockActiveTx(ctx, tx, realmID, id, false)
}

// Writers take their final lock immediately. Acquiring FOR SHARE first and
// upgrading it makes concurrent writers wait on each other's shared locks.
func (s *Service) lockActiveTx(ctx context.Context, tx pgx.Tx, realmID, id string, exclusive bool) (*Organization, error) {
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	o, err := scanOrg(tx.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE realm_id=$1 AND id=$2`+lock, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if o.State != "active" {
		return nil, problem.ErrAccountState.WithDetail("The organization is not active.")
	}
	return o, nil
}

// Input creates or updates an organization (TEN-002).
type Input struct {
	Slug        string           `json:"slug"`
	DisplayName string           `json:"display_name"`
	Locale      string           `json:"locale"`
	TimeZone    string           `json:"time_zone"`
	Metadata    map[string]any   `json:"metadata"`
	Contact     map[string]any   `json:"contact"`
	ExternalID  string           `json:"external_id"`
	Policy      *realm.OrgPolicy `json:"policy"`
	// Omitted lists members a partial update did not include; they keep
	// their current values (an empty string given explicitly clears).
	Omitted []string `json:"-"`
}

var localeTag = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$`)

func (in *Input) validate(metadataBytes int) *problem.Error {
	if in.DisplayName == "" || len(in.DisplayName) > 200 {
		return problem.ErrValidation.WithField("display_name", "required, at most 200 characters")
	}
	slug, ok := canonical.Slug(in.Slug)
	if !ok {
		return problem.ErrValidation.WithField("slug", "2-63 lowercase letters, digits or dashes")
	}
	in.Slug = slug
	if in.TimeZone != "" {
		if _, err := time.LoadLocation(in.TimeZone); err != nil {
			return problem.ErrValidation.WithField("time_zone", "unknown time zone")
		}
	}
	if in.Locale != "" && !localeTag.MatchString(in.Locale) {
		return problem.ErrValidation.WithField("locale", "a BCP 47 language tag such as en or pt-BR")
	}
	if m, _ := json.Marshal(in.Metadata); len(m) > metadataBytes {
		return problem.ErrValidation.WithField("metadata", fmt.Sprintf("at most %d bytes (limits.metadata_bytes)", metadataBytes))
	}
	// Contact is a small, typed record (TEN-002): known keys only.
	if c, _ := json.Marshal(in.Contact); len(c) > 4*1024 {
		return problem.ErrValidation.WithField("contact", "too large")
	}
	for k, v := range in.Contact {
		sv, ok := v.(string)
		if !ok || len(sv) > 320 {
			return problem.ErrValidation.WithField("contact."+k, "must be a string of at most 320 characters")
		}
		switch k {
		case "email", "security_email", "billing_email":
			if _, _, err := canonical.Email(sv); err != nil {
				return problem.ErrValidation.WithField("contact."+k, "invalid email address")
			}
		case "name", "phone", "url":
		default:
			return problem.ErrValidation.WithField("contact."+k, "unknown contact field (email, security_email, billing_email, name, phone, url)")
		}
	}
	if len(in.ExternalID) > 200 {
		return problem.ErrValidation.WithField("external_id", "too long")
	}
	return nil
}

// CreateTx creates an organization. When creatorUserID is set the creator becomes
// the initial owner in the same transaction (§27.1 step 4).
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, realmID string, in Input, creatorUserID string, actor audit.Ref) (*Organization, error) {
	if perr := in.validate(s.d.Cfg.Limits.MetadataBytes); perr != nil {
		return nil, perr
	}
	policy := realm.OrgPolicy{}
	if in.Policy != nil {
		policy = *in.Policy
		if perr := validateOrgPolicy(policy); perr != nil {
			return nil, perr
		}
		// A new organization owns no connection yet: only a realm-wide one
		// can be required (TEN-007, FED-006).
		if policy.SSOProviderID != "" {
			if err := ssoProviderUsableTx(ctx, tx, realmID, "", policy.SSOProviderID); err != nil {
				return nil, err
			}
		}
	}
	meta, _ := json.Marshal(nonNilMap(in.Metadata))
	contact, _ := json.Marshal(nonNilMap(in.Contact))
	pol, _ := json.Marshal(policy)
	now := s.d.Now()
	id := ids.New(ids.Organization)
	if err := s.slugFreeTx(ctx, tx, realmID, in.Slug, ""); err != nil {
		return nil, err
	}
	_, err := tx.Exec(ctx, `INSERT INTO organizations (id, realm_id, slug, display_name, locale, time_zone, metadata, contact, external_id, policy, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`, id, realmID, in.Slug, in.DisplayName, nilIfEmpty(in.Locale), nilIfEmpty(in.TimeZone),
		meta, contact, nilIfEmpty(in.ExternalID), pol, now)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, problem.ErrConflict.WithField("slug", "already in use")
		}
		return nil, err
	}
	if creatorUserID != "" {
		m, err := s.createMembershipTx(ctx, tx, realmID, id, creatorUserID, "creator", "", "active")
		if err != nil {
			return nil, err
		}
		owner, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgOwner)
		if err != nil {
			return nil, err
		}
		if _, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: owner.ID,
			Subject: authorization.Subject{Type: authorization.SubjectUser, ID: creatorUserID}, Scope: authorization.Scope{Type: authorization.ScopeOrganization, ID: id},
			Source: "creator", SkipCeiling: true}, actor); err != nil {
			return nil, err
		}
		_ = m
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.created", RealmID: realmID, OrgID: id, Actor: actor,
		Target: &audit.Ref{Type: "organization", ID: id}, Metadata: map[string]any{"slug": in.Slug, "creator_user_id": creatorUserID}}); err != nil {
		return nil, err
	}
	if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.created", RealmID: realmID, OrgID: id,
		AggregateType: "organization", AggregateID: id, Data: map[string]any{"organization_id": id, "slug": in.Slug}}); err != nil {
		return nil, err
	}
	return s.Get(ctx, tx, realmID, id)
}

// Create wraps CreateTx.
func (s *Service) Create(ctx context.Context, realmID string, in Input, creatorUserID string, actor audit.Ref) (*Organization, error) {
	var out *Organization
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.CreateTx(ctx, tx, realmID, in, creatorUserID, actor)
		return err
	})
	return out, err
}

// Update edits organization metadata and policy with optimistic concurrency.
func (s *Service) Update(ctx context.Context, realmID, id string, expectedVersion int64, in Input, actor audit.Ref, realmPolicy realm.Policy) (*Organization, error) {
	var out *Organization
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := scanOrg(tx.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE realm_id=$1 AND id=$2 AND state <> 'deleted' FOR UPDATE`, realmID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if in.Slug == "" {
			in.Slug = cur.Slug
		}
		if in.DisplayName == "" {
			in.DisplayName = cur.DisplayName
		}
		if in.Metadata == nil {
			in.Metadata = cur.Metadata
		}
		if in.Contact == nil {
			in.Contact = cur.Contact
		}
		for _, f := range in.Omitted {
			switch f {
			case "locale":
				in.Locale = cur.Locale
			case "time_zone":
				in.TimeZone = cur.TimeZone
			case "external_id":
				in.ExternalID = cur.ExternalID
			}
		}
		if perr := in.validate(s.d.Cfg.Limits.MetadataBytes); perr != nil {
			return perr
		}
		policy := cur.Policy
		if in.Policy != nil {
			policy = *in.Policy
			if perr := validateOrgPolicy(policy); perr != nil {
				return perr
			}
			if policy.SSOProviderID != "" && policy.SSOProviderID != cur.Policy.SSOProviderID {
				if err := ssoProviderUsableTx(ctx, tx, realmID, id, policy.SSOProviderID); err != nil {
					return err
				}
			}
		}
		if in.Slug != cur.Slug {
			// A renamed organization keeps its former slug as an alias, so
			// existing links resolve and nobody else can take the name (TEN-011).
			if err := s.slugFreeTx(ctx, tx, realmID, in.Slug, id); err != nil {
				return err
			}
			if err := s.addAliasTx(ctx, tx, realmID, id, cur.Slug, actor); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM organization_aliases WHERE realm_id=$1 AND organization_id=$2 AND alias=$3`, realmID, id, in.Slug); err != nil {
				return err
			}
		}
		meta, _ := json.Marshal(nonNilMap(in.Metadata))
		contact, _ := json.Marshal(nonNilMap(in.Contact))
		pol, _ := json.Marshal(policy)
		if _, err := tx.Exec(ctx, `UPDATE organizations SET slug=$3, display_name=$4, locale=$5, time_zone=$6, metadata=$7, contact=$8,
			external_id=$9, policy=$10, version=version+1, updated_at=$11 WHERE realm_id=$1 AND id=$2`, realmID, id, in.Slug, in.DisplayName,
			nilIfEmpty(in.Locale), nilIfEmpty(in.TimeZone), meta, contact, nilIfEmpty(in.ExternalID), pol, s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("slug", "already in use")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.updated", RealmID: realmID, OrgID: id, Actor: actor,
			Target: &audit.Ref{Type: "organization", ID: id}, Metadata: map[string]any{"policy_changed": in.Policy != nil}}); err != nil {
			return err
		}
		out, err = s.Get(ctx, tx, realmID, id)
		return err
	})
	return out, err
}

// validateOrgPolicy checks an organization policy; organization policy may
// only tighten realm policy (TEN-012).
// ssoProviderUsableTx allows an organization to require a connection that is
// realm-wide (shared by the realm administrator) or its own; another
// organization's connection is never usable, so the required-SSO path cannot
// bypass the cross-organization rule (FED-006, TEN-007).
func ssoProviderUsableTx(ctx context.Context, tx pgx.Tx, realmID, orgID, providerID string) error {
	var owner *string
	err := tx.QueryRow(ctx, `SELECT organization_id FROM identity_providers WHERE realm_id=$1 AND id=$2`, realmID, providerID).Scan(&owner)
	if storage.IsNoRows(err) || err == nil && owner != nil && *owner != orgID {
		return problem.ErrValidation.WithField("policy.sso_provider_id", "unknown connection, or one that belongs to another organization")
	}
	return err
}

func validateOrgPolicy(policy realm.OrgPolicy) *problem.Error {
	if policy.SessionIdleSeconds < 0 || policy.SessionAbsoluteSeconds < 0 {
		return problem.ErrValidation.WithField("policy", "session lifetimes must be positive")
	}
	if d := policy.AuditRetentionDays; d != 0 && (d < 30 || d > 3650) {
		return problem.ErrValidation.WithField("policy.audit_retention_days", "30..3650 days (it only ever extends retention)")
	}
	for _, d := range policy.AllowedEmailDomains {
		if _, err := canonical.Domain(d); err != nil {
			return problem.ErrValidation.WithField("policy.allowed_email_domains", "invalid domain "+d)
		}
	}
	if policy.ImpersonationApproval != "" && policy.ImpersonationApproval != "organization_owner" && policy.ImpersonationApproval != "customer" &&
		policy.ImpersonationApproval != "second_operator" && policy.ImpersonationApproval != "none" {
		return problem.ErrValidation.WithField("policy.impersonation_approval", "unsupported approval mode")
	}
	for _, m := range policy.AllowedLoginMethods {
		switch m {
		case "password", "passkey", "email_otp", "magic_link", "sms_otp", "sso", "certificate":
		default:
			return problem.ErrValidation.WithField("policy.allowed_login_methods", "password, passkey, email_otp, magic_link, sms_otp, sso or certificate")
		}
	}
	switch policy.RegistrationMode {
	case "", "inherit", "public", "closed", "invitation_only", "domain_restricted":
	default:
		return problem.ErrValidation.WithField("policy.registration_mode", "inherit, closed, invitation_only or domain_restricted")
	}
	return nil
}

// SetState suspends, reactivates or archives an organization (TEN-001). Suspension
// revokes all grants bound to the organization; reactivation never resurrects them.
func (s *Service) SetState(ctx context.Context, realmID, id, state string, actor audit.Ref, reason string) error {
	if state != "active" && state != "suspended" && state != "archived" {
		return problem.ErrValidation.WithField("state", "active, suspended or archived")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var cur string
		if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).Scan(&cur); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if cur == "deleting" || cur == "deleted" {
			return problem.ErrConflict.WithDetail("organization is being deleted")
		}
		if _, err := tx.Exec(ctx, `UPDATE organizations SET state=$3, authz_revision=authz_revision+1, version=version+1, updated_at=$4
			WHERE realm_id=$1 AND id=$2`, realmID, id, state, s.d.Now()); err != nil {
			return err
		}
		if state != "active" {
			if err := s.Sessions.RevokeOrganizationTx(ctx, tx, realmID, id, "organization_"+state); err != nil {
				return err
			}
		}
		ev := map[string]string{"active": "organization.reactivated", "suspended": "organization.suspended", "archived": "organization.archived"}[state]
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: ev, RealmID: realmID, OrgID: id, Actor: actor,
			Target: &audit.Ref{Type: "organization", ID: id}, ReasonCode: reason, Metadata: map[string]any{"previous_state": cur}}); err != nil {
			return err
		}
		_, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: ev, RealmID: realmID, OrgID: id, AggregateType: "organization", AggregateID: id,
			Data: map[string]any{"organization_id": id, "state": state}})
		return err
	})
}

// DeletionPreview summarizes the effect of deleting an organization (TEN-024).
type DeletionPreview struct {
	Members      int `json:"active_members"`
	Invitations  int `json:"pending_invitations"`
	ActiveGrants int `json:"active_grants"`
	Projects     int `json:"owned_projects"`
	// Clients of owned projects and service principals, suspended at once.
	Clients       int `json:"owned_clients"`
	Connectors    int `json:"provisioning_connectors"`
	SupportGrants int `json:"active_support_grants"`
	// Authorization and directory data removed by the deletion.
	RoleAssignments int `json:"role_assignments"`
	Groups          int `json:"groups"`
	VerifiedDomains int `json:"verified_domains"`
	// Clients and integrations disabled at once and their credentials erased.
	ServicePrincipals        int  `json:"owned_service_principals"`
	AutomationCredentials    int  `json:"active_automation_credentials"`
	Webhooks                 int  `json:"webhook_subscriptions"`
	IdentityProviders        int  `json:"identity_providers"`
	MailServer               bool `json:"mail_server_configured"`
	ConsentPreauthorizations int  `json:"consent_preauthorizations"`
	ExportResults            int  `json:"export_results"`
	PendingJobs              int  `json:"pending_jobs"`
	// Retained records: audit evidence stays under the audit retention policy
	// and any legal hold; deletion is itself recorded.
	AuditEvents int      `json:"retained_audit_events"`
	LegalHolds  int      `json:"active_legal_holds"`
	Retained    []string `json:"retained"`
}

// PreviewDeletion returns counts of affected records.
func (s *Service) PreviewDeletion(ctx context.Context, realmID, id string) (*DeletionPreview, error) {
	if _, err := s.Get(ctx, nil, realmID, id); err != nil {
		return nil, err
	}
	var p DeletionPreview
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM memberships WHERE organization_id=$1 AND state='active'),
		(SELECT count(*) FROM invitations WHERE organization_id=$1 AND state IN ('created','pending_delivery','pending_acceptance')),
		(SELECT count(*) FROM authorization_grants WHERE organization_id=$1 AND state='active'),
		(SELECT count(*) FROM projects WHERE owner_organization_id=$1 AND state <> 'archived'),
		(SELECT count(*) FROM clients WHERE state='active' AND (project_id IN (SELECT id FROM projects WHERE owner_organization_id=$1)
			OR service_principal_id IN (SELECT id FROM service_principals WHERE owner_organization_id=$1))),
		(SELECT count(*) FROM provisioning_connectors WHERE organization_id=$1 AND state='active'),
		(SELECT count(*) FROM impersonation_grants WHERE organization_id=$1 AND state='active'),
		(SELECT count(*) FROM role_assignments WHERE scope_type='organization' AND scope_id=$1),
		(SELECT count(*) FROM groups WHERE organization_id=$1),
		(SELECT count(*) FROM organization_domains WHERE organization_id=$1 AND state='verified'),
		(SELECT count(*) FROM service_principals WHERE owner_organization_id=$1 AND state <> 'deleted'),
		(SELECT count(*) FROM automation_credentials WHERE organization_id=$1 AND state='active'),
		(SELECT count(*) FROM webhook_subscriptions WHERE organization_id=$1),
		(SELECT count(*) FROM identity_providers WHERE organization_id=$1),
		EXISTS (SELECT 1 FROM notification_settings WHERE organization_id=$1 AND (smtp_config <> '{}'::jsonb OR smtp_secret_ciphertext IS NOT NULL)),
		(SELECT count(*) FROM consent_preauthorizations WHERE organization_id=$1 AND revoked_at IS NULL),
		(SELECT count(*) FROM jobs WHERE organization_id=$1 AND result_ciphertext IS NOT NULL),
		(SELECT count(*) FROM jobs WHERE organization_id=$1 AND state IN ('queued','running')),
		(SELECT count(*) FROM audit_events WHERE organization_id=$1),
		(SELECT count(*) FROM audit_legal_holds h WHERE h.realm_id=$2 AND h.released_at IS NULL AND (h.organization_id=$1
			OR (h.organization_id IS NULL AND (h.subject_id IS NULL OR EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=$1 AND m.user_id=h.subject_id)))))`,
		id, realmID).Scan(&p.Members, &p.Invitations, &p.ActiveGrants, &p.Projects, &p.Clients, &p.Connectors, &p.SupportGrants,
		&p.RoleAssignments, &p.Groups, &p.VerifiedDomains, &p.ServicePrincipals, &p.AutomationCredentials, &p.Webhooks, &p.IdentityProviders,
		&p.MailServer, &p.ConsentPreauthorizations, &p.ExportResults, &p.PendingJobs, &p.AuditEvents, &p.LegalHolds)
	p.Retained = []string{"audit events (until audit retention expires, longer under a legal hold)", "the organization record as a deleted tombstone",
		"memberships and invitations as removed or revoked records", "federated identity links of members (with the provider disabled)"}
	return &p, err
}

// BeginDeletion revokes access immediately and returns; the remaining cleanup runs
// as a retryable job (TEN-024). Audit records are retained.
func (s *Service) BeginDeletionTx(ctx context.Context, tx pgx.Tx, realmID, id string, actor audit.Ref, reason string) error {
	var cur string
	if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).Scan(&cur); err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	if cur == "deleting" || cur == "deleted" {
		return problem.ErrConflict.WithDetail("deletion already in progress")
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE organizations SET state='deleting', authz_revision=authz_revision+1, version=version+1, updated_at=$3
		WHERE realm_id=$1 AND id=$2`, realmID, id, now); err != nil {
		return err
	}
	if err := s.Sessions.RevokeOrganizationTx(ctx, tx, realmID, id, "organization_deleted"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE invitations SET state='revoked', updated_at=$2 WHERE organization_id=$1 AND state IN ('created','pending_delivery','pending_acceptance')`, id, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET state='disabled' WHERE organization_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE automation_credentials SET state='revoked', revoked_at=$2, revoke_reason='organization_deleted' WHERE organization_id=$1 AND state='active'`, id, now); err != nil {
		return err
	}
	// The organization's clients and integrations stop at once (TEN-024):
	// its service principals, webhooks, identity providers and consent
	// pre-authorizations; export results are erased and other queued work is
	// cancelled. Their credentials are revoked and erased when the deletion
	// finishes.
	for _, q := range []string{
		// Projects the organization owns are suspended with their clients and
		// those clients' refresh tokens (TEN-024): nothing it owned keeps
		// issuing tokens.
		`UPDATE projects SET state='suspended', updated_at=$2 WHERE owner_organization_id=$1 AND state='active'`,
		`UPDATE clients SET state='suspended', updated_at=$2 WHERE state='active' AND (project_id IN (SELECT id FROM projects WHERE owner_organization_id=$1)
			OR service_principal_id IN (SELECT id FROM service_principals WHERE owner_organization_id=$1))`,
		`UPDATE refresh_families SET state='revoked', revoked_at=$2, revoke_reason='organization_deleted' WHERE state='active' AND client_ref IN
			(SELECT id FROM clients WHERE project_id IN (SELECT id FROM projects WHERE owner_organization_id=$1)
				OR service_principal_id IN (SELECT id FROM service_principals WHERE owner_organization_id=$1))`,
		`UPDATE service_principals SET state='disabled', updated_at=$2 WHERE owner_organization_id=$1 AND state='active'`,
		`UPDATE webhook_subscriptions SET state='disabled', updated_at=$2 WHERE organization_id=$1 AND state <> 'disabled'`,
		`UPDATE identity_providers SET state='disabled', updated_at=$2 WHERE organization_id=$1 AND state <> 'disabled'`,
		`UPDATE consent_preauthorizations SET revoked_at=$2 WHERE organization_id=$1 AND revoked_at IS NULL`,
		`UPDATE jobs SET result_ciphertext=NULL, updated_at=$2 WHERE organization_id=$1 AND result_ciphertext IS NOT NULL`,
		`UPDATE jobs SET cancel_requested=true, state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END, updated_at=$2
			WHERE organization_id=$1 AND type <> 'organization.delete' AND state IN ('queued','running')`,
	} {
		if _, err := tx.Exec(ctx, q, id, now); err != nil {
			return err
		}
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.deletion.started", RealmID: realmID, OrgID: id, Actor: actor,
		Target: &audit.Ref{Type: "organization", ID: id}, ReasonCode: reason}); err != nil {
		return err
	}
	_, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.deleted", RealmID: realmID, OrgID: id, AggregateType: "organization", AggregateID: id,
		Data: map[string]any{"organization_id": id}})
	return err
}

// FinishDeletion removes memberships, assignments and private data in bounded steps.
// It is idempotent so a retried job cannot cause harm (TEST-058).
func (s *Service) FinishDeletion(ctx context.Context, realmID, id string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).Scan(&state); err != nil {
			return err
		}
		if state == "deleted" {
			return nil
		}
		if state != "deleting" {
			return problem.ErrConflict.WithDetail("organization is not being deleted")
		}
		now := s.d.Now()
		stmts := []string{
			`DELETE FROM role_assignments WHERE scope_type='organization' AND scope_id=$1`,
			`DELETE FROM group_memberships WHERE organization_id=$1`,
			// Membership metadata (USR-009) is erased with the membership.
			`UPDATE memberships SET state='removed', removed_at=$2, updated_at=$2, metadata='{}' WHERE organization_id=$1 AND state NOT IN ('removed','expired')`,
			`UPDATE organization_domains SET state='removed', updated_at=$2 WHERE organization_id=$1`,
			`UPDATE join_requests SET state='withdrawn' WHERE organization_id=$1 AND state='pending'`,
			// Former slugs and aliases are released with the organization, like
			// its slug (TEN-011).
			`DELETE FROM organization_aliases WHERE organization_id=$1`,
			// Customer-owned credentials are erased (TEN-022, TEN-024): the mail
			// server, webhook subscriptions (with their deliveries) and identity
			// provider secrets; disabled providers stay for their links.
			`DELETE FROM notification_settings WHERE organization_id=$1`,
			`DELETE FROM webhook_subscriptions WHERE organization_id=$1`,
			`UPDATE identity_providers SET secret_ciphertext=NULL, state='disabled' WHERE organization_id=$1`,
			// Credentials of the organization's service principals and of its
			// projects' clients are revoked; their digests and keys erased.
			`UPDATE client_credentials SET state='revoked', revoked_at=coalesce(revoked_at, $2), secret_digest=NULL, public_jwk=NULL WHERE client_ref IN
				(SELECT id FROM clients WHERE project_id IN (SELECT id FROM projects WHERE owner_organization_id=$1)
					OR service_principal_id IN (SELECT id FROM service_principals WHERE owner_organization_id=$1))`,
			`UPDATE organizations SET state='deleted', metadata='{}', contact='{}', external_id=NULL, display_name='[deleted]',
				slug=slug || '-deleted-' || substr(id, 5, 8), version=version+1, updated_at=$2 WHERE id=$1`,
		}
		for _, q := range stmts {
			args := []any{id}
			if strings.Contains(q, "$2") {
				args = append(args, now)
			}
			if _, err := tx.Exec(ctx, q, args...); err != nil {
				return err
			}
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.deletion.completed", RealmID: realmID, OrgID: id, Actor: audit.System,
			Target: &audit.Ref{Type: "organization", ID: id}})
		return err
	})
}

// List lists organizations for realm administrators.
func (s *Service) List(ctx context.Context, realmID, after string, limit int, q string) ([]*Organization, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+orgCols+` FROM organizations WHERE realm_id=$1 AND state <> 'deleted' AND ($2='' OR id > $2)
		AND ($4='' OR slug=$4 OR lower(display_name) LIKE '%' || lower($4) || '%') ORDER BY id LIMIT $3`, realmID, after, limit, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Organization{}
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---------- memberships ----------

const membershipCols = `m.id, m.organization_id, m.user_id, m.state, m.source, coalesce(m.source_reference,''), coalesce(m.external_id,''),
	m.joined_at, m.expires_at, m.removed_at, m.revision, m.created_at`

func scanMembership(row pgx.Row) (*Membership, error) {
	var m Membership
	err := row.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.State, &m.Source, &m.SourceRef, &m.ExternalID, &m.JoinedAt, &m.ExpiresAt,
		&m.RemovedAt, &m.Revision, &m.CreatedAt)
	return &m, err
}

// CreateMembershipTx records a membership with its provenance (TEN-015). Callers
// are responsible for authorization and role assignment.
func (s *Service) CreateMembershipTx(ctx context.Context, tx pgx.Tx, realmID, orgID, userID, source, sourceRef, state string) (*Membership, error) {
	return s.createMembershipTx(ctx, tx, realmID, orgID, userID, source, sourceRef, state)
}

func (s *Service) createMembershipTx(ctx context.Context, tx pgx.Tx, realmID, orgID, userID, source, sourceRef, state string) (*Membership, error) {
	var guest bool
	if err := tx.QueryRow(ctx, `SELECT is_guest FROM users WHERE realm_id=$1 AND id=$2`, realmID, userID).Scan(&guest); err == nil && guest {
		return nil, problem.ErrValidation.WithDetail("guest accounts cannot join organizations; upgrade the account first (REG-010)")
	}
	now := s.d.Now()
	id := ids.New(ids.Membership)
	var joined *time.Time
	if state == "active" {
		joined = &now
	}
	_, err := tx.Exec(ctx, `INSERT INTO memberships (id, realm_id, organization_id, user_id, state, source, source_reference, joined_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, id, realmID, orgID, userID, state, source, nilIfEmpty(sourceRef), joined, now)
	if err != nil {
		if storage.IsUniqueViolation(err, "memberships_single_live") {
			return nil, problem.ErrConflict.WithDetail("the user already has a membership in this organization")
		}
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithDetail("unknown user or organization in this realm")
		}
		return nil, err
	}
	return scanMembership(tx.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m WHERE id=$1`, id))
}

// Membership loads a membership in an organization (scoped by org to avoid IDOR).
func (s *Service) Membership(ctx context.Context, q storage.Querier, orgID, id string) (*Membership, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	m, err := scanMembership(q.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m WHERE m.organization_id=$1 AND m.id=$2`, orgID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return m, nil
}

// ActiveMembership returns the user's active membership in an organization, checking
// expiry and organization state (TEN-005).
func (s *Service) ActiveMembership(ctx context.Context, q storage.Querier, realmID, orgID, userID string) (*Membership, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	m, err := scanMembership(q.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m JOIN organizations o ON o.id=m.organization_id
		WHERE m.realm_id=$1 AND m.organization_id=$2 AND m.user_id=$3 AND m.state='active' AND o.state='active'
		AND (m.expires_at IS NULL OR m.expires_at > $4)`, realmID, orgID, userID, s.d.Now()))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return m, nil
}

// UserMemberships lists a user's live memberships (for self-service, never other users').
func (s *Service) UserMemberships(ctx context.Context, realmID, userID string) ([]map[string]any, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT m.id, m.organization_id, o.slug, o.display_name, m.state, o.state, m.joined_at
		FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.realm_id=$1 AND m.user_id=$2
		AND m.state NOT IN ('removed','expired') AND o.state NOT IN ('deleted','deleting') ORDER BY o.display_name`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var mid, oid, slug, name, mstate, ostate string
		var joined *time.Time
		if err := rows.Scan(&mid, &oid, &slug, &name, &mstate, &ostate, &joined); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"membership_id": mid, "organization_id": oid, "slug": slug, "display_name": name,
			"membership_state": mstate, "organization_state": ostate, "joined_at": joined})
	}
	return out, rows.Err()
}

// ListMembers lists members of one organization. The organization ID is a selector
// already authorized by the caller; every query is bound to it (TEST-009).
// withMetadata includes the membership metadata (USR-009); callers pass it
// only for readers who can manage the organization's members.
func (s *Service) ListMembers(ctx context.Context, orgID, after string, limit int, state string, withMetadata bool) ([]*Membership, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+membershipCols+`, coalesce(u.display_name,''),
		coalesce((SELECT original_value FROM user_identifiers i WHERE i.user_id=u.id AND i.type='email' AND i.is_primary LIMIT 1), ''), m.metadata
		FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND ($2='' OR m.id > $2)
		AND (($4='' AND m.state NOT IN ('removed','expired')) OR m.state=$4) ORDER BY m.id LIMIT $3`, orgID, after, limit, state)
	if err != nil {
		return nil, err
	}
	out := []*Membership{}
	for rows.Next() {
		var m Membership
		var meta []byte
		if err := rows.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.State, &m.Source, &m.SourceRef, &m.ExternalID, &m.JoinedAt, &m.ExpiresAt,
			&m.RemovedAt, &m.Revision, &m.CreatedAt, &m.DisplayName, &m.Email, &meta); err != nil {
			rows.Close()
			return nil, err
		}
		if withMetadata {
			m.Metadata = json.RawMessage(meta)
		}
		out = append(out, &m)
	}
	rows.Close()
	for _, m := range out {
		r, err := s.membershipRoles(ctx, s.d.DB.Pool, m.ID)
		if err != nil {
			return nil, err
		}
		m.Roles = r
	}
	return out, nil
}

func (s *Service) membershipRoles(ctx context.Context, q storage.Querier, membershipID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT r.name FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.membership_id=$1 ORDER BY r.name`, membershipID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AddMember adds an existing realm user to an organization by an administrator, with
// role assignments checked against the actor's ceiling (TEN-007, TEN-008).
func (s *Service) AddMember(ctx context.Context, realmID, orgID, userID string, roleIDs []string, actor authorization.Subject, auditActor audit.Ref) (*Membership, error) {
	var out *Membership
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.LockActiveTx(ctx, tx, realmID, orgID); err != nil {
			return err
		}
		if !s.Authz.Check(ctx, tx, realmID, actor, "org.members.write", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
			return problem.ErrForbidden
		}
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM users WHERE realm_id=$1 AND id=$2`, realmID, userID).Scan(&state); err != nil {
			return problem.ErrValidation.WithField("user_id", "unknown user")
		}
		if state != "active" {
			return problem.ErrValidation.WithField("user_id", "user is not active")
		}
		m, err := s.createMembershipTx(ctx, tx, realmID, orgID, userID, "admin", auditActor.ID, "active")
		if err != nil {
			return err
		}
		if len(roleIDs) == 0 {
			member, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgMember)
			if err != nil {
				return err
			}
			roleIDs = []string{member.ID}
		}
		for _, rid := range roleIDs {
			if _, err := s.Authz.AssignTx(ctx, tx, realmID, &actor, authorization.AssignInput{RoleID: rid,
				Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID}, Scope: authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID},
				Source: "admin"}, auditActor); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.added", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "membership", ID: m.ID}, Metadata: map[string]any{"source": "admin"}}); err != nil {
			return err
		}
		if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.membership.added", RealmID: realmID, OrgID: orgID,
			AggregateType: "membership", AggregateID: m.ID, Data: map[string]any{"user_id": userID, "membership_id": m.ID}}); err != nil {
			return err
		}
		out, err = s.Membership(ctx, tx, orgID, m.ID)
		return err
	})
	return out, err
}

// SetMembershipState suspends or reactivates a membership. Suspension in one
// organization never affects other memberships (TEN-004) and cannot remove the last
// active owner (TEN-006).
func (s *Service) SetMembershipState(ctx context.Context, realmID, orgID, membershipID, state string, actor authorization.Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.SetMembershipStateTx(ctx, tx, realmID, orgID, membershipID, state, &actor, auditActor)
	})
}

// SetMembershipStateTx is SetMembershipState inside tx. actor may be nil for
// trusted internal callers that checked their own scope (connector-scoped
// deprovisioning, PROV-005).
func (s *Service) SetMembershipStateTx(ctx context.Context, tx pgx.Tx, realmID, orgID, membershipID, state string, actor *authorization.Subject, auditActor audit.Ref) error {
	if state != "active" && state != "suspended" {
		return problem.ErrValidation.WithField("state", "active or suspended")
	}
	{
		if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, orgID); err != nil {
			return err
		}
		m, err := scanMembership(tx.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m WHERE m.organization_id=$1 AND m.id=$2 FOR UPDATE`, orgID, membershipID))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if m.State == "removed" || m.State == "expired" {
			return problem.ErrConflict.WithDetail("membership is no longer live")
		}
		if actor != nil {
			if err := s.requireMemberAuthority(ctx, tx, realmID, orgID, m, *actor); err != nil {
				return err
			}
		}
		if state == "suspended" {
			if err := s.guardLastOwner(ctx, tx, orgID, m); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET state=$2, revision=revision+1, updated_at=$3 WHERE id=$1`, membershipID, state, s.d.Now()); err != nil {
			return err
		}
		if state == "suspended" {
			if err := s.Sessions.RevokeOrgGrantsTx(ctx, tx, realmID, m.UserID, orgID, "membership_suspended"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$2, revoked_by_type='system', revoke_reason='membership_suspended'
				WHERE target_membership_id=$1 AND state='active'`, membershipID, s.d.Now()); err != nil {
				return err
			}
		}
		ev := "organization.membership.suspended"
		if state == "active" {
			ev = "organization.membership.reactivated"
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: ev, RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Subject: &audit.Ref{Type: "user", ID: m.UserID}, Target: &audit.Ref{Type: "membership", ID: membershipID}}); err != nil {
			return err
		}
		_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: ev, RealmID: realmID, OrgID: orgID, AggregateType: "membership", AggregateID: membershipID,
			Data: map[string]any{"user_id": m.UserID, "membership_id": membershipID, "authorization_revision": m.Revision + 1}})
		return err
	}
}

// MembershipMetadata returns a membership's metadata (USR-009), scoped by
// organization like Membership. Callers show it only to readers who can manage
// the organization's members.
func (s *Service) MembershipMetadata(ctx context.Context, q storage.Querier, orgID, membershipID string) (json.RawMessage, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	var meta []byte
	if err := q.QueryRow(ctx, `SELECT metadata FROM memberships WHERE organization_id=$1 AND id=$2`, orgID, membershipID).Scan(&meta); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return json.RawMessage(meta), nil
}

// SetMembershipMetadataTx merges patch into a live membership's metadata
// (USR-009): a key set to null is removed, other keys are replaced. Only an
// actor holding org.members.write in this organization, within the
// member-management ceiling, may change it; the result is bounded by
// limits.metadata_bytes. The audit record names the keys, never the values.
// Membership metadata is the organization's own data about the member: it is
// not the user's profile, admin_metadata or internal metadata, the user does
// not see it, and it never enters tokens.
func (s *Service) SetMembershipMetadataTx(ctx context.Context, tx pgx.Tx, realmID, orgID, membershipID string, patch map[string]any,
	actor authorization.Subject, auditActor audit.Ref) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, orgID); err != nil {
		return err
	}
	m, err := scanMembership(tx.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m WHERE m.organization_id=$1 AND m.id=$2 FOR UPDATE`, orgID, membershipID))
	if err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	if m.State == "removed" || m.State == "expired" {
		return problem.ErrConflict.WithDetail("membership is no longer live")
	}
	if err := s.requireMemberAuthority(ctx, tx, realmID, orgID, m, actor); err != nil {
		return err
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT metadata FROM memberships WHERE id=$1`, membershipID).Scan(&raw); err != nil {
		return err
	}
	cur := map[string]any{}
	_ = json.Unmarshal(raw, &cur)
	if cur == nil {
		cur = map[string]any{}
	}
	keys := make([]string, 0, len(patch))
	for k, v := range patch {
		keys = append(keys, k)
		if v == nil {
			delete(cur, k)
		} else {
			cur[k] = v
		}
	}
	slices.Sort(keys)
	out, err := json.Marshal(cur)
	if err != nil {
		return problem.ErrValidation.WithField("metadata", "must be a JSON object")
	}
	if len(out) > s.d.Cfg.Limits.MetadataBytes {
		return problem.ErrValidation.WithField("metadata", fmt.Sprintf("at most %d bytes (limits.metadata_bytes)", s.d.Cfg.Limits.MetadataBytes))
	}
	if _, err := tx.Exec(ctx, `UPDATE memberships SET metadata=$2, updated_at=$3 WHERE id=$1`, membershipID, out, s.d.Now()); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.metadata_updated", RealmID: realmID, OrgID: orgID, Actor: auditActor,
		Subject: &audit.Ref{Type: "user", ID: m.UserID}, Target: &audit.Ref{Type: "membership", ID: membershipID},
		Metadata: map[string]any{"metadata_keys": keys}})
	return err
}

// requireMemberAuthority checks org.members.write and prevents an administrator
// from acting on a member whose roles exceed the administrator's ceiling.
func (s *Service) requireMemberAuthority(ctx context.Context, tx pgx.Tx, realmID, orgID string, m *Membership, actor authorization.Subject) error {
	scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
	eff, err := s.Authz.Effective(ctx, tx, realmID, actor, scope)
	if err != nil {
		return err
	}
	if !eff.Has("org.members.write") {
		return problem.ErrForbidden
	}
	target, err := s.Authz.Effective(ctx, tx, realmID, authorization.Subject{Type: authorization.SubjectUser, ID: m.UserID}, scope)
	if err != nil {
		return err
	}
	for _, p := range target.List() {
		if strings.HasPrefix(p, "org.") && !eff.Has(p) {
			return problem.ErrGrantCeiling.WithDetail("the member holds organization permissions you cannot manage")
		}
	}
	return nil
}

func (s *Service) guardLastOwner(ctx context.Context, tx pgx.Tx, orgID string, m *Membership) error {
	isOwner, err := s.Authz.IsOrgOwnerTx(ctx, tx, m.ID)
	if err != nil || !isOwner {
		return err
	}
	var others int
	if err := tx.QueryRow(ctx, `SELECT count(DISTINCT m.user_id) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		JOIN memberships m ON m.id=ra.membership_id JOIN users u ON u.id=m.user_id WHERE ra.scope_type='organization' AND ra.scope_id=$1
		AND r.is_owner_role AND m.state='active' AND u.state='active' AND m.id <> $2`, orgID, m.ID).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return problem.ErrLastOwner
	}
	return nil
}

// RemoveMember removes a membership (§27.7): revokes the user's grants for this
// organization, stops support grants scoped to it and leaves other memberships and
// the realm-wide identity untouched.
func (s *Service) RemoveMember(ctx context.Context, realmID, orgID, membershipID string, actor *authorization.Subject, auditActor audit.Ref, reason string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.RemoveMemberTx(ctx, tx, realmID, orgID, membershipID, actor, auditActor, reason)
	})
}

// RemoveMemberTx is RemoveMember inside tx. actor may be nil for trusted internal
// callers (e.g. connector-scoped deprovisioning that already checked its scope).
func (s *Service) RemoveMemberTx(ctx context.Context, tx pgx.Tx, realmID, orgID, membershipID string, actor *authorization.Subject, auditActor audit.Ref, reason string) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, orgID); err != nil {
		return err
	}
	m, err := scanMembership(tx.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m WHERE m.organization_id=$1 AND m.id=$2 FOR UPDATE`, orgID, membershipID))
	if err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	if m.State == "removed" {
		return nil
	}
	selfLeave := actor != nil && actor.Type == authorization.SubjectUser && actor.ID == m.UserID
	if actor != nil && !selfLeave {
		if err := s.requireMemberAuthority(ctx, tx, realmID, orgID, m, *actor); err != nil {
			return err
		}
	}
	if err := s.guardLastOwner(ctx, tx, orgID, m); err != nil {
		return err
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE membership_id=$1`, membershipID); err != nil {
		return err
	}
	// Project roles the organization assigned to this member (TEN-020) end
	// with the membership.
	if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE realm_id=$1 AND subject_type='user' AND subject_id=$2 AND scope_type='project'
		AND ((source='project_grant' AND reason LIKE '%:direct:' || $3) OR (source='admin' AND reason = 'organization:' || $3))`,
		realmID, m.UserID, orgID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM group_memberships WHERE membership_id=$1`, membershipID); err != nil {
		return err
	}
	// The membership's metadata (USR-009) ends with it.
	if _, err := tx.Exec(ctx, `UPDATE memberships SET state='removed', removed_at=$2, revision=revision+1, updated_at=$2, metadata='{}' WHERE id=$1`, membershipID, now); err != nil {
		return err
	}
	if err := s.Sessions.RevokeOrgGrantsTx(ctx, tx, realmID, m.UserID, orgID, "membership_removed"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$2, revoked_by_type='system', revoke_reason='membership_removed'
		WHERE target_membership_id=$1 AND state='active'`, membershipID, now); err != nil {
		return err
	}
	// Owned automation credentials scoped to this organization stop working (MCH-007).
	if _, err := tx.Exec(ctx, `UPDATE automation_credentials SET state='revoked', revoked_at=$3, revoke_reason='membership_removed'
		WHERE owner_type='user' AND owner_id=$1 AND organization_id=$2 AND state='active'`, m.UserID, orgID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET authz_revision=authz_revision+1 WHERE id=$1`, m.UserID); err != nil {
		return err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.removed", RealmID: realmID, OrgID: orgID, Actor: auditActor,
		Subject: &audit.Ref{Type: "user", ID: m.UserID}, Target: &audit.Ref{Type: "membership", ID: membershipID}, ReasonCode: reason,
		Metadata: map[string]any{"self_leave": selfLeave}}); err != nil {
		return err
	}
	_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.membership.removed", RealmID: realmID, OrgID: orgID,
		AggregateType: "membership", AggregateID: membershipID, Data: map[string]any{"user_id": m.UserID, "membership_id": membershipID,
			"authorization_revision": m.Revision + 1}})
	return err
}

// TransferOwnership grants ownership to another active member and optionally
// releases the actor's ownership, atomically (TEN-006, USR-020).
func (s *Service) TransferOwnership(ctx context.Context, realmID, orgID, toMembershipID string, releaseOwn bool, actor authorization.Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.lockActiveTx(ctx, tx, realmID, orgID, true); err != nil {
			return err
		}
		scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
		if !s.Authz.Check(ctx, tx, realmID, actor, "org.ownership.transfer", scope) {
			return problem.ErrForbidden
		}
		target, err := scanMembership(tx.QueryRow(ctx, `SELECT `+membershipCols+` FROM memberships m WHERE m.organization_id=$1 AND m.id=$2 FOR UPDATE`, orgID, toMembershipID))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if target.State != "active" {
			return problem.ErrValidation.WithDetail("ownership can only move to an active member")
		}
		owner, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgOwner)
		if err != nil {
			return err
		}
		isOwner, err := s.Authz.IsOrgOwnerTx(ctx, tx, target.ID)
		if err != nil {
			return err
		}
		if !isOwner {
			if _, err := s.Authz.AssignTx(ctx, tx, realmID, &actor, authorization.AssignInput{RoleID: owner.ID,
				Subject: authorization.Subject{Type: authorization.SubjectUser, ID: target.UserID}, Scope: scope, Source: "ownership_transfer"}, auditActor); err != nil {
				return err
			}
		}
		if releaseOwn && actor.Type == authorization.SubjectUser && actor.ID != target.UserID {
			var aid string
			err := tx.QueryRow(ctx, `SELECT ra.id FROM role_assignments ra JOIN memberships m ON m.id=ra.membership_id
				WHERE ra.role_id=$1 AND m.organization_id=$2 AND m.user_id=$3`, owner.ID, orgID, actor.ID).Scan(&aid)
			if err == nil {
				if err := s.Authz.UnassignTx(ctx, tx, realmID, aid, nil, auditActor, true); err != nil {
					return err
				}
			}
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.ownership.transferred", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Subject: &audit.Ref{Type: "user", ID: target.UserID}, Metadata: map[string]any{"released_previous": releaseOwn}})
		return err
	})
}

// ExpireMemberships marks expired memberships (USR-015 lifecycle job).
func (s *Service) ExpireMemberships(ctx context.Context) (int, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, realm_id, organization_id, user_id FROM memberships WHERE state='active' AND expires_at IS NOT NULL AND expires_at <= $1 LIMIT 500`, s.d.Now())
	if err != nil {
		return 0, err
	}
	type item struct{ id, realm, org, user string }
	var list []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.realm, &it.org, &it.user); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, it)
	}
	rows.Close()
	for _, it := range list {
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE memberships SET state='expired', revision=revision+1, updated_at=$2, metadata='{}' WHERE id=$1 AND state='active'`, it.id, s.d.Now()); err != nil {
				return err
			}
			if err := s.Sessions.RevokeOrgGrantsTx(ctx, tx, it.realm, it.user, it.org, "membership_expired"); err != nil {
				return err
			}
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.expired", RealmID: it.realm, OrgID: it.org, Actor: audit.System,
				Subject: &audit.Ref{Type: "user", ID: it.user}, Target: &audit.Ref{Type: "membership", ID: it.id}})
			return err
		})
		if err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// OwnedResources lists the live projects, clients, service principals,
// resources and connections whose recorded owner is userID. Deleting the
// account first needs their ownership transferred (USR-020, MCH-007).
func (s *Service) OwnedResources(ctx context.Context, q storage.Querier, userID string) (map[string][]string, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT 'projects', id FROM projects WHERE owner_user_id=$1 AND state <> 'archived'
		UNION ALL SELECT 'clients', id FROM clients WHERE owner_user_id=$1 AND state <> 'decommissioned'
		UNION ALL SELECT 'service_principals', id FROM service_principals WHERE owner_user_id=$1 AND state <> 'deleted'
		UNION ALL SELECT 'resources', id FROM api_resources WHERE owner_user_id=$1 AND state = 'active'
		UNION ALL SELECT 'identity_providers', id FROM identity_providers WHERE owner_user_id=$1 AND state = 'active'
		ORDER BY 1, 2`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var kind, id string
		if err := rows.Scan(&kind, &id); err != nil {
			return nil, err
		}
		out[kind] = append(out[kind], id)
	}
	return out, rows.Err()
}

// SoleOwnerships returns the organizations in which userID is the only active
// owner. Removing such a user would leave the organization ownerless (USR-020).
func (s *Service) SoleOwnerships(ctx context.Context, q storage.Querier, userID string) ([]string, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT DISTINCT m.organization_id FROM role_assignments ra JOIN roles ro ON ro.id=ra.role_id
		JOIN memberships m ON m.id=ra.membership_id JOIN organizations o ON o.id=m.organization_id
		WHERE m.user_id=$1 AND ro.is_owner_role AND m.state='active' AND o.state NOT IN ('deleting','deleted')
		AND NOT EXISTS (SELECT 1 FROM role_assignments ra2 JOIN roles r2 ON r2.id=ra2.role_id JOIN memberships m2 ON m2.id=ra2.membership_id
			WHERE r2.is_owner_role AND m2.organization_id=m.organization_id AND m2.user_id<>$1 AND m2.state='active')
		ORDER BY 1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
