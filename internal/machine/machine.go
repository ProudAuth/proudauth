// Package machine manages non-human identities: service principals, scoped API
// keys and personal access tokens (§17).
package machine

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// ServicePrincipal is a non-human principal (MCH-001).
type ServicePrincipal struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	Description            string    `json:"description,omitempty"`
	OwnerUserID            string    `json:"owner_user_id,omitempty"`
	OwnerOrganizationID    string    `json:"owner_organization_id,omitempty"`
	State                  string    `json:"state"`
	AllowedOrganizationIDs []string  `json:"allowed_organization_ids"`
	IsAgent                bool      `json:"is_agent"`
	PermissionRevision     int64     `json:"permission_revision"`
	Version                int64     `json:"version"`
	CreatedAt              time.Time `json:"created_at"`
}

// Service manages machine identities.
type Service struct {
	d    *runtime.Deps
	Apps *application.Service
	Orgs *organization.Service
	// ScopePolicy narrows scopes to what the owner may currently hold
	// (organization ceiling and scope required permissions, TOK-008). Personal
	// tokens and API keys never exceed their owner's authority (MCH-006).
	ScopePolicy func(ctx context.Context, realmID, subjectType, subjectID, orgID string, scopes []string) ([]string, error)
}

// NewService returns the service.
func NewService(d *runtime.Deps, apps *application.Service, orgs *organization.Service) *Service {
	return &Service{d: d, Apps: apps, Orgs: orgs}
}

const spCols = `id, name, coalesce(description,''), coalesce(owner_user_id,''), coalesce(owner_organization_id,''), state, allowed_organization_ids,
	is_agent, permission_revision, version, created_at`

func scanSP(row pgx.Row) (*ServicePrincipal, error) {
	var p ServicePrincipal
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.OwnerUserID, &p.OwnerOrganizationID, &p.State, &p.AllowedOrganizationIDs, &p.IsAgent,
		&p.PermissionRevision, &p.Version, &p.CreatedAt)
	return &p, err
}

// SPInput creates or updates a service principal.
type SPInput struct {
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	OwnerUserID            string   `json:"owner_user_id"`
	OwnerOrganizationID    string   `json:"owner_organization_id"`
	AllowedOrganizationIDs []string `json:"allowed_organization_ids"`
	IsAgent                bool     `json:"is_agent"`
}

// Create creates a service principal with an accountable owner (DOM-009).
func (s *Service) Create(ctx context.Context, realmID string, in SPInput, actor audit.Ref) (*ServicePrincipal, error) {
	var out *ServicePrincipal
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.CreateTx(ctx, tx, realmID, in, actor)
		return err
	})
	return out, err
}

// CreateTx creates a service principal in tx.
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, realmID string, in SPInput, actor audit.Ref) (*ServicePrincipal, error) {
	if in.Name == "" || len(in.Name) > 200 {
		return nil, problem.ErrValidation.WithField("name", "required")
	}
	if in.OwnerUserID == "" && in.OwnerOrganizationID == "" {
		if actor.Type == "user" {
			in.OwnerUserID = actor.ID
		} else {
			return nil, problem.ErrValidation.WithField("owner_user_id", "an accountable owner is required (DOM-009)")
		}
	}
	// An autonomous agent answers to a person (MCH-017): an organization
	// alone is not an accountable owner for it.
	if in.IsAgent && in.OwnerUserID == "" {
		return nil, problem.ErrValidation.WithField("owner_user_id", "an agent needs an accountable human owner (MCH-017)")
	}
	id := ids.New(ids.ServicePrinc)
	_, err := tx.Exec(ctx, `INSERT INTO service_principals (id, realm_id, name, description, owner_user_id, owner_organization_id, allowed_organization_ids,
		is_agent, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, id, realmID, in.Name, nilIfEmpty(in.Description),
		nilIfEmpty(in.OwnerUserID), nilIfEmpty(in.OwnerOrganizationID), nonNil(in.AllowedOrganizationIDs), in.IsAgent, s.d.Now())
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, problem.ErrConflict.WithField("name", "already exists")
		}
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithDetail("unknown owner user or organization")
		}
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "service_principal.created", RealmID: realmID, OrgID: in.OwnerOrganizationID, Actor: actor,
		Target: &audit.Ref{Type: "service_principal", ID: id}, Metadata: map[string]any{"name": in.Name, "is_agent": in.IsAgent}}); err != nil {
		return nil, err
	}
	return scanSP(tx.QueryRow(ctx, `SELECT `+spCols+` FROM service_principals WHERE id=$1`, id))
}

// Get loads a service principal.
func (s *Service) Get(ctx context.Context, realmID, id string) (*ServicePrincipal, error) {
	p, err := scanSP(s.d.DB.Pool.QueryRow(ctx, `SELECT `+spCols+` FROM service_principals WHERE realm_id=$1 AND id=$2 AND state <> 'deleted'`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return p, err
}

// List lists service principals.
func (s *Service) List(ctx context.Context, realmID, after string, limit int) ([]*ServicePrincipal, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+spCols+` FROM service_principals WHERE realm_id=$1 AND state <> 'deleted' AND ($2='' OR id > $2)
		ORDER BY id LIMIT $3`, realmID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ServicePrincipal{}
	for rows.Next() {
		p, err := scanSP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Update edits a service principal.
func (s *Service) Update(ctx context.Context, realmID, id string, expectedVersion int64, in SPInput, actor audit.Ref) (*ServicePrincipal, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := scanSP(tx.QueryRow(ctx, `SELECT `+spCols+` FROM service_principals WHERE realm_id=$1 AND id=$2 AND state <> 'deleted' FOR UPDATE`, realmID, id))
		if err != nil {
			return problem.ErrNotFound
		}
		if expectedVersion != 0 && p.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		name := p.Name
		if in.Name != "" {
			name = in.Name
		}
		orgs := p.AllowedOrganizationIDs
		if in.AllowedOrganizationIDs != nil {
			orgs = in.AllowedOrganizationIDs
		}
		owner := p.OwnerUserID
		if in.OwnerUserID != "" {
			owner = in.OwnerUserID
		}
		if _, err := tx.Exec(ctx, `UPDATE service_principals SET name=$3, description=coalesce(nullif($4,''), description), allowed_organization_ids=$5,
			owner_user_id=$6, permission_revision=permission_revision+1, version=version+1, updated_at=$7 WHERE realm_id=$1 AND id=$2`,
			realmID, id, name, in.Description, orgs, nilIfEmpty(owner), s.d.Now()); err != nil {
			if storage.IsForeignKeyViolation(err) {
				return problem.ErrValidation.WithDetail("unknown owner")
			}
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "service_principal.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "service_principal", ID: id}, Metadata: map[string]any{"owner_changed": owner != p.OwnerUserID}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, realmID, id)
}

// SetState disables, re-enables or deletes a service principal. Disabling stops all
// issuance and makes online verification fail immediately; deletion also revokes
// its keys (MCH-001, MCH-007).
func (s *Service) SetState(ctx context.Context, realmID, id, state string, actor audit.Ref) error {
	if state != "active" && state != "disabled" && state != "deleted" {
		return problem.ErrValidation.WithField("state", "active, disabled or deleted")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE service_principals SET state=$3, permission_revision=permission_revision+1, version=version+1, updated_at=$4
			WHERE realm_id=$1 AND id=$2 AND state <> 'deleted'`, realmID, id, state, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if state != "active" {
			if _, err := tx.Exec(ctx, `UPDATE automation_credentials SET state='revoked', revoked_at=$2, revoke_reason='owner_'||$3
				WHERE owner_type='service_principal' AND owner_id=$1 AND state='active'`, id, s.d.Now(), state); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE subject_id=$1 AND revoked_at IS NULL`, id, s.d.Now()); err != nil {
				return err
			}
		}
		if state == "deleted" {
			if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE subject_type='service_principal' AND subject_id=$1`, id); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "service_principal." + state, RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "service_principal", ID: id}}); err != nil {
			return err
		}
		_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "service_principal.state_changed", RealmID: realmID, AggregateType: "service_principal",
			AggregateID: id, Data: map[string]any{"service_principal_id": id, "state": state}})
		return err
	})
}

// ---------- API keys and personal access tokens ----------

// Credential is safe automation-credential metadata (MCH-008).
type Credential struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	OwnerType      string     `json:"owner_type"`
	OwnerID        string     `json:"owner_id"`
	Name           string     `json:"name"`
	DisplayPrefix  string     `json:"display_prefix"`
	Scopes         []string   `json:"scopes"`
	ResourceID     string     `json:"resource_id"`
	OrganizationID string     `json:"organization_id,omitempty"`
	State          string     `json:"state"`
	ExpiresAt      time.Time  `json:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

const credCols = `id, kind, owner_type, owner_id, name, display_prefix, scopes, resource_id, coalesce(organization_id,''), state, expires_at,
	last_used_at, created_at, revoked_at`

func scanCred(row pgx.Row) (*Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.Kind, &c.OwnerType, &c.OwnerID, &c.Name, &c.DisplayPrefix, &c.Scopes, &c.ResourceID, &c.OrganizationID, &c.State,
		&c.ExpiresAt, &c.LastUsedAt, &c.CreatedAt, &c.RevokedAt)
	return &c, err
}

// CredentialInput creates an API key or PAT.
type CredentialInput struct {
	Name           string   `json:"name"`
	Audience       string   `json:"audience"`
	Scopes         []string `json:"scopes"`
	OrganizationID string   `json:"organization_id"`
	TTLDays        int      `json:"ttl_days"`
}

// Create issues an API key (owner service principal) or PAT (owner user). The secret
// is shown once (MCH-008). Credentials never target the account or admin APIs and
// never carry privileged scopes (IMP-012, MCH-004).
func (s *Service) CreateCredential(ctx context.Context, realmID, kind, ownerType, ownerID string, in CredentialInput, actor audit.Ref) (string, *Credential, error) {
	if kind != "api_key" && kind != "personal_token" {
		return "", nil, problem.ErrValidation.WithField("kind", "api_key or personal_token")
	}
	if in.Name == "" || len(in.Name) > 100 {
		return "", nil, problem.ErrValidation.WithField("name", "required")
	}
	if in.TTLDays <= 0 {
		in.TTLDays = 90
	}
	if in.TTLDays > 365 {
		return "", nil, problem.ErrValidation.WithField("ttl_days", "at most 365 days (expiry is mandatory)")
	}
	res, err := s.Apps.ResourceByAudience(ctx, nil, realmID, in.Audience)
	if err != nil || res.State != "active" {
		return "", nil, problem.ErrValidation.WithField("audience", "unknown resource")
	}
	if res.Kind != application.KindBusiness {
		return "", nil, problem.ErrValidation.WithField("audience", "automation credentials can only target business APIs")
	}
	if len(in.Scopes) == 0 {
		return "", nil, problem.ErrValidation.WithField("scopes", "at least one scope is required")
	}
	for _, sc := range in.Scopes {
		idx := slices.IndexFunc(res.Scopes, func(d application.Scope) bool { return d.Name == sc })
		if idx < 0 {
			return "", nil, problem.ErrValidation.WithField("scopes", "scope "+sc+" is not declared by the resource")
		}
		if res.Scopes[idx].Sensitivity == "privileged" {
			return "", nil, problem.ErrValidation.WithField("scopes", "privileged scopes cannot be delegated to automation credentials")
		}
	}
	if res.RequiresOrganization && in.OrganizationID == "" {
		return "", nil, problem.ErrValidation.WithField("organization_id", "required for this resource")
	}
	if kind == "personal_token" && in.OrganizationID != "" && s.Orgs != nil {
		org, err := s.Orgs.Get(ctx, nil, realmID, in.OrganizationID)
		if err != nil {
			return "", nil, problem.ErrValidation.WithField("organization_id", "unknown organization")
		}
		if org.Policy.PersonalTokens == "disabled" {
			return "", nil, problem.ErrForbidden.WithDetail("this organization does not allow personal access tokens")
		}
		if max := org.Policy.PersonalTokenMaxDays; max > 0 && in.TTLDays > max {
			return "", nil, problem.ErrValidation.WithField("ttl_days", fmt.Sprintf("this organization allows at most %d days", max))
		}
	}
	if s.ScopePolicy != nil {
		permitted, err := s.ScopePolicy(ctx, realmID, ownerType, ownerID, in.OrganizationID, in.Scopes)
		if err != nil {
			return "", nil, err
		}
		for _, sc := range in.Scopes {
			if !slices.Contains(permitted, sc) {
				return "", nil, problem.ErrGrantCeiling.WithDetail("scope " + sc + " exceeds the owner's current authority")
			}
		}
	}
	prefix := secret.PrefixAPIKey
	if kind == "personal_token" {
		prefix = secret.PrefixPAT
	}
	plain := secret.Token(prefix)
	var out *Credential
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if in.OrganizationID != "" {
			if ownerType == "user" {
				if _, err := s.Orgs.ActiveMembership(ctx, tx, realmID, in.OrganizationID, ownerID); err != nil {
					return problem.ErrForbidden.WithDetail("no active membership in that organization")
				}
			} else {
				var allowed []string
				var ownerOrg *string
				if err := tx.QueryRow(ctx, `SELECT allowed_organization_ids, owner_organization_id FROM service_principals WHERE id=$1 AND state='active'`, ownerID).Scan(&allowed, &ownerOrg); err != nil {
					return problem.ErrValidation.WithDetail("service principal is not active")
				}
				if !slices.Contains(allowed, in.OrganizationID) && (ownerOrg == nil || *ownerOrg != in.OrganizationID) {
					return problem.ErrForbidden.WithDetail("service principal is not allowed in that organization")
				}
			}
		}
		id := ids.New(ids.Automation)
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO automation_credentials (id, realm_id, kind, owner_type, owner_id, name, display_prefix, secret_digest,
			scopes, resource_id, organization_id, expires_at, created_by_type, created_by_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			id, realmID, kind, ownerType, ownerID, in.Name, plain[:len(prefix)+6], secret.Digest(plain), in.Scopes, res.ID, nilIfEmpty(in.OrganizationID),
			now.Add(time.Duration(in.TTLDays)*24*time.Hour), actor.Type, actor.ID, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "automation_credential.created", RealmID: realmID, OrgID: in.OrganizationID, Actor: actor,
			Subject: &audit.Ref{Type: ownerType, ID: ownerID}, Target: &audit.Ref{Type: kind, ID: id},
			Metadata: map[string]any{"display_prefix": plain[:len(prefix)+6], "audience": res.Audience, "scopes": in.Scopes, "ttl_days": in.TTLDays}}); err != nil {
			return err
		}
		var err error
		out, err = scanCred(tx.QueryRow(ctx, `SELECT `+credCols+` FROM automation_credentials WHERE id=$1`, id))
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return plain, out, nil
}

// ListCredentials lists credentials for an owner.
func (s *Service) ListCredentials(ctx context.Context, realmID, ownerType, ownerID string) ([]*Credential, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+credCols+` FROM automation_credentials WHERE realm_id=$1 AND ($2='' OR owner_type=$2) AND ($3='' OR owner_id=$3)
		ORDER BY created_at DESC LIMIT 500`, realmID, ownerType, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Credential{}
	for rows.Next() {
		c, err := scanCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeCredential revokes immediately; online verification observes it at once (MCH-005).
func (s *Service) RevokeCredential(ctx context.Context, realmID, id, ownerType, ownerID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE automation_credentials SET state='revoked', revoked_at=$5, revoke_reason='revoked'
			WHERE realm_id=$1 AND id=$2 AND ($3='' OR owner_type=$3) AND ($4='' OR owner_id=$4) AND state='active'`, realmID, id, ownerType, ownerID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "automation_credential.revoked", RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "automation_credential", ID: id}})
		return err
	})
}

// Introspect validates an API key or PAT against central state, so every
// authentication adapter observes revocation identically (TEST-065).
func (s *Service) Introspect(ctx context.Context, realmID, issuer, plain string, allowed map[string]bool) map[string]any {
	inactive := map[string]any{"active": false}
	if !(strings.HasPrefix(plain, secret.PrefixAPIKey) || strings.HasPrefix(plain, secret.PrefixPAT)) || len(plain) > 100 {
		return inactive
	}
	c, err := scanCred(s.d.DB.Pool.QueryRow(ctx, `SELECT `+credCols+` FROM automation_credentials WHERE realm_id=$1 AND secret_digest=$2`, realmID, secret.Digest(plain)))
	if err != nil || c.State != "active" || !s.d.Now().Before(c.ExpiresAt) || !allowed[c.ResourceID] {
		return inactive
	}
	// Owner must still be eligible.
	var ok, agent bool
	if c.OwnerType == "user" {
		_ = s.d.DB.Pool.QueryRow(ctx, `SELECT state='active' FROM users WHERE id=$1`, c.OwnerID).Scan(&ok)
		if ok && c.OrganizationID != "" {
			_, err := s.Orgs.ActiveMembership(ctx, nil, realmID, c.OrganizationID, c.OwnerID)
			ok = err == nil
		}
	} else {
		_ = s.d.DB.Pool.QueryRow(ctx, `SELECT state='active', is_agent FROM service_principals WHERE id=$1`, c.OwnerID).Scan(&ok, &agent)
	}
	if !ok {
		return inactive
	}
	res, err := s.Apps.Resource(ctx, nil, realmID, c.ResourceID)
	if err != nil || res.State != "active" {
		return inactive
	}
	// Scopes are re-checked against the owner's current authority on every
	// use; a credential never outlives the permissions it was minted under.
	scopes := c.Scopes
	if s.ScopePolicy != nil {
		if scopes, err = s.ScopePolicy(ctx, realmID, c.OwnerType, c.OwnerID, c.OrganizationID, c.Scopes); err != nil || len(scopes) == 0 {
			return inactive
		}
	}
	// Last-use metadata (MCH-005), written at most once a minute. The cast
	// types the parameter: an untyped "$2 - interval" resolves to interval
	// arithmetic and the statement fails.
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE automation_credentials SET last_used_at=$2 WHERE id=$1
		AND (last_used_at IS NULL OR last_used_at < $2::timestamptz - interval '1 minute')`, c.ID, s.d.Now())
	kind := "api_key"
	if c.Kind == "personal_token" {
		kind = "personal_access"
	}
	out := map[string]any{"active": true, "iss": issuer, "sub": c.OwnerID, "aud": res.Audience, "scope": strings.Join(scopes, " "),
		"exp": c.ExpiresAt.Unix(), "iat": c.CreatedAt.Unix(), "jti": c.ID, "token_kind": kind, "subject_type": c.OwnerType, "token_type": "Bearer"}
	if c.OrganizationID != "" {
		out["org_id"] = c.OrganizationID
	}
	if agent {
		// An agent's credentials are marked as its access tokens are (MCH-017).
		out["agent"] = true
	}
	return out
}

// HandleOwnerDepartures applies a realm's owner-departure policy (MCH-007) to
// service principals whose accountable owner is no longer active: the
// departure is recorded and audited once, and under "disable" the principal is
// disabled (revoking its credentials) once the grace period has passed. A new
// active owner clears the marker.
func (s *Service) HandleOwnerDepartures(ctx context.Context, realmID, policy string, grace time.Duration) (int, error) {
	now := s.d.Now()
	if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE service_principals p SET owner_departed_at=NULL WHERE realm_id=$1 AND owner_departed_at IS NOT NULL
		AND EXISTS (SELECT 1 FROM users u WHERE u.id=p.owner_user_id AND u.state='active')`, realmID); err != nil {
		return 0, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `UPDATE service_principals p SET owner_departed_at=$2 WHERE realm_id=$1 AND state='active'
		AND owner_departed_at IS NULL AND owner_user_id IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=p.owner_user_id AND u.state='active') RETURNING id, owner_user_id`, realmID, now)
	if err != nil {
		return 0, err
	}
	type dep struct{ id, owner string }
	var found []dep
	for rows.Next() {
		var d dep
		if err := rows.Scan(&d.id, &d.owner); err != nil {
			rows.Close()
			return 0, err
		}
		found = append(found, d)
	}
	rows.Close()
	n := 0
	for _, d := range found {
		if _, err := s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "service_principal.owner_departed", RealmID: realmID, Actor: audit.System,
			Target: &audit.Ref{Type: "service_principal", ID: d.id}, Subject: &audit.Ref{Type: "user", ID: d.owner},
			Metadata: map[string]any{"policy": policy}}); err != nil {
			return n, err
		}
		n++
	}
	if policy != "disable" {
		return n, nil
	}
	due, err := s.d.DB.Pool.Query(ctx, `SELECT id FROM service_principals WHERE realm_id=$1 AND state='active' AND owner_departed_at IS NOT NULL
		AND owner_departed_at <= $2 LIMIT 100`, realmID, now.Add(-grace))
	if err != nil {
		return n, err
	}
	var ids []string
	for due.Next() {
		var id string
		if err := due.Scan(&id); err != nil {
			due.Close()
			return n, err
		}
		ids = append(ids, id)
	}
	due.Close()
	for _, id := range ids {
		if err := s.SetState(audit.WithOverride(ctx, audit.Override{Reason: "owner_departed"}), realmID, id, "disabled", audit.System); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// InventoryItem flags risky automation credentials (MCH-016).
type InventoryItem struct {
	Credential
	Flags []string `json:"flags"`
}

// Inventory lists credentials that need attention (MCH-016, MCH-007, APP-014):
// expiring, unused, ownerless, owned by a service principal whose accountable
// owner left (owner_departed), carrying scopes beyond the owner's current
// authority (over_privileged); client secrets are included with kind
// client_secret.
func (s *Service) Inventory(ctx context.Context, realmID string, expiringWithin, unusedFor time.Duration) ([]InventoryItem, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+credCols+`,
		(owner_type='user' AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=owner_id AND u.state='active')) OR
		(owner_type='service_principal' AND NOT EXISTS (SELECT 1 FROM service_principals p WHERE p.id=owner_id AND p.state='active')),
		owner_type='service_principal' AND EXISTS (SELECT 1 FROM service_principals p WHERE p.id=owner_id AND p.owner_user_id IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=p.owner_user_id AND u.state='active'))
		FROM automation_credentials WHERE realm_id=$1 AND state='active' ORDER BY expires_at`, realmID)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	out := []InventoryItem{}
	for rows.Next() {
		var it InventoryItem
		var ownerless, departed bool
		c := &it.Credential
		if err := rows.Scan(&c.ID, &c.Kind, &c.OwnerType, &c.OwnerID, &c.Name, &c.DisplayPrefix, &c.Scopes, &c.ResourceID, &c.OrganizationID, &c.State,
			&c.ExpiresAt, &c.LastUsedAt, &c.CreatedAt, &c.RevokedAt, &ownerless, &departed); err != nil {
			rows.Close()
			return nil, err
		}
		it.Flags = ageFlags(now, c.ExpiresAt, c.LastUsedAt, c.CreatedAt, expiringWithin, unusedFor)
		if ownerless {
			it.Flags = append(it.Flags, "ownerless")
		}
		if departed {
			it.Flags = append(it.Flags, "owner_departed")
		}
		out = append(out, it)
	}
	rows.Close()
	// Over-privilege is evaluated outside the row loop (it queries again).
	kept := out[:0]
	for _, it := range out {
		c := it.Credential
		if s.ScopePolicy != nil && !slices.Contains(it.Flags, "ownerless") {
			if permitted, err := s.ScopePolicy(ctx, realmID, c.OwnerType, c.OwnerID, c.OrganizationID, c.Scopes); err == nil && len(permitted) < len(c.Scopes) {
				it.Flags = append(it.Flags, "over_privileged")
			}
		}
		if len(it.Flags) > 0 {
			kept = append(kept, it)
		}
	}
	out = kept
	crows, err := s.d.DB.Pool.Query(ctx, `SELECT cc.id, c.id, c.client_id, coalesce(cc.display_prefix,''), cc.state, cc.expires_at, cc.last_used_at, cc.created_at,
		(c.owner_user_id IS NULL OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id=c.owner_user_id AND u.state='active')) AND cardinality(c.contacts)=0
		FROM client_credentials cc JOIN clients c ON c.id=cc.client_ref WHERE cc.realm_id=$1 AND cc.state='active' AND cc.kind='secret' AND c.state='active'`, realmID)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var it InventoryItem
		var exp *time.Time
		var orphan bool
		c := &it.Credential
		if err := crows.Scan(&c.ID, &c.OwnerID, &c.Name, &c.DisplayPrefix, &c.State, &exp, &c.LastUsedAt, &c.CreatedAt, &orphan); err != nil {
			return nil, err
		}
		c.Kind, c.OwnerType = "client_secret", "client"
		if exp != nil {
			c.ExpiresAt = *exp
			it.Flags = ageFlags(now, *exp, c.LastUsedAt, c.CreatedAt, expiringWithin, unusedFor)
		} else {
			it.Flags = ageFlags(now, now.Add(100*365*24*time.Hour), c.LastUsedAt, c.CreatedAt, expiringWithin, unusedFor)
			it.Flags = append(it.Flags, "no_expiry")
		}
		if orphan {
			it.Flags = append(it.Flags, "ownerless")
		}
		if len(it.Flags) > 0 {
			out = append(out, it)
		}
	}
	return out, crows.Err()
}

func ageFlags(now, expires time.Time, lastUsed *time.Time, created time.Time, expiringWithin, unusedFor time.Duration) []string {
	var f []string
	if expires.Sub(now) < expiringWithin {
		f = append(f, "expiring")
	}
	if (lastUsed == nil && now.Sub(created) > unusedFor) || (lastUsed != nil && now.Sub(*lastUsed) > unusedFor) {
		f = append(f, "unused")
	}
	return f
}

// ExpireCredentials marks expired credentials.
func (s *Service) ExpireCredentials(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE automation_credentials SET state='expired' WHERE state='active' AND expires_at <= $1`, s.d.Now())
	return tag.RowsAffected(), err
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
