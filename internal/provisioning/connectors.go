// Package provisioning implements SCIM 2.0 provisioning (PROV-001..PROV-009,
// PROV-018): connectors are separately authenticated provisioners bound to
// one organization, the resource types they may manage and a role ceiling.
// A connector manages exactly the accounts and groups it provisioned (or
// adopted through a domain the organization verified); its external IDs are
// its own namespace, and deprovisioning only ever removes the
// organization's access, never the realm-wide account.
package provisioning

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/storage"
)

// Service manages connectors and serves SCIM.
type Service struct {
	d        *runtime.Deps
	Users    *identity.Service
	Orgs     *organization.Service
	Authz    *authorization.Service
	Sessions *session.Service
}

// New returns the service.
func New(d *runtime.Deps, users *identity.Service, orgs *organization.Service, authz *authorization.Service, sessions *session.Service) *Service {
	return &Service{d: d, Users: users, Orgs: orgs, Authz: authz, Sessions: sessions}
}

// Connector is a provisioning connector (PROV-003).
type Connector struct {
	ID                   string              `json:"id"`
	RealmID              string              `json:"-"`
	OrganizationID       string              `json:"organization_id"`
	Name                 string              `json:"name"`
	Kind                 string              `json:"kind"`
	State                string              `json:"state"`
	AllowedResourceTypes []string            `json:"allowed_resource_types"`
	RoleCeilingIDs       []string            `json:"role_ceiling_ids"`
	GroupRoleMappings    map[string][]string `json:"group_role_mappings"`
	DefaultRoleID        string              `json:"default_role_id,omitempty"`
	Config               map[string]any      `json:"config"`
	LastSyncAt           *time.Time          `json:"last_sync_at,omitempty"`
	LastError            string              `json:"last_error,omitempty"`
	Stats                map[string]any      `json:"stats"`
	Version              int64               `json:"version"`
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
}

// ConnectorInput creates or updates a connector.
type ConnectorInput struct {
	Name                 string              `json:"name"`
	Kind                 string              `json:"kind"`
	AllowedResourceTypes []string            `json:"allowed_resource_types"`
	RoleCeilingIDs       []string            `json:"role_ceiling_ids"`
	GroupRoleMappings    map[string][]string `json:"group_role_mappings"`
	DefaultRoleID        string              `json:"default_role_id"`
	Config               map[string]any      `json:"config"`
}

const connectorCols = `id, realm_id, organization_id, name, kind, state, allowed_resource_types, role_ceiling_ids, group_role_mappings,
	coalesce(default_role_id,''), config, last_sync_at, coalesce(last_error,''), stats, version, created_at, updated_at`

func scanConnector(row pgx.Row) (*Connector, error) {
	var c Connector
	var mappings, cfg, stats []byte
	err := row.Scan(&c.ID, &c.RealmID, &c.OrganizationID, &c.Name, &c.Kind, &c.State, &c.AllowedResourceTypes, &c.RoleCeilingIDs, &mappings,
		&c.DefaultRoleID, &cfg, &c.LastSyncAt, &c.LastError, &stats, &c.Version, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(mappings, &c.GroupRoleMappings)
	_ = json.Unmarshal(cfg, &c.Config)
	_ = json.Unmarshal(stats, &c.Stats)
	if c.GroupRoleMappings == nil {
		c.GroupRoleMappings = map[string][]string{}
	}
	if c.Stats == nil {
		c.Stats = map[string]any{}
	}
	return &c, nil
}

// Allows reports whether the connector may manage a SCIM resource type.
func (c *Connector) Allows(resourceType string) bool {
	return slices.Contains(c.AllowedResourceTypes, resourceType)
}

// Ref is the connector as an audit actor.
func (c *Connector) Ref() audit.Ref { return audit.Ref{Type: "connector", ID: c.ID} }

// validate checks a connector definition with the creator's authority: every
// role it may grant must be within the creator's delegation ceiling in the
// organization (PROV-003, PROV-006).
func (s *Service) validate(ctx context.Context, tx pgx.Tx, realmID, orgID string, in *ConnectorInput, actor authorization.Subject) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return problem.ErrValidation.WithField("name", "1 to 100 characters")
	}
	if in.Kind == "" {
		in.Kind = "scim_inbound"
	}
	// Outbound SCIM and LDAP connectors carry egress destinations and
	// credentials that internal/directory validates; they are managed only
	// through /directory-connectors (PROV-010, PROV-011).
	if in.Kind != "scim_inbound" {
		return problem.ErrValidation.WithField("kind", "scim_inbound (outbound and directory connectors are managed at /directory-connectors)")
	}
	if len(in.AllowedResourceTypes) == 0 {
		in.AllowedResourceTypes = []string{"User", "Group"}
	}
	for _, t := range in.AllowedResourceTypes {
		if t != "User" && t != "Group" {
			return problem.ErrValidation.WithField("allowed_resource_types", "User and/or Group")
		}
	}
	if in.RoleCeilingIDs == nil {
		in.RoleCeilingIDs = []string{}
	}
	if in.GroupRoleMappings == nil {
		in.GroupRoleMappings = map[string][]string{}
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	if len(in.RoleCeilingIDs) > 50 || len(in.GroupRoleMappings) > 200 {
		return problem.ErrValidation.WithDetail("at most 50 ceiling roles and 200 group mappings")
	}
	scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
	for _, id := range in.RoleCeilingIDs {
		role, err := s.Authz.Role(ctx, tx, realmID, id)
		if err != nil || role.Boundary != "organization" || (role.OrganizationID != "" && role.OrganizationID != orgID) {
			return problem.ErrValidation.WithField("role_ceiling_ids", "organization roles of this organization only")
		}
		if err := s.Authz.CheckAssignable(ctx, tx, realmID, actor, role, scope); err != nil {
			return problem.ErrGrantCeiling.WithDetail("role " + role.Name + " is beyond your own delegation ceiling")
		}
	}
	within := func(ids []string) bool {
		for _, id := range ids {
			if !slices.Contains(in.RoleCeilingIDs, id) {
				return false
			}
		}
		return true
	}
	if in.DefaultRoleID != "" && !within([]string{in.DefaultRoleID}) {
		return problem.ErrValidation.WithField("default_role_id", "must be one of role_ceiling_ids")
	}
	for group, roles := range in.GroupRoleMappings {
		if group == "" || len(group) > 256 || !within(roles) {
			return problem.ErrValidation.WithField("group_role_mappings", "each mapping names an external group and roles from role_ceiling_ids")
		}
	}
	return nil
}

// Create registers a connector and returns its bearer token once.
func (s *Service) Create(ctx context.Context, realmID, orgID string, in ConnectorInput, actor authorization.Subject, auditActor audit.Ref) (*Connector, string, error) {
	token := secret.Token(secret.PrefixSCIM)
	id := ids.New("con")
	var out *Connector
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.validate(ctx, tx, realmID, orgID, &in, actor); err != nil {
			return err
		}
		maps, _ := json.Marshal(in.GroupRoleMappings)
		cfg, _ := json.Marshal(in.Config)
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO provisioning_connectors (id, realm_id, organization_id, name, kind, token_digest, config, allowed_resource_types,
			role_ceiling_ids, group_role_mappings, default_role_id, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,nullif($11,''),$12,$12)`,
			id, realmID, orgID, in.Name, in.Kind, secret.Digest(token), cfg, in.AllowedResourceTypes, in.RoleCeilingIDs, maps, in.DefaultRoleID, now); err != nil {
			if storage.IsForeignKeyViolation(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "provisioning.connector.created", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id},
			Metadata: map[string]any{"kind": in.Kind, "resource_types": in.AllowedResourceTypes, "role_ceiling_ids": in.RoleCeilingIDs}}); err != nil {
			return err
		}
		var err error
		out, err = scanConnector(tx.QueryRow(ctx, `SELECT `+connectorCols+` FROM provisioning_connectors WHERE id=$1`, id))
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return out, token, nil
}

// Update replaces a connector's definition (not its token).
// Update replaces a connector's settings; version must match (API-010).
func (s *Service) Update(ctx context.Context, realmID, orgID, id string, version int64, in ConnectorInput, state string, actor authorization.Subject, auditActor audit.Ref) (*Connector, error) {
	var out *Connector
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := s.connector(ctx, tx, realmID, orgID, id)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return problem.ErrPrecondition
		}
		in.Kind = cur.Kind
		if err := s.validate(ctx, tx, realmID, orgID, &in, actor); err != nil {
			return err
		}
		if state == "" {
			state = cur.State
		}
		if state != "active" && state != "disabled" {
			return problem.ErrValidation.WithField("state", "active or disabled")
		}
		maps, _ := json.Marshal(in.GroupRoleMappings)
		cfg, _ := json.Marshal(in.Config)
		// Conditional on the version checked above, so a concurrent update
		// committed in between is never overwritten (API-010).
		tag, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET name=$2, state=$3, config=$4, allowed_resource_types=$5, role_ceiling_ids=$6,
			group_role_mappings=$7, default_role_id=nullif($8,''), version=version+1, updated_at=$9 WHERE id=$1 AND version=$10`,
			id, in.Name, state, cfg, in.AllowedResourceTypes, in.RoleCeilingIDs, maps, in.DefaultRoleID, s.d.Now(), version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrPrecondition
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "provisioning.connector.updated", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id}, Metadata: map[string]any{"state": state}}); err != nil {
			return err
		}
		out, err = scanConnector(tx.QueryRow(ctx, `SELECT `+connectorCols+` FROM provisioning_connectors WHERE id=$1`, id))
		return err
	})
	return out, err
}

// RotateToken issues a new token; the old one stops working at once.
func (s *Service) RotateToken(ctx context.Context, realmID, orgID, id string, auditActor audit.Ref) (string, error) {
	token := secret.Token(secret.PrefixSCIM)
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET token_digest=$4, version=version+1, updated_at=$5
			WHERE realm_id=$1 AND organization_id=$2 AND id=$3 AND kind='scim_inbound'`, realmID, orgID, id, secret.Digest(token), s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "provisioning.connector.token_rotated", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id}})
		return err
	})
	return token, err
}

func (s *Service) connector(ctx context.Context, q storage.Querier, realmID, orgID, id string) (*Connector, error) {
	c, err := scanConnector(q.QueryRow(ctx, `SELECT `+connectorCols+` FROM provisioning_connectors WHERE realm_id=$1 AND organization_id=$2 AND id=$3
		AND kind='scim_inbound'`, realmID, orgID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return c, err
}

// Get returns one connector of an organization.
func (s *Service) Get(ctx context.Context, realmID, orgID, id string) (*Connector, error) {
	return s.connector(ctx, s.d.DB.Pool, realmID, orgID, id)
}

// List returns an organization's connectors.
func (s *Service) List(ctx context.Context, realmID, orgID string) ([]*Connector, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+connectorCols+` FROM provisioning_connectors WHERE realm_id=$1 AND organization_id=$2
		AND kind='scim_inbound' ORDER BY name`, realmID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Connector{}
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Authenticate resolves a connector token. Disabled connectors and
// connectors of inactive organizations are refused.
func (s *Service) Authenticate(ctx context.Context, realmID, token string) (*Connector, error) {
	if !strings.HasPrefix(token, secret.PrefixSCIM) || len(token) > 256 {
		return nil, problem.ErrUnauthenticated
	}
	c, err := scanConnector(s.d.DB.Pool.QueryRow(ctx, `SELECT c.id, c.realm_id, c.organization_id, c.name, c.kind, c.state, c.allowed_resource_types,
		c.role_ceiling_ids, c.group_role_mappings, coalesce(c.default_role_id,''), c.config, c.last_sync_at, coalesce(c.last_error,''), c.stats, c.version,
		c.created_at, c.updated_at FROM provisioning_connectors c
		JOIN organizations o ON o.id=c.organization_id WHERE c.realm_id=$1 AND c.token_digest=$2 AND c.state='active' AND c.kind='scim_inbound'
		AND o.state='active'`, realmID, secret.Digest(token)))
	if err != nil {
		return nil, problem.ErrUnauthenticated
	}
	return c, nil
}

// RecordUse updates a connector's operational evidence (PROV-018): the last
// successful call, the last error, and counters per operation and outcome.
func (s *Service) RecordUse(ctx context.Context, c *Connector, op string, failure string) {
	now := s.d.Now()
	if failure == "" {
		_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE provisioning_connectors SET last_sync_at=$2,
			stats = jsonb_set(stats, ARRAY[$3], to_jsonb(coalesce((stats->>$3)::bigint, 0) + 1)) WHERE id=$1`, c.ID, now, op)
		return
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE provisioning_connectors SET last_error=$2,
		stats = jsonb_set(stats, ARRAY['errors'], to_jsonb(coalesce((stats->>'errors')::bigint, 0) + 1)) WHERE id=$1`, c.ID, truncate(failure, 200))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
