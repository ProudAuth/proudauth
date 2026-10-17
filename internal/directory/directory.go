// Package directory integrates external directories and downstream systems
// with the identity domain:
//
//   - LDAP / Active Directory federation (PROV-011, FED-015): connectors per
//     realm (workforce) or per organization, with ordered endpoints, TLS,
//     timeouts and failover on transport errors only (PROV-014); passwords of
//     directory-sourced accounts are verified by a bind as the user, never by
//     reading password hashes, and an unreachable directory fails closed.
//   - Directory synchronization (PROV-012, PROV-017): full and incremental
//     runs as worker jobs with change cursors, dry-run plans, conflict
//     reports, deletion detection behind a safety threshold, and
//     per-attribute authority that prevents oscillating overwrites.
//   - Directory-authoritative accounts (USR-022, PROV-013): read-only,
//     import-only and write-back modes; local edits of externally managed
//     attributes are refused through every API.
//   - Outbound SCIM provisioning (PROV-010): eligible account and group
//     lifecycle pushed to downstream SCIM 2.0 services from the outbox, with
//     retries, dead-lettering, idempotency and reconciliation.
//   - Operational evidence (PROV-018) without credentials.
//
// Connectors are rows of provisioning_connectors (kinds 'ldap' and
// 'scim_outbound'); inbound SCIM connectors stay with internal/provisioning.
// Kerberos/SPNEGO (PROV-015) and password write-back (PROV-013) are not
// offered; see the module documentation.
package directory

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/slots"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Service is the directory integration module.
type Service struct {
	d     *runtime.Deps
	Users *identity.Service
	Orgs  *organization.Service
	Authz *authorization.Service
	Jobs  *jobs.Service
	m     *metrics
	// RootCAs are the trusted roots for directory TLS (system roots plus
	// directory.ca_file); connectors may add their own.
	RootCAs *x509.CertPool
	// Egress is the address policy for directory connections; Outbound the
	// policy for downstream SCIM services (the delivery egress policy, as for
	// webhooks).
	Egress   egress.Policy
	Outbound egress.Policy

	// Disabled is set when directory.enabled is false: connector APIs,
	// synchronization and outbound provisioning stop, but accounts that a
	// directory sources keep failing closed — they never fall back to a local
	// password and their managed attributes stay read-only.
	Disabled bool

	// bindSlots bounds concurrent sign-in directory work
	// (directory.max_concurrent_binds, signIn); nil: unbounded.
	bindSlots *slots.Pool

	healthMu sync.Mutex
	health   map[string]*endpointHealth
}

// active reports whether the module runs connectors.
func (s *Service) active() bool { return s != nil && !s.Disabled }

// New builds the module. metrics may be nil (a private registry is used).
func New(d *runtime.Deps, users *identity.Service, orgs *organization.Service, authz *authorization.Service, m *observability.Metrics) *Service {
	cfg := d.Cfg
	s := &Service{d: d, Users: users, Orgs: orgs, Authz: authz, Jobs: jobs.NewService(d), health: map[string]*endpointHealth{}}
	if m == nil {
		m = observability.NewMetrics()
	}
	s.m = newMetrics(m.Registry)
	s.Egress = egress.Policy{AllowPrivate: cfg.Directory.AllowPrivateNetwork, AllowCIDRs: cfg.Directory.EgressAllowlist}
	s.Outbound = egress.Policy{AllowPrivate: cfg.Delivery.AllowPrivateWebhooks, AllowCIDRs: cfg.Delivery.EgressAllowlist,
		RequireHTTPS: cfg.Mode == configuration.ModeProduction, Timeout: 10 * time.Second, MaxBytes: 1 << 20}
	s.bindSlots = slots.New(BindSlots(cfg))
	return s
}

// defaultSignInTimeout applies when directory.sign_in_timeout is unset.
const defaultSignInTimeout = 8 * time.Second

// BindSlots is the bound on concurrent sign-in directory work:
// directory.max_concurrent_binds, or half the storage transaction slots, so
// an unreachable directory can hold at most half of them while its sign-ins
// wait for sign_in_timeout.
func BindSlots(cfg *configuration.Config) int {
	if n := cfg.Directory.MaxConcurrentBinds; n > 0 {
		return n
	}
	return max(1, storage.TxSlots(cfg.Storage.MaxConns)/2)
}

// Connector is a directory or outbound provisioning connector. Credentials
// are never part of it (PROV-018).
type Connector struct {
	ID                  string              `json:"id"`
	RealmID             string              `json:"-"`
	OrganizationID      string              `json:"organization_id,omitempty"`
	Name                string              `json:"name"`
	Kind                string              `json:"kind"`
	State               string              `json:"state"`
	Config              any                 `json:"config"`
	RoleCeilingIDs      []string            `json:"role_ceiling_ids"`
	GroupRoleMappings   map[string][]string `json:"group_role_mappings"`
	DefaultRoleID       string              `json:"default_role_id,omitempty"`
	CredentialSet       bool                `json:"credential_set"`
	CredentialSetAt     *time.Time          `json:"credential_set_at,omitempty"`
	LastSyncAt          *time.Time          `json:"last_sync_at,omitempty"`
	LastSuccessAt       *time.Time          `json:"last_success_at,omitempty"`
	LastError           string              `json:"last_error,omitempty"`
	ConsecutiveFailures int                 `json:"consecutive_failures"`
	Version             int64               `json:"version"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`

	ldap     *LDAPConfig
	out      *OutboundConfig
	secretCT []byte
	cursor   string
	evidence map[string]any
	stats    map[string]any
}

// Ref is the connector as an audit actor.
func (c *Connector) Ref() audit.Ref { return audit.Ref{Type: "connector", ID: c.ID} }

// LDAP returns the LDAP configuration (nil for other kinds).
func (c *Connector) LDAP() *LDAPConfig { return c.ldap }

// Input creates or updates a connector.
type Input struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// OrganizationID binds a connector created through the realm API to an
	// organization; organization APIs bind to their own organization.
	OrganizationID    string              `json:"organization_id"`
	Config            json.RawMessage     `json:"config"`
	RoleCeilingIDs    []string            `json:"role_ceiling_ids"`
	GroupRoleMappings map[string][]string `json:"group_role_mappings"`
	DefaultRoleID     string              `json:"default_role_id"`
	// Credential is the service-account bind password (ldap) or the
	// downstream bearer token (scim_outbound); write-only.
	Credential string `json:"credential"`
}

const connCols = `id, realm_id, coalesce(organization_id,''), name, kind, state, config, role_ceiling_ids, group_role_mappings, coalesce(default_role_id,''),
	secret_ciphertext, secret_set_at, last_sync_at, last_success_at, coalesce(last_error,''), consecutive_failures, coalesce(cursor,''), evidence, stats,
	version, created_at, updated_at`

func scanConnector(row pgx.Row) (*Connector, error) {
	var c Connector
	var cfg, maps, ev, stats []byte
	if err := row.Scan(&c.ID, &c.RealmID, &c.OrganizationID, &c.Name, &c.Kind, &c.State, &cfg, &c.RoleCeilingIDs, &maps, &c.DefaultRoleID,
		&c.secretCT, &c.CredentialSetAt, &c.LastSyncAt, &c.LastSuccessAt, &c.LastError, &c.ConsecutiveFailures, &c.cursor, &ev, &stats,
		&c.Version, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(maps, &c.GroupRoleMappings)
	_ = json.Unmarshal(ev, &c.evidence)
	_ = json.Unmarshal(stats, &c.stats)
	if c.GroupRoleMappings == nil {
		c.GroupRoleMappings = map[string][]string{}
	}
	if c.RoleCeilingIDs == nil {
		c.RoleCeilingIDs = []string{}
	}
	if c.evidence == nil {
		c.evidence = map[string]any{}
	}
	if c.stats == nil {
		c.stats = map[string]any{}
	}
	c.CredentialSet = len(c.secretCT) > 0
	switch c.Kind {
	case KindLDAP:
		var l LDAPConfig
		_ = json.Unmarshal(cfg, &l)
		c.ldap, c.Config = &l, &l
	case KindOutbound:
		var o OutboundConfig
		_ = json.Unmarshal(cfg, &o)
		c.out, c.Config = &o, &o
	}
	return &c, nil
}

// load returns a connector of the realm; orgID, when set, confines the
// lookup to that organization's connectors (tenant isolation).
func (s *Service) load(ctx context.Context, q storage.Querier, realmID, orgID, id string, forUpdate bool) (*Connector, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	lock := ""
	if forUpdate {
		lock = " FOR UPDATE"
	}
	c, err := scanConnector(q.QueryRow(ctx, `SELECT `+connCols+` FROM provisioning_connectors WHERE realm_id=$1 AND id=$2
		AND kind IN ('ldap','scim_outbound') AND ($3='' OR organization_id=$3)`+lock, realmID, id, orgID))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return c, err
}

// byID loads a connector by ID alone (workers, job handlers).
func (s *Service) byID(ctx context.Context, q storage.Querier, id string) (*Connector, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	c, err := scanConnector(q.QueryRow(ctx, `SELECT `+connCols+` FROM provisioning_connectors WHERE id=$1 AND kind IN ('ldap','scim_outbound')`, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return c, err
}

// Get returns one connector; orgID confines it to an organization.
func (s *Service) Get(ctx context.Context, realmID, orgID, id string) (*Connector, error) {
	return s.load(ctx, nil, realmID, orgID, id, false)
}

// List returns the realm's directory and outbound connectors, or one
// organization's when orgID is set.
func (s *Service) List(ctx context.Context, realmID, orgID string) ([]*Connector, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+connCols+` FROM provisioning_connectors WHERE realm_id=$1 AND kind IN ('ldap','scim_outbound')
		AND ($2='' OR organization_id=$2) ORDER BY name, id`, realmID, orgID)
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

func credentialAAD(id string) []byte { return []byte("directory-connector-credential:" + id) }

// credential decrypts a connector's credential; the purpose and the
// connector ID bind the ciphertext so it cannot be moved to another row.
func (s *Service) credential(c *Connector) (string, error) {
	if len(c.secretCT) == 0 {
		return "", errors.New("connector credential is not set")
	}
	pt, err := s.d.Keys.Decrypt(keys.PurposeData, c.secretCT, credentialAAD(c.ID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// validate checks a definition against the creator's own authority: an
// organization connector's role ceiling must lie within the actor's
// delegation ceiling in the organization (PROV-003, PROV-006, PROV-007).
func (s *Service) validate(ctx context.Context, tx pgx.Tx, realmID, orgID string, in *Input, actor authorization.Subject) (any, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return nil, problem.ErrValidation.WithField("name", "1 to 100 characters")
	}
	if in.RoleCeilingIDs == nil {
		in.RoleCeilingIDs = []string{}
	}
	if in.GroupRoleMappings == nil {
		in.GroupRoleMappings = map[string][]string{}
	}
	if len(in.RoleCeilingIDs) > 50 || len(in.GroupRoleMappings) > 200 {
		return nil, problem.ErrValidation.WithDetail("at most 50 ceiling roles and 200 group mappings")
	}
	if orgID == "" && (len(in.RoleCeilingIDs) > 0 || len(in.GroupRoleMappings) > 0 || in.DefaultRoleID != "") {
		// A workforce directory grants no organization access: membership in
		// a customer organization is decided there, never assumed (FED-015).
		return nil, problem.ErrValidation.WithField("role_ceiling_ids", "realm connectors grant no roles; bind the connector to an organization")
	}
	if in.Kind == KindOutbound && (len(in.GroupRoleMappings) > 0 || in.DefaultRoleID != "" || len(in.RoleCeilingIDs) > 0) {
		return nil, problem.ErrValidation.WithField("group_role_mappings", "outbound connectors grant no roles")
	}
	scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
	for _, id := range in.RoleCeilingIDs {
		role, err := s.Authz.Role(ctx, tx, realmID, id)
		if err != nil || role.Boundary != "organization" || (role.OrganizationID != "" && role.OrganizationID != orgID) {
			return nil, problem.ErrValidation.WithField("role_ceiling_ids", "organization roles of this organization only")
		}
		if err := s.Authz.CheckAssignable(ctx, tx, realmID, actor, role, scope); err != nil {
			return nil, problem.ErrGrantCeiling.WithDetail("role " + role.Name + " is beyond your own delegation ceiling")
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
		return nil, problem.ErrValidation.WithField("default_role_id", "must be one of role_ceiling_ids")
	}
	for group, roles := range in.GroupRoleMappings {
		if strings.TrimSpace(group) == "" || len(group) > 512 || !within(roles) {
			// An approved mapping never reaches beyond the ceiling (TEST-049).
			return nil, problem.ErrValidation.WithField("group_role_mappings", "each mapping names a directory group and roles from role_ceiling_ids")
		}
	}
	if len(in.Config) == 0 {
		return nil, problem.ErrValidation.WithField("config", "required")
	}
	dec := json.NewDecoder(strings.NewReader(string(in.Config)))
	dec.DisallowUnknownFields()
	production := s.d.Cfg.Mode == configuration.ModeProduction
	switch in.Kind {
	case KindLDAP:
		var l LDAPConfig
		if err := dec.Decode(&l); err != nil {
			return nil, problem.ErrValidation.WithField("config", "invalid LDAP configuration: "+sanitize(err))
		}
		if perr := l.normalize(orgID != "", production); perr != nil {
			return nil, perr
		}
		return &l, nil
	case KindOutbound:
		var o OutboundConfig
		if err := dec.Decode(&o); err != nil {
			return nil, problem.ErrValidation.WithField("config", "invalid outbound configuration: "+sanitize(err))
		}
		if perr := o.normalize(orgID != "", s.Outbound); perr != nil {
			return nil, perr
		}
		for _, oid := range o.EligibleOrganizationIDs {
			if _, err := s.Orgs.Get(ctx, tx, realmID, oid); err != nil {
				return nil, problem.ErrValidation.WithField("config.eligible_organization_ids", "unknown organization "+oid)
			}
		}
		for _, gid := range append(slices.Clone(o.EligibleGroupIDs), o.PushGroupIDs...) {
			if _, err := s.Orgs.GetGroup(ctx, orgID, gid); err != nil {
				return nil, problem.ErrValidation.WithField("config.push_group_ids", "unknown group "+gid+" in this organization")
			}
		}
		return &o, nil
	}
	return nil, problem.ErrValidation.WithField("kind", "ldap or scim_outbound")
}

// checkMaxEntries refuses an LDAP connector max_entries above the
// operator's directory.max_entries_per_run: a connector may only lower the
// deployment bound. An update that keeps the stored value is accepted even
// if the operator lowered the bound since (runs are clamped to it anyway),
// so such a connector can still be edited or disabled.
func (s *Service) checkMaxEntries(cfg any, cur *Connector) error {
	l, ok := cfg.(*LDAPConfig)
	if !ok || l.MaxEntries == 0 {
		return nil
	}
	limit := s.maxEntriesLimit()
	if l.MaxEntries <= limit || (cur != nil && cur.ldap != nil && cur.ldap.MaxEntries == l.MaxEntries) {
		return nil
	}
	return problem.ErrValidation.WithField("config.max_entries", fmt.Sprintf("0 (deployment default) to %d (directory.max_entries_per_run)", limit))
}

func sanitize(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "json: "); i >= 0 {
		msg = msg[i+6:]
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// describe is non-secret audit metadata for a definition.
func describe(kind string, cfg any) map[string]any {
	meta := map[string]any{"kind": kind}
	switch c := cfg.(type) {
	case *LDAPConfig:
		hosts := []string{}
		for _, e := range c.Endpoints {
			hosts = append(hosts, hostOf(e))
		}
		meta["endpoint_hosts"], meta["mode"], meta["dialect"], meta["jit_provisioning"] = hosts, c.Mode, c.Dialect, c.JITProvisioning
	case *OutboundConfig:
		meta["destination_host"], meta["deprovision_action"] = hostOf(c.BaseURL), c.DeprovisionAction
	}
	return meta
}

func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

// Create registers a connector with its encrypted credential.
func (s *Service) Create(ctx context.Context, realmID, orgID string, in Input, actor authorization.Subject, auditActor audit.Ref) (*Connector, error) {
	if in.OrganizationID != "" {
		if orgID != "" && orgID != in.OrganizationID {
			return nil, problem.ErrValidation.WithField("organization_id", "must match the organization in the path")
		}
		orgID = in.OrganizationID
	}
	if in.Credential == "" || len(in.Credential) > 4096 {
		return nil, problem.ErrValidation.WithField("credential", "the service-account password (ldap) or bearer token (scim_outbound) is required (at most 4096 bytes)")
	}
	id := ids.New(ids.Connector)
	var out *Connector
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if orgID != "" {
			if _, err := s.Orgs.Get(ctx, tx, realmID, orgID); err != nil {
				return problem.ErrNotFound
			}
		}
		cfg, err := s.validate(ctx, tx, realmID, orgID, &in, actor)
		if err != nil {
			return err
		}
		if err := s.checkMaxEntries(cfg, nil); err != nil {
			return err
		}
		ct, kv, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(in.Credential), credentialAAD(id))
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(cfg)
		maps, _ := json.Marshal(in.GroupRoleMappings)
		now := s.d.Now()
		ev, _ := json.Marshal(map[string]any{"operator_actions": []any{operatorAction("created", auditActor, now)}})
		if _, err := tx.Exec(ctx, `INSERT INTO provisioning_connectors (id, realm_id, organization_id, name, kind, config, secret_ciphertext, key_version,
			secret_set_at, allowed_resource_types, role_ceiling_ids, group_role_mappings, default_role_id, evidence, created_at, updated_at)
			VALUES ($1,$2,nullif($3,''),$4,$5,$6,$7,$8,$9,'{User,Group}',$10,$11,nullif($12,''),$13,$9,$9)`,
			id, realmID, orgID, in.Name, in.Kind, raw, ct, kv, now, in.RoleCeilingIDs, maps, in.DefaultRoleID, ev); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.connector.created", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id}, Metadata: describe(in.Kind, cfg)}); err != nil {
			return err
		}
		out, err = s.load(ctx, tx, realmID, "", id, false)
		return err
	})
	return out, err
}

// Update replaces a connector's definition (not its credential); version
// must match (API-010).
func (s *Service) Update(ctx context.Context, realmID, orgID, id string, version int64, in Input, state string, actor authorization.Subject, auditActor audit.Ref) (*Connector, error) {
	var out *Connector
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := s.load(ctx, tx, realmID, orgID, id, true)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return problem.ErrPrecondition
		}
		if in.Credential != "" {
			return problem.ErrValidation.WithField("credential", "set credentials with PUT .../credential")
		}
		if in.OrganizationID != "" && in.OrganizationID != cur.OrganizationID {
			return problem.ErrValidation.WithField("organization_id", "fixed after creation")
		}
		if in.Kind != "" && in.Kind != cur.Kind {
			return problem.ErrValidation.WithField("kind", "fixed after creation")
		}
		in.Kind = cur.Kind
		cfg, err := s.validate(ctx, tx, realmID, cur.OrganizationID, &in, actor)
		if err != nil {
			return err
		}
		if err := s.checkMaxEntries(cfg, cur); err != nil {
			return err
		}
		if state == "" {
			state = cur.State
		}
		if state != "active" && state != "disabled" {
			return problem.ErrValidation.WithField("state", "active or disabled")
		}
		raw, _ := json.Marshal(cfg)
		maps, _ := json.Marshal(in.GroupRoleMappings)
		now := s.d.Now()
		action := "updated"
		if state != cur.State {
			action = "state_" + state
		}
		tag, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET name=$2, state=$3, config=$4, role_ceiling_ids=$5, group_role_mappings=$6,
			default_role_id=nullif($7,''), next_sync_at=NULL, next_full_sync_at=NULL, evidence=$8, version=version+1, updated_at=$9 WHERE id=$1 AND version=$10`,
			id, in.Name, state, raw, in.RoleCeilingIDs, maps, in.DefaultRoleID, withAction(cur.evidence, action, auditActor, now), now, version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrPrecondition
		}
		meta := describe(cur.Kind, cfg)
		meta["state"] = state
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.connector.updated", RealmID: realmID, OrgID: cur.OrganizationID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id}, Metadata: meta}); err != nil {
			return err
		}
		out, err = s.load(ctx, tx, realmID, "", id, false)
		return err
	})
	return out, err
}

// SetCredential replaces the encrypted credential; the old one stops
// being used at once.
func (s *Service) SetCredential(ctx context.Context, realmID, orgID, id, credential string, auditActor audit.Ref) (*Connector, error) {
	if credential == "" || len(credential) > 4096 {
		return nil, problem.ErrValidation.WithField("credential", "1 to 4096 bytes")
	}
	var out *Connector
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := s.load(ctx, tx, realmID, orgID, id, true)
		if err != nil {
			return err
		}
		ct, kv, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(credential), credentialAAD(id))
		if err != nil {
			return err
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET secret_ciphertext=$2, key_version=$3, secret_set_at=$4, evidence=$5,
			version=version+1, updated_at=$4 WHERE id=$1`, id, ct, kv, now, withAction(cur.evidence, "credential_set", auditActor, now)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.connector.credential_set", RealmID: realmID, OrgID: cur.OrganizationID,
			Actor: auditActor, Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id}, Metadata: map[string]any{"kind": cur.Kind}}); err != nil {
			return err
		}
		out, err = s.load(ctx, tx, realmID, "", id, false)
		return err
	})
	return out, err
}

// Delete removes a disabled connector with its links, runs and deliveries.
// Accounts stay: they keep their history (created_via) but no longer have a
// directory password, so their owners recover access through the realm's
// recovery methods. The connector must be disabled first, so a deletion is
// always a deliberate second step.
func (s *Service) Delete(ctx context.Context, realmID, orgID, id string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := s.load(ctx, tx, realmID, orgID, id, true)
		if err != nil {
			return err
		}
		// An outbound connector without a usable configuration (a legacy
		// row of the old /provisioning-connectors API) never runs or
		// delivers, so it can be retired at once; disabling it would first
		// need a valid configuration.
		if cur.State != "disabled" && cur.outboundConfigIssue() == "" {
			return problem.ErrConflict.WithDetail("disable the connector before deleting it")
		}
		var links int
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM connector_external_ids WHERE connector_id=$1`, id).Scan(&links)
		if _, err := tx.Exec(ctx, `DELETE FROM provisioning_connectors WHERE id=$1`, id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.connector.deleted", RealmID: realmID, OrgID: cur.OrganizationID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "connector", ID: id}, Metadata: map[string]any{"kind": cur.Kind, "links_removed": links}})
		return err
	})
}

// operatorAction is one entry of the connector's recent operator actions
// (PROV-018): what was done, by whom and when; never request content.
func operatorAction(action string, actor audit.Ref, at time.Time) map[string]any {
	return map[string]any{"action": action, "actor_type": actor.Type, "actor_id": actor.ID, "at": at.UTC().Format(time.RFC3339)}
}

// withAction appends an operator action, keeping the latest 20.
func withAction(evidence map[string]any, action string, actor audit.Ref, at time.Time) []byte {
	ev := map[string]any{}
	for k, v := range evidence {
		ev[k] = v
	}
	list, _ := ev["operator_actions"].([]any)
	list = append([]any{operatorAction(action, actor, at)}, list...)
	if len(list) > 20 {
		list = list[:20]
	}
	ev["operator_actions"] = list
	b, _ := json.Marshal(ev)
	return b
}

// recordOperatorAction stores an operator action on the connector evidence
// inside tx.
func (s *Service) recordOperatorAction(ctx context.Context, tx pgx.Tx, c *Connector, action string, actor audit.Ref) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT evidence FROM provisioning_connectors WHERE id=$1 FOR UPDATE`, c.ID).Scan(&raw); err != nil {
		return err
	}
	ev := map[string]any{}
	_ = json.Unmarshal(raw, &ev)
	_, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET evidence=$2 WHERE id=$1`, c.ID, withAction(ev, action, actor, s.d.Now()))
	return err
}

// requesterMayManage re-checks that the person or service that requested a
// run still holds the authority to manage the connector when it executes
// (INT-006): losing the permission after enqueueing never leaves a way in.
func (s *Service) requesterMayManage(ctx context.Context, c *Connector, typ, id string) bool {
	switch typ {
	case "system", "operator", "connector":
		return true
	}
	subj := authorization.Subject{Type: authorization.SubjectUser, ID: id}
	if typ == "service_principal" {
		subj = authorization.Subject{Type: authorization.SubjectService, ID: id}
	}
	if s.Authz.Check(ctx, nil, c.RealmID, subj, "realm.provisioning.manage", authorization.Scope{Type: authorization.ScopeRealm, ID: c.RealmID}) {
		return true
	}
	return c.OrganizationID != "" && s.Authz.Check(ctx, nil, c.RealmID, subj, "org.integrations.write",
		authorization.Scope{Type: authorization.ScopeOrganization, ID: c.OrganizationID})
}

// organizationActive reports whether an organization connector's
// organization may still be served; realm connectors always may.
func (s *Service) organizationActive(ctx context.Context, q storage.Querier, c *Connector) bool {
	if c.OrganizationID == "" {
		return true
	}
	o, err := s.Orgs.Get(ctx, q, c.RealmID, c.OrganizationID)
	return err == nil && o.State == "active"
}
