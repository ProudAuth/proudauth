package organization

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/storage"
)

// Group is an organization-scoped collection of members (TEN-013).
type Group struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"organization_id"`
	ParentID    string         `json:"parent_id,omitempty"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata"`
	ExternalID  string         `json:"external_id,omitempty"`
	Source      string         `json:"source"`
	Version     int64          `json:"version"`
	CreatedAt   time.Time      `json:"created_at"`
}

const groupCols = `id, organization_id, coalesce(parent_id,''), name, coalesce(description,''), metadata, coalesce(external_id,''), source, version, created_at`

func scanGroup(row pgx.Row) (*Group, error) {
	var g Group
	var meta []byte
	err := row.Scan(&g.ID, &g.OrgID, &g.ParentID, &g.Name, &g.Description, &meta, &g.ExternalID, &g.Source, &g.Version, &g.CreatedAt)
	_ = json.Unmarshal(meta, &g.Metadata)
	if g.Metadata == nil {
		g.Metadata = map[string]any{}
	}
	return &g, err
}

// GroupInput creates or updates a group.
type GroupInput struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	ParentID    *string        `json:"parent_id"`
	Metadata    map[string]any `json:"metadata"`
	ExternalID  string         `json:"external_id"`
	Source      string         `json:"-"`
}

// CreateGroupTx creates a group, validating depth limits.
func (s *Service) CreateGroupTx(ctx context.Context, tx pgx.Tx, realmID, orgID string, in GroupInput, auditActor audit.Ref) (*Group, error) {
	if in.Name == "" || len(in.Name) > 200 {
		return nil, problem.ErrValidation.WithField("name", "required")
	}
	parent := ""
	if in.ParentID != nil {
		parent = *in.ParentID
	}
	if parent != "" {
		if err := s.checkDepth(ctx, tx, orgID, parent, ""); err != nil {
			return nil, err
		}
	}
	if in.Source == "" {
		in.Source = "admin"
	}
	meta, _ := json.Marshal(nonNilMap(in.Metadata))
	id := ids.New(ids.Group)
	now := s.d.Now()
	_, err := tx.Exec(ctx, `INSERT INTO groups (id, realm_id, organization_id, parent_id, name, description, metadata, external_id, source, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, id, realmID, orgID, nilIfEmpty(parent), in.Name, nilIfEmpty(in.Description), meta,
		nilIfEmpty(in.ExternalID), in.Source, now)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, problem.ErrConflict.WithField("name", "already exists")
		}
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithField("parent_id", "unknown parent group in this organization")
		}
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.created", RealmID: realmID, OrgID: orgID, Actor: auditActor,
		Target: &audit.Ref{Type: "group", ID: id}, Metadata: map[string]any{"name": in.Name, "parent_id": parent}}); err != nil {
		return nil, err
	}
	return scanGroup(tx.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id=$1`, id))
}

// checkDepth walks up from parent rejecting cycles (when moving self) and excessive depth.
func (s *Service) checkDepth(ctx context.Context, tx pgx.Tx, orgID, parent, self string) error {
	return s.checkDepthWith(ctx, tx, orgID, parent, self, 0)
}

// checkDepthWith is checkDepth for a group with height levels below it.
func (s *Service) checkDepthWith(ctx context.Context, tx pgx.Tx, orgID, parent, self string, height int) error {
	cur := parent
	for depth := 1; cur != ""; depth++ {
		if depth+height > s.d.Cfg.Limits.MaxGroupDepth {
			return problem.ErrValidation.WithField("parent_id", "group nesting exceeds the depth limit")
		}
		if cur == self {
			return problem.ErrValidation.WithField("parent_id", "group nesting must not form a cycle")
		}
		var next *string
		if err := tx.QueryRow(ctx, `SELECT parent_id FROM groups WHERE organization_id=$1 AND id=$2`, orgID, cur).Scan(&next); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrValidation.WithField("parent_id", "unknown parent group")
			}
			return err
		}
		if next == nil {
			return nil
		}
		cur = *next
	}
	return nil
}

// subtreeHeight is the number of levels below a group (0 for a leaf).
func subtreeHeight(ctx context.Context, tx pgx.Tx, id string) (int, error) {
	var h int
	err := tx.QueryRow(ctx, `WITH RECURSIVE down(id, depth) AS (
			SELECT id, 0 FROM groups WHERE id=$1
			UNION ALL SELECT g.id, down.depth+1 FROM groups g JOIN down ON g.parent_id=down.id WHERE down.depth < 64)
		SELECT coalesce(max(depth), 0) FROM down`, id).Scan(&h)
	return h, err
}

// UpdateGroup updates a group, including re-parenting with cycle, depth and
// delegation-ceiling checks: members of the moved subtree inherit the roles
// of the new ancestors, so actor (nil for trusted callers) must be able to
// assign them (TEN-008, TEN-013).
func (s *Service) UpdateGroup(ctx context.Context, realmID, orgID, id string, expectedVersion int64, in GroupInput, actor *authorization.Subject, auditActor audit.Ref) (*Group, error) {
	var out *Group
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		g, err := scanGroup(tx.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && g.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		parent := g.ParentID
		if in.ParentID != nil {
			parent = *in.ParentID
			if parent != "" && parent != g.ParentID {
				// The whole subtree moves: its deepest level must fit too.
				h, err := subtreeHeight(ctx, tx, id)
				if err != nil {
					return err
				}
				if err := s.checkDepthWith(ctx, tx, orgID, parent, id, h); err != nil {
					return err
				}
				if actor != nil {
					if err := s.checkGroupCeilingTx(ctx, tx, realmID, orgID, parent, *actor); err != nil {
						return err
					}
				}
				// The subtree's members inherit the new ancestors' roles (AZ-018).
				if roles, err := groupRolesTx(ctx, tx, orgID, parent); err != nil {
					return err
				} else if len(roles) > 0 {
					rows, err := tx.Query(ctx, `WITH RECURSIVE down(id, depth) AS (
							SELECT id, 0 FROM groups WHERE id=$1
							UNION ALL SELECT g.id, down.depth+1 FROM groups g JOIN down ON g.parent_id=down.id WHERE down.depth < 64)
						SELECT DISTINCT m.user_id FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
						WHERE gm.group_id IN (SELECT id FROM down) AND m.state <> 'removed'`, id)
					if err != nil {
						return err
					}
					var users []string
					for rows.Next() {
						var u string
						if err := rows.Scan(&u); err != nil {
							rows.Close()
							return err
						}
						users = append(users, u)
					}
					rows.Close()
					if err := s.Authz.CheckSeparation(ctx, tx, realmID, users, roles); err != nil {
						return err
					}
				}
			}
		}
		name := g.Name
		if in.Name != "" {
			name = in.Name
		}
		meta := g.Metadata
		if in.Metadata != nil {
			meta = in.Metadata
		}
		mb, _ := json.Marshal(meta)
		if _, err := tx.Exec(ctx, `UPDATE groups SET name=$3, description=coalesce(nullif($4,''), description), parent_id=$5, metadata=$6,
			version=version+1, updated_at=$7 WHERE organization_id=$1 AND id=$2`, orgID, id, name, in.Description, nilIfEmpty(parent), mb, s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("name", "already exists")
			}
			return err
		}
		// Members anywhere in the subtree may hold different inherited roles.
		if _, err := tx.Exec(ctx, `WITH RECURSIVE down(id, depth) AS (
				SELECT id, 0 FROM groups WHERE id=$1
				UNION ALL SELECT g.id, down.depth+1 FROM groups g JOIN down ON g.parent_id=down.id WHERE down.depth < 64)
			UPDATE memberships SET revision=revision+1 WHERE id IN (SELECT membership_id FROM group_memberships WHERE group_id IN (SELECT id FROM down))`, id); err != nil {
			return err
		}
		auditMeta := map[string]any{}
		if parent != g.ParentID {
			auditMeta["parent_id"], auditMeta["previous_parent_id"] = parent, g.ParentID
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.updated", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "group", ID: id}, Metadata: auditMeta}); err != nil {
			return err
		}
		out, err = scanGroup(tx.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id=$1`, id))
		return err
	})
	return out, err
}

// DeleteGroup deletes a group without children.
func (s *Service) DeleteGroup(ctx context.Context, realmID, orgID, id string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.DeleteGroupTx(ctx, tx, realmID, orgID, id, auditActor)
	})
}

// DeleteGroupTx is DeleteGroup inside tx. The role assignments the group
// held end with it, each recorded like any other unassignment.
func (s *Service) DeleteGroupTx(ctx context.Context, tx pgx.Tx, realmID, orgID, id string, auditActor audit.Ref) error {
	// Group mutations take the group before connector mappings and members
	// (PROV-008, DB-014). Deleting members first can deadlock a connector
	// holding this group while waiting to update a member's revision.
	var locked string
	if err := tx.QueryRow(ctx, `SELECT id FROM groups WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, id).Scan(&locked); err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound
		}
		return err
	}
	var children int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM groups WHERE parent_id=$1`, id).Scan(&children); err != nil {
		return err
	}
	if children > 0 {
		return problem.ErrConflict.WithDetail("delete or move child groups first")
	}
	// Inbound/directory references cannot outlive their local group
	// (PROV-004). Outbound references must survive until remote deletion is
	// delivered; the outbound worker removes them after that acknowledgement.
	if _, err := tx.Exec(ctx, `DELETE FROM connector_external_ids WHERE resource_type='Group' AND local_id=$1
		AND coalesce(link_kind,'scim') IN ('scim','directory')`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id IN (SELECT membership_id FROM group_memberships WHERE group_id=$1)`, id); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `DELETE FROM role_assignments WHERE subject_type='group' AND subject_id=$1 RETURNING id, role_id`, id)
	if err != nil {
		return err
	}
	type removed struct{ id, role string }
	var gone []removed
	for rows.Next() {
		var r removed
		if err := rows.Scan(&r.id, &r.role); err != nil {
			rows.Close()
			return err
		}
		gone = append(gone, r)
	}
	rows.Close()
	for _, r := range gone {
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "role.unassigned", RealmID: realmID, OrgID: orgID, Actor: auditActor, Category: "authorization",
			Target: &audit.Ref{Type: "role_assignment", ID: r.id}, ReasonCode: "GROUP_DELETED",
			Metadata: map[string]any{"role_id": r.role, "subject_type": "group", "subject_id": id}}); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `DELETE FROM groups WHERE organization_id=$1 AND id=$2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return problem.ErrNotFound
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.deleted", RealmID: realmID, OrgID: orgID, Actor: auditActor, Target: &audit.Ref{Type: "group", ID: id}})
	return err
}

// ListGroups lists groups in an organization.
func (s *Service) ListGroups(ctx context.Context, orgID string) ([]*Group, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+groupCols+` FROM groups WHERE organization_id=$1 ORDER BY name LIMIT 1000`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroup loads a group scoped to its organization.
func (s *Service) GetGroup(ctx context.Context, orgID, id string) (*Group, error) {
	g, err := scanGroup(s.d.DB.Pool.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE organization_id=$1 AND id=$2`, orgID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return g, err
}

// AddGroupMemberTx adds an active membership to a group.
func (s *Service) AddGroupMemberTx(ctx context.Context, tx pgx.Tx, realmID, orgID, groupID, membershipID, source string, auditActor audit.Ref) error {
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM memberships WHERE organization_id=$1 AND id=$2`, orgID, membershipID).Scan(&state); err != nil {
		return problem.ErrValidation.WithField("membership_id", "unknown membership in this organization")
	}
	if state == "removed" || state == "expired" {
		// An ended membership is history; a returning member gets a new one.
		return problem.ErrValidation.WithField("membership_id", "the membership has ended ("+state+")")
	}
	if source == "" {
		source = "admin"
	}
	var dynamic bool
	if err := tx.QueryRow(ctx, `SELECT dynamic_rule IS NOT NULL FROM groups WHERE organization_id=$1 AND id=$2`, orgID, groupID).Scan(&dynamic); err == nil && dynamic {
		return problem.ErrConflict.WithDetail("members of a dynamic group come from its rule (TEN-014)")
	}
	// Joining a group must not combine incompatible roles (AZ-018).
	if roles, err := groupRolesTx(ctx, tx, orgID, groupID); err != nil {
		return err
	} else if len(roles) > 0 {
		var userID string
		if err := tx.QueryRow(ctx, `SELECT user_id FROM memberships WHERE id=$1`, membershipID).Scan(&userID); err != nil {
			return err
		}
		if err := s.Authz.CheckSeparation(ctx, tx, realmID, []string{userID}, roles); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `INSERT INTO group_memberships (id, realm_id, organization_id, group_id, membership_id, source) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (group_id, membership_id) DO NOTHING`, ids.New(ids.GroupMember), realmID, orgID, groupID, membershipID, source)
	if err != nil {
		if storage.IsForeignKeyViolation(err) {
			return problem.ErrValidation.WithDetail("unknown group in this organization")
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil // already a member: nothing changed, nothing to audit
	}
	if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, membershipID); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.member.added", RealmID: realmID, OrgID: orgID, Actor: auditActor,
		Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"membership_id": membershipID, "source": source}})
	return err
}

// AddGroupMember checks that the actor's ceiling covers the group's role grants.
func (s *Service) AddGroupMember(ctx context.Context, realmID, orgID, groupID, membershipID string, actor authorization.Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.checkGroupCeilingTx(ctx, tx, realmID, orgID, groupID, actor); err != nil {
			return err
		}
		return s.AddGroupMemberTx(ctx, tx, realmID, orgID, groupID, membershipID, "admin", auditActor)
	})
}

// checkGroupCeilingTx requires the actor to be able to assign every role the
// group grants, including roles its members inherit from ancestor groups:
// whoever decides who is in the group decides who holds them (TEN-008).
func (s *Service) checkGroupCeilingTx(ctx context.Context, tx pgx.Tx, realmID, orgID, groupID string, actor authorization.Subject) error {
	scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
	roles, err := groupRolesTx(ctx, tx, orgID, groupID)
	if err != nil {
		return err
	}
	for _, rid := range roles {
		role, err := s.Authz.Role(ctx, tx, realmID, rid)
		if err != nil {
			return err
		}
		if err := s.Authz.CheckAssignable(ctx, tx, realmID, actor, role, scope); err != nil {
			return err
		}
	}
	return nil
}

// groupRolesTx lists the roles a group grants its members, including those
// assigned to its ancestors.
// GroupRolesTx lists the roles a group grants its members, including those
// assigned to its ancestors.
func GroupRolesTx(ctx context.Context, tx pgx.Tx, orgID, groupID string) ([]string, error) {
	return groupRolesTx(ctx, tx, orgID, groupID)
}

func groupRolesTx(ctx context.Context, tx pgx.Tx, orgID, groupID string) ([]string, error) {
	rows, err := tx.Query(ctx, `WITH RECURSIVE up(id, parent_id, depth) AS (
			SELECT id, parent_id, 0 FROM groups WHERE organization_id=$2 AND id=$1
			UNION ALL SELECT g.id, g.parent_id, up.depth+1 FROM groups g JOIN up ON g.id=up.parent_id WHERE up.depth < 64)
		SELECT DISTINCT role_id FROM role_assignments WHERE subject_type='group' AND subject_id IN (SELECT id FROM up)`, groupID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// RemoveGroupMember removes a membership from a group.
func (s *Service) RemoveGroupMember(ctx context.Context, realmID, orgID, groupID, membershipID string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var dynamic bool
		// The share lock orders the removal with a SCIM write to the group,
		// which locks the row before comparing its entity tag (TEST-050).
		if err := tx.QueryRow(ctx, `SELECT dynamic_rule IS NOT NULL FROM groups WHERE organization_id=$1 AND id=$2 FOR SHARE`, orgID, groupID).Scan(&dynamic); err == nil && dynamic {
			return problem.ErrConflict.WithDetail("members of a dynamic group come from its rule (TEN-014)")
		}
		tag, err := tx.Exec(ctx, `DELETE FROM group_memberships WHERE organization_id=$1 AND group_id=$2 AND membership_id=$3`, orgID, groupID, membershipID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, membershipID); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.member.removed", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"membership_id": membershipID}})
		return err
	})
}

// GroupMembers lists memberships in a group.
func (s *Service) GroupMembers(ctx context.Context, orgID, groupID string) ([]map[string]any, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT gm.membership_id, m.user_id, gm.source, gm.created_at FROM group_memberships gm
		JOIN memberships m ON m.id=gm.membership_id WHERE gm.organization_id=$1 AND gm.group_id=$2 ORDER BY gm.created_at`, orgID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var mid, uid, src string
		var at time.Time
		if err := rows.Scan(&mid, &uid, &src, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"membership_id": mid, "user_id": uid, "source": src, "added_at": at})
	}
	return out, rows.Err()
}

// ---------- domains ----------

// Domain is an organization domain claim (TEN-009).
type Domain struct {
	ID                 string     `json:"id"`
	Domain             string     `json:"domain"`
	State              string     `json:"state"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	ChallengeExpiresAt *time.Time `json:"challenge_expires_at,omitempty"`
	RecheckAt          *time.Time `json:"recheck_at,omitempty"`
	IncludeSubdomains  bool       `json:"include_subdomains"`
	CreatedAt          time.Time  `json:"created_at"`
}

// DomainChallenge is returned once when a domain is added.
type DomainChallenge struct {
	Domain     Domain `json:"domain"`
	RecordName string `json:"dns_record_name"`
	RecordType string `json:"dns_record_type"`
	Value      string `json:"dns_record_value"`
}

// AddDomain registers a domain and issues an expiring DNS TXT proof challenge.
func (s *Service) AddDomain(ctx context.Context, realmID, orgID, raw string, auditActor audit.Ref) (*DomainChallenge, error) {
	d, err := canonical.Domain(raw)
	if err != nil {
		return nil, problem.ErrValidation.WithField("domain", "invalid domain")
	}
	value := "proudauth-verification=" + secret.Token("")[:43]
	id := ids.New(ids.Domain)
	exp := s.d.Now().Add(7 * 24 * time.Hour)
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organization_domains (id, realm_id, organization_id, domain, challenge_digest, challenge_expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)`, id, realmID, orgID, d, secret.Digest(value), exp)
		if err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("domain", "already registered for this organization")
			}
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.added", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "domain", ID: id}, Metadata: map[string]any{"domain": d}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &DomainChallenge{Domain: Domain{ID: id, Domain: d, State: "pending", ChallengeExpiresAt: &exp, CreatedAt: s.d.Now()},
		RecordName: "_proudauth-challenge." + d, RecordType: "TXT", Value: value}, nil
}

// TXTResolver resolves DNS TXT records; replaceable in tests.
var TXTResolver = func(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// VerifyDomain checks the DNS proof and enforces realm-wide uniqueness of verified
// domains (conflict check). A verified domain enables routing, never membership (TEN-010).
func (s *Service) VerifyDomain(ctx context.Context, realmID, orgID, domainID string, auditActor audit.Ref) (*Domain, error) {
	var d Domain
	var digest *string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT id, domain, state, challenge_digest, challenge_expires_at, created_at FROM organization_domains
		WHERE organization_id=$1 AND id=$2`, orgID, domainID).Scan(&d.ID, &d.Domain, &d.State, &digest, &d.ChallengeExpiresAt, &d.CreatedAt)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if d.State == "verified" {
		return &d, nil
	}
	if d.State != "pending" && d.State != "conflict" {
		// A removed or expired claim is never revived; add the domain again.
		return nil, problem.ErrConflict.WithDetail("the domain claim is " + d.State + "; add the domain again")
	}
	if digest == nil || d.ChallengeExpiresAt == nil || !s.d.Now().Before(*d.ChallengeExpiresAt) {
		return nil, problem.ErrConflict.WithDetail("challenge expired; remove and add the domain again")
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	records, _ := TXTResolver(lctx, "_proudauth-challenge."+d.Domain)
	matched := false
	for _, r := range records {
		if secret.Equal(secret.Digest(strings.TrimSpace(r)), *digest) {
			matched = true
		}
	}
	if !matched {
		return nil, problem.ErrInvalidProof.WithDetail("DNS proof record not found")
	}
	conflict := false
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		now := s.d.Now()
		conflict = false
		// Another organization already holds the domain: the claim is marked
		// conflicting and audited, and stays so until resolved (TEN-009).
		var held bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organization_domains WHERE realm_id=$1 AND domain=$2 AND state='verified' AND id<>$3)`,
			realmID, d.Domain, domainID).Scan(&held); err != nil {
			return err
		}
		if held {
			// Guarded on the state read above: a claim removed while the DNS
			// proof was being checked must not be revived as a conflict.
			tag, err := tx.Exec(ctx, `UPDATE organization_domains SET state='conflict', updated_at=$3
				WHERE organization_id=$1 AND id=$2 AND state IN ('pending','conflict')`, orgID, domainID, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return problem.ErrConflict.WithDetail("the domain claim changed; add the domain again")
			}
			conflict = true
			_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.conflict", RealmID: realmID, OrgID: orgID, Actor: auditActor,
				Target: &audit.Ref{Type: "domain", ID: domainID}, Outcome: audit.Denied, Category: "security", Metadata: map[string]any{"domain": d.Domain}})
			return err
		}
		recheck := now.Add(s.recheckInterval(ctx, realmID))
		tag, err := tx.Exec(ctx, `UPDATE organization_domains SET state='verified', verified_at=$3, recheck_at=$4, proof_digest=challenge_digest,
			challenge_digest=NULL, recheck_failures=0, updated_at=$3 WHERE organization_id=$1 AND id=$2 AND state IN ('pending','conflict')`, orgID, domainID, now, recheck)
		if err == nil && tag.RowsAffected() == 0 {
			// Removed while the DNS proof was being checked.
			return problem.ErrConflict.WithDetail("the domain claim changed; add the domain again")
		}
		if storage.IsUniqueViolation(err) {
			// Lost a race with a concurrent verification.
			return problem.ErrConflict.WithDetail("domain is verified by another organization")
		}
		if err != nil {
			return err
		}
		d.State, d.VerifiedAt, d.RecheckAt = "verified", &now, &recheck
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.verified", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "domain", ID: domainID}, Metadata: map[string]any{"domain": d.Domain}})
		return err
	})
	if err == nil && conflict {
		return nil, problem.ErrConflict.WithDetail("domain is verified by another organization")
	}
	return &d, err
}

// DomainRecheckPolicy configures periodic domain re-verification (TEN-009).
type DomainRecheckPolicy struct {
	Interval     time.Duration
	LapseAfter   int
	RetryBackoff time.Duration
}

// DefaultRecheckPolicy re-verifies every 30 days and lapses after three
// failed daily retries.
var DefaultRecheckPolicy = DomainRecheckPolicy{Interval: 30 * 24 * time.Hour, LapseAfter: 3, RetryBackoff: 24 * time.Hour}

func (s *Service) recheckPolicy(ctx context.Context, realmID string) DomainRecheckPolicy {
	p := DefaultRecheckPolicy
	if s.RecheckPolicy != nil {
		p = s.RecheckPolicy(ctx, realmID)
	}
	if p.Interval <= 0 {
		p.Interval = DefaultRecheckPolicy.Interval
	}
	if p.LapseAfter <= 0 {
		p.LapseAfter = DefaultRecheckPolicy.LapseAfter
	}
	if p.RetryBackoff <= 0 {
		p.RetryBackoff = DefaultRecheckPolicy.RetryBackoff
	}
	return p
}

func (s *Service) recheckInterval(ctx context.Context, realmID string) time.Duration {
	return s.recheckPolicy(ctx, realmID).Interval
}

// RecheckDomains re-verifies verified domains that are due (TEN-009). A domain
// whose DNS proof is still published stays verified until the next interval;
// a missing proof is retried after the backoff, and after the allowed number
// of consecutive failures the verification lapses: the domain stops routing
// sign-ins, satisfying domain-restricted registration and trusted-email
// linking until the organization proves control again.
func (s *Service) RecheckDomains(ctx context.Context, limit int) (int, error) {
	now := s.d.Now()
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, realm_id, organization_id, domain, proof_digest, recheck_failures FROM organization_domains
		WHERE state='verified' AND proof_digest IS NOT NULL AND recheck_at <= $1 ORDER BY recheck_at LIMIT $2`, now, limit)
	if err != nil {
		return 0, err
	}
	type due struct {
		id, realm, org, domain, digest string
		failures                       int
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.realm, &d.org, &d.domain, &d.digest, &d.failures); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	n := 0
	for _, d := range list {
		pol := s.recheckPolicy(ctx, d.realm)
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		records, _ := TXTResolver(lctx, "_proudauth-challenge."+d.domain)
		cancel()
		found := slices.ContainsFunc(records, func(r string) bool { return secret.Equal(secret.Digest(strings.TrimSpace(r)), d.digest) })
		// Every write is guarded on the state read above (still verified, same
		// failure count): a domain removed or rechecked concurrently while DNS
		// was queried is left alone instead of being revived or double-counted.
		applied := false
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			ref := &audit.Ref{Type: "domain", ID: d.id}
			switch {
			case found:
				tag, err := tx.Exec(ctx, `UPDATE organization_domains SET recheck_at=$3, recheck_failures=0, updated_at=$4
					WHERE id=$1 AND state='verified' AND recheck_failures=$2`, d.id, d.failures, now.Add(pol.Interval), now)
				if err != nil || tag.RowsAffected() == 0 {
					return err
				}
				applied = true
				_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.rechecked", RealmID: d.realm, OrgID: d.org, Actor: audit.System,
					Target: ref, Category: "configuration", Metadata: map[string]any{"domain": d.domain}})
				return err
			case d.failures+1 >= pol.LapseAfter:
				tag, err := tx.Exec(ctx, `UPDATE organization_domains SET state='expired', recheck_failures=$3, updated_at=$4
					WHERE id=$1 AND state='verified' AND recheck_failures=$2`, d.id, d.failures, d.failures+1, now)
				if err != nil || tag.RowsAffected() == 0 {
					return err
				}
				applied = true
				_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.verification_lapsed", RealmID: d.realm, OrgID: d.org,
					Actor: audit.System, Target: ref, Outcome: audit.Failure, Metadata: map[string]any{"domain": d.domain, "failures": d.failures + 1}})
				return err
			default:
				tag, err := tx.Exec(ctx, `UPDATE organization_domains SET recheck_failures=$3, recheck_at=$4, updated_at=$5
					WHERE id=$1 AND state='verified' AND recheck_failures=$2`, d.id, d.failures, d.failures+1, now.Add(pol.RetryBackoff), now)
				applied = err == nil && tag.RowsAffected() > 0
				return err
			}
		})
		if err != nil {
			return n, err
		}
		if applied {
			n++
		}
	}
	return n, nil
}

// SetIncludeSubdomains lets a verified domain route its subdomains too
// (TEN-011).
func (s *Service) SetIncludeSubdomains(ctx context.Context, realmID, orgID, domainID string, include bool, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE organization_domains SET include_subdomains=$3, updated_at=$4 WHERE organization_id=$1 AND id=$2 AND state <> 'removed'`,
			orgID, domainID, include, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.updated", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "domain", ID: domainID}, Metadata: map[string]any{"include_subdomains": include}})
		return err
	})
}

// ListDomains lists an organization's domains.
func (s *Service) ListDomains(ctx context.Context, orgID string) ([]Domain, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, domain, state, verified_at, challenge_expires_at, recheck_at, include_subdomains, created_at
		FROM organization_domains WHERE organization_id=$1 AND state <> 'removed' ORDER BY domain`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Domain{}
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.Domain, &d.State, &d.VerifiedAt, &d.ChallengeExpiresAt, &d.RecheckAt, &d.IncludeSubdomains, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RemoveDomain removes a domain claim.
func (s *Service) RemoveDomain(ctx context.Context, realmID, orgID, domainID string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE organization_domains SET state='removed', updated_at=$3 WHERE organization_id=$1 AND id=$2 AND state <> 'removed'`, orgID, domainID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.domain.removed", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "domain", ID: domainID}})
		return err
	})
}

// DiscoverByEmailDomain returns routing for a verified domain (AUT-009). It only
// reveals routing configuration, never membership or account existence.
func (s *Service) DiscoverByEmailDomain(ctx context.Context, realmID, domain string) (orgID string, ssoRequired bool, providerID string, err error) {
	var policy []byte
	// Routing is deterministic (TEN-011): verified domains are unique in the
	// realm, an exact match wins, and otherwise the most specific verified
	// parent domain that opted into subdomains routes the address.
	err = s.d.DB.Pool.QueryRow(ctx, `SELECT o.id, o.policy FROM organization_domains d JOIN organizations o ON o.id=d.organization_id
		WHERE d.realm_id=$1 AND d.state='verified' AND o.state='active' AND (d.domain=$2 OR (d.include_subdomains AND $2 LIKE '%.' || d.domain))
		ORDER BY (d.domain=$2) DESC, length(d.domain) DESC LIMIT 1`, realmID, domain).Scan(&orgID, &policy)
	if err != nil {
		if storage.IsNoRows(err) {
			return "", false, "", nil
		}
		return "", false, "", err
	}
	var p struct {
		SSORequired   bool   `json:"sso_required"`
		SSOProviderID string `json:"sso_provider_id"`
	}
	_ = json.Unmarshal(policy, &p)
	return orgID, p.SSORequired, p.SSOProviderID, nil
}

// ---------- join requests ----------

// JoinRequest is a user's request to join an organization (INV-013).
type JoinRequest struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"organization_id"`
	UserID      string     `json:"user_id"`
	Reason      string     `json:"reason,omitempty"`
	State       string     `json:"state"`
	ReviewerIDs []string   `json:"reviewer_ids"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// joinReviewersTx returns up to 20 users who may review the organization's
// join requests: the assigned reviewers when there are any, otherwise the
// members holding org.join_requests.review.
func (s *Service) joinReviewersTx(ctx context.Context, tx pgx.Tx, realmID, orgID string, assigned []string) ([]string, error) {
	candidates := assigned
	if len(candidates) == 0 {
		rows, err := tx.Query(ctx, `SELECT DISTINCT subject_id FROM role_assignments WHERE realm_id=$1 AND scope_type='organization' AND scope_id=$2
			AND subject_type='user' ORDER BY subject_id LIMIT 200`, realmID, orgID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			candidates = append(candidates, id)
		}
		rows.Close()
	}
	scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
	var out []string
	for _, id := range candidates {
		if len(out) == 20 {
			break
		}
		if s.Authz.Check(ctx, tx, realmID, authorization.Subject{Type: authorization.SubjectUser, ID: id}, "org.join_requests.review", scope) {
			out = append(out, id)
		}
	}
	return out, nil
}

// notifyUsersTx queues a notice to each user's primary verified address in
// the same transaction as the change it reports.
func (s *Service) notifyUsersTx(ctx context.Context, tx pgx.Tx, realmID, orgID, tpl string, users []string, data map[string]string) error {
	if s.Notify == nil || len(users) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (user_id) user_id, original_value FROM user_identifiers WHERE user_id = ANY($1) AND type='email'
		AND verified_at IS NOT NULL ORDER BY user_id, is_primary DESC`, users)
	if err != nil {
		return err
	}
	type recipient struct{ user, email string }
	var list []recipient
	for rows.Next() {
		var r recipient
		if err := rows.Scan(&r.user, &r.email); err != nil {
			rows.Close()
			return err
		}
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		// The recipient's account localizes the notice (MSG-006).
		if _, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, OrgID: orgID, Template: tpl, Recipient: r.email,
			UserID: r.user, Data: data}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) noticeData(ctx context.Context, tx pgx.Tx, realmID, orgID string) map[string]string {
	data := map[string]string{"realm": realmID, "organization": orgID}
	var realmName, orgName string
	if err := tx.QueryRow(ctx, `SELECT coalesce(display_name, name) FROM realms WHERE id=$1`, realmID).Scan(&realmName); err == nil {
		data["realm"] = realmName
	}
	if err := tx.QueryRow(ctx, `SELECT coalesce(display_name, slug) FROM organizations WHERE id=$1`, orgID).Scan(&orgName); err == nil {
		data["organization"] = orgName
	}
	return data
}

// RequestJoin creates a join request. The response never reveals membership lists.
func (s *Service) RequestJoin(ctx context.Context, realmID, orgID, userID, reason string, auditActor audit.Ref) (*JoinRequest, error) {
	org, err := s.Get(ctx, nil, realmID, orgID)
	if err != nil || org.State != "active" || !org.Policy.JoinRequestsEnabled {
		return nil, problem.ErrNotFound
	}
	if len(reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "too long")
	}
	jr := &JoinRequest{ID: ids.New(ids.JoinRequest), OrgID: orgID, UserID: userID, Reason: reason, State: "pending",
		ExpiresAt: s.d.Now().Add(14 * 24 * time.Hour), CreatedAt: s.d.Now()}
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var exists bool
		_ = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired'))`, orgID, userID).Scan(&exists)
		if exists {
			return problem.ErrConflict.WithDetail("you already have a membership in this organization")
		}
		_, err := tx.Exec(ctx, `INSERT INTO join_requests (id, realm_id, organization_id, user_id, reason, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			jr.ID, realmID, orgID, userID, nilIfEmpty(reason), jr.ExpiresAt, jr.CreatedAt)
		if storage.IsUniqueViolation(err) {
			return problem.ErrConflict.WithDetail("a request is already pending")
		}
		if err != nil {
			return err
		}
		// The requester holds a pending_approval membership until a reviewer
		// decides (TEN-003); it grants no sign-in or token in the organization.
		if _, err := s.createMembershipTx(ctx, tx, realmID, orgID, userID, "self_join", jr.ID, "pending_approval"); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.join_request.created", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "join_request", ID: jr.ID}})
		if err != nil {
			return err
		}
		if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.join_request.created", RealmID: realmID, OrgID: orgID,
			AggregateType: "join_request", AggregateID: jr.ID, Data: map[string]any{"join_request_id": jr.ID}}); err != nil {
			return err
		}
		// Reviewers learn that a request waits; the notice names no requester,
		// and the requester never learns who the reviewers are.
		reviewers, err := s.joinReviewersTx(ctx, tx, realmID, orgID, nil)
		if err != nil {
			return err
		}
		return s.notifyUsersTx(ctx, tx, realmID, orgID, notification.TplJoinRequest, reviewers, s.noticeData(ctx, tx, realmID, orgID))
	})
	jr.ReviewerIDs = []string{}
	return jr, err
}

// AssignJoinReviewers restricts who may decide a pending request (INV-013).
// Every assignee must hold org.join_requests.review in the organization; the
// assignees are notified.
func (s *Service) AssignJoinReviewers(ctx context.Context, realmID, orgID, id string, reviewers []string, auditActor audit.Ref) error {
	if len(reviewers) == 0 || len(reviewers) > 10 {
		return problem.ErrValidation.WithField("reviewer_ids", "1 to 10 reviewers")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var state, requester string
		if err := tx.QueryRow(ctx, `SELECT state, user_id FROM join_requests WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, id).Scan(&state, &requester); err != nil {
			return problem.ErrNotFound
		}
		if state != "pending" {
			return problem.ErrConflict.WithDetail("request is not pending")
		}
		eligible, err := s.joinReviewersTx(ctx, tx, realmID, orgID, reviewers)
		if err != nil {
			return err
		}
		if len(eligible) != len(reviewers) || slices.Contains(reviewers, requester) {
			return problem.ErrValidation.WithField("reviewer_ids", "every reviewer must be able to review join requests, and none may be the requester")
		}
		if _, err := tx.Exec(ctx, `UPDATE join_requests SET reviewer_ids=$2 WHERE id=$1`, id, reviewers); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.join_request.reviewers_assigned", RealmID: realmID, OrgID: orgID,
			Actor: auditActor, Target: &audit.Ref{Type: "join_request", ID: id}, Metadata: map[string]any{"reviewer_ids": reviewers}}); err != nil {
			return err
		}
		return s.notifyUsersTx(ctx, tx, realmID, orgID, notification.TplJoinRequest, reviewers, s.noticeData(ctx, tx, realmID, orgID))
	})
}

// WithdrawJoinRequest lets the requester withdraw a pending request.
func (s *Service) WithdrawJoinRequest(ctx context.Context, realmID, orgID, id, userID string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE join_requests SET state='withdrawn', decided_at=$4 WHERE organization_id=$1 AND id=$2 AND user_id=$3 AND state='pending'`,
			orgID, id, userID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if err := s.releasePendingMembershipTx(ctx, tx, orgID, "pending_approval", id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.join_request.withdrawn", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "join_request", ID: id}})
		return err
	})
}

// MyJoinRequests lists a user's own requests: organization and state only.
func (s *Service) MyJoinRequests(ctx context.Context, realmID, userID string) ([]JoinRequest, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, organization_id, user_id, coalesce(reason,''), state, decided_at, expires_at, created_at
		FROM join_requests WHERE realm_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 100`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JoinRequest{}
	for rows.Next() {
		j := JoinRequest{ReviewerIDs: []string{}}
		if err := rows.Scan(&j.ID, &j.OrgID, &j.UserID, &j.Reason, &j.State, &j.DecidedAt, &j.ExpiresAt, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ListJoinRequests lists requests for reviewers.
func (s *Service) ListJoinRequests(ctx context.Context, orgID, state string) ([]JoinRequest, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, organization_id, user_id, coalesce(reason,''), state, coalesce(decided_by_id,''), decided_at, expires_at, created_at,
		reviewer_ids FROM join_requests WHERE organization_id=$1 AND ($2='' OR state=$2) ORDER BY created_at DESC LIMIT 500`, orgID, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JoinRequest{}
	for rows.Next() {
		var j JoinRequest
		if err := rows.Scan(&j.ID, &j.OrgID, &j.UserID, &j.Reason, &j.State, &j.DecidedBy, &j.DecidedAt, &j.ExpiresAt, &j.CreatedAt, &j.ReviewerIDs); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// DecideJoinRequest approves or denies a request. Reviewers cannot approve their own
// request, and approval creates a member-only membership.
func (s *Service) DecideJoinRequest(ctx context.Context, realmID, orgID, id string, approve bool, reason string, actor authorization.Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.LockActiveTx(ctx, tx, realmID, orgID); err != nil {
			return err
		}
		if !s.Authz.Check(ctx, tx, realmID, actor, "org.join_requests.review", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
			return problem.ErrForbidden
		}
		var j JoinRequest
		err := tx.QueryRow(ctx, `SELECT id, user_id, state, expires_at, reviewer_ids FROM join_requests WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, id).
			Scan(&j.ID, &j.UserID, &j.State, &j.ExpiresAt, &j.ReviewerIDs)
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if j.State != "pending" || !s.d.Now().Before(j.ExpiresAt) {
			return problem.ErrConflict.WithDetail("request is not pending")
		}
		if j.UserID == actor.ID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		// With assigned reviewers, only they (or a member administrator) decide.
		if len(j.ReviewerIDs) > 0 && !slices.Contains(j.ReviewerIDs, actor.ID) &&
			!s.Authz.Check(ctx, tx, realmID, actor, "org.members.write", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
			return problem.ErrForbidden.WithDetail("the request is assigned to other reviewers")
		}
		state := "denied"
		now := s.d.Now()
		if approve {
			state = "approved"
			tag, err := tx.Exec(ctx, `UPDATE memberships SET state='active', joined_at=$3, revision=revision+1, updated_at=$3
				WHERE organization_id=$1 AND user_id=$2 AND state='pending_approval' AND source_reference=$4`, orgID, j.UserID, now, id)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				if _, err := s.createMembershipTx(ctx, tx, realmID, orgID, j.UserID, "self_join", id, "active"); err != nil {
					return err
				}
			}
			member, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgMember)
			if err != nil {
				return err
			}
			if _, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: member.ID,
				Subject: authorization.Subject{Type: authorization.SubjectUser, ID: j.UserID}, Scope: authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID},
				Source: "join_request", SkipCeiling: true}, auditActor); err != nil {
				return err
			}
		}
		if !approve {
			if err := s.releasePendingMembershipTx(ctx, tx, orgID, "pending_approval", id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE join_requests SET state=$2, decided_by_id=$3, decision_reason=$4, decided_at=$5 WHERE id=$1`,
			id, state, actor.ID, nilIfEmpty(reason), now); err != nil {
			return err
		}
		if _, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.join_request." + state, RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Subject: &audit.Ref{Type: "user", ID: j.UserID}, Target: &audit.Ref{Type: "join_request", ID: id}, ReasonCode: reason}); err != nil {
			return err
		}
		data := s.noticeData(ctx, tx, realmID, orgID)
		data["decision"] = state
		return s.notifyUsersTx(ctx, tx, realmID, orgID, notification.TplJoinDecision, []string{j.UserID}, data)
	})
}

// releasePendingMembershipTx ends a not-yet-active membership (invited or
// pending_approval) created for a request or invitation that will not complete.
func (s *Service) releasePendingMembershipTx(ctx context.Context, tx pgx.Tx, orgID, state, reference string) error {
	_, err := tx.Exec(ctx, `UPDATE memberships SET state='removed', removed_at=$4, revision=revision+1, updated_at=$4, metadata='{}'
		WHERE organization_id=$1 AND state=$2 AND source_reference=$3`, orgID, state, reference, s.d.Now())
	return err
}

// ExpireJoinRequests expires undecided requests and releases their pending
// memberships (INV-013, TEN-003).
func (s *Service) ExpireJoinRequests(ctx context.Context) (int64, error) {
	var n int64
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE join_requests SET state='expired' WHERE id IN (SELECT id FROM join_requests WHERE state='pending'
			AND expires_at <= $1 LIMIT 500 FOR UPDATE SKIP LOCKED) RETURNING id, realm_id, organization_id, user_id`, s.d.Now())
		if err != nil {
			return err
		}
		type jr struct{ id, realm, org, user string }
		var list []jr
		for rows.Next() {
			var j jr
			if err := rows.Scan(&j.id, &j.realm, &j.org, &j.user); err != nil {
				rows.Close()
				return err
			}
			list = append(list, j)
		}
		rows.Close()
		for _, j := range list {
			if err := s.releasePendingMembershipTx(ctx, tx, j.org, "pending_approval", j.id); err != nil {
				return err
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.join_request.expired", RealmID: j.realm, OrgID: j.org,
				Actor: audit.System, Subject: &audit.Ref{Type: "user", ID: j.user}, Target: &audit.Ref{Type: "join_request", ID: j.id}}); err != nil {
				return err
			}
		}
		n = int64(len(list))
		return nil
	})
	return n, err
}

// VerifiedDomains returns the organization's verified email domains.
// DomainCovered reports whether host is a verified domain of the
// organization, or a subdomain of one verified with include_subdomains
// (TEN-010, TEN-011).
func (s *Service) DomainCovered(ctx context.Context, realmID, orgID, host string) (bool, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var ok bool
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organization_domains WHERE realm_id=$1 AND organization_id=$2 AND state='verified'
		AND (domain=$3 OR (include_subdomains AND right($3, length(domain)+1) = '.' || domain)))`, realmID, orgID, host).Scan(&ok)
	return ok, err
}

func (s *Service) VerifiedDomains(ctx context.Context, realmID, orgID string) ([]string, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT domain FROM organization_domains WHERE realm_id=$1 AND organization_id=$2 AND state='verified'`, realmID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
