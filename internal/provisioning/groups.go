package provisioning

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/storage"
)

// managedGroup is a connector's view of one local group.
type managedGroup struct {
	id, name, external string
	version            int64
	created, updated   time.Time
	members            []map[string]any
}

func (s *Service) loadGroup(ctx context.Context, q storage.Querier, c *Connector, id string) (*managedGroup, error) {
	var g managedGroup
	err := q.QueryRow(ctx, `SELECT x.external_id, x.resource_version, x.created_at, x.updated_at, g.name FROM connector_external_ids x
		JOIN groups g ON g.id=x.local_id AND g.organization_id=$3
		JOIN organizations o ON o.id=g.organization_id AND o.realm_id=$4
		WHERE x.connector_id=$1 AND x.resource_type='Group' AND x.local_id=$2`,
		c.ID, id, c.OrganizationID, c.RealmID).Scan(&g.external, &g.version, &g.created, &g.updated, &g.name)
	if storage.IsNoRows(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	g.id = id
	rows, err := q.Query(ctx, `SELECT m.user_id, coalesce(u.display_name,'') FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
		JOIN users u ON u.id=m.user_id AND u.realm_id=$3
		WHERE gm.group_id=$1 AND m.organization_id=$2 AND m.realm_id=$3 ORDER BY m.user_id`, id, c.OrganizationID, c.RealmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g.members = []map[string]any{}
	for rows.Next() {
		var uid, display string
		if err := rows.Scan(&uid, &display); err != nil {
			return nil, err
		}
		g.members = append(g.members, map[string]any{"value": uid, "display": display})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	g.version = contentVersion(g.version, s.groupResource(&g, ""))
	return &g, nil
}

func (s *Service) groupResource(g *managedGroup, base string) map[string]any {
	members := make([]map[string]any, 0, len(g.members))
	for _, m := range g.members {
		members = append(members, map[string]any{"value": m["value"], "display": m["display"], "$ref": base + "/Users/" + m["value"].(string)})
	}
	r := map[string]any{"schemas": []string{SchemaGroup}, "id": g.id, "displayName": g.name, "members": members,
		"meta": map[string]any{"resourceType": "Group", "created": g.created.UTC().Format(time.RFC3339), "lastModified": g.updated.UTC().Format(time.RFC3339),
			"version": etag(g.version), "location": base + "/Groups/" + g.id}}
	if !strings.HasPrefix(g.external, "~") {
		r["externalId"] = g.external
	}
	return r
}

// memberIDs reads member values (user IDs) from a members array.
func memberIDs(v any) []string {
	var out []string
	for _, el := range asList(v) {
		if m, ok := el.(map[string]any); ok {
			if id := str(m, "value"); id != "" && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// mappedRoles returns the approved roles for an external group, matched by
// display name or external ID (PROV-007).
func (c *Connector) mappedRoles(name, external string) []string {
	var out []string
	for _, key := range []string{name, external} {
		for k, roles := range c.GroupRoleMappings {
			if key != "" && strings.EqualFold(k, key) {
				for _, r := range roles {
					if !slices.Contains(out, r) && slices.Contains(c.RoleCeilingIDs, r) {
						out = append(out, r)
					}
				}
			}
		}
	}
	return out
}

// syncGroupRoles makes the group's connector-granted roles equal to its
// approved mapping; roles granted by administrators are left alone.
func (s *Service) syncGroupRoles(ctx context.Context, tx pgx.Tx, c *Connector, groupID, name, external string) error {
	want := c.mappedRoles(name, external)
	rows, err := tx.Query(ctx, `SELECT id, role_id FROM role_assignments WHERE subject_type='group' AND subject_id=$1 AND source='scim'`, groupID)
	if err != nil {
		return err
	}
	have := map[string]string{}
	for rows.Next() {
		var id, role string
		if err := rows.Scan(&id, &role); err != nil {
			rows.Close()
			return err
		}
		have[role] = id
	}
	rows.Close()
	for role, assignment := range have {
		if !slices.Contains(want, role) {
			if err := s.Authz.UnassignTx(ctx, tx, c.RealmID, assignment, nil, c.Ref(), true); err != nil {
				return err
			}
		}
	}
	for _, role := range want {
		if _, ok := have[role]; ok {
			continue
		}
		if _, err := s.Authz.AssignTx(ctx, tx, c.RealmID, nil, authorization.AssignInput{RoleID: role,
			Subject: authorization.Subject{Type: authorization.SubjectGroup, ID: groupID},
			Scope:   authorization.Scope{Type: authorization.ScopeOrganization, ID: c.OrganizationID}, Source: "scim", SkipCeiling: true}, c.Ref()); err != nil {
			return err
		}
	}
	return nil
}

// setGroupMembers makes the group's members equal to the given user IDs;
// only accounts this connector manages can be members it adds.
func (s *Service) setGroupMembers(ctx context.Context, tx pgx.Tx, c *Connector, groupID string, add, remove []string, replace bool) error {
	if replace {
		cur, err := s.loadGroup(ctx, tx, c, groupID)
		if err != nil {
			return err
		}
		remove = nil
		for _, m := range cur.members {
			if id := m["value"].(string); !slices.Contains(add, id) {
				remove = append(remove, id)
			}
		}
	}
	for _, uid := range remove {
		var mid string
		if tx.QueryRow(ctx, `SELECT gm.membership_id FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id WHERE gm.group_id=$1 AND m.user_id=$2`,
			groupID, uid).Scan(&mid) != nil {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM group_memberships WHERE group_id=$1 AND membership_id=$2`, groupID, mid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, mid); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.member.removed", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Category: "authorization", Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"membership_id": mid, "source": "scim"}}); err != nil {
			return err
		}
	}
	if len(add) > 0 {
		// Whoever decides who is in a group decides who holds its roles: a
		// connector adds members only to groups whose roles — granted to the
		// group by anyone, or inherited from its parents — are within its
		// ceiling (PROV-003, TEN-008).
		roles, err := organization.GroupRolesTx(ctx, tx, c.OrganizationID, groupID)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if !slices.Contains(c.RoleCeilingIDs, r) {
				return scimErr(403, "", "the group grants roles beyond this connector's ceiling")
			}
		}
	}
	for _, uid := range add {
		var managed bool
		_ = tx.QueryRow(ctx, `SELECT true FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=$2`, c.ID, uid).Scan(&managed)
		var mid string
		if !managed || tx.QueryRow(ctx, `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
			c.OrganizationID, uid).Scan(&mid) != nil {
			return scimErr(400, "invalidValue", "member "+uid+" is not a user this connector provisioned")
		}
		if err := s.Orgs.AddGroupMemberTx(ctx, tx, c.RealmID, c.OrganizationID, groupID, mid, "scim", c.Ref()); err != nil {
			return err
		}
	}
	return nil
}

// CreateGroup provisions a local group (PROV-007).
func (s *Service) CreateGroup(ctx context.Context, c *Connector, doc map[string]any, base string) (map[string]any, int64, error) {
	name := strings.TrimSpace(str(doc, "displayName"))
	external := str(doc, "externalId")
	if name == "" || len(name) > 200 || len(external) > 256 {
		return nil, 0, scimErr(400, "invalidValue", "displayName is required (at most 200 characters)")
	}
	members, _ := get(doc, "members")
	var id string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if external != "" {
			// Repair legacy inbound references left by local group deletion;
			// a live group and outbound cleanup authority remain untouched.
			if _, err := tx.Exec(ctx, `DELETE FROM connector_external_ids x WHERE connector_id=$1 AND resource_type='Group' AND external_id=$2
				AND coalesce(link_kind,'scim')='scim' AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.id=x.local_id)`, c.ID, external); err != nil {
				return err
			}
			var exists bool
			_ = tx.QueryRow(ctx, `SELECT true FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group' AND external_id=$2`, c.ID, external).Scan(&exists)
			if exists {
				return scimErr(409, "uniqueness", "externalId already provisioned by this connector")
			}
		}
		var taken bool
		_ = tx.QueryRow(ctx, `SELECT true FROM groups WHERE organization_id=$1 AND lower(name)=lower($2)`, c.OrganizationID, name).Scan(&taken)
		if taken {
			return scimErr(409, "uniqueness", "a group with this displayName exists")
		}
		g, err := s.Orgs.CreateGroupTx(ctx, tx, c.RealmID, c.OrganizationID, organization.GroupInput{Name: name, ExternalID: external, Source: "scim"}, c.Ref())
		if err != nil {
			return err
		}
		id = g.ID
		ext := external
		if ext == "" {
			ext = "~" + id
		}
		if _, err := tx.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id) VALUES ($1,'Group',$2,$3)`,
			c.ID, ext, id); err != nil {
			return err
		}
		if err := s.setGroupMembers(ctx, tx, c, id, memberIDs(members), nil, false); err != nil {
			return err
		}
		return s.syncGroupRoles(ctx, tx, c, id, name, external)
	})
	if err != nil {
		return nil, 0, err
	}
	return s.GetGroup(ctx, c, id, base)
}

// GetGroup returns one group the connector manages.
func (s *Service) GetGroup(ctx context.Context, c *Connector, id, base string) (map[string]any, int64, error) {
	g, err := s.loadGroup(ctx, s.d.DB.Pool, c, id)
	if err != nil {
		return nil, 0, err
	}
	return s.groupResource(g, base), g.version, nil
}

// ListGroups filters and pages the groups the connector manages.
func (s *Service) ListGroups(ctx context.Context, c *Connector, f Filter, startIndex, count int, base string, withMembers bool) ([]map[string]any, int, error) {
	idsList, err := s.candidates(ctx, c, "Group", f)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	matched := []map[string]any{}
	total := 0
	err = s.scanGroups(ctx, c, idsList, func(g *managedGroup) {
		r := s.groupResource(g, base)
		if f == nil || f.Match(r) {
			total++
			if total >= startIndex && len(matched) < count {
				if !withMembers {
					delete(r, "members")
				}
				matched = append(matched, r)
			}
		}
	})
	if err != nil {
		return nil, 0, err
	}
	return matched, total, nil
}

// ReplaceGroup applies a full Group document (PUT).
func (s *Service) ReplaceGroup(ctx context.Context, c *Connector, id string, doc map[string]any, ifMatch, base string) (map[string]any, int64, error) {
	name := strings.TrimSpace(str(doc, "displayName"))
	if name == "" {
		return nil, 0, scimErr(400, "invalidValue", "displayName is required")
	}
	members, _ := get(doc, "members")
	err := s.updateGroup(ctx, c, id, ifMatch, func(tx pgx.Tx, g *managedGroup) (string, error) {
		return name, s.setGroupMembers(ctx, tx, c, id, memberIDs(members), nil, true)
	})
	if err != nil {
		return nil, 0, err
	}
	return s.GetGroup(ctx, c, id, base)
}

// PatchGroup applies PatchOp operations on displayName and members,
// including Azure AD's members[value eq "id"] removal paths.
func (s *Service) PatchGroup(ctx context.Context, c *Connector, id string, ops []any, ifMatch, base string) (map[string]any, int64, error) {
	if len(ops) == 0 || len(ops) > 100 {
		return nil, 0, scimErr(400, "invalidValue", "1 to 100 operations")
	}
	err := s.updateGroup(ctx, c, id, ifMatch, func(tx pgx.Tx, g *managedGroup) (string, error) {
		name := g.name
		for _, raw := range ops {
			op, ok := raw.(map[string]any)
			if !ok {
				return "", scimErr(400, "invalidSyntax", "operations must be objects")
			}
			kind := strings.ToLower(str(op, "op"))
			path := strings.ToLower(str(op, "path"))
			value, _ := get(op, "value")
			switch {
			case path == "displayname" && (kind == "replace" || kind == "add"):
				name, _ = value.(string)
			case path == "" && (kind == "replace" || kind == "add"):
				doc, _ := value.(map[string]any)
				if dn := str(doc, "displayName"); dn != "" {
					name = dn
				}
				if m, ok := get(doc, "members"); ok {
					if err := s.setGroupMembers(ctx, tx, c, id, memberIDs(m), nil, kind == "replace"); err != nil {
						return "", err
					}
				}
			case path == "members" && kind == "add":
				if err := s.setGroupMembers(ctx, tx, c, id, memberIDs(value), nil, false); err != nil {
					return "", err
				}
			case path == "members" && kind == "replace":
				if err := s.setGroupMembers(ctx, tx, c, id, memberIDs(value), nil, true); err != nil {
					return "", err
				}
			case path == "members" && kind == "remove":
				remove := memberIDs(value)
				if value == nil {
					cur, err := s.loadGroup(ctx, tx, c, id)
					if err != nil {
						return "", err
					}
					for _, m := range cur.members {
						remove = append(remove, m["value"].(string))
					}
				}
				if err := s.setGroupMembers(ctx, tx, c, id, nil, remove, false); err != nil {
					return "", err
				}
			case strings.HasPrefix(path, "members[") && kind == "remove":
				f, err := ParseFilter(strings.TrimSuffix(strings.TrimPrefix(str(op, "path")[len("members["):], ""), "]"))
				if err != nil {
					return "", scimErr(400, "invalidPath", "invalid members filter")
				}
				cur, err2 := s.loadGroup(ctx, tx, c, id)
				if err2 != nil {
					return "", err2
				}
				var remove []string
				for _, m := range cur.members {
					if f.Match(m) {
						remove = append(remove, m["value"].(string))
					}
				}
				if err := s.setGroupMembers(ctx, tx, c, id, nil, remove, false); err != nil {
					return "", err
				}
			default:
				return "", scimErr(400, "invalidPath", "supported paths: displayName, members")
			}
		}
		return name, nil
	})
	if err != nil {
		return nil, 0, err
	}
	return s.GetGroup(ctx, c, id, base)
}

// lockOwnedGroup follows the same group -> mapping -> member order as local
// deletion and directory sync (PROV-008, DB-014). The join checks connector
// ownership before locking a group, so foreign IDs do not lock another owner.
func lockOwnedGroup(ctx context.Context, tx pgx.Tx, c *Connector, id string) error {
	var locked string
	if err := tx.QueryRow(ctx, `SELECT g.id FROM groups g JOIN connector_external_ids x ON x.local_id=g.id
		WHERE g.organization_id=$3 AND g.id=$2 AND x.connector_id=$1 AND x.resource_type='Group' FOR UPDATE OF g`,
		c.ID, id, c.OrganizationID).Scan(&locked); err != nil {
		if storage.IsNoRows(err) {
			return errNotFound
		}
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group' AND local_id=$2 FOR UPDATE`, c.ID, id)
	return err
}

func (s *Service) updateGroup(ctx context.Context, c *Connector, id, ifMatch string, apply func(pgx.Tx, *managedGroup) (string, error)) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// The group row is locked before the tag is compared, like the
		// account row of a User (TEST-050): an administrator's rename
		// (organization.UpdateGroup locks the row) or member change (adding
		// takes a key-share lock on it, removing a share lock) either commits
		// first and makes If-Match stale, or waits for this write; it is never
		// overwritten with the name read before it committed.
		if err := lockOwnedGroup(ctx, tx, c, id); err != nil {
			return err
		}
		g, err := s.loadGroup(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if !matchVersion(ifMatch, g.version) {
			return errPrecondition
		}
		name, err := apply(tx, g)
		if err != nil {
			return err
		}
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 200 {
			return scimErr(400, "invalidValue", "displayName is required (at most 200 characters)")
		}
		if name != g.name {
			if _, err := tx.Exec(ctx, `UPDATE groups SET name=$2, version=version+1, updated_at=$3 WHERE id=$1`, id, name, s.d.Now()); err != nil {
				if storage.IsUniqueViolation(err) {
					return scimErr(409, "uniqueness", "a group with this displayName exists")
				}
				return err
			}
		}
		external := g.external
		if strings.HasPrefix(external, "~") {
			external = ""
		}
		if err := s.syncGroupRoles(ctx, tx, c, id, name, external); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE connector_external_ids SET resource_version=resource_version+1, updated_at=$3
			WHERE connector_id=$1 AND resource_type='Group' AND local_id=$2`, c.ID, id, s.d.Now())
		return err
	})
}

// DeleteGroup removes a group the connector created, with the roles granted
// to it (PROV-007 controlled deletion); members keep their memberships.
func (s *Service) DeleteGroup(ctx context.Context, c *Connector, id, ifMatch string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// The If-Match check and the deletion run under the same row lock an
		// update takes, so a concurrent change cannot slip in between
		// (PROV-008).
		if err := lockOwnedGroup(ctx, tx, c, id); err != nil {
			return err
		}
		g, err := s.loadGroup(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if !matchVersion(ifMatch, g.version) {
			return errPrecondition
		}
		// The connector owns the group (lockOwnedGroup): its deletion is not
		// bounded by an administrator's ceiling (PROV-007).
		return s.Orgs.DeleteGroupTx(ctx, tx, c.RealmID, c.OrganizationID, id, nil, c.Ref())
	})
}
