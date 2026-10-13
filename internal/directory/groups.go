package directory

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/jobs"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/storage"
)

// normDN is a comparison key for a distinguished name: attribute types and
// values lower-cased, insignificant spaces removed.
func normDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	var parts []string
	for _, rdn := range parsed.RDNs {
		var avas []string
		for _, a := range rdn.Attributes {
			avas = append(avas, strings.ToLower(a.Type)+"="+strings.ToLower(a.Value))
		}
		slices.Sort(avas)
		parts = append(parts, strings.Join(avas, "+"))
	}
	return strings.Join(parts, ",")
}

// syncGroups mirrors the directory groups named in the connector's approved
// mappings into organization groups (PROV-007): the connector creates and
// owns one local group per mapped directory group, keeps its members equal
// to the group's members that this connector manages, and grants the mapped
// roles, all within the connector's role ceiling. Unmapped directory groups
// are never imported, and groups the connector did not create are never
// touched.
func (s *Service) syncGroups(ctx context.Context, cn *conn, c *Connector, r *runCtx) error {
	cfg := c.ldap
	members := map[string]string{} // normalized DN or lower-cased username -> user ID
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+linkCols+` FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User'
		AND link_kind='directory' AND coalesce(source_state,'active') <> 'missing'`, c.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			rows.Close()
			return err
		}
		members[normDN(l.DN)] = l.UserID
		if u := l.Snapshot["username"]; u != "" {
			members["uid:"+strings.ToLower(u)] = l.UserID
		}
	}
	rows.Close()
	attrs := []string{cfg.GroupNameAttribute, cfg.GroupMemberAttribute}
	for _, key := range sortedKeys(c.GroupRoleMappings) {
		var entries []*ldap.Entry
		var err error
		if strings.Contains(key, "=") {
			entries, err = cn.search(key, ldap.ScopeBaseObject, cfg.GroupFilter, attrs, 2)
		} else {
			entries, err = cn.search(cfg.GroupBaseDN, ldap.ScopeWholeSubtree,
				"(&"+cfg.GroupFilter+"("+cfg.GroupNameAttribute+"="+ldap.EscapeFilter(key)+"))", attrs, 2)
		}
		if err != nil {
			return err
		}
		if len(entries) != 1 {
			reason := "group_not_found"
			if len(entries) > 1 {
				reason = "group_ambiguous"
			}
			r.add(Finding{Kind: FindConflict, Reason: reason, ExternalID: key})
			continue
		}
		g := entries[0]
		name := strings.TrimSpace(g.GetEqualFoldAttributeValue(cfg.GroupNameAttribute))
		if name == "" {
			name = key
		}
		var want []string
		for _, v := range g.GetEqualFoldAttributeValues(cfg.GroupMemberAttribute) {
			k := normDN(v)
			if cfg.GroupMemberAttribute == "memberUid" {
				k = "uid:" + strings.ToLower(v)
			}
			if id, ok := members[k]; ok && !slices.Contains(want, id) {
				want = append(want, id)
			}
		}
		err = s.runTx(ctx, r, func(tx pgx.Tx) error {
			if err := s.applyGroup(ctx, tx, c, r, key, normDN(g.DN), clip(name, 200), want, c.GroupRoleMappings[key]); err != nil {
				return err
			}
			if r.dry {
				return errDryRun
			}
			return nil
		})
		if err != nil && !errors.Is(err, errDryRun) {
			if errors.Is(err, jobs.ErrLeaseLost) {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.d.Log.Warn("directory group not applied", "connector_id", c.ID, "error", err)
			r.add(Finding{Kind: FindError, Reason: "group_apply_failed", ExternalID: key})
		}
	}
	return nil
}

func (s *Service) applyGroup(ctx context.Context, tx pgx.Tx, c *Connector, r *runCtx, key, ext, name string, want, mapped []string) error {
	var groupID string
	err := tx.QueryRow(ctx, `SELECT x.local_id FROM connector_external_ids x JOIN groups g ON g.id=x.local_id AND g.organization_id=$3
		WHERE x.connector_id=$1 AND x.resource_type='Group' AND x.external_id=$2 FOR UPDATE OF g`, c.ID, ext, c.OrganizationID).Scan(&groupID)
	created := false
	if storage.IsNoRows(err) {
		// Older local deletions could leave an orphaned directory Group
		// link. Repair only that missing local reference, within this apply;
		// dry runs roll it back and outbound cleanup links are unaffected.
		if _, err := tx.Exec(ctx, `DELETE FROM connector_external_ids x WHERE connector_id=$1 AND resource_type='Group' AND external_id=$2
			AND link_kind='directory' AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.id=x.local_id)`, c.ID, ext); err != nil {
			return err
		}
		var taken bool
		_ = tx.QueryRow(ctx, `SELECT true FROM groups WHERE organization_id=$1 AND lower(name)=lower($2)`, c.OrganizationID, name).Scan(&taken)
		if taken {
			// An existing group of the same name was not created by this
			// connector: it is never taken over.
			r.add(Finding{Kind: FindConflict, Reason: "group_name_in_use", ExternalID: key})
			return nil
		}
		g, err := s.Orgs.CreateGroupTx(ctx, tx, c.RealmID, c.OrganizationID, organization.GroupInput{Name: name, Source: "directory",
			Description: "Managed by directory connector " + c.Name}, c.Ref())
		if err != nil {
			return err
		}
		groupID, created = g.ID, true
		if _, err := tx.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id, link_kind, source_dn, last_seen_at)
			VALUES ($1,'Group',$2,$3,'directory',$4,$5)`, c.ID, ext, groupID, key, s.d.Now()); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// As with SCIM and local deletion, lock the group before its mapping
	// and members (PROV-008, DB-014). A missing/replaced link fails this apply
	// rather than changing a group no longer owned by the connector.
	var linked string
	if err := tx.QueryRow(ctx, `SELECT local_id FROM connector_external_ids WHERE connector_id=$1
		AND resource_type='Group' AND external_id=$2 AND local_id=$3 FOR UPDATE`, c.ID, ext, groupID).Scan(&linked); err != nil {
		return err
	}
	// Whoever decides who is in a group decides who holds its roles: roles
	// granted to the group by anyone else, or inherited from a parent, must
	// be within the connector's ceiling before it changes membership
	// (PROV-003, TEN-008, TEST-049).
	roles, err := organization.GroupRolesTx(ctx, tx, c.OrganizationID, groupID)
	if err != nil {
		return err
	}
	for _, role := range append(slices.Clone(roles), mapped...) {
		if !slices.Contains(c.RoleCeilingIDs, role) {
			r.add(Finding{Kind: FindConflict, Reason: "group_roles_beyond_ceiling", ExternalID: key, LocalID: groupID})
			return nil
		}
	}
	if err := s.syncGroupRoles(ctx, tx, c, groupID, mapped); err != nil {
		return err
	}
	// Members are exactly the mapped directory members that this connector
	// manages and that hold a live membership in the organization.
	cur := map[string]string{} // user -> membership
	rows, err := tx.Query(ctx, `SELECT m.user_id, m.id FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id WHERE gm.group_id=$1`, groupID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var uid, mid string
		if err := rows.Scan(&uid, &mid); err != nil {
			rows.Close()
			return err
		}
		cur[uid] = mid
	}
	rows.Close()
	added, removed := 0, 0
	for uid, mid := range cur {
		if slices.Contains(want, uid) {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM group_memberships WHERE group_id=$1 AND membership_id=$2`, groupID, mid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, mid); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.member.removed", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Category: "authorization", Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"membership_id": mid, "source": "directory"}}); err != nil {
			return err
		}
		removed++
	}
	for _, uid := range want {
		if _, ok := cur[uid]; ok {
			continue
		}
		var mid string
		if tx.QueryRow(ctx, `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
			c.OrganizationID, uid).Scan(&mid) != nil {
			continue
		}
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		if err := s.Orgs.AddGroupMemberTx(ctx, sp, c.RealmID, c.OrganizationID, groupID, mid, "directory", c.Ref()); err != nil {
			_ = sp.Rollback(ctx)
			r.add(Finding{Kind: FindConflict, Reason: "group_member_refused", ExternalID: key, LocalID: uid})
			continue
		}
		if err := sp.Commit(ctx); err != nil {
			return err
		}
		added++
	}
	if created || added > 0 || removed > 0 {
		r.add(Finding{Kind: FindGroup, Reason: map[bool]string{true: "group_created", false: "members_changed"}[created], ExternalID: key, LocalID: groupID,
			Applied: !r.dry, Detail: map[string]any{"members_added": added, "members_removed": removed}})
	}
	return nil
}

// syncGroupRoles makes the group's directory-granted roles equal to the
// approved mapping; roles administrators granted are left alone.
func (s *Service) syncGroupRoles(ctx context.Context, tx pgx.Tx, c *Connector, groupID string, want []string) error {
	rows, err := tx.Query(ctx, `SELECT id, role_id FROM role_assignments WHERE subject_type='group' AND subject_id=$1 AND source='directory'`, groupID)
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
		if _, ok := have[role]; ok || !slices.Contains(c.RoleCeilingIDs, role) {
			continue
		}
		var exists bool
		_ = tx.QueryRow(ctx, `SELECT true FROM role_assignments WHERE subject_type='group' AND subject_id=$1 AND role_id=$2`, groupID, role).Scan(&exists)
		if exists {
			continue
		}
		if _, err := s.Authz.AssignTx(ctx, tx, c.RealmID, nil, authorization.AssignInput{RoleID: role,
			Subject: authorization.Subject{Type: authorization.SubjectGroup, ID: groupID},
			Scope:   authorization.Scope{Type: authorization.ScopeOrganization, ID: c.OrganizationID}, Source: "directory", SkipCeiling: true}, c.Ref()); err != nil {
			return err
		}
	}
	return nil
}
