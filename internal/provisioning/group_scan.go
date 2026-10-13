package provisioning

import (
	"context"
	"fmt"
)

// scanGroups batches connector/org/realm-qualified metadata and streams members
// in group order (PROV-002, PROV-008, NFR-004, NFR-006). Only one group's member
// collection is live at a time, in addition to the page retained by the caller.
// Any read error invalidates the entire scan, including earlier page matches.
func (s *Service) scanGroups(ctx context.Context, c *Connector, candidates []string, visit func(*managedGroup)) error {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) > maxScan {
		return scimErr(400, "tooMany", "group scan exceeds the managed-resource bound")
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT x.local_id, x.external_id, x.resource_version, x.created_at, x.updated_at, g.name
		FROM connector_external_ids x JOIN groups g ON g.id=x.local_id AND g.organization_id=$3
		JOIN organizations o ON o.id=g.organization_id AND o.realm_id=$4
		WHERE x.connector_id=$1 AND x.resource_type='Group' AND x.local_id=ANY($2)
		ORDER BY x.local_id`, c.ID, candidates, c.OrganizationID, c.RealmID)
	if err != nil {
		return err
	}
	groups := make(map[string]*managedGroup, len(candidates))
	ids := make([]string, 0, len(candidates))
	positions := make(map[string]int, len(candidates))
	for rows.Next() {
		g := &managedGroup{members: []map[string]any{}}
		if err := rows.Scan(&g.id, &g.external, &g.version, &g.created, &g.updated, &g.name); err != nil {
			rows.Close()
			return err
		}
		groups[g.id] = g
		positions[g.id] = len(ids)
		ids = append(ids, g.id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(groups) == 0 {
		return nil // Missing/deleted/foreign mappings remain invisible.
	}
	rows, err = s.d.DB.Pool.Query(ctx, `SELECT gm.group_id, m.user_id, coalesce(u.display_name,'')
		FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
		JOIN users u ON u.id=m.user_id AND u.realm_id=$3
		WHERE gm.group_id=ANY($1) AND m.organization_id=$2 AND m.realm_id=$3
		ORDER BY gm.group_id, m.user_id`, ids, c.OrganizationID, c.RealmID)
	if err != nil {
		return err
	}
	defer rows.Close()
	i := 0
	finish := func() {
		g := groups[ids[i]]
		g.version = contentVersion(g.version, s.groupResource(g, ""))
		visit(g)
		g.members = nil
		i++
	}
	for rows.Next() {
		var groupID, userID, display string
		if err := rows.Scan(&groupID, &userID, &display); err != nil {
			return err
		}
		position, exists := positions[groupID]
		if !exists || position < i {
			return fmt.Errorf("group scan: member row outside the scoped ordered set")
		}
		for i < position {
			finish() // Also emit empty groups between member-bearing groups.
		}
		if i == len(ids) || ids[i] != groupID {
			return fmt.Errorf("group scan: member row outside the scoped ordered set")
		}
		g := groups[groupID]
		g.members = append(g.members, map[string]any{"value": userID, "display": display})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i < len(ids) {
		finish()
	}
	return nil
}
