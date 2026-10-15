package provisioning

import (
	"context"

	"github.com/proudauth/proudauth/internal/identity"
)

// loadUsers reads managed mappings, identities and memberships in fixed-size
// query batches. Every predicate retains realm/organization/connector scope;
// disappeared or deleted candidates are absent, while read failures abort.
func (s *Service) loadUsers(ctx context.Context, c *Connector, userIDs []string) (map[string]*managedUser, error) {
	out := make(map[string]*managedUser, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := s.d.DB.Pool.Query(ctx, userMapping+` AND x.local_id=ANY($2)`, c.ID, userIDs)
	if err != nil {
		return nil, err
	}
	managedIDs := make([]string, 0, len(userIDs))
	for rows.Next() {
		var id string
		var mu managedUser
		if err := rows.Scan(&mu.external, &id, &mu.version, &mu.created, &mu.updated); err != nil {
			rows.Close()
			return nil, err
		}
		out[id] = &mu
		managedIDs = append(managedIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	users, err := s.Users.UsersByID(ctx, s.d.DB.Pool, c.RealmID, managedIDs)
	if err != nil {
		return nil, err
	}
	for id, mu := range out {
		u := users[id]
		if u == nil || u.State == identity.StateDeleted {
			delete(out, id)
			continue
		}
		mu.user = u
	}
	rows, err = s.d.DB.Pool.Query(ctx, `SELECT user_id, id, state FROM memberships
		WHERE realm_id=$1 AND organization_id=$2 AND user_id=ANY($3) AND state NOT IN ('removed','expired')`, c.RealmID, c.OrganizationID, managedIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid, id, state string
		if err := rows.Scan(&uid, &id, &state); err != nil {
			return nil, err
		}
		if mu := out[uid]; mu != nil {
			mu.membership = id
			mu.memberOn = state == "active"
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, mu := range out {
		mu.version = contentVersion(mu.version, s.userResource(mu, ""))
	}
	return out, nil
}
