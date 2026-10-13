package identity

import (
	"context"

	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// UsersByID loads a realm-qualified, bounded set in two queries, including
// identifiers in the same order as User. Missing IDs are absent; any read
// failure aborts the whole result. Internal callers establish their own
// read authority (SCIM uses only its connector's managed candidates).
func (s *Service) UsersByID(ctx context.Context, q storage.Querier, realmID string, userIDs []string) (map[string]*User, error) {
	if len(userIDs) > 20000 {
		return nil, problem.ErrValidation.WithDetail("at most 20000 users per internal batch read")
	}
	if q == nil {
		q = s.d.DB.Pool
	}
	out := make(map[string]*User, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT `+userCols+` FROM users WHERE realm_id=$1 AND id=ANY($2)`, realmID, userIDs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		u.Identifiers = []Identifier{}
		out[u.ID] = u
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT user_id, id, type, original_value, canonical_value, verified_at, is_primary, source
		FROM user_identifiers WHERE realm_id=$1 AND user_id=ANY($2) ORDER BY user_id, created_at, id`, realmID, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid string
		var i Identifier
		if err := rows.Scan(&uid, &i.ID, &i.Type, &i.Value, &i.Canonical, &i.VerifiedAt, &i.IsPrimary, &i.Source); err != nil {
			return nil, err
		}
		if u := out[uid]; u != nil {
			u.Identifiers = append(u.Identifiers, i)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
