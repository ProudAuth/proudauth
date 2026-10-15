package organization

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// RemoveGroupMemberTx is RemoveGroupMember inside the caller's transaction,
// for callers whose removal must commit together with their own record
// (lifecycle workflow steps and their compensation, EXT-016). It returns
// ErrNotFound when the membership is not in the group.
func (s *Service) RemoveGroupMemberTx(ctx context.Context, tx pgx.Tx, realmID, orgID, groupID, membershipID string, auditActor audit.Ref) error {
	var dynamic bool
	if err := tx.QueryRow(ctx, `SELECT dynamic_rule IS NOT NULL FROM groups WHERE organization_id=$1 AND id=$2`, orgID, groupID).Scan(&dynamic); err == nil && dynamic {
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
}
