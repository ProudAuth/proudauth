package organization

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/ratelimit"
)

// joinBudget applies the join-request budgets (INV-013, REG-012, TEN-018):
// per requester across the realm, then per organization. A request the
// requester's budget refuses does not count toward the organization's, so one
// account cannot spend the organization's budget for everyone else; a request
// the requester's budget admits counts toward both, also when the
// organization's refuses it. Budgets fail closed, and withdrawing a request
// never refunds them.
func (s *Service) joinBudget(ctx context.Context, realmID, orgID, userID string) error {
	if s.Limiter == nil {
		return nil
	}
	rl := s.d.Cfg.Security.RateLimits
	for _, b := range []ratelimit.Budget{
		{Key: "join-req-user:" + realmID + ":" + userID, Limit: rl.JoinRequestsPerUser, Window: rl.JoinRequestWindow},
		{Key: "join-req-org:" + orgID, Limit: rl.JoinRequestsPerOrganization, Window: rl.JoinRequestWindow},
	} {
		d, err := s.Limiter.Hit(ctx, b)
		if err != nil {
			return err
		}
		if !d.Allowed {
			return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter).WithDetail("join request budget exhausted")
		}
	}
	return nil
}

// repeatJoinRequestTx reports whether the user filed another request to the
// organization within the join-request window before this one, whatever
// became of it. Such a repeat does not notify the reviewers again: a
// request-withdraw loop costs them one notice, not one per request. A zero
// window turns this off.
func (s *Service) repeatJoinRequestTx(ctx context.Context, tx pgx.Tx, jr *JoinRequest) (bool, error) {
	window := s.d.Cfg.Security.RateLimits.JoinRequestWindow
	if window <= 0 {
		return false, nil
	}
	var repeat bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM join_requests WHERE organization_id=$1 AND user_id=$2 AND id<>$3 AND created_at > $4)`,
		jr.OrgID, jr.UserID, jr.ID, jr.CreatedAt.Add(-window)).Scan(&repeat)
	return repeat, err
}
