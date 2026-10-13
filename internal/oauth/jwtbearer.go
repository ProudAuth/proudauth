package oauth

import (
	"context"
	"errors"
	"net/url"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/token"
	"github.com/proudbase/proudauth/internal/workload"
)

// jwtBearerGrant is the RFC 7523 authorization grant, offered for workload
// federation (MCH-011, ADV-004): the "assertion" parameter is a workload
// token from an issuer the client trusts, never a client_assertion (client
// authentication stays separate, in client_assertion). The token represents
// the client's service principal, within its grants, and does not outlive
// the assertion.
func (s *Service) jwtBearerGrant(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation) (*IssuedTokens, *Error) {
	if s.Workload == nil || c.ServicePrincipalID == "" {
		return nil, ErrUnauthorizedClient("workload federation is not configured for this client")
	}
	assertion := f.Get("assertion")
	if assertion == "" {
		return nil, ErrInvalidRequest("assertion is required")
	}
	v, err := s.Workload.Verify(ctx, rlm.ID, c, assertion)
	if err != nil {
		var re *workload.RejectedError
		if !errors.As(err, &re) {
			return nil, serverError(s, err)
		}
		return nil, s.rejectAssertion(ctx, rlm, c, re)
	}
	ttlCap := v.Expiry.Sub(s.d.Now())
	if ttlCap <= 0 {
		return nil, ErrInvalidGrant("the assertion was not accepted")
	}
	// The assertion's jti is spent only by a request that is otherwise
	// accepted, in the transaction that issues the token: a request refused
	// for its resource, organization or scope leaves the assertion usable.
	var replayed *workload.RejectedError
	out, oe := s.issueServiceToken(ctx, rlm, c, f, cnf, serviceIssue{grant: application.GrantJWTBearer, ttlCap: ttlCap,
		meta: map[string]any{"workload_trust_id": v.Trust.ID, "workload_issuer": v.Trust.Issuer, "workload_subject": v.Subject, "workload_profile": v.Trust.Profile},
		consume: func(tx pgx.Tx) (*Error, error) {
			replayed = nil // a retried transaction starts clean (DB-014)
			if err := s.Workload.Consume(ctx, tx, v); err != nil {
				if errors.As(err, &replayed) {
					return ErrInvalidGrant("the assertion was not accepted"), nil
				}
				return nil, err
			}
			return nil, nil
		}})
	if replayed != nil {
		return nil, s.rejectAssertion(ctx, rlm, c, replayed)
	}
	return out, oe
}

// rejectAssertion audits a refused workload assertion. The reason is
// evidence for administrators, not an oracle for the presenter, who gets a
// generic invalid_grant.
func (s *Service) rejectAssertion(ctx context.Context, rlm *realm.Realm, c *application.Client, re *workload.RejectedError) *Error {
	_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "workload.assertion.rejected", RealmID: rlm.ID, Actor: audit.Ref{Type: "client", ID: c.Ref},
		ClientID: c.ClientID, Outcome: audit.Failure, Category: "token", Metadata: map[string]any{"reason": re.Reason}})
	return ErrInvalidGrant("the assertion was not accepted")
}
