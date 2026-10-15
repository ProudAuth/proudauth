package authentication

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/session"
)

// CompleteUpstream applies the outcome of an upstream sign-in round trip,
// whatever the protocol (OIDC/OAuth callback or SAML response, FED-014), to
// what the request was for: a pending self-service link, or the bound
// authentication transaction. failure is a stable reason code when the
// upstream round trip failed; up is the validated identity otherwise.
//
// Linking, just-in-time provisioning and organization rules come from one
// place (federation.ResolveTx) for every protocol, so a SAML connection gets
// exactly the FED-004/FED-005 linking behavior of an OIDC connection.
func (s *Service) CompleteUpstream(ctx context.Context, realmID string, req *federation.Request, prov *federation.Provider, up *federation.Upstream, failure string) (*CallbackResult, error) {
	res := &CallbackResult{TransactionID: req.TransactionID}
	if prov.State != "active" {
		// A connection disabled while the round trip was in flight (SEC-020
		// emergency control) signs no one in and links nothing, whatever the
		// protocol.
		failure, up = federation.FailureConnectionDisabled, nil
	}
	if req.Purpose == "link" {
		if failure != "" {
			res.Error = failure
			_ = s.recordFederationFailure(ctx, realmID, prov, req.UserID, failure)
			return res, nil
		}
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			code, err := s.Federation.StorePendingLinkTx(ctx, tx, realmID, req, up)
			res.LinkCode = code
			return err
		})
		return res, err
	}
	err := s.External(ctx, realmID, req.TransactionID, func(tx pgx.Tx, t *Transaction) error {
		if failure != "" {
			t.Pending.ExternalError = failure
			res.Error = failure
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.login.failed", RealmID: realmID, Actor: audit.Ref{Type: "identity_provider", ID: prov.ID},
				Outcome: audit.Failure, ReasonCode: failure, Metadata: map[string]any{"provider": prov.Alias, "transaction_id": t.ID}})
			return err
		}
		rsl, err := s.Federation.ResolveTx(ctx, tx, realmID, prov, up)
		if err != nil {
			var pe *problem.Error
			if errors.As(err, &pe) && pe.Status < 500 {
				t.Pending.ExternalError = "account_conflict"
				res.Error = t.Pending.ExternalError
				return nil
			}
			return err
		}
		switch {
		case rsl.Denied != "":
			t.Pending.ExternalError = rsl.Denied
			res.Error = rsl.Denied
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.login.denied", RealmID: realmID, Actor: audit.Ref{Type: "identity_provider", ID: prov.ID},
				Outcome: audit.Denied, ReasonCode: rsl.Denied, Metadata: map[string]any{"provider": prov.Alias, "transaction_id": t.ID}})
			return err
		case rsl.Candidate != nil:
			// Proof of control of the existing account is required (FED-005): the
			// user signs in to it locally in this transaction, then the link is made.
			t.UserID, t.Factors, t.AuthTime = "", nil, nil
			t.Pending.PendingLink = rsl.Candidate
			// A sign-in code requested before the link was pending is not
			// proof for it (PWDLESS-008): a new, link-bound one is sent.
			t.Pending.LoginOTPChallenge = ""
			t.Pending.Identifier = ""
			if rsl.Candidate.Email != "" {
				if c, _, ok := canonicalEmail(rsl.Candidate.Email); ok {
					t.Pending.Identifier, t.Pending.IdentifierType = c, "email"
				}
			}
			t.Pending.SSORouted = false
			t.Pending.ExternalError = ""
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.link.verification_required", RealmID: realmID,
				Actor: audit.Ref{Type: "identity_provider", ID: prov.ID}, Subject: &audit.Ref{Type: "user", ID: rsl.Candidate.UserID},
				Metadata: map[string]any{"provider": prov.Alias, "transaction_id": t.ID}})
			return err
		}
		u, err := s.Users.User(ctx, tx, realmID, rsl.UserID)
		if err != nil {
			return err
		}
		// A pending-deletion account may sign in to cancel (USR-012).
		if !u.CanAuthenticate(s.d.Now()) && !u.MayCancelDeletion(s.d.Now()) {
			t.Pending.ExternalError = "account_unavailable"
			res.Error = t.Pending.ExternalError
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.denied", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: u.ID},
				Subject: &audit.Ref{Type: "user", ID: u.ID}, Outcome: audit.Denied, ReasonCode: "ACCOUNT_UNAVAILABLE", Metadata: map[string]any{"provider": prov.Alias}})
			return err
		}
		if t.UserID != "" && t.UserID != u.ID {
			// The transaction already authenticated someone else: never switch subject.
			t.Pending.ExternalError = "account_mismatch"
			res.Error = t.Pending.ExternalError
			return nil
		}
		now := s.d.Now()
		t.UserID = u.ID
		t.IdentifiedVia = "federation"
		t.Factors = append(t.Factors, session.Factor{Type: "fed", At: now, Upstream: prov.ID})
		if up.MFA {
			t.Factors = append(t.Factors, session.Factor{Type: "fed_mfa", At: now, Upstream: prov.ID})
		}
		if t.AuthTime == nil {
			t.AuthTime = &now
		}
		t.Pending.ExternalError = ""
		t.Pending.PendingLink = nil
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.login.succeeded", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: u.ID},
			Subject: &audit.Ref{Type: "user", ID: u.ID}, Metadata: map[string]any{"provider": prov.Alias, "created": rsl.Created, "linked": rsl.Linked,
				"upstream_mfa": up.MFA, "transaction_id": t.ID}})
		return err
	})
	return res, err
}

// SAMLCallback handles a SAML response posted to a connection's assertion
// consumer service (FED-014). The response is validated and its request
// consumed by the broker; the outcome is applied like any upstream
// callback. As with OIDC, completing the login still needs the
// transaction's continuation, so a response replayed from another browser
// cannot finish someone else's sign-in.
func (s *Service) SAMLCallback(ctx context.Context, realmID, realmName, alias, samlResponse, relayState string) (*CallbackResult, error) {
	if s.Federation == nil || s.Federation.SAML == nil {
		return nil, problem.ErrFeatureDisabled
	}
	r, err := s.Federation.SAML.Consume(ctx, realmID, realmName, alias, samlResponse, relayState)
	if err != nil {
		return nil, err
	}
	return s.CompleteUpstream(ctx, realmID, r.Request, r.Provider, r.Upstream, r.Failure)
}
