package authentication

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/certauth"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/session"
)

// Certificate signs a person in with an X.509 certificate presented over TLS
// (PROV-016). The certificate must chain to one of the realm's user trust
// anchors, be valid and not revoked under the anchor's policy, and be bound
// to the account (or carry an e-mail address the anchor maps to a verified
// account address). When the transaction already names an account, the
// certificate must be that account's. A certificate whose key the anchor
// declares protected by a second factor (a smart card with a PIN) counts as
// phishing-resistant multi-factor authentication.
func (s *Service) Certificate(ctx context.Context, realmID, id string, p Proof, cert *x509.Certificate, intermediates []*x509.Certificate) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if !rlm.Policy.Login.Certificates || s.Certs == nil {
			return nil, problem.ErrUnexpectedStep.WithDetail("certificate sign-in is not enabled in this realm")
		}
		if cert == nil {
			return nil, problem.ErrBadRequest.WithDetail("no client certificate was presented; use the mutual-TLS endpoint")
		}
		if err := s.verifyBudget(ctx, t.RealmID, certificateBudgetSubject(ctx, t, cert), requesterOf(ctx, t), t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		fail := func(reason string) (map[string]any, error) {
			_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.certificate.failed", RealmID: t.RealmID, Actor: actorFor(t),
				Outcome: audit.Failure, Category: "security", ReasonCode: reason, Metadata: map[string]any{"subject_dn": cert.Subject.String(),
					"issuer_dn": cert.Issuer.String(), "transaction_id": t.ID}})
			return nil, errProof(problem.ErrInvalidProof)
		}
		userID, anchor, err := s.Certs.ResolveUser(ctx, tx, t.RealmID, cert, intermediates)
		switch {
		case errors.Is(err, certauth.ErrRevoked):
			return fail("CERTIFICATE_REVOKED")
		case errors.Is(err, certauth.ErrNoCRL):
			return fail("REVOCATION_UNAVAILABLE")
		case errors.Is(err, certauth.ErrUntrusted):
			return fail("CERTIFICATE_UNTRUSTED")
		case errors.Is(err, certauth.ErrUnbound):
			return fail("CERTIFICATE_UNBOUND")
		case err != nil:
			return nil, err
		}
		if t.UserID != "" && t.UserID != userID {
			return fail("CERTIFICATE_OTHER_ACCOUNT")
		}
		u, err := s.Users.User(ctx, tx, t.RealmID, userID)
		// A pending-deletion account may sign in to cancel (USR-012).
		if err != nil || (!u.CanAuthenticate(s.d.Now()) && !u.MayCancelDeletion(s.d.Now())) {
			return fail("ACCOUNT_UNAVAILABLE")
		}
		now := s.d.Now()
		t.UserID = userID
		if t.AuthTime == nil {
			t.AuthTime = &now
		}
		t.Factors = append(t.Factors, session.Factor{Type: "x509", At: now, CredentialID: anchor.ID, UserVerified: anchor.MultiFactor})
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.certificate.used", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: userID},
			Subject: &audit.Ref{Type: "user", ID: userID}, Category: "security", Metadata: map[string]any{"anchor_id": anchor.ID,
				"subject_dn": cert.Subject.String(), "multi_factor": anchor.MultiFactor, "transaction_id": t.ID}})
		return nil, err
	})
}

// certificateBudgetSubject keys the certificate step's per-subject attempt
// budget. Once the transaction names an account it is that account, as for
// every other proof. Before identify no account is known, so the attempt is
// counted against the certificate (its thumbprint) from the client's network
// (/24 or /48): one certificate, or one network, cannot use up a budget that
// every other person of the realm shares.
func certificateBudgetSubject(ctx context.Context, t *Transaction, cert *x509.Certificate) string {
	if t.UserID != "" {
		return t.UserID
	}
	return "x509:" + certauth.Thumbprint(cert) + ":" + reqctx.NetworkContext(chargeIP(ctx, t), false)
}
