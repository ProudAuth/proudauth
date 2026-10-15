package authentication

import (
	"context"
	"errors"
	"github.com/proudauth/proudauth/internal/storage"
	"net/url"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/session"
)

// StartFederation begins upstream sign-in for the transaction (FED-001). The
// returned state carries the upstream authorization URL in ExternalRedirect.
func (s *Service) StartFederation(ctx context.Context, realmID, id string, p Proof, providerRef string) (*State, error) {
	if s.Federation == nil {
		return nil, problem.ErrFeatureDisabled
	}
	var redirect string
	st, err := s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		prov, err := s.Federation.Get(ctx, tx, t.RealmID, providerRef)
		if err != nil || prov.State != "active" {
			return nil, problem.ErrValidation.WithField("provider", "unknown or disabled connection")
		}
		// An organization's connection cannot be used to sign in to a different
		// organization's context (FED-006); without an organization context it may
		// be chosen explicitly (e.g. "sign in with Corp SSO").
		orgCtx := t.SelectedOrgID
		if orgCtx == "" {
			orgCtx = t.RequestedOrgID
		}
		if prov.OrganizationID != "" && orgCtx != "" && orgCtx != prov.OrganizationID {
			return nil, problem.ErrValidation.WithField("provider", "this connection is not available for this sign-in")
		}
		if err := s.loginBudgetIP(ctx, t); err != nil {
			return nil, err
		}
		hint := ""
		if t.Pending.IdentifierType == "email" {
			hint = t.Pending.Identifier
		}
		redirect, err = s.Federation.BeginTx(ctx, tx, t.RealmID, rlm.Name, prov, "login", t.ID, "", "", hint)
		if err != nil {
			if errors.Is(err, federation.ErrUpstream) {
				t.Pending.ExternalError = "upstream_unavailable"
				return nil, nil
			}
			return nil, err
		}
		t.Pending.ExternalProvider = prov.ID
		t.Pending.ExternalError = ""
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	st.ExternalRedirect = redirect
	return st, nil
}

// ForeignConnection reports whether the factors include a federated sign-in
// through a connection that belongs to an organization other than orgID: an
// organization's connection never authenticates into another organization's
// context, whichever way that context is entered (FED-006).
func (s *Service) ForeignConnection(ctx context.Context, q storage.Querier, realmID string, factors []session.Factor, orgID string) bool {
	if orgID == "" {
		return false
	}
	for _, f := range factors {
		if f.Type != "fed" || f.Upstream == "" {
			continue
		}
		prov, err := s.Federation.Get(ctx, q, realmID, f.Upstream)
		if err != nil {
			return true // an unknown connection is not trusted for any organization
		}
		if prov.OrganizationID != "" && prov.OrganizationID != orgID {
			return true
		}
	}
	return false
}

// CallbackResult tells the HTTP layer where to send the browser.
type CallbackResult struct {
	TransactionID string
	// LinkCode is set for a completed self-service link awaiting confirmation.
	LinkCode string
	// Error is a stable reason code when the upstream round trip failed.
	Error string
}

// FederationCallback handles the upstream redirect. The request is consumed
// first (single use) and the code is exchanged outside any database
// transaction; the result is then applied to the bound authentication
// transaction. Completion still requires the transaction's continuation proof,
// so a callback URL replayed in another browser cannot finish a login.
func (s *Service) FederationCallback(ctx context.Context, realmID, alias string, q url.Values) (*CallbackResult, error) {
	if s.Federation == nil {
		return nil, problem.ErrFeatureDisabled
	}
	var req *federation.Request
	var prov *federation.Provider
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		req, prov, err = s.Federation.ConsumeTx(ctx, tx, realmID, alias, q.Get("state"))
		return err
	})
	if err != nil {
		return nil, err
	}
	var up *federation.Upstream
	failure := ""
	if prov.State != "active" {
		// Disabled (for example by the emergency control, SEC-020) after the
		// round trip started: the upstream is not contacted and its answer
		// is not used (CompleteUpstream refuses it as well).
		failure = federation.FailureConnectionDisabled
	} else if e := q.Get("error"); e != "" {
		failure = "upstream_denied"
		if e == "temporarily_unavailable" || e == "server_error" {
			failure = "upstream_unavailable"
		}
	} else {
		up, err = s.Federation.Exchange(ctx, prov, q.Get("code"), req.Verifier, req.RedirectURI, req.Nonce)
		switch {
		case err == nil:
		case errors.Is(err, federation.ErrUpstream):
			failure = "upstream_unavailable"
		default:
			failure = "upstream_invalid_response"
			if pe, ok := problem.As(err); ok && pe.Extensions["reason"] == "upstream_tenant_not_allowed" {
				failure = "upstream_tenant_not_allowed"
			}
		}
	}
	return s.CompleteUpstream(ctx, realmID, req, prov, up, failure)
}

func (s *Service) recordFederationFailure(ctx context.Context, realmID string, prov *federation.Provider, userID, reason string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		ev := audit.Event{Type: "federation.link.failed", RealmID: realmID, Actor: audit.Ref{Type: "identity_provider", ID: prov.ID},
			Outcome: audit.Failure, ReasonCode: reason, Metadata: map[string]any{"provider": prov.Alias}}
		if userID != "" {
			ev.Subject = &audit.Ref{Type: "user", ID: userID}
		}
		_, err := s.d.Audit.Record(ctx, tx, ev)
		return err
	})
}

// External applies a server-side update to a pending transaction without a
// client proof. It is used only by flows bound by their own single-use secret
// (the upstream state value); it cannot complete the transaction.
func (s *Service) External(ctx context.Context, realmID, id string, fn func(tx pgx.Tx, t *Transaction) error) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		t, err := scanTx(tx.QueryRow(ctx, `SELECT `+txCols+` FROM auth_transactions WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return problem.ErrTransactionInvalid
		}
		if t.Status != StatusPending {
			return problem.ErrTransactionInvalid
		}
		if !s.d.Now().Before(t.ExpiresAt) {
			return problem.ErrTransactionExpired
		}
		if err := fn(tx, t); err != nil {
			return err
		}
		return s.save(ctx, tx, t)
	})
}

// settlePendingLink links a pending upstream identity once the user has proven
// control of the matching local account in this transaction (FED-004). A local
// sign-in to a different account abandons the link instead of attaching the
// upstream identity anywhere else.
func (s *Service) settlePendingLink(ctx context.Context, tx pgx.Tx, t *Transaction) error {
	l := t.Pending.PendingLink
	if l == nil || s.Federation == nil || t.UserID == "" || !localPrimaryDone(t) {
		return nil
	}
	// An account waiting for its deletion is not changed: the link settles
	// once cancel_deletion has made it active again (USR-012).
	if u, err := s.Users.User(ctx, tx, t.RealmID, t.UserID); err != nil {
		return err
	} else if u.State == identity.StatePendingDeletion {
		return nil
	}
	t.Pending.PendingLink = nil
	if t.UserID != l.UserID {
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.link.abandoned", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: t.UserID},
			Subject: &audit.Ref{Type: "user", ID: t.UserID}, ReasonCode: "different_account_authenticated", Metadata: map[string]any{"provider_id": l.ProviderID}})
		return err
	}
	prov, err := s.Federation.Get(ctx, tx, t.RealmID, l.ProviderID)
	if err != nil {
		return err
	}
	if err := s.Federation.LinkTx(ctx, tx, t.RealmID, prov, l, "verified_local_login", audit.Ref{Type: "user", ID: t.UserID}); err != nil {
		return err
	}
	t.Factors = append(t.Factors, session.Factor{Type: "fed", At: s.d.Now(), Upstream: prov.ID})
	return s.notifySecurity(ctx, tx, t.RealmID, t.UserID, notification.TplMFAChanged, "a "+prov.DisplayName+" account was linked to your account")
}

// localPrimaryDone reports a local sign-in that proves control of the
// account for linking an external identity (FED-005, PWDLESS-008): a
// password, a passkey, or an emailed code or magic link that was sent for
// this link and said so (linkProofMatches). An SMS code never does: it is
// the weaker channel (PWDLESS-006) and its message cannot describe the link.
func localPrimaryDone(t *Transaction) bool {
	for _, f := range t.Factors {
		switch f.Type {
		case "pwd", "otp", "magic_link", "hwk", "swk":
			return true
		}
	}
	return false
}

// Challenge metadata binding an emailed code or magic link to a pending
// account link (PWDLESS-008).
const (
	linkMetaProvider = "link_provider"
	linkMetaUser     = "link_user"
)

// linkProof returns the template, its data and the challenge metadata for an
// emailed sign-in code or magic link. While an external identity waits to be
// linked to the account (PWDLESS-008), the message is the linking template,
// which names the connection and says that it will be linked, and the
// challenge is bound to that link; otherwise it is the ordinary sign-in
// template tpl.
func (s *Service) linkProof(ctx context.Context, q storage.Querier, t *Transaction, tpl string, data map[string]string) (string, map[string]string, map[string]any, error) {
	l := t.Pending.PendingLink
	if l == nil || s.Federation == nil {
		return tpl, data, nil, nil
	}
	prov, err := s.Federation.Get(ctx, q, t.RealmID, l.ProviderID)
	if err != nil {
		return "", nil, nil, err
	}
	name := prov.DisplayName
	if name == "" {
		name = prov.Alias
	}
	data["provider"] = name
	linkTpl := notification.TplAccountLinkCode
	if tpl == notification.TplMagicLink {
		linkTpl = notification.TplAccountLinkMagicLink
	}
	return linkTpl, data, map[string]any{linkMetaProvider: l.ProviderID, linkMetaUser: l.UserID}, nil
}

// linkProofMatches binds emailed proofs to the account-linking workflow
// (PWDLESS-008): while an external identity waits to be linked, only a code
// or link sent for that link proves control (a sign-in code or link sent
// before the link was pending does not), and a linking code or link never
// serves as a plain sign-in.
func linkProofMatches(t *Transaction, c *ConsumedChallenge) bool {
	prov, _ := c.Metadata[linkMetaProvider].(string)
	l := t.Pending.PendingLink
	if l == nil {
		return prov == ""
	}
	user, _ := c.Metadata[linkMetaUser].(string)
	return prov == l.ProviderID && user == l.UserID && c.IdentifierType == "email"
}

func canonicalEmail(e string) (string, string, bool) {
	c, d, err := canonical.Email(e)
	return c, d, err == nil
}
