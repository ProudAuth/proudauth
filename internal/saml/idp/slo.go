package idp

import (
	"context"
	"encoding/base64"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/saml"
)

var (
	errLogoutUnsupported = problem.ErrBadRequest.WithDetail("this service provider has no registered single logout endpoint").
				WithExtension("reason", "saml_logout_unsupported")
	errLogoutResponse = problem.ErrBadRequest.WithDetail("logout responses are not expected: this identity provider does not send logout requests").
				WithExtension("reason", "saml_logout_response_unexpected")
)

// Logout handles a service provider's LogoutRequest (SAML-008). The
// supported subset, declared in metadata and documentation:
//
//   - SP-initiated logout over HTTP-Redirect or HTTP-POST; the request must
//     be signed with a registered key of that service provider and name
//     its own session (SessionIndex issued to it) and subject;
//   - the identified IdP session ends, with everything derived from it
//     (grants, refresh tokens; OIDC clients with back-channel logout are
//     notified as for any session revocation);
//   - the response goes to the service provider's registered logout
//     endpoint. Other SAML service providers in the same session are not
//     sent logout requests: the response then carries the second-level
//     status PartialLogout instead of claiming a complete logout.
//
// IdP-initiated logout (this realm sending LogoutRequests) is not
// implemented, so LogoutResponses are refused.
func (s *Service) Logout(ctx context.Context, rlm *realm.Realm, m Message, sessionCookie string) (*Delivery, error) {
	root, relay, sig, err := s.decode(m, "SAMLRequest")
	if err != nil {
		if m.Binding == saml.BindingRedirect {
			if _, _, _, rerr := saml.ParseRedirect(m.RawQuery, "SAMLResponse"); rerr == nil {
				return nil, errLogoutResponse
			}
		}
		s.reject(ctx, rlm, nil, "logout_decode:"+reasonOf(err))
		return nil, errBadRequest
	}
	if saml.Is(root, saml.NSProtocol, "LogoutResponse") {
		return nil, errLogoutResponse
	}
	if !saml.Is(root, saml.NSProtocol, "LogoutRequest") {
		s.reject(ctx, rlm, nil, "not_a_logout_request")
		return nil, errBadRequest
	}
	app, err := s.ByEntityID(ctx, nil, rlm, issuerOf(root))
	if err != nil {
		s.reject(ctx, rlm, nil, "logout_unknown_service_provider")
		return nil, errUnknownSP
	}
	if len(app.SLO) == 0 {
		return nil, errLogoutUnsupported
	}
	// Logout requests are always signed: an unsigned one could end anyone's
	// session (the validation of RequireSignedRequests does not apply here).
	certs := app.certificates()
	now := s.d.Now()
	var req = root
	switch {
	case len(certs) == 0:
		return nil, errLogoutUnsupported
	case sig != nil:
		if err := sig.Verify(certs, now); err != nil {
			s.reject(ctx, rlm, app, "logout_signature:"+reasonOf(err))
			return nil, errBadSignature
		}
	case saml.Signed(root):
		v, err := saml.Verify(root, certs, now)
		if err != nil {
			s.reject(ctx, rlm, app, "logout_signature:"+reasonOf(err))
			return nil, errBadSignature
		}
		req = v
	default:
		s.reject(ctx, rlm, app, "logout_unsigned")
		return nil, errBadSignature
	}
	id := saml.Attr(req, "ID")
	if saml.Attr(req, "Version") != "2.0" || !saml.ValidID(id) || issuerOf(req) != app.EntityID || !inWindow(saml.Attr(req, "IssueInstant"), now, app.skew()) {
		s.reject(ctx, rlm, app, "logout_malformed")
		return nil, errBadRequest
	}
	if dest := saml.Attr(req, "Destination"); dest != "" && dest != s.IdPEndpoints(rlm).SLOURL {
		s.reject(ctx, rlm, app, "logout_destination")
		return nil, errBadRequest
	}
	if v := saml.Attr(req, "NotOnOrAfter"); v != "" {
		t, err := saml.ParseTime(v)
		if err != nil || !now.Before(t.Add(app.skew())) {
			s.reject(ctx, rlm, app, "logout_expired")
			return nil, errBadRequest
		}
	}
	nid, err := saml.RequiredChild(req, saml.NSAssertion, "NameID")
	if err != nil {
		s.reject(ctx, rlm, app, "logout_name_id")
		return nil, errBadRequest
	}
	nameID, err := saml.Text(nid)
	if err != nil || nameID == "" {
		s.reject(ctx, rlm, app, "logout_name_id")
		return nil, errBadRequest
	}
	format := saml.Attr(nid, "Format")
	if format == "" {
		format = app.NameIDFormat
	}
	var indexes []string
	for _, si := range saml.Children(req, saml.NSProtocol, "SessionIndex") {
		v, err := saml.Text(si)
		if err != nil || v == "" {
			s.reject(ctx, rlm, app, "logout_session_index")
			return nil, errBadRequest
		}
		indexes = append(indexes, v)
	}
	// The browser's own session, if it sent its cookie: its cookie is
	// cleared when that session is among those that end.
	browserSession := ""
	if sessionCookie != "" {
		if sess, err := s.Sessions.ByCookie(ctx, rlm.ID, sessionCookie); err == nil {
			browserSession = sess.ID
		}
	}
	ended, partial := 0, false
	clear := false
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// Sessions of this service provider for this subject: the listed
		// session indexes, or every one for the subject when none is listed
		// (core §3.7.1).
		rows, err := tx.Query(ctx, `SELECT session_id FROM saml_idp_sessions WHERE app_id=$1 AND name_id_digest=$2 AND ended_at IS NULL
			AND (cardinality($3::text[]) = 0 OR session_index = ANY($3)) FOR UPDATE`, app.ID, nameIDDigest(format, nameID), nonNil(indexes))
		if err != nil {
			return err
		}
		var sessions []string
		for rows.Next() {
			var sid string
			if err := rows.Scan(&sid); err != nil {
				rows.Close()
				return err
			}
			sessions = append(sessions, sid)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, sid := range sessions {
			// Other participants that are not told: SAML service providers
			// (no IdP-initiated logout) and clients without back-channel logout.
			var others int
			if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM saml_idp_sessions WHERE session_id=$1 AND app_id<>$2 AND ended_at IS NULL)
				+ (SELECT count(*) FROM client_sessions cs JOIN clients c ON c.id=cs.client_ref WHERE cs.session_id=$1 AND cs.state='active'
				   AND c.protocol <> 'saml' AND c.backchannel_logout_uri IS NULL)`, sid, app.ID).Scan(&others); err != nil {
				return err
			}
			if others > 0 {
				partial = true
			}
			if err := s.Sessions.RevokeTx(ctx, tx, rlm.ID, sid, "saml_logout"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE saml_idp_sessions SET ended_at=$2 WHERE session_id=$1 AND ended_at IS NULL`, sid, s.d.Now()); err != nil {
				return err
			}
			if sid == browserSession {
				clear = true
			}
			ended++
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.logout.completed", RealmID: rlm.ID, OrgID: app.OrganizationID,
			Actor: audit.Ref{Type: "saml_application", ID: app.ID}, Target: &audit.Ref{Type: "saml_application", ID: app.ID}, ClientID: app.ClientID,
			Category: "security", Metadata: map[string]any{"entity_id": app.EntityID, "sessions_ended": ended, "partial": partial,
				"binding": m.Binding}})
		return err
	})
	if err != nil {
		return nil, err
	}
	sub := ""
	if partial {
		sub = saml.StatusPartialLogout
	}
	d, err := s.logoutResponse(ctx, rlm, app, id, relay, sub)
	if err != nil {
		return nil, err
	}
	d.ClearSession = clear
	return d, nil
}

// logoutResponse answers at the service provider's registered logout
// endpoint, signed, in that endpoint's binding.
func (s *Service) logoutResponse(ctx context.Context, rlm *realm.Realm, app *App, inResponseTo, relay, subStatus string) (*Delivery, error) {
	ep := app.SLO[0]
	dest := ep.URL
	if ep.ResponseURL != "" {
		dest = ep.ResponseURL
	}
	key, err := s.Keys.Active(ctx, rlm.ID)
	if err != nil {
		return nil, err
	}
	r := saml.NewElement("samlp", "LogoutResponse")
	r.CreateAttr("xmlns:samlp", saml.NSProtocol)
	r.CreateAttr("xmlns:saml", saml.NSAssertion)
	r.CreateAttr("ID", saml.NewID())
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", saml.Time(s.d.Now()))
	r.CreateAttr("Destination", dest)
	r.CreateAttr("InResponseTo", inResponseTo)
	saml.AddChild(r, "saml", "Issuer").SetText(s.IdPEndpoints(rlm).EntityID)
	st := saml.AddChild(r, "samlp", "Status")
	code := saml.AddChild(st, "samlp", "StatusCode")
	code.CreateAttr("Value", saml.StatusSuccess)
	if subStatus != "" {
		saml.AddChild(code, "samlp", "StatusCode").CreateAttr("Value", subStatus)
	}
	if ep.Binding == saml.BindingRedirect {
		raw, err := saml.Serialize(r)
		if err != nil {
			return nil, err
		}
		enc, err := saml.EncodeRedirect(raw)
		if err != nil {
			return nil, err
		}
		q, err := saml.SignRedirect("SAMLResponse", enc, relay, key.Signer, app.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}
		sep := "?"
		for _, c := range dest {
			if c == '?' {
				sep = "&"
			}
		}
		return &Delivery{RedirectURL: dest + sep + q}, nil
	}
	if err := saml.Sign(r, key.Signer, key.CertDER, app.SignatureAlgorithm); err != nil {
		return nil, err
	}
	raw, err := saml.Serialize(r)
	if err != nil {
		return nil, err
	}
	return &Delivery{Form: &saml.PostForm{Action: dest, Param: "SAMLResponse", Value: base64.StdEncoding.EncodeToString(raw), RelayState: relay}}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
