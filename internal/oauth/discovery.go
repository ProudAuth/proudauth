package oauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/token"
)

// DPoPSigningAlgorithms are the DPoP proof algorithms the server verifies
// (the asymmetric algorithms of application.AsymmetricAlgorithms): discovery
// advertises them as dpop_signing_alg_values_supported and a DPoP challenge
// names them in algs (RFC 9449 §5.1, §7.1).
var DPoPSigningAlgorithms = []string{"RS256", "PS256", "ES256", "EdDSA"}

// Features enabled for discovery. Only implemented and enabled capabilities are
// advertised (APP-020, OIDC-015).
type Features struct {
	DeviceFlow        bool
	TokenExchange     bool
	PAR               bool
	DPoP              bool
	Logout            bool
	BackchannelLogout bool
	Registration      bool
	// MTLS: client certificates reach the server (mutual-TLS listener or a
	// trusted proxy header), so RFC 8705 is offered (TOK-019, MCH-014).
	MTLS bool
	// MTLSOrigin is the public origin of the mutual-TLS listener.
	MTLSOrigin string
}

// Discovery builds OpenID Provider / OAuth AS metadata for one issuer.
func (s *Service) Discovery(ctx context.Context, rlm *realm.Realm, f Features) (map[string]any, error) {
	iss := rlm.Issuer
	keys, err := s.KeyMgr.Published(ctx, rlm.ID)
	if err != nil {
		return nil, err
	}
	algs := []string{}
	for _, k := range keys {
		if !slices.Contains(algs, k.Algorithm) {
			algs = append(algs, k.Algorithm)
		}
	}
	grants := []string{"authorization_code", "refresh_token", "client_credentials"}
	if f.DeviceFlow {
		grants = append(grants, application.GrantDeviceCode)
	}
	if f.TokenExchange {
		grants = append(grants, application.GrantTokenExchange)
	}
	if s.Workload != nil {
		// Workload federation (MCH-011): assertions from issuers a client
		// explicitly trusts.
		grants = append(grants, application.GrantJWTBearer)
	}
	// Grant types the realm switched off are not advertised (OIDC-015, SEC-020).
	grants = slices.DeleteFunc(grants, rlm.GrantDisabled)
	scopes := []string{"openid", "profile", "email", "phone", "address", "offline_access"}
	m := map[string]any{
		"issuer":                                           iss,
		"authorization_endpoint":                           iss + "/oauth/authorize",
		"token_endpoint":                                   iss + "/oauth/token",
		"jwks_uri":                                         iss + "/jwks",
		"userinfo_endpoint":                                iss + "/oidc/userinfo",
		"introspection_endpoint":                           iss + "/oauth/introspect",
		"revocation_endpoint":                              iss + "/oauth/revoke",
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query", "query.jwt", "jwt"},
		"authorization_signing_alg_values_supported":       algs,
		"authorization_encryption_alg_values_supported":    application.ResponseEncryptionAlgs,
		"authorization_encryption_enc_values_supported":    application.ResponseEncryptionEncs,
		"grant_types_supported":                            grants,
		"subject_types_supported":                          []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported":            algs,
		"userinfo_signing_alg_values_supported":            append([]string{"none"}, algs...),
		"id_token_encryption_alg_values_supported":         application.ResponseEncryptionAlgs,
		"id_token_encryption_enc_values_supported":         application.ResponseEncryptionEncs,
		"userinfo_encryption_alg_values_supported":         application.ResponseEncryptionAlgs,
		"userinfo_encryption_enc_values_supported":         application.ResponseEncryptionEncs,
		"token_endpoint_auth_methods_supported":            []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "PS256", "ES256", "EdDSA"},
		"introspection_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
		"revocation_endpoint_auth_methods_supported":       []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"code_challenge_methods_supported":                 []string{"S256"},
		"scopes_supported":                                 scopes,
		"claims_supported":                                 []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid", "name", "given_name", "family_name", "preferred_username", "locale", "zoneinfo", "updated_at", "email", "email_verified", "phone_number", "phone_number_verified", "address", "org_id"},
		"claims_parameter_supported":                       true,
		"request_parameter_supported":                      false,
		"request_uri_parameter_supported":                  f.PAR,
		"require_request_uri_registration":                 false,
		"prompt_values_supported":                          []string{"none", "login", "consent", "select_account", "create"},
		"acr_values_supported":                             []string{"urn:proudauth:acr:single_factor", "urn:proudauth:acr:federated", "urn:proudauth:acr:recovery", "urn:proudauth:acr:mfa", "urn:proudauth:acr:phishing_resistant"},
		"authorization_response_iss_parameter_supported":   true,
		"tls_client_certificate_bound_access_tokens":       false,
		"frontchannel_logout_supported":                    false,
	}
	if f.Logout {
		m["end_session_endpoint"] = iss + "/oidc/logout"
		// Front-channel logout (SES-018) is offered with the logout endpoint;
		// it depends on the browser and is never the only mechanism.
		m["frontchannel_logout_supported"] = true
		m["frontchannel_logout_session_supported"] = true
	}
	if f.Logout && rlm.Policy.Sessions.CheckSessionIframe {
		// OpenID Connect Session Management 1.0 (OIDC-014), opt-in per realm.
		m["check_session_iframe"] = iss + "/oidc/check-session"
	}
	if f.BackchannelLogout {
		m["backchannel_logout_supported"] = true
		m["backchannel_logout_session_supported"] = true
	}
	if f.DeviceFlow {
		m["device_authorization_endpoint"] = iss + "/oauth/device_authorization"
	}
	if f.PAR {
		m["pushed_authorization_request_endpoint"] = iss + "/oauth/par"
		m["require_pushed_authorization_requests"] = false
	}
	if f.DPoP {
		m["dpop_signing_alg_values_supported"] = slices.Clone(DPoPSigningAlgorithms)
	}
	if f.Registration {
		m["registration_endpoint"] = iss + "/oauth/register"
	}
	if f.MTLS {
		m["tls_client_certificate_bound_access_tokens"] = true
		for _, k := range []string{"token_endpoint_auth_methods_supported", "introspection_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"} {
			m[k] = append(slices.Clone(m[k].([]string)), "tls_client_auth", "self_signed_tls_client_auth")
		}
		if f.MTLSOrigin != "" {
			base := strings.TrimSuffix(f.MTLSOrigin, "/") + "/realms/" + rlm.Name
			aliases := map[string]string{"token_endpoint": base + "/oauth/token", "introspection_endpoint": base + "/oauth/introspect",
				"revocation_endpoint": base + "/oauth/revoke", "userinfo_endpoint": base + "/oidc/userinfo"}
			if f.PAR {
				aliases["pushed_authorization_request_endpoint"] = base + "/oauth/par"
			}
			if f.DeviceFlow {
				aliases["device_authorization_endpoint"] = base + "/oauth/device_authorization"
			}
			m["mtls_endpoint_aliases"] = aliases
		}
	}
	return m, nil
}

// UserInfo returns claims for an access token issued for the UserInfo audience
// with the openid scope (OIDC-006). Business-audience tokens are rejected even when
// they carry "openid" text.
func (s *Service) UserInfo(ctx context.Context, rlm *realm.Realm, raw string) (map[string]any, error) {
	out, _, _, err := s.userInfo(ctx, rlm, raw)
	return out, err
}

func (s *Service) userInfo(ctx context.Context, rlm *realm.Realm, raw string) (map[string]any, *application.Client, *token.Confirmation, error) {
	ui, err := s.Apps.ResourceByKind(ctx, nil, rlm.ID, application.KindUserInfo)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := s.Verifier.VerifyAccess(ctx, rlm.ID, rlm.Issuer, ui.Audience, raw)
	if err != nil || !c.HasScope("openid") || c.TokenKind != token.KindUserAccess {
		return nil, nil, nil, problem.ErrUnauthenticated
	}
	if revoked, _ := s.Sessions.JTIRevoked(ctx, nil, rlm.ID, c.JTI); revoked {
		return nil, nil, nil, problem.ErrUnauthenticated
	}
	if c.SessionID != "" {
		if _, err := s.Sessions.Active(ctx, nil, rlm.ID, c.SessionID); err != nil {
			return nil, nil, nil, problem.ErrUnauthenticated
		}
	} else if revoked, err := s.Sessions.UserTokenRevoked(ctx, nil, rlm.ID, c.Subject, time.Unix(c.IssuedAt, 0)); err != nil || revoked {
		// An offline grant's token issued before "log out everywhere" (SES-005).
		return nil, nil, nil, problem.ErrUnauthenticated
	}
	u, err := s.Users.User(ctx, nil, rlm.ID, c.Subject)
	if err != nil || !u.CanAuthenticate(s.d.Now()) {
		return nil, nil, nil, problem.ErrUnauthenticated
	}
	client, err := s.Apps.ClientByClientID(ctx, nil, rlm.ID, c.ClientID)
	if err != nil || !client.Active() {
		return nil, nil, nil, problem.ErrUnauthenticated
	}
	if !s.Sessions.AccessGrantActive(ctx, nil, rlm.ID, c.GrantID, c.Subject, client.Ref) {
		return nil, nil, nil, problem.ErrUnauthenticated
	}
	out := UserClaims(u, c.Scopes())
	// The "userinfo" member of the authorization's claims request narrows
	// UserInfo release (OIDC-008); the grant is found through the session.
	if c.SessionID != "" {
		var claimsReq string
		_ = s.d.DB.Pool.QueryRow(ctx, `SELECT coalesce(claims_request,'') FROM authorization_grants WHERE session_id=$1 AND client_ref=$2
			AND state='active' ORDER BY created_at DESC LIMIT 1`, c.SessionID, client.Ref).Scan(&claimsReq)
		out = releaseFor(out, claimsReq, "userinfo")
	}
	sub, err := s.SubjectFor(ctx, client, u.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	out["sub"] = sub
	return out, client, c.Cnf, nil
}

// UserInfoResponse renders UserInfo claims for the client that holds the
// access token (OIDC-013): plain JSON by default; a signed JWT carrying iss
// and aud when the client registered userinfo_signed_response_alg; and
// encrypted to the client (nested when also signed) when it registered
// userinfo_encrypted_response_alg. It returns the body and its media type.
func (s *Service) UserInfoResponse(ctx context.Context, rlm *realm.Realm, raw string) ([]byte, string, *token.Confirmation, error) {
	claims, client, cnf, err := s.userInfo(ctx, rlm, raw)
	if err != nil {
		return nil, "", nil, err
	}
	body, ctype, err := s.renderUserInfo(ctx, rlm, claims, client)
	return body, ctype, cnf, err
}

func (s *Service) renderUserInfo(ctx context.Context, rlm *realm.Realm, claims map[string]any, client *application.Client) ([]byte, string, error) {
	if client.UserinfoSignedResponseAlg == "" && client.UserinfoEncryptedResponseAlg == "" {
		b, err := json.Marshal(claims)
		return b, "application/json", err
	}
	var payload []byte
	var err error
	cty := ""
	if client.UserinfoSignedResponseAlg != "" {
		claims["iss"], claims["aud"] = rlm.Issuer, client.ClientID
		signed, err := s.Signer.Sign(ctx, rlm.ID, "JWT", claims)
		if err != nil {
			return nil, "", err
		}
		payload, cty = []byte(signed), "JWT"
	} else if payload, err = json.Marshal(claims); err != nil {
		return nil, "", err
	}
	if client.UserinfoEncryptedResponseAlg == "" {
		return payload, "application/jwt", nil
	}
	enc, err := s.encryptTo(ctx, client, payload, client.UserinfoEncryptedResponseAlg, client.UserinfoEncryptedResponseEnc, cty)
	if err != nil {
		return nil, "", err
	}
	return []byte(enc), "application/jwt", nil
}

// LogoutRequest is an RP-initiated logout (SES-016).
type LogoutRequest struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	SessionCookie         string
	// UpstreamLogout asks to also end the federated provider's session
	// (FED-013, extension parameter upstream_logout=true).
	UpstreamLogout bool
}

// UpstreamLogoutStatus reports what happened to a federated provider's
// session (FED-013). Statuses: not_federated (the session did not use a
// provider), not_requested (only the local session ended; the provider's
// session may remain), redirect (the browser is sent to the provider's
// logout endpoint), unsupported (the provider offers no logout endpoint),
// unavailable (the endpoint could not be resolved). A provider's own logout
// is never confirmed: a return from it is reported as returned, not done.
type UpstreamLogoutStatus struct {
	Provider string `json:"provider,omitempty"`
	Status   string `json:"status"`
}

// LogoutResult says where to send the browser.
type LogoutResult struct {
	Redirect     string
	SessionEnded bool
	ClearCookie  bool
	Upstream     *UpstreamLogoutStatus
	// FrontChannel lists the front-channel logout URIs (SES-018) of the
	// clients that took part in the ended session, for the browser to load
	// in iframes before it continues to Redirect.
	FrontChannel []string
}

// Logout ends the IdP session identified by the session cookie and/or a valid ID
// token hint and returns only a registered post-logout destination. Clearing the
// cookie is paired with server-side revocation (SES-004).
func (s *Service) Logout(ctx context.Context, rlm *realm.Realm, req LogoutRequest) (*LogoutResult, error) {
	var hint *token.IDClaims
	if req.IDTokenHint != "" {
		h, err := s.Verifier.VerifyIDTokenHint(ctx, rlm.ID, rlm.Issuer, req.IDTokenHint)
		if err != nil {
			return nil, problem.ErrBadRequest.WithDetail("invalid id_token_hint")
		}
		hint = h
	}
	clientID := req.ClientID
	if hint != nil {
		if clientID != "" && len(hint.Audience) > 0 && hint.Audience[0] != clientID {
			return nil, problem.ErrBadRequest.WithDetail("client_id does not match id_token_hint")
		}
		if clientID == "" && len(hint.Audience) > 0 {
			clientID = hint.Audience[0]
		}
	}
	res := &LogoutResult{ClearCookie: true}
	var target *session.Session
	if req.SessionCookie != "" {
		if sess, err := s.Sessions.ByCookie(ctx, rlm.ID, req.SessionCookie); err == nil {
			target = sess
		}
	}
	if target == nil && hint != nil && hint.SessionID != "" {
		// Without a cookie, a hint alone may end only the session it names.
		if sess, err := s.Sessions.Active(ctx, nil, rlm.ID, hint.SessionID); err == nil {
			target = sess
		}
	}
	if target != nil {
		if hint != nil && hint.SessionID != "" && hint.SessionID != target.ID && req.SessionCookie != "" {
			// The hint refers to a different session than the browser's: do not end
			// the browser session on the strength of a foreign hint.
			target = nil
		}
	}
	// Local and upstream logout are separate (FED-013): the local session ends
	// here; the provider's session ends only through its own logout endpoint.
	var upstream *federation.Provider
	if target != nil && s.Auth != nil && s.Auth.Federation != nil {
		for _, f := range target.Factors {
			if f.Type == "fed" && f.Upstream != "" {
				if p, err := s.Auth.Federation.Get(ctx, nil, rlm.ID, f.Upstream); err == nil {
					upstream = p
				}
			}
		}
	}
	switch {
	case upstream == nil:
		res.Upstream = &UpstreamLogoutStatus{Status: "not_federated"}
	case !req.UpstreamLogout:
		res.Upstream = &UpstreamLogoutStatus{Provider: upstream.Alias, Status: "not_requested"}
	default:
		res.Upstream = &UpstreamLogoutStatus{Provider: upstream.Alias}
	}
	// A bad redirect is refused before anything changes: the request either
	// completes as asked or leaves the session as it was.
	if req.PostLogoutRedirectURI != "" {
		if clientID == "" {
			return nil, problem.ErrBadRequest.WithDetail("post_logout_redirect_uri requires client_id or id_token_hint")
		}
		c, err := s.Apps.ClientByClientID(ctx, nil, rlm.ID, clientID)
		if err != nil || !slices.Contains(c.PostLogoutRedirects, req.PostLogoutRedirectURI) {
			return nil, problem.ErrBadRequest.WithDetail("post_logout_redirect_uri is not registered")
		}
	}
	if target != nil {
		tx, err := s.d.DB.Pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		fc, err := s.frontChannelURIs(ctx, tx, rlm, target.ID)
		if err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
		res.FrontChannel = fc
		if err := s.Sessions.RevokeTx(ctx, tx, rlm.ID, target.ID, "rp_logout"); err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
		meta := map[string]any{"client_id": clientID}
		if upstream != nil {
			meta["upstream_provider"], meta["upstream_logout_requested"] = upstream.Alias, req.UpstreamLogout
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "session.logout", RealmID: rlm.ID, Actor: audit.Ref{Type: "user", ID: target.UserID, SessionID: target.ID},
			Subject: &audit.Ref{Type: "user", ID: target.UserID}, SessionID: target.ID, Metadata: meta}); err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		res.SessionEnded = true
	}
	if req.PostLogoutRedirectURI != "" {
		if clientID == "" {
			return nil, problem.ErrBadRequest.WithDetail("post_logout_redirect_uri requires client_id or id_token_hint")
		}
		c, err := s.Apps.ClientByClientID(ctx, nil, rlm.ID, clientID)
		if err != nil || !slices.Contains(c.PostLogoutRedirects, req.PostLogoutRedirectURI) {
			return nil, problem.ErrBadRequest.WithDetail("post_logout_redirect_uri is not registered")
		}
		u := req.PostLogoutRedirectURI
		if req.State != "" {
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			u += sep + "state=" + urlEscape(req.State)
		}
		res.Redirect = u
	}
	if upstream != nil && req.UpstreamLogout {
		// The browser visits the provider's logout endpoint, which returns to
		// this realm with a sealed state naming the final destination.
		state, err := s.sealLogoutState(rlm.ID, res.Redirect)
		if err != nil {
			return nil, err
		}
		u, err := s.Auth.Federation.UpstreamLogoutURL(ctx, upstream, rlm.Issuer+"/oidc/logout/upstream-return", state)
		switch {
		case err == nil:
			res.Upstream.Status, res.Redirect = "redirect", u
		case errors.Is(err, federation.ErrNoUpstreamLogout):
			res.Upstream.Status = "unsupported"
		default:
			res.Upstream.Status = "unavailable"
		}
		if res.Upstream.Status != "redirect" && res.Redirect != "" {
			res.Redirect = appendParam(res.Redirect, "upstream_logout", res.Upstream.Status)
		}
	}
	return res, nil
}

// frontChannelURIs returns the front-channel logout URIs of the active
// clients that took part in a session (SES-018), with iss and sid when the
// client asked for them.
func (s *Service) frontChannelURIs(ctx context.Context, q pgx.Tx, rlm *realm.Realm, sessionID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT c.protocol_options->>'frontchannel_logout_uri', coalesce((c.protocol_options->>'frontchannel_logout_session_required')::boolean, false)
		FROM client_sessions cs JOIN clients c ON c.id=cs.client_ref
		WHERE cs.session_id=$1 AND cs.state='active' AND c.state='active' AND coalesce(c.protocol_options->>'frontchannel_logout_uri','') <> ''
		ORDER BY c.client_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uri string
		var withSession bool
		if err := rows.Scan(&uri, &withSession); err != nil {
			return nil, err
		}
		if withSession {
			uri = appendParam(appendParam(uri, "iss", rlm.Issuer), "sid", sessionID)
		}
		out = append(out, uri)
	}
	return out, rows.Err()
}

// UpstreamLogoutReturn resolves the provider's return to this realm after an
// upstream logout: the final destination from the sealed state, marked
// upstream_logout=returned. The provider's return does not prove its session
// ended, so it is never reported as done.
func (s *Service) UpstreamLogoutReturn(ctx context.Context, rlm *realm.Realm, state string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(raw) > 4096 {
		return "", problem.ErrBadRequest.WithDetail("invalid state")
	}
	pt, err := s.d.Keys.Decrypt(keys.PurposeData, raw, []byte("upstream-logout:"+rlm.ID))
	if err != nil {
		return "", problem.ErrBadRequest.WithDetail("invalid state")
	}
	var st struct {
		Redirect string `json:"r"`
		Expires  int64  `json:"e"`
		Nonce    string `json:"n"`
	}
	if json.Unmarshal(pt, &st) != nil || s.d.Now().Unix() > st.Expires || st.Nonce == "" {
		return "", problem.ErrBadRequest.WithDetail("expired state")
	}
	// Single use: a replayed return is refused (the replay table also backs
	// DPoP proof replay detection).
	tag, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO dpop_proof_jtis (realm_id, jkt, jti, expires_at) VALUES ($1, 'upstream-logout', $2, $3)
		ON CONFLICT DO NOTHING`, rlm.ID, st.Nonce, time.Unix(st.Expires, 0).Add(time.Minute))
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", problem.ErrBadRequest.WithDetail("state already used")
	}
	if st.Redirect == "" {
		return "", nil
	}
	return appendParam(st.Redirect, "upstream_logout", "returned"), nil
}

func (s *Service) sealLogoutState(realmID, redirect string) (string, error) {
	b, _ := json.Marshal(map[string]any{"r": redirect, "e": s.d.Now().Add(15 * time.Minute).Unix(), "n": hex.EncodeToString(secret.Random(12))})
	ct, _, err := s.d.Keys.Encrypt(keys.PurposeData, b, []byte("upstream-logout:"+realmID))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func appendParam(u, k, v string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + k + "=" + urlEscape(v)
}

func urlEscape(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "=", "%3D", "#", "%23", "+", "%2B", " ", "%20", "?", "%3F")
	return r.Replace(s)
}
