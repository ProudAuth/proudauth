package oauth

import (
	"context"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/authentication"
	"github.com/proudbase/proudauth/internal/realm"
)

// JARM (ADV-002): with response_mode=jwt or query.jwt the authorization
// response is one JWT in the "response" query parameter, signed with the
// realm key and, when the client registered authorization response
// encryption, encrypted to it (nested). The JWT carries iss, aud (the
// client_id), exp and the response parameters, so the client checks the
// issuer and that the response was meant for it. fragment.jwt and
// form_post.jwt are not offered.
const jarmTTL = 600 // seconds; the response is consumed at once

// IsJARM reports a JWT response mode ("jwt" means query.jwt for the code
// flow).
func IsJARM(mode string) bool { return mode == "jwt" || mode == "query.jwt" }

// ValidResponseMode reports a response mode this server offers.
func ValidResponseMode(mode string) bool { return mode == "" || mode == "query" || IsJARM(mode) }

// AuthorizationResponse returns the redirect carrying an authorization
// response (code or error) in the requested mode.
func (s *Service) AuthorizationResponse(ctx context.Context, rlm *realm.Realm, c *application.Client, mode, redirectURI string, params map[string]string) (string, error) {
	if !IsJARM(mode) || c == nil {
		return authentication.BuildRedirect(redirectURI, params), nil
	}
	claims := map[string]any{"iss": rlm.Issuer, "aud": c.ClientID, "exp": s.d.Now().Unix() + jarmTTL}
	for k, v := range params {
		if v != "" && k != "iss" {
			claims[k] = v
		}
	}
	tok, err := s.Signer.Sign(ctx, rlm.ID, "JWT", claims)
	if err != nil {
		return "", err
	}
	if c.AuthorizationEncryptedResponseAlg != "" {
		if tok, err = s.encryptTo(ctx, c, []byte(tok), c.AuthorizationEncryptedResponseAlg, c.AuthorizationEncryptedResponseEnc, "JWT"); err != nil {
			return "", err
		}
	}
	return authentication.BuildRedirect(redirectURI, map[string]string{"response": tok}), nil
}

// respond builds an authorization response at the authorize endpoint; when
// a JWT response cannot be produced the plain error is returned instead, so
// the client is never left without an answer.
func (s *Service) respond(ctx context.Context, rlm *realm.Realm, req AuthorizeRequest, c *application.Client, params map[string]string) string {
	if c == nil && IsJARM(req.ResponseMode) {
		c, _ = s.Apps.ClientByClientID(ctx, nil, rlm.ID, req.ClientID)
	}
	u, err := s.AuthorizationResponse(ctx, rlm, c, req.ResponseMode, req.RedirectURI, params)
	if err != nil {
		return authentication.BuildRedirect(req.RedirectURI, map[string]string{"error": "server_error", "state": req.State, "iss": rlm.Issuer})
	}
	return u
}
