package application

import (
	"net/url"
	"slices"
	"strings"

	"github.com/proudbase/proudauth/internal/platform/problem"
)

// ProtocolOptions are optional per-client protocol settings, stored together
// (migration 0050) and shown flat in the client representation, under their
// registration metadata names.
type ProtocolOptions struct {
	// FrontchannelLogoutURI is rendered in an iframe when a browser session
	// the client takes part in ends at the logout endpoint (OIDC Front-Channel
	// Logout 1.0, SES-018). Delivery depends on the browser: third-party
	// cookie restrictions often keep the client from seeing its own session
	// in the frame, so it is never treated as guaranteed; back-channel logout
	// is the reliable mechanism.
	FrontchannelLogoutURI string `json:"frontchannel_logout_uri,omitempty"`
	// FrontchannelLogoutSessionRequired adds iss and sid to the URI.
	FrontchannelLogoutSessionRequired bool `json:"frontchannel_logout_session_required,omitempty"`

	// ID tokens encrypted to one of the client's registered public keys
	// (TOK-020): a nested JWT, signed first. Encryption protects claims from
	// intermediaries that see the token; it is not a substitute for
	// validating the signature, issuer, audience and nonce.
	IDTokenEncryptedResponseAlg string `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc string `json:"id_token_encrypted_response_enc,omitempty"`
	// UserInfo returned as a signed JWT (with iss and aud) instead of JSON,
	// and optionally encrypted (OIDC-013).
	UserinfoSignedResponseAlg    string `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`
	// JWT-secured authorization responses (JARM, ADV-002), used when a
	// request asks for response_mode=jwt or query.jwt. The response is always
	// signed with the realm key; authorization_signed_response_alg, when
	// given, must be the realm's algorithm.
	AuthorizationSignedResponseAlg    string `json:"authorization_signed_response_alg,omitempty"`
	AuthorizationEncryptedResponseAlg string `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string `json:"authorization_encrypted_response_enc,omitempty"`
	// Mutual-TLS client authentication (RFC 8705, MCH-014). With
	// tls_client_auth the certificate must chain to a realm client trust
	// anchor and carry exactly the one registered identity below; with
	// self_signed_tls_client_auth it must be one registered in the client's
	// key set (x5c or x5t#S256).
	TLSClientAuthSubjectDN string `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS    string `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANURI    string `json:"tls_client_auth_san_uri,omitempty"`
	TLSClientAuthSANIP     string `json:"tls_client_auth_san_ip,omitempty"`
	TLSClientAuthSANEmail  string `json:"tls_client_auth_san_email,omitempty"`
	// TLSClientCertificateBoundAccessTokens binds every access token of the
	// client to its TLS certificate (cnf x5t#S256, TOK-019): requests without
	// a certificate are refused rather than given a bearer token.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	// Display metadata shown to users at consent (registration metadata,
	// APP-016). These URLs are stored as given and never fetched.
	ClientURI string `json:"client_uri,omitempty"`
	LogoURI   string `json:"logo_uri,omitempty"`
	PolicyURI string `json:"policy_uri,omitempty"`
	TOSURI    string `json:"tos_uri,omitempty"`
}

// Response encryption profiles (TOK-020, OIDC-013): RSA-OAEP-256 or ECDH-ES
// key agreement with AES-GCM content encryption. RSA1_5, RSA-OAEP with SHA-1
// and CBC content encryption are not offered.
var (
	ResponseEncryptionAlgs = []string{"RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"}
	ResponseEncryptionEncs = []string{"A128GCM", "A256GCM"}
	ResponseSigningAlgs    = []string{"RS256", "PS256", "ES256", "EdDSA"}
)

// Encrypted reports whether any response is encrypted to the client.
func (o ProtocolOptions) Encrypted() bool {
	return o.IDTokenEncryptedResponseAlg != "" || o.UserinfoEncryptedResponseAlg != "" || o.AuthorizationEncryptedResponseAlg != ""
}

func (o *ProtocolOptions) validate(in *ClientInput) *problem.Error {
	verr := problem.ErrValidation
	ids := 0
	for _, v := range []string{o.TLSClientAuthSubjectDN, o.TLSClientAuthSANDNS, o.TLSClientAuthSANURI, o.TLSClientAuthSANIP, o.TLSClientAuthSANEmail} {
		if v != "" {
			ids++
		}
		if len(v) > 1024 {
			return verr.WithField("tls_client_auth_subject_dn", "at most 1024 characters")
		}
	}
	switch {
	case in.AuthMethod == "tls_client_auth" && ids != 1:
		return verr.WithField("tls_client_auth_subject_dn", "tls_client_auth needs exactly one of tls_client_auth_subject_dn, _san_dns, _san_uri, _san_ip, _san_email")
	case in.AuthMethod != "tls_client_auth" && ids > 0:
		return verr.WithField("tls_client_auth_subject_dn", "only with token_endpoint_auth_method tls_client_auth")
	}
	for field, raw := range map[string]string{"client_uri": o.ClientURI, "logo_uri": o.LogoURI, "policy_uri": o.PolicyURI, "tos_uri": o.TOSURI} {
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(raw) > 2048 {
			return verr.WithField(field, "an https URL (at most 2048 characters)")
		}
	}
	for _, p := range []struct{ field, alg, enc string }{
		{"id_token_encrypted_response", o.IDTokenEncryptedResponseAlg, o.IDTokenEncryptedResponseEnc},
		{"userinfo_encrypted_response", o.UserinfoEncryptedResponseAlg, o.UserinfoEncryptedResponseEnc},
		{"authorization_encrypted_response", o.AuthorizationEncryptedResponseAlg, o.AuthorizationEncryptedResponseEnc},
	} {
		switch {
		case p.alg == "" && p.enc != "":
			return verr.WithField(p.field+"_enc", "requires "+p.field+"_alg")
		case p.alg == "":
		case !slices.Contains(ResponseEncryptionAlgs, p.alg):
			return verr.WithField(p.field+"_alg", "one of "+strings.Join(ResponseEncryptionAlgs, ", "))
		case !slices.Contains(ResponseEncryptionEncs, p.enc):
			// The specification's default (A128CBC-HS256) is not offered, so
			// the content encryption is always explicit.
			return verr.WithField(p.field+"_enc", "required: one of "+strings.Join(ResponseEncryptionEncs, ", "))
		}
	}
	for field, a := range map[string]string{"userinfo_signed_response_alg": o.UserinfoSignedResponseAlg,
		"authorization_signed_response_alg": o.AuthorizationSignedResponseAlg} {
		if a != "" && !slices.Contains(ResponseSigningAlgs, a) {
			return verr.WithField(field, "one of "+strings.Join(ResponseSigningAlgs, ", ")+" (the realm's signing algorithm)")
		}
	}
	if o.FrontchannelLogoutURI == "" {
		if o.FrontchannelLogoutSessionRequired {
			return verr.WithField("frontchannel_logout_session_required", "requires frontchannel_logout_uri")
		}
		return nil
	}
	if msg := ValidateRedirectRegistration(o.FrontchannelLogoutURI, TypeConfidential, in.Environment); msg != "" {
		return verr.WithField("frontchannel_logout_uri", msg)
	}
	u, _ := url.Parse(o.FrontchannelLogoutURI)
	if u.Scheme != "https" && u.Scheme != "http" {
		return verr.WithField("frontchannel_logout_uri", "must be an http(s) URL")
	}
	// The specification ties the URI to the client's own site: its scheme,
	// host and port are those of a registered redirect URI.
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, r := range in.RedirectURIs {
		if ru, err := url.Parse(r); err == nil && strings.ToLower(ru.Scheme+"://"+ru.Host) == origin {
			return nil
		}
	}
	return verr.WithField("frontchannel_logout_uri", "must have the scheme, host and port of a registered redirect URI")
}
