package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/certauth"

	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/storage"
)

// ErrClientAuth is returned for every client-authentication failure; the protocol
// layer maps it to OAuth "invalid_client" without detail.
var ErrClientAuth = errors.New("client authentication failed")

// ClientAuthInput carries the credentials presented at a protocol endpoint.
type ClientAuthInput struct {
	HasBasic      bool
	BasicID       string
	BasicSecret   string
	FormClientID  string
	FormSecret    string
	AssertionType string
	Assertion     string
	// Certificate is the TLS client certificate presented with the request
	// (mutual-TLS listener or trusted proxy), with any intermediates.
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
}

// AsymmetricAlgorithms accepted for client assertions (no HMAC: the server must not
// hold a secret that can mint assertions for the client).
var AsymmetricAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA}

const jwtBearerAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Authenticate validates client authentication at a token-type endpoint. Exactly one
// method may be used, and it must be the client's registered method.
func (s *Service) Authenticate(ctx context.Context, realmID, issuer, endpoint string, in ClientAuthInput) (*Client, error) {
	c, err := s.authenticate(ctx, realmID, issuer, endpoint, in)
	if err == nil && c.Protocol == ProtocolSAML {
		// A SAML application's backing client exists for consent, session and
		// audit bookkeeping; it never authenticates at an OAuth endpoint
		// (APP-018), whatever credential an administrator attaches to it.
		return nil, ErrClientAuth
	}
	return c, err
}

func (s *Service) authenticate(ctx context.Context, realmID, issuer, endpoint string, in ClientAuthInput) (*Client, error) {
	methods := 0
	if in.HasBasic {
		methods++
	}
	if in.FormSecret != "" {
		methods++
	}
	if in.Assertion != "" || in.AssertionType != "" {
		methods++
	}
	if methods > 1 {
		return nil, ErrClientAuth
	}
	switch {
	case in.HasBasic:
		if in.FormClientID != "" && in.FormClientID != in.BasicID {
			return nil, ErrClientAuth
		}
		return s.authSecret(ctx, realmID, in.BasicID, in.BasicSecret, "client_secret_basic")
	case in.FormSecret != "":
		return s.authSecret(ctx, realmID, in.FormClientID, in.FormSecret, "client_secret_post")
	case in.Assertion != "":
		if in.AssertionType != jwtBearerAssertion {
			return nil, ErrClientAuth
		}
		return s.authAssertion(ctx, realmID, issuer, endpoint, in.FormClientID, in.Assertion)
	case in.Certificate != nil:
		c, err := s.ClientByClientID(ctx, nil, realmID, in.FormClientID)
		if err != nil || !c.Active() {
			return nil, ErrClientAuth
		}
		switch c.AuthMethod {
		case "tls_client_auth", "self_signed_tls_client_auth":
			if err := s.authCertificate(ctx, c, in.Certificate, in.Intermediates); err != nil {
				return nil, ErrClientAuth
			}
			return c, nil
		case "none":
			return c, nil // a public client: the certificate can only bind tokens
		}
		return nil, ErrClientAuth
	default:
		c, err := s.ClientByClientID(ctx, nil, realmID, in.FormClientID)
		if err != nil || c.AuthMethod != "none" || !c.Active() {
			return nil, ErrClientAuth
		}
		return c, nil
	}
}

func (s *Service) authSecret(ctx context.Context, realmID, clientID, presented, method string) (*Client, error) {
	c, err := s.ClientByClientID(ctx, nil, realmID, clientID)
	if err != nil || !c.Active() {
		return nil, ErrClientAuth
	}
	// Methods are interchangeable only between basic and post for secret clients.
	if c.AuthMethod != method && !(c.AuthMethod == "client_secret_basic" && method == "client_secret_post") &&
		!(c.AuthMethod == "client_secret_post" && method == "client_secret_basic") {
		return nil, ErrClientAuth
	}
	if !secret.HasPrefix(presented, secret.PrefixClientSecret) || len(presented) > 200 {
		return nil, ErrClientAuth
	}
	var credID string
	err = s.d.DB.Pool.QueryRow(ctx, `SELECT id FROM client_credentials WHERE client_ref=$1 AND kind='secret' AND state='active'
		AND secret_digest=$2 AND (expires_at IS NULL OR expires_at > $3)`, c.Ref, secret.Digest(presented), s.d.Now()).Scan(&credID)
	if err != nil {
		return nil, ErrClientAuth
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE client_credentials SET last_used_at=$2 WHERE id=$1`, credID, s.d.Now())
	return c, nil
}

// authAssertion validates private_key_jwt (APP-009, MCH-010): registered asymmetric
// key, iss = sub = client_id, audience = token endpoint or issuer, bounded lifetime,
// and single-use jti.
func (s *Service) authAssertion(ctx context.Context, realmID, issuer, endpoint, formClientID, assertion string) (*Client, error) {
	if len(assertion) > 8192 {
		return nil, ErrClientAuth
	}
	tok, err := jwt.ParseSigned(assertion, AsymmetricAlgorithms)
	if err != nil || len(tok.Headers) != 1 {
		return nil, ErrClientAuth
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, ErrClientAuth
	}
	if unverified.Issuer == "" || unverified.Issuer != unverified.Subject {
		return nil, ErrClientAuth
	}
	if formClientID != "" && formClientID != unverified.Issuer {
		return nil, ErrClientAuth
	}
	c, err := s.ClientByClientID(ctx, nil, realmID, unverified.Issuer)
	if err != nil || !c.Active() || c.AuthMethod != "private_key_jwt" {
		return nil, ErrClientAuth
	}
	// FAPI 2.0 (ADV-001) allows PS256, ES256 and EdDSA only.
	if c.FAPI2() && !slices.Contains(FAPI2SigningAlgs, tok.Headers[0].Algorithm) {
		return nil, ErrClientAuth
	}
	keys, err := s.clientKeys(ctx, c.Ref)
	if err != nil || len(keys) == 0 {
		return nil, ErrClientAuth
	}
	kid := tok.Headers[0].KeyID
	var claims jwt.Claims
	verified := false
	for _, k := range keys {
		if kid != "" && k.KeyID != "" && k.KeyID != kid {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != tok.Headers[0].Algorithm {
			continue
		}
		if err := tok.Claims(k.Key, &claims); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrClientAuth
	}
	now := s.d.Now()
	if claims.Expiry == nil || claims.ID == "" {
		return nil, ErrClientAuth
	}
	exp := claims.Expiry.Time()
	if now.After(exp.Add(30*time.Second)) || exp.Sub(now) > 5*time.Minute {
		return nil, ErrClientAuth
	}
	if claims.NotBefore != nil && now.Add(30*time.Second).Before(claims.NotBefore.Time()) {
		return nil, ErrClientAuth
	}
	// Every audience value must name this authorization server (MCH-010): an
	// assertion also addressed to another party is not accepted here.
	if len(claims.Audience) == 0 || len(claims.Audience) > 2 {
		return nil, ErrClientAuth
	}
	for _, a := range claims.Audience {
		if a != endpoint && a != issuer {
			return nil, ErrClientAuth
		}
	}
	// Single use: a replayed jti is rejected (DB-005 style conditional insert).
	tag, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO client_assertion_jtis (realm_id, client_ref, jti, expires_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT DO NOTHING`, realmID, c.Ref, claims.ID, exp.Add(time.Minute))
	if err != nil || tag.RowsAffected() != 1 {
		return nil, ErrClientAuth
	}
	return c, nil
}

func (s *Service) clientKeys(ctx context.Context, ref string) ([]jose.JSONWebKey, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT public_jwk FROM client_credentials WHERE client_ref=$1 AND kind='public_key' AND state='active'
		AND (expires_at IS NULL OR expires_at > $2)`, ref, s.d.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []jose.JSONWebKey
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err == nil && k.IsPublic() {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

func (s *Service) addJWKS(ctx context.Context, tx pgx.Tx, realmID, ref string, raw json.RawMessage) error {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) == 0 {
		return errors.New("jwks must be a JSON Web Key Set with at least one public key")
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || !k.Valid() {
			return errors.New("jwks must only contain valid public keys")
		}
		b, _ := k.MarshalJSON()
		if _, err := tx.Exec(ctx, `INSERT INTO client_credentials (id, realm_id, client_ref, kind, public_jwk, key_id, created_at)
			VALUES ($1,$2,$3,'public_key',$4,$5,$6)`, ids.New(ids.ClientCred), realmID, ref, b, k.KeyID, s.d.Now()); err != nil {
			return err
		}
	}
	return nil
}

// AddPublicKeys registers additional client keys (rotation). Registering a
// key is a credential change and leaves evidence like a secret (ARC-008).
func (s *Service) AddPublicKeys(ctx context.Context, realmID, ref string, raw json.RawMessage, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM clients WHERE realm_id=$1 AND id=$2`, realmID, ref).Scan(&exists); err != nil {
			if storage.IsNoRows(err) {
				// An unknown client is a missing resource, as for every
				// other client route, not an unacceptable key set.
				return problem.ErrNotFound
			}
			return err
		}
		if err := s.addJWKS(ctx, tx, realmID, ref, raw); err != nil {
			return err
		}
		var kids []string
		var set jose.JSONWebKeySet
		if json.Unmarshal(raw, &set) == nil {
			for _, k := range set.Keys {
				kids = append(kids, k.KeyID)
			}
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.credential.public_key_added", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"key_ids": kids}})
		return err
	})
}

// CleanupAssertionJTIs removes expired replay records.
func (s *Service) CleanupAssertionJTIs(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM client_assertion_jtis WHERE expires_at < $1`, s.d.Now())
	return tag.RowsAffected(), err
}

// authCertificate authenticates a mutual-TLS client (RFC 8705, MCH-014).
// tls_client_auth: the certificate chains to a realm client trust anchor and
// carries the client's one registered identity. self_signed_tls_client_auth:
// it is one of the certificates registered in the client's key set and is
// within its validity period.
func (s *Service) authCertificate(ctx context.Context, c *Client, cert *x509.Certificate, intermediates []*x509.Certificate) error {
	now := s.d.Now()
	if c.AuthMethod == "tls_client_auth" {
		if s.Certs == nil {
			return ErrClientAuth
		}
		if _, err := s.Certs.Verify(ctx, nil, c.RealmID, certauth.PurposeClient, cert, intermediates); err != nil {
			return err
		}
		o := c.ProtocolOptions
		switch {
		case o.TLSClientAuthSubjectDN != "":
			if cert.Subject.String() == o.TLSClientAuthSubjectDN {
				return nil
			}
		case o.TLSClientAuthSANDNS != "":
			if slices.Contains(cert.DNSNames, o.TLSClientAuthSANDNS) {
				return nil
			}
		case o.TLSClientAuthSANURI != "":
			if slices.ContainsFunc(cert.URIs, func(u *url.URL) bool { return u.String() == o.TLSClientAuthSANURI }) {
				return nil
			}
		case o.TLSClientAuthSANIP != "":
			want := net.ParseIP(o.TLSClientAuthSANIP)
			if want != nil && slices.ContainsFunc(cert.IPAddresses, func(ip net.IP) bool { return ip.Equal(want) }) {
				return nil
			}
		case o.TLSClientAuthSANEmail != "":
			if slices.Contains(cert.EmailAddresses, o.TLSClientAuthSANEmail) {
				return nil
			}
		}
		return ErrClientAuth
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return ErrClientAuth
	}
	want := sha256.Sum256(cert.Raw)
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT public_jwk FROM client_credentials WHERE client_ref=$1 AND kind='public_key' AND state='active'
		AND public_jwk IS NOT NULL`, c.Ref)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var k jose.JSONWebKey
		if json.Unmarshal(raw, &k) != nil {
			continue
		}
		if len(k.Certificates) > 0 && bytes.Equal(k.Certificates[0].Raw, cert.Raw) {
			return nil
		}
		if len(k.CertificateThumbprintSHA256) > 0 && bytes.Equal(k.CertificateThumbprintSHA256, want[:]) {
			return nil
		}
	}
	return ErrClientAuth
}
