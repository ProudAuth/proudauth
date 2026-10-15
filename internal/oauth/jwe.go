package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/proudauth/proudauth/internal/application"
)

// ErrNoEncryptionKey means a client asked for encrypted responses but has no
// registered public key that can receive them.
var ErrNoEncryptionKey = errors.New("the client has no registered public key for the requested response encryption")

// encryptTo encrypts payload to the client's newest active public key that
// fits alg (TOK-020, OIDC-013): RSA keys for RSA-OAEP-256, EC keys for
// ECDH-ES. A key marked "use": "enc" is preferred over one without a use;
// signature-only keys and keys bound to another algorithm are never used.
func (s *Service) encryptTo(ctx context.Context, c *application.Client, payload []byte, alg, enc, cty string) (string, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT public_jwk FROM client_credentials WHERE client_ref=$1 AND kind='public_key' AND state='active'
		AND public_jwk IS NOT NULL ORDER BY created_at DESC`, c.Ref)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var chosen *jose.JSONWebKey
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return "", err
		}
		var k jose.JSONWebKey
		if json.Unmarshal(raw, &k) != nil || !k.IsPublic() || (k.Use != "" && k.Use != "enc") || (k.Algorithm != "" && k.Algorithm != alg) {
			continue
		}
		switch k.Key.(type) {
		case *rsa.PublicKey:
			if alg != "RSA-OAEP-256" {
				continue
			}
		case *ecdsa.PublicKey:
			if !strings.HasPrefix(alg, "ECDH-ES") {
				continue
			}
		default:
			continue
		}
		if chosen == nil || (chosen.Use == "" && k.Use == "enc") {
			kk := k
			chosen = &kk
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if chosen == nil {
		return "", ErrNoEncryptionKey
	}
	opts := (&jose.EncrypterOptions{}).WithType("JWT")
	if cty != "" {
		// cty names a nested JWT (RFC 7516 §4.1.12, OIDC Core §16.14); an
		// encrypt-only payload of plain JSON claims carries no cty at all.
		opts = opts.WithContentType(jose.ContentType(cty))
	}
	e, err := jose.NewEncrypter(jose.ContentEncryption(enc), jose.Recipient{Algorithm: jose.KeyAlgorithm(alg), Key: chosen.Key, KeyID: chosen.KeyID}, opts)
	if err != nil {
		return "", err
	}
	obj, err := e.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}
