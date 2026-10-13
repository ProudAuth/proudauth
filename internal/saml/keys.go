package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
)

// Key states. A pending key is published in metadata before it signs
// anything ("next" key); a retiring key is still published for a bounded
// window after it stopped signing (SAML-002).
const (
	KeyPending  = "pending"
	KeyActive   = "active"
	KeyRetiring = "retiring"
	KeyRetired  = "retired"
)

// keyIDPrefix prefixes SAML signing key identifiers.
const keyIDPrefix = "ssk"

// certificateValidity is the lifetime of a generated signing certificate.
// Trust comes from the published metadata, not from the certificate's
// dates; rotation follows the operator's schedule, independent of expiry.
const certificateValidity = 5 * 365 * 24 * time.Hour

// Keys owns the realm SAML signing keys. They are separate from the realm's
// JWT signing keys: SAML counterparties pin X.509 certificates (not JWKs),
// cache metadata for long periods and need an RSA key whatever the realm's
// token algorithm is, so the two rotate on their own schedules. Private
// keys are envelope-encrypted with the key-wrapping key like token keys
// (DEP-008); one set serves both SAML roles of the realm.
type Keys struct {
	d        *runtime.Deps
	RSABits  int
	CacheTTL time.Duration
	mu       sync.Mutex
	cache    map[string]*realmKeys
}

type realmKeys struct {
	loaded    time.Time
	active    *SigningKey
	published []*x509.Certificate
}

// SigningKey is the decrypted active key.
type SigningKey struct {
	ID      string
	Signer  crypto.Signer
	Cert    *x509.Certificate
	CertDER []byte
}

// KeyInfo is lifecycle metadata for administrators; it carries the public
// certificate only.
type KeyInfo struct {
	ID           string          `json:"id"`
	State        string          `json:"state"`
	Published    bool            `json:"published"`
	Certificate  CertificateInfo `json:"certificate"`
	CreatedAt    time.Time       `json:"created_at"`
	ActivatedAt  *time.Time      `json:"activated_at,omitempty"`
	RetiringAt   *time.Time      `json:"retiring_at,omitempty"`
	PublishUntil *time.Time      `json:"publish_until,omitempty"`
}

// NewKeys builds the key store.
func NewKeys(d *runtime.Deps) *Keys {
	return &Keys{d: d, RSABits: 3072, CacheTTL: 5 * time.Second, cache: map[string]*realmKeys{}}
}

func (k *Keys) invalidate(realmID string) {
	k.mu.Lock()
	delete(k.cache, realmID)
	k.mu.Unlock()
}

// create generates a key and a self-signed certificate and stores them.
func (k *Keys) create(ctx context.Context, q storage.Querier, realmID, state, label string) (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, k.RSABits)
	if err != nil {
		return "", err
	}
	now := k.d.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", err
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ProudAuth SAML signing " + label},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certificateValidity), KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, SignatureAlgorithm: x509.SHA256WithRSA}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	id := ids.New(keyIDPrefix)
	ct, ver, err := k.d.Keys.Encrypt(keys.PurposeSigningWrap, pkcs8, []byte("saml-signing-key:"+id))
	if err != nil {
		return "", err
	}
	var activated *time.Time
	if state == KeyActive {
		activated = &now
	}
	_, err = q.Exec(ctx, `INSERT INTO saml_signing_keys (id, realm_id, state, private_ciphertext, enc_key_version, certificate, not_after,
		created_at, activated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, realmID, state, ct, ver, der, tpl.NotAfter, now, activated)
	return id, err
}

// lock serializes key lifecycle changes for a realm.
func lock(ctx context.Context, tx pgx.Tx, realmID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('saml-signing:' || $1))`, realmID)
	return err
}

func (k *Keys) load(ctx context.Context, realmID string) (*realmKeys, error) {
	k.mu.Lock()
	if rk, ok := k.cache[realmID]; ok && k.d.Now().Sub(rk.loaded) < k.CacheTTL {
		k.mu.Unlock()
		return rk, nil
	}
	k.mu.Unlock()
	var n int
	if err := k.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM saml_signing_keys WHERE realm_id=$1 AND state='active'`, realmID).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		// The first key is created on first use, under the realm lock so
		// concurrent first requests agree on one key.
		if err := k.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if err := lock(ctx, tx, realmID); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM saml_signing_keys WHERE realm_id=$1 AND state='active'`, realmID).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			id, err := k.create(ctx, tx, realmID, KeyActive, "initial")
			if err != nil {
				return err
			}
			_, err = k.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.signing_key.created", RealmID: realmID, Actor: audit.System,
				Target: &audit.Ref{Type: "saml_signing_key", ID: id}, Category: "configuration", Metadata: map[string]any{"state": KeyActive}})
			return err
		}); err != nil {
			return nil, err
		}
	}
	now := k.d.Now()
	rows, err := k.d.DB.Pool.Query(ctx, `SELECT id, state, private_ciphertext, certificate, publish_until FROM saml_signing_keys
		WHERE realm_id=$1 AND state IN ('pending','active','retiring') ORDER BY created_at`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rk := &realmKeys{loaded: now}
	for rows.Next() {
		var id, state string
		var ct, der []byte
		var until *time.Time
		if err := rows.Scan(&id, &state, &ct, &der, &until); err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("saml: corrupt certificate %s: %w", id, err)
		}
		if state == KeyRetiring && until != nil && now.After(*until) {
			continue
		}
		rk.published = append(rk.published, cert)
		if state != KeyActive {
			continue
		}
		raw, err := k.d.Keys.Decrypt(keys.PurposeSigningWrap, ct, []byte("saml-signing-key:"+id))
		if err != nil {
			// Key integrity cannot be established: fail closed (SEC-009).
			return nil, fmt.Errorf("saml: cannot decrypt active key %s: %w", id, err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, err
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, errors.New("saml: active key is not a signer")
		}
		rk.active = &SigningKey{ID: id, Signer: signer, Cert: cert, CertDER: der}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rk.active == nil {
		return nil, errors.New("saml: no active signing key")
	}
	k.mu.Lock()
	k.cache[realmID] = rk
	k.mu.Unlock()
	return rk, nil
}

// Active returns the realm's active signing key, creating the first one.
func (k *Keys) Active(ctx context.Context, realmID string) (*SigningKey, error) {
	rk, err := k.load(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return rk.active, nil
}

// Published returns the certificates to publish in metadata: the next
// (pending) key, the active key and retiring keys still in their window.
func (k *Keys) Published(ctx context.Context, realmID string) ([]*x509.Certificate, error) {
	rk, err := k.load(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return rk.published, nil
}

// List returns lifecycle metadata for every key of the realm.
func (k *Keys) List(ctx context.Context, realmID string) ([]KeyInfo, error) {
	if _, err := k.load(ctx, realmID); err != nil {
		return nil, err
	}
	rows, err := k.d.DB.Pool.Query(ctx, `SELECT id, state, certificate, created_at, activated_at, retiring_at, publish_until
		FROM saml_signing_keys WHERE realm_id=$1 ORDER BY created_at`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := k.d.Now()
	out := []KeyInfo{}
	for rows.Next() {
		var ki KeyInfo
		var der []byte
		if err := rows.Scan(&ki.ID, &ki.State, &der, &ki.CreatedAt, &ki.ActivatedAt, &ki.RetiringAt, &ki.PublishUntil); err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		ki.Certificate = Describe(cert)
		ki.Published = ki.State == KeyPending || ki.State == KeyActive || (ki.State == KeyRetiring && (ki.PublishUntil == nil || now.Before(*ki.PublishUntil)))
		out = append(out, ki)
	}
	return out, rows.Err()
}

// Prepare creates the next key in the pending state: published in metadata
// at once, signing nothing until it is activated, so counterparties that
// refresh metadata trust it before it is used (controlled rollover, SAML-002).
func (k *Keys) Prepare(ctx context.Context, realmID string, actor audit.Ref, reason string) (*KeyInfo, error) {
	if _, err := k.load(ctx, realmID); err != nil {
		return nil, err
	}
	var id string
	err := k.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := lock(ctx, tx, realmID); err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM saml_signing_keys WHERE realm_id=$1 AND state='pending'`, realmID).Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return problem.ErrConflict.WithDetail("a next SAML signing key is already published; activate it first")
		}
		var err error
		if id, err = k.create(ctx, tx, realmID, KeyPending, "next"); err != nil {
			return err
		}
		_, err = k.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.signing_key.prepared", RealmID: realmID, Actor: actor, ReasonCode: reason,
			Target: &audit.Ref{Type: "saml_signing_key", ID: id}, Category: "configuration", Metadata: map[string]any{"state": KeyPending}})
		return err
	})
	k.invalidate(realmID)
	if err != nil {
		return nil, err
	}
	list, err := k.List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, problem.ErrNotFound
}

// Activate promotes the pending key. It refuses until the key has been
// published for minPublished, unless force is set (an emergency, recorded
// as such): counterparties that have not refreshed metadata would reject
// responses signed with a key they never saw. The previous active key keeps
// being published as retiring for retirePublish.
func (k *Keys) Activate(ctx context.Context, realmID, id string, minPublished, retirePublish time.Duration, force bool, actor audit.Ref, reason string) error {
	err := k.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := lock(ctx, tx, realmID); err != nil {
			return err
		}
		var state string
		var created time.Time
		if err := tx.QueryRow(ctx, `SELECT state, created_at FROM saml_signing_keys WHERE realm_id=$1 AND id=$2`, realmID, id).Scan(&state, &created); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if state != KeyPending {
			return problem.ErrConflict.WithDetail("only the published next key can be activated")
		}
		now := k.d.Now()
		if published := now.Sub(created); published < minPublished && !force {
			return problem.ErrConflict.WithDetailf("the next key has been published for %s; activation needs %s (saml.key_prepublish) or force",
				published.Truncate(time.Second), minPublished)
		}
		if _, err := tx.Exec(ctx, `UPDATE saml_signing_keys SET state='retiring', retiring_at=$2, publish_until=$3 WHERE realm_id=$1 AND state='active'`,
			realmID, now, now.Add(retirePublish)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE saml_signing_keys SET state='active', activated_at=$2 WHERE id=$1`, id, now); err != nil {
			return err
		}
		category := "configuration"
		if force {
			category = "emergency"
		}
		_, err := k.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.signing_key.activated", RealmID: realmID, Actor: actor, ReasonCode: reason,
			Target: &audit.Ref{Type: "saml_signing_key", ID: id}, Category: category, Metadata: map[string]any{"forced": force}})
		return err
	})
	k.invalidate(realmID)
	return err
}

// Cleanup retires keys whose publication window has ended.
func (k *Keys) Cleanup(ctx context.Context) (int64, error) {
	tag, err := k.d.DB.Pool.Exec(ctx, `UPDATE saml_signing_keys SET state='retired', retired_at=$1
		WHERE state='retiring' AND publish_until IS NOT NULL AND publish_until < $1`, k.d.Now())
	if err != nil {
		return 0, err
	}
	k.mu.Lock()
	k.cache = map[string]*realmKeys{}
	k.mu.Unlock()
	return tag.RowsAffected(), nil
}
