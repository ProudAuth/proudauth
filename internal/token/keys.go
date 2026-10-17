// Package token implements signing-key lifecycle, JWT minting and strict
// verification for the identity provider (§14).
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Key states.
const (
	StatePending     = "pending"
	StateActive      = "active"
	StateRetiring    = "retiring"
	StateRetired     = "retired"
	StateCompromised = "compromised"
)

// ErrNoActiveKey means issuance must stop (SEC-009, §31.2 signing provider unavailable).
var ErrNoActiveKey = errors.New("token: no usable active signing key")

// ErrKeyUnavailable means the realm has an active key that the key provider
// cannot unwrap (keyring, KMS or HSM unavailable, other root keys, or a
// wrapped key that fails its integrity check). It is
// an ErrNoActiveKey: issuance answers temporarily_unavailable and rolls back
// what it consumed (TEST-059); no replacement key is ever created for it.
var ErrKeyUnavailable = fmt.Errorf("%w: the key provider cannot unwrap the active key", ErrNoActiveKey)

// SigningKey is a decrypted signing key.
type SigningKey struct {
	KID       string
	Algorithm string
	State     string
	Private   crypto.Signer
	Public    jose.JSONWebKey
}

// PublicKey is published verification material.
type PublicKey struct {
	KID          string
	Algorithm    string
	State        string
	JWK          jose.JSONWebKey
	PublishUntil *time.Time
}

type realmKeys struct {
	loadedAt    time.Time
	active      *SigningKey
	public      []PublicKey
	byKID       map[string]PublicKey
	compromised map[string]bool
}

// KeyManager owns signing-key lifecycle. Keys are persisted encrypted so a restart
// never silently creates a new key identity (DEP-008).
type KeyManager struct {
	d        *runtime.Deps
	RSABits  int
	CacheTTL time.Duration
	mu       sync.Mutex
	cache    map[string]*realmKeys
}

// NewKeyManager creates a key manager.
func NewKeyManager(d *runtime.Deps) *KeyManager {
	return &KeyManager{d: d, RSABits: 3072, CacheTTL: 5 * time.Second, cache: map[string]*realmKeys{}}
}

// Invalidate drops cached key material for a realm (after rotation).
func (m *KeyManager) Invalidate(realmID string) {
	m.mu.Lock()
	delete(m.cache, realmID)
	m.mu.Unlock()
}

func (m *KeyManager) generate(alg string) (crypto.Signer, error) {
	switch alg {
	case "RS256", "PS256":
		return rsa.GenerateKey(rand.Reader, m.RSABits)
	case "ES256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EdDSA":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("token: unsupported signing algorithm %q", alg)
	}
}

// CreateKey generates and stores a key in the given state inside tx.
func (m *KeyManager) CreateKey(ctx context.Context, q storage.Querier, realmID, alg, state, purpose string) (string, error) {
	priv, err := m.generate(alg)
	if err != nil {
		return "", err
	}
	kid := fmt.Sprintf("%s-%s-%x", strings.ToLower(alg), m.d.Now().Format("20060102"), secret.Random(8))
	pub := jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: alg, Use: "sig"}
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	ct, ver, err := m.d.Keys.Encrypt(keys.PurposeSigningWrap, der, []byte("signing-key:"+kid))
	if err != nil {
		return "", err
	}
	now := m.d.Now()
	var activatedAt *time.Time
	if state == StateActive {
		activatedAt = &now
	}
	_, err = q.Exec(ctx, `INSERT INTO signing_keys (kid, realm_id, algorithm, public_jwk, private_ciphertext, enc_key_version,
		state, purpose, created_at, activated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		kid, realmID, alg, pubJSON, ct, ver, state, purpose, now, activatedAt)
	if err != nil {
		return "", err
	}
	return kid, nil
}

// EnsureActive creates an active key if the realm has none.
func (m *KeyManager) EnsureActive(ctx context.Context, q storage.Querier, realmID, alg string) error {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE realm_id=$1 AND state='active' AND purpose='token'`, realmID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := m.CreateKey(ctx, q, realmID, alg, StateActive, "token")
	return err
}

func (m *KeyManager) load(ctx context.Context, realmID string) (*realmKeys, error) {
	m.mu.Lock()
	if rk, ok := m.cache[realmID]; ok && m.d.Now().Sub(rk.loadedAt) < m.CacheTTL {
		m.mu.Unlock()
		return rk, nil
	}
	m.mu.Unlock()

	rows, err := m.d.DB.Pool.Query(ctx, `SELECT kid, algorithm, public_jwk, private_ciphertext, state, publish_until
		FROM signing_keys WHERE realm_id=$1 AND purpose='token' AND state <> 'retired'`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := m.d.Now()
	rk := &realmKeys{loadedAt: now, byKID: map[string]PublicKey{}, compromised: map[string]bool{}}
	for rows.Next() {
		var kid, alg, state string
		var pubJSON, ct []byte
		var publishUntil *time.Time
		if err := rows.Scan(&kid, &alg, &pubJSON, &ct, &state, &publishUntil); err != nil {
			return nil, err
		}
		if state == StateCompromised {
			rk.compromised[kid] = true
			continue
		}
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(pubJSON); err != nil {
			return nil, fmt.Errorf("token: corrupt public key %s: %w", kid, err)
		}
		if publishUntil != nil && now.After(*publishUntil) {
			continue
		}
		pk := PublicKey{KID: kid, Algorithm: alg, State: state, JWK: jwk, PublishUntil: publishUntil}
		rk.public = append(rk.public, pk)
		rk.byKID[kid] = pk
		if state == StateActive {
			der, err := m.d.Keys.Decrypt(keys.PurposeSigningWrap, ct, []byte("signing-key:"+kid))
			if err != nil {
				// Key integrity cannot be established: fail closed (SEC-009).
				return nil, fmt.Errorf("token: cannot decrypt active key %s: %w: %w", kid, ErrKeyUnavailable, err)
			}
			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, err
			}
			signer, ok := parsed.(crypto.Signer)
			if !ok {
				return nil, errors.New("token: active key is not a signer")
			}
			rk.active = &SigningKey{KID: kid, Algorithm: alg, State: state, Private: signer, Public: jwk}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.cache[realmID] = rk
	m.mu.Unlock()
	return rk, nil
}

// Active returns the active signing key or ErrNoActiveKey.
func (m *KeyManager) Active(ctx context.Context, realmID string) (*SigningKey, error) {
	rk, err := m.load(ctx, realmID)
	if err != nil {
		return nil, err
	}
	if rk.active == nil {
		return nil, ErrNoActiveKey
	}
	return rk.active, nil
}

// Published returns the public verification keys (pending, active, retiring).
func (m *KeyManager) Published(ctx context.Context, realmID string) ([]PublicKey, error) {
	rk, err := m.load(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return rk.public, nil
}

// Lookup resolves a kid only within the realm's trusted key set (§14.4 step 4).
func (m *KeyManager) Lookup(ctx context.Context, realmID, kid string) (PublicKey, bool, error) {
	rk, err := m.load(ctx, realmID)
	if err != nil {
		return PublicKey{}, false, err
	}
	if rk.compromised[kid] {
		return PublicKey{}, false, nil
	}
	pk, ok := rk.byKID[kid]
	return pk, ok, nil
}

// JWKS returns the public JWK set document (TOK-011). Private material is never included.
func (m *KeyManager) JWKS(ctx context.Context, realmID string) ([]byte, error) {
	pub, err := m.Published(ctx, realmID)
	if err != nil {
		return nil, err
	}
	set := jose.JSONWebKeySet{}
	for _, p := range pub {
		k := p.JWK
		if !k.IsPublic() {
			return nil, errors.New("token: refusing to publish non-public key")
		}
		set.Keys = append(set.Keys, k)
	}
	return json.Marshal(set)
}

// KeyMetadata is public lifecycle metadata for administrators.
type KeyMetadata struct {
	KID           string     `json:"kid"`
	Algorithm     string     `json:"algorithm"`
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	ActivatedAt   *time.Time `json:"activated_at,omitempty"`
	RetiringAt    *time.Time `json:"retiring_at,omitempty"`
	PublishUntil  *time.Time `json:"publish_until,omitempty"`
	CompromisedAt *time.Time `json:"compromised_at,omitempty"`
}

// List returns lifecycle metadata for all keys of a realm.
func (m *KeyManager) List(ctx context.Context, realmID string) ([]KeyMetadata, error) {
	rows, err := m.d.DB.Pool.Query(ctx, `SELECT kid, algorithm, state, created_at, activated_at, retiring_at, publish_until, compromised_at
		FROM signing_keys WHERE realm_id=$1 AND purpose='token' ORDER BY created_at`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyMetadata
	for rows.Next() {
		var k KeyMetadata
		if err := rows.Scan(&k.KID, &k.Algorithm, &k.State, &k.CreatedAt, &k.ActivatedAt, &k.RetiringAt, &k.PublishUntil, &k.CompromisedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RotationMode selects planned or emergency rotation.
type RotationMode string

const (
	RotationPlanned   RotationMode = "planned"
	RotationEmergency RotationMode = "emergency"
)

// Rotation refusals (TOK-005, ADV-001). Rotate returns them inside a
// 409 conflict problem; errors.Is tells them apart.
var (
	// ErrRotationPinnedResources means active business resources pin a
	// signing algorithm other than the one the new key would use.
	ErrRotationPinnedResources = errors.New("token: resources pin a different signing algorithm")
	// ErrRotationFAPI2Clients means fapi2 clients would be left with a
	// realm key whose algorithm FAPI 2.0 does not allow.
	ErrRotationFAPI2Clients = errors.New("token: fapi2 clients need a PS256, ES256 or EdDSA realm key")
)

// fapi2Algorithms are the algorithms FAPI 2.0 allows for signatures; they
// match application.FAPI2SigningAlgs, checked at client registration.
var fapi2Algorithms = []string{"PS256", "ES256", "EdDSA"}

// Rotate performs signing-key rotation with audit (TOK-012, TOK-013).
//
// An empty alg keeps the realm's algorithm: that of its active key, or
// keys.signing_algorithm when it has none (the realm's algorithm is derived
// from its active key). Every caller, the admin API and the scheduled
// rotation alike, runs the same guards inside the rotation's transaction: a
// rotation whose algorithm active business resources do not pin, or that
// would leave fapi2 clients with a non-FAPI 2.0 algorithm, is refused with a
// 409 conflict naming them (TOK-005, ADV-001).
//
// Planned: a new key is prepublished as "pending"; ActivateDue promotes it after the
// prepublish period, and the previous key keeps being published as "retiring" until
// dependent tokens and verifier caches have aged out.
//
// Emergency: a new key becomes active immediately and the previous active key is
// marked compromised: it disappears from JWKS and this server rejects its tokens.
// Removing a JWKS entry does not purge external verifier caches, so an outbox
// event notifies relying services to drop trust (§31.3).
func (m *KeyManager) Rotate(ctx context.Context, realmID, alg string, mode RotationMode, actor audit.Ref, reason string) (string, error) {
	var newKID string
	err := m.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('signing:' || $1))`, realmID); err != nil {
			return err
		}
		now := m.d.Now()
		var oldKID, oldAlg *string
		_ = tx.QueryRow(ctx, `SELECT kid, algorithm FROM signing_keys WHERE realm_id=$1 AND state='active' AND purpose='token'`, realmID).Scan(&oldKID, &oldAlg)
		if alg == "" {
			alg = m.d.Cfg.Keys.SigningAlgorithm
			if oldAlg != nil {
				alg = *oldAlg
			}
		}
		if err := checkRotation(ctx, tx, realmID, alg); err != nil {
			return err
		}
		var err error
		switch mode {
		case RotationPlanned:
			var pending int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE realm_id=$1 AND state='pending' AND purpose='token'`, realmID).Scan(&pending); err != nil {
				return err
			}
			if pending > 0 {
				return errors.New("a planned rotation is already pending")
			}
			newKID, err = m.CreateKey(ctx, tx, realmID, alg, StatePending, "token")
			if err != nil {
				return err
			}
		case RotationEmergency:
			if oldKID != nil {
				if _, err := tx.Exec(ctx, `UPDATE signing_keys SET state='compromised', compromised_at=$2 WHERE kid=$1`, *oldKID, now); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO token_revocations (id, realm_id, reference_type, reference_id, reason, effective_at)
					VALUES ($1,$2,'key',$3,$4,$5)`, ids.New(ids.Revocation), realmID, *oldKID, "key_compromised", now); err != nil {
					return err
				}
			}
			// Pending keys created before the compromise are discarded as well.
			if _, err := tx.Exec(ctx, `UPDATE signing_keys SET state='retired', retired_at=$2 WHERE realm_id=$1 AND state='pending'`, realmID, now); err != nil {
				return err
			}
			newKID, err = m.CreateKey(ctx, tx, realmID, alg, StateActive, "token")
			if err != nil {
				return err
			}
		default:
			return errors.New("unknown rotation mode")
		}
		old := ""
		if oldKID != nil {
			old = *oldKID
		}
		if _, err := m.d.Audit.Record(ctx, tx, audit.Event{
			Type: "signing_key.rotation." + string(mode), RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "signing_key", ID: newKID}, ReasonCode: reason,
			Metadata: map[string]any{"previous_kid": old, "algorithm": alg},
		}); err != nil {
			return err
		}
		_, err = m.d.Outbox.Publish(ctx, tx, events.Event{
			EventType: "signing_key.rotated", RealmID: realmID, AggregateType: "realm", AggregateID: realmID,
			Data: map[string]any{"mode": string(mode), "new_kid": newKID, "previous_kid": old, "previous_key_compromised": mode == RotationEmergency},
		})
		return err
	})
	m.Invalidate(realmID)
	return newKID, err
}

// checkRotation refuses a key algorithm that would stop issuance for pinned
// resources (TOK-005) or sign fapi2 clients' responses with an algorithm
// FAPI 2.0 does not allow (ADV-001).
func checkRotation(ctx context.Context, tx pgx.Tx, realmID, alg string) error {
	pinned, err := firstColumn(ctx, tx, `SELECT audience FROM api_resources WHERE realm_id=$1 AND state='active'
		AND kind='business' AND signing_algorithm IS NOT NULL AND signing_algorithm <> $2 ORDER BY audience LIMIT 20`, realmID, alg)
	if err != nil {
		return err
	}
	if len(pinned) > 0 {
		return problem.ErrConflict.WithDetail("resources pin a different signing algorithm; update their signing_algorithm first").
			WithExtension("resources", pinned).With(ErrRotationPinnedResources)
	}
	if slices.Contains(fapi2Algorithms, alg) {
		return nil
	}
	clients, err := firstColumn(ctx, tx, `SELECT client_id FROM clients WHERE realm_id=$1 AND security_profile='fapi2'
		AND state <> 'decommissioned' ORDER BY client_id LIMIT 20`, realmID)
	if err != nil {
		return err
	}
	if len(clients) > 0 {
		return problem.ErrConflict.WithDetail("fapi2 clients need a realm signing algorithm of PS256, ES256 or EdDSA").
			WithExtension("clients", clients).With(ErrRotationFAPI2Clients)
	}
	return nil
}

func firstColumn(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ActivateDue promotes pending keys older than the prepublish period and moves the
// previous active key to retiring. publishFor bounds how long the retiring key stays
// in JWKS (max token lifetime + verifier cache window).
func (m *KeyManager) ActivateDue(ctx context.Context, prepublish, publishFor time.Duration) (int, error) {
	now := m.d.Now()
	rows, err := m.d.DB.Pool.Query(ctx, `SELECT kid, realm_id FROM signing_keys WHERE state='pending' AND purpose='token' AND created_at <= $1`, now.Add(-prepublish))
	if err != nil {
		return 0, err
	}
	type due struct{ kid, realm string }
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.kid, &d.realm); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	for _, k := range list {
		err := m.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('signing:' || $1))`, k.realm); err != nil {
				return err
			}
			until := now.Add(publishFor)
			if _, err := tx.Exec(ctx, `UPDATE signing_keys SET state='retiring', retiring_at=$2, publish_until=$3
				WHERE realm_id=$1 AND state='active' AND purpose='token'`, k.realm, now, until); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE signing_keys SET state='active', activated_at=$2 WHERE kid=$1 AND state='pending'`, k.kid, now); err != nil {
				return err
			}
			_, err := m.d.Audit.Record(ctx, tx, audit.Event{Type: "signing_key.activated", RealmID: k.realm,
				Actor: audit.System, Target: &audit.Ref{Type: "signing_key", ID: k.kid}})
			return err
		})
		if err != nil {
			return 0, err
		}
		m.Invalidate(k.realm)
	}
	return len(list), nil
}

// RetireExpired retires retiring keys whose publication window has ended.
func (m *KeyManager) RetireExpired(ctx context.Context) (int64, error) {
	tag, err := m.d.DB.Pool.Exec(ctx, `UPDATE signing_keys SET state='retired', retired_at=$1
		WHERE state='retiring' AND publish_until IS NOT NULL AND publish_until < $1`, m.d.Now())
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.cache = map[string]*realmKeys{}
	m.mu.Unlock()
	return tag.RowsAffected(), nil
}

// DueForRotation lists realms whose active key is older than interval.
func (m *KeyManager) DueForRotation(ctx context.Context, interval time.Duration) ([]string, error) {
	rows, err := m.d.DB.Pool.Query(ctx, `SELECT realm_id FROM signing_keys k WHERE state='active' AND purpose='token'
		AND activated_at < $1 AND NOT EXISTS (SELECT 1 FROM signing_keys p WHERE p.realm_id=k.realm_id AND p.state='pending')`,
		m.d.Now().Add(-interval))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
