// Package keys holds the deployment key hierarchy.
//
// Operators supply one or more versioned 256-bit root keys (from files or secret
// references, DEP-006). Independent purpose keys are derived with HKDF-SHA256 so
// that data encryption, signing-key wrapping, webhook secrets, OTP verifiers and
// the password pepper never share key material (SEC-010). An operator may instead
// supply a dedicated root for any purpose (e.g. an externally protected pepper,
// CRED-009); dedicated roots take precedence over derivation.
//
// Ciphertext layout: 0x01 | key_version (uint32 BE) | nonce (12) | AES-256-GCM sealed box.
// Associated data binds a ciphertext to its owning row so it cannot be swapped.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/proudbase/proudauth/internal/platform/secret"
)

// Purpose separates derived keys.
type Purpose string

const (
	PurposeData        Purpose = "data-encryption"
	PurposeSigningWrap Purpose = "signing-key-wrap"
	PurposeWebhook     Purpose = "webhook-secrets"
	PurposeOTP         Purpose = "otp-verifier"
	PurposePepper      Purpose = "password-pepper"
	PurposePairwise    Purpose = "pairwise-subject"
	PurposeLookup      Purpose = "lookup-digest"
)

var (
	ErrNoKey          = errors.New("keys: no key for requested version")
	ErrDecrypt        = errors.New("keys: ciphertext authentication failed")
	ErrMalformed      = errors.New("keys: malformed ciphertext")
	ErrNotInitialized = errors.New("keys: keyring has no active root key")
)

// Keyring holds versioned root keys and derived purpose keys.
type Keyring struct {
	mu        sync.RWMutex
	active    uint32
	roots     map[uint32][]byte
	dedicated map[Purpose]map[uint32][]byte
	derived   map[string][]byte
	// fault is the fault-injection seam of SetFault (TEST-059).
	fault atomic.Pointer[func(Purpose) error]
}

// SetFault installs a fault-injection seam for tests, in the style of
// impersonation's FailAudit (TEST-059): while set, Encrypt and Decrypt for a
// purpose f returns an error for fail with that error, as when the KMS or HSM
// holding the key cannot be reached. nil removes it. Production code never
// sets it.
func (k *Keyring) SetFault(f func(Purpose) error) {
	if f == nil {
		k.fault.Store(nil)
		return
	}
	k.fault.Store(&f)
}

func (k *Keyring) injectFault(p Purpose) error {
	if f := k.fault.Load(); f != nil {
		return (*f)(p)
	}
	return nil
}

// New creates a keyring from versioned root keys; activeVersion selects the key used
// for new encryptions. Older versions remain available for decryption (rotation).
func New(roots map[uint32][]byte, activeVersion uint32) (*Keyring, error) {
	if len(roots) == 0 {
		return nil, ErrNotInitialized
	}
	for v, k := range roots {
		if len(k) != 32 {
			return nil, fmt.Errorf("keys: root key version %d must be 32 bytes, got %d", v, len(k))
		}
	}
	if _, ok := roots[activeVersion]; !ok {
		return nil, fmt.Errorf("keys: active version %d not present", activeVersion)
	}
	return &Keyring{
		active:    activeVersion,
		roots:     roots,
		dedicated: map[Purpose]map[uint32][]byte{},
		derived:   map[string][]byte{},
	}, nil
}

// NewRandom returns a keyring with a fresh random root key. Only for tests and
// explicitly ephemeral development runs; production rejects it (QA-007).
func NewRandom() *Keyring {
	k, _ := New(map[uint32][]byte{1: secret.Random(32)}, 1)
	return k
}

// SetDedicated installs an operator-supplied key for a purpose.
func (k *Keyring) SetDedicated(p Purpose, keys map[uint32][]byte) error {
	for v, key := range keys {
		if len(key) != 32 {
			return fmt.Errorf("keys: dedicated %s key version %d must be 32 bytes", p, v)
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dedicated[p] = keys
	for name := range k.derived {
		delete(k.derived, name)
	}
	return nil
}

// ActiveVersion returns the active root key version.
func (k *Keyring) ActiveVersion() uint32 { return k.active }

// Versions lists available root versions (ascending).
func (k *Keyring) Versions() []uint32 {
	out := make([]uint32, 0, len(k.roots))
	for v := range k.roots {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Fingerprint returns a non-secret identifier of the active key hierarchy, suitable
// for detecting a restore performed with the wrong keys (OPS-005).
func (k *Keyring) Fingerprint() string {
	key, _ := k.purposeKey(PurposeLookup, k.active)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("proudauth-keyring-fingerprint"))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

func (k *Keyring) purposeKey(p Purpose, version uint32) ([]byte, error) {
	name := fmt.Sprintf("%s/%d", p, version)
	k.mu.RLock()
	if d, ok := k.derived[name]; ok {
		k.mu.RUnlock()
		return d, nil
	}
	ded := k.dedicated[p]
	k.mu.RUnlock()

	var key []byte
	if ded != nil {
		dk, ok := ded[version]
		if !ok {
			return nil, ErrNoKey
		}
		key = dk
	} else {
		root, ok := k.roots[version]
		if !ok {
			return nil, ErrNoKey
		}
		d, err := hkdf.Key(sha256.New, root, []byte("proudauth/hkdf-salt/v1"), "proudauth/v1/"+string(p), 32)
		if err != nil {
			return nil, err
		}
		key = d
	}
	k.mu.Lock()
	k.derived[name] = key
	k.mu.Unlock()
	return key, nil
}

func (k *Keyring) activeFor(p Purpose) uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if ded := k.dedicated[p]; ded != nil {
		var max uint32
		for v := range ded {
			if v > max {
				max = v
			}
		}
		return max
	}
	return k.active
}

// Encrypt seals plaintext for a purpose, binding aad. Returns the ciphertext and the key version used.
func (k *Keyring) Encrypt(p Purpose, plaintext, aad []byte) ([]byte, int, error) {
	if err := k.injectFault(p); err != nil {
		return nil, 0, err
	}
	version := k.activeFor(p)
	key, err := k.purposeKey(p, version)
	if err != nil {
		return nil, 0, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	nonce := secret.Random(gcm.NonceSize())
	out := make([]byte, 0, 1+4+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, 0x01)
	out = binary.BigEndian.AppendUint32(out, version)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)
	return out, int(version), nil
}

// Decrypt opens a ciphertext produced by Encrypt for the same purpose and aad.
func (k *Keyring) Decrypt(p Purpose, ciphertext, aad []byte) ([]byte, error) {
	if err := k.injectFault(p); err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+4+12+16 || ciphertext[0] != 0x01 {
		return nil, ErrMalformed
	}
	version := binary.BigEndian.Uint32(ciphertext[1:5])
	key, err := k.purposeKey(p, version)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[5 : 5+gcm.NonceSize()]
	pt, err := gcm.Open(nil, nonce, ciphertext[5+gcm.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// MAC computes a keyed verifier for low-entropy secrets such as OTP codes
// (PWDLESS-007, DB-008). Returns the verifier and key version.
func (k *Keyring) MAC(p Purpose, data ...string) (string, int) {
	version := k.activeFor(p)
	return k.macWith(p, version, data...), int(version)
}

func (k *Keyring) macWith(p Purpose, version uint32, data ...string) string {
	key, err := k.purposeKey(p, version)
	if err != nil {
		return ""
	}
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(d)))
		m.Write(l[:])
		m.Write([]byte(d))
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// MACVersion computes a keyed verifier with a specific key version (for verifying
// material keyed under an older version, e.g. a rotated pepper).
func (k *Keyring) MACVersion(p Purpose, version int, data ...string) string {
	if version < 0 {
		return ""
	}
	return k.macWith(p, uint32(version), data...)
}

// VerifyMAC checks a keyed verifier in constant time.
func (k *Keyring) VerifyMAC(p Purpose, version int, verifier string, data ...string) bool {
	if version < 0 {
		return false
	}
	expected := k.macWith(p, uint32(version), data...)
	if expected == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(verifier))
}

// DeriveBytes returns deterministic purpose-bound bytes (e.g. pairwise subjects).
// DeriveBytesVersion derives with a specific root-key version (for verifying
// material created before a root-key rotation).
func (k *Keyring) DeriveBytesVersion(p Purpose, version uint32, data ...string) []byte {
	key, err := k.purposeKey(p, version)
	if err != nil {
		return nil
	}
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write([]byte(d))
		m.Write([]byte{0})
	}
	return m.Sum(nil)
}

// ActiveVersionFor returns the root-key version used for a purpose.
func (k *Keyring) ActiveVersionFor(p Purpose) uint32 { return k.activeFor(p) }

func (k *Keyring) DeriveBytes(p Purpose, data ...string) []byte {
	key, err := k.purposeKey(p, k.activeFor(p))
	if err != nil {
		return nil
	}
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write([]byte(d))
		m.Write([]byte{0})
	}
	return m.Sum(nil)
}
