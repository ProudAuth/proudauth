package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/proudauth/proudauth/internal/keys"
)

// Batch signatures (AUD-008). Each sealed batch hash is signed with an Ed25519
// key derived from the root key (purpose signing-key-wrap, label
// "audit-batch-signing"). Anyone holding the published public key can verify
// exported batches; rewriting history requires the root key. The key ID encodes
// the root-key version so batches stay verifiable across root-key rotation.

func batchKey(kr *keys.Keyring, version uint32) ed25519.PrivateKey {
	seed := kr.DeriveBytesVersion(keys.PurposeSigningWrap, version, "audit-batch-signing")
	if len(seed) < ed25519.SeedSize {
		return nil
	}
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
}

func batchKID(pub ed25519.PublicKey, version uint32) string {
	return "audit-ed25519-v" + strconv.FormatUint(uint64(version), 10) + "-" + hex.EncodeToString(pub[:6])
}

// BatchSigner returns the signer passed to SealBatch.
func BatchSigner(kr *keys.Keyring) func(hash string) (string, string, error) {
	return func(hash string) (string, string, error) {
		v := kr.ActiveVersionFor(keys.PurposeSigningWrap)
		priv := batchKey(kr, v)
		if priv == nil {
			return "", "", fmt.Errorf("audit signing key unavailable")
		}
		sig := ed25519.Sign(priv, []byte(hash))
		return base64.RawURLEncoding.EncodeToString(sig), batchKID(priv.Public().(ed25519.PublicKey), v), nil
	}
}

// BatchPublicKey returns the current verification key and its ID, for
// publication to independent verifiers.
func BatchPublicKey(kr *keys.Keyring) (string, ed25519.PublicKey) {
	v := kr.ActiveVersionFor(keys.PurposeSigningWrap)
	priv := batchKey(kr, v)
	if priv == nil {
		return "", nil
	}
	pub := priv.Public().(ed25519.PublicKey)
	return batchKID(pub, v), pub
}

// BatchVerifier verifies batch signatures by key ID. With requireSigned false,
// unsigned batches (sealed before signing was enabled) are accepted while any
// present signature must still verify.
func BatchVerifier(kr *keys.Keyring, requireSigned bool) func(kid, hash, sig string) bool {
	return func(kid, hash, sig string) bool {
		if sig == "" {
			return !requireSigned
		}
		rest, ok := strings.CutPrefix(kid, "audit-ed25519-v")
		if !ok {
			return false
		}
		vs, _, ok := strings.Cut(rest, "-")
		if !ok {
			return false
		}
		v, err := strconv.ParseUint(vs, 10, 32)
		if err != nil {
			return false
		}
		priv := batchKey(kr, uint32(v))
		if priv == nil {
			return false
		}
		pub := priv.Public().(ed25519.PublicKey)
		if batchKID(pub, uint32(v)) != kid {
			return false
		}
		raw, err := base64.RawURLEncoding.DecodeString(sig)
		return err == nil && ed25519.Verify(pub, []byte(hash), raw)
	}
}
