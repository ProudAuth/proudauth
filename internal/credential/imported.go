package credential

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Imported foreign verifier formats (MIG-006, MIG-018). Besides Argon2id and
// the legacy salted SHA-256 form, an import may carry bcrypt and PBKDF2
// verifiers produced by another identity system, as long as their cost lies
// within the bounds below: the floor keeps verifiers too cheap to be worth
// protecting out (those accounts recover their password instead), and the
// ceiling keeps a stored verifier from turning a sign-in into a CPU
// exhaustion. They verify the password exactly as the source hashed it (no
// local normalization or pepper), always request a rehash to the
// deployment's Argon2id parameters, and, like the salted SHA-256 form, stop
// verifying after security.password.legacy_hashes_until (CRED-004).
//
// Formats:
//
//	$2a$<cost>$<22 salt><31 hash>   (also $2b$ and $2y$; bcrypt's own base64)
//	$pbkdf2-sha256$i=<iterations>$<salt>$<hash>   (also -sha512 and -sha1;
//	                                               unpadded standard base64)
const (
	MinBcryptCost       = 10
	MaxBcryptCost       = 15
	MinPBKDF2Iterations = 10_000
	MaxPBKDF2Iterations = 2_000_000
)

// pbkdf2Hashes maps the PHC identifier of a PBKDF2 verifier to its PRF and
// the derived-key length bounds it accepts.
var pbkdf2Hashes = map[string]func() hash.Hash{
	"pbkdf2-sha1":   sha1.New,
	"pbkdf2-sha256": sha256.New,
	"pbkdf2-sha512": sha512.New,
}

// IsForeignVerifier reports whether v is an imported bcrypt or PBKDF2
// verifier.
func IsForeignVerifier(v string) bool {
	return isBcrypt(v) || strings.HasPrefix(v, "$pbkdf2-")
}

// IsLegacyVerifier reports whether v is a verifier that only verifies during
// the migration window (security.password.legacy_hashes_until): the salted
// SHA-256 form and the foreign bcrypt and PBKDF2 formats.
func IsLegacyVerifier(v string) bool {
	return strings.HasPrefix(v, "$legacy-sha256$") || IsForeignVerifier(v)
}

func isBcrypt(v string) bool {
	return strings.HasPrefix(v, "$2a$") || strings.HasPrefix(v, "$2b$") || strings.HasPrefix(v, "$2y$")
}

type pbkdf2Verifier struct {
	prf       func() hash.Hash
	iter      int
	salt, sum []byte
}

func parsePBKDF2(v string) (*pbkdf2Verifier, error) {
	parts := strings.Split(v, "$")
	if len(parts) != 5 || parts[0] != "" {
		return nil, fmt.Errorf("malformed PBKDF2 verifier")
	}
	prf, ok := pbkdf2Hashes[parts[1]]
	if !ok {
		return nil, fmt.Errorf("unsupported PBKDF2 pseudorandom function %q", parts[1])
	}
	is, ok := strings.CutPrefix(parts[2], "i=")
	if !ok {
		return nil, fmt.Errorf("malformed PBKDF2 verifier")
	}
	iter, err := strconv.Atoi(is)
	if err != nil {
		return nil, fmt.Errorf("malformed PBKDF2 verifier")
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	sum, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(salt) > 64 || len(sum) < 16 || len(sum) > 64 {
		return nil, fmt.Errorf("malformed PBKDF2 verifier")
	}
	return &pbkdf2Verifier{prf: prf, iter: iter, salt: salt, sum: sum}, nil
}

// validateForeign checks an imported bcrypt or PBKDF2 verifier against the
// format and the cost bounds.
func validateForeign(v string) error {
	if isBcrypt(v) {
		cost, err := bcrypt.Cost([]byte(v))
		if err != nil || len(v) != 60 {
			return fmt.Errorf("malformed bcrypt verifier")
		}
		if cost < MinBcryptCost || cost > MaxBcryptCost {
			return fmt.Errorf("bcrypt cost %d outside the accepted bounds (%d to %d); the user must recover the password", cost, MinBcryptCost, MaxBcryptCost)
		}
		return nil
	}
	p, err := parsePBKDF2(v)
	if err != nil {
		return err
	}
	if p.iter < MinPBKDF2Iterations || p.iter > MaxPBKDF2Iterations {
		return fmt.Errorf("PBKDF2 iteration count %d outside the accepted bounds (%d to %d); the user must recover the password",
			p.iter, MinPBKDF2Iterations, MaxPBKDF2Iterations)
	}
	return nil
}

// verifyForeign checks raw (the password exactly as typed, which is what the
// source system hashed) and, if it differs, its normalized form against an
// imported bcrypt or PBKDF2 verifier. Verifiers outside the bounds never
// verify, even if stored by an earlier release.
func verifyForeign(v, raw, normalized string) error {
	if err := validateForeign(v); err != nil {
		return ErrUnsupported
	}
	candidates := []string{raw}
	if normalized != raw {
		candidates = append(candidates, normalized)
	}
	if isBcrypt(v) {
		for _, c := range candidates {
			if bcrypt.CompareHashAndPassword([]byte(v), []byte(c)) == nil {
				return nil
			}
		}
		return ErrMismatch
	}
	p, err := parsePBKDF2(v)
	if err != nil {
		return ErrUnsupported
	}
	for _, c := range candidates {
		sum, err := pbkdf2.Key(p.prf, c, p.salt, p.iter, len(p.sum))
		if err == nil && hmac.Equal(sum, p.sum) {
			return nil
		}
	}
	return ErrMismatch
}

// PBKDF2Verifier encodes a PBKDF2 verifier in the import format. prf is
// "sha1", "sha256" or "sha512".
func PBKDF2Verifier(prf string, iterations int, salt, sum []byte) string {
	return fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", prf, iterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
}
