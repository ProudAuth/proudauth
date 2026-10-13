// Package secret generates high-entropy bearer secrets and their storage digests.
//
// High-entropy bearer artifacts (refresh tokens, authorization codes, invitation
// secrets, API keys) are stored as SHA-256 digests (DB-008, TOK-003). Low-entropy
// codes (OTPs) must instead use keyed verifiers from package keys.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
)

// Prefixes identify the purpose of a bearer secret. A secret presented to the
// wrong endpoint is rejected before any lookup (token-confusion defense).
const (
	PrefixRefresh       = "pa_rt_"
	PrefixAuthCode      = "pa_ac_"
	PrefixOpaqueAccess  = "pa_at_"
	PrefixImpersonation = "pa_it_"
	PrefixHandoff       = "pa_hc_"
	PrefixInvitation    = "pa_inv_"
	PrefixContinuation  = "pa_tx_"
	PrefixCSRF          = "pa_csrf_"
	PrefixSession       = "pa_ses_"
	PrefixClientSecret  = "pa_cs_"
	PrefixAPIKey        = "pa_key_"
	PrefixPAT           = "pa_pat_"
	PrefixLink          = "pa_lnk_"
	PrefixDeviceCode    = "pa_dc_"
	PrefixPAR           = "urn:ietf:params:oauth:request_uri:"
	PrefixRegistration  = "pa_rat_"
	PrefixInitialAccess = "pa_iat_"
	PrefixDownload      = "pa_dl_"
	PrefixRemember      = "pa_rmd_"
	PrefixSCIM          = "pa_scim_"
)

// Random returns n cryptographically secure random bytes.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("secret: crypto/rand failure: " + err.Error())
	}
	return b
}

// Token returns prefix + 256 bits of base64url randomness.
func Token(prefix string) string {
	return prefix + base64.RawURLEncoding.EncodeToString(Random(32))
}

// Digest returns the storage digest of a high-entropy secret.
func Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Numeric returns a uniformly random decimal code of the given length.
func Numeric(length int) string {
	var sb strings.Builder
	ten := big.NewInt(10)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, ten)
		if err != nil {
			panic("secret: crypto/rand failure: " + err.Error())
		}
		sb.WriteByte(byte('0' + n.Int64()))
	}
	return sb.String()
}

// userCodeAlphabet excludes vowels and confusable characters (RFC 8628 §6.1).
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCode returns a device-flow user code such as "WDJB-MJHT".
func UserCode() string {
	var sb strings.Builder
	max := big.NewInt(int64(len(userCodeAlphabet)))
	for i := 0; i < 8; i++ {
		if i == 4 {
			sb.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("secret: crypto/rand failure: " + err.Error())
		}
		sb.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return sb.String()
}

// RecoveryCode returns a high-entropy single-use recovery code (MFA-004),
// formatted as four groups of five base32-like characters (~100 bits).
func RecoveryCode() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	var sb strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < 20; i++ {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("secret: crypto/rand failure: " + err.Error())
		}
		sb.WriteByte(alphabet[n.Int64()])
	}
	return sb.String()
}

// NormalizeRecoveryCode removes formatting so users may type codes loosely.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("-", "", " ", "").Replace(s)
}

// HasPrefix reports whether s carries the purpose prefix.
func HasPrefix(s, prefix string) bool { return strings.HasPrefix(s, prefix) }

// Redact returns a non-secret display form of a bearer secret for diagnostics.
func Redact(s string) string {
	if len(s) <= 10 {
		return "[REDACTED]"
	}
	i := strings.LastIndexByte(s[:min(len(s), 12)], '_')
	if i < 0 {
		return "[REDACTED]"
	}
	return s[:i+1] + "[REDACTED]"
}
