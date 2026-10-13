package credential

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"

	"github.com/proudbase/proudauth/internal/platform/secret"
)

// TOTP parameters (RFC 6238). SHA-1/6 digits/30s is the interoperable default
// supported by common authenticator apps.
const (
	TOTPPeriod = 30
	TOTPDigits = 6
)

// NewTOTPSecret returns a fresh 160-bit base32 seed.
func NewTOTPSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret.Random(20))
}

// NormalizeImportedTOTPSeed validates a TOTP seed carried over from another
// system (MIG-007): base32 (case and padding insensitive) for SHA-1, 6 digits
// and 30-second steps, with at least 80 bits of key material. It returns the
// canonical unpadded upper-case form.
func NormalizeImportedTOTPSeed(seed string) (string, error) {
	s := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(seed), " ", ""), "="))
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return "", errors.New("totp seed is not base32")
	}
	if len(raw) < 10 || len(raw) > 64 {
		return "", errors.New("totp seed must carry 80 to 512 bits")
	}
	return s, nil
}

// TOTPURI returns the otpauth:// provisioning URI. It is returned once to the
// enrolling user and never logged.
func TOTPURI(issuer, account, seed string) string {
	v := url.Values{}
	v.Set("secret", seed)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(TOTPDigits))
	v.Set("period", fmt.Sprint(TOTPPeriod))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// TOTPStep returns the time step for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// TOTPCode computes the code for a step (used by tests and fixtures).
func TOTPCode(seed string, step int64) (string, error) {
	return hotp.GenerateCodeCustom(seed, uint64(step), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

// MatchTOTP checks code against steps in [now-skew, now+skew] and returns the
// matched step. Replay control is enforced by the caller with an atomic conditional
// update of the last consumed step (MFA-002).
func MatchTOTP(seed, code string, now time.Time, skewSteps int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	var matched int64
	found := 0
	for d := -skewSteps; d <= skewSteps; d++ {
		step := cur + int64(d)
		want, err := TOTPCode(seed, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && found == 0 {
			matched = step
			found = 1
		}
	}
	return matched, found == 1
}

// HOTP limits (MFA-013): the look-ahead accepted at sign-in and the wider,
// two-code window accepted only by an explicit resynchronization.
const (
	HOTPDefaultLookAhead = 10
	HOTPMaxLookAhead     = 50
	HOTPDefaultResync    = 100
	HOTPMaxResync        = 1000
)

// HOTPCode computes the code for a counter (used by tests and fixtures).
func HOTPCode(seed string, counter int64) (string, error) {
	return hotp.GenerateCodeCustom(seed, uint64(counter), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

// HOTPURI returns the otpauth://hotp provisioning URI, starting at counter.
// It is returned once to the enrolling user and never logged.
func HOTPURI(issuer, account, seed string, counter int64) string {
	v := url.Values{}
	v.Set("secret", seed)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(TOTPDigits))
	v.Set("counter", fmt.Sprint(counter))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://hotp/" + label + "?" + v.Encode()
}

// MatchHOTP checks code against counters [counter, counter+window) for optional
// HOTP compatibility (MFA-013) and returns the matched counter. Every counter
// in the window is computed, so the time taken does not reveal the position.
// The caller advances the stored counter past the match atomically.
func MatchHOTP(seed, code string, counter int64, window int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits || counter < 0 || window <= 0 {
		return 0, false
	}
	var matched int64
	found := false
	for i := 0; i < window; i++ {
		want, err := HOTPCode(seed, counter+int64(i))
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && !found {
			matched, found = counter+int64(i), true
		}
	}
	return matched, found
}

// ResyncHOTP finds two consecutive codes within [counter, counter+window) for
// an explicit resynchronization (MFA-013): a single code that far ahead is
// never accepted. It returns the counter of the second code.
func ResyncHOTP(seed, code, next string, counter int64, window int) (int64, bool) {
	first, ok := MatchHOTP(seed, code, counter, window)
	if !ok {
		return 0, false
	}
	second, ok := MatchHOTP(seed, next, first+1, 1)
	if !ok {
		return 0, false
	}
	return second, true
}

// NewRecoveryCodes returns n fresh high-entropy codes for one-time display (MFA-004).
func NewRecoveryCodes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = secret.RecoveryCode()
	}
	return out
}
