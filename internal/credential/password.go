// Package credential implements password verifiers, password policy, TOTP and
// recovery-code primitives. Cryptography comes from vetted libraries (ARC-009):
// golang.org/x/crypto/argon2 for hashing and github.com/pquerna/otp for HOTP/TOTP.
package credential

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/secret"
)

// Params are versioned Argon2id parameters (CRED-001).
type Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	KeyLen  uint32
	SaltLen int
}

// Hasher produces and verifies PHC-format Argon2id verifiers.
//
// Format: $argon2id$v=19$m=65536,t=3,p=2[,k=<pepper version>]$<salt>$<hash>
// When a pepper is configured the password is first keyed with HMAC-SHA256 under
// the pepper version recorded in the verifier, so pepper rotation is tracked per
// verifier (CRED-009). Losing the pepper makes peppered verifiers unusable; this is
// documented in docs/operations/keys.md.
type Hasher struct {
	Params   Params
	MaxBytes int
	Keys     *keys.Keyring
	Pepper   bool
	// LegacyUntil, when set, ends legacy verification (CRED-004); Now
	// supplies the time (defaults to the system clock).
	LegacyUntil time.Time
	Now         func() time.Time
}

// ErrLegacyRetired reports a legacy verifier after the migration ended.
var ErrLegacyRetired = errors.New("credential: legacy password hashes are no longer accepted; recover the password")

// LegacyRetired reports whether legacy verifiers are no longer accepted.
func (h *Hasher) LegacyRetired() bool {
	if h.LegacyUntil.IsZero() {
		return false
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	return !now.Before(h.LegacyUntil)
}

var (
	ErrMismatch       = errors.New("credential: password mismatch")
	ErrUnsupported    = errors.New("credential: unsupported verifier format")
	ErrTooLong        = errors.New("credential: password exceeds byte limit")
	ErrInvalidUnicode = errors.New("credential: password is not valid UTF-8")
)

// Normalize applies the documented Unicode normalization (NFKC) before hashing so
// that canonically equivalent inputs verify identically (CRED-003). Passwords are
// never truncated: oversized input is rejected before hashing.
func (h *Hasher) Normalize(pw string) (string, error) {
	if !utf8.ValidString(pw) {
		return "", ErrInvalidUnicode
	}
	if len(pw) > h.MaxBytes {
		return "", ErrTooLong
	}
	n := norm.NFKC.String(pw)
	if len(n) > h.MaxBytes {
		return "", ErrTooLong
	}
	return n, nil
}

// ErrPepperUnavailable reports a verifier that references a pepper version the
// keyring no longer (or never) held (CRED-009). Verification fails closed;
// callers log or audit it, because every password of that version is now
// unusable and the operator has a key problem, not the user a typo.
var ErrPepperUnavailable = errors.New("credential: the pepper version the verifier references is not available")

func (h *Hasher) prepare(pw string, pepperVersion int) ([]byte, error) {
	if pepperVersion <= 0 {
		return []byte(pw), nil
	}
	if h.Keys == nil {
		return nil, errors.New("credential: pepper required but no keyring")
	}
	// A missing version must never fall through to hashing an empty input
	// (which would make every password of that version equivalent).
	mac, ok := h.macPepper(pw, pepperVersion)
	if !ok {
		return nil, fmt.Errorf("%w (version %d)", ErrPepperUnavailable, pepperVersion)
	}
	return mac, nil
}

func (h *Hasher) macPepper(pw string, version int) ([]byte, bool) {
	v := h.Keys.MACVersion(keys.PurposePepper, version, pw)
	if v == "" {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	return b, err == nil && len(b) > 0
}

// Hash returns a new verifier.
func (h *Hasher) Hash(pw string) (string, error) {
	n, err := h.Normalize(pw)
	if err != nil {
		return "", err
	}
	pepperVersion := 0
	if h.Pepper && h.Keys != nil {
		_, pepperVersion = h.Keys.MAC(keys.PurposePepper, "probe")
	}
	input, err := h.prepare(n, pepperVersion)
	if err != nil {
		return "", err
	}
	p := h.Params
	if p.KeyLen == 0 {
		p.KeyLen = 32
	}
	if p.SaltLen == 0 {
		p.SaltLen = 16
	}
	salt := secret.Random(p.SaltLen)
	sum := argon2.IDKey(input, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	params := fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Time, p.Threads)
	if pepperVersion > 0 {
		params += fmt.Sprintf(",k=%d", pepperVersion)
	}
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, params,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

type parsed struct {
	memory, time  uint32
	threads       uint8
	pepperVersion int
	salt, sum     []byte
}

func parse(verifier string) (*parsed, error) {
	parts := strings.Split(verifier, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return nil, ErrUnsupported
	}
	p := &parsed{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, ErrUnsupported
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrUnsupported
		}
		switch k {
		case "m":
			p.memory = uint32(n)
		case "t":
			p.time = uint32(n)
		case "p":
			if n > 255 {
				return nil, ErrUnsupported
			}
			p.threads = uint8(n)
		case "k":
			p.pepperVersion = int(n)
		}
	}
	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, ErrUnsupported
	}
	if p.sum, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, ErrUnsupported
	}
	if p.memory == 0 || p.time == 0 || p.threads == 0 || len(p.sum) < 16 {
		return nil, ErrUnsupported
	}
	// Ceilings keep a stored (possibly imported) verifier from turning a login
	// into a memory or CPU exhaustion (MIG-006).
	if p.memory > MaxVerifierMemoryKiB || p.time > MaxVerifierTime || p.threads > MaxVerifierThreads ||
		len(p.salt) < 8 || len(p.salt) > 64 || len(p.sum) > 64 {
		return nil, ErrUnsupported
	}
	return p, nil
}

// Verifier parameter ceilings (MIG-006).
const (
	MaxVerifierMemoryKiB = 1 << 20 // 1 GiB
	MaxVerifierTime      = 16
	MaxVerifierThreads   = 16
)

// ValidateImportedHash checks a migrated password verifier before it is stored
// (MIG-006): only Argon2id within the parameter ceilings and without a local
// pepper version, the documented legacy salted SHA-256 form, or bcrypt and
// PBKDF2 within their cost bounds (imported.go) are accepted. Weaker but
// supported parameters are accepted and rehashed at the next login.
func ValidateImportedHash(v string) error {
	switch {
	case v == "":
		return nil
	case strings.HasPrefix(v, "$argon2id$"):
		p, err := parse(v)
		if err != nil {
			return fmt.Errorf("malformed Argon2id verifier or parameters above the ceiling (m<=%d, t<=%d, p<=%d)",
				MaxVerifierMemoryKiB, MaxVerifierTime, MaxVerifierThreads)
		}
		if p.pepperVersion != 0 {
			return fmt.Errorf("imported verifiers cannot reference a local pepper version")
		}
		return nil
	case strings.HasPrefix(v, "$legacy-sha256$"):
		parts := strings.Split(v, "$")
		if len(parts) != 4 {
			return fmt.Errorf("malformed legacy verifier")
		}
		salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
		sum, err2 := base64.RawStdEncoding.DecodeString(parts[3])
		if err1 != nil || err2 != nil || len(salt) < 8 || len(salt) > 64 || len(sum) != sha256.Size {
			return fmt.Errorf("malformed legacy verifier")
		}
		return nil
	case IsForeignVerifier(v):
		// bcrypt and PBKDF2 within their cost bounds (imported.go).
		return validateForeign(v)
	}
	return fmt.Errorf("unsupported password hash format; the user must recover or re-enroll")
}

// Verify checks pw against verifier. needsRehash is true when the verifier uses
// obsolete parameters, a legacy algorithm or an old pepper version (CRED-004).
func (h *Hasher) Verify(verifier, pw string) (needsRehash bool, err error) {
	n, err := h.Normalize(pw)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(verifier, "$legacy-sha256$") {
		if h.LegacyRetired() {
			return false, ErrLegacyRetired
		}
		return h.verifyLegacy(verifier, n)
	}
	if IsForeignVerifier(verifier) {
		// Imported bcrypt or PBKDF2 (MIG-006): migration window only, and
		// always rehashed after a successful verification.
		if h.LegacyRetired() {
			return false, ErrLegacyRetired
		}
		if err := verifyForeign(verifier, pw, n); err != nil {
			return false, err
		}
		return true, nil
	}
	p, err := parse(verifier)
	if err != nil {
		return false, err
	}
	input, err := h.prepare(n, p.pepperVersion)
	if err != nil {
		return false, err
	}
	sum := argon2.IDKey(input, p.salt, p.time, p.memory, p.threads, uint32(len(p.sum)))
	rawMatch := false
	if subtle.ConstantTimeCompare(sum, p.sum) != 1 {
		// An imported, unpeppered verifier was computed by its source
		// system over the password as typed, without NFKC normalization
		// (MIG-006); a match on that form is rehashed to the local one.
		if p.pepperVersion != 0 || n == pw {
			return false, ErrMismatch
		}
		raw := argon2.IDKey([]byte(pw), p.salt, p.time, p.memory, p.threads, uint32(len(p.sum)))
		if subtle.ConstantTimeCompare(raw, p.sum) != 1 {
			return false, ErrMismatch
		}
		rawMatch = true
	}
	rehash := rawMatch || p.memory != h.Params.Memory || p.time != h.Params.Time || p.threads != h.Params.Threads
	if h.Pepper && h.Keys != nil {
		_, active := h.Keys.MAC(keys.PurposePepper, "probe")
		rehash = rehash || p.pepperVersion != active
	}
	return rehash, nil
}

// verifyLegacy supports imported salted SHA-256 verifiers only during a controlled
// migration (CRED-004, MIG-006): "$legacy-sha256$<b64 salt>$<b64 sha256(salt||pw)>".
// A successful verification always requests a rehash to Argon2id.
func (h *Hasher) verifyLegacy(verifier, pw string) (bool, error) {
	parts := strings.Split(verifier, "$")
	if len(parts) != 4 {
		return false, ErrUnsupported
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false, ErrUnsupported
	}
	m := sha256.New()
	m.Write(salt)
	m.Write([]byte(pw))
	if !hmac.Equal(m.Sum(nil), want) {
		return false, ErrMismatch
	}
	return true, nil
}

var dummyOnce sync.Once
var dummyVerifier string

// DummyVerify performs a full-cost hash so that unknown accounts take comparable
// time to known ones (AUT-005, SEC-005).
func (h *Hasher) DummyVerify(pw string) {
	dummyOnce.Do(func() {
		dummyVerifier, _ = h.Hash("proudauth-dummy-password-for-timing")
	})
	_, _ = h.Verify(dummyVerifier, pw)
}

// Policy implements the password policy (CRED-002): length-based, no composition
// rules, paste allowed, common/compromised passwords rejected.
type Policy struct {
	MinLength int
	MaxLength int
	MaxBytes  int
	blocklist map[string]bool
}

//go:embed data/common-passwords.txt
var embedded embed.FS

// NewPolicy builds a policy with the embedded blocklist plus an optional operator
// file of additional compromised passwords (offline screening, SEC-013).
func NewPolicy(minLen, maxLen, maxBytes int, extraFile string) (*Policy, error) {
	p := &Policy{MinLength: minLen, MaxLength: maxLen, MaxBytes: maxBytes, blocklist: map[string]bool{}}
	f, err := embedded.Open("data/common-passwords.txt")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if w := strings.TrimSpace(sc.Text()); w != "" && !strings.HasPrefix(w, "#") {
			p.blocklist[strings.ToLower(w)] = true
		}
	}
	f.Close()
	if extraFile != "" {
		ef, err := os.Open(extraFile)
		if err != nil {
			return nil, fmt.Errorf("password blocklist: %w", err)
		}
		defer ef.Close()
		sc := bufio.NewScanner(ef)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			if w := strings.TrimSpace(sc.Text()); w != "" {
				p.blocklist[strings.ToLower(w)] = true
			}
		}
	}
	return p, nil
}

// Violation describes a policy failure with a stable machine-readable code.
type Violation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Check validates a candidate password. contextWords (e.g. email local part,
// username) must not be the whole password.
func (p *Policy) Check(pw string, minOverride int, contextWords ...string) *Violation {
	if !utf8.ValidString(pw) {
		return &Violation{"invalid_encoding", "Password must be valid Unicode text."}
	}
	if len(pw) > p.MaxBytes {
		return &Violation{"too_long", fmt.Sprintf("Password must not exceed %d bytes.", p.MaxBytes)}
	}
	n := norm.NFKC.String(pw)
	length := utf8.RuneCountInString(n)
	min := p.MinLength
	if minOverride > min {
		min = minOverride
	}
	if length < min {
		return &Violation{"too_short", fmt.Sprintf("Password must be at least %d characters.", min)}
	}
	if length > p.MaxLength {
		return &Violation{"too_long", fmt.Sprintf("Password must not exceed %d characters.", p.MaxLength)}
	}
	lower := strings.ToLower(n)
	if p.blocklist[lower] {
		return &Violation{"compromised", "Password appears in a list of common or compromised passwords."}
	}
	if isRepetitive(lower) {
		return &Violation{"repetitive", "Password is a repetitive or sequential pattern."}
	}
	for _, w := range contextWords {
		w = strings.ToLower(strings.TrimSpace(w))
		if len(w) >= 4 && (lower == w || strings.ReplaceAll(lower, w, "") == "") {
			return &Violation{"contains_identifier", "Password must not be derived from your account identifier."}
		}
	}
	return nil
}

func isRepetitive(s string) bool {
	runes := []rune(s)
	if len(runes) == 0 {
		return true
	}
	// single repeated unit of length 1..4
	for unit := 1; unit <= 4 && unit < len(runes); unit++ {
		rep := true
		for i := unit; i < len(runes); i++ {
			if runes[i] != runes[i%unit] {
				rep = false
				break
			}
		}
		if rep {
			return true
		}
	}
	// strictly ascending or descending sequence
	asc, desc := true, true
	for i := 1; i < len(runes); i++ {
		if runes[i] != runes[i-1]+1 {
			asc = false
		}
		if runes[i] != runes[i-1]-1 {
			desc = false
		}
	}
	return asc || desc
}
