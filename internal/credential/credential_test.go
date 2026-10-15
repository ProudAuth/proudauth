package credential

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/secret"
)

func testHasher() *Hasher {
	return &Hasher{Params: Params{Time: 1, Memory: 8 * 1024, Threads: 1}, MaxBytes: 1024}
}

// TestHashVerifyAndRehash covers CRED-001: verifiers are Argon2id PHC strings
// that record their parameters (so they are versioned and rehashed when the
// configured parameters change) and carry a fresh salt per hash.
func TestHashVerifyAndRehash(t *testing.T) {
	h := testHasher()
	v, err := h.Hash("correct horse battery staple!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("unexpected format %s", v)
	}
	// Unique salts: hashing the same password again yields a different salt
	// and digest, and both verify.
	v2, err := h.Hash("correct horse battery staple!")
	if err != nil {
		t.Fatal(err)
	}
	salt := func(v string) string { return strings.Split(v, "$")[4] }
	if v2 == v || salt(v2) == salt(v) || len(salt(v)) < 16 {
		t.Fatalf("salts must be unique per verifier: %s / %s", v, v2)
	}
	if _, err := h.Verify(v2, "correct horse battery staple!"); err != nil {
		t.Fatalf("second verifier: %v", err)
	}
	if re, err := h.Verify(v, "correct horse battery staple!"); err != nil || re {
		t.Fatalf("verify: %v rehash=%v", err, re)
	}
	if _, err := h.Verify(v, "correct horse battery staple?"); err != ErrMismatch {
		t.Fatal("wrong password must not verify")
	}
	h2 := testHasher()
	h2.Params.Time = 2
	if re, err := h2.Verify(v, "correct horse battery staple!"); err != nil || !re {
		t.Fatal("obsolete parameters must request rehash (CRED-004)")
	}
}

func TestPasswordNeverTruncated(t *testing.T) {
	h := testHasher()
	long := strings.Repeat("a", 1025)
	if _, err := h.Hash(long); err != ErrTooLong {
		t.Fatal("oversized passwords must be rejected, not truncated (CRED-003)")
	}
	v, _ := h.Hash(strings.Repeat("ab", 300))
	if _, err := h.Verify(v, strings.Repeat("ab", 299)+"a"); err == nil {
		t.Fatal("prefix must not verify")
	}
}

func TestUnicodeNormalization(t *testing.T) {
	h := testHasher()
	v, _ := h.Hash("café au lait forever")                          // precomposed
	if _, err := h.Verify(v, "café au lait forever"); err != nil { // decomposed
		t.Fatal("canonically equivalent passwords must verify")
	}
}

// TestPepper covers CRED-009: a peppered verifier records the pepper key
// version, verifies only with that pepper, survives rotation (older versions
// still verify and request a rehash to the newest), and becomes unusable when
// the version it references is removed.
func TestPepper(t *testing.T) {
	kr := keys.NewRandom()
	h := testHasher()
	h.Keys, h.Pepper = kr, true
	v, _ := h.Hash("a peppered passphrase value")
	if !strings.Contains(v, ",k=1$") {
		t.Fatalf("pepper version must be recorded: %s", v)
	}
	if _, err := h.Verify(v, "a peppered passphrase value"); err != nil {
		t.Fatal(err)
	}
	other := testHasher()
	other.Keys, other.Pepper = keys.NewRandom(), true
	if _, err := other.Verify(v, "a peppered passphrase value"); err == nil {
		t.Fatal("a different pepper must not verify")
	}

	// Dedicated (externally supplied) pepper keys and their rotation.
	const pw = "a rotated pepper passphrase"
	k1, k2 := secret.Random(32), secret.Random(32)
	ext := keys.NewRandom()
	if err := ext.SetDedicated(keys.PurposePepper, map[uint32][]byte{1: k1}); err != nil {
		t.Fatal(err)
	}
	ph := testHasher()
	ph.Keys, ph.Pepper = ext, true
	unpeppered, _ := testHasher().Hash(pw)
	if re, err := ph.Verify(unpeppered, pw); err != nil || !re {
		t.Fatalf("an unpeppered verifier must verify and request a peppered rehash: %v rehash=%v", err, re)
	}
	v1, _ := ph.Hash(pw)
	if !strings.Contains(v1, ",k=1$") {
		t.Fatalf("pepper version 1 not recorded: %s", v1)
	}
	if err := ext.SetDedicated(keys.PurposePepper, map[uint32][]byte{1: k1, 2: k2}); err != nil {
		t.Fatal(err)
	}
	if re, err := ph.Verify(v1, pw); err != nil || !re {
		t.Fatalf("after rotation the old pepper version must verify and request a rehash: %v rehash=%v", err, re)
	}
	v2, _ := ph.Hash(pw)
	if !strings.Contains(v2, ",k=2$") {
		t.Fatalf("new verifiers must use the newest pepper version: %s", v2)
	}
	if re, err := ph.Verify(v2, pw); err != nil || re {
		t.Fatalf("current-version verifier: %v rehash=%v", err, re)
	}
	if err := ext.SetDedicated(keys.PurposePepper, map[uint32][]byte{2: k2}); err != nil {
		t.Fatal(err)
	}
	if _, err := ph.Verify(v1, pw); err == nil {
		t.Fatal("a verifier whose pepper version was removed must not verify")
	}
	if _, err := ph.Verify(v2, pw); err != nil {
		t.Fatalf("verifier on the kept pepper version: %v", err)
	}
}

// TestMissingPepperVersionFailsClosed covers CRED-009: a verifier that names a
// pepper version the keyring does not hold is reported as
// ErrPepperUnavailable (so the caller can log it) and never verifies. Before,
// the missing pepper turned into an empty hash input, so a verifier computed
// over the empty string accepted every password.
func TestMissingPepperVersionFailsClosed(t *testing.T) {
	h := testHasher()
	h.Keys, h.Pepper = keys.NewRandom(), true // holds pepper version 1 only
	salt := secret.Random(16)
	sum := argon2.IDKey([]byte{}, salt, 1, 8*1024, 1, 32)
	forged := fmt.Sprintf("$argon2id$v=%d$m=8192,t=1,p=1,k=7$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	for _, pw := range []string{"any password at all", "another guess entirely"} {
		if _, err := h.Verify(forged, pw); !errors.Is(err, ErrPepperUnavailable) {
			t.Fatalf("missing pepper version must fail closed with ErrPepperUnavailable, got %v", err)
		}
	}
	// No keyring at all is an error too, not an unpeppered fallback.
	bare := testHasher()
	if _, err := bare.Verify(forged, "any password at all"); err == nil {
		t.Fatal("a peppered verifier verified without a keyring")
	}
}

// TestPolicy covers CRED-002: with the default settings a password needs 15
// to 128 Unicode characters (counted as characters, not bytes), common or
// compromised and trivially patterned passwords are rejected, and there are
// no composition rules (an all-lower-case passphrase is accepted).
func TestPolicy(t *testing.T) {
	d := configuration.Defaults().Security.Password
	if d.MinLength != 15 || d.MaxLength != 128 {
		t.Fatalf("default length bounds: min %d max %d, want 15 and 128", d.MinLength, d.MaxLength)
	}
	p, err := NewPolicy(d.MinLength, d.MaxLength, d.MaxBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	// Length is counted in characters: 15 two-byte characters pass, 14 do
	// not; 128 characters (also beyond 64) pass, 129 do not.
	word := func(n int) string {
		runes := []rune("çàéñöüßøåæ")
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteRune(runes[(i*7+i/3)%len(runes)])
		}
		return b.String()
	}
	for n, want := range map[int]string{14: "too_short", 15: "", 64: "", 128: "", 129: "too_long"} {
		got := ""
		if v := p.Check(word(n), 0); v != nil {
			got = v.Code
		}
		if got != want {
			t.Errorf("%d-character password: %q want %q", n, got, want)
		}
	}
	cases := map[string]string{
		"short":                       "too_short",
		"passwordpassword":            "compromised",
		"aaaaaaaaaaaaaaaaaaaa":        "repetitive",
		"abcdefghijklmnopqrst":        "repetitive",
		"alice@example.comalice":      "",
		"a perfectly fine passphrase": "",
	}
	for pw, want := range cases {
		v := p.Check(pw, 0)
		got := ""
		if v != nil {
			got = v.Code
		}
		if got != want {
			t.Errorf("Check(%q)=%q want %q", pw, got, want)
		}
	}
	if v := p.Check("aliceexample1234", 0, "aliceexample1234"); v == nil || v.Code != "contains_identifier" {
		t.Fatal("identifier-derived password must be rejected")
	}
}

// TestTOTPWindowAndStep covers MFA-002's bounded clock tolerance: a code
// matches only within the configured number of steps around now, and the
// matched step is returned so the caller can refuse a consumed step.
func TestTOTPWindowAndStep(t *testing.T) {
	seed := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	code, _ := TOTPCode(seed, TOTPStep(now))
	step, ok := MatchTOTP(seed, code, now, 1)
	if !ok || step != TOTPStep(now) {
		t.Fatal("current code must match")
	}
	prev, _ := TOTPCode(seed, TOTPStep(now)-1)
	if s, ok := MatchTOTP(seed, prev, now, 1); !ok || s != TOTPStep(now)-1 {
		t.Fatal("one-step skew allowed")
	}
	if _, ok := MatchTOTP(seed, prev, now, 0); ok && prev != code {
		t.Fatal("with no skew configured only the current step matches")
	}
	old, _ := TOTPCode(seed, TOTPStep(now)-3)
	if _, ok := MatchTOTP(seed, old, now, 1); ok {
		t.Fatal("codes outside the window must fail")
	}
}
