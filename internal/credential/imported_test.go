package credential

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// TestImportedForeignVerifiers covers MIG-006 for the bcrypt and PBKDF2
// import formats: accepted within the cost bounds, verified against the
// password as the source hashed it, always rehashed, refused outside the
// bounds and retired with the legacy window.
func TestImportedForeignVerifiers(t *testing.T) {
	h := &Hasher{Params: Params{Memory: 1024, Time: 1, Threads: 1}, MaxBytes: 1024}
	pw := "correct horse battery staple"
	bc := func(cost int) string {
		b, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	pb := func(prf string, fn func() hash.Hash, iter int) string {
		salt := []byte("0123456789abcdef")
		sum, err := pbkdf2.Key(fn, pw, salt, iter, 32)
		if err != nil {
			t.Fatal(err)
		}
		return PBKDF2Verifier(prf, iter, salt, sum)
	}
	good := map[string]string{
		"bcrypt 10":       bc(10),
		"bcrypt 2b":       strings.Replace(bc(10), "$2a$", "$2b$", 1),
		"pbkdf2-sha1":     pb("sha1", sha1.New, 10_000),
		"pbkdf2-sha256":   pb("sha256", sha256.New, 27_500),
		"pbkdf2-sha512":   pb("sha512", sha512.New, 10_000),
		"pbkdf2 max iter": pb("sha256", sha256.New, MaxPBKDF2Iterations),
	}
	for name, v := range good {
		if err := ValidateImportedHash(v); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
		if !IsLegacyVerifier(v) || !IsForeignVerifier(v) {
			t.Fatalf("%s not classified as a legacy foreign verifier", name)
		}
		rehash, err := h.Verify(v, pw)
		if err != nil || !rehash {
			t.Fatalf("%s: verify=%v rehash=%v", name, err, rehash)
		}
		if _, err := h.Verify(v, pw+"!"); !errors.Is(err, ErrMismatch) {
			t.Fatalf("%s accepted a wrong password: %v", name, err)
		}
	}
	bad := map[string]string{
		"bcrypt below the floor": bc(8),
		"bcrypt malformed":       "$2a$10$tooshort",
		"pbkdf2 below the floor": pb("sha256", sha256.New, 1000),
		"pbkdf2 above the ceiling": PBKDF2Verifier("sha256", MaxPBKDF2Iterations+1, []byte("0123456789abcdef"),
			make([]byte, 32)),
		"pbkdf2 unknown prf":     "$pbkdf2-md5$i=20000$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"pbkdf2 short salt":      "$pbkdf2-sha256$i=20000$YWJj$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"pbkdf2 no i= prefix":    "$pbkdf2-sha256$20000$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"md5crypt":               "$1$q8Fz3kLp$5gCbBfSTKFEkVwsPpodgv0",
		"firebase scrypt":        "$f_scrypt$abc$def$m=14$r=8$s=Bw==",
		"plain sha512crypt":      "$6$salt$hash",
		"argon2i (not argon2id)": "$argon2i$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
	}
	for name, v := range bad {
		if err := ValidateImportedHash(v); err == nil {
			t.Fatalf("%s accepted", name)
		}
		if _, err := h.Verify(v, pw); err == nil {
			t.Fatalf("%s verified", name)
		}
	}

	// The migration window ends for every legacy format (CRED-004).
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	h.Now = func() time.Time { return now }
	h.LegacyUntil = now
	if _, err := h.Verify(good["bcrypt 10"], pw); !errors.Is(err, ErrLegacyRetired) {
		t.Fatalf("bcrypt verifier after the window: %v", err)
	}
	if _, err := h.Verify(good["pbkdf2-sha256"], pw); !errors.Is(err, ErrLegacyRetired) {
		t.Fatalf("PBKDF2 verifier after the window: %v", err)
	}
}

// TestImportedVerifierRawPassword covers verifiers computed by a source over
// the password as typed: a password that NFKC normalization changes still
// verifies (and is rehashed to the normalized local form), while native
// verifiers keep verifying the normalized form.
func TestImportedVerifierRawPassword(t *testing.T) {
	h := &Hasher{Params: Params{Memory: 1024, Time: 1, Threads: 1}, MaxBytes: 1024}
	raw := "ｆｕｌｌｗｉｄｔｈ ﬁle passphrase 2026" // full-width letters and a ligature
	if n, _ := h.Normalize(raw); n == raw {
		t.Fatal("test password must change under NFKC")
	}
	salt := []byte("saltsaltsaltsalt")
	sum := argon2.IDKey([]byte(raw), salt, 2, 1024, 1, 32)
	imported := fmt.Sprintf("$argon2id$v=19$m=1024,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	rehash, err := h.Verify(imported, raw)
	if err != nil || !rehash {
		t.Fatalf("imported Argon2id over the raw password: %v rehash=%v", err, rehash)
	}
	b, _ := bcrypt.GenerateFromPassword([]byte(raw), 10)
	if _, err := h.Verify(string(b), raw); err != nil {
		t.Fatalf("imported bcrypt over the raw password: %v", err)
	}
	native, err := h.Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rehash, err := h.Verify(native, raw); err != nil || rehash {
		t.Fatalf("native verifier: %v rehash=%v", err, rehash)
	}
	if _, err := h.Verify(native, "wrong passphrase"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("native verifier accepted a wrong password: %v", err)
	}
}
